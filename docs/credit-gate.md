# Credit gate

The credit gate lets bulk machine work (the Batch API client) and read-only
headless `claude -p` runs spend the Team API credit first, so the
subscription quota lasts longer, and it stops them before the protected
credit (the old promo remainder R and the purchased balance V) is touched.
It lives in the dashboard process: the decision and the reservation are ONE
synchronous SQLite transaction, so no second process can decide on a stale
sum. It is off by default and changes nothing until `CREDIT_GATE_MODE` says
otherwise.

What it is not: it is not a billing system. Every number is an overestimate
from local data (usage.jsonl and the headless runs, priced from a price
table), calibrated by an owner-approved reading of the Console Billing page.
The gate can only close on its own; opening needs the owner's button press.

Card fec6335f. Source: `src/web/credit-gate/`, `src/web/routes/credit-gate.ts`,
the caller `scripts/credit-run.py`.

## Contents

- [States and transitions](#states-and-transitions)
- [What R_est is](#what-r_est-is)
- [Reservations](#reservations)
- [Signals](#signals)
- [The STOP file](#the-stop-file)
- [Notifications: classes and quotas](#notifications-classes-and-quotas)
- [The status endpoint](#the-status-endpoint)
- [Calibration, canary and incident-clear approvals](#calibration-canary-and-incident-clear-approvals)
- [Headless runs: API and CLI](#headless-runs-api-and-cli)
- [The canary flow](#the-canary-flow)
- [The Vault key-read counter](#the-vault-key-read-counter)
- [Configuration and modes](#configuration-and-modes)
- [Deployment order](#deployment-order)
- [Rollback](#rollback)
- [Known limits](#known-limits)

## States and transitions

| State | Meaning | Leaves it by |
|---|---|---|
| `CLOSED` | Default. No new batch or run is admitted. | Transient reasons lift on their own; a latched one needs a NEWER calibration. |
| `OPEN` | Work is admitted against the reservation rules. | Any closing reason. |
| `HOLD` | The measurement is uncertain. | A newer calibration AND every HOLD condition gone. |
| `INCIDENT` | A protected store or a safety rule is hurt. | Only an owner `credit_gate_incident_clear` approval (one cause per approval), which lands in a latched `CLOSED`; then a newer calibration. |

Severity order: OPEN < CLOSED < HOLD < INCIDENT. A cause that arrives in the
gate (a signal, a closure found inside a reservation) can keep or raise the
severity, never lower it, and never opens. OPEN is reached only from the
gate's own tick (`decide()`), only in `enforce` mode, and only when no closing
reason of any kind is present.

Closing reasons:

- Transient (lift when the cause is gone): `shadow_mode`, `mode_unknown`,
  `config_missing`/`config_invalid`, `pricing_*` (missing, stale = `verified_at`
  older than 30 days), `no_calibration`/`calibration_invalid`, `ledger_stale`
  (older than `maxLedgerAgeS`), `unpriced_rows`, `no_live_grant`, `expired`
  (now is past `close_at`), `protected_mismatch` (the calibration shows R or V
  other than `config.protected`), `stop_unverifiable` (shadow mode only; in
  enforce mode a STOP that cannot be checked is the `stop_place_failed` HOLD),
  `stop_release_failed` (the gate's own STOP could not be taken away; it goes
  when a release goes through, see the STOP file).
- Latched (need a calibration newer than the one current when they latched):
  `threshold` (R_est at or below the effective T_close, C-04/C-05),
  `human_stop`, `disarm`, `auth_401`, `ledger_saturated`, `incident_cleared`.
- HOLD events: `ledger_error`, `tick_error`, `batch_overrun`,
  `reservation_unknown`, `usage_log_failed`, `stop_race`, B-05 mismatches and
  undecidable canaries. HOLD conditions that must also be gone:
  `ledger_broken:<source>`, `canary_close_timeout` (a canary window whose
  after-reading was not recorded within `canaryCloseMaxH` hours of the
  canary's settle; it goes with the close, see the STOP file), and
  `stop_place_failed` (the gate's STOP could not be put down when it had to
  be, or in enforce mode could not even be checked; it goes when the STOP is
  down again, see the STOP file).
- INCIDENT: `guard_event` (one per line the PR-A guard appends), `guard_backlog`
  (the guard-event file already had lines when the gate first read it),
  damage to that file, `credit_balance_too_low`, a protected store that fell
  (D-02), a canary that spent from a protected store or from no grant (K-03).

A latch binds to the LARGEST calibration id the gate has ever seen, not to the
current one, so a calibration source that is empty for a moment cannot make an
old calibration lift a new closure.

Opening a CLOSED gate needs, in one tick: enforce mode, a valid calibration,
a fresh ledger and price table, `now < close_at`, no human STOP, no open
INCIDENT, and `R_est >= T_reopen` (otherwise the reason is `below_reopen`).
Once OPEN the gate stays open down to T_close (hysteresis).

Thresholds (config, USD, two decimals): `tClose` (not below 20.00), `tLowcal`,
`tReopen`, `tCloseLowcalFallback`, `lowcalWaitH`; the order
`tClose <= tCloseLowcalFallback < tReopen <= tLowcal` is enforced by the
loader. At `R_est <= tLowcal` the gate asks once per calibration for a fresh
Console reading (`lowcal_request`, a directive); after `lowcalWaitH` hours
without a newer calibration the effective T_close rises to
`tCloseLowcalFallback` (`lowcal_fallback`). A newer calibration resets both.

## What R_est is

```
R_est(t) = sum of remaining(g) for calibration grants g with expiry(g) > t
         - L(t)
         - open reservations
```

- L(t) is the ledger's `max(est, cli)` sum for rows stamped at or after the
  calibration's `captured_at_lb` (the earliest moment the screenshot may have
  been taken; the overlap overcounts, the safe direction).
- An open batch reservation counts `max(0, amount - what the ledger already
  holds for its batch_id)`, so a request is never subtracted twice.
- A grant that expired drops out with its whole calibrated remainder (D-04).
- `close_at` = latest expiry of a grant that still has a remainder minus
  `expiryMarginH` (at least 2 hours); a date-only expiry counts from 00:00:00Z.
- C-06b (admission only): a job counts only the grants still alive at
  `now + horizon` (24 h for a batch via `batchHorizonH`, `wallClockMin` for a
  headless run), and nothing is admitted after the last expiry minus
  `max(expiryMarginH, horizon)` (`expiry_horizon`; status `close_at_batch`).
  The tick's R_est and `close_at` stay instantaneous.

Money is integer micro-USD everywhere; the API shows decimal strings.

## Reservations

`reserve()` is one `BEGIN IMMEDIATE` transaction with no `await`. It checks, in
this order (first failure wins; a closing failure also closes the gate):

1. mode (`mode_unknown`), state `OPEN` (`gate_closed` with the state's reason),
   no canary window: `canary_in_progress` while a canary's reservation is open,
   `canary_window_open` after its settle until its after-reading is recorded;
   and for a canary nothing else open or unknown (`reservations_open`);
2. the config, the ledger (age at most `maxLedgerAgeS`, `ledger_stale`), the
   tick's evaluation (at most that old, `gate_state_stale`), the price table,
   the calibration (the tick must have seen this very one:
   `calibration_changed`);
3. `no_live_grant`, `expired`; `headless_disabled` (no headless config),
   `concurrency_limit` (`headless.maxConcurrent`), `expiry_horizon`;
4. `unpriced_rows`, `ledger_saturated`, `model_unpriced`, `daily_cap`
   (`headless.dailyCapUsd`, off unless set);
5. `R_est <= T_close` closes the gate (`threshold`, answer `below_threshold`);
   admission needs `R_est(at horizon) - amount >= T_close` (`below_threshold`).

If the reservation brings R_est exactly to T_close, it is admitted and the
gate closes right behind it (`closed: true`). `gate_busy` means the write lock
was not free; nothing was decided.

Amounts: a headless run or canary reserves `budget x reservationFactor`
(factor at least 1.5, C-02). A batch reserves the server-side upper estimate
from the client's token totals: every input token at the worst input rate of
every price band, every output token at the worst output rate, the batch
discount only when the price table carries a verified one.

Lifecycle of a batch reservation: `reserve` -> `bind` (batch_id and
`expected_requests`, which must equal the reserved request count; a batch id
that already has ledger rows or another reservation is refused) -> `complete`
(settles when the ledger holds `expected_requests` rows for the batch).
`release` with `rejected_4xx` gives the reservation back, only before a bind;
`unknown_outcome` keeps it counted and goes to HOLD. An unbound batch
reservation older than 1 hour and an unsettled headless or canary
reservation older than 24 hours become `unknown` (HOLD). A batch whose
ingested cost exceeds its amount is a one-time `batch_overrun` HOLD.
A batch whose requests partly failed never reaches `expected_requests` and
stays reserved (safe; see Known limits).

Headless and canary reservations are settled by the runner at the end of the
run together with the ledger booking (`settleHeadless`, one transaction;
idempotent). If the ledger throws, nothing is settled and the gate goes to
HOLD.

## Signals

`POST /api/credit-gate/signals {kind, source, detail?}` is open to any Bearer
caller, so it is built to be harmless: it only closes.

| kind | effect |
|---|---|
| `disarm` | latched `CLOSED` (`disarm`) |
| `auth_401` | latched `CLOSED` (`auth_401`) |
| `usage_log_failed` | `HOLD` |
| `credit_balance_too_low` | `INCIDENT` |

Limits, all by design (review rounds B10, B12-B14):

- One open INCIDENT cause per signal kind. The cause's identity is the signal
  kind alone; a new `source` or `detail` does not open a new cause, a new
  directive or a new owner clear. The source and detail stay in the signal's
  own audit row.
- A gate that is already latched at least as hard as the signal would latch it
  (CLOSED or higher for `disarm`/`auth_401`, HOLD or higher for
  `usage_log_failed`, bound to the largest calibration id) ignores a repeat:
  the state row is untouched. The signal still gets its own `signal` audit row.
  A latch bound below the newest calibration id is re-latched as before.
- A signal never makes a `transition` row for a new reason in the same state
  (`stateOnly`): only a change of STATE does. A genuine state change is never
  queued behind a signal flood.
- The report decision is keyed on the last REPORTED pair (`reported_state`,
  `reported_reason`), not on the state row's reason. A signal may rewrite the
  row's reason; the next tick gives the gate's own reason back, and that is no
  change against what was reported. Transitions are written in `writeState`
  and nowhere else.
- Off mode answers `{enforced:false}`. Shadow mode records the signal and
  answers `enforced:false`; enforce mode answers `{enforced:true, state}`.
  `source`: 1-64 of `A-Za-z0-9_.:-`; `detail`: at most 2000 characters, scrubbed
  of key-like strings before it is stored.
- The headless runner sends `disarm` on its own faults (a failed launch, an
  unusable `ps`, a settle that keeps failing, an untrusted row, a startup
  reconcile problem), `credit_balance_too_low` when a run's answer says the
  balance is too low, and `auth_401` for an authentication error.

## The STOP file

The batch client stops its new submissions when a STOP file exists. The gate
writes its own STOP while it is not OPEN (enforce mode only) and removes it
when it opens again: a tick that would open the gate takes its STOP away
first, while the gate is still closed, and only then decides the opening in
the same tick (the `stop_released` row comes before the OPEN transition). It
never touches a human's.

- Writing: a tmp file (`O_EXCL`, 0600, content `credit-gate v1 <nonce>`)
  hard-linked to the STOP name with `link()`. `EEXIST` means a STOP is already
  there: the gate does not overwrite it and does not own it (`stop_exists`).
- The gate owns a STOP only while it is exactly what it wrote (regular file,
  recorded dev, inode, size, mtime in nanoseconds, content). A `touch` on the
  gate's own STOP is a human STOP. A human STOP while OPEN is a latched
  `human_stop`; while one is there the gate does not open.
- Removing: check, `rename` to `STOP.credit-gate-release.<nonce>`, check the
  renamed file again on its open descriptor, then `unlink`. If it is not the
  gate's it is put back (with `link()`, so a newer STOP is never overwritten);
  if both exist, both stay, and the gate goes to HOLD (`stop_race`).
- A canary keeps the gate's STOP down even in OPEN, so the canary's cost is the
  only one between its two readings (K-01). The canary WINDOW opens with the
  canary's admission and stays open after its run is settled, until the
  explicit close step: the recording of the after-reading (the next
  non-rejected reading the processor records, `closeCanary`, audit row
  `canary_window_closed`). Until then every other reservation is refused
  (`canary_in_progress` during the run, `canary_window_open` after it). A
  rejected reading does not close it; a repeated close or one without a window
  is refused and changes nothing. The window is in the database
  (`credit_gate_state.canary_res_id`), so a dashboard restart keeps it. If the
  after-reading is not recorded within `canaryCloseMaxH` hours of the settle
  (config, default 6, at most 24 in the code), the gate goes on HOLD
  `canary_close_timeout`: it does not open and the STOP stays down; the late
  after-reading closes the window and, as a newer calibration, lifts the HOLD.
- A STOP the gate must put down but cannot (CW1) -- the directory is not
  writable (`EACCES`), missing (`ENOENT`), on a read-only file system
  (`EROFS`), or another file took the name meanwhile -- is a HOLD
  `stop_place_failed`, latched under the latch base. So is a canary admission
  after which no STOP is down (none there, or none that can be checked): the
  canary's reservation stands, its window keeps everything else out, and the
  gate holds. The gate is never OPEN in this state. The episode is reported
  once, when it starts: one report row (the HOLD transition with `why` and the
  error code; a `stop_place_failed` row when the state does not change, e.g. in
  INCIDENT), so one message and one daily line, and one error log line.
  Every tick tries the STOP again and, while it still fails, writes nothing
  (`credit_gate_state.stop_place_failed_at` marks the episode). What lifts the
  HOLD is the ordinary HOLD rule, both parts: (1) the condition is gone -- the
  gate's STOP is down again (a tick placed it, or found its own in place);
  (2) a calibration newer than the one the HOLD latched under. Neither alone
  opens: a newer calibration while the STOP still cannot be written keeps the
  HOLD, and a repaired directory without a newer calibration keeps it too.
- In enforce mode a STOP that cannot even be checked -- the directory has mode
  000 (`lstat` `EACCES`), an `EIO` -- is the same HOLD `stop_place_failed`
  (`why` `not_down`, the error code), not a transient close: the batch path
  may be unstopped, and the gate cannot show otherwise. It is reported once,
  as the HOLD itself. The gate's owner record stays (the STOP under the name
  may be its own, only hidden), so after the repair its own STOP is found as
  the gate's, not as a human's. Repairing the permissions lifts nothing on
  its own: the STOP must be shown down (found, or placed) AND a calibration
  newer than the latch must come; until then the gate holds on the same
  calibration. In shadow mode (no STOP duty) it stays the transient
  `stop_unverifiable`.
- A STOP the gate must take away but cannot (CS1) -- the directory is `r-x`
  (`rename` `EACCES`), a read-only file system (`EROFS`) -- keeps the gate
  CLOSED `stop_release_failed` (transient, `why` `error` with the error code),
  never OPEN with its STOP still down; the STOP stays, so the batch path stays
  stopped. On an OPEN gate (a canary window just closed) the gate closes the
  same way. `credit_gate_state.stop_release_failed_at` marks the episode: it
  is reported once, against the last reported state and reason (one message,
  one daily line), with one error log line; every later tick that would open
  the gate tries the release again first and, while it still fails, writes
  nothing. Another closing reason during the episode keeps the STOP down as
  usual -- the release is only tried when nothing else closes the gate. The
  first release that goes through clears the column, and the same tick opens
  the gate.
- Switching to `off` leaves the STOP in hand. The status shows its owner:
  `gate`, `human`, `none` or `unknown`.

## Notifications: classes and quotas

Every audit row of `credit_gate_events` is delivered to the main agent by the
notifier after each tick: a line in the main agent's daily log, and by class a
message. A delivery counts only when a message id came back. One try plus 3
retries inside 5 minutes (20 s apart); then the row is `failed` (status
`notify.failed`, one error log). A claim that never reported back is retried
after 2 minutes.

| Class | Rows | Delivery |
|---|---|---|
| directive | a `transition` into `INCIDENT`, `incident_cause`, `lowcal_request` | `sendSystemDirective` (authenticated; the main agent can verify the queue row by `msg_id`), with a `TEENDO` (to-do) line |
| info | other transitions and the remaining actionable kinds (`fault`, `batch_overrun`, `reservation_unknown`, `guard_*`, `stop_*`, `reservation_rejected`, `signal`, `canary_evaluated`, `calibration_*`, ...) | an info message from `system` to the main agent |
| quiet | `stop_placed`, `stop_released`, `calibration`, `incident_clear`, `canary_consumed`, `canary_window_opened`, `canary_window_closed`, `key_reads_daily`, ... | daily-log line only |
| silent | `reservation_bound`, `reservation_released`, `reservation_settled` | audit row only |

Each round takes the rows in four classes, most urgent first, each with its own
quota of 50 rows: (1) directives, (2) other transitions, (3) all other
non-coalescing kinds, (4) the coalescing kinds. A backlog in one class (a flood
of Bearer signals or refusals) never holds back the next, so a genuine INCIDENT
goes out in the first round (L-01: within 5 minutes).

Coalescing (B12): `reservation_rejected`, `fault` and `signal` rows repeat
every tick or every request. A row of the same kind and reason inside 10
minutes of the newest one already SENT is not messaged: it gets its daily line,
marked "osszevont ismetles" (repeat), and the state `coalesced`. In the last
class the quota of 50 counts the rows tried as messages, so repeats, however
many, take no share of the round and are marked in bulk. E2 holds: transitions
and `incident_cause` rows are never coalesced. Free text typed by a caller
(a signal's `detail`, an unknown `source` in a directive) does not ride on a
message; in a directive an unknown signal source reads `egyeb`.

## The status endpoint

`GET /api/credit-gate/status` (Bearer) answers in every mode, also with the gate
off: `mode`, `state`, `reason`, `since`, `r_est_usd`, `ledger` (`l_usd`,
`age_s`, `unpriced`, `error`, `saturated`, `sources[]` with `ok`/`partial`/
`broken`), `reservations`, `thresholds`, `calibration`, `close_at`,
`close_at_batch`, `next_expiry`, `latch`, `lowcal`, `stop` (`present`, `owner`),
`canary_in_progress` (a canary's reservation is open), `canary_window` (null, or
`reservation_id`, `run_id`, `opened_at`, `run_ended_at`, `close_by`: the open
canary window and its deadline), plus `notify` (`failed`, `pending`), `approvals.
payload_mismatch`, `key_reads` (today's count by principal), `last_event`, and
`canary` (`approved_hash`, `current_hash`, `match`). It never carries a secret.
The `/status` system block shows one line (`creditGateStatusLine`).

## Calibration, canary and incident-clear approvals

Three approval categories carry the owner's decisions; the prefix
`credit_gate_` is reserved for them. Each has a canonical payload (the text
`json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",",":"))`
gives, UTF-8) and `content_hash` is its sha256; the dashboard refuses any other
spelling (400, naming the first bad field). The requester (`agent_id`) must be
a bare agent id.

| Category | Payload | Effect |
|---|---|---|
| `credit_gate_calibration` | `captured_at_lb`, `grants[]` (granted, expires, original_usd, remaining_usd), `protected` (R, V), `screenshot` | One `credit_calibrations` row, whatever came of it |
| `credit_gate_canary` | `config_hash`, `model`, `budget_usd` (below 1.00), `min_expected_usd` (0.10 up to the budget), `before_calibration_id` (the approval id of the before-reading), `node`, `cwd`, `prompt_sha256` | Lets exactly one canary run start (below) |
| `credit_gate_incident_clear` | `incident_event_id` | Lifts the newest open INCIDENT cause it names |

Who may decide: only the owner's Telegram button counts (`resolved_by =
owner:telegram:<id>` with the button trace, `isOwnerVerified`). A PATCH-decided
approval, another user's press, a changed payload or the wrong category is
skipped, never consumed, never opening. The owner is `ALLOWED_CHAT_ID` from
`.env` and nothing else; empty or a placeholder means nothing is processed
(`owner_unset` HOLD). The id that decided the first accepted reading is pinned.
If the configured owner later differs, the gate goes to HOLD `owner_changed`
and processes nothing for the new owner; only a NEW incident-clear decided by
the PINNED owner that names the `owner_changed` event re-pins it (or the
configuration goes back, `owner_change_reverted`).

Evaluation of a reading (`evaluateCalibration`): D-02 first, before anything
else: V or R below the baseline or below the previous reading is an INCIDENT.
Then time rules (not in the future, at most 24 hours old, strictly newer than
the previous reading, newer than the last incident-clear) reject it without a
state change; a store the reading does not show is a HOLD; then B-05: the
provider's spend on the grants both readings show against the ledger between
the two lower bounds, `|diff| <= max(1 USD, 5%)`, else HOLD. Only the newest
`accepted` row is the gate's calibration.

## Headless runs: API and CLI

### API (Bearer + `X-Agent-Id`)

`POST /api/credit-gate/runs` `{node_id, model, effort, budget_usd, cwd, prompt,
mode, canary_approval_id?}` -> `202 {run_id, mode, status:"running"}`.

- 409 with a `reason`: the gate does not run it (`gate_off`, `gate_shadow`,
  `gate_not_running`, `runs_unavailable`, `gate_closed`, `canary_in_progress`,
  `canary_window_open`, `reservations_open`, `caller_not_allowed`, `hash_not_approved`,
  `key_missing`, `headless_disabled`, `config_invalid`, `concurrency_limit`,
  `daily_cap`, `below_threshold`, `expiry_horizon`, `canary_*`, ...).
  `approval_spent: true` marks a canary approval that was consumed.
- 400 / 413: the request is wrong (node id, model outside Opus 5.5 / Sonnet 5.5
  and the config list, effort other than `high`/`xhigh`, budget not a two-decimal
  string or above `maxBudgetUsd`, empty or over-256 KB prompt, any `cwd_*`
  refusal, a `config_hash` in the body).
- The caller is only the `X-Agent-Id` claim (shared Bearer token), checked
  against `headless.allowedCallers`. It stops an accidental caller, not a
  deliberate one; what bounds the spending is the gate.
- `cwd` must be a LINKED git worktree (`.git` is a file), canonical (no `..`, no
  symlink in the path), owned by the dashboard's user, strictly under a
  configured root, not inside or around the install root, the store or the runs
  dir, and no symlink in its tree may resolve outside it
  (`cwd_symlink_escape`, e.g. a symlinked `node_modules`).

`GET /api/credit-gate/runs/<id>` and `POST .../cancel` serve only the caller that
started the run; anyone else gets what an unknown id gets (404), so the run does
not show. The caller's own run stays visible and stoppable even when the config
goes invalid mid-run. The view carries state, `exit_code`, `signal`, `reason`,
`budget_usd`, `est_usd`, `cli_usd`, `basis` (how the ledger booked it),
`is_error`, `num_turns`, `total_cost_usd`, `usage` and `result_text` (the
answer, key-shaped strings replaced, at most 64 KB) -- never the prompt, the key
or the run directory. Cancel: 202 `{cancelling:true}`, or 409 `not_running`.

Run status: `starting`, `spawning`, `running`, then `succeeded`, `failed`,
`timeout`, `cancelled`, `killed`, `lost`, `refused`, `spawn_failed`,
`secret_residue`.

### What the child is

The runner starts the pinned `claude` binary (`headless.claudeBin`, its sha256
checked before every spawn) with the exact argv of the canary template:
`-p --bare --restricted --model --effort --max-budget-usd --output-format json
--no-session-persistence --settings --tools Read --allowedTools Read
--permission-mode dontAsk --permission-prompts none --strict-mcp-config
--disable-slash-commands`. The prompt goes on stdin. The environment is built
from nothing (no parent env): a fixed `PATH`, `HOME`, `TMPDIR`,
`CLAUDE_CONFIG_DIR`, an empty `TELEGRAM_STATE_DIR`, and a few `DISABLE_*`
variables. The key reaches the CLI by default through an `apiKeyHelper` that
prints a 0600 file of the 0700 run directory (`keyMode: helper`); that file is
deleted first at the end of every run, and every dashboard start sweeps the
runs directory. **The only enabled tool profile is `read`: a headless run can
read the worktree and answer in text. It cannot run Bash, edit or write files.**

At the end of a run: the JSON result is read (usage and cost only), the run
directory is scanned for key material, the gate books the run in the ledger
(the JSON, else the transcript, else the whole reservation: B-04) and settles
the reservation. After a dashboard restart the runner re-attaches a live run
(same pid and start time) or closes it by B-04.

### CLI: `scripts/credit-run.py`

```
credit-run.py --node <id> --model <claude-opus-5-5|claude-sonnet-5-5> --effort <high|xhigh>
              --budget <USD, two decimals> --cwd <worktree> --prompt-file <path>
              [--canary-approval-id <id>] [--api http://localhost:3420]
              [--token-file PATH] [--max-wait-min 120]
```

It POSTs, then polls every 10 s. The token is read from the file at run time
and sent only to a loopback dashboard; the JSON body is built by `json.dumps`.
One JSON line on stdout says what happened; progress goes to stderr.

| Exit | Meaning | What the caller does |
|---|---|---|
| 0 | the run succeeded; result on stdout | use it |
| 2 | the run failed, timed out, was cancelled or lost; or the dashboard stopped following it and the cancel was taken | the run is over; decide on the cost and the output |
| 3 | the gate does not run it (any 409) | use the subagent |
| 4 | bad request (refused locally, or 400/404/413) | fix the request |
| 5 | the dashboard cannot be used and nothing started (refused connection, no token, 401/403, 5xx) | use the subagent |
| 6 | interrupted and NOTHING is left running: nothing had been sent, or the cancel was taken (202) | nothing runs |
| 7 | UNKNOWN: the POST's answer was lost, the started run cannot be polled, or it had to be stopped and the dashboard did not take the cancel | a run may be going on |

**6 versus 7.** 6 is only for a cancel the dashboard took (202) or a signal
before anything was sent. Every other case in which a run may exist or still
run is 7, with `run_id` in the output and `cancelled:false`. On 7 do NOT fall
back to the subagent on the same worktree: a second writer would be unleashed
next to a possibly live run. Check `GET /runs/<run_id>` and the status, cancel
by hand if needed, and let the coordinator decide. Signals (SIGTERM, SIGHUP,
SIGINT) are blocked while the POST is in flight, so the id of a run the
dashboard has just started is never lost; the run is cancelled right after the
answer.

## The canary flow

A normal run starts only under a config hash that a successful canary approved.
The hash is the sha256 of the canonical launch template (code version, key
mode, argv template with placeholders for model/effort/budget, env names and
values, settings, `prompt: stdin`). A different key mode is a different hash and
needs its own canary. The CLI's path, sha256 and version are NOT in the hash:
the binary is pinned by `claudeBinSha256` and the version is logged on every
run, so a CLI update asks for a new pin in the config, not for a new canary.

Steps (spec K-01..K-03):

1. Console screenshot right before; the owner approves a
   `credit_gate_calibration` (the before-reading, accepted).
2. The owner approves a `credit_gate_canary` bound to the config hash, the
   model, the budget (below 1.00), the expected minimum (at least 0.10), the
   before-reading's approval id, and the run's `node`, `cwd` and the sha256 of
   its prompt.
3. `POST /runs` with `mode:"canary"` and `canary_approval_id`. The route checks
   everything that costs nothing first, then takes a run id from the runner,
   and `consumeCanaryApproval` consumes the approval ONCE for exactly this
   hash, model, budget, run id, node, cwd and prompt hash, and only if the
   before-reading is the newest accepted calibration, at most 24 hours old,
   with no canary yet. The runner then takes the hash from the consumed row,
   once, for this run only. A `config_hash` in the request body is refused.
4. A canary is admitted alone: no other reservation open or unknown. Its
   admission opens the canary window: the gate's STOP stays down, and nothing
   else is admitted, for the run AND after it (status `canary_in_progress`
   false, `canary_window` set) until step 5.
5. Console screenshot right after; the owner approves another calibration. It
   is the after-reading: evaluating it evaluates the canary, and recording it
   is the close step of the canary window (`canary_window_closed`). Only then
   does the STOP follow the state again (in OPEN it goes). A rejected reading
   is no after-reading; if none is recorded within `canaryCloseMaxH` hours of
   the run's settle, the gate holds (`canary_close_timeout`).

Outcomes (`evaluateCanary`):

| Outcome | When | Effect |
|---|---|---|
| success | one Team grant fell by the ledger amount within `max(0.05 USD, 20%)`, V and R unchanged | the hash is approved (`canary.approved_hash`); a later failure withdraws it |
| INCIDENT (protected) | V or R fell | the after-reading's own D-02 INCIDENT `protected_decreased` (checked first, so no second `canary_*` cause); the canary row records `incident` |
| INCIDENT (no grant) | V and R unchanged, no Team grant fell, and no grant expired between the two readings (a grant that expired in between makes it undecidable instead) | `canary_no_grant_decreased` INCIDENT |
| undecidable | any other case: the run is not in the window, below the minimum, the amount does not match, other headless rows in the window, V or R rose, the after-reading is not the next reading | HOLD `canary_undecidable`; repeat only with a new approval |

The grant that fell is recorded: it answers which of the two 200 USD grants
pays first.

## The Vault key-read counter

`GET /api/vault/<id>` counts a read when `<id>` is the config's `vaultKeyId`
(default `ANTHROPIC_API_KEY_BATCH` if the config is unusable), in shadow and
enforce mode, per Budapest calendar day and per principal's name (never a
value). The count is best effort and never in the Vault's way. Today's count is
in the status; each finished day becomes one `key_reads_daily` event that the
notifier writes to the daily log, so a reader nobody expects shows up there.
With the gate off, nothing is written, not even a table.

## Configuration and modes

`CREDIT_GATE_MODE` is read from `.env` only (not the Settings registry, so a
Bearer call cannot switch it off):

| Value | Behaviour |
|---|---|
| missing or empty, `off` | Today's behaviour, byte for byte. No table, no timer, no file. Reservations answer `{enforced:false}`, runs 409 `gate_off`. The runs directory is still swept at start (the rollback path). |
| `shadow` | Ledger, R_est, events and notices run; the gate never opens (`shadow_mode`), never touches the STOP, and reservations answer `{enforced:false}`; runs 409 `gate_shadow`. |
| `enforce` | The gate decides. |
| anything else | Treated as `enforce` and the gate never opens (`mode_unknown`): a typo must not read as a decision to spend. |

A web-only (staging) instance never runs the gate (`gate_not_running`).

Data files under `store/credit-gate/` (folder 0700, files 0600, no symlink; the
loader rejects the whole file on any doubt and the gate stays closed with the
reason): `config.json` (`credit-gate-config/v1`) and `pricing.json`
(`credit-pricing/v1`, `verified_at` at most 30 days old). No endpoint writes
either.

`config.json` keys: `ledgerSources[]` (`id`, absolute `path`, `format:
"usage-jsonl-v1"`), `stopFile`, `thresholds`, `expiryMarginH` (2-168),
`batchHorizonH` (24-168), `refreshS` (5-60), `maxLedgerAgeS` (30-120, at least
twice `refreshS`), `reservationFactor` (at least 1.5), `protected {R, V}`,
`calibrationMaxAgeH`, `vaultKeyId`, and the optional `headless`:
`allowedCallers`, `cwdRoots`, `forbiddenCwds`, `runsDir`, `claudeBin`,
`claudeBinSha256`, `models`, `maxBudgetUsd`, `wallClockMin` (1-600), and
optionally `keyMode` (`helper` default, or `env`), `toolProfile` (only `read`),
`maxConcurrent` (1-16, default 1), `dailyCapUsd` (default none). Optional at the
top level: `canaryCloseMaxH` (1-24, default 6): hours from a canary's settle to
the recording of its after-reading before the gate holds
(`canary_close_timeout`).

Other file: `store/interactive-key-guard-events.jsonl` (written by PR-A's guard,
read by the gate: the first read sets a baseline at the file's end; its lines
carry env NAMES only, never values).

Tables (additive, `applyCreditGateSchema`): `credit_ledger_entries`,
`credit_ledger_cursors`, `credit_reservations`, `credit_gate_state`,
`credit_gate_events`, `credit_calibrations`, `credit_calibration_state`,
`credit_canaries`, `credit_headless_runs`, `credit_key_reads`.

## Deployment order

1. PR-A (interactive key guard) and the owner-button approvals (card 345f34e2)
   are live first; the gate cannot open without owner-verified approvals.
2. Install `config.json` and `pricing.json`, set `CREDIT_GATE_MODE=shadow`,
   restart the dashboard.
3. First calibration through the owner button; compare the status numbers with
   the Console. A second reading reconciles under B-05 in shadow mode.
4. `enforce`, a fresh calibration with `R_est >= T_reopen`: OPEN.
5. Canary (above), then the first headless nodes with a small budget.

Every step that restarts a service or edits a live file needs the owner's
approval; the operational runbook is kept with the project, not in this repo.

## Rollback

- `CREDIT_GATE_MODE=off` (or remove the line) and restart: the gate is CLOSED,
  no headless run starts, the batch client gets `{enforced:false}` (today's
  path), the STOP stays where it is, and the status names its owner. The
  tables stay and are inert. The PR-A guard stays live (it protects V on its
  own).
- A revert of the PR removes the code; the additive tables remain.
- A rollback while a canary window is open (after the canary's admission,
  before its after-reading is recorded) leaves `canary_res_id` in
  `credit_gate_state`. When the code is deployed again, that window is still
  open: every reservation is refused `canary_window_open`, the STOP stays
  down, and once the canary's reservation has ended (settled, or `unknown`
  when stale) and `canaryCloseMaxH` hours have passed, the gate holds
  `canary_close_timeout`. This is fail-closed and needs no database edit: the
  next recorded (non-rejected) Console reading closes the window as its
  after-reading and, as a newer calibration, lifts the HOLD.
- The same for `stop_place_failed_at` (a STOP that could not be put down): the
  column stays, and after a redeploy the gate holds `stop_place_failed` until a
  tick puts the STOP down and a newer calibration lifts the latch.
  `stop_release_failed_at` (a STOP that could not be taken away) stays too and
  only marks the episode: after a redeploy the next tick that would open the
  gate tries the release again; the first one that goes through clears it.
- Last resort: revoke the shared key in the Console (this stops the batch path
  too).

## Known limits

- The enabled headless profile is `read`: no Bash, no edit. `edit` stays off
  until a canary measures what the CLI does with it under `--restricted`.
- A ledger source that went `broken` stays broken, with one exception: reason
  `missing` (the file was not there) is retried on every poll and, when the
  file is back, read again from its first byte. Every other reason (damaged
  line, `truncated`, `replaced`, `rewritten`, `symlink`, `not_regular`,
  `too_large`, `partial_timeout`, `batch_conflict`, ...) only clears through
  `CreditLedger.resetSource`, which nothing in the product calls. A HOLD that
  `ledger_broken:<id>` already latched also needs a newer calibration, as every
  latch does.
- A batch whose requests partly failed never reaches `expected_requests`; its
  reservation (`max(0, amount - ingested)`) stays counted.
- The `--max-budget-usd` cap is checked after a response, so a run can exceed it
  by about one response; the 1.5 reservation factor is the headroom (N0 facts,
  not yet measured on this install).
- `X-Agent-Id` is self-declared and the Bearer token is shared; anything with the
  token can read the Vault key. The gate makes this visible (key-read counter,
  B-05 reconciliation); it cannot prevent it.
- Spending outside the ledger (the Playground, another key, a CLI started with
  the key elsewhere) shows only through the B-05 reconciliation of the next
  Console reading.
