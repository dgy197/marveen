# Memory write gate (b1, shadow mode)

The memory write gate watches new memories written through `POST /api/memories`
and asks a small model (Haiku) one question per memory: is this a new fact
(`CREATE`), or does it replace (`SUPERSEDE`), repeat (`REINFORCE`), contradict
(`CONTRADICT`), retire (`EXPIRE`) or duplicate (`MERGE`) an older memory of the
same agent? In b1 the answer is only LOGGED. Nothing is applied, no memory row
is written, edited or hidden, and the save and the search behave exactly as
before. It is off by default and changes nothing until `MEMORY_GATE_MODE` and
`MEMORY_GATE_OWNERS` say otherwise.

Card 3e9f6c28. Source: `src/memory-gate/`, `src/web/memory-gate-runner.ts`,
`src/web/routes/memory-gate.ts`, `scripts/memory-gate/gate_adapter.py`.

## Contents

- [What it does and what it does not](#what-it-does-and-what-it-does-not)
- [What leaves the machine](#what-leaves-the-machine)
- [Configuration (`.env` only)](#configuration-env-only)
- [Who is covered: owners](#who-is-covered-owners)
- [The decision log and the API](#the-decision-log-and-the-api)
- [Limits, errors and the kill switch](#limits-errors-and-the-kill-switch)
- [Revert](#revert)
- [Known limits](#known-limits)

## What it does and what it does not

Does:

- Marks a row as a gate candidate when it arrives through `POST /api/memories`
  (table `memory_gate_origin`). The mark is written AFTER the response is out
  (one deferred `setImmediate`), is total (never throws) and is a no-op unless
  the tables are verified, the mode is not `off` and at least one owner is set.
- Every 60 seconds a single-flight round enqueues marked rows that are at least
  60 seconds old and belong to an allowed owner, finds up to 5 older candidates
  of the SAME owner (`warm` or `cold` rows, keyword and vector branch, filtered
  in SQL), asks the model, parses the answer strictly and records it.
- Evaluates what a later stage WOULD apply (`would_apply`, `apply_block`), so
  the decision log can be reviewed by a human before anything has an effect.

Does not:

- Never writes `memories`, `memory_versions` or any existing table. The
  `memory_gate_*` tables are new and additive; no column is added anywhere.
- Never changes a response. The `POST /api/memories` and `POST /api/daily-log`
  answers, the `GET /api/memories` search branches and `GET /api/memories/:id`
  are byte-identical with the gate off or in shadow mode (measured
  in the b1 trial, card 3e9f6c28 node B1-M: identity probes on a scratch
  server, p95 difference of the two POSTs under 0.2 ms).
- Never classifies daily-log mirror rows, imports, migrations or any row
  without an origin mark.
- Never applies a decision (there is no effect table in b1). `active` mode is
  not available: `MEMORY_GATE_MODE=active` runs as `shadow` and logs a WARN.
- Never lets a failure reach the caller: a failed migration, a config error,
  a transport error or a daily cap leaves the save and the search untouched;
  the item is closed as `op = 'UNKNOWN'` with a named `error_class`.

## What leaves the machine

Only the classifier call. Per call, exactly: a fixed system text (the rubric),
the new memory (masked text, masked keywords, creation DATE) and up to 5
candidates of the same owner (the same three things each). Never an id, an agent
id, a category name or a vector: candidates are addressed as `C1`..`C5` and the
server maps the labels back. Blocks are delimited with a per-call random nonce,
and any copy of the delimiter inside a memory text is removed first.

Every text passes, in this order: Unicode NFKC, deletion of control and format
characters (not `\n`, `\t`), masking, truncation. The mask covers the repo's
secret patterns plus long hex runs, secret labels with a value, PIN/code
values, high-entropy strings and Luhn-valid card numbers; over-masking is the
safe direction (the model sees `<REDACTED>`). The finished prompt is scanned
again; any finding means the item is NOT sent (`secret_residue`).

Path: the dashboard runs `/usr/bin/python3 -I scripts/memory-gate/gate_adapter.py`
(minimal environment, no shell, one child per round, hard deadline, stdout
capped at 256 KB), which calls the shared batch client
(`caller='memoria-iras-kapu'`). The API key is read by the batch client from
the Vault inside the child; the dashboard process never sees it. Spend goes to
`usage.jsonl`, so the credit gate's ledger counts it.

The model's one-line `reason` is stored masked and at most 200 characters, and
is NEVER returned by the API (see below). Logs carry numbers and error classes,
never memory text.

## Configuration (`.env` only)

Every `MEMORY_GATE_*` key is read from the `.env` file ONLY (`readEnvFile`),
never from `store/config-overrides.json`, never from the process environment
and never from the Settings page, so the dashboard UI cannot widen the gate's
data scope or budget. A change needs a dashboard restart; the `DISABLE` file
below is the restart-free switch.

| Key | Default | Meaning |
|---|---|---|
| `MEMORY_GATE_MODE` | `off` | `off`, `shadow`, `active` (runs as `shadow` in b1). Missing, empty or unknown = `off`. |
| `MEMORY_GATE_OWNERS` | empty | Comma-separated agent ids (`[a-z0-9_-]{1,32}`) whose memories may be classified. Empty = the gate does nothing. A malformed element or `feszek` is a config error: the whole gate stays inert. |
| `MEMORY_GATE_MAIN_AGENT_OK` | empty | `tg-<digits>`, the reference of the owner's decision to include the main agent. Any other value (missing, empty, wrong shape) = the main agent is dropped from the owners; the others keep working. |
| `MEMORY_GATE_BATCH_DIR` | empty | Absolute path of the shared batch client directory (`batch_client.py`, `usage_log.py`). Required once the gate would call; missing or relative = config error. |
| `MEMORY_GATE_MODEL` | `claude-haiku-5-5` | Model id. |
| `MEMORY_GATE_MAX_CALLS_PER_DAY` | `300` | 1-2000, per Budapest day. |
| `MEMORY_GATE_DAILY_USD` | `0.50` | 0.01-0.50, at most two decimals. The code ceiling is 0.50: `.env` can only lower it. Reserved before each call. |
| `MEMORY_GATE_MAX_PROMPT_BYTES` | `12000` | 2000-48000. |
| `MEMORY_GATE_MAX_TOKENS` | `300` | 64-1000, answer length. |
| `MEMORY_GATE_CANDIDATES` | `5` | 1-5 candidates per call. |
| `MEMORY_GATE_SUPERSEDE_MIN_CONF` | `0.85` | 0.5-1, used by the `would_apply` evaluation only. |
| `MEMORY_GATE_OTHER_MIN_CONF` | `0.70` | 0.5-1, same. |
| `MEMORY_GATE_MAX_SUPERSEDE_PER_DAY` | `20` | 0-1000, same. |
| `MEMORY_GATE_MAX_CONTRADICT_PER_DAY` | `20` | 0-1000, same. |

An out-of-range or malformed value is a config error (`bad_<key>`): the gate
stays inert and says so in the status endpoint; it does not fall back to a
looser value.

## Who is covered: owners

Only the agents listed in `MEMORY_GATE_OWNERS`, and only their `warm` and
`cold` rows, ever reach a prompt (the filter is in the SQL of both candidate
branches, then re-checked per candidate). Rules fixed in code:

- `feszek` (family-private content) is on a deny list: no `.env` value can add
  it, and naming it turns the whole gate off (`forbidden_owner`).
- The main agent (`MAIN_AGENT_ID`) counts as an owner only with a valid
  `MEMORY_GATE_MAIN_AGENT_OK=tg-<digits>` (the reference of the owner's
  decision, e.g. the Telegram message number). The code checks the shape only;
  the value is written into `.env` by the operator, never into code or a package.
- `hajcsar` may be listed (company content, owner's decision); each additional
  agent is a decision of the owner, not of this document.
- Secrets and tokens are masked for every owner, the main agent included.

## The decision log and the API

Read-only, Bearer-gated like every `/api/*` path:

```
GET /api/memories/gate/status
GET /api/memories/gate/decisions?limit=&before_id=&op=&state=
GET /api/memories/gate/decisions/:id
```

`status` shows the effective mode, the NUMBER of owners (never the names), config
errors, whether `DISABLE` exists, whether the tables are ready, row counts by
state, today's calls and reserved USD, and the cursor. `decisions` lists the
log (limit 1-200, default 50); one decision adds its candidate labels and ids.

No route returns the `reason` column or its text, by construction: every query
names its columns and none uses `SELECT *`. The reason is kept only for a later
human labelling run. A 10-minute sweep (and one at start) sets `reason` to NULL
when its source, target or candidate row no longer exists. A test pins the
absence of a `reason` key for all three routes.

Tables: `memory_gate_origin`, `memory_gate_decisions`, `memory_gate_candidates`,
`memory_gate_daily`, `memory_gate_kv` (created idempotently at start; a failed
migration is recorded as an error class and keeps the gate inert, it never
stops the dashboard from booting).

## Limits, errors and the kill switch

Per round: at most 5 calls, one child process. Per day: the call count and the
USD reservation above, plus at most 20 `SUPERSEDE` and 20 `CONTRADICT`
`would_apply` marks. A pending row older than 72 hours closes as `UNKNOWN` /
`too_old`. A call whose outcome is not provably "not sent" is `maybe_billed`
and is not retried the same day. When the credit gate is in `enforce` mode, a
round runs only if the gate object exists and is `OPEN`; every other state
(no gate, a start error, unknown mode) pauses it (`credit_paused` /
`credit_unknown`) and nothing is called.

Switches, from the quickest to the most complete:

1. `store/iras-kapu/DISABLE` (any file or symlink; checked with `lstat`, at
   most 5 seconds of cache): no new round does anything. No restart needed.
   Remove the file to resume.
2. `MEMORY_GATE_OWNERS=` (empty) or `MEMORY_GATE_MODE=off` in `.env`, then a
   dashboard restart: the origin marker and the runner become no-ops, 0 rows,
   0 calls.
3. The shared batch client's STOP file (fleet-wide, see
   [credit-gate.md](credit-gate.md#the-stop-file)): the client refuses the
   calls (error class `stopped`), nothing is sent.
4. Revert the package (below).

## Revert

The b1 change is a handful of lines outside `src/memory-gate/`: the migration
call in `src/db.ts`, the origin mark in `src/web/routes/memories.ts`, the route
line in `src/web.ts`, and the runner start and stop in `src/index.ts`. Reverting
them (or the package that carries them) and restarting removes the gate. The
five `memory_gate_*` tables are additive and may stay: nothing else reads them.
Drop them by hand only if the log is no longer wanted.

## Known limits

- b1 has no effect by design. A decision's value is judged from the log; `active`
  is a later, separately approved step.
- The shadow worker does its database work synchronously on the main thread. A
  burst (a restart with a backlog of hundreds of marked rows) can hold the event
  loop for about 100-150 ms once (measured in the B1-M stress run); in normal
  operation the queue is a few rows a day.
- Without an Ollama embedding the vector branch of the candidate search is
  skipped and the row waits up to 10 minutes for its vector; after that the
  keyword branch alone decides.
