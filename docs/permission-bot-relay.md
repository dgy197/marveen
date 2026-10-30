# Permission-bot relay

Card d7f586bf (split from 9a77b3e5). The relay is the only process that polls
the permission bot (`getUpdates`). It forwards a press on an `apv:` approval
button to the dashboard and shows the answer to the owner as a toast. It makes
no decision itself: the route `POST /api/approvals/:id/permission-bot` (card
9a77b3e5) is the single place where an approval is decided, and it re-checks
everything the relay pre-filters.

```
owner presses a button (message of the permission bot)
  -> Telegram -> getUpdates (relay only, allowed_updates=["callback_query"])
  -> prefix dispatcher: "apv:" -> apv handler (pre-filter, F3.1)
       -> POST http://127.0.0.1:<WEB_PORT>/api/approvals/<id>/permission-bot (Bearer)
  <- outcome text / refusal -> answerCallbackQuery (toast) -> offset saved
```

## Files

| Path | Purpose |
|---|---|
| `src/permission-bot-relay.ts` | entry point, wiring, `--status` |
| `src/permission-bot-relay/` | bot API client, lock, offset/status files, poll loop, start-up gates, apv handler, dispatcher |
| `scripts/install-permission-bot-relay.sh` | launchd unit installer |
| `store/permission-bot-relay.lock` | single-instance lock (0600) |
| `store/permission-bot-relay.offset` | next offset and the in-flight update (0600) |
| `store/permission-bot-relay.status.json` | state, reason code, last poll, counters, pid (0600) |
| `store/permission-bot-relay.log`, `.error.log` | launchd stdout/stderr |

## Install (dormant by default)

```bash
npm run build
scripts/install-permission-bot-relay.sh            # writes the plist only
scripts/install-permission-bot-relay.sh --load     # loads it (explicit step)
scripts/install-permission-bot-relay.sh --uninstall
```

The installer writes `~/Library/LaunchAgents/com.<SERVICE_ID>.permission-bot-relay.plist`.
It never calls `launchctl` unless `--load` or `--uninstall` is given, never
reads a token, and the plist holds no token (neither in `ProgramArguments` nor
in the environment). The only extra variable is `TELEGRAM_STATE_DIR`, a path to
the main channel's state dir, written when it is known (see "Main-bot
exclusion").

Going live is a separate decision (not part of the card): the Vault read access
of the token must be narrowed first (card 8e9f4670), otherwise another reader
could race the relay's `getUpdates`.

## Configuration

| Setting | Where | Meaning |
|---|---|---|
| `PERMISSION_BOT_RELAY_ENABLED=1` | install `.env` | switch; anything else is off |
| `PERMISSION_BOT_ID` | process env or install `.env` | pinned id of the permission bot (digits) |
| `WEB_PORT` | install `.env` | dashboard port; the relay only talks to `127.0.0.1` |
| token `telegram-engedely-bot-token` | Vault only | never read from env, argv, a file or the dashboard API |

The Bearer for the dashboard is read from `store/.dashboard-token` on every
request, so a rotation needs no restart.

### Main-bot exclusion

The pinned id must not be the main bot's. The relay takes the main bot's id
(the digits before the colon, nothing else) from `TELEGRAM_BOT_TOKEN` in the
install `.env` and from the `.env` of the main channel's state dir
(`TELEGRAM_STATE_DIR`, else `<install>/.claude/channels/telegram`, else the
legacy `~/.claude/channels/telegram`). Both ids are excluded when they differ.
If no id can be resolved, the relay refuses to start (`main_bot_unresolved`).

## States

`starting -> refused:<reason> | disabled | polling`, `polling <-> degraded`
(transient errors, backoff 1 s to 60 s), `polling -> conflict` (HTTP 409,
retried at most every 5 minutes), `polling -> stopping -> stopped`.

Run `node dist/permission-bot-relay.js --status` to print the status file. It
reads that file only (no network, no Vault, no lock) and warns when the
recorded pid is gone. Exit code 1 means there is no readable status file.

## Exit codes and reason codes

| Exit | Meaning |
|---|---|
| 0 | clean shutdown (SIGTERM/SIGINT, drained) |
| 1 | crash, fatal Bot API error (`api_unauthorized`, `api_fatal`), unreadable offset file, or shutdown with a handler still running |
| 2 | refused (see below) |
| 3 | lock not acquired (`already_running`, `lock_busy`, `lock_unverifiable`, `lock_identity_unavailable`, `lock_io_error`); the status file is left untouched |
| 64 | bad command line |

Refusal reasons (`refused:<reason>` in the status file, named in the log, never
with a value): `bot_id_missing`, `bot_id_invalid`, `owner_unresolved`,
`token_missing`, `token_malformed`, `token_bot_mismatch`, `main_bot_unresolved`,
`same_as_main_bot`, `getme_mismatch`, `getme_unauthorized`, `getme_unavailable`,
and from the loop `webhook_set` (a webhook is set; the relay never deletes it),
`offset_unreadable`.

Disabled mode (`PERMISSION_BOT_RELAY_ENABLED` not `1`) writes state `disabled`
and idles, so `KeepAlive` does not respawn it in a loop. A refusal exits with 2;
`ThrottleInterval` (60 s) spaces the restarts.

## Behaviour worth knowing

- Start-up backlog (K3): updates that piled up while the relay was down are
  dropped, counted in `dropped`, never decided. The one update that was in
  flight when the previous process died is handed to the handler again; the
  server decides once, so a replay ends in `already_resolved`.
- Unknown prefixes (for example `ppr:` until its handler exists) and every
  pre-filter failure get a generic "not valid" toast and are not forwarded.
- A dashboard that is down, slow (10 s) or answers 5xx gives the "nothing was
  decided" toast. There is no automatic retry; the owner presses again.
- Logs hold update ids, counters, reason codes and a short hash of the presser.
  Never the token, the callback data, the nonce, the approval id or a user id.

## Rollback

1. `scripts/install-permission-bot-relay.sh --uninstall` stops the job and
   removes the plist. The `store/permission-bot-relay.*` files stay.
2. To pause without removing: set `PERMISSION_BOT_RELAY_ENABLED` to anything
   but `1` and restart the job; it then idles in state `disabled`.
3. The code change is reverted by reverting the PR.

If another process polls the bot (`conflict` state), stop that process; the
relay never takes the bot over and never deletes a webhook.
