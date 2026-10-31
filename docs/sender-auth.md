# Inter-agent sender authentication (card 0d7e2c04)

## Threat model

1. Every agent shares one dashboard Bearer token, so `POST /api/messages` cannot tell who really sent a row.
2. Any agent can therefore write `from=<another agent>` (or the owner) and be delivered as that sender.
3. The receiver treats `from` as identity (trust framing, coordinator and system rules), so a forged `from` borrows trust.
4. Fix: each agent gets its own send key; the server checks the `X-Agent-Key` header against the claimed `from`.
5. Keys are stored only as hashes in `agent_send_keys`; the raw key lives in `store/.agent-keys/<agent>` (dir 0700, file 0600), passed to the agent as the path in `MARVEEN_AGENT_KEY_FILE`. `scripts/agent-msg.sh` and `scripts/lib/marveen_api.py` send it from the file (never argv).

## What shadow does (phase 1, the only phase shipped here)

`MESSAGE_SENDER_AUTH=shadow` is the default. Delivery and the response are unchanged; the verdict is stored in `agent_messages.sender_auth` and a warning is logged (never the key):

- `verified` / `verified_prev` (rotated key inside the 10 minute grace window): key matches `from`.
- `mismatch`: valid key of another agent. `invalid`: unknown, oversized or repeated header. `unsigned`: no header.
- `session` / `device`: owner session or device key. `internal`: in-process writers. `legacy` (report only): rows from before the column.

The dashboard writes every agent's key file at start, including the main agent's (decision K3, Brainy). Unknown or mistyped flag values fall back to `shadow`, never to `off` or `enforce`.

## Reading the shadow report

Read-only, behind the normal dashboard auth: `GET /api/messages/sender-auth-report?days=7` (1-90, default 7).

```bash
curl -s -H "Authorization: Bearer $(cat /Users/gyorgydecsi/marveen/store/.dashboard-token)" \
  "http://localhost:3420/api/messages/sender-auth-report?days=7"
```

Returns `{mode, days, rows:[{from, sender_auth, count, last_seen}]}`. Counts and last-seen time only: no keys, hashes or message content. The thing to watch: agent senders with `unsigned`, `invalid` or `mismatch`.

## Rollout (each step only with Gyuri's GO)

1. Shadow (this change): collect 7 days of clean report (agent senders not `unsigned`/`mismatch`/`invalid`, or explained).
2. Mark: after 7 clean days and Gyuri's GO, unverified `from=<agent>` rows are delivered with an untrusted mark. Then another 7 days.
3. Enforce: after those 7 days and a separate GO, unverified agent senders get a 403.

Decided (Gyuri, 2026-10-31, K2 = A): in enforce, a message with `from=OWNER_NAME` or another `SYSTEM_SENDER_IDS` value that arrives with the shared token is delivered but marked as an unverified sender, and it never triggers an action. `from=system` from outside stays refused with 403, as today.

Open decision (Gyuri): K5 - OS-user isolation (separate card) to close the gap below.

Before enforce (review residual, 0d7e2c04 BE round 2): the key directory check and the write are not pinned to one directory handle (no openat), so a same-uid process can swap the directory between them, and the parent `store/` directory is not checked; the sender scripts read the key file without the same hardening.

## Rollback

Set `MESSAGE_SENDER_AUTH=off` and restart the dashboard (needs Brainy's approval). The table and column are additive and may stay; key files are removed when each agent next stops. Full removal: revert the PR.

## What it does not fix

All agents run as the same macOS user, so an agent that can read `store/.agent-keys/<other>` can send as that other agent. Only OS-user isolation (K5) or a deny rule closes that. This control stops accidental and token-only forgery, not a deliberate same-user attacker.
