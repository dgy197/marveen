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

Before enforce (review residual, 0d7e2c04 BE round 2), closed in card ed5fc02c: Node has no openat, so provisioning keeps the keys-dir fd open and re-checks the dir path against it (same dev+ino, not a symlink, own uid, 0700) before and after the rename, then re-opens the final key file O_NOFOLLOW (regular, nlink 1, own uid, 0600, same device and inode as written); any mismatch unlinks the new file only if dev/ino still match, revokes the hash and refuses, so the agent starts unsigned. Every component from the install root down to `store/` must be a real directory, own uid, not group/other-writable. The sender scripts (`agent-msg.sh`, `marveen_api.py`) open the key file O_NOFOLLOW and judge the open descriptor: regular file, own uid, mode exactly 0600, at most 256 bytes; otherwise they send unsigned and print one warning without the path or key. A same-uid attacker can still read the file (K5), and a swap inside the remaining window leaves a revoked, useless key in the displaced directory.

## Rollback

Two levels (both need Brainy's approval for the restarts).

(a) Runtime, no code change: set `MESSAGE_SENDER_AUTH=off`, restart the dashboard, then restart the agents. `off` makes the feature fully inert (card 3f6500e6):
- no key is minted, no file is written, `MARVEEN_AGENT_KEY_FILE` is exported nowhere (the dashboard launch strings and the respawn launcher skip it; `scripts/channels.sh` exports it only when the mode is not `off`);
- on dashboard boot and on every agent start the dashboard revokes all rows of `agent_send_keys` and removes what is left in `store/.agent-keys/` (verified dir, regular files only, dev/ino re-checked before each unlink, never through a link; any anomaly is refused quietly); one log line with the counts;
- `POST /api/messages` does not compute `sender_auth`; the sender scripts find no key file and send unsigned, as before.

(b) Full: `git revert` of the branch(es) (0d7e2c04, ed5fc02c, 3f6500e6). No data migration is needed. The additive `agent_messages.sender_auth` column and the `agent_send_keys` table may stay: they are harmless and unused. The operator may delete `store/.agent-keys/` if anything is left in it; nothing else.
Note: after the revert, the older `/api/messages` code reads rows with `SELECT *` and therefore serves the leftover `sender_auth` (and, with card f137f980, `closer_auth`) columns again in its responses. They hold only labels (`verified`, `unsigned`, ...), no key or hash, so this is harmless; prefer level (a) when the labels should stay hidden.

## What it does not fix

All agents run as the same macOS user, so an agent that can read `store/.agent-keys/<other>` can send as that other agent. Only OS-user isolation (K5) or a deny rule closes that. This control stops accidental and token-only forgery, not a deliberate same-user attacker.
