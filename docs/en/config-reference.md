# Configuration Reference

> Which file does what, where it lives, what it contains. All configuration files in one place.

---

## store/ -- Runtime State

These files are managed by the dashboard and change at runtime. They are not checked into git (`.gitignore`).

| File | Editable | Description |
|------|----------|-------------|
| `store/.dashboard-token` | no | Dashboard Bearer token -- required for all `/api/*` calls |
| `store/federation.json` | dashboard UI (Federation page) | Federation config: enabled, systemId, peers[] with per-peer inbound/outbound tokens (0600) -- see docs/en/federation.md |
| `store/autonomy-config.json` | dashboard UI | Heartbeat autonomy levels by category (1=notify, 2=propose, 3=autonomous) |
| `store/dashboard-settings.json` | dashboard UI | GitHub repo integration, update settings |
| `store/agents-desired.json` | dashboard UI | Which sub-agents to keep alive (auto-restart list) |
| `store/auto-restart.json` | dashboard UI | Per-agent auto-restart config (enabled, mode, dailyTime) |
| `store/vault.json` | dashboard UI | Encrypted secrets (AES-256-GCM) |
| `store/.vault-key` | no | Vault decryption key (migrated to OS keychain when available) |
| `store/schedule-last-run.json` | automatic | Last-run timestamps for scheduled tasks (crash-safe skip guard) |
| `store/kanban-audit-state.json` | automatic | Last kanban audit timestamp |
| `store/claudeclaw.db` | not directly | SQLite database -- memory, kanban, messages, token log, etc. |
| `store/config-overrides.json` | dashboard UI | Settings-page overrides (plain values only, never contains secrets) |
| `store/update.pid` | automatic | Update process PID file (concurrency lock) |
| `store/telegram-topics.json` | `/topic new <name>` (Telegram) | The named topics of the main chat: `{ "chatId", "topics": { "<name>": <message_thread_id> } }` (0600); written only while `TELEGRAM_TOPICS_ENABLED` is on |
| `store/interactive-key-guard-events.jsonl` | automatic | Guard events of the interactive key guard (names only, never values) -- see [INTERACTIVE_ANTHROPIC_KEY_POLICY](#interactive_anthropic_key_policy----interactive-key-guard) |
| `store/interactive-key-guard-audit.jsonl` | automatic | The runtime guard's findings in `allow` mode (names only, 0600) |
| `store/interactive-key-guard-owner-alerts.json` | automatic | Dedupe log of the owner's Telegram alerts (0600) |
| `store/interactive-key-guard-runner.json` | automatic | The runtime guard's cursor and alert log (0600) |
| `store/.channels-key-guard-refused` | automatic (channels.sh) | Refusal marker for the main agent's launch under `forbid` |

### Dashboard language

A `HU / EN` button appears in the bottom-left corner of the sidebar. Clicking it switches the entire interface immediately -- navigation labels, buttons, messages, and the Documentation page all re-render in the newly selected language. The choice persists within the browser session.

To make a particular language the default for every new visit, set `DASHBOARD_LANG` to `hu` or `en` on the Settings page (System module). The sidebar button overrides the server default; if no client-side choice has been stored, `DASHBOARD_LANG` takes effect.

The Documentation page follows the global language setting -- there is no separate docs language selector.

---

### Settings page

The "Settings" entry in the dashboard's left-hand navigation opens the configuration UI, where env-backed parameters can be viewed and changed directly in the browser -- no `.env` editing or server access required.

**How to change a value**

Settings are grouped by module (Kanban, System, Heartbeat). Each row shows:
- the key name and its description,
- the current value in an editable input (number fields show the valid range; colour fields show a colour picker with a preview swatch; enum-style keys show a dropdown).

Editing an input marks the row as dirty. A sticky save bar appears at the bottom of the page showing the number of pending changes, with two buttons:
- **Save** -- saves all dirty rows at once. Rows that fail validation are flagged with an error; the rest are saved.
- **Reset** -- restores all inputs to their last-loaded values; the save bar disappears.

**What does a validation error mean?**

If you enter an invalid value (e.g. 150 where the maximum is 100, or a colour that isn't in `#rrggbb` format), an error message appears directly below the row after you press Save. The other rows are saved; only the failing row stays dirty. Fix the value and press Save again.

**Unsaved-change guard**

If you try to leave the Settings page (by clicking another menu entry or closing the browser tab) while there are unsaved changes, the browser shows a confirmation dialog. Dismissing it keeps you on the page with the dirty values intact.

**When is a restart required?**

Some rows carry a "Requires restart" badge -- changes to those settings (e.g. `DASHBOARD_PUBLIC_URL`, `OLLAMA_URL`, `HEARTBEAT_AGENT_ENABLED`) only take effect after the next server restart. Kanban and heartbeat window settings (e.g. `KANBAN_WIP_*`, `KANBAN_AGING_*`, `HEARTBEAT_START_HOUR`) apply immediately, no restart needed.

**What can you configure?**

Settings are organised into three modules:

*Kanban* -- how the kanban board behaves:
- WIP limits and badge colours: how many cards per column before the badge turns yellow or red (available since v1)
- Card aging: after how many hours a stale-card indicator appears in yellow, orange, or red -- if your team works in longer cycles, raise the default 24h/72h/168h thresholds accordingly
- Archiving: how many days after a card is closed before it moves to the archive automatically (default: 30 days)
- Swimlane default: which grouping the kanban board opens in ("none", "by assignee", "by priority")

*System* -- infrastructure parameters:
- The publicly accessible URL of the dashboard (used by webhooks and external links; restart required)
- The Ollama embedding server URL (used for memory search; restart required)
- Default UI language (`DASHBOARD_LANG`): `hu` or `en` -- the sidebar button overrides this per-session, but when no client-side choice is stored this value applies on every new visit (no restart needed)

*Heartbeat* -- the background summary agent:
- On/off toggle: "1" = active, "0" = stopped (restart required)
- Active window: which hours of the day the agent is allowed to run (e.g. 9-23 = daytime only)

---

### Settings System

The dashboard Settings page manages a three-layer configuration system.

**Resolution order (first match wins):**
1. `store/config-overrides.json` -- overrides saved by the dashboard
2. `.env` -- project-level values (read fresh on every request, not frozen at boot)
3. Registry default (`src/config-registry.ts`)

**`store/config-overrides.json` structure:**

```json
{
  "KANBAN_WIP_PLANNED": 10,
  "KANBAN_WIP_WARN_PCT": 80,
  "KANBAN_WIP_OK_COLOR": "#6b7280"
}
```

Only overridden keys appear in the file; the rest fall through to the registry default. Writes are atomic (tmp file + rename), so partial writes are impossible.

**Settings registry (`src/config-registry.ts`):**

Every dashboard-editable setting is a registry entry with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | ENV-compatible key (e.g. `KANBAN_WIP_PLANNED`) |
| `type` | `int` / `color` / `string` / `boolean` | Value type (drives validation + UI widget). `boolean` renders as an on/off checkbox with a canonical `"1"`/`"0"` value |
| `default` | any | Fallback when no override and no `.env` entry |
| `description` | string | Human-readable description shown in the UI |
| `module` | string | Grouping label on the Settings page (e.g. `kanban`) |
| `secret` | boolean | If `true`: the API never returns the value; POST is rejected |
| `requiresRestart` | boolean | If `true`: a badge warns the user that the value takes effect after restart |
| `min` / `max` | number? | Bounds for `int` type |
| `valueSet` | string[]? | If set: only these values are accepted (select widget in UI) |

**Registry -- Kanban module:**

| Key | Type | Default | Constraint | Restart |
|-----|------|---------|------------|---------|
| `KANBAN_WIP_PLANNED` | int | 0 (unlimited) | max 100 | no |
| `KANBAN_WIP_IN_PROGRESS` | int | 0 | max 100 | no |
| `KANBAN_WIP_WAITING` | int | 0 | max 100 | no |
| `KANBAN_WIP_DONE` | int | 0 | max 100 | no |
| `KANBAN_WIP_WARN_PCT` | int | 80 | min 1, max 100 | no |
| `KANBAN_WIP_OK_COLOR` | color | `#6b7280` | #rrggbb | no |
| `KANBAN_WIP_WARN_COLOR` | color | `#c9a000` | #rrggbb | no |
| `KANBAN_WIP_FULL_COLOR` | color | `#d46b00` | #rrggbb | no |
| `KANBAN_WIP_OVER_COLOR` | color | `#c53030` | #rrggbb | no |
| `KANBAN_ARCHIVE_DONE_DAYS` | int | 30 | min 1, max 365 | no |
| `KANBAN_DISPATCH_SKIP_AGENTS` | string | (empty) | agent names, comma-separated, for example `pm,reviewer` (an agent listed here is not woken when a card is moved to `in_progress`, see `kanban.md`) | no |
| `KANBAN_CLAIM_LOCK` | boolean | `0` | `0` or `1` (card claim lock, see `kanban.md`) | no |
| `KANBAN_AGING_WARN_H` | int | 24 | min 1, max 8760 | no |
| `KANBAN_AGING_CAUTION_H` | int | 72 | min 1, max 8760 | no |
| `KANBAN_AGING_CRITICAL_H` | int | 168 | min 1, max 8760 | no |
| `KANBAN_AGING_WARN_COLOR` | color | `#c9a000` | #rrggbb | no |
| `KANBAN_AGING_CAUTION_COLOR` | color | `#d46b00` | #rrggbb | no |
| `KANBAN_AGING_CRITICAL_COLOR` | color | `#c53030` | #rrggbb | no |
| `KANBAN_SWIMLANE_DEFAULT_GROUP` | string | `none` | `none`, `assignee`, `priority` | no |
| `KANBAN_SWIMLANE_SEPARATOR_COLOR` | color | `#374151` | #rrggbb | no |

**Registry -- System module:**

| Key | Type | Default | Description | Restart |
|-----|------|---------|-------------|---------|
| `DASHBOARD_PUBLIC_URL` | string | (empty) | Publicly accessible URL of the dashboard | yes |
| `OLLAMA_URL` | string | `http://localhost:11434` | Ollama API base URL | yes |
| `EMBED_KEEP_ALIVE` | string | `24h` | How long Ollama keeps the embedding model loaded after the last request (the request's `keep_alive` field). An Ollama duration (`24h`, `30m`, `90s`, `500ms`) or an integer number of seconds; `-1` (forever), `0` and invalid values are not accepted: the default applies and one WARN is logged. `0` (`0s`, `0ms`, ...) is refused because Ollama then unloads the model after every request, so every search would pay a cold load. The Settings page refuses these at save time | yes |
| `EMBED_KEEPWARM_MINUTES` | int | `5` | Keep-warm: after this many minutes without an embedding call the dashboard sends one short embedding request with a fixed text to the model that is already loaded, so the first search after a quiet stretch is not slow. It first reads `GET /api/ps` to see whether `EMBED_MODEL` is loaded and how much time it has left; the ping's `keep_alive` is that remaining time (whole seconds, rounded down), so it never extends the `EMBED_KEEP_ALIVE` window and never loads a model. No ping when the model is not loaded, when 60 seconds or less or more than 30 days are left, while an embedding call or a backfill pass runs, during an embedding outage, and when `EMBED_URL` is not a loopback address (127.0.0.1, ::1, localhost). After a failure it pauses 15 minutes, doubling up to 4 hours; a real embedding call that succeeds ends the pause. `0` = off; otherwise a whole number from 5 to 10. Invalid = 5, one WARN; the Settings page refuses it at save time. Read only from `store/config-overrides.json` and `.env`; the launchd plist key is NOT consulted | yes |
| `MEMORY_IMPORT_CATEGORIZE_MODEL` | string | (empty) | Ollama model that tiers memories on import (override); empty = auto-detect an installed `gemma4`, else all warm | yes |
| `MEMORY_CONTENT_FILTER_STRICT_COMMANDS` | boolean | `0` (off) | Strict command-syntax group of the memory content filter (curl http(s), bash -c, eval(, exec(, import subprocess, rm -rf) on memory POST/PUT/PATCH; cost: prose that only quotes a command form is a 400 too | yes |

**Registry -- Heartbeat module:**

| Key | Type | Default | Constraint | Restart |
|-----|------|---------|------------|---------|
| `HEARTBEAT_START_HOUR` | int | 9 | min 0, max 22 | no |
| `HEARTBEAT_END_HOUR` | int | 23 | min 1, max 24 | no |
| `HEARTBEAT_AGENT_ENABLED` | string | `1` | `0` or `1` | yes |
**Registry -- Idea-box module:**

| Key | Type | Default | Constraint | Restart |
|-----|------|---------|------------|---------|
| `IDEA_BREAKDOWN_MAX_SUBTASKS` | int | 10 | min 2, max 20 | no |
| `IDEA_STALE_DAYS` | int | 7 | min 1, max 365 | no |

**Registry -- Channels module:**

| Key | Type | Default | Platform | Restart |
|-----|------|---------|----------|---------|
| `MAIN_AGENT_ISOLATED_CONFIG` | boolean | `0` (off) | macOS only | yes |
| `TELEGRAM_TOPICS_ENABLED` | boolean | `0` (off) | all | yes (channel start) |

#### `MAIN_AGENT_ISOLATED_CONFIG` -- main-agent config isolation (macOS)

**What it is for.** An opt-in fix for the periodic `401 Invalid authentication
credentials` / "Please run /login" the main channels agent hits on macOS. Symptom:
the main bot goes silent every so often, needs a manual `/login`, and recurs a few
days later -- while the sub-agents never drop.

**Root cause.** By default the main channels agent uses the shared `~/.claude`
config dir. On macOS that authenticates from the **rotating Keychain OAuth session**,
which periodically expires → 401. The sub-agents instead run with their own isolated
`CLAUDE_CONFIG_DIR` and the long-lived fleet setup-token
(`store/.claude-oauth-token`), so they stay stable.

**What it does when on.** The main agent gets the SAME isolated config dir as the
sub-agents (`<install>/.channels-config`: shared parts symlinked, but its own
`settings.json`/`plugins/` state and NO `.credentials.json`). It then authenticates
from the stable `CLAUDE_CODE_OAUTH_TOKEN` instead of the expiring Keychain.

**Single gate.** The on/off decision is made by one helper
(`ensureMainAgentIsolatedConfigDir`), which reads the effective setting (resolution:
`config-overrides.json` > `.env` > default `0`). All THREE main-agent launch paths
call this helper, so the toggle governs them uniformly:
1. the `scripts/channels.sh` boot (launch helper),
2. the dashboard channel-monitor `--continue` resume respawn,
3. the dashboard channel-monitor fresh hard-restart respawn.

**Gating (when it is a no-op).** No effect (keeps the shared `~/.claude`) when: not
macOS; no valid fleet setup-token; or no built `dist/`. On Linux the rotating
`credentials.json` is handled by the separate credentials-guard instead.

**Enabling.** Dashboard: *Settings → Channels → `MAIN_AGENT_ISOLATED_CONFIG`* (the
toggle writes to `store/config-overrides.json`). Or by hand: `MAIN_AGENT_ISOLATED_CONFIG=1`
in `.env`. The change takes effect on the next channels-session restart (the
`requiresRestart` badge signals this).

**Reverting.** Turn it OFF (dashboard) or set `MAIN_AGENT_ISOLATED_CONFIG=0` (`.env`),
then restart the channels session -- all three launch paths fall back to the shared
`~/.claude` behaviour.

#### `TELEGRAM_TOPICS_ENABLED`: the answer goes to the topic the message came from

**What it is for.** Telegram allows topics in a bot's private chat as well (switched on
for the bot in BotFather). Every message is then written in a topic, but the Telegram
plugin does not pass the topic id on to the agent, and its `reply` tool cannot address
a topic: the answer lands outside the topic.

**What it does when on.** At channel start `scripts/patch-telegram-plugin.py` (the same
script that handles `/status` and the inbound evidence) adds a patch to the plugin source:
- the `<channel>` tag of a topic message carries a `message_thread_id` attribute (only
  for a real topic message, `is_topic_message`);
- the typing indicator shows in the topic;
- the new, optional `message_thread_id` parameter of the `reply` tool sends every text
  chunk and every attached file into the topic; a value that is not a positive integer
  is an error, and nothing is sent;
- the plugin's instructions and the `telegram-reply-directive.py` hook ask the agent to
  pass the topic back.

Marveen's own answer paths follow the same topic: the "Dolgozom rajta" placeholder and
its fallback senders (`telegram_progress*.py`), the commands the hook answers
(`marveen-commands.py`, mid-turn commands included), and the fallback poller's handoff
(`channel-coordinator`).

For a message without a topic every call is exactly what it is with the switch off.

**Shared plugin cache.** The patch changes the plugin source in the plugin cache
(`$CLAUDE_CONFIG_DIR/plugins/cache`, else `~/.claude/plugins/cache`), and every Claude Code
session that uses the same cache loads the Telegram plugin from there, sessions outside
Marveen included. They see the optional `message_thread_id` parameter of the `reply` tool
and the attribute on a topic message's tag as well; as long as they do not pass the
parameter, they behave as before.

**What does not change.** The `chat_id` stays the same, so owner identification, command
permissions and approvals are not affected. Alerts, approval requests and the voice reply
still go out without a topic; a scheduled task's result goes to a topic only when the task
asks for it (below).

**Named topics (`/topic`).** While the switch is on, `/topic` appears in `/help` and in the
bot menu, in three forms: `/topic` lists the named topics, `/topic new <name>` (a write command,
main chat only) opens a new topic with the Bot API's `createForumTopic` and stores its name
with the returned `message_thread_id` in `store/telegram-topics.json`. This is needed
because with user-created topics switched off in BotFather only the bot can open a topic,
and because only the Bot API hands out the id. A name that already exists opens no new
topic. On an error the command does not retry: a timed-out call may still have opened the
topic, and the answer says so. `/topic remove <name>` (a write) forgets a name: it removes
the local row only, not the Telegram topic. It is needed after a topic is deleted by hand in
Telegram; otherwise the stale row keeps the name from being opened again, and a scheduled
task pointing at it sends into a topic that no longer exists. The file also records the chat its topics belong to; if the
main chat changes, the old topics are dropped on the next write and are never used before
that. With the switch off `/topic` does not exist (the dashboard decides at start), so
`/help`, the menu and command handling are what they are today.

**Scheduled task result into a topic (`telegramTopic`).** In a task's `task-config.json`,
`"telegramTopic": "<name>"` names a topic opened with `/topic new`. The runner turns the name
into the topic's id from `store/telegram-topics.json` and writes `message_thread_id` next to
the `chat_id` in the task's delivery instruction, so the agent gets the number and never
guesses it from the name. It works only for the main agent's tasks delivered on Telegram:
named topics exist only in the main bot's chat, and a topic id is valid only in the chat of
the bot that opened it. If the name is not found, the task belongs to a sub-agent, or it
delivers on another channel, the result goes to the chat without a topic and a warning in
the log says why. With the switch off the runner does not look at the field, and the
instruction is letter for letter what it is today.

**Muting.** In a chat with topics, Telegram mutes per topic: a muted topic sends no
notification even while the rest of the chat does. If an answer "did not arrive", check
whether its topic is muted first.

**Enabling.** Dashboard: *Settings → Channels → `TELEGRAM_TOPICS_ENABLED`*, or
`TELEGRAM_TOPICS_ENABLED=1` in `.env`. It takes effect at the next channel start. While
it is on, the "Telegram plugin-patch" row of `/status` measures the patch as well: a
missing one shows as a `HIÁNYZIK (témák)` line.

**Reverting.** Turn it OFF and restart the channel: the script takes the patch out, and
the plugin file is byte for byte what it was before the patch.

**After a plugin update.** The next channel start patches the new plugin version. If the
anchors of the patch do not match, the whole patch is left out (one loud line in
`store/channels-failures.log`, and `/status` says so); answers then land outside the
topic, and the channel itself keeps working.

**API endpoints:**

`GET /api/settings` -- fetch all non-secret settings:

```bash
curl -s -H "Authorization: Bearer $(cat store/.dashboard-token)" \
  http://localhost:3420/api/settings
```

Response: `{ "settings": [ { "key", "type", "value", "default", "description", "module", "requiresRestart", "min", "max", "valueSet" }, ... ] }`

`POST /api/settings` -- save a single setting:

```bash
curl -s -X POST http://localhost:3420/api/settings \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $(cat store/.dashboard-token)" \
  -d '{"key": "KANBAN_WIP_WARN_PCT", "value": 75}'
```

Success response: `{ "ok": true, "key": "KANBAN_WIP_WARN_PCT", "value": 75, "requiresRestart": false }`

Error response: `{ "error": "..." }` (400 validation error, 403 secret key, 404 unknown key)

**Hot-reload:** after a successful POST, the `/api/marveen` `kanbanWip` block immediately reflects the new value with no restart needed (for keys where `requiresRestart: false`).

**Change log:** every successful POST appends an audit row to the `config_change_log` SQLite table (key, old value, new value, actor, timestamp). For secret keys the value is stored as `null`. There is no UI for this table; query it directly:

```sql
SELECT key, old_value, new_value, actor, datetime(created_at, 'unixepoch', 'localtime')
FROM config_change_log ORDER BY created_at DESC LIMIT 20;
```

---

### autonomy-config.json Structure

```json
{
  "version": 1,
  "categories": [
    {
      "key": "kanban_archive_done",
      "label": "Archive done cards older than 7 days",
      "level": 2,
      "locked": false,
      "maxLevel": 3
    }
  ]
}
```

Autonomy levels: `1` = notify only, `2` = propose + approval required, `3` = autonomous + reports afterwards. `locked: true` means max level is 1 (cannot be raised due to hard safety rule).

---

## agents/<name>/ -- Sub-agent Configuration

Every sub-agent's directory is gitignored (`agents/` folder), keeping secrets safe.

| File | Editable | Description |
|------|----------|-------------|
| `agents/<name>/agent-config.json` | dashboard UI | Model, team hierarchy, permission profile |
| `agents/<name>/.mcp.json` | manually | MCP servers for this agent (gitignored!) |
| `agents/<name>/.claude/settings.json` | scaffold + manually | Claude Code permissions, hooks, allowed tools |
| `agents/<name>/CLAUDE.md` | manually | Agent instructions and persona |
| `agents/<name>/SOUL.md` | manually | Optional deeper persona descriptor |
| `agents/<name>/avatar.png` | manually | Agent Telegram bot profile picture |

### agent-config.json Structure

```json
{
  "model": "claude-sonnet-5",
  "profileId": "developer-senior",
  "team": {
    "role": "member",
    "reportsTo": "marveen",
    "delegatesTo": [],
    "autoDelegation": false,
    "trustFrom": []
  }
}
```

---

## INTERACTIVE_ANTHROPIC_KEY_POLICY -- interactive key guard

**Purpose.** An interactive Claude Code session (every tmux agent, the worker, the main agent, a background task) that runs on an API key spends that key's own prepaid balance, not the subscription. `forbid` rules this out for every first-party Claude agent, on every launch path this install owns. First-party means: a `claude-` model without a custom provider; a custom provider that is Anthropic itself (a `*.anthropic.com` endpoint, or one that reads the shared `ANTHROPIC_API_KEY_BATCH` key); and every path that exports no provider URL (the worker, the remote ssh launch, `scripts/watchdog.sh`), where the model name does not matter (an `opus` alias included). Whether `authMode: api` is refused differs per path, see the `forbid`, sub-agent item.

**Values.** Read from `.env` only. The Settings page and `config-overrides.json` do not write it (a Bearer call cannot switch it; the fleet import cannot write it into `.env` either).

| `.env` line | Effect |
|-------------|--------|
| no such line, no `.env`, or an empty value | `allow` (the previous behaviour, byte-identical) |
| `INTERACTIVE_ANTHROPIC_KEY_POLICY=allow` | `allow` |
| `INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid` | `forbid` |
| anything else (`Allow`, `frobid`, an `export ...` prefix, an unreadable `.env`) | `forbid` (fail-closed: a typo cannot switch the guard off) |

With several lines, the LAST matching `INTERACTIVE_ANTHROPIC_KEY_POLICY=...` line wins, even if its value is invalid (`=frobid` as the last line is `forbid`; an earlier invalid line, on the other hand, is overridden by a later `=allow`). Independently of that, any non-comment line that carries the name in another shape (an `export ` prefix, a Unicode space around the name) is `forbid`, wherever it sits. The dashboard reads it once per process (a change takes effect on dashboard restart); the shell launchers (`channels.sh`, `channel-watchdog.sh`, `stuck-modal-guard.sh`, `watchdog.sh`, `morning-briefing.sh`) read it on every run. The TS and the shell reader give the same answer for the same text (pinned by a test).

**Behaviour per mode.**

- **`allow`**: every launch command is unchanged. The runtime guard still runs, but only writes to the audit log (one line per fingerprint per day); it sends no message and no guard event, and causes no INCIDENT.
- **`forbid`, sub-agent** (dashboard launch, remote ssh launch, worker, background task; `watchdog.sh` is a separate item, below): the launch does not start, and a guard event is written, if `authMode: api`, if the custom provider is Anthropic itself, or if any settings file the session loads carries a key route (`ANTHROPIC_API_KEY` / `ANTHROPIC_AUTH_TOKEN` under `env`, or a top-level `apiKeyHelper`), because the settings `env` overrides a shell `unset`. Every allowed launch starts with `unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` (the tmux pane inherits the server's global env), and the finished command is checked once more before the sink (`assertLaunchCmdClean`). The dashboard's agent-modifying endpoints answer 422 to a change that would put a first-party agent on a key.
  - *Refusing `authMode: api` differs per path.* The dashboard launch and the 422 endpoints refuse only for a `claude-` model (`agent-process.ts:2210`, `routes/agents.ts:252`; only then does the agent's own key go into the launch, `agent-process.ts:2256`). The remote ssh launch, however, refuses for an alias model (`opus`, `sonnet`, `chatgpt/...`) too, because it exports no provider URL (`directAnthropic: true`, `agent-process.ts:1981`; the `authMode` comes from the config, `:1982`). The worker and the background task call the decision with a fixed `authMode: 'shared'` (`agent-worker.ts:662`, `routes/background-tasks.ts:104`), so `authMode` never refuses there; a settings key or an Anthropic custom provider does.
- **`forbid`, `scripts/watchdog.sh`** (the cron restarter for sub-agents): it does not behave like the dashboard paths.
  - *No guard event.* On a refusal it writes only one line to its own log (`logs/watchdog.log`, `$LOG`, `scripts/watchdog.sh:352`): `[watchdog] <agent>: interactive-key-guard <reason> (INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid), not starting`. Nothing goes into `store/interactive-key-guard-events.jsonl`, so this refusal produces neither a message to the main agent nor an owner alert. Anyone who expects an event under `forbid` for a watchdog refusal will not find one there; look in `logs/watchdog.log` instead (`grep interactive-key-guard logs/watchdog.log`). The agent stays down until the cause is gone, and the watchdog logs it again on every run.
  - *The custom provider does not count.* It does not read the `customProvider` field, so it does not refuse a `customProvider` = Anthropic case; it starts the agent with `unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN` (`scripts/watchdog.sh:354`; the decision function is `interactive_key_decision`, from `:131`). This is safe because the watchdog exports no key and no provider URL (so every agent it starts is first-party, whatever the model name).
  - *`authMode: api` refuses only for a `claude-` model* (`:144`, `startswith('claude-')`). An alias model (`opus`, `sonnet`, `chatgpt/...`) starts with the `unset`, because the watchdog never puts the agent's own key into the launch. This is where it differs from the remote ssh path, which refuses for an alias too (see above).
  - *No `assertLaunchCmdClean`.* It does not check the finished command again; the protection is the decision (`allow` / `unset` / `refuse:<reason>`) and the `unset` prefix. The reasons: `auth-mode-api`, `settings-auth-key` (for any model name: a key name or `apiKeyHelper` in the loaded settings files), `settings-unreadable`, `guard-error`.
  - The watchdog leaves the main agent's restart to `channels.sh` (`scripts/watchdog.sh:293`), so the `channels.sh` rules apply to it (below).
- **`forbid`, main agent**: `channels.sh` does not read or export the `.env` key, clears an inherited value, removes it from the tmux server's global env with `-g -u`, and the pane command starts with an `unset`. If the main agent's settings files carry a key route, the main agent STILL starts (channel availability comes first), but a guard event and a direct Telegram alert go to the owner. If the main agent's customProvider is Anthropic itself, `channels.sh` does not start it (the helper's exit code 3) and keeps that decision for 300 seconds (`store/.channels-key-guard-refused`), so launchd does not repeat it every 30 seconds.
- **Runtime guard**: at startup and every 10 minutes, looking at names only, it scans the tmux global and session env, the settings files, `.env`, the dashboard's own env, the shell rc files, this install's launchd plists and the env names of running `claude` processes; every minute it reads the launch paths' guard events. Under `forbid` it messages the main agent (once per fingerprint per day), and for an event about the main agent the owner also gets a Telegram message (at most one per hour). There is no automatic fix. The own key of a non-Anthropic custom provider agent does not alert.

**Store files.** Each holds names and locations only, never values.

| File | Written by | Content |
|------|------------|---------|
| `store/interactive-key-guard-events.jsonl` | every launch path, `channels.sh`, the runtime guard (`forbid` only); `scripts/watchdog.sh` does NOT write here, it logs its refusal to `logs/watchdog.log` | One guard event per line: `{ts, source, where, names, agent}`. The PR-B credit gate goes into INCIDENT from this. |
| `store/interactive-key-guard-audit.jsonl` | the runtime guard, `allow` only | The findings, one line per fingerprint per day. |
| `store/interactive-key-guard-owner-alerts.json` | the dashboard | The shared dedupe log of owner alerts (24 hours per fingerprint, at most one alert per hour); survives a dashboard restart. |
| `store/interactive-key-guard-runner.json` | the runtime guard | The event file's read cursor and the log of alerts sent to the main agent. |
| `store/.channels-key-guard-refused` | `channels.sh` | `<epoch> <sha256 of the decision's inputs>`. Only under `forbid`, and it counts only as a regular file of our own uid (not a symlink), with no future timestamp and an unchanged input hash. |

**Known limits.**

- *Forged marker.* Any process of the same uid can write a marker with a valid hash (the inputs are readable). The dashboard then sends the once-a-day "customProvider = Anthropic" alert instead of the "session vanished, restarting" one. `channels.sh` still starts and decides again, so the marker does not bypass the decision, it only swaps the alert text. The alert therefore says it speaks from the marker and gives its path; if `store/channels-failures.log` has no fresh `main-agent-custom-provider refused` line, the marker was not written by `channels.sh`.
- *Remote ssh launch with a non-Anthropic custom provider.* There is deliberately no `unset`: the agent is not first-party, its provider route comes from the remote host's own env (the command exports nothing), and a custom provider authenticates with exactly these names. If the remote host's env has no provider URL, a key there reaches Anthropic unguarded; the runtime guard does not see the remote host.
- *The guard event's `where` field* appears in the message to the main agent only if it is (a) a known launch label (`<launcher>:<fixed reason>`), or (b) a settings file under the home or the install: `.claude/settings.json`, `.claude/settings.local.json`, `.claude-config/settings.json`, `.claude-config/settings.local.json`, or the same with an `agents/<id>/` prefix, where `<id>` is text that passes the agent-id filter: the same pattern as `AGENT_ID_RX`, which filters the event file's `agent` field (`interactive-key-guard-runner.ts:742`, `^[A-Za-z0-9_-]{1,64}$`), with `SETTINGS_UNDER_ROOT_RX` (`:759`) holding its own identical copy (`shownGuardWhere`, `:761`). So a message to the main agent may quote an `agents/<id>/...` path, but the `<id>` can only be ASCII letters, digits, `_` and `-`, at most 64 characters. The id after the `main-agent-custom-provider:` label is shown as `<egyéb>`; everything else is shown as `<egyéb>` too (the full line stays in the event file).
- The `unset` at launch protects new sessions only; a session that is already running is flagged by the guard but not stopped.

**Rollback.** In `.env` set `INTERACTIVE_ANTHROPIC_KEY_POLICY=allow` (or delete the line), then restart the dashboard; the shell launchers read `allow` on their next run. Under `allow` every launch command is byte-identical to the old one, the marker has no effect, and on the next start `channels.sh` puts the `.env` key back into the tmux global env. The store files need not be deleted: under `allow` the marker is inert, and the runtime guard writes no guard event and sends no alert.

---

## templates/ -- Agent Creation Templates

These templates are populated during agent scaffolding and placed into `agents/<name>/`.

| File / Folder | Description |
|---------------|-------------|
| `templates/CLAUDE.md.template` | Default CLAUDE.md template for new agents |
| `templates/SOUL.md.template` | Default SOUL.md template |
| `templates/settings.json.template` | Claude Code settings template (hooks, permissions) |
| `templates/profiles/` | Permission profile templates (JSON files) |
| `templates/scheduled-tasks/` | Built-in scheduled tasks (morning briefing, memoria-heartbeat, etc.) |

### Permission Profiles (templates/profiles/)

| Profile | permissionMode | Description |
|---------|---------------|-------------|
| `default.json` | permissive | Default fallback, everything allowed |
| `developer-senior.json` | permissive | SSH/AWS/sudo blocked, otherwise unrestricted |
| `developer-junior.json` | strict | Strict sandbox, only allowed paths |
| `marketer.json` | strict | Marketing-specific access |
| `researcher.json` | strict | Researcher profile, limited writes |

Profile is set via the `profileId` field in `agent-config.json` and configurable from the dashboard "Agents" view.

Under a strict profile Claude Code runs in `dontAsk` mode, where a command substitution
(`$(cat <token>)`) never matches the allow-list, so such an agent cannot run the token `curl`
recipes (#2232). It reaches the dashboard API through `scripts/marveen-api.sh` instead, which
reads the token itself and takes every text from a file (`bash scripts/marveen-api.sh --help`
lists the verbs). The helper and `scripts/agent-msg.sh` are on the `developer-junior.json`
allow-list, and the generated CLAUDE.md blocks give a strict agent this recipe; every other
agent keeps the `curl` recipe unchanged. The helper sends the token only to a loopback address, or to exactly the
`AGENT_API_ORIGIN` / `DASHBOARD_PUBLIC_URL` in the install's `.env` (`MARVEEN_API_BASE`), and reads it only from a `.dashboard-token` file.

---

## Memory: daily-log mirror and date filter

There is nothing to configure: both are always on. Details: [memory-system.md](memory-system.md) (Hungarian).

| What | Behaviour |
|------|-----------|
| Log mirror | Every `POST /api/daily-log` entry also creates a `cold`-tier, `episodic` `memories` row (`[Napló YYYY-MM-DD HH:MM] <text>`, keywords `napi-naplo, YYYY-MM-DD`); the `daily_log_memory` table holds the link. Text that fails the memory content filter is still saved to the log, without a mirror (`memory_mirror: "skipped:content-filter"`). |
| Backfill | `npx tsx scripts/daily-log-backfill-memories.ts [--db <path>] [--apply]`. A dry run by default that writes nothing (the database is opened read-only, no migration); `--apply` writes, idempotent. |
| Date filter | `GET /api/memories?...&date=<expression>` or `&since=YYYY-MM-DD&until=YYYY-MM-DD`, calendar days in the install time zone (`APP_TZ`). Applied in SQL before the LIMIT in every search branch. An invalid value is a 400. The `X-Memory-Search` header carries `date=<from>..<to>` with the range actually used. |
| Relevance | The similarity floor (`MEMORY_VECTOR_MIN_MARGIN`, `MEMORY_VECTOR_BASELINE_MIN_ROWS`, `MEMORY_VECTOR_SMALL_CORPUS_MIN_SIMILARITY`) is computed from the candidates inside the date window; a narrow window can fall back to the small-corpus floor. |
| Indexes | `memories(agent_id, created_at)`, `memories(category, created_at)` (created at startup, idempotent). |

---

## Memory: daily-log mirror and date filter

There is nothing to configure: both are always on. Details: [memory-system.md](memory-system.md) (Hungarian).

| What | Behaviour |
|------|-----------|
| Log mirror | Every `POST /api/daily-log` entry also creates a `cold`-tier, `episodic` `memories` row (`[Napló YYYY-MM-DD HH:MM] <text>`, keywords `napi-naplo, YYYY-MM-DD`); the `daily_log_memory` table holds the link. Text that fails the memory content filter is still saved to the log, without a mirror (`memory_mirror: "skipped:content-filter"`). |
| Backfill | `npx tsx scripts/daily-log-backfill-memories.ts [--db <path>] [--apply]`. A dry run by default that writes nothing (the database is opened read-only, no migration); `--apply` writes, idempotent. |
| Date filter | `GET /api/memories?...&date=<expression>` or `&since=YYYY-MM-DD&until=YYYY-MM-DD`, calendar days in the install time zone (`APP_TZ`). Applied in SQL before the LIMIT in every search branch. An invalid value is a 400. The `X-Memory-Search` header carries `date=<from>..<to>` with the range actually used. |
| Relevance | The similarity floor (`MEMORY_VECTOR_MIN_MARGIN`, `MEMORY_VECTOR_BASELINE_MIN_ROWS`, `MEMORY_VECTOR_SMALL_CORPUS_MIN_SIMILARITY`) is computed from the candidates inside the date window; a narrow window can fall back to the small-corpus floor. |
| Indexes | `memories(agent_id, created_at)`, `memories(category, created_at)` (created at startup, idempotent). |

---

## ~/.claude/scheduled-tasks/ -- Scheduled Tasks

Each task lives in its own folder with two files. Detailed description: [scheduled-tasks.md](scheduled-tasks.md).

| File | Description |
|------|-------------|
| `SKILL.md` | YAML frontmatter (name, description) + prompt body |
| `task-config.json` | Cron expression, agent, type, behaviour flags |

---

## ~/.claude/channels/ -- Channel Access

| File | Description |
|------|-------------|
| `~/.claude/channels/telegram/access.json` | Telegram allowFrom list, paired senders |
| `~/.claude/channels/slack/access.json` | Slack allowFrom list |

---

## .mcp.json -- MCP Servers

MCP configurations are scoped: agent `agents/<name>/.mcp.json` files contain only the servers relevant to that agent. The `.mcp.json` at the project root applies to the main agent (marveen/Jarvis).

```json
{
  "mcpServers": {
    "gitlab": {
      "command": "npx",
      "args": ["-y", "@zereight/mcp-gitlab"],
      "env": {
        "GITLAB_PERSONAL_ACCESS_TOKEN": "...",
        "GITLAB_API_URL": "https://gitlab.com/api/v4"
      }
    },
    "google-workspace": {
      "command": "npx",
      "args": ["-y", "google-workspace-mcp", "serve"]
    }
  }
}
```

**Important:** the `agents/` folder is gitignored, so secrets in `.mcp.json` files don't end up in the repository. Verify the project-root `.mcp.json` is also gitignored.

---

## Environment Variables (.env / launchd plist)

Key configuration variables live in the launchd plist (`~/Library/LaunchAgents/com.marveen.dashboard.plist`) or `.env` file.

| Variable | Description |
|----------|-------------|
| `CHANNEL_PROVIDER` | `telegram` or `slack` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot API token |
| `ALLOWED_CHAT_ID` | The single allowed Telegram chat ID |
| `SLACK_BOT_TOKEN` | Slack bot token (if Slack provider) |
| `SLACK_CHANNEL_ID` | Slack channel ID |
| `WEB_PORT` | Dashboard port (default: 3420). Can be set at install time via the `--port <N>` CLI flag (`./install-linux.sh --port 3421`) or as an env variable (`WEB_PORT=3421 ./install.sh`). |
| `ANTHROPIC_API_KEY` | Claude API key |
| `INTERACTIVE_ANTHROPIC_KEY_POLICY` | `allow` (default; a missing or empty value too) or `forbid` (any other value too): whether an interactive first-party Claude session may be started on an API key. `.env` only. See [above](#interactive_anthropic_key_policy----interactive-key-guard) |
| `OWNER_NAME` | Owner name (e.g. "Jónás Gergő") |
| `BOT_NAME` | Main agent name (e.g. "Jarvis") |
| `VOICE_TRANSCRIBE_INBOUND` | `1` = transcribe inbound voice notes for text-mode agents too (default off; per-agent `voice.transcribeInbound` overrides). See `voice.md` |
| `MEMORY_ABSTAIN_MIN_COS` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Threshold (0-1) of the hybrid memory search's relevance label. Only `GET /api/memories?mode=hybrid` called with `abstain=1` uses it: `X-Memory-Search` then ends in `; top-cos=<x.xx>; overlap=<n>; relevance=<low\|ok\|unknown>`. A label, not a filter: the rows are the same. Score = topCos + `W_GAP` * (topCos - second cosine) + `W_OVERLAP` * min(overlap, 2) + `W_FTS` * (strict keyword match); `low` when the score is below the threshold. Empty (default) or invalid = off: `relevance=unknown`. When the vector branch is out (embedding failure) always `unknown`, never `low`. Calibrated (2026-10-17, v2 set, bge-m3): 0.53, every weight 0; do NOT set it before the hold-out measurement (fitted on 6 negative questions, upper margin 0.011) |
| `MEMORY_ABSTAIN_W_GAP` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Weight of the gap (best minus second cosine) in the relevance score, 0-10, default 0. Invalid = 0 |
| `MEMORY_ABSTAIN_W_OVERLAP` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Weight of the rows shared by the two branches' top 10 (at most 2), 0-1, default 0. Invalid = 0 |
| `MEMORY_ABSTAIN_W_FTS` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Weight of a strict (not relaxed) keyword match, 0-1, default 0. Invalid = 0 |
| `MEMORY_HYBRID_RECENCY_WEIGHT` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Weight of the hybrid memory search's recency term, 0-1, default 0 (off: the order is the previous one, bit for bit). A row scores `RRF + weight * exp(-age / TAU)`, the age taken from `created_at` (not `updated_at`, which tier moves restamp; a future value counts as 0 days). Rank 1 of one RRF branch is about 0.0164, so a weight around 0.005 puts the newer of two near-equal rows first, while 0.02 can outweigh a whole branch. Invalid = 0, one WARN |
| `MEMORY_HYBRID_RECENCY_TAU_DAYS` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. Time constant of the recency term in days, above 0, at most 3650, default 30. Invalid = 30, one WARN |
| `MEMORY_HYBRID_FTS_RECENCY` | Read only from `store/config-overrides.json` and `.env` (in that order); the process environment, the launchd plist included, is NOT consulted. `on` (default) or `off`: the hybrid search's keyword branch keeps its own recency re-rank (λ 0.7, τ 7 days). `off` = the branch keeps the plain bm25 order, so the time signal is not counted twice. The keyword-only search is not affected. Invalid = `on`, one WARN |
| `MEMORY_GATE_MODE` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Mode of the memory write gate: `off` (default; a missing, empty or unknown value too), `shadow` or `active`. In b1 it only logs: it writes nothing to `memories`; `active` also runs as `shadow` (WARN) |
| `MEMORY_GATE_OWNERS` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Comma-separated agent ids (`[a-z0-9_-]{1,32}`) whose `warm`/`cold` memories may reach the gate. Empty (default) = the gate does nothing. A malformed element or `feszek` = config error, the whole gate stays inert |
| `MEMORY_GATE_MAIN_AGENT_OK` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). A `tg-<digits>` reference to the owner's decision; only with it does the main agent count as an owner. Any other shape or empty = the main agent is dropped, the other owners keep working |
| `MEMORY_GATE_BATCH_DIR` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Absolute path of the shared batch client directory (`batch_client.py`, `usage_log.py`). Required once the gate would call; missing or relative = config error |
| `MEMORY_GATE_MODEL` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Classifier model id, default `claude-haiku-5-5` |
| `MEMORY_GATE_MAX_CALLS_PER_DAY` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Daily call cap per Budapest day, 1-2000, default 300. Invalid = config error |
| `MEMORY_GATE_DAILY_USD` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Daily spend cap in USD, 0.01-0.50, at most two decimals, default 0.50. The upper bound is fixed in code: `.env` can only lower it. Reserved before every call. Invalid = config error |
| `MEMORY_GATE_MAX_PROMPT_BYTES` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Upper size of the outgoing prompt in bytes, 2000-48000, default 12000 |
| `MEMORY_GATE_MAX_TOKENS` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Answer length in tokens, 64-1000, default 300 |
| `MEMORY_GATE_CANDIDATES` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Candidates per call, 1-5, default 5 |
| `MEMORY_GATE_SUPERSEDE_MIN_CONF` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Confidence threshold of a `SUPERSEDE` decision, 0.5-1, default 0.85. In b1 it only feeds the `would_apply` evaluation |
| `MEMORY_GATE_OTHER_MIN_CONF` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). Threshold of the other effect-bearing decisions, 0.5-1, default 0.70. In b1 it only feeds the `would_apply` evaluation |
| `MEMORY_GATE_MAX_SUPERSEDE_PER_DAY` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). At most this many `SUPERSEDE` decisions a day may be marked `would_apply`, 0-1000, default 20 |
| `MEMORY_GATE_MAX_CONTRADICT_PER_DAY` | `.env` only (neither `store/config-overrides.json`, nor the process environment, nor the Settings page is consulted); a change needs a dashboard restart. See [memory-write-gate.md](memory-write-gate.md). At most this many `CONTRADICT` decisions a day may be marked `would_apply`, 0-1000, default 20 |

---

## Related Documents

- [Vault and Encryption](vault.md)
- [MCP Configuration](mcp-config.md)
- [Scheduled Tasks](scheduled-tasks.md)
- [Security Model](security.md)
- [Migration](MIGRATION.md)
