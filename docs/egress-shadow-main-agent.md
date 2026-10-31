# Bash egress gate in SHADOW mode on the main agent (card 59d87635)

`scripts/hooks/egress-gate-shadow.mjs` runs the same classification as the enforcing Bash gate
(`scripts/hooks/bash-egress-parser.mjs`: `classify`, `measureOnly`, vendor-host lists are imported, not
copied) and logs what the gate WOULD decide. It always exits 0 and prints nothing: it cannot deny, also
not when the classifier throws, the input is garbage or the hook is killed by its timeout. No argument or
env variable turns it into enforce. Sub-agents keep running `bash-egress-parser.mjs` in enforce mode,
unchanged.

The main agent's `permissions.deny` (`curl *https://*`, wget, nc, ncat, telnet) stays as it is; this hook
only adds a measurement next to it.

## Which settings file

Registered in the tracked project file `.claude/settings.json` (deployed to
`/Users/gyorgydecsi/marveen/.claude/settings.json` by merging this commit), in `hooks.PreToolUse`, as a
`Bash` matcher entry AFTER the existing Bash gates, with the `--main-scope` flag. Not
`/Users/gyorgydecsi/marveen/.channels-config/settings.json`, although that file is the main agent's own:

- The repo's own provisioner drops `hooks` from the isolated config dir on every start
  (`src/web/agent-process.ts`, #1305: "hooks never ride the clone", and a `hooks` key found in the
  target's own settings is explicitly not inherited back). The header of `bash-egress-parser.mjs` says the
  same: the main agent's own config dir cannot carry hooks, that is why its registration is
  project scope with `--main-scope`. An entry in `.channels-config/settings.json` would be silently gone
  after the next `channels.sh` start. (Read from the code, not tested on a live restart.)
- `--main-scope` makes the hook judge only sessions on a config dir of their own (the main agent's
  `.channels-config`, or a provisioned sub-agent dir), and skip Gyuri's interactive sessions on the shared
  `~/.claude` (same rule as the enforcing hook, `mainScopeAppliesTo`).
- The project file is git-tracked: the entry arrives by merge, and the rollback is a revert or removing
  the entry. A provisioned sub-agent session that also loads this file is judged too (it has a config dir
  of its own) and its line goes to the same log, tagged by the `agent` field (payload `agent_type`, else
  `MARVEEN_AGENT_ID` / `MAIN_AGENT_ID`, else `null`). It is harmless (exit 0, no output); filter on `agent`
  when reading the log. Which value the main agent itself carries was not measured.

JSON to add (one more element in `hooks.PreToolUse`, next to the existing Bash entries):

```json
{
  "matcher": "Bash",
  "hooks": [
    {
      "type": "command",
      "command": "node \"$CLAUDE_PROJECT_DIR/scripts/hooks/egress-gate-shadow.mjs\" --main-scope; exit 0",
      "timeout": 5
    }
  ]
}
```

`timeout: 5` (seconds) bounds the hook; a command above 64 KiB or 2000 lines is not classified and is
logged as `too_large` (the parser is quadratic in lines, card 80743e3a). `; exit 0` makes even a missing `node` or a load error non-blocking. Use the same node binary path as
the neighbouring entries if they pin one (`/opt/homebrew/opt/node@22/bin/node`).

## Rollback (one step)

Remove that entry from `hooks.PreToolUse` (or `git revert` the commit that added it). Takes effect on the
next session start. The log files can stay or be deleted by Brainy.

## The log

`/Users/gyorgydecsi/marveen/store/egress-shadow.jsonl` (0600; at 2 MiB it rotates to
`egress-shadow.jsonl.1`, so both together stay under 5 MB). One line per Bash call:

```
{"ts":"...","cmd_sha256":"<hex>","decision":"allow|deny-would-be","reason":"<code>","agent":"<id|null>"}
```

Reason codes: `clean`, `measure-only`, the classifier's own codes for a would-be deny (`curl-external`,
`wget-external`, `one-liner-external`, `function-indirect`, ...), `bad-input`, `too_large`,
`shadow-error:<ErrorName>`. Never the command text, URL, host or token. To find which command a hash
belongs to, hash the suspected command (`printf %s "$CMD" | shasum -a 256`) and compare.

Count decisions and reasons:

```
python3 -c "import json,collections as c; L=[json.loads(l) for l in open('/Users/gyorgydecsi/marveen/store/egress-shadow.jsonl') if l.strip()]; print(len(L), c.Counter((x['decision'],x['reason']) for x in L).most_common())"
```

## Enforce is a separate GO

Read the log for 7 days. Enforce on the main agent (replacing this entry with the enforcing
`bash-egress-parser.mjs --main-scope` registration) happens only after those 7 days, with a separate GO
from Gyuri, and only after every `deny-would-be` line has been explained as a true positive or fixed in
the parser. This card does not enable enforce.
