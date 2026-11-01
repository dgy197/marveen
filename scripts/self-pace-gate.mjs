#!/usr/bin/env node
// PreToolUse hard-gate: blocks SELF-PACE for sub-agents.
//
// Governance control (2026-06-26, after the autonom-kor incident: a sub-agent
// scheduled its own wakeups via ScheduleWakeup, fed itself prompts, and acted
// on a SELF-GENERATED "A) zárjuk le" decision -- dispatching real development
// -- while the operator slept. Two independent adversarial audits confirmed the
// root cause is the agent's own self-pace loop, not an external vector).
//
// A sub-agent must be INPUT-DRIVEN: it acts on operator / peer messages, never
// on prompts it scheduled for itself. This gate blocks every self-pace path:
//   - the Claude Code runtime tools ScheduleWakeup / CronCreate / CronList /
//     CronDelete / RemoteTrigger (the autonomous-loop machinery), AND
//   - the Bash escape routes that achieve the same self-injection: writing the
//     Claude scheduled_tasks.json directly, tmux send-keys into a session, or
//     creating/changing a dashboard schedule -- through /api/schedules with ANY
//     client, or by writing the scheduled-tasks store it lives in (Bash or the
//     native Write/Edit/NotebookEdit tools). See scheduleSurfaceDeny.
//
// Why a hook and not only a permissions deny-list: permissive profiles launch
// with --dangerously-skip-permissions. A whole-tool-name deny DOES survive that
// (deny is checked before the bypass allow), so the scaffold also adds these
// names to permissions.deny -- but the Bash-command routes can ONLY be caught
// by a PreToolUse hook, which runs regardless of permission mode. Defense in
// depth: deny-list for the tool names, this hook for the Bash routes (+ the
// names again, redundantly fail-closed).
//
// Wired into every sub-agent's .claude/settings.json by
// writeAgentSettingsFromProfile() (agent-scaffold.ts), guarded by
// name !== MAIN_AGENT_ID, re-applied on every spawn (respawn-safe).

import { readFileSync, realpathSync } from 'node:fs'
import { randomBytes } from 'node:crypto'
import { homedir } from 'node:os'
import { basename, dirname, join, relative, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { Worker, isMainThread, parentPort, workerData } from 'node:worker_threads'
import { joinShellLines, shellContext, CTX_CLASS } from './shell-line-join.mjs'

// The allowlist this install's egress-gate.mjs reads (scripts/ -> repo root -> store/).
const DEFAULT_ALLOWLIST_PATH = join(dirname(fileURLToPath(import.meta.url)), '..', 'store', 'egress-allowlist.json')

// Claude Code runtime self-pace / scheduling tools. A sub-agent has no
// legitimate need to schedule its own future turns -- it is input-driven.
const SELF_PACE_TOOLS = new Set([
  'ScheduleWakeup',
  'CronCreate',
  'CronDelete',
  'CronList',
  'RemoteTrigger',
])

// Bash command patterns that achieve self-pace by another route. These are
// tested per COMMAND SEGMENT (see splitSegments), so a token in one part of a
// compound command never trips a pattern that belongs to another part.
const SELF_PACE_BASH_PATTERNS = [
  // tmux pane injection -- every write-subcommand that can push keys/text/commands
  // into a pane (the actual incident vector), not just send-keys. [\s\S] (not
  // [^\n]) so an intra-segment newline cannot split the match.
  /\btmux\b[\s\S]*\b(send-keys|paste-buffer|run-shell|set-buffer)\b/i,
  // self-backgrounding that relaunches claude (nohup/setsid/disown + claude)
  /\b(nohup|setsid|disown)\b[\s\S]*\bclaude\b/i,
  // the loop slash-skill driven from a shell. `/loop` must be in SLASH-COMMAND
  // position -- a standalone token (segment-start / whitespace / quote before it,
  // whitespace / quote / end after it) -- never a PATH segment. The old
  // `\/loop\b` fired on any `loop`-prefixed path component whenever `.claude` was
  // in the same command (\bclaude\b matches the `.claude` in every memory/skill
  // path), so reading `.../memory/loop-stop-...md` or `~/.claude/skills/loop/...`
  // was denied (measured 2026-07-26, found by pg: Heli denied a harmless memory
  // read). Same bug class as the at/batch and launchctl fixes below: a keyword in
  // a PATH collided with a call pattern; the fix is to match the invocation SHAPE.
  // Every real form stays denied: `claude /loop 5m`, `claude -p "/loop x"`,
  // `claude '/loop'`, bare `claude /loop`.
  /\bclaude\b[\s\S]*(?:^|[\s'"])\/loop(?=[\s'"]|$)/i,
]

// OS-level schedulers + delayed exec (cron / launchd / systemd / at / batch): the
// shell route to the same self-pace the CronCreate tool-deny blocks at the runtime
// layer. Anchored to command position (segment start), but a leading wrapper is
// allowed before the binary -- sudo/env/command/nice, a VAR=val environment, and
// an absolute/relative path -- so `sudo crontab -r`, `/usr/bin/at now`,
// `PATH=/bin crontab -` are all caught. Trailing \b(?!-) so it never fires on
// "netstat" / "crontab-helper.sh"; (?!\s*=) so a bare NAME=value assignment
// (`at=$(...)`) is not mistaken for the `at` binary.
const SCHED_PREFIX = String.raw`(?:(?:[A-Za-z_]\w*=\S*|sudo|env|command|exec|nice|builtin|time)\s+)*(?:\S*/)?`
// The command-boundary anchor includes `(` so a $(...) command substitution
// (`X=$(crontab -)`) is caught, AND a backtick so a legacy `...` substitution
// (`X=`crontab -r``) is caught too -- both run the enclosed command in a shell
// context, so a scheduler binary immediately inside either is a real self-pace.
const SCHED_BOUNDARY = '[;&|(`]'
// `at` and `batch` are also ordinary English words, and splitSegments splits on
// NEWLINES -- so a PROSE line inside a multi-line commit body ("at least 80% of
// entries", "batch size is 50") lands at a segment start and looked exactly like
// the at(1)/batch(1) binaries. Measured 2026-07-25 (found by JogAsz): a heredoc
// commit message was denied for the words "at least"; the identical command
// passed after rewording that one line. The `-m "$(...)"` form is deliberately
// NOT blanked by stripGitCommitMessages (a real substitution could hide there),
// so the body does reach the splitter -- the fix belongs here, not there.
//
// For these two words ONLY, also require something that looks like an actual
// invocation: end of segment (a bare `batch` reads stdin -- still a real vector),
// a flag, an input redirect, or an at(1) TIMESPEC (which at(1) requires anyway,
// so a real submit can never omit it). crontab/launchctl/systemd-run keep the
// plain match: they are not English words, so prose cannot collide with them.
const AT_INVOCATION = String.raw`(?=\s*$|\s+-|\s*<|\s+(?:now|noon|midnight|teatime|today|tomorrow|next\b|\+\s*\d|\d{1,2}:\d{2}|\d{3,4}\b|\d{1,2}\s*(?:am|pm)\b|\d{1,2}[./]\d{1,2}|(?:mon|tue|wed|thu|fri|sat|sun)|(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)))`
// `launchctl` needed the SAME narrowing, for a different reason than at/batch, and
// the comment above ("not English words, so prose cannot collide") was measured
// wrong on 2026-07-26 (found by Hacker). It is not an English word -- but the
// fleet's own heartbeats ORDER every agent to report `launchctl list | grep
// com.jarvis.channels` output, so a launchd JOB LABEL appears in prose constantly.
// splitSegments splits on `;`, so a report line "...; launchctl com.jarvis.channels
// PID 555" put `launchctl <label>` at a segment start and it read as a real
// invocation. His status message was denied; the finding is systemic, not his.
//
// The narrowing mirrors AT_INVOCATION: instead of enumerating dangerous
// subcommands (a denylist -- miss one and it is a hole), require the SHAPE of a
// real invocation. Every launchctl self-pace vector (load/bootstrap/submit/
// kickstart/start/enable/...) takes a SUBCOMMAND word first, so demand that the
// next token could be one: a bare lowercase word, no dot and no slash. A job
// label (`com.jarvis.channels`) and a path both fail that and pass through as
// prose. End-of-segment and a flag stay DENIED -- a bare `launchctl` is
// interactive, still a real vector.
const LAUNCHCTL_SUBCOMMAND = String.raw`(?=\s*$|\s+-|\s+[a-z][a-z-]*(?:\s|$))`
const SCHEDULER_RX = new RegExp(
  String.raw`(^|${SCHED_BOUNDARY}\s*)${SCHED_PREFIX}(?:(?:crontab|systemd-run)\b(?!-)(?!\s*=)|launchctl\b(?!-)(?!\s*=)${LAUNCHCTL_SUBCOMMAND}|(?:batch|at)\b(?!-)(?!\s*=)${AT_INVOCATION})`,
  'i',
)
// ...but allow a pure READ-listing of one's own schedule (parity with the store /
// schedule-API read exemptions): crontab -l, launchctl list/print, atq.
const SCHEDULER_READ_RX = new RegExp(String.raw`(^|${SCHED_BOUNDARY}\s*)${SCHED_PREFIX}(crontab\s+-l\b|launchctl\s+(?:list|print|dumpstate|blame|examine)\b|atq\b)`, 'i')

// The Claude self-schedule store. Blocked for WRITE on any route (a Bash write,
// or the native Write/Edit/NotebookEdit tool); a read/grep is legit diagnostics.
const SCHEDULE_STORE_RX = /scheduled_tasks\.json/i
// Write-intent shell tokens (redirect / tee / in-place edit / dd / copy-move).
const WRITE_INTENT_RX = /(>>?|\btee\b|\bsed\b[\s\S]*\s-i|\bdd\b|\bcp\b|\bmv\b)/i
// Dashboard schedule API, curl spelling only. A WRITE method (POST/PUT/PATCH/
// DELETE) creates/edits a self-paced cron; a GET is legit diagnostics. This pair
// never saw any other HTTP client -- see scheduleSurfaceDeny,
// which covers the API and its on-disk store for every client.
const SCHEDULE_API_RX = /\/api\/schedules\b/i
const HTTP_WRITE_RX = /(-X\s*(POST|PUT|PATCH|DELETE)|--request\s+(POST|PUT|PATCH|DELETE)|(^|\s)(--data\b|--data-\w+\b|-d\b))/i

// THE EGRESS ALLOWLIST IS A GATE ON THE SUB-AGENT ITSELF (EGRESSSELFEDIT824).
// store/egress-allowlist.json decides which hosts egress-gate.mjs lets through, and it
// was a plain writable file in the sub-agent's own tree: on 2026-08-24 a nested
// sub-agent added a domain to reach it and removed it afterwards. Its legitimate
// writers are the MAIN agent (on the owner's go) and the owner by hand -- neither runs
// this gate (it is wired for sub-agents only), so neither is affected.
//
// Native file tools: denied on the file name AND on the resolved real path, so a
// relative path or a symlink created earlier does not walk past the name check.
// Bash: FAIL-CLOSED. A segment that mentions the file may only be a plain READ
// (cat/grep/jq/...), and an output redirect in it may not point at the file. An
// interpreter (python/node/...), cp/mv/tee/sed/ln/... or anything else that names the
// file is denied, because whether it writes cannot be read off the command string.
//
// What this gate CANNOT see -- a script that builds the path at runtime, a glob that
// does not spell the name -- is written down, not hidden: the dashboard keeps a hash
// baseline of the file and reports every change, whoever made it, by whatever route
// (src/egress-allowlist-baseline.ts). This gate narrows the casual route; that one
// catches the rest after the fact.
const ALLOWLIST_BASENAME = 'egress-allowlist.json'
// The STORE objects, not the concept: the file and its history directory, or a glob that
// starts on the name (egress-allow*, egress-allowlist.*). A plain /egress[-_]?allow/ also
// matched this gate's own source and test names (egress-allowlist-baseline.ts), so no
// sub-agent could run, stage or diff them -- review on #1678.
const ALLOWLIST_MENTION_RX = /egress[-_]?allowlist(?:\.json|\.history)|egress[-_]?allow[\w.]*[*?[]/i
const ALLOWLIST_READERS = new Set([
  'cat', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'jq', 'wc', 'ls', 'stat',
  'file', 'shasum', 'sha256sum', 'md5', 'md5sum', 'diff', 'cmp', 'echo', 'printf',
])
// Output redirects: `>`, `>>`, `>|`, `&>`, `&>>`, `N>`. The target is the next word.
const OUTPUT_REDIRECT_RX = /(?:&>>?|\d*>>?\|?)\s*([^\s;&|<>]+)/g

export function allowlistBashSegmentAllowed(seg) {
  return readOnlyMentionAllowed(seg, ALLOWLIST_MENTION_RX)
}

// MORE STORE FILES ARE GATES ON THE SUB-AGENT ITSELF (kanban c556a35a), and get the same
// treatment as the allowlist above:
//   egress-vendor-hosts.json       -- the hosts bash-egress-parser lets curl/wget reach
//   config-overrides.json          -- dashboard settings; BASH_SANDBOX_AGENTS is one of them
//   bash-sandbox-write-paths.json  -- where a sandboxed agent may write (#2149)
//   email-standing-recipients.json -- an address on it (once activated) takes letters with
//                                     no per-letter approval (email-approval-gate.py)
//   .approval-bot-token, .approval-bot-key -- the owner's approval bot and the key its button data is
//                                     signed with (src/approval-bot.ts, #2160)
// Their writers are the owner, the main agent and, for config-overrides.json, the dashboard
// process; none of them runs this gate. Unlike the allowlist, these have no hash baseline yet,
// so what this gate cannot see (a path built at runtime) is not reported after the fact.
const DEFAULT_STORE_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', 'store')
export const PROTECTED_STORE_FILES = new Set([
  'egress-vendor-hosts.json',
  'config-overrides.json',
  'bash-sandbox-write-paths.json',
  'bash-sandbox-hosts.json',
  'email-standing-recipients.json',
  '.approval-bot-token',
  '.approval-bot-key',
])
// The file, or a glob that starts on its name. The prefixes are long enough that this gate's
// and the features' own sources (bash-sandbox.ts, config-registry.ts) stay out of it; the
// approval-bot files need their leading dot, so a source or doc named approval-bot-key-*.md or a
// glob over src/approval-bot* stays out too.
const PROTECTED_MENTION_RX =
  /(?:egress[-_]?vendor[-_]?hosts|config[-_]?overrides|bash[-_]?sandbox[-_]?write[-_]?paths|bash[-_]?sandbox[-_]?hosts|email[-_]?standing[-_]?recipients)\.json|\.approval[-_]?bot[-_]?(?:token|key)\b|(?:egress[-_]?vendor|config[-_]?overrid|bash[-_]?sandbox[-_]?write|bash[-_]?sandbox[-_]?h|email[-_]?standing|\.approval[-_]?bot)[\w.-]*[*?[]/i

// One rule for every protected store object: a segment that mentions it may only be a plain
// READ, and no output redirect in it may point at it (or at a target built at runtime).
function readOnlyMentionAllowed(seg, mentionRx) {
  const s = String(seg ?? '').trim()
  if (!mentionRx.test(s)) return true
  const words = s.split(/\s+/)
  let i = 0
  while (i < words.length && /^[A-Za-z_][A-Za-z0-9_]*=/.test(words[i])) i++ // leading VAR=x
  const cmd = (words[i] ?? '').replace(/^.*\//, '')
  if (!ALLOWLIST_READERS.has(cmd)) return false
  for (const m of s.matchAll(OUTPUT_REDIRECT_RX)) {
    const target = m[1]
    if (/^&?\d+$/.test(target) || target === '/dev/null') continue // 2>&1, >/dev/null
    if (mentionRx.test(target) || /[$`]/.test(target)) return false
  }
  return true
}

export function protectedStoreBashSegmentAllowed(seg) {
  return readOnlyMentionAllowed(seg, PROTECTED_MENTION_RX)
}

// Does a native file-tool call target one of the protected store files? By name anywhere
// (fail-closed, as for the allowlist), or by real path, so a symlink under another name does
// not walk past it. `storeDir` is this install's store; tests pass a tmp one.
export function fileToolTargetsProtectedStoreFile(toolInput, storeDir = DEFAULT_STORE_DIR, cwd = process.cwd()) {
  const raw = String(toolInput?.file_path ?? toolInput?.notebook_path ?? '')
  if (!raw) return false
  if (PROTECTED_STORE_FILES.has(basename(raw).toLowerCase())) return true
  const real = realOrSelf(resolve(cwd, expandHome(raw)))
  return [...PROTECTED_STORE_FILES].some((f) => real === realOrSelf(join(storeDir, f)))
}

function expandHome(p) {
  return p.startsWith('~/') ? join(homedir(), p.slice(2)) : p
}
function realOrSelf(p) {
  try { return realpathSync(p) } catch { return p }
}

// Does a native file-tool call target the allowlist? `allowlistPath` is the real file
// this install's egress-gate reads; tests pass a tmp one.
export function fileToolTargetsAllowlist(toolInput, allowlistPath = DEFAULT_ALLOWLIST_PATH, cwd = process.cwd()) {
  const raw = String(toolInput?.file_path ?? toolInput?.notebook_path ?? '')
  if (!raw) return false
  if (basename(raw).toLowerCase() === ALLOWLIST_BASENAME) return true
  const abs = resolve(cwd, expandHome(raw))
  return realOrSelf(abs) === realOrSelf(allowlistPath)
}

// Split a compound command into individual simple commands, so a token in one
// segment cannot trip a check anchored in another (e.g. `cat store && cp a b`).
// Line-continuations (backslash-newline) are collapsed FIRST, exactly as the
// shell's lexer does it (joinShellLines: an odd backslash run before LF only, not
// inside '...' or a comment, nothing left in their place), so a single command
// continued across lines stays ONE segment and a `\\<newline>` or a comment ending
// in a backslash does NOT hide the next line; only real separators split.
// (`tmux \<newline>send-keys` joins to `tmux send-keys`; `tmux\<newline>send-keys`
// joins to the single word `tmuxsend-keys`, which is what the shell runs.)
//
// KNOWN LIMITATIONS (accepted, defense-in-depth -- the runtime tool-deny is the
// primary guard, this Bash hook is a second layer; a sub-agent is not adversarial
// to its own gate, it just must not casually self-pace):
//   - Not quote-aware: a separator INSIDE quotes (e.g. a commit message
//     `git commit -m "fix; crontab -r"`) splits and could false-deny. Rare
//     enough (the quoted ; must be immediately followed by a blocked binary at a
//     segment start) that a full shell-tokenizer is not warranted here. The
//     opposite error is covered too (card 0bb35172): a quoted newline or `;`
//     can also cut a dangerous pair in two (`tmux 'a<NL>' send-keys`), so the
//     gate additionally runs maskedSegments, which cuts only where the shell
//     does, on top of this naive list. Still open (accepted, spec Q2): a QUOTED
//     command word followed by a quoted newline (`'tmux' 'a<NL>' send-keys`):
//     the naive pass cuts it in two and the masked pass blanks the quoted word.
//   - A $(...) or backtick substitution that assigns a scheduler result
//     (`X=$(crontab -)`, `X=`crontab -``) is caught by SCHEDULER_RX's boundary
//     anchor, which now includes both `(` and the backtick.
// The shell's command separators, shared by splitSegments and anchoredSegments.
const SEGMENT_SEPARATOR_SOURCE = '&&|\\|\\||[;&|]|\\r?\\n'

export function splitSegments(command) {
  return joinShellLines(String(command ?? ''))
    .split(new RegExp(SEGMENT_SEPARATOR_SOURCE))
    // trim so a leading-separator segment (" at now") anchors at ^ correctly
    .map((s) => s.trim())
}

// Split like splitSegments, but ONLY on separators the shell would actually
// treat as separators -- never on one that sits inside a quoted string or a
// heredoc body. Returns null when the quoting cannot be resolved with
// confidence, and every caller must then fall back to the naive splitter.
//
// WHY THIS EXISTS (measured 2026-08-05, five denials in one morning -- three
// mine, two taric's): splitSegments is not quote-aware, so PROSE can manufacture
// a command position that never existed. All five denials had the same cause: a
// grep pattern quoted inside an inter-agent message,
//   Minta: stop.sh <bar> launchctl <bar> com.janna.dashboard
// The `<bar>` split it, the middle piece trimmed down to the bare word
// `launchctl`, and SCHEDULER_RX's end-of-segment branch reads a bare `launchctl`
// as a real (interactive) invocation -- correctly, for a real command line.
// Nothing was scheduled; five messages simply never went out. From outside, a
// hard-gate denial is indistinguishable from an agent that stayed silent.
//
// The route decided it: the SAME text passes as `curl -d '<json>'` (the payload
// is blanked by stripDataPayloads) and is denied when sent from a python
// heredoc, which has no -d argument to blank. Choosing how to send a message
// had quietly become a security decision. stripDataPayloads' own comment names
// this false-positive class as its target -- it is implemented for exactly one
// route, so the gap is unfinished work, not an oversight.
//
// SCOPE, and this is the part that matters: the result feeds ONLY the anchored
// scheduler check. The unanchored patterns (tmux+send-keys, nohup+claude,
// claude+/loop) keep scanning naive segments, quoted regions included, because
// they do NOT depend on a command position that prose can fake -- and because
// measurement showed the naive scan is what catches a real
// `subprocess.run(['tmux','send-keys',...])` hidden in a heredoc body. Handing
// them quote-aware segments would have removed the detection of the very
// incident vector this gate was built for, under the banner of a structural fix.
//
// FAIL-CLOSED in three places, because "could not parse" must mean "scan more",
// never "scan less":
//   - unterminated quote or heredoc -> null (caller uses the naive split)
//   - a double-quoted region containing $(...) or a backtick -> null; the shell
//     runs what is inside, so a `;` in there IS a real separator
//   - a heredoc with an UNQUOTED tag whose body contains $(...) or a backtick
//     -> null, same reason (an unquoted tag expands the body)
// NOTE ON THE SHAPE OF THIS FIX. The first attempt made the SEGMENTER
// quote-aware and left the regexes alone. It failed one corpus case:
//   echo 'grep: foo <bar> crontab <bar> bar'
// stayed denied, because SCHEDULER_RX carries its OWN boundary anchor
// (SCHED_BOUNDARY includes the bar), so it re-finds a command position INSIDE a
// segment. Keeping the quoted text in the segment at all was the mistake. The
// `launchctl` cases passed only by luck -- LAUNCHCTL_SUBCOMMAND's lookahead
// happened to reject the following bar. So the primitive is not "split more
// carefully", it is "the inert text must not be there": mask it out, then let
// the existing splitter and regexes run unchanged on what remains.
// `heredocs` (optional): when an array is passed, every heredoc the scan resolved
// is pushed onto it as { opStart, bodyStart, bodyEnd, end, quotedTag, runsBody } in the coordinates
// of the continuation-joined source (which has the same length as the returned
// mask). shellSegments uses it to hand a heredoc body back to the command that
// owns it; the scan itself is unchanged.
// Index of the `)` closing a `$(` whose body starts at `from`, or -1. Quotes
// and nested substitutions inside the body are skipped as bash reads them, so
// `"$(grep -o '"x": "[^"]*"' f)"` closes where bash closes it.
function substEnd(src, from) {
  let depth = 1
  for (let k = from; k < src.length; k++) {
    const c = src[k]
    if (c === '\\') { k++; continue }
    if (c === "'") { const e = src.indexOf("'", k + 1); if (e === -1) return -1; k = e; continue }
    if (c === '"') { const e = dquoteEnd(src, k + 1); if (e === -1) return -1; k = e; continue }
    if (c === '(') depth++
    else if (c === ')' && --depth === 0) return k
  }
  return -1
}
// Index of the `"` closing a double-quoted string whose body starts at `from`.
function dquoteEnd(src, from) {
  for (let k = from; k < src.length; k++) {
    const c = src[k]
    if (c === '\\') { k++; continue }
    if (c === '"') return k
    if (c === '$' && src[k + 1] === '(') { const e = substEnd(src, k + 2); if (e === -1) return -1; k = e; continue }
    if (c === '`') { const e = src.indexOf('`', k + 1); if (e === -1) return -1; k = e; continue }
  }
  return -1
}

// maskInertLiterals reads quotes, comments and heredocs from shellContext (shell-line-join.mjs): the ONE lexer
// model of the gates (card 0bb35172). Nothing here searches for a heredoc opener or a quote with a pattern of its
// own, so an opener inside a comment or a quote opens nothing (finding 3660cf43 B3).
//
// null stays the answer for what the scanner always gave up on: a quote or a heredoc the text never closes, a
// double quote with a substitution (strict mode), an unquoted heredoc body with one (strict mode), and `$$'`.
// Any OTHER unsure reading (`case` inside $( ), a continuation inside backticks, an unclosed backtick) still gets a
// mask, as before: the egress parser calls this on arbitrary text and reads null as "cannot parse" (fail-open for a
// command without curl/wget), so a new null here would be a new hole there.
const MASK_HARD_REASONS = new Set([
  'unterminated single quote',
  "unterminated $'...'",
  'unterminated double quote',
  'unterminated heredoc',
  'unterminated quote in a heredoc delimiter',
])

// Did the lexer leave a quote or a heredoc body open? Read off the structure, not only off `reason`: `reason` keeps
// the FIRST cause, and a soft one (a `case` in $( )) would hide a later hard one. Only called when exact is false.
function hasOpenLiteral(ctx) {
  const { text, cls, quotes, heredocs } = ctx
  const n = text.length
  for (const h of heredocs) if (h.bodyEnd === h.termEnd) return true
  // a "..." the text never closes is not in `quotes`: its characters are DQ-class outside every recorded one
  const covered = new Int32Array(n + 1)
  for (const q of quotes) {
    if (q.kind === 'sq') {
      if (q.end === n && (q.end - q.start < 2 || text[q.end - 1] !== "'")) return true
    } else if (q.kind === 'ansi') {
      if (q.end === n) {
        let k = q.start + 2
        while (k < n && text[k] !== "'") k += text[k] === '\\' ? 2 : 1
        if (k >= n) return true
      }
    } else {
      covered[q.start]++
      covered[q.end]--
    }
  }
  let depth = 0
  for (let k = 0; k < n; k++) {
    depth += covered[k]
    if (depth === 0 && cls[k] === CTX_CLASS.DQ) return true
  }
  return false
}

// true when the character at k is escaped by an odd run of backslashes before it
function escapedAt(text, k) {
  let run = 0
  while (k - run - 1 >= 0 && text[k - run - 1] === '\\') run++
  return run % 2 === 1
}

// options.keepRunBodies (default false, the egress parser relies on it and that path is unchanged): leave the body of
// a heredoc visible unless heredocBodyIsData says its owner provably takes it as data (the same inverted rule the
// heredoc stripper uses; limits: see the comment above heredocBodyIsData). runsBody is true for a visible body.
export function maskInertLiterals(command, heredocs, lenient = false, diagnostic = {}, options = {}) {
  diagnostic.reason = null
  // The shared shell join and context (odd backslash run before LF only, quote/heredoc/comment aware). It is
  // idempotent, so a caller that already joined (shellSegments, quotedWords) gets the same text back and the heredoc
  // coordinates it collects stay valid for that caller.
  const ctx = shellContext(String(command ?? ''))
  const { text, cls, quotes, exact } = ctx

  // Shell-dependent quoting cannot safely preserve literals or heredoc boundaries (a `$$'` in code position).
  for (let k = text.indexOf("$$'"); k !== -1; k = text.indexOf("$$'", k + 1)) {
    if ((cls[k] === CTX_CLASS.CODE || cls[k] === CTX_CLASS.BQ) && !escapedAt(text, k)) {
      diagnostic.reason = 'ambiguous-dollar-quote'
      return null
    }
  }
  if (!exact && (MASK_HARD_REASONS.has(ctx.reason) || hasOpenLiteral(ctx))) return null

  const keepRunBodies = options?.keepRunBodies === true
  const chars = text.split('')
  const blank = (from, to) => {
    for (let k = from; k < to; k++) chars[k] = ' '
  }
  // Inert regions collapse to spaces: the text is gone, and with it every separator inside it -- which is
  // precisely what prose was faking.
  for (const q of quotes) {
    if (q.kind === 'dq' && q.subst && !lenient) return null // may run a command -> not inert
    blank(q.start, q.end)
  }
  for (const h of ctx.heredocs) {
    if (!h.quoted && h.subst && !lenient) return null // unquoted tag expands the body
    const runsBody = keepRunBodies && !heredocBodyIsData(ctx, h)
    if (!runsBody) blank(h.bodyStart, h.bodyEnd)
    if (Array.isArray(heredocs)) {
      heredocs.push({
        opStart: h.opStart,
        bodyStart: h.bodyStart,
        bodyEnd: h.bodyEnd,
        end: text[h.termEnd - 1] === '\n' ? h.termEnd - 1 : h.termEnd, // the terminator line without its LF
        quotedTag: h.quoted,
        runsBody, // true: kept visible (keepRunBodies and the body is not provably data)
      })
    }
  }
  return chars.join('')
}

// The segments the anchored scheduler check scans, on a mask made with keepRunBodies (the `heredocs` array it filled
// says which bodies it left visible). A body that an interpreter executes is code, so every line of it is checked --
// but it is code of ANY language: in python or node `;` `|` `&` are not shell separators (`t = "a | launchctl | b"` is
// a string, and the python heredoc that carries a message must keep passing), so inside such a body ONLY a newline
// cuts. The anchored pattern has its own boundary for a real `echo job | crontab -` on one line.
function anchoredSegments(masked, heredocs) {
  const visible = heredocs.filter((h) => h.runsBody)
  if (!visible.length) return splitSegments(masked)
  const segs = []
  let start = 0
  for (const m of masked.matchAll(new RegExp(SEGMENT_SEPARATOR_SOURCE, 'g'))) {
    const newline = m[0].includes('\n')
    if (!newline && visible.some((h) => m.index >= h.bodyStart && m.index < h.bodyEnd)) continue
    segs.push(masked.slice(start, m.index).trim())
    start = m.index + m[0].length
  }
  segs.push(masked.slice(start).trim())
  return segs
}

// The segments of the text the way the SHELL cuts it, from the same context map: every character of a literal
// (single quote, $'...', double quote, heredoc body) becomes a space -- a quoted newline too -- and a separator
// (; & | or a newline, && and || as one) cuts only where it is CODE, a backtick run or a heredoc line. So a
// separator inside quotes does not split the dangerous pair in two (finding 3660cf43 B4), and the literal text
// is simply not in any segment (a trigger word that only sits in a message does not count).
//
// This pass only ADDS to splitSegments: the gate runs its checks on both lists. The naive list stays because it
// is the one that sees INSIDE a literal (a `subprocess.run(['tmux','send-keys',..])` in a heredoc body, a kanban
// SQL in a heredoc) -- and because it also cuts a quoted newline, which only ever errs towards denying.
export function maskedSegments(command) {
  const { text, cls } = shellContext(String(command ?? ''))
  const { SQ, ANSI, DQ, HEREDOC_Q, HEREDOC_U, CODE, BQ } = CTX_CLASS
  const segs = []
  let cur = ''
  for (let k = 0; k < text.length; k++) {
    const c = text[k]
    const kind = cls[k]
    const cuts = kind === CODE || kind === BQ || kind === HEREDOC_Q || kind === HEREDOC_U
    if (cuts && (c === ';' || c === '&' || c === '|' || c === '\n')) {
      segs.push(cur.trim())
      cur = ''
      if ((c === '&' || c === '|') && text[k + 1] === c && cls[k + 1] === kind) k++
      continue
    }
    if (cuts && c === '\r' && text[k + 1] === '\n') continue
    const literal = kind === SQ || kind === ANSI || kind === DQ || kind === HEREDOC_Q || kind === HEREDOC_U
    cur += literal ? ' ' : c
  }
  segs.push(cur.trim())
  return segs
}

// Blank out curl/HTTP DATA-PAYLOAD arguments before self-pace matching. A -d /
// --data body is data sent over the wire, NEVER a shell invocation, so a trigger
// token that only appears INSIDE the payload must not false-deny. The classic
// false-positive: an /api/messages inter-agent dispatch (a legit peer message in
// a green, operator-authorised review-loop) whose JSON body happens to mention
// "/api/schedules", "tmux send-keys", "scheduled_tasks.json" or "/loop" -- pure
// text, not an invocation. Only PROVABLY-LITERAL payloads are stripped:
// single-quoted '...', ANSI-C $'...', and double-quoted "..." WITHOUT
// $(...)/backtick. A payload that can run a command substitution (double-quoted
// with $(...) / backticks) is left intact so a real command-substitution payload
// is not blanked. Such a payload is then still denied by SCHEDULER_RX, whose
// boundary anchor recognises both `$(` and the backtick as a command boundary,
// so a scheduler binary inside either substitution form is caught. The data FLAG
// itself is kept, so HTTP-write detection (-d /
// --data) is unchanged; the URL and method args live OUTSIDE the payload, so a
// real WRITE to /api/schedules is still denied.
//
// Quote classes match BASH parsing, not C. Inside a plain '...' a backslash is
// LITERAL and the FIRST following ' always closes the string, so the class is
// '[^']*'. A C-style '(?:[^'\\]|\\.)*' would treat \' as an escaped quote and
// scan PAST bash's real closing quote -- e.g. `curl -d 'x\' ; crontab -r` would
// blank the out-of-band `; crontab -r` and let a real self-pace command slip.
// ANSI-C $'...' DOES process \', so that branch keeps the \\. escape form; "..."
// keeps it too (backslash is special inside bash double quotes).
// Human prose in a command-argument position is DATA, not commands. The heredoc
// fix closed one wrapper; this closes the rest of the family: a PR body, a PR
// comment, a release note. The failure mode is identical -- a sentence like
// "runs at the same time" reads as the `at` scheduler at a segment start, and
// the better the prose, the likelier it contains words like at / cron /
// schedule. Same literal-only rule as the other strippers: a double-quoted
// value with $( or ` may substitute, so it is left alone.
const PROSE_FLAGS = String.raw`--body|--message|--notes|--title|--subject|-b|-m|-t`

// The flag-and-quoted-argument strippers below (data payload, commit message, prose) all work on the lexer's
// context map, never on the raw text (card 0bb35172, finding 3660cf43 B3): the flag must sit in CODE position
// (a `-d` / `-m` in a comment, a quote or a heredoc body is not a flag), and the argument must be exactly ONE quote
// token the lexer closed -- so a look-alike `-d '` in a comment can no longer pair with a later real `'` and
// swallow the command lines between them. The flag and the blank after it must be on the same line (a quote that
// starts the NEXT line is a new command word, not this flag's argument). A reading the lexer is not sure of
// (exact=false) strips NOTHING: stripping removes text from the checks, so doubt must leave the text visible.
// Output is the continuation-joined text, which is what the gate hands in anyway.
const flagArgumentRx = (flags) => String.raw`(^|\s)(${flags})([ \t]+|=)`

function stripFlagArguments(ctx, flagSource) {
  const { text, cls, quotes, exact } = ctx
  if (!exact) return text
  const quoteAt = new Map()
  for (const q of quotes) quoteAt.set(q.start, q)
  const rx = new RegExp(flagSource, 'gi')
  let out = ''
  let last = 0
  let m
  while ((m = rx.exec(text))) {
    const flagStart = m.index + m[1].length
    const argStart = m.index + m[0].length
    // Only a CODE-class flag strips. KNOWN LIMIT (0bb35172 ellenor E1, accepted fail-closed): the lexer
    // keeps a backtick run as one BQ span without quote tokens, so a payload flag inside backticks
    // (r=`curl -d '...'`) is not stripped and its payload stays visible (it may over-deny, never under).
    const q = cls[flagStart] === CTX_CLASS.CODE ? quoteAt.get(argStart) : undefined
    // a double-quoted value that substitutes may run a command -> keep it visible
    if (!q || (q.kind === 'dq' && q.subst)) {
      rx.lastIndex = flagStart + 1
      continue
    }
    out += text.slice(last, argStart) + (q.kind === 'dq' ? '""' : "''") // literal payload -> blank the content
    last = q.end
    rx.lastIndex = q.end
  }
  return out + text.slice(last)
}

const PROSE_FLAG_RX = flagArgumentRx(PROSE_FLAGS)
const PROSE_GUARD_RX = /\b(?:gh|git|glab)\b/i

export function stripProseArguments(seg) {
  const src = joinShellLines(String(seg ?? ''))
  // Scoped to the tools these prose flags were written for: gh, git, glab (a PR
  // body, a PR comment, a release note). A short flag means different things to
  // different binaries (`tar -t`, `cut -b`, `sort -t`), so blanking it on an
  // unrelated tool would hide real data from the gate (PR #770 review, Szotasz).
  // Same coarse command-word guard as stripGitCommitMessages just below.
  if (!new RegExp(PROSE_FLAG_RX, 'i').test(src) || !PROSE_GUARD_RX.test(src)) return src
  return stripFlagArguments(shellContext(src), PROSE_FLAG_RX)
}

const DATA_FLAG_RX = flagArgumentRx(String.raw`-d|--data(?:-(?:raw|binary|ascii|urlencode))?`)

export function stripDataPayloads(seg) {
  const src = joinShellLines(String(seg ?? ''))
  if (!new RegExp(DATA_FLAG_RX, 'i').test(src)) return src
  return stripFlagArguments(shellContext(src), DATA_FLAG_RX)
}

// Blank out git commit/tag/stash -m/--message LITERAL text before self-pace
// matching. A commit message is prose, NEVER a shell invocation, so a trigger
// token that only appears INSIDE the message must not false-deny (2026-07-13,
// DrCode: a long `git commit -m "...batch...; at..."` blocked twice, the short
// one passed -- the message text was split as shell segments). Same principle
// and same literal-only quote handling as stripDataPayloads: single-quoted,
// ANSI-C $'...', and double-quoted WITHOUT $(...)/backtick are blanked; a
// double-quoted message that CAN command-substitute (`git commit -m "$(crontab
// -r)"`) is left intact so SCHEDULER_RX still catches the real substitution.
// Scoped to git commit/tag/stash so a `-m` on an unrelated binary is untouched.
// Heredoc bodies are DATA, not commands. A worker writing a real commit message
// through `git commit -F - <<EOF … EOF` had the turn denied because one prose
// line happened to start with "at " -- which SCHEDULER_RX reads as the `at`
// scheduler at a segment start. A heredoc body is data, so blank it before any
// pattern runs. Handles <<- for tab-indented bodies.
//
// EXCEPT when the body can still run something. A QUOTED marker (<<'EOF' or
// <<"EOF") is literal: the shell performs no expansion inside it, so blanking is
// safe. An UNQUOTED marker (<<EOF) is not -- the shell expands $(...) and
// backticks in that body at exec time, so blanking one would hide a live
// command substitution from SCHEDULER_RX and the gate would stop seeing
// something that really runs:
//
//     git commit -m "$(cat <<EOF
//     fix
//     $(at now)
//     EOF
//     )"
//
// This is the same rule the other strippers already apply: stripDataPayloads,
// stripGitCommitMessages and stripProseArguments all leave a double-quoted
// value alone when it contains `$(` or a backtick. An unquoted heredoc is the
// same category; it was simply missing the guard. Reported on PR #770.
// WHEN IS A HEREDOC BODY DATA (card 6f27c86a, the rule is INVERTED). Blanking a body hides it from every check,
// so it is allowed only when the body provably reaches a command that does not run it. The old rule listed the
// interpreters that DO run a body (bash, sh, python, ssh ...) and read only the first word of the segment before the
// `<<`; everything it did not know was "data". That missed `cat <<'EOF' | bash`, `env -i bash <<'EOF'`,
// `bash -c "$(cat <<'EOF' ...)"`, `bash <(cat <<'EOF' ...)` and `for ..; do env -i bash <<'EOF'`. Now the default is
// "visible", and a body is data only when ALL of these hold (heredocBodyIsData, the one place that decides):
//   0. the command defines no function and no alias, and has no `<(`, `>(` or exec redirection at code level
//      anywhere (a redefined `cat`, an output sent to a process or to the shell's own descriptors: nothing about
//      where the text goes can be proved); and the meaning of every command word is FIXED BY THE TEXT (card
//      a6422462, B6; bindsNames). Read on the code-level text of the whole command (codeLevelText: heredoc bodies
//      and comments out, quote characters and backslashes gone, so `e'v'al` is eval), the command has none of:
//      a. a command word that is not literal: one with `$` (a variable, a `$( )`, an ANSI-C `$'..'`), a backtick
//         run or a brace expansion in it, past assignments, keywords, redirections and the precommand words with
//         their options (a `${..}` argument is one argument word; `[` and `[[` are tests);
//      b. a builtin that binds a name, runs a string as code or loads code (NAME_BINDING_WORDS: eval, source, `.`,
//         hash, typeset, read ..., bash 5 and zsh 5), `printf -v` / `print -v`, `set` with a/A/k or allexport
//         (`setopt allexport` too);
//      c. a name the command lookup or the shell's code hooks read (LOOKUP_NAMES): the upper-case PATH, FPATH,
//         BASH_CMDS ... as a whole identifier anywhere, the zsh tables (path, commands, functions, aliases ...) as a
//         bare word or followed by `[`, `=`, `+=` or `:`, and any `${..}` expansion of one of them, quoted or not;
//      d. an assignment to a computed name: an indirect expansion that assigns (bash `${!x:=..}`, zsh `${(P)x::=..}`)
//         or an arithmetic assignment with a `$` in it.
//      Whether a builtin binds a name is a property of bash and zsh, not of the text, so the two lists are closed
//      and pinned by a test: a new member is a decision, and a longer list only blocks more. KNOWN LIMITS (Q4, not
//      in the text): the state before the command (aliases and functions of the shell snapshot, variables an
//      earlier command exported: a plain `X=..` then rewrites the environment), a file that runs later (O14), and
//      a glob in a command word (it reads the file system, the same O14 class);
//   1. the command word that owns the redirect is in the closed DATA_OWNERS list (cat, tee, grep, jq ...; gh and
//      glab only for the API subcommands; curl; no option that names a program or a config file: curl -K/--config,
//      sort --compress-program; option tokens are compared after their quotes and backslashes are removed), after
//      skipping shell keywords (do, then ...) and the pass-through prefixes (sudo, env ...) -- a prefix WITH an
//      option (`env -i`, `sudo -u x`, `nice -n 5`, `timeout 5`, `command -p`) is an unknown owner, and so is a
//      path-qualified word outside the system bin directories. An ASSIGNMENT in front of the command word (`X=1 cat`,
//      `env X=1 cat`, `GIT_EDITOR=x git ..`) makes it an unknown consumer in every role (owner, pipe stage, the
//      command around a `$( )`): the program reads its environment, and what a variable configures is not known
//      here (card a6422462, B6/B7). A pure assignment (`x=$(cat <<'EOF' ..)`) stays data. git is NO data owner
//      (card a6422462, B7): a commit, a tag, a note, a stash, an am or an apply updates a ref or the index, so the
//      repository's hooks (reference-transaction, prepare-commit-msg, post-commit, post-index-change), its filters
//      and its signer run, and no subcommand option turns them off (`--no-verify` skips only pre-commit and
//      commit-msg); only `-c core.hooksPath=..` or a `GIT_CONFIG_*` variable would, and those are a global option
//      and an assignment prefix, which make the owner unknown anyway;
//   2. every code-level `|` stage on the operator line (`cat <<'EOF' | stage`) is a data command too, and so is every
//      `|` stage that follows a closer after the terminator (`{ cat <<'EOF' .. EOF }`, `( .. )`, `done`, `fi`,
//      `esac`, the `)` of a `$( )`): the output of the whole compound goes on to that stage;
//   3. every substitution frame around the heredoc, innermost out, is a `$( )` (ctx.substs, the lexer's own frames:
//      no bracket is counted here) that is either a pure assignment (`x=$(cat <<'EOF' ..)`) or the argument of a
//      data command; a `<( )`, `>( )`, a backtick run or a frame the lexer could not close is never data.
// A script-running interpreter (bash x.sh, python3 x.py, node x.js ...) counts as a data CONSUMER in 2. and 3. only
// (`cat <<'EOF' | bash /abs/agent-msg.sh .. -`, `bash /abs/agent-msg.sh .. "$(cat <<'EOF' ..)"`, the fleet's own
// message idiom), and only with NO assignment prefix (`BASH_ENV=x bash ..`, see 1.) and when its first argument is an
// ABSOLUTE plain path that is not the stdin of the shell itself (/dev/stdin, /dev/fd/N, /proc/*/fd/N, anything
// under /dev or /proc, `..` segments, quotes, `$`): `bash /dev/stdin`, `bash -s`, `bash -c`, `python3 -` run the
// body. As the direct owner (`bash /abs/agent-msg.sh .. - <<'EOF'`) it stays visible.
//
// Still accepted (measured, card 6f27c86a): a body written to a file and run later (`cat <<'EOF' > s.sh && bash
// s.sh`, O14) is not followed -- the file is what runs, and the scheduler surface check still catches the
// /api/schedules form; text that flows through a variable (`x=$(cat <<'EOF' ..)` then `bash -c "$x"`) is data at
// the assignment and is not followed; a script file that itself runs its stdin is trusted (it could be run as
// well from a file Write put there, so the absolute path is no new door); an option spelled through a variable
// (`$K`) is not resolved, a data owner whose first argument starts with `$` is unknown instead. The rule only ever
// ADDS visible text, so it can over-block (a body that mentions a trigger word inside `echo "$(cat <<'EOF' ..)"`,
// F11; any `)`, `}`, `done`, `fi` or `esac` after the terminator that is piped on to a non-data stage, even one
// that closes an unrelated compound; any function, alias, name binding, `<(` or exec redirection in the same
// command; the bare word `path` anywhere at code level) but
// never newly allow. A backtick run keeps its own limit: a heredoc or a quoted payload inside backticks is always
// visible, and the lexer does not tokenise quotes inside a backtick run (0bb35172 E1: `r=`curl -d '..' ..``
// denies where the `$( )` form allows).
const DATA_OWNERS = new Set(['cat', 'tee', 'wc', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'sort', 'uniq', 'tr', 'base64', 'diff', 'cmp', 'shasum', 'sha256sum', 'md5', 'jq', 'gh', 'glab', 'curl'])
// gh / glab talk to the hosting API with these; an alias, an extension or an unknown word runs a program
const FORGE_DATA_SUBCOMMANDS = new Set(['api', 'pr', 'mr', 'issue', 'release', 'repo', 'run', 'workflow', 'gist', 'label', 'search', 'status', 'secret', 'variable', 'ci', 'snippet'])
// long options that name a program to run, per data owner (GNU getopt takes any unique prefix of them)
const PROGRAM_OPTIONS = { sort: ['compress-program'], curl: ['config'] }
const OPTION_SENSITIVE_OWNERS = new Set(['curl', 'sort', 'gh', 'glab'])
// a path-qualified command word is only the data command if it lives in a system bin directory
const DATA_COMMAND_BIN_DIRS = new Set(['/bin', '/usr/bin', '/usr/local/bin', '/opt/homebrew/bin'])
const PASS_THROUGH_PREFIXES = new Set(['sudo', 'env', 'nice', 'time', 'exec', 'command', 'nohup', 'stdbuf'])
const SHELL_KEYWORDS = new Set(['do', 'then', 'else', 'elif', 'if', 'while', 'until', '!', '{', 'time'])
// the interpreters that run a script FILE given as the first argument (ssh is not one of them: `| ssh box` runs stdin)
const SCRIPT_INTERPRETER_RX = /^(?:bash|sh|zsh|dash|ksh|ash|python[0-9.]*|node|nodejs|ruby|perl|php)$/
const SEGMENT_SEPARATOR_RX = /[\n;|&({]/
const NOT_CODE_BLANK_RX = /[\s;|&(){}]/

// The text of [from, to) with the white space and separators of every non-code character (quote, comment, heredoc
// body) turned into `_`, so a quoted `; cat ` or `x cat` cannot pass for a command word.
function codeOnlyText(ctx, from, to) {
  const { text, cls } = ctx
  let out = ''
  for (let k = from; k < to; k++) {
    const code = cls[k] === CTX_CLASS.CODE || cls[k] === CTX_CLASS.BQ
    out += code || !NOT_CODE_BLANK_RX.test(text[k]) ? text[k] : '_'
  }
  return out
}

// Rule 0, fixed name resolution (card a6422462, B6): the two closed lists. A member is a property of bash 5 or zsh 5
// that the text cannot show; a new member is a decision, and the structural test pins the exact membership.
// Frozen arrays (an exported Set stays writable through add even when frozen); the checks use the Sets below.
export const NAME_BINDING_WORDS = Object.freeze([
  'eval', // bash, zsh: runs a string as code (and so any definition in it)
  'source', // bash, zsh: runs a file in this shell (its definitions stay)
  '.', // bash, zsh: the same as source
  'hash', // bash: `hash -p /x cat` binds cat to a path; zsh: writes the commands table
  'enable', // bash: `enable -f lib.so cat` loads a builtin, `-n` turns one off; zsh: turns builtins on
  'builtin', // bash, zsh: reaches a builtin past a function (`builtin eval ..`)
  'zmodload', // zsh: loads a module and its builtins
  'autoload', // zsh, bash 5 loadables: makes a name a function loaded from fpath
  'functions', // zsh: defines and copies functions (`functions -c`), the builtin as well as the table
  'fc', // bash, zsh: runs edited history lines as code
  'trap', // bash, zsh: a string that runs on a signal, on DEBUG, ERR or EXIT
  'disable', // zsh: turns off a builtin, an alias or a function, so the name resolves elsewhere
  'emulate', // zsh: switches the option set (alias and function behaviour), `-c` runs a string
  'read', // bash, zsh: assigns a named variable (`read -A path`, a name from input)
  'mapfile', // bash: assigns a named array, `-C` runs a callback
  'readarray', // bash: the same as mapfile
  'getopts', // bash, zsh: assigns a named variable
  'vared', // zsh: assigns a named variable
  'zparseopts', // zsh: assigns named arrays
  'let', // bash, zsh: arithmetic assignment, the target may be computed
  'declare', // bash: assigns, exports, and binds a nameref (`-n`)
  'typeset', // bash, zsh: the same as declare (zsh `-T` ties a scalar to an array)
  'local', // bash, zsh: the declare family inside a function
  'export', // bash, zsh: assigns and puts the name into the environment of every later command
  'readonly', // bash, zsh: the declare family
])
export const LOOKUP_NAMES = Object.freeze([
  'PATH', // bash, zsh: the command search path
  'FPATH', // zsh, bash 5 loadables: the function search path for autoload
  'BASH_CMDS', // bash: the hash table of the command lookup, writable
  'BASH_ALIASES', // bash: the alias table, writable
  'BASH_ENV', // bash: a file every non-interactive bash child runs first
  'ENV', // sh, bash --posix, zsh in sh emulation: the same for an interactive shell
  'PS4', // bash, zsh: expanded (and its $( ) run) before every traced command
  'PROMPT_COMMAND', // bash: code that runs before a prompt
  'path', // zsh: the array tied to PATH
  'fpath', // zsh: the array tied to FPATH
  'commands', // zsh: the command hash table, writable
  'functions', // zsh: the function table, writable
  'aliases', // zsh: the alias table, writable
  'galiases', // zsh: the global alias table
  'saliases', // zsh: the suffix alias table
  'builtins', // zsh: the builtin table (read only, but listed with the others)
  'reswords', // zsh: the reserved word table
  'dis_aliases', // zsh: the disabled-entry twins of the tables above
  'dis_galiases',
  'dis_saliases',
  'dis_functions',
  'dis_builtins',
  'dis_reswords',
])
const BINDING_WORD_SET = new Set(NAME_BINDING_WORDS)
const LOOKUP_LOWER_SET = new Set(LOOKUP_NAMES.filter((n) => /^[a-z]/.test(n)))
// an upper-case lookup name as a whole identifier, anywhere (`PATH=..`, `$PATH`, `BASH_CMDS[cat]=..`)
const LOOKUP_UPPER_RX = new RegExp(String.raw`(?<![A-Za-z0-9_])(?:${LOOKUP_NAMES.filter((n) => /^[A-Z]/.test(n)).join('|')})(?![A-Za-z0-9_])`)
// a `${..}` expansion of any lookup name, with zsh flags or modifiers in front (`${commands[cat]::=x}`, `${=path}`)
const LOOKUP_EXPANSION_RX = new RegExp(String.raw`\$\{(?:\([^)]*\))?[#=~^+!]*(?:${LOOKUP_NAMES.join('|')})(?![A-Za-z0-9_])`)
// the precommand words that are skipped on the way to the command word, with their own `-` options
const NAME_SCAN_PREFIXES = new Set([...PASS_THROUGH_PREFIXES, 'noglob', 'nocorrect', '-', 'coproc'])

// The code-level text of the whole command (card a6422462), read once per reading: the heredoc bodies with their
// terminator lines and the comments are blanked (a newline stays a newline), the quote characters and backslashes
// are gone (a code-level backslash-newline joins, an escaped character is a letter), so a quoted or escaped word
// reads as the word the shell hands over (`al'i'as` is alias, `e\val` is eval, `$'\x65'` is `$x65`, still a `$`
// word). Two spellings: words, where a blank or a separator inside a quote (or escaped) is `_`, so a quoted
// `; eval` is no command position; literal, where they stay, so a quoted `"${commands[cat]::=x}"` keeps its braces.
const CODE_LEVEL_TEXT = new WeakMap()
function codeLevelText(ctx) {
  let read = CODE_LEVEL_TEXT.get(ctx)
  if (read !== undefined) return read
  const { text, cls, heredocs } = ctx
  const out = new Uint8Array(text.length)
  for (const h of heredocs) out.fill(1, h.bodyStart, Math.max(h.bodyStart, h.termEnd))
  let words = ''
  let literal = ''
  for (let k = 0; k < text.length; k++) {
    const c = text[k]
    const kind = cls[k]
    if (out[k] || kind === CTX_CLASS.COMMENT || kind === CTX_CLASS.HEREDOC_Q || kind === CTX_CLASS.HEREDOC_U) {
      words += c === '\n' ? '\n' : ' '
      literal += c === '\n' ? '\n' : ' '
      continue
    }
    const code = kind === CTX_CLASS.CODE || kind === CTX_CLASS.BQ
    if (c === '\\' && code && k + 1 < text.length) {
      const next = text[++k]
      if (next === '\n' || next === '\\' || next === "'" || next === '"') continue
      words += NOT_CODE_BLANK_RX.test(next) ? '_' : next
      literal += next
      continue
    }
    if (c === '\\' || c === "'" || c === '"') continue
    words += code || !NOT_CODE_BLANK_RX.test(c) ? c : '_'
    literal += c
  }
  read = { words, literal }
  CODE_LEVEL_TEXT.set(ctx, read)
  return read
}

// The command segment that ends at `pos`: back to the last code-level separator, but never into an earlier heredoc
// (its body and terminator are not command text).
function segmentBefore(ctx, pos) {
  const { text, cls, heredocs } = ctx
  let floor = 0
  for (const h of heredocs) if (h.termEnd <= pos && h.termEnd > floor) floor = h.termEnd
  let k = pos
  while (k > floor) {
    const code = cls[k - 1] === CTX_CLASS.CODE || cls[k - 1] === CTX_CLASS.BQ
    if (code && SEGMENT_SEPARATOR_RX.test(text[k - 1])) break
    k--
  }
  return codeOnlyText(ctx, k, pos)
}

// The command of a segment: { word, rest, assigned } past assignments, shell keywords and option-free pass-through
// prefixes, or null when a pass-through prefix carries an option (the owner is then unknown). An empty word with
// assigned > 0 is a pure assignment.
function commandOfSegment(segment) {
  const tokens = segment.trim().split(/\s+/).filter(Boolean)
  let i = 0
  let assigned = 0
  while (i < tokens.length) {
    const t = tokens[i]
    if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) { i++; assigned++; continue }
    if (SHELL_KEYWORDS.has(t)) { i++; continue } // `do cat <<EOF`
    if (PASS_THROUGH_PREFIXES.has(t)) {
      if ((tokens[i + 1] ?? '').startsWith('-')) return null
      i++
      continue
    }
    break
  }
  if (i >= tokens.length) return { word: '', rest: [], assigned }
  return { word: wordCommandName(tokens[i]), rest: tokens.slice(i + 1), assigned }
}

// `/usr/bin/cat` is cat; `./cat` or `/tmp/x/cat` is some program that merely carries the name (a name no list has).
function wordCommandName(token) {
  const at = token.lastIndexOf('/')
  if (at === -1) return token
  return DATA_COMMAND_BIN_DIRS.has(token.slice(0, at)) ? token.slice(at + 1) : `?${token}`
}

// A script path that is plainly a file: absolute, not an option, no quote or expansion, no `..`, and not stdin in
// any spelling.
function isPlainScriptFile(path) {
  if (path === undefined || !path.startsWith('/') || !/^[\w.\/+@%-]+$/.test(path)) return false
  const parts = path.split('/').filter(Boolean)
  if (parts.some((p) => p === '.' || p === '..')) return false
  return !(path.startsWith('/') && (parts[0] === 'dev' || parts[0] === 'proc'))
}

// Does this command take the heredoc text as DATA? role: 'owner' (the command the redirect belongs to), 'pipe' (a
// stage after a `|` on the operator line) or 'subst' (the command around a `$( )`).
function consumesAsData(command, role) {
  if (!command) return false
  const { word, rest, assigned } = command
  if (word === '') return role === 'subst' && assigned > 0 // x=$(cat <<EOF ..) stores the text; a bare $(..) runs it
  // an assignment prefix configures the program (BASH_ENV=.., GIT_EDITOR=.., LESSOPEN=..): unknown, in every role
  if (assigned > 0) return false
  // an interpreter consumes a body as data only as `bash /abs/script ..`
  if (role !== 'owner' && SCRIPT_INTERPRETER_RX.test(word)) return isPlainScriptFile(rest[0])
  if (!DATA_OWNERS.has(word)) return false
  if (rest.some((t) => /[<>]\(/.test(t))) return false // a process substitution can hand the text to a command
  const opts = optionWords(rest)
  if (opts === null) return false
  // an option spelled through a variable (`$K`) or a first argument that is one cannot be read: unknown
  if (OPTION_SENSITIVE_OWNERS.has(word) && rest.some((t) => t.startsWith('$'))) return false
  if (opts.some((t) => namesProgramOption(word, t))) return false
  if (word === 'gh' || word === 'glab') return FORGE_DATA_SUBCOMMANDS.has(opts.find((t) => !t.startsWith('-')))
  if (word === 'curl') return !opts.some((t) => /^-[A-Za-z]*K/.test(t))
  return true
}

// The tokens of a command as the shell hands them over: quotes and backslashes are gone (`'-K'`, `"--config"`,
// `-"K"` and `--conf\ig` are the options they spell). null for ANSI-C quoting with an escape (`$'\x2dK'`), which
// can spell any option.
function optionWords(tokens) {
  const out = []
  for (const t of tokens) {
    if (/\$['"]/.test(t) && t.includes('\\')) return null
    out.push(t.replace(/\$(?=['"])/g, '').replace(/[\\'"]/g, ''))
  }
  return out
}

// Does this (unquoted) token spell a long option of PROGRAM_OPTIONS for the owner, as the full name or any prefix
// of it that getopt would still take?
function namesProgramOption(owner, token) {
  if (!token.startsWith('--')) return false
  const name = token.slice(2).split('=')[0]
  return name.length >= 2 && (PROGRAM_OPTIONS[owner] ?? []).some((long) => long.startsWith(name))
}

const isCodeAt = (cls, k) => cls[k] === CTX_CLASS.CODE || cls[k] === CTX_CLASS.BQ

// Facts about the whole command that make every heredoc body unprovable, computed once per reading: an output that
// is sent to a process (`<(`, `>(`) or to the shell's own descriptors (`exec >f`, `exec 3>&1`), and a function or
// an alias definition (a redefined `cat` is any command; a function body is not followed to its callers).
const WHOLE_COMMAND_BLOCKS = new WeakMap()
function wholeCommandBlocksData(ctx) {
  let blocked = WHOLE_COMMAND_BLOCKS.get(ctx)
  if (blocked === undefined) {
    blocked = redirectsOutputElsewhere(ctx) || definesFunctionOrAlias(ctx) || bindsNames(ctx)
    WHOLE_COMMAND_BLOCKS.set(ctx, blocked)
  }
  return blocked
}

function redirectsOutputElsewhere(ctx) {
  const { text, cls, substs } = ctx
  if (substs.some((s) => s.kind === 'proc-in' || s.kind === 'proc-out')) return true
  for (const m of text.matchAll(/[<>]\(|(?<![\w$-])exec\s*(?:\d+|\{[A-Za-z_]\w*\})?[<>&]/g)) if (isCodeAt(cls, m.index)) return true
  return false
}

function definesFunctionOrAlias(ctx) {
  const { text, cls } = ctx
  for (const m of text.matchAll(/(?<![$<>])\(\s*\)|(?<![\w$.-])function\s/g)) if (isCodeAt(cls, m.index)) return true
  // alias is a builtin and stays the alias command through quotes (`al'i'as cat=bash`): read the code-level text
  // (no quote and backslash characters, no heredoc bodies, no comments), the same text bindsNames reads
  return /(?<![\w$.-])alias\s[^;&|\n]*?[\w.+-]+=/.test(codeLevelText(ctx).words)
}

// Rule 0 a-d (card a6422462, B6): true when the meaning of some command word is not fixed by the text, so no body
// of the command can be proved to be data. Only ever blocks: a false here changes nothing.
function bindsNames(ctx) {
  const { words, literal } = codeLevelText(ctx)
  // c. the lookup names: upper case anywhere, the zsh tables as a bare word or before `[`, `=`, `+=`, `:`, and any
  //    `${..}` of one of them, also inside double quotes (the literal spelling keeps the braces there)
  if (LOOKUP_UPPER_RX.test(words) || LOOKUP_EXPANSION_RX.test(literal)) return true
  for (const token of words.split(/[\s;|&(){}`]/)) {
    const m = /^([a-z_]+)(?:$|\[|\+?=|:)/.exec(token)
    if (m && LOOKUP_LOWER_SET.has(m[1])) return true
  }
  // d. an assignment to a computed name: an indirect expansion that assigns, an arithmetic assignment through `$`
  if (/\$\{(?:!|\([^)]*P)[^}]*=/.test(literal)) return true
  if (/\(\([^)]*\$[^)]*=|\$\[[^\]]*\$[^\]]*=/.test(literal)) return true
  // a. and b. at every command position. A `${..}` is one argument word (collapsed innermost first, a bounded number
  // of rounds: what is left only splits into more positions, which blocks more); a `{` that opens no group is a
  // brace expansion and makes its word non-literal; a backtick run marks the word in front of it as `$`; every
  // redirection operator is one `>` token that takes its target with it.
  let scan = words
  for (let round = 0; round < 8 && scan.includes('${'); round++) scan = scan.replace(/\$\{[^{}]*\}/g, '$V')
  scan = scan
    .replace(/(?<!\$)\{(?![\s}])/g, '$')
    .replace(/`/g, () => '$`') // a function: in a replacement string `$` + backtick means "the text before"
    .replace(/>\|/g, '>')
    .replace(/(?<=[<>])&|&(?=>)/g, '')
    .replace(/[<>]+-?/g, ' > ')
  for (const segment of scan.split(/[\n;|&(){}`]/)) {
    const tokens = segment.split(/\s+/).filter(Boolean)
    let i = 0
    while (i < tokens.length) {
      const t = tokens[i]
      // the precommand words first: `time` is a keyword too, and `time -p eval ..` must skip its option
      if (NAME_SCAN_PREFIXES.has(t)) {
        i++
        while (i < tokens.length && tokens[i].startsWith('-') && tokens[i] !== '-') i++
        continue
      }
      if (/^[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=/.test(t) || SHELL_KEYWORDS.has(t)) { i++; continue }
      if (t === '>') { i += 2; continue } // a redirection and its target
      if (/^\d+$/.test(t) && tokens[i + 1] === '>') { i++; continue } // the descriptor of `2>f`
      if (t === 'repeat') { i += 2; continue } // zsh: repeat N command
      if (t === '[' || t === '[[') { // a test; in zsh a command may follow its closer (`if [[ .. ]] cmd`)
        const close = tokens.indexOf(t === '[' ? ']' : ']]', i + 1)
        i = close === -1 ? tokens.length : close + 1
        continue
      }
      break
    }
    if (i >= tokens.length) continue
    const word = tokens[i]
    const args = tokens.slice(i + 1)
    if (/[$`]/.test(word)) return true // a. not literal
    if (BINDING_WORD_SET.has(word)) return true // b.
    if ((word === 'printf' || word === 'print') && args.some((x) => /^-[A-Za-z]*v/.test(x))) return true
    if ((word === 'set' || word === 'setopt' || word === 'unsetopt') && args.some((x) => (word === 'set' && /^[-+][A-Za-z]*[aAk]/.test(x)) || /allexport|keyword/i.test(x.replace(/_/g, '')))) return true
  }
  return false
}

const PIPE_SCAN_LIMIT = 1500

// The stages that follow `from` on its logical line: a code-level `|` opens one (behind a trailing `|` it may open on
// the next line), and `;`, `&&`, `||`, a background `&`, the end of the line or an outer closer end the scan. True
// when every stage is a data consumer.
function pipeStagesAreData(ctx, from) {
  const { text, cls } = ctx
  let k = from
  while (k < text.length) {
    if (k - from > PIPE_SCAN_LIMIT) return false // a line this long behind a closer is not read: unknown
    const c = text[k]
    if (!isCodeAt(cls, k) || c === ' ' || c === '\t') { k++; continue }
    if (c === '\n' || c === ';' || c === ')' || c === '}') return true
    if (c === '&') {
      if (text[k + 1] !== '&' && (text[k - 1] === '>' || text[k - 1] === '<' || text[k + 1] === '>')) { k++; continue } // 2>&1, &>
      return true
    }
    if (c !== '|') { k++; continue }
    if (text[k + 1] === '|') return true
    let s = k + (text[k + 1] === '&' ? 2 : 1)
    while (s < text.length && isCodeAt(cls, s) && /\s/.test(text[s])) s++
    let e = s
    while (e < text.length && e - from <= PIPE_SCAN_LIMIT && !(isCodeAt(cls, e) && /[;&|\n)}]/.test(text[e]))) e++
    if (e - from > PIPE_SCAN_LIMIT) return false
    if (!consumesAsData(commandOfSegment(codeOnlyText(ctx, s, e)), 'pipe')) return false
    k = e
  }
  return true
}

const CLOSER_RX = /[)}]|(?<![\w$.\/-])(?:done|fi|esac)(?![\w.\/-])/g
const LAST_NON_DATA_CLOSER = new WeakMap()

// The heredoc may sit inside a group, a subshell, a loop, an if/case or a `$( )` that closes AFTER its terminator,
// and the compound's whole output goes on into a pipe behind the closer (`{ cat <<'EOF' .. } | bash`). The lexer has
// no frames for those, so every code-level closer of the command is looked at once (cached per reading): if a pipe
// follows it, each stage must be a data consumer. The heredoc is data only if no such closer that fails comes
// after its terminator. (A closer of an unrelated compound is looked at too: that only over-blocks.)
function compoundOutputIsData(ctx, from) {
  let last = LAST_NON_DATA_CLOSER.get(ctx)
  if (last === undefined) {
    last = -1
    const { text, cls } = ctx
    CLOSER_RX.lastIndex = 0
    let m
    while ((m = CLOSER_RX.exec(text)) !== null) {
      if (isCodeAt(cls, m.index) && !pipeStagesAreData(ctx, m.index + m[0].length)) last = m.index
    }
    LAST_NON_DATA_CLOSER.set(ctx, last)
  }
  return last < from
}

// ctx is a shellContext result, h one of its heredocs. False is the default: every unknown owner, wrapper option,
// pipe stage, process substitution, backtick and unclosed frame answers false (see the rule above).
export function heredocBodyIsData(ctx, h) {
  const { text, cls, substs } = ctx
  if (cls[h.opStart] === CTX_CLASS.BQ) return false
  // 0. the whole command: no function or alias, no output sent to a process or the shell's descriptors
  if (wholeCommandBlocksData(ctx)) return false
  // 1. the owner of the redirect
  if (!consumesAsData(commandOfSegment(segmentBefore(ctx, h.opStart)), 'owner')) return false
  // 2. where the owner's output goes: the operator line, from the end of the delimiter to the first body line
  for (const m of text.slice(h.tagEnd, h.bodyStart).matchAll(/[<>]\(|\|+/g)) {
    const at = h.tagEnd + m.index
    if (cls[at] !== CTX_CLASS.CODE) continue
    if (/^[<>]/.test(m[0])) return false // a process substitution on the operator line
    if (m[0] !== '|') continue // `||`: the next command, not a pipe
    let from = at + 1
    if (text[from] === '&') from++ // `|&`
    let to = from
    while (to < h.bodyStart && !(cls[to] === CTX_CLASS.CODE && /[;&|\n)]/.test(text[to]))) to++
    if (!consumesAsData(commandOfSegment(codeOnlyText(ctx, from, to)), 'pipe')) return false
  }
  // 2b. where the output of a compound that closes after the terminator goes: `{ .. } | stage`, `done | stage`, ...
  if (!compoundOutputIsData(ctx, h.termEnd)) return false
  // 3. the substitution frames around the heredoc, innermost out. start is the first character of the opener, end
  //    the index after the closer, -1 for a frame that is not known to be closed.
  for (let i = substs.length - 1; i >= 0; i--) {
    const s = substs[i]
    if (s.start >= h.opStart) continue
    if (s.end !== -1 && s.end <= h.opStart) continue // closed before the heredoc: not around it
    if (s.end === -1 || s.kind !== 'cmd') return false
    if (!consumesAsData(commandOfSegment(segmentBefore(ctx, s.start)), 'subst')) return false
  }
  return true
}

// Only the heredocs the lexer OPENED are stripped (shellContext): an opener inside a comment, a quote or a
// here-string opens nothing, so the lines after it are never taken for a body (finding 3660cf43 B3). The rest of
// the operator line (`cat <<'EOF' > f; <command>`) is code and stays; only the body lines between the operator
// line and the terminator go. A heredoc the text never terminates keeps its body visible, and so does every
// heredoc of a reading the lexer is not sure of (exact=false): stripping removes text from the checks.
export function stripHeredocBodies(command) {
  const ctx = shellContext(String(command ?? ''))
  const { text, heredocs, exact } = ctx
  if (!exact || !heredocs.length) return text
  let out = ''
  let last = 0
  for (const h of heredocs) {
    if (h.bodyEnd === h.termEnd) continue // unterminated
    // an unquoted tag expands the body: a $( ) or a backtick there still runs
    if (!h.quoted && h.subst) continue
    // A quoted body the shell will not expand is still executed unless its owner provably takes it as data.
    if (!heredocBodyIsData(ctx, h)) continue
    out += text.slice(last, h.bodyStart)
    last = h.bodyEnd
  }
  return out + text.slice(last)
}

const COMMIT_FLAG_RX = flagArgumentRx(String.raw`-m|--message`)
const COMMIT_GUARD_RX = /\bgit\b[\s\S]*\b(commit|tag|stash)\b/i

export function stripGitCommitMessages(command) {
  const src = joinShellLines(String(command ?? ''))
  // the flag probe first: it is linear, the guard is not (a `git` followed by a long text scans to its end)
  if (!new RegExp(COMMIT_FLAG_RX, 'i').test(src) || !COMMIT_GUARD_RX.test(src)) return src
  return stripFlagArguments(shellContext(src), COMMIT_FLAG_RX)
}

// Normalise two shell-level obfuscations that bash resolves at EXEC time, so an
// invocation whose SHAPE is a real self-pace cannot dodge the slash-command match
// with quoting the shell undoes anyway. Measured end-to-end through the gate hook
// (upstream review, 2026-07-27): `claude \/loop` and `claude$IFS/loop` BOTH run
// `claude /loop` in bash but slipped the `(?:^|[\s'"])\/loop` match -- the char
// before `/loop` was `\` and `S` (end of `$IFS`), neither in the [\s'"] class.
// The fix is NOT to widen that class (that would let more prose through); it is to
// resolve what the shell resolves before matching: `$IFS`/`${IFS}` word-splits to
// a space, and a backslash escape `\X` collapses to `X`. Side effect: also closes
// `claude /lo\op`. Applied ONLY to the self-pace bash patterns below; the
// scheduler/store/API checks keep the raw segment (upstream measured them clean,
// and this PR is scoped to these two loop regressions). This cannot introduce a
// false positive: collapsing escapes / dropping `$IFS` never synthesises the
// literal `tmux`+send-keys, `nohup`+claude, or `claude`+`/loop` tokens out of
// prose -- it only removes an evasion.
export function normalizeShellEvasion(seg) {
  return String(seg ?? '')
    .replace(/\$\{IFS\}|\$IFS\b/g, ' ') // $IFS / ${IFS} -> the space it expands to
    .replace(/\\(.)/g, '$1') // \X -> X (bash unescape of a backslash-escaped char)
}

// ---------------------------------------------------------------------------
// Dashboard schedule surface: the /api/schedules API and the on-disk store it
// writes (~/.claude/scheduled-tasks/).
//
// Measured on a live install: a sub-agent created four schedules with a python
// urllib POST, four times HTTP 200. The per-segment check below this block only
// knew the CURL spelling of a write (-X POST / -d / --data), so every other
// HTTP client -- python urllib/requests, node fetch, wget --post-data, httpie,
// nc -- was a write the gate could not see. Adding those spellings one by one
// is a losing blacklist (miss one client and it is a hole), so this block
// inverts the question:
//
//   1. Does the command REFERENCE the schedule surface at all, in any spelling?
//      (path /api/schedules through any host/port, the scheduled-tasks
//      directory, the schedule-registry-cli tool by name, or an SQL write on
//      a scheduled_task* table; the database file has its own narrower rule,
//      see DASHBOARD_DB_REF_RX; also after the shell's own quote and backslash removal, after
//      \xHH / \uHHHH / octal / %HH decoding, after string concatenation glued to
//      a slash, after brace expansion, and through any glob or bracket segment
//      that could expand onto the store or the route -- see globRefs.)
//   2. If it does, the command is judged by FLAT, fail-closed invariants -- no
//      shell-state modelling (an earlier cwd/shadow-tracking draft had bypasses:
//      cd -/OLDPWD/failed-cd, a function shadowing an allowed name):
//      - ANY cd/pushd/popd whose argument references the store denies the whole
//        command (a sub-agent has no reason to enter the store);
//      - ANY function/alias/shadow definition (name(), function, alias, enable,
//        builtin, command, exec) denies;
//      - a variable that carries a reference may not reach a program's
//        environment (export, declare -x, set -a), and the builtins that
//        assign a variable without a NAME=value word (printf -v, read,
//        mapfile, a nameref) deny;
//      - a command is trusted (below) only by a bare name or an exact system
//        binary path, so `/tmp/cat` and `./curl` do not pass.
//      Then every segment that carries the reference must be one of a few forms
//      that are PROVABLY unable to write it:
//        a. a plain curl GET: `curl -q [-s -S -f -L -i -k -v ...] [-H v] [-m n]
//           URL` -- -q FIRST (no curlrc), no -w/-X/-d/--data*/--json/-F/-T/-K/
//           -o/-D/--url, exactly one URL, a literal http(s):// scheme, no
//           unquoted $ expansion (word splitting can inject -X POST), and
//           header values that cannot carry a line break (curl sends one
//           verbatim, so a smuggled second request could ride along). The one
//           file-content a header may carry is the fleet token file, injected as
//           a NUL nonce that shell source cannot express -- a literal
//           `${DASHBOARD_TOKEN}` (or any surviving $) in a header denies;
//        b. a read-only file command (ls, cat, grep, head, tail, wc, stat, ...;
//           find without -exec/-delete/-fprint) whose output, if piped, only
//           reaches plain text filters -- `cat <<EOF | python3` stays denied;
//        c. a carrier whose reference sits ONLY in literal message data: a curl
//           -d/--data value (or a quoted heredoc fed to --data-binary @-), a git
//           commit/tag/stash -m message (or -F - heredoc), a gh/glab prose
//           argument (--body/--title/--notes/... or a --body-file - heredoc,
//           any subcommand but `api`: the same scope stripProseArguments
//           blanks), the content argument of scripts/agent-msg.sh. The value
//           is identified by PARSING the command's own option grammar, not by
//           a regex over the text, so `curl -H -d 'http://.../api/schedules'`
//           (where the "payload" is the URL) is not mistaken for data.
//      Anything else -- any interpreter, any other client, a redirect, cp/mv/
//      tee, an unknown curl option, quoting that cannot be resolved -- is
//      denied. A segment that does NOT reference the surface is judged exactly
//      as it would be on its own, so a pipe consumer like `| python3 -c ...`
//      after a plain curl GET stays allowed.
//
// What this does NOT close, stated so nobody mistakes it for more:
//   - a script FILE the agent wrote in an EARLIER call (the Write tool, or a
//     Bash call that never mentions the surface) and then runs -- allowed on
//     purpose, since the Write tool can write any file. In the SAME command a
//     heredoc that carries a reference may not be redirected to a file
//     (`cat <<'EOF' > /tmp/x.py ... EOF; python3 /tmp/x.py` is denied);
//   - a list of store paths written to a file in one segment and consumed in
//     another (`ls -d <store>/*/SKILL.md > /tmp/l; while read f; do echo x >>
//     "$f"; done < /tmp/l`): the write segment's path comes from `read`, not
//     from the command text;
//   - a reference assembled at run time (chr(), base64, `$(echo sch)edules`, a
//     variable split across segments, a symlink to the store), or a URL/config
//     taken from the environment;
//   - a curlrc: ~/.curlrc can turn ANY curl, even one with no reference, into a
//     write; only form (a) is protected, by requiring -q;
//   - a cd into the store whose effect PERSISTS to a LATER Bash call, IF Claude
//     Code keeps the cwd across calls (unverified): a per-command gate cannot
//     see the earlier cd. Rule 1 still denies that cd in the command where it
//     appears.
// None of these are provable from a single command's text. They belong to the
// server side (a per-agent dashboard token the schedule routes can refuse) and
// the runner side (a registry the runner checks before it fires a task), both
// separate changes. The gate stays what its header says: a hard stop for the
// casual self-pace, not a sandbox.
// ---------------------------------------------------------------------------

// The route, as the dashboard router resolves it. Up to three intermediate path
// segments are tolerated because the router's URL parser resolves dot segments
// (`/api/./schedules`, `/api/x/../schedules`) onto the same route; a lookalike
// that is not a real route is denied as well, which costs nothing.
// Intermediate segments are NON-empty ({1,64}): with {0,64} a run of slashes
// could be split between the \/+ groups in O(n^4) ways, and a hook that times
// out is a hook that did not block.
const SCHEDULE_API_REF_RX = /api\/+(?:[^\s/]{1,64}\/+){0,3}schedules/i
// The store the schedule runner reads. Matched by NAME, not by the
// ~/.claude/ prefix, on purpose: the same directory is reachable through
// links (the isolated config dirs .claude-config / .channels-config link
// their scheduled-tasks entry to ~/.claude/scheduled-tasks), and the repo's
// scheduled-tasks/ and seed-scheduled-tasks/ are copied INTO it by the dashboard
// start and update.sh. The lookahead keeps files that merely share the prefix
// (scheduled-tasks-io.ts, docs/scheduled-tasks.md) out of it.
const SCHEDULE_DIR_REF_RX = /scheduled-tasks(?![\w-]|\.\w)/i
const SCHEDULE_DIR_NAME = 'scheduled-tasks'
// Directories the store is reachable under (the home config dir and the two
// symlinked config dirs, see SCHEDULE_DIR_REF_RX).
const STORE_PARENTS = ['.claude', '.claude-config', '.channels-config']
// Names a glob or bracket segment is checked against: if it can expand to one
// of them, it is read as that name.
// The registry operator tool (and the module behind it), matched by NAME in
// any path, extension and runner form: it opens the database directly, so a
// task registered through it never passes the dashboard's routes. Only its
// read-only subcommands are accepted (isRegistryCliRead). The lookahead keeps
// test files that share the prefix (schedule-registry-shell-paths.test.ts)
// out of it. The tool may not exist on a given install; the rule does not
// depend on it.
const SCHEDULE_CLI_REF_RX = /schedule-registry(?:-cli)?(?:\.[cm]?[jt]s)?(?![\w.-])/i
const SCHEDULE_CLI_NAMES = ['schedule-registry-cli.js', 'schedule-registry-cli.ts', 'schedule-registry.js', 'schedule-registry.ts']
// An SQL write on a schedule table (scheduled_tasks, scheduled_task_registry,
// ...), whatever program runs it: the sqlite3 CLI, python, node, a heredoc.
const SCHEDULE_SQL_WRITE_RX = /\b(?:insert(?:\s+or\s+\w+)?\s+into|replace\s+into|delete\s+from|update(?:\s+or\s+\w+)?|drop\s+(?:table|trigger|view)(?:\s+if\s+exists)?|alter\s+table|create\s+(?:temp\w*\s+)?(?:table|view)(?:\s+if\s+not\s+exists)?)\s+(?:\w+\.)?scheduled_task|\bcreate\s+(?:temp\w*\s+)?trigger\b[\s\S]{0,300}?\bon\s+(?:\w+\.)?scheduled_task/i
// The dashboard database file (and its WAL/SHM/journal). Reads by any program
// stay allowed (a worker reads the board with sqlite3 SELECT); a FILE-level
// write -- a redirect onto it, cp/mv/tee/dd/rm/ln/... naming it, or a sqlite3
// dot-command that replaces or runs files -- is denied (dbSegmentWrites).
const DASHBOARD_DB_REF_RX = /claudeclaw\.db(?:-wal|-shm|-journal)?(?![\w.-])/i
const GLOB_TARGETS = [SCHEDULE_DIR_NAME, 'schedules', 'api', ...STORE_PARENTS, ...SCHEDULE_CLI_NAMES, 'claudeclaw.db']
const FILE_GLOB_TARGETS = new Set([...SCHEDULE_CLI_NAMES, 'claudeclaw.db'])
// Brace expansion is enumerated up to this many words; beyond it, a word that
// could still spell a reference is treated as one (fail closed).
const BRACE_EXPANSION_CAP = 1024

function codePoint(n) {
  try { return String.fromCodePoint(n) } catch { return '' }
}

// Escapes that a shell (printf/echo -e/$'...') or the interpreter the command
// runs (python, node, perl) resolves before the text becomes a URL or a path.
function decodeEscapes(s) {
  return s
    .replace(/\\x([0-9a-f]{2})/gi, (_, h) => codePoint(parseInt(h, 16)))
    .replace(/\\u\{([0-9a-f]{1,6})\}/gi, (_, h) => codePoint(parseInt(h, 16)))
    .replace(/\\u([0-9a-f]{4})/gi, (_, h) => codePoint(parseInt(h, 16)))
    .replace(/\\([0-7]{3})/g, (_, o) => codePoint(parseInt(o, 8)))
    .replace(/%([0-9a-f]{2})/gi, (_, h) => codePoint(parseInt(h, 16)))
}

// Spellings of the same text that the matchers run against. Each one can only
// ADD matches (it removes or decodes characters), so it can never let a
// reference through that the raw text would have caught.
//
// The first four are the canonical reading (joinShellLines: what the shell sees
// after line continuation). When the old naive join -- EVERY backslash + newline
// dropped, in any context -- reads differently, its four spellings are appended as
// extra variants: they can only add a denial (a word cut by `\\<newline>` that the
// shell does not join), never remove one. Index [1] stays the canonical unquoted
// spelling for the callers that take it.
export function scheduleSurfaceVariants(text) {
  const raw = String(text ?? '')
  const canonical = joinShellLines(raw)
  // deliberately NOT a replace(): the structural test keeps the gates free of private joins
  const naive = raw.split(/\\\r?\n/).join('')
  return naive === canonical ? surfaceSpellings(canonical) : [...surfaceSpellings(canonical), ...surfaceSpellings(naive)]
}

function surfaceSpellings(joined) {
  const decoded = decodeEscapes(decodeEscapes(joined)) // twice: %5cx73 -> \x73 -> s
  // quotes, backslashes and $IFS are shell syntax: gone before the program runs
  const unquoted = decoded.replace(/\$\{IFS\}|\$IFS\b/g, '').replace(/[\\'"`]/g, '')
  // string concatenation in any language ('/api/' + 'schedules', "/api/"."x",
  // implicit "a" "b", ','.join): separators glued to a slash disappear...
  // (the lookbehind starts a match only at the beginning of a separator run, so
  // a long run with no slash is scanned once, not once per character)
  const glued = unquoted.replace(/(?<![\s+,.])[\s+,.]*\/[\s+,.]*/g, '/')
  // ...and a literal split mid-word ('sch' + 'edules', "sch"."edules") closes up
  const joinedLiterals = decoded.replace(/(['"`])\s*(?:[+.,]\s*)?(['"`])/g, '')
    .replace(/\$\{IFS\}|\$IFS\b/g, '').replace(/[\\'"`]/g, '')
  return [joined, unquoted, glued, joinedLiterals]
}

function globMatchesName(glob, name) {
  let rx = ''
  for (let i = 0; i < glob.length; i++) {
    const c = glob[i]
    if (c === '*') rx += '.*'
    else if (c === '?') rx += '.'
    else if (c === '[') {
      const j = glob.indexOf(']', i + 1)
      if (j === -1) { rx += '\\['; continue }
      rx += '[' + glob.slice(i + 1, j).replace(/^!/, '^').replace(/\\/g, '\\\\') + ']'
      i = j
    } else rx += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
  }
  try { return new RegExp(`^${rx}$`, 'i').test(name) } catch { return true } // unreadable glob: fail closed
}

// Bash brace expansion of one word: `api/sch{e,}dules` -> [api/schedules,
// api/schdules]; `{a..c}` sequences too. Returns null past `cap` words. `${`
// is a parameter expansion, not a brace group, and is left alone.
function findBraceGroup(w) {
  for (let i = 0; i < w.length; i++) {
    if (w[i] !== '{' || w[i - 1] === '$') continue
    let depth = 0
    let last = i + 1
    const parts = []
    for (let j = i; j < w.length; j++) {
      if (w[j] === '{') depth++
      else if (w[j] === ',' && depth === 1) { parts.push(w.slice(last, j)); last = j + 1 }
      else if (w[j] === '}' && --depth === 0) {
        parts.push(w.slice(last, j))
        if (parts.length > 1) return { start: i, end: j, alts: parts }
        const seq = /^(-?\d+|[a-zA-Z])\.\.(-?\d+|[a-zA-Z])$/.exec(parts[0])
        if (!seq) break
        const num = /^-?\d+$/.test(seq[1]) && /^-?\d+$/.test(seq[2])
        const [a, b] = num ? [Number(seq[1]), Number(seq[2])] : [seq[1].charCodeAt(0), seq[2].charCodeAt(0)]
        if (!num && /^-?\d+$/.test(seq[1]) !== /^-?\d+$/.test(seq[2])) break
        if (Math.abs(b - a) > BRACE_EXPANSION_CAP) return { start: i, end: j, alts: null }
        const alts = []
        for (let k = a; a <= b ? k <= b : k >= b; k += a <= b ? 1 : -1) alts.push(num ? String(k) : String.fromCharCode(k))
        return { start: i, end: j, alts }
      }
    }
  }
  return null
}
function expandBraces(word, cap) {
  const out = []
  const todo = [word]
  while (todo.length) {
    const w = todo.pop()
    const g = findBraceGroup(w)
    if (!g) { out.push(w); continue }
    if (!g.alts) return null
    for (const alt of g.alts) todo.push(w.slice(0, g.start) + alt + w.slice(g.end + 1))
    if (todo.length + out.length > cap) return null
  }
  return out
}

// Is `needle` a subsequence of `hay`? Every brace expansion of a word is a
// subsequence of that word with `{`, `}` and `,` removed, so a word that fails
// this for every target cannot expand to a reference -- no enumeration needed.
function isSubsequence(needle, hay) {
  let i = 0
  for (let j = 0; j < hay.length && i < needle.length; j++) if (hay[j] === needle[i]) i++
  return i === needle.length
}

// Shell words of `text` with a per-character quoted flag: [[{ c, q }]]. Heredoc
// bodies are dropped (they are data for the program that reads them, never
// expanded as words). A command substitution inside double quotes, $(...) or
// `...`, is a fresh unquoted context in bash, so its text is scanned again as
// words of its own. Returns null when the quoting cannot be resolved.
export function quotedWords(text, depth = 0) {
  if (depth > 8) return null
  const src = joinShellLines(String(text ?? ''))
  const heredocs = []
  if (maskInertLiterals(src, heredocs, true) == null) return null
  let s = src
  for (const h of heredocs) s = s.slice(0, h.bodyStart) + ' '.repeat(h.end - h.bodyStart) + s.slice(h.end)
  const words = []
  let cur = []
  const flush = () => { if (cur.length) words.push(cur); cur = [] }
  const inner = (from, close) => (close === '`' ? s.indexOf('`', from) : substEnd(s, from))
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === "'") {
      const e = s.indexOf("'", i + 1)
      if (e === -1) return null
      for (const ch of s.slice(i + 1, e)) cur.push({ c: ch, q: true })
      i = e; continue
    }
    if (c === '"') {
      let j = i + 1
      for (; j < s.length && s[j] !== '"'; j++) {
        if (s[j] === '\\' && j + 1 < s.length) { j++; cur.push({ c: s[j], q: true }); continue }
        const sub = s[j] === '`' ? '`' : (s[j] === '$' && s[j + 1] === '(' ? ')' : '')
        if (sub) {
          const from = j + (sub === '`' ? 1 : 2)
          const e = inner(from, sub)
          if (e === -1) return null
          const nested = quotedWords(s.slice(from, e), depth + 1)
          if (nested == null) return null
          words.push(...nested)
          cur.push({ c: '\u0002', q: true }) // the substituted output: unknown, literal
          j = e; continue
        }
        cur.push({ c: s[j], q: true })
      }
      if (j >= s.length) return null
      i = j; continue
    }
    if (c === '\\' && i + 1 < s.length) { cur.push({ c: s[i + 1], q: true }); i++; continue }
    if (/\s/.test(c) || ';&|<>()`'.includes(c)) { flush(); continue }
    cur.push({ c, q: false })
  }
  flush()
  return words
}

// Words the shell (brace expansion, pathname globbing) or curl (URL globbing:
// {a,b} and [a-z], even inside quotes) turns into OTHER words. Each is expanded
// and every glob or bracket segment is read as the target name it can match, so
// `api/sch{e,}dules`, `api/sch[e]dules`, `~/.c*/sch*`, `.channels-config/sched*`
// and `cd sched*` all count. Only UNQUOTED metacharacters count -- bash expands
// nothing inside quotes, and a python regex like '[a-z]*' is not a path --
// except in a URL word, where curl globs quoted text too. A pure `*` segment
// only counts under a store parent (`~/.claude/*`, or after a cd into one:
// opts.parentCtx), otherwise every `ls src/*` would. A bracket segment counts
// on ANY match: rare in paths, and it fails closed.
const NEUTRAL = '\u0002' // stands in for a quoted metacharacter: literal, matches no target
function globRefs(text, opts) {
  const out = { api: false, dir: false, cli: false, db: false }
  const words = quotedWords(text)
  const list = words
    ? words.map((w) => {
      // a real URL (scheme://host...): curl globs {a,b} and [x-y] in it even
      // when quoted. A grep pattern like 'https\?://[^ ]*' is not one.
      const url = /^[a-z][a-z0-9+.-]*:\/\/[a-z0-9.\-[\]:$]+(?:\/|$)/i.test(w.map((x) => x.c).join(''))
      return w.map((x) => (x.q && '*?[]{},'.includes(x.c) && !(url && '[]{},'.includes(x.c)) ? NEUTRAL : x.c)).join('')
    })
    : scheduleSurfaceVariants(text)[1].split(/[\s;&|<>()]+/) // unresolvable quoting: read every metachar (fail closed)
  for (const raw of list) {
    const word = raw.replace(/[\\'"`]/g, '')
    if (!/[*?[\]{}]/.test(word)) continue
    const flat = word.replace(/[{},]/g, '').toLowerCase()
    // a glob character can stand for any letters, so then always enumerate
    const mayBrace = /[*?[]/.test(word) || ['schedules', 'scheduled-tasks', 'schedule-registry', 'claudeclaw.db'].some((t) => isSubsequence(t, flat))
    const exps = /[{}]/.test(word) ? (mayBrace ? expandBraces(word, BRACE_EXPANSION_CAP) : [word.replace(/[{}]/g, '')]) : [word]
    if (!exps) return { api: true, dir: true, cli: true, db: true } // too many expansions to prove harmless
    for (const e of exps) {
      if (SCHEDULE_API_REF_RX.test(e)) out.api = true
      if (SCHEDULE_DIR_REF_RX.test(e)) out.dir = true
      const segs = normalizePathSegments(e)
      const mapped = segs.map((seg, i) => {
        if (!/[*?[]/.test(seg)) return seg
        const bracket = /\[[^\]]*\]/.test(seg)
        const literal = seg.replace(/\[[^\]]*\]|[*?]/g, '').length
        // the parent segment must name a store parent with some literal text
        // (`.claude`, `.c*`): a bare `*/*` is not evidence of anything
        const prev = segs[i - 1] ?? ''
        const parent = i > 0
          ? prev.replace(/\[[^\]]*\]|[*?]/g, '').length >= 2 && STORE_PARENTS.some((p) => globMatchesName(prev, p))
          : !!opts?.parentCtx
        // a file name target needs literal text beyond its extension: `*.ts`
        // or `*.db` alone is every such file, not evidence of this one
        const stem = seg.replace(/\.[cm]?[jt]s$|\.db$/i, '').replace(/\[[^\]]*\]|[*?]/g, '').length
        for (const name of GLOB_TARGETS) {
          if (!globMatchesName(seg, name)) continue
          if (FILE_GLOB_TARGETS.has(name) && !bracket && stem < 3) continue
          if (bracket || literal >= 3 || (name === SCHEDULE_DIR_NAME && parent)) return name
        }
        return seg
      }).join('/')
      if (SCHEDULE_API_REF_RX.test(mapped)) out.api = true
      if (SCHEDULE_DIR_REF_RX.test(mapped)) out.dir = true
      if (SCHEDULE_CLI_REF_RX.test(e) || SCHEDULE_CLI_REF_RX.test(mapped)) out.cli = true
      if (DASHBOARD_DB_REF_RX.test(e) || DASHBOARD_DB_REF_RX.test(mapped)) out.db = true
    }
  }
  return out
}

// Lexical path normalisation before a word is read segment by segment: `//`
// and `/./` collapse and `x/..` resolves, exactly as the kernel would walk
// them, so `~/.claude//sc*` and `~/.claude/./sc*` still show `.claude` as the
// parent of `sc*`. (A `..` after a symlink can differ from the lexical result;
// that is inside the stated symlink limit.)
function normalizePathSegments(word) {
  const out = []
  for (const seg of String(word).split('/')) {
    if (seg === '.' || (seg === '' && out.length)) continue
    if (seg === '..' && out.length && out[out.length - 1] !== '..' && out[out.length - 1] !== '') { out.pop(); continue }
    out.push(seg)
  }
  return out
}

// Does this text reference the schedule surface? { api, dir, cli, sql, db }
// (route, store, registry tool, schedule-table SQL write, database file).
// opts.parentCtx: the command cd's into a store parent, so a bare glob word
// (`s*`) may be resolved relative to it.
export function scheduleSurfaceRefs(text, opts) {
  const vs = scheduleSurfaceVariants(text)
  const r = {
    api: vs.some((v) => SCHEDULE_API_REF_RX.test(v)),
    dir: vs.some((v) => SCHEDULE_DIR_REF_RX.test(v)),
    cli: vs.some((v) => SCHEDULE_CLI_REF_RX.test(v)),
    sql: vs.some((v) => SCHEDULE_SQL_WRITE_RX.test(v)),
    db: vs.some((v) => DASHBOARD_DB_REF_RX.test(v)),
  }
  if (!r.api || !r.dir || !r.cli || !r.db) {
    const g = globRefs(text, opts)
    r.api ||= g.api
    r.dir ||= g.dir
    r.cli ||= g.cli
    r.db ||= g.db
  }
  return r
}
// Everything except the database file, which has its own, narrower rule.
const strongRef = (r) => r.api || r.dir || r.cli || r.sql

// Does the command cd/pushd into a store PARENT (~/.claude, a config dir)?
// Then a relative glob anywhere in it may land on the store.
function cdsIntoStoreParent(command) {
  const unquoted = scheduleSurfaceVariants(command)[1]
  for (const m of unquoted.matchAll(/(?:^|[\s;&|(])(?:cd|pushd)\s+(\S+)/g)) {
    const last = normalizePathSegments(m[1]).filter(Boolean).pop() ?? ''
    if (STORE_PARENTS.some((p) => globMatchesName(last, p))) return true
  }
  return false
}

// `"$(cat <<'EOF' ... EOF)"` -- the canonical multi-line commit message -- is a
// LITERAL string: a quoted tag expands nothing and cat prints the body verbatim.
// Rewrite it to the single-quoted literal it evaluates to, so the parser below
// can see it as a plain word. If the body contains a line equal to the tag, the
// shell would have ended the heredoc THERE and run the rest; that case is left
// untouched, and maskInertLiterals then fails closed on it.
const LITERAL_HEREDOC_SUBST_RX = /"\$\(\s*cat\s+<<-?\s*(['"])([A-Za-z_]\w*)\1[ \t]*\r?\n([\s\S]*?)\r?\n[ \t]*\2[ \t]*\r?\n\s*\)"/g
function resolveLiteralHeredocSubst(cmd) {
  return cmd.replace(LITERAL_HEREDOC_SUBST_RX, (full, _q, tag, body) => {
    if (new RegExp(`^[ \\t]*${tag}[ \\t]*$`, 'm').test(body)) return full
    return `'${body.replace(/'/g, '')}'`
  })
}

// `$(cat PATH)` / `$(< PATH)` only reads a file -- the dashboard token header
// `-H "Authorization: Bearer $(cat store/.dashboard-token)"` is the fleet's own
// documented form. It becomes a marker: harmless inside double quotes, and
// rejected unquoted by the word parser (an unquoted substitution word-splits,
// so `curl -H $(cat args) URL` could smuggle -X POST in). Only when the path
// itself does not reference the surface. The TOKEN path gets a distinct marker
// because its file content is the ONLY thing form (a) accepts inside a header
// (isPlainCurlGet). That marker MUST NOT be expressible in shell source: an
// earlier draft used the literal `${DASHBOARD_TOKEN}`, which an agent can
// itself write as a real expansion -- `DASHBOARD_TOKEN=$'...\r\n...'; curl -H
// "X: ${DASHBOARD_TOKEN}"` -- reopening CR/LF smuggling. So it is a per-run
// nonce fenced by NUL, which cannot occur in a shell command's argv.
const CAT_SUBST_RX = /\$\(\s*(?:cat\s+|<\s*)((?:[\w./~@+-]|\$\w+|\$\{\w+\})+)\s*\)/g
const TOKEN_NONCE = `\u0000SPTOK${randomBytes(9).toString('hex')}\u0000`
const NONCONTENT_MARKER = '\u0000SPVAL\u0000' // any other $(...) whose output is opaque
const PROJECT_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..')
// The token files a header may read, as LITERAL absolute paths (the form the
// scaffold writes into every sub-agent's CLAUDE.md: tokenPath is
// join(PROJECT_ROOT, 'store', '.dashboard-token')):
//   - <root>/store/.dashboard-token, the shared dashboard token;
//   - <root>/agents/<self>/.dashboard-token, a per-agent token file, for the
//     calling agent only (opts.selfAgent, see selfAgentFromProjectDir). On an
//     install without per-agent tokens that file does not exist, so it is
//     refused by the content check below.
// No relative path (a sub-agent runs in agents/<name>/ and could create its
// own store/.dashboard-token there), no ~ or $HOME (an expansion the command
// can redefine). And the file's CONTENT must look like a token, read when the
// gate decides: a token file with a CR/LF in it would put a second, pipelined
// request (a POST) inside the "GET". Missing or unreadable = refused.
const TOKEN_CONTENT_RX = /^[A-Za-z0-9._~+/=-]+\n?$/
export function tokenFileContentOk(path) {
  try { return TOKEN_CONTENT_RX.test(readFileSync(path, 'utf-8')) } catch { return false }
}
export function acceptedTokenFile(path, opts = {}) {
  const root = opts.projectRoot ?? PROJECT_ROOT
  const allowed = [join(root, 'store', '.dashboard-token')]
  if (opts.selfAgent && /^[A-Za-z0-9_-]+$/.test(opts.selfAgent)) allowed.push(join(root, 'agents', opts.selfAgent, '.dashboard-token'))
  return allowed.includes(path) && tokenFileContentOk(path)
}
// The calling agent: the hook's CLAUDE_PROJECT_DIR (the directory the agent's
// session was launched in, set by Claude Code for every hook process; a Bash
// `cd` does not change it) when it is exactly <root>/agents/<name>. Anything
// else -- unset, the repo root, a deeper or outside path -- is no agent, so
// only the shared token file is accepted.
export function selfAgentFromProjectDir(dir, root = PROJECT_ROOT) {
  if (!dir) return undefined
  const rel = relative(join(root, 'agents'), resolve(String(dir)))
  if (!rel || rel.startsWith('..') || rel.includes(sep) || !/^[A-Za-z0-9_-]+$/.test(rel)) return undefined
  return rel
}
function resolveCatSubst(cmd, opts) {
  return cmd.replace(CAT_SUBST_RX, (full, path) => {
    if (strongRef(scheduleSurfaceRefs(path, opts))) return full
    return acceptedTokenFile(path, opts) ? TOKEN_NONCE : NONCONTENT_MARKER
  })
}

// Any other flat `$(CMD)` -- no quotes, no nesting, no expansion inside, and no
// reference in CMD -- becomes NONCONTENT_MARKER (NUL-fenced, see above). CMD
// itself would be allowed on its own (it references nothing), and its OUTPUT is
// run-time data, which this gate cannot see in any spelling. Without this, one
// `"$(date -Iseconds)"` anywhere in a command made the whole quoting
// unresolvable and denied an unrelated read of the store (replay of real
// sub-agent tool calls). readWord treats an unquoted marker as an expansion (unknown word
// count), and headerValueIsInert rejects it in a header, so the curl checks
// still refuse it there and as a URL's start. There is no "inside the store"
// case to guard any more: a cd/pushd/popd into the store denies the whole
// command (scheduleSurfaceDeny, rule 1).
const FLAT_SUBST_RX = /\$\(([^()'"`$\\]*)\)/g
function resolveFlatSubst(cmd, opts) {
  return cmd.replace(FLAT_SUBST_RX, (full, inner) => {
    return strongRef(scheduleSurfaceRefs(inner, opts)) ? full : NONCONTENT_MARKER
  })
}

// Split a command into the segments the SHELL would see: separators inside
// quotes or heredoc bodies do not split (maskInertLiterals decides that), and
// a heredoc body is handed back to the segment whose `<<` owns it. Returns null
// when the quoting cannot be resolved -- the caller then denies.
const SEGMENT_SEP_RX = /\|\||&&|\|&|;;|[;|\n]|(?<![<>])&(?!>)/g
export function shellSegments(command, opts) {
  // Join first: the substitution resolvers below must see the text the shell sees. The result is the
  // coordinate system of `heredocs`, `masked` and the segment slices (maskInertLiterals joins again, a no-op).
  const src = resolveFlatSubst(resolveCatSubst(resolveLiteralHeredocSubst(joinShellLines(String(command ?? ''))), opts), opts)
  const heredocs = []
  const masked = maskInertLiterals(src, heredocs)
  if (masked == null || masked.length !== src.length) return null
  const ranges = []
  let start = 0
  for (const m of masked.matchAll(SEGMENT_SEP_RX)) {
    ranges.push({ start, end: m.index, sep: m[0] })
    start = m.index + m[0].length
  }
  ranges.push({ start, end: src.length, sep: '' })
  const segs = []
  for (const r of ranges) {
    // a range that lies inside a heredoc body/terminator belongs to its owner
    if (heredocs.some((h) => r.start >= h.bodyStart && r.end <= h.end)) continue
    const own = src.slice(r.start, r.end)
    // an empty range (`a |<newline>b`) is skipped WITHOUT touching the previous
    // separator: the pipe before it still connects to the next real command
    if (!own.trim()) continue
    const bodies = heredocs
      .filter((h) => h.opStart >= r.start && h.opStart < r.end)
      .map((h) => src.slice(h.bodyStart, h.bodyEnd))
    segs.push({ own: own.trim(), bodies, text: [own.trim(), ...bodies].join('\n'), sep: r.sep })
  }
  return segs
}

// Plain-word parser for one segment. Returns [{ value, dollar, star, ansi }] or
// null when the segment is not a plain word list: a command or process
// substitution, grouping, brace expansion, a here-string. Redirections are
// parsed, not rejected: an output target lands on `words.redirects` (the caller
// decides whether it may be written), an fd dup (2>&1) and an input redirect
// are dropped.
const HEREDOC_OP_RX = /<<-?\s*(?:'[^']*'|"[^"]*"|[A-Za-z_]\w*)/g
const REDIRECT_OP_RX = /^(?:\d|&)?(?:>>|>\||>|<(?![<(]))/

function readWord(s, i) {
  let value = ''
  let dollar = false // an UNQUOTED expansion: word splitting can turn it into several words
  let star = false // an unquoted * or [ glob
  let ansi = false // a $'...' part: its \r \n escapes become real control characters
  while (i < s.length && !/\s/.test(s[i])) {
    const c = s[i]
    if (c === "'") {
      const e = s.indexOf("'", i + 1)
      if (e === -1) return null
      value += s.slice(i + 1, e); i = e + 1; continue
    }
    if (s.startsWith("$$'", i)) return null
    if (c === '$' && s[i + 1] === "'") {
      let j = i + 2
      while (j < s.length && s[j] !== "'") j += s[j] === '\\' ? 2 : 1
      if (j >= s.length) return null
      value += s.slice(i + 2, j); ansi = true; i = j + 1; continue
    }
    if (c === '"') {
      let j = i + 1
      while (j < s.length && s[j] !== '"') {
        if (s[j] === '`' || (s[j] === '$' && s[j + 1] === '(')) return null
        // inside "..." bash drops the backslash only before $ ` " \ and newline
        if (s[j] === '\\' && j + 1 < s.length) {
          value += '$`"\\\n'.includes(s[j + 1]) ? s[j + 1] : s.slice(j, j + 2)
          j += 2; continue
        }
        value += s[j]; j++
      }
      if (j >= s.length) return null
      i = j + 1; continue
    }
    if (c === '\\') {
      if (i + 1 >= s.length) return null
      value += s[i + 1]; i += 2; continue
    }
    if (c === '$' && s[i + 1] === '{') { // ${NAME...}: an expansion, unless it nests a command
      const e = s.indexOf('}', i + 2)
      if (e === -1 || /[`{]|\$\(/.test(s.slice(i + 2, e))) return null
      value += s.slice(i, e + 1); dollar = true; i = e + 1; continue
    }
    if ('`(){}<>;&|'.includes(c)) return null
    if (c === '$' || c === '\u0000') dollar = true // $ or a NUL substitution marker
    if (c === '*' || c === '[') star = true
    value += c; i++
  }
  return { word: { value, dollar, star, ansi }, i }
}

function shellWords(text) {
  const s = String(text).replace(HEREDOC_OP_RX, ' ')
  const words = []
  words.redirects = []
  let i = 0
  while (i < s.length) {
    while (i < s.length && /\s/.test(s[i])) i++
    if (i >= s.length) break
    const op = REDIRECT_OP_RX.exec(s.slice(i))
    if (op) {
      i += op[0].length
      if (s[i] === '&' && /\d/.test(s[i + 1] ?? '')) { i += 2; continue } // 2>&1: fd dup, no file
      while (i < s.length && /\s/.test(s[i])) i++
      const t = readWord(s, i)
      if (!t || !t.word.value) return null
      if (op[0].includes('>')) words.redirects.push(t.word) // output: a file gets written
      i = t.i
      continue
    }
    const r = readWord(s, i)
    if (!r) return null
    words.push(r.word)
    i = r.i
  }
  return words
}

// System directories a tool's real binary lives in. A command word is trusted
// (forms a/b/c) only as a BARE name (`curl`) or as an EXACT absolute path in one
// of these (`/usr/bin/curl`). `./curl`, `/tmp/cat`, `$X/curl`, a relative path:
// not trusted -> commandName returns '' -> neither form matches -> deny.
const SYSTEM_BIN_DIRS = ['/usr/bin/', '/bin/', '/usr/local/bin/', '/usr/sbin/', '/sbin/', '/opt/homebrew/bin/']
function commandName(words) {
  const w = words[0]
  if (!w || w.dollar || w.value.includes('$')) return ''
  const v = w.value
  if (!v.includes('/')) return v // bare name
  const base = v.slice(v.lastIndexOf('/') + 1)
  return SYSTEM_BIN_DIRS.some((d) => v === d + base) ? base : ''
}

// curl's option grammar, as far as this gate needs it. An option not listed
// here makes parseCurl return null: unknown means not provable.
const CURL_NOARG = new Set([
  '-s', '--silent', '-S', '--show-error', '-f', '--fail', '--fail-with-body', '-L', '--location',
  '-i', '--include', '-I', '--head', '-k', '--insecure', '-v', '--verbose', '-g', '--globoff',
  '-G', '--get', '--compressed', '--no-progress-meter', '-N', '--no-buffer', '-4', '-6',
])
const CURL_SHORT_NOARG = 'sSfLiIkvgGN46'
const CURL_ARG_OPTS = new Map([
  ['-H', 'header'], ['--header', 'header'],
  // 'safe' = checked against the installed curl 8.5.0 man page (2026-09-28):
  // no file written, no config read, no change to the request. -w/--write-out
  // is NOT safe: its %output{file} / %output{>>file} (curl >= 8.3.0) writes a
  // file of the caller's choosing.
  ['-m', 'safe'], ['--max-time', 'safe'], ['--connect-timeout', 'safe'],
  ['-w', 'file'], ['--write-out', 'file'],
  ['-A', 'header'], ['--user-agent', 'header'], ['-e', 'header'], ['--referer', 'header'],
  ['--retry', 'safe'], ['--retry-delay', 'safe'], ['--retry-max-time', 'safe'],
  ['-X', 'method'], ['--request', 'method'],
  ['-d', 'data'], ['--data', 'data'], ['--data-raw', 'data'], ['--data-binary', 'data'],
  ['--data-ascii', 'data'], ['--data-urlencode', 'data'], ['--json', 'data'],
  ['-F', 'body'], ['--form', 'body'], ['-T', 'body'], ['--upload-file', 'body'],
  ['-K', 'config'], ['--config', 'config'],
  ['-o', 'file'], ['--output', 'file'], ['-D', 'file'], ['--dump-header', 'file'], ['-c', 'file'], ['--cookie-jar', 'file'],
  ['-u', 'auth'], ['--user', 'auth'], ['-b', 'auth'], ['--cookie', 'auth'],
  ['--url', 'url'],
  ['-x', 'route'], ['--proxy', 'route'], ['--resolve', 'route'], ['--connect-to', 'route'], ['--unix-socket', 'route'],
])

function parseCurl(words) {
  const out = { urls: [], kinds: new Set(), dataIdx: new Set(), stdinData: false, sent: [], noCurlrc: false }
  const record = (kind, idx, value) => {
    out.kinds.add(kind)
    if (kind === 'header') out.sent.push({ value, ansi: words[idx].ansi })
    if (kind === 'data') {
      out.dataIdx.add(idx)
      if (value === '@-') out.stdinData = true
    }
    if (kind === 'url') out.urls.push(words[idx])
  }
  for (let i = 1; i < words.length; i++) {
    const w = words[i]
    const v = w.value
    if (w.dollar) return null // unquoted expansion: its word count is unknown
    // -q / --disable skips the curlrc, but ONLY as the very first argument
    if (i === 1 && (v === '-q' || v === '--disable')) { out.noCurlrc = true; continue }
    if (v === '--') return null
    if (v.startsWith('--')) {
      const eq = v.indexOf('=')
      const name = eq >= 0 ? v.slice(0, eq) : v
      if (eq < 0 && CURL_NOARG.has(name)) continue
      const kind = CURL_ARG_OPTS.get(name)
      if (!kind) return null
      if (eq >= 0) { record(kind, i, v.slice(eq + 1)); continue }
      if (i + 1 >= words.length) return null
      i++; record(kind, i, words[i].value); continue
    }
    if (v.startsWith('-') && v.length > 1) {
      if (v.includes('$')) return null
      for (let j = 1; j < v.length; j++) {
        if (CURL_SHORT_NOARG.includes(v[j])) continue
        const kind = CURL_ARG_OPTS.get('-' + v[j])
        if (!kind) return null
        const rest = v.slice(j + 1)
        if (rest) record(kind, i, rest)
        else { if (i + 1 >= words.length) return null; i++; record(kind, i, words[i].value) }
        break
      }
      continue
    }
    out.urls.push(w)
  }
  return out
}

// Form (a): a plain curl GET. The scheme must be literal: a URL that STARTS with
// an expansion (`"$D/api/schedules"`) can carry gopher:// or dict://, which let
// curl write raw bytes -- a POST -- to the port.
//
// Header values (-H, -A, -e) must not be able to carry a line break. Measured
// 2026-09-28 against a raw socket: curl 8.5.0 sends `-H $'X: a\r\n\r\nPOST
// /api/schedules HTTP/1.1...'` VERBATIM, i.e. a second, pipelined POST rides
// inside the "GET". (A CR/LF in the URL is refused by curl itself, exit 3,
// measured the same way.) So a header value may contain no control character,
// no $'...' part, and no expansion other than the dashboard token file; and
// not the `@file` form, which reads header lines from a file this gate cannot
// see. (Residual, not closed: the token FILE's own content is trusted.) The
// token nonce (the resolved `$(cat store/.dashboard-token)`) is stripped FIRST;
// then any control char -- a NUL from a non-token substitution, or a real
// CR/LF -- and any surviving `$` (a literal `${DASHBOARD_TOKEN}` the agent
// wrote, or any other expansion) make the value non-inert.
function headerValueIsInert(h) {
  if (h.ansi || h.value.startsWith('@')) return false
  const stripped = h.value.split(TOKEN_NONCE).join('')
  if (/[\x00-\x1f\x7f]/.test(stripped)) return false
  return !stripped.includes('$')
}
//
// curl reads ~/.curlrc (or $CURL_HOME/.curlrc, $XDG_CONFIG_HOME/curlrc) before
// its command line, and a curlrc can say `request = POST` / `data = ...` /
// `output = ...`. Form (a) therefore requires -q as the FIRST argument (the
// only position where curl honours it) instead of guessing at run time whether
// a curlrc exists: that guess could not see one written earlier in the same
// command. The scheme must be a literal http(s)://: without one, curl guesses
// the protocol from the host name (ftp., dict., ...).
function isPlainCurlGet(words) {
  const p = parseCurl(words)
  if (!p || !p.noCurlrc) return false
  for (const k of p.kinds) if (k !== 'header' && k !== 'safe') return false
  if (!p.sent.every(headerValueIsInert)) return false
  if (p.urls.length !== 1) return false
  const u = p.urls[0]
  if (u.star) return false
  return /^https?:\/\//i.test(u.value)
}

// Form (b): commands that can neither write a file (other than through a
// redirect, which the caller checks) nor open a socket, and -- for their output
// -- the only consumers allowed on a pipe. No tee, awk, xargs, tree (-o), file
// (-C); sed and sort only in a shape whose options cannot write or exec.
const READ_ONLY_FS = new Set([
  'ls', 'cat', 'head', 'tail', 'grep', 'egrep', 'fgrep', 'rg', 'wc', 'stat', 'du', 'readlink', 'realpath',
  'basename', 'dirname', 'test', '[', 'diff', 'cmp', 'md5sum', 'sha1sum', 'sha256sum', 'find', 'echo', 'printf',
  'date', 'pwd', 'true', 'false', 'sed', 'sort', 'cut', 'tr', 'nl', 'uniq', 'column',
])
const TEXT_FILTERS = new Set(['grep', 'egrep', 'fgrep', 'head', 'tail', 'wc', 'cut', 'tr', 'nl', 'cat', 'uniq', 'column', 'sort', 'sed'])
const FIND_ACTION_RX = /^-(?:exec|execdir|ok|okdir|delete|fprint|fprint0|fprintf|fls)$/
// sed: only -n/-E/-r and line-range print/delete scripts (`1,60p`, `$d`) -- no
// `w file`, no `e command`, no -i.
const SED_SCRIPT_RX = /^(?:(?:\d+|\$)(?:,(?:\d+|\$))?[pd];?)+$/
function sedIsPrintOnly(words) {
  let script = 0
  for (const w of words.slice(1)) {
    if (/^-[nEr]+$/.test(w.value) || w.value === '--quiet') continue
    if (w.value.startsWith('-')) return false
    if (!script++) { if (!SED_SCRIPT_RX.test(w.value)) return false }
  }
  return script > 0
}
// sort: -o writes a file, --compress-program runs one
function sortIsReadOnly(words) {
  return words.slice(1).every((w) => !w.value.startsWith('-') || /^-[bdfghinMRrsuVz]+$/.test(w.value) || /^-[kt]/.test(w.value))
}

function isReadOnlyFsCommand(words, name) {
  if (!READ_ONLY_FS.has(name)) return false
  // uniq's SECOND operand is an output file
  if (name === 'uniq') return words.slice(1).filter((w) => !w.value.startsWith('-')).length <= 1
  if (name === 'find') return !words.some((w) => w.dollar || w.star || FIND_ACTION_RX.test(w.value))
  if (name === 'rg') return !words.some((w) => w.value.startsWith('--pre'))
  if (name === 'sed') return sedIsPrintOnly(words)
  if (name === 'sort') return sortIsReadOnly(words)
  return true
}

const AGENT_MSG_RX = /(?:^|\/)scripts\/agent-msg\.sh$/
function isPipeSink(words, name) {
  if (TEXT_FILTERS.has(name)) return isReadOnlyFsCommand(words, name)
  // the inter-agent helper: its stdin becomes message content, nothing else
  const script = (name === 'bash' || name === 'sh') ? words[1] : words[0]
  return !!script && AGENT_MSG_RX.test(script.value) && words.every((w) => !w.dollar)
}

function pipesOnlyIntoSinks(segs, k, redirectsOk) {
  for (let j = k; j < segs.length - 1 && (segs[j].sep === '|' || segs[j].sep === '|&'); j++) {
    const next = segs[j + 1]
    const words = shellWords(next.own)
    if (!words || !isPipeSink(words, commandName(words)) || next.bodies.length || !redirectsOk(words)) return false
  }
  return true
}

// gh/glab prose flags (the set stripProseArguments blanks), and the flags that
// read the same prose from a file (`-` = stdin, i.e. a heredoc on the segment).
const GH_PROSE_FLAGS = new Set(['--body', '--message', '--notes', '--title', '--subject', '-b', '-m', '-t'])
const GH_PROSE_FILE_FLAGS = new Set(['--body-file', '--notes-file', '-F'])

// Form (c): the segment's text with its LITERAL message data removed. The data
// words are found by the carrier's own grammar; anything not recognised keeps
// the full text, so the reference stays and the segment is denied.
function dataResidue(seg, words, name) {
  const keep = (drop) => words.filter((_, i) => !drop.has(i)).map((w) => w.value).join(' ')
  if (name === 'curl') {
    const p = parseCurl(words)
    if (!p || p.kinds.has('config')) return seg.text
    return [keep(p.dataIdx), ...(p.stdinData ? [] : seg.bodies)].join('\n')
  }
  if (name === 'git') {
    let i = 1
    while (i < words.length && words[i].value.startsWith('-')) {
      if (['-C', '-c', '--git-dir', '--work-tree', '--namespace'].includes(words[i].value)) i++
      i++
    }
    if (!['commit', 'tag', 'stash'].includes(words[i]?.value)) return seg.text
    const drop = new Set()
    let stdinMsg = false
    for (let j = i + 1; j < words.length; j++) {
      const v = words[j].value
      if (v === '--message' || /^-[a-zA-Z]*m$/.test(v)) { drop.add(j + 1); j++; continue }
      if (/^-m./.test(v) || v.startsWith('--message=')) { drop.add(j); continue }
      if ((v === '-F' || v === '--file') && words[j + 1]?.value === '-') { stdinMsg = true; j++; continue }
      if (v === '-F-' || v === '--file=-') stdinMsg = true
    }
    return [keep(drop), ...(stdinMsg ? [] : seg.bodies)].join('\n')
  }
  if (name === 'gh' || name === 'glab') {
    // `gh api` sends a request of the caller's choosing: never message data
    if (words.slice(1).some((w) => w.value === 'api')) return seg.text
    const drop = new Set()
    let stdinMsg = false
    for (let j = 1; j < words.length; j++) {
      const v = words[j].value
      const eq = v.indexOf('=')
      const flag = v.startsWith('--') && eq > 0 ? v.slice(0, eq) : v
      if (GH_PROSE_FLAGS.has(flag)) {
        if (flag !== v) drop.add(j) // --body=TEXT
        else { drop.add(j + 1); j++ }
        continue
      }
      if (GH_PROSE_FILE_FLAGS.has(flag)) {
        const val = flag !== v ? v.slice(eq + 1) : words[j + 1]?.value
        if (val === '-') stdinMsg = true
        if (flag === v) j++
      }
    }
    return [keep(drop), ...(stdinMsg ? [] : seg.bodies)].join('\n')
  }
  const helperAt = (name === 'bash' || name === 'sh') ? 1 : 0
  if (words[helperAt] && AGENT_MSG_RX.test(words[helperAt].value) && !words.some((w) => w.dollar)) {
    // <from> <to> <content | -> ; stdin content comes from a heredoc or a pipe
    const contentIdx = helperAt + 3
    const drop = new Set([contentIdx])
    const stdinMsg = words[contentIdx]?.value === '-'
    return [keep(drop), ...(stdinMsg ? [] : seg.bodies)].join('\n')
  }
  return seg.text
}

// The registry tool's read-only use: `node|tsx <path>/schedule-registry-cli.(js|ts)
// status|verify ...` or `npx [--no-install|-y] tsx <path> status|verify ...`.
// No runner option before the script (`node --import X`, `-e`), no expansion
// in any word. register / unregister / no subcommand / anything else: denied.
const SCHEDULE_CLI_SCRIPT_RX = /(?:^|\/)schedule-registry-cli\.(?:[cm]?js|[cm]?ts)$/
const SCHEDULE_CLI_READ_SUBCOMMANDS = new Set(['status', 'verify'])
function isRegistryCliRead(words, name) {
  let i = 1
  if (name === 'npx') {
    while (['--no-install', '--yes', '-y'].includes(words[i]?.value)) i++
    if (words[i]?.value !== 'tsx') return false
    i++
  } else if (name !== 'node' && name !== 'tsx') return false
  const script = words[i]
  if (!script || script.dollar || script.star || !SCHEDULE_CLI_SCRIPT_RX.test(script.value)) return false
  if (!SCHEDULE_CLI_READ_SUBCOMMANDS.has(words[i + 1]?.value)) return false
  return words.every((w) => !w.dollar && !w.star)
}
// A developer sub-agent may stage, diff or log the tool's SOURCE: git index and
// history commands that never execute it, without -c (an alias or a pager is a
// command) and without an external diff driver.
const GIT_SOURCE_SUBCOMMANDS = new Set(['add', 'diff', 'log', 'show', 'status', 'blame', 'ls-files', 'grep', 'restore'])
function isGitSourceCommand(words, name) {
  if (name !== 'git') return false
  if (words.some((w) => w.dollar || /^(?:-c|--exec-path(?:=.*)?|--ext-diff|--textconv|-p|--paginate)$/.test(w.value))) return false
  return GIT_SOURCE_SUBCOMMANDS.has(words[1]?.value)
}

// The database file: a FILE-level write. Reads by any program pass; an SQL
// write on a schedule table is caught separately (SCHEDULE_SQL_WRITE_RX), and
// an SQL write through a script file is a stated limit.
const DB_FILE_WRITERS = new Set(['cp', 'mv', 'tee', 'dd', 'rm', 'ln', 'truncate', 'install', 'rsync', 'shred', 'unlink', 'touch', 'scp', 'tar', 'unzip', 'patch'])
const SQLITE_FILE_DOT_RX = /(?:^|[\s'"])\.(?:read|restore|import|load|shell|system|clone|backup|save)\b|(?:^|\s)-init\b/
function dbSegmentWrites(words, name, text) {
  if (DB_FILE_WRITERS.has(name)) return true
  if (name === 'sed' && words.some((w) => /^-[a-zA-Z]*i/.test(w.value) || w.value.startsWith('--in-place'))) return true
  if ((name === 'perl' || name === 'ruby') && words.some((w) => /^-[a-zA-Z]*i/.test(w.value))) return true
  if (/^sqlite3?$/.test(name) && SQLITE_FILE_DOT_RX.test(text)) return true
  return name === '' // an untrusted command path (./x, $X/x) naming the database
}

// Shell grammar around a command that this check steps over: a loop/branch
// keyword in front of it, or a keyword standing alone.
const CONTROL_PREFIX_RX = /^(?:(?:do|then|else|elif|if|while|until|!|\{)\s+)+/
const CONTROL_ALONE_RX = /^(?:done|fi|esac|\}|else|then|do)$/
const ASSIGN_RX = /^([A-Za-z_]\w*)=/
const DECLARE_WORDS = new Set(['export', 'local', 'declare', 'readonly', 'typeset'])

// The names an assignment-only segment (`D=~/.claude/scheduled-tasks/x`,
// `export U=...`) assigns, or null when the segment does anything else.
function assignedNames(words) {
  const rest = DECLARE_WORDS.has(words[0]?.value) ? words.slice(1).filter((w) => !/^-\w+$/.test(w.value)) : words
  if (!rest.length || !rest.every((w) => ASSIGN_RX.test(w.value))) return null
  return rest.map((w) => ASSIGN_RX.exec(w.value)[1])
}

// Words that name/shadow a command: a definition (`function`), a builtin that
// runs or redefines one (`alias`, `enable`, `builtin`, `command`, `exec`). When
// the command touches the surface, ANY of these in command position denies --
// they exist to make an allowed name (`ls`, `curl`) do something else.
const SHADOW_WORDS = new Set(['alias', 'enable', 'builtin', 'command', 'exec', 'function'])
// A function definition in command position: `name()` / `name ()` / `function name`.
const FUNCTION_DEF_RX = /^(?:function\s+[\w-]+|[\w-]+\s*\(\s*\))/

// The same invariants, applied to the WHOLE command with quoted text and
// heredoc bodies blanked, at every command position -- after `(`, `{`, `;`,
// `&`, `|`, a backtick or a newline, past `!`/keywords/env assignments -- so a
// definition opening a subshell or group (`(ls(){ cp ...; }; ls <store>)`) is
// seen too. A `name()` anywhere in unquoted shell text is a definition (or a
// syntax error), so that one needs no position at all.
const CMD_POS = String.raw`(?:^|[;&|(){}\n\x60])\s*(?:(?:!|do|then|else|elif|if|while|until|time)\s+|[A-Za-z_]\w*=\S*\s+)*(?:\S*/)?`
const ANY_FUNCTION_DEF_RX = /[\w.:-]+\s*\(\s*\)/
const SHADOW_ANYWHERE_RX = new RegExp(`${CMD_POS}(?:alias|enable|builtin|command|exec|function)(?=\\s|$)`)
// Builtins that assign a variable the taint tracking cannot see (their NAME is
// not a `NAME=value` word): printf -v, read, mapfile/readarray, getopts, and a
// nameref (declare/local/typeset -n). Once the command references the surface,
// any of them denies -- flat, instead of modelling each one's assignment.
const VAR_WRITER_RX = new RegExp(`${CMD_POS}(?:printf\\s+(?:-[^\\s]*\\s+)*-v\\b|read\\b|mapfile\\b|readarray\\b|getopts\\b|(?:declare|local|typeset)\\s+(?:-\\w+\\s+)*-\\w*n)`)
function wholeCommandShadows(command) {
  const masked = maskInertLiterals(joinShellLines(String(command ?? '')), [], true)
  if (masked == null) return true // unresolvable: fail closed
  return ANY_FUNCTION_DEF_RX.test(masked) || SHADOW_ANYWHERE_RX.test(masked) || VAR_WRITER_RX.test(masked)
}

// The definition/shadow half of wholeCommandShadows, without the variable writers.
function wholeCommandDefines(command) {
  const masked = maskInertLiterals(joinShellLines(String(command ?? '')), [], true)
  return masked == null || ANY_FUNCTION_DEF_RX.test(masked) || SHADOW_ANYWHERE_RX.test(masked)
}

// Builtins that put a shell variable into the ENVIRONMENT of later commands:
// export, declare/typeset/local -x, and set -a / set -o allexport. A program
// reads its environment without spelling `$NAME` on the command line
// (`os.environ['U']`, `process.env.U`), so the taint tracking below cannot see
// that use. Once a variable carries a reference, any of these denies (flat).
const ENV_EXPORT_RX = new RegExp(`${CMD_POS}(?:export(?=\\s|$)|(?:declare|local|typeset)\\s+(?:-\\w+\\s+)*-\\w*x|set\\s+(?:-\\w*a|-o\\s+allexport))`)
function wholeCommandExports(command) {
  const masked = maskInertLiterals(joinShellLines(String(command ?? '')), [], true)
  return masked == null || ENV_EXPORT_RX.test(masked)
}

// The decision for one Bash command. true = deny.
//
// Once the command references the API or the store surface (raw or decoded),
// the check is FLAT and fail-closed -- it does NOT model shell state:
//   1. ANY cd/pushd/popd whose argument references the store denies the whole
//      command. A sub-agent has no reason to enter the schedule store, and this
//      removes the working-directory state machine (and its cd -/OLDPWD/failed-cd
//      bypasses) entirely. (A cd whose effect PERSISTS to a LATER Bash call, if
//      Claude Code keeps the cwd across calls, is outside a per-command gate;
//      rule 1 still denies the cd itself when it appears.)
//   2. ANY function/alias/shadow definition anywhere denies -- it can make an
//      allowed name write.
//   3. Forms (a)/(b)/(c) trust a command only by a bare name or an exact system
//      binary path (commandName), so `/tmp/cat` and `./curl` do not pass.
// The only cross-segment state left is a tainted VARIABLE (`F=<store path>;
// cat >> $F`): a value carrying a reference taints its name, and a later use of
// it counts as a reference. That only ADDS denials.
export function scheduleSurfaceDeny(command, gateOpts = {}) {
  const opts = { parentCtx: cdsIntoStoreParent(command), projectRoot: gateOpts.projectRoot, selfAgent: gateOpts.selfAgent }
  const whole = scheduleSurfaceRefs(command, opts)
  const wholeStrong = strongRef(whole)
  if (!wholeStrong && !whole.db) return false
  const segs = shellSegments(command, opts)
  if (!segs) return true // unresolvable quoting around a reference: fail closed

  const tainted = new Set()
  const dbTainted = new Set()
  const usesVar = (set, text) => [...set].some((v) => new RegExp(`\\$\\{?${v}(?!\\w)`).test(text))
  // Once a schedule reference is present, a token-file mention other than an
  // accepted `$(cat <token file>)` (already replaced by the nonce) is one too:
  // `echo ... > <root>/store/.dashboard-token; curl -q ... $(cat <it>)` would
  // otherwise rewrite the file between the gate's content check and curl.
  const tokenMention = (text) => wholeStrong && scheduleSurfaceVariants(text).some((v) => /dashboard[-_.]?token/i.test(v))
  const refsIn = (text) => strongRef(scheduleSurfaceRefs(text, opts)) || usesVar(tainted, text) || tokenMention(text)
  const dbRefsIn = (text) => scheduleSurfaceRefs(text, opts).db || usesVar(dbTainted, text)
  // A redirect target may not reference the store or the database (a tainted
  // var or the path).
  const redirectsOk = (words) => words.redirects.every((t) => t.value === '/dev/null' || (!refsIn(t.value) && !dbRefsIn(t.value)))

  // Flat invariant 2 (and the variable writers), over the whole command at every
  // command position -- a subshell/group opener is not a segment start. A
  // command that names only the database file gets the definition/shadow part:
  // a reader that pipes into `while read` must keep working.
  if (wholeStrong ? wholeCommandShadows(command) : wholeCommandDefines(command)) return true

  // Flat invariants 1 & 2, scanned across EVERY segment (a shadow/def or a cd
  // segment need carry no reference of its own).
  for (const seg of segs) {
    const own = seg.own.slice((CONTROL_PREFIX_RX.exec(seg.own)?.[0] ?? '').length).trimStart()
    if (FUNCTION_DEF_RX.test(own)) return true // rule 2: `name() {`
    const first = /^([\w./-]+)/.exec(own)?.[1] ?? ''
    const base = first.slice(first.lastIndexOf('/') + 1)
    if (SHADOW_WORDS.has(base)) return true // rule 2: alias/enable/builtin/command/exec/function
    if ((base === 'cd' || base === 'pushd' || base === 'popd') && refsIn(seg.text)) return true // rule 1
  }

  let carried = false
  for (let k = 0; k < segs.length; k++) {
    const seg = segs[k]
    const own = seg.own.slice((CONTROL_PREFIX_RX.exec(seg.own)?.[0] ?? '').length)
    if (CONTROL_ALONE_RX.test(own.trim()) && !seg.bodies.length) continue
    const view = { ...seg, own, text: [own, ...seg.bodies].join('\n') }
    const strong = refsIn(view.text)
    const db = !strong && dbRefsIn(view.text)
    if (!strong && !db) continue // no reference in this segment -> not this segment's problem
    carried = true
    const words = shellWords(own)
    if (!words) return true
    // Only redirections / a bare heredoc, no command word: not a known form, and
    // a bare `> file` truncates. (Guards words[0] too: a throw here exits 1,
    // which PreToolUse does not block.)
    if (!words.length) return true
    if (!redirectsOk(words)) return true
    const names = assignedNames(words)
    if (names) { names.forEach((n) => (strong ? tainted : dbTainted).add(n)); continue } // an assignment writes nothing
    if (words[0].value === 'for' && /^[A-Za-z_]\w*$/.test(words[1]?.value ?? '')) { (strong ? tainted : dbTainted).add(words[1].value); continue }
    const name = commandName(words) // '' for an untrusted path -> matches no form -> deny
    if (db) {
      if (dbSegmentWrites(words, name, view.text)) return true
      continue
    }
    // A reference that sits in a heredoc body, with the command's output going
    // to a file: `cat <<'X' > /tmp/s.sh ... X; bash /tmp/s.sh`. The file is a
    // script the next segment can run, so no redirect but /dev/null is
    // accepted there -- whatever the consumer (message carriers included).
    if (seg.bodies.length && refsIn(seg.bodies.join('\n')) && words.redirects.some((t) => t.value !== '/dev/null')) return true
    if (!refsIn(dataResidue(view, words, name))) continue // (c) only message data mentions it
    if (name === 'curl' && isPlainCurlGet(words)) continue // (a)
    if (isReadOnlyFsCommand(words, name) && pipesOnlyIntoSinks(segs, k, redirectsOk)) continue // (b)
    // the registry tool's read-only subcommands, and git on its source
    const r = scheduleSurfaceRefs(view.text, opts)
    const cliOnly = r.cli && !r.api && !r.dir && !r.sql && !usesVar(tainted, view.text) && !tokenMention(view.text)
    if (cliOnly && (isRegistryCliRead(words, name) || isGitSourceCommand(words, name)) && pipesOnlyIntoSinks(segs, k, redirectsOk)) continue
    return true
  }
  // A variable that carries a reference must not reach a program's environment.
  if (tainted.size && wholeCommandExports(command)) return true
  // The whole command references the surface but no single segment does: the
  // reference only exists across a boundary this parser drew. Fail closed.
  return !carried
}

// Native file tools: a path through a *scheduled-tasks directory (same scope
// as SCHEDULE_DIR_REF_RX, see there).
const SCHEDULE_DIR_PATH_RX = /scheduled-tasks([/\\]|$)/i

// Pure decision: does this tool call set up self-pace / self-injection?
// Any exception inside the decision is a DENY: a gate that throws must never
// be read as "nothing to block" (see also the hook entry below).
export function gateDecision(toolName, toolInput, opts = {}) {
  try {
    return decide(toolName, toolInput, opts)
  } catch (err) {
    return { deny: true, error: String(err?.stack ?? err) }
  }
}

function decide(toolName, toolInput, opts = {}) {
  const name = String(toolName ?? '')
  if (SELF_PACE_TOOLS.has(name)) return { deny: true }
  // Native file tools writing the self-schedule store would bypass any Bash regex.
  if (name === 'Write' || name === 'Edit' || name === 'MultiEdit' || name === 'NotebookEdit') {
    const fp = String(toolInput?.file_path ?? toolInput?.notebook_path ?? '')
    if (SCHEDULE_STORE_RX.test(fp)) return { deny: true }
    if (fileToolTargetsAllowlist(toolInput, opts.allowlistPath, opts.cwd)) return { deny: true, reason: 'egress-allowlist' }
    if (fileToolTargetsProtectedStoreFile(toolInput, opts.storeDir, opts.cwd)) return { deny: true, reason: 'protected-store-file' }
    // ...and the dashboard's schedule store, which the runner turns into turns
    if (SCHEDULE_DIR_PATH_RX.test(fp)) return { deny: true }
  }
  if (name === 'Bash') {
    // Line continuations are resolved ONCE here, the way the shell lexer does it (joinShellLines, the one
    // shared join); every helper below joins again on its own entrance, which is a no-op on this text.
    // A reading the joiner is not sure of (unterminated quote or heredoc, a continuation inside backticks
    // or arithmetic) must not let anything through: with a backslash-newline in the command, DENY.
    const joinInfo = {}
    const command = joinShellLines(String(toolInput?.command ?? ''), joinInfo)
    if (!joinInfo.exact && /\\\n/.test(String(toolInput?.command ?? ''))) return { deny: true, reason: 'ambiguous-continuation' }
    // The schedule surface is judged on the command BEFORE the payload and
    // commit-message blanking below: that blanking is regex-based and trusts a
    // `-d` wherever it appears (`python3 -c CODE -d URL` would blank the URL),
    // so this check does its own grammar-aware data removal instead.
    if (scheduleSurfaceDeny(command, opts)) return { deny: true }
    // Strip -d/--data payloads on the WHOLE command BEFORE splitting. A payload is
    // data, not an invocation; and since splitSegments is NOT quote-aware, a shell
    // separator (; && | &) INSIDE a dispatch body would otherwise orphan a fragment
    // that false-matches. Stripping first blanks the body (incl. any separators in
    // it), so the URL/method args still match but the body text never does. A
    // separator OUTSIDE the payload still splits, so `curl -d '' x ; crontab -r`
    // is still caught.
    const safeCommand = stripProseArguments(stripDataPayloads(stripGitCommitMessages(stripHeredocBodies(command))))
    // Per-segment so an unrelated token elsewhere in a compound command cannot
    // turn a legit read (store inspection, schedule-API GET) into a false deny.
    const naiveSegs = splitSegments(safeCommand)
    // Every check below runs on the naive segments AND on maskedSegments (card 0bb35172, finding 3660cf43 B4): the
    // masked pass is cut where the SHELL cuts (never inside a quote) and has the literal text blanked, so a quoted
    // newline or `;` can no longer split the dangerous pair in two. It only ADDS segments: nothing below `continue`s
    // or allows because of it, and it is not skipped when the lexer is unsure of its reading.
    for (const seg of [...naiveSegs, ...maskedSegments(safeCommand)]) {
      // Match the self-pace bash patterns against the shell-normalised segment so a
      // `\/loop` / `$IFS/loop` evasion (which bash resolves to `/loop` at exec) is
      // still caught; the scheduler/store/API checks below use the RAW seg (scoped).
      //
      // These stay on the NAIVE segments ON PURPOSE. They are unanchored, so a
      // quoted region is not a hiding place for them -- and the naive scan is
      // what catches a real `subprocess.run(['tmux','send-keys',...])` inside a
      // heredoc body (measured 2026-08-05). Quote-aware segments here would have
      // dropped the detection of this gate's own founding incident vector.
      if (SELF_PACE_BASH_PATTERNS.some((re) => re.test(normalizeShellEvasion(seg)))) return { deny: true }
      // self-schedule store: block WRITE only (a read/grep is legit diagnostics)
      if (SCHEDULE_STORE_RX.test(seg) && WRITE_INTENT_RX.test(seg)) return { deny: true }
      // dashboard schedule API: block WRITE methods only (GET list/pending is legit)
      if (SCHEDULE_API_RX.test(seg) && HTTP_WRITE_RX.test(seg)) return { deny: true }
      // the egress allowlist: a plain read only (EGRESSSELFEDIT824)
      if (!allowlistBashSegmentAllowed(seg)) return { deny: true, reason: 'egress-allowlist' }
      // ...and the other store files that gate the sub-agent (c556a35a)
      if (!protectedStoreBashSegmentAllowed(seg)) return { deny: true, reason: 'protected-store-file' }
    }
    // The scheduler check is the ANCHORED one -- it fires on what sits at a
    // segment START -- so it is the one a fake segment boundary can mislead, and
    // the only one that gets quote-aware segments. Preserve the legacy null fallback,
    // except for shell-dependent dollar quoting, which cannot use read exemptions.
    // The mask leaves the body of a heredoc visible when its owner EXECUTES it (bash <<'EOF', python3 - <<'PY',
    // ssh box <<'EOF'): that body is code, and the anchored check must see it. A reading the lexer is not sure of
    // (joinInfo.exact false) falls back to the naive segments, like an unresolvable mask: doubt scans more.
    const diagnostic = {}
    const bodies = []
    const masked = maskInertLiterals(safeCommand, bodies, false, diagnostic, { keepRunBodies: true })
    if (diagnostic.reason === 'ambiguous-dollar-quote') return { deny: true, reason: diagnostic.reason }
    for (const seg of (masked == null || !joinInfo.exact ? naiveSegs : anchoredSegments(masked, bodies))) {
      // scheduler binaries: deny the exec/submit forms, allow pure read-listing
      if (SCHEDULER_RX.test(seg) && !SCHEDULER_READ_RX.test(seg)) return { deny: true }
    }
  }
  return { deny: false }
}

const GATE_MSG =
  'Self-pace TILTOTT (governance hard-gate). Sub-agentkent NEM utemezhetsz sajat ' +
  'jovobeli turn-t: se ScheduleWakeup/Cron*/RemoteTrigger, se tmux send-keys, se ' +
  'scheduled_tasks.json iras, se /api/schedules iras (semmilyen klienssel: curl, python, node, ' +
  'wget, httpie...; olvasasra csak a `curl -q -s -H "Authorization: Bearer $(cat <TOKEN>)" ' +
  'http://...` GET megy at: -q ELSO argumentumkent, <TOKEN> pedig SZO SZERINT a repo-gyoker abszolut ' +
  '<repo>/store/.dashboard-token, vagy a sajat <repo>/agents/<nev>/.dashboard-token utja -- relativ ut, ~ vagy ' +
  '$HOME nem), se ~/.claude/scheduled-tasks/ iras (olvasni ls/cat/grep/sed -n lehet, ' +
  'de NE cd-vel a store-ba -- abszolut uttal hivatkozz ra), se schedule-registry-cli register/unregister ' +
  '(csak status es verify), se utemezes-tabla SQL-iras vagy a claudeclaw.db fajl felulirasa, ' +
  'se /loop self-pace. Ha csak egy dokumentumot irsz, ami az utemezo API-t vagy a store-t emliti ' +
  '(jegyzet, review-tervezet): a nativ Write tool-lal ird, a store-on kivuli utra -- az atmegy; ' +
  'egy fajlba iranyitott heredoc (cat <<EOF > fajl) nem. Utemezest a fo agenstol kerj inter-agent uzenetben. ' +
  'Input-vezerelt ' +
  'vagy: csak az operator (channel) vagy egy peer (inter-agent) uzenete inditson. Ha varakozol, ' +
  'maradj idle a prompt-on -- a beerkezo uzenet majd ujrainditja a turn-t. SOHA ne valaszolj ' +
  'magadnak es SOHA ne dontsd el az operator helyett egy hozza intezett kerdest.'

const ALLOWLIST_GATE_MSG =
  'Egress-engedelylista TILTOTT (governance hard-gate). Sub-agentkent NEM irhatod a ' +
  'store/egress-allowlist.json-t: ez a kapu RAD vonatkozik. Ha egy domain kell, kerd a fo ' +
  'agenst (inter-agent uzenet: domain + miert); o a gazda jovahagyasaval veszi fel. ' +
  'Olvasni szabad: cat / grep / jq a fajlra (ertelmezo -- python, node -- nem).'

const PROTECTED_STORE_GATE_MSG =
  'Vedett store-fajl TILTOTT (governance hard-gate). Sub-agentkent NEM irhatod a ' +
  'store/egress-vendor-hosts.json, store/config-overrides.json, store/bash-sandbox-write-paths.json, store/bash-sandbox-hosts.json, ' +
  'store/email-standing-recipients.json, store/.approval-bot-token es store/.approval-bot-key ' +
  'fajlt: mindegyik RAD vonatkozo kapu beallitasa. ' +
  'Ha valtoztatas kell, kerd a fo agenst (inter-agent uzenet: mit es miert); o a gazda ' +
  'jovahagyasaval irja. Olvasni szabad: cat / grep / jq a fajlra (ertelmezo -- python, node -- nem).'

function allow() { process.exit(0) }

function deny(reason) {
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: {
      hookEventName: 'PreToolUse',
      permissionDecision: 'deny',
      permissionDecisionReason: reason,
    },
  }))
  process.exit(0)
}

function isInvokedDirectly() {
  try {
    const self = realpathSync(fileURLToPath(import.meta.url))
    const entry = process.argv[1] ? realpathSync(process.argv[1]) : ''
    return self === entry
  } catch {
    return false
  }
}

// The hook entry. PreToolUse reads exit 2 as "block", exit 0 as "allow" (unless
// a deny is printed) -- and exit 1, or a hook killed by the harness timeout, as
// a NON-blocking error: the tool call runs as if the gate had not been there.
// So nothing on this path may end in a crash or a hang:
//   - the decision runs in a worker thread with a deadline; a decision that
//     throws, never answers, or outlives the deadline (a pathological regex
//     backtrack blocks a thread, it cannot be interrupted from inside) is a
//     DENY, printed by the main thread, which stays responsive;
//   - uncaughtException / unhandledRejection on the main thread deny as well.
// Measured cost of the worker: about +100 ms per call (whole hook process,
// median of 20 runs: 200 ms vs 100 ms without it, node 22, Linux).
//
// Stated exception: stdin that is not JSON still ALLOWS (unchanged). It comes
// from the harness, not from the agent, and a gate that blocks every tool on a
// harness glitch takes the whole fleet down (hook-exit-code-invariant pins it).
const DECISION_DEADLINE_MS = Math.min(5000, Math.max(100, Number(process.env.SELF_PACE_GATE_DEADLINE_MS) || 5000))

const FAIL_CLOSED_MSG = (why) => 'Self-pace kapu: belso hiba vagy idotullepes a vizsgalat kozben ' +
  `(${String(why).slice(0, 200)}). Fail-closed: a hivas nem vizsgalhato, ezert TILTVA. ` + GATE_MSG

function decideInWorker(toolName, toolInput, opts = {}) {
  return new Promise((resolve, reject) => {
    const w = new Worker(new URL(import.meta.url), {
      workerData: { selfPaceGateWorker: true, toolName, toolInput, opts },
    })
    const timer = setTimeout(() => {
      w.terminate()
      reject(new Error(`decision exceeded ${DECISION_DEADLINE_MS} ms`))
    }, DECISION_DEADLINE_MS)
    w.once('message', (m) => {
      clearTimeout(timer)
      w.terminate()
      if (m?.ok === true && typeof m.deny === 'boolean') resolve(m)
      else reject(new Error(m?.error ?? 'malformed verdict from the decision worker'))
    })
    w.once('error', (e) => { clearTimeout(timer); reject(e) })
    w.once('exit', (code) => { clearTimeout(timer); reject(new Error(`decision worker exited ${code} without a verdict`)) })
  })
}

if (!isMainThread && workerData?.selfPaceGateWorker) {
  try {
    const verdict = gateDecision(workerData.toolName, workerData.toolInput, workerData.opts ?? {})
    parentPort.postMessage({ ok: true, deny: verdict.deny === true, reason: verdict.reason, error: verdict.error })
  } catch (err) {
    parentPort.postMessage({ ok: false, error: String(err?.stack ?? err) })
  }
} else if (isMainThread && isInvokedDirectly()) {
  process.on('uncaughtException', (err) => deny(FAIL_CLOSED_MSG(err?.message ?? err)))
  process.on('unhandledRejection', (err) => deny(FAIL_CLOSED_MSG(err?.message ?? err)))
  let payload
  try {
    payload = JSON.parse(readFileSync(0, 'utf-8'))
  } catch {
    allow() // malformed/empty input must never break the agent's tool calls
  }
  try {
    const selfAgent = selfAgentFromProjectDir(process.env.CLAUDE_PROJECT_DIR)
    const verdict = await decideInWorker(payload?.tool_name, payload?.tool_input, { cwd: payload?.cwd, selfAgent })
    if (verdict.error) deny(FAIL_CLOSED_MSG(verdict.error.split('\n')[0]))
    if (verdict.deny) {
      deny(verdict.reason === 'egress-allowlist' ? ALLOWLIST_GATE_MSG
        : verdict.reason === 'protected-store-file' ? PROTECTED_STORE_GATE_MSG : GATE_MSG)
    }
    allow()
  } catch (err) {
    deny(FAIL_CLOSED_MSG(err?.message ?? err))
  }
}
