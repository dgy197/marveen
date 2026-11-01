#!/usr/bin/env node
// PreToolUse hard-gate: blocks outbound email-send for sub-agents.
//
// Governance control (Szabi 2026-06-25, after the Boni incident: a sub-agent
// autonomously emailed a fabricated address asking for money in Szabi's name).
// Sub-agents may NOT send outbound email; any email must be routed through the
// main agent (Marveen) for approval -- only Marveen retains email-send.
//
// STATED LIMIT (msg 14298): this gate catches the ACCIDENTAL send, not a
// determined evader. Static analysis of arbitrary interpreter code is
// undecidable, so a sub-agent CAN send through interpreter code the patterns
// do not model -- the premise "a sub-agent cannot send outbound" does NOT
// hold against intent, only against accident. The exec-heuristic below covers
// the naive shapes (process-spawn plus a known mailer name in one code
// string) and claims no more. Our sub-agents are not adversaries; if that
// assumption ever changes, this gate is the wrong tool.
//
// Why a hook and not a permissions deny-list: the hook is version- and
// mode-independent, and it can analyze command CONTENT (the Bash send-shape
// heuristics below), which a name/prefix deny rule cannot express.
// CORRECTION (SKIPDENY910, measured 2026-09-10): this comment used to claim
// that --dangerously-skip-permissions BYPASSES the settings.json deny list.
// That is false on every CLI version we measured (2.1.63, 2.1.110, 2.1.267;
// marker-file ground truth, deny arm vs no-deny control, -p AND interactive
// TUI): the deny list IS enforced under the flag, and a tool-name deny is
// enforced by removing the tool from the session entirely. The hook remains
// the primary gate anyway -- future CLI behavior is not a contract, and the
// deny list stays a second, independent layer, not the load-bearing one.
//
// This file is wired into every sub-agent's .claude/settings.json by
// writeAgentSettingsFromProfile() (agent-scaffold.ts), guarded by
// name !== MAIN_AGENT_ID, and re-applied on every spawn (respawn-safe).

import { closeSync, openSync, readdirSync, readFileSync, readSync, realpathSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, isAbsolute, join, resolve } from 'node:path'
import { homedir } from 'node:os'

// HOOKDEPLOAD1008: the ledger module is a DYNAMIC import. As a static import, a
// broken recipient-ledger.mjs (a syntax error, a conflicted merge, a missing
// export) failed the module link before any line of this file ran: node exited
// 1, which PreToolUse treats as NON-blocking, so EVERY call went through
// unchecked -- the send_email deny included, which never needs the ledger.
// Now the failure is kept, only a decision that needs the ledger hits it, and
// that one fails closed at the entrypoint (exit 2, the reason on stderr).
let loadLedger, isVerifiedIn, splitAddresses, parseAddresses, SOURCE_HELP
let LEDGER_LOAD_ERROR = null
try {
  ({ loadLedger, isVerifiedIn, splitAddresses, parseAddresses, SOURCE_HELP } = await import('./recipient-ledger.mjs'))
  const missing = Object.entries({ loadLedger, isVerifiedIn, splitAddresses, parseAddresses })
    .filter(([, fn]) => typeof fn !== 'function').map(([name]) => name)
  if (missing.length) throw new Error(`missing export: ${missing.join(', ')}`)
} catch (err) {
  LEDGER_LOAD_ERROR = err
  const unavailable = () => { throw new Error(`recipient-ledger.mjs did not load: ${err?.message ?? err}`) }
  loadLedger = isVerifiedIn = splitAddresses = parseAddresses = unavailable
  SOURCE_HELP = '(a ledger modul nem toltheto be)'
}

// Bash command patterns that send mail. SUBGATEPOZ822 (2026-08-22): these are
// no longer the primary trigger -- they matched CONTENT anywhere in the
// command string, and the header's old premise ("a sub-agent has no
// legitimate need to invoke these") broke measurably: the developer of the
// mail tooling IS a sub-agent, and the gate blocked the delivery of the
// mail-gate fix three times in one afternoon (commit message, PR body,
// card-comment sqlite write), plus five more content hits across the fleet
// the same day. The primary trigger is now isSendInvocation() below
// (command-position analysis); this list remains ONLY as the conservative
// fallback when a command cannot be tokenized (unbalanced quote) -- on
// unparseable input the gate behaves exactly as before, never weaker.
const SEND_PATTERNS = [
  /support-mail\/send\.py/i,
  /\bsend\.py\b/i,
  /api\.resend\.com/i,
  /\bresend\b[^\n]*\b(email|send|message)\b/i,
  /\bsendmail\b/i,
  /\bmsmtp\b/i,
  /\bswaks\b/i,
  /\bsmtplib\b|SMTP\s*\(/i,
  /\bmail\.send\b|\bsendEmail\b/i,
  // graph-mail.ts (PR #668, M365/Exchange Online client-credentials mailbox):
  // its CLI is `tsx scripts/graph-mail.ts send ...`, which none of the above
  // patterns catch (no "sendmail"/"mail.send" substring). Also gate any direct
  // call to the exported sendMail() (e.g. a one-off `node -e`/`tsx -e` that
  // imports the module without going through the CLI).
  // graph-forward (Brainy 2958): the CLI gained `forward`, and on an unparseable
  // command the subcommand cannot be located, so ANY mention of graph-mail counts
  // (it used to need the word `send` after it). Same literal as the python twin's
  // _FALLBACK_LITERALS, which had no graph-mail at all (T3).
  /\bgraph-mail\b/i,
  /\bsendMail\s*\(/i,
  /\bforwardMail\s*\(/i,
]

// --- command-position analysis (SUBGATEPOZ822) ------------------------------
// Ported from scripts/hooks/outgoing-copy-gate.py (KAPUHATOKOR822, PR #1042,
// two adversarial rounds): quote-aware tokenization, then the INVOKED program
// of each pipeline/sequence segment decides. A quoted token keeps its
// POSITION, so a quoted provider URL in curl argument position still fires
// (the normal way curl is written), while the same domain inside a quoted -d
// payload stays content (the target pattern is anchored to the token start).
// Wrapper-shell -c strings recurse; interpreter code-string arguments
// (python -c / node -e) are scanned for code-level send calls -- code handed
// to an interpreter IS operation, not content.
// Order-independent heredoc stripping (round 3, msg 14286): the rest of
// the intro line (e.g. a redirect after the marker) is command text and
// is KEPT -- only the body is cut. Without this, marker-first spellings
// leaked the body into command position (FP), and dropping the intro
// would have lost a heredoc-fed real sender (FN).
const HEREDOC_RE = /(<<-?\s*'?(\w+)'?[^\n]*)\n[\s\S]*?\n\2(?=\s|$)/g
const ENV_ASSIGN = /^[A-Za-z_][A-Za-z_0-9]*=/
// KWSPLIT924: shell reserved words that put the NEXT word in command position.
// Stripped only at the head of a segment, never used as separators -- see the
// full rationale at _CMD_POSITION_KEYWORDS in outgoing-copy-gate.py (the python
// twin); the shared send-invocation-cases.json binds the two copies.
const CMD_POSITION_KEYWORDS = new Set(['if', 'then', 'else', 'elif', 'do', 'while', 'until', '{', '!'])
const SENDER_PROG = /^(sendmail|msmtp|swaks)$/i
const SENDPY = /^send\.py$/i
// SUBAGENTMAILGATE1016: a version-suffixed interpreter (python3.12, python3.13, and
// the free-threaded python3.13t) is the same python; the old /^python3?$/ let it
// through as "not an interpreter".
const PYTHON = /^python(3(\.\d+t?)?)?$/i
const NODEISH = /^(node|tsx|ts-node|deno|bun|npx)$/i
const GRAPHMAIL = /^graph-mail(\.ts|\.js)?$/i
// graph-forward (Brainy 2958): the CLI dispatches on the one word after its file
// name; verify/list/show are the reads, every other word (forward, send, FORWARD,
// `--`, a flag, a $VAR, nothing) is a send. Applies where the CLI RUNS: the file in
// program position, or behind a node-like or package runner. See _GRAPHMAIL_READS
// in hooks/outgoing-copy-gate.py (the python twin) for the full rationale.
const GRAPHMAIL_READS = new Set(['verify', 'list', 'show'])
const GRAPHMAIL_RUNNER = /^(node|nodejs|tsx|ts-node|deno|bun|bunx|npx|pnpx|npm|pnpm|yarn)$/i
// Shared by the `-c` rule, the heredoc-to-shell rules and the pipe rule (card 11f53410: ksh, mksh,
// csh, tcsh and fish were not shells to the gate). Mirrors _WRAPPER_SHELL in outgoing-copy-gate.py.
const WRAPPER_SHELL = /^(sh|bash|zsh|dash|ksh|mksh|csh|tcsh|fish)$/i
const CURLISH = /^(curl|wget|http)$/i
const RESEND_TARGET = /^(https?:\/\/)?([^/@\s]*\.)?api\.resend\.com(\/|$)/i
// RESENDGETTWIN1010: port of the python twin's method verdict (RESENDGATE826,
// outgoing-copy-gate.py :: _curl_resend_verdict). Until now this copy was
// method-blind and denied a read-only GET /domains the python copy passed.
// Strict direction kept: the method must be RECOGNIZED (explicit -X/--request/
// --method, or an implicit POST from a body flag); an undecidable method
// (variable, truncated flag, config file) stays a send. httpie (`http`) takes
// its method positionally and its body as `key=value` items, none of which this
// flag scan reads, so it is undecidable too and stays a send in both twins.
const HTTPIE = /^http$/i
const CURL_BODY_OPTS = new Set([
  '-d', '--data', '--data-raw', '--data-binary', '--data-urlencode',
  '--data-ascii', '-F', '--form', '--form-string', '--json',
  '-T', '--upload-file',
  // wget body flags
  '--post-data', '--post-file', '--body-data', '--body-file',
])
const SAFE_METHODS = new Set(['GET', 'HEAD'])
const ALPHA = /^\p{L}+$/u // python str.isalpha()

// 'read' | 'send' | 'unknown' -- the caller treats unknown as a send.
function curlResendVerdict(prog, rest) {
  if (HTTPIE.test(prog)) return 'unknown'
  let method = null
  let hasBody = false
  let getForced = false
  const n = rest.length
  for (let i = 0; i < n; i++) {
    const t = rest[i]
    if (t === '-X' || t === '--request' || t === '--method') {
      if (i + 1 >= n || !ALPHA.test(rest[i + 1])) return 'unknown'
      method = rest[i + 1].toUpperCase()
      i++
      continue
    }
    if (t.startsWith('--request=') || t.startsWith('--method=')) {
      const m = t.split('=').slice(1).join('=')
      if (!ALPHA.test(m)) return 'unknown'
      method = m.toUpperCase()
      continue
    }
    if (t === '-G' || t === '--get') { getForced = true; continue }
    if (t === '-K' || t === '--config') return 'unknown' // a config file can carry a hidden method or body
    if (CURL_BODY_OPTS.has(t) ||
        [...CURL_BODY_OPTS].some((o) => o.startsWith('--') && t.startsWith(o + '='))) {
      hasBody = true
      continue
    }
    if (t.startsWith('-') && !t.startsWith('--') && t.length > 1) {
      // single-dash cluster (-sS, -sX POST, -sd '{}'): the letters are bundled
      const letters = t.slice(1)
      if (letters.includes('X')) {
        const after = letters.slice(letters.indexOf('X') + 1)
        if (after) {
          if (!ALPHA.test(after)) return 'unknown'
          method = after.toUpperCase()
        } else {
          if (i + 1 >= n || !ALPHA.test(rest[i + 1])) return 'unknown'
          method = rest[i + 1].toUpperCase()
          i++
        }
      } else if (letters.includes('d') || letters.includes('F') || letters.includes('T')) {
        hasBody = true
      } else if (letters.includes('G')) {
        getForced = true
      } else if (letters.includes('K')) {
        return 'unknown'
      }
    }
  }
  if (method !== null && !SAFE_METHODS.has(method)) return 'send'
  // implicit POST (the default of curl -d/-F/--json/-T), or a suspicious
  // "GET with a body" -- both are treated as a send
  if (hasBody && !getForced) return 'send'
  return 'read'
}
// forwardMail: the Graph sender's second outbound export (graph-forward, Brainy 2958).
const CODE_SEND = /\bsmtplib\b|SMTP\s*\(|\bsendMail\s*\(|\bforwardMail\s*\(|\bsendEmail\b|\bmail\.send\b/i
// Naive-shape exec heuristic (msg 14298): process-spawn AND a known mailer
// name together in one interpreter code string. Covers the accidental shapes;
// see the STATED LIMIT in the header for what it deliberately does not claim.
const CODE_EXECISH = /\bsubprocess\b|os\.system|\bpopen\b|child_process|\bexec[A-Za-z]*\s*\(|\bspawn[A-Za-z]*\s*\(/i
const CODE_SENDER_LIT = /sendmail|msmtp|swaks|send\.py/i
// Issue #1853 (stylnet): the support-mail sender LOADED AS A MODULE (`import send`,
// `from send import main`, runpy, __import__/import_module, a spec built from send.py).
// Case-sensitive on purpose; `send` must be the whole module name. Mirrors
// _CODE_SEND_MODULE in hooks/outgoing-copy-gate.py; send-invocation-cases.json binds them.
const CODE_SEND_MODULE = new RegExp(
  String.raw`\bimport\s+(?:[\w.]+\s*,\s*)*send\b(?![\w.])` +
  String.raw`|\bfrom\s+send\s+import\b` +
  String.raw`|\brunpy\b[^\n]*\bsend\b` +
  String.raw`|\b(?:__import__|import_module)\s*\(\s*['"]send['"]` +
  String.raw`|\bspec_from_file_location\b[^\n]*\bsend\.py\b` +
  // The same class on the Graph sender (export sendMail): renamed on import, or a string key.
  String.raw`|\bsendMail\s+as\b|\[\s*['"]sendMail['"]\s*\]` +
  // ... and on its forward export (graph-forward, Brainy 2958).
  String.raw`|\bforwardMail\s+as\b|\[\s*['"]forwardMail['"]\s*\]`,
)
const codeStringSends = (code) =>
  CODE_SEND.test(code) || CODE_SEND_MODULE.test(code) || (CODE_EXECISH.test(code) && CODE_SENDER_LIT.test(code))

// Index of the quote that closes the ANSI-C string opened by `$'` at i, or -1.
function ansiCEnd(cmd, i) {
  for (let j = i + 2; j < cmd.length; j++) {
    if (cmd[j] === '\\' && j + 1 < cmd.length) { j++; continue }
    if (cmd[j] === "'") return j
  }
  return -1
}

// A word starts after one of these (or at the start): where `#` opens a comment.
const WORD_BREAK = ' \t\n;&|()<>`'

// Unquoted newline / backtick / `$(` become segment separators; quoted text is
// untouched (it is content). Tracks quote state by hand -- no shell involved.
// QUOTEPARITY1018 (graph-forward, Brainy 2958): `$'...'` (ANSI-C, where `\'` is an
// escaped quote, not the end) is rewritten into a plain single-quoted string with
// the shell's boundaries (`$$` consumed first), the `$` of `$"..."` is dropped, an
// unquoted backslash-newline (line continuation) is removed, and with comments=true
// a `#` at the start of a word skips to the end of its line, raw, as the shell
// does; comments=false reads every word. The same fixes, with the measured cases,
// as _mask_subshell_markers in hooks/outgoing-copy-gate.py (the python twin).
export function maskSubshellMarkers(cmd, comments = true) {
  let out = ''
  let q = null
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (q) {
      if (ch === '\\' && q === '"' && i + 1 < cmd.length) { out += cmd[i] + cmd[i + 1]; i++; continue }
      if (ch === q) q = null
      out += ch
      continue
    }
    if (comments && ch === '#' && (i === 0 || WORD_BREAK.includes(cmd[i - 1]))) {
      const j = cmd.indexOf('\n', i)
      if (j === -1) break
      i = j - 1 // the newline itself stays: it ends the command
      continue
    }
    if (ch === "'" || ch === '"') { q = ch; out += ch; continue }
    if (ch === '\\' && cmd[i + 1] === '\n') { i++; continue }
    if (ch === '\\' && i + 1 < cmd.length) { out += cmd[i] + cmd[i + 1]; i++; continue }
    if (ch === '\n' || ch === '`') { out += ';'; continue }
    if (ch === '$' && cmd[i + 1] === '(') { out += ';'; i++; continue }
    if (ch === '$' && cmd[i + 1] === '$') { out += '$$'; i++; continue }
    if (ch === '$' && cmd[i + 1] === '"') continue
    if (ch === '$' && cmd[i + 1] === "'") {
      const j = ansiCEnd(cmd, i)
      if (j !== -1) {
        out += "'" + cmd.slice(i + 2, j).split("\\'").join(`'"'"'`) + "'"
        i = j
        continue
      }
    }
    out += ch
  }
  return out
}

const HEREDOC_STICKY = new RegExp(HEREDOC_RE.source, 'y')

// The heredocs of cmd, in order: HEREDOC_RE matches whose `<<` is NOT inside quotes. A quoted
// `<<` (`echo "<<EOF"`) is text, and taking it for a heredoc dropped the commands after it as
// a body (H1, card 11f53410). The quote scan skips each heredoc BODY it finds, so an
// apostrophe in prose does not flip the state for the next one. Read with and without shell
// comments like the classifier itself and the matches of both readings are united: a `<<`
// counts as text only when BOTH readings see it quoted. Mirrors _heredoc_matches in
// hooks/outgoing-copy-gate.py.
let heredocCache = { cmd: null, out: null } // one scan per command string, not one per caller
function heredocMatches(cmd) {
  if (heredocCache.cmd === cmd) return heredocCache.out
  const found = new Map()
  const n = cmd.length
  for (const comments of [true, false]) {
    let i = 0
    let q = null
    while (i < n) {
      const ch = cmd[i]
      if (q) {
        if (ch === '\\' && q === '"') { i += 2; continue }
        if (ch === q) q = null
        i++
        continue
      }
      if (ch === '\\') { i += 2; continue }
      if (ch === '$' && cmd[i + 1] === "'") {
        const j = ansiCEnd(cmd, i)
        if (j !== -1) { i = j + 1; continue }
      }
      if (ch === "'" || ch === '"') { q = ch; i++; continue }
      if (comments && ch === '#' && (i === 0 || WORD_BREAK.includes(cmd[i - 1]))) {
        const j = cmd.indexOf('\n', i)
        i = j === -1 ? n : j
        continue
      }
      if (ch === '<' && cmd.startsWith('<<', i)) {
        HEREDOC_STICKY.lastIndex = i
        const m = HEREDOC_STICKY.exec(cmd)
        if (m) {
          if (!found.has(m.index)) found.set(m.index, m)
          i = m.index + m[0].length
          continue
        }
      }
      i++
    }
  }
  const out = []
  let lastEnd = 0
  for (const start of [...found.keys()].sort((a, b) => a - b)) {
    if (start >= lastEnd) { const m = found.get(start); out.push(m); lastEnd = start + m[0].length }
  }
  heredocCache = { cmd, out }
  return out
}

// cmd with every heredoc body cut and its opening line kept (was cmd.replace(HEREDOC_RE, '$1')).
function stripHeredocBodies(cmd) {
  let out = ''
  let last = 0
  for (const m of heredocMatches(cmd)) {
    out += cmd.slice(last, m.index) + m[1]
    last = m.index + m[0].length
  }
  return out + cmd.slice(last)
}

// Quote-aware tokenizer -> [[token, ...], ...] per segment. Throws on an
// unbalanced quote (the caller falls back to the legacy content patterns).
export function segmentsTokens(cmd, comments = true) {
  const s = maskSubshellMarkers(stripHeredocBodies(cmd), comments)
  const segments = []
  let cur = []
  let tok = ''
  let hasTok = false
  let q = null
  const pushTok = () => { if (hasTok) { cur.push(tok); tok = ''; hasTok = false } }
  const pushSeg = () => { pushTok(); if (cur.length) { segments.push(cur); cur = [] } }
  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (q) {
      if (ch === '\\' && q === '"' && i + 1 < s.length) { tok += s[++i]; continue }
      if (ch === q) { q = null; continue }
      tok += ch
      continue
    }
    if (ch === "'" || ch === '"') { q = ch; hasTok = true; continue }
    if (ch === '\\' && i + 1 < s.length) { tok += s[++i]; hasTok = true; continue }
    if (ch === ' ' || ch === '\t') { pushTok(); continue }
    if ('|&;()'.includes(ch)) { pushSeg(); continue }
    tok += ch
    hasTok = true
  }
  if (q) throw new Error('unbalanced quote')
  pushSeg()
  return segments
}

const basename = (t) => t.split('/').pop()

// The segments of the comment reading AND the no-comment reading together
// (QUOTEPARITY1018); a reading that does not parse contributes nothing.
function bothReadings(cmd) {
  const segs = []
  for (const comments of [true, false]) {
    try { segs.push(...segmentsTokens(cmd, comments)) } catch { /* unparseable reading */ }
  }
  return segs
}

// SENDWRAP924: a wrapper in front of the sender is stepped over WITH its own
// flags -- see the full rationale at _WRAPPERS in outgoing-copy-gate.py (the
// python twin). An unknown long flag without `=` is read both ways, so it errs
// toward auditing. send-invocation-cases.json binds the two copies.
const WRAPPERS = new Map([
  ['time', ['fo', ['format', 'output'], 0]],
  ['sudo', ['ughpCUrtDRT', ['user', 'group', 'host', 'prompt', 'close-from', 'other-user',
    'role', 'type', 'chdir', 'chroot', 'command-timeout'], 0]],
  ['env', ['uCS', ['unset', 'chdir', 'split-string'], 0]],
  ['nohup', ['', [], 0]],
  ['nice', ['n', ['adjustment'], 0]],
  ['exec', ['a', [], 0]],
  ['command', ['', [], 0]],
  ['xargs', ['ILnPsdEa', ['arg-file', 'delimiter', 'eof', 'replace', 'max-lines', 'max-args',
    'max-procs', 'max-chars', 'process-slot-var'], 0]],
  ['timeout', ['sk', ['signal', 'kill-after'], 1]],
  ['setsid', ['', [], 0]],
  // Card 11f53410: more programs that run their trailing words -- see _WRAPPERS in
  // outgoing-copy-gate.py (the python twin) for the value flags and the positionals.
  ['caffeinate', ['wt', [], 0]],
  ['stdbuf', ['ioe', ['input', 'output', 'error'], 0]],
  ['unbuffer', ['', [], 0]],
  ['doas', ['uC', [], 0]],
  ['busybox', ['', [], 0]],
  ['flock', ['wE', ['timeout', 'wait', 'conflict-exit-code'], 1]],
  ['script', ['FtcEIOBTmo', ['command', 'log-in', 'log-out', 'log-io', 'log-timing',
    'logging-format', 'timing', 'output-limit', 'echo'], 1]],
  // watch hands its words, joined by spaces, to `sh -c`: the joined rest is judged as a string.
  ['watch', ['nq', ['interval', 'equexit'], 0]],
])
const JOIN_WRAPPERS = new Set(['watch'])
const COMMAND_STRING_WRAPPERS = new Set(['flock', 'script'])
const FIND_EXEC = new Set(['-exec', '-execdir', '-ok', '-okdir'])
const HEAD_DEPTH = 8

// The command of every -exec / -execdir / -ok / -okdir of a find line: the words up to the `;`
// (a `\;` is a `;` token once dequoted) or `+`, or to the end. Scanning resumes AFTER the
// terminator, so a head that itself holds a find is that head's business (no blow-up).
function findExecHeads(toks) {
  const heads = []
  let i = 0
  while (i < toks.length) {
    if (FIND_EXEC.has(toks[i])) {
      let j = i + 1
      while (j < toks.length && toks[j] !== ';' && toks[j] !== '+') j++
      heads.push(toks.slice(i + 1, j))
      i = j + 1
    } else i++
  }
  return heads
}

// The words `env -S` makes of its string (shell quoting rules, no operators); an unbalanced
// quote falls back to whitespace splitting. Mirrors _split_words.
function splitWords(value) {
  const words = []
  let tok = ''
  let has = false
  let q = null
  for (let i = 0; i < value.length; i++) {
    const ch = value[i]
    if (q) {
      if (ch === '\\' && q === '"' && i + 1 < value.length && '"\\'.includes(value[i + 1])) { tok += value[++i]; continue }
      if (ch === q) { q = null; continue }
      tok += ch
      continue
    }
    if (ch === "'" || ch === '"') { q = ch; has = true; continue }
    if (ch === '\\' && i + 1 < value.length) { tok += value[++i]; has = true; continue }
    if (/\s/.test(ch)) { if (has) { words.push(tok); tok = ''; has = false } continue }
    tok += ch
    has = true
  }
  if (q) return value.split(/\s+/).filter(Boolean)
  if (has) words.push(tok)
  return words
}

// [value, next index] when toks[i] is env's -S / -SSTR / --split-string[=STR] (any unambiguous
// prefix of the long name), else null. Mirrors _env_split_string.
function envSplitString(toks, i) {
  const t = toks[i]
  if (t.startsWith('--')) {
    const eq = t.indexOf('=')
    const name = eq < 0 ? t.slice(2) : t.slice(2, eq)
    if (name && 'split-string'.startsWith(name)) {
      if (eq >= 0) return [t.slice(eq + 1), i + 1]
      return [i + 1 < toks.length ? toks[i + 1] : '', i + 2]
    }
    return null
  }
  if (t.startsWith('-') && t.length > 1) {
    let k = -1
    for (let x = 1; x < t.length; x++) if ('uCS'.includes(t[x])) { k = x; break }
    if (k !== -1 && t[k] === 'S') {
      if (k < t.length - 1) return [t.slice(k + 1), i + 1]
      return [i + 1 < toks.length ? toks[i + 1] : '', i + 2]
    }
  }
  return null
}

// GNU parallel runs its command template through a shell; the template is every word up to the
// first `:::` / `::::`. Each word of the option run that could be the template is judged (an
// unknown option errs toward auditing); more than six candidates is an unreadable option run:
// audit (null). Mirrors _parallel_heads.
function parallelHeads(toks) {
  const starts = []
  let x = 1
  let prevDash = false
  while (x < toks.length) {
    const t = toks[x]
    if (t === '--') { starts.push(x + 1); break }
    if (t.startsWith('-') && t.length > 1) { prevDash = true; x++; continue }
    starts.push(x)
    if (!prevDash) break
    prevDash = false
    x++
  }
  const heads = []
  for (const s of starts.slice(0, 6)) {
    const words = []
    for (const t of toks.slice(s)) {
      if (t.startsWith(':::')) break
      words.push(t)
    }
    if (words.length) heads.push(['sh', '-c', words.join(' ')])
  }
  if (starts.length > 6) heads.push(null)
  return heads
}

// MAILGATEUV1020: a project launcher's `run` subcommand in front of the sender --
// see the full rationale at _LAUNCHERS in outgoing-copy-gate.py (the python twin).
// name -> [subcommand, short flags taking a value, long flags taking a value,
// module flags, flag lists measured as complete].
const UV_RUN_LONG_VAL = ['extra', 'no-extra', 'group', 'no-group', 'only-group', 'env-file', 'with',
  'with-editable', 'with-requirements', 'package', 'python-platform', 'index', 'default-index',
  'index-url', 'extra-index-url', 'find-links', 'index-strategy', 'keyring-provider',
  'upgrade-package', 'resolution', 'prerelease', 'fork-strategy', 'exclude-newer',
  'exclude-newer-package', 'no-sources-package', 'reinstall-package', 'link-mode',
  'config-setting', 'config-settings-package', 'no-build-isolation-package', 'no-build-package',
  'no-binary-package', 'cache-dir', 'refresh-package', 'python', 'color', 'allow-insecure-host',
  'directory', 'project', 'config-file']
const LAUNCHERS = new Map([
  ['uv', ['run', 'wifPCp', UV_RUN_LONG_VAL, ['-m', '--module'], true]],
  ['pipx', ['run', '', ['index-url', 'pip-args', 'python', 'spec', 'with'], [], true]],
  ...['poetry', 'pdm', 'hatch', 'pipenv', 'rye', 'conda', 'mamba', 'micromamba']
    .map((n) => [n, ['run', '', [], [], false]]),
])

function launcherHeads(toks, spec, d) {
  const [sub, shortVal, longVal, moduleFlags, complete] = spec
  // The subcommand may follow the launcher's global options (`uv --directory d run`):
  // every word before it is an option or the value right after one.
  let j = -1
  for (let x = 1; x < toks.length; x++) {
    if (toks[x] === sub) { j = x; break }
    if (!toks[x].startsWith('-') && !(x > 1 && toks[x - 1].startsWith('-'))) break
  }
  if (j < 0) return [toks]
  const heads = []
  if (!complete) {
    // An unmeasured launcher's options are unknown, so every word in its option
    // run that could be the program is judged as the program: the word after an
    // option may be that option's value, or the command (Dani's #2086 review:
    // `conda run --no-capture-output -n base python send.py` mixes a flag and a
    // value option, which no single reading of all options fits).
    for (let x = j + 1; x < toks.length; x++) {
      if (toks[x] === '--') { heads.push(toks.slice(x + 1)); break }
      if (toks[x].startsWith('-') && toks[x].length > 1) continue
      heads.push(toks.slice(x))
      if (!(x > j + 1 && toks[x - 1].startsWith('-') && toks[x - 1].length > 1)) break
    }
    if (!heads.length) heads.push([])
    return heads.flatMap((h) => commandHeads(h, d + 1))
  }
  let i = j + 1
  let head = null
  while (i < toks.length) {
    const t = toks[i]
    if (t === '--') { i++; break }
    if (moduleFlags.includes(t)) { head = ['python3', '-m', ...toks.slice(i + 1)]; break }
    if (t.startsWith('--')) {
      const eq = t.indexOf('=')
      if (eq > 0 && moduleFlags.includes(t.slice(0, eq))) { head = ['python3', '-m', t.slice(eq + 1), ...toks.slice(i + 1)]; break }
      i += eq < 0 && longVal.includes(t.slice(2)) ? 2 : 1
      continue
    }
    if (t.startsWith('-') && t.length > 1) {
      let k = -1
      for (let x = 1; x < t.length; x++) if (shortVal.includes(t[x])) { k = x; break }
      i += k === t.length - 1 ? 2 : 1
      continue
    }
    break
  }
  heads.push(head ?? toks.slice(i))
  return heads.flatMap((h) => commandHeads(h, d + 1))
}

function commandHeads(toksIn, d = 0) {
  let toks = toksIn
  while (toks.length && (ENV_ASSIGN.test(toks[0]) || CMD_POSITION_KEYWORDS.has(toks[0]))) toks = toks.slice(1)
  if (!toks.length) return [toks]
  const w = basename(toks[0])
  // Still a wrapper at the depth bound: counts as a send (null), see the python twin.
  if (d >= HEAD_DEPTH) {
    // find with an -exec is a wrapper too: the command it runs is out of sight here
    const isWrapper = WRAPPERS.has(w) || LAUNCHERS.has(w) || w === 'parallel' || w === 'function' || w === 'coproc' ||
      ((w === 'find' || FIND_EXEC.has(toks[0])) && findExecHeads(toks).length > 0)
    return isWrapper ? [null] : [toks]
  }
  if (w === 'function') return commandHeads(toks.slice(2), d + 1)
  if (w === 'coproc') return [...commandHeads(toks.slice(1), d + 1), ...commandHeads(toks.slice(2), d + 1)]
  const launcher = LAUNCHERS.get(w)
  if (launcher) return launcherHeads(toks, launcher, d)
  if (w === 'find' || FIND_EXEC.has(toks[0])) {
    // The find line itself stays a head (graph-mail words in its arguments are judged as before);
    // every -exec / -execdir / -ok / -okdir command is a head of its own. A segment that STARTS
    // with -exec is the tail of a `\;`-split find line (python only; harmless here).
    return [toks, ...findExecHeads(toks).flatMap((h) => commandHeads(h, d + 1))]
  }
  if (w === 'parallel') return [toks, ...parallelHeads(toks)]
  const spec = WRAPPERS.get(w)
  if (!spec) return [toks]
  const [shortVal, longVal, positionals] = spec
  let i = 1
  const starts = []
  let extra = []
  while (i < toks.length) {
    const t = toks[i]
    if (t === '--') { i++; break }
    if (w === 'env') {
      // env -S STR / -SSTR / --split-string=STR: STR is split into words that run as a command
      // line, in front of the words after it (a command string, card 11f53410).
      const sv = envSplitString(toks, i)
      if (sv) {
        extra = commandHeads(['env', ...splitWords(sv[0]), ...toks.slice(sv[1])], d + 1)
        i = toks.length
        break
      }
    }
    if (t.startsWith('--')) {
      if (!t.includes('=') && longVal.includes(t.slice(2))) { i += 2; continue }
      if (!t.includes('=')) starts.push(i + 2)
      i++
      continue
    }
    if (t.startsWith('-') && t.length > 1) {
      if (w === 'command' && (t.includes('v') || t.includes('V'))) return []
      let k = -1
      for (let j = 1; j < t.length; j++) if (shortVal.includes(t[j])) { k = j; break }
      i += k === t.length - 1 ? 2 : 1
      continue
    }
    break
  }
  starts.unshift(i)
  const heads = [...extra]
  for (const s of starts) {
    const rest = toks.slice(s + positionals)
    if (JOIN_WRAPPERS.has(w)) { if (rest.length) heads.push(['sh', '-c', rest.join(' ')]) }
    else heads.push(...commandHeads(rest, d + 1))
  }
  if (COMMAND_STRING_WRAPPERS.has(w)) {
    // `flock FILE -c STR` / `script -c STR`: the option's value is a command string
    const seen = new Set()
    for (let k = 1; k < toks.length; k++) {
      const t = toks[k]
      const cs = (t === '-c' || t === '--command') && k + 1 < toks.length ? toks[k + 1]
        : t.startsWith('--command=') ? t.slice(10) : null
      if (cs !== null && !seen.has(cs)) { seen.add(cs); heads.push(['sh', '-c', cs]) }
    }
  }
  return heads
}

// SUBAGENTMAILGATE1016 (measured on the sub-agent gate, 2026-10-16): the
// support-mail sender was recognised only as `python3 <path>/send.py --to ...`,
// that is, with the script as the FIRST argument and the exact `--to` flag. Six
// spellings ran the same sender past this gate: an interpreter option first
// (`python3 -u`, `python3 -X utf8`), a version-suffixed interpreter, a glob or a
// variable as the script path (`s?nd.py`, `$P`), and the program read from
// stdin (`python3 - --to ... < send.py`). argparse also takes `--t` for `--to`.
// The boundary, fail-closed where the command cannot be read statically:
//   - the script operand is found past the interpreter's own options (a
//     separate argument for -X / -W / --check-hash-based-pycs);
//   - a recipient flag is `--to` or any argparse abbreviation of it (`--t`),
//     with or without `=value` (the sender's --to is required, so every
//     delivering call carries one of these);
//   - send.py by basename + a recipient flag: a send (as before, now from any
//     operand position, interpreter spelling and flag spelling);
//   - a script operand that cannot be resolved statically (glob or brace
//     characters, or a `$` expansion) + a recipient flag: a send, because what
//     runs is undecidable here (until MAILGATEVARARGS1020 also "or another `$`
//     token", see below);
//   - a program read from stdin (`-`, or no script operand and a `<` redirect)
//     + a recipient flag: a send (a heredoc-fed program is judged by its body,
//     heredocProgramSends, as before).
// Anything else stays allowed: `python3 -u other.py`, `python3 -c "print(1)"`,
// `for f in *.py; do python3 $f; done`, `python3 x.py --to-date ...`,
// `python3 "$DIR/gen.py" "$OUT"`.
// Mirrors _python_head_sends in hooks/outgoing-copy-gate.py; the shared
// send-invocation-cases.json binds the two.
//
// MAILGATEVARARGS1020 (measured on a production install, 2026-10-19): the
// "or another `$` token" half denied ordinary scripted work. In one day 26
// sub-agent Bash calls, across four agents, were denied as mail sends; none
// of them was one (no recipient flag, no sender, no mail program). Each was a
// script run from a variable path with a variable argument:
// `python3 "$SP/gen.py" "$SP/out.json"`, `python3 "$L" /dev/null "$SP/o.txt"`,
// `python3 $A/check.py $S/x.json && python3 $A/stamp.py --note-file "$A/n.json"`.
// The agents lost turns on rewrites and workarounds. The extra `$` rule also
// guarded nothing the rest of the gate guards: a literal sender path with a
// variable argument (`python3 scripts/support-mail/send.py $ARGS`) has always
// passed, because a recipient flag inside a variable is not visible statically
// on ANY branch. So this branch now asks what the send.py and the stdin
// branches ask: is there a recipient flag. A variable path WITH one
// (`python3 $P --to ...`) is still a send; `python3 $SENDER $ARGS` passes,
// pinned as a documented limit in send-invocation-cases.json.
const PY_OPT_WITH_ARG = new Set(['-X', '-W', '--check-hash-based-pycs'])
const RECIPIENT_FLAG = /^--to?(=|$)/
const UNDECIDABLE_PATH = /[*?[{$]/

// FLEETTOFLAG1025 v4 (Merlin 34827; the python twin: _FLEET_EXEMPT_BLOCK / _known_agents / _fleet_to_exempt): no tokenizer reading
// of the recipient value any more. On an UNDECIDABLE program or script the recipient flag is a send, EXCEPT when every --to / --to=
// value is a KNOWN agent name (the install's agents/ directories and its MAIN_AGENT_ID) AND the WHOLE command line has no `@`, no `~`
// word other than a `~/` path and no --cc / --bcc. Every other shape is a send (fail-closed).
const FLEET_EXEMPT_BLOCK = /@|(?:^|[\s='"(])~(?!\/)|--b?cc\b/
const FLEET_TOKEN_BLOCK = /^(?:--(?:cc?|bc{0,2})(?:=|$)|~(?!\/))/ // on the DEQUOTED words: `--c""c`, `--\cc` are `--cc` to the program;
// (v4.1, Merlin 34962) an argparse abbreviation (--c, --b, --bc) is --cc / --bcc to a default-argparse script: a send
const AGENT_NAME = /^[a-z0-9][a-z0-9_-]*$/
let knownAgentsOverride = null // the shared conformance list sets it (send-invocation-cases.json known_agents); null = the install
let lineExemptOk = false // set per top-level isSendInvocation call from the WHOLE command line
export function setKnownAgentsOverride(list) { knownAgentsOverride = list == null ? null : new Set(list) }
const tok = (t) => t.replace(/^\n+|\n+$/g, '')
const recipientFlag = (t) => RECIPIENT_FLAG.test(tok(t))
// the agent names of THIS install: <root>/agents/* directories and MAIN_AGENT_ID in <root>/.env (root = one level above this
// file). Any read error = an empty set, i.e. no exception (fail-closed).
function knownAgents() {
  if (knownAgentsOverride !== null) return knownAgentsOverride
  const root = join(dirname(fileURLToPath(import.meta.url)), '..')
  const names = new Set()
  try {
    const d = join(root, 'agents')
    for (const e of readdirSync(d, { withFileTypes: true })) if (e.isDirectory() && AGENT_NAME.test(e.name)) names.add(e.name)
  } catch { /* no agents/ directory: only the main agent can be known */ }
  try {
    const m = readFileSync(join(root, '.env'), 'utf-8').match(/^\s*MAIN_AGENT_ID\s*=\s*['"]?([^'"\s#]+)/m)
    if (m && AGENT_NAME.test(m[1])) names.add(m[1])
  } catch { /* no .env: the main agent is not known (fail-closed) */ }
  return names
}
// FLEETTOFLAG1025 v4 (Codex 0dd77c650df7): no address marker in the line -- neither in the raw text nor in any DEQUOTED word of any
// segment, the substitution-flattened form included. An unparseable line is not clean (fail-closed).
function lineClean(cmd) {
  if (FLEET_EXEMPT_BLOCK.test(cmd)) return false
  let words
  try {
    words = [cmd, flattenSubstitutions(cmd)].flatMap((c) => segmentsTokens(c).flat())
  } catch { return false }
  return !words.some((w) => w.includes('@') || FLEET_TOKEN_BLOCK.test(tok(w)))
}
// true (not a letter) only if the whole line passed the address check and every --to / --t value -- the very next token, or the
// part after `=` -- is a known agent name. A missing or empty value is not a name.
function fleetToExempt(rest) {
  if (!lineExemptOk) return false
  const vals = []
  for (let i = 0; i < rest.length; i++) {
    const t = tok(rest[i])
    if (t === '--to' || t === '--t') vals.push(i + 1 < rest.length ? tok(rest[i + 1]) : '')
    else if (t.startsWith('--to=') || t.startsWith('--t=')) vals.push(t.slice(t.indexOf('=') + 1))
  }
  if (!vals.length) return false
  const known = knownAgents()
  return vals.every((v) => known.has(v))
}
// an undecidable program / script with a recipient flag is a send unless the fleet-agent exception holds
const undecidableRecipientSends = (rest) => rest.some((t) => recipientFlag(t)) && !fleetToExempt(rest)
function pythonScriptOperand(rest) {
  let stdinRedirect = false
  for (let i = 0; i < rest.length; i++) {
    const t = rest[i]
    if (t === '--') return { script: rest[i + 1] ?? null, stdin: false, stdinRedirect }
    if (t === '-') return { script: null, stdin: true, stdinRedirect }
    if (/^-[cm]/.test(t)) return { script: null, stdin: false, stdinRedirect } // code string / module: judged elsewhere
    if (PY_OPT_WITH_ARG.has(t)) { i++; continue }
    if (t.startsWith('<')) { stdinRedirect = true; if (t === '<') i++; continue }
    if (/^\d*>/.test(t)) { if (/^\d*>>?$/.test(t)) i++; continue }
    if (t.startsWith('-') && t.length > 1) continue
    return { script: t, stdin: false, stdinRedirect }
  }
  return { script: null, stdin: false, stdinRedirect }
}
// A command or process substitution as a word of the command (`$(...)`, a
// backtick pair, `<(...)`, `>(...)`), with the substitution replaced by one
// placeholder word that carries a `$`. maskSubshellMarkers splits these into
// their own segments, which is right for judging the INNER command, but it
// leaves the outer one without the word: `python3 $(echo .../send.py) --to x`
// became `python3` and `--to x`. Judged on this form as well, the word is an
// undecidable script path (or interpreter) like a variable. Quoted text is left
// alone: a quoted `"$(...)"` already reaches the tokenizer as a `$` word.
export function flattenSubstitutions(cmd) {
  let out = ''
  let q = null
  for (let i = 0; i < cmd.length; i++) {
    const ch = cmd[i]
    if (q) {
      if (ch === '\\' && q === '"' && i + 1 < cmd.length) { out += ch + cmd[++i]; continue }
      if (ch === q) q = null
      out += ch
      continue
    }
    if (ch === "'" || ch === '"') { q = ch; out += ch; continue }
    if (ch === '\\' && i + 1 < cmd.length) { out += ch + cmd[++i]; continue }
    const opens = (ch === '$' || ch === '<' || ch === '>') && cmd[i + 1] === '('
    if (opens || ch === '`') {
      let depth = 1
      let j = i + (opens ? 2 : 1)
      let iq = null
      for (; j < cmd.length && depth > 0; j++) {
        const c = cmd[j]
        if (iq) { if (c === iq) iq = null; continue }
        if (c === "'" || c === '"') { iq = c; continue }
        if (ch === '`') { if (c === '`') depth = 0; continue }
        if (c === '(') depth++
        else if (c === ')') depth--
      }
      out += ' $__SUBST__ '
      i = j - 1
      continue
    }
    out += ch
  }
  return out
}

function pythonHeadSends(rest) {
  const recipient = rest.some((t) => recipientFlag(t))
  const { script, stdin, stdinRedirect } = pythonScriptOperand(rest)
  if (script !== null && SENDPY.test(basename(script))) return recipient
  if (script !== null && UNDECIDABLE_PATH.test(script)) return undecidableRecipientSends(rest) // MAILGATEVARARGS1020, FLEETTOFLAG1025 v4
  if (stdin || (script === null && stdinRedirect)) return recipient
  return false
}

const VAR_WORD = /^\$(?:\{(\w+)\}|(\w+))$/
const ASSIGN_PREFIX = new Set(['export', 'declare', 'readonly', 'local', 'typeset'])

function segmentIsSend(toksIn, depth, env = null) {
  for (const h of commandHeads(toksIn)) {
    if (headIsSend(h, depth)) return true
    // Q4: a program word that is exactly $NAME / ${NAME}, with NAME assigned a literal earlier
    // in the same line, is judged with that literal (word-split) as the program.
    const m = env && env.size && h && h.length ? VAR_WORD.exec(h[0]) : null
    if (m) {
      for (const lit of env.get(m[1] ?? m[2]) ?? []) {
        if (commandHeads([...lit.split(/\s+/).filter(Boolean), ...h.slice(1)], 1).some((h2) => headIsSend(h2, depth))) return true
      }
    }
  }
  return false
}

// Literal NAME=value words at the head of a segment (after export / declare ...) into env;
// every earlier value of a name is kept (a branch may have taken either), at most 8 per name.
// A value with a substitution or a glob is not a literal. Mirrors _collect_assignments.
function collectAssignments(toks, env) {
  let i = 0
  while (i < toks.length && ASSIGN_PREFIX.has(toks[i])) i++
  while (i < toks.length && ENV_ASSIGN.test(toks[i])) {
    const eq = toks[i].indexOf('=')
    const name = toks[i].slice(0, eq)
    const val = toks[i].slice(eq + 1)
    if (val && !UNDECIDABLE_PATH.test(val)) {
      if (!env.has(name)) env.set(name, [])
      const vals = env.get(name)
      if (!vals.includes(val) && vals.length < 8) vals.push(val)
    }
    i++
  }
}

function segmentsSend(segments, depth) {
  const env = new Map()
  for (const toks of segments) {
    if (segmentIsSend(toks, depth, env)) return true
    collectAssignments(toks, env)
  }
  return false
}

// The command strings a shell is given -- see _shell_command_strings in outgoing-copy-gate.py.
function shellCommandStrings(rest) {
  const out = new Set()
  for (let i = 0; i < rest.length; i++) {
    if (rest[i] === '-c' && rest[i + 1]) out.add(rest[i + 1])
  }
  let cSeen = false
  let i = 0
  while (i < rest.length) {
    const t = rest[i]
    if (t === '--') { i++; break }
    if (t === '--command' && i + 1 < rest.length) { out.add(rest[i + 1]); break }
    if (t.startsWith('--command=')) { out.add(t.slice(10)); break }
    if (t.startsWith('--')) { i += ['--rcfile', '--init-file', '--init-command'].includes(t) ? 2 : 1; continue }
    if (t.length > 1 && (t[0] === '-' || t[0] === '+')) {
      if (t[0] === '-' && t.slice(1).includes('c')) cSeen = true
      i += t.endsWith('o') || t.endsWith('O') ? 2 : 1
      continue
    }
    break
  }
  if (cSeen && i < rest.length && rest[i]) out.add(rest[i])
  return [...out]
}

function headIsSend(toks, depth) {
  if (toks === null) return true // the depth bound was hit on a wrapper: audit it
  if (!toks.length) return false
  const prog = basename(toks[0])
  const rest = toks.slice(1)
  if (SENDER_PROG.test(prog)) return true
  // (card 11f53410: option clusters with c, `--`, option values; at the string-depth bound a
  // command string is out of sight, so it counts as a send, like the head-depth bound)
  if (WRAPPER_SHELL.test(prog)) {
    for (const cs of shellCommandStrings(rest)) {
      if (depth >= 3 || isSendInvocation(cs, depth + 1)) return true
    }
  }
  // eval joins its words with spaces and runs the result as a command string
  if (prog === 'eval' && rest.length) {
    if (depth >= 3 || isSendInvocation(rest.join(' '), depth + 1)) return true
  }
  if (PYTHON.test(prog) || NODEISH.test(prog)) {
    for (let i = 0; i < rest.length; i++) {
      if ((rest[i] === '-c' || rest[i] === '-e' || rest[i] === '--eval') &&
          rest[i + 1] && codeStringSends(rest[i + 1])) return true
    }
  }
  const candidates = [prog]
  if ((PYTHON.test(prog) || NODEISH.test(prog)) && rest.length) candidates.push(basename(rest[0]))
  // Issue #1853: `python3 -m send` (or -m pkg.send) is the same sender by module name.
  if (PYTHON.test(prog)) {
    for (let i = 0; i < rest.length - 1; i++) {
      if (rest[i] === '-m' && rest[i + 1].split('.').pop() === 'send') candidates.push('send.py')
    }
  }
  if (candidates.some((c) => SENDPY.test(c)) && rest.some((t) => recipientFlag(t))) return true
  if (PYTHON.test(prog) && pythonHeadSends(rest)) return true
  // An interpreter or program that cannot be resolved statically ($PY, a glob,
  // a substitution) with a recipient flag: what runs is undecidable here.
  // FLEETTOFLAG1025: the address rule -- but a send.py run by it (`$PY scripts/support-mail/send.py --to x`) keeps the bare flag rule
  const scriptTok = pythonScriptOperand(rest).script // the script position (interpreter options, redirections skipped), not a data argument
  if (UNDECIDABLE_PATH.test(toks[0]) && (undecidableRecipientSends(rest)
      || (scriptTok != null && SENDPY.test(basename(scriptTok)) && rest.some((t) => recipientFlag(t))))) return true
  if (toks.some((t) => GRAPHMAIL.test(basename(t))) && rest.includes('send')) return true
  // graph-forward: the CLI run as a program -- every subcommand but the three reads
  // is a send, a missing one too (see GRAPHMAIL_READS).
  if (GRAPHMAIL.test(prog) || GRAPHMAIL_RUNNER.test(prog)) {
    for (let k = 0; k < toks.length; k++) {
      if (GRAPHMAIL.test(basename(toks[k])) && (k + 1 >= toks.length || !GRAPHMAIL_READS.has(toks[k + 1]))) return true
    }
  }
  // RESENDGETTWIN1010: only an actual send (POST/PUT/..., or a body) fires; a
  // read-only GET/HEAD passes; an undecidable method stays fail-closed.
  if (CURLISH.test(prog) && rest.some((t) => RESEND_TARGET.test(t))) {
    return curlResendVerdict(prog, rest) !== 'read'
  }
  return false
}

// True when some segment is still a wrapper at the depth bound (HEADDEPTH924),
// so the deny says WHY -- see wrapper_depth_hit in outgoing-copy-gate.py.
export function wrapperDepthHit(cmd) {
  // Only when the bound is the WHOLE reason: a visible send in another segment wins.
  const heads = bothReadings(cmd).flatMap((toks) => commandHeads(toks))
  return heads.some((h) => h === null) && !heads.some((h) => h !== null && headIsSend(h, 0))
}

export function buildWrapperDepthMsg() {
  return (
    'TILTVA (governance hard-gate): a parancs valodi fejet nem latom. ' +
    `A parancs a burkolo-korlatnal (${HEAD_DEPTH} egymasba agyazott burkolo: sudo, time, env, nohup, nice, timeout...) ` +
    'is meg burkolo, tehat nem tudom eldonteni, hogy levelkuldes-e, es a kapu ilyenkor fail-closed. ' +
    `Ha ez NEM levelkuldes: csokkentsd a burkolok szamat ${HEAD_DEPTH} vagy kevesebb ala. ` +
    'Ha levelkuldes: sub-agentkent Bash-bol amugy sem kuldhetsz, a kimeno emailt a fo-agens kuldi.'
  )
}

// Issue #1853, the heredoc form: the segmenter drops heredoc BODIES, but when the
// command that opens one is an interpreter (`python3 - <<'PY'`, `node <<EOF`) the body
// IS the program. Mirrors _heredoc_program_sends in hooks/outgoing-copy-gate.py.
// NARROWED (Geri's #1855 review): inside a heredoc body the exec + sender-literal half takes
// the literal only as a lowercase, QUOTED command word (an argv item or an os.system command),
// so a card id like SENDMAIL... in a report's prose no longer matches. Mirrors
// _HEREDOC_SENDER_ARGV / _heredoc_body_sends in hooks/outgoing-copy-gate.py.
// NOT COVERED, named: a program the classifier never reads -- `python3 /tmp/x.py`,
// `python3 < /tmp/x.py`, `cat /tmp/x.py | python3 -`, `python3 -c "exec(open('/tmp/x.py').read())"`;
// also a here-string fed to an interpreter (`python3 <<<'import send'`) and a CommonJS
// destructuring rename of the Graph sender (`const { sendMail: s } = require(...)`).
// A heredoc fed to a SHELL (`bash <<EOF`) is a shell program: its body is judged with
// isSendInvocation itself, one level deeper (Geri/Samu, #1855).
// WRITTEN, THEN RUN IN THE SAME COMMAND (#1855): `cat > P <<TAG` / `cat <<TAG > P`, then an
// interpreter or a shell on the same path token P: the body is judged as if fed directly.
// Exact token match; a file run by ANOTHER Bash call stays out of reach.
// PIPED (#1855): `cat <<'EOF' | bash` or `| python3 -` hands the body over the pipe on the
// heredoc's opening line; it is judged the same way.
const HEREDOC_SENDER_ARGV = /['"](?:[^'"\s]*\/)?(?:sendmail|msmtp|swaks|send\.py)(?=['"\s])/
const heredocBodySends = (body) =>
  CODE_SEND.test(body) || CODE_SEND_MODULE.test(body) || (CODE_EXECISH.test(body) && HEREDOC_SENDER_ARGV.test(body))
const HEREDOC_SHELL = /(?:^|[\s;&|(])(?:\S*\/)?(?:bash|sh|zsh|dash|ksh|mksh|csh|tcsh|fish)\b[^\n<]*$/i
const HEREDOC_INTERP = /(?:^|[\s;&|(])(?:\S*\/)?(python3?(?:\.\d+)?|node|tsx|ts-node|deno|bun)\b[^\n<]*$/i
const HEREDOC_PIPE = /\|\s*(?:\S*\/)?(python3?(?:\.\d+)?|node|tsx|ts-node|deno|bun|bash|sh|zsh|dash|ksh|mksh|csh|tcsh|fish)\b/i
const HEREDOC_REDIRECT = /(?:^|[\s;&|(])(?:cat|tee)\b[^\n]*?(?:>>?|\btee(?:\s+-a)?)\s*(['"]?)([^\s'"<>;&|]+)\1/
function writtenThenRun(cmd, written, depth) {
  if (!written.size) return false
  for (const toks of bothReadings(cmd)) {
    for (const head of commandHeads(toks)) {
      if (!head || !head.length) continue
      const prog = basename(head[0])
      let args = head.slice(1).filter((t) => !t.startsWith('-'))
      if (prog.toLowerCase() === 'npx' && args.length) args = args.slice(1) // npx <runner> <file>
      if (!args.length || !written.has(args[0])) continue
      const body = written.get(args[0])
      if ((PYTHON.test(prog) || NODEISH.test(prog)) && heredocBodySends(body)) return true
      if (WRAPPER_SHELL.test(prog) && depth < 3 && isSendInvocation(body, depth + 1)) return true
    }
  }
  return false
}
function heredocProgramSends(cmd, depth = 0) {
  const written = new Map()
  for (const m of heredocMatches(cmd)) {
    const opener = cmd.slice(cmd.lastIndexOf('\n', m.index - 1) + 1, m.index) + m[1]
    const w = HEREDOC_REDIRECT.exec(opener)
    if (w) written.set(w[2], cmd.slice(m.index + m[1].length + 1, m.index + m[0].length - m[2].length))
    const piped = HEREDOC_PIPE.exec(m[1])
    if (piped) {
      const pbody = cmd.slice(m.index + m[1].length + 1, m.index + m[0].length - m[2].length)
      if (WRAPPER_SHELL.test(piped[1])) {
        if (depth < 3 && isSendInvocation(pbody, depth + 1)) return true
      } else if (heredocBodySends(pbody)) return true
    }
    const lineStart = cmd.lastIndexOf('\n', m.index - 1) + 1
    const head = cmd.slice(lineStart, m.index)
    const bodyStart = m.index + m[1].length + 1
    const body = cmd.slice(bodyStart, m.index + m[0].length - m[2].length)
    if (HEREDOC_INTERP.test(head)) {
      if (heredocBodySends(body)) return true
    } else if (HEREDOC_SHELL.test(head) && depth < 3) {
      if (isSendInvocation(body, depth + 1)) return true
    }
  }
  return writtenThenRun(cmd, written, depth)
}

export function isSendInvocation(cmd, depth = 0) {
  // FLEETTOFLAG1025 v4: the fleet-agent exception is decided on the WHOLE line; a wrapper body (depth > 0) can only tighten it.
  // A module-level flag is enough: the hook is one process per tool call, and the evaluation is single-threaded.
  lineExemptOk = (depth === 0 || lineExemptOk) && lineClean(cmd)
  if (heredocProgramSends(cmd, depth)) return true
  // QUOTEPARITY1018: read with and without shell comments; a send in EITHER
  // reading counts (see is_send_invocation in hooks/outgoing-copy-gate.py).
  for (const comments of [true, false]) {
    let segments
    try {
      segments = segmentsTokens(cmd, comments)
    } catch {
      // Unparseable command: fall back to the LEGACY content patterns, so on
      // this path the gate is exactly as strict as before -- never weaker.
      if (SEND_PATTERNS.some((re) => re.test(cmd))) return true
      continue
    }
    if (segmentsSend(segments, depth)) return true
  }
  // The same command with every substitution as one undecidable word (see
  // flattenSubstitutions): the outer command keeps the word it would run. Read
  // with and without shell comments like the loop above (QUOTEPARITY1018): a
  // send in EITHER reading counts.
  const flat = flattenSubstitutions(cmd)
  if (flat === cmd) return false
  for (const comments of [true, false]) {
    try {
      if (segmentsSend(segmentsTokens(flat, comments), depth)) return true
    } catch {
      if (SEND_PATTERNS.some((re) => re.test(cmd))) return true
    }
  }
  return false
}

// SCRIPTSENDGATE1020: a sender script under any name. isSendInvocation knows a
// Python sender only by the file name send.py, so `python3 helden_send.py --to
// x@y.hu < body.txt` -- a self-written SMTP script, the usual way a mail goes
// out on this fleet -- was no send for this gate (measured 2026-10-20). Cheap,
// local signals close it for the sub-agents. A run is a send when:
//   1. an interpreter (python, node, tsx, bun, deno) or a directly executed
//      script is given an e-mail address after --to / --cc / --bcc. This holds
//      with no script file too (`python3 -m pkg`, `python3 -c ...`);
//   2. the script file IMPORTS a mail library: an import statement of the
//      python SMTP modules (smtplib, aiosmtplib, yagmail), or a require /
//      import of nodemailer for a node script. A bare mention (a comment, a
//      mock, a regex like this file's own) is no import and passes;
//   3. one level of local helper modules imported by the script, resolved
//      next to it, imports one (`from mailhelper import send_mail`);
//   4. a shell `-c` string (sh, bash, zsh, dash) runs one of the above.
// A directly executed file (`./x`, `/abs/x`, `x.py`) is read as python or node
// by its #! line, else by its extension; an extensionless file without a
// python/node #! line is not judged.
// Deliberately NOT part of isSendInvocation: that function is the shared
// contract with the main agent's python gates (send-invocation-cases.json),
// and on the main agent the owner's single approval in the chat is the rule
// (owner decision, 2026-10-20). This narrowing is for the sub-agent hard gate
// only, where every recognised Bash send is denied anyway.
// Not seen, on purpose (docs/security-hardening.md lists them): mail sent
// without one of these libraries (Gmail API client, an HTTP mail API, raw
// socket SMTP, perl/ruby), a script read from stdin or named through a
// variable, a script reached after `cd dir &&` (resolved against the session
// cwd), helpers past the first level, an import after the first 1 MiB, and
// code assembled at runtime.
const PY_MAIL_MODULE = String.raw`(?:(?:aio)?smtplib|yagmail)`
const PY_MAIL_IMPORT = new RegExp(
  String.raw`^[ \t]*(?:import[ \t]+[^\n#]*\b${PY_MAIL_MODULE}\b|from[ \t]+${PY_MAIL_MODULE}\b[^\n]*\bimport\b)` +
  String.raw`|\bimport_module\(\s*['"]${PY_MAIL_MODULE}['"]`,
  'm',
)
const NODE_MAIL_MODULE = String.raw`['"]nodemailer['"]`
const NODE_MAIL_IMPORT = new RegExp(
  String.raw`\brequire\s*\(\s*${NODE_MAIL_MODULE}\s*\)|^[ \t]*import\b[^\n]*${NODE_MAIL_MODULE}|\bimport\s*\(\s*${NODE_MAIL_MODULE}\s*\)`,
  'm',
)
const PY_LOCAL_IMPORT = /^[ \t]*(?:from[ \t]+([\w.]+)[ \t]+import\b|import[ \t]+([\w., \t]+))/gm
const NODE_LOCAL_IMPORT = /(?:\brequire\s*\(\s*|^[ \t]*import\b[^\n]*?\bfrom\s*|^[ \t]*import\s*|\bimport\s*\(\s*)['"](\.{1,2}\/[^'"\n]+)['"]/gm
const NODE_EXTS = ['', '.js', '.mjs', '.cjs', '.ts', '/index.js', '/index.mjs', '/index.ts']
const HELPER_LIMIT = 40
const ADDRESS_FLAG = /^--(?:to|cc|bcc)(?:=(.*))?$/
const SCRIPT_FILE = /\.(?:py|mjs|cjs|js|ts)$/i
const SHELL_C_FLAG = /^-[a-zA-Z]*c[a-zA-Z]*$/
const SCRIPT_READ_LIMIT = 1024 * 1024
const SHEBANG_READ_LIMIT = 512
const SHELL_C_DEPTH = 3

function readScriptHead(path, limit = SCRIPT_READ_LIMIT) {
  let fd = null
  try {
    fd = openSync(path, 'r')
    const buf = Buffer.alloc(limit)
    const n = readSync(fd, buf, 0, limit, 0)
    return buf.subarray(0, n).toString('utf-8')
  } catch {
    return null
  } finally {
    if (fd !== null) {
      try { closeSync(fd) } catch { /* already closed */ }
    }
  }
}

function resolveScriptPath(script, cwd) {
  if (!script || UNDECIDABLE_PATH.test(script)) return null
  let p = script
  if (p === '~' || p.startsWith('~/')) p = join(homedir(), p.slice(1))
  if (isAbsolute(p)) return p
  return cwd ? resolve(cwd, p) : null
}

// node/tsx/bun/deno: the first non-option word is the script; -e/--eval code
// strings are isSendInvocation's to judge.
function nodeScriptOperand(rest) {
  for (const t of rest) {
    if (t === '--') continue
    if (t.startsWith('-')) return null
    return t
  }
  return null
}

function addressFlagGiven(rest) {
  for (let i = 0; i < rest.length; i++) {
    const m = ADDRESS_FLAG.exec(rest[i])
    if (!m) continue
    const val = m[1] ?? rest[i + 1] ?? ''
    if (val.includes('@')) return true
  }
  return false
}

// 'py' | 'node' | null from a #! line (`#!/usr/bin/python3`, `#!/usr/bin/env -S node`).
function shebangKind(text) {
  const m = /^#!\s*(\S+)([^\n]*)/.exec(text ?? '')
  if (!m) return null
  let prog = basename(m[1])
  if (prog === 'env') prog = basename(m[2].trim().split(/\s+/).find((w) => w && !w.startsWith('-') && !w.includes('=')) ?? '')
  if (PYTHON.test(prog)) return 'py'
  if (NODEISH.test(prog) && prog !== 'npx') return 'node'
  return null
}

// One level of local helpers: modules the script imports, resolved next to it.
function localHelperPaths(path, text, kind) {
  const dir = dirname(path)
  const out = []
  if (kind === 'py') {
    for (const m of text.matchAll(PY_LOCAL_IMPORT)) {
      const names = m[1] ? [m[1]] : m[2].split(',').map((n) => n.trim().split(/\s+/)[0])
      for (const name of names) {
        if (!name || name.startsWith('.')) continue
        const rel = name.split('.').join('/')
        out.push(join(dir, `${rel}.py`), join(dir, rel, '__init__.py'))
      }
    }
  } else {
    for (const m of text.matchAll(NODE_LOCAL_IMPORT)) {
      for (const ext of NODE_EXTS) out.push(resolve(dir, m[1] + ext))
    }
  }
  return [...new Set(out)].filter((p) => p !== path).slice(0, HELPER_LIMIT)
}

function fileSends(path, text, kind, readScript) {
  const imports = kind === 'py' ? PY_MAIL_IMPORT : NODE_MAIL_IMPORT
  if (imports.test(text)) return true
  return localHelperPaths(path, text, kind).some((h) => {
    const t = readScript(h)
    return t !== null && imports.test(t)
  })
}

function headRunsSenderScript(toks, cwd, readScript, depth) {
  if (!toks || !toks.length) return false
  const prog = basename(toks[0])
  const rest = toks.slice(1)
  if (WRAPPER_SHELL.test(prog)) {
    if (depth >= SHELL_C_DEPTH) return false
    for (let i = 0; i < rest.length - 1; i++) {
      if (SHELL_C_FLAG.test(rest[i]) && scriptRunSends(rest[i + 1], cwd, readScript, depth + 1)) return true
    }
    return false
  }
  let script
  let kind
  if (PYTHON.test(prog)) {
    if (addressFlagGiven(rest)) return true // also under -m / -c, where no file is named
    script = pythonScriptOperand(rest).script
    kind = 'py'
  } else if (NODEISH.test(prog) && prog !== 'npx') {
    if (addressFlagGiven(rest)) return true
    script = nodeScriptOperand(rest)
    kind = 'node'
  } else if (SCRIPT_FILE.test(toks[0]) || toks[0].includes('/')) {
    // a directly executed file: its #! line picks the interpreter, else its extension
    const path = resolveScriptPath(toks[0], cwd)
    if (!path) return false
    kind = shebangKind(readScript(path, SHEBANG_READ_LIMIT)) ??
      (/\.py$/i.test(toks[0]) ? 'py' : SCRIPT_FILE.test(toks[0]) ? 'node' : null)
    if (!kind) return false
    if (addressFlagGiven(rest)) return true
    const text = readScript(path)
    return text !== null && fileSends(path, text, kind, readScript)
  } else {
    return false
  }
  if (script === null) return false
  const path = resolveScriptPath(script, cwd)
  if (!path) return false
  const text = readScript(path)
  return text !== null && fileSends(path, text, kind, readScript)
}

export function scriptRunSends(cmd, cwd = process.cwd(), readScript = readScriptHead, depth = 0) {
  // Both comment readings (QUOTEPARITY1018); an unparseable reading contributes
  // nothing: isSendInvocation's legacy fallback already judged it.
  return bothReadings(cmd).some((toks) => commandHeads(toks).some((h) => headRunsSenderScript(h, cwd, readScript, depth)))
}

// Outbound-shaped operations of the multiplexed manage_email tool, in NORMALISED
// form (see manageEmailOpKey). Each of these sends for real unless the call
// explicitly asks for a draft.
const MANAGE_EMAIL_SEND_OPS = new Set(['send', 'reply', 'replyall', 'forward'])

// JS twin of email_extract.manage_email_op_outbound (scripts/hooks/email_extract.py,
// the main agent's gates), bound by the manage_email_ops block of
// scripts/hooks/mail-tool-action-cases.json (card 2f835ee4 r5). ASCII-whitespace
// strip (explicit, NOT trim(): trim() takes NBSP, U+FEFF... that Python's strip()
// does not), ASCII lower-case, every "-" and "_" removed, then an EXACT match.
// A non-ASCII character is never folded to ASCII. Pure, never throws; a missing
// or non-string operation is simply not outbound here (the caller owns that policy).
// Index loops, not a /^\s+|\s+$/ regex: the trailing-run pattern backtracks
// quadratically on a long run of spaces that does not end the string.
const ASCII_WS = ' \t\r\n\f\v'
export function manageEmailOpKey(op) {
  if (typeof op !== 'string') return ''
  let start = 0
  let end = op.length
  while (start < end && ASCII_WS.includes(op[start])) start++
  while (end > start && ASCII_WS.includes(op[end - 1])) end--
  return op.slice(start, end).replace(/[A-Z]/g, (c) => String.fromCharCode(c.charCodeAt(0) + 32)).replace(/[-_]/g, '')
}
export function manageEmailOpOutbound(op) {
  return MANAGE_EMAIL_SEND_OPS.has(manageEmailOpKey(op))
}
// JS twin of email_extract.manage_email_op_closed (card d8d3441e): outbound OR
// unreadable (not a string, or empty after the normalisation). String() is NOT
// used: String(["send"]) would read as "send".
// E2: also closed when nothing but the EXPLICIT blank set below remains (identical
// to _CLOSED_BLANK_CHARS in email_extract.py): ASCII whitespace, U+001C-U+001F,
// U+0085, U+00A0, U+1680, U+2000-U+200B, U+2028, U+2029, U+202F, U+205F, U+3000,
// U+FEFF. manageEmailOpKey / manageEmailOpOutbound keep the ASCII-only rule.
const CLOSED_BLANK_CHARS =
  ' \t\r\n\f\v'
  + '\u001c\u001d\u001e\u001f\u0085\u00a0\u1680'
  + '\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u200b'
  + '\u2028\u2029\u202f\u205f\u3000\ufeff'
export function manageEmailOpClosed(op) {
  if (typeof op !== 'string') return true
  const key = manageEmailOpKey(op)
  if (key === '' || MANAGE_EMAIL_SEND_OPS.has(key)) return true
  for (const ch of op) if (!CLOSED_BLANK_CHARS.includes(ch)) return false
  return true
}

// --- tool-name classification ------------------------------------------------
// JS twin of email_extract.classify_mail_tool (scripts/hooks/email_extract.py,
// the main agent's gates). Both are bound by the shared case list
// scripts/hooks/mail-tool-name-cases.json, which
// src/__tests__/email-gate-matcher-drift.test.ts runs through BOTH copies; the
// full rationale is at the python twin.
//
// Classified by the base-name SUFFIX, never by what precedes it:
// vendor/gmail-mcp-fork prepends its tool prefix to every tool name verbatim
// (v2_, v2, work-, ...), so `(^|__)draft_email$`, `(^|__)manage_email$` and
// `gmail__reply_all$` missed every prefixed form: a prefixed draft skipped the
// recipient ledger, and a prefixed (or non-"gmail"-server) reply_all was no
// send at all. send_draft is a send this gate never knew. The classifier is a
// superset of the patterns this gate carried: send_email and the draft names
// keep a substring match, manage_email is the suffix (a look-alike such as
// manage_emails_bulk stays out); the generic connector words count only with
// "gmail" in the qualified name (the Telegram tool is `..._telegram__reply`).
// Kinds: 'send_email' | 'connector_send' | 'send_draft' | 'manage_email' |
// 'draft' | null (reads, search, labels, delete: not outbound).
const CONNECTOR_GENERIC_SUFFIXES = ['send_message', 'reply', 'forward']
const DRAFT_NAMES = ['draft_email', 'create_draft', 'update_draft', 'draft_gmail_message']
// The harder-mail MCP's sends (HARDERMAILGATES1019): connector_send, so the
// thread-reply narrowing (send_email only) can never release one.
const MAILBOX_SEND_SUFFIXES = ['send_mail', 'send_mail_auto']
// The Microsoft Graph MCP's names, hyphens normalized (MS365MAIL1024): the
// server names its tools with hyphens (send-mail, create-draft-email, ...),
// which no underscore-shaped suffix ever matched.
const MS365_SEND_SUFFIXES = ['send_mail', 'send_shared_mailbox_mail', 'reply_mail_message',
  'reply_all_mail_message', 'forward_mail_message', 'reply_shared_mailbox_mail',
  'reply_all_shared_mailbox_mail', 'forward_shared_mailbox_mail', 'forward_calendar_event',
  'reply_to_group_thread']
const MS365_DRAFT_SEND_SUFFIXES = ['send_draft_message', 'send_shared_mailbox_draft']
const MS365_DRAFT_SUFFIXES = ['create_draft_email', 'create_shared_mailbox_draft', 'create_reply_draft',
  'create_reply_all_draft', 'create_forward_draft', 'create_shared_mailbox_reply_draft',
  'create_shared_mailbox_reply_all_draft', 'create_shared_mailbox_forward_draft',
  'update_mail_message', 'update_shared_mailbox_message']

export function classifyMailTool(toolName) {
  const n = String(toolName ?? '').toLowerCase().replaceAll('-', '_')
  if (!n || n === 'bash') return null
  // send_gmail_message: the Google Workspace MCP's Gmail send tool
  if (n.includes('send_email') || n.includes('send_gmail_message')) return 'send_email'
  if (n.endsWith('reply_all')) return 'connector_send'
  if (n.includes('gmail') && CONNECTOR_GENERIC_SUFFIXES.some((b) => n.endsWith(b))) return 'connector_send'
  if (MAILBOX_SEND_SUFFIXES.some((b) => n.endsWith(b))) return 'connector_send'
  if (MS365_SEND_SUFFIXES.some((b) => n.endsWith(b))) return 'connector_send'
  if (MS365_DRAFT_SEND_SUFFIXES.some((b) => n.endsWith(b))) return 'send_draft'
  if (n.endsWith('send_draft')) return 'send_draft'
  if (n.endsWith('manage_email')) return 'manage_email'
  if (MS365_DRAFT_SUFFIXES.some((b) => n.endsWith(b))) return 'draft'
  if (DRAFT_NAMES.some((d) => n.includes(d))) return 'draft'
  return null
}

// --- Microsoft Graph letters (MS365MAIL1024) ----------------------------------
// The ms365 MCP server carries the letter Graph-shaped: body.Message.{subject,
// body:{contentType, content}, toRecipients/ccRecipients/bccRecipients:
// [{emailAddress:{address, name?}}]}, a reply's Comment, a forward's
// ToRecipients. The server reads keys in ANY case (so a key twice in different
// case is ambiguous -> reason), and moves a stray top-level field into body
// (so a stray is read wherever it sits). Reading is STRICT for the recipient
// checks (an unreadable list fails closed, like the Python gate's copy).
const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v)

const MS365_TOP_GRAPH_KEYS = new Set(['torecipients', 'ccrecipients', 'bccrecipients'])

export function isMs365Shaped(toolInput) {
  if (!isPlainObject(toolInput)) return false
  for (const [k, v] of Object.entries(toolInput)) {
    const lk = String(k).toLowerCase()
    if (isPlainObject(v) && (lk === 'body' || lk === 'message' || lk === 'post')) return true
    if (Array.isArray(v) && MS365_TOP_GRAPH_KEYS.has(lk)) return true
  }
  return false
}

// A Microsoft Graph MCP mail tool, decided by NAME (MS365MAIL1024 round 2): the
// Graph server names its tools with hyphens, and the last segment of the
// qualified name must contain one -- so the harder-mail server's underscored
// send_mail is never Graph, however its payload looks. Same rule as
// ms365_tool_kind in email_extract.py; the suffix lists are classifyMailTool's.
export function ms365ToolKind(toolName) {
  const raw = String(toolName ?? '').toLowerCase()
  const last = raw.split('__').pop()
  if (!last.includes('-')) return null
  const n = raw.replaceAll('-', '_')
  if (MS365_SEND_SUFFIXES.some((s) => n.endsWith(s))) return 'send'
  if (MS365_DRAFT_SEND_SUFFIXES.some((s) => n.endsWith(s))) return 'draft_send'
  if (MS365_DRAFT_SUFFIXES.some((s) => n.endsWith(s)) || n.endsWith('create_draft_email')) return 'draft'
  return null
}

export function isMs365Tool(toolName) {
  return ms365ToolKind(toolName) !== null
}

// Does the call carry Graph MATERIAL at all: an object body/Message/Post, or a
// top-level Graph recipient key in ANY shape (a non-list toRecipients is
// Graph material -- it must be read strictly, and fails there)? A Graph-named
// draft with flat-only fields has none and keeps the flat checks, which is the
// pinned contract for the ledger-checked drafts; a non-Graph tool with an
// object body never enters the Graph block.
function ms365HasGraphFields(toolInput) {
  if (!isPlainObject(toolInput)) return false
  for (const [k, v] of Object.entries(toolInput)) {
    const lk = String(k).toLowerCase()
    if (isPlainObject(v) && (lk === 'body' || lk === 'message' || lk === 'post')) return true
    if (MS365_TOP_GRAPH_KEYS.has(lk)) return true
  }
  return false
}

// A Graph-shaped call that ALSO carries flat to/cc/bcc is ambiguous: one reader
// would hide the other's addresses (SECURITY review on MS365MAIL1024).
export function ms365FlatConflict(toolInput) {
  if (!isPlainObject(toolInput)) return null
  const flat = Object.entries(toolInput)
    .filter(([k, v]) => ['to', 'cc', 'bcc'].includes(String(k).toLowerCase())
      && !(v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)))
    .map(([k]) => k)
  return flat.length
    ? `a hivas lapos (${flat.sort().join(', ')}) es Graph-alaku cimzettet is visz -- nem egyertelmu`
    : null
}

// (the object with lowercased keys, reason). A key twice in a different case is
// ambiguous.
export function ms365Lower(d, where) {
  const out = {}
  for (const [k, v] of Object.entries(d)) {
    const lk = String(k).toLowerCase()
    if (lk in out) {
      return [null, `${where}: a(z) '${lk}' mezo ketszer szerepel (kis/nagybetu) -- nem egyertelmu`]
    }
    out[lk] = v
  }
  return [out, null]
}

// Python-style sorted set repr, so the deny reasons read the same as the
// Python gate's: ['a', 'b'].
function ms365FieldRepr(keys) {
  const sorted = [...new Set(keys)].sort()
  return `['${sorted.join("', '")}']`
}

// Python-style repr of one short string (the quote Python's repr would pick),
// so an address named in a deny reason reads the same on both gates.
function ms365StrRepr(s) {
  const q = s.includes("'") && !s.includes('"') ? '"' : "'"
  return q + s.replace(/\\/g, '\\\\').split(q).join(`\\${q}`) + q
}

// [{emailAddress: {address, name?}}] -> (addresses, reason). Strict: nothing
// else is accepted.
export function ms365RecipientList(value, where) {
  if (value === null || value === undefined) return [[], null]
  if (!Array.isArray(value)) return [[], `${where}: nem lista`]
  const out = []
  for (let i = 0; i < value.length; i++) {
    const here = `${where}[${i}]`
    const item = value[i]
    if (!isPlainObject(item)) return [[], `${here}: nem objektum`]
    const [it, reason] = ms365Lower(item, here)
    if (reason) return [[], reason]
    const extra = Object.keys(it).filter((k) => k !== 'emailaddress')
    if (extra.length) return [[], `${here}: ismeretlen mezo ${ms365FieldRepr(extra)}`]
    const ea = it.emailaddress
    if (!isPlainObject(ea)) return [[], `${here}.emailAddress: nem objektum`]
    const [e, reason2] = ms365Lower(ea, `${here}.emailAddress`)
    if (reason2) return [[], reason2]
    const extra2 = Object.keys(e).filter((k) => k !== 'address' && k !== 'name')
    if (extra2.length) return [[], `${here}.emailAddress: ismeretlen mezo ${ms365FieldRepr(extra2)}`]
    const addr = e.address
    if (typeof addr !== 'string' || !addr.trim()) {
      return [[], `${here}.emailAddress.address: hianyzik vagy nem szoveg`]
    }
    if (!MS365_ADDR_RE.test(addr.trim())) {
      return [[], `${here}.emailAddress.address: nem egyetlen puszta cim (${ms365StrRepr(addr.slice(0, 60))})`]
    }
    if ('name' in e && typeof e.name !== 'string') {
      return [[], `${here}.emailAddress.name: nem szoveg`]
    }
    out.push(addr.trim())
  }
  return [out, null]
}

const MS365_RECIPIENT_FIELDS = ['torecipients', 'ccrecipients', 'bccrecipients']

// One bare address, nothing around it: a '"owner@x" <stranger@y>' entry would
// let a recipient check find the owner while the letter goes to the stranger.
const MS365_ADDR_RE = /^[^\s<>,;:"'()\[\]@]+@[^\s<>,;:"'()\[\]@]+$/

// {to, cc, bcc, reason} of a Graph-shaped call, for the recipient checks: only
// the recipient fields are read, each strictly, wherever the server would take
// them from -- the top level and the top-level message object (strays the server
// moves into body), body itself (create-draft-email, update-mail-message),
// body.Message, and body.ToRecipients (a forward). A flat to/cc/bcc next to the
// Graph shape is a reason first: one reader would hide the other's addresses.
// A port of ms365_recipients in email_extract.py (same logic, same reason
// texts), so the two gates cannot drift.
export function ms365Recipients(toolInput) {
  if (!isPlainObject(toolInput)) return { to: [], cc: [], bcc: [], reason: 'a hivas: nem objektum' }
  const flat = ms365FlatConflict(toolInput)
  if (flat) return { to: [], cc: [], bcc: [], reason: flat }
  const [top, topReason] = ms365Lower(toolInput, 'a hivas')
  if (topReason) return { to: [], cc: [], bcc: [], reason: topReason }
  const places = [['a hivas', top]]
  if (top.message !== null && top.message !== undefined) {
    if (!isPlainObject(top.message)) return { to: [], cc: [], bcc: [], reason: 'a hivas.Message: nem objektum' }
    const [m, msgReason] = ms365Lower(top.message, 'a hivas.Message')
    if (msgReason) return { to: [], cc: [], bcc: [], reason: msgReason }
    places.push(['a hivas.Message', m])
  }
  const body = top.body
  if (isPlainObject(body)) {
    const [b, bodyReason] = ms365Lower(body, 'body')
    if (bodyReason) return { to: [], cc: [], bcc: [], reason: bodyReason }
    places.push(['body', b])
    if (b.message !== null && b.message !== undefined) {
      if (!isPlainObject(b.message)) return { to: [], cc: [], bcc: [], reason: 'body.Message: nem objektum' }
      const [m, msgReason] = ms365Lower(b.message, 'body.Message')
      if (msgReason) return { to: [], cc: [], bcc: [], reason: msgReason }
      places.push(['body.Message', m])
    }
  }
  const to = [], cc = [], bcc = []
  const buckets = [to, cc, bcc]
  for (const [where, d] of places) {
    for (let f = 0; f < MS365_RECIPIENT_FIELDS.length; f++) {
      const field = MS365_RECIPIENT_FIELDS[f]
      const [got, reason] = ms365RecipientList(d[field], `${where}.${field}`)
      if (reason) return { to: [], cc: [], bcc: [], reason }
      const bucket = buckets[f]
      for (const x of got) if (!bucket.includes(x)) bucket.push(x)
    }
  }
  return { to, cc, bcc, reason: null }
}

// graph-forward N1b (spec G1-G5): the ACTION of a mail tool, whatever its
// server name or version prefix. The name patterns in gateDecision recognised a
// fixed list of names, so a sub-agent could send through
// mcp__gmail-v2__v2_send_draft or __v2_reply_all with no gate at all, and
// v2_draft_email skipped the ledger check. Same rules, word for word, as
// mail_tool_action in scripts/hooks/email_extract.py (the main agent's gates);
// the shared vectors (scripts/hooks/mail-tool-action-cases.json) and the
// conformance test bind the two:
//   - only MCP tools (mcp__<server>__<tool>); every "__" segment after the
//     server on its own, the most severe one wins;
//   - words: camelCase and acronyms apart, any non-alphanumeric a separator,
//     lowercase, leading v<n> dropped; a verb alone or glued to a mail noun;
//   - send: a send/resend verb anywhere, or the first verb reply/forward/fwd;
//     draft: the first verb draft/create/update/save/compose/edit;
//   - channel plugins (Telegram/Discord/Slack) are never mail.
// It only ADDS: gateDecision asks its name patterns first, unchanged.
const MAIL_SEND_VERBS = new Set(['send', 'resend', 'reply', 'replyall', 'forward', 'fwd'])
const MAIL_SEND_ANYWHERE = new Set(['send', 'resend'])
const MAIL_DRAFT_VERBS = new Set(['draft', 'create', 'update', 'save', 'compose', 'edit'])
const MAIL_OTHER_VERBS = new Set([
  'search', 'find', 'query', 'lookup', 'read', 'get', 'fetch', 'list', 'show', 'view',
  'open', 'download', 'export', 'count', 'check', 'describe', 'inspect', 'summarize',
  'delete', 'remove', 'trash', 'untrash', 'archive', 'unarchive', 'move', 'copy',
  'mark', 'label', 'unlabel', 'tag', 'untag', 'star', 'unstar', 'flag', 'unflag',
  'modify', 'set', 'unset', 'add', 'watch', 'unwatch', 'stop', 'subscribe',
  'unsubscribe', 'block', 'unblock', 'mute', 'unmute', 'snooze', 'sync', 'refresh',
  'import', 'upload', 'attach', 'detach', 'parse', 'extract', 'verify', 'validate',
  'ping', 'auth', 'authenticate', 'login', 'logout', 'revoke', 'whoami', 'poll',
  'clear', 'purge', 'restore', 'preview', 'print', 'filter', 'sort', 'scan',
  'report', 'track', 'translate', 'convert', 'render',
])
const MAIL_VERBS = new Set([...MAIL_SEND_VERBS, ...MAIL_DRAFT_VERBS, ...MAIL_OTHER_VERBS])
const MAIL_GLUE_NOUNS = ['mail', 'email', 'emails', 'message', 'messages', 'msg',
  'draft', 'drafts', 'all', 'now', 'reply']
const CHANNEL_PLUGIN_RE = /^mcp__plugin_(?:telegram|discord|slack)[-_]/

// Channel-like servers, the same exclusions the hook matcher carries
// (NON_MAIL_SERVERS in src/web/agent-scaffold.ts; card 6151bb4d): the slack
// server unless the rest of the name says "mail" (mcp__slack__send_email stays
// in), and the ms365 chat / channel / activity tools (its mail tools stay in).
// Applied to what follows "mcp__". A chat reply is the owner's channel, not a
// letter. Twin: _NON_MAIL_SERVER_RE in scripts/hooks/email_extract.py.
const NON_MAIL_SERVER_RE = /^(?:slack__(?![\s\S]*mail)|ms365[^_]*__(?![\s\S]*mail)[^\n\r]*(?:chat|channel|activity))/i
// One invariant for "create" (card 6151bb4d, direction of msg 6348, r1 B1): create
// is a DRAFT (ledger-checked) by default, whatever follows it (create_draft,
// create_reply, create_event, create_appointment, create_rsvp ...). It is not mail
// only when EVERY word after `create` is on the closed noun list or on the closed
// modifier list, and at least one is a noun (create_label, createGoogleDoc,
// create_shared_folder ...). Any other word (reply, forward, message, mail, email,
// invite, event, to, for, send ...) keeps it a draft: fail-closed, no synonym list
// of mail words to grow. rule / filter are nouns only when the tool INPUT is clean
// of forwarding (hasForwardKey); with forwarding input the call is denied outright
// (mailRuleForward).
// Twin: _CREATE_NONMAIL_NOUNS / _CREATE_MODIFIERS in scripts/hooks/email_extract.py.
const MAIL_CREATE_NOUNS = ['draft', 'drafts', 'message', 'messages', 'msg', 'mail', 'email', 'emails']
const CREATE_NONMAIL_NOUNS = new Set(['label', 'labels', 'folder', 'folders', 'doc', 'docs',
  'document', 'documents', 'googledoc', 'googledocs', 'contact', 'contacts', 'task', 'tasks',
  'note', 'notes', 'tag', 'tags', 'category', 'categories'])
const CREATE_RULE_NOUNS = new Set(['rule', 'rules', 'filter', 'filters'])
const CREATE_MODIFIERS = new Set(['google', 'new', 'shared', 'smart', 'custom', 'user', 'personal'])
// A tool that writes a rule / filter (create_rule, updateFilter, set_inbox_rules,
// createrule ...): a rule noun plus a write verb, apart or glued.
const RULE_WRITE_VERBS = new Set(['create', 'update', 'set', 'add', 'save', 'edit', 'modify', 'put',
  'patch', 'upsert', 'replace', 'new', 'insert', 'import', 'enable', 'apply'])

// Does the tool input carry forwarding anywhere (card 6151bb4d r2, B3)? Forwarding is:
//   - a KEY containing forward / redirect (forwardTo, autoForward, action.forward,
//     redirectTo, forwarding_address ...), case-insensitive;
//   - a STRING VALUE containing forward / redirect (type:"forward", a Sieve
//     `redirect :copy "x@y"`), case-insensitive, or `mailto:` (the enotify method
//     that mails out; card 61fcac1e), or an address (an "@" with a character on both
//     sides);
//   - a string value that parses as JSON is walked too (a stringified rule body,
//     also escape-hidden keys such as "forward"), double encoding included.
// Objects and arrays are walked iteratively, bounded: too deep, too many nodes, a
// string that is too long to parse, or a parse that blows the stack counts as
// forwarding (fail-closed), and so does an input that is not an object / array.
// Twin: _has_forward_key in scripts/hooks/email_extract.py.
const FORWARD_WALK_MAX_DEPTH = 12
const FORWARD_WALK_MAX_NODES = 5000
const FORWARD_JSON_MAX_CHARS = 100000
const FORWARD_JSON_START = /^[ \t\n\r]*[{["]/
export function hasForwardKey(input) {
  if (typeof input !== 'object' || input === null) return true
  let nodes = 0
  const stack = [[input, 0]]
  while (stack.length) {
    const [v, depth] = stack.pop()
    if (depth > FORWARD_WALK_MAX_DEPTH) return true
    if (typeof v === 'string') {
      const low = v.toLowerCase()
      if (low.includes('forward') || low.includes('redirect') || low.includes('mailto:') || /[^@]@[^@]/.test(v)) return true
      if (FORWARD_JSON_START.test(v)) {
        if (v.length > FORWARD_JSON_MAX_CHARS) return true
        let parsed
        try { parsed = JSON.parse(v) } catch (err) { if (err instanceof SyntaxError) continue; return true }
        if ((typeof parsed === 'object' && parsed !== null) || typeof parsed === 'string') stack.push([parsed, depth + 1])
      }
      continue
    }
    const items = Array.isArray(v) ? v.map((x) => [null, x]) : Object.entries(v)
    for (const [k, x] of items) {
      if (++nodes > FORWARD_WALK_MAX_NODES) return true
      if (k !== null) {
        const key = k.toLowerCase()
        if (key.includes('forward') || key.includes('redirect')) return true
      }
      if (typeof x === 'string' || (typeof x === 'object' && x !== null)) stack.push([x, depth + 1])
    }
  }
  return false
}

// {verb, noun}: the verb a word stands for ("sendmessage" -> send + message), or null.
function mailVerb(word) {
  if (MAIL_VERBS.has(word)) return { verb: word, noun: '' }
  for (const noun of MAIL_GLUE_NOUNS) {
    if (word.endsWith(noun) && MAIL_VERBS.has(word.slice(0, -noun.length))) return { verb: word.slice(0, -noun.length), noun }
  }
  // A version or one-letter prefix glued to get / delete (v2get_draft,
  // xdelete_draft) is that read verb. It only narrows: a send or draft verb
  // behind a prefix is not touched. Twin: _GLUED_READ_VERB in email_extract.py.
  const m = /^[a-z0-9]{1,2}(get|delete)$/.exec(word)
  if (m) return { verb: m[1], noun: '' }
  return null
}

// The create verb is no letter only when every word after it is a closed noun or a
// closed modifier, with at least one noun (see above). rule / filter count as nouns
// only with a clean input (ruleOk); a glued mail noun (createmessage) is a letter.
function createNotMail(entry, words, ruleOk) {
  if (entry.noun) return false
  const after = words.slice(entry.index + 1)
  if (!after.length) return false
  let nouns = 0
  for (const w of after) {
    if (CREATE_NONMAIL_NOUNS.has(w)) nouns++
    else if (CREATE_RULE_NOUNS.has(w)) { if (!ruleOk) return false; nouns++ }
    else if (!CREATE_MODIFIERS.has(w)) return false
  }
  return nouns > 0
}

// "new" + a mail noun (new_email, newEmail, new-mail, new_message, new_draft,
// newmail) starts a letter: a draft, ledger-checked, like create + mail noun.
// "new" alone, new_folder and new_label are not mail. Only ADDS: it runs after the
// verb rules found nothing, and only when the name has no recognised verb at all
// (list_new_emails, get_new_messages stay readers; card 6151bb4d).
// Twin: _new_mail in email_extract.py.
function newMail(words) {
  return words.some((w, i) =>
    (w === 'new' && MAIL_CREATE_NOUNS.includes(words[i + 1])) ||
    (w.startsWith('new') && MAIL_CREATE_NOUNS.includes(w.slice(3))))
}

function segmentWords(segment) {
  const s = segment
    .replace(/[^\x00-\x7f]/g, '_')
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .replace(/([A-Z]+)([A-Z][a-z])/g, '$1_$2')
  const words = s.toLowerCase().split(/[^a-z0-9]+/).filter(Boolean)
  while (words.length && /^v[0-9]+$/.test(words[0])) words.shift()
  return words
}

function segmentAction(segment, ruleOk = false) {
  const words = segmentWords(segment)
  const entries = []
  words.forEach((w, index) => {
    const v = mailVerb(w)
    if (v) entries.push({ ...v, index })
  })
  if (entries.some((e) => MAIL_SEND_ANYWHERE.has(e.verb))) return 'send'
  if (entries.length && MAIL_SEND_VERBS.has(entries[0].verb)) return 'send'
  if (entries.length && MAIL_DRAFT_VERBS.has(entries[0].verb)) {
    if (entries[0].verb === 'create' && createNotMail(entries[0], words, ruleOk)) return null
    return 'draft'
  }
  return entries.length === 0 && newMail(words) ? 'draft' : null
}

// Is this action segment a rule / filter WRITE (create_rule, update_filter,
// set_inbox_rules, createRule, createrule ...)? Twin: _segment_writes_rule.
function segmentWritesRule(segment) {
  const words = segmentWords(segment)
  let noun = false
  let write = false
  for (const w of words) {
    if (CREATE_RULE_NOUNS.has(w)) noun = true
    if (RULE_WRITE_VERBS.has(w)) write = true
    for (const n of CREATE_RULE_NOUNS) {
      if (w.length > n.length && w.endsWith(n) && RULE_WRITE_VERBS.has(w.slice(0, -n.length))) { noun = true; write = true }
    }
  }
  return noun && write
}

// ---- Name-independent forwarding rule (card 3d6e5181 N3) ----------------------------
// The closed rule / filter name lists above (RULE_WRITE_VERBS, segmentWritesRule) did
// not converge: a rule or forwarding setting under a name nobody listed (manage_rules,
// define_rule, configure_filter, set_messagerules, update_auto_forwarding ...) passed.
// The rule below does not read the name's nouns at all, it asks two questions: is the
// tool a READER (isReadAction: a closed list, fail-closed), and does its input FORWARD
// (hasForwardKeyName)? A non-reader whose input forwards is mail-rule-forward under
// ANY name. The 6151bb4d rule stays on top of it, unchanged (it also counts a bare
// address, but only for rule / filter names).
//
// READER = some word of the action segment(s) is a READ word (whole word, or the start
// of a glued word: getrules, listemails) AND no word contains a write / forwarding SIGN
// (substring, so createrule, get_or_create_rule, list_and_forward are not readers).
// Nouns (rule, filter, setting, alias, vacation, label) are NOT signs: list_rules,
// get_rules and get_settings are readers. Everything else is NOT a reader: an unknown
// verb is a write. No position is looked at, so a prefix (v2_, gmail_) does not matter.
// 'watch' and 'export' are readers (spec 3.3). Benign look-alikes (address, settings,
// input, output, asset, offset ...) are stripped before the sign test: they contain
// 'add', 'set', 'put' without being verbs. A sign can only make the call a non-reader,
// i.e. stricter. Twin: _is_read_action in scripts/hooks/email_extract.py.
const READ_WORDS = ['get', 'list', 'search', 'read', 'fetch', 'count', 'watch', 'describe', 'view',
  'find', 'query', 'peek', 'show', 'check', 'download', 'export', 'lookup', 'preview', 'verify']
const NON_READ_SIGNS = ['create', 'update', 'set', 'add', 'save', 'edit', 'modify', 'put', 'patch',
  'upsert', 'replace', 'insert', 'import', 'enable', 'disable', 'apply', 'manage', 'configure',
  'define', 'toggle', 'change', 'write', 'post', 'make', 'delete', 'remove', 'move', 'mark',
  'forward', 'redirect', 'fwd', 'send', 'reply', 'delegate', 'purge', 'clear', 'empty', 'trash',
  'archive', 'unsubscribe', 'subscribe', 'block', 'snooze', 'run', 'exec', 'submit', 'grant',
  'share', 'invite', 'register', 'schedule', 'copy', 'clone', 'route', 'relay', 'bounce',
  'deliver', 'dispatch', 'publish', 'push', 'transfer', 'assign', 'link', 'append', 'attach',
  'upload', 'init', 'rename', 'reset', 'restore', 'revoke', 'sync']
const NON_READ_WORDS = new Set(['and', 'then'])
const BENIGN_LOOKALIKES = /settings?|address(?:es)?|inputs?|outputs?|assets?|datasets?|offsets?|bookmarks?|rulesets?/g
export function isReadAction(segments) {
  const words = []
  for (const s of segments) words.push(...segmentWords(String(s)))
  let read = false
  for (const w of words) {
    if (NON_READ_WORDS.has(w)) return false
    const bare = w.replace(BENIGN_LOOKALIKES, '')
    if (NON_READ_SIGNS.some((n) => bare.includes(n))) return false
    if (READ_WORDS.some((r) => w === r || w.startsWith(r))) read = true
  }
  return read
}

// Forwarding in the tool INPUT, name-independent (card 3d6e5181 N3, decisions Q3, Q4;
// the free-text invariant is card 61fcac1e).
// A KEY containing forward / redirect (any depth, also inside a string that parses as
// JSON, double encoding included), case-insensitive; and, only with `valueWords`, a
// forward / redirect WORD in a string value (word start: "type":"forward", `redirect
// :copy`, autoForward count; "straightforward" does not). A bare address ("@") does
// NOT count here (IMAP Message-IDs).
//
// The invariant. A message can leave the house through a rule / script only by a Sieve
// `redirect` or an enotify `mailto:` (or a forward KEY of a settings API), and the
// command name cannot be encoded (encoded-character acts inside a string literal
// only), so the word test finds it whatever the syntax around it. No syntax pattern
// is kept: Sieve is an executable language and a closed list of its spellings did not
// converge (card 3d6e5181 N4 B2). So there are two modes, chosen by the CALLER from the
// tool NAME (which the installed MCP server gives, not the attacker; a name-side list
// can only err towards strict):
//   - strict (a tool that is NOT a plain draft, see isPlainDraft): every string value
//     gets the word test and the `mailto:` test, whatever its key, except INERT keys.
//     Free text is not exempt here: a rule description or a settings message that says
//     "forwarded" is denied (fail-closed price of the invariant, Brainy 6415).
//   - plain draft: prose keys (FREE_TEXT_KEYS, or a key that ENDS in body / text /
//     content / html: message_body, plainText) and the file NAMES of an attachment
//     (ATTACH_FILE_KEYS: filename, attachmentName, name, but only INSIDE an attachment
//     container, ATTACH_KEYS: attachments, attachment, and files below one; the strings
//     directly in the container count too: Fwd_invoice.pdf) are letter content and exempt
//     from the word test; every other value still gets the word test, but not `mailto:`
//     (a link in a signature is no forwarding). A bare `path`, `paths`, `file`, `files`
//     or `filePath` key is NOT a file name (a JSON-patch `path: /forwardTo` is one),
//     and the match is exact or by suffix on purpose, so `actionName` or `bodyAction` are
//     NOT free text, and a rule script (`sieveScript`) is not either.
// INERT keys are exempt in both modes: label / folder identifiers ("Forwarded") name a
// place (a bare `destination` / `target` / `targetFolder` is NOT inert: a global exemption
// there let a script or redirect value through in strict mode, 61fcac1e BE r2 B4), a
// selector (`query`, `search` ..) only picks messages, and an auto-reply text is stored,
// not executed; none of them sends a message to a third party. They
// exempt the VALUE words only: a forward KEY below them (also inside a JSON string in
// the value) still counts, in every mode. A label / folder tool (isLabelFolderTool) is
// strict, and only its NAME keys (LABEL_NAME_KEYS: name, displayName, label, labelName,
// folderName, title) are inert, so a forwarding setting in any other key still denies.
// Same bounds and fail-closed exits as
// hasForwardKey (too deep, too many nodes, a string too long to parse, a non-object
// input = true).
// Twin: _has_forward_key_name in scripts/hooks/email_extract.py.
const FREE_TEXT_KEYS = new Set(['body', 'htmlbody', 'textbody', 'plaintext', 'plainbody', 'bodypreview',
  'subject', 'text', 'content', 'html', 'snippet',
  'title', 'description', 'comment', 'note', 'summary', 'preview', 'message', 'name'])
const INERT_KEYS = new Set(['label', 'labels',
  'labelids', 'addlabelids', 'removelabelids', 'labelid', 'labelname', 'folder', 'folderid', 'foldername',
  'destinationfolder', 'destinationfolderid', 'parentfolderid', 'mailbox',
  'signature', 'query', 'q', 'search', 'keyword', 'keywords',
  'responsebodyplaintext', 'responsebodyhtml', 'internalreplymessage', 'externalreplymessage', 'autoreplymessage'])
// the name keys of a label / folder tool: inert only for such a tool (isLabelFolderTool)
const LABEL_NAME_KEYS = new Set(['name', 'displayname', 'label', 'labelname', 'foldername', 'title'])
// an attachment container (and `files` below one), and the file-name keys that count inside it
const ATTACH_KEYS = new Set(['attachments', 'attachment'])
const ATTACH_FILE_KEYS = new Set(['filename', 'attachmentname', 'name'])
const FREE_TEXT_SUFFIX = /(?:body|text|content|html)$/
const FORWARD_WORD = /(?<![A-Za-z])(?:forward|redirect|fwd)/i
const MAILTO = /mailto:/i
// the walk's `free` flag: 0 not free text, 1 prose, 2 inert key, 3 attachment file name,
// 4 attachment container (its own strings are file names, its keys are classified again)
const FORWARD_WORD_CAMEL = /[a-z](?:Forward|Redirect)/
export function hasForwardKeyName(input, valueWords = true, strict = false, labelNameKeys = false) {
  if (typeof input !== 'object' || input === null) return true
  let nodes = 0
  const stack = [[input, 0, 0]]
  while (stack.length) {
    const [v, depth, free] = stack.pop()
    if (depth > FORWARD_WALK_MAX_DEPTH) return true
    if (typeof v === 'string') {
      const exempt = free === 2 || (!strict && free !== 0)
      if (valueWords && !exempt && (FORWARD_WORD.test(v) || FORWARD_WORD_CAMEL.test(v))) return true
      if (valueWords && strict && !exempt && MAILTO.test(v)) return true
      if (FORWARD_JSON_START.test(v)) {
        if (v.length > FORWARD_JSON_MAX_CHARS) return true
        let parsed
        try { parsed = JSON.parse(v) } catch (err) { if (err instanceof SyntaxError) continue; return true }
        if (typeof parsed === 'string') stack.push([parsed, depth + 1, free])
        else if (typeof parsed === 'object' && parsed !== null) stack.push([parsed, depth + 1, 0])
      }
      continue
    }
    const isArr = Array.isArray(v)
    for (const [k, x] of (isArr ? v.map((y) => [null, y]) : Object.entries(v))) {
      if (++nodes > FORWARD_WALK_MAX_NODES) return true
      let childFree = isArr ? free : 0
      if (k !== null) {
        const key = k.toLowerCase()
        if (key.includes('forward') || key.includes('redirect')) return true
        const norm = key.replace(/[^a-z0-9]/g, '')
        childFree = (labelNameKeys && LABEL_NAME_KEYS.has(norm)) || INERT_KEYS.has(norm) ? 2
          : ATTACH_KEYS.has(norm) || (free === 4 && norm === 'files') ? 4
          : free === 4 && ATTACH_FILE_KEYS.has(norm) ? 3
          : (FREE_TEXT_KEYS.has(norm) || FREE_TEXT_SUFFIX.test(norm)) ? 1 : 0
      }
      if (typeof x === 'string' || (typeof x === 'object' && x !== null)) stack.push([x, depth + 1, childFree])
    }
  }
  return false
}

// A non-reader call whose input forwards, under any name. A name the NAME classifier
// calls a send is left to the send branches (false here); readers never match. Every
// other tool, the draft class included (update_settings, create_forwarding_address,
// update_auto_forwarding: update / create are draft verbs), needs a forward / redirect
// KEY or a forward / redirect WORD in a value (decision Q4, AC10); a plain draft
// (isPlainDraft) is read in the lenient mode, every other tool in the strict one (see
// hasForwardKeyName). The "looking forward" of a plain draft body is prose and a bare
// address is no forwarding, so a draft still goes the ledger way (AC8, AC12). Note:
// decision Q3 said KEY only for drafts; AC10 (update_settings with a Sieve `redirect`
// value, a `type: forward` action) needs the value words for the draft class too.
function nameIndependentForward(segments, toolInput) {
  const classes = segments.map((p) => segmentAction(p, false))
  if (classes.includes('send') || isReadAction(segments)) return false
  // manage_email multiplexes its operations in a VALUE (operation: "forward"), and its own
  // branch below decides those (kind draft-required): only a forward KEY counts here, so the
  // kind of the existing manage_email denies does not change.
  const multiplexed = segments.some((s) => segmentWords(s).join('_') === 'manage_email')
  const labelFolder = isLabelFolderTool(segments)
  return hasForwardKeyName(toolInput, !multiplexed, labelFolder || !isPlainDraft(segments, classes), labelFolder)
}

// A rule / filter / script / settings / automation word in a segment: such a tool is no
// letter. A word is matched as a substring (automat: automation, automatic; auto:
// autoreply, auto_forward).
const RULE_CLASS_WORDS = ['rule', 'filter', 'script', 'sieve', 'setting', 'vacation', 'forwarding', 'alias',
  'automat', 'flow', 'policy', 'auto', 'responder', 'config', 'hook', 'trigger', 'route', 'routing', 'account',
  'profile']
// A mail or calendar item noun: a draft verb with no such noun in its name (create_label,
// create_thing) is no letter either. A noun matches a WHOLE name segment word (after the
// camelCase / _ / - split), never a substring: "profile" is not "file", "gmailbox" is not "mail".
const MAIL_NOUNS = ['draft', 'drafts', 'message', 'messages', 'mail', 'mails', 'email', 'emails', 'reply', 'replies',
  'compose', 'forward', 'event', 'events', 'appointment', 'appointments', 'calendar', 'calendars', 'rsvp',
  'response', 'responses', 'answer', 'answers', 'file', 'files', 'doc', 'docs', 'document', 'documents']
// A plain draft is identified POSITIVELY: the NAME classifier calls it a draft, a segment
// has a mail noun, and no segment has a rule-class word (the rule word wins: compose_rule,
// draft_filter). Its prose and file values are letter content (a body that says "please
// forward this to x@y" is a letter, the ledger checks the recipients); every other
// non-reader tool is read in strict mode. The two lists are closed on purpose: the name
// comes from the installed MCP server, not from the attacker, so a miss only makes a
// tool strict (it never opens the exemption for an unknown name).
// Twin: _is_plain_draft in scripts/hooks/email_extract.py.
export function isPlainDraft(segments, classes) {
  if (!classes.includes('draft')) return false
  if (!segments.some((s) => segmentWords(s).some((w) => MAIL_NOUNS.includes(w)))) return false
  return !segments.some((s) => segmentWords(s).some((w) => RULE_CLASS_WORDS.some((r) => w.includes(r))))
}

// A label / folder / category / tag tool (create_label, update_folder, ...) names a
// container, not a letter or a rule: its NAME ("Forwarded", "Forwarded Items") is not a
// forward. Only that name is exempt from the free-text word test (LABEL_NAME_KEYS: name,
// displayName, label, labelName, folderName, title); every other key of the tool keeps the
// strict word test, and the forward KEY test applies to all of it. It needs a create /
// update / rename / add / move verb word, and no segment may have a rule-class, forward or
// redirect word (create_folder_rule, update_label_settings stay strict). A mailbox is NOT a
// label: a mailbox object carries forwarding settings. Closed list, whole words only.
// Twin: _is_label_folder_tool in scripts/hooks/email_extract.py.
const LABEL_FOLDER_NOUNS = ['label', 'labels', 'folder', 'folders', 'category', 'categories', 'tag', 'tags']
const LABEL_FOLDER_VERBS = ['create', 'update', 'rename', 'add', 'move']
export function isLabelFolderTool(segments) {
  const words = segments.flatMap((s) => segmentWords(s))
  if (!words.some((w) => LABEL_FOLDER_NOUNS.includes(w)) || !words.some((w) => LABEL_FOLDER_VERBS.includes(w))) return false
  return !words.some((w) => [...RULE_CLASS_WORDS, 'forward', 'redirect'].some((r) => w.includes(r)))
}

// A rule / filter write whose input forwards (hasForwardKey), or any non-reader call
// whose input forwards (nameIndependentForward): a standing rule that sends mail out.
// It is not a draft the ledger could vouch for: the gate denies it outright (kind
// mail-rule-forward; card 6151bb4d r2 B2, card 3d6e5181 N3). Needs the input: name
// only, there is nothing to classify. Pure, never throws.
// Twin: mail_rule_forward in scripts/hooks/email_extract.py.
export function mailRuleForward(toolName, toolInput = undefined) {
  if (toolInput === undefined) return false
  const name = typeof toolName === 'string' ? toolName : ''
  const parts = name.split('__')
  if (parts.length < 3 || parts[0].toLowerCase() !== 'mcp' || CHANNEL_PLUGIN_RE.test(name)) return false
  if (NON_MAIL_SERVER_RE.test(name.slice(5))) return false
  const segments = parts.slice(2)
  if (segments.some(segmentWritesRule) && hasForwardKey(toolInput)) return true
  return nameIndependentForward(segments, toolInput)
}

// 'send', 'draft' or null. Pure, never throws. Name only: create + rule / filter is
// a draft (fail-closed). With the tool INPUT as the second argument the input-aware
// layer lowers create_rule / create_filter to null when the input carries no
// forwarding (hasForwardKey), and classifies a rule / filter write that forwards as
// a send (mailRuleForward).
export function mailToolAction(toolName, toolInput = undefined) {
  const name = typeof toolName === 'string' ? toolName : ''
  const parts = name.split('__')
  if (parts.length < 3 || parts[0].toLowerCase() !== 'mcp' || CHANNEL_PLUGIN_RE.test(name)) return null
  if (NON_MAIL_SERVER_RE.test(name.slice(5))) return null
  if (mailRuleForward(name, toolInput)) return 'send'
  const ruleOk = toolInput !== undefined && !hasForwardKey(toolInput)
  const found = new Set(parts.slice(2).map((p) => segmentAction(p, ruleOk)))
  if (found.has('send')) return 'send'
  if (found.has('draft')) return 'draft'
  return null
}

// RECOVERYPATH920: the recovery command in the deny message used to be the
// relative `node scripts/recipient-ledger.mjs`. Sub-agents run with cwd
// agents/<name>/, which has NO scripts/ directory, so from a gated agent the
// command died with "Cannot find module .../agents/<name>/scripts/
// recipient-ledger.mjs" -- the one path the gate offers was unreachable from
// the only place it is ever read. Resolve it from this file's own location:
// the gate script and the ledger CLI ship in the same directory, so this is
// correct from any cwd.
const LEDGER_CLI = join(dirname(fileURLToPath(import.meta.url)), 'recipient-ledger.mjs')

// Tool-input fields that carry recipient addresses across the mail tools we
// have. A reply that only names a messageId has none of these -- it is
// addressed by the thread, not by us, so there is nothing to invent.
const RECIPIENT_FIELDS = ['to', 'cc', 'bcc', 'recipients', 'recipient', 'recipient_email']

// Every address in this call that the ledger does not know. Pure: the lookup is
// injected so tests never touch the real ledger file.
export function unverifiedRecipients(toolInput, isVerified) {
  const out = []
  for (const field of RECIPIENT_FIELDS) {
    const value = toolInput?.[field]
    if (value === undefined || value === null || value === '') continue
    for (const addr of parseAddresses(value).addresses) {
      if (!isVerified(addr) && !out.includes(addr)) out.push(addr)
    }
  }
  return out
}

// Every recipient piece of this call that is not exactly ONE address
// (recipient-ledger.mjs parseAddresses): two addresses in one array item, an
// address in the display name, two <...> pairs, an object value. The ledger
// cannot vouch for what it cannot read as one address, and the mail tool may
// still deliver to it, so the gate denies on any such piece.
export function unparseableRecipients(toolInput) {
  const out = []
  for (const field of RECIPIENT_FIELDS) {
    const value = toolInput?.[field]
    if (value === undefined || value === null || value === '') continue
    for (const piece of parseAddresses(value).unparseable) {
      if (!out.includes(piece)) out.push(piece)
    }
  }
  return out
}

// Default lookup for the live hook: read the ledger once per invocation. A
// missing or corrupt ledger means nothing is verified, so the gate blocks --
// an evidence store that cannot be read must never open the gate silently.
function ledgerLookup() {
  const ledger = loadLedger()
  return (addr) => isVerifiedIn(ledger, addr)
}

// Pure decision: does this tool call send (or attempt to send) email?
// Returns { deny, kind? }. `kind` selects the deny wording at the hook
// entrypoint: 'draft-required' is the manage_email case (drafting is fine,
// only the actual send is refused), 'send_email' is the direct MCP send tool
// (the only path the thread-reply capability below can narrow),
// 'unverified-recipient' is a draft/manage_email address with no recorded
// source, and everything else is the sub-agent governance block.
export function gateDecision(toolName, toolInput, isVerified = null, cwd = process.cwd()) {
  const name = String(toolName ?? '')
  // A rule / filter write that forwards (card 6151bb4d r2 B2): a standing rule that
  // sends mail out is denied outright, before any name branch, whatever the ledger
  // says about an address in it (mailRuleForward).
  if (mailRuleForward(name, toolInput)) return { deny: true, kind: 'mail-rule-forward' }
  // Lazy: only build the ledger lookup when a call actually carries addresses,
  // so a read-shaped tool call never pays a file read.
  const verify = isVerified ?? (() => {
    let cached = null
    return (addr) => (cached ??= ledgerLookup())(addr)
  })()
  // Any MCP send_email tool, name-agnostic (gmail or a differently-named
  // server in a customer install -> the matcher + this both key on send_email).
  // Deliberately NOT ledger-checked. This branch is either an unconditional
  // deny, or -- with --allow-thread-reply -- a narrowing that only passes
  // recipients read back from the live thread the reply belongs to. A
  // participant of a thread we can read IS a sourced address in the same sense
  // the ledger means it (the From header of a mail they sent us), so gating it
  // against the file would refuse a legitimately sourced reply. The ledger
  // guards the paths where an address can be typed from memory: drafting and
  // manage_email.
  const mailKind = classifyMailTool(name)
  if (mailKind === 'send_email') return { deny: true, kind: 'send_email' }
  // The claude.ai Gmail connector (mcp__claude_ai_Gmail__*) has no send_email:
  // its sends are send_message / reply / forward. Drafts stay allowed and the
  // reads are not sends, only the three send-shaped tools are denied
  // (GMAILCONNECTOR914 -- before this line a sub-agent could send through the
  // connector with no gate at all).
  // Kind is NOT 'send_email' on purpose: the thread-reply narrowing at the
  // entrypoint reads send_email-shaped fields (threadId/to), which a connector
  // reply does not carry, so the connector stays fully gated for every agent.
  // reply_all is a send on a server of any name, and a tool prefix does not
  // hide any of the four (classifyMailTool).
  if (mailKind === 'connector_send') return { deny: true, kind: 'connector-send' }
  // send_draft sends an existing draft by draftId: a send like any other, and
  // one whose recipients this gate cannot even see. Sub-agents may not send,
  // so it gets the governance deny, with no narrowing.
  if (mailKind === 'send_draft') return { deny: true, kind: 'send-draft' }
  // Draft-creating MCP tools. Drafting is allowed (that is the whole point of
  // the draft-required rule), but the ADDRESS in a draft still has to be
  // verified: the owner presses send on what we typed, so an invented address
  // reaches the outside world through a draft just as surely as through a send.
  if (mailKind === 'draft') {
    // MS365MAIL1024, round 2: the Graph read is decided by the tool NAME, not
    // by the payload's shape -- a non-Graph tool with an object body keeps the
    // flat checks below, and a Graph draft carries its recipients as
    // toRecipients/ccRecipients/bccRecipients items, read the same strict way;
    // an unreadable recipient list fails closed. A Graph-named draft with no
    // Graph material at all (flat to/cc/bcc only) keeps the flat checks too:
    // that is the pinned draft contract, and it errs toward the flat read,
    // which checks every field it can see.
    if (isMs365Tool(name) && ms365HasGraphFields(toolInput)) {
      const r = ms365Recipients(toolInput)
      if (r.reason) return { deny: true, kind: 'unparseable-recipient', addresses: [r.reason] }
      const all = [...r.to, ...r.cc, ...r.bcc]
      const unparseable = unparseableRecipients({ to: all })
      if (unparseable.length) return { deny: true, kind: 'unparseable-recipient', addresses: unparseable }
      const bad = unverifiedRecipients({ to: all }, verify)
      if (bad.length) return { deny: true, kind: 'unverified-recipient', addresses: bad }
      return { deny: false }
    }
    const unparseable = unparseableRecipients(toolInput)
    if (unparseable.length) return { deny: true, kind: 'unparseable-recipient', addresses: unparseable }
    const bad = unverifiedRecipients(toolInput, verify)
    if (bad.length) return { deny: true, kind: 'unverified-recipient', addresses: bad }
    return { deny: false }
  }
  // @aaronsb/google-workspace-mcp multiplexes read, draft and send behind one
  // manage_email tool, so the tool NAME cannot decide this one -- the operation
  // plus the draft flag can. This is what replaces the server's own
  // draft-only-email safety policy, which blocks drafting too: that policy keys
  // on ctx.operation alone and never looks at draft:true, so with it enabled the
  // mailbox is effectively read-only (verified live, 2026-08-10).
  if (mailKind === 'manage_email') {
    // A missing or non-string operation is closed (card d8d3441e): it goes down
    // the address check + draft rule like an outbound one.
    if (!manageEmailOpClosed(toolInput?.operation)) return { deny: false }
    // The address check runs before the draft rule, so it applies to the send
    // AND to the draft the deny message would send us back to write.
    const unparseable = unparseableRecipients(toolInput)
    if (unparseable.length) return { deny: true, kind: 'unparseable-recipient', addresses: unparseable }
    const bad = unverifiedRecipients(toolInput, verify)
    if (bad.length) return { deny: true, kind: 'unverified-recipient', addresses: bad }
    // Fail safe: only an explicit draft request passes. A missing/ambiguous
    // flag is treated as a real send, even though the server would itself
    // force a draft when attachments are present.
    const draft = toolInput?.draft
    if (draft === true || draft === 'true') return { deny: false }
    return { deny: true, kind: 'draft-required' }
  }
  if (name === 'Bash') {
    const cmd = String(toolInput?.command ?? '')
    if (isSendInvocation(cmd)) return wrapperDepthHit(cmd) ? { deny: true, kind: 'wrapper-depth' } : { deny: true }
    if (scriptRunSends(cmd, cwd)) return { deny: true, kind: 'script-send' }
  }
  // graph-forward N1b: a mail tool none of the names above lists, by its
  // action. A send is the governance block, unconditionally (never the
  // thread-reply narrowing, which reads send_email-shaped fields); a draft is
  // allowed to a sourced address only, exactly like DRAFT_TOOL_RE above.
  const action = mailToolAction(name, toolInput)
  if (action === 'send') return { deny: true, kind: 'mail-tool-send' }
  if (action === 'draft') {
    const bad = unverifiedRecipients(toolInput, verify)
    if (bad.length) return { deny: true, kind: 'unverified-recipient', addresses: bad }
  }
  return { deny: false }
}

// Deny wording for the manage_email case. Unlike the sub-agent governance
// block this is not about who the agent is: drafting stays open, so the fix is
// to re-issue the same call with draft: true and hand the draft to the owner.
export function buildDraftOnlyMsg(ownerName) {
  return (
    'Kimeno email kuldese tiltott (draft-kapu). ' +
    'Ird meg ugyanezt draft: true kapcsoloval, es jelezd a tulajdonosnak ' +
    `(${ownerName}), hogy a Gmail piszkozatok kozott varja a jovahagyasat. ` +
    'Csak VERIFIKALT cimre. A kuldes gombot ember nyomja meg.'
  )
}

// Deny wording for an address the ledger does not know. This is the one deny
// the agent can clear on its own -- by going and finding where the address
// actually comes from. It names the exact command, so the cheap path is the
// correct path and not "write it anyway".
export function buildUnverifiedRecipientMsg(addresses) {
  const list = addresses.join(', ')
  const first = addresses[0] ?? 'cim@pelda.hu'
  return (
    `Nem igazolt cimzett: ${list}. ` +
    'Ez a kapu azert van, mert egy kitalalt cimre meno level neman elveszik ' +
    '(support@connectors.hu, 2026-08-14, 550 User doesn\'t exist). ' +
    'Ne talalgass es ne a support@/info@ szokast hasznald: keresd meg a cimet ' +
    'egy valodi forrasban -- a toluk kapott level From fejleceben ' +
    '(manage_email search: from:<domain> in:anywhere), az elo oldalukon, ' +
    'a Woo rendelesben vagy a Notion lapon. Aztan vedd fel a ledgerbe:\n' +
    `  node ${LEDGER_CLI} add ${first} --source <forras> --note "<honnan>"\n` +
    `  --source: ${SOURCE_HELP}\n` +
    'Ha nem talalsz forrast, a cim NINCS meg: mondd meg a gazdanak, ne kuldj levelet.'
  )
}

// Deny wording for a rule / filter that forwards or redirects mail. No ledger entry
// helps: the rule would send every matching mail out for good, unseen.
export function buildRuleForwardMsg() {
  return (
    'Tovabbito szabaly / szuro tiltott (mail-rule-forward): a szabaly a beerkezo leveleket ' +
    'tartosan kifele kuldene. Hozz letre szabalyt tovabbitas / atiranyitas nelkul ' +
    '(csak cimke, mappa, olvasottnak jeloles), a tovabbitast a gazda allitja be.'
  )
}

// Deny wording for a recipient piece that is not exactly one address. The fix
// is on the caller's side: one clean address per item.
export function buildUnparseableRecipientMsg(pieces) {
  return (
    `Nem ertelmezheto cimzett: ${pieces.join(' | ')}. ` +
    'A cimzett-mezo minden eleme (vesszovel vagy pontosvesszovel elvalasztva) ' +
    'pontosan EGY cim legyen: "cim@pelda.hu" vagy "Nev <cim@pelda.hu>". ' +
    'Ket cim egy elemben, cim a megjelenitett nevben vagy tobb <...> ' +
    'nem ellenorizheto a cimzett-ledgerrel, ezert a kapu tilt (fail-closed). ' +
    'Ird at a mezot tiszta cimekre, aztan kuldd ujra.'
  )
}

// Wording for a call that needs the ledger while the ledger MODULE does not
// load (HOOKDEPLOAD1008). It goes to stderr with exit 2, not as the JSON deny:
// no rewrite of the call helps, the module has to be repaired, and that is the
// main agent's job -- this gate does not run in its session.
export function buildLedgerUnavailableMsg(err) {
  return (
    'EMAIL-KAPU: TILTVA. A kapu fuggosege (scripts/recipient-ledger.mjs) nem toltheto be ' +
    `(${err?.message ?? err}) -- fail-closed: a cimzett nem ellenorizheto, ezert a hivas nem mehet at. ` +
    'A modult a fo ugynok javitja (ez a kapu az o munkameneteben nem fut): jelezd neki.\n'
  )
}

// Pure builder for the deny message, so the brand/owner substitution is
// provable without spawning the hook. With the stock defaults (botName
// 'Marveen', ownerName 'Szabolcs') the wording is byte-identical to before.
export function buildGateMsg(botName, ownerName) {
  return (
    'Email-kuldes sub-agentkent tiltott (governance hard-gate). ' +
    `Kuldd a tervezett emailt (CIMZETT + TARGY + TELJES SZOVEG) ${botName}nek inter-agent uzenetben ` +
    `jovahagyasra; a kimeno emailt ${botName} kuldi. Csak VERIFIKALT cimre (soha nem nevbol talalt cim). ` +
    `Soha ne irj ala ${ownerName} nevevel, es soha ne kerj penzt senki neveben.`
  )
}

// Resolve the brand + owner display names for the deny message. The hook runs
// standalone (no config.ts), so read the install's .env directly, keyed off
// this file's own location (<root>/scripts/email-send-gate.mjs -> <root>/.env).
// Any failure falls back to the stock defaults, so the gate never breaks and a
// bare install keeps the original wording.
export function readBrandEnv(readFile = (p) => readFileSync(p, 'utf-8')) {
  const fallback = { botName: 'Marveen', ownerName: 'Szabolcs' }
  try {
    const envPath = join(dirname(fileURLToPath(import.meta.url)), '..', '.env')
    const raw = readFile(envPath)
    const pick = (key) => {
      const m = raw.match(new RegExp(`^\\s*${key}\\s*=\\s*(.*)$`, 'm'))
      if (!m) return ''
      return m[1].trim().replace(/^["']|["']$/g, '').trim()
    }
    return {
      botName: pick('BOT_NAME') || fallback.botName,
      ownerName: pick('OWNER_NAME') || fallback.ownerName,
    }
  } catch {
    return fallback
  }
}

// --- thread-scoped reply (BONIMAIL910) --------------------------------------
// Owner decision 2026-09-10: ONE named agent may send outbound email, but ONLY
// into an EXISTING Gmail thread and ONLY to addresses that already appear in
// that thread's headers. The capability is granted per agent in code
// (agent-scaffold.ts appends --allow-thread-reply to this hook's command when
// the agent's capability list contains EMAIL_THREAD_REPLY_CAPABILITY); every
// other agent keeps the unconditional deny above.
//
// Why THREAD-MEMBERSHIP and not a topic rule: the 2026-06-25 incident that
// created this gate was a sub-agent mailing a FABRICATED address in the
// owner's name. Membership in an existing thread is checkable in code; "is
// this financial" is not. The narrowing closes exactly the failure shape that
// created the rule: a new address can never be introduced.
//
// Every branch below fails CLOSED: missing threadId, unparseable recipient,
// empty participant list, credential/fetch/HTTP error, timeout -> deny.

// One address token. Deliberately simple: it must match what appears both in
// the tool input and in Gmail's From/To/Cc header values.
const ADDR_TOKEN = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi

// Parse one recipient entry ("addr" or "Name <addr>") to a bare lowercase
// address. Returns '' when the entry is not a single clean address -- the
// caller treats that as deny (an unparseable recipient must never slip past
// the membership check).
export function extractAddress(raw) {
  const s = String(raw ?? '').trim()
  // More than one '@' is ONE clean address only when the display name IS the
  // bracketed address ("jane@example.com" <jane@example.com>, a common client
  // form). "invented@example.org <known@example.com>" would otherwise pass the
  // trailing-bracket test as known@example.com, with a second address in the
  // display name the membership check never looked at.
  if ((s.match(/@/g) ?? []).length > 1) {
    const m = s.match(/^([^<>]*)<([^<>]+)>$/)
    if (!m) return ''
    const display = m[1].trim().replace(/^"(.*)"$/, '$1').trim()
    if (display.toLowerCase() !== m[2].trim().toLowerCase()) return ''
  }

  const angle = s.match(/<([^<>]+)>$/)
  const cand = (angle ? angle[1] : s).trim()
  return /^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$/i.test(cand) ? cand.toLowerCase() : ''
}

// Validate the send_email tool input as a thread-reply request. Pure.
// Returns { ok: true, threadId, recipients } or { ok: false, reason }.
export function threadReplyRequest(toolInput) {
  const threadId = toolInput?.threadId
  if (typeof threadId !== 'string' || !threadId.trim()) {
    return { ok: false, reason: 'threadId hianyzik (uj szal nyitasa tiltott)' }
  }
  const raw = [toolInput?.to, toolInput?.cc, toolInput?.bcc]
    .flatMap((v) => (Array.isArray(v) ? v : v == null ? [] : [v]))
  if (!raw.length) return { ok: false, reason: 'nincs cimzett' }
  const recipients = []
  for (const r of raw) {
    const addr = extractAddress(r)
    if (!addr) return { ok: false, reason: `ertelmezhetetlen cimzett: ${String(r)}` }
    recipients.push(addr)
  }
  return { ok: true, threadId: threadId.trim(), recipients }
}

// The membership decision itself. Pure. Empty participant list denies: a
// thread we could not read participants from authorizes nothing.
export function threadMembershipDecision(recipients, participants) {
  const set = new Set((participants ?? []).map((p) => String(p).toLowerCase()).filter(Boolean))
  if (!set.size) return { allow: false, reason: 'a szal resztvevo-listaja ures (fail-closed)' }
  for (const r of recipients) {
    if (!set.has(r)) return { allow: false, reason: `cimzett nincs a szalban: ${r}` }
  }
  return { allow: true }
}

// Collect every address that appears in the thread's From/To/Cc/Reply-To
// headers. Pure over the Gmail API thread payload (format=metadata).
export function extractParticipants(threadData) {
  const out = new Set()
  for (const msg of threadData?.messages ?? []) {
    for (const h of msg?.payload?.headers ?? []) {
      const n = String(h?.name ?? '').toLowerCase()
      if (n === 'from' || n === 'to' || n === 'cc' || n === 'reply-to') {
        for (const m of String(h?.value ?? '').matchAll(ADDR_TOKEN)) out.add(m[0].toLowerCase())
      }
    }
  }
  return [...out]
}

// Fetch the thread's participant addresses with the same credentials the Gmail
// MCP server uses (same mailbox the send would go through, so the gate and the
// send see the same thread). Path resolution mirrors the MCP server's own:
// GMAIL_CREDENTIALS_PATH / GMAIL_OAUTH_PATH env overrides, else ~/.gmail-mcp.
// Throws on ANY failure; per-request timeouts keep the whole check well under
// the hook's 10s budget (a hook timeout would be a NON-blocking error, i.e.
// fail-open -- the script must always decide first).
export async function fetchThreadParticipants(threadId, opts = {}) {
  const fetchImpl = opts.fetchImpl ?? fetch
  const readFile = opts.readFile ?? ((p) => readFileSync(p, 'utf-8'))
  const now = opts.now ?? (() => Date.now())
  const home = process.env.HOME || homedir()
  const credPath = process.env.GMAIL_CREDENTIALS_PATH || join(home, '.gmail-mcp', 'credentials.json')
  const keysPath = process.env.GMAIL_OAUTH_PATH || join(home, '.gmail-mcp', 'gcp-oauth.keys.json')
  const creds = JSON.parse(readFile(credPath))
  let accessToken = creds.access_token
  const fresh = typeof creds.expiry_date === 'number' && creds.expiry_date > now() + 60_000
  if (!fresh) {
    const keys = JSON.parse(readFile(keysPath))
    const k = keys.installed ?? keys.web
    if (!k?.client_id || !k?.client_secret || !creds.refresh_token) {
      throw new Error('gmail credentials incomplete')
    }
    const res = await fetchImpl(k.token_uri || 'https://oauth2.googleapis.com/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: k.client_id,
        client_secret: k.client_secret,
        refresh_token: creds.refresh_token,
        grant_type: 'refresh_token',
      }).toString(),
      signal: AbortSignal.timeout(3500),
    })
    if (!res.ok) throw new Error(`token refresh failed: ${res.status}`)
    accessToken = (await res.json())?.access_token
  }
  if (!accessToken) throw new Error('no gmail access token')
  const url = 'https://gmail.googleapis.com/gmail/v1/users/me/threads/'
    + encodeURIComponent(threadId)
    + '?format=metadata&metadataHeaders=From&metadataHeaders=To&metadataHeaders=Cc&metadataHeaders=Reply-To'
  const res = await fetchImpl(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
    signal: AbortSignal.timeout(3500),
  })
  if (!res.ok) throw new Error(`thread fetch failed: ${res.status}`)
  return extractParticipants(await res.json())
}

// Deny wording for the thread-reply case: the agent HAS a send right, the
// specific call fell outside it. Says what the right covers and the way out.
export function buildThreadDenyMsg(botName, detail) {
  return (
    'Kimeno email ezzel a jogosultsaggal CSAK meglevo szalba mehet, es csak a ' +
    `szalban mar szereplo cimzettnek (szal-kapu). Elutasitva: ${detail}. ` +
    `Uj cimzetthez vagy uj szalhoz kuldd a tervezett emailt ${botName}nek ` +
    'inter-agent uzenetben jovahagyasra.'
  )
}

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

// Run as the hook entrypoint only when invoked directly (not when imported by a
// test). Reads the PreToolUse payload from stdin and emits a deny decision for
// email-send tool calls. realpath both sides so a symlinked install path (the
// hook command is an absolute path that may traverse a symlink, e.g. /tmp ->
// /private/tmp on macOS, or a symlinked /home on Linux) still matches -- a raw
// url-vs-argv compare would silently no-op the gate (a security bypass).
function isInvokedDirectly() {
  try {
    const self = realpathSync(fileURLToPath(import.meta.url))
    const entry = process.argv[1] ? realpathSync(process.argv[1]) : ''
    return self === entry
  } catch {
    return false
  }
}
if (isInvokedDirectly()) {
  let payload
  try {
    payload = JSON.parse(readFileSync(0, 'utf-8'))
  } catch {
    allow() // malformed/empty input must never break the agent's tool calls
  }
  let decision
  try {
    decision = gateDecision(payload?.tool_name, payload?.tool_input, null, payload?.cwd || process.cwd())
  } catch (err) {
    // HOOKDEPLOAD1008: the call needed the ledger, and the ledger module did
    // not load. Anything else that throws here is not this branch's to judge.
    if (!LEDGER_LOAD_ERROR) throw err
    process.stderr.write(buildLedgerUnavailableMsg(LEDGER_LOAD_ERROR))
    process.exit(2)
  }
  const { deny: shouldDeny, kind, addresses } = decision
  if (shouldDeny) {
    const { botName, ownerName } = readBrandEnv()
    // An address with no recorded source loses before every other branch,
    // including the thread-reply narrowing below: a verified thread cannot
    // vouch for an unsourced recipient.
    if (kind === 'unparseable-recipient') deny(buildUnparseableRecipientMsg(addresses ?? []))
    if (kind === 'unverified-recipient') deny(buildUnverifiedRecipientMsg(addresses ?? []))
    if (kind === 'draft-required') deny(buildDraftOnlyMsg(ownerName))
    if (kind === 'wrapper-depth') deny(buildWrapperDepthMsg())
    if (kind === 'mail-rule-forward') deny(buildRuleForwardMsg())
    // Thread-scoped narrowing: only when the scaffold wired this agent's hook
    // command with the flag (capability-driven, regenerated on every spawn),
    // and only for the direct send_email tool. Bash send routes and
    // manage_email stay fully gated even for the capable agent.
    if (kind === 'send_email' && process.argv.includes('--allow-thread-reply')) {
      const req = threadReplyRequest(payload?.tool_input)
      if (!req.ok) deny(buildThreadDenyMsg(botName, req.reason))
      let verdict
      try {
        const participants = await fetchThreadParticipants(req.threadId)
        verdict = threadMembershipDecision(req.recipients, participants)
      } catch {
        verdict = { allow: false, reason: 'a szal resztvevoi nem olvashatok (fail-closed)' }
      }
      if (verdict.allow) allow()
      deny(buildThreadDenyMsg(botName, verdict.reason))
    }
    deny(buildGateMsg(botName, ownerName))
  }
  allow()
}
