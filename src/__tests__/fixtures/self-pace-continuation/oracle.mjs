// Card 3660cf43 (planned under the duplicate id 3e13973c), node N0: the differential shell oracle and its guard.
//
// What it is for: the self-pace gate must decide a multi-line command the way the REAL shell reads it. The only
// ground truth is a shell, so a test has to run one. That is dangerous for a corpus full of `crontab -r`, so the
// shell never sees the corpus text. It sees a marker-rewritten copy:
//   - every command word of the corpus (crontab, at, tmux, curl, git, ls, cat, grep, python3) is replaced by a
//     shell FUNCTION defined at the top of the script (`__m1() { printf '@@M1@@\n'; }`), which only prints a marker;
//   - the executed text therefore contains only those function names, printf, echo, true and shell syntax;
//   - BEFORE anything is spawned, guardOracleScript() refuses (throws OracleRefused) every text that is not provably
//     that. The guard is a POSITIVE allowlist (fix round 1, B2): the text is de-quoted and its backslashes removed
//     (so c""rontab, cr\ontab and $'cron'tab are all `crontab`), quote-blind on purpose (everything inside a quote
//     is read as if it were code, which can only refuse more), and then EVERY command word must be one of
//     __m1..__m9, echo, printf, true or a shell keyword the corpus needs; any other command word is refused. On top:
//     zmodload / zf_ / sysopen / ztcp / zpty / sched / enable / builtin / autoload / emulate anywhere, a function
//     definition, a `.` command, a relative-path word, an absolute-path word, `$((`, `((`, process substitution
//     and a redirect to anywhere but ./name or /dev/null. Two things are cut out of the text before the word check,
//     each only where it is provably inert: a comment whose tail holds nothing but harmless characters, and the
//     body of a heredoc written in the simple first-line form (no `$` and no backtick in it).
//   - the child runs with env = { PATH: '/var/empty' } only, stdin closed, a fresh temp cwd, restricted mode
//     (bash -r / zsh -r) and a 5 s kill timeout. The empty PATH does NOT stop a zsh builtin that zmodload could load
//     (zf_rm ...), which is why the guard refuses the module commands themselves.
// The marker for a dangerous binary (M1 crontab, M2 at, M3 tmux) printing means: the real shell reached that
// command. Nothing here can run the real binary: the names do not resolve (PATH is empty) and the guard has
// already refused every text that could reach one by another route.
// A row that cannot be rewritten safely, or that the allowlist cannot prove safe, is not run: the caller declares it
// with `noOracle` and the test counts it.

import { spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

export const SHELLS = { bash: '/bin/bash', zsh: '/bin/zsh' }
export const DANGER_MARKERS = new Set([1, 2, 3])
export const ORACLE_TIMEOUT_MS = 5000

const MARKER_FUNCTIONS = [1, 2, 3, 4, 5, 6, 7, 8, 9]
export const ORACLE_DEFS = MARKER_FUNCTIONS.map((n) => `__m${n}() { printf '@@M${n}@@\\n'; }`).join('\n') + '\n'

// order matters: `at now` before the bare words
const RENAMES = [
  [/\bat now\b/g, '__m2 now'],
  [/\bcrontab\b/g, '__m1'],
  [/\btmux\b/g, '__m3'],
  [/\bcurl\b/g, '__m4'],
  [/\bgit\b/g, '__m5'],
  [/\bls\b/g, '__m6'],
  [/\bcat\b/g, '__m7'],
  [/\bgrep\b/g, '__m8'],
  [/\bpython3\b/g, '__m9'],
  [/\/tmp\//g, './'],
]

export function rewriteForOracle(text) {
  let out = String(text)
  for (const [rx, to] of RENAMES) out = out.replace(rx, to)
  return out
}

export class OracleRefused extends Error {
  constructor(reason) {
    super(`oracle guard refused: ${reason}`)
    this.name = 'OracleRefused'
    this.reason = reason
  }
}

// --- the guard -------------------------------------------------------------------------------------------
// Words that name a real program or a way to load one; refused anywhere in the de-quoted text, even as an argument
// (belt and braces: the allowlist below already refuses them as command words).
const FORBIDDEN_NAMED = /\b(crontab|at|batch|tmux|launchctl|kill|rm|shutdown|reboot|osascript|curl|wget|nc|ssh|sudo)\b/
const FORBIDDEN_EXEC = /\b(bash|zsh|sh|dash|ksh|csh|tcsh|fish|eval|source|exec|env|xargs|nohup|setsid|command|trap|coproc|find|node|npx|npm|perl|ruby|php|python3?|open|su|doas|chmod|chown|mv|cp|dd|mkfifo|sqlite3|git|gh|ls|cat|grep|tee|mkdir|touch|ln|killall|pkill)\b/
// zsh module loading and the commands that reach out of the function-only world (B2: zmodload z""s""h/files gives
// zf_rm / zf_mv / zf_ln, which the empty PATH does not stop)
const FORBIDDEN_ZSH = /\b(zmodload|sysopen|ztcp|zpty|sched|enable|builtin|autoload|emulate)\b|\bzf_/
const DOT_COMMAND = /(^|[\n;&|({]|&&|\|\|)[ \t]*\.([ \t]|$)/
const ABSOLUTE_WORD = /(^|[\s;&|(){}<>"'`])(\/|~)[A-Za-z0-9_.-]/
const RELATIVE_PARENT = /\.\./
const RELATIVE_WORD = /(^|[^A-Za-z0-9_.-])\.\//
const ALLOWED_REDIRECT = /(?:&>>?|[0-9]?>>?)[ \t]*(?:\.\/[A-Za-z0-9_][A-Za-z0-9_.-]*|\/dev\/null)/g

// the only command words: the marker functions and three harmless builtins
const MARKER_WORD = /^__m[1-9]$/
const PLAIN_COMMANDS = new Set(['echo', 'printf', 'true'])
// keywords after which a command follows / that close a block
const KEYWORDS_OPEN = new Set(['if', 'then', 'elif', 'else', 'do', 'while', 'until', '!', '{'])
const KEYWORDS_CLOSE = new Set(['fi', 'done', '}'])

// Removes quote characters and backslashes the way a reader that trusts nothing would: the quoted text stays
// (it is read as code), a backslash-newline pair vanishes, a backslash before any other character is dropped, and
// the `$` of $'..' / $".." goes. quote-split words (c""rontab, cr\ontab, $'cron'tab) become the plain word.
export function dequote(text) {
  const s = String(text)
  let out = ''
  for (let i = 0; i < s.length; i++) {
    const c = s[i]
    if (c === '\\') {
      i++
      if (i >= s.length) break
      if (s[i] === '\n') continue
      out += s[i]
    } else if (c === "'" || c === '"') {
      continue
    } else if (c === '$' && (s[i + 1] === "'" || s[i + 1] === '"')) {
      continue
    } else {
      out += c
    }
  }
  return out
}

const count = (str, ch) => str.split(ch).length - 1

// A heredoc is cut out only in the simple form: it is on the FIRST line, the line holds nothing but plain words,
// a redirect target and the operator, so no quote, comment or brace can have changed the reading. The body ends at
// the EARLIEST line that either shell could take as the terminator (raw line, or the line after backslash-newline
// joining, blanks and CR ignored): text wrongly kept as code can only be refused, never hidden. A body with `$`
// or a backtick would expand (`$(...)` runs in an unquoted body), so it is not cut out and the text is refused.
const HEREDOC_FIRST_LINE = /^[A-Za-z0-9_ \t.\/>-]*<<-?[ \t]*(?:'([A-Za-z0-9_]+)'|"([A-Za-z0-9_]+)"|([A-Za-z0-9_]+))[ \t]*\r?$/

function cutHeredocBody(body) {
  const lines = body.split('\n')
  const m = HEREDOC_FIRST_LINE.exec(lines[0])
  if (!m) return { text: body, matched: false }
  const tag = m[1] ?? m[2] ?? m[3]
  let rawEnd = -1
  for (let k = 1; k < lines.length; k++) {
    if (lines[k].trim() === tag) { rawEnd = k; break }
  }
  let joinedEnd = -1
  let acc = ''
  for (let k = 1; k < lines.length; k++) {
    const line = lines[k]
    const run = /\\*$/.exec(line)[0].length
    if (run % 2 === 1) { acc += line.slice(0, -1); continue }
    acc += line
    if (acc.trim() === tag) { joinedEnd = k; break }
    acc = ''
  }
  const ends = [rawEnd, joinedEnd].filter((e) => e >= 0)
  const end = ends.length ? Math.min(...ends) : lines.length - 1
  const bodyText = lines.slice(1, end + 1).join('\n')
  if (/[$`]/.test(bodyText)) return { text: body, refused: 'heredoc body with an expansion' }
  return { text: [lines[0], ...lines.slice(end + 1)].join('\n'), matched: true }
}

// A comment is cut out only when the `#` is provably word-initial outside any quote (no quote, backtick or
// backslash earlier on the line) and its tail holds nothing but harmless characters (and backslashes: the shell
// does not continue a comment, so the next line is code, which the allowlist then reads on its own). A line whose
// `#` cannot be proven a comment but which ends in a backslash is refused: the joining would hide the next line.
const SAFE_COMMENT_TAIL = /^[A-Za-z0-9 \t_.,:=@%+-]*\\*$/

function cutComments(text) {
  const lines = text.split('\n')
  for (let k = 0; k < lines.length; k++) {
    const line = lines[k]
    const m = /(^|[ \t;&|()<>])#/.exec(line)
    if (!m) continue
    const hash = m.index + m[1].length
    const prefix = line.slice(0, hash)
    const tail = line.slice(hash + 1)
    if (!/['"`\\]/.test(prefix) && SAFE_COMMENT_TAIL.test(tail)) {
      lines[k] = prefix
    } else if (/\\$/.test(line)) {
      return { text, refused: 'a # line that ends in a backslash' }
    }
  }
  return { text: lines.join('\n') }
}

// word / operator tokens of the de-quoted text; quote-blind: ; & | ( ) ` newline and redirects always separate
const REDIRECT_AT = /^(?:&>>|&>|>>|>\||>&|<<<|<<-|<<|<&|<>|>|<)/

function tokenize(text) {
  const tokens = []
  let i = 0
  const n = text.length
  while (i < n) {
    const c = text[i]
    if (c === ' ' || c === '\t') { i++; continue }
    if (c === '\n') { tokens.push({ op: 'NL' }); i++; continue }
    if (c === ';' && text[i + 1] === ';') { tokens.push({ op: ';;' }); i += 2; continue }
    if (c === '&' || c === '|' || c === '<' || c === '>') {
      const r = REDIRECT_AT.exec(text.slice(i, i + 3))
      if (r) { tokens.push({ op: 'redir' }); i += r[0].length; continue }
      tokens.push({ op: c }); i++
      if (c === '&' && text[i] === '&') i++
      if (c === '|' && text[i] === '|') i++
      continue
    }
    if (c === ';' || c === '(' || c === ')' || c === '`') { tokens.push({ op: c }); i++; continue }
    let j = i
    while (j < n && !' \t\n;&|()`<>'.includes(text[j])) j++
    tokens.push({ word: text.slice(i, j) })
    i = j
  }
  return tokens
}

// The positive allowlist. Returns a refusal reason or null. cmdPos = the next word is a command word.
function commandWordRefusal(text) {
  let cmdPos = true
  let pendingRedirect = false
  let caseState = null // 'subject' | 'in' while `case WORD in` is being read
  let caseDepth = 0
  let expectPattern = false
  let expectClose = false
  for (const tok of tokenize(text)) {
    if (tok.op) {
      const op = tok.op
      if (op === 'redir') { pendingRedirect = true; continue }
      if (caseState) return 'malformed case header'
      if (op === 'NL') {
        if (expectClose) return 'malformed case pattern'
        if (!expectPattern) cmdPos = true
        continue
      }
      if (op === '(' && expectPattern) continue
      if (op === ')') {
        if (expectPattern) return 'empty case pattern'
        expectClose = false
        cmdPos = true
        continue
      }
      if (expectClose || expectPattern) return 'malformed case pattern'
      if (op === ';;') { if (caseDepth > 0) { expectPattern = true; cmdPos = false } else cmdPos = true; continue }
      cmdPos = true
      continue
    }
    const w = tok.word
    if (pendingRedirect) { pendingRedirect = false; continue }
    if (expectClose) return 'malformed case pattern'
    if (expectPattern) {
      expectPattern = false
      if (w === 'esac') { caseDepth--; cmdPos = false } else expectClose = true
      continue
    }
    if (caseState === 'subject') { caseState = 'in'; continue }
    if (caseState === 'in') {
      if (w !== 'in') return 'malformed case header'
      caseState = null
      caseDepth++
      expectPattern = true
      continue
    }
    if (!cmdPos) continue
    if (w === 'case') { caseState = 'subject'; cmdPos = false; continue }
    if (w === 'esac') {
      if (caseDepth === 0) return 'esac without case'
      caseDepth--
      cmdPos = false
      continue
    }
    if (KEYWORDS_OPEN.has(w)) continue
    if (w === 'for' || KEYWORDS_CLOSE.has(w) || PLAIN_COMMANDS.has(w) || MARKER_WORD.test(w)) { cmdPos = false; continue }
    return `command word not on the allowlist: ${w.slice(0, 24)}`
  }
  if (caseState || expectClose) return 'malformed case'
  return null
}

// Returns { ok: true } or { ok: false, reason }. Pure text analysis, no spawn.
export function guardOracleScript(script) {
  const text = String(script)
  if (text.length > 4000) return { ok: false, reason: 'script too long' }
  if (text.includes('\0')) return { ok: false, reason: 'NUL byte' }
  // the marker definitions are the only function definitions; they are checked by equality, not by reading
  const body = text.startsWith(ORACLE_DEFS) ? text.slice(ORACLE_DEFS.length) : text
  const full = dequote(body)
  let m = FORBIDDEN_ZSH.exec(full)
  if (m) return { ok: false, reason: `forbidden shell-module / builtin word ${m[0]}` }
  m = FORBIDDEN_NAMED.exec(full)
  if (m) return { ok: false, reason: `forbidden word ${m[1]}` }
  m = FORBIDDEN_EXEC.exec(full)
  if (m) return { ok: false, reason: `forbidden command word ${m[1]}` }
  if (DOT_COMMAND.test(full)) return { ok: false, reason: 'dot (source) command' }
  if (/\$\(\(|\(\(|\$\[/.test(full)) return { ok: false, reason: 'arithmetic / double paren' }
  if (/[<>=]\(/.test(full)) return { ok: false, reason: 'process substitution' }
  if (/\(\s*\)/.test(full)) return { ok: false, reason: 'function definition' }
  const noRedirects = full.replace(ALLOWED_REDIRECT, ' ')
  if (/>/.test(noRedirects.replace(/<<<?-?/g, ' '))) return { ok: false, reason: 'redirect to an unlisted target' }
  if (ABSOLUTE_WORD.test(noRedirects)) return { ok: false, reason: 'absolute-path word' }
  if (RELATIVE_PARENT.test(noRedirects)) return { ok: false, reason: 'parent-path word' }
  if (RELATIVE_WORD.test(noRedirects)) return { ok: false, reason: 'relative-path word' }
  // a heredoc operator is understood only in the simple first-line form; any other << is refused
  const hd = cutHeredocBody(body)
  if (hd.refused) return { ok: false, reason: hd.refused }
  const rest = hd.matched ? hd.text.split('\n').slice(1).join('\n') : hd.text
  if (/<<(?!<)/.test(rest.replace(/<<</g, ' '))) return { ok: false, reason: 'heredoc operator in an unsupported form' }
  const cc = cutComments(hd.text)
  if (cc.refused) return { ok: false, reason: cc.refused }
  const why = commandWordRefusal(dequote(cc.text))
  if (why) return { ok: false, reason: why }
  return { ok: true }
}

const createdDirs = []

function realSpawn(file, args, options) {
  return spawnSync(file, args, options)
}

// One fresh temp cwd for a whole test run (tracked, removed by cleanupOracleDirs).
export function freshOracleDir(tmpBase = tmpdir()) {
  const d = mkdtempSync(join(tmpBase, 'self-pace-oracle-'))
  createdDirs.push(d)
  return d
}

export function shellAvailable(shell) {
  return existsSync(SHELLS[shell])
}

// Runs the marker-rewritten body on one shell. Throws OracleRefused BEFORE any spawn if the guard refuses.
// opts.spawn lets the self-test prove that a refused text never reaches a spawn; opts.cwd/opts.tmpBase pick the dir.
export function runOracle(body, shell, opts = {}) {
  const script = ORACLE_DEFS + String(body)
  const verdict = guardOracleScript(script)
  if (!verdict.ok) throw new OracleRefused(verdict.reason)
  const file = SHELLS[shell]
  if (!file) throw new OracleRefused(`unknown shell ${shell}`)
  let cwd = opts.cwd
  if (!cwd) {
    cwd = mkdtempSync(join(opts.tmpBase ?? tmpdir(), 'self-pace-oracle-'))
    createdDirs.push(cwd)
  }
  const args = shell === 'bash'
    ? ['--noprofile', '--norc', '-r', '-c', script]
    : ['-f', '-r', '-c', script]
  const r = (opts.spawn ?? realSpawn)(file, args, {
    cwd,
    env: { PATH: '/var/empty' },
    stdio: ['ignore', 'pipe', 'pipe'],
    encoding: 'utf8',
    timeout: ORACLE_TIMEOUT_MS,
    killSignal: 'SIGKILL',
  })
  // markers can be glued to other output (`printf x` has no newline, `$(...)` joins words), so match anywhere
  const ran = new Set([...String(r.stdout ?? '').matchAll(/@@M(\d+)@@/g)].map((x) => Number(x[1])))
  return {
    ran,
    danger: [...ran].some((n) => DANGER_MARKERS.has(n)),
    timedOut: r.error?.code === 'ETIMEDOUT',
    status: r.status,
  }
}

// Removes only the temp dirs this module created itself (names start with self-pace-oracle-).
export function cleanupOracleDirs() {
  while (createdDirs.length > 0) {
    const d = createdDirs.pop()
    if (/self-pace-oracle-[A-Za-z0-9]+$/.test(d)) rmSync(d, { recursive: true, force: true })
  }
}

// Deliberately dangerous texts. Every one must be refused by the guard before a spawn.
export const GUARD_SELF_TEST_TEXTS = [
  'crontab -r',
  'echo ok; at now',
  'tmux send-keys -t x Enter',
  "bash -c 'echo x'",
  'sh -c "echo x"',
  'echo $(rm -rf x)',
  'echo `kill 1`',
  '/bin/echo hi',
  'eval "echo x"',
  '. ./x',
  'source ./x',
  'exec true',
  'echo hi > /etc/x',
  'cat <(echo x)',
  'curl http://localhost:1/',
  'echo $(date)',
  // fix round 1 (B2): quote-split words and the zsh module route that the empty PATH does not stop
  'zmodload z""s""h/files',
  'zmodload zsh/files; zf_rm x',
  'z""modload zsh/files',
  'c""rontab -r',
  'cr\\ontab -r',
  "$'cron'tab -r",
  'echo ok; c""rontab -r',
  'echo $(c""rontab -r)',
  'echo `cr\\ontab -r`',
  't"mu"x send-keys -t x Enter',
  'zpty z cat',
  'emulate sh',
  'builtin kill 1',
  'autoload -U x',
  'sched +1 true',
  'x=1',
  '$x -r',
  'echo hi; ../x',
  'cat <<EOF\n$(rm -rf x)\nEOF',
]

// Runs the self-test: every dangerous text must raise OracleRefused with the spawn spy untouched.
export function guardSelfTest() {
  let spawned = 0
  const spy = () => { spawned++; throw new Error('spawn reached') }
  const refused = []
  const notRefused = []
  for (const t of GUARD_SELF_TEST_TEXTS) {
    for (const shell of Object.keys(SHELLS)) {
      try {
        runOracle(t, shell, { spawn: spy, cwd: '/var/empty' })
        notRefused.push(t)
      } catch (e) {
        if (e instanceof OracleRefused) refused.push(t)
        else notRefused.push(t)
      }
    }
  }
  return { refused: refused.length, notRefused, spawned, total: GUARD_SELF_TEST_TEXTS.length * Object.keys(SHELLS).length }
}
