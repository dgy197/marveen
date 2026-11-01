// Card 3660cf43 (planned under the duplicate id 3e13973c), node N0: the differential shell oracle and its guard.
//
// What it is for: the self-pace gate must decide a multi-line command the way the REAL shell reads it. The only
// ground truth is a shell, so a test has to run one. That is dangerous for a corpus full of `crontab -r`, so the
// shell never sees the corpus text. It sees a marker-rewritten copy:
//   - every command word of the corpus (crontab, at, tmux, curl, git, ls, cat, grep, python3) is replaced by a
//     shell FUNCTION defined at the top of the script (`__m1() { printf '@@M1@@\n'; }`), which only prints a marker;
//   - the executed text therefore contains only those function names, printf, echo, true and shell syntax;
//   - BEFORE anything is spawned, guardOracleScript() refuses (throws OracleRefused) any text that still contains
//     a real scheduler / process / network word, `bash -c`, `sh -c`, eval, source, exec, a `.` command, an
//     absolute-path command, a redirect to anywhere but ./name or /dev/null, process substitution, `$((`, or a
//     backtick / `$(` whose commands are not marker functions, echo, printf or true;
//   - the child runs with env = { PATH: '/var/empty' } only, stdin closed, a fresh temp cwd, restricted mode
//     (bash -r / zsh -r) and a 5 s kill timeout.
// The marker for a dangerous binary (M1 crontab, M2 at, M3 tmux) printing means: the real shell reached that
// command. Nothing here can run the real binary: the names do not resolve (PATH is empty) and the guard has
// already refused every text that could reach one by another route.
// A row that cannot be rewritten safely is not run: the caller declares it with `noOracle` and the test counts it.

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

const FORBIDDEN_NAMED = /\b(crontab|at|batch|tmux|launchctl|kill|rm|shutdown|reboot|osascript|curl|wget|nc|ssh|sudo)\b/
// anything that could run another program or re-enter a shell, plus the corpus words the rewrite must have removed
const FORBIDDEN_EXEC = /\b(bash|zsh|sh|dash|ksh|csh|tcsh|fish|eval|source|exec|env|xargs|nohup|setsid|command|builtin|trap|coproc|find|node|npx|npm|perl|ruby|php|python3?|open|su|doas|chmod|chown|mv|cp|dd|mkfifo|sqlite3|git|gh|ls|cat|grep|tee|mkdir|touch|ln|killall|pkill)\b/
const DOT_COMMAND = /(^|[\n;&|({]|&&|\|\|)[ \t]*\.([ \t]|$)/
const ABSOLUTE_WORD = /(^|[\s;&|(){}<>"'`])(\/|~)[A-Za-z0-9_.-]/
const ALLOWED_REDIRECT = /(?:&>>?|[0-9]?>>?)[ \t]*(?:\.\/[A-Za-z0-9_.-]+|\/dev\/null)/g
const SUBST_FIRST_WORD = /^(?:__m\d+|echo|printf|true)(?:[\s\\]|$)/

function substitutionBodies(script) {
  const bodies = []
  for (let i = 0; i < script.length; i++) {
    if (script[i] === '$' && script[i + 1] === '(') {
      let depth = 1
      let j = i + 2
      for (; j < script.length && depth > 0; j++) {
        if (script[j] === '(') depth++
        else if (script[j] === ')') depth--
      }
      bodies.push(script.slice(i + 2, depth === 0 ? j - 1 : j))
    }
  }
  const ticks = script.split('`')
  for (let k = 1; k < ticks.length; k += 2) bodies.push(ticks[k])
  if (ticks.length % 2 === 0) bodies.push(ticks[ticks.length - 1]) // unbalanced backtick: check the tail too
  return bodies
}

// Returns { ok: true } or { ok: false, reason }. Pure text analysis, no spawn.
export function guardOracleScript(script) {
  const text = String(script)
  if (text.length > 4000) return { ok: false, reason: 'script too long' }
  if (text.includes('\0')) return { ok: false, reason: 'NUL byte' }
  let m = FORBIDDEN_NAMED.exec(text)
  if (m) return { ok: false, reason: `forbidden word ${m[1]}` }
  m = FORBIDDEN_EXEC.exec(text)
  if (m) return { ok: false, reason: `forbidden command word ${m[1]}` }
  if (DOT_COMMAND.test(text)) return { ok: false, reason: 'dot (source) command' }
  if (/\$\(\(|\(\(/.test(text)) return { ok: false, reason: 'arithmetic / double paren' }
  if (/[<>]\(/.test(text)) return { ok: false, reason: 'process substitution' }
  const noRedirects = text.replace(ALLOWED_REDIRECT, ' ')
  if (/>/.test(noRedirects.replace(/<<<?-?/g, ' '))) return { ok: false, reason: 'redirect to an unlisted target' }
  if (ABSOLUTE_WORD.test(noRedirects)) return { ok: false, reason: 'absolute-path word' }
  for (const body of substitutionBodies(text)) {
    for (const part of body.split(/[;&|\n]+/)) {
      const s = part.trim()
      if (s === '' || s === ')') continue
      if (!SUBST_FIRST_WORD.test(s)) return { ok: false, reason: `substitution runs a non-marker command: ${s.slice(0, 20)}` }
    }
  }
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
