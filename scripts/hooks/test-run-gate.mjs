// PreToolUse hook (Bash): the test-run gate (card d6d2d686).
//
// Why: on 2026-10-24 a full vitest run inside a /Volumes worktree executed a test cleanup that built a
// path from an empty variable (`rmSync(join('', '..'))`) and deleted the parent of the working directory.
// scripts/safe-vitest.sh runs vitest in a write-restricted sandbox and refuses /Volumes itself; this gate
// makes it the ONLY way a JS test run can start, and stops every test runner (JS and Python) whose
// effective cwd is under /Volumes.
//
// Rules (spec.md of the card):
//   R1 a JS test runner is denied: vitest, jest, mocha, `node --test`, npm|pnpm|yarn|bun test / t / run test*,
//      npx | pnpm exec | pnpm dlx | yarn vitest ..., */node_modules/.bin/vitest -- through any wrapper
//      (env, bash -c, sh -c, eval, command, exec, time, nice, timeout, gtimeout, run-sandboxed.sh,
//      sandbox-exec, perl -e 'exec @ARGV', script, xargs, find -exec, subshell, substitution, heredoc /
//      here-string fed shell, a function or alias the text itself defines). ssh is not unwrapped (remote).
//      A plain variable as the command word with a python test shape (`"$PY" -m pytest`, `${PY} a.test.py`)
//      is a Python runner (Brainy N1b D2); any other computed command word stays "unknown".
//   R2 except safe-vitest.sh: the one under the live root (derived from this file's place, like
//      egress-gate.mjs REPO_ROOT), or a copy whose safe-vitest.sh AND sibling safe-vitest.sb are
//      byte-identical (sha256) to the live ones. Unreadable -> deny.
//   R3 any test run (R1, R2, Python: pytest, python -m pytest|unittest, python <x>.test.py | *_test.py |
//      test_*.py) is denied when the effective cwd is under /Volumes: the hook cwd followed through the
//      cd / pushd steps of the command, symlinks resolved. The same for --root / --dir / --prefix / -C /
//      --cwd / --rootdir pointing there. A cwd that cannot be resolved (variable, missing path) next to
//      a runner denies. A Python runner is otherwise allowed (Brainy decision D2).
//   R4 fail-closed inside its own class only: when the parser throws (or the text is unparseable), the
//      raw text decides -- a runner word (RUNNER_WORD_RE) denies, anything else is allowed.
//
// Quoted argument text is not a runner (`echo "npm test"`, `git commit -m "vitest"`); the body of
// `bash -c '...'`, `eval '...'` and of a heredoc / here-string fed to a shell IS parsed.
// Stated residual (Brainy): a test run wrapped into a shell script (`bash run-tests.sh`) is not read.
// Stated residual: the hash is checked when the command is judged, not when it runs (TOCTOU).
//
// Test seams are FUNCTION PARAMETERS of gateDecision (opts.liveRoot, opts.volumesRoot, opts.parser),
// never environment variables: an env override would be a way to loosen the gate from outside.
//
// Parser reuse (scripts/hooks/bash-egress-parser.mjs, scripts/self-pace-gate.mjs, scripts/shell-line-join.mjs):
// joinShellLines, liftSubstitutions, maskInertLiterals, functionDefs, subshellParens, shellWords, commandIndex.
// New here: the command splitter over the masked text (the parser's spans() is not exported), the
// shell -c / xargs / find -exec / package-manager peeling, and the runner classification.

import { readFileSync, realpathSync, writeSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { fileURLToPath } from 'node:url'
import { dirname, join, resolve, basename, isAbsolute } from 'node:path'
import { homedir } from 'node:os'
import { shellWords, commandIndex, liftSubstitutions, functionDefs, subshellParens } from './bash-egress-parser.mjs'
import { maskInertLiterals } from '../self-pace-gate.mjs'
import { joinShellLines } from '../shell-line-join.mjs'

// Derive the live root from this script's location (scripts/hooks/test-run-gate.mjs).
const LIVE_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const DEFAULT_VOLUMES_ROOT = '/Volumes'
const MAX_DEPTH = 8
const MAX_COMMAND_LENGTH = 200000

// The runner words of the R4 fallback (raw text, no parsing). Not global: no lastIndex state.
export const RUNNER_WORD_RE = new RegExp([
  '\\b(?:vitest|jest|mocha|pytest|unittest)\\b',
  '\\bnode\\b[^\\n;&|]*\\s--test\\b',
  '\\b(?:npm|pnpm|yarn|bun)\\b[^\\n;&|]*?\\b(?:test|t|tst)\\b',
  '\\.test\\.py\\b',
  '_test\\.py\\b',
  '\\btest_[\\w.-]*\\.py\\b',
].join('|'))

const MSG_JS = 'Teszt-kapu: JS tesztfuttató csak a scripts/safe-vitest.sh-n keresztül indítható (write-korlátozott sandbox). ' +
  'Futtasd egy belső lemezes worktree gyökeréből: bash scripts/safe-vitest.sh <tesztfájl>. (card d6d2d686)'
const MSG_VOLUMES = 'Teszt-kapu: /Volumes alatti munkakönyvtárban tesztfuttatás nem indulhat (a 10-24-i adatvesztés miatt). ' +
  'Dolgozz belső lemezes klónban vagy worktree-ben (pl. ~/marveen-wt). (card d6d2d686)'
const MSG_CWD = 'Teszt-kapu: a tesztfuttató munkakönyvtára nem feloldható (változó, nem létező vagy ismeretlen cd/pushd/popd cél), ' +
  'ezért nem zárható ki a /Volumes. Adj abszolút, létező munkakönyvtárat. (card d6d2d686)'
const MSG_SAFE = 'Teszt-kapu: a safe-vitest.sh másolata nem egyezik az élővel (safe-vitest.sh és safe-vitest.sb sha256), ' +
  'vagy nem olvasható. Csak az élő scripts/safe-vitest.sh vagy bájtra azonos másolata futhat. (card d6d2d686)'
const MSG_UNKNOWN = 'Teszt-kapu: a parancsszó futásidőben számolódik, és a szöveg tesztfuttató szót tartalmaz; nem ellenőrizhető. ' +
  'Írd ki a parancsot szó szerint. (card d6d2d686)'
const MSG_PARSE = 'Teszt-kapu: a parancs nem elemezhető, és tesztfuttató szót tartalmaz (fail-closed). (card d6d2d686)'

const ALLOW = Object.freeze({ deny: false })
const deny = (reason) => ({ deny: true, reason })

// ---------------------------------------------------------------- small helpers

const SHELL_NAME = /^(?:bash|sh|zsh|dash|ksh|ash|mksh)$/
const PY_NAME = /^(?:python|python\d+(?:\.\d+)*|pypy\d*)$/
const PYTEST_NAME = /^py\.?test(?:-?\d+(?:\.\d+)*)?$/
const NODE_NAME = /^(?:node|nodejs|tsx|ts-node)$/
const JS_BINS = new Set(['vitest', 'jest', 'mocha', '_mocha', 'jest-cli'])
const TEST_VERB = /^(?:t|tst|test(?:[:-].*)?)$/
const LAUNCHERS = new Set(['npx', 'pnpx', 'bunx'])
const PM_NAMES = new Set(['npm', 'pnpm', 'yarn', 'bun'])
const SIMPLE_WRAPPERS = new Set(['caffeinate', 'arch', 'ionice', 'unbuffer', 'doas', 'corepack'])
const PY_RUNNER_LAUNCHERS = new Set(['uv', 'poetry', 'pipenv', 'hatch', 'pdm', 'rye'])
const PM_VALUE_OPTS = new Set(['--prefix', '-C', '--dir', '--cwd', '--workspace', '-w', '--filter', '-F', '--registry',
  '--userconfig', '--loglevel', '--cache', '--reporter', '--config', '-p', '--package'])
const NODE_VALUE_OPTS = new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '--env-file',
  '--input-type', '-C', '--conditions', '--title', '--stack-size'])
const XARGS_VALUE_OPTS = new Set(['-a', '-d', '-E', '-I', '-J', '-L', '-n', '-P', '-R', '-S', '-s', '--arg-file',
  '--delimiter', '--eof', '--max-args', '--max-procs', '--max-lines', '--max-chars'])
const SANDBOX_EXEC_VALUE_OPTS = new Set(['-f', '-p', '-n', '-D'])
const TIMEOUT_VALUE_OPTS = new Set(['-s', '--signal', '-k', '--kill-after'])
const VAR_WORD = /^\$(?:[A-Za-z_][A-Za-z0-9_]*|\{[A-Za-z_][A-Za-z0-9_]*\})$/
const DIR_OPTS = new Set(['--root', '--dir', '--prefix', '--cwd', '--rootdir', '-C'])
const DIR_OPT_EQ = /^(--root|--dir|--prefix|--cwd|--rootdir)=([\s\S]*)$/
const REDIR_OP = /^(?:\d+|&)?(?:<<<|<<-?|<>|>>|>\||>&?|<&?|&>>?)/

const baseName = (w) => basename(String(w))
// `vitest@1.2` / `jest@latest`: the package spec of an npx-style call, without the version.
const stripVersion = (w) => (String(w).startsWith('@') ? String(w) : String(w).replace(/@[^/]*$/, ''))
const isJsBin = (w) => JS_BINS.has(stripVersion(baseName(w)))
const shq = (w) => `'${String(w).replace(/'/g, "'\\''")}'`

function blankRanges(text, ranges) {
  let out = text
  for (const [s, e] of ranges) out = out.slice(0, s) + out.slice(s, e).replace(/[^\n]/g, ' ') + out.slice(e)
  return out
}

// Command separators over the masked text (the parser's own spans() is not exported). A lone `&` ends a
// command, the `&` of a redirection does not; a backslash-escaped separator is a literal character.
function spans(masked) {
  const out = []; let start = 0
  const re = /&&|\|\||;|(?<!>)\||\n|(?<![<>])&(?!>)/g; let m
  while ((m = re.exec(masked))) {
    let bs = 0
    while (m.index - bs > 0 && masked[m.index - bs - 1] === '\\') bs++
    if (bs % 2 === 1 && m[0] !== '\n') { re.lastIndex = m.index + 1; continue }
    out.push([start, m.index]); start = m.index + m[0].length
  }
  out.push([start, masked.length])
  return out
}

// Redirections out of a word list: `2>&1`, `>out`, `<<EOF` go; a bare operator takes the next word with it.
function stripRedirections(words) {
  const out = []
  for (let k = 0; k < words.length; k++) {
    const m = REDIR_OP.exec(words[k])
    if (!m) { out.push(words[k]); continue }
    if (m[0] === words[k] && !/&$/.test(words[k]) && k + 1 < words.length) k++
  }
  return out
}

// A path word as the shell would hand it over, or null where it is only known at run time.
function expandPath(word) {
  if (typeof word !== 'string' || word === '') return null
  let s = word
  if (s === '~' || s.startsWith('~/')) s = homedir() + s.slice(1)
  else if (s.startsWith('~')) return null
  s = s.replace(/^\$\{HOME\}|^\$HOME(?![A-Za-z0-9_])/, homedir())
  if (/[$`*?[{]/.test(s)) return null
  return s
}

// ---------------------------------------------------------------- parser: text -> ordered steps
//
// Steps, in execution order:
//   { type: 'cd', kind: 'cd'|'pushd'|'popd', target }        a directory change
//   { type: 'run', kind: 'js'|'safe'|'py', script?, args }   a test run
//   { type: 'unknown', word }                               a command word computed at run time
// opts.parser(command) replaces parseCommand in tests; it must return that array or throw.

function newContext(raw) {
  return { raw, funcs: new Map(), aliases: new Map(), active: new Set() }
}

export function parseCommand(command) {
  return parseSteps(String(command ?? ''), newContext(String(command ?? '')), 0)
}

function parseSteps(text, ctx, depth) {
  if (depth > MAX_DEPTH) throw new Error('nesting-too-deep')
  const norm = joinShellLines(text)
  const lifted = liftSubstitutions(norm)
  const { inners, innerAts, herestrings, heredocs, bodies } = lifted
  const stripped = lifted.stripped
  let orig = stripped
  let masked = maskInertLiterals(orig)
  if (masked === null || masked.length !== orig.length) throw new Error('unparseable')

  // Shell functions: cut out of the text, judged per call (an uncalled function runs nothing).
  const defs = functionDefs(masked)
  for (const d of defs) ctx.funcs.set(d.name, [...(ctx.funcs.get(d.name) ?? []), norm.slice(d.bodyStart, d.bodyEnd)])
  if (defs.length) {
    const ranges = defs.map((d) => [d.start, d.end])
    orig = blankRanges(orig, ranges); masked = blankRanges(masked, ranges)
  }
  const parens = subshellParens(masked)
  if (parens.length) {
    const ranges = parens.map((k) => [k, k + 1])
    orig = blankRanges(orig, ranges); masked = blankRanges(masked, ranges)
  }
  const inDef = (at) => defs.some((d) => at >= d.start && at < d.end)
  // Heredoc bodies are data for the command that owns them: they are not words of the span.
  const wordSource = bodies.length ? blankRanges(orig, bodies) : orig

  const steps = []
  for (const [a, b] of spans(masked)) {
    // Substitutions run before the command they sit in.
    for (const [n, inner] of inners.entries()) {
      if (innerAts[n] < a || innerAts[n] >= b || inDef(innerAts[n])) continue
      if (/^\(.*\)$/s.test(inner)) { // $(( ... )) is arithmetic: only the substitutions inside it run
        for (const t of liftSubstitutions(inner.slice(1, -1)).inners) steps.push(...parseSteps(t, ctx, depth + 1))
        continue
      }
      steps.push(...parseSteps(inner, ctx, depth + 1))
    }
    const words = shellWords(wordSource.slice(a, b))
    if (!words.length) continue
    const extra = {
      heredocs: heredocs.filter((h) => h.opStart >= a && h.opStart < b && !inDef(h.opStart))
        .map((h) => stripped.slice(h.bodyStart, h.bodyEnd)),
      herestring: herestrings.some((p) => p >= a && p < b),
    }
    analyzeWords(words, extra, ctx, depth, steps)
  }
  return steps
}

// Options of a launcher / package manager up to its first positional word: the rest is the command.
// `-c <string>` (npm exec -c) carries a shell command of its own.
function peelLauncherOptions(args, steps, ctx, depth) {
  let k = 0
  while (k < args.length) {
    const w = args[k]
    if (w === '--') { k++; continue }
    if (!(w.startsWith('-') && w.length > 1)) break
    if (w === '-c' || w === '--call') { if (args[k + 1] !== undefined) steps.push(...parseSteps(args[k + 1], ctx, depth + 1)); k += 2; continue }
    k += PM_VALUE_OPTS.has(w) ? 2 : 1
  }
  return args.slice(k)
}

// `bash [options] -c BODY [name args...]` / `bash [options] SCRIPT [args...]`.
function shellInvocation(args) {
  let sawC = false
  for (let k = 0; k < args.length; k++) {
    const w = args[k]
    if (w === '--' || w === '-') return sawC && k + 1 < args.length ? { body: args[k + 1] } : (k + 1 < args.length ? { script: args[k + 1] } : {})
    if (!w.startsWith('-') && !w.startsWith('+')) return sawC ? { body: w } : { script: w }
    if (/^[-+][A-Za-z]+$/.test(w) && w.includes('c')) sawC = true
    if (w === '-o' || w === '+o' || w === '-O' || w === '+O' || w === '--rcfile' || w === '--init-file') k++
  }
  return {}
}

function analyzeWords(rawWords, extra, ctx, depth, steps) {
  if (depth > MAX_DEPTH) throw new Error('nesting-too-deep')
  const words = stripRedirections(rawWords)
  const i = commandIndex(words)
  if (i >= words.length) return
  const prefix = words.slice(0, i)
  const cmd = words[i]
  const args = words.slice(i + 1)
  const name = baseName(cmd)

  // `command -v vitest` / `command -V` looks a command up, it does not run it.
  const ci = prefix.findIndex((p) => baseName(p) === 'command')
  if (ci !== -1 && prefix.slice(ci + 1).some((p) => /^-[A-Za-z]*[vV]/.test(p))) return

  // A word computed at run time ($X, $(...), a glob or brace pattern) may be anything.
  if (/[$`*?[{]/.test(cmd) && !/^(?:\[|\[\[|\{|\})$/.test(cmd)) {
    // D2: a plain variable in the command word with a python test shape (`"$PY" -m pytest`,
    // `${PY} -I a/b.test.py`) is a python runner; every other computed word stays unknown.
    if (VAR_WORD.test(cmd)) {
      const py = []
      pythonRun(args, py)
      if (py.length) { steps.push(...py); return }
    }
    steps.push({ type: 'unknown', word: cmd })
    return
  }

  if (name === 'alias') {
    for (const a of args) {
      const eq = a.indexOf('=')
      if (eq > 0 && !a.startsWith('-')) ctx.aliases.set(a.slice(0, eq), a.slice(eq + 1))
    }
    return
  }
  if (ctx.aliases.has(name) && !ctx.active.has(`a:${name}`)) {
    ctx.active.add(`a:${name}`)
    try { steps.push(...parseSteps(`${ctx.aliases.get(name)} ${args.map(shq).join(' ')}`, ctx, depth + 1)) } finally { ctx.active.delete(`a:${name}`) }
    return
  }
  if (ctx.funcs.has(name) && !ctx.active.has(`f:${name}`)) {
    ctx.active.add(`f:${name}`)
    try { for (const body of ctx.funcs.get(name)) steps.push(...parseSteps(body, ctx, depth + 1)) } finally { ctx.active.delete(`f:${name}`) }
    return
  }

  if (name === 'cd' || name === 'pushd' || name === 'popd' || name === 'chdir') {
    let k = 0
    while (k < args.length && args[k].startsWith('-') && args[k] !== '-' && args[k] !== '--') k++
    if (args[k] === '--') k++
    steps.push({ type: 'cd', kind: name === 'chdir' ? 'cd' : name, target: args[k] })
    return
  }

  if (name === 'eval') { steps.push(...parseSteps(args.join(' '), ctx, depth + 1)); return }

  if (SHELL_NAME.test(name)) {
    const inv = shellInvocation(args)
    if (inv.body !== undefined) { steps.push(...parseSteps(inv.body, ctx, depth + 1)); return }
    if (inv.script !== undefined && baseName(inv.script) === 'safe-vitest.sh' && !extra.herestring) {
      steps.push({ type: 'run', kind: 'safe', script: inv.script, args: args.filter((w) => w !== inv.script) })
      return
    }
    // A shell reading its program from stdin: the heredoc / here-string body is that program.
    if (inv.script === undefined || args.includes('-s') || extra.herestring) {
      for (const body of extra.heredocs) steps.push(...parseSteps(body, ctx, depth + 1))
      if (extra.herestring && args.length) steps.push(...parseSteps(args[args.length - 1], ctx, depth + 1))
    }
    return
  }
  if (name === 'safe-vitest.sh') { steps.push({ type: 'run', kind: 'safe', script: cmd, args }); return }

  if (name === 'xargs') {
    let k = 0
    while (k < args.length && args[k].startsWith('-') && args[k] !== '--') k += XARGS_VALUE_OPTS.has(args[k]) ? 2 : 1
    if (args[k] === '--') k++
    analyzeWords(args.slice(k), { heredocs: [], herestring: false }, ctx, depth + 1, steps)
    return
  }
  if (name === 'find') {
    for (let k = 0; k < args.length; k++) {
      if (!/^-(?:exec|execdir|ok|okdir)$/.test(args[k])) continue
      let e = k + 1
      while (e < args.length && args[e] !== ';' && args[e] !== '+') e++
      analyzeWords(args.slice(k + 1, e), { heredocs: [], herestring: false }, ctx, depth + 1, steps)
      k = e
    }
    return
  }
  if (SIMPLE_WRAPPERS.has(name)) {
    let k = 0
    while (k < args.length && args[k].startsWith('-')) k++
    analyzeWords(args.slice(k), { heredocs: [], herestring: false }, ctx, depth + 1, steps)
    return
  }
  // D1: sandbox-style wrappers run the rest of the line; judge it like a bare command. ssh is NOT here (remote).
  const wrapped = wrappedCommand(name, args)
  if (wrapped !== null) {
    analyzeWords(wrapped, { heredocs: [], herestring: false }, ctx, depth + 1, steps)
    return
  }
  if (PY_RUNNER_LAUNCHERS.has(name)) {
    const rest = peelLauncherOptions(args, steps, ctx, depth)
    if (rest[0] === 'run') analyzeWords(peelLauncherOptions(rest.slice(1), steps, ctx, depth), { heredocs: [], herestring: false }, ctx, depth + 1, steps)
    return
  }

  // ---- runners
  if (isJsBin(cmd)) { steps.push({ type: 'run', kind: 'js', args }); return }
  if (PYTEST_NAME.test(name)) { steps.push({ type: 'run', kind: 'py', args }); return }
  if (PY_NAME.test(name)) { pythonRun(args, steps); return }
  if (NODE_NAME.test(name)) { nodeRun(args, steps); return }
  if (LAUNCHERS.has(name)) {
    analyzeWords(peelLauncherOptions(args, steps, ctx, depth), { heredocs: [], herestring: false }, ctx, depth + 1, steps)
    return
  }
  if (PM_NAMES.has(name)) packageManagerRun(name, args, steps, ctx, depth)
}

// The words a D1 wrapper hands to the command it runs, or null when `name` is not such a wrapper.
// A wrapper with no command after its options yields [] (nothing runs).
//   run-sandboxed.sh <cmd...>                       (any path: basename match)
//   sandbox-exec [-f file | -p profile | -n name | -D k=v] <cmd...>
//   perl -e '<code with exec / system>' <cmd...>    (argv after the code; without exec / system, nothing runs)
//   script [-aeFkqr] [-t time] <file> [<cmd...>]    (macOS form)
//   gtimeout [opts] <duration> <cmd...>             (GNU timeout, like timeout in commandIndex)
function wrappedCommand(name, args) {
  if (name === 'run-sandboxed.sh') return args
  if (name === 'sandbox-exec') {
    let k = 0
    while (k < args.length && args[k].startsWith('-') && args[k] !== '--') k += SANDBOX_EXEC_VALUE_OPTS.has(args[k]) ? 2 : 1
    if (args[k] === '--') k++
    return args.slice(k)
  }
  if (name === 'perl') {
    let k = 0
    let code = ''
    while (k < args.length) {
      const w = args[k]
      if (w === '--') { k++; break }
      if (!w.startsWith('-') || w === '-') break
      if (/^-[A-Za-z]*[eE]$/.test(w)) { code += `${args[k + 1] ?? ''}\n`; k += 2; continue }
      k += w === '-I' ? 2 : 1
    }
    return /\b(?:exec|system)\b/.test(code) ? args.slice(k) : []
  }
  if (name === 'script') {
    let k = 0
    while (k < args.length && args[k].startsWith('-') && args[k] !== '--') k += args[k] === '-t' ? 2 : 1
    if (args[k] === '--') k++
    return args.slice(k + 1) // args[k] is the typescript file
  }
  if (name === 'gtimeout') {
    let k = 0
    while (k < args.length && args[k].startsWith('-') && args[k] !== '--' && args[k].length > 1) k += TIMEOUT_VALUE_OPTS.has(args[k]) ? 2 : 1
    if (args[k] === '--') k++
    return args.slice(k + 1) // args[k] is the duration
  }
  return null
}

function nodeRun(args, steps) {
  for (let k = 0; k < args.length; k++) {
    const w = args[k]
    if (w.startsWith('-')) {
      if (w === '--test' || w.startsWith('--test-')) { steps.push({ type: 'run', kind: 'js', args }); return }
      if (w === '-e' || w === '-p' || w === '--eval' || w === '--print') return
      if (NODE_VALUE_OPTS.has(w)) k++
      continue
    }
    if (isJsBin(w.replace(/\.(?:m?js|cjs)$/, '')) || /node_modules\/(?:vitest|jest|jest-cli|mocha)\//.test(w)) {
      steps.push({ type: 'run', kind: 'js', args })
    }
    return
  }
}

function pythonRun(args, steps) {
  for (let k = 0; k < args.length; k++) {
    const w = args[k]
    if (w === '-c') return
    let mod
    if (/^-[A-Za-z]*m$/.test(w)) mod = args[k + 1]
    else if (/^-m./.test(w)) mod = w.slice(2)
    if (mod !== undefined || /^-[A-Za-z]*m$/.test(w)) {
      if (mod !== undefined && /^(?:pytest|py\.test|unittest)(?:\.|$)/.test(mod)) steps.push({ type: 'run', kind: 'py', args })
      return
    }
    if (w.startsWith('-')) { if (w === '-W' || w === '-X' || w === '-Q') k++; continue }
    if (/(?:\.test\.py|_test\.py)$/.test(baseName(w)) || /^test_.*\.py$/.test(baseName(w))) steps.push({ type: 'run', kind: 'py', args })
    return
  }
}

function packageManagerRun(pm, args, steps, ctx, depth) {
  const pos = []
  for (let k = 0; k < args.length; k++) {
    const w = args[k]
    if (w === '--') continue
    if (w.startsWith('-') && w.length > 1) {
      if (w === '-c' || w === '--call') { if (args[k + 1] !== undefined) steps.push(...parseSteps(args[k + 1], ctx, depth + 1)); k++; continue }
      if (PM_VALUE_OPTS.has(w)) k++
      continue
    }
    pos.push({ w, k })
  }
  for (let j = 0; j < pos.length; j++) {
    const p = pos[j].w
    if (p === 'exec' || p === 'dlx' || p === 'x') {
      const rest = peelLauncherOptions(args.slice(pos[j].k + 1), steps, ctx, depth)
      analyzeWords(rest, { heredocs: [], herestring: false }, ctx, depth + 1, steps)
      return
    }
    if (p === 'run' || p === 'run-script') {
      const q = pos[j + 1]?.w
      if (q !== undefined && (TEST_VERB.test(q) || isJsBin(q))) steps.push({ type: 'run', kind: 'js', args })
      return
    }
    if (p === 'workspace') { j++; continue }
    if (p === 'workspaces' || p === 'foreach' || p === 'recursive') continue
    if (TEST_VERB.test(p) || isJsBin(p)) steps.push({ type: 'run', kind: 'js', args })
    return
  }
}

// ---------------------------------------------------------------- decision

function realOrNull(p) {
  try { return realpathSync(p) } catch { return null }
}
function isUnder(p, root) {
  if (!root) return false
  const r = root.length > 1 && root.endsWith('/') ? root.slice(0, -1) : root
  return p === r || p.startsWith(`${r}/`)
}
// The textual path AND its realpath are both judged: a symlink into the volume, or a path written under
// it that resolves elsewhere, is stopped either way.
function underVolumes(p, volumesRoot) {
  const roots = [volumesRoot]
  const rr = realOrNull(volumesRoot)
  if (rr) roots.push(rr)
  const cands = [p]
  const real = realOrNull(p)
  if (real) cands.push(real)
  return cands.some((c) => roots.some((r) => isUnder(c, r)))
}

const sha256File = (path) => createHash('sha256').update(readFileSync(path)).digest('hex')

function safeVitestMatchesLive(script, cwd, liveRoot) {
  const wanted = expandPath(script)
  if (wanted === null) return false
  try {
    const abs = resolve(cwd, wanted)
    const shReal = realpathSync(abs)
    // safe-vitest.sh reads the profile from `cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P`.
    const dirReal = realpathSync(dirname(abs))
    const liveSh = join(liveRoot, 'scripts', 'safe-vitest.sh')
    const liveSb = join(liveRoot, 'scripts', 'safe-vitest.sb')
    return sha256File(shReal) === sha256File(liveSh) && sha256File(join(dirReal, 'safe-vitest.sb')) === sha256File(liveSb)
  } catch {
    return false
  }
}

function fallbackDecision(raw, why) {
  return RUNNER_WORD_RE.test(raw) ? deny(`${MSG_PARSE} [${String(why).slice(0, 120)}]`) : ALLOW
}

// opts: { liveRoot, volumesRoot, parser } -- test seams, function parameters only.
export function gateDecision(command, cwd, opts = {}) {
  const raw = String(command ?? '')
  if (!raw.trim()) return ALLOW
  if (raw.length > MAX_COMMAND_LENGTH) return fallbackDecision(raw, 'command too long')
  const liveRoot = opts.liveRoot ?? LIVE_ROOT
  const volumesRoot = opts.volumesRoot ?? DEFAULT_VOLUMES_ROOT
  const parser = opts.parser ?? parseCommand
  let steps
  try {
    steps = parser(raw)
    if (!Array.isArray(steps)) throw new Error('parser returned no step list')
  } catch (e) {
    return fallbackDecision(raw, e?.message)
  }
  try {
    return evaluate(steps, raw, typeof cwd === 'string' && isAbsolute(cwd) ? cwd : process.cwd(), liveRoot, volumesRoot)
  } catch (e) {
    return fallbackDecision(raw, e?.message)
  }
}

function evaluate(steps, raw, startCwd, liveRoot, volumesRoot) {
  let cur = startCwd // null = not resolvable
  for (const step of steps) {
    if (step.type === 'cd') {
      if (step.kind === 'popd' || (step.kind === 'pushd' && step.target === undefined) || step.target === '-') { cur = null; continue }
      const target = step.target === undefined ? homedir() : expandPath(step.target)
      cur = target === null ? null : (isAbsolute(target) ? resolve(target) : (cur === null ? null : resolve(cur, target)))
      continue
    }
    if (step.type === 'unknown') {
      if (RUNNER_WORD_RE.test(raw)) return deny(MSG_UNKNOWN)
      continue
    }
    if (step.type !== 'run') continue
    if (step.kind === 'js') return deny(MSG_JS)
    // From here on: safe-vitest.sh or a Python runner. Both must not start under /Volumes.
    if (cur === null || realOrNull(cur) === null) return deny(MSG_CWD)
    if (underVolumes(cur, volumesRoot)) return deny(MSG_VOLUMES)
    for (let k = 0; k < step.args.length; k++) {
      const w = step.args[k]
      let val
      if (DIR_OPTS.has(w)) val = step.args[k + 1]
      else {
        const m = DIR_OPT_EQ.exec(w)
        if (m) val = m[2]
        else if (/^-C./.test(w)) val = w.slice(2)
        else continue
      }
      if (val === undefined) continue
      const p = expandPath(val)
      if (p === null) return deny(MSG_CWD)
      if (underVolumes(resolve(cur, p), volumesRoot)) return deny(MSG_VOLUMES)
    }
    if (step.kind === 'safe' && !safeVitestMatchesLive(step.script, cur, liveRoot)) return deny(MSG_SAFE)
  }
  return ALLOW
}

// ---------------------------------------------------------------- hook entry (stdin JSON -> exit 0 / 2)

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
    process.exit(0) // malformed or empty input comes from the harness: it must never block the agent
  }
  if (payload?.tool_name !== 'Bash') process.exit(0)
  const command = payload?.tool_input?.command
  if (typeof command !== 'string' || !command.trim()) process.exit(0)
  let decision
  try {
    decision = gateDecision(command, payload?.cwd)
  } catch (e) {
    decision = fallbackDecision(command, e?.message)
  }
  if (decision.deny) {
    try { writeSync(2, `${decision.reason}\n`) } catch { /* the exit code still blocks */ }
    process.exit(2)
  }
  process.exit(0)
}
