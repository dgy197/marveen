// Card d6d2d686, N1: the test-run gate (PreToolUse Bash).
//
// Why it exists: on 2026-10-24 a full vitest run inside a /Volumes worktree ran a cleanup
// `rmSync(join('', '..'))` and deleted the parent of the working directory. The only JS test run the
// fleet may start is scripts/safe-vitest.sh (write-restricted sandbox), and NO test runner may start
// with an effective cwd under /Volumes.
//
// Every probe below is TEXT handed to gateDecision(); nothing is launched through a shell (the few
// CLI rows start the gate itself with node, and the gate only parses what it is given).
// The test seams are function parameters (liveRoot, volumesRoot, parser), never environment variables.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, symlinkSync, realpathSync } from 'node:fs'
import { join } from 'node:path'
import { tmpdir } from 'node:os'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, RUNNER_WORD_RE } from '../../scripts/hooks/test-run-gate.mjs'

const GATE = fileURLToPath(new URL('../../scripts/hooks/test-run-gate.mjs', import.meta.url))
const REPO_ROOT = fileURLToPath(new URL('../..', import.meta.url)).replace(/\/$/, '')
const SH = readFileSync(join(REPO_ROOT, 'scripts', 'safe-vitest.sh'))
const SB = readFileSync(join(REPO_ROOT, 'scripts', 'safe-vitest.sb'))

let base: string // scratch root (realpath)
let ok: string // a plain, existing, non-volumes cwd
let live: string // fixture "live root" with the real safe-vitest bytes
let vol: string // fixture standing in for /Volumes (opts.volumesRoot)
let volp: string // a project directory under the fixture volume
let volWt: string // a worktree under the fixture volume, with matching hashes
let brainy: string // symlink in base -> volp (like ~/Brainy -> /Volumes/8T/10_LOCAL/Brainy)
let wtGood: string
let wtShChanged: string
let wtSbChanged: string
let wtNoSb: string
let wtLinkBadSb: string

function mkWt(name: string, sh: Buffer | null, sb: Buffer | null): string {
  const d = join(base, name)
  mkdirSync(join(d, 'scripts'), { recursive: true })
  if (sh) writeFileSync(join(d, 'scripts', 'safe-vitest.sh'), sh)
  if (sb) writeFileSync(join(d, 'scripts', 'safe-vitest.sb'), sb)
  return d
}

beforeAll(() => {
  base = realpathSync(mkdtempSync(join(tmpdir(), 'test-run-gate-')))
  ok = join(base, 'ok'); mkdirSync(ok)
  live = mkWt('live', SH, SB)
  vol = join(base, 'vol'); mkdirSync(vol)
  volp = join(vol, 'proj'); mkdirSync(volp)
  volWt = join(vol, 'wt'); mkdirSync(join(volWt, 'scripts'), { recursive: true })
  writeFileSync(join(volWt, 'scripts', 'safe-vitest.sh'), SH)
  writeFileSync(join(volWt, 'scripts', 'safe-vitest.sb'), SB)
  brainy = join(base, 'brainy'); symlinkSync(volp, brainy)
  wtGood = mkWt('wt-good', SH, SB)
  wtShChanged = mkWt('wt-sh-changed', Buffer.concat([SH, Buffer.from('\n# tampered\n')]), SB)
  wtSbChanged = mkWt('wt-sb-changed', SH, Buffer.concat([SB, Buffer.from('\n;; tampered\n')]))
  wtNoSb = mkWt('wt-no-sb', SH, null)
  wtLinkBadSb = mkWt('wt-link-bad-sb', null, Buffer.concat([SB, Buffer.from('\n;; tampered\n')]))
  symlinkSync(join(live, 'scripts', 'safe-vitest.sh'), join(wtLinkBadSb, 'scripts', 'safe-vitest.sh'))
})
afterAll(() => { rmSync(base, { recursive: true, force: true }) })

type Opts = Record<string, unknown>
const decide = (cmd: string, cwd: string = ok, extra: Opts = {}) =>
  gateDecision(cmd, cwd, { liveRoot: live, volumesRoot: vol, ...extra })
const denies = (cmd: string, cwd?: string, extra?: Opts): boolean => decide(cmd, cwd, extra).deny === true

describe('E1: a JS test runner outside safe-vitest.sh is denied', () => {
  it.each([
    'vitest run',
    'vitest',
    'vitest run src/__tests__/x.test.ts',
    'npm test',
    'npm t',
    'npm run test',
    'npm run test:unit',
    'npm run-script test',
    'npm --prefix . test',
    'pnpm test',
    'pnpm run test',
    'pnpm -r test',
    'yarn test',
    'yarn run test',
    'bun test',
    'bun run test',
    'npx vitest',
    'npx --yes vitest run',
    'npx vitest@latest run',
    'pnpm exec vitest',
    'pnpm dlx vitest',
    'yarn vitest',
    'bunx vitest',
    './node_modules/.bin/vitest run',
    'node_modules/.bin/vitest',
    '/some/where/node_modules/.bin/vitest run',
    'jest',
    'npx jest --ci',
    'mocha',
    'npx mocha test/',
    'node --test x.test.mjs',
    'node --import tsx --test',
    'FOO=1 vitest run',
    'cd src && vitest run',
    'git status && vitest run',
    'vitest run | tail -5',
    'vitest run 2>&1',
  ])('denies: %s', (cmd) => {
    const r = decide(cmd)
    expect(r.deny).toBe(true)
    expect(typeof r.reason).toBe('string')
    expect(r.reason.length).toBeGreaterThan(0)
  })

  it.each([
    'git status',
    'ls -la',
    'npm install vitest',
    'npm i -D vitest',
    'npm run build',
    'npm run lint',
    'pnpm install',
    'echo "npm test"',
    "echo 'vitest run'",
    'echo vitest',
    'git commit -m "vitest"',
    'git commit -m "fix: npm test and jest, mocha"',
    "cat <<'EOF'\nnpm test\nvitest run\nEOF",
    'grep -rn vitest src',
    'cat package.json | grep jest',
    'which vitest',
    'command -v vitest',
    'node script.js --test',
    'node --check scripts/hooks/test-run-gate.mjs',
    "printf '%s' \"mocha\"",
    // accepted residual (Brainy): a test run wrapped into a shell script is not read
    'bash run-tests.sh',
  ])('allows: %s', (cmd) => {
    expect(denies(cmd)).toBe(false)
  })
})

describe('E2: the live safe-vitest.sh', () => {
  it.each([
    () => `bash ${live}/scripts/safe-vitest.sh src/__tests__/x.test.ts`,
    () => `${live}/scripts/safe-vitest.sh src/__tests__/x.test.ts`,
    () => `sh ${live}/scripts/safe-vitest.sh`,
    () => `cd ${live} && bash scripts/safe-vitest.sh x.test.ts`,
    () => `cd ${live} && bash ./scripts/../scripts/safe-vitest.sh x.test.ts`,
  ])('allows (non-volumes cwd): %#', (mk) => {
    expect(denies(mk())).toBe(false)
  })

  it('the default live root is the tree the gate sits in', () => {
    expect(gateDecision(`bash ${REPO_ROOT}/scripts/safe-vitest.sh x.test.ts`, ok, { volumesRoot: vol }).deny).toBe(false)
  })

  it('does not allow a vitest call just because a safe-vitest call sits next to it', () => {
    expect(denies(`bash ${live}/scripts/safe-vitest.sh x.test.ts && vitest run`)).toBe(true)
  })
})

describe('E3: a worktree copy of safe-vitest.sh needs both hashes to match the live files', () => {
  it('allows a copy whose .sh and .sb are byte-identical', () => {
    expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtGood)).toBe(false)
    expect(denies('./scripts/safe-vitest.sh x.test.ts', wtGood)).toBe(false)
    expect(denies('bash ./scripts/../scripts/safe-vitest.sh', wtGood)).toBe(false)
  })
  it('denies a modified .sh', () => { expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtShChanged)).toBe(true) })
  it('denies a modified .sb', () => { expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtSbChanged)).toBe(true) })
  it('denies a copy with no .sb beside it', () => { expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtNoSb)).toBe(true) })
  it('denies a symlink to the live .sh whose sibling .sb differs', () => {
    expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtLinkBadSb)).toBe(true)
  })
  it('denies when the script cannot be read at all', () => {
    expect(denies('bash scripts/safe-vitest.sh x.test.ts', ok)).toBe(true)
  })
  it('denies when the live files cannot be read (unreadable -> deny)', () => {
    expect(denies('bash scripts/safe-vitest.sh x.test.ts', wtGood, { liveRoot: join(base, 'no-such-live') })).toBe(true)
  })
  it('a bash/sh that runs some other script is not a test run', () => {
    expect(denies('bash scripts/other.sh', wtGood)).toBe(false)
  })
})

describe('E4: nothing test-like starts with an effective cwd under /Volumes', () => {
  const RUNNERS: [string, string][] = [
    ['vitest', 'vitest run'],
    ['npm test', 'npm test'],
    ['pytest', 'pytest'],
    ['python3 -m pytest', 'python3 -m pytest -x'],
    ['python -m unittest', 'python -m unittest discover'],
    ['python3 -I a/b.test.py', 'python3 -I a/b.test.py'],
    ['python3 a/b_test.py', 'python3 a/b_test.py'],
    ['python3 a/test_b.py', 'python3 a/test_b.py'],
  ]
  it.each(RUNNERS)('denies %s with the hook cwd under the volume', (_n, cmd) => {
    expect(denies(cmd, volp)).toBe(true)
  })
  it.each(RUNNERS)('denies %s with the hook cwd a symlink that resolves under the volume', (_n, cmd) => {
    expect(denies(cmd, brainy)).toBe(true)
  })
  it.each(RUNNERS)('denies %s after cd into the volume', (_n, cmd) => {
    expect(denies(`cd ${volp} && ${cmd}`)).toBe(true)
  })
  it.each(RUNNERS)('denies %s after cd into a symlink that resolves under the volume', (_n, cmd) => {
    expect(denies(`cd ${brainy} && ${cmd}`)).toBe(true)
  })

  it('denies safe-vitest.sh, live or hash-identical copy, with a volume cwd', () => {
    expect(denies(`bash ${live}/scripts/safe-vitest.sh x.test.ts`, volp)).toBe(true)
    expect(denies('bash scripts/safe-vitest.sh x.test.ts', volWt)).toBe(true)
    expect(denies(`cd ${volWt} && bash scripts/safe-vitest.sh x.test.ts`)).toBe(true)
  })

  it('pushd counts like cd', () => {
    expect(denies(`pushd ${volp} && pytest`)).toBe(true)
    expect(denies(`pushd ${volp} >/dev/null; pytest -q`)).toBe(true)
  })

  it('the last cd wins', () => {
    expect(denies(`cd ${volp} && cd ${ok} && pytest`)).toBe(false)
    expect(denies(`cd ${ok} && cd ${volp} && pytest`)).toBe(true)
  })

  it('a relative cd is resolved against the running cwd', () => {
    expect(denies('cd vol/proj && pytest', base)).toBe(true)
    expect(denies('cd ok && pytest', base)).toBe(false)
  })

  it.each([
    ['--root', 'pytest --root VOLP'],
    ['--root=', 'pytest --root=VOLP'],
    ['--dir', 'pytest --dir VOLP'],
    ['--dir=', 'pytest --dir=VOLP'],
    ['--prefix', 'pytest --prefix VOLP'],
    ['-C', 'pytest -C VOLP'],
    ['--cwd', 'pytest --cwd VOLP'],
    ['--rootdir', 'pytest --rootdir VOLP'],
    ['--rootdir=', 'pytest --rootdir=VOLP'],
    ['python -m pytest --rootdir', 'python3 -m pytest --rootdir VOLP'],
    ['safe-vitest --root', 'bash scripts/safe-vitest.sh --root VOLP x.test.ts'],
    ['npm --prefix', 'npm --prefix VOLP test'],
    ['vitest --root', 'vitest run --root VOLP'],
  ])('denies a directory option pointing under the volume: %s', (_n, tpl) => {
    expect(denies(tpl.replace('VOLP', volp), wtGood)).toBe(true)
  })

  it('a relative directory option is resolved against the cwd', () => {
    expect(denies('pytest --rootdir vol/proj', base)).toBe(true)
    expect(denies('pytest --rootdir ok', base)).toBe(false)
  })

  it('a directory option pointing at a non-volumes path is fine', () => {
    expect(denies(`pytest --rootdir ${ok}`)).toBe(false)
    expect(denies(`pytest -C ${ok}`)).toBe(false)
  })

  it('an unresolvable cwd next to a runner denies', () => {
    expect(denies('cd $SOMEWHERE && pytest')).toBe(true)
    expect(denies('cd "$(pwd)/x" && pytest')).toBe(true)
    expect(denies(`cd ${join(base, 'no-such-dir')} && pytest`)).toBe(true)
    expect(denies('pytest', join(base, 'no-such-dir'))).toBe(true)
    expect(denies('cd - && pytest')).toBe(true)
  })

  it('an unresolvable cwd without a runner does not matter', () => {
    expect(denies('cd $SOMEWHERE && echo hi')).toBe(false)
    expect(denies(`cd ${join(base, 'no-such-dir')} && ls`)).toBe(false)
  })

  it('commands that are not test runs are not stopped by a volume cwd', () => {
    expect(denies('ls -la', volp)).toBe(false)
    expect(denies('git status', volp)).toBe(false)
    expect(denies('python3 script.py', volp)).toBe(false)
    expect(denies('npm run build', volp)).toBe(false)
  })

  it('the default volumes root is /Volumes', () => {
    expect(gateDecision('pytest', '/Volumes/8T/10_LOCAL/Brainy/x', { liveRoot: live }).deny).toBe(true)
    expect(gateDecision('cd /Volumes/x && pytest', ok, { liveRoot: live }).deny).toBe(true)
    expect(gateDecision('pytest', ok, { liveRoot: live }).deny).toBe(false)
  })
})

describe('E5: wrappers decide exactly like the bare command', () => {
  const WRAPPERS: [string, (inner: string) => string][] = [
    ['env', (c) => `env FOO=1 ${c}`],
    ['env -i', (c) => `env -i FOO=1 ${c}`],
    ['assignment prefix', (c) => `FOO=1 ${c}`],
    ['bash -c single', (c) => `bash -c '${c}'`],
    ['bash -c double', (c) => `bash -c "${c}"`],
    ['bash -lc', (c) => `bash -lc '${c}'`],
    ['sh -c', (c) => `sh -c '${c}'`],
    ['sh -c with args', (c) => `sh -c '${c}' _ one two`],
    ['nested bash -c', (c) => `bash -c "sh -c '${c}'"`],
    ['eval', (c) => `eval '${c}'`],
    ['eval unquoted', (c) => `eval ${c}`],
    ['command', (c) => `command ${c}`],
    ['exec', (c) => `exec ${c}`],
    ['time', (c) => `time ${c}`],
    ['nice', (c) => `nice -n 5 ${c}`],
    ['timeout', (c) => `timeout 60 ${c}`],
    ['timeout -k', (c) => `timeout -k 5 60 ${c}`],
    ['xargs', (c) => `echo x | xargs ${c}`],
    ['xargs -I', (c) => `echo x | xargs -I{} ${c}`],
    ['subshell', (c) => `(${c})`],
    ['brace group', (c) => `{ ${c}; }`],
    ['command substitution', (c) => `echo $(${c})`],
    ['backticks', (c) => `echo \`${c}\``],
    ['in double quotes', (c) => `echo "$(${c})"`],
    ['if', (c) => `if true; then ${c}; fi`],
    ['for loop', (c) => `for i in 1 2; do ${c}; done`],
    ['function', (c) => `f() { ${c}; }; f`],
    ['function keyword', (c) => `function f { ${c}; }; f arg`],
    ['alias', (c) => `alias t='${c}'; t`],
    ['shell heredoc', (c) => `bash <<'EOF'\n${c}\nEOF`],
    ['shell here-string', (c) => `bash <<< '${c}'`],
    ['find -exec', (c) => `find . -name x -exec ${c} \\;`],
    ['quoted pieces', (c) => c.replace(/^(\S)/, "'$1'")],
    ['backslash', (c) => `\\${c}`],
    // N1b (Brainy D1): sandbox-style wrappers run the rest of the line as the command.
    ['run-sandboxed.sh', (c) => `run-sandboxed.sh ${c}`],
    ['run-sandboxed.sh by path', (c) => `/Users/x/.claude/sandbox/run-sandboxed.sh ${c}`],
    ['sandbox-exec -f', (c) => `sandbox-exec -f p.sb ${c}`],
    ['sandbox-exec -p -D -n', (c) => `sandbox-exec -n no-network -D A=b -p '(version 1)' ${c}`],
    ['perl exec @ARGV', (c) => `perl -e 'exec @ARGV or die' ${c}`],
    ['perl -e exec', (c) => `perl -e 'alarm 5; exec @ARGV' ${c}`],
    ['script', (c) => `script -q /dev/null ${c}`],
    ['script -t', (c) => `script -a -t 5 out.log ${c}`],
    ['gtimeout', (c) => `gtimeout 60 ${c}`],
    ['gtimeout -k', (c) => `gtimeout -k 5 -s KILL 60 ${c}`],
  ]

  describe.each(WRAPPERS)('%s', (_n, wrap) => {
    it('denies a JS runner', () => { expect(denies(wrap('vitest run'))).toBe(true) })
    it('denies npm test', () => { expect(denies(wrap('npm test'))).toBe(true) })
    it('allows a non-runner', () => { expect(denies(wrap('git status'))).toBe(false) })
    it('allows pytest on a plain cwd', () => { expect(denies(wrap('pytest -q'))).toBe(false) })
    it('denies pytest on a volume cwd', () => { expect(denies(wrap('pytest -q'), volp)).toBe(true) })
    it('allows the live safe-vitest.sh', () => {
      expect(denies(wrap(`bash ${live}/scripts/safe-vitest.sh x.test.ts`))).toBe(false)
    })
    it('denies the live safe-vitest.sh on a volume cwd', () => {
      expect(denies(wrap(`bash ${live}/scripts/safe-vitest.sh x.test.ts`), volp)).toBe(true)
    })
  })

  it('a wrapped cd moves the cwd for what follows (subshell cd stays conservative: it denies)', () => {
    expect(denies(`bash -c 'cd ${volp} && pytest'`)).toBe(true)
    expect(denies(`(cd ${volp} && pytest)`)).toBe(true)
    expect(denies(`sh -c "cd ${ok} && pytest"`)).toBe(false)
  })

  it('an uncalled function runs nothing', () => {
    expect(denies('f() { vitest run; }')).toBe(false)
  })

  it('a computed command word is judged by the raw text', () => {
    expect(denies('${X:-vitest} run')).toBe(true)
    expect(denies('$(echo vitest) run')).toBe(true)
    expect(denies('"$HOME/bin/tool" run')).toBe(false)
  })
})

describe('E5b (N1b, Brainy D1): the sandbox wrappers in detail', () => {
  it('a wrapper with no command after it is not a test run', () => {
    expect(denies('sandbox-exec -f p.sb')).toBe(false)
    expect(denies('script -q /dev/null')).toBe(false)
    expect(denies('script out.log')).toBe(false)
    expect(denies("perl -e 'exec @ARGV'")).toBe(false)
    expect(denies('gtimeout 60')).toBe(false)
    expect(denies('run-sandboxed.sh')).toBe(false)
  })
  it('perl -e without exec / system does not run its argv', () => {
    expect(denies("perl -e 'print 1' npx vitest")).toBe(false)
  })
  it('perl without -e runs a script file, not a command', () => {
    expect(denies('perl tool.pl npm test')).toBe(false)
  })
  it('the wrapped python runner follows the /Volumes rule', () => {
    expect(denies('run-sandboxed.sh pytest -q')).toBe(false)
    expect(denies('run-sandboxed.sh pytest -q', volp)).toBe(true)
    expect(denies('sandbox-exec -f p.sb python3 -m pytest', volp)).toBe(true)
  })
  it('ssh stays out: the command runs on the remote host', () => {
    expect(denies('ssh host npx vitest run')).toBe(false)
  })
  it('wrappers nest', () => {
    expect(denies('run-sandboxed.sh gtimeout 60 sandbox-exec -f p.sb npx vitest run')).toBe(true)
    expect(denies('timeout 5 run-sandboxed.sh npm test')).toBe(true)
  })
})

describe('E5c (N1b, Brainy D2): a variable interpreter running pytest is a python runner', () => {
  it.each([
    '"$PY" -m pytest',
    '"$PY" -m pytest -q tests/',
    '$PY -m unittest discover',
    '${PY} -I a/b.test.py',
    '"${PY}" a/b_test.py',
    '"$PY" -I tests/test_a.py',
    'FOO=1 "$PY" -m pytest',
    'cd . && "$PY" -m pytest',
  ])('allows outside /Volumes: %s', (cmd) => {
    expect(denies(cmd)).toBe(false)
  })
  it.each([
    '"$PY" -m pytest',
    '${PY} -I a/b.test.py',
    'cd . && "$PY" -m unittest',
  ])('denies under /Volumes: %s', (cmd) => {
    expect(denies(cmd, volp)).toBe(true)
  })
  it('a directory option under /Volumes still denies', () => {
    expect(denies(`"$PY" -m pytest --rootdir ${volp}`)).toBe(true)
  })
  it.each([
    '"$X" vitest',
    '$X vitest run',
    '"$X" -m npm test',
    '"$X" npm test',
    '"$X" node --test a.test.mjs',
    '${X:-vitest} -m pytest',
    '$(echo vitest) -m pytest',
  ])('every other variable command word keeps the raw-text rule: %s', (cmd) => {
    expect(denies(cmd)).toBe(true)
  })
  it('a variable command word without a runner word is fine', () => {
    expect(denies('"$PY" script.py')).toBe(false)
    expect(denies('"$TOOL" status')).toBe(false)
  })
})

describe('E6: a parser that throws', () => {
  const boom = { parser: () => { throw new Error('boom') } }
  it.each([
    'vitest run',
    'npm test',
    'npm run test:unit',
    'pnpm test',
    'yarn test',
    'bun test',
    'jest --ci',
    'mocha',
    'pytest -q',
    'python3 -m pytest',
    'python3 -m unittest',
    'node --test x.test.mjs',
    'bash scripts/safe-vitest.sh x',
    'python3 a/b.test.py',
    'python3 a/b_test.py',
    'python3 a/test_b.py',
  ])('denies a runner-word text: %s', (cmd) => {
    expect(denies(cmd, ok, boom)).toBe(true)
  })
  it.each([
    'git status',
    'ls -la',
    'echo hello',
    'npm run build',
    'python3 script.py',
    'node server.js',
  ])('allows any other text: %s', (cmd) => {
    expect(denies(cmd, ok, boom)).toBe(false)
  })
  it('an unparseable text follows the same rule: runner word -> deny, otherwise allow', () => {
    expect(denies("echo 'unterminated vitest", ok)).toBe(true)
    expect(denies("echo 'unterminated quote", ok)).toBe(false)
  })

  it('RUNNER_WORD_RE matches the runner words and only them', () => {
    for (const t of ['vitest', 'run jest now', 'mocha x', 'pytest', 'python -m unittest', 'node --test a.mjs',
      'npm test', 'npm run test:unit', 'pnpm t', 'yarn test', 'bun test', 'a.test.py', 'a_test.py', 'test_a.py']) {
      expect(RUNNER_WORD_RE.test(t), t).toBe(true)
    }
    for (const t of ['git status', 'ls', 'npm install', 'npm run build', 'node server.js', 'python3 main.py', 'echo hello']) {
      expect(RUNNER_WORD_RE.test(t), t).toBe(false)
    }
  })
  it('RUNNER_WORD_RE is not global (no lastIndex state between calls)', () => {
    expect(RUNNER_WORD_RE.global).toBe(false)
    expect(RUNNER_WORD_RE.test('vitest')).toBe(true)
    expect(RUNNER_WORD_RE.test('vitest')).toBe(true)
  })
})

describe('E7: python runners are fine outside /Volumes', () => {
  it.each([
    'pytest',
    'pytest -x tests/',
    'python -m pytest',
    'python3 -m pytest tests/test_a.py',
    'python3.11 -m pytest',
    'python3 -I -m pytest',
    'python -m unittest',
    'python3 -m unittest discover',
    'python3 -I a/b.test.py',
    'python3 a/b_test.py',
    'python3 a/test_b.py',
    'python3 script.py',
    'python3 -c "print(1)"',
  ])('allows: %s', (cmd) => {
    expect(denies(cmd)).toBe(false)
  })
})

describe('R1 (review round 1): bypasses found by the review', () => {
  describe('B1: the install-test verbs run the test script', () => {
    it.each([
      'npm it', 'npm cit', 'npm sit', 'npm install-test', 'npm install-ci-test', 'npm clean-install-test',
      'npm --silent it', 'pnpm it', 'pnpm install-test', 'cd . && npm it',
    ])('denies: %s', (cmd) => {
      expect(denies(cmd)).toBe(true)
    })
    it.each(['npm install', 'npm i', 'npm ci', 'npm init', 'npm install-something-else', 'pnpm install'])('allows: %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
  })

  describe('B2: node --run <script> is npm run <script>', () => {
    it.each(['node --run test', 'node --run=test', 'node --run test:unit', 'node --run=test:unit', 'node --no-warnings --run test'])('denies: %s', (cmd) => {
      expect(denies(cmd)).toBe(true)
    })
    it.each(['node --run build', 'node --run=lint', 'node --run'])('allows: %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
  })

  describe('B3: a shell that reads its program from stdin', () => {
    it.each([
      'echo npx vitest | bash',
      "printf 'npx vitest run' | sh",
      "echo 'npx vitest' | bash -s",
      "echo 'npm test' | zsh",
      "cat <<'E' | bash\nnpx vitest\nE",
      "echo 'pytest' | bash -s -- a",
      "bash < /dev/null; echo vitest",
    ])('denies: %s', (cmd) => {
      expect(denies(cmd)).toBe(true)
    })
    it.each([
      'echo hello | bash',
      'cat script.sh | bash',
      'bash < script.sh',
      "bash -c 'echo hi'",
      'bash script.sh',
    ])('allows (no runner word in the text): %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
  })

  describe('B4: code handed to an interpreter on the command line', () => {
    it.each([
      `node -e "require('child_process').execSync('npx vitest')"`,
      `node -p "require('child_process').execSync('npm test').toString()"`,
      `node --eval="require('child_process').execSync('npx jest')"`,
      `node --print "require('child_process').execSync('npx jest')"`,
      `python3 -c "import subprocess; subprocess.run(['npx','vitest'])"`,
      `python -c "import os; os.system('npm test')"`,
      `osascript -e 'do shell script "npx vitest"'`,
      `perl -e 'system("npx vitest")'`,
      `perl -e 'exec("npm", "test")'`,
      'bun ./node_modules/vitest/vitest.mjs run',
      'bun node_modules/vitest/vitest.mjs',
      'bun run ./node_modules/vitest/vitest.mjs',
    ])('denies: %s', (cmd) => {
      expect(denies(cmd)).toBe(true)
    })
    it.each([
      `node -e "console.log(1)"`,
      `node -p "process.version"`,
      `python3 -c "print(1)"`,
      `osascript -e 'display dialog "hi"'`,
      `perl -e 'print "hi"'`,
      'bun script.ts',
      'bun run build',
    ])('allows: %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
    it('python -c running pytest is a python runner: the cwd rule applies', () => {
      expect(denies(`python3 -c "import pytest; pytest.main()"`)).toBe(false)
      expect(denies(`python3 -c "import pytest; pytest.main()"`, volp)).toBe(true)
      expect(denies(`python3 -c "import unittest; unittest.main()"`, volp)).toBe(true)
      expect(denies(`python3 -Ic "import pytest; pytest.main()"`, volp)).toBe(true)
      expect(denies(`python3 -c "print(1)"`, volp)).toBe(false)
    })
  })

  describe('B5: env -S / --split-string carries a command', () => {
    it.each([
      `env -S 'npx vitest'`,
      `env --split-string='npx vitest'`,
      `env --split-string 'npm test'`,
      `env -S'npx vitest run'`,
      `env -i -S 'FOO=1 npx vitest'`,
    ])('denies: %s', (cmd) => {
      expect(denies(cmd)).toBe(true)
    })
    it('the value is judged like a command: cwd rule for pytest', () => {
      expect(denies(`env -S 'pytest -q'`)).toBe(false)
      expect(denies(`env -S 'pytest -q'`, volp)).toBe(true)
    })
    it.each([`env -S 'ls -la'`, 'env FOO=1 ls', `env -u HOME ls`])('allows: %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
  })

  describe('B7: the /Volumes prefix is compared case-insensitively', () => {
    const up = (p: string) => p.toUpperCase()
    it('the hook cwd in another case', () => {
      expect(denies('pytest', up(volp))).toBe(true)
    })
    it('a cd target in another case', () => {
      expect(denies(`cd ${up(volp)} && pytest`)).toBe(true)
    })
    it.each(['--rootdir', '--root', '--dir', '--prefix', '-C'])('the %s value in another case', (opt) => {
      expect(denies(`pytest ${opt} ${up(volp)}`)).toBe(true)
    })
    it('the default root: /volumes and /VOLUMES', () => {
      expect(gateDecision('cd /volumes/8T && pytest', ok, { liveRoot: live }).deny).toBe(true)
      expect(gateDecision('pytest', '/VOLUMES/8T/x', { liveRoot: live }).deny).toBe(true)
    })
    it('a path that only starts with the same letters is not under the volume', () => {
      expect(denies(`pytest -C ${vol}-other`)).toBe(false)
    })
  })

  describe('a missing or relative hook cwd', () => {
    const open = (cmd: string, cwd?: unknown) => gateDecision(cmd, cwd, { liveRoot: live, volumesRoot: vol }).deny === true
    it.each([undefined, null, '', 'relative/dir', 42])('a python runner with cwd %s is denied', (cwd) => {
      expect(open('pytest', cwd)).toBe(true)
      expect(open('python3 -m pytest -q', cwd)).toBe(true)
    })
    it('a JS runner is denied anyway, a non-runner is allowed', () => {
      expect(open('vitest run', undefined)).toBe(true)
      expect(open('ls -la', undefined)).toBe(false)
      expect(open('git status && echo hi', 'relative/dir')).toBe(false)
    })
    it('an absolute cd gives the command a cwd of its own', () => {
      expect(open(`cd ${ok} && pytest`, undefined)).toBe(false)
      expect(open(`cd ${volp} && pytest`, undefined)).toBe(true)
    })
    it('the hook entry: no cwd + pytest exits 2, no cwd + ls exits 0', () => {
      const run = (command: string) => spawnSync(process.execPath, [GATE], {
        input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }), encoding: 'utf8', timeout: 20000,
      })
      expect(run('pytest').status).toBe(2)
      expect(run('ls -la').status).toBe(0)
    })
  })

  // Rows are templates (@OK@, @VOLP@, @VOL@): the fixture paths exist only after beforeAll.
  const fx = (s: string) => s.replace(/@OK@/g, ok).replace(/@VOLP@/g, volp).replace(/@VOL@/g, vol)
  describe('B6: a cd in a subshell, pipeline element, background job, substitution or bash -c stays there', () => {
    it.each([
      `(cd @OK@); pytest`,
      `(cd @OK@ && ls); python3 -m pytest`,
      `bash -c 'cd @OK@'; pytest`,
      `x=$(cd @OK@; pwd); pytest`,
      `cd @OK@ | cat; pytest`,
      `cd @OK@ & pytest`,
      `pytest $(cd @OK@; echo x)`,
    ])('the outer cwd is unchanged, denies on a volume cwd: %s', (cmd) => {
      expect(denies(fx(cmd), volp)).toBe(true)
    })
    it.each([
      `(cd @VOLP@); pytest`,
      `bash -c 'cd @VOLP@'; pytest`,
      `x=$(cd @VOLP@; pwd); pytest`,
      `cd @VOLP@ | cat; pytest`,
      `cd @VOLP@ & pytest`,
    ])('and a cd into the volume inside a scope does not poison the outer cwd: %s', (cmd) => {
      expect(denies(fx(cmd), ok)).toBe(false)
    })
    it.each([
      `(cd @VOLP@ && pytest)`,
      `bash -c 'cd @VOLP@ && pytest'`,
      `x=$(cd @VOLP@; pytest)`,
    ])('a runner inside the scope still sees the scope cwd: %s', (cmd) => {
      expect(denies(fx(cmd), ok)).toBe(true)
    })
    it('a plain cd still moves the cwd for what follows', () => {
      expect(denies(`cd ${ok} && pytest`, volp)).toBe(false)
      expect(denies(`cd ${volp} && pytest`, ok)).toBe(true)
      expect(denies(`{ cd ${volp}; }; pytest`, ok)).toBe(true)
    })
    it('a cd in the LAST pipeline element leaves the cwd unknown (zsh runs it in the current shell, bash does not)', () => {
      expect(denies(`ls | cd ${base}; pytest`, ok)).toBe(true)
      expect(denies(`ls | cd ${ok}; ls`, ok)).toBe(false)
    })
    it('a subshell inside a subshell restores one level at a time', () => {
      expect(denies(`(cd ${volp}; (cd ${ok}); pytest)`, ok)).toBe(true)
      expect(denies(`(cd ${volp}; (cd ${ok}; pytest))`, ok)).toBe(false)
      expect(denies(`(cd ${ok}); (cd ${volp}); pytest`, ok)).toBe(false)
    })
  })

  describe('B8: an assigned HOME or CDPATH makes ~, $HOME, a bare cd and a relative cd unresolvable', () => {
    it.each([
      `export HOME=@VOLP@; cd; pytest`,
      `HOME=@VOLP@; cd ~ && pytest`,
      `HOME=@VOLP@; cd $HOME && pytest`,
      'export HOME=@OK@; cd ~ && pytest',
      `export CDPATH=@VOL@; cd ok && pytest`,
      `CDPATH=@VOL@ cd ok && pytest`,
    ])('denies: %s', (cmd) => {
      expect(denies(fx(cmd), base)).toBe(true)
    })
    it('without such an assignment ~ and a relative cd resolve as before', () => {
      expect(denies('cd ok && pytest', base)).toBe(false)
      expect(denies('cd ./ok && pytest', base)).toBe(false)
    })
    it('a CDPATH assignment does not touch an explicit ./ cd', () => {
      expect(denies(`export CDPATH=${vol}; cd ./ok && pytest`, base)).toBe(false)
    })
  })

  describe('over-block controls: a runner word in quoted data or in a non-runner stays allowed', () => {
    it.each([
      'echo "node -e vitest"',
      'grep -rn "npm it" src',
      'git commit -m "npm it works, node --run test"',
      'cat package.json | grep vitest',
      'ls | bash',
    ])('allows: %s', (cmd) => {
      expect(denies(cmd)).toBe(false)
    })
  })
})

describe('the hook entry (stdin JSON -> exit 0 / 2)', () => {
  const run = (payload: unknown) => spawnSync(process.execPath, [GATE], {
    input: typeof payload === 'string' ? payload : JSON.stringify(payload),
    encoding: 'utf8',
    timeout: 20000,
  })
  it('exits 2 with a reason on stderr for a bare test run', () => {
    const r = run({ tool_name: 'Bash', tool_input: { command: 'vitest run' }, cwd: ok })
    expect(r.status).toBe(2)
    expect(r.stderr.length).toBeGreaterThan(0)
    expect(r.stdout).toBe('')
  })
  it('exits 2 for npm test', () => {
    expect(run({ tool_name: 'Bash', tool_input: { command: 'npm test' }, cwd: ok }).status).toBe(2)
  })
  it('exits 0 for an ordinary command', () => {
    expect(run({ tool_name: 'Bash', tool_input: { command: 'git status' }, cwd: ok }).status).toBe(0)
  })
  it('exits 0 for pytest on a plain cwd and 2 on a /Volumes cwd', () => {
    expect(run({ tool_name: 'Bash', tool_input: { command: 'pytest' }, cwd: ok }).status).toBe(0)
    expect(run({ tool_name: 'Bash', tool_input: { command: 'pytest' }, cwd: '/Volumes/8T/x' }).status).toBe(2)
  })
  it('ignores other tools', () => {
    expect(run({ tool_name: 'Read', tool_input: { command: 'vitest run' }, cwd: ok }).status).toBe(0)
  })
  it('exits 0 on stdin that is not JSON or has no command', () => {
    expect(run('not json').status).toBe(0)
    expect(run('').status).toBe(0)
    expect(run({ tool_name: 'Bash', tool_input: {}, cwd: ok }).status).toBe(0)
  })
  it('does not read test seams from the environment', () => {
    const r = spawnSync(process.execPath, [GATE], {
      input: JSON.stringify({ tool_name: 'Bash', tool_input: { command: 'vitest run' }, cwd: ok }),
      encoding: 'utf8',
      timeout: 20000,
      env: { ...process.env, LIVE_ROOT: base, VOLUMES_ROOT: base, TEST_RUN_GATE_LIVE_ROOT: base, TEST_RUN_GATE_DISABLE: '1' },
    })
    expect(r.status).toBe(2)
  })
})
