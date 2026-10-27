/**
 * Memory write gate b1 (card 3e9f6c28, node G2b): transport + Python adapter.
 *
 * Every test drives the REAL adapter under /usr/bin/python3 -I against a FAKE
 * batch client copied into a fresh os.tmpdir() directory (no network: the fake
 * scripts every outcome). Covered: the exact child environment, stdlib-first
 * import order, untrusted batch dir / contract mismatch, the usage-log wrapper
 * (GB3), the GN4 error classes, the token residue check (GB2), the deadline
 * SIGKILL, the stdout cap and the vitest guard.
 */
import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { spawn, spawnSync, type ChildProcess } from 'node:child_process'
import { chmodSync, copyFileSync, existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync, mkdirSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logger } from '../logger.js'
import {
  runGateCalls, gateChildEnv, parseAdapterOutput, DEFAULT_ADAPTER, GATE_PYTHON,
  type GateCall, type SpawnFn,
} from '../memory-gate/transport.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const FIX = join(HERE, 'fixtures', 'memory-gate')
const DASH_TOKEN = readFileSync(join(FIX, 'fake-store', '.dashboard-token'), 'utf8').trim()
const OAUTH_TOKEN = readFileSync(join(FIX, 'fake-store', '.claude-oauth-token'), 'utf8').trim()

let root: string
let batchDir: string
let storeDir: string

function call(k: number, scn: string, extra: Partial<GateCall> = {}): GateCall {
  return { k: String(k), model: 'claude-haiku-5-5', max_tokens: 300, system: 'sys', prompt: `SCN:${scn}\nbody`, ...extra }
}

function callsLog(): Array<{ scn: string; caller: string; timeout: number }> {
  const p = join(batchDir, 'calls.log')
  if (!existsSync(p)) return []
  return readFileSync(p, 'utf8').trim().split('\n').filter(Boolean).map(l => JSON.parse(l))
}

beforeEach(() => {
  root = mkdtempSync(join(tmpdir(), 'mg-transport-'))
  batchDir = join(root, 'batch')
  storeDir = join(root, 'store')
  mkdirSync(batchDir, { mode: 0o700 })
  mkdirSync(storeDir, { mode: 0o700 })
  for (const f of readdirSync(join(FIX, 'fake-batch'))) {
    if (f.endsWith('.py')) copyFileSync(join(FIX, 'fake-batch', f), join(batchDir, f))
  }
  for (const f of ['.dashboard-token', '.claude-oauth-token']) copyFileSync(join(FIX, 'fake-store', f), join(storeDir, f))
  for (const f of readdirSync(batchDir)) chmodSync(join(batchDir, f), 0o600)
  chmodSync(batchDir, 0o700)
})

afterEach(() => {
  vi.restoreAllMocks()
  try { chmodSync(batchDir, 0o700) } catch { /* ignore */ }
  rmSync(root, { recursive: true, force: true })
})

const run = (calls: GateCall[], extra: Record<string, unknown> = {}) => runGateCalls(calls, { batchDir, storeDir, ...extra })
const errs = (r: Awaited<ReturnType<typeof run>>) => r.map(x => (x.ok ? 'ok' : x.error))

describe('child process: environment, flags, import order', () => {
  it('passes exactly the four 4.3 keys; proxy / keylog / PYTHONPATH of the parent never cross', async () => {
    process.env.SSLKEYLOGFILE = join(root, 'keys.log')
    process.env.HTTPS_PROXY = 'http://127.0.0.1:9'
    process.env.PYTHONPATH = batchDir
    try {
      const seen: Array<{ cmd: string; args: readonly string[]; opts: Record<string, unknown> }> = []
      const spy: SpawnFn = (cmd, args, opts) => { seen.push({ cmd, args, opts: opts as Record<string, unknown> }); return spawn(cmd, args as string[], opts) }
      const [r] = await run([call(1, 'env')], { spawn: spy })
      expect(r.ok).toBe(true)
      const keys = JSON.parse((r as { text: string }).text) as string[]
      // What WE pass is exactly the four keys (spawn spy below). Inside the child,
      // /usr/bin/python3 is the xcrun shim, which adds its own SDK keys (measured:
      // SDKROOT, CPATH, LIBRARY_PATH, MANPATH); nothing of the parent's env appears.
      const shimKeys = new Set(['SDKROOT', 'CPATH', 'LIBRARY_PATH', 'MANPATH', '__CF_USER_TEXT_ENCODING'])
      expect(keys.filter(k => !shimKeys.has(k))).toEqual(['HOME', 'LANG', 'PATH', 'PYTHONDONTWRITEBYTECODE'])
      for (const k of ['SSLKEYLOGFILE', 'HTTPS_PROXY', 'PYTHONPATH', 'VITEST', 'NODE_OPTIONS']) expect(keys).not.toContain(k)
      expect(seen).toHaveLength(1)
      expect(seen[0].cmd).toBe(GATE_PYTHON)
      expect(seen[0].args).toEqual(['-I', DEFAULT_ADAPTER, '--batch-dir', batchDir, '--store-dir', storeDir])
      expect(seen[0].opts.shell).toBe(false)
      expect(seen[0].opts.env).toEqual(gateChildEnv())
      expect(seen[0].opts.cwd).toBe(join(storeDir, 'iras-kapu', 'run'))
      expect(existsSync(join(root, 'keys.log'))).toBe(false)
    } finally {
      delete process.env.SSLKEYLOGFILE
      delete process.env.HTTPS_PROXY
      delete process.env.PYTHONPATH
    }
  })

  it('-I + append: a json.py / colorsys.py in the batch dir does NOT shadow the stdlib', async () => {
    writeFileSync(join(batchDir, 'json.py'), 'raise RuntimeError("shadowed json")\n', { mode: 0o600 })
    writeFileSync(join(batchDir, 'colorsys.py'), 'raise RuntimeError("shadowed colorsys")\n', { mode: 0o600 })
    const [r] = await run([call(1, 'modules')])
    expect(r.ok).toBe(true)
    const files = JSON.parse((r as { text: string }).text) as Record<string, string>
    expect(files.json.startsWith(batchDir)).toBe(false)
    expect(files.colorsys.startsWith(batchDir)).toBe(false)
  })

  it('a same-named batch_client earlier on sys.path (site-packages) -> contract_mismatch, and it never executes', () => {
    const shadow = join(root, 'site-packages')
    mkdirSync(shadow)
    const marker = join(root, 'shadow-ran')
    writeFileSync(join(shadow, 'batch_client.py'), `open(${JSON.stringify(marker)}, "w").write("x")\n`)
    const driver = [
      'import importlib.util, sys',
      `spec = importlib.util.spec_from_file_location("gate_adapter", ${JSON.stringify(DEFAULT_ADAPTER)})`,
      'm = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)',
      `sys.path.insert(0, ${JSON.stringify(shadow)})`,
      'try:',
      `    m.load_client(${JSON.stringify(batchDir)}); sys.__stdout__.write("loaded")`,
      'except m._Fatal as f:',
      '    sys.__stdout__.write(f.cls)',
    ].join('\n')
    const out = spawnSync(GATE_PYTHON, ['-I', '-c', driver], { env: gateChildEnv(), encoding: 'utf8' })
    expect(out.stdout).toBe('contract_mismatch')
    expect(existsSync(marker)).toBe(false)
  })

  it('a client whose __file__ points outside the batch dir -> contract_mismatch, no call', async () => {
    const src = readFileSync(join(batchDir, 'batch_client.py'), 'utf8')
    writeFileSync(join(batchDir, 'batch_client.py'), src + `\n__file__ = ${JSON.stringify(join(root, 'elsewhere', 'batch_client.py'))}\n`)
    expect(errs(await run([call(1, 'ok')]))).toEqual(['contract_mismatch'])
    expect(callsLog()).toHaveLength(0)
  })
})

describe('untrusted batch dir and contract', () => {
  it('symlinked batch_client.py -> untrusted_batch_dir', async () => {
    const real = join(root, 'real_client.py')
    copyFileSync(join(batchDir, 'batch_client.py'), real)
    rmSync(join(batchDir, 'batch_client.py'))
    symlinkSync(real, join(batchDir, 'batch_client.py'))
    expect(errs(await run([call(1, 'ok')]))).toEqual(['untrusted_batch_dir'])
  })

  it('world-writable dir or group-writable client file -> untrusted_batch_dir', async () => {
    chmodSync(batchDir, 0o777)
    expect(errs(await run([call(1, 'ok')]))).toEqual(['untrusted_batch_dir'])
    chmodSync(batchDir, 0o700)
    chmodSync(join(batchDir, 'usage_log.py'), 0o660)
    expect(errs(await run([call(2, 'ok')]))).toEqual(['untrusted_batch_dir'])
    expect(callsLog()).toHaveLength(0)
  })

  it('relative batch dir -> untrusted_batch_dir without a spawn', async () => {
    const spy = vi.fn() as unknown as SpawnFn
    const r = await runGateCalls([call(1, 'ok')], { batchDir: 'batch', storeDir, spawn: spy })
    expect(errs(r)).toEqual(['untrusted_batch_dir'])
    expect(spy).not.toHaveBeenCalled()
  })

  it('ask() without a `timeout` keyword -> contract_mismatch', async () => {
    const src = readFileSync(join(batchDir, 'batch_client.py'), 'utf8').replace('timeout=120, ', '')
    writeFileSync(join(batchDir, 'batch_client.py'), src)
    expect(errs(await run([call(1, 'ok')]))).toEqual(['contract_mismatch'])
  })

  it('a non-module-level / foreign append_usage -> contract_mismatch', async () => {
    const src = readFileSync(join(batchDir, 'batch_client.py'), 'utf8')
    writeFileSync(join(batchDir, 'batch_client.py'), src + '\ndef append_usage(path, record):\n    return True\n')
    expect(errs(await run([call(1, 'ok')]))).toEqual(['contract_mismatch'])
  })
})

describe('calls and error classes', () => {
  it('ok: text back, caller and timeout fixed, usage written', async () => {
    const r = await run([call(7, 'ok')])
    expect(r).toEqual([{ k: '7', ok: true, text: '{"op":"CREATE","target":null,"confidence":0.9,"reason":"fake"}' }])
    expect(callsLog()).toEqual([{ scn: 'ok', caller: 'memoria-iras-kapu', timeout: 30, model: 'claude-haiku-5-5' }])
    expect(readFileSync(join(batchDir, 'usage.jsonl'), 'utf8')).toContain('memoria-iras-kapu')
  })

  it('HTTP mapping: credit / bad_request / auth / transient', async () => {
    expect(errs(await run([call(1, 'http400credit'), call(2, 'http400'), call(3, 'http401'), call(4, 'http403'), call(5, 'http404')])))
      .toEqual(['credit', 'bad_request', 'auth', 'auth', 'bad_request'])
    expect(errs(await run([call(6, 'http429'), call(7, 'http500'), call(8, 'http529')])))
      .toEqual(['transient', 'transient', 'transient'])
  })

  it('GN4: only provably pre-send failures are transient; every other transport failure is maybe_billed', async () => {
    expect(errs(await run([call(1, 'refused'), call(2, 'refused_url'), call(3, 'gaierror'), call(4, 'timeout'), call(5, 'timeout_url')])))
      .toEqual(['transient', 'transient', 'transient', 'maybe_billed', 'maybe_billed'])
    expect(errs(await run([call(6, 'reset'), call(7, 'remote_disc'), call(8, 'incomplete'), call(9, 'ssl'), call(10, 'urlerror_other')])))
      .toEqual(['maybe_billed', 'maybe_billed', 'maybe_billed', 'maybe_billed', 'maybe_billed'])
    expect(errs(await run([call(11, 'badjson'), call(12, 'boom'), call(13, 'big')]))).toEqual(['error', 'error', 'error'])
  })

  it('GB3: append_usage BlockingIOError -> usage_log_failed and the rest of the run is not called', async () => {
    expect(errs(await run([call(1, 'usage_blocking'), call(2, 'ok'), call(3, 'ok')])))
      .toEqual(['usage_log_failed', 'stopped', 'stopped'])
    expect(callsLog().map(c => c.scn)).toEqual(['usage_blocking'])
  })

  it('GB3: the usage flag wins over the class of the ask() exception (ValueError then HTTP 429)', async () => {
    expect(errs(await run([call(1, 'usage_value_then_429'), call(2, 'ok')]))).toEqual(['usage_log_failed', 'stopped'])
  })

  it('STOP file (ask -> None) -> stopped; a print() inside the client cannot corrupt the protocol', async () => {
    expect(errs(await run([call(1, 'print'), call(2, 'stop'), call(3, 'ok')]))).toEqual(['ok', 'stopped', 'stopped'])
  })

  it('more than five calls -> error without a spawn', async () => {
    const spy = vi.fn() as unknown as SpawnFn
    const r = await run([1, 2, 3, 4, 5, 6].map(i => call(i, 'ok')), { spawn: spy })
    expect(errs(r)).toEqual(Array(6).fill('error'))
    expect(spy).not.toHaveBeenCalled()
  })
})

describe('GB2: token residue', () => {
  it('a prompt or system carrying the dashboard / oauth token -> secret_residue, ask() never called, value nowhere in the output', async () => {
    const warn = vi.spyOn(logger, 'warn')
    const debug = vi.spyOn(logger, 'debug')
    const calls = [
      call(1, 'ok', { prompt: `SCN:ok\nthe token is ${DASH_TOKEN} ok` }),
      call(2, 'ok', { system: `x${OAUTH_TOKEN}x` }),
      call(3, 'ok'),
    ]
    expect(errs(await run(calls))).toEqual(['secret_residue', 'secret_residue', 'ok'])
    expect(callsLog()).toHaveLength(1)
    const logged = JSON.stringify([...warn.mock.calls, ...debug.mock.calls])
    expect(logged).not.toContain(DASH_TOKEN)
    expect(logged).not.toContain(OAUTH_TOKEN)
    // Direct run: the raw stdout and stderr of the child.
    const req = JSON.stringify({ v: 1, caller: 'memoria-iras-kapu', timeout_s: 30, calls })
    const out = spawnSync(GATE_PYTHON, ['-I', DEFAULT_ADAPTER, '--batch-dir', batchDir, '--store-dir', storeDir],
      { input: req, env: gateChildEnv(), encoding: 'utf8' })
    for (const t of [DASH_TOKEN, OAUTH_TOKEN]) {
      expect(out.stdout).not.toContain(t)
      expect(out.stderr).not.toContain(t)
    }
    expect(out.stderr).toBe('')
  })

  it('missing oauth file: that check is skipped; unreadable token file -> residue_check_unavailable', async () => {
    rmSync(join(storeDir, '.claude-oauth-token'))
    expect(errs(await run([call(1, 'ok', { system: `x${OAUTH_TOKEN}` })]))).toEqual(['ok'])
    rmSync(join(storeDir, '.dashboard-token'))
    expect(errs(await run([call(2, 'ok')]))).toEqual(['residue_check_unavailable'])
    copyFileSync(join(FIX, 'fake-store', '.dashboard-token'), join(storeDir, '.dashboard-token'))
    copyFileSync(join(FIX, 'fake-store', '.claude-oauth-token'), join(storeDir, '.claude-oauth-token'))
    chmodSync(join(storeDir, '.claude-oauth-token'), 0o000)
    expect(errs(await run([call(3, 'ok')]))).toEqual(['residue_check_unavailable'])
    expect(callsLog().map(c => c.scn)).toEqual(['ok'])
  })
})

describe('parent side: deadline, stdout cap, vitest guard, parsing', () => {
  it('deadline: SIGKILL mid-call -> maybe_billed, the child is gone (no zombie, no orphan)', async () => {
    let child: ChildProcess | null = null
    const spy: SpawnFn = (cmd, args, opts) => { child = spawn(cmd, args as string[], opts); return child }
    const t0 = Date.now()
    const r = await run([call(1, 'sleep')], { spawn: spy, callTimeoutS: 1, graceS: 0 })
    expect(errs(r)).toEqual(['maybe_billed'])
    expect(Date.now() - t0).toBeLessThan(10_000)
    const pid = (child as unknown as ChildProcess).pid!
    expect(() => process.kill(pid, 0)).toThrow()
  })

  it('stdout above 256 KB -> error', async () => {
    const big: SpawnFn = (_cmd, _args, opts) =>
      spawn(process.execPath, ['-e', 'process.stdout.write("x".repeat(300000)); setTimeout(()=>{}, 5000)'], { ...opts, env: { PATH: '/usr/bin:/bin' } })
    expect(errs(await run([call(1, 'ok')], { spawn: big }))).toEqual(['error'])
  })

  it('vitest guard: a batch dir outside os.tmpdir() is refused before any spawn', async () => {
    const spy = vi.fn() as unknown as SpawnFn
    const real = await runGateCalls([call(1, 'ok')], { batchDir: process.cwd(), storeDir, spawn: spy })
    expect(errs(real)).toEqual(['untrusted_batch_dir'])
    const realStore = await runGateCalls([call(1, 'ok')], { batchDir, storeDir: process.cwd(), spawn: spy })
    expect(errs(realStore)).toEqual(['untrusted_batch_dir'])
    expect(spy).not.toHaveBeenCalled()
  })

  it('parser: unknown k, unknown class, oversize text, missing answers', () => {
    const calls = [call(1, 'x'), call(2, 'x'), call(3, 'x'), call(4, 'x')]
    const raw = JSON.stringify({ v: 1, results: [
      { k: '1', ok: false, error: 'pwned' },
      { k: '2', ok: true, text: 'y'.repeat(5000) },
      { k: '3', ok: true, text: 'fine' },
      { k: '3', ok: false, error: 'auth' },
      { k: '99', ok: true, text: 'stray' },
    ] })
    expect(errs(parseAdapterOutput(raw, calls))).toEqual(['error', 'error', 'ok', 'maybe_billed'])
    expect(errs(parseAdapterOutput('not json', calls))).toEqual(Array(4).fill('maybe_billed'))
  })
})
