import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import net from 'node:net'
import http from 'node:http'
import { EventEmitter } from 'node:events'
import { spawn, spawnSync } from 'node:child_process'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// Credit gate, node N4b (card fec6335f): the runs endpoints of the HTTP API
// (blueprint 4.2) and the hand-over between the route, the N4a runner and the
// N2c canary (spec E-04, E-05, K-01..K-03; blueprint 4.3, N4b, 8, 11.6). The
// test list is the blueprint's N4b list plus the coordinator's N4b brief
// (2026-10-16), written from those, not from the code:
//  - who: the caller must be on headless.allowedCallers; X-Agent-Id is a label
//    (one shared Bearer token), so this only stops accidental use;
//  - what: the budget a two-decimal string at most the maximum, the effort
//    high/xhigh, the cwd by N4a's validateCwd, the prompt at most 256 KB;
//  - normal mode: only enforce + OPEN + the hash the newest evaluated canary
//    approved (approvedCanary), else 409 with the exact reason;
//  - canary mode: only with the owner's credit_gate_canary approval consumed
//    by consumeCanaryApproval for a run id the route takes from the runner
//    first, a budget below 1.00, the hash taken from the consumed approval's
//    row once, for that run only (takeCanaryHash), never from the request
//    (coordinator, 2026-10-16: the N2c round's API); K-01: the batch path is on the gate's
//    STOP for the canary's duration (a batch reservation gets 409
//    canary_in_progress), and after its run until its after-reading is
//    recorded (N7B1: 409 canary_window_open), released only then;
//  - cancel kills the run and the reservation is settled by B-04;
//  - the CLI (scripts/credit-run.py): exit 3 on a closed gate, 0 on a finished
//    run -- against this route over a loopback socket -- and its own suite
//    against a stub server.
//
// Everything is in-process on a tmp store and a tmp SQLite file (db.ts's own
// connection, where the approvals are). The child is fake-claude.mjs behind a
// tmp launcher: no real CLI, no real key, no Vault, no live dashboard or store.
// A process-level guard refuses every non-loopback connect() and the live CDP
// ports (18800, 18899) BEFORE the connect, self-tested against this file's own
// blocked port 18994; the Python child installs its own (credit-run.test.py).

const BLOCKED_PORTS = new Set([18800, 18899, 18994])
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const origConnect = net.Socket.prototype.connect
const origFetch = globalThis.fetch

function guardTarget(args: unknown[]): { host: string; port: number } | null {
  const first = Array.isArray(args[0]) ? (args[0] as unknown[])[0] : args[0]
  if (typeof first === 'object' && first !== null) {
    const o = first as { host?: unknown; port?: unknown; path?: unknown }
    if (typeof o.path === 'string') return { host: 'unix', port: 0 }
    const port = Number(o.port)
    if (o.host !== undefined && typeof o.host !== 'string') return null
    return Number.isInteger(port) ? { host: (o.host as string | undefined) ?? 'localhost', port } : null
  }
  const port = Number(first)
  if (!Number.isInteger(port)) return null
  return { host: typeof args[1] === 'string' ? args[1] : 'localhost', port }
}

beforeAll(() => {
  net.Socket.prototype.connect = function guarded(this: net.Socket, ...args: unknown[]) {
    const t = guardTarget(args)
    if (t === null || (t.host !== 'unix' && (!LOOPBACK.has(t.host) || BLOCKED_PORTS.has(t.port)))) {
      throw new Error(`credit-gate test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  globalThis.fetch = (() => { throw new Error('credit-gate test guard: fetch is not allowed') }) as typeof fetch
})

afterAll(() => {
  net.Socket.prototype.connect = origConnect
  globalThis.fetch = origFetch
})

import {
  initDatabase, getDb, getApproval, createApproval, setApprovalCallbackNonceHashes, setApprovalTelegramMessageId,
  resolveApprovalFromTelegram, resolveApproval,
} from '../db.js'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { CreditGate } from '../web/credit-gate/gate.js'
import { readCreditGateMode, loadCreditGateConfigFile, parseCreditGateConfig } from '../web/credit-gate/config.js'
import { parseCreditGatePayload, type CreditGatePayload } from '../web/credit-gate/approval-payload.js'
import { buildCreditGateApprovalText } from '../web/approval-telegram-text.js'
import { fileGateDeps, setCreditGateRuntime, type CreditGateRuntime } from '../web/credit-gate/runtime.js'
import { calibrationSource, CalibrationProcessor, takeCanaryHash } from '../web/credit-gate/calibration.js'
import { getHeadlessRunner, startHeadlessRuntime, type HeadlessRuntimeHandle } from '../web/credit-gate/headless/reconcile.js'
import { MAX_PROMPT_BYTES, type HeadlessRunner, type Spawner } from '../web/credit-gate/headless/runner.js'
import { tryHandleCreditGate } from '../web/routes/credit-gate.js'
import type { RouteContext } from '../web/routes/types.js'
import { configObject, Harness, HOUR, pricingText, simpleCal, T0 } from './fixtures/credit-gate/gate-harness.js'
import { alive, FAKE_CLAUDE, until } from './fixtures/credit-gate/headless-harness.js'

const ROOT = resolve(__dirname, '..', '..')
const CLI = join(ROOT, 'scripts', 'credit-run.py')
const CLI_SUITE = join(ROOT, 'scripts', '__tests__', 'credit-run.test.py')
const OWNER = '1000000001'

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    expect(() => net.connect({ host: '127.0.0.1', port: 18994 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
    expect(() => net.connect(443, 'example.com')).toThrow(/refused/)
    expect(() => new net.Socket().connect(18994, '::1')).toThrow(/refused/)
    expect(() => fetch('https://example.com')).toThrow(/not allowed/)
  })
})

// --- approvals the way the owner's Telegram button decides them ------------------------------

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

/** Python json.dumps(sort_keys=True, separators=(",", ":")) for these ASCII values. */
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

const stamp = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

function calPayload(lbMs: number, p2Remaining: string): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_calibration',
    captured_at_lb: stamp(lbMs),
    grants: [{ granted: '2026-10-14', expires: '2026-11-17', original_usd: '200.00', remaining_usd: p2Remaining }],
    protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.00' } },
    screenshot: '/Volumes/8T/00 CLOUD/console/n4b-test.png',
  }
}

let msgSeq = 7000

function requestApproval(category: string, payload: Record<string, unknown>): string {
  const text = canon(payload)
  const id = randomUUID()
  createApproval({
    id, agent_id: 'brainy', category, action_description: 'n4b test', action_payload: text,
    timeout_at: Math.floor(Date.now() / 1000) + 3600, content_hash: sha(text),
  })
  return id
}

function ownerApproved(category: string, payload: Record<string, unknown>): string {
  const id = requestApproval(category, payload)
  const yes = sha(randomBytes(16).toString('hex'))
  const no = sha(randomBytes(16).toString('hex'))
  expect(setApprovalCallbackNonceHashes(id, { approved: yes, rejected: no })).toBe(true)
  const mid = msgSeq++
  expect(setApprovalTelegramMessageId(id, mid)).toBe(true)
  expect(resolveApprovalFromTelegram({ id, status: 'approved', ownerId: OWNER, messageId: mid, nonceHash: yes }).ok).toBe(true)
  return id
}

// --- the harness: a tmp install with db.ts's database, the gate, N2c, N4a ---------------------

interface RunsOptions {
  readonly mode?: string
  readonly runner?: NonNullable<NonNullable<Parameters<typeof startHeadlessRuntime>[0]>['runnerDeps']>
}

class RH {
  readonly real: string
  readonly storeDir: string
  readonly gateDir: string
  readonly usagePath: string
  readonly stopPath: string
  readonly wtRoot: string
  readonly worktree: string
  readonly runsDir: string
  readonly installRoot: string
  readonly bin: string
  readonly binSha: string
  readonly key: string
  readonly gate: CreditGate
  readonly proc: CalibrationProcessor
  readonly rt: CreditGateRuntime
  readonly handle: HeadlessRuntimeHandle | undefined
  readonly spawnCalls: string[] = []
  now = T0
  /** E-05: the Vault has no key while set. */
  keyMissing = false
  private obsN = 0

  constructor(o: RunsOptions = {}) {
    this.real = realpathSync(mkdtempSync(join(tmpdir(), 'credit-runs-')))
    this.storeDir = join(this.real, 'store')
    this.gateDir = join(this.storeDir, 'credit-gate')
    mkdirSync(this.gateDir, { recursive: true, mode: 0o700 })
    chmodSync(this.storeDir, 0o700)
    chmodSync(this.gateDir, 0o700)
    this.usagePath = join(this.real, 'usage.jsonl')
    writeFileSync(this.usagePath, '')
    mkdirSync(join(this.real, 'batch'))
    this.stopPath = join(this.real, 'batch', 'STOP')
    this.wtRoot = join(this.real, 'wt')
    this.worktree = join(this.wtRoot, 'proj')
    mkdirSync(this.worktree, { recursive: true })
    writeFileSync(join(this.worktree, '.git'), 'gitdir: /nowhere/.git/worktrees/proj\n')
    this.runsDir = join(this.real, 'runs')
    this.installRoot = join(this.real, 'install')
    mkdirSync(join(this.installRoot, 'store'), { recursive: true })
    writeFileSync(join(this.installRoot, '.git'), 'gitdir: /nowhere\n')
    mkdirSync(join(this.real, 'bin'))
    this.bin = join(this.real, 'bin', 'claude-fake.mjs')
    writeFileSync(this.bin, `#!${process.execPath}\nimport ${JSON.stringify(FAKE_CLAUDE)}\n`)
    chmodSync(this.bin, 0o755)
    this.binSha = createHash('sha256').update(readFileSync(this.bin)).digest('hex')
    this.key = `sk-ant-TEST-DUMMY-${randomBytes(16).toString('hex')}`
    this.writeConfig()
    const pricing = join(this.gateDir, 'pricing.json')
    writeFileSync(pricing, pricingText('2026-10-16'), { mode: 0o600 })
    chmodSync(pricing, 0o600)

    initDatabase(join(this.real, 'claudeclaw.db'))
    const db = getDb()
    applyCreditGateSchema(db)
    const mode = readCreditGateMode(o.mode ?? 'enforce')
    const configPath = join(this.gateDir, 'config.json')
    this.gate = new CreditGate(fileGateDeps({ storeDir: this.storeDir, db, mode, calibration: calibrationSource(db), now: () => this.now }))
    this.proc = new CalibrationProcessor({ db, gate: this.gate, loadConfig: () => loadCreditGateConfigFile(configPath), ownerId: () => OWNER, now: () => this.now })
    this.rt = { mode, gate: this.gate, storeDir: this.storeDir, db, startError: null, calibrations: this.proc }
    setCreditGateRuntime(this.rt)
    const spawner: Spawner = (file, args, options) => {
      if (!file.startsWith(this.real + '/')) throw new Error(`test spawner: refusing ${file}`)
      this.spawnCalls.push(file)
      return spawn(file, args, options)
    }
    this.handle = startHeadlessRuntime({
      runtime: this.rt,
      getKey: () => (this.keyMissing ? null : this.key),
      installRoot: this.installRoot,
      listProcesses: () => [],
      kill: (pid, sig) => { process.kill(pid, sig) },
      runnerDeps: {
        spawner,
        now: () => this.now,
        procStart: (pid) => (alive(pid) ? 'runs-start' : null),
        killGraceMs: 300,
        pollMs: 50,
        installSignalHandlers: false,
        ...o.runner,
      },
    })
  }

  get runner(): HeadlessRunner {
    const r = getHeadlessRunner()
    if (r === null) throw new Error('no headless runner')
    return r
  }

  writeConfig(headless: Record<string, unknown> = {}): void {
    const p = join(this.gateDir, 'config.json')
    writeFileSync(p, JSON.stringify(configObject(this.usagePath, this.stopPath, {
      headless: {
        allowedCallers: ['ezermester'], cwdRoots: [this.wtRoot], forbiddenCwds: [this.installRoot],
        runsDir: this.runsDir, claudeBin: this.bin, claudeBinSha256: this.binSha,
        models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'], maxBudgetUsd: '5.00', wallClockMin: 90, ...headless,
      },
    })), { mode: 0o600 })
    chmodSync(p, 0o600)
  }

  /** What the runtime does every refreshS: tick, process the approvals, tick. */
  cycle(): { state: string; reason: string } {
    this.gate.tick(this.now)
    this.proc.process(this.now)
    this.gate.tick(this.now)
    return this.state()
  }

  state(): { state: string; reason: string } {
    return getDb().prepare('SELECT state, reason FROM credit_gate_state WHERE id = 1').get() as { state: string; reason: string }
  }

  /** An owner-approved reading, processed: returns its approval id. */
  calibrate(lbMs: number, p2Remaining: string): string {
    const id = ownerApproved('credit_gate_calibration', calPayload(lbMs, p2Remaining))
    this.cycle()
    return id
  }

  /** The gate OPEN on a first reading (P2 200.00, read two hours ago). */
  open(): string {
    const id = this.calibrate(this.now - 2 * HOUR, '200.00')
    expect(this.state().state).toBe('OPEN')
    return id
  }

  /** The owner's canary approval for exactly this prompt, node N9x and the worktree (BE-4b P6). */
  canaryApproval(before: string, prompt: string, over: Record<string, unknown> = {}): string {
    return ownerApproved('credit_gate_canary', this.canaryPayload(before, prompt, over))
  }

  canaryPayload(before: string, prompt: string, over: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      v: 1, kind: 'credit_gate_canary', config_hash: this.runner.configHash(), model: 'claude-sonnet-5-5',
      budget_usd: '0.90', min_expected_usd: '0.10', before_calibration_id: before,
      node: 'N9x', cwd: this.worktree, prompt_sha256: sha(prompt), ...over,
    }
  }

  /** N2c's verdict row for a successful canary of `hash` (what approvedCanary reads). */
  approveHash(hash: string): void {
    getDb().prepare(`INSERT INTO credit_canaries (approval_id, config_hash, model, budget_micro, min_expected_micro,
        before_calibration_id, run_id, status, consumed_at, evaluated_at)
      VALUES (?, ?, 'claude-sonnet-5-5', 900000, 100000, ?, 'hr-earlier', 'success', ?, ?)`)
      .run(randomUUID(), hash, 900_000 + this.obsN++, this.now, this.now)
  }

  prompt(mode: string, extra: Record<string, unknown> = {}): { prompt: string; observe: string } {
    const observe = join(this.real, `obs-${++this.obsN}.json`)
    return { prompt: `FAKE ${JSON.stringify({ mode, observe, ...extra })}\nDo the node.\n`, observe }
  }

  body(prompt: string, over: Record<string, unknown> = {}): Record<string, unknown> {
    return { node_id: 'N9x', model: 'claude-sonnet-5-5', effort: 'high', budget_usd: '0.40', cwd: this.worktree, prompt, mode: 'normal', ...over }
  }

  reservations(): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_reservations ORDER BY created_at, id').all() as Array<Record<string, unknown>>
  }

  canary(approvalId: string): Record<string, unknown> | undefined {
    return getDb().prepare('SELECT * FROM credit_canaries WHERE approval_id = ?').get(approvalId) as Record<string, unknown> | undefined
  }

  runRow(id: string): Record<string, unknown> {
    return getDb().prepare('SELECT * FROM credit_headless_runs WHERE id = ?').get(id) as Record<string, unknown>
  }

  ledgerRow(runId: string): Record<string, unknown> | undefined {
    return getDb().prepare('SELECT * FROM credit_ledger_entries WHERE run_id = ?').get(runId) as Record<string, unknown> | undefined
  }

  stopOwner(): string | null {
    if (!existsSync(this.stopPath)) return null
    return readFileSync(this.stopPath, 'utf8').startsWith('credit-gate v1 ') ? 'gate' : 'other'
  }

  async done(runId: string): Promise<void> {
    const r = this.runner
    if (r.activeIds().includes(runId)) await r.whenDone(runId)
  }

  cleanup(): void {
    this.handle?.stop()
    setCreditGateRuntime(null)
    rmSync(this.real, { recursive: true, force: true })
  }
}

// --- the route, in-process -------------------------------------------------------------------

interface Out { status: number; body: any }

type Auth = RouteContext['auth']
const AS_EZERMESTER: Auth = { kind: 'token', agent: 'ezermester' }

async function request(method: string, path: string, body?: unknown, o: { auth?: Auth; raw?: string } = {}): Promise<Out> {
  const out: Out = { status: 0, body: null }
  let resolveDone!: () => void
  const done = new Promise<void>((r) => { resolveDone = r })
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { /* unused */ },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk); resolveDone() },
  }
  const req: any = new EventEmitter()
  req.headers = {}
  req.destroy = () => { /* noop */ }
  const payload = o.raw ?? (body === undefined ? '' : JSON.stringify(body))
  setImmediate(() => {
    if (payload) req.emit('data', Buffer.from(payload))
    req.emit('end')
  })
  const ctx = { req, res, path, method, url: new URL(`http://localhost:3420${path}`), auth: 'auth' in o ? o.auth : AS_EZERMESTER } as RouteContext
  expect(await tryHandleCreditGate(ctx)).toBe(true)
  await done
  return out
}

const startRun = (b: Record<string, unknown>, o: { auth?: Auth } = {}) => request('POST', '/api/credit-gate/runs', b, o)

const BATCH = {
  kind: 'batch', model: 'claude-haiku-5-5', input_tokens_total: 1000, max_output_tokens_total: 0, request_count: 1, caller: 'rag-gold-label',
}

let rh: RH | undefined
afterEach(() => {
  rh?.cleanup()
  rh = undefined
})

// =====================================================================================
// Who and what
// =====================================================================================

describe('POST /runs: who may ask, and what (blueprint 4.2, N4b; 11.6)', () => {
  it('a caller not on allowedCallers -> 409 caller_not_allowed; no label, a session or a device -> 409 too; nothing reserved or spawned', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success')
    for (const auth of [{ kind: 'token', agent: 'fejleszto' }, { kind: 'token' }, { kind: 'session', user: 'gyuri' }, { kind: 'device', device: 'phone' }, undefined] as Auth[]) {
      expect(await startRun(rh.body(prompt), { auth })).toMatchObject({ status: 409, body: { reason: 'caller_not_allowed' } })
    }
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })

  it('the budget: "5", "-1.00", "0.00", "1e2", " 1.00", a number, or above the maximum -> 400; nothing reserved', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success')
    for (const budget of ['5', '-1.00', '0.00', '1e2', ' 1.00', '1.000', 5, null, '5.01', '99.00']) {
      const out = await startRun(rh.body(prompt, { budget_usd: budget }))
      expect(out.status, `budget ${JSON.stringify(budget)}`).toBe(400)
    }
    expect((await startRun(rh.body(prompt, { budget_usd: '5.01' }))).body).toMatchObject({ reason: 'budget_over_max' })
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })

  it('model, effort, mode, node id, prompt (empty, NUL, above 256 KB), unknown fields, bad JSON -> 400; a body above the cap -> 413', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success')
    const bad: Array<[Record<string, unknown>, string]> = [
      [{ model: 'claude-haiku-5-5' }, 'model_not_allowed'],
      [{ model: 'claude-sonnet-5-5[1m]' }, ''],
      [{ effort: 'medium' }, ''],
      [{ effort: 'max' }, ''],
      [{ mode: 'turbo' }, ''],
      [{ node_id: 'N 1' }, ''],
      [{ node_id: '' }, ''],
      [{ prompt: '' }, ''],
      [{ prompt: 'a\u0000b' }, ''],
      [{ prompt: 'x'.repeat(MAX_PROMPT_BYTES + 1) }, ''],
      [{ prompt: 'é'.repeat(MAX_PROMPT_BYTES / 2 + 1) }, ''],
      [{ extra: 1 }, ''],
      [{ canary_approval_id: 'abc' }, ''],
    ]
    for (const [over, reason] of bad) {
      const out = await startRun(rh.body(prompt, over))
      expect(out.status, JSON.stringify(over).slice(0, 80)).toBe(400)
      if (reason) expect(out.body.reason).toBe(reason)
    }
    expect((await startRun(rh.body('x'.repeat(MAX_PROMPT_BYTES)))).status).not.toBe(400)
    await rh.done(rh.reservations()[0]?.ref as string)
    const missing = rh.body(prompt) as Record<string, unknown>
    delete missing.cwd
    expect((await startRun(missing)).status).toBe(400)
    expect((await request('POST', '/api/credit-gate/runs', undefined, { raw: '{"node_id":' })).status).toBe(400)
    expect((await request('POST', '/api/credit-gate/runs', undefined, { raw: '[1]' })).status).toBe(400)
    expect((await request('POST', '/api/credit-gate/runs', undefined, { raw: JSON.stringify(rh.body('y'.repeat(3 * 1024 * 1024))) })).status).toBe(413)
  })

  it('the cwd by validateCwd: relative, "..", outside the roots, the install root, a clone, a symlink -> 400 with the reason', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success')
    const clone = join(rh.wtRoot, 'clone')
    mkdirSync(join(clone, '.git'), { recursive: true })
    const link = join(rh.wtRoot, 'link')
    symlinkSync(rh.worktree, link)
    const cases: Array<[unknown, string]> = [
      ['wt/proj', 'cwd_invalid'],
      [`${rh.worktree}/../proj`, 'cwd_not_canonical'],
      [rh.real, 'cwd_forbidden'],
      [rh.installRoot, 'cwd_forbidden'],
      [clone, 'cwd_not_linked_worktree'],
      [link, 'cwd_not_canonical'],
      [42, ''],
    ]
    for (const [cwd, reason] of cases) {
      const out = await startRun(rh.body(prompt, { cwd }))
      expect(out.status, String(cwd)).toBe(400)
      if (reason) expect(out.body.reason).toBe(reason)
    }
    expect(rh.reservations()).toHaveLength(0)
  })

  it('a hash in the request is never used: config_hash -> 409 hash_not_approved, in both modes; nothing consumed or reserved', async () => {
    rh = new RH()
    const before = rh.open()
    const hash = rh.runner.configHash() as string
    const { prompt } = rh.prompt('success')
    const k = rh.canaryApproval(before, prompt)
    expect(await startRun(rh.body(prompt, { config_hash: hash }))).toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    expect(await startRun(rh.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k, config_hash: hash })))
      .toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })
})

// =====================================================================================
// Normal mode
// =====================================================================================

describe('normal mode: enforce + OPEN + the hash a canary approved (E-04, E-05)', () => {
  it('off -> 409 gate_off; shadow -> 409 gate_shadow; enforce without a headless runtime -> runs_unavailable', async () => {
    setCreditGateRuntime(null)
    const b = { node_id: 'N1', model: 'claude-sonnet-5-5', effort: 'high', budget_usd: '0.40', cwd: '/x', prompt: 'p', mode: 'normal' }
    expect(await startRun(b)).toMatchObject({ status: 409, body: { reason: 'gate_off' } })
    expect(await request('GET', '/api/credit-gate/runs/hr-x')).toMatchObject({ status: 409, body: { reason: 'gate_off' } })
    rh = new RH({ mode: 'shadow' })
    expect(await startRun(rh.body('p'))).toMatchObject({ status: 409, body: { reason: 'gate_shadow' } })
    rh.cleanup()
    rh = new RH()
    rh.handle?.stop()
    expect(getHeadlessRunner()).toBeNull()
    expect(await startRun(rh.body('p'))).toMatchObject({ status: 409, body: { reason: 'runs_unavailable' } })
  })

  it('no canary-approved hash -> 409 hash_not_approved; another hash -> 409; this hash -> 202, the run succeeds and is booked once', async () => {
    rh = new RH()
    rh.open()
    const { prompt, observe } = rh.prompt('success')
    expect(await startRun(rh.body(prompt))).toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    rh.approveHash('f'.repeat(64))
    expect(await startRun(rh.body(prompt))).toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    expect(rh.reservations()).toHaveLength(0)
    rh.approveHash(rh.runner.configHash() as string)
    const out = await startRun(rh.body(prompt))
    expect(out).toMatchObject({ status: 202, body: { mode: 'normal' } })
    const runId = out.body.run_id as string
    await rh.done(runId)
    expect(existsSync(observe)).toBe(true)
    expect(rh.runRow(runId)).toMatchObject({ status: 'succeeded', caller: 'ezermester', mode: 'normal', node_id: 'N9x' })
    expect(rh.reservations()).toMatchObject([{ kind: 'headless', status: 'settled', ref: runId }])
    expect(rh.ledgerRow(runId)).toMatchObject({ basis: 'headless_json' })
  })

  it('E-05: no key -> 409 key_missing, in both modes; a canary approval is not spent on it', async () => {
    rh = new RH()
    const before = rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success')
    const k = rh.canaryApproval(before, prompt)
    rh.keyMissing = true
    expect(await startRun(rh.body(prompt))).toMatchObject({ status: 409, body: { reason: 'key_missing' } })
    expect(await startRun(rh.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k })))
      .toMatchObject({ status: 409, body: { reason: 'key_missing' } })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })

  it('a closed gate -> 409 gate_closed with the gate\'s reason; nothing reserved or spawned', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    rh.gate.signal('disarm', 'test', null, rh.now)
    const { prompt } = rh.prompt('success')
    expect(await startRun(rh.body(prompt))).toMatchObject({ status: 409, body: { reason: 'gate_closed', detail: 'disarm' } })
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })

  it('GET /runs/:id: the state and the result -- usage, cli_usd, est_usd, is_error, num_turns, the exit code; never the key or the prompt', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt } = rh.prompt('success', { result: { result: 'done; the key was {KEY}' } })
    const runId = (await startRun(rh.body(prompt))).body.run_id as string
    await rh.done(runId)
    const out = await request('GET', `/api/credit-gate/runs/${runId}`)
    // The answer quoted the key: N4a marks the run secret_residue and filters the stored text.
    expect(out).toMatchObject({
      status: 200,
      body: {
        run_id: runId, node_id: 'N9x', model: 'claude-sonnet-5-5', effort: 'high', mode: 'normal', status: 'secret_residue', done: true,
        exit_code: 0, budget_usd: '0.40', cli_usd: '0.074983', is_error: false, num_turns: 3, basis: 'headless_json',
        usage: { input_tokens: 8, output_tokens: 647 },
      },
    })
    expect(typeof out.body.est_usd).toBe('string')
    expect(out.body.result_text).toContain('done; the key was')
    const text = JSON.stringify(out.body)
    expect(text).not.toContain(rh.key)
    expect(text).not.toContain(rh.key.slice(-20))
    expect(text).not.toContain('Do the node.')
    expect(await request('GET', '/api/credit-gate/runs/hr-nope')).toMatchObject({ status: 404 })
    expect(await request('GET', '/api/credit-gate/runs/..%2F..')).toMatchObject({ status: 404 })
    expect(await request('GET', `/api/credit-gate/runs/${runId}`, undefined, { auth: { kind: 'token', agent: 'fejleszto' } }))
      .toMatchObject({ status: 409, body: { reason: 'caller_not_allowed' } })
    expect(await request('POST', `/api/credit-gate/runs/${runId}`)).toMatchObject({ status: 405 })
  })

  it('cancel kills the run (and its group); the reservation is settled by B-04 -- the whole reservation without a JSON result', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const { prompt, observe } = rh.prompt('hang')
    const runId = (await startRun(rh.body(prompt))).body.run_id as string
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    const seen = JSON.parse(readFileSync(observe, 'utf8')) as { pid: number; grandchild: number }
    expect((await request('GET', `/api/credit-gate/runs/${runId}`)).body).toMatchObject({ status: 'running', done: false })
    expect(await request('POST', `/api/credit-gate/runs/${runId}/cancel`, undefined, { auth: { kind: 'token', agent: 'fejleszto' } }))
      .toMatchObject({ status: 409, body: { reason: 'caller_not_allowed' } })
    expect(alive(seen.pid)).toBe(true)
    expect(await request('POST', `/api/credit-gate/runs/${runId}/cancel`)).toMatchObject({ status: 202, body: { run_id: runId, cancelling: true } })
    await rh.done(runId)
    await until(() => !alive(seen.pid) && !alive(seen.grandchild), 5_000, 'the group to die')
    expect((await request('GET', `/api/credit-gate/runs/${runId}`)).body).toMatchObject({ status: 'cancelled', done: true, basis: 'headless_reservation', est_usd: '0.60' })
    expect(rh.reservations()).toMatchObject([{ kind: 'headless', status: 'settled', amount_micro: 600_000 }])
    expect(rh.ledgerRow(runId)).toMatchObject({ basis: 'headless_reservation', est_micro: 600_000 })
    expect(await request('POST', `/api/credit-gate/runs/${runId}/cancel`)).toMatchObject({ status: 409, body: { reason: 'not_running', status: 'cancelled' } })
    expect(await request('POST', '/api/credit-gate/runs/hr-nope/cancel')).toMatchObject({ status: 404 })
  })
})

// =====================================================================================
// Canary mode
// =====================================================================================

describe('canary mode: the owner\'s approval, consumed once, the hash from its row (K-01..K-03)', () => {
  it('no approval id -> 409; a budget of 1.00 or more -> 409; a bad cwd -> 400; a closed gate -> 409 -- the approval is not spent', async () => {
    rh = new RH()
    const before = rh.open()
    const { prompt } = rh.prompt('success')
    const k = rh.canaryApproval(before, prompt)
    const canary = (over: Record<string, unknown> = {}) => rh!.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k, ...over })
    const noId = canary()
    delete noId.canary_approval_id
    expect(await startRun(noId)).toMatchObject({ status: 409, body: { reason: 'canary_approval_missing' } })
    expect(await startRun(canary({ budget_usd: '1.00' }))).toMatchObject({ status: 409, body: { reason: 'budget_over_canary' } })
    expect(await startRun(canary({ budget_usd: '1.50' }))).toMatchObject({ status: 409, body: { reason: 'budget_over_canary' } })
    expect(await startRun(canary({ cwd: rh.installRoot }))).toMatchObject({ status: 400, body: { reason: 'cwd_forbidden' } })
    expect(await startRun(canary({ model: 'claude-opus-5-5' }))).toMatchObject({ status: 409, body: { reason: 'canary_terms_mismatch' } })
    // The run's budget may not exceed the approved one.
    const small = rh.canaryApproval(before, prompt, { budget_usd: '0.50' })
    expect(await startRun(canary({ canary_approval_id: small }))).toMatchObject({ status: 409, body: { reason: 'canary_terms_mismatch' } })
    expect(getApproval(small)!.consumed_at).toBeNull()
    rh.gate.signal('disarm', 'test', null, rh.now)
    expect(await startRun(canary())).toMatchObject({ status: 409, body: { reason: 'gate_closed' } })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(rh.canary(k)).toBeUndefined()
    expect(rh.reservations()).toHaveLength(0)
    expect(rh.spawnCalls).toHaveLength(0)
  })

  it('a legacy-PATCH approval, an approval for another hash, an unknown id, a used approval -> 409', async () => {
    rh = new RH()
    const before = rh.open()
    const { prompt } = rh.prompt('success')
    const canary = (id: string) => rh!.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: id })
    const legacy = requestApproval('credit_gate_canary', rh.canaryPayload(before, prompt))
    resolveApproval(legacy, 'approved', 'dashboard')
    expect(await startRun(canary(legacy))).toMatchObject({ status: 409, body: { reason: 'canary_not_owner_verified' } })
    const other = rh.canaryApproval(before, prompt, { config_hash: 'e'.repeat(64), budget_usd: '0.80' })
    expect(await startRun(canary(other))).toMatchObject({ status: 409, body: { reason: 'canary_hash_mismatch' } })
    expect(getApproval(other)!.consumed_at).toBeNull()
    expect(await startRun(canary('no-such-approval'))).toMatchObject({ status: 409, body: { reason: 'canary_not_found' } })
    expect(rh.spawnCalls).toHaveLength(0)

    const k = rh.canaryApproval(before, prompt)
    const out = await startRun(canary(k))
    expect(out).toMatchObject({ status: 202, body: { mode: 'canary' } })
    const runId = out.body.run_id as string
    // The approval was consumed for this run, and its hash was taken once, for it.
    expect(rh.canary(k)).toMatchObject({ status: 'consumed', run_id: runId, config_hash: rh.runner.configHash() })
    expect(rh.canary(k)!.hash_taken_at).not.toBeNull()
    expect(takeCanaryHash(getDb(), k, runId)).toBeNull()
    expect(rh.runRow(runId)).toMatchObject({ mode: 'canary', config_hash: rh.runner.configHash() })
    expect(rh.reservations()).toMatchObject([{ kind: 'canary', ref: runId }])
    await rh.done(runId)
    // N7B1: until the after-reading is recorded the canary window refuses it first.
    expect(await startRun(canary(k))).toMatchObject({ status: 409, body: { reason: 'canary_window_open' } })
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '199.89')
    expect(rh.canary(k)).toMatchObject({ status: 'success' })
    expect(await startRun(canary(k))).toMatchObject({ status: 409, body: { reason: 'canary_already_consumed' } })
    expect(rh.spawnCalls).toHaveLength(1)
  })

  it('the runner hands a canary hash only to the run id the approval was consumed for, and only ids it allocated, once', async () => {
    rh = new RH()
    const before = rh.open()
    const { prompt } = rh.prompt('success')
    const k = rh.canaryApproval(before, prompt)
    const req = { node_id: 'N9x', model: 'claude-sonnet-5-5', effort: 'high', budget_usd: '0.90', cwd: rh.worktree, prompt, mode: 'canary' as const }
    const hash = rh.runner.configHash() as string
    const a = rh.runner.allocateRunId()
    const b = rh.runner.allocateRunId()
    expect(rh.proc.consumeCanaryApproval(k, hash, { model: 'claude-sonnet-5-5', budget_micro: 900_000, runId: a, node: 'N9x', cwd: rh.worktree, prompt_sha256: sha(prompt) }))
      .toMatchObject({ ok: true })
    expect(rh.runner.start(req, { caller: 'ezermester', canaryApprovalId: k, runId: 'hr-forged' })).toMatchObject({ ok: false, reason: 'run_id_unknown' })
    expect(rh.runner.start(req, { caller: 'ezermester', canaryApprovalId: k })).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(rh.runner.start(req, { caller: 'ezermester', canaryApprovalId: k, runId: b })).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(rh.canary(k)!.hash_taken_at).toBeNull()
    const ok = rh.runner.start(req, { caller: 'ezermester', canaryApprovalId: k, runId: a })
    expect(ok).toMatchObject({ ok: true, run_id: a })
    await rh.done(a)
    expect(rh.runner.start(req, { caller: 'ezermester', canaryApprovalId: k, runId: a })).toMatchObject({ ok: false, reason: 'run_id_unknown' })
    expect(rh.spawnCalls).toHaveLength(1)
  })

  it('K-01: during the canary the batch path is on the gate\'s STOP and every other reservation gets canary_in_progress; after its run both stay until the after-reading is recorded (N7B1), then both go', async () => {
    rh = new RH()
    const before = rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    expect(rh.stopOwner()).toBeNull()
    const { prompt, observe } = rh.prompt('wait_usr2')
    const k = rh.canaryApproval(before, prompt)
    const out = await startRun(rh.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))
    expect(out.status).toBe(202)
    const runId = out.body.run_id as string
    // The STOP is down before the child could spend anything; the gate itself stays OPEN.
    expect(rh.stopOwner()).toBe('gate')
    expect(rh.state().state).toBe('OPEN')
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'canary_in_progress' } })
    const normal = rh.prompt('success')
    expect(await startRun(rh.body(normal.prompt))).toMatchObject({ status: 409, body: { reason: 'canary_in_progress' } })
    // A second canary is refused before its approval could be spent.
    const k2 = rh.canaryApproval(before, normal.prompt, { budget_usd: '0.50' })
    expect(await startRun(rh.body(normal.prompt, { mode: 'canary', budget_usd: '0.50', canary_approval_id: k2 })))
      .toMatchObject({ status: 409, body: { reason: 'canary_in_progress' } })
    expect(getApproval(k2)!.consumed_at).toBeNull()
    rh.cycle()
    expect(rh.stopOwner()).toBe('gate')
    expect(rh.state().state).toBe('OPEN')

    process.kill((JSON.parse(readFileSync(observe, 'utf8')) as { pid: number }).pid, 'SIGUSR2')
    await rh.done(runId)
    expect(rh.runRow(runId)).toMatchObject({ status: 'succeeded', mode: 'canary' })
    expect(rh.reservations()).toMatchObject([{ kind: 'canary', status: 'settled' }])
    // N7B1: the run is over, its window is not: the STOP stays down and nothing
    // else is admitted until the after-reading is recorded.
    expect(rh.gate.canaryInProgress()).toBe(false)
    expect(rh.stopOwner()).toBe('gate')
    expect(rh.state().state).toBe('OPEN')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'canary_window_open' } })
    expect(await startRun(rh.body(normal.prompt))).toMatchObject({ status: 409, body: { reason: 'canary_window_open' } })
    expect((await request('GET', '/api/credit-gate/status')).body).toMatchObject({ canary_in_progress: false, canary_window: { run_id: runId } })
    rh.cycle()
    expect(rh.stopOwner()).toBe('gate')
    // The close step: the after-reading recorded (the canary succeeds on it).
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '199.89')
    expect(rh.canary(k)).toMatchObject({ status: 'success', run_id: runId })
    expect(rh.stopOwner()).toBeNull()
    expect(rh.state().state).toBe('OPEN')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200, body: { enforced: true } })
  })

  it('K-01: a canary that is cancelled keeps the STOP until its after-reading as well, then releases it (the reservation settled by B-04)', async () => {
    rh = new RH()
    const before = rh.open()
    const { prompt, observe } = rh.prompt('hang_term')
    const k = rh.canaryApproval(before, prompt)
    const runId = (await startRun(rh.body(prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))).body.run_id as string
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    expect(rh.stopOwner()).toBe('gate')
    expect(await request('POST', `/api/credit-gate/runs/${runId}/cancel`)).toMatchObject({ status: 202 })
    await rh.done(runId)
    expect(rh.reservations()).toMatchObject([{ kind: 'canary', status: 'settled' }])
    expect(rh.ledgerRow(runId)).toMatchObject({ basis: 'headless_reservation', est_micro: 1_350_000 })
    // N7B1: settled, but its window is open until the after-reading.
    expect(rh.stopOwner()).toBe('gate')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'canary_window_open' } })
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '198.65')
    expect(rh.state().state).toBe('OPEN')
    expect(rh.stopOwner()).toBeNull()
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200 })
  })

  it('N7B1: a rejected reading is no after-reading -- the window stays; the first recorded one closes it', async () => {
    rh = new RH()
    const before = rh.open()
    const c = rh.prompt('success')
    const k = rh.canaryApproval(before, c.prompt)
    const runId = (await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))).body.run_id as string
    await rh.done(runId)
    expect(rh.stopOwner()).toBe('gate')
    // Not newer than the before-reading: rejected, nothing recorded, the window and the STOP stay.
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 - 3 * HOUR, '199.89')
    expect(getDb().prepare('SELECT outcome, reason FROM credit_calibrations ORDER BY id DESC LIMIT 1').get())
      .toEqual({ outcome: 'rejected', reason: 'not_newer_than_previous' })
    expect(rh.canary(k)).toMatchObject({ status: 'consumed' })
    expect(rh.stopOwner()).toBe('gate')
    expect(rh.gate.canaryBlock()).toBe('canary_window_open')
    expect(getDb().prepare(`SELECT COUNT(*) AS n FROM credit_gate_events WHERE kind = 'canary_window_closed'`).get()).toEqual({ n: 0 })
    // The after-reading: recorded, the canary evaluated, the window closed with it.
    rh.calibrate(T0 + 5 * 60_000, '199.89')
    expect(rh.canary(k)).toMatchObject({ status: 'success' })
    expect(rh.gate.canaryBlock()).toBeNull()
    expect(rh.stopOwner()).toBeNull()
    const closed = getDb().prepare(`SELECT reason, calibration_id FROM credit_gate_events WHERE kind = 'canary_window_closed'`).all()
    expect(closed).toEqual([{ reason: 'after_reading', calibration_id: rh.canary(k)!.after_calibration_id }])
  })

  it('N7B1: an undecidable after-reading closes the window too, and the HOLD keeps the STOP', async () => {
    rh = new RH()
    const before = rh.open()
    const c = rh.prompt('success')
    const k = rh.canaryApproval(before, c.prompt)
    const runId = (await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))).body.run_id as string
    await rh.done(runId)
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '199.50')
    expect(rh.canary(k)).toMatchObject({ status: 'undecidable' })
    expect(rh.gate.canaryBlock()).toBeNull()
    expect(rh.state()).toEqual({ state: 'HOLD', reason: 'canary_undecidable' })
    expect(rh.stopOwner()).toBe('gate')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'gate_closed' } })
  })

  it('E-04 end to end: the canary through the API, the after-reading, and only then a normal run starts', async () => {
    rh = new RH()
    const before = rh.calibrate(T0 - 2 * HOUR, '200.00')
    expect(rh.state().state).toBe('OPEN')
    const normal = rh.prompt('success')
    expect(await startRun(rh.body(normal.prompt))).toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    const c = rh.prompt('success', { result: { total_cost_usd: 0.3 } })
    const k = rh.canaryApproval(before, c.prompt)
    const runId = (await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))).body.run_id as string
    await rh.done(runId)
    const cost = rh.ledgerRow(runId) as { est_micro: number; cli_micro: number }
    const spent = Math.max(cost.est_micro, cost.cli_micro)
    expect(spent).toBe(300_000)
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '199.70')
    expect(rh.canary(k)).toMatchObject({ status: 'success', run_id: runId })
    expect(rh.state().state).toBe('OPEN')
    const out = await startRun(rh.body(normal.prompt))
    expect(out).toMatchObject({ status: 202, body: { mode: 'normal' } })
    await rh.done(out.body.run_id as string)
  })
})

// =====================================================================================
// The gate's side of K-01 (gate.ts), without the runner
// =====================================================================================

describe('the gate during a canary reservation (K-01)', () => {
  let h: Harness | undefined
  afterEach(() => {
    h?.cleanup()
    h = undefined
  })

  function openHarness(): Harness {
    h = new Harness({ cal: simpleCal(1, '95.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    return h
  }
  const canaryReq = (ref: string) => ({ kind: 'canary' as const, budget_micro: 900_000 as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
  const batchReq = { kind: 'batch' as const, model: 'claude-haiku-5-5', input_tokens_total: 1000, max_output_tokens_total: 0, request_count: 1, caller: 'rag' }

  it('an open canary reservation puts the STOP down while OPEN, refuses every other reservation and a second canary; its settle keeps both until the close step (N7B1), which lifts both', () => {
    const g = openHarness()
    expect(existsSync(g.stopPath)).toBe(false)
    expect(g.gate.canaryInProgress()).toBe(false)
    const c = g.gate.reserve(canaryReq('hr-canary'))
    expect(c).toMatchObject({ enforced: true, ok: true })
    expect(g.gate.canaryInProgress()).toBe(true)
    expect(existsSync(g.stopPath)).toBe(true)
    expect(g.state()).toMatchObject({ state: 'OPEN' })
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'canary_in_progress' })
    expect(g.gate.reserve({ kind: 'headless', budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-other', caller: 'ezermester' }))
      .toMatchObject({ ok: false, reason: 'canary_in_progress' })
    expect(g.gate.reserve(canaryReq('hr-canary-2'))).toMatchObject({ ok: false, reason: 'canary_in_progress' })
    // Ticks keep the STOP down (the gate owns it, a tick does not release it).
    g.gate.tick()
    g.gate.tick()
    expect(existsSync(g.stopPath)).toBe(true)
    expect(g.state()).toMatchObject({ state: 'OPEN' })
    expect(g.events('reservation_rejected').map((e) => e.reason)).toEqual(['canary_in_progress', 'canary_in_progress', 'canary_in_progress'])
    if (!(c as { ok: boolean }).ok) throw new Error('unreachable')
    expect(g.gate.settleHeadless((c as { reservation_id: string }).reservation_id, null)).toMatchObject({ ok: true, status: 'settled' })
    expect(g.gate.canaryInProgress()).toBe(false)
    // N7B1: the window stays open until the after-reading is recorded.
    expect(existsSync(g.stopPath)).toBe(true)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'canary_window_open' })
    g.gate.tick()
    expect(existsSync(g.stopPath)).toBe(true)
    expect(g.gate.closeCanary(2)).toMatchObject({ ok: true })
    expect(existsSync(g.stopPath)).toBe(false)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: true })
  })

  it('a human STOP during the canary still closes the gate, and the gate never removes it', () => {
    const g = openHarness()
    const c = g.gate.reserve(canaryReq('hr-canary')) as { ok: true; reservation_id: string }
    expect(c.ok).toBe(true)
    rmSync(g.stopPath)
    writeFileSync(g.stopPath, 'human\n')
    g.gate.tick()
    expect(g.state()).toMatchObject({ state: 'CLOSED' })
    g.gate.settleHeadless(c.reservation_id, null)
    g.gate.tick()
    expect(readFileSync(g.stopPath, 'utf8')).toBe('human\n')
    expect(lstatSync(g.stopPath).isFile()).toBe(true)
  })

  it('a canary reservation that went unknown (stale) is no longer in progress; the HOLD (and its window, N7B1) hold the batch path', () => {
    const g = openHarness()
    expect(g.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    g.now += 25 * HOUR
    g.cal = simpleCal(1, '95.00', { captured_at_lb_ms: g.now - HOUR })
    g.gate.tick()
    expect(g.gate.canaryInProgress()).toBe(false)
    expect(g.state()).toMatchObject({ state: 'HOLD' })
    expect(existsSync(g.stopPath)).toBe(true)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'gate_closed' })
    expect(g.gate.canaryBlock()).toBe('canary_window_open')
  })
})

// =====================================================================================
// BE-4b (2026-10-16): the security review's proofs P1-P6, as regressions
// =====================================================================================

describe('BE-4b regressions: concurrency, a lone canary, own runs, the settle retry, a bound canary', () => {
  it('P1: headless.maxConcurrent (default 1) in the reserve transaction -- a second run while one is open gets 409 concurrency_limit', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const first = rh.prompt('hang_term')
    const a = await startRun(rh.body(first.prompt, { budget_usd: '5.00', node_id: 'forged-0' }))
    expect(a.status).toBe(202)
    for (let i = 1; i <= 3; i++) {
      const { prompt } = rh.prompt('hang_term')
      expect(await startRun(rh.body(prompt, { budget_usd: '5.00', node_id: `forged-${i}` })))
        .toMatchObject({ status: 409, body: { reason: 'concurrency_limit' } })
    }
    expect(rh.reservations().filter((r) => r.status === 'open')).toHaveLength(1)
    expect(rh.runner.activeCount()).toBe(1)
    expect(rh.spawnCalls).toHaveLength(1)
    await request('POST', `/api/credit-gate/runs/${a.body.run_id}/cancel`)
    await rh.done(a.body.run_id)
    // The slot is free again; with maxConcurrent 2, two at once and not three.
    rh.writeConfig({ maxConcurrent: 2 })
    const ids: string[] = []
    for (let i = 0; i < 3; i++) {
      const { prompt } = rh.prompt('hang_term')
      const out = await startRun(rh.body(prompt))
      if (i < 2) {
        expect(out.status).toBe(202)
        ids.push(out.body.run_id)
      } else {
        expect(out).toMatchObject({ status: 409, body: { reason: 'concurrency_limit' } })
      }
    }
    for (const id of ids) await request('POST', `/api/credit-gate/runs/${id}/cancel`)
    for (const id of ids) await rh.done(id)
  })

  it('dailyCapUsd: off by default (D-10); when set, a run that would pass it gets 409 daily_cap', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    for (let i = 0; i < 3; i++) {
      const { prompt } = rh.prompt('success')
      const out = await startRun(rh.body(prompt, { budget_usd: '2.00' }))
      expect(out.status).toBe(202)
      await rh.done(out.body.run_id)
    }
    rh.writeConfig({ dailyCapUsd: '10.00' })
    // 3 x 3.00 already reserved today; one more 3.00 would make 12.00.
    const { prompt } = rh.prompt('success')
    expect(await startRun(rh.body(prompt, { budget_usd: '2.00' }))).toMatchObject({ status: 409, body: { reason: 'daily_cap' } })
    const small = rh.prompt('success')
    const ok = await startRun(rh.body(small.prompt, { budget_usd: '0.40' }))
    expect(ok.status).toBe(202)
    await rh.done(ok.body.run_id)
  })

  it('P2: a canary while a normal run is open -> 409 reservations_open before the consume', async () => {
    rh = new RH()
    const before = rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const n = rh.prompt('hang_term')
    const normal = await startRun(rh.body(n.prompt))
    expect(normal.status).toBe(202)
    const c = rh.prompt('hang_term')
    const k = rh.canaryApproval(before, c.prompt)
    expect(await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k })))
      .toMatchObject({ status: 409, body: { reason: 'reservations_open' } })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(rh.spawnCalls).toHaveLength(1)
    await request('POST', `/api/credit-gate/runs/${normal.body.run_id}/cancel`)
    await rh.done(normal.body.run_id)
  })

  it('P3: a canary while a batch reservation is open -> 409 reservations_open, the approval not spent; then it may start', async () => {
    rh = new RH()
    const before = rh.open()
    const b = await request('POST', '/api/credit-gate/reservations', BATCH)
    expect(b.status).toBe(200)
    const c = rh.prompt('success')
    const k = rh.canaryApproval(before, c.prompt)
    expect(await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k })))
      .toMatchObject({ status: 409, body: { reason: 'reservations_open' } })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(await request('POST', `/api/credit-gate/reservations/${b.body.reservation_id}/release`, { reason: 'rejected_4xx' })).toMatchObject({ status: 200 })
    const out = await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))
    expect(out.status).toBe(202)
    await rh.done(out.body.run_id)
  })

  it('P4: GET and cancel answer only the caller who started the run; to anyone else the run does not exist (404)', async () => {
    rh = new RH()
    rh.writeConfig({ allowedCallers: ['ezermester', 'fejleszto'] })
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const n = rh.prompt('hang_term')
    const out = await startRun(rh.body(n.prompt))
    await until(() => existsSync(n.observe), 10_000, 'the fake to start')
    const other = { kind: 'token', agent: 'fejleszto' } as Auth
    expect(await request('GET', `/api/credit-gate/runs/${out.body.run_id}`, undefined, { auth: other })).toMatchObject({ status: 404 })
    expect(await request('POST', `/api/credit-gate/runs/${out.body.run_id}/cancel`, undefined, { auth: other })).toMatchObject({ status: 404 })
    expect((await request('GET', `/api/credit-gate/runs/${out.body.run_id}`)).body).toMatchObject({ status: 'running' })
    expect(await request('POST', `/api/credit-gate/runs/${out.body.run_id}/cancel`)).toMatchObject({ status: 202 })
    await rh.done(out.body.run_id)
    expect(rh.runRow(out.body.run_id)).toMatchObject({ status: 'cancelled' })
  })

  it('B7: the config goes invalid while a run is live -- its owner still sees it and cancels it; anyone else gets the config\'s 409, for a run and for no run alike', async () => {
    rh = new RH()
    rh.writeConfig({ allowedCallers: ['ezermester', 'fejleszto'] })
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const n = rh.prompt('hang_term')
    const out = await startRun(rh.body(n.prompt))
    expect(out.status).toBe(202)
    await until(() => existsSync(n.observe), 10_000, 'the fake to start')
    writeFileSync(join(rh.gateDir, 'config.json'), '{ not json', { mode: 0o600 })
    expect(rh.runner.configHash()).toBeNull()
    const id = out.body.run_id as string
    const other = { kind: 'token', agent: 'fejleszto' } as Auth
    // Not the owner: exactly what an unknown id gets, so the run's existence does not show.
    for (const path of [`/api/credit-gate/runs/${id}`, '/api/credit-gate/runs/hr-none']) {
      expect(await request('GET', path, undefined, { auth: other })).toMatchObject({ status: 409, body: { reason: 'config_invalid' } })
      expect(await request('POST', `${path}/cancel`, undefined, { auth: other })).toMatchObject({ status: 409, body: { reason: 'config_invalid' } })
    }
    expect(await request('GET', '/api/credit-gate/runs/hr-none')).toMatchObject({ status: 409, body: { reason: 'config_invalid' } })
    expect(await request('GET', `/api/credit-gate/runs/${id}`, undefined, { auth: { kind: 'session', user: 'gyuri' } as Auth }))
      .toMatchObject({ status: 409, body: { reason: 'config_invalid' } })
    // The owner.
    expect(await request('GET', `/api/credit-gate/runs/${id}`)).toMatchObject({ status: 200, body: { run_id: id, status: 'running', done: false } })
    expect(await request('POST', `/api/credit-gate/runs/${id}/cancel`)).toMatchObject({ status: 202, body: { run_id: id, cancelling: true } })
    await rh.done(id)
    expect(rh.runRow(id)).toMatchObject({ status: 'cancelled' })
    expect(await request('GET', `/api/credit-gate/runs/${id}`)).toMatchObject({ status: 200, body: { status: 'cancelled', done: true } })
    expect(await request('POST', `/api/credit-gate/runs/${id}/cancel`)).toMatchObject({ status: 409, body: { reason: 'not_running', status: 'cancelled' } })
    // A new run is still refused on the invalid config.
    expect(await startRun(rh.body(rh.prompt('success').prompt))).toMatchObject({ status: 409, body: { reason: 'config_invalid' } })
  })

  it('B7: a caller taken off allowedCallers mid-run still sees and cancels its own run; it starts none, and another\'s run stays hidden', async () => {
    rh = new RH()
    rh.writeConfig({ allowedCallers: ['ezermester', 'fejleszto'] })
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const n = rh.prompt('hang_term')
    const out = await startRun(rh.body(n.prompt))
    expect(out.status).toBe(202)
    await until(() => existsSync(n.observe), 10_000, 'the fake to start')
    rh.writeConfig({ allowedCallers: ['fejleszto'] })
    const id = out.body.run_id as string
    const other = { kind: 'token', agent: 'fejleszto' } as Auth
    expect(await request('GET', `/api/credit-gate/runs/${id}`, undefined, { auth: other })).toMatchObject({ status: 404, body: { reason: 'not_found' } })
    expect(await request('GET', '/api/credit-gate/runs/hr-none')).toMatchObject({ status: 409, body: { reason: 'caller_not_allowed' } })
    expect(await startRun(rh.body(rh.prompt('success').prompt))).toMatchObject({ status: 409, body: { reason: 'caller_not_allowed' } })
    expect(await request('GET', `/api/credit-gate/runs/${id}`)).toMatchObject({ status: 200, body: { run_id: id, status: 'running' } })
    expect(await request('POST', `/api/credit-gate/runs/${id}/cancel`)).toMatchObject({ status: 202 })
    await rh.done(id)
    expect(rh.runRow(id)).toMatchObject({ status: 'cancelled' })
  })

  it('P5: a canary settle that failed is retried by the runner; meanwhile /status shows canary_in_progress; then the batch path is free again', async () => {
    rh = new RH()
    const before = rh.open()
    const c = rh.prompt('success', { result: { total_cost_usd: 0.3 } })
    const k = rh.canaryApproval(before, c.prompt)
    const ledger = (rh.gate as unknown as { ledgerCache: { ledger: { recordHeadless: (...a: unknown[]) => unknown } } }).ledgerCache.ledger
    const orig = ledger.recordHeadless.bind(ledger)
    let thrown = 0
    let failing = true
    ledger.recordHeadless = (...a: unknown[]) => {
      if (failing) {
        thrown++
        throw new Error('n4b test: the ledger is down')
      }
      return orig(...a)
    }
    const out = await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))
    await rh.done(out.body.run_id)
    expect(thrown).toBeGreaterThanOrEqual(1)
    expect(rh.gate.canaryInProgress()).toBe(true)
    expect(rh.gate.status().canary_in_progress).toBe(true)
    expect((await request('GET', '/api/credit-gate/status')).body).toMatchObject({ canary_in_progress: true })
    failing = false
    await until(() => !rh!.gate.canaryInProgress(), 10_000, 'the settle retry')
    expect(rh.reservations()).toMatchObject([{ kind: 'canary', status: 'settled' }])
    expect(rh.ledgerRow(out.body.run_id)).toMatchObject({ basis: 'headless_json' })
    expect(rh.runRow(out.body.run_id)).toMatchObject({ basis: 'headless_json' })
    expect(rh.gate.status().canary_in_progress).toBe(false)
    // The ledger fault held the gate; a newer reading reopens it, and the STOP follows.
    rh.now = T0 + 10 * 60_000
    rh.calibrate(T0 + 5 * 60_000, '199.70')
    expect(rh.state().state).toBe('OPEN')
    expect(rh.stopOwner()).toBeNull()
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200 })
  })

  it('P5: the retry has a limit; then the gate is told (disarm), and the reservation stays counted', async () => {
    rh = new RH({ runner: { settleRetryLimit: 3 } })
    const before = rh.open()
    const c = rh.prompt('success')
    const k = rh.canaryApproval(before, c.prompt)
    const ledger = (rh.gate as unknown as { ledgerCache: { ledger: { recordHeadless: (...a: unknown[]) => unknown } } }).ledgerCache.ledger
    ledger.recordHeadless = () => { throw new Error('n4b test: the ledger stays down') }
    const out = await startRun(rh.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k }))
    await rh.done(out.body.run_id)
    const settleFailed = () => getDb().prepare(`SELECT COUNT(*) AS n FROM credit_gate_events WHERE kind = 'signal' AND detail_json LIKE '%settle_failed%'`).get() as { n: number }
    await until(() => settleFailed().n === 1, 10_000, 'the give-up signal')
    expect(rh.reservations()).toMatchObject([{ kind: 'canary', status: 'open' }])
    expect(rh.gate.status().canary_in_progress).toBe(true)
  })

  it('P6: the canary approval binds the node, the cwd and the prompt\'s sha256; any other -> 409 canary_terms_mismatch, nothing spent', async () => {
    rh = new RH()
    const before = rh.open()
    const c = rh.prompt('success')
    const k = rh.canaryApproval(before, c.prompt)
    const otherWt = join(rh.wtRoot, 'other')
    mkdirSync(otherWt)
    writeFileSync(join(otherWt, '.git'), 'gitdir: /nowhere/.git/worktrees/other\n')
    const canary = (over: Record<string, unknown>) => rh!.body(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: k, ...over })
    const other = rh.prompt('success')
    for (const over of [{ node_id: 'not-the-owners-node' }, { cwd: otherWt }, { prompt: other.prompt }]) {
      expect(await startRun(canary(over)), JSON.stringify(over).slice(0, 60)).toMatchObject({ status: 409, body: { reason: 'canary_terms_mismatch' } })
    }
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(rh.spawnCalls).toHaveLength(0)
    const out = await startRun(canary({}))
    expect(out.status).toBe(202)
    await rh.done(out.body.run_id)
  })

  it('P6: the canary payload must carry node, cwd and prompt_sha256 in their alphabets; the owner\'s message shows them, the hash shortened', () => {
    const base = {
      v: 1, kind: 'credit_gate_canary', config_hash: 'ab'.repeat(32), model: 'claude-sonnet-5-5', budget_usd: '0.90',
      min_expected_usd: '0.10', before_calibration_id: '0b9c2c1e-1111-4222-8333-444455556666',
      node: 'N4b', cwd: '/Volumes/8T/10_LOCAL/Brainy/credit-fallback', prompt_sha256: 'cd'.repeat(32),
    }
    expect(parseCreditGatePayload('credit_gate_canary', canon(base))).toMatchObject({ ok: true })
    const without = (k: string) => { const o: Record<string, unknown> = { ...base }; delete o[k]; return canon(o) }
    for (const k of ['node', 'cwd', 'prompt_sha256']) expect(parseCreditGatePayload('credit_gate_canary', without(k))).toMatchObject({ ok: false, field: 'keys' })
    const bad: Array<[Record<string, unknown>, string]> = [
      [{ node: 'N 4' }, 'node'], [{ node: '' }, 'node'], [{ node: 7 }, 'node'],
      [{ cwd: 'relative/path' }, 'cwd'], [{ cwd: '/a/../b' }, 'cwd'], [{ cwd: '/a\u202eb' }, 'cwd'], [{ cwd: '/a//b' }, 'cwd'],
      [{ prompt_sha256: 'CD'.repeat(32) }, 'prompt_sha256'], [{ prompt_sha256: 'cd'.repeat(31) }, 'prompt_sha256'],
    ]
    for (const [over, field] of bad) expect(parseCreditGatePayload('credit_gate_canary', canon({ ...base, ...over })), field).toMatchObject({ ok: false, field })
    const text = buildCreditGateApprovalText(base as unknown as CreditGatePayload, {
      agentId: 'brainy', category: 'credit_gate_canary', shortId: '1a2b3c4d', hash16: '0123456789abcdef', timeoutAt: 1_792_000_000,
    } as never)
    expect(text).toContain('Node: N4b')
    expect(text).toContain('Munkakönyvtár: /Volumes/8T/10_LOCAL/Brainy/credit-fallback')
    expect(text).toContain(`Prompt (sha256 eleje): ${'cd'.repeat(8)}`)
    expect(text).not.toContain('cd'.repeat(32))
  })

  it('the config: maxConcurrent 1 and dailyCapUsd off by default; out-of-range values reject the config', () => {
    const cfg = (headless: Record<string, unknown>) => {
      const o = configObject('/tmp/u.jsonl', '/tmp/STOP') as { headless: Record<string, unknown> }
      return JSON.stringify({ ...o, headless: { ...o.headless, ...headless } })
    }
    const d = parseCreditGateConfig(cfg({}))
    expect(d).toMatchObject({ ok: true, config: { headless: { maxConcurrent: 1, dailyCap: null } } })
    expect(parseCreditGateConfig(cfg({ maxConcurrent: 3, dailyCapUsd: '25.00' }))).toMatchObject({ ok: true, config: { headless: { maxConcurrent: 3, dailyCap: 25_000_000 } } })
    expect(parseCreditGateConfig(cfg({ dailyCapUsd: null }))).toMatchObject({ ok: true, config: { headless: { dailyCap: null } } })
    for (const bad of [{ maxConcurrent: 0 }, { maxConcurrent: 17 }, { maxConcurrent: 1.5 }, { maxConcurrent: '1' }, { dailyCapUsd: '0.00' }, { dailyCapUsd: '5' }, { dailyCapUsd: 5 }]) {
      expect(parseCreditGateConfig(cfg(bad)), JSON.stringify(bad)).toMatchObject({ ok: false })
    }
  })
})

describe('the gate: a lone canary, maxConcurrent and the daily cap in the reserve transaction', () => {
  let h: Harness | undefined
  afterEach(() => {
    h?.cleanup()
    h = undefined
  })
  const headlessReq = (ref: string, budget = 400_000) => ({ kind: 'headless' as const, budget_micro: budget as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
  const canaryReq = (ref: string) => ({ kind: 'canary' as const, budget_micro: 900_000 as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
  const batchReq = { kind: 'batch' as const, model: 'claude-haiku-5-5', input_tokens_total: 1000, max_output_tokens_total: 0, request_count: 1, caller: 'rag' }
  const headlessConfig = (over: Record<string, unknown> = {}) => ({
    headless: {
      allowedCallers: ['ezermester'], cwdRoots: ['/Volumes/8T/10_LOCAL/Brainy'], forbiddenCwds: ['/Users/x/marveen'],
      runsDir: '/tmp/credit-gate-runs', claudeBin: '/opt/homebrew/bin/claude', claudeBinSha256: 'a'.repeat(64), models: ['claude-opus-5-5', 'claude-sonnet-5-5'],
      maxBudgetUsd: '5.00', wallClockMin: 90, ...over,
    },
  })
  function openHarness(over: Record<string, unknown> = {}): Harness {
    h = new Harness({ cal: simpleCal(1, '95.00'), config: headlessConfig(over) })
    expect(h.gate.tick().state).toBe('OPEN')
    return h
  }

  it('a canary is refused while ANY reservation is open or unknown (batch, headless), in the transaction', () => {
    const g = openHarness()
    const b = g.gate.reserve(batchReq) as { ok: boolean; reservation_id: string }
    expect(b.ok).toBe(true)
    expect(g.gate.reserve(canaryReq('hr-c1'))).toMatchObject({ ok: false, reason: 'reservations_open' })
    g.gate.release(b.reservation_id, 'rejected_4xx')
    const hd = g.gate.reserve(headlessReq('hr-h1')) as { ok: boolean; reservation_id: string }
    expect(hd.ok).toBe(true)
    expect(g.gate.reserve(canaryReq('hr-c2'))).toMatchObject({ ok: false, reason: 'reservations_open' })
    g.gate.settleHeadless(hd.reservation_id, null)
    // An unknown one (its outcome never known) blocks the canary too.
    const b2 = g.gate.reserve(batchReq) as { ok: boolean; reservation_id: string }
    g.db.prepare(`UPDATE credit_reservations SET status = 'unknown' WHERE id = ?`).run(b2.reservation_id)
    expect(g.gate.openReservationCount()).toBe(1)
    expect(g.gate.reserve(canaryReq('hr-c3'))).toMatchObject({ ok: false, reason: 'reservations_open' })
    g.db.prepare(`UPDATE credit_reservations SET status = 'released' WHERE id = ?`).run(b2.reservation_id)
    expect(g.gate.reserve(canaryReq('hr-c4'))).toMatchObject({ ok: true })
  })

  it('maxConcurrent counts the open headless and canary reservations; the batch path is not counted', () => {
    const g = openHarness({ maxConcurrent: 2 })
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: true })
    expect(g.gate.reserve(headlessReq('hr-1'))).toMatchObject({ ok: true })
    const second = g.gate.reserve(headlessReq('hr-2')) as { ok: boolean; reservation_id: string }
    expect(second.ok).toBe(true)
    expect(g.gate.reserve(headlessReq('hr-3'))).toMatchObject({ ok: false, reason: 'concurrency_limit' })
    g.gate.settleHeadless(second.reservation_id, null)
    expect(g.gate.reserve(headlessReq('hr-4'))).toMatchObject({ ok: true })
  })

  it('the daily cap: the headless reservations of the last 24 hours (released ones aside) plus this one; a day later there is room', () => {
    const g = openHarness({ dailyCapUsd: '1.00', maxConcurrent: 4 })
    const a = g.gate.reserve(headlessReq('hr-1')) as { ok: boolean; reservation_id: string }
    expect(a).toMatchObject({ ok: true, amount_micro: 600_000 })
    g.gate.settleHeadless(a.reservation_id, null)
    expect(g.gate.reserve(headlessReq('hr-2'))).toMatchObject({ ok: false, reason: 'daily_cap' })
    const c = g.gate.reserve(headlessReq('hr-3', 260_000)) as { ok: boolean; reservation_id: string }
    expect(c).toMatchObject({ ok: true, amount_micro: 390_000 })
    g.gate.settleHeadless(c.reservation_id, null)
    expect(g.gate.reserve(headlessReq('hr-3b', 10_000))).toMatchObject({ ok: false, reason: 'daily_cap' })
    g.now += 24 * HOUR + 1000
    g.cal = simpleCal(1, '95.00', { captured_at_lb_ms: g.now - HOUR })
    g.gate.tick()
    expect(g.gate.reserve(headlessReq('hr-4'))).toMatchObject({ ok: true })
  })
})

// =====================================================================================
// The CLI
// =====================================================================================

const TOKEN = `test-token-${randomBytes(8).toString('hex')}`

/** A loopback HTTP server in front of the route, with the dashboard's Bearer check and X-Agent-Id claim. */
function serve(): Promise<{ server: http.Server; api: string }> {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://127.0.0.1')
    if (req.headers.authorization !== `Bearer ${TOKEN}`) {
      res.writeHead(401, { 'Content-Type': 'application/json' })
      res.end('{"error":"Unauthorized"}')
      return
    }
    const claim = req.headers['x-agent-id']
    const agent = typeof claim === 'string' && /^[a-z][a-z0-9_-]{0,63}$/.test(claim) ? claim : undefined
    const ctx = { req, res, path: url.pathname, method: req.method ?? 'GET', url, auth: { kind: 'token', agent } } as RouteContext
    tryHandleCreditGate(ctx).then((handled) => {
      if (!handled) {
        res.writeHead(404)
        res.end('{}')
      }
    }, () => {
      res.writeHead(500)
      res.end('{}')
    })
  })
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => {
    const port = (server.address() as net.AddressInfo).port
    ok({ server, api: `http://127.0.0.1:${port}` })
  }))
}

/** The CLI in a child python, behind the suite's own loopback guard (credit-run.test.py --guarded-run). */
function cli(args: string[]): Promise<{ code: number | null; stdout: string; stderr: string }> {
  return new Promise((ok) => {
    const child = spawn('python3', ['-I', CLI_SUITE, '--guarded-run', CLI, ...args], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += String(d) })
    child.stderr.on('data', (d) => { stderr += String(d) })
    child.on('close', (code) => ok({ code, stdout, stderr }))
  })
}

describe('scripts/credit-run.py (E-05 exit codes)', () => {
  it('against the real route over loopback: a closed gate exits 3, a finished run exits 0 with its result', async () => {
    rh = new RH()
    rh.open()
    rh.approveHash(rh.runner.configHash() as string)
    const tokenFile = join(rh.real, 'token')
    writeFileSync(tokenFile, `${TOKEN}\n`, { mode: 0o600 })
    const { server, api } = await serve()
    try {
      const { prompt } = rh.prompt('success', { result: { result: 'node finished' } })
      const promptFile = join(rh.real, 'prompt.txt')
      writeFileSync(promptFile, prompt)
      const args = ['--api', api, '--token-file', tokenFile, '--poll-s', '0.2', '--node', 'N4b-e2e', '--model', 'claude-sonnet-5-5',
        '--effort', 'xhigh', '--budget', '0.40', '--cwd', rh.worktree, '--prompt-file', promptFile]
      const ok = await cli(args)
      expect(ok.code, ok.stderr).toBe(0)
      const last = JSON.parse(ok.stdout.trim().split('\n').pop() as string) as Record<string, unknown>
      expect(last).toMatchObject({ rc: 0, status: 'succeeded', result_text: 'node finished' })
      expect(rh.runRow(last.run_id as string)).toMatchObject({ caller: 'ezermester', node_id: 'N4b-e2e', effort: 'xhigh' })
      expect(ok.stdout + ok.stderr).not.toContain(TOKEN)

      rh.gate.signal('disarm', 'test', null, rh.now)
      const closed = await cli(args)
      expect(closed.code, closed.stderr).toBe(3)
      expect(JSON.parse(closed.stdout.trim().split('\n').pop() as string)).toMatchObject({ rc: 3, reason: 'gate_closed' })
      const bad = await cli([...args.slice(0, -6), '--budget', '5', '--cwd', rh.worktree, '--prompt-file', promptFile])
      expect(bad.code).toBe(4)
    } finally {
      await new Promise((r) => server.close(r))
    }
  })

  it('the python suite passes (stub dashboard: request shape, every exit code, polling, the token)', () => {
    const res = spawnSync('python3', ['-I', CLI_SUITE], { encoding: 'utf-8', timeout: 120_000 })
    if (res.status !== 0) {
      console.error(res.stdout)
      console.error(res.stderr)
    }
    expect(res.status).toBe(0)
  })
})
