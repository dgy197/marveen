import { describe, it, expect, beforeAll, afterAll, afterEach } from 'vitest'
import net from 'node:net'
import { EventEmitter } from 'node:events'
import { existsSync, mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { readCreditGateMode } from '../web/credit-gate/config.js'
import {
  getCreditGateRuntime,
  setCreditGateRuntime,
  startCreditGateRuntime,
} from '../web/credit-gate/runtime.js'
import { tryHandleCreditGate } from '../web/routes/credit-gate.js'
import type { RouteContext } from '../web/routes/types.js'
import { Harness, simpleCal, USD, type HarnessOptions } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a: the HTTP API (card fec6335f, blueprint 4.2 -- status,
// reservations, signals; the runs part is N4b's) and the off-mode guarantee:
// with CREDIT_GATE_MODE missing the dashboard behaves as before.
//
// The routes are driven IN-PROCESS with fake request/response objects: no
// socket is opened. On top of that a process-level guard refuses any
// non-loopback connect() and the live CDP ports (18800, 18899) BEFORE the
// connect, and the global fetch throws (blueprint 6.1); both are self-tested.

const BLOCKED_PORTS = new Set([18800, 18899, 18997])
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const origConnect = net.Socket.prototype.connect
const origFetch = globalThis.fetch

/**
 * Where a Socket#connect call would go. net.connect() hands the prototype
 * method its normalised arguments as ONE array ([options, cb]), a direct call
 * passes (options) or (port, host): every form is unpacked. Anything that
 * cannot be read is refused (fail-closed).
 */
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

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    // 18997 is this file's own blocked test port; the live 18800 is never dialled.
    expect(() => net.connect({ host: '127.0.0.1', port: 18997 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
    expect(() => net.connect(443, 'example.com')).toThrow(/refused/)
    expect(() => net.createConnection(18997, '127.0.0.1')).toThrow(/refused/)
    expect(() => new net.Socket().connect({ host: '127.0.0.1', port: 18997 })).toThrow(/refused/)
    expect(() => new net.Socket().connect(18997, '::1')).toThrow(/refused/)
    expect(() => fetch('https://example.com')).toThrow(/not allowed/)
  })
})

interface Out { status: number; body: any; headers: Record<string, unknown> }

function call(method: string, path: string, body?: unknown, raw?: string): { ctx: RouteContext; out: Out; done: Promise<void> } {
  const out: Out = { status: 0, body: null, headers: {} }
  let resolve!: () => void
  const done = new Promise<void>((r) => { resolve = r })
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    setHeader() { /* unused */ },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk); resolve() },
  }
  const req: any = new EventEmitter()
  req.headers = {}
  req.destroy = () => { /* noop */ }
  const payload = raw ?? (body === undefined ? '' : JSON.stringify(body))
  // Asynchronous delivery, like a socket: parallel requests really interleave.
  setImmediate(() => {
    if (payload) req.emit('data', Buffer.from(payload))
    req.emit('end')
  })
  const url = new URL(`http://localhost:3420${path}`)
  return { ctx: { req, res, path, method, url } as RouteContext, out, done }
}

async function request(method: string, path: string, body?: unknown, raw?: string): Promise<Out> {
  const c = call(method, path, body, raw)
  const handled = await tryHandleCreditGate(c.ctx)
  expect(handled).toBe(true)
  await c.done
  return c.out
}

const BATCH = {
  kind: 'batch', model: 'claude-haiku-5-5', input_tokens_total: 10_000_000, max_output_tokens_total: 0, request_count: 1, caller: 'rag-gold-label',
}

let h: Harness | undefined
function harness(o: HarnessOptions = {}): Harness {
  h = new Harness(o)
  setCreditGateRuntime({ mode: h.mode, gate: h.gate, storeDir: h.storeDir, db: h.db, startError: null })
  return h
}

afterEach(() => {
  setCreditGateRuntime(null)
  h?.cleanup()
  h = undefined
})

describe('routing', () => {
  it('only /api/credit-gate/* is ours', async () => {
    const c = call('GET', '/api/kanban')
    expect(await tryHandleCreditGate(c.ctx)).toBe(false)
  })

  it('an unknown credit-gate path is 404, a wrong method 405', async () => {
    harness()
    expect((await request('GET', '/api/credit-gate/nope')).status).toBe(404)
    expect((await request('GET', '/api/credit-gate/reservations')).status).toBe(405)
    expect((await request('POST', '/api/credit-gate/status')).status).toBe(405)
  })
})

describe('off mode (the default): today\'s behaviour', () => {
  it('without the runtime started the gate is off: reservations are not enforced, runs are gate_off', async () => {
    setCreditGateRuntime(null)
    expect(getCreditGateRuntime().mode.mode).toBe('off')
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200, body: { enforced: false } })
    // Even a body the gate would refuse: the batch client's off-mode path must not change.
    expect(await request('POST', '/api/credit-gate/reservations', undefined, '{garbage')).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/reservations/abc/bind', { batch_id: 'msgbatch_1', expected_requests: 1 })).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/reservations/abc/complete')).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/reservations/abc/release', { reason: 'rejected_4xx' })).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/signals', { kind: 'disarm', source: 'x' })).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/runs', { node_id: 'n' })).toMatchObject({ status: 409, body: { reason: 'gate_off' } })
    expect(await request('GET', '/api/credit-gate/status')).toMatchObject({ status: 200, body: { mode: 'off', enforced: false, state: 'CLOSED', reason: 'gate_off' } })
  })

  it('startCreditGateRuntime with the flag missing does nothing: no tick, no tables, no files', () => {
    const dir = mkdtempSync(join(tmpdir(), 'credit-gate-off-'))
    const db = new Database(join(dir, 'db.sqlite'))
    try {
      const before = readdirSync(dir).sort()
      for (const v of [undefined, '', '  ', 'off']) {
        const interval = startCreditGateRuntime({ webOnly: false, modeValue: v ?? null, db, storeDir: join(dir, 'store') })
        expect(interval).toBeUndefined()
        expect(getCreditGateRuntime()).toMatchObject({ mode: { mode: 'off' }, gate: null })
      }
      expect(db.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'credit_%'").all()).toEqual([])
      expect(readdirSync(dir).sort()).toEqual(before)
      expect(existsSync(join(dir, 'store'))).toBe(false)
    } finally {
      db.close()
      rmSync(dir, { recursive: true, force: true })
    }
  })

  it('web.ts wires the gate through the runtime only (the tick never starts unconditionally)', () => {
    const src = readFileSync(join(__dirname, '..', 'web.ts'), 'utf8')
    expect(src).toMatch(/import \{ tryHandleCreditGate \} from '\.\/web\/routes\/credit-gate\.js'/)
    expect(src).toMatch(/if \(await tryHandleCreditGate\(routeCtx\)\) return/)
    expect(src).toMatch(/const creditGateInterval = startCreditGateRuntime\(\{ webOnly \}\)/)
    expect(src).toMatch(/if \(creditGateInterval\) clearInterval\(creditGateInterval\)/)
    // No other credit-gate entry point in web.ts (no tick, no schema call of its own).
    expect(src).not.toMatch(/applyCreditGateSchema|new CreditGate|\.tick\(/)
  })
})

describe('enforce and shadow runtime start', () => {
  it('enforce with a valid store: tables, a first tick and an interval', () => {
    const x = new Harness({ cal: null })
    try {
      const fresh = new Database(join(x.dir, 'fresh.sqlite'))
      try {
        const interval = startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: fresh, storeDir: x.storeDir, now: () => x.now })
        expect(interval).toBeDefined()
        clearInterval(interval)
        const rt = getCreditGateRuntime()
        expect(rt.gate).not.toBeNull()
        expect(fresh.prepare("SELECT state, reason FROM credit_gate_state").get()).toEqual({ state: 'CLOSED', reason: 'no_calibration' })
        expect(existsSync(x.stopPath)).toBe(true)
      } finally {
        fresh.close()
      }
    } finally {
      setCreditGateRuntime(null)
      x.cleanup()
    }
  })

  it('a web-only instance never runs the gate: reservations are refused, not waved through', async () => {
    const x = new Harness()
    try {
      expect(startCreditGateRuntime({ webOnly: true, modeValue: 'enforce', db: x.db, storeDir: x.storeDir })).toBeUndefined()
      expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'gate_not_running' } })
      expect(await request('GET', '/api/credit-gate/status')).toMatchObject({ status: 200, body: { mode: 'enforce', state: 'CLOSED', reason: 'gate_not_running' } })
      expect(existsSync(x.stopPath)).toBe(false)
    } finally {
      setCreditGateRuntime(null)
      x.cleanup()
    }
  })

  it('shadow: reservations {enforced:false}, runs gate_shadow', async () => {
    harness({ mode: 'shadow', cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await request('POST', '/api/credit-gate/runs', { node_id: 'n' })).toMatchObject({ status: 409, body: { reason: 'gate_shadow' } })
  })

  it('shadow: a signal reaches the gate (recorded, state changed), the answer says not enforced', async () => {
    harness({ mode: 'shadow', cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const r = await request('POST', '/api/credit-gate/signals', { kind: 'credit_balance_too_low', source: 'batch_client' })
    expect(r).toMatchObject({ status: 200, body: { enforced: false, state: 'INCIDENT' } })
    expect(h!.events('signal').map((e) => e.reason)).toEqual(['credit_balance_too_low'])
    expect(h!.state().state).toBe('INCIDENT')
  })
})

describe('K3 over HTTP: 20 parallel reservations, room for 7', () => {
  it('exactly 7 succeed, and the reserved total never exceeds the room', async () => {
    // R_est 95, T_close 20: 75 USD of room; each reservation is 10.00.
    harness({ cal: simpleCal(1, '95.00') })
    h!.gate.tick()
    const outs = await Promise.all(Array.from({ length: 20 }, () => request('POST', '/api/credit-gate/reservations', BATCH)))
    const ok = outs.filter((o) => o.status === 200 && o.body.enforced === true)
    const refused = outs.filter((o) => o.status === 409)
    expect(ok).toHaveLength(7)
    expect(refused).toHaveLength(13)
    for (const o of ok) expect(o.body).toMatchObject({ enforced: true, amount_usd: '10.00' })
    for (const o of refused) expect(o.body.reason).toBe('below_threshold')
    const total = h!.reservations().reduce((s, r) => s + (r.amount_micro as number), 0)
    expect(total).toBe(70 * USD)
    expect(new Set(ok.map((o) => o.body.reservation_id)).size).toBe(7)
  })
})

describe('reservation API', () => {
  it('validates the body strictly', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const bad: unknown[] = [
      { ...BATCH, kind: 'headless' },
      { ...BATCH, input_tokens_total: 1.5 },
      { ...BATCH, input_tokens_total: -1 },
      { ...BATCH, request_count: 0 },
      { ...BATCH, model: 'claude haiku' },
      { ...BATCH, caller: '' },
      { ...BATCH, extra: true },
      [BATCH],
    ]
    for (const b of bad) expect((await request('POST', '/api/credit-gate/reservations', b)).status).toBe(400)
    expect((await request('POST', '/api/credit-gate/reservations', undefined, '{oops')).status).toBe(400)
    expect(h!.reservations()).toHaveLength(0)
  })

  it('an unpriced model is refused (409), not reserved at zero', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    expect(await request('POST', '/api/credit-gate/reservations', { ...BATCH, model: 'claude-unknown-9' })).toMatchObject({ status: 409, body: { reason: 'model_unpriced' } })
  })

  it('bind, complete and release over HTTP, with 404 for an unknown id', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const r = await request('POST', '/api/credit-gate/reservations', BATCH)
    const id = r.body.reservation_id as string
    expect(await request('POST', `/api/credit-gate/reservations/${id}/bind`, { batch_id: 'msgbatch_01Q', expected_requests: 1 })).toMatchObject({ status: 200, body: { ok: true } })
    expect(await request('POST', `/api/credit-gate/reservations/${id}/release`, { reason: 'rejected_4xx' })).toMatchObject({ status: 409, body: { reason: 'bound' } })
    expect(await request('POST', `/api/credit-gate/reservations/${id}/complete`)).toMatchObject({ status: 200, body: { ok: true, status: 'open' } })
    expect((await request('POST', '/api/credit-gate/reservations/nope/complete')).status).toBe(404)
    expect((await request('POST', `/api/credit-gate/reservations/${id}/release`, { reason: 'timeout' })).status).toBe(400)
    expect((await request('POST', `/api/credit-gate/reservations/${id}/bind`, { batch_id: 'msgbatch_01Q', expected_requests: 0 })).status).toBe(400)
  })

  it('a closed gate answers 409 with the reason', async () => {
    harness({ cal: null })
    h!.gate.tick()
    expect(await request('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'gate_closed' } })
  })
})

describe('signals and status over HTTP', () => {
  it('a signal closes, an unknown kind is 400, and no response carries a key', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const dummy = `sk-ant-TEST-DUMMY-${Math.random().toString(36).slice(2)}0123456789abcdef`
    const s = await request('POST', '/api/credit-gate/signals', { kind: 'auth_401', source: 'batch_client', detail: `got 401 for ${dummy}` })
    expect(s).toMatchObject({ status: 200, body: { enforced: true, state: 'CLOSED' } })
    expect((await request('POST', '/api/credit-gate/signals', { kind: 'open_please', source: 'x' })).status).toBe(400)
    expect((await request('POST', '/api/credit-gate/signals', { kind: 'disarm', source: 'bad source!' })).status).toBe(400)
    const st = await request('GET', '/api/credit-gate/status')
    for (const o of [s, st]) expect(JSON.stringify(o.body)).not.toContain(dummy)
    expect(JSON.stringify(h!.events())).not.toContain(dummy)
  })

  it('status: the blueprint fields, money as decimal strings', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const st = await request('GET', '/api/credit-gate/status')
    expect(st.status).toBe(200)
    expect(st.body).toMatchObject({
      mode: 'enforce',
      enforced: true,
      state: 'OPEN',
      r_est_usd: '100.00',
      ledger: { l_usd: '0.00', age_s: 0 },
      reservations: { open_count: 0, open_usd: '0.00' },
      thresholds: { t_close_usd: '20.00', t_reopen_usd: '50.00', t_lowcal_usd: '60.00', t_close_eff_usd: '20.00' },
      calibration: { id: 1, grants: [{ expires: '2026-11-17', remaining_usd: '100.00' }] },
      close_at: '2026-11-16T22:00:00.000Z',
      stop: { present: false, owner: 'none' },
    })
  })

  it('runs in enforce mode without a headless runtime: runs_unavailable (N4b serves them through its runner)', async () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(await request('POST', '/api/credit-gate/runs', { node_id: 'n' })).toMatchObject({ status: 409, body: { reason: 'runs_unavailable' } })
  })
})

describe('mode reading from .env', () => {
  it('an unknown value is reported in the status as enforce', async () => {
    harness({ mode: 'Enforce', cal: simpleCal(1, '100.00') })
    h!.gate.tick()
    const st = await request('GET', '/api/credit-gate/status')
    expect(st.body).toMatchObject({ mode: 'enforce', mode_raw: 'Enforce', state: 'CLOSED', reason: 'mode_unknown' })
    expect(readCreditGateMode('Enforce').unknown).toBe(true)
  })
})
