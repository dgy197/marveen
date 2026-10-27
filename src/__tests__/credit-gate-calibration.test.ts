import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import net from 'node:net'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Credit gate, node N2c (card fec6335f): the owner-approved calibration, the
// protected stores, the incident-clear and the canary's verdict.
//
// Written from the spec (G-02, D-01..D-05, B-05, K-01..K-03, C-05, C-06b) and
// the blueprint (3.3, 3.5, 3.7, N2c test list, 8, 14), plus the coordinator's
// N2c brief (2026-10-16: a reading without V is undecidable; the canary's
// window may hold covered usage rows, never another headless run) and the
// BE-3b conditions (the exact category on every path; isOwnerVerified always
// with the configured owner). Not from the code.
//
// Everything runs in-process on a tmp store and a tmp SQLite file: the
// approvals are created and decided through db.ts exactly as the owner's
// Telegram button decides them (resolveApprovalFromTelegram), the legacy
// PATCH through resolveApproval (what the PATCH route calls). No live
// dashboard, store, Telegram or API. A process-level guard refuses every
// non-loopback connect() and the live CDP ports (18800, 18899) before the
// connect, self-tested against this file's own blocked port 18996.

// The owner the default resolver (strictOwnerUserId -> resolveAlertOwnerChat)
// sees: the .env value only; access.json is never read (no live file).
const mocked = vi.hoisted(() => ({ allowedChatId: '', accessJson: null as string | null }))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return { ...real, get ALLOWED_CHAT_ID() { return mocked.allowedChatId } }
})

vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  // access.json is a test value (never the live file): the old fallback the gate must no longer use (LOW-A).
  const read = () => {
    if (mocked.accessJson !== null) return mocked.accessJson
    throw new Error('ENOENT')
  }
  return {
    ...real,
    resolveAlertOwnerChat: vi.fn((_read?: unknown, configured?: string | null) => real.resolveAlertOwnerChat(read, configured)),
  }
})

import {
  initDatabase, getDb, getApproval, createApproval, setApprovalCallbackNonceHashes, setApprovalTelegramMessageId,
  resolveApprovalFromTelegram, resolveApproval, isOwnerVerified, consumeCreditGateApproval, listApprovalEvents,
} from '../db.js'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { CreditGate } from '../web/credit-gate/gate.js'
import { fileGateDeps, getCreditGateRuntime, setCreditGateRuntime, startCreditGateRuntime } from '../web/credit-gate/runtime.js'
import { loadCreditGateConfigFile, readCreditGateMode, type ConfigLoadResult } from '../web/credit-gate/config.js'
import type { CalibrationPayload } from '../web/credit-gate/approval-payload.js'
import {
  approvedCanary,
  calibrationSource,
  CalibrationProcessor,
  strictOwnerUserId,
  takeCanaryHash,
  evaluateCalibration,
  evaluateCanary,
  parseReadings,
  readingsFromPayload,
  type Readings,
  type WindowRow,
} from '../web/credit-gate/calibration.js'
import { configObject, pricingText, T0, HOUR, USD } from './fixtures/credit-gate/gate-harness.js'
import { creditGateIncidentEvent } from '../web/routes/approvals.js'

const OWNER = '1000000001'
const STRANGER = '2000000002'

// --- network guard (self-tested) ----------------------------------------------------

const BLOCKED_PORTS = new Set([18800, 18899, 18996])
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

let scratch = ''

beforeAll(() => {
  net.Socket.prototype.connect = function guarded(this: net.Socket, ...args: unknown[]) {
    const t = guardTarget(args)
    if (t === null || (t.host !== 'unix' && (!LOOPBACK.has(t.host) || BLOCKED_PORTS.has(t.port)))) {
      throw new Error(`credit-gate N2c test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  globalThis.fetch = (() => { throw new Error('credit-gate N2c test guard: fetch is not allowed') }) as typeof fetch
  scratch = mkdtempSync(join(tmpdir(), 'cg-n2c-'))
})

afterAll(() => {
  net.Socket.prototype.connect = origConnect
  globalThis.fetch = origFetch
  if (scratch) rmSync(scratch, { recursive: true, force: true })
})

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    expect(() => net.connect({ host: '127.0.0.1', port: 18996 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
    expect(() => net.connect(443, 'api.anthropic.com')).toThrow(/refused/)
    expect(() => fetch('https://api.telegram.org/')).toThrow(/not allowed/)
  })
})

// --- fixtures -------------------------------------------------------------------------

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// An independent canonical form (Python json.dumps sort_keys, no whitespace) for these ASCII values.
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

const stamp = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

type G = readonly [granted: string, expires: string, original: string, remaining: string]
const P1 = (remaining: string): G => ['2026-10-10', '2026-10-17', '200.00', remaining]
const P2 = (remaining: string): G => ['2026-10-14', '2026-11-17', '200.00', remaining]

function calPayload(lbMs: number, grants: readonly G[], R = '3.63', V = '10.00'): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_calibration',
    captured_at_lb: stamp(lbMs),
    grants: grants.map(([granted, expires, original_usd, remaining_usd]) => ({ granted, expires, original_usd, remaining_usd })),
    protected: { R: { remaining_usd: R, expires: '2027-01-31' }, V: { remaining_usd: V } },
    screenshot: '/Volumes/8T/00 CLOUD/console/n2c-test.png',
  }
}

function readings(lbMs: number, grants: readonly G[], R: string | null = '3.63', V: string | null = '10.00'): Readings {
  const p = calPayload(lbMs, grants, R ?? '0.00', V ?? '0.00') as { protected: Record<string, unknown> }
  // A store that is not on the screenshot is simply missing from the reading.
  if (R === null) delete p.protected.R
  if (V === null) delete p.protected.V
  const r = readingsFromPayload(p as unknown as CalibrationPayload)
  if (!r.ok) throw new Error(`fixture: ${r.field}`)
  return r.readings
}

const CONFIG_HASH = 'c0ffee'.padEnd(64, '7')
/** BE-4b P6: the run a canary approval names (payload) and the runner's terms carry alike. */
const CANARY_RUN = { node: 'N9x', cwd: '/Volumes/8T/10_LOCAL/Brainy/n2c-test', prompt_sha256: 'cd'.repeat(32) }
const OTHER_HASH = 'beef'.padEnd(64, '1')

function canaryPayload(beforeApprovalId: string, over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_canary',
    config_hash: CONFIG_HASH,
    model: 'claude-sonnet-5-5',
    budget_usd: '0.90',
    min_expected_usd: '0.10',
    before_calibration_id: beforeApprovalId,
    ...CANARY_RUN,
    ...over,
  }
}

const incidentClear = (id: number) => ({ v: 1, kind: 'credit_gate_incident_clear', incident_event_id: id })

/** The canary terms the runner binds (LOW-3: all mandatory; BE-4b P6: the run's node, cwd and prompt too). */
const TERMS = (runId: string, over: Partial<{ model: string; budget_micro: number }> = {}) =>
  ({ model: 'claude-sonnet-5-5', budget_micro: 900_000, runId, ...CANARY_RUN, ...over })

let msgSeq = 9000

/** Create a request the way the route does (canonical payload + its hash), still pending. */
function requestApproval(category: string, payload: Record<string, unknown> | string): string {
  const text = typeof payload === 'string' ? payload : canon(payload)
  const id = randomUUID()
  createApproval({
    id, agent_id: 'brainy', category, action_description: 'n2c test', action_payload: text,
    timeout_at: Math.floor(Date.now() / 1000) + 3600, content_hash: sha(text),
  })
  return id
}

/** The owner's Telegram button: the nonce binding, the message id, the strict press. */
function pressApprove(id: string, ownerId = OWNER): ReturnType<typeof resolveApprovalFromTelegram> {
  const yes = sha(randomBytes(16).toString('hex'))
  const no = sha(randomBytes(16).toString('hex'))
  expect(setApprovalCallbackNonceHashes(id, { approved: yes, rejected: no })).toBe(true)
  const mid = msgSeq++
  expect(setApprovalTelegramMessageId(id, mid)).toBe(true)
  return resolveApprovalFromTelegram({ id, status: 'approved', ownerId, messageId: mid, nonceHash: yes })
}

function ownerApproved(category: string, payload: Record<string, unknown>, ownerId = OWNER): string {
  const id = requestApproval(category, payload)
  expect(pressApprove(id, ownerId).ok).toBe(true)
  return id
}

class H {
  readonly dir: string
  readonly storeDir: string
  readonly gateDir: string
  readonly usagePath: string
  readonly stopPath: string
  now = T0
  ownerId: string | null = OWNER
  configThrows = false
  /** Set: the consume of db.ts is replaced (the rollback test). */
  consumeOverride: ((p: Parameters<typeof consumeCreditGateApproval>[0]) => ReturnType<typeof consumeCreditGateApproval>) | null = null
  readonly gate: CreditGate
  readonly proc: CalibrationProcessor

  constructor() {
    this.dir = mkdtempSync(join(scratch, 'h-'))
    this.storeDir = join(this.dir, 'store')
    this.gateDir = join(this.storeDir, 'credit-gate')
    mkdirSync(this.gateDir, { recursive: true, mode: 0o700 })
    chmodSync(this.storeDir, 0o700)
    chmodSync(this.gateDir, 0o700)
    this.usagePath = join(this.dir, 'usage.jsonl')
    writeFileSync(this.usagePath, '')
    mkdirSync(join(this.dir, 'batch'))
    this.stopPath = join(this.dir, 'batch', 'STOP')
    const cfg = join(this.gateDir, 'config.json')
    writeFileSync(cfg, JSON.stringify(configObject(this.usagePath, this.stopPath)), { mode: 0o600 })
    const pricing = join(this.gateDir, 'pricing.json')
    writeFileSync(pricing, pricingText('2026-10-16'), { mode: 0o600 })
    initDatabase(join(this.dir, 'claudeclaw.db'))
    const db = getDb()
    applyCreditGateSchema(db)
    this.gate = new CreditGate(fileGateDeps({
      storeDir: this.storeDir, db, mode: readCreditGateMode('enforce'), calibration: calibrationSource(db), now: () => this.now,
    }))
    this.proc = new CalibrationProcessor({
      db,
      gate: this.gate,
      loadConfig: (): ConfigLoadResult => {
        if (this.configThrows) throw new RangeError('injected config fault')
        return loadCreditGateConfigFile(cfg)
      },
      ownerId: () => this.ownerId,
      now: () => this.now,
      consume: (p) => (this.consumeOverride ?? consumeCreditGateApproval)(p),
    })
  }

  /** What the runtime does every refreshS: tick (ledger refresh), process, tick. */
  cycle(): { state: string; reason: string } {
    this.gate.tick(this.now)
    this.proc.process(this.now)
    this.gate.tick(this.now)
    return this.state()
  }

  state(): { state: string; reason: string } {
    return getDb().prepare('SELECT state, reason FROM credit_gate_state WHERE id = 1').get() as { state: string; reason: string }
  }

  stateRow(): Record<string, unknown> {
    return getDb().prepare('SELECT * FROM credit_gate_state WHERE id = 1').get() as Record<string, unknown>
  }

  calibrations(): Array<{ id: number; approval_id: string; outcome: string; reason: string | null; reconcile_json: string | null }> {
    return getDb().prepare('SELECT id, approval_id, outcome, reason, reconcile_json FROM credit_calibrations ORDER BY id').all() as never
  }

  canary(approvalId: string): Record<string, unknown> | undefined {
    return getDb().prepare('SELECT * FROM credit_canaries WHERE approval_id = ?').get(approvalId) as Record<string, unknown> | undefined
  }

  events(kind: string): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_gate_events WHERE kind = ? ORDER BY id').all(kind) as Array<Record<string, unknown>>
  }

  /** One ledger row (as N1b stores it), stamped `tsMs`. */
  row(o: { tsMs: number; est: number | null; cli?: number | null; source?: string; run_id?: string | null; batch_id?: string | null }): void {
    const batch = o.batch_id ?? null
    getDb().prepare(`INSERT INTO credit_ledger_entries
        (source, dedupe_key, ts, model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens,
         batch_id, custom_id, run_id, est_micro, cli_micro, priced_with, basis, ingested_at)
      VALUES (?, ?, ?, 'claude-sonnet-5-5', 1, 1, 0, 0, ?, ?, ?, ?, ?, NULL, ?, ?)`).run(
      o.source ?? 'anthropic-batch', `test:${randomUUID()}`, Math.floor(o.tsMs / 1000), batch, batch === null ? null : randomUUID(),
      o.run_id ?? null, o.est, o.cli ?? null, (o.source ?? 'anthropic-batch') === 'headless' ? 'headless_json' : 'usage', this.now,
    )
  }

  /** A calibration approved by the owner's button and processed: returns the approval id. */
  calibrate(lbMs: number, grants: readonly G[], R = '3.63', V = '10.00'): string {
    const id = ownerApproved('credit_gate_calibration', calPayload(lbMs, grants, R, V))
    this.cycle()
    return id
  }

  cleanup(): void {
    rmSync(this.dir, { recursive: true, force: true })
  }
}

let h: H
beforeEach(() => {
  h = new H()
})
afterEach(() => {
  h?.cleanup()
})

const LB1 = T0 - 3 * HOUR
const LB2 = T0 - 1 * HOUR
const BASE = { R: 3_630_000, V: 10 * USD }

function ctx(o: { prev?: Readings | null; window?: WindowRow[] | null; nowMs?: number } = {}) {
  return { nowMs: o.nowMs ?? T0, maxAgeMs: 24 * HOUR, baseline: BASE, prev: o.prev ?? null, window: o.window ?? (o.prev ? [] : null) }
}

const usageRow = (est: number, over: Partial<WindowRow> = {}): WindowRow =>
  ({ source: 'anthropic-batch', run_id: null, batch_id: null, est_micro: est, cli_micro: null, ...over })
const headlessRow = (runId: string, cost: number): WindowRow =>
  ({ source: 'headless', run_id: runId, batch_id: null, est_micro: Math.min(cost, 1000), cli_micro: cost })

// =====================================================================================
// The reading itself (3.7, strict)
// =====================================================================================

describe('parseReadings: the approved payload, strictly (3.7)', () => {
  it('reads every grant and both protected stores in micro-USD', () => {
    const r = parseReadings(canon(calPayload(LB1, [P1('195.64'), P2('200.00')])))
    if (!r.ok) throw new Error(r.field)
    expect(r.readings.captured_at_lb_ms).toBe(LB1)
    expect(r.readings.grants.map((g) => g.remaining_micro)).toEqual([195_640_000, 200 * USD])
    expect(r.readings.grants[0].expires_ms).toBe(Date.UTC(2026, 9, 17))
    expect(r.readings).toMatchObject({ R_micro: 3_630_000, V_micro: 10 * USD })
  })

  it('"10.0", "10", " 10.00" and a non-canonical text are refused', () => {
    for (const bad of ['10.0', '10', ' 10.00', '1e1']) {
      expect(parseReadings(canon(calPayload(LB1, [P2('200.00')], '3.63', bad))).ok).toBe(false)
      expect(parseReadings(canon(calPayload(LB1, [P2(bad)]))).ok).toBe(false)
    }
    expect(parseReadings(JSON.stringify(calPayload(LB1, [P2('200.00')]), null, 1)).ok).toBe(false)
    expect(parseReadings(canon({ ...calPayload(LB1, [P2('200.00')]), kind: 'credit_gate_canary' })).ok).toBe(false)
  })

  it('a reading on which V (or R) is not visible keeps the store as null, never as a number', () => {
    expect(readings(LB1, [P2('200.00')], '3.63', null)).toMatchObject({ V_micro: null, R_micro: 3_630_000 })
    expect(readings(LB1, [P2('200.00')], null, '10.00')).toMatchObject({ R_micro: null, V_micro: 10 * USD })
  })
})

// =====================================================================================
// evaluateCalibration: time, D-02, B-05 (pure)
// =====================================================================================

describe('evaluateCalibration: the time of the reading', () => {
  const r = (lb: number) => readings(lb, [P2('200.00')])

  it('a captured_at_lb in the future is refused; now itself is fine', () => {
    expect(evaluateCalibration(r(T0 + 1000), ctx())).toMatchObject({ outcome: 'rejected', reason: 'captured_in_future' })
    expect(evaluateCalibration(r(T0), ctx())).toMatchObject({ outcome: 'accepted' })
  })

  it('older than 24 h is refused; exactly 24 h is fine', () => {
    expect(evaluateCalibration(r(T0 - 24 * HOUR - 1000), ctx())).toMatchObject({ outcome: 'rejected', reason: 'reading_too_old' })
    expect(evaluateCalibration(r(T0 - 24 * HOUR), ctx())).toMatchObject({ outcome: 'accepted' })
  })

  it('older than the previous reading is refused, and so is the same instant (nothing new)', () => {
    expect(evaluateCalibration(r(LB1 - 1000), ctx({ prev: r(LB1) }))).toMatchObject({ outcome: 'rejected', reason: 'not_newer_than_previous' })
    expect(evaluateCalibration(r(LB1), ctx({ prev: r(LB1) }))).toMatchObject({ outcome: 'rejected', reason: 'not_newer_than_previous' })
    expect(evaluateCalibration(r(LB1 + 1000), ctx({ prev: r(LB1) }))).toMatchObject({ outcome: 'accepted' })
  })
})

describe('evaluateCalibration: the protected stores (D-01, D-02)', () => {
  it('V 9.99 is an INCIDENT', () => {
    expect(evaluateCalibration(readings(LB1, [P2('200.00')], '3.63', '9.99'), ctx()))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased', detail: { store: 'V' } })
  })

  it('R 3.62 is an INCIDENT', () => {
    expect(evaluateCalibration(readings(LB1, [P2('200.00')], '3.62', '10.00'), ctx()))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased', detail: { store: 'R' } })
  })

  it('a decrease against the previous reading is an INCIDENT even above the baseline', () => {
    const prev = readings(LB1, [P2('200.00')], '3.63', '12.00')
    expect(evaluateCalibration(readings(LB2, [P2('200.00')], '3.63', '11.00'), ctx({ prev })))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased', detail: { store: 'V' } })
  })

  it('V not visible on the reading: undecidable, a HOLD -- never accepted (mért eset 2026-10-16 07:18)', () => {
    expect(evaluateCalibration(readings(LB1, [P2('200.00')], '3.63', null), ctx()))
      .toMatchObject({ outcome: 'hold', reason: 'reading_undecidable', detail: { missing: ['V'] } })
    expect(evaluateCalibration(readings(LB1, [P2('200.00')], null, '10.00'), ctx()))
      .toMatchObject({ outcome: 'hold', reason: 'reading_undecidable', detail: { missing: ['R'] } })
  })

  it('a visible decrease wins over a missing store: INCIDENT', () => {
    expect(evaluateCalibration(readings(LB1, [P2('200.00')], '3.62', null), ctx()))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased', detail: { store: 'R' } })
  })

  it('both at the baseline: accepted (no previous reading: no B-05)', () => {
    expect(evaluateCalibration(readings(LB1, [P2('200.00')]), ctx())).toEqual({ outcome: 'accepted', reconcile: null })
  })
})

describe('evaluateCalibration: B-05 against the ledger between the two lower bounds', () => {
  const prev = readings(LB1, [P2('100.00')])
  const next = (rem: string) => readings(LB2, [P2(rem)])

  it('1 USD off is exactly on the border (provider 10.00): ledger 11.00 and 9.00 pass, one micro more is a HOLD', () => {
    expect(evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(11 * USD)] }))).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(9 * USD)] }))).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(11 * USD), usageRow(1)] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_mismatch' })
    expect(evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(9 * USD - 1)] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_mismatch' })
  })

  it('5% is the border above 20 USD (provider 40.00): ledger 42.00 and 38.00 pass, one micro more is a HOLD', () => {
    expect(evaluateCalibration(next('60.00'), ctx({ prev, window: [usageRow(42 * USD)] }))).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(next('60.00'), ctx({ prev, window: [usageRow(38 * USD)] }))).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(next('60.00'), ctx({ prev, window: [usageRow(42 * USD + 1)] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_mismatch' })
    expect(evaluateCalibration(next('60.00'), ctx({ prev, window: [usageRow(38 * USD - 1)] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_mismatch' })
  })

  it('the report carries the numbers it decided on', () => {
    const v = evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(10_500_000), headlessRow('r1', 250_000)] }))
    expect(v).toMatchObject({ outcome: 'accepted', reconcile: { provider_usd: '10.00', ledger_usd: '10.75', rows: 2 } })
  })

  it('a new grant is accepted and left out of B-05', () => {
    const v = evaluateCalibration(readings(LB2, [P2('90.00'), ['2026-11-14', '2026-12-17', '200.00', '200.00']]),
      ctx({ prev, window: [usageRow(10 * USD)] }))
    expect(v).toMatchObject({ outcome: 'accepted', reconcile: { provider_usd: '10.00', new_grants: 1 } })
  })

  it('a grant that expired between the readings may have spent anything up to its remainder', () => {
    const before = readings(LB1, [P1('5.00'), P2('100.00')])
    const after = readings(Date.UTC(2026, 9, 17, 6), [P2('90.00')])
    const at = Date.UTC(2026, 9, 17, 8)
    expect(evaluateCalibration(after, { ...ctx({ prev: before, window: [usageRow(15 * USD)] }), nowMs: at })).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(after, { ...ctx({ prev: before, window: [usageRow(16 * USD)] }), nowMs: at })).toMatchObject({ outcome: 'accepted' })
    expect(evaluateCalibration(after, { ...ctx({ prev: before, window: [usageRow(16 * USD + 1)] }), nowMs: at }))
      .toMatchObject({ outcome: 'hold', reason: 'b05_mismatch' })
  })

  it('a grant that vanished before its expiry, or one that grew, cannot be reconciled: HOLD', () => {
    expect(evaluateCalibration(readings(LB2, [P2('90.00')]), ctx({ prev: readings(LB1, [P1('5.00'), P2('100.00')]), window: [] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'grant_missing' } })
    expect(evaluateCalibration(next('100.01'), ctx({ prev, window: [] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'grant_increased' } })
  })

  it('an unpriced ledger row in the window cannot be reconciled: HOLD', () => {
    expect(evaluateCalibration(next('90.00'), ctx({ prev, window: [usageRow(10 * USD), { ...usageRow(0), est_micro: null }] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'unpriced_rows' } })
  })
})

// =====================================================================================
// evaluateCanary (K-02, K-03, pure)
// =====================================================================================

describe('evaluateCanary: the four outcomes (K-02, K-03) and the window rule', () => {
  const before = readings(LB1, [P1('195.64'), P2('200.00')])
  const after = (p1: string, p2: string, R = '3.63', V = '10.00') => readings(LB2, [P1(p1), P2(p2)], R, V)
  const canary = { run_id: 'run-canary', min_expected_micro: 100_000 }

  it('success: one Team grant fell by the canary\'s ledger amount; the grant is named', () => {
    expect(evaluateCanary(before, after('195.64', '199.70'), [headlessRow('run-canary', 300_000)], canary))
      .toMatchObject({ outcome: 'success', basis: 'run', grant: '2026-10-14|2026-11-17|200000000', decrease_micro: 300_000, expected_micro: 300_000 })
  })

  it('the tolerance is max(0.05 USD, 20%): on the border succeeds, past it is undecidable', () => {
    // 0.20 expected: 20% = 0.04 < 0.05, so +-0.05.
    expect(evaluateCanary(before, after('195.39', '200.00'), [headlessRow('run-canary', 200_000)], canary)).toMatchObject({ outcome: 'success' })
    expect(evaluateCanary(before, after('195.38', '200.00'), [headlessRow('run-canary', 200_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'canary_amount_mismatch' })
    // 0.50 expected: 20% = 0.10.
    expect(evaluateCanary(before, after('195.04', '200.00'), [headlessRow('run-canary', 500_000)], canary)).toMatchObject({ outcome: 'success' })
    expect(evaluateCanary(before, after('195.24', '200.00'), [headlessRow('run-canary', 500_000)], canary)).toMatchObject({ outcome: 'success' })
    expect(evaluateCanary(before, after('195.25', '200.00'), [headlessRow('run-canary', 500_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'canary_amount_mismatch' })
  })

  it('INCIDENT when V or R fell', () => {
    expect(evaluateCanary(before, after('195.34', '200.00', '3.63', '9.99'), [headlessRow('run-canary', 300_000)], canary))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
    expect(evaluateCanary(before, after('195.34', '200.00', '3.60', '10.00'), [headlessRow('run-canary', 300_000)], canary))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
  })

  it('INCIDENT when no Team grant fell at all', () => {
    expect(evaluateCanary(before, after('195.64', '200.00'), [headlessRow('run-canary', 300_000)], canary))
      .toMatchObject({ outcome: 'incident', reason: 'no_grant_decreased' })
  })

  it('undecidable when another headless run is in the window', () => {
    expect(evaluateCanary(before, after('195.34', '200.00'), [headlessRow('run-canary', 300_000), headlessRow('run-other', 1)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'other_headless_rows' })
  })

  it('refinement: only covered usage rows (batch or sync) besides the canary -> judged on the whole window (0.28 vs 0.287)', () => {
    const batchRow = usageRow(87_000, { batch_id: 'msgbatch_x' })
    expect(evaluateCanary(before, after('195.36', '200.00'), [headlessRow('run-canary', 200_000), batchRow], canary))
      .toMatchObject({ outcome: 'success', basis: 'window', expected_micro: 287_000, decrease_micro: 280_000 })
    expect(evaluateCanary(before, after('195.36', '200.00'), [headlessRow('run-canary', 200_000), usageRow(87_000)], canary))
      .toMatchObject({ outcome: 'success', basis: 'window' })
  })

  it('refinement: one headless row of another run among them -> undecidable', () => {
    expect(evaluateCanary(before, after('195.36', '200.00'), [headlessRow('run-canary', 200_000), usageRow(40_000), headlessRow('run-x', 47_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'other_headless_rows' })
  })

  it('undecidable when the canary is not in the window, cost below its minimum, or V is not visible', () => {
    expect(evaluateCanary(before, after('195.34', '200.00'), [], canary)).toMatchObject({ outcome: 'undecidable', reason: 'canary_not_in_window' })
    expect(evaluateCanary(before, after('195.34', '200.00'), [headlessRow('run-canary', 300_000)], { ...canary, run_id: null }))
      .toMatchObject({ outcome: 'undecidable', reason: 'canary_run_unbound' })
    expect(evaluateCanary(before, after('195.64', '200.00'), [headlessRow('run-canary', 99_999)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'canary_below_minimum' })
    expect(evaluateCanary(before, readings(LB2, [P1('195.34'), P2('200.00')], '3.63', null), [headlessRow('run-canary', 300_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'protected_not_visible' })
  })

  it('an unpriced row of another source in the window: undecidable', () => {
    expect(evaluateCanary(before, after('195.34', '200.00'), [headlessRow('run-canary', 300_000), { ...usageRow(0), est_micro: null }], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'unpriced_rows' })
  })
})

// =====================================================================================
// Processing in the tick: who may open (G-02)
// =====================================================================================

describe('processing: only the owner\'s button opens, once (G-02, BE-3b)', () => {
  it('an owner-approved reading is consumed once, recorded, and opens the gate', () => {
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    const id = h.calibrate(LB1, [P2('200.00')])
    expect(h.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    expect(h.calibrations()).toMatchObject([{ approval_id: id, outcome: 'accepted' }])
    const a = getApproval(id)!
    expect(a.consumed_at).not.toBeNull()
    expect(a.consumed_by).toBe('credit-gate')
    expect(listApprovalEvents(id).map((e) => e.event)).toEqual(['consumed'])
    expect(h.events('calibration')).toHaveLength(1)
    // A second pass changes nothing; a second consume is refused.
    h.cycle()
    expect(h.calibrations()).toHaveLength(1)
    expect(consumeCreditGateApproval({ id, category: 'credit_gate_calibration', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'already_consumed' })
  })

  it('the legacy PATCH decides the row, but nothing is consumed and the gate does not open', () => {
    const id = requestApproval('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    expect(resolveApproval(id, 'approved', 'dashboard')).toBe(true)
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.calibrations()).toHaveLength(0)
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('a row approved as owner:telegram: before the trace table existed (pre-migration) does not open', () => {
    const id = requestApproval('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    getDb().prepare("UPDATE approvals SET status = 'approved', resolved_by = ?, resolved_at = ? WHERE id = ?")
      .run(`owner:telegram:${OWNER}`, Math.floor(Date.now() / 1000), id)
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.calibrations()).toHaveLength(0)
  })

  it('a button-approved email_send id is never a calibration (isOwnerVerified alone would say yes)', () => {
    const id = requestApproval('email_send', '{"envelope_v":1,"to":["x@example.invalid"]}')
    expect(pressApprove(id).ok).toBe(true)
    expect(isOwnerVerified(id, OWNER)).toBe(true)
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(consumeCreditGateApproval({ id, category: 'credit_gate_calibration', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'wrong_category' })
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('a reading approved under another category (a canary approval) is not a calibration', () => {
    ownerApproved('credit_gate_canary', canaryPayload(randomUUID()))
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.calibrations()).toHaveLength(0)
  })

  it('a foreign owner: pressed by another user, or the configured owner is someone else -> nothing opens', () => {
    const byStranger = ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]), STRANGER)
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(getApproval(byStranger)!.consumed_at).toBeNull()
    expect(consumeCreditGateApproval({ id: byStranger, category: 'credit_gate_calibration', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'not_owner_verified' })
    const byOwner = ownerApproved('credit_gate_calibration', calPayload(LB1 + 1000, [P2('200.00')]))
    h.ownerId = '3000000003'
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    h.ownerId = null
    expect(h.cycle()).toMatchObject({ state: 'HOLD', reason: 'owner_unset' })
    expect(getApproval(byOwner)!.consumed_at).toBeNull()
    // The configured owner back: the owner's own approval is processed.
    h.ownerId = OWNER
    expect(h.cycle().state).toBe('OPEN')
    expect(h.calibrations()).toMatchObject([{ approval_id: byOwner, outcome: 'accepted' }])
  })

  it('a payload changed after the press does not open', () => {
    const id = ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    const forged = canon(calPayload(LB1, [P2('999.00'), P1('200.00')]))
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(forged, id)
    expect(h.cycle().state).toBe('CLOSED')
    getDb().prepare('UPDATE approvals SET content_hash = ? WHERE id = ?').run(sha(forged), id)
    expect(h.cycle().state).toBe('CLOSED')
    expect(h.calibrations()).toHaveLength(0)
  })

  it('"10.0" cannot even be approved: the press closes it, nothing is processed', () => {
    const id = requestApproval('credit_gate_calibration', calPayload(LB1, [P2('200.00')], '3.63', '10.0'))
    expect(pressApprove(id)).toMatchObject({ ok: false, reason: 'payload_mismatch' })
    expect(h.cycle().state).toBe('CLOSED')
    expect(h.calibrations()).toHaveLength(0)
  })

  it('a reading without V cannot become an owner approval at all, so it never opens', () => {
    const p = calPayload(LB1, [P2('200.00')]) as { protected: Record<string, unknown> }
    delete p.protected.V
    const id = requestApproval('credit_gate_calibration', p)
    expect(pressApprove(id)).toMatchObject({ ok: false, reason: 'payload_mismatch' })
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.calibrations()).toHaveLength(0)
  })
})

describe('processing: the time rules, recorded and refused (never opening)', () => {
  it('a reading from the future, one older than 24 h, and one older than the previous are consumed and refused', () => {
    h.calibrate(LB2, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    h.calibrate(T0 + 60_000, [P2('200.00')])
    h.calibrate(T0 - 25 * HOUR, [P2('200.00')])
    h.calibrate(LB2 - 1000, [P2('200.00')])
    expect(h.calibrations().map((c) => [c.outcome, c.reason])).toEqual([
      ['accepted', null],
      ['rejected', 'captured_in_future'],
      ['rejected', 'reading_too_old'],
      ['rejected', 'not_newer_than_previous'],
    ])
    expect(h.events('calibration_rejected')).toHaveLength(3)
    // The accepted calibration stays the one in force.
    expect(h.stateRow().calibration_id).toBe(h.calibrations()[0].id)
  })

  it('T_reopen: 49.99 left is accepted but does not open', () => {
    h.calibrate(LB1, [P2('49.99')])
    expect(h.calibrations().map((c) => c.outcome)).toEqual(['accepted'])
    expect(h.state()).toEqual({ state: 'CLOSED', reason: 'below_reopen' })
  })

  it('T_reopen: 50.00 left opens', () => {
    h.calibrate(LB1, [P2('50.00')])
    expect(h.state().state).toBe('OPEN')
  })

  it('a ledger that has not been read past the reading defers it (not consumed), and it is processed later', () => {
    const id = ownerApproved('credit_gate_calibration', calPayload(T0 - 30_000, [P2('200.00')]))
    // No tick yet: the ledger was never read.
    h.proc.process(h.now)
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(h.cycle().state).toBe('OPEN')
    expect(getApproval(id)!.consumed_at).not.toBeNull()
  })
})

describe('processing: D-02, B-05 and the INCIDENT path', () => {
  it('V 9.99: INCIDENT, the reading is not the calibration in force', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    h.calibrate(LB2, [P2('200.00')], '3.63', '9.99')
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'protected_decreased' })
    expect(h.calibrations().map((c) => c.outcome)).toEqual(['accepted', 'incident'])
    expect(h.stateRow().calibration_id).toBe(h.calibrations()[0].id)
  })

  it('R 3.62 on the very first reading: INCIDENT', () => {
    h.calibrate(LB1, [P2('200.00')], '3.62', '10.00')
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'protected_decreased' })
  })

  it('INCIDENT: a new reading does not open without the incident-clear; the clear names THIS incident; then a newer reading opens', () => {
    h.calibrate(LB1, [P2('200.00')], '3.62', '10.00')
    const incidentId = h.stateRow().incident_event_id as number
    expect(incidentId).toBeGreaterThan(0)
    h.now += 60_000
    h.calibrate(LB2, [P2('200.00')], '3.63', '10.00')
    expect(h.state().state).toBe('INCIDENT')
    // A clear naming another event: consumed, refused, nothing lifted.
    const wrong = ownerApproved('credit_gate_incident_clear', incidentClear(incidentId + 1000))
    h.cycle()
    expect(h.state().state).toBe('INCIDENT')
    expect(getApproval(wrong)!.consumed_at).not.toBeNull()
    expect(h.events('incident_clear_refused')).toHaveLength(1)
    // A legacy-PATCH clear does nothing.
    const legacy = requestApproval('credit_gate_incident_clear', incidentClear(incidentId))
    resolveApproval(legacy, 'approved', 'dashboard')
    h.cycle()
    expect(h.state().state).toBe('INCIDENT')
    // The owner's clear of this incident: CLOSED, still latched (the reading before the clear does not count).
    ownerApproved('credit_gate_incident_clear', incidentClear(incidentId))
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.now += 60_000
    h.calibrate(h.now - 10_000, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
  })

  it('B-05 mismatch: HOLD; a newer reading that reconciles lifts it', () => {
    h.calibrate(LB1, [P2('100.00')])
    expect(h.state().state).toBe('OPEN')
    // Provider: 10.00 spent; the ledger saw 8.50 -> 1.50 off.
    h.row({ tsMs: LB1 + HOUR, est: 8_500_000 })
    h.calibrate(LB2, [P2('90.00')])
    expect(h.state()).toEqual({ state: 'HOLD', reason: 'b05_mismatch' })
    const held = h.calibrations()[1]
    expect(held.outcome).toBe('hold')
    expect(JSON.parse(held.reconcile_json!)).toMatchObject({ provider_usd: '10.00', ledger_usd: '8.50' })
    // Next reading: 2.00 spent, the ledger saw 2.00 since the held one -> lifted.
    h.row({ tsMs: LB2 + 60_000, est: 2 * USD })
    h.now += 60_000
    h.calibrate(T0, [P2('88.00')])
    expect(h.state().state).toBe('OPEN')
  })

  it('C-05: after a threshold closure a refused reading changes nothing; a newer accepted one (with a new grant) reopens', () => {
    h.calibrate(LB1, [P2('61.00')])
    expect(h.state().state).toBe('OPEN')
    h.row({ tsMs: LB1 + HOUR, est: 41 * USD })
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'threshold' })
    h.calibrate(LB1 - 1000, [P2('61.00')])
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'rejected' })
    expect(h.state()).toEqual({ state: 'CLOSED', reason: 'threshold' })
    h.calibrate(LB2, [P2('20.00'), ['2026-10-16', '2026-11-30', '200.00', '200.00']])
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'accepted' })
    expect(h.state().state).toBe('OPEN')
  })

  it('a reading on the B-05 border opens', () => {
    h.calibrate(LB1, [P2('100.00')])
    h.row({ tsMs: LB1 + HOUR, est: 11 * USD })
    h.calibrate(LB2, [P2('90.00')])
    expect(h.state().state).toBe('OPEN')
    expect(h.calibrations().map((c) => c.outcome)).toEqual(['accepted', 'accepted'])
  })

  it('a damaged guard-event file: the owner\'s incident-clear also resets the guard cursor, so the gate can reopen', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    // The guard file turns into a symlink: unreadable -> an INCIDENT on every evaluation.
    const guard = join(h.storeDir, 'interactive-key-guard-events.jsonl')
    writeFileSync(join(h.dir, 'elsewhere.jsonl'), '')
    symlinkSync(join(h.dir, 'elsewhere.jsonl'), guard)
    h.now += 30_000
    h.cycle()
    expect(h.state().state).toBe('INCIDENT')
    rmSync(guard)
    const incidentId = h.stateRow().incident_event_id as number
    ownerApproved('credit_gate_incident_clear', incidentClear(incidentId))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.now += 30_000
    h.calibrate(h.now - 10_000, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
  })

  it('an exception while processing: HOLD, and the approval is not consumed', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    const id = ownerApproved('credit_gate_calibration', calPayload(LB2, [P2('200.00')]))
    h.configThrows = true
    h.proc.process(h.now)
    expect(h.state()).toEqual({ state: 'HOLD', reason: 'calibration_error' })
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(h.events('fault').length + h.events('calibration_error').length).toBeGreaterThan(0)
  })
})

// =====================================================================================
// The canary: consume, run, after-reading, verdict
// =====================================================================================

describe('consumeCanaryApproval: owner, category, hash, the reading right before (K-01)', () => {
  function before(): string {
    const id = h.calibrate(LB1, [P1('195.64'), P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    return id
  }

  it('the owner\'s canary approval is consumed once and hands over the approved hash and terms', () => {
    const b = before()
    const k = ownerApproved('credit_gate_canary', canaryPayload(b))
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('run-1')))
      .toMatchObject({ ok: true, config_hash: CONFIG_HASH, model: 'claude-sonnet-5-5', budget_micro: 900_000, min_expected_micro: 100_000 })
    expect(getApproval(k)!.consumed_by).toBe('credit-gate')
    expect(h.canary(k)).toMatchObject({ status: 'consumed', before_calibration_id: h.calibrations()[0].id })
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('run-2'))).toMatchObject({ ok: false, reason: 'already_consumed' })
  })

  it('LOW-3 / BE-3c P4: the terms and the run id are mandatory, and the runner takes the hash once, for that run only', () => {
    const b = before()
    const k = ownerApproved('credit_gate_canary', canaryPayload(b))
    const consume = h.proc.consumeCanaryApproval.bind(h.proc) as (...a: unknown[]) => unknown
    expect(consume(k, CONFIG_HASH)).toMatchObject({ ok: false, reason: 'bad_request' })
    expect(consume(k, CONFIG_HASH, {})).toMatchObject({ ok: false, reason: 'bad_request' })
    expect(consume(k, CONFIG_HASH, { model: 'claude-sonnet-5-5', budget_micro: 900_000 })).toMatchObject({ ok: false, reason: 'bad_request' })
    expect(consume(k, CONFIG_HASH, { model: 'claude-sonnet-5-5', runId: 'run-1' })).toMatchObject({ ok: false, reason: 'bad_request' })
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(takeCanaryHash(getDb(), k, 'run-1')).toBeNull()
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('run-1'))).toMatchObject({ ok: true, config_hash: CONFIG_HASH, run_id: 'run-1' })
    expect(h.canary(k)).toMatchObject({ run_id: 'run-1', status: 'consumed' })
    expect(takeCanaryHash(getDb(), k, 'run-other')).toBeNull()
    expect(takeCanaryHash(getDb(), b, 'run-1')).toBeNull()
    expect(takeCanaryHash(getDb(), k, 'run-1')).toBe(CONFIG_HASH)
    // The second lookup gets nothing: one approval, one run.
    expect(takeCanaryHash(getDb(), k, 'run-1')).toBeNull()
  })

  it('refused: another hash, other terms, a legacy-PATCH approval, a stranger, the tick never consumes it', () => {
    const b = before()
    const k = ownerApproved('credit_gate_canary', canaryPayload(b))
    h.cycle()
    expect(getApproval(k)!.consumed_at).toBeNull()
    expect(h.proc.consumeCanaryApproval(k, OTHER_HASH, TERMS('r'))).toMatchObject({ ok: false, reason: 'hash_mismatch' })
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('r', { budget_micro: 900_001 }))).toMatchObject({ ok: false, reason: 'terms_mismatch' })
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('r', { model: 'claude-opus-5-5' }))).toMatchObject({ ok: false, reason: 'terms_mismatch' })
    // Pressed by a stranger: not the owner's. The owner configured as someone else: an owner change.
    const byStranger = ownerApproved('credit_gate_canary', canaryPayload(b, { budget_usd: '0.85' }), STRANGER)
    expect(h.proc.consumeCanaryApproval(byStranger, CONFIG_HASH, TERMS('r', { budget_micro: 850_000 }))).toMatchObject({ ok: false, reason: 'not_owner_verified' })
    h.ownerId = STRANGER
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('r'))).toMatchObject({ ok: false, reason: 'owner_changed' })
    h.ownerId = OWNER
    expect(getApproval(k)!.consumed_at).toBeNull()
    const legacy = requestApproval('credit_gate_canary', canaryPayload(b, { budget_usd: '0.80' }))
    resolveApproval(legacy, 'approved', 'dashboard')
    expect(h.proc.consumeCanaryApproval(legacy, CONFIG_HASH, TERMS('r', { budget_micro: 800_000 }))).toMatchObject({ ok: false, reason: 'not_owner_verified' })
  })

  it('refused: a calibration approval passed as a canary, an email_send id as the before-reading, a before that is not the latest', () => {
    const b = before()
    expect(h.proc.consumeCanaryApproval(b, CONFIG_HASH, TERMS('r'))).toMatchObject({ ok: false, reason: 'wrong_category' })
    const mail = requestApproval('email_send', '{"envelope_v":1,"to":["x@example.invalid"]}')
    expect(pressApprove(mail).ok).toBe(true)
    const viaMail = ownerApproved('credit_gate_canary', canaryPayload(mail))
    expect(h.proc.consumeCanaryApproval(viaMail, CONFIG_HASH, TERMS('r'))).toMatchObject({ ok: false, reason: 'before_not_accepted' })
    h.calibrate(LB2, [P1('195.64'), P2('200.00')])
    const stale = ownerApproved('credit_gate_canary', canaryPayload(b, { budget_usd: '0.70' }))
    expect(h.proc.consumeCanaryApproval(stale, CONFIG_HASH, TERMS('r', { budget_micro: 700_000 }))).toMatchObject({ ok: false, reason: 'before_not_latest' })
    expect(getApproval(viaMail)!.consumed_at).toBeNull()
    expect(getApproval(stale)!.consumed_at).toBeNull()
  })
})

describe('the canary end to end: the after-reading decides (K-02, K-03)', () => {
  function startCanary(): { k: string; runId: string } {
    const b = h.calibrate(LB1, [P1('195.64'), P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    const k = ownerApproved('credit_gate_canary', canaryPayload(b))
    const runId = 'run-canary-1'
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS(runId))).toMatchObject({ ok: true })
    return { k, runId }
  }

  it('success: the hash is approved (canary.approved_hash), and handed over with its approval id', () => {
    const { k, runId } = startCanary()
    expect(approvedCanary(getDb())).toBeNull()
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: runId, est: 1000, cli: 300_000 })
    h.calibrate(LB2, [P1('195.34'), P2('200.00')])
    expect(h.canary(k)).toMatchObject({ status: 'success', after_calibration_id: h.calibrations()[1].id })
    expect(JSON.parse(h.canary(k)!.result_json as string)).toMatchObject({ outcome: 'success', grant: '2026-10-10|2026-10-17|200000000' })
    expect(approvedCanary(getDb())).toEqual({ approval_id: k, config_hash: CONFIG_HASH })
    expect(h.state().state).toBe('OPEN')
  })

  it('success with covered batch rows in the window (the 2026-10-16 measurement)', () => {
    const { runId } = startCanary()
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: runId, est: 1000, cli: 200_000 })
    h.row({ tsMs: LB1 + HOUR + 5000, est: 87_000, batch_id: 'msgbatch_hajcsar' })
    h.calibrate(LB2, [P1('195.36'), P2('200.00')])
    expect(approvedCanary(getDb())).toMatchObject({ config_hash: CONFIG_HASH })
  })

  it('INCIDENT: no Team grant fell -> the gate is in INCIDENT, no hash approved', () => {
    const { k, runId } = startCanary()
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: runId, est: 1000, cli: 300_000 })
    h.calibrate(LB2, [P1('195.64'), P2('200.00')])
    expect(h.canary(k)).toMatchObject({ status: 'incident' })
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'canary_no_grant_decreased' })
    expect(approvedCanary(getDb())).toBeNull()
  })

  it('undecidable: another headless run in the window -> HOLD, no hash approved', () => {
    const { k, runId } = startCanary()
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: runId, est: 1000, cli: 200_000 })
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: 'run-someone-else', est: 87_000 })
    h.calibrate(LB2, [P1('195.36'), P2('200.00')])
    expect(h.canary(k)).toMatchObject({ status: 'undecidable' })
    expect(h.state()).toEqual({ state: 'HOLD', reason: 'canary_undecidable' })
    expect(approvedCanary(getDb())).toBeNull()
  })

  it('a later failed canary withdraws an earlier approval', () => {
    const { runId } = startCanary()
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: runId, est: 1000, cli: 300_000 })
    const after = h.calibrate(LB2, [P1('195.34'), P2('200.00')])
    expect(approvedCanary(getDb())).not.toBeNull()
    const k2 = ownerApproved('credit_gate_canary', canaryPayload(after))
    expect(h.proc.consumeCanaryApproval(k2, CONFIG_HASH, TERMS('run-canary-2'))).toMatchObject({ ok: true })
    // No row for run-canary-2: the reading after cannot tell.
    h.now += 60_000
    h.calibrate(T0, [P1('195.34'), P2('200.00')])
    expect(h.canary(k2)).toMatchObject({ status: 'undecidable' })
    expect(approvedCanary(getDb())).toBeNull()
  })
})

// =====================================================================================
// The runtime wiring
// =====================================================================================

describe('runtime: the real calibration source and processor are wired in', () => {
  it('the default owner is the strict one: the configured user id, never a group or nothing', () => {
    mocked.allowedChatId = OWNER
    expect(strictOwnerUserId()).toBe(OWNER)
    mocked.allowedChatId = '-1001234567890'
    expect(strictOwnerUserId()).toBeNull()
    mocked.allowedChatId = ''
    expect(strictOwnerUserId()).toBeNull()
  })

  it('on the dashboard database the processor runs in the tick; an owner reading opens without any injected source', () => {
    ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    mocked.allowedChatId = OWNER
    try {
      const interval = startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: getDb(), storeDir: h.storeDir, now: () => h.now })
      clearInterval(interval)
      const rt = getCreditGateRuntime()
      expect(rt.calibrations).not.toBeNull()
      // The first run: tick, process, tick.
      expect(h.state().state).toBe('OPEN')
    } finally {
      mocked.allowedChatId = ''
      setCreditGateRuntime(null)
    }
  })

  it('without a configured owner nothing is processed: HOLD owner_unset', () => {
    const id = ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    try {
      clearInterval(startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: getDb(), storeDir: h.storeDir, now: () => h.now }))
      expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'owner_unset' })
      expect(getApproval(id)!.consumed_at).toBeNull()
    } finally {
      setCreditGateRuntime(null)
    }
  })
})

// =====================================================================================
// Review round (ellenőr + BE-3c on 642f697d): each finding pinned by a test that
// failed before the fix. P1..P7 are the BE-3c proofs, turned around.
// =====================================================================================

describe('0 (blocker): a protected store that fell is an INCIDENT before every other check', () => {
  const v999 = (lb: number) => readings(lb, [P2('200.00')], '3.63', '9.99')

  it('pure: in the future, too old, or not newer than the previous reading -- still INCIDENT', () => {
    expect(evaluateCalibration(v999(T0 + 60_000), ctx())).toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
    expect(evaluateCalibration(v999(T0 - 25 * HOUR), ctx())).toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
    expect(evaluateCalibration(v999(LB1 - 1000), ctx({ prev: readings(LB1, [P2('200.00')]) })))
      .toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
    // A rise is no decrease: the time rules still refuse it.
    expect(evaluateCalibration(readings(T0 + 60_000, [P2('200.00')], '3.63', '10.01'), ctx())).toMatchObject({ outcome: 'rejected' })
  })

  it('processing: a reading the ledger is not ready for is not deferred when V fell -- INCIDENT at once', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    ownerApproved('credit_gate_calibration', calPayload(h.now - 5_000, [P2('200.00')], '3.63', '9.99'))
    // The ledger was last read before this reading: a normal reading would wait.
    getDb().prepare('UPDATE credit_ledger_cursors SET checked_at = ?').run(h.now - 10_000)
    h.proc.process(h.now)
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'protected_decreased' })
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'incident' })
  })

  it('processing: an old (not newer) reading showing R below the baseline is an INCIDENT, not a refusal', () => {
    h.calibrate(LB2, [P2('200.00')])
    h.calibrate(LB1, [P2('200.00')], '3.50', '10.00')
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'protected_decreased' })
  })
})

describe('1 (HIGH): the owner is pinned at the first accepted reading; another configured owner is a HOLD', () => {
  const NEW_OWNER = '3000000003'

  it('owner change -> HOLD owner_changed; nothing of the new owner is processed; no canary', () => {
    const b = h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    h.ownerId = NEW_OWNER
    const byNew = ownerApproved('credit_gate_calibration', calPayload(LB2, [P2('200.00')]), NEW_OWNER)
    expect(h.cycle()).toEqual({ state: 'HOLD', reason: 'owner_changed' })
    expect(getApproval(byNew)!.consumed_at).toBeNull()
    expect(h.events('owner_changed')).toHaveLength(1)
    const k = ownerApproved('credit_gate_canary', canaryPayload(b), NEW_OWNER)
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('r'))).toMatchObject({ ok: false, reason: 'owner_changed' })
    // A second cycle: still HOLD, no second event.
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'HOLD', reason: 'owner_changed' })
    expect(h.events('owner_changed')).toHaveLength(1)
  })

  it('only a NEW incident-clear from the OLD owner, naming the owner_changed event, re-pins; then a later reading opens', () => {
    h.calibrate(LB1, [P2('200.00')])
    h.ownerId = NEW_OWNER
    h.cycle()
    const ev = h.events('owner_changed')[0].id as number
    // The new owner cannot clear it.
    const byNew = ownerApproved('credit_gate_incident_clear', incidentClear(ev), NEW_OWNER)
    h.cycle()
    expect(h.state()).toEqual({ state: 'HOLD', reason: 'owner_changed' })
    expect(getApproval(byNew)!.consumed_at).toBeNull()
    // An old-owner approval requested BEFORE the change is not "new".
    const stale = ownerApproved('credit_gate_incident_clear', incidentClear(ev), OWNER)
    getDb().prepare('UPDATE approvals SET requested_at = ? WHERE id = ?').run(Math.floor((T0 - HOUR) / 1000), stale)
    h.cycle()
    expect(getApproval(stale)!.consumed_at).toBeNull()
    expect(h.state().reason).toBe('owner_changed')
    // The old owner's fresh clear: re-pinned to the new owner; the HOLD waits for a newer reading.
    ownerApproved('credit_gate_incident_clear', incidentClear(ev), OWNER)
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'HOLD', reason: 'owner_changed' })
    const clearedAt = h.now
    h.now += 30_000
    // A reading of the new owner taken before that clear does not count.
    ownerApproved('credit_gate_calibration', calPayload(clearedAt - 1000, [P2('200.00')]), NEW_OWNER)
    h.cycle()
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'rejected', reason: 'captured_before_clear' })
    expect(h.state().state).toBe('HOLD')
    // Pressed by the old owner (the helper's default): no longer the configured owner, not processed.
    h.calibrate(h.now - 5_000, [P2('200.00')])
    expect(h.state().state).toBe('HOLD')
    ownerApproved('credit_gate_calibration', calPayload(h.now - 4_000, [P2('200.00')]), NEW_OWNER)
    h.cycle()
    expect(h.state().state).toBe('OPEN')
  })
})

describe('2 (MED-1) / BE-3c P1: every INCIDENT cause has its own event; a clear lifts only the newest one', () => {
  it('two causes: two events; the older one cannot be cleared first; each clear lifts one; then a later reading opens', () => {
    h.calibrate(LB1, [P2('200.00')])
    h.gate.raiseIncident('protected_decreased', { store: 'V' }, h.now)
    const e1 = h.stateRow().incident_event_id as number
    h.gate.raiseIncident('canary_no_grant_decreased', { canary: 'x' }, h.now)
    const e2 = h.stateRow().incident_event_id as number
    expect(e2).not.toBe(e1)
    expect(h.events('incident_cause').map((e) => [e.id, e.reason])).toEqual([[e2, 'canary_no_grant_decreased']])
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'canary_no_grant_decreased' })
    // The owner's text can be built for either event (the notifier needs it for the buttons).
    expect(creditGateIncidentEvent(e1)).toMatchObject({ reason: 'protected_decreased' })
    expect(creditGateIncidentEvent(e2)).toMatchObject({ reason: 'canary_no_grant_decreased' })
    // The clear of e1 (not the newest open one): consumed, refused.
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 30_000
    h.cycle()
    expect(h.state().state).toBe('INCIDENT')
    expect(h.stateRow().incident_event_id).toBe(e2)
    // e2 cleared: e1 is still open -> INCIDENT stays.
    ownerApproved('credit_gate_incident_clear', incidentClear(e2))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'INCIDENT', reason: 'protected_decreased' })
    expect(h.stateRow().incident_event_id).toBe(e1)
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.now += 30_000
    h.calibrate(h.now - 5_000, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
  })

  it('the guard cursor is reset only by the clear of a guard cause', () => {
    h.calibrate(LB1, [P2('200.00')])
    getDb().prepare('UPDATE credit_gate_state SET guard_cursor_json = ? WHERE id = 1').run(JSON.stringify({ broken: 'guard_events_truncated' }))
    h.now += 30_000
    h.cycle()
    expect(h.state()).toEqual({ state: 'INCIDENT', reason: 'guard_events_truncated' })
    const eg = h.stateRow().incident_event_id as number
    h.gate.raiseIncident('protected_decreased', null, h.now)
    const en = h.stateRow().incident_event_id as number
    ownerApproved('credit_gate_incident_clear', incidentClear(en))
    h.now += 30_000
    h.cycle()
    // A non-guard clear: the cursor stays broken, the guard cause stays open (no new event for it either).
    expect(String(h.stateRow().guard_cursor_json)).toContain('broken')
    expect(h.stateRow().incident_event_id).toBe(eg)
    expect(h.events('incident_cause')).toHaveLength(1)
    ownerApproved('credit_gate_incident_clear', incidentClear(eg))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    expect(String(h.stateRow().guard_cursor_json)).not.toContain('broken')
  })
})

describe('3 (MED-2) / BE-3c P7: after an incident-clear only a reading taken after the INCIDENT and the clear opens', () => {
  it('credit_balance_too_low -> clear -> a reading from before is refused; one from after the clear opens', () => {
    h.calibrate(LB1, [P2('200.00')])
    h.gate.signal('credit_balance_too_low', 'batch', null, h.now)
    const e1 = h.stateRow().incident_event_id as number
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 60_000
    expect(h.cycle().state).toBe('CLOSED')
    const clearedAt = h.now
    h.now += 60_000
    h.calibrate(T0 - 30 * 60_000, [P2('200.00')])
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'rejected', reason: 'captured_before_clear' })
    expect(h.state().state).toBe('CLOSED')
    h.calibrate(clearedAt - 1000, [P2('200.00')])
    expect(h.calibrations().at(-1)).toMatchObject({ outcome: 'rejected', reason: 'captured_before_clear' })
    h.calibrate(clearedAt, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
  })
})

describe('4 (MED-3) / BE-3c P2: the window basis must not hide the canary', () => {
  const before = readings(LB1, [P2('200.00')])
  const canary = { run_id: 'run-c', min_expected_micro: 100_000 }

  it('the grant fell by exactly the other rows: undecidable (0.2 x 2.00 = 0.40 >= the canary 0.30)', () => {
    expect(evaluateCanary(before, readings(LB2, [P2('198.00')]), [usageRow(2_000_000), headlessRow('run-c', 300_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'window_hides_canary' })
  })

  it('the full 0.89 budget against 3.60 USD of other rows: the grant fell by the others only -> undecidable', () => {
    expect(evaluateCanary(before, readings(LB2, [P2('196.40')]), [usageRow(3_600_000), headlessRow('run-c', 890_000)], canary))
      .toMatchObject({ outcome: 'undecidable' })
  })

  it('the measured case still succeeds: 0.087 of batch rows, canary 0.20, the grant fell 0.28', () => {
    expect(evaluateCanary(before, readings(LB2, [P2('199.72')]), [usageRow(87_000, { batch_id: 'msgbatch_x' }), headlessRow('run-c', 200_000)], canary))
      .toMatchObject({ outcome: 'success', basis: 'window' })
  })

  it('the border: max(0.05, 0.2 W) must be strictly below the canary', () => {
    // W = 1.00 -> 0.20; a canary of exactly 0.20 is not enough, 0.21 is.
    expect(evaluateCanary(before, readings(LB2, [P2('198.80')]), [usageRow(1_000_000), headlessRow('run-c', 200_000)], canary))
      .toMatchObject({ outcome: 'undecidable', reason: 'window_hides_canary' })
    expect(evaluateCanary(before, readings(LB2, [P2('198.79')]), [usageRow(1_000_000), headlessRow('run-c', 210_000)], canary))
      .toMatchObject({ outcome: 'success', basis: 'window' })
  })
})

describe('5 (LOW-1) / BE-3c P6: a "new" grant that cannot be new is a HOLD', () => {
  const Q1: G = ['2026-10-09', '2026-10-16T06:00:00Z', '200.00', '150.00']
  const Q1b: G = ['2026-10-09', '2026-10-17', '200.00', '150.00']

  it('an expired grant re-entered with another expiry', () => {
    expect(evaluateCalibration(readings(LB2, [Q1b, P2('200.00')]), ctx({ prev: readings(LB1, [Q1, P2('200.00')]), window: [] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'grant_reappeared' } })
  })

  it('a grant credited on a day before the previous reading', () => {
    expect(evaluateCalibration(readings(LB2, [P2('200.00'), ['2026-10-15', '2026-12-31', '200.00', '200.00']]),
      ctx({ prev: readings(LB1, [P2('200.00')]), window: [] })))
      .toMatchObject({ outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'grant_new_but_old' } })
    // Credited on the previous reading's own day: it may have come after it.
    expect(evaluateCalibration(readings(LB2, [P2('200.00'), ['2026-10-16', '2026-12-31', '200.00', '200.00']]),
      ctx({ prev: readings(LB1, [P2('200.00')]), window: [] })))
      .toMatchObject({ outcome: 'accepted', reconcile: { new_grants: 1 } })
  })

  it('processing: R_est does not count the re-entered grant again', () => {
    h.calibrate(LB1, [Q1, P2('200.00')])
    h.calibrate(LB2, [Q1b, P2('200.00')])
    expect(h.state()).toEqual({ state: 'HOLD', reason: 'b05_undecidable' })
  })
})

describe('6 (LOW-2) / BE-3c P3: legacy-approved rows cannot push the owner\'s approval out of the window', () => {
  it('500 newer legacy-PATCH calibration requests: the owner\'s older one is still processed', () => {
    const genuine = ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]))
    getDb().prepare('UPDATE approvals SET requested_at = requested_at - 3600 WHERE id = ?').run(genuine)
    for (let i = 0; i < 500; i++) {
      const id = requestApproval('credit_gate_calibration', calPayload(LB1 + (i + 1) * 1000, [P2('200.00')]))
      resolveApproval(id, 'approved', 'brainy')
    }
    h.cycle()
    expect(h.calibrations()).toMatchObject([{ approval_id: genuine, outcome: 'accepted' }])
    expect(h.state().state).toBe('OPEN')
  })
})

describe('8: the gaps the mutants found', () => {
  it('a canary whose after-reading shows V fell is recorded as an INCIDENT (K-03), not left open', () => {
    const b = h.calibrate(LB1, [P1('195.64'), P2('200.00')])
    const k = ownerApproved('credit_gate_canary', canaryPayload(b))
    expect(h.proc.consumeCanaryApproval(k, CONFIG_HASH, TERMS('run-k'))).toMatchObject({ ok: true })
    h.row({ tsMs: LB1 + HOUR, source: 'headless', run_id: 'run-k', est: 1000, cli: 300_000 })
    h.calibrate(LB2, [P1('195.34'), P2('200.00')], '3.63', '9.99')
    expect(h.canary(k)).toMatchObject({ status: 'incident' })
    expect(JSON.parse(h.canary(k)!.result_json as string)).toMatchObject({ outcome: 'incident', reason: 'protected_decreased' })
    expect(h.state().state).toBe('INCIDENT')
  })

  it('V or R rising during the canary is not a success: undecidable, HOLD (a purchase could hide a charge to V)', () => {
    const before = readings(LB1, [P2('200.00')])
    const run = [headlessRow('run-c', 300_000)]
    expect(evaluateCanary(before, readings(LB2, [P2('199.70')], '3.63', '10.50'), run, { run_id: 'run-c', min_expected_micro: 100_000 }))
      .toMatchObject({ outcome: 'undecidable', reason: 'protected_changed' })
    expect(evaluateCanary(before, readings(LB2, [P2('199.70')], '3.70', '10.00'), run, { run_id: 'run-c', min_expected_micro: 100_000 }))
      .toMatchObject({ outcome: 'undecidable', reason: 'protected_changed' })
  })

  it('ledgerReady: a source read before the reading, or read too long ago, defers it', () => {
    h.calibrate(LB1, [P2('200.00')])
    const id = ownerApproved('credit_gate_calibration', calPayload(LB2, [P2('200.00')]))
    getDb().prepare('UPDATE credit_ledger_cursors SET checked_at = ?').run(LB2 - 1)
    h.proc.process(h.now)
    expect(getApproval(id)!.consumed_at).toBeNull()
    getDb().prepare('UPDATE credit_ledger_cursors SET checked_at = ?').run(h.now - 121_000)
    h.proc.process(h.now)
    expect(getApproval(id)!.consumed_at).toBeNull()
    getDb().prepare('UPDATE credit_ledger_cursors SET checked_at = ?').run(h.now - 120_000)
    h.proc.process(h.now)
    expect(getApproval(id)!.consumed_at).not.toBeNull()
  })

  it('a stored reading that no longer matches its hash is never the calibration, nor the previous reading', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    const row = h.calibrations()[0]
    const forged = canon(calPayload(LB1, [P2('999.00')]))
    getDb().prepare('UPDATE credit_calibrations SET readings_json = ? WHERE id = ?').run(forged, row.id)
    h.now += 30_000
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
    ownerApproved('credit_gate_calibration', calPayload(LB2, [P2('200.00')]))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'HOLD', reason: 'calibration_error' })
  })

  it('a row and its approval rewritten alike, their hashes kept: the hash check refuses it', () => {
    h.calibrate(LB1, [P2('100.00')])
    expect(h.state().state).toBe('OPEN')
    const row = h.calibrations()[0]
    const forged = canon(calPayload(LB1, [['2026-10-14', '2026-11-17', '999.00', '999.00']]))
    getDb().prepare('UPDATE credit_calibrations SET readings_json = ? WHERE id = ?').run(forged, row.id)
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(forged, row.approval_id)
    h.now += 30_000
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
  })

  it('9: a stored row re-hashed to forged readings is refused: it must still be the approval it came from', () => {
    h.calibrate(LB1, [P2('100.00')])
    expect(h.state().state).toBe('OPEN')
    const row = h.calibrations()[0]
    // A valid reading in itself (999 of 999), with a hash that matches it.
    const forged = canon(calPayload(LB1, [['2026-10-14', '2026-11-17', '999.00', '999.00']]))
    expect(parseReadings(forged).ok).toBe(true)
    getDb().prepare('UPDATE credit_calibrations SET readings_json = ?, content_hash = ? WHERE id = ?').run(forged, sha(forged), row.id)
    h.now += 30_000
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
  })

  it('a consume that fails rolls the whole step back: no row, no state change', () => {
    h.calibrate(LB1, [P2('200.00')])
    const id = ownerApproved('credit_gate_calibration', calPayload(LB2, [P2('200.00')], '3.63', '9.99'))
    h.consumeOverride = () => ({ ok: false, reason: 'already_consumed' })
    h.cycle()
    expect(h.calibrations()).toHaveLength(1)
    expect(h.state().state).toBe('OPEN')
    expect(getApproval(id)!.consumed_at).toBeNull()
  })
})

// =====================================================================================
// BE-3c round 2 (on df543822): P9, P1b and the N8 gap.
// =====================================================================================

describe('LOW-A / BE-3c P9: the owner comes from .env ALLOWED_CHAT_ID only, never from access.json', () => {
  afterEach(() => {
    mocked.allowedChatId = ''
    mocked.accessJson = null
  })

  it('strictOwnerUserId: an empty or placeholder ALLOWED_CHAT_ID is no owner, whatever access.json says', () => {
    mocked.accessJson = JSON.stringify({ allowFrom: [STRANGER] })
    for (const v of ['', ' ', '0', 'your_chat_id', '-1001234567890', '01000000001']) {
      mocked.allowedChatId = v
      expect(strictOwnerUserId(), JSON.stringify(v)).toBeNull()
    }
    mocked.allowedChatId = OWNER
    expect(strictOwnerUserId()).toBe(OWNER)
  })

  it('no trust on first use: with ALLOWED_CHAT_ID empty, an access.json user\'s reading is not pinned nor processed -- HOLD owner_unset', () => {
    mocked.allowedChatId = ''
    mocked.accessJson = JSON.stringify({ allowFrom: [STRANGER] })
    const id = ownerApproved('credit_gate_calibration', calPayload(LB1, [P2('200.00')]), STRANGER)
    try {
      clearInterval(startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: getDb(), storeDir: h.storeDir, now: () => h.now }))
      expect(h.state()).toEqual({ state: 'HOLD', reason: 'owner_unset' })
      expect(getApproval(id)!.consumed_at).toBeNull()
      expect((getDb().prepare('SELECT owner_id FROM credit_calibration_state WHERE id = 1').get() as { owner_id: string | null }).owner_id).toBeNull()
    } finally {
      setCreditGateRuntime(null)
    }
  })

  it('owner_unset is raised once, not on every pass, and a configured owner\'s newer reading lifts it', () => {
    h.ownerId = null
    h.cycle()
    h.now += 30_000
    h.cycle()
    expect(h.events('transition').filter((e) => e.reason === 'owner_unset')).toHaveLength(1)
    // A further pass does not even write the state row again.
    const version = h.stateRow().version
    h.proc.process(h.now)
    expect(h.stateRow().version).toBe(version)
    h.ownerId = OWNER
    h.now += 30_000
    h.calibrate(h.now - 5_000, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
  })
})

describe('LOW-B / BE-3c P1b: the same reason with another detail is a cause of its own', () => {
  it('credit_balance_too_low twice: two events; the older clear is refused; both clears are needed', () => {
    h.calibrate(LB1, [P2('200.00')])
    h.gate.raiseIncident('credit_balance_too_low', { n: 1 }, h.now)
    const e1 = h.stateRow().incident_event_id as number
    h.now += 30 * 60_000
    h.gate.raiseIncident('credit_balance_too_low', { n: 2 }, h.now)
    const e2 = h.stateRow().incident_event_id as number
    expect(e2).not.toBe(e1)
    // The very same cause again (same reason, same detail): no new event.
    h.gate.raiseIncident('credit_balance_too_low', { n: 2 }, h.now)
    expect(h.stateRow().incident_event_id).toBe(e2)
    expect(h.events('incident_cause')).toHaveLength(1)
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 60_000
    expect(h.cycle().state).toBe('INCIDENT')
    expect(h.stateRow().incident_event_id).toBe(e2)
    ownerApproved('credit_gate_incident_clear', incidentClear(e2))
    h.now += 60_000
    expect(h.cycle().state).toBe('INCIDENT')
    expect(h.stateRow().incident_event_id).toBe(e1)
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 60_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
  })

  it('B10: a signal\'s cause is its kind only: credit-too-low from another source or with another detail joins the open cause', () => {
    h.calibrate(LB1, [P2('200.00')])
    h.gate.signal('credit_balance_too_low', 'batch', 'job 1', h.now)
    const e1 = h.stateRow().incident_event_id as number
    h.gate.signal('credit_balance_too_low', 'headless', 'run 7', h.now)
    h.gate.signal('credit_balance_too_low', 'headless', 'run 7', h.now)
    expect(h.stateRow().incident_event_id).toBe(e1)
    expect(JSON.parse(String(h.stateRow().incident_open_json))).toHaveLength(1)
    expect(h.events('incident_cause')).toHaveLength(0)
    // Source and detail stay in the signal's own audit row; the cause's row only names that row.
    const signals = h.events('signal')
    expect(signals.map((s) => JSON.parse(String(s.detail_json)))).toEqual([
      { source: 'batch', detail: 'job 1' }, { source: 'headless', detail: 'run 7' }, { source: 'headless', detail: 'run 7' },
    ])
    const entry = h.events('transition').find((e) => e.id === e1) as Record<string, unknown>
    expect(JSON.parse(String(entry.detail_json))).toEqual({ signal_event_id: signals[0]!.id })
    // One clear lifts it; a signal after the clear is a new INCIDENT of its own.
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 60_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.gate.signal('credit_balance_too_low', 'batch', 'job 2', h.now)
    expect(h.stateRow().state).toBe('INCIDENT')
    expect(h.stateRow().incident_event_id).not.toBe(e1)
  })

  it('B10: a signal opens at most one cause per signal kind, also beside a genuine cause of the same reason, and a genuine one still opens beside it', () => {
    h.calibrate(LB1, [P2('200.00')])
    const open = () => JSON.parse(String(h.stateRow().incident_open_json)) as Array<{ event_id: number; reason: string }>
    const causeRows = () => [...h.events('transition'), ...h.events('incident_cause')]
    const bySignal = (c: { event_id: number }) => 'signal_event_id' in JSON.parse(String(causeRows().find((e) => e.id === c.event_id)?.detail_json ?? '{}'))
    // A genuine cause of the reason first, then a flood of that signal kind: ONE signal cause beside it, not one per signal.
    h.gate.raiseIncident('credit_balance_too_low', { n: 1 }, h.now)
    for (let i = 0; i < 20; i++) h.gate.signal('credit_balance_too_low', `src-${i}`, `d${i}`, h.now)
    expect(open().map((c) => [c.reason, bySignal(c)])).toEqual([['credit_balance_too_low', false], ['credit_balance_too_low', true]])
    // Genuine causes still open beside the signal's: another reason, and another detail of the same reason.
    h.gate.raiseIncident('protected_decreased', { store: 'V' }, h.now)
    h.gate.raiseIncident('credit_balance_too_low', { n: 2 }, h.now)
    for (let i = 20; i < 40; i++) h.gate.signal('credit_balance_too_low', `src-${i}`, `d${i}`, h.now)
    expect(open().map((c) => [c.reason, bySignal(c)])).toEqual([
      ['credit_balance_too_low', false], ['credit_balance_too_low', true], ['protected_decreased', false], ['credit_balance_too_low', false],
    ])
    expect(h.events('incident_cause')).toHaveLength(3)
    expect(h.events('signal')).toHaveLength(40)
  })

  it('a second guard event with another key name during the INCIDENT gets its own event and its own clear', () => {
    h.calibrate(LB1, [P2('200.00')])
    const guard = join(h.storeDir, 'interactive-key-guard-events.jsonl')
    const line = (name: string) => JSON.stringify({ ts: '2026-10-16T08:00:00Z', source: 'tmux', where: 'global', names: [name] }) + '\n'
    writeFileSync(guard, line('ANTHROPIC_API_KEY'))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'INCIDENT', reason: 'guard_event' })
    const e1 = h.stateRow().incident_event_id as number
    writeFileSync(guard, line('ANTHROPIC_API_KEY') + line('ANTHROPIC_AUTH_TOKEN'))
    h.now += 30_000
    h.cycle()
    const e2 = h.stateRow().incident_event_id as number
    expect(e2).not.toBe(e1)
    expect(h.events('incident_cause').map((e) => e.reason)).toEqual(['guard_event'])
    ownerApproved('credit_gate_incident_clear', incidentClear(e2))
    h.now += 30_000
    expect(h.cycle().state).toBe('INCIDENT')
    expect(h.stateRow().incident_event_id).toBe(e1)
    ownerApproved('credit_gate_incident_clear', incidentClear(e1))
    h.now += 30_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
  })
})

describe('N8: a calibration row whose approval the gate did not consume', () => {
  it('consumed_by other than credit-gate: not the calibration, the gate closes', () => {
    h.calibrate(LB1, [P2('200.00')])
    expect(h.state().state).toBe('OPEN')
    getDb().prepare("UPDATE approvals SET consumed_by = 'someone-else' WHERE id = ?").run(h.calibrations()[0].approval_id)
    h.now += 30_000
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
  })
})
