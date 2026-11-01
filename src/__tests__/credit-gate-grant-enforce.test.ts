import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import net from 'node:net'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Credit gate grant_model, node N2 (card 40e03382): the ONE owner button
// (credit_gate_enforce), the period rows the tick advances, and the source the
// gate reads them through. Written from the spec (4, 5: A2, A3, A6, A7, A9,
// A10) and the blueprint (N2), not from the code.
//
// Everything runs in-process on a tmp store and a tmp SQLite file; the
// approvals are created and decided through db.ts exactly as the owner's
// Telegram button (resolveApprovalFromTelegram) and the legacy PATCH
// (resolveApproval) decide them. No live dashboard, store, Telegram or API.
// A process-level guard refuses every non-loopback connect() and the live CDP
// ports (18800, 18899) before the connect, self-tested against this file's own
// blocked port 18997.

const mocked = vi.hoisted(() => ({ allowedChatId: '' }))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return { ...real, get ALLOWED_CHAT_ID() { return mocked.allowedChatId } }
})

import {
  initDatabase, getDb, getApproval, createApproval, setApprovalCallbackNonceHashes, setApprovalTelegramMessageId,
  resolveApprovalFromTelegram, resolveApproval, isOwnerVerified, consumeCreditGateApproval, consumeCategoryApproval,
  TELEGRAM_BUTTON_CATEGORIES,
} from '../db.js'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { CreditGate } from '../web/credit-gate/gate.js'
import {
  fileGateDeps, getCreditGateRuntime, loadPricingFile, setCreditGateRuntime, startCreditGateRuntime,
} from '../web/credit-gate/runtime.js'
import { loadCreditGateConfigFile, readCreditGateMode } from '../web/credit-gate/config.js'
import { CalibrationProcessor, calibrationSource } from '../web/credit-gate/calibration.js'
import {
  CREDIT_GATE_APPROVAL_CATEGORIES,
  claimsCreditGatePrefix,
  creditGateBinding,
  isCreditGateCategory,
  parseCreditGatePayload,
} from '../web/credit-gate/approval-payload.js'
import { grantModelHash } from '../web/credit-gate/grant-model.js'
import { dispatchCalibrationSource, GRANT_CONSUMER } from '../web/credit-gate/grant-period.js'
import { buildCreditGateApprovalText } from '../web/approval-telegram-text.js'
import { configObject, pricingText, USD } from './fixtures/credit-gate/gate-harness.js'

const OWNER = '1000000001'
const STRANGER = '2000000002'
const NEW_OWNER = '3000000003'

// --- network guard (self-tested) ----------------------------------------------------

const BLOCKED_PORTS = new Set([18800, 18899, 18997])
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
      throw new Error(`credit-gate N2 test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  globalThis.fetch = (() => { throw new Error('credit-gate N2 test guard: fetch is not allowed') }) as typeof fetch
  scratch = mkdtempSync(join(tmpdir(), 'cg-n2-grant-'))
})

afterAll(() => {
  net.Socket.prototype.connect = origConnect
  globalThis.fetch = origFetch
  if (scratch) rmSync(scratch, { recursive: true, force: true })
})

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    expect(() => net.connect({ host: '127.0.0.1', port: 18997 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
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

const HASH_A = 'a1'.repeat(32)
const CONFIG_HASH = 'c0ffee'.padEnd(64, '7')
const CANARY_TERMS = {
  config_hash: CONFIG_HASH,
  model: 'claude-sonnet-5-5',
  budget_usd: '0.99',
  min_expected_usd: '0.10',
  node: 'N9x',
  cwd: '/Volumes/8T/10_LOCAL/Brainy/n2-grant-test',
  prompt_sha256: 'cd'.repeat(32),
}

function enforcePayload(hash: string, over: Record<string, unknown> = {}, canary: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, kind: 'credit_gate_enforce', grant_model_hash: hash, mode: 'enforce', canary: { ...CANARY_TERMS, ...canary }, ...over }
}

let msgSeq = 19000

function requestApproval(category: string, payload: Record<string, unknown> | string): string {
  const text = typeof payload === 'string' ? payload : canon(payload)
  const id = randomUUID()
  createApproval({
    id, agent_id: 'brainy', category, action_description: 'n2 grant test', action_payload: text,
    timeout_at: Math.floor(Date.now() / 1000) + 3600, content_hash: sha(text),
  })
  return id
}

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

/** Decided `seconds` earlier: the approval row and the owner's button trace both (isOwnerVerified compares them). */
function backdate(id: string, seconds: number): void {
  const db = getDb()
  db.prepare('UPDATE approvals SET resolved_at = resolved_at - ? WHERE id = ?').run(seconds, id)
  db.prepare('UPDATE approval_owner_resolutions SET resolved_at = resolved_at - ? WHERE approval_id = ?').run(seconds, id)
}

const incidentClear = (id: number) => ({ v: 1, kind: 'credit_gate_incident_clear', incident_event_id: id })

// 2026-10-20 12:00Z (before the real clock, so the approvals' real decision times are never earlier than the processor's clock).
// With grantDays [15] and no lead the period is 10-15 00:00Z .. 11-15 00:00Z.
const NOW0 = Date.UTC(2026, 9, 20, 12)
const P1 = { lb: Date.UTC(2026, 9, 15), expires: Date.UTC(2026, 10, 15) }
const P2 = { lb: Date.UTC(2026, 10, 15), expires: Date.UTC(2026, 11, 15) }
const BOUNDARY_AFTER = Date.UTC(2026, 10, 15, 0, 0, 30)

function grantBlock(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { grantUsd: '200.00', grantDays: [15], boundaryLeadH: 0, ...over }
}

interface GhOptions {
  readonly calibrationSource?: 'console' | 'grant_model'
  readonly grantModel?: Record<string, unknown> | null
}

class GH {
  readonly dir: string
  readonly storeDir: string
  readonly gateDir: string
  readonly cfgPath: string
  readonly pricingPath: string
  readonly usagePath: string
  now = NOW0
  ownerId: string | null = OWNER
  consumeOverride: ((p: Parameters<typeof consumeCreditGateApproval>[0]) => ReturnType<typeof consumeCreditGateApproval>) | null = null
  readonly gate: CreditGate
  readonly proc: CalibrationProcessor
  readonly source: ReturnType<typeof dispatchCalibrationSource>

  constructor(o: GhOptions = {}) {
    this.dir = mkdtempSync(join(scratch, 'g-'))
    this.storeDir = join(this.dir, 'store')
    this.gateDir = join(this.storeDir, 'credit-gate')
    mkdirSync(this.gateDir, { recursive: true, mode: 0o700 })
    chmodSync(this.storeDir, 0o700)
    chmodSync(this.gateDir, 0o700)
    this.usagePath = join(this.dir, 'usage.jsonl')
    writeFileSync(this.usagePath, '')
    mkdirSync(join(this.dir, 'batch'))
    this.cfgPath = join(this.gateDir, 'config.json')
    const source = o.calibrationSource ?? 'grant_model'
    const cfg: Record<string, unknown> = { ...configObject(this.usagePath, join(this.dir, 'batch', 'STOP')), calibrationSource: source }
    const gm = o.grantModel === undefined ? grantBlock() : o.grantModel
    if (gm !== null) cfg.grantModel = gm
    this.writeConfig(cfg)
    this.pricingPath = join(this.gateDir, 'pricing.json')
    writeFileSync(this.pricingPath, pricingText('2026-10-18'), { mode: 0o600 })
    initDatabase(join(this.dir, 'claudeclaw.db'))
    const db = getDb()
    applyCreditGateSchema(db)
    const loadConfig = () => loadCreditGateConfigFile(this.cfgPath)
    this.source = dispatchCalibrationSource(calibrationSource(db), db, loadConfig)
    this.gate = new CreditGate(fileGateDeps({
      storeDir: this.storeDir, db, mode: readCreditGateMode('enforce'), calibration: this.source, now: () => this.now,
    }))
    this.proc = new CalibrationProcessor({
      db,
      gate: this.gate,
      loadConfig,
      loadPricing: (nowMs) => loadPricingFile(this.pricingPath, nowMs),
      ownerId: () => this.ownerId,
      now: () => this.now,
      consume: (p) => (this.consumeOverride ?? consumeCreditGateApproval)(p),
    })
  }

  writeConfig(cfg: Record<string, unknown>): void {
    writeFileSync(this.cfgPath, JSON.stringify(cfg), { mode: 0o600 })
    chmodSync(this.cfgPath, 0o600)
  }

  /** Read-modify-write of the config file. */
  editConfig(fn: (cfg: Record<string, unknown>) => void): void {
    const cfg = JSON.parse(readFileSync(this.cfgPath, 'utf8')) as Record<string, unknown>
    fn(cfg)
    this.writeConfig(cfg)
  }

  /** grantModelHash of the config file as it is now (the reconstructed file measured). */
  hash(): string {
    const r = loadCreditGateConfigFile(this.cfgPath)
    if (!r.ok) throw new Error(`config: ${r.reason}`)
    const rc = r.config.grantModel?.reconstructed ?? null
    return grantModelHash(r.config, rc === null ? null : sha(readFileSync(rc.path, 'utf8')))
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

  periods(): Array<Record<string, unknown> & { id: number; approval_id: string; lb: number; expires: number; remaining_micro: number }> {
    return getDb().prepare('SELECT * FROM credit_grant_periods ORDER BY id').all() as never
  }

  canaries(): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_canaries ORDER BY consumed_at, approval_id').all() as never
  }

  calState(): { owner_id: string | null; min_captured_at_lb: number | null } {
    return getDb().prepare('SELECT owner_id, min_captured_at_lb FROM credit_calibration_state WHERE id = 1').get() as never
  }

  events(kind: string): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_gate_events WHERE kind = ? ORDER BY id').all(kind) as Array<Record<string, unknown>>
  }

  /** The owner's one button for the config as it is now; processed. Returns the approval id. */
  enforce(over: Record<string, unknown> = {}): string {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(this.hash(), over))
    this.cycle()
    return id
  }

  /** A Console row, accepted, with an explicit id (the shared id space is the point). */
  consoleRow(id: number): void {
    getDb().prepare(`INSERT INTO credit_calibrations (id, approval_id, captured_at_lb, readings_json, content_hash, accepted_at, outcome)
      VALUES (?, ?, ?, '{}', ?, ?, 'accepted')`).run(id, randomUUID(), this.now - 3_600_000, 'a'.repeat(64), this.now)
  }

  cleanup(): void {
    rmSync(this.dir, { recursive: true, force: true })
  }
}

let h: GH
beforeEach(() => {
  h = new GH()
})
afterEach(() => {
  h?.cleanup()
  mocked.allowedChatId = ''
})

// =====================================================================================
// The payload and the category (spec 4)
// =====================================================================================

describe('credit_gate_enforce: the category and its payload (spec 4)', () => {
  const parse = (v: unknown) => parseCreditGatePayload('credit_gate_enforce', canon(v))
  const field = (v: unknown) => { const r = parse(v); return r.ok ? 'OK' : r.field }

  it('is a credit-gate button category, in the reserved prefix, and never consumed by the generic consume', () => {
    expect(CREDIT_GATE_APPROVAL_CATEGORIES).toContain('credit_gate_enforce')
    expect(isCreditGateCategory('credit_gate_enforce')).toBe(true)
    expect(claimsCreditGatePrefix(' Credit_Gate_Enforce ')).toBe(true)
    expect(TELEGRAM_BUTTON_CATEGORIES).toContain('credit_gate_enforce')
    const id = ownerApproved('credit_gate_enforce', enforcePayload(HASH_A))
    const text = canon(enforcePayload(HASH_A))
    expect(consumeCategoryApproval({ id, category: 'credit_gate_enforce', contentHash: sha(text), consumer: 'x', windowSeconds: 3600 }))
      .toMatchObject({ ok: false, reason: 'wrong_category' })
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('accepts the canonical payload with the canary terms of the canary rules (a 0.99 USD canary)', () => {
    const r = parse(enforcePayload(HASH_A))
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.contentHash).toBe(sha(canon(enforcePayload(HASH_A))))
    expect(r.payload).toMatchObject({ kind: 'credit_gate_enforce', mode: 'enforce', grant_model_hash: HASH_A })
    expect(creditGateBinding({ category: 'credit_gate_enforce', content_hash: r.contentHash, action_payload: r.canonical })).toMatchObject({ bound: true })
    expect(creditGateBinding({ category: 'credit_gate_enforce', content_hash: sha('x'), action_payload: r.canonical })).toMatchObject({ bound: false, reason: 'hash_mismatch' })
  })

  it('the canary budget stays strictly below 1 USD (the limit is not raised), and the minimum rules hold', () => {
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '0.99', min_expected_usd: '0.99' }))).toBe('OK')
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '1.00' }))).toBe('canary.budget_usd')
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '2.00' }))).toBe('canary.budget_usd')
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '0.00', min_expected_usd: '0.00' }))).toBe('canary.budget_usd')
    expect(field(enforcePayload(HASH_A, {}, { min_expected_usd: '0.09' }))).toBe('canary.min_expected_usd')
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '0.50', min_expected_usd: '0.51' }))).toBe('canary.min_expected_usd')
    expect(field(enforcePayload(HASH_A, {}, { budget_usd: '0.9' }))).toBe('canary.budget_usd')
  })

  it('every other field is closed: keys, mode, hash, model, run terms, canonical form', () => {
    expect(field({ ...enforcePayload(HASH_A), extra: 1 })).toBe('keys')
    expect(field(enforcePayload(HASH_A, { mode: 'shadow' }))).toBe('mode')
    expect(field(enforcePayload('nothex'))).toBe('grant_model_hash')
    expect(field(enforcePayload(HASH_A.toUpperCase()))).toBe('grant_model_hash')
    expect(field(enforcePayload(HASH_A, { kind: 'credit_gate_canary' }))).toBe('kind')
    expect(field(enforcePayload(HASH_A, {}, { model: 'gpt-6' }))).toBe('canary.model')
    expect(field(enforcePayload(HASH_A, {}, { config_hash: 'abc' }))).toBe('canary.config_hash')
    expect(field(enforcePayload(HASH_A, {}, { node: 'bad node' }))).toBe('canary.node')
    expect(field(enforcePayload(HASH_A, {}, { cwd: 'relative/dir' }))).toBe('canary.cwd')
    expect(field(enforcePayload(HASH_A, {}, { prompt_sha256: 'cd' }))).toBe('canary.prompt_sha256')
    const noCanary = enforcePayload(HASH_A) as Record<string, unknown>
    delete noCanary.canary
    expect(field(noCanary)).toBe('keys')
    const noBudget = enforcePayload(HASH_A) as { canary: Record<string, unknown> }
    delete noBudget.canary.budget_usd
    expect(field(noBudget)).toBe('canary.keys')
    // Another before-calibration field has no place here: there is no Console reading to follow.
    expect(field(enforcePayload(HASH_A, {}, { before_calibration_id: randomUUID() }))).toBe('canary.keys')
    const pretty = JSON.stringify(enforcePayload(HASH_A), null, 1)
    expect(parseCreditGatePayload('credit_gate_enforce', pretty)).toMatchObject({ ok: false, field: 'canonical_form' })
    expect(parseCreditGatePayload('credit_gate_calibration', canon(enforcePayload(HASH_A)))).toMatchObject({ ok: false })
  })

  it('the owner\'s button message shows the hash, enforce and every canary term', () => {
    const p = parse(enforcePayload(HASH_A))
    if (!p.ok) throw new Error(p.field)
    const text = buildCreditGateApprovalText(p.payload, { agentId: 'brainy', category: 'credit_gate_enforce', shortId: 'abcd1234', hash16: p.contentHash.slice(0, 16), timeoutAt: null })
    expect(text).toContain('credit_gate_enforce')
    expect(text).toContain(HASH_A)
    expect(text).toContain('enforce')
    expect(text).toContain('0.99')
    expect(text).toContain('0.10')
    expect(text).toContain('N9x')
    expect(text).toContain(CANARY_TERMS.cwd)
    expect(text).toContain(CANARY_TERMS.model)
  })
})

// =====================================================================================
// A2: no button, no calibration
// =====================================================================================

describe('A2: without the owner\'s consumed enforce approval the calibration is null', () => {
  it('a fresh grant_model gate has no calibration and does not open', () => {
    expect(h.source()).toBeNull()
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.periods()).toHaveLength(0)
  })

  it('an accepted Console row does not count under grant_model', () => {
    h.consoleRow(5)
    expect(h.source()).toBeNull()
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
  })

  it('an approved but not yet processed enforce approval is no calibration either', () => {
    ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    expect(h.source()).toBeNull()
  })

  it('the Console path is untouched: console (or no) calibrationSource uses the Console source, grantModel block or not', () => {
    const c = new GH({ calibrationSource: 'console', grantModel: grantBlock() })
    expect(c.source()).toBeNull()
    c.consoleRow(7)
    // The Console source verifies its row against the approval it was consumed from: a forged row throws, as before.
    expect(() => c.source()).toThrow()
    c.cleanup()
  })

  it('under console an enforce approval is not consumed', () => {
    const c = new GH({ calibrationSource: 'console', grantModel: grantBlock() })
    const id = ownerApproved('credit_gate_enforce', enforcePayload(c.hash()))
    c.cycle()
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(c.periods()).toHaveLength(0)
    c.cleanup()
  })
})

// =====================================================================================
// The button: consumed once, one transaction (spec 4)
// =====================================================================================

describe('the enforce button: one owner press = one consume = the first period, the canary row and the owner pin', () => {
  it('writes the first period row, the canary row and the owner pin in the consuming transaction, and opens the gate', () => {
    h.consoleRow(50)
    const id = h.enforce()
    const rows = h.periods()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ approval_id: id, lb: P1.lb, expires: P1.expires, remaining_micro: 200 * USD })
    expect(rows[0].id).toBe(51)
    const a = getApproval(id)!
    expect(a.consumed_by).toBe(GRANT_CONSUMER)
    expect(a.consumed_at).toBe(Math.floor(NOW0 / 1000))
    const c = h.canaries()
    expect(c).toHaveLength(1)
    expect(c[0]).toMatchObject({
      approval_id: id, config_hash: CONFIG_HASH, model: 'claude-sonnet-5-5', budget_micro: 990_000, min_expected_micro: 100_000,
      before_calibration_id: 51, run_id: null, status: 'consumed',
    })
    expect(h.calState().owner_id).toBe(OWNER)
    expect(h.events('grant_enforce')).toHaveLength(1)
    expect(h.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    expect(h.source()).toMatchObject({ id: 51, captured_at_lb_ms: P1.lb })
  })

  it('the gate gets ONE synthetic grant: granted = lb, expires = the next grant, original 200, remaining 200 (A4), protected = the baseline', () => {
    h.enforce()
    expect(h.source()).toEqual({
      id: h.periods()[0].id,
      captured_at_lb_ms: P1.lb,
      grants: [{ granted: '2026-10-15T00:00:00Z', expires: '2026-11-15T00:00:00Z', original_micro: 200 * USD, remaining_micro: 200 * USD }],
      protected: { R_micro: 3_630_000, V_micro: 10 * USD },
    })
  })

  it('a second pass changes nothing; a second consume of the same approval is refused', () => {
    const id = h.enforce()
    h.cycle()
    h.cycle()
    expect(h.periods()).toHaveLength(1)
    expect(h.canaries()).toHaveLength(1)
    expect(consumeCreditGateApproval({ id, category: 'credit_gate_enforce', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'already_consumed' })
  })

  it('a second approved enforce approval is its own button: one more row, one more canary, a higher id', () => {
    const first = h.enforce()
    const second = h.enforce()
    const rows = h.periods()
    expect(rows.map((r) => r.approval_id)).toEqual([first, second])
    expect(rows[1].id).toBeGreaterThan(rows[0].id)
    expect(h.canaries()).toHaveLength(2)
  })

  it('a consume that fails rolls the whole step back: no period row, no canary row, no pin', () => {
    h.consumeOverride = () => ({ ok: false, reason: 'already_consumed' })
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    h.cycle()
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(h.periods()).toHaveLength(0)
    expect(h.canaries()).toHaveLength(0)
    expect(h.calState().owner_id).toBeNull()
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
  })
})

// =====================================================================================
// A7: every way an enforce approval must NOT open
// =====================================================================================

describe('A7: the G-02 path, every branch (never consumed, never opening)', () => {
  const closed = () => {
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.periods()).toHaveLength(0)
    expect(h.canaries()).toHaveLength(0)
    expect(h.source()).toBeNull()
  }

  it('wrong category: a button-approved email_send, a canary approval, a calibration approval', () => {
    const mail = requestApproval('email_send', '{"envelope_v":1,"to":["x@example.invalid"]}')
    expect(pressApprove(mail).ok).toBe(true)
    expect(isOwnerVerified(mail, OWNER)).toBe(true)
    const cal = ownerApproved('credit_gate_canary', {
      v: 1, kind: 'credit_gate_canary', config_hash: CONFIG_HASH, model: 'claude-sonnet-5-5', budget_usd: '0.90', min_expected_usd: '0.10',
      before_calibration_id: randomUUID(), node: 'N9x', cwd: CANARY_TERMS.cwd, prompt_sha256: 'cd'.repeat(32),
    })
    closed()
    expect(getApproval(mail)!.consumed_at).toBeNull()
    expect(getApproval(cal)!.consumed_at).toBeNull()
    expect(consumeCreditGateApproval({ id: mail, category: 'credit_gate_enforce', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'wrong_category' })
  })

  it('another user pressed the button: not consumed, and the owner\'s consume of it is refused', () => {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()), STRANGER)
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(consumeCreditGateApproval({ id, category: 'credit_gate_enforce', ownerId: OWNER, consumer: 'credit-gate' }))
      .toMatchObject({ ok: false, reason: 'not_owner_verified' })
  })

  it('the configured owner is someone else, or unset: nothing is processed; the owner back, it opens', () => {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    h.ownerId = NEW_OWNER
    closed()
    h.ownerId = null
    expect(h.cycle()).toMatchObject({ state: 'HOLD', reason: 'owner_unset' })
    expect(getApproval(id)!.consumed_at).toBeNull()
    h.ownerId = OWNER
    h.cycle()
    expect(h.periods()).toHaveLength(1)
    expect(getApproval(id)!.consumed_at).not.toBeNull()
  })

  it('the legacy PATCH decides the row, but nothing is consumed', () => {
    const id = requestApproval('credit_gate_enforce', enforcePayload(h.hash()))
    expect(resolveApproval(id, 'approved', 'dashboard')).toBe(true)
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('a row approved as owner:telegram: before the trace table existed does not open', () => {
    const id = requestApproval('credit_gate_enforce', enforcePayload(h.hash()))
    getDb().prepare("UPDATE approvals SET status = 'approved', resolved_by = ?, resolved_at = ? WHERE id = ?")
      .run(`owner:telegram:${OWNER}`, Math.floor(Date.now() / 1000), id)
    closed()
  })

  it('a payload changed after the press does not open (the text, then text and hash together)', () => {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    const forged = canon(enforcePayload(h.hash(), {}, { budget_usd: '0.50' }))
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(forged, id)
    closed()
    getDb().prepare('UPDATE approvals SET content_hash = ? WHERE id = ?').run(sha(forged), id)
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('a stale grant-model hash (the config moved on after the press) is not consumed and does not open', () => {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    h.editConfig((c) => { (c.grantModel as Record<string, unknown>).grantDays = [1, 15] })
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
    // The very same approval is still not valid for another hash; a new one for the new hash is.
    const fresh = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    h.cycle()
    expect(h.periods().map((r) => r.approval_id)).toEqual([fresh])
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('a wrong hash (never the config\'s) is not consumed', () => {
    const id = ownerApproved('credit_gate_enforce', enforcePayload(HASH_A))
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
  })

  it('under grant_model a credit_gate_calibration approval is not consumed (it stays pending, unchanged)', () => {
    const id = ownerApproved('credit_gate_calibration', {
      v: 1, kind: 'credit_gate_calibration', captured_at_lb: '2026-11-10T11:00:00Z',
      grants: [{ granted: '2026-10-14', expires: '2026-11-17', original_usd: '200.00', remaining_usd: '200.00' }],
      protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.00' } },
      screenshot: '/Volumes/8T/00 CLOUD/console/n2-test.png',
    })
    closed()
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(getDb().prepare('SELECT COUNT(*) AS n FROM credit_calibrations').get()).toEqual({ n: 0 })
    expect(h.stateRow().state).toBe('CLOSED')
  })
})

// =====================================================================================
// A3: the tick advances the periods
// =====================================================================================

describe('A3: the tick writes exactly one new row when the period changes, with an id above every calibration', () => {
  it('two ticks in one period make one row; the boundary makes exactly one more', () => {
    h.consoleRow(80)
    h.enforce()
    h.now += 60_000
    h.cycle()
    h.now += 3_600_000
    h.cycle()
    expect(h.periods()).toHaveLength(1)
    h.now = BOUNDARY_AFTER
    h.cycle()
    h.cycle()
    const rows = h.periods()
    expect(rows).toHaveLength(2)
    expect(rows[1]).toMatchObject({ lb: P2.lb, expires: P2.expires, remaining_micro: 200 * USD })
    expect(rows[1].id).toBeGreaterThan(80)
    expect(rows[1].id).toBeGreaterThan(rows[0].id)
    expect(rows[1].approval_id).toBe(rows[0].approval_id)
    // No button for the advance: the approval is not consumed twice, no second canary.
    expect(h.canaries()).toHaveLength(1)
    expect(h.events('grant_period')).toHaveLength(1)
    expect(h.source()).toMatchObject({ id: rows[1].id, captured_at_lb_ms: P2.lb })
  })

  it('an id is above a Console id issued later than the first period (the sequence and both tables count)', () => {
    h.enforce()
    const first = h.periods()[0].id
    h.consoleRow(first + 40)
    h.now = BOUNDARY_AFTER
    h.cycle()
    expect(h.periods()[1].id).toBe(first + 41)
  })

  it('the latch lifts at the new period and not inside the old one', () => {
    h.enforce()
    expect(h.state().state).toBe('OPEN')
    h.gate.raiseHold('canary_undecidable', { why: 'test' }, h.now)
    h.cycle()
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'canary_undecidable' })
    h.now += 3_600_000
    h.cycle()
    expect(h.state().state).toBe('HOLD')
    h.now = BOUNDARY_AFTER
    h.cycle()
    expect(h.state().state).toBe('OPEN')
  })

  it('a tick after a long pause writes one row for the period it is in, not one per missed period', () => {
    h.enforce()
    h.now = Date.UTC(2027, 1, 20)
    h.cycle()
    const rows = h.periods()
    expect(rows).toHaveLength(2)
    expect(rows[1]).toMatchObject({ lb: Date.UTC(2027, 1, 15), expires: Date.UTC(2027, 2, 15) })
  })

  it('both candidate days: the earlier lb and the earlier expiry win (A5), and a month change is one period', () => {
    const g = new GH({ grantModel: grantBlock({ grantDays: [1, 15] }) })
    g.now = Date.UTC(2026, 10, 14, 23, 59, 59)
    g.enforce()
    expect(g.periods()[0]).toMatchObject({ lb: Date.UTC(2026, 9, 15), expires: Date.UTC(2026, 10, 15) })
    g.now = Date.UTC(2026, 10, 15, 0, 0, 0)
    g.cycle()
    expect(g.periods()[1]).toMatchObject({ lb: Date.UTC(2026, 10, 1), expires: Date.UTC(2026, 11, 1) })
    g.cleanup()
  })

  it('the advance is not made while the gate is in INCIDENT', () => {
    h.enforce()
    h.gate.raiseIncident('protected_decreased', { store: 'V' }, h.now)
    h.now = BOUNDARY_AFTER
    h.cycle()
    expect(h.state().state).toBe('INCIDENT')
    expect(h.periods()).toHaveLength(1)
  })
})

// =====================================================================================
// A9: after an INCIDENT only a NEW enforce approval opens
// =====================================================================================

describe('A9: an INCIDENT ends the chain; only a new enforce approval, decided after the clear, reopens', () => {
  function incidentAndClear(): void {
    h.gate.raiseIncident('protected_decreased', { store: 'V' }, h.now)
    h.cycle()
    const incidentId = h.stateRow().incident_event_id as number
    expect(incidentId).toBeGreaterThan(0)
    h.now += 60_000
    ownerApproved('credit_gate_incident_clear', incidentClear(incidentId))
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
  }

  it('after the clear the old chain is no calibration, neither now nor at the next period boundary', () => {
    h.enforce()
    incidentAndClear()
    expect(h.source()).toBeNull()
    h.now += 3_600_000
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.now = BOUNDARY_AFTER
    h.cycle()
    h.cycle()
    expect(h.state().state).toBe('CLOSED')
    expect(h.source()).toBeNull()
    expect(h.periods()).toHaveLength(1)
  })

  it('a NEW enforce approval, pressed after the clear, opens with a higher id', () => {
    h.enforce()
    const before = h.periods()[0].id
    incidentAndClear()
    h.now += 60_000
    const fresh = h.enforce()
    expect(h.periods().at(-1)).toMatchObject({ approval_id: fresh })
    expect(h.periods().at(-1)!.id).toBeGreaterThan(before)
    expect(h.state().state).toBe('OPEN')
  })

  it('an enforce approval decided BEFORE the clear is not the new button: skipped, still unconsumed', () => {
    h.enforce()
    h.gate.raiseIncident('protected_decreased', { store: 'V' }, h.now)
    h.cycle()
    const incidentId = h.stateRow().incident_event_id as number
    // Pressed during the INCIDENT: not consumed while it lasts.
    const early = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    h.cycle()
    expect(getApproval(early)!.consumed_at).toBeNull()
    expect(h.periods()).toHaveLength(1)
    backdate(early, 40 * 86_400)
    h.now += 60_000
    ownerApproved('credit_gate_incident_clear', incidentClear(incidentId))
    expect(h.cycle()).toEqual({ state: 'CLOSED', reason: 'incident_cleared' })
    h.now += 60_000
    h.cycle()
    expect(getApproval(early)!.consumed_at).toBeNull()
    expect(h.state().state).toBe('CLOSED')
    expect(h.periods()).toHaveLength(1)
  })
})

// =====================================================================================
// Config change, the reconstructed file (A6)
// =====================================================================================

describe('a changed config is a new button: the old chain is no calibration', () => {
  it('any change of what the hash rests on closes the gate and stops the advance', () => {
    h.enforce()
    expect(h.state().state).toBe('OPEN')
    h.editConfig((c) => { (c.thresholds as Record<string, unknown>).tClose = '21.00' })
    expect(h.source()).toBeNull()
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    h.now = BOUNDARY_AFTER
    h.cycle()
    expect(h.periods()).toHaveLength(1)
    // The new button for the new hash opens again.
    h.enforce()
    expect(h.periods()).toHaveLength(2)
    expect(h.state().state).toBe('OPEN')
  })

  it('a part the hash does not rest on (refreshS) does not close it', () => {
    h.enforce()
    h.editConfig((c) => { c.refreshS = 20 })
    expect(h.source()).not.toBeNull()
  })
})

describe('A6: the reconstructed file', () => {
  const REC_MODEL = 'claude-sonnet-5-5'
  const line = (ts: number): string => JSON.stringify({ month: '2026-10', caller: 'test', model: REC_MODEL, in: 1_000_000, out: 100_000, ts }) + '\n'
  // Two rows after P1.lb: 3.00 USD each at the Sonnet rates of the fixture.
  const GOOD = line(Date.UTC(2026, 9, 20) / 1000) + line(Date.UTC(2026, 9, 21) / 1000)

  function withReconstructed(text = GOOD): { g: GH; path: string } {
    const g = new GH()
    const dir = join(g.dir, 'recon')
    mkdirSync(dir, { mode: 0o700 })
    chmodSync(dir, 0o700)
    const path = join(dir, 'reconstructed.jsonl')
    writeFileSync(path, text, { mode: 0o600 })
    chmodSync(path, 0o600)
    g.editConfig((c) => {
      (c.grantModel as Record<string, unknown>).reconstructed = {
        path, sha256: sha(text), multiplier: '2', gap: { from: '2026-10-05T00:00:00Z', to: '2026-10-06T00:00:00Z', chargeUsd: '0.50' },
      }
    })
    return { g, path }
  }

  it('the remaining is the grant less the prior charge: 2 rows x 3.00 x 2 = 12.00 (the gap ended before lb)', () => {
    const { g } = withReconstructed()
    g.enforce()
    expect(g.periods()[0].remaining_micro).toBe(188 * USD)
    expect(g.source()).toMatchObject({ grants: [{ original_micro: 200 * USD, remaining_micro: 188 * USD }] })
    expect(g.state().state).toBe('OPEN')
    g.cleanup()
  })

  it('a sha256 that does not match: HOLD grant_model_reconstructed_bad, no calibration, the approval not consumed', () => {
    const { g, path } = withReconstructed()
    const id = ownerApproved('credit_gate_enforce', enforcePayload(g.hash()))
    writeFileSync(path, GOOD + line(Date.UTC(2026, 9, 22) / 1000), { mode: 0o600 })
    expect(g.cycle()).toMatchObject({ state: 'HOLD', reason: 'grant_model_reconstructed_bad' })
    expect(g.source()).toBeNull()
    expect(getApproval(id)!.consumed_at).toBeNull()
    expect(g.periods()).toHaveLength(0)
    g.cleanup()
  })

  it('a missing file, and a file with a row the v1 parser rejects: the same HOLD (the sha256 pinned to the bad bytes)', () => {
    const { g, path } = withReconstructed()
    rmSync(path)
    expect(g.cycle()).toMatchObject({ state: 'HOLD', reason: 'grant_model_reconstructed_bad' })
    g.cleanup()
    const bad = GOOD + '{"month": "2026-10", "surprise": 1}\n'
    const second = withReconstructed(bad)
    expect(second.g.cycle()).toMatchObject({ state: 'HOLD', reason: 'grant_model_reconstructed_bad' })
    expect(second.g.source()).toBeNull()
    expect(second.g.events('grant_model_bad').length).toBeGreaterThanOrEqual(1)
    second.g.cleanup()
  })

  it('the HOLD is raised once, not on every tick', () => {
    const { g, path } = withReconstructed()
    rmSync(path)
    g.cycle()
    g.cycle()
    g.cycle()
    expect(g.events('grant_model_bad')).toHaveLength(1)
    g.cleanup()
  })

  it('the file changed after the button: the chain is no calibration (the hash rests on the file)', () => {
    const { g, path } = withReconstructed()
    g.enforce()
    expect(g.source()).not.toBeNull()
    const text = GOOD + line(Date.UTC(2026, 9, 22) / 1000)
    writeFileSync(path, text, { mode: 0o600 })
    g.editConfig((c) => { ((c.grantModel as Record<string, unknown>).reconstructed as Record<string, unknown>).sha256 = sha(text) })
    expect(g.source()).toBeNull()
    g.cleanup()
  })
})

// =====================================================================================
// A10: the stored side is re-checked on every read
// =====================================================================================

describe('A10: a forged period row or approval is calibration_invalid (the gate closes)', () => {
  const expectInvalid = () => {
    expect(() => h.source()).toThrow()
    expect(h.cycle()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
  }

  it('row_json changed (a larger remaining) with its content_hash left alone', () => {
    h.enforce()
    const row = h.periods()[0]
    const forged = String(row.row_json).replace(`"remaining_micro":${200 * USD}`, '"remaining_micro":1')
    expect(forged).not.toBe(row.row_json)
    getDb().prepare('UPDATE credit_grant_periods SET row_json = ? WHERE id = ?').run(forged, row.id)
    expectInvalid()
  })

  it('row_json and content_hash forged together are caught by the columns', () => {
    h.enforce()
    const row = h.periods()[0]
    const forged = String(row.row_json).replace(`"remaining_micro":${200 * USD}`, `"remaining_micro":${150 * USD}`)
    getDb().prepare('UPDATE credit_grant_periods SET row_json = ?, content_hash = ? WHERE id = ?').run(forged, sha(forged), row.id)
    expectInvalid()
  })

  it('a column changed (lb earlier) while the record stays', () => {
    h.enforce()
    const row = h.periods()[0]
    getDb().prepare('UPDATE credit_grant_periods SET lb = ? WHERE id = ?').run(row.lb - 86_400_000, row.id)
    expectInvalid()
  })

  it('a record and columns forged to a longer period than the config derives', () => {
    h.enforce()
    const row = h.periods()[0]
    const forged = String(row.row_json).replace(`"expires_ms":${P1.expires}`, `"expires_ms":${P1.expires + 86_400_000}`)
    getDb().prepare('UPDATE credit_grant_periods SET row_json = ?, content_hash = ?, expires = ? WHERE id = ?')
      .run(forged, sha(forged), P1.expires + 86_400_000, row.id)
    expectInvalid()
  })

  it('a remaining above the grant is refused', () => {
    h.enforce()
    const row = h.periods()[0]
    const forged = String(row.row_json).replace(`"remaining_micro":${200 * USD}`, `"remaining_micro":${300 * USD}`)
    getDb().prepare('UPDATE credit_grant_periods SET row_json = ?, content_hash = ?, remaining_micro = ? WHERE id = ?')
      .run(forged, sha(forged), 300 * USD, row.id)
    expectInvalid()
  })

  it('the approval re-checked: payload swapped, consumed_by or consumed_at changed, category changed, trace gone', () => {
    const id = h.enforce()
    const db = getDb()
    const original = getApproval(id)!
    const restore = () => db.prepare('UPDATE approvals SET action_payload = ?, content_hash = ?, consumed_by = ?, consumed_at = ?, category = ? WHERE id = ?')
      .run(original.action_payload, original.content_hash, original.consumed_by, original.consumed_at, original.category, id)

    const other = canon(enforcePayload(HASH_A))
    db.prepare('UPDATE approvals SET action_payload = ?, content_hash = ? WHERE id = ?').run(other, sha(other), id)
    expectInvalid()
    restore()

    db.prepare("UPDATE approvals SET consumed_by = 'someone' WHERE id = ?").run(id)
    expectInvalid()
    restore()

    db.prepare('UPDATE approvals SET consumed_at = consumed_at + 5 WHERE id = ?').run(id)
    expectInvalid()
    restore()

    db.prepare("UPDATE approvals SET category = 'credit_gate_canary' WHERE id = ?").run(id)
    expectInvalid()
    restore()

    db.prepare('DELETE FROM approval_owner_resolutions WHERE approval_id = ?').run(id)
    expectInvalid()
  })

  it('a row whose approval is gone', () => {
    const id = h.enforce()
    getDb().prepare('DELETE FROM approvals WHERE id = ?').run(id)
    expectInvalid()
  })

  it('an untouched chain verifies on every read (the happy control of the rows above)', () => {
    h.enforce()
    for (let i = 0; i < 3; i++) expect(h.source()).not.toBeNull()
    expect(h.cycle().state).toBe('OPEN')
  })
})

// =====================================================================================
// The dispatcher
// =====================================================================================

describe('the source dispatcher', () => {
  it('an unreadable or throwing config falls back to the Console source, as before', () => {
    const db = getDb()
    let called = 0
    const consoleSource = () => { called++; return null }
    const broken = dispatchCalibrationSource(consoleSource, db, () => { throw new RangeError('injected') })
    expect(broken()).toBeNull()
    const missing = dispatchCalibrationSource(consoleSource, db, () => ({ ok: false, reason: 'missing', detail: 'x' }))
    expect(missing()).toBeNull()
    expect(called).toBe(2)
  })

  it('grant_model never calls the Console source', () => {
    h.enforce()
    const db = getDb()
    const src = dispatchCalibrationSource(() => { throw new Error('the Console source must not be read') }, db, () => loadCreditGateConfigFile(h.cfgPath))
    expect(src()).not.toBeNull()
  })
})

// =====================================================================================
// The runtime wiring (as web.ts starts it)
// =====================================================================================

describe('the runtime: startCreditGateRuntime wires the dispatcher and the enforce processing', () => {
  it('an owner-approved enforce approval opens the gate on the runtime\'s first run', () => {
    mocked.allowedChatId = OWNER
    const id = ownerApproved('credit_gate_enforce', enforcePayload(h.hash()))
    const interval = startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: getDb(), storeDir: h.storeDir, now: () => h.now })
    try {
      expect(getApproval(id)!.consumed_at).not.toBeNull()
      expect(h.periods()).toHaveLength(1)
      expect(getCreditGateRuntime().gate).not.toBeNull()
      expect(h.state().state).toBe('OPEN')
    } finally {
      if (interval) clearInterval(interval)
      setCreditGateRuntime(null)
    }
  })
})
