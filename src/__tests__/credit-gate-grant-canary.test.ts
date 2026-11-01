import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import net from 'node:net'
import { EventEmitter } from 'node:events'
import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Credit gate grant_model, node N3 (card 40e03382): the enforce button's canary
// binds ONE headless run, is judged on that run's own ledger rows (there is no
// Console after-reading under the grant model), the status endpoint previews
// the model. Written from the spec (A8, A9) and the blueprint (N3), not from the
// code.
//
// Everything runs in-process on a tmp store and a tmp SQLite file; approvals are
// created and decided through db.ts exactly as the owner's Telegram button
// decides them. No real headless run, no claude process, no live dashboard,
// store, Telegram or API. A process-level guard refuses every non-loopback
// connect() and the live CDP ports (18800, 18899) before the connect,
// self-tested against this file's own blocked port 18997.

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
import {
  approvedCanary, CalibrationProcessor, calibrationSource, takeCanaryHash, type WindowRow,
} from '../web/credit-gate/calibration.js'
import { evaluateGrantCanary, type GrantCanaryTerms } from '../web/credit-gate/grant-canary.js'
import { tryHandleCreditGate } from '../web/routes/credit-gate.js'
import type { RouteContext } from '../web/routes/types.js'
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
      throw new Error(`credit-gate N3 test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  globalThis.fetch = (() => { throw new Error('credit-gate N3 test guard: fetch is not allowed') }) as typeof fetch
  scratch = mkdtempSync(join(tmpdir(), 'cg-n3-grant-'))
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
  cwd: '/Volumes/8T/10_LOCAL/Brainy/n3-grant-canary-test',
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
    id, agent_id: 'brainy', category, action_description: 'n3 grant canary test', action_payload: text,
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
  setCreditGateRuntime(null)
  h?.cleanup()
  mocked.allowedChatId = ''
})


// =====================================================================================
// Helpers of this file
// =====================================================================================

const HOUR = 3_600_000
const RUN = 'run_n3_canary_1'
const BUDGET = 990_000
const MIN_EXPECTED = 100_000

/** The terms the runs route hands to consumeCanaryApproval: exactly what CANARY_TERMS approved, unless overridden. */
function runTerms(over: Record<string, unknown> = {}) {
  return {
    model: CANARY_TERMS.model, budget_micro: BUDGET, runId: RUN, node: CANARY_TERMS.node, cwd: CANARY_TERMS.cwd,
    prompt_sha256: CANARY_TERMS.prompt_sha256, ...over,
  }
}

/** What the runs route does for a canary run under the grant model: bind the enforce canary row to a run. */
function bind(approvalId: string, over: Record<string, unknown> = {}, hash: string = CONFIG_HASH) {
  return h.proc.consumeCanaryApproval(approvalId, hash, runTerms(over), h.now)
}

/** The gate side of a canary run: the canary reservation admitted, the run over (the window stays open). */
function runCanary(runId = RUN): void {
  const r = h.gate.reserve({ kind: 'canary', budget_micro: BUDGET as never, model: CANARY_TERMS.model, ref: runId, caller: 'ezermester' }, h.now)
  if (!r.enforced || !r.ok) throw new Error(`the canary was not admitted: ${JSON.stringify(r)}`)
  expect(h.gate.settleHeadless(r.reservation_id, null, h.now)).toMatchObject({ ok: true, status: 'settled' })
}

let ledgerSeq = 0

/** A ledger row as the headless runner (source headless) or a usage reader leaves it. */
function ledgerRow(o: { source?: string; runId?: string | null; est?: number | null; cli?: number | null; ts?: number } = {}): void {
  const source = o.source ?? 'headless'
  getDb().prepare(`INSERT INTO credit_ledger_entries
      (source, dedupe_key, ts, model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens, batch_id, custom_id,
       run_id, est_micro, cli_micro, priced_with, basis, ingested_at)
    VALUES (?, ?, ?, ?, 0, 0, 0, 0, NULL, NULL, ?, ?, ?, NULL, ?, ?)`).run(
    source, `n3-${ledgerSeq++}`, o.ts ?? Math.floor(h.now / 1000), CANARY_TERMS.model,
    o.runId === undefined ? RUN : o.runId, o.est === undefined ? 300_000 : o.est, o.cli === undefined ? 280_000 : o.cli,
    source === 'headless' ? 'headless_json' : 'usage', h.now,
  )
}

function canary(): Record<string, unknown> & { status: string; run_id: string | null; result_json: string | null; hash_taken_at: number | null } {
  const rows = h.canaries()
  expect(rows).toHaveLength(1)
  return rows[0] as never
}

function verdict(): { outcome: string; reason?: string } {
  return JSON.parse(String(canary().result_json))
}

/** Enforce, bind, take the hash like the runner, run the canary on the gate: the middle of a canary. */
function started(): string {
  const id = h.enforce()
  expect(bind(id)).toMatchObject({ ok: true })
  expect(takeCanaryHash(getDb(), id, RUN, h.now)).toBe(CONFIG_HASH)
  runCanary()
  return id
}

// =====================================================================================
// evaluateGrantCanary: the verdict on the run's own ledger rows (spec A8)
// =====================================================================================

describe('A8: evaluateGrantCanary(window, terms)', () => {
  const row = (o: Partial<WindowRow> = {}): WindowRow => ({ source: 'headless', run_id: RUN, batch_id: null, est_micro: 300_000, cli_micro: 280_000, ...o })
  const terms = (o: Partial<GrantCanaryTerms> = {}): GrantCanaryTerms => ({
    run_id: RUN, min_expected_micro: MIN_EXPECTED, budget_micro: BUDGET, signal: null, ...o,
  })

  it('success: the run\'s own priced row costs between the minimum and the budget (the dearer of est and cli counts)', () => {
    expect(evaluateGrantCanary([row()], terms())).toMatchObject({ outcome: 'success', cost_micro: 300_000 })
    expect(evaluateGrantCanary([row({ est_micro: 250_000, cli_micro: 320_000 })], terms())).toMatchObject({ outcome: 'success', cost_micro: 320_000 })
  })

  it('both limits are inclusive; several rows of the run add up', () => {
    expect(evaluateGrantCanary([row({ est_micro: MIN_EXPECTED, cli_micro: null })], terms())).toMatchObject({ outcome: 'success', cost_micro: MIN_EXPECTED })
    expect(evaluateGrantCanary([row({ est_micro: BUDGET, cli_micro: null })], terms())).toMatchObject({ outcome: 'success', cost_micro: BUDGET })
    expect(evaluateGrantCanary([row({ est_micro: 60_000, cli_micro: null }), row({ est_micro: 60_000, cli_micro: null })], terms()))
      .toMatchObject({ outcome: 'success', cost_micro: 120_000 })
  })

  it('over the budget: undecidable, never success', () => {
    expect(evaluateGrantCanary([row({ est_micro: BUDGET + 1, cli_micro: null })], terms())).toEqual({ outcome: 'undecidable', reason: 'canary_over_budget' })
    expect(evaluateGrantCanary([row({ est_micro: 100, cli_micro: BUDGET + 1 })], terms())).toEqual({ outcome: 'undecidable', reason: 'canary_over_budget' })
  })

  it('under the minimum: undecidable', () => {
    expect(evaluateGrantCanary([row({ est_micro: MIN_EXPECTED - 1, cli_micro: null })], terms())).toEqual({ outcome: 'undecidable', reason: 'canary_below_minimum' })
  })

  it('an unpriced row of the run (no estimate) is undecidable, whatever the CLI says', () => {
    expect(evaluateGrantCanary([row({ est_micro: null, cli_micro: 500_000 })], terms())).toEqual({ outcome: 'undecidable', reason: 'unpriced_rows' })
  })

  it('a foreign headless row in the window is undecidable (the canary runs alone)', () => {
    expect(evaluateGrantCanary([row(), row({ run_id: 'run_other' })], terms())).toEqual({ outcome: 'undecidable', reason: 'other_headless_rows' })
    expect(evaluateGrantCanary([row(), row({ run_id: null })], terms())).toEqual({ outcome: 'undecidable', reason: 'other_headless_rows' })
  })

  it('rows of other sources do not move the verdict (the model has no after-reading to match them against)', () => {
    expect(evaluateGrantCanary([row(), row({ source: 'anthropic-batch', run_id: null, est_micro: 5_000_000, cli_micro: null })], terms()))
      .toMatchObject({ outcome: 'success', cost_micro: 300_000 })
  })

  it('credit_balance_too_low or a 401 in the window is an incident, even with a good row', () => {
    expect(evaluateGrantCanary([row()], terms({ signal: 'credit_balance_too_low' }))).toMatchObject({ outcome: 'incident' })
    expect(evaluateGrantCanary([row()], terms({ signal: 'auth_401' }))).toMatchObject({ outcome: 'incident' })
  })

  it('an unbound run, or no row of the run yet, is undecidable', () => {
    expect(evaluateGrantCanary([row()], terms({ run_id: null }))).toEqual({ outcome: 'undecidable', reason: 'canary_run_unbound' })
    expect(evaluateGrantCanary([], terms())).toEqual({ outcome: 'undecidable', reason: 'canary_not_in_window' })
    expect(evaluateGrantCanary([row({ run_id: 'run_other' })], terms())).toEqual({ outcome: 'undecidable', reason: 'canary_not_in_window' })
  })
})

// =====================================================================================
// The route's bind: the enforce canary row <-> one headless run
// =====================================================================================

describe('the canary run binds the enforce button\'s canary row (no new approval)', () => {
  it('binds the run to the row with the approved terms, consumes nothing, and hands the config hash to that run once', () => {
    const id = h.enforce()
    const consumedAt = getApproval(id)!.consumed_at
    const approvalsBefore = getDb().prepare('SELECT COUNT(*) AS n FROM approvals').get() as { n: number }
    const b = bind(id)
    expect(b).toMatchObject({
      ok: true, approval_id: id, config_hash: CONFIG_HASH, model: CANARY_TERMS.model, budget_micro: BUDGET,
      min_expected_micro: MIN_EXPECTED, before_calibration_id: h.periods()[0].id, run_id: RUN,
    })
    expect(canary()).toMatchObject({ approval_id: id, status: 'consumed', run_id: RUN })
    expect(getApproval(id)!.consumed_at).toBe(consumedAt)
    expect(getDb().prepare('SELECT COUNT(*) AS n FROM approvals').get()).toEqual(approvalsBefore)
    expect(takeCanaryHash(getDb(), id, 'run_someone_else', h.now)).toBeNull()
    expect(takeCanaryHash(getDb(), id, RUN, h.now)).toBe(CONFIG_HASH)
    expect(takeCanaryHash(getDb(), id, RUN, h.now)).toBeNull()
  })

  it('a second binding is refused, for the same run id and for another; the first run keeps its hash', () => {
    const id = h.enforce()
    expect(bind(id)).toMatchObject({ ok: true })
    expect(bind(id)).toEqual({ ok: false, reason: 'canary_exists' })
    expect(bind(id, { runId: 'run_n3_canary_2' })).toEqual({ ok: false, reason: 'canary_exists' })
    expect(canary()).toMatchObject({ run_id: RUN })
    expect(takeCanaryHash(getDb(), id, 'run_n3_canary_2', h.now)).toBeNull()
    expect(takeCanaryHash(getDb(), id, RUN, h.now)).toBe(CONFIG_HASH)
  })

  it.each([
    ['the prompt', { prompt_sha256: 'ef'.repeat(32) }],
    ['the model', { model: 'claude-opus-5-5' }],
    ['the node', { node: 'N9y' }],
    ['the cwd', { cwd: '/Volumes/8T/10_LOCAL/Brainy/other' }],
    ['a budget above the approved one', { budget_micro: BUDGET + 1 }],
  ])('differing %s: terms_mismatch, nothing bound, the approved run can still bind', (_name, over) => {
    const id = h.enforce()
    expect(bind(id, over)).toEqual({ ok: false, reason: 'terms_mismatch' })
    expect(canary()).toMatchObject({ status: 'consumed', run_id: null })
    expect(bind(id)).toMatchObject({ ok: true })
  })

  it('another config hash than the approved one, or an unknown approval: refused, nothing bound', () => {
    const id = h.enforce()
    expect(bind(id, {}, 'ab'.repeat(32))).toEqual({ ok: false, reason: 'hash_mismatch' })
    expect(bind(randomUUID())).toMatchObject({ ok: false, reason: 'not_found' })
    expect(canary()).toMatchObject({ run_id: null })
  })

  it('the old credit_gate_canary approval is refused under grant_model and is NOT consumed', () => {
    h.enforce()
    const old = ownerApproved('credit_gate_canary', {
      v: 1, kind: 'credit_gate_canary', config_hash: CONFIG_HASH, model: CANARY_TERMS.model, budget_usd: '0.90', min_expected_usd: '0.10',
      before_calibration_id: randomUUID(), node: CANARY_TERMS.node, cwd: CANARY_TERMS.cwd, prompt_sha256: CANARY_TERMS.prompt_sha256,
    })
    expect(h.proc.consumeCanaryApproval(old, CONFIG_HASH, runTerms(), h.now)).toEqual({ ok: false, reason: 'grant_model' })
    expect(getApproval(old)!.consumed_at).toBeNull()
    expect(h.canaries()).toHaveLength(1)
    expect(canary()).toMatchObject({ run_id: null })
  })
})

// =====================================================================================
// Close: the run's ledger row (A8), the signals (A9), the timeout
// =====================================================================================

describe('A8: the canary closes on the run\'s own ledger row', () => {
  it('success: the row is priced and within [min, budget]; the window closes, the hash is approved, the gate stays OPEN', () => {
    const id = started()
    expect(h.gate.canaryBlock()).toBe('canary_window_open')
    h.now += 120_000
    ledgerRow({ est: 300_000, cli: 280_000 })
    expect(h.cycle()).toMatchObject({ state: 'OPEN' })
    expect(canary()).toMatchObject({ status: 'success', run_id: RUN })
    expect(verdict()).toMatchObject({ outcome: 'success', cost_micro: 300_000 })
    expect(h.gate.canaryBlock()).toBeNull()
    expect(approvedCanary(getDb())).toEqual({ approval_id: id, config_hash: CONFIG_HASH })
    expect(h.events('canary_evaluated')).toHaveLength(1)
    expect(h.events('canary_window_closed')).toHaveLength(1)
    // Evaluated once: another cycle changes nothing.
    h.cycle()
    expect(h.events('canary_evaluated')).toHaveLength(1)
  })

  it('no row of the run yet: nothing is decided, the canary waits', () => {
    started()
    h.now += 120_000
    expect(h.cycle()).toMatchObject({ state: 'OPEN' })
    expect(canary()).toMatchObject({ status: 'consumed' })
    expect(h.gate.canaryBlock()).toBe('canary_window_open')
    expect(approvedCanary(getDb())).toBeNull()
  })

  it.each([
    ['over the budget', { est: 1_200_000, cli: 1_100_000 }, 'canary_over_budget'],
    ['over the budget by the CLI figure', { est: 300_000, cli: 995_000 }, 'canary_over_budget'],
    ['under the minimum', { est: 50_000, cli: 40_000 }, 'canary_below_minimum'],
    ['unpriced', { est: null, cli: 500_000 }, 'unpriced_rows'],
  ])('%s: undecidable, the gate HOLDs, nothing is approved, the window is closed', (_name, row, reason) => {
    started()
    h.now += 120_000
    ledgerRow(row)
    expect(h.cycle().state).toBe('HOLD')
    expect(canary()).toMatchObject({ status: 'undecidable' })
    expect(verdict()).toMatchObject({ outcome: 'undecidable', reason })
    expect(approvedCanary(getDb())).toBeNull()
    expect(h.gate.canaryBlock()).toBeNull()
  })

  it('a foreign headless row in the window: undecidable, HOLD', () => {
    started()
    h.now += 120_000
    ledgerRow()
    ledgerRow({ runId: 'run_foreign', est: 200_000, cli: null })
    expect(h.cycle()).toMatchObject({ state: 'HOLD', reason: 'canary_undecidable' })
    expect(verdict()).toMatchObject({ outcome: 'undecidable', reason: 'other_headless_rows' })
    expect(approvedCanary(getDb())).toBeNull()
  })

  it('a headless row from before the run started is not in its window', () => {
    started()
    h.now += 120_000
    ledgerRow({ runId: 'run_older', ts: Math.floor(h.now / 1000) - 3600 })
    ledgerRow()
    expect(h.cycle()).toMatchObject({ state: 'OPEN' })
    expect(canary()).toMatchObject({ status: 'success' })
  })

  it.each(['credit_balance_too_low', 'auth_401'] as const)('%s since the consume: an INCIDENT, the canary is not a success', (kind) => {
    started()
    h.now += 60_000
    h.gate.signal(kind, 'test', null, h.now)
    h.now += 60_000
    ledgerRow()
    expect(h.cycle()).toMatchObject({ state: 'INCIDENT' })
    expect(canary()).toMatchObject({ status: 'incident' })
    expect(approvedCanary(getDb())).toBeNull()
  })

  it('timeout: canaryCloseMaxH after the run was taken without a row of its own -> HOLD canary_close_timeout, nothing approved', () => {
    const id = h.enforce()
    expect(bind(id)).toMatchObject({ ok: true })
    expect(takeCanaryHash(getDb(), id, RUN, h.now)).toBe(CONFIG_HASH)
    const taken = h.now
    h.now = taken + 6 * HOUR - 60_000
    expect(h.cycle()).toMatchObject({ state: 'OPEN' })
    expect(canary()).toMatchObject({ status: 'consumed' })
    h.now = taken + 6 * HOUR
    expect(h.cycle()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
    expect(canary()).toMatchObject({ status: 'undecidable' })
    expect(verdict()).toMatchObject({ outcome: 'undecidable', reason: 'canary_close_timeout' })
    expect(approvedCanary(getDb())).toBeNull()
  })

  it('a canary nobody bound a run to does not time out (no run, no window, nothing to hold)', () => {
    h.enforce()
    h.now += 7 * HOUR
    expect(h.cycle()).toMatchObject({ state: 'OPEN' })
    expect(canary()).toMatchObject({ status: 'consumed', run_id: null })
  })
})

// =====================================================================================
// N2 left-over: an orphaned grant canary after a switch back to Console
// =====================================================================================

describe('switching back to console: an orphaned grant_model canary is closed explicitly, never read against a Console reading', () => {
  it('an unbound canary row is closed as undecidable (grant_source_switched), without a HOLD', () => {
    h.enforce()
    expect(canary()).toMatchObject({ status: 'consumed', run_id: null })
    h.editConfig((c) => { c.calibrationSource = 'console' })
    h.cycle()
    expect(canary()).toMatchObject({ status: 'undecidable' })
    expect(verdict()).toMatchObject({ outcome: 'undecidable', reason: 'grant_source_switched' })
    expect(h.state().reason).not.toBe('canary_undecidable')
    expect(h.state().state).not.toBe('HOLD')
    expect(approvedCanary(getDb())).toBeNull()
    // Closed once.
    h.cycle()
    expect(h.events('canary_evaluated')).toHaveLength(1)
  })

  it('a bound one too (its run id does not make it a Console canary)', () => {
    const id = h.enforce()
    expect(bind(id)).toMatchObject({ ok: true })
    h.editConfig((c) => { c.calibrationSource = 'console' })
    h.cycle()
    expect(canary()).toMatchObject({ status: 'undecidable', run_id: RUN })
    expect(verdict()).toMatchObject({ reason: 'grant_source_switched' })
  })

  it('a config that cannot be read closes nothing (only an explicit console config does)', () => {
    h.enforce()
    writeFileSync(h.cfgPath, '{not json', { mode: 0o600 })
    h.cycle()
    expect(canary()).toMatchObject({ status: 'consumed' })
  })

  it('a Console canary row is not touched by this close', () => {
    const c = new GH({ calibrationSource: 'console', grantModel: grantBlock() })
    getDb().prepare(`INSERT INTO credit_canaries (approval_id, config_hash, model, budget_micro, min_expected_micro, before_calibration_id, run_id, status, consumed_at)
      VALUES (?, ?, ?, 900000, 100000, 41, ?, 'consumed', ?)`).run(randomUUID(), CONFIG_HASH, CANARY_TERMS.model, RUN, c.now)
    c.cycle()
    expect(c.canaries()).toMatchObject([{ status: 'consumed', run_id: RUN }])
    c.cleanup()
  })
})

// =====================================================================================
// The status endpoint: the grant_model block
// =====================================================================================

interface Out { status: number; body: any }

function call(method: string, path: string): { ctx: RouteContext; out: Out; done: Promise<void> } {
  const out: Out = { status: 0, body: null }
  let resolve!: () => void
  const done = new Promise<void>((r) => { resolve = r })
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { /* unused */ },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk); resolve() },
  }
  const req: any = new EventEmitter()
  req.headers = {}
  req.destroy = () => { /* noop */ }
  setImmediate(() => { req.emit('end') })
  const url = new URL(`http://localhost:3420${path}`)
  return { ctx: { req, res, path, method, url } as RouteContext, out, done }
}

async function status(mode: 'shadow' | 'enforce' = 'shadow'): Promise<Out> {
  setCreditGateRuntime({ mode: readCreditGateMode(mode), gate: h.gate, storeDir: h.storeDir, db: getDb(), startError: null, calibrations: h.proc })
  const c = call('GET', '/api/credit-gate/status')
  expect(await tryHandleCreditGate(c.ctx)).toBe(true)
  await c.done
  return c.out
}

describe('the status endpoint shows the grant_model block (also in shadow mode)', () => {
  const iso = (ms: number) => new Date(ms).toISOString()

  it('before the button: the config hash, the current period, no prior charge, the full grant as the preview, no chain', async () => {
    const out = await status('shadow')
    expect(out.status).toBe(200)
    expect(out.body.mode).toBe('shadow')
    expect(out.body.grant_model).toMatchObject({
      source: 'grant_model',
      config_hash: h.hash(),
      period: { lb: iso(P1.lb), expires: iso(P1.expires) },
      prior_charge_usd: '0.00',
      remaining_usd: '200.00',
      r_est_preview_usd: '200.00',
      chain: { state: 'none' },
    })
  })

  it('after the button: the chain is in force on the first period, the canary row is shown (unbound, then bound)', async () => {
    const id = h.enforce()
    let out = await status('enforce')
    expect(out.body.grant_model).toMatchObject({
      chain: { state: 'ok', period_id: h.periods()[0].id },
      canary: { status: 'consumed', run_bound: false },
    })
    bind(id)
    out = await status('enforce')
    expect(out.body.grant_model.canary).toMatchObject({ status: 'consumed', run_bound: true })
  })

  it('a changed config: the hash moves and the old chain reads as stale', async () => {
    h.enforce()
    const before = (await status()).body.grant_model.config_hash
    h.editConfig((c) => { (c.thresholds as Record<string, unknown>).tClose = '21.00' })
    const out = await status()
    expect(out.body.grant_model.config_hash).not.toBe(before)
    expect(out.body.grant_model.chain.state).toBe('stale')
  })

  it('with a reconstructed file: the prior charge and the remaining show, and no path, hash of the file or temp dir is in the answer', async () => {
    const g = new GH()
    const dir = join(g.dir, 'recon')
    mkdirSync(dir, { mode: 0o700 })
    chmodSync(dir, 0o700)
    const path = join(dir, 'reconstructed.jsonl')
    const line = (ts: number): string => JSON.stringify({ month: '2026-10', caller: 'test', model: 'claude-sonnet-5-5', in: 1_000_000, out: 100_000, ts }) + '\n'
    const text = line(Date.UTC(2026, 9, 20) / 1000) + line(Date.UTC(2026, 9, 21) / 1000)
    writeFileSync(path, text, { mode: 0o600 })
    chmodSync(path, 0o600)
    g.editConfig((c) => {
      (c.grantModel as Record<string, unknown>).reconstructed = {
        path, sha256: sha(text), multiplier: '2', gap: { from: '2026-10-05T00:00:00Z', to: '2026-10-06T00:00:00Z', chargeUsd: '0.50' },
      }
    })
    h.cleanup()
    h = g
    const out = await status('shadow')
    expect(out.body.grant_model).toMatchObject({ prior_charge_usd: '12.00', remaining_usd: '188.00', r_est_preview_usd: '188.00' })
    const text2 = JSON.stringify(out.body.grant_model)
    expect(text2).not.toContain(path)
    expect(text2).not.toContain(sha(text))
    expect(text2).not.toContain(g.dir)
    expect(text2).not.toContain(g.storeDir)
  })

  it('is secret-free: no key or value of the block names a path, a secret, a token or the vault', async () => {
    h.enforce()
    const out = await status()
    const keys: string[] = []
    const walk = (v: unknown): void => {
      if (Array.isArray(v)) v.forEach(walk)
      else if (v !== null && typeof v === 'object') {
        for (const [k, x] of Object.entries(v)) { keys.push(k); walk(x) }
      }
    }
    walk(out.body.grant_model)
    expect(keys.filter((k) => /path|secret|token|password|vault|key$/i.test(k))).toEqual([])
    const text = JSON.stringify(out.body.grant_model)
    expect(text).not.toContain(h.dir)
    expect(text).not.toMatch(/ANTHROPIC_API_KEY|sk-ant/)
  })

  it('a bad reconstructed file shows no hash and says why; the block is still there', async () => {
    const g = new GH()
    g.editConfig((c) => {
      (c.grantModel as Record<string, unknown>).reconstructed = {
        path: join(g.dir, 'missing.jsonl'), sha256: 'ab'.repeat(32), multiplier: '2', gap: { from: '2026-10-05T00:00:00Z', to: '2026-10-06T00:00:00Z', chargeUsd: '0.50' },
      }
    })
    h.cleanup()
    h = g
    const out = await status()
    expect(out.body.grant_model).toMatchObject({ source: 'grant_model', config_hash: null, inputs: { ok: false } })
    expect(JSON.stringify(out.body.grant_model)).not.toContain('missing.jsonl')
  })

  it('under the console source the block is null', async () => {
    const c = new GH({ calibrationSource: 'console', grantModel: grantBlock() })
    h.cleanup()
    h = c
    const out = await status()
    expect(out.status).toBe(200)
    expect(out.body.grant_model).toBeNull()
  })
})
