// The credit gate (card fec6335f, spec A, B-06, C, D-04, D-05; blueprint
// 3.4-3.6, 4.2; node N2a): R_est, reservations, thresholds, expiry, the
// low-calibration timer, the STOP file, signals and the PR-A guard events.
//
//   R_est(t) = sum of the calibration's grants still alive at t (expiry > t)
//            - L(t) - the open reservations.
// L(t) is the ledger's max(est, cli) sum since the calibration's lower bound
// (N1b's ledgerSum). An open batch reservation counts max(0, amount - what the
// ledger already holds for its batch_id), so a request is never subtracted
// twice. An expired grant drops out of the sum with its whole calibrated
// remainder (D-04); overlapping grants add up (D-05).
//
// One decision at a time (C-01): reserve() is ONE synchronous BEGIN IMMEDIATE
// transaction -- read the state, sum the ledger and the open reservations,
// decide, insert -- with no await in it. Another process (another
// connection) waits for the write lock or gets `gate_busy`; it never decides
// on a stale sum. The tick gathers its file inputs first (config, price
// table, ledger refresh, calibration, guard events, STOP inspection) and then
// decides inside one such transaction as well, so a reservation that lands
// while the tick reads its files is still counted.
//
// What the gate may do on its own is close. Opening needs enforce mode, a
// calibration (N2c: owner-approved), and nothing at all against it -- see
// gate-state.ts. Signals, reservations and the tick's findings can only keep
// or raise the severity. The STOP file is handled by stop-file.ts; a human
// STOP is never touched, and keeps the gate closed until a newer calibration.
// A STOP the gate must put down but cannot (CW1), or cannot even check in
// enforce mode (CS2), is a HOLD (`stop_place_failed`) until it is down again
// and a newer calibration lifts the latch. A tick that would open the gate
// takes its own STOP away first and decides the opening on the outcome (CS1):
// a STOP it cannot take away keeps it CLOSED (`stop_release_failed`), never
// OPEN with the STOP still down, reported once per episode.
// K-01 (N4b, N7B1): the canary's cost must be the only one between its two
// Console readings. Admitting a canary opens the canary WINDOW
// (credit_gate_state.canary_res_id, in the database, so a restart keeps it).
// While it is open the gate's own STOP stays down even in OPEN, and every
// other reservation (and a second canary) is refused: `canary_in_progress`
// while the canary's reservation is open, `canary_window_open` after its
// settle. The settle does NOT close the window: only closeCanary does, and the
// calibration processor calls it when it records the after-reading (the next
// non-rejected reading). Repeated or without a window it is refused and
// changes nothing. If the after-reading is not recorded within
// canaryCloseMaxH hours of the settle, the tick holds the gate
// (`canary_close_timeout`, a HOLD condition: it never opens, the STOP stays
// down) until the close and a newer calibration. BE-4b: a canary is admitted
// only alone (no open or unknown reservation of any kind: `reservations_open`),
// and headless runs are capped by headless.maxConcurrent (`concurrency_limit`)
// and, when configured, headless.dailyCapUsd (`daily_cap`) -- all inside the
// reserve transaction.
//
// Faults fail closed (BE-2): an exception from the ledger (refresh, ledgerSum,
// ageS, ingestedForBatch, recordHeadless) is a HOLD with reason
// `ledger_error`, one from the price table or the pricing of a request a
// CLOSED with `pricing_error`, anything else in a tick a HOLD with
// `tick_error`. Each is logged as an error AND written as a `fault` event;
// none is swallowed, and none can open the gate.
//
// Everything is synchronous (fs + better-sqlite3).

import { createHash, randomBytes, randomUUID } from 'node:crypto'
import { closeSync, constants as fsConstants, fstatSync, openSync, readSync } from 'node:fs'
import type Database from 'better-sqlite3'
import { logger } from '../../logger.js'
import { MAX_CANARY_CLOSE_H, parseUtcInstant, type ConfigLoadResult, type CreditGateConfig, type ModeReading } from './config.js'
import {
  applyCause,
  applySignal,
  clearIncident as clearIncidentState,
  decide,
  STATE_SEVERITY,
  type Cause,
  type GateState,
  type StateSnapshot,
} from './gate-state.js'
import { CreditLedger, type HeadlessRun, type LedgerOptions, type LedgerSum, type RefreshResult } from './ledger.js'
import { scanUsageFile, type FileCursor } from './ledger-usage-jsonl.js'
import { applyFactorCeil, asMicro, ceilDiv, MAX_USD_AMOUNT_MICRO, MICRO_PER_USD, microFromBigInt } from './money.js'
import { matchModel } from './pricing.js'
import {
  inspectStop,
  nodeStopFs,
  parseStopOwner,
  placeStop,
  releaseStop,
  type StopFs,
  type StopInspection,
  type StopOwnerRecord,
} from './stop-file.js'
import type { Micro, PricingLoadResult, PricingTable } from './types.js'

/** An unbound batch reservation this old never got its batch_id: unknown (HOLD). */
export const UNBOUND_BATCH_MAX_MS = 60 * 60 * 1000
/** A headless or canary reservation this old was never settled: unknown (HOLD). */
export const OPEN_HEADLESS_MAX_MS = 24 * 60 * 60 * 1000
/** At most this many guard-event lines become their own audit row per tick. */
const GUARD_EVENTS_PER_TICK = 20
const GUARD_MAX_FILE_BYTES = 64 * 1024 * 1024
const HOUR_MS = 60 * 60 * 1000

const MODEL_RE = /^[A-Za-z0-9_.-]{1,128}$/
const CALLER_RE = /^[A-Za-z0-9_.-]{1,64}$/
const REF_RE = /^[A-Za-z0-9_.:-]{1,128}$/
const RESERVATION_ID_RE = /^[A-Za-z0-9-]{1,64}$/
const BATCH_ID_RE = /^msgbatch_[A-Za-z0-9_-]{1,160}$/
const MAX_TOKENS_TOTAL = 10_000_000_000
const MAX_REQUESTS = 100_000
/** A plausible Team grant is 200 USD; anything above these is a misreading (BE-3). */
export const MAX_GRANT_MICRO = 10_000 * MICRO_PER_USD
export const MAX_GRANTS_TOTAL_MICRO = 20_000 * MICRO_PER_USD
const MINUTE_MS = 60 * 1000
const DAY_MS = 24 * HOUR_MS

export interface CalibrationGrant {
  readonly granted: string
  readonly expires: string
  readonly original_micro: Micro
  readonly remaining_micro: Micro
}

/** What N2c hands over: an owner-approved, processed Console reading. */
export interface Calibration {
  /** credit_calibrations.id: increasing, a newer calibration has a larger id. */
  readonly id: number
  /** The earliest moment the reading may have been taken (epoch ms). */
  readonly captured_at_lb_ms: number
  readonly grants: readonly CalibrationGrant[]
  readonly protected: { readonly R_micro: Micro; readonly V_micro: Micro }
}

export type CalibrationSource = () => Calibration | null
/** No calibration: the gate never opens (calibration.ts has the real source). */
export const noCalibration: CalibrationSource = () => null

export type PricingFileResult =
  | PricingLoadResult
  | { readonly ok: false; readonly reason: 'missing' | 'unreadable' | 'permissions'; readonly detail: string }

export interface CreditGateDeps {
  readonly db: Database.Database
  /** Never `off`: in off mode no gate is built. */
  readonly mode: ModeReading
  readonly loadConfig: () => ConfigLoadResult
  readonly loadPricing: (nowMs: number) => PricingFileResult
  readonly calibration: CalibrationSource
  /** store/interactive-key-guard-events.jsonl (PR-A); null = none. */
  readonly guardEventsPath: string | null
  readonly stopFs?: StopFs
  readonly now?: () => number
  readonly newId?: () => string
  readonly newNonce?: () => string
  /** Builds the ledger; tests inject a failing one. */
  readonly ledgerFactory?: (db: Database.Database, opts: LedgerOptions) => CreditLedger
}

export interface BatchReserveRequest {
  readonly kind: 'batch'
  readonly model: string
  readonly input_tokens_total: number
  readonly max_output_tokens_total: number
  readonly request_count: number
  readonly caller: string
}

export interface HeadlessReserveRequest {
  readonly kind: 'headless' | 'canary'
  readonly budget_micro: Micro
  readonly model: string
  readonly ref: string
  readonly caller: string
}

export type ReserveRequest = BatchReserveRequest | HeadlessReserveRequest

export type ReserveResult =
  | { readonly enforced: false }
  | {
      readonly enforced: true
      readonly ok: true
      readonly reservation_id: string
      readonly amount_micro: Micro
      readonly r_est_after_micro: Micro
      /** The reservation brought R_est to T_close: the gate closed behind it. */
      readonly closed: boolean
    }
  | { readonly enforced: true; readonly ok: false; readonly reason: string; readonly detail?: string }

export type ReservationStatus = 'open' | 'settled' | 'released' | 'unknown'

/** K-01 (N7B1): the close step of the canary window, as closeCanary answers it. */
export type CanaryCloseResult =
  | { readonly ok: true; readonly reservation_id: string }
  | { readonly ok: false; readonly reason: 'invalid_request' | 'no_canary_window' | 'not_an_after_reading' }

/** K-01 (N7B1): the open canary window, as the status shows it. */
export interface CanaryWindowView {
  readonly reservation_id: string
  readonly run_id: string | null
  readonly opened_at: string | null
  /** When the canary's reservation left `open` (its settle); null while the run goes on. */
  readonly run_ended_at: string | null
  /** run_ended_at + canaryCloseMaxH: past it the gate holds (`canary_close_timeout`). */
  readonly close_by: string | null
}

export type OpResult =
  | { readonly ok: true; readonly status: ReservationStatus; readonly changed: boolean }
  | { readonly ok: false; readonly code: 404 | 409; readonly reason: string }

export type SignalKind = 'disarm' | 'credit_balance_too_low' | 'auth_401' | 'usage_log_failed'
export const SIGNAL_KINDS: readonly SignalKind[] = ['disarm', 'credit_balance_too_low', 'auth_401', 'usage_log_failed']

/** Every unapproved signal maps to a closing cause (blueprint 3.5, 14). */
const SIGNAL_CAUSE: Readonly<Record<SignalKind, Cause>> = Object.freeze({
  disarm: { kind: 'latch', reason: 'disarm' },
  auth_401: { kind: 'latch', reason: 'auth_401' },
  credit_balance_too_low: { kind: 'incident', reason: 'credit_balance_too_low' },
  usage_log_failed: { kind: 'hold', reason: 'usage_log_failed' },
})

export interface TickResult {
  readonly state: GateState
  readonly reason: string
  readonly r_est_micro: Micro | null
}

export interface GateStatus {
  readonly mode: string
  readonly mode_raw: string | null
  readonly enforced: boolean
  readonly state: GateState
  readonly reason: string
  readonly since: string | null
  readonly evaluated_at: string | null
  readonly r_est_usd: string | null
  readonly ledger: {
    readonly l_usd: string | null
    readonly age_s: number | null
    readonly unpriced: number
    /** The ledger failed while this status was computed (the tick turns it into a HOLD). */
    readonly error: string | null
    /** L is above 100 000 USD: the ledger only says "at least that much" (the gate closes). */
    readonly saturated: boolean
    readonly sources: ReadonlyArray<{ readonly id: string; readonly status: string; readonly reason: string | null }>
  }
  readonly reservations: { readonly open_count: number; readonly open_usd: string }
  readonly thresholds: Record<string, string> | null
  readonly calibration: {
    readonly id: number
    readonly captured_at_lb: string
    readonly grants: ReadonlyArray<{ readonly granted: string; readonly expires: string; readonly remaining_usd: string }>
  } | null
  readonly close_at: string | null
  /** No batch is admitted from here on: the last expiry minus max(margin, batch horizon). */
  readonly close_at_batch: string | null
  readonly next_expiry: string | null
  readonly latch: { readonly calibration_id: number; readonly reason: string | null } | null
  /** The largest calibration id ever seen; every latch binds to it. */
  readonly max_calibration_id: number
  readonly lowcal: { readonly requested_at: string | null; readonly fallback_at: string | null }
  readonly stop: { readonly path: string | null; readonly present: boolean | null; readonly owner: 'gate' | 'human' | 'none' | 'unknown' }
  /** K-01: a canary's reservation is open (its run goes on). */
  readonly canary_in_progress: boolean
  /**
   * K-01 (N7B1): the canary window, from the canary's admission until its
   * after-reading is recorded; while it is open the batch path stays on the
   * gate's STOP and nothing else is admitted. null = none.
   */
  readonly canary_window: CanaryWindowView | null
}

interface StateRow {
  state: GateState
  reason: string
  since: number
  calibration_id: number | null
  max_calibration_id: number
  t_close_eff_micro: number | null
  lowcal_requested_at: number | null
  lowcal_fallback_at: number | null
  latch_cal_id: number | null
  latch_reason: string | null
  stop_owner_json: string | null
  last_stop_file: string | null
  guard_cursor_json: string | null
  evaluated_at: number | null
  incident_event_id: number | null
  /** The open INCIDENT causes, newest last: [{event_id, reason}] (N2c MED-1). */
  incident_open_json: string | null
  mode: string | null
  /** What the last reported change said (B14); null on a row from before the columns. */
  reported_state: GateState | null
  reported_reason: string | null
  /** K-01 (N7B1): the canary reservation whose window is open; null = none. */
  canary_res_id: string | null
  canary_opened_at: number | null
  /** CW1: the gate's STOP could not be put down (since then, and still): a HOLD condition; null = none. */
  stop_place_failed_at: number | null
  /** CS1: the gate's own STOP could not be taken away (since then, and still); null = none. */
  stop_release_failed_at: number | null
  version: number
}

/**
 * CS1: what taking the gate's own STOP away came to, when the tick has to
 * decide again: it went (`released`), or it failed and the episode starts
 * (`failed`, with the error code). null: nothing for the tick to redo.
 */
type ReleaseOutcome = { readonly released: true } | { readonly released: false; readonly failed: string } | null

interface Evaluation {
  readonly state: GateState
  readonly reason: string
  readonly rEst: number | null
  /** CS1: the gate would open but its STOP is still down; the state version the release may act on. */
  readonly releaseFirst: number | null
  /** CS2: this evaluation started a stop_place_failed episode (an unverifiable STOP): its one log line. */
  readonly placeFailStarted: string | null
}

/** One open INCIDENT cause: its own event, why, and the fingerprint of its identity. */
interface IncidentCause {
  readonly event_id: number
  readonly reason: string
  /** causeFingerprint of the key, else of the detail ('' for a cause stored before it existed). */
  readonly fp?: string
}

/** A cause found now: the same reason with another detail is another cause (LOW-B). */
interface IncidentCauseIn {
  readonly reason: string
  readonly detail?: Record<string, unknown> | null
  /**
   * The cause's identity when it is not its detail. A signal's is its kind
   * alone (B10): its source and detail are a Bearer caller's words, and new
   * words must not open a new cause.
   */
  readonly key?: Record<string, unknown>
}

/** A detail's identity: sha256 of its JSON with sorted keys (names and reasons only, never a value). */
function causeFingerprint(detail: Record<string, unknown> | null | undefined): string {
  const canon = (v: unknown): unknown => Array.isArray(v) ? v.map(canon)
    : v !== null && typeof v === 'object'
      ? Object.fromEntries(Object.keys(v as Record<string, unknown>).sort().map((k) => [k, canon((v as Record<string, unknown>)[k])]))
      : v
  let text: string
  try {
    text = JSON.stringify(canon(detail ?? null)) ?? 'null'
  } catch {
    text = 'unserializable'
  }
  return createHash('sha256').update(text, 'utf8').digest('hex').slice(0, 32)
}

/**
 * The open INCIDENT causes of a row in INCIDENT, newest last. A row written
 * before the list existed has one: its entry event.
 */
function openIncidentCauses(row: StateRow): IncidentCause[] {
  if (row.state !== 'INCIDENT') return []
  try {
    const v: unknown = row.incident_open_json === null ? null : JSON.parse(row.incident_open_json)
    if (Array.isArray(v) && v.length > 0 && v.every((c) => typeof c === 'object' && c !== null
      && Number.isSafeInteger((c as IncidentCause).event_id) && typeof (c as IncidentCause).reason === 'string')) {
      return v.map((c) => ({
        event_id: (c as IncidentCause).event_id,
        reason: (c as IncidentCause).reason,
        fp: typeof (c as IncidentCause).fp === 'string' ? (c as IncidentCause).fp : '',
      }))
    }
  } catch {
    // fall back to the entry event
  }
  return row.incident_event_id === null ? [] : [{ event_id: row.incident_event_id, reason: row.reason }]
}

interface ReservationRow {
  id: string
  kind: 'headless' | 'batch' | 'canary'
  ref: string | null
  amount_micro: number
  request_count: number | null
  expected_requests: number | null
  status: ReservationStatus
  calibration_id: number | null
  complete_requested_at: number | null
  overrun_at: number | null
  created_at: number
  updated_at: number
}

/** K-01 (N7B1): the open canary window with its reservation. */
interface CanaryWindow {
  readonly reservationId: string
  readonly runId: string | null
  readonly openedAt: number | null
  /** The reservation left `open` at this moment (settled or unknown); null = still open. */
  readonly endedAt: number | null
  /** The calibration the canary was admitted under; its after-reading must be newer. */
  readonly calibrationId: number | null
}

interface ValidCalibration {
  readonly cal: Calibration
  /** Each grant's expiry instant (epoch ms), in the calibration's order. */
  readonly expiresMs: readonly number[]
}

interface GrantMoney {
  /** Sum of the remainders of the grants alive at now. */
  readonly live: number
  /** The last expiry of a grant with a remainder; null = none. */
  readonly lastExpiryMs: number | null
  /** lastExpiry minus the margin: the gate closes here (C-06); null = none. */
  readonly closeAtMs: number | null
  /** The next expiry after now; null = none. */
  readonly nextExpiryMs: number | null
}

/**
 * Where the PR-A guard-event file is read from (credit_gate_state.guard_cursor_json):
 *  - null: never initialised -- the first read sets a baseline at the file's end;
 *  - a file cursor: new lines are read from `offset`;
 *  - absent: initialised while there was no file (or it vanished) -- a file
 *    that appears later is read from its first byte;
 *  - broken: damaged and not readable -- an INCIDENT on every evaluation
 *    until resetGuardCursor() (N2c, after an owner reviewed it).
 */
type GuardCursorState = FileCursor | { readonly absent: true } | { readonly broken: string } | null

interface GuardBaseline {
  /** Non-empty complete lines that were already in the file (not incidents). */
  readonly lines: number
  readonly bytes: number
  /** sha256 of those bytes; null when there was no file. */
  readonly sha256: string | null
  readonly why: 'init' | 'after_damage' | 'reset'
}

interface GuardRead {
  readonly events: ReadonlyArray<Record<string, unknown>>
  /** Lines that were already in the file at the first init (an INCIDENT, decision 2026-10-16 round 2). */
  readonly backlog: number
  readonly cursor: GuardCursorState
  /** The file was truncated, replaced, rewritten, removed, ... (an INCIDENT). */
  readonly damage: string | null
  /** True when the damage was found by this read (not a stored, already reported one). */
  readonly newDamage: boolean
  readonly baseline: GuardBaseline | null
}

interface Gathered {
  readonly config: CreditGateConfig | null
  readonly configReason: string | null
  /** The STOP path in force: the config's, or the last valid one when the config is not. */
  readonly stopPath: string | null
  readonly ledger: CreditLedger | null
  readonly refresh: RefreshResult | null
  /** The ledger threw while it was built or refreshed (already logged and recorded). */
  readonly ledgerFailed: boolean
  readonly table: PricingTable | null
  readonly pricingReason: string | null
  readonly cal: ValidCalibration | null
  readonly calReason: string | null
  readonly guard: GuardRead
  readonly stop: StopInspection | null
}

interface EventFields {
  readonly from?: GateState | null
  readonly to?: GateState | null
  readonly reason?: string | null
  readonly rEst?: number | null
  readonly l?: number | null
  readonly ageS?: number | null
  readonly open?: number | null
  readonly calId?: number | null
  readonly detail?: Record<string, unknown> | null
}

/** micro-USD as a decimal USD string: at least two decimals, exact. */
export function formatUsd(micro: number): string {
  const m = asMicro(micro)
  const neg = m < 0
  const a = Math.abs(m)
  const whole = Math.floor(a / MICRO_PER_USD)
  let frac = String(a % MICRO_PER_USD).padStart(6, '0')
  while (frac.length > 2 && frac.endsWith('0')) frac = frac.slice(0, -1)
  return `${neg ? '-' : ''}${whole}.${frac}`
}

function isCount(v: unknown, max: number): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v <= max
}

/**
 * The batch upper estimate (blueprint 3.4): every input token at the worst
 * input rate of every price band -- max(input with the batch discount, the
 * 1-hour cache write without it) -- and every output token at the worst
 * output rate with the discount (the discount only when the table carries a
 * verified one). Rounded up. null = the model has no price.
 */
export function batchReservationAmount(table: PricingTable, model: string, inputTokens: number, outputTokens: number): Micro | null {
  const p = matchModel(table, model)
  if (!p) return null
  if (!isCount(inputTokens, MAX_TOKENS_TOTAL) || !isCount(outputTokens, MAX_TOKENS_TOTAL)) return null
  const keep = BigInt(100 - (table.batch_discount_pct ?? 0))
  let inRate = 0n
  let outRate = 0n
  for (const b of p.long_context ? [p.base, p.long_context] : [p.base]) {
    const inB = BigInt(b.input) * keep
    const cw = BigInt(b.cache_write_1h) * 100n
    if (inB > inRate) inRate = inB
    if (cw > inRate) inRate = cw
    const outB = BigInt(b.output) * keep
    if (outB > outRate) outRate = outB
  }
  const scaled = BigInt(inputTokens) * inRate + BigInt(outputTokens) * outRate
  return microFromBigInt(ceilDiv(scaled, 100n * 1_000_000n))
}

/** A calibration as handed over, checked again (fail-closed): null = unusable. */
function validateCalibration(c: unknown, nowMs: number): ValidCalibration | null {
  if (typeof c !== 'object' || c === null) return null
  const cal = c as Calibration
  if (!Number.isSafeInteger(cal.id) || cal.id <= 0) return null
  // A lower bound in the future would leave the requests in between out of L.
  if (!Number.isSafeInteger(cal.captured_at_lb_ms) || cal.captured_at_lb_ms <= 0 || cal.captured_at_lb_ms > nowMs) return null
  if (!Array.isArray(cal.grants) || cal.grants.length === 0 || cal.grants.length > 16) return null
  const expiresMs: number[] = []
  for (const g of cal.grants) {
    if (typeof g !== 'object' || g === null) return null
    if (parseUtcInstant(g.granted) === null) return null
    const e = parseUtcInstant(g.expires)
    if (e === null) return null
    if (!isCount(g.original_micro, MAX_GRANT_MICRO) || !isCount(g.remaining_micro, MAX_GRANT_MICRO)) return null
    if (g.remaining_micro > g.original_micro) return null
    expiresMs.push(e)
  }
  // BE-3: a misread or forged reading must not buy room. Real grants are 200 USD.
  const sum = (k: 'original_micro' | 'remaining_micro') => cal.grants.reduce((t, g) => t + g[k], 0)
  if (sum('original_micro') > MAX_GRANTS_TOTAL_MICRO || sum('remaining_micro') > MAX_GRANTS_TOTAL_MICRO) return null
  const p = cal.protected
  if (typeof p !== 'object' || p === null || !isCount(p.R_micro, MAX_USD_AMOUNT_MICRO) || !isCount(p.V_micro, MAX_USD_AMOUNT_MICRO)) return null
  return { cal, expiresMs }
}

function grantMoney(v: ValidCalibration, nowMs: number, marginH: number): GrantMoney {
  let lastExpiry: number | null = null
  let nextExpiry: number | null = null
  v.cal.grants.forEach((g, i) => {
    const e = v.expiresMs[i]
    if (e > nowMs && (nextExpiry === null || e < nextExpiry)) nextExpiry = e
    if (g.remaining_micro > 0 && (lastExpiry === null || e > lastExpiry)) lastExpiry = e
  })
  return {
    live: liveAt(v, nowMs),
    lastExpiryMs: lastExpiry,
    closeAtMs: lastExpiry === null ? null : lastExpiry - marginH * HOUR_MS,
    nextExpiryMs: nextExpiry,
  }
}

/** The remainders of the grants still alive at `atMs` (expiry strictly after it). */
function liveAt(v: ValidCalibration, atMs: number): number {
  let live = 0
  v.cal.grants.forEach((g, i) => {
    if (v.expiresMs[i] > atMs) live += g.remaining_micro
  })
  return live
}

const NAME_RE = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/
const SOURCE_RE = /^[A-Za-z0-9_.:-]{1,64}$/
const WHERE_RE = /^[A-Za-z0-9_.:/~@ -]{1,200}$/
const AGENT_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/
const STAMP_RE = /^[0-9T:.+Z-]{1,40}$/
/** PR-A's marker for a settings file it could not read (UNREADABLE_SETTINGS); no value can ride on it. */
export const GUARD_UNREADABLE_NAME = '<unreadable>'

/** A name a guard line may carry: an env-like identifier, or PR-A's unreadable marker (N6). */
export function isGuardName(n: unknown): n is string {
  return typeof n === 'string' && (NAME_RE.test(n) || n === GUARD_UNREADABLE_NAME)
}

/** Long runs of key-like characters and anything that looks like an Anthropic key. */
function scrub(s: string): string {
  return s
    .replace(/sk-ant-[A-Za-z0-9_-]*/g, '[redacted]')
    .replace(/[A-Za-z0-9_+/=-]{32,}/g, '[redacted]')
}

/** A free-text detail for the audit: no control characters, no key-like value, bounded. */
export function scrubDetail(v: unknown, max = 300): string | null {
  if (typeof v !== 'string') return null
  // eslint-disable-next-line no-control-regex
  return scrub(v.replace(/[\u0000-\u001f\u007f]/g, ' ')).slice(0, max)
}

/**
 * One guard-event line of PR-A ({ts, source, where, names[], agent?}), reduced
 * to fields that cannot carry a value: anything else is dropped or '?'.
 */
function sanitizeGuardLine(text: string | null): Record<string, unknown> {
  if (text === null) return { unparseable: true }
  let o: unknown
  try {
    o = JSON.parse(text)
  } catch {
    return { unparseable: true }
  }
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return { unparseable: true }
  const r = o as Record<string, unknown>
  const safe = (v: unknown, re: RegExp) => (typeof v === 'string' && re.test(v) && !/sk-ant/i.test(v) ? v : '?')
  const out: Record<string, unknown> = {
    ts: typeof r.ts === 'string' && STAMP_RE.test(r.ts) ? r.ts : '?',
    source: safe(r.source, SOURCE_RE),
    where: safe(r.where, WHERE_RE),
    names: Array.isArray(r.names) ? r.names.filter(isGuardName).slice(0, 16) : [],
  }
  if (r.agent !== undefined) out.agent = safe(r.agent, AGENT_RE)
  return out
}

function parseGuardCursor(json: string | null): GuardCursorState {
  if (json === null) return null
  try {
    const o = JSON.parse(json) as Record<string, unknown>
    if (typeof o.broken === 'string') return { broken: o.broken }
    if (o.absent === true) return { absent: true }
    if (typeof o.dev === 'string' && typeof o.ino === 'string' && Number.isSafeInteger(o.offset)
      && (typeof o.tail_sha256 === 'string' || o.tail_sha256 === null)) {
      return { dev: o.dev, ino: o.ino, offset: o.offset as number, tail_sha256: o.tail_sha256 as string | null }
    }
  } catch {
    // fall through
  }
  // An unreadable stored cursor cannot prove that nothing was missed.
  return { broken: 'guard_cursor_invalid' }
}

/** sha256 of the first `bytes` bytes of the file, if it is still the inode `ino`. */
function sha256Prefix(path: string, ino: string, bytes: number): string | null {
  let fd: number
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
  } catch {
    return null
  }
  try {
    if (fstatSync(fd, { bigint: true }).ino.toString() !== ino) return null
    const h = createHash('sha256')
    const buf = Buffer.alloc(64 * 1024)
    let pos = 0
    while (pos < bytes) {
      const n = readSync(fd, buf, 0, Math.min(buf.length, bytes - pos), pos)
      if (n === 0) return null
      h.update(buf.subarray(0, n))
      pos += n
    }
    return h.digest('hex')
  } catch {
    return null
  } finally {
    closeSync(fd)
  }
}

/** A cursor at the file's current end, with what was already in it. */
function guardBaseline(path: string, why: GuardBaseline['why']): { cursor: GuardCursorState; baseline: GuardBaseline } | { damage: string } {
  const scan = scanUsageFile(path, null, GUARD_MAX_FILE_BYTES)
  if (!scan.ok) {
    if (scan.reason === 'missing') return { cursor: { absent: true }, baseline: { lines: 0, bytes: 0, sha256: null, why } }
    return { damage: `guard_events_${scan.reason}` }
  }
  let offset = 0
  let lines = 0
  for (const line of scan.lines) {
    offset = line.end
    if (line.text === null || line.text.trim() !== '') lines++
  }
  const sha256 = sha256Prefix(path, scan.ino, offset)
  if (sha256 === null) return { damage: 'guard_events_replaced' }
  return {
    cursor: { dev: scan.dev, ino: scan.ino, offset, tail_sha256: scan.tailShaAt(offset) },
    baseline: { lines, bytes: offset, sha256, why },
  }
}

/**
 * New complete lines of the append-only guard-event file since the cursor.
 * The first read sets a baseline at the file's end (line count + sha256); if
 * the file already held lines, that backlog is ONE INCIDENT that only an
 * owner's clearIncident lifts (coordinator decision 2026-10-16, round 2: the
 * gate starts CLOSED anyway, so this only asks for a deliberate review). An
 * empty or missing file is no INCIDENT. Every line after the baseline is an
 * INCIDENT, and so is any damage to a file already read (truncated, replaced,
 * rewritten, removed): an event may have been hidden. After damage the cursor
 * is set to the damaged file's end, so the INCIDENT is raised once.
 */
function readGuardEvents(path: string | null, stored: GuardCursorState): GuardRead {
  const none = { events: [], backlog: 0, damage: null, newDamage: false, baseline: null }
  if (path === null) return { ...none, cursor: stored }
  if (stored === null) {
    const b = guardBaseline(path, 'init')
    if ('damage' in b) return { ...none, cursor: { broken: b.damage }, damage: b.damage, newDamage: true }
    return { ...none, cursor: b.cursor, baseline: b.baseline, backlog: b.baseline.lines }
  }
  if ('broken' in stored) return { ...none, cursor: stored, damage: stored.broken }
  const from = 'absent' in stored ? null : stored
  const scan = scanUsageFile(path, from, GUARD_MAX_FILE_BYTES)
  if (!scan.ok) {
    if (scan.reason === 'missing' && from === null) return { ...none, cursor: stored }
    const damage = `guard_events_${scan.reason}`
    // Gone: a file that comes back is read from its first byte.
    if (scan.reason === 'missing') return { ...none, cursor: { absent: true }, damage, newDamage: true }
    const b = guardBaseline(path, 'after_damage')
    if ('damage' in b) return { ...none, cursor: { broken: damage }, damage, newDamage: true }
    return { ...none, cursor: b.cursor, damage, newDamage: true, baseline: b.baseline }
  }
  const events: Array<Record<string, unknown>> = []
  let offset = from?.offset ?? 0
  for (const line of scan.lines) {
    offset = line.end
    if (line.text !== null && line.text.trim() === '') continue
    events.push(sanitizeGuardLine(line.text))
  }
  return { ...none, events, cursor: { dev: scan.dev, ino: scan.ino, offset, tail_sha256: scan.tailShaAt(offset) } }
}

function iso(ms: number | null | undefined): string | null {
  return typeof ms === 'number' && Number.isFinite(ms) ? new Date(ms).toISOString() : null
}

function errorName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err
}

function isBusy(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code
  return typeof code === 'string' && code.startsWith('SQLITE_BUSY')
}

function snapshotOf(row: StateRow): StateSnapshot {
  return { state: row.state, reason: row.reason, latchCalId: row.latch_cal_id, latchReason: row.latch_reason }
}

export class CreditGate {
  private readonly db: Database.Database
  private readonly stopFs: StopFs
  private readonly nowFn: () => number
  private readonly newId: () => string
  private readonly newNonce: () => string
  private ledgerCache: { key: string; ledger: CreditLedger } | null = null

  constructor(private readonly deps: CreditGateDeps) {
    if (deps.mode.mode === 'off') throw new Error('CreditGate: off mode builds no gate')
    this.db = deps.db
    this.stopFs = deps.stopFs ?? nodeStopFs
    this.nowFn = deps.now ?? Date.now
    this.newId = deps.newId ?? randomUUID
    this.newNonce = deps.newNonce ?? (() => randomBytes(16).toString('hex'))
  }

  get mode(): ModeReading {
    return this.deps.mode
  }

  private get enforcing(): boolean {
    return this.deps.mode.mode === 'enforce'
  }

  // ---------------------------------------------------------------- storage

  private ensureStateRow(nowMs: number): void {
    this.db.prepare(`INSERT OR IGNORE INTO credit_gate_state (id, state, reason, since, reported_state, reported_reason, version)
      VALUES (1, 'CLOSED', 'initial', ?, 'CLOSED', 'initial', 0)`).run(nowMs)
  }

  private readState(nowMs: number): StateRow {
    this.ensureStateRow(nowMs)
    return this.db.prepare('SELECT * FROM credit_gate_state WHERE id = 1').get() as StateRow
  }

  /** The state row without creating it (outside a transaction, read-only). */
  private peekState(): StateRow | null {
    return (this.db.prepare('SELECT * FROM credit_gate_state WHERE id = 1').get() as StateRow | undefined) ?? null
  }

  private updateState(fields: Partial<StateRow>): void {
    const keys = Object.keys(fields) as Array<keyof StateRow>
    if (keys.length === 0) return
    const sets = keys.map((k) => `${k} = @${k}`).join(', ')
    this.db.prepare(`UPDATE credit_gate_state SET ${sets}, version = version + 1 WHERE id = 1`).run(fields)
  }

  private event(nowMs: number, kind: string, f: EventFields = {}): number {
    const info = this.db.prepare(`INSERT INTO credit_gate_events
        (at, kind, from_state, to_state, reason, r_est_micro, l_micro, ledger_age_s, open_res_micro, calibration_id, detail_json)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
      nowMs,
      kind,
      f.from ?? null,
      f.to ?? null,
      f.reason ?? null,
      f.rEst ?? null,
      f.l ?? null,
      f.ageS === null || f.ageS === undefined ? null : Math.ceil(f.ageS),
      f.open ?? null,
      f.calId ?? null,
      f.detail ? JSON.stringify(f.detail) : null,
    )
    return Number(info.lastInsertRowid)
  }

  /**
   * Store a new state; a change of state or reason is a `transition` event
   * (the audit and N5's outbox). In INCIDENT every cause has its own event
   * (N2c MED-1): the entry is a `transition`, every further cause found while
   * in INCIDENT (`incidentCauses`, one not open yet) an `incident_cause`. A
   * cause is its reason AND its detail (LOW-B): the same reason with another
   * detail is a cause of its own, the very same one is not repeated -- except
   * a signal's, which is its kind alone (B10, `key`). The
   * newest open cause is the state's reason and incident_event_id -- the one an
   * incident-clear names. `stateOnly` (a signal, B12): only a change of state
   * is a transition, a new reason in the same state is not.
   *
   * B14: this is the one place that decides whether a change is reported, and
   * it compares with what was REPORTED last (reported_state/_reason), not with
   * the row's reason: a signal may have rewritten that (B12 lets it), and a
   * tick giving the gate's own reason back would otherwise be a change again
   * after every signal. A genuine change is a transition exactly as before (E2).
   * True when a report row (a transition, or an INCIDENT cause) was written.
   */
  private writeState(prevRow: StateRow, next: StateSnapshot, nowMs: number, extra: Partial<StateRow> = {}, f: EventFields = {}, incidentCauses: readonly IncidentCauseIn[] = [], stateOnly = false): boolean {
    // N6: OPEN 'opened' -> OPEN 'open' (the tick after an opening) is no
    // transition: only a change of state, or of the reason a non-OPEN gate gives.
    const reportedState = prevRow.reported_state ?? prevRow.state
    const reportedReason = prevRow.reported_reason ?? prevRow.reason
    const changed = next.state !== reportedState || (!stateOnly && next.reason !== reportedReason && next.state !== 'OPEN')
    const fields: Partial<StateRow> = {
      state: next.state,
      reason: next.reason,
      latch_cal_id: next.latchCalId,
      latch_reason: next.latchReason,
      ...extra,
    }
    // Never decreases: the latch base of every later closure (BE-3).
    fields.max_calibration_id = Math.max(prevRow.max_calibration_id ?? 0, next.latchCalId ?? 0, extra.max_calibration_id ?? 0)
    if (next.state !== prevRow.state) fields.since = nowMs
    let reported = false
    if (next.state === 'INCIDENT') {
      const open = openIncidentCauses(prevRow)
      const entering = prevRow.state !== 'INCIDENT'
      const fallback: IncidentCauseIn = { reason: next.reason, detail: f.detail ?? null }
      const candidates = entering
        ? (incidentCauses.length > 0 ? incidentCauses : [fallback])
        : [...incidentCauses, ...(open.length === 0 ? [fallback] : [])]
      for (const cause of candidates) {
        const fp = causeFingerprint(cause.key ?? cause.detail)
        if (open.some((c) => c.reason === cause.reason && (c.fp ?? '') === fp)) continue
        const first = entering && open.length === 0
        const from: GateState = first ? prevRow.state : 'INCIDENT'
        const id = this.event(nowMs, first ? 'transition' : 'incident_cause', { ...f, from, to: 'INCIDENT', reason: cause.reason, detail: cause.detail ?? f.detail ?? null })
        reported = true
        open.push({ event_id: id, reason: cause.reason, fp })
        logger.warn({ from, to: 'INCIDENT', reason: cause.reason }, first ? 'credit gate: state change' : 'credit gate: a further INCIDENT cause')
      }
      const newest = open[open.length - 1] as IncidentCause
      fields.reason = newest.reason
      fields.incident_event_id = newest.event_id
      fields.incident_open_json = JSON.stringify(open)
      // Every open cause has its own reported row; the newest is the last one.
      fields.reported_state = 'INCIDENT'
      fields.reported_reason = newest.reason
    } else {
      if (changed) {
        this.event(nowMs, 'transition', { ...f, from: prevRow.state, to: next.state, reason: next.reason })
        const log = next.state === 'OPEN' ? logger.info.bind(logger) : logger.warn.bind(logger)
        log({ from: prevRow.state, to: next.state, reason: next.reason }, 'credit gate: state change')
        reported = true
      }
      fields.reported_state = changed ? next.state : reportedState
      fields.reported_reason = changed ? next.reason : reportedReason
      fields.incident_event_id = null
      fields.incident_open_json = null
    }
    this.updateState(fields)
    return reported
  }

  /**
   * A caught exception: logged as an error and written as a `fault` event (in
   * the caller's transaction, or on its own). The caller fails closed.
   */
  private fault(nowMs: number, reason: string, where: string, err: unknown): void {
    logger.error({ err, where, reason }, 'credit gate: fault, failing closed')
    this.event(nowMs, 'fault', {
      reason,
      detail: { where, error: errorName(err), message: scrubDetail(err instanceof Error ? err.message : String(err), 200) },
    })
  }

  /** BEGIN IMMEDIATE: the write lock is taken before anything is read. */
  private txImmediate<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate()
  }

  // ---------------------------------------------------------------- inputs

  private ledgerFor(config: CreditGateConfig): CreditLedger {
    const key = JSON.stringify(config.ledgerSources)
    if (this.ledgerCache?.key !== key) {
      const make = this.deps.ledgerFactory ?? ((db, opts) => new CreditLedger(db, opts))
      this.ledgerCache = { key, ledger: make(this.db, { sources: config.ledgerSources }) }
    }
    return this.ledgerCache.ledger
  }

  private loadConfig(): { config: CreditGateConfig | null; reason: string | null } {
    const r = this.deps.loadConfig()
    if (r.ok) return { config: r.config, reason: null }
    return { config: null, reason: r.reason === 'missing' ? 'config_missing' : 'config_invalid' }
  }

  private loadTable(nowMs: number): { table: PricingTable | null; reason: string | null } {
    let r: PricingFileResult
    try {
      r = this.deps.loadPricing(nowMs)
    } catch (err) {
      this.fault(nowMs, 'pricing_error', 'loadPricing', err)
      return { table: null, reason: 'pricing_error' }
    }
    if (r.ok) return { table: r.table, reason: null }
    return { table: null, reason: `pricing_${r.reason}` }
  }

  private loadCalibration(nowMs: number): { cal: ValidCalibration | null; reason: string | null } {
    let c: Calibration | null
    try {
      c = this.deps.calibration()
    } catch {
      return { cal: null, reason: 'calibration_invalid' }
    }
    if (c === null) return { cal: null, reason: 'no_calibration' }
    const v = validateCalibration(c, nowMs)
    return v ? { cal: v, reason: null } : { cal: null, reason: 'calibration_invalid' }
  }

  /**
   * The calibration id a closing cause latches under: the largest one ever
   * seen -- stored, from the last evaluation, or in the source right now.
   * Never the current one alone: it may be missing for a moment (BE-3).
   */
  private latchBaseFor(row: StateRow | null, nowMs: number): number {
    const fromSource = this.loadCalibration(nowMs).cal?.cal.id ?? 0
    return Math.max(row?.max_calibration_id ?? 0, row?.calibration_id ?? 0, fromSource)
  }

  private gather(nowMs: number): Gathered {
    const { config, reason: configReason } = this.loadConfig()
    const { table, reason: pricingReason } = this.loadTable(nowMs)
    let ledger: CreditLedger | null = null
    let refresh: RefreshResult | null = null
    let ledgerFailed = false
    if (config) {
      try {
        ledger = this.ledgerFor(config)
        refresh = ledger.refresh(nowMs, table)
      } catch (err) {
        ledgerFailed = true
        this.fault(nowMs, 'ledger_error', ledger ? 'refresh' : 'ledger_init', err)
      }
    }
    const { cal, reason: calReason } = this.loadCalibration(nowMs)
    const row = this.peekState()
    const guard = readGuardEvents(this.deps.guardEventsPath, parseGuardCursor(row?.guard_cursor_json ?? null))
    // An invalid config must not leave the batch path unstopped: the last
    // valid STOP path stays in force.
    const stopPath = config?.stopFile ?? row?.last_stop_file ?? null
    const stop = stopPath ? inspectStop(this.stopFs, stopPath, parseStopOwner(row?.stop_owner_json)) : null
    return { config, configReason, stopPath, ledger, refresh, ledgerFailed, table, pricingReason, cal, calReason, guard, stop }
  }

  // ---------------------------------------------------------------- money

  private openReservations(ledger: CreditLedger | null): { total: number; count: number; saturated: boolean } {
    const rows = this.db.prepare(`SELECT id, kind, ref, amount_micro FROM credit_reservations
      WHERE status IN ('open', 'unknown')`).all() as Array<Pick<ReservationRow, 'id' | 'kind' | 'ref' | 'amount_micro'>>
    let total = 0
    let saturated = false
    for (const r of rows) {
      if (r.kind === 'batch' && r.ref !== null && ledger !== null) {
        const got = ledger.ingestedForBatch(r.ref)
        // A saturated batch sum is a floor, so the open part below is an
        // overstatement -- safe; the flag still closes the gate.
        if (got.saturated) saturated = true
        total += Math.max(0, r.amount_micro - got.l_micro)
      } else {
        total += r.amount_micro
      }
    }
    return { total, count: rows.length, saturated }
  }

  /** Batch reservations: overruns (HOLD, once), settlement, stale ones (unknown, HOLD). */
  private upkeep(ledger: CreditLedger | null, nowMs: number, holdEvents: string[]): void {
    if (ledger !== null) {
      const bound = this.db.prepare(`SELECT * FROM credit_reservations
        WHERE kind = 'batch' AND ref IS NOT NULL AND status IN ('open', 'unknown')`).all() as ReservationRow[]
      for (const r of bound) {
        const got = ledger.ingestedForBatch(r.ref as string)
        if (got.l_micro > r.amount_micro && r.overrun_at === null) {
          this.db.prepare('UPDATE credit_reservations SET overrun_at = ?, updated_at = ? WHERE id = ?').run(nowMs, nowMs, r.id)
          this.event(nowMs, 'batch_overrun', { reason: 'batch_overrun', detail: { reservation_id: r.id, amount_micro: r.amount_micro, ingested_micro: got.l_micro } })
          holdEvents.push('batch_overrun')
        }
        this.trySettleBatch(r, ledger, nowMs)
      }
    }
    const stale = this.db.prepare(`SELECT id, kind FROM credit_reservations WHERE status = 'open' AND (
        (kind = 'batch' AND ref IS NULL AND created_at <= ?) OR (kind IN ('headless', 'canary') AND created_at <= ?))`)
      .all(nowMs - UNBOUND_BATCH_MAX_MS, nowMs - OPEN_HEADLESS_MAX_MS) as Array<{ id: string; kind: string }>
    for (const r of stale) {
      this.db.prepare(`UPDATE credit_reservations SET status = 'unknown', reason = 'stale', updated_at = ? WHERE id = ?`).run(nowMs, r.id)
      this.event(nowMs, 'reservation_unknown', { reason: 'stale', detail: { reservation_id: r.id, kind: r.kind } })
      holdEvents.push('reservation_unknown')
    }
  }

  /** A bound batch whose client said "complete" settles once every request is in the ledger. */
  private trySettleBatch(r: ReservationRow, ledger: CreditLedger, nowMs: number): boolean {
    if (r.complete_requested_at === null || r.ref === null || r.expected_requests === null) return false
    if (r.status !== 'open' && r.status !== 'unknown') return false
    const got = ledger.ingestedForBatch(r.ref)
    // TODO(N2d): a batch whose requests partly failed never reaches
    // expected_requests (a failed request writes no usage row), so it stays
    // open and keeps max(0, amount - ingested) reserved -- safe, but the room
    // is held until N2d settles it (decision 2026-10-16).
    if (got.count < r.expected_requests) return false
    const n = this.db.prepare(`UPDATE credit_reservations SET status = 'settled', updated_at = ?
      WHERE id = ? AND status IN ('open', 'unknown')`).run(nowMs, r.id).changes
    if (n === 1) this.event(nowMs, 'reservation_settled', { detail: { reservation_id: r.id, kind: 'batch', ingested_micro: got.l_micro } })
    return n === 1
  }

  // ---------------------------------------------------------------- tick

  /** One full evaluation: ledger refresh, every closing condition, maybe open. */
  tick(nowMs: number = this.nowFn()): TickResult {
    let rEst: number | null = null
    try {
      const g = this.gather(nowMs)
      const ev = this.txImmediate(() => this.evaluate(g, nowMs))
      rEst = ev.rEst
      if (ev.placeFailStarted !== null) this.logPlaceFailed('not_down', ev.placeFailStarted)
      if (this.enforcing && g.stopPath) {
        const out = this.syncStop(g.stopPath, nowMs, ev.releaseFirst)
        // CS1: the STOP came off, or would not for the first time: decide in
        // this tick, so the gate neither sits CLOSED without its STOP nor
        // keeps a stale reason. Once.
        if (out !== null) {
          const g2 = this.gather(nowMs)
          const ev2 = this.txImmediate(() => this.evaluate(g2, nowMs, out.released ? null : out.failed))
          rEst = ev2.rEst
          if (ev2.placeFailStarted !== null) this.logPlaceFailed('not_down', ev2.placeFailStarted)
          if (g2.stopPath) this.syncStop(g2.stopPath, nowMs)
        }
      }
    } catch (err) {
      // Anything unexpected: HOLD with the reason, never a silent skip. If
      // even that write fails, the error goes up to the caller's log.
      rEst = null
      this.txImmediate(() => this.fault(nowMs, 'tick_error', 'tick', err))
      this.applyCauseTx({ kind: 'hold', reason: 'tick_error' }, nowMs)
      this.syncStopNow(nowMs)
    }
    const final = this.peekState()
    return { state: final?.state ?? 'CLOSED', reason: final?.reason ?? 'initial', r_est_micro: rEst === null ? null : asMicro(rEst) }
  }

  /**
   * `releaseFailed`: CS1, this tick already tried to take the gate's own STOP
   * away and could not (the error code); the evaluation then decides the
   * closure instead of asking for the release again.
   */
  private evaluate(g: Gathered, nowMs: number, releaseFailed: string | null = null): Evaluation {
    const row = this.readState(nowMs)
    const prev = snapshotOf(row)
    const cfg = g.config
    const holdEvents: string[] = []
    // Every ledger call is guarded: a throw is recorded, and the evaluation
    // goes on without that number -- toward HOLD, never toward OPEN.
    let ledgerFailed = g.ledgerFailed
    const ledgerSafe = <T>(where: string, fn: () => T, fallback: T): T => {
      try {
        return fn()
      } catch (err) {
        ledgerFailed = true
        this.fault(nowMs, 'ledger_error', where, err)
        return fallback
      }
    }
    const ledger = g.ledgerFailed ? null : g.ledger
    ledgerSafe('upkeep', () => this.upkeep(ledger, nowMs, holdEvents), undefined)

    const calId = g.cal?.cal.id ?? null
    // The latch base: the largest calibration id ever seen, kept through an
    // outage of the source (BE-3).
    const maxCal = Math.max(row.max_calibration_id ?? 0, row.calibration_id ?? 0, row.latch_cal_id ?? 0, calId ?? 0)
    const sum: LedgerSum | null = ledger && g.cal
      ? ledgerSafe('ledgerSum', () => ledger.ledgerSum((g.cal as ValidCalibration).cal.captured_at_lb_ms), null)
      : null
    // Without a working ledger every open reservation counts in full.
    const open = ledgerSafe('openReservations', () => this.openReservations(ledger), null) ?? this.openReservations(null)
    const ageS = ledger ? ledgerSafe('ageS', () => ledger.ageS(nowMs), null) : null
    const money = g.cal && cfg ? grantMoney(g.cal, nowMs, cfg.expiryMarginH) : null
    const rEst = money && sum && !ledgerFailed ? money.live - sum.l_micro - open.total : null
    if (ledgerFailed) holdEvents.push('ledger_error')

    // B-06: one fresh-reading request per calibration at T_lowcal; after
    // lowcalWaitH without a new calibration the closing threshold rises. Only
    // a NEWER calibration resets it -- not a source outage and the same one back.
    const newerCal = calId !== null && calId > (row.max_calibration_id ?? 0)
    let lowReq = newerCal ? null : row.lowcal_requested_at
    let lowFb = newerCal ? null : row.lowcal_fallback_at
    const fe: EventFields = { rEst, l: sum?.l_micro ?? null, ageS, open: open.total, calId }
    if (cfg && rEst !== null) {
      if (rEst <= cfg.thresholds.tLowcal && lowReq === null) {
        lowReq = nowMs
        this.event(nowMs, 'lowcal_request', { ...fe, reason: 'lowcal' })
      }
      if (lowReq !== null && lowFb === null && nowMs - lowReq >= cfg.thresholds.lowcalWaitH * HOUR_MS) {
        lowFb = nowMs
        this.event(nowMs, 'lowcal_fallback', { ...fe, reason: 'lowcal_timeout' })
      }
    }
    const tCloseEff = cfg ? (lowFb !== null ? cfg.thresholds.tCloseLowcalFallback : cfg.thresholds.tClose) : null

    const incidents: string[] = []
    if (g.guard.events.length > 0) incidents.push('guard_event')
    if (g.guard.backlog > 0) incidents.push('guard_backlog')
    if (g.guard.damage) incidents.push(g.guard.damage)
    // LOW-B: every guard line is a cause of its own (in the order of `incidents`).
    const causes: IncidentCauseIn[] = []
    const shownEvents = g.guard.events.slice(0, GUARD_EVENTS_PER_TICK)
    for (const e of shownEvents) causes.push({ reason: 'guard_event', detail: { ...e } })
    if (g.guard.events.length > shownEvents.length) causes.push({ reason: 'guard_event', detail: { more: g.guard.events.length - shownEvents.length, at: nowMs } })
    if (g.guard.backlog > 0) causes.push({ reason: 'guard_backlog', detail: { lines: g.guard.backlog } })
    if (g.guard.damage) causes.push({ reason: g.guard.damage, detail: { damage: g.guard.damage } })
    const holdConditions: string[] = []
    // CW1: the gate's STOP could not be put down, and has not been since. First,
    // so the reason the failure set stays the reason while it lasts (B14).
    // CS2: in enforce mode a STOP that cannot even be checked (lstat EACCES on
    // a 000 directory, EIO) cannot be shown down either: the same episode, not
    // a transient close. It starts here, in the tick's own transaction, so its
    // one report is the HOLD itself (with why) -- not a CLOSED
    // `stop_unverifiable` first and the HOLD after it.
    const placeFailing = row.stop_place_failed_at !== null && row.stop_place_failed_at !== undefined
    const stopUnchecked = this.enforcing && g.stop?.kind === 'error' ? g.stop.why : null
    const placeFailStarts = !placeFailing && stopUnchecked !== null
    if (placeFailing || placeFailStarts) holdConditions.push('stop_place_failed')
    for (const id of g.refresh?.broken ?? []) holdConditions.push(`ledger_broken:${id}`)
    // K-01 (N7B1): a settled canary's after-reading is overdue. HOLD, the
    // STOP down, until the reading is recorded (the close) and a newer
    // calibration lifts the latch.
    const closeBy = this.canaryCloseBy(this.canaryWindow(), cfg)
    if (closeBy !== null && nowMs >= closeBy) holdConditions.push('canary_close_timeout')

    const latchCauses: string[] = []
    // L above 100 000 USD: the ledger only gives a floor; it will not shrink.
    if (sum?.saturated || open.saturated) latchCauses.push('ledger_saturated')
    if (rEst !== null && tCloseEff !== null && rEst <= tCloseEff) latchCauses.push('threshold')
    if (g.stop?.kind === 'human') latchCauses.push('human_stop')

    const closeReasons: string[] = []
    if (this.deps.mode.unknown) closeReasons.push('mode_unknown')
    else if (this.deps.mode.mode === 'shadow') closeReasons.push('shadow_mode')
    if (g.configReason) closeReasons.push(g.configReason)
    if (g.pricingReason) closeReasons.push(g.pricingReason)
    if (g.calReason) closeReasons.push(g.calReason)
    if (cfg && (ageS === null || ageS > cfg.maxLedgerAgeS)) closeReasons.push('ledger_stale')
    if (sum && sum.unpriced > 0) closeReasons.push('unpriced_rows')
    if (money && money.closeAtMs === null) closeReasons.push('no_live_grant')
    else if (money && money.closeAtMs !== null && nowMs >= money.closeAtMs) closeReasons.push('expired')
    if (cfg && g.cal && (g.cal.cal.protected.R_micro !== cfg.protected.R || g.cal.cal.protected.V_micro !== cfg.protected.V)) {
      closeReasons.push('protected_mismatch')
    }
    if (g.stop?.kind === 'error') closeReasons.push('stop_unverifiable')

    const reopenBlockers: string[] = cfg && rEst !== null && rEst < cfg.thresholds.tReopen ? ['below_reopen'] : []
    let next = decide({ prev, calibrationId: calId, latchBase: maxCal, incidents, holdEvents, holdConditions, latchCauses, closeReasons, reopenBlockers })

    // CS1: the gate would open, but its own STOP is still down (no canary
    // window keeps it). The STOP comes off FIRST, on the non-OPEN side
    // (syncStop with releaseFirst), and the opening is decided on the outcome:
    // the gate is never OPEN with its STOP down, and a release that keeps
    // failing is one closure, not an opening and a closure on every tick.
    // Until then the state stays as it was, with nothing reported (stateOnly).
    // Once this tick's release has failed, the closure is decided here:
    // CLOSED `stop_release_failed`, transient (nothing else closes the gate),
    // reported against the last reported pair (B14), so once per episode.
    const ownStopUp = next.state === 'OPEN' && row.state !== 'OPEN' && this.enforcing
      && g.stop?.kind === 'gate' && !this.canaryWindowOpen()
    const keep = ownStopUp && releaseFailed === null
    if (keep) next = prev
    else if (ownStopUp) next = { state: 'CLOSED', reason: 'stop_release_failed', latchCalId: null, latchReason: null }
    const placeFailReported = placeFailStarts && next.state === 'HOLD' && next.reason === 'stop_place_failed'
    const detail: Record<string, unknown> = ownStopUp && !keep
      ? { why: 'error', detail: releaseFailed }
      : placeFailReported
        ? { why: 'not_down', detail: stopUnchecked }
        : { close: closeReasons, hold: [...holdEvents, ...holdConditions], latch: latchCauses, guard_events: g.guard.events.length }

    if (g.guard.baseline) this.event(nowMs, 'guard_baseline', { ...fe, reason: g.guard.baseline.why, detail: { ...g.guard.baseline } })
    if (g.guard.damage && g.guard.newDamage) this.event(nowMs, 'guard_damage', { ...fe, reason: g.guard.damage })
    for (const e of g.guard.events.slice(0, GUARD_EVENTS_PER_TICK)) this.event(nowMs, 'guard_event', { ...fe, reason: 'guard_event', detail: e })
    const reported = this.writeState(row, next, nowMs, {
      calibration_id: calId,
      max_calibration_id: maxCal,
      last_stop_file: g.stopPath,
      t_close_eff_micro: tCloseEff,
      lowcal_requested_at: lowReq,
      lowcal_fallback_at: lowFb,
      guard_cursor_json: g.guard.cursor === null ? null : JSON.stringify(g.guard.cursor),
      evaluated_at: nowMs,
      mode: this.deps.mode.raw ?? this.deps.mode.mode,
      // CS2: the episode's start; the owner record stays (the STOP may be the gate's, only hidden).
      ...(placeFailStarts ? { stop_place_failed_at: nowMs } : {}),
      // CS1: an opening ends a release episode -- the STOP is gone.
      ...(next.state === 'OPEN' ? { stop_release_failed_at: null } : {}),
    }, { ...fe, detail }, causes, keep)
    // CS2, as CW1: the episode's one report row when its HOLD was not reported (INCIDENT, another HOLD reason, ...).
    if (placeFailStarts && !(reported && placeFailReported)) {
      this.event(nowMs, 'stop_place_failed', { ...fe, reason: 'not_down', calId: maxCal, detail: { why: 'not_down', detail: stopUnchecked } })
    }
    return {
      state: next.state,
      reason: next.reason,
      rEst,
      releaseFirst: keep ? (this.peekState() as StateRow).version : null,
      placeFailStarted: placeFailStarts ? stopUnchecked : null,
    }
  }

  // ---------------------------------------------------------------- STOP

  /**
   * Make the STOP match the state (enforce mode only): the gate's own STOP
   * down while not OPEN, away while OPEN. A human STOP is left alone; a race
   * during the release is a HOLD, and so is a STOP that cannot be put down or,
   * here, checked (CW1, CS2: stopPlaceFailed). `releaseFirst` (CS1): the
   * tick would open the gate and wrote this state version; if nothing has
   * changed it since, the gate's STOP comes off now, before the opening, and
   * the outcome goes back to the tick.
   */
  private syncStop(stopPath: string, nowMs: number, releaseFirst: number | null = null): ReleaseOutcome {
    const row = this.peekState()
    if (!row) return null
    const rec = parseStopOwner(row.stop_owner_json)
    const insp = inspectStop(this.stopFs, stopPath, rec)
    // K-01: an open canary window keeps the batch path stopped, OPEN or not.
    if (row.state === 'OPEN' && !this.canaryWindowOpen()) {
      if (insp.kind === 'human') {
        this.applyCauseTx({ kind: 'latch', reason: 'human_stop' }, nowMs)
        return null
      }
      if (insp.kind !== 'gate' || rec === null) return null
      this.releaseOwnStop(stopPath, rec, nowMs, true)
      return null
    }
    if (row.state === 'OPEN' && insp.kind === 'human') {
      this.applyCauseTx({ kind: 'latch', reason: 'human_stop' }, nowMs)
      return null
    }
    if (releaseFirst !== null && row.version === releaseFirst && insp.kind === 'gate' && rec !== null) {
      return this.releaseOwnStop(stopPath, rec, nowMs, false)
    }
    if (insp.kind === 'gate' && row.stop_place_failed_at !== null && row.stop_place_failed_at !== undefined) {
      // CW1: the gate's own STOP is down after all: the failure is over.
      this.txImmediate(() => this.updateState({ stop_place_failed_at: null }))
      return null
    }
    if (insp.kind === 'error') {
      // CS2: whether the STOP is down cannot be checked (lstat EACCES, EIO):
      // the batch path may be unstopped. The owner record stays: the STOP
      // under the name may well be the gate's own, only hidden.
      this.stopPlaceFailed(nowMs, 'not_down', insp.why, true)
      return null
    }
    if (insp.kind !== 'absent') return null
    const placed = placeStop(this.stopFs, stopPath, this.newNonce(), nowMs)
    if (!placed.placed && placed.why !== 'exists') {
      this.stopPlaceFailed(nowMs, placed.why, placed.detail ?? null)
      return null
    }
    this.txImmediate(() => {
      if (placed.placed) {
        // A new STOP of the gate's: the one it could not take away (CS1) is gone too.
        this.updateState({ stop_owner_json: JSON.stringify(placed.rec), stop_place_failed_at: null, stop_release_failed_at: null })
        this.event(nowMs, 'stop_placed', { detail: { nonce: placed.rec.nonce } })
      } else {
        this.updateState({ stop_owner_json: null })
        this.event(nowMs, 'stop_exists', { reason: placed.why, detail: { detail: placed.detail ?? null } })
      }
    })
    return null
  }

  /**
   * Take the gate's own STOP away: on an OPEN gate (`closeOpen`, e.g. once a
   * canary window closed), or before an opening (CS1, releaseFirst). A swap
   * during it is a HOLD (stop_race), a STOP that turned out not to be the
   * gate's a latched human_stop, and one that cannot be removed is
   * stopReleaseFailed. What the tick must decide again comes back.
   */
  private releaseOwnStop(stopPath: string, rec: StopOwnerRecord, nowMs: number, closeOpen: boolean): ReleaseOutcome {
    const rel = releaseStop(this.stopFs, stopPath, rec)
    if (rel.released) {
      this.txImmediate(() => {
        this.updateState({ stop_owner_json: null, stop_release_failed_at: null })
        this.event(nowMs, 'stop_released', { detail: { how: rel.how } })
      })
      return { released: true }
    }
    if (rel.why === 'raced') {
      this.txImmediate(() => {
        this.updateState({ stop_owner_json: null })
        this.event(nowMs, 'stop_race', { reason: 'stop_race', detail: { restored: rel.restored, both_present: rel.bothPresent } })
      })
      this.applyCauseTx({ kind: 'hold', reason: 'stop_race' }, nowMs)
      return null
    }
    if (rel.why === 'not_owner') {
      this.applyCauseTx({ kind: 'latch', reason: 'human_stop' }, nowMs)
      return null
    }
    this.stopReleaseFailed(nowMs, rel.detail, closeOpen)
    if (closeOpen) return null
    // Before an opening: the tick decides the closure (with why) unless the
    // gate already shows it -- every later failure in the episode is silent.
    const now = this.peekState()
    return now?.state === 'CLOSED' && now.reason === 'stop_release_failed' ? null : { released: false, failed: rel.detail }
  }

  /**
   * CS1: the gate's own STOP could not be taken away (rename EACCES on an r-x
   * directory, EROFS, ...), so the batch path stays stopped and the gate must
   * not claim OPEN. stop_release_failed_at marks the episode: the gate stays
   * CLOSED `stop_release_failed` while it lasts (each tick that would open it
   * tries the release first; evaluate() decides the closure), and the episode
   * gets ONE error log line. On an OPEN gate (`closeOpen`) the closure is
   * applied here, as a transient cause (never opens, never lowers a HOLD).
   * Reporting is writeState's, against the last reported pair (B14): one row
   * when the gate comes to CLOSED `stop_release_failed`, none while it stays.
   */
  private stopReleaseFailed(nowMs: number, detail: string, closeOpen: boolean): void {
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    const started = this.txImmediate((): boolean => {
      const row = this.readState(nowMs)
      const ongoing = row.stop_release_failed_at !== null && row.stop_release_failed_at !== undefined
      const at = ongoing ? row.stop_release_failed_at : nowMs
      if (closeOpen) {
        const next = applyCause(snapshotOf(row), { kind: 'transient', reason: 'stop_release_failed' }, calId)
        this.writeState(row, next, nowMs, { stop_release_failed_at: at }, { calId, detail: { why: 'error', detail } })
      } else if (!ongoing) {
        this.updateState({ stop_release_failed_at: at })
      }
      return !ongoing
    })
    if (started) logger.error({ detail }, 'credit gate: could not take its own STOP away; CLOSED until it can')
  }

  private logPlaceFailed(why: string, detail: string | null): void {
    logger.error({ why, detail }, 'credit gate: could not put the STOP down; HOLD until it is down and a newer calibration')
  }

  /**
   * CW1: the gate's STOP is not down when it must be -- placeStop failed
   * (EACCES, EROFS, a missing directory, a race), or a canary was admitted and
   * no STOP is down. HOLD `stop_place_failed`, latched under the latch base,
   * and the HOLD condition stop_place_failed_at, so the gate holds (never
   * OPEN) until the STOP is down again AND a calibration newer than the latch
   * lifts it -- decide()'s HOLD rule. The episode is reported ONCE, when it
   * starts: one report row (the HOLD transition carrying `why`; a
   * `stop_place_failed` row when the state does not change, e.g. INCIDENT) and
   * one error log line. Every later failure in the episode -- every tick tries
   * the STOP again -- writes nothing on a gate already holding at least this
   * hard (B14: no change against what was reported). `keepOwner` (CS2): the
   * STOP could not be checked, so it may be the gate's own, only hidden; its
   * record stays, or a repair would make it a human STOP.
   */
  private stopPlaceFailed(nowMs: number, why: string, detail: string | null, keepOwner = false): void {
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    const started = this.txImmediate((): boolean => {
      const row = this.readState(nowMs)
      const ongoing = row.stop_place_failed_at !== null && row.stop_place_failed_at !== undefined
      if (ongoing && STATE_SEVERITY[row.state] >= STATE_SEVERITY.HOLD) return false
      const next = applyCause(snapshotOf(row), { kind: 'hold', reason: 'stop_place_failed' }, calId)
      const d = { why, detail }
      const owner = keepOwner ? row.stop_owner_json : null
      const reported = this.writeState(row, next, nowMs, { stop_owner_json: owner, stop_place_failed_at: ongoing ? row.stop_place_failed_at : nowMs }, { calId, detail: d })
      if (ongoing) return false
      if (!reported) this.event(nowMs, 'stop_place_failed', { reason: why, calId, detail: d })
      return true
    })
    if (started) this.logPlaceFailed(why, detail)
  }

  /**
   * K-01 / CW1: right after a canary's admission (and its STOP step) the
   * batch path must be stopped: a STOP of the gate's or a human's under the
   * name. Anything else -- no STOP path, none there, or one that cannot be
   * checked -- is stopPlaceFailed.
   */
  private requireStopDown(nowMs: number): void {
    const { config } = this.loadConfig()
    const row = this.peekState()
    const stopPath = config?.stopFile ?? row?.last_stop_file ?? null
    if (stopPath === null) {
      this.stopPlaceFailed(nowMs, 'not_down', 'no_stop_path')
      return
    }
    const insp = inspectStop(this.stopFs, stopPath, parseStopOwner(row?.stop_owner_json))
    if (insp.kind === 'gate' || insp.kind === 'human') return
    this.stopPlaceFailed(nowMs, 'not_down', insp.kind === 'error' ? insp.why : 'absent', insp.kind === 'error')
  }

  /** One closing cause in its own transaction (never opens). */
  private applyCauseTx(cause: Cause, nowMs: number, detail: Record<string, unknown> | null = null): StateSnapshot {
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    return this.txImmediate(() => {
      const row = this.readState(nowMs)
      const next = applyCause(snapshotOf(row), cause, calId)
      this.writeState(row, next, nowMs, {}, { calId, detail }, cause.kind === 'incident' ? [{ reason: cause.reason, detail }] : [])
      return next
    })
  }

  private syncStopNow(nowMs: number): void {
    if (!this.enforcing) return
    const { config } = this.loadConfig()
    const stopPath = config?.stopFile ?? this.peekState()?.last_stop_file ?? null
    if (stopPath) this.syncStop(stopPath, nowMs)
  }

  // ---------------------------------------------------------------- reservations

  /** K-01: a canary run holds its reservation open (settled at its end, or unknown when stale). */
  canaryInProgress(): boolean {
    return this.db.prepare(`SELECT 1 FROM credit_reservations WHERE kind = 'canary' AND status = 'open' LIMIT 1`).get() !== undefined
  }

  /** K-01 (N7B1): the open canary window, read from the database; null = none. */
  private canaryWindow(): CanaryWindow | null {
    const row = this.peekState()
    if (!row || row.canary_res_id === null || row.canary_res_id === undefined) return null
    const r = this.reservation(row.canary_res_id)
    return {
      reservationId: row.canary_res_id,
      runId: r?.ref ?? null,
      openedAt: row.canary_opened_at,
      // A reservation that cannot be read counts as ended at the opening:
      // the deadline runs, and the window still holds (fail-closed).
      endedAt: r ? (r.status === 'open' ? null : r.updated_at) : (row.canary_opened_at ?? 0),
      calibrationId: r?.calibration_id ?? null,
    }
  }

  /** When an open window's after-reading is overdue (its settle + canaryCloseMaxH); null = not yet running. */
  private canaryCloseBy(w: CanaryWindow | null, config: CreditGateConfig | null): number | null {
    if (w === null || w.endedAt === null) return null
    // Without a valid config the code's ceiling applies; the config never goes above it.
    return w.endedAt + Math.min(config?.canaryCloseMaxH ?? MAX_CANARY_CLOSE_H, MAX_CANARY_CLOSE_H) * HOUR_MS
  }

  /**
   * K-01 (N7B1): why nothing else may be admitted now -- the canary's
   * reservation is open, or its window is (settled, after-reading not yet
   * recorded); null = no canary holds the batch path.
   */
  canaryBlock(): 'canary_in_progress' | 'canary_window_open' | null {
    if (this.canaryInProgress()) return 'canary_in_progress'
    const row = this.peekState()
    return row && row.canary_res_id !== null && row.canary_res_id !== undefined ? 'canary_window_open' : null
  }

  /** K-01 (N7B1): the batch path stays on the gate's STOP (from the canary's admission to its close). */
  canaryWindowOpen(): boolean {
    return this.canaryBlock() !== null
  }

  /** BE-4b: reservations of any kind that are open or unknown; a canary starts only at zero. */
  openReservationCount(): number {
    return (this.db.prepare(`SELECT COUNT(*) AS n FROM credit_reservations WHERE status IN ('open', 'unknown')`).get() as { n: number }).n
  }

  /** BE-4b: the open headless and canary reservations (headless.maxConcurrent). */
  private openHeadlessCount(): number {
    return (this.db.prepare(`SELECT COUNT(*) AS n FROM credit_reservations
      WHERE kind IN ('headless', 'canary') AND status = 'open'`).get() as { n: number }).n
  }

  /** BE-4b: what the headless and canary reservations since `sinceMs` add up to, released ones aside. */
  private headlessReservedSince(sinceMs: number): number {
    return (this.db.prepare(`SELECT COALESCE(SUM(amount_micro), 0) AS t FROM credit_reservations
      WHERE kind IN ('headless', 'canary') AND status <> 'released' AND created_at > ?`).get(sinceMs) as { t: number }).t
  }

  /** Admit one job, or refuse it: one BEGIN IMMEDIATE transaction, no await. */
  reserve(req: ReserveRequest, nowMs: number = this.nowFn()): ReserveResult {
    if (!this.enforcing) return { enforced: false }
    const invalid = this.validateRequest(req)
    if (invalid) return { enforced: true, ok: false, reason: 'invalid_request', detail: invalid }

    // File inputs first, outside the lock; the decision below cross-checks them.
    const { config, reason: configReason } = this.loadConfig()
    const { table, reason: pricingReason } = this.loadTable(nowMs)
    const { cal, reason: calReason } = this.loadCalibration(nowMs)
    let ledger: CreditLedger | null = null
    let ledgerInitError: unknown = null
    try {
      ledger = config ? this.ledgerFor(config) : null
    } catch (err) {
      ledgerInitError = err
    }

    let closed = false
    let result: ReserveResult
    try {
      result = this.txImmediate((): ReserveResult => {
        const row = this.readState(nowMs)
        const prev = snapshotOf(row)
        const fe: { rEst?: number; l?: number; open?: number } = {}
        const reject = (reason: string, detail?: string): ReserveResult => {
          this.event(nowMs, 'reservation_rejected', { ...fe, reason, calId: row.calibration_id, detail: { kind: req.kind, caller: req.caller, detail: detail ?? null } })
          return { enforced: true, ok: false, reason, ...(detail ? { detail } : {}) }
        }
        // Every closure here latches under the largest calibration id ever seen.
        const latchBase = Math.max(row.max_calibration_id ?? 0, row.calibration_id ?? 0)
        const close = (cause: Cause, answer: string = cause.reason): ReserveResult => {
          const next = applyCause(prev, cause, latchBase)
          this.writeState(row, next, nowMs, {}, { ...fe, calId: row.calibration_id })
          closed = next.state !== 'OPEN'
          return reject(answer)
        }
        // A throw from the ledger is a HOLD, from the pricing a CLOSED; both
        // are recorded in this transaction, which then commits the closure.
        const fail = (reason: 'ledger_error' | 'pricing_error', where: string, err: unknown): ReserveResult => {
          this.fault(nowMs, reason, where, err)
          return close({ kind: reason === 'ledger_error' ? 'hold' : 'transient', reason })
        }
        type Guarded<T> = { ok: true; v: T } | { ok: false; r: ReserveResult }
        const guard = <T>(reason: 'ledger_error' | 'pricing_error', where: string, fn: () => T): Guarded<T> => {
          try {
            return { ok: true, v: fn() }
          } catch (err) {
            return { ok: false, r: fail(reason, where, err) }
          }
        }

        if (this.deps.mode.unknown) return reject('gate_closed', 'mode_unknown')
        if (row.state !== 'OPEN') return reject('gate_closed', row.reason)
        // K-01 (N7B1): nothing else (and no second canary) from a canary's
        // admission until its after-reading is recorded.
        const block = this.canaryBlock()
        if (block !== null) return reject(block)
        // BE-4b: a canary only alone -- nothing else open or unknown, of any kind.
        if (req.kind === 'canary' && this.openReservationCount() > 0) return reject('reservations_open')
        if (ledgerInitError !== null) return fail('ledger_error', 'ledger_init', ledgerInitError)
        if (!config || !ledger) return close({ kind: 'transient', reason: configReason ?? 'config_invalid' })
        const lg = ledger
        const maxAgeMs = config.maxLedgerAgeS * 1000
        // A-02: the ledger must be at most maxLedgerAgeS old, right now.
        const ageG = guard('ledger_error', 'ageS', () => lg.ageS(nowMs))
        if (!ageG.ok) return ageG.r
        const age = ageG.v
        if (age === null || age > config.maxLedgerAgeS) return close({ kind: 'transient', reason: 'ledger_stale' })
        // A-04: the decision stands on an evaluation at most as old as that.
        if (row.evaluated_at === null || nowMs - row.evaluated_at > maxAgeMs) return close({ kind: 'transient', reason: 'gate_state_stale' })
        if (!table) return close({ kind: 'transient', reason: pricingReason ?? 'pricing_invalid' })
        if (!cal) return close({ kind: 'transient', reason: calReason ?? 'no_calibration' })
        // The tick decided on another calibration: let it evaluate this one first.
        if (cal.cal.id !== row.calibration_id) return reject('calibration_changed')
        const money = grantMoney(cal, nowMs, config.expiryMarginH)
        if (money.closeAtMs === null) return close({ kind: 'transient', reason: 'no_live_grant' })
        if (nowMs >= money.closeAtMs) return close({ kind: 'transient', reason: 'expired' })
        // BE-3 (decision 2026-10-16, a stricter reading of C-06/D-04): the job
        // must be able to finish before the credit it is counted against
        // expires. Its horizon: 24 h for a batch, wallClockMin for a headless
        // run. Only grants alive at now + horizon count, and nothing is
        // admitted after the last expiry - max(margin, horizon).
        const horizonMs = req.kind === 'batch'
          ? config.batchHorizonH * HOUR_MS
          : config.headless === null ? null : config.headless.wallClockMin * MINUTE_MS
        if (horizonMs === null) return reject('headless_disabled')
        const hc = config.headless
        if (req.kind !== 'batch' && hc !== null && this.openHeadlessCount() >= hc.maxConcurrent) {
          return reject('concurrency_limit', String(hc.maxConcurrent))
        }
        const cutoffMs = (money.lastExpiryMs as number) - Math.max(config.expiryMarginH * HOUR_MS, horizonMs)
        if (nowMs >= cutoffMs) return reject('expiry_horizon', iso(cutoffMs) ?? undefined)
        const sumG = guard('ledger_error', 'ledgerSum', () => lg.ledgerSum(cal.cal.captured_at_lb_ms))
        if (!sumG.ok) return sumG.r
        const sum = sumG.v
        if (sum.unpriced > 0) return close({ kind: 'transient', reason: 'unpriced_rows' })
        if (sum.saturated) return close({ kind: 'latch', reason: 'ledger_saturated' })

        const amountG = guard('pricing_error', 'amount', () => req.kind === 'batch'
          ? batchReservationAmount(table, req.model, req.input_tokens_total, req.max_output_tokens_total)
          : applyFactorCeil(req.budget_micro, config.reservationFactor))
        if (!amountG.ok) return amountG.r
        const amount = amountG.v
        if (amount === null) return reject('model_unpriced', req.model)
        // BE-4b: the optional daily cap (off unless headless.dailyCapUsd is set; D-10).
        if (req.kind !== 'batch' && hc !== null && hc.dailyCap !== null && this.headlessReservedSince(nowMs - DAY_MS) + amount > hc.dailyCap) {
          return reject('daily_cap', formatUsd(hc.dailyCap))
        }
        const openG = guard('ledger_error', 'openReservations', () => this.openReservations(lg))
        if (!openG.ok) return openG.r
        const open = openG.v
        if (open.saturated) return close({ kind: 'latch', reason: 'ledger_saturated' })
        const rEst = money.live - sum.l_micro - open.total
        fe.rEst = rEst
        fe.l = sum.l_micro
        fe.open = open.total
        const tCloseEff = row.t_close_eff_micro ?? config.thresholds.tClose
        // C-04: at or below T_close the gate is closed, whatever is asked.
        if (rEst <= tCloseEff) return close({ kind: 'latch', reason: 'threshold' }, 'below_threshold')
        const after = rEst - amount
        // C-02/C-03: admitted only if R_est after the reservation is still >=
        // T_close -- counted on the grants alive at the end of the horizon.
        const afterAtHorizon = liveAt(cal, nowMs + horizonMs) - sum.l_micro - open.total - amount
        if (afterAtHorizon < tCloseEff) return reject('below_threshold', `amount ${formatUsd(amount)}`)

        const id = this.newId()
        if (!RESERVATION_ID_RE.test(id)) throw new Error('credit gate: the id generator returned an unusable id')
        this.db.prepare(`INSERT INTO credit_reservations
            (id, kind, ref, amount_micro, request_count, expected_requests, status, caller, model, calibration_id, created_at, updated_at)
          VALUES (?, ?, ?, ?, ?, NULL, 'open', ?, ?, ?, ?, ?)`).run(
          id, req.kind, req.kind === 'batch' ? null : req.ref, amount, req.kind === 'batch' ? req.request_count : null,
          req.caller, req.model, row.calibration_id, nowMs, nowMs,
        )
        if (req.kind === 'canary') {
          // K-01 (N7B1): the window opens with the admission, in this
          // transaction; only closeCanary (the after-reading) closes it.
          this.updateState({ canary_res_id: id, canary_opened_at: nowMs })
          this.event(nowMs, 'canary_window_opened', { reason: 'canary_admitted', calId: row.calibration_id, detail: { reservation_id: id, run_id: req.ref } })
        }
        let closedNow = false
        if (after <= tCloseEff) {
          // C-04 right behind the admission: R_est is now exactly T_close.
          const next = applyCause(prev, { kind: 'latch', reason: 'threshold' }, latchBase)
          this.writeState(row, next, nowMs, {}, { rEst: after, l: sum.l_micro, open: open.total + amount, calId: row.calibration_id })
          closedNow = true
          closed = true
        }
        return { enforced: true, ok: true, reservation_id: id, amount_micro: amount, r_est_after_micro: asMicro(after), closed: closedNow }
      })
    } catch (err) {
      if (isBusy(err)) return { enforced: true, ok: false, reason: 'gate_busy' }
      throw err
    }
    // K-01: a canary's STOP is down before its run can spend anything; if it
    // is not, the gate holds (CW1). The canary's own reservation stands: it was
    // admitted, and its window keeps everything else out.
    const canaryAdmitted = req.kind === 'canary' && result.enforced && result.ok
    if (closed || canaryAdmitted) this.syncStopNow(nowMs)
    if (canaryAdmitted) this.requireStopDown(nowMs)
    return result
  }

  private validateRequest(req: ReserveRequest): string | null {
    if (typeof req !== 'object' || req === null) return 'request'
    if (typeof req.model !== 'string' || !MODEL_RE.test(req.model)) return 'model'
    if (typeof req.caller !== 'string' || !CALLER_RE.test(req.caller)) return 'caller'
    if (req.kind === 'batch') {
      if (!isCount(req.input_tokens_total, MAX_TOKENS_TOTAL)) return 'input_tokens_total'
      if (!isCount(req.max_output_tokens_total, MAX_TOKENS_TOTAL)) return 'max_output_tokens_total'
      if (!isCount(req.request_count, MAX_REQUESTS) || req.request_count < 1) return 'request_count'
      return null
    }
    if (req.kind === 'headless' || req.kind === 'canary') {
      if (!isCount(req.budget_micro, MAX_USD_AMOUNT_MICRO) || req.budget_micro <= 0) return 'budget'
      if (typeof req.ref !== 'string' || !REF_RE.test(req.ref)) return 'ref'
      return null
    }
    return 'kind'
  }

  private reservation(id: string): ReservationRow | null {
    if (typeof id !== 'string' || !RESERVATION_ID_RE.test(id)) return null
    return (this.db.prepare('SELECT * FROM credit_reservations WHERE id = ?').get(id) as ReservationRow | undefined) ?? null
  }

  private opTx(fn: () => OpResult): OpResult {
    try {
      return this.txImmediate(fn)
    } catch (err) {
      if (isBusy(err)) return { ok: false, code: 409, reason: 'gate_busy' }
      throw err
    }
  }

  /**
   * The batch was accepted: tie the reservation to its batch_id. Idempotent.
   * BE-3: the binding cannot shrink the reservation -- expected_requests must
   * be the request count it was reserved for, and a batch_id that already has
   * ledger rows (or another reservation) is refused, since those rows would
   * count against this reservation's open part at once.
   */
  bind(id: string, batchId: string, expectedRequests: number, nowMs: number = this.nowFn()): OpResult {
    if (typeof batchId !== 'string' || !BATCH_ID_RE.test(batchId)) return { ok: false, code: 409, reason: 'invalid_batch_id' }
    if (!isCount(expectedRequests, MAX_REQUESTS) || expectedRequests < 1) return { ok: false, code: 409, reason: 'invalid_expected_requests' }
    const { config } = this.loadConfig()
    let ledger: CreditLedger | null = null
    let ledgerInitError: unknown = null
    try {
      ledger = config ? this.ledgerFor(config) : null
    } catch (err) {
      ledgerInitError = err
    }
    const latchBase = this.latchBaseFor(this.peekState(), nowMs)
    let held = false
    const out = this.opTx(() => {
      const r = this.reservation(id)
      if (!r) return { ok: false, code: 404, reason: 'not_found' }
      if (r.kind !== 'batch') return { ok: false, code: 409, reason: 'not_batch' }
      if (r.ref !== null) {
        if (r.ref === batchId && r.expected_requests === expectedRequests) return { ok: true, status: r.status, changed: false }
        return { ok: false, code: 409, reason: 'bound' }
      }
      if (r.status !== 'open') return { ok: false, code: 409, reason: `status_${r.status}` }
      if (r.request_count === null || expectedRequests !== r.request_count) return { ok: false, code: 409, reason: 'expected_mismatch' }
      const taken = this.db.prepare(`SELECT id FROM credit_reservations WHERE kind = 'batch' AND ref = ?`).get(batchId)
      if (taken) return { ok: false, code: 409, reason: 'batch_taken' }
      if (ledgerInitError === null && ledger === null) return { ok: false, code: 409, reason: 'ledger_unavailable' }
      try {
        if (ledgerInitError !== null) throw ledgerInitError
        if ((ledger as CreditLedger).ingestedForBatch(batchId).count > 0) return { ok: false, code: 409, reason: 'batch_has_rows' }
      } catch (err) {
        this.fault(nowMs, 'ledger_error', 'bind', err)
        const row = this.readState(nowMs)
        this.writeState(row, applyCause(snapshotOf(row), { kind: 'hold', reason: 'ledger_error' }, latchBase), nowMs, {}, { calId: latchBase })
        held = true
        return { ok: false, code: 409, reason: 'ledger_error' }
      }
      this.db.prepare('UPDATE credit_reservations SET ref = ?, expected_requests = ?, updated_at = ? WHERE id = ?')
        .run(batchId, expectedRequests, nowMs, r.id)
      this.event(nowMs, 'reservation_bound', { detail: { reservation_id: r.id, batch_id: batchId, expected_requests: expectedRequests } })
      return { ok: true, status: 'open', changed: true }
    })
    if (held) this.syncStopNow(nowMs)
    return out
  }


  /** The batch client has every result: settle once the ledger holds them all. Idempotent. */
  complete(id: string, nowMs: number = this.nowFn()): OpResult {
    const { config } = this.loadConfig()
    let ledger: CreditLedger | null = null
    let ledgerInitError: unknown = null
    try {
      ledger = config ? this.ledgerFor(config) : null
    } catch (err) {
      ledgerInitError = err
    }
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    let held = false
    const out = this.opTx(() => {
      const r = this.reservation(id)
      if (!r) return { ok: false, code: 404, reason: 'not_found' }
      if (r.kind !== 'batch') return { ok: false, code: 409, reason: 'not_batch' }
      if (r.status === 'settled') return { ok: true, status: 'settled', changed: false }
      if (r.status === 'released') return { ok: false, code: 409, reason: 'status_released' }
      if (r.ref === null) return { ok: false, code: 409, reason: 'unbound' }
      const requestedNow = r.complete_requested_at === null
      if (requestedNow) {
        this.db.prepare('UPDATE credit_reservations SET complete_requested_at = ?, updated_at = ? WHERE id = ?').run(nowMs, nowMs, r.id)
        r.complete_requested_at = nowMs
      }
      let settled = false
      try {
        if (ledgerInitError !== null) throw ledgerInitError
        settled = ledger !== null && this.trySettleBatch(r, ledger, nowMs)
      } catch (err) {
        // The request to complete is kept; the reservation stays counted, and HOLD.
        this.fault(nowMs, 'ledger_error', 'complete', err)
        const row = this.readState(nowMs)
        this.writeState(row, applyCause(snapshotOf(row), { kind: 'hold', reason: 'ledger_error' }, calId), nowMs, {}, { calId })
        held = true
        return { ok: false, code: 409, reason: 'ledger_error' }
      }
      return { ok: true, status: settled ? 'settled' : r.status, changed: settled || requestedNow }
    })
    if (held) this.syncStopNow(nowMs)
    return out
  }

  /**
   * `rejected_4xx`: the API provably refused the batch, the reservation is
   * given back (only before a batch_id was bound). `unknown_outcome`: nobody
   * knows whether it went out -- the reservation stays counted, and HOLD.
   */
  release(id: string, reason: 'rejected_4xx' | 'unknown_outcome', nowMs: number = this.nowFn()): OpResult {
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    let held = false
    const out = this.opTx(() => {
      const r = this.reservation(id)
      if (!r) return { ok: false, code: 404, reason: 'not_found' }
      if (reason === 'rejected_4xx') {
        if (r.kind !== 'batch') return { ok: false, code: 409, reason: 'not_batch' }
        if (r.ref !== null) return { ok: false, code: 409, reason: 'bound' }
        if (r.status === 'released') return { ok: true, status: 'released', changed: false }
        if (r.status !== 'open') return { ok: false, code: 409, reason: `status_${r.status}` }
        this.db.prepare(`UPDATE credit_reservations SET status = 'released', reason = ?, updated_at = ? WHERE id = ?`).run(reason, nowMs, r.id)
        this.event(nowMs, 'reservation_released', { reason, detail: { reservation_id: r.id } })
        return { ok: true, status: 'released', changed: true }
      }
      if (reason !== 'unknown_outcome') return { ok: false, code: 409, reason: 'invalid_reason' }
      if (r.status === 'unknown') return { ok: true, status: 'unknown', changed: false }
      if (r.status !== 'open') return { ok: false, code: 409, reason: `status_${r.status}` }
      this.db.prepare(`UPDATE credit_reservations SET status = 'unknown', reason = ?, updated_at = ? WHERE id = ?`).run(reason, nowMs, r.id)
      this.event(nowMs, 'reservation_unknown', { reason, detail: { reservation_id: r.id, kind: r.kind } })
      const row = this.readState(nowMs)
      this.writeState(row, applyCause(snapshotOf(row), { kind: 'hold', reason: 'reservation_unknown' }, calId), nowMs, {}, { calId })
      held = true
      return { ok: true, status: 'unknown', changed: true }
    })
    if (held) this.syncStopNow(nowMs)
    return out
  }

  /**
   * A headless (or canary) run is over: book it in the ledger (when `run` is
   * given; N4a passes it) and settle its reservation, in one transaction.
   * The booking uses the reservation's own amount for B-04. If the ledger
   * throws, nothing is settled -- the reservation keeps counting in full --
   * and the gate goes to HOLD. Idempotent.
   */
  settleHeadless(id: string, run: HeadlessRun | null = null, nowMs: number = this.nowFn()): OpResult {
    let ledger: CreditLedger | null = null
    let ledgerInitError: unknown = null
    let table: PricingTable | null = null
    if (run !== null) {
      const { config } = this.loadConfig()
      table = this.loadTable(nowMs).table
      try {
        ledger = config ? this.ledgerFor(config) : null
      } catch (err) {
        ledgerInitError = err
      }
    }
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    let held = false
    let canaryEnded = false
    const out = this.opTx(() => {
      const r = this.reservation(id)
      if (!r) return { ok: false, code: 404, reason: 'not_found' }
      if (r.kind === 'batch') return { ok: false, code: 409, reason: 'not_headless' }
      if (r.status === 'settled') return { ok: true, status: 'settled', changed: false }
      if (r.status === 'released') return { ok: false, code: 409, reason: 'status_released' }
      if (run !== null) {
        if (ledger === null && ledgerInitError === null) return { ok: false, code: 409, reason: 'ledger_unavailable' }
        try {
          if (ledgerInitError !== null) throw ledgerInitError
          ;(ledger as CreditLedger).recordHeadless({ ...run, reservation_micro: asMicro(r.amount_micro) }, table, nowMs)
        } catch (err) {
          this.fault(nowMs, 'ledger_error', 'recordHeadless', err)
          const row = this.readState(nowMs)
          this.writeState(row, applyCause(snapshotOf(row), { kind: 'hold', reason: 'ledger_error' }, calId), nowMs, {}, { calId })
          held = true
          return { ok: false, code: 409, reason: 'ledger_error' }
        }
      }
      this.db.prepare(`UPDATE credit_reservations SET status = 'settled', updated_at = ? WHERE id = ?`).run(nowMs, r.id)
      this.event(nowMs, 'reservation_settled', { detail: { reservation_id: r.id, kind: r.kind } })
      if (r.kind === 'canary') canaryEnded = true
      return { ok: true, status: 'settled', changed: true }
    })
    // K-01: the canary's run is over, but its window stays open -- the STOP
    // stays down -- until its after-reading is recorded (closeCanary, N7B1).
    if (held || canaryEnded) this.syncStopNow(nowMs)
    return out
  }

  /**
   * K-01 (N7B1): the close step of the canary window. The calibration
   * processor calls it when it records the after-reading -- the next
   * non-rejected reading -- inside its own transaction (`syncStop: false`; it
   * syncs the STOP after the commit). The reading must be newer than the
   * calibration the canary was admitted under. Without an open window (never
   * one, or closed already) it is refused and nothing changes. A window whose
   * canary still runs closes as well: the open reservation keeps the STOP
   * down until its settle, and that early reading cannot see the run's cost.
   */
  closeCanary(afterCalibrationId: number, nowMs: number = this.nowFn(), syncStop = true): CanaryCloseResult {
    if (!Number.isSafeInteger(afterCalibrationId) || afterCalibrationId <= 0) return { ok: false, reason: 'invalid_request' }
    const out = this.txImmediate((): CanaryCloseResult => {
      const w = this.canaryWindow()
      if (w === null) return { ok: false, reason: 'no_canary_window' }
      if (w.calibrationId !== null && afterCalibrationId <= w.calibrationId) return { ok: false, reason: 'not_an_after_reading' }
      this.updateState({ canary_res_id: null, canary_opened_at: null })
      this.event(nowMs, 'canary_window_closed', {
        reason: 'after_reading',
        calId: afterCalibrationId,
        detail: { reservation_id: w.reservationId, run_id: w.runId, opened_at: iso(w.openedAt), run_ended_at: iso(w.endedAt) },
      })
      return { ok: true, reservation_id: w.reservationId }
    })
    if (out.ok && syncStop) this.syncStopNow(nowMs)
    return out
  }

  // ---------------------------------------------------------------- signals, incidents

  /** An unapproved signal: it can only close (blueprint 3.5, 14). */
  signal(kind: SignalKind, source: string, detail: string | null, nowMs: number = this.nowFn()): { readonly enforced: boolean; readonly state: GateState } {
    const cause = SIGNAL_CAUSE[kind]
    if (!cause) throw new Error('credit gate: unknown signal kind')
    const src = typeof source === 'string' && SOURCE_RE.test(source) ? source : '?'
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    const next = this.txImmediate(() => {
      const row = this.readState(nowMs)
      const prev = snapshotOf(row)
      // B14: on a gate already latched this hard, the signal is its own audit
      // row below and nothing else -- no new reason, no new latch reason.
      const n = applySignal(prev, cause, calId)
      const signalId = this.event(nowMs, 'signal', { reason: kind, calId, detail: { source: src, detail: scrubDetail(detail) } })
      if (n === prev && cause.kind !== 'incident') return n
      // B10: any Bearer caller can send a signal, with any source and detail.
      // Those stay in the signal's own audit row above; the INCIDENT cause is
      // the kind alone (at most one open per kind) and only names that row.
      // Otherwise every new detail would open a cause, a directive and an
      // owner clear of its own. B12: and a new reason in the same state (a
      // transient CLOSED gate's first disarm, a re-latch under a newer
      // calibration) is no transition either -- the state row takes it, the
      // signal's own row reports it (coalesced per kind), and a genuine state
      // change never queues behind it. B14: a tick that gives the gate's own
      // reason back is no transition either -- writeState compares with what
      // was reported, which a signal moves only with a change of state; a tick
      // that keeps the signal's reason (a first latch) reports it once.
      this.writeState(row, n, nowMs, {}, { calId }, cause.kind === 'incident'
        ? [{ reason: cause.reason, detail: { signal_event_id: signalId }, key: { signal_kind: kind } }]
        : [], true)
      return n
    })
    if (next.state !== 'OPEN') this.syncStopNow(nowMs)
    return { enforced: this.enforcing, state: next.state }
  }

  /**
   * N2c: an owner's incident-clear lifts ONE cause -- the newest open one,
   * named by its event id (MED-1). With another cause still open the gate
   * stays in INCIDENT and the next clear names that one; the last one leaves
   * INCIDENT into a latched CLOSED. True when a cause was lifted.
   */
  clearIncident(eventId: number, nowMs: number = this.nowFn()): boolean {
    const calId = this.latchBaseFor(this.peekState(), nowMs)
    return this.txImmediate(() => {
      const row = this.readState(nowMs)
      if (row.state !== 'INCIDENT' || row.incident_event_id === null || row.incident_event_id !== eventId) return false
      const rest = openIncidentCauses(row).filter((c) => c.event_id !== eventId)
      if (rest.length > 0) {
        const newest = rest[rest.length - 1] as IncidentCause
        this.event(nowMs, 'incident_cause_cleared', { reason: row.reason, calId, detail: { incident_event_id: eventId, open: rest.map((c) => c.event_id) } })
        this.updateState({ reason: newest.reason, incident_event_id: newest.event_id, incident_open_json: JSON.stringify(rest) })
        return true
      }
      this.writeState(row, clearIncidentState(snapshotOf(row), calId), nowMs, {}, { calId, detail: { incident_event_id: eventId } })
      return true
    })
  }

  /**
   * N2c: D-02 / K-03 findings. `syncStop: false` when the caller runs inside
   * its own transaction: it calls syncStopFile() after the commit.
   */
  raiseIncident(reason: string, detail: Record<string, unknown> | null, nowMs: number = this.nowFn(), syncStop = true): void {
    this.applyCauseTx({ kind: 'incident', reason }, nowMs, detail)
    if (syncStop) this.syncStopNow(nowMs)
  }

  /** N2c: B-05, an undecidable reading or canary: HOLD, lifted only by a newer calibration. */
  raiseHold(reason: string, detail: Record<string, unknown> | null, nowMs: number = this.nowFn(), syncStop = true): void {
    this.applyCauseTx({ kind: 'hold', reason }, nowMs, detail)
    if (syncStop) this.syncStopNow(nowMs)
  }

  /** N2c: make the STOP match the state now (after a transaction that changed it). */
  syncStopFile(nowMs: number = this.nowFn()): void {
    this.syncStopNow(nowMs)
  }

  /** N2c: an audit row of its own (calibration, incident-clear, canary). Names and numbers only. */
  audit(kind: string, f: { readonly reason?: string | null; readonly calId?: number | null; readonly detail?: Record<string, unknown> | null } = {}, nowMs: number = this.nowFn()): number {
    return this.event(nowMs, kind, f)
  }

  /**
   * N2c, after an owner reviewed a damaged guard-event file: a new baseline
   * at the file's current end (the lines in it now count as reviewed). A file
   * that still cannot be read stays broken.
   */
  resetGuardCursor(nowMs: number = this.nowFn()): void {
    const path = this.deps.guardEventsPath
    if (path === null) return
    const b = guardBaseline(path, 'reset')
    this.txImmediate(() => {
      this.readState(nowMs)
      if ('damage' in b) {
        this.updateState({ guard_cursor_json: JSON.stringify({ broken: b.damage }) })
        this.event(nowMs, 'guard_damage', { reason: b.damage, detail: { during: 'reset' } })
        return
      }
      this.updateState({ guard_cursor_json: JSON.stringify(b.cursor) })
      this.event(nowMs, 'guard_baseline', { reason: 'reset', detail: { ...b.baseline } })
    })
  }

  // ---------------------------------------------------------------- status

  /** The read-only view (L-03); never writes. */
  status(nowMs: number = this.nowFn()): GateStatus {
    const row = this.peekState()
    const { config } = this.loadConfig()
    const { cal } = this.loadCalibration(nowMs)
    let ledger: CreditLedger | null = null
    let ledgerInitFailed = false
    try {
      ledger = config ? this.ledgerFor(config) : null
    } catch (err) {
      ledgerInitFailed = true
      logger.error({ err }, 'credit gate: the ledger could not be built for the status')
    }
    // Read-only: a ledger failure is logged and shown, not written (the tick
    // records it and holds).
    let ledgerError: string | null = null
    let sum: LedgerSum | null = null
    let open = { total: 0, count: 0, saturated: false }
    let age: number | null = null
    try {
      sum = ledger && cal ? ledger.ledgerSum(cal.cal.captured_at_lb_ms) : null
      open = this.openReservations(ledger)
      age = ledger ? ledger.ageS(nowMs) : null
    } catch (err) {
      ledgerError = 'ledger_error'
      logger.error({ err }, 'credit gate: the ledger failed while computing the status')
      sum = null
      open = this.openReservations(null)
      age = null
    }
    const money = cal && config ? grantMoney(cal, nowMs, config.expiryMarginH) : null
    const rEst = money && sum ? money.live - sum.l_micro - open.total : null
    const sources = config
      ? config.ledgerSources.map((s) => {
          const c = this.db.prepare('SELECT status, reason FROM credit_ledger_cursors WHERE source = ?').get(s.id) as
            { status: string; reason: string | null } | undefined
          return { id: s.id, status: c?.status ?? 'unread', reason: c?.reason ?? null }
        })
      : []
    const t = config?.thresholds
    return {
      mode: this.deps.mode.mode,
      mode_raw: this.deps.mode.raw,
      enforced: this.enforcing,
      state: row?.state ?? 'CLOSED',
      reason: row?.reason ?? 'initial',
      since: iso(row?.since),
      evaluated_at: iso(row?.evaluated_at),
      r_est_usd: rEst === null ? null : formatUsd(rEst),
      ledger: {
        l_usd: sum ? formatUsd(sum.l_micro) : null,
        age_s: age,
        unpriced: sum?.unpriced ?? 0,
        error: ledgerError ?? (ledgerInitFailed ? 'ledger_error' : null),
        saturated: (sum?.saturated ?? false) || open.saturated,
        sources,
      },
      reservations: { open_count: open.count, open_usd: formatUsd(open.total) },
      thresholds: t
        ? {
            t_close_usd: formatUsd(t.tClose),
            t_close_eff_usd: formatUsd(row?.t_close_eff_micro ?? t.tClose),
            t_lowcal_usd: formatUsd(t.tLowcal),
            t_reopen_usd: formatUsd(t.tReopen),
            t_close_lowcal_fallback_usd: formatUsd(t.tCloseLowcalFallback),
          }
        : null,
      calibration: cal
        ? {
            id: cal.cal.id,
            captured_at_lb: iso(cal.cal.captured_at_lb_ms) as string,
            grants: cal.cal.grants.map((g) => ({ granted: g.granted, expires: g.expires, remaining_usd: formatUsd(g.remaining_micro) })),
          }
        : null,
      close_at: iso(money?.closeAtMs),
      close_at_batch: money?.lastExpiryMs != null && config
        ? iso(money.lastExpiryMs - Math.max(config.expiryMarginH, config.batchHorizonH) * HOUR_MS)
        : null,
      next_expiry: iso(money?.nextExpiryMs),
      latch: row && row.latch_cal_id !== null ? { calibration_id: row.latch_cal_id, reason: row.latch_reason } : null,
      max_calibration_id: row?.max_calibration_id ?? 0,
      lowcal: { requested_at: iso(row?.lowcal_requested_at), fallback_at: iso(row?.lowcal_fallback_at) },
      stop: stopView(this.stopFs, config?.stopFile ?? row?.last_stop_file ?? null, parseStopOwner(row?.stop_owner_json)),
      canary_in_progress: this.canaryInProgress(),
      canary_window: this.canaryWindowView(config),
    }
  }

  private canaryWindowView(config: CreditGateConfig | null): CanaryWindowView | null {
    const w = this.canaryWindow()
    if (w === null) return null
    return {
      reservation_id: w.reservationId,
      run_id: w.runId,
      opened_at: iso(w.openedAt),
      run_ended_at: iso(w.endedAt),
      close_by: iso(this.canaryCloseBy(w, config)),
    }
  }
}

/** The STOP as the status shows it (read-only). */
export function stopView(fs: StopFs, path: string | null, rec: StopOwnerRecord | null): GateStatus['stop'] {
  if (path === null) return { path: null, present: null, owner: 'unknown' }
  const i = inspectStop(fs, path, rec)
  switch (i.kind) {
    case 'absent': return { path, present: false, owner: 'none' }
    case 'gate': return { path, present: true, owner: 'gate' }
    case 'human': return { path, present: true, owner: 'human' }
    default: return { path, present: null, owner: 'unknown' }
  }
}
