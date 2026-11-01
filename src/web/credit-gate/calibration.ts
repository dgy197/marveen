// The credit gate's calibration (card fec6335f, spec G-02, D-01..D-05, B-05,
// K-02, K-03, C-05; blueprint 3.3, 3.5, 3.7, node N2c): the owner-approved
// Console readings, the protected stores, the incident-clear approval and the
// canary's verdict.
//
// Who may open (G-02): only an approval that the owner decided with the
// Telegram button. Every path checks, in this order and again inside the
// transaction that consumes it: the EXACT category (isOwnerVerified does not
// look at it -- a button-approved email_send would pass), isOwnerVerified
// with the configured owner's id (never without it, BE-3b), the payload still
// the canonical one its content_hash approves, and one consume
// (consumeCreditGateApproval, db.ts). The pending requests are listed in SQL
// by that owner's button trace before any limit (listOwnerApprovedUnconsumed),
// so legacy-approved rows cannot crowd them out. A legacy PATCH, a row decided
// before the trace table existed, another user's press or a changed payload
// is skipped: never consumed, never opening.
//
// The owner (BE-3c P5, P9): the Telegram user id in .env ALLOWED_CHAT_ID, and
// nothing else -- never the access.json fallback the alerts use, which a fleet
// import onto a fresh target could fill. Empty or a placeholder: nothing is
// processed, and the gate goes on HOLD (owner_unset). The id that decided the
// first accepted reading is pinned in credit_calibration_state. If the configured owner
// (.env, which the fleet import can no longer write) later differs, the gate
// goes on HOLD (owner_changed) and nothing is processed for the new owner; only
// a NEW incident-clear decided by the PINNED owner and naming the
// owner_changed event re-pins it (or the configuration goes back).
//
// A consumed calibration approval is ONE credit_calibrations row, whatever
// came of it (schema-calibration.ts), decided by evaluateCalibration:
//   D-02   FIRST, before any other rule: V or R below the baseline
//          (config.protected) or below the previous reading is an INCIDENT --
//          whatever the reading's time and whether or not the ledger is ready.
//          Closing is always the safe direction;
//   time   captured_at_lb in the future, older than 24 h (min of the config's
//          calibrationMaxAgeH and 24), not strictly newer than the previous
//          reading, or older than the last incident-clear (MED-2): rejected
//          (no state change; the calibration in force stays);
//          a store the reading does not show cannot be decided: HOLD (the
//          2026-10-16 07:18 screenshot had no V on it);
//   B-05   the provider's spend on the grants both readings show vs the
//          ledger between the two lower bounds, |diff| <= max(1 USD, 5% of
//          the provider's spend): else HOLD. A new grant is accepted and left
//          out -- unless it cannot be new (credited on a day before the
//          previous reading, or a known grant back with another expiry). A
//          grant that expired in between may have spent anything up to its
//          remainder (an interval); one that vanished before its expiry or
//          grew, or an unpriced ledger row, cannot be reconciled: HOLD.
// Only an `accepted` row is ever the gate's calibration (calibrationSource:
// the newest accepted row, re-checked on every read against its hash AND the
// approval it was consumed from). The HOLD or INCIDENT is raised in the same
// transaction as the consume, so no crash can leave a consumed reading
// without its consequence.
//
// The previous reading is the non-rejected row with the latest lower bound
// that was not in the future when processed (a held or incident reading is
// still what the Console showed): B-05 and D-02 compare against it, so a HOLD
// is lifted by the next reading that reconciles from there.
//
// INCIDENT (blueprint 3.5, MED-1): every cause has its own event (gate.ts);
// an incident_clear approval lifts only the cause it names, and only while
// that is the newest open one. A clear naming anything else is consumed and
// refused, so it cannot be held back for a later incident. With another cause
// open the gate stays in INCIDENT; the last one leaves it into a latched
// CLOSED, and from then on only a reading captured after the INCIDENT began
// and after the clear counts (MED-2). A broken guard-event cursor is reset only
// by the clear of a guard cause (that clear is the owner's review of it).
// Approvals are processed in the order the owner decided them (resolved_at).
//
// The canary (K-01..K-03): consumeCanaryApproval -- one atomic step, with the
// model, the budget and the run id all mandatory -- consumes the owner's
// credit_gate_canary approval once, for the exact config hash, and only when
// its before-reading is the newest accepted calibration. takeCanaryHash hands
// the hash to the runner once, for that run. The next reading processed is the
// after-reading: evaluateCanary on the ledger rows between the two, and its
// recording is the close step of the gate's canary window (closeCanary,
// N7B1): until then the batch path stays on the gate's STOP. Success
// approves the hash (approvedCanary: the newest evaluated canary, if it
// succeeded -- a later failure withdraws it); INCIDENT and undecidable raise
// INCIDENT and HOLD.
//
// Any exception: HOLD (calibration_error), the approval unconsumed. Nothing
// here can open the gate by itself: an accepted row only lets the gate's own
// tick decide (gate-state.ts).
//
// The grant model (card 40e03382, config calibrationSource = grant_model) swaps
// the source of the calibration, not the order above. The processor then takes
// credit_gate_enforce approvals INSTEAD of credit_gate_calibration ones (those
// stay pending, untouched, as do the enforce approvals under the Console
// path): the same G-02 steps, and in the transaction that consumes the owner's
// ONE button it writes the chain's first credit_grant_periods row (grant-
// period.ts), the canary row of the approval's canary terms (run_id null; node
// N3 binds and judges the run) and the owner pin. The tick then advances the
// chain by itself, one row when the period changes, no button -- but only
// while the chain is in force (same config hash, enforced after the owner's last
// incident-clear, gate not in INCIDENT): after an INCIDENT only a NEW enforce
// approval, decided after the clear, reopens. A bad reconstructed file (A6) is a
// HOLD and nothing is consumed.
//
// The grant model's canary (node N3, grant-canary.ts): the canary row of the
// button is bound to ONE run by consumeCanaryApproval (the enforce approval id,
// the same run terms; the old credit_gate_canary approval is refused and stays
// unconsumed). There is no after-reading, so the tick judges the run on its own
// ledger rows (evaluateGrantCanary) when the first of them appears, closes the
// gate's canary window with a fresh id of the shared id space, and HOLDs
// (canary_close_timeout) canaryCloseMaxH after the run was taken if no row came.
// After a switch back to the Console source the open grant canaries are closed
// as undecidable (grant_source_switched), never read against a Console reading.

import { createHash } from 'node:crypto'
import type Database from 'better-sqlite3'
import { consumeCreditGateApproval, getApproval, getDb, isOwnerVerified, listOwnerApprovedUnconsumed, type Approval } from '../../db.js'
import { ALLOWED_CHAT_ID } from '../../config.js'
import { logger } from '../../logger.js'
import {
  creditGateBinding,
  parseCreditGatePayload,
  type CalibrationPayload,
  type CanaryPayload,
  type CreditGateApprovalCategory,
  type EnforcePayload,
  type IncidentClearPayload,
} from './approval-payload.js'
import { parseUtcInstant, type ConfigLoadResult, type CreditGateConfig } from './config.js'
import { formatUsd, type Calibration, type CalibrationSource, type CanaryCloseResult, type PricingFileResult } from './gate.js'
import { currentPeriod, grantRemaining, priorCharge, type GrantPeriod } from './grant-model.js'
import {
  evaluateGrantCanary, GRANT_CANARY_COLUMNS, GRANT_CANARY_SQL, grantCanaryStart, openGrantCanaries, signalSince, windowSince,
  type GrantCanaryRow, type GrantCanaryVerdict,
} from './grant-canary.js'
import { insertPeriod, measureGrantInputs, newestPeriod, nextCalibrationId, readChain, type ChainRead, type GrantInputs } from './grant-period.js'
import { HEADLESS_SOURCE } from './ledger.js'
import { MICRO_PER_USD, parseUsd } from './money.js'
import type { Micro, PricingTable } from './types.js'

const HOUR_MS = 60 * 60 * 1000
const DAY_MS = 24 * HOUR_MS
/** The brief's ceiling: a reading is never used more than 24 h after it was taken. */
export const MAX_CALIBRATION_AGE_H = 24
/** B-05: max(1 USD, 5%). */
const B05_ABS_MICRO = 1 * MICRO_PER_USD
/** K-02: max(0.05 USD, 20%) (blueprint 12.9). */
const CANARY_ABS_MICRO = 50_000
const CONSUMER = 'credit-gate'
const TELEGRAM_USER_ID_RE = /^[1-9][0-9]{0,15}$/
const SHA256_HEX_RE = /^[0-9a-f]{64}$/
const RUN_ID_RE = /^[A-Za-z0-9_-]{1,128}$/
const DATE_ONLY_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}$/
const PROCESSED: readonly CreditGateApprovalCategory[] = ['credit_gate_calibration', 'credit_gate_incident_clear']
/** Under the grant model the owner's one button is the enforce approval; no Console reading is processed. */
const PROCESSED_GRANT: readonly CreditGateApprovalCategory[] = ['credit_gate_enforce', 'credit_gate_incident_clear']
/** The HOLD of a reconstructed file (or its pricing) that cannot be trusted (A6). */
const RECONSTRUCTED_BAD = 'grant_model_reconstructed_bad'
/**
 * Under the grant model the gate's closings that only a new owner enforce button
 * lifts (R1): the period boundary writes no row while the gate is latched by one.
 */
const BUTTON_ONLY_LATCHES: ReadonlySet<string> = new Set(['auth_401', 'credit_balance_too_low', 'canary_undecidable', 'calibration_error'])
const PENDING_LIMIT = 500

// ------------------------------------------------------------------ readings

export interface GrantReading {
  readonly granted: string
  readonly expires: string
  readonly expires_ms: number
  readonly original_micro: Micro
  readonly remaining_micro: Micro
}

/** One Console reading in micro-USD. A protected store the screenshot does not show is null. */
export interface Readings {
  readonly captured_at_lb_ms: number
  readonly grants: readonly GrantReading[]
  readonly R_micro: Micro | null
  readonly V_micro: Micro | null
}

export type ReadingsResult = { readonly ok: true; readonly readings: Readings } | { readonly ok: false; readonly field: string }

/**
 * A reading from an already validated 3.7 payload. A protected store that is
 * missing (or whose remaining_usd is missing or null) is null -- never a
 * number; a malformed amount ("10.0") is refused.
 */
export function readingsFromPayload(p: CalibrationPayload): ReadingsResult {
  const lb = parseUtcInstant(p.captured_at_lb)
  if (lb === null) return { ok: false, field: 'captured_at_lb' }
  const grants: GrantReading[] = []
  for (const [i, g] of p.grants.entries()) {
    const expires = parseUtcInstant(g.expires)
    const original = parseUsd(g.original_usd)
    const remaining = parseUsd(g.remaining_usd)
    if (expires === null || original === null || remaining === null || parseUtcInstant(g.granted) === null) return { ok: false, field: `grants[${i}]` }
    grants.push({ granted: g.granted, expires: g.expires, expires_ms: expires, original_micro: original, remaining_micro: remaining })
  }
  const store = (name: 'R' | 'V'): Micro | null | undefined => {
    const s = (p.protected as Record<string, { remaining_usd?: unknown } | undefined> | undefined)?.[name]
    if (s === undefined || s === null || s.remaining_usd === undefined || s.remaining_usd === null) return null
    return parseUsd(s.remaining_usd) ?? undefined
  }
  const R = store('R')
  const V = store('V')
  if (R === undefined) return { ok: false, field: 'protected.R' }
  if (V === undefined) return { ok: false, field: 'protected.V' }
  return { ok: true, readings: { captured_at_lb_ms: lb, grants, R_micro: R, V_micro: V } }
}

/** The approved payload text, strictly (3.7: canonical, every field, exact decimals). */
export function parseReadings(text: unknown): ReadingsResult {
  const r = parseCreditGatePayload('credit_gate_calibration', text)
  if (!r.ok) return { ok: false, field: r.field }
  return readingsFromPayload(r.payload as CalibrationPayload)
}

// ------------------------------------------------------------------ the ledger window

/** One ledger row between two lower bounds (credit_ledger_entries). */
export interface WindowRow {
  readonly source: string
  readonly run_id: string | null
  readonly batch_id: string | null
  readonly est_micro: number | null
  readonly cli_micro: number | null
}

/** The row's L contribution: max(est, cli); a row without est counts its cli (or 0). */
function rowCost(r: WindowRow): number {
  if (r.est_micro === null) return r.cli_micro ?? 0
  return r.cli_micro === null || r.est_micro >= r.cli_micro ? r.est_micro : r.cli_micro
}

/** The sum of rows, or null when it leaves the safe-integer range. */
function sumCost(rows: readonly WindowRow[]): number | null {
  let t = 0
  for (const r of rows) {
    t += rowCost(r)
    if (!Number.isSafeInteger(t)) return null
  }
  return t
}

// ------------------------------------------------------------------ grants between two readings

type GrantAnomaly = 'grant_increased' | 'grant_missing' | 'grant_reappeared' | 'grant_new_but_old'

interface GrantDiff {
  /** key -> how much the grant fell (before - after), for grants both readings show. */
  readonly common: ReadonlyMap<string, number>
  readonly added: number
  /** Remainders of grants that expired in between and are gone from the second reading. */
  readonly expiredGone: number
  readonly anomaly: GrantAnomaly | null
}

/** A grant's identity across readings (same day credited, same expiry, same original amount). */
function grantKey(g: GrantReading): string {
  return `${g.granted}|${g.expires}|${g.original_micro}`
}

function byKey(r: Readings): Map<string, { remaining: number; expires_ms: number; granted: string; original: number }> {
  const m = new Map<string, { remaining: number; expires_ms: number; granted: string; original: number }>()
  for (const g of r.grants) {
    const k = grantKey(g)
    const prev = m.get(k)
    m.set(k, { remaining: (prev?.remaining ?? 0) + g.remaining_micro, expires_ms: g.expires_ms, granted: g.granted, original: g.original_micro })
  }
  return m
}

/**
 * A grant first seen now that must have existed at `beforeLbMs`: credited on
 * a whole day before it (a date-only `granted` may be any time of that day),
 * or at an instant before it.
 */
function creditedBefore(granted: string, beforeLbMs: number): boolean {
  const ms = parseUtcInstant(granted)
  if (ms === null) return true
  return DATE_ONLY_RE.test(granted) ? ms + DAY_MS <= beforeLbMs : ms < beforeLbMs
}

function diffGrants(before: Readings, after: Readings): GrantDiff {
  const a = byKey(before)
  const b = byKey(after)
  const common = new Map<string, number>()
  let expiredGone = 0
  let anomaly: GrantAnomaly | null = null
  for (const [k, g] of a) {
    const n = b.get(k)
    if (n === undefined) {
      if (g.expires_ms <= after.captured_at_lb_ms) expiredGone += g.remaining
      else anomaly ??= 'grant_missing'
      continue
    }
    if (n.remaining > g.remaining) anomaly ??= 'grant_increased'
    common.set(k, g.remaining - n.remaining)
  }
  let added = 0
  for (const [k, n] of b) {
    if (a.has(k)) continue
    added++
    // LOW-1: a known grant back with another expiry, or one older than the previous reading, is no new grant.
    if ([...a.values()].some((g) => g.granted === n.granted && g.original === n.original)) anomaly ??= 'grant_reappeared'
    else if (creditedBefore(n.granted, before.captured_at_lb_ms)) anomaly ??= 'grant_new_but_old'
  }
  return { common, added, expiredGone, anomaly }
}

// ------------------------------------------------------------------ evaluateCalibration

export interface CalibrationContext {
  readonly nowMs: number
  /** captured_at_lb may be at most this much older than now. */
  readonly maxAgeMs: number
  /** D-01: the protected stores' baseline (config.protected); null = no config (only the previous reading counts). */
  readonly baseline: { readonly R: number; readonly V: number } | null
  /** The newest non-rejected reading before this one; null = this is the first. */
  readonly prev: Readings | null
  /** The ledger rows from prev's lower bound up to (not including) this one's; null without prev. */
  readonly window: readonly WindowRow[] | null
  /** MED-2: after an incident-clear, the earliest lower bound that counts; null = none. */
  readonly minCapturedAtLbMs?: number | null
}

export interface B05Report {
  readonly provider_usd: string
  /** Above provider_usd when a grant expired in between (its spend is unknown). */
  readonly provider_max_usd: string
  readonly ledger_usd: string
  readonly rows: number
  readonly new_grants: number
}

type RejectReason = 'captured_in_future' | 'reading_too_old' | 'not_newer_than_previous' | 'captured_before_clear'

export type CalibrationVerdict =
  | { readonly outcome: 'accepted'; readonly reconcile: B05Report | null }
  | { readonly outcome: 'rejected'; readonly reason: RejectReason }
  | { readonly outcome: 'incident'; readonly reason: 'protected_decreased'; readonly detail: Record<string, unknown> }
  | { readonly outcome: 'hold'; readonly reason: 'reading_undecidable' | 'b05_mismatch' | 'b05_undecidable'; readonly detail: Record<string, unknown> }

/** The time rules of a reading; null = fine. */
export function checkTiming(r: Readings, prev: Readings | null, nowMs: number, maxAgeMs: number, minLbMs: number | null = null): RejectReason | null {
  if (r.captured_at_lb_ms > nowMs) return 'captured_in_future'
  if (nowMs - r.captured_at_lb_ms > maxAgeMs) return 'reading_too_old'
  if (prev !== null && r.captured_at_lb_ms <= prev.captured_at_lb_ms) return 'not_newer_than_previous'
  if (minLbMs !== null && r.captured_at_lb_ms < minLbMs) return 'captured_before_clear'
  return null
}

/**
 * D-02: a visible protected store below its baseline or below the previous
 * reading. Checked before anything else: it is an INCIDENT whatever the rest.
 */
export function protectedDecrease(r: Readings, baseline: CalibrationContext['baseline'], prev: Readings | null): Record<string, unknown> | null {
  for (const [store, value, base, prevValue] of [
    ['V', r.V_micro, baseline?.V ?? null, prev?.V_micro ?? null],
    ['R', r.R_micro, baseline?.R ?? null, prev?.R_micro ?? null],
  ] as const) {
    if (value === null) continue
    if ((base !== null && value < base) || (prevValue !== null && value < prevValue)) {
      return {
        store,
        reading_usd: formatUsd(value),
        baseline_usd: base === null ? null : formatUsd(base),
        previous_usd: prevValue === null ? null : formatUsd(prevValue),
      }
    }
  }
  return null
}

/** |diff| <= max(abs, x / div) in integers: diff * div <= max(abs * div, x). */
function within(diff: number, x: number, absMicro: number, div: number): boolean {
  return diff * div <= Math.max(absMicro * div, x)
}

/** D-02, time, B-05: what the gate does with one owner-approved reading. */
export function evaluateCalibration(r: Readings, c: CalibrationContext): CalibrationVerdict {
  // D-02 before every other rule (the blocker of the 642f697d review).
  const dec = protectedDecrease(r, c.baseline, c.prev)
  if (dec !== null) return { outcome: 'incident', reason: 'protected_decreased', detail: dec }

  const timing = checkTiming(r, c.prev, c.nowMs, c.maxAgeMs, c.minCapturedAtLbMs ?? null)
  if (timing !== null) return { outcome: 'rejected', reason: timing }

  const missing = [r.V_micro === null ? 'V' : null, r.R_micro === null ? 'R' : null].filter((x): x is string => x !== null)
  if (missing.length > 0) return { outcome: 'hold', reason: 'reading_undecidable', detail: { missing } }

  if (c.prev === null) return { outcome: 'accepted', reconcile: null }
  const d = diffGrants(c.prev, r)
  if (d.anomaly !== null) return { outcome: 'hold', reason: 'b05_undecidable', detail: { why: d.anomaly } }
  const rows = c.window ?? []
  if (rows.some((w) => w.est_micro === null)) return { outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'unpriced_rows' } }
  const ledger = sumCost(rows)
  let lo = 0
  for (const v of d.common.values()) lo += v
  const hi = lo + d.expiredGone
  if (ledger === null || !Number.isSafeInteger(hi)) return { outcome: 'hold', reason: 'b05_undecidable', detail: { why: 'overflow' } }
  const report: B05Report = {
    provider_usd: formatUsd(lo),
    provider_max_usd: formatUsd(hi),
    ledger_usd: formatUsd(ledger),
    rows: rows.length,
    new_grants: d.added,
  }
  const ok = ledger < lo ? within(lo - ledger, lo, B05_ABS_MICRO, 20)
    : ledger > hi ? within(ledger - hi, hi, B05_ABS_MICRO, 20)
    : true
  if (!ok) return { outcome: 'hold', reason: 'b05_mismatch', detail: { ...report } }
  return { outcome: 'accepted', reconcile: report }
}

// ------------------------------------------------------------------ evaluateCanary

export interface CanaryTerms {
  /** The headless run the canary started; null = never bound. */
  readonly run_id: string | null
  readonly min_expected_micro: number
}

export type CanaryVerdict =
  | {
      readonly outcome: 'success'
      /** The grant that fell (K-02: which 200 USD grant pays first). */
      readonly grant: string
      readonly decrease_micro: number
      readonly expected_micro: number
      /** `run`: the canary alone; `window`: with covered usage rows. */
      readonly basis: 'run' | 'window'
    }
  | { readonly outcome: 'incident'; readonly reason: 'protected_decreased' | 'no_grant_decreased' }
  | { readonly outcome: 'undecidable'; readonly reason: string }

/**
 * K-02/K-03 on the readings right before and right after a canary run and the
 * ledger rows between their lower bounds. Success: one Team grant fell by the
 * ledger amount within max(0.05 USD, 20%), V and R unchanged. INCIDENT: V or R
 * fell, or no grant fell at all. A rise of V or R is undecidable too (a
 * purchase could hide a charge to V). Otherwise undecidable (repeat with a new
 * approval). The ledger amount is the canary's own row. If the window also has
 * rows -- only priced usage.jsonl rows (sync or batch) are acceptable, never
 * another headless run -- the whole window W + c is matched, and only when the
 * other rows cannot hide the canary (MED-3): max(0.05 USD, 0.2 W) must be
 * strictly below the canary's own cost c, and the tolerance is then
 * max(0.05 USD, 0.2 W, 0.2 c), still below c.
 */
export function evaluateCanary(before: Readings, after: Readings, window: readonly WindowRow[], canary: CanaryTerms): CanaryVerdict {
  const undecidable = (reason: string): CanaryVerdict => ({ outcome: 'undecidable', reason })
  if (before.R_micro === null || before.V_micro === null || after.R_micro === null || after.V_micro === null) {
    return undecidable('protected_not_visible')
  }
  if (after.V_micro < before.V_micro || after.R_micro < before.R_micro) return { outcome: 'incident', reason: 'protected_decreased' }
  if (after.V_micro !== before.V_micro || after.R_micro !== before.R_micro) return undecidable('protected_changed')
  if (canary.run_id === null) return undecidable('canary_run_unbound')
  const own = window.filter((w) => w.source === HEADLESS_SOURCE && w.run_id === canary.run_id)
  if (own.length === 0) return undecidable('canary_not_in_window')
  const runCost = sumCost(own)
  if (runCost === null) return undecidable('overflow')
  if (runCost < canary.min_expected_micro) return undecidable('canary_below_minimum')

  const d = diffGrants(before, after)
  if (d.anomaly !== null) return undecidable(d.anomaly)
  const fell = [...d.common.values()].some((v) => v > 0)
  if (!fell && d.expiredGone === 0) return { outcome: 'incident', reason: 'no_grant_decreased' }

  const others = window.filter((w) => !(w.source === HEADLESS_SOURCE && w.run_id === canary.run_id))
  if (others.some((w) => w.source === HEADLESS_SOURCE)) return undecidable('other_headless_rows')
  if (others.some((w) => w.est_micro === null)) return undecidable('unpriced_rows')
  let expected = runCost
  let matches = (decrease: number): boolean => within(Math.abs(decrease - runCost), runCost, CANARY_ABS_MICRO, 5)
  if (others.length > 0) {
    const w = sumCost(others)
    if (w === null || runCost + w > Number.MAX_SAFE_INTEGER) return undecidable('overflow')
    // max(0.05, 0.2 W) < c  <=>  0.05 < c and W < 5 c.
    if (!(CANARY_ABS_MICRO < runCost && w < 5 * runCost)) return undecidable('window_hides_canary')
    expected = runCost + w
    matches = (decrease) => Math.abs(decrease - expected) * 5 <= Math.max(CANARY_ABS_MICRO * 5, w, runCost)
  }
  for (const [grant, decrease] of d.common) {
    if (decrease > 0 && matches(decrease)) {
      return { outcome: 'success', grant, decrease_micro: decrease, expected_micro: expected, basis: others.length === 0 ? 'run' : 'window' }
    }
  }
  return undecidable('canary_amount_mismatch')
}

// ------------------------------------------------------------------ the gate's calibration source

interface CalibrationRow {
  id: number
  approval_id: string
  captured_at_lb: number
  readings_json: string
  content_hash: string
  outcome: 'accepted' | 'incident' | 'hold' | 'rejected'
}

const ROW_COLUMNS = 'id, approval_id, captured_at_lb, readings_json, content_hash, outcome'

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

/**
 * A stored row's readings, re-checked against its hash and against the
 * approval it was consumed from (the same category, payload and hash, consumed
 * by the gate); null = unusable.
 */
function rowReadings(row: CalibrationRow): Readings | null {
  if (sha256(row.readings_json) !== row.content_hash) return null
  const a = getApproval(row.approval_id)
  if (!a || a.category !== 'credit_gate_calibration' || a.content_hash !== row.content_hash || a.action_payload !== row.readings_json
    || a.consumed_at == null || a.consumed_by !== CONSUMER) return null
  const r = parseReadings(row.readings_json)
  return r.ok && r.readings.captured_at_lb_ms === row.captured_at_lb ? r.readings : null
}

/**
 * The gate's calibration: the newest ACCEPTED row. A row that no longer
 * matches its hash or its approval, or does not parse, throws -- the gate reads
 * that as calibration_invalid and stays closed.
 */
export function calibrationSource(db: Database.Database): CalibrationSource {
  return (): Calibration | null => {
    const row = (db.prepare(`SELECT ${ROW_COLUMNS} FROM credit_calibrations WHERE outcome = 'accepted'
      ORDER BY id DESC LIMIT 1`).get() as CalibrationRow | undefined) ?? null
    if (row === null) return null
    const r = rowReadings(row)
    if (r === null || r.R_micro === null || r.V_micro === null) throw new Error('credit gate: the stored calibration does not verify')
    return {
      id: row.id,
      captured_at_lb_ms: r.captured_at_lb_ms,
      grants: r.grants.map((g) => ({ granted: g.granted, expires: g.expires, original_micro: g.original_micro, remaining_micro: g.remaining_micro })),
      protected: { R_micro: r.R_micro, V_micro: r.V_micro },
    }
  }
}

/** canary.approved_hash: the newest evaluated canary's hash, if it succeeded; else null. */
export function approvedCanary(db: Database.Database): { readonly approval_id: string; readonly config_hash: string } | null {
  const row = db.prepare(`SELECT approval_id, config_hash, status FROM credit_canaries
    WHERE status <> 'consumed' ORDER BY evaluated_at DESC, rowid DESC LIMIT 1`).get() as
    { approval_id: string; config_hash: string; status: string } | undefined
  return row && row.status === 'success' && SHA256_HEX_RE.test(row.config_hash) ? { approval_id: row.approval_id, config_hash: row.config_hash } : null
}

/**
 * LOW-3: the config hash of a consumed canary approval, handed to the runner
 * ONCE and only for the run the approval was consumed for (one atomic UPDATE).
 * Any further call, another run id, or an evaluated canary: null.
 */
export function takeCanaryHash(db: Database.Database, approvalId: string, runId: string, nowMs: number = Date.now()): string | null {
  if (typeof approvalId !== 'string' || approvalId === '' || typeof runId !== 'string' || !RUN_ID_RE.test(runId)) return null
  const row = db.prepare(`UPDATE credit_canaries SET hash_taken_at = ?
    WHERE approval_id = ? AND run_id = ? AND status = 'consumed' AND hash_taken_at IS NULL
    RETURNING config_hash`).get(nowMs, approvalId, runId) as { config_hash: string } | undefined
  return row && SHA256_HEX_RE.test(row.config_hash) ? row.config_hash : null
}

/**
 * The owner's Telegram user id: .env ALLOWED_CHAT_ID only (LOW-A, BE-3c P9),
 * a positive decimal user id. Empty, '0', a placeholder or a group id: null.
 * Unlike resolveAlertOwnerChat there is no access.json fallback.
 */
export function strictOwnerUserId(): string | null {
  const v = typeof ALLOWED_CHAT_ID === 'string' ? ALLOWED_CHAT_ID.trim() : ''
  return TELEGRAM_USER_ID_RE.test(v) ? v : null
}

// ------------------------------------------------------------------ processing

/** What the processor needs of the gate (CreditGate has it). */
export interface CalibrationGatePort {
  raiseIncident(reason: string, detail: Record<string, unknown> | null, nowMs?: number, syncStop?: boolean): void
  raiseHold(reason: string, detail: Record<string, unknown> | null, nowMs?: number, syncStop?: boolean): void
  clearIncident(eventId: number, nowMs?: number): boolean
  resetGuardCursor(nowMs?: number): void
  closeCanary(afterCalibrationId: number, nowMs?: number, syncStop?: boolean): CanaryCloseResult
  syncStopFile(nowMs?: number): void
  audit(kind: string, f?: { readonly reason?: string | null; readonly calId?: number | null; readonly detail?: Record<string, unknown> | null }, nowMs?: number): number
}

export interface CalibrationDeps {
  /** db.ts's connection (the approvals are read through db.ts): the processor refuses any other. */
  readonly db: Database.Database
  readonly gate: CalibrationGatePort
  readonly loadConfig: () => ConfigLoadResult
  /**
   * The gate's pricing table (the runtime passes the same file the gate reads). Only the grant model
   * needs it, and only with a reconstructed block: its rows are priced to make the prior charge.
   * Absent or failing: no period is written (the gate's own pricing closure says why).
   */
  readonly loadPricing?: (nowMs: number) => PricingFileResult
  /** The configured owner's Telegram user id; default strictOwnerUserId. null = nothing is processed. */
  readonly ownerId?: () => string | null
  readonly now?: () => number
  /** Tests: db.ts's consume, replaceable to prove the rollback. */
  readonly consume?: typeof consumeCreditGateApproval
}

export interface ProcessReport {
  accepted: number
  rejected: number
  held: number
  incidents: number
  cleared: number
  refused: number
  deferred: number
  errors: number
  /** Anything was consumed or the gate's state was touched: the caller ticks again. */
  changed: boolean
}

export type CanaryConsumeRefusal =
  | 'bad_request' | 'no_owner' | 'owner_changed' | 'config_invalid' | 'not_found' | 'wrong_category' | 'already_consumed'
  | 'not_owner_verified' | 'unbound' | 'hash_mismatch' | 'terms_mismatch'
  | 'before_not_accepted' | 'before_not_latest' | 'before_too_old' | 'canary_exists' | 'busy'
  /** Grant model (card 40e03382): the old credit_gate_canary approval is not the canary there; the enforce button's chain is not in force. */
  | 'grant_model' | 'chain_not_in_force'

export type CanaryConsumeResult =
  | {
      readonly ok: true
      readonly approval_id: string
      readonly config_hash: string
      readonly model: string
      readonly budget_micro: number
      readonly min_expected_micro: number
      readonly before_calibration_id: number
      readonly run_id: string
    }
  | { readonly ok: false; readonly reason: CanaryConsumeRefusal }

/** What the runner binds a canary to (LOW-3): every field mandatory. */
export interface CanaryRunTerms {
  /** The run's model: exactly the approved one. */
  readonly model: string
  /** The run's --max-budget-usd in micro-USD: at most the approved budget. */
  readonly budget_micro: number
  /** The run id the ledger row will carry. */
  readonly runId: string
  /** BE-4b P6: the run's node id, cwd and the sha256 of its prompt -- exactly the approved ones. */
  readonly node: string
  readonly cwd: string
  readonly prompt_sha256: string
}

type Step = 'skipped' | 'deferred' | 'accepted' | 'rejected' | 'hold' | 'incident' | 'cleared' | 'refused'

/** Thrown inside a transaction to roll it back without it being an error. */
class Rollback extends Error {
  constructor(readonly step: Step) {
    super(step)
  }
}

interface CanaryRow {
  approval_id: string
  run_id: string | null
  min_expected_micro: number
  before_calibration_id: number
}

interface CalState {
  owner_id: string | null
  owner_changed_event_id: number | null
  owner_changed_at: number | null
  min_captured_at_lb: number | null
}

/** Guard causes of an INCIDENT (gate.ts readGuardEvents and parseGuardCursor). */
function isGuardReason(reason: string): boolean {
  return reason === 'guard_event' || reason === 'guard_backlog' || reason === 'guard_cursor_invalid' || reason.startsWith('guard_events_')
}

function isBusy(err: unknown): boolean {
  const code = (err as { code?: unknown })?.code
  return typeof code === 'string' && code.startsWith('SQLITE_BUSY')
}

export class CalibrationProcessor {
  private readonly db: Database.Database
  private readonly gate: CalibrationGatePort
  private readonly nowFn: () => number
  private readonly ownerFn: () => string | null
  private readonly consumeFn: typeof consumeCreditGateApproval
  private readonly warned = new Set<string>()
  /** The reconstructed file's HOLD was raised in this episode (reset when the file reads fine again). */
  private badRaised = false

  constructor(private readonly deps: CalibrationDeps) {
    // isOwnerVerified and the consume run on db.ts's connection; a second
    // connection would split one decision over two transactions.
    if (deps.db !== getDb()) throw new Error('CalibrationProcessor: the gate must use the dashboard database (db.ts)')
    this.db = deps.db
    this.gate = deps.gate
    this.nowFn = deps.now ?? Date.now
    this.ownerFn = deps.ownerId ?? strictOwnerUserId
    this.consumeFn = deps.consume ?? consumeCreditGateApproval
  }

  private owner(): string | null {
    try {
      const id = this.ownerFn()
      return typeof id === 'string' && TELEGRAM_USER_ID_RE.test(id) ? id : null
    } catch {
      return null
    }
  }

  private warnOnce(key: string, msg: string, fields: Record<string, unknown> = {}): void {
    if (this.warned.has(key)) return
    this.warned.add(key)
    logger.warn(fields, msg)
  }

  private tx<T>(fn: () => T): T {
    return this.db.transaction(fn).immediate()
  }

  private calState(): CalState {
    this.db.prepare('INSERT OR IGNORE INTO credit_calibration_state (id) VALUES (1)').run()
    return this.db.prepare(`SELECT owner_id, owner_changed_event_id, owner_changed_at, min_captured_at_lb
      FROM credit_calibration_state WHERE id = 1`).get() as CalState
  }

  private updateCalState(fields: Partial<CalState & { owner_pinned_at: number | null }>): void {
    const keys = Object.keys(fields)
    if (keys.length === 0) return
    this.db.prepare(`UPDATE credit_calibration_state SET ${keys.map((k) => `${k} = @${k}`).join(', ')} WHERE id = 1`).run(fields)
  }

  /** The configured owner differs from the pinned one (a null configured owner processes nothing anyway). */
  private ownerMismatch(owner: string, cs: CalState): boolean {
    return cs.owner_id !== null && cs.owner_id !== owner
  }

  /**
   * The newest non-rejected reading whose lower bound was not in the future
   * when processed: what the next one is compared with.
   */
  private previous(): { row: CalibrationRow; readings: Readings } | null {
    const row = (this.db.prepare(`SELECT ${ROW_COLUMNS} FROM credit_calibrations
      WHERE outcome <> 'rejected' AND captured_at_lb <= accepted_at
      ORDER BY captured_at_lb DESC, id DESC LIMIT 1`).get() as CalibrationRow | undefined) ?? null
    if (row === null) return null
    const r = rowReadings(row)
    if (r === null) throw new Error('credit gate: the previous calibration does not verify')
    return { row, readings: r }
  }

  private windowRows(fromMs: number, toMs: number): WindowRow[] {
    return this.db.prepare(`SELECT source, run_id, batch_id, est_micro, cli_micro FROM credit_ledger_entries
      WHERE ts >= ? AND ts < ? ORDER BY id`).all(Math.floor(fromMs / 1000), Math.floor(toMs / 1000)) as WindowRow[]
  }

  /**
   * The ledger has read every configured source past `lbMs`, recently enough
   * (maxLedgerAgeS), and none is broken or half-read: the window up to lbMs
   * is complete as far as the files go.
   */
  private ledgerReady(cfg: CreditGateConfig, lbMs: number, nowMs: number): boolean {
    for (const s of cfg.ledgerSources) {
      const c = this.db.prepare('SELECT status, checked_at FROM credit_ledger_cursors WHERE source = ?').get(s.id) as
        { status: string; checked_at: number | null } | undefined
      if (!c || c.status !== 'ok' || c.checked_at === null) return false
      if (c.checked_at < lbMs || nowMs - c.checked_at > cfg.maxLedgerAgeS * 1000) return false
    }
    return true
  }

  /** The approval of `category` as `owner` decided it, its payload bound; else null. */
  private verified(id: string, category: CreditGateApprovalCategory, owner: string): Approval | null {
    const a = getApproval(id)
    if (!a || a.category !== category || a.status !== 'approved' || a.consumed_at != null) return null
    if (!isOwnerVerified(id, owner)) return null
    const b = creditGateBinding(a)
    if (!b.bound || b.payload.kind !== category) return null
    return a
  }

  private consume(a: Approval, owner: string, ref: string, nowMs: number): void {
    const c = this.consumeFn({ id: a.id, category: a.category, ownerId: owner, consumer: CONSUMER, ref, nowS: Math.floor(nowMs / 1000) })
    if (!c.ok) throw new Rollback('skipped')
  }

  /**
   * Process the owner-approved calibration and incident-clear approvals.
   * Called by the runtime between ticks; synchronous.
   */
  process(nowMs: number = this.nowFn()): ProcessReport {
    const rep: ProcessReport = { accepted: 0, rejected: 0, held: 0, incidents: 0, cleared: 0, refused: 0, deferred: 0, errors: 0, changed: false }
    let current: string | null = null
    try {
      const owner = this.owner()
      if (owner === null) {
        this.warnOnce('no_owner', 'credit gate: ALLOWED_CHAT_ID is not a Telegram user id, no approval is processed (HOLD owner_unset)')
        this.ownerUnset(nowMs, rep)
      } else {
        this.processFor(owner, nowMs, rep, (id) => { current = id })
      }
    } catch (err) {
      rep.errors++
      rep.changed = true
      logger.error({ err, approval_id: current }, 'credit gate: processing an approval failed, HOLD')
      this.gate.raiseHold('calibration_error', { approval_id: current }, nowMs, false)
      this.gate.audit('calibration_error', { reason: 'calibration_error', detail: { approval_id: current, error: err instanceof Error ? err.name : typeof err } }, nowMs)
    }
    if (rep.changed) this.gate.syncStopFile(nowMs)
    return rep
  }

  /** LOW-A: no owner configured -- HOLD owner_unset, once (an INCIDENT stays as it is). */
  private ownerUnset(nowMs: number, rep: ProcessReport): void {
    const st = this.db.prepare('SELECT state, reason FROM credit_gate_state WHERE id = 1').get() as { state: string; reason: string } | undefined
    if (st && (st.state === 'INCIDENT' || (st.state === 'HOLD' && st.reason === 'owner_unset'))) return
    this.gate.raiseHold('owner_unset', null, nowMs, false)
    rep.held++
    rep.changed = true
  }

  private processFor(owner: string, nowMs: number, rep: ProcessReport, setCurrent: (id: string) => void): void {
    const cs = this.calState()
    if (this.ownerMismatch(owner, cs)) {
      this.ownerChanged(owner, cs, nowMs, rep)
    } else {
      if (cs.owner_changed_event_id !== null) {
        // The configuration went back to the pinned owner: the HOLD stays until a newer reading.
        this.tx(() => {
          this.updateCalState({ owner_changed_event_id: null, owner_changed_at: null })
          this.gate.audit('owner_change_reverted', { reason: 'owner_change_reverted' }, nowMs)
        })
      }
      // Card 40e03382: under the grant model the enforce approval replaces the calibration one.
      const grant = this.grantConfig()
      const inputs = grant === null ? null : this.measureInputs(grant, nowMs, rep)
      const pending = listOwnerApprovedUnconsumed(grant === null ? PROCESSED : PROCESSED_GRANT, owner, PENDING_LIMIT)
      const cfgR = pending.length > 0 ? this.deps.loadConfig() : null
      const cfg = cfgR?.ok ? cfgR.config : null
      let deferred = false
      for (const a of pending) {
        setCurrent(a.id)
        if (!isOwnerVerified(a.id, owner)) {
          this.warnOnce(`unverified:${a.id}`, 'credit gate: an approved request did not verify as the owner\'s, ignored', { approval_id: a.id })
          continue
        }
        const step = a.category === 'credit_gate_calibration'
          ? this.calibrationStep(a.id, owner, cfg, nowMs)
          : a.category === 'credit_gate_enforce'
            ? this.enforceStep(a.id, owner, grant, inputs, nowMs, rep)
            : this.incidentClearStep(a.id, owner, nowMs)
        if (step === 'skipped') continue
        // Order matters (a clear counts only for readings after it): a deferred approval stops the pass.
        if (step === 'deferred') {
          rep.deferred++
          deferred = true
          break
        }
        rep.changed = true
        if (step === 'accepted') rep.accepted++
        else if (step === 'rejected') rep.rejected++
        else if (step === 'hold') rep.held++
        else if (step === 'incident') rep.incidents++
        else if (step === 'cleared') rep.cleared++
        else rep.refused++
      }
      if (grant !== null && !deferred) this.advanceGrantPeriod(grant, inputs, nowMs, rep)
      if (grant !== null) this.settleGrantCanaries(grant, nowMs, rep)
      else this.closeOrphanGrantCanaries(nowMs, rep)
    }
  }

  // ------------------------------------------------------------------ the grant model (card 40e03382)

  /** The config when it selects the grant model (and holds its block); else null -- the Console path, untouched. A config that cannot be read is the Console path's business. */
  private grantConfig(): CreditGateConfig | null {
    try {
      const r = this.deps.loadConfig()
      return r.ok && r.config.calibrationSource === 'grant_model' && r.config.grantModel !== null ? r.config : null
    } catch {
      return null
    }
  }

  /**
   * The reconstructed file measured (A6). A file that is not exactly the pinned
   * bytes, or does not parse, is a HOLD -- once per episode: the state is
   * HOLD already (or an INCIDENT, which stays), or this processor raised it.
   */
  private measureInputs(cfg: CreditGateConfig, nowMs: number, rep: ProcessReport): GrantInputs {
    const inputs = measureGrantInputs(cfg)
    if (inputs.ok) {
      this.badRaised = false
      return inputs
    }
    this.raiseBad(inputs.why, inputs.detail, nowMs, rep)
    return inputs
  }

  private raiseBad(why: string, detail: string, nowMs: number, rep: ProcessReport): void {
    if (this.badRaised) return
    this.badRaised = true
    const st = this.db.prepare('SELECT state, reason FROM credit_gate_state WHERE id = 1').get() as { state: string; reason: string } | undefined
    if (st && (st.state === 'INCIDENT' || (st.state === 'HOLD' && st.reason === RECONSTRUCTED_BAD))) return
    this.warnOnce(`grant_bad:${why}`, 'credit gate: the grant model\'s reconstructed file cannot be used, HOLD', { why })
    this.gate.audit('grant_model_bad', { reason: RECONSTRUCTED_BAD, detail: { why, error: detail } }, nowMs)
    this.gate.raiseHold(RECONSTRUCTED_BAD, { why }, nowMs, false)
    rep.held++
    rep.changed = true
  }

  /**
   * The period at `nowMs` and what remains of the grant in it (A4): the prior
   * charge of the reconstructed rows and the gap, priced with the gate's own
   * table. `skip`: no table right now (the gate says pricing_error itself);
   * `bad`: a reconstructed row that cannot be priced -- the data is not usable.
   */
  private periodOf(cfg: CreditGateConfig, inputs: GrantInputs & { ok: true }, nowMs: number):
    | { readonly ok: true; readonly period: GrantPeriod; readonly remaining: Micro }
    | { readonly ok: false; readonly kind: 'skip' | 'bad'; readonly why: string } {
    const gm = cfg.grantModel
    if (gm === null) return { ok: false, kind: 'skip', why: 'no_grant_model' }
    const period = currentPeriod(gm, nowMs)
    let table: PricingTable | null = null
    if (gm.reconstructed !== null) {
      let p: PricingFileResult | null = null
      try {
        p = this.deps.loadPricing ? this.deps.loadPricing(nowMs) : null
      } catch {
        p = null
      }
      if (p === null || !p.ok) return { ok: false, kind: 'skip', why: 'pricing_unavailable' }
      table = p.table
    }
    const prior = priorCharge(inputs.rows, gm, period.lbMs, table as PricingTable)
    if (prior === null) return { ok: false, kind: 'bad', why: 'reconstructed_row_unpriced' }
    return { ok: true, period, remaining: grantRemaining(gm, prior) }
  }

  /**
   * The owner's ONE button (spec 4): the same G-02 order as every approval --
   * exact category, isOwnerVerified with the configured owner, the canonical
   * payload, one consume -- and, in that transaction, the chain's first period
   * row, the canary row of the approval's terms and the owner pin. It binds
   * the hash of the config as it is now: another hash, a bad reconstructed
   * file, an open INCIDENT, a decision before the owner's last clear: skipped,
   * unconsumed.
   */
  private enforceStep(id: string, owner: string, cfg: CreditGateConfig | null, inputs: GrantInputs | null, nowMs: number, rep: ProcessReport): Step {
    if (cfg === null || inputs === null || !inputs.ok) return 'skipped'
    const calc = this.periodOf(cfg, inputs, nowMs)
    if (!calc.ok) {
      if (calc.kind === 'bad') this.raiseBad(calc.why, calc.why, nowMs, rep)
      else this.warnOnce(`grant_skip:${calc.why}`, 'credit gate: no grant period can be written now', { why: calc.why })
      return 'skipped'
    }
    try {
      return this.tx((): Step => {
        const a = this.verified(id, 'credit_gate_enforce', owner)
        if (a === null) return 'skipped'
        const p = (creditGateBinding(a) as { bound: true; payload: EnforcePayload }).payload
        if (p.grant_model_hash !== inputs.hash) {
          this.warnOnce(`enforce_hash:${a.id}`, 'credit gate: an enforce approval binds another grant model hash, left unconsumed', { approval_id: a.id })
          return 'skipped'
        }
        const st = this.db.prepare('SELECT state FROM credit_gate_state WHERE id = 1').get() as { state: string } | undefined
        if (st?.state === 'INCIDENT') return 'skipped'
        const cs = this.calState()
        if (this.ownerMismatch(owner, cs)) return 'skipped'
        // A9: after an incident-clear (or an owner re-pin) only an approval decided after it counts.
        // Fail-closed compare (R1 B2): an approval decided in the floor's own second, before the floor ms, does not count.
        if (cs.min_captured_at_lb !== null && (a.resolved_at == null || a.resolved_at * 1000 < cs.min_captured_at_lb)) return 'skipped'
        const budget = parseUsd(p.canary.budget_usd)
        const minExpected = parseUsd(p.canary.min_expected_usd)
        if (budget === null || minExpected === null) return 'skipped'
        const gm = cfg.grantModel as NonNullable<CreditGateConfig['grantModel']>
        const periodId = insertPeriod(this.db, {
          approvalId: a.id, hash: inputs.hash, enforcedAtMs: nowMs, period: calc.period, original: gm.grantUsd, remaining: calc.remaining, nowMs,
        })
        this.consume(a, owner, `credit_grant_periods:${periodId}`, nowMs)
        this.db.prepare(`INSERT INTO credit_canaries
            (approval_id, config_hash, model, budget_micro, min_expected_micro, before_calibration_id, run_id, status, consumed_at)
          VALUES (?, ?, ?, ?, ?, ?, NULL, 'consumed', ?)`).run(a.id, p.canary.config_hash, p.canary.model, budget, minExpected, periodId, nowMs)
        if (cs.owner_id === null) this.updateCalState({ owner_id: owner, owner_pinned_at: nowMs })
        this.gate.audit('grant_enforce', {
          reason: 'grant_enforce',
          calId: periodId,
          detail: { approval_id: a.id, period: calc.period.key, remaining_usd: formatUsd(calc.remaining) },
        }, nowMs)
        return 'accepted'
      })
    } catch (err) {
      if (err instanceof Rollback) return err.step
      if (isBusy(err)) return 'deferred'
      throw err
    }
  }

  /**
   * A3: when the period changes, ONE new row (same approval, a higher id) --
   * no button. Only a chain in force advances: it verifies (readChain), binds
   * the config as it is now, was enforced after the owner's last clear, and the
   * gate is not in INCIDENT nor latched by a 401, a balance signal or a
   * canary_undecidable / calibration_error HOLD (R1: a new button lifts those). A row that does not verify is left to the source,
   * which makes the gate read calibration_invalid.
   */
  private advanceGrantPeriod(cfg: CreditGateConfig, inputs: GrantInputs | null, nowMs: number, rep: ProcessReport): void {
    if (inputs === null || !inputs.ok || cfg.grantModel === null) return
    const st = this.db.prepare('SELECT state, latch_cal_id, latch_reason FROM credit_gate_state WHERE id = 1').get() as
      { state: string; latch_cal_id: number | null; latch_reason: string | null } | undefined
    if (!st || st.state === 'INCIDENT') return
    // R1 B1: these closings are not lifted by a new period row, only by a new owner enforce button.
    if (st.latch_cal_id !== null && st.latch_reason !== null && BUTTON_ONLY_LATCHES.has(st.latch_reason)) return
    let read: ChainRead
    try {
      read = readChain(this.db, cfg, inputs.hash)
    } catch (err) {
      this.warnOnce('grant_chain_invalid', 'credit gate: the grant period chain does not verify, not advanced', { error: err instanceof Error ? err.name : typeof err })
      return
    }
    if (read.kind !== 'ok' || currentPeriod(cfg.grantModel, nowMs).key === read.record.key) return
    const calc = this.periodOf(cfg, inputs, nowMs)
    if (!calc.ok) {
      if (calc.kind === 'bad') this.raiseBad(calc.why, calc.why, nowMs, rep)
      return
    }
    const record = read.record
    try {
      const id = this.tx((): number | null => {
        // Still the newest row, and still in the old period: nobody wrote between the read and here.
        const newest = newestPeriod(this.db)
        if (newest === null || newest.id !== read.row.id) return null
        const gm = cfg.grantModel as NonNullable<CreditGateConfig['grantModel']>
        const newId = insertPeriod(this.db, {
          approvalId: record.approval_id, hash: record.grant_model_hash, enforcedAtMs: record.enforced_at_ms, period: calc.period,
          original: gm.grantUsd, remaining: calc.remaining, nowMs,
        })
        this.gate.audit('grant_period', {
          reason: 'grant_period',
          calId: newId,
          detail: { approval_id: record.approval_id, period: calc.period.key, remaining_usd: formatUsd(calc.remaining) },
        }, nowMs)
        return newId
      })
      if (id !== null) rep.changed = true
    } catch (err) {
      if (isBusy(err)) return
      throw err
    }
  }

  /**
   * N3 (spec A8, A9): the bound grant canaries get their verdict from the run's
   * own ledger rows -- when the first of them appears, or a signal came; else,
   * canaryCloseMaxH after the run was taken, HOLD (`canary_close_timeout`, the
   * gate's window and STOP stay as they are). An unbound canary waits: no run,
   * no window, nothing to hold. The verdict closes the gate's canary window
   * (the grant model has no after-reading, so the close step carries a fresh id
   * from the shared id space) -- except on the timeout.
   */
  private settleGrantCanaries(cfg: CreditGateConfig, nowMs: number, rep: ProcessReport): void {
    for (const c of openGrantCanaries(this.db)) {
      if (c.run_id === null) continue
      const start = grantCanaryStart(c)
      const window = windowSince(this.db, start)
      const signal = signalSince(this.db, c.consumed_at)
      let v: GrantCanaryVerdict
      if (signal !== null || window.some((w) => w.source === HEADLESS_SOURCE && w.run_id === c.run_id)) {
        v = evaluateGrantCanary(window, { run_id: c.run_id, min_expected_micro: c.min_expected_micro, budget_micro: c.budget_micro, signal })
      } else if (nowMs >= start + cfg.canaryCloseMaxH * HOUR_MS) {
        v = { outcome: 'undecidable', reason: 'canary_close_timeout' }
      } else {
        continue
      }
      try {
        this.tx(() => {
          const after = nextCalibrationId(this.db)
          const info = this.db.prepare(`UPDATE credit_canaries SET status = ?, after_calibration_id = ?, result_json = ?, evaluated_at = ?
            WHERE approval_id = ? AND status = 'consumed'`).run(v.outcome, after, JSON.stringify(v), nowMs, c.approval_id)
          if (info.changes !== 1) return
          const detail = { canary_approval_id: c.approval_id, after_calibration_id: after, ...v }
          this.gate.audit('canary_evaluated', { reason: v.outcome, calId: after, detail }, nowMs)
          const timeout = v.outcome === 'undecidable' && v.reason === 'canary_close_timeout'
          if (v.outcome === 'incident') {
            const st = this.db.prepare('SELECT state FROM credit_gate_state WHERE id = 1').get() as { state: string } | undefined
            if (st?.state !== 'INCIDENT') this.gate.raiseIncident(`canary_${v.reason}`, detail, nowMs, false)
            rep.incidents++
          } else if (v.outcome === 'undecidable') {
            this.gate.raiseHold(timeout ? 'canary_close_timeout' : 'canary_undecidable', detail, nowMs, false)
            rep.held++
          }
          if (!timeout) this.closeCanaryWindow(after, nowMs)
          rep.changed = true
        })
      } catch (err) {
        if (!isBusy(err)) throw err
      }
    }
  }

  /**
   * After a switch back to the Console source a grant canary row can only be an
   * orphan: the next Console reading would call it `not_the_next_reading` and
   * HOLD the gate for a canary that was never the Console's. Closed here,
   * explicitly, once -- and only on a config that is readable and says console.
   */
  private closeOrphanGrantCanaries(nowMs: number, rep: ProcessReport): void {
    let cfgR: ConfigLoadResult
    try {
      cfgR = this.deps.loadConfig()
    } catch {
      return
    }
    if (!cfgR.ok || cfgR.config.calibrationSource === 'grant_model') return
    for (const c of openGrantCanaries(this.db)) {
      const v: GrantCanaryVerdict = { outcome: 'undecidable', reason: 'grant_source_switched' }
      try {
        this.tx(() => {
          const info = this.db.prepare(`UPDATE credit_canaries SET status = 'undecidable', result_json = ?, evaluated_at = ?
            WHERE approval_id = ? AND status = 'consumed'`).run(JSON.stringify(v), nowMs, c.approval_id)
          if (info.changes !== 1) return
          this.gate.audit('canary_evaluated', {
            reason: v.outcome, calId: c.before_calibration_id, detail: { canary_approval_id: c.approval_id, ...v },
          }, nowMs)
          rep.changed = true
        })
      } catch (err) {
        if (!isBusy(err)) throw err
      }
    }
  }

  /**
   * The runs route's canary start under the grant model (N3), ONE atomic step:
   * the enforce button's canary row, bound to this run -- no new approval. The
   * approval must still verify as the owner's consumed credit_gate_enforce, its
   * chain must be in force, and the run must be exactly what the owner saw:
   * config hash, model, budget (at most), node, cwd and prompt hash. Once: a
   * row that has a run is spent. The old credit_gate_canary approval is refused
   * here and stays unconsumed.
   */
  private bindGrantCanary(
    cfg: CreditGateConfig, approvalId: string, configHash: string, terms: CanaryRunTerms, owner: string, nowMs: number,
    refuse: (reason: CanaryConsumeRefusal) => CanaryConsumeResult,
  ): CanaryConsumeResult {
    if (cfg.grantModel === null) return refuse('config_invalid')
    const maxAgeMs = Math.min(cfg.calibrationMaxAgeH, MAX_CALIBRATION_AGE_H) * HOUR_MS
    try {
      return this.tx((): CanaryConsumeResult => {
        if (this.ownerMismatch(owner, this.calState())) return refuse('owner_changed')
        const a = getApproval(approvalId)
        if (!a) return refuse('not_found')
        if (a.category === 'credit_gate_canary') return refuse('grant_model')
        if (a.category !== 'credit_gate_enforce') return refuse('wrong_category')
        if (a.status !== 'approved' || a.consumed_at == null || a.consumed_by !== CONSUMER || !isOwnerVerified(a.id, owner)) return refuse('not_owner_verified')
        const b = creditGateBinding(a)
        if (!b.bound || b.payload.kind !== 'credit_gate_enforce') return refuse('unbound')
        const p = (b.payload as EnforcePayload).canary
        const row = this.db.prepare(`SELECT ${GRANT_CANARY_COLUMNS} FROM credit_canaries c
          WHERE c.approval_id = ? AND ${GRANT_CANARY_SQL}`).get(approvalId) as GrantCanaryRow | undefined
        if (!row) return refuse('not_found')
        if (row.status !== 'consumed' || row.run_id !== null) return refuse('canary_exists')
        if (p.config_hash !== configHash || row.config_hash !== configHash) return refuse('hash_mismatch')
        const budget = parseUsd(p.budget_usd)
        if (budget === null) return refuse('unbound')
        if (terms.model !== p.model || terms.budget_micro > budget) return refuse('terms_mismatch')
        if (terms.node !== p.node || terms.cwd !== p.cwd || terms.prompt_sha256 !== p.prompt_sha256) return refuse('terms_mismatch')
        const inputs = measureGrantInputs(cfg)
        if (!inputs.ok) return refuse('config_invalid')
        let read: ChainRead
        try {
          read = readChain(this.db, cfg, inputs.hash)
        } catch {
          return refuse('chain_not_in_force')
        }
        if (read.kind !== 'ok' || read.record.approval_id !== a.id || (b.payload as EnforcePayload).grant_model_hash !== inputs.hash) return refuse('chain_not_in_force')
        if (nowMs - row.consumed_at > maxAgeMs) return refuse('before_too_old')
        const u = this.db.prepare(`UPDATE credit_canaries SET run_id = ? WHERE approval_id = ? AND status = 'consumed' AND run_id IS NULL`).run(terms.runId, a.id)
        if (u.changes !== 1) return refuse('canary_exists')
        this.gate.audit('canary_consumed', {
          reason: 'canary_consumed',
          calId: row.before_calibration_id,
          detail: { approval_id: a.id, model: p.model, budget_usd: formatUsd(terms.budget_micro), run_id: terms.runId, grant_model: true },
        }, nowMs)
        return {
          ok: true, approval_id: a.id, config_hash: p.config_hash, model: p.model, budget_micro: budget,
          min_expected_micro: row.min_expected_micro, before_calibration_id: row.before_calibration_id, run_id: terms.runId,
        }
      })
    } catch (err) {
      if (isBusy(err)) return refuse('busy')
      throw err
    }
  }

  /**
   * BE-3c P5: the configured owner is not the pinned one. HOLD once; then only
   * the pinned owner's NEW incident-clear naming the owner_changed event counts.
   */
  private ownerChanged(owner: string, cs: CalState, nowMs: number, rep: ProcessReport): void {
    let state = cs
    if (state.owner_changed_event_id === null) {
      this.tx(() => {
        const ev = this.gate.audit('owner_changed', { reason: 'owner_changed', detail: { why: 'the configured owner is not the pinned one' } }, nowMs)
        this.gate.raiseHold('owner_changed', { owner_changed_event_id: ev }, nowMs, false)
        this.updateCalState({ owner_changed_event_id: ev, owner_changed_at: nowMs })
      })
      rep.held++
      rep.changed = true
      state = this.calState()
    }
    const pinned = state.owner_id as string
    for (const a of listOwnerApprovedUnconsumed(['credit_gate_incident_clear'], pinned, PENDING_LIMIT)) {
      if (this.ownerClearStep(a.id, pinned, owner, state, nowMs) === 'cleared') {
        rep.cleared++
        rep.changed = true
        return
      }
    }
  }

  private ownerClearStep(id: string, pinned: string, owner: string, cs: CalState, nowMs: number): Step {
    try {
      return this.tx((): Step => {
        const a = this.verified(id, 'credit_gate_incident_clear', pinned)
        if (a === null || cs.owner_changed_event_id === null || cs.owner_changed_at === null) return 'skipped'
        const p = (creditGateBinding(a) as { bound: true; payload: IncidentClearPayload }).payload
        // A NEW clear (requested after the change) naming exactly this event.
        if (p.incident_event_id !== cs.owner_changed_event_id || a.requested_at < Math.floor(cs.owner_changed_at / 1000)) return 'skipped'
        this.consume(a, pinned, `owner_changed:${cs.owner_changed_event_id}`, nowMs)
        const floor = Math.max(this.calState().min_captured_at_lb ?? 0, nowMs)
        this.updateCalState({ owner_id: owner, owner_pinned_at: nowMs, owner_changed_event_id: null, owner_changed_at: null, min_captured_at_lb: floor })
        this.gate.audit('owner_change_cleared', { reason: 'owner_change_cleared', detail: { approval_id: a.id, owner_changed_event_id: p.incident_event_id } }, nowMs)
        return 'cleared'
      })
    } catch (err) {
      if (err instanceof Rollback) return err.step
      if (isBusy(err)) return 'deferred'
      throw err
    }
  }

  private calibrationStep(id: string, owner: string, cfg: CreditGateConfig | null, nowMs: number): Step {
    const maxAgeMs = Math.min(cfg?.calibrationMaxAgeH ?? MAX_CALIBRATION_AGE_H, MAX_CALIBRATION_AGE_H) * HOUR_MS
    try {
      return this.tx((): Step => {
        const a = this.verified(id, 'credit_gate_calibration', owner)
        if (a === null) return 'skipped'
        const parsed = parseReadings(a.action_payload)
        if (!parsed.ok) return 'skipped'
        const r = parsed.readings
        const prev = this.previous()
        const cs = this.calState()
        const baseline = cfg?.protected ?? null
        // D-02 first: a fallen protected store is not deferred and not refused.
        const decreased = protectedDecrease(r, baseline, prev?.readings ?? null) !== null
        let window: WindowRow[] | null = null
        if (!decreased) {
          if (cfg === null) {
            this.warnOnce('config', 'credit gate: no valid config, calibrations wait')
            return 'deferred'
          }
          const timing = checkTiming(r, prev?.readings ?? null, nowMs, maxAgeMs, cs.min_captured_at_lb)
          if (timing === null && !this.ledgerReady(cfg, r.captured_at_lb_ms, nowMs)) return 'deferred'
          if (timing === null && prev) window = this.windowRows(prev.readings.captured_at_lb_ms, r.captured_at_lb_ms)
        }
        const v = evaluateCalibration(r, { nowMs, maxAgeMs, baseline, prev: prev?.readings ?? null, window, minCapturedAtLbMs: cs.min_captured_at_lb })
        const reason = v.outcome === 'accepted' ? null : v.reason
        const reconcile = v.outcome === 'accepted' ? v.reconcile : v.outcome === 'rejected' ? null : v.detail
        const info = this.db.prepare(`INSERT INTO credit_calibrations
            (approval_id, captured_at_lb, readings_json, content_hash, accepted_at, outcome, reason, reconcile_json)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
          a.id, r.captured_at_lb_ms, a.action_payload, a.content_hash, nowMs, v.outcome, reason, reconcile === null ? null : JSON.stringify(reconcile),
        )
        const calId = Number(info.lastInsertRowid)
        this.consume(a, owner, `credit_calibrations:${calId}`, nowMs)
        // BE-3c P5: the owner of the first accepted reading is pinned.
        if (v.outcome === 'accepted' && cs.owner_id === null) this.updateCalState({ owner_id: owner, owner_pinned_at: nowMs })
        const detail = { approval_id: a.id, calibration_id: calId, captured_at_lb: new Date(r.captured_at_lb_ms).toISOString(), reason, reconcile }
        this.gate.audit(v.outcome === 'accepted' ? 'calibration' : `calibration_${v.outcome}`, { reason, calId, detail }, nowMs)
        if (v.outcome === 'incident') this.gate.raiseIncident(v.reason, detail, nowMs, false)
        else if (v.outcome === 'hold') this.gate.raiseHold(v.reason, detail, nowMs, false)
        if (v.outcome !== 'rejected' && prev !== null) this.evaluateOpenCanaries(prev, { id: calId, readings: r }, v.outcome, nowMs)
        // K-01 (N7B1): a recorded reading is the after-reading of an open
        // canary window -- its close step, in this transaction. No window: refused, nothing changes.
        if (v.outcome !== 'rejected') this.closeCanaryWindow(calId, nowMs)
        return v.outcome === 'accepted' ? 'accepted' : v.outcome
      })
    } catch (err) {
      if (err instanceof Rollback) return err.step
      if (isBusy(err)) return 'deferred'
      throw err
    }
  }

  /** The gate's canary window closes with the after-reading's recording (K-01, N7B1). */
  private closeCanaryWindow(calId: number, nowMs: number): void {
    const c = this.gate.closeCanary(calId, nowMs, false)
    // No window is the normal case (no canary ran); any other refusal keeps
    // the window -- and the STOP -- and the deadline's HOLD will say so.
    if (!c.ok && c.reason !== 'no_canary_window') logger.warn({ calibration_id: calId, reason: c.reason }, 'credit gate: the canary window was not closed by this reading')
  }

  /** The canaries waiting for this reading: their after-reading is this one. */
  private evaluateOpenCanaries(
    prev: { row: CalibrationRow; readings: Readings },
    after: { id: number; readings: Readings },
    outcome: CalibrationVerdict['outcome'],
    nowMs: number,
  ): void {
    // A grant_model canary has no Console after-reading: it is judged on the run's own rows (settleGrantCanaries).
    const open = this.db.prepare(`SELECT c.approval_id, c.run_id, c.min_expected_micro, c.before_calibration_id
      FROM credit_canaries c WHERE c.status = 'consumed' AND NOT ${GRANT_CANARY_SQL} ORDER BY c.consumed_at, c.approval_id`).all() as CanaryRow[]
    for (const c of open) {
      let v: CanaryVerdict
      if (outcome === 'incident') v = { outcome: 'incident', reason: 'protected_decreased' }
      else if (c.before_calibration_id !== prev.row.id) v = { outcome: 'undecidable', reason: 'not_the_next_reading' }
      else if (outcome !== 'accepted') v = { outcome: 'undecidable', reason: `after_reading_${outcome}` }
      else {
        v = evaluateCanary(prev.readings, after.readings, this.windowRows(prev.readings.captured_at_lb_ms, after.readings.captured_at_lb_ms), {
          run_id: c.run_id, min_expected_micro: c.min_expected_micro,
        })
      }
      this.db.prepare(`UPDATE credit_canaries SET status = ?, after_calibration_id = ?, result_json = ?, evaluated_at = ?
        WHERE approval_id = ? AND status = 'consumed'`).run(v.outcome, after.id, JSON.stringify(v), nowMs, c.approval_id)
      const detail = { canary_approval_id: c.approval_id, after_calibration_id: after.id, ...v }
      this.gate.audit('canary_evaluated', { reason: v.outcome, calId: after.id, detail }, nowMs)
      // A calibration INCIDENT is already raised; the canary only adds its own.
      if (v.outcome === 'incident' && outcome !== 'incident') this.gate.raiseIncident(`canary_${v.reason}`, detail, nowMs, false)
      else if (v.outcome === 'undecidable' && outcome === 'accepted') this.gate.raiseHold('canary_undecidable', detail, nowMs, false)
    }
  }

  private incidentClearStep(id: string, owner: string, nowMs: number): Step {
    try {
      return this.tx((): Step => {
        const a = this.verified(id, 'credit_gate_incident_clear', owner)
        if (a === null) return 'skipped'
        const p = (creditGateBinding(a) as { bound: true; payload: IncidentClearPayload }).payload
        const eventId = p.incident_event_id
        const st = this.db.prepare('SELECT state, reason, since, incident_event_id, guard_cursor_json FROM credit_gate_state WHERE id = 1').get() as
          { state: string; reason: string; since: number; incident_event_id: number | null; guard_cursor_json: string | null } | undefined
        this.consume(a, owner, `credit_gate_events:${eventId}`, nowMs)
        const detail = { approval_id: a.id, incident_event_id: eventId }
        // Only the newest open cause it names: an approval for another (or a future) one is spent here.
        if (!st || st.state !== 'INCIDENT' || st.incident_event_id !== eventId) {
          this.gate.audit('incident_clear_refused', { reason: 'not_the_open_incident', detail: { ...detail, open_incident_event_id: st?.incident_event_id ?? null } }, nowMs)
          return 'refused'
        }
        // The owner's clear of a guard cause is the review of the guard file: only then is a broken cursor reset.
        if (isGuardReason(st.reason) && guardCursorBroken(st.guard_cursor_json)) this.gate.resetGuardCursor(nowMs)
        if (!this.gate.clearIncident(eventId, nowMs)) throw new Error('credit gate: the incident clear did not apply')
        const after = this.db.prepare('SELECT state FROM credit_gate_state WHERE id = 1').get() as { state: string }
        const lifted = after.state !== 'INCIDENT'
        if (lifted) {
          // MED-2: only a reading taken after the INCIDENT began and after this clear opens.
          const floor = Math.max(this.calState().min_captured_at_lb ?? 0, st.since, nowMs)
          this.updateCalState({ min_captured_at_lb: floor })
        }
        this.gate.audit('incident_clear', { reason: lifted ? 'incident_cleared' : 'incident_cause_cleared', detail: { ...detail, cause: st.reason } }, nowMs)
        return 'cleared'
      })
    } catch (err) {
      if (err instanceof Rollback) return err.step
      if (isBusy(err)) return 'deferred'
      throw err
    }
  }

  /**
   * The runner's canary start (K-01), ONE atomic step (LOW-3): the owner's
   * credit_gate_canary approval, consumed once, for exactly `configHash`, bound
   * to the run's model (the approved one), budget (at most the approved one)
   * and run id -- all mandatory. Its before-reading must be the newest accepted
   * calibration (nothing read since), at most 24 h old, with no canary yet.
   */
  consumeCanaryApproval(approvalId: string, configHash: string, terms: CanaryRunTerms, nowMs: number = this.nowFn()): CanaryConsumeResult {
    const refuse = (reason: CanaryConsumeRefusal): CanaryConsumeResult => {
      logger.warn({ approval_id: typeof approvalId === 'string' ? approvalId.slice(0, 64) : null, reason }, 'credit gate: canary approval refused')
      return { ok: false, reason }
    }
    if (typeof approvalId !== 'string' || approvalId === '' || typeof configHash !== 'string' || !SHA256_HEX_RE.test(configHash)) return refuse('bad_request')
    if (typeof terms !== 'object' || terms === null || typeof terms.model !== 'string' || terms.model === ''
      || !Number.isSafeInteger(terms.budget_micro) || terms.budget_micro <= 0
      || typeof terms.runId !== 'string' || !RUN_ID_RE.test(terms.runId)
      || typeof terms.node !== 'string' || terms.node === '' || typeof terms.cwd !== 'string' || terms.cwd === ''
      || typeof terms.prompt_sha256 !== 'string' || !SHA256_HEX_RE.test(terms.prompt_sha256)) return refuse('bad_request')
    const owner = this.owner()
    if (owner === null) return refuse('no_owner')
    const cfgR = this.deps.loadConfig()
    if (!cfgR.ok) return refuse('config_invalid')
    // Card 40e03382: under the grant model the canary is the enforce button's own; no credit_gate_canary approval is consumed.
    if (cfgR.config.calibrationSource === 'grant_model') return this.bindGrantCanary(cfgR.config, approvalId, configHash, terms, owner, nowMs, refuse)
    const maxAgeMs = Math.min(cfgR.config.calibrationMaxAgeH, MAX_CALIBRATION_AGE_H) * HOUR_MS
    try {
      return this.tx((): CanaryConsumeResult => {
        if (this.ownerMismatch(owner, this.calState())) return refuse('owner_changed')
        const a = getApproval(approvalId)
        if (!a) return refuse('not_found')
        if (a.category !== 'credit_gate_canary') return refuse('wrong_category')
        if (a.consumed_at != null) return refuse('already_consumed')
        if (a.status !== 'approved' || !isOwnerVerified(a.id, owner)) return refuse('not_owner_verified')
        const b = creditGateBinding(a)
        if (!b.bound || b.payload.kind !== 'credit_gate_canary') return refuse('unbound')
        const p = b.payload as CanaryPayload
        if (p.config_hash !== configHash) return refuse('hash_mismatch')
        const budget = parseUsd(p.budget_usd)
        const minExpected = parseUsd(p.min_expected_usd)
        if (budget === null || minExpected === null) return refuse('unbound')
        if (terms.model !== p.model || terms.budget_micro > budget) return refuse('terms_mismatch')
        // BE-4b P6: only for the run the owner saw (node, cwd, prompt).
        if (terms.node !== p.node || terms.cwd !== p.cwd || terms.prompt_sha256 !== p.prompt_sha256) return refuse('terms_mismatch')
        const before = this.db.prepare(`SELECT ${ROW_COLUMNS} FROM credit_calibrations WHERE approval_id = ?`)
          .get(p.before_calibration_id) as CalibrationRow | undefined
        if (!before || before.outcome !== 'accepted' || rowReadings(before) === null) return refuse('before_not_accepted')
        if (this.previous()?.row.id !== before.id) return refuse('before_not_latest')
        if (nowMs - before.captured_at_lb > maxAgeMs) return refuse('before_too_old')
        if (this.db.prepare('SELECT 1 FROM credit_canaries WHERE before_calibration_id = ?').get(before.id)) return refuse('canary_exists')
        const c = this.consumeFn({ id: a.id, category: 'credit_gate_canary', ownerId: owner, consumer: CONSUMER, ref: `credit_calibrations:${before.id}`, nowS: Math.floor(nowMs / 1000) })
        if (!c.ok) return refuse(c.reason === 'already_consumed' ? 'already_consumed' : 'not_owner_verified')
        this.db.prepare(`INSERT INTO credit_canaries
            (approval_id, config_hash, model, budget_micro, min_expected_micro, before_calibration_id, run_id, status, consumed_at)
          VALUES (?, ?, ?, ?, ?, ?, ?, 'consumed', ?)`).run(a.id, p.config_hash, p.model, budget, minExpected, before.id, terms.runId, nowMs)
        this.gate.audit('canary_consumed', { reason: 'canary_consumed', calId: before.id, detail: { approval_id: a.id, model: p.model, budget_usd: formatUsd(terms.budget_micro), run_id: terms.runId } }, nowMs)
        return { ok: true, approval_id: a.id, config_hash: p.config_hash, model: p.model, budget_micro: budget, min_expected_micro: minExpected, before_calibration_id: before.id, run_id: terms.runId }
      })
    } catch (err) {
      if (isBusy(err)) return refuse('busy')
      throw err
    }
  }
}

/**
 * The gate's stored guard cursor is broken -- or unreadable, which the gate
 * treats as broken too (gate.ts parseGuardCursor): either way an INCIDENT on
 * every evaluation until it is reset.
 */
function guardCursorBroken(json: string | null): boolean {
  if (json === null) return false
  try {
    const o = JSON.parse(json) as Record<string, unknown> | null
    if (typeof o !== 'object' || o === null) return true
    if (typeof o.broken === 'string') return true
    if (o.absent === true) return false
    return !(typeof o.dev === 'string' && typeof o.ino === 'string' && Number.isSafeInteger(o.offset)
      && (typeof o.tail_sha256 === 'string' || o.tail_sha256 === null))
  } catch {
    return true
  }
}
