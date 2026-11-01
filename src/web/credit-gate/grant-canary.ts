// The grant_model canary (card 40e03382, node N3): the verdict on one headless
// run, and the rows it is read from.
//
// The Console canary (calibration.ts evaluateCanary) compares a grant's fall
// between two Console readings with the run's ledger cost. The grant model has
// no readings, so there is nothing to compare: the verdict rests on the run's
// OWN ledger rows alone (spec A8). The canary row is the one the enforce
// button's consume wrote (run_id null); the runs route binds it to exactly one
// run (calibration.ts bindGrantCanary), and the tick closes it here.
//
//   success      the run's own rows are all priced, they cost at least
//                min_expected and at most the approved budget, no other
//                headless row is in the window, and no credit_balance_too_low
//                or 401 signal came since the button was consumed.
//   incident     such a signal came (A9; the gate is already closing on it).
//   undecidable  anything else -- over the budget (a run that cost more than its
//                hard ceiling, or whose cost fell back to the whole reservation),
//                under the minimum, an unpriced row, another headless run in
//                the window, no row of the run (yet).
//
// Rows of other sources do not move the verdict: the model has no second
// reading for them to hide a charge from.

import type Database from 'better-sqlite3'
import type { WindowRow } from './calibration.js'
import { HEADLESS_SOURCE } from './ledger.js'

export type GrantCanarySignal = 'credit_balance_too_low' | 'auth_401'

export interface GrantCanaryTerms {
  /** The headless run the canary row is bound to; null = never bound. */
  readonly run_id: string | null
  readonly min_expected_micro: number
  readonly budget_micro: number
  /** The signal the gate recorded since the button was consumed, if any. */
  readonly signal: GrantCanarySignal | null
}

export type GrantCanaryVerdict =
  | { readonly outcome: 'success'; readonly cost_micro: number; readonly rows: number }
  | { readonly outcome: 'incident'; readonly reason: string }
  | { readonly outcome: 'undecidable'; readonly reason: string }

/** The row's L contribution, as calibration.ts counts it: max(est, cli); without an estimate its CLI figure. */
export function rowCost(r: WindowRow): number {
  if (r.est_micro === null) return r.cli_micro ?? 0
  return r.cli_micro === null || r.est_micro >= r.cli_micro ? r.est_micro : r.cli_micro
}

export function evaluateGrantCanary(window: readonly WindowRow[], terms: GrantCanaryTerms): GrantCanaryVerdict {
  const undecidable = (reason: string): GrantCanaryVerdict => ({ outcome: 'undecidable', reason })
  if (terms.signal !== null) return { outcome: 'incident', reason: terms.signal }
  if (terms.run_id === null) return undecidable('canary_run_unbound')
  const own = window.filter((w) => w.source === HEADLESS_SOURCE && w.run_id === terms.run_id)
  if (own.length === 0) return undecidable('canary_not_in_window')
  if (own.some((w) => w.est_micro === null)) return undecidable('unpriced_rows')
  if (window.some((w) => w.source === HEADLESS_SOURCE && w.run_id !== terms.run_id)) return undecidable('other_headless_rows')
  let cost = 0
  for (const w of own) {
    cost += rowCost(w)
    if (!Number.isSafeInteger(cost)) return undecidable('overflow')
  }
  if (cost < terms.min_expected_micro) return undecidable('canary_below_minimum')
  if (cost > terms.budget_micro) return undecidable('canary_over_budget')
  return { outcome: 'success', cost_micro: cost, rows: own.length }
}

// ------------------------------------------------------------------ the rows

/**
 * A canary row of the grant model: its before_calibration_id names a
 * credit_grant_periods row of the same approval (the shared id space makes the
 * pair unambiguous). Console canary rows never match. For the alias `c`.
 */
export const GRANT_CANARY_SQL = `EXISTS (SELECT 1 FROM credit_grant_periods g
  WHERE g.id = c.before_calibration_id AND g.approval_id = c.approval_id)`

export interface GrantCanaryRow {
  readonly approval_id: string
  readonly run_id: string | null
  readonly config_hash: string
  readonly model: string
  readonly budget_micro: number
  readonly min_expected_micro: number
  readonly before_calibration_id: number
  readonly status: string
  readonly consumed_at: number
  readonly hash_taken_at: number | null
}

export const GRANT_CANARY_COLUMNS = `c.approval_id, c.run_id, c.config_hash, c.model, c.budget_micro, c.min_expected_micro,
  c.before_calibration_id, c.status, c.consumed_at, c.hash_taken_at`

/** The grant canaries still waiting for a verdict, oldest first. */
export function openGrantCanaries(db: Database.Database): GrantCanaryRow[] {
  return db.prepare(`SELECT ${GRANT_CANARY_COLUMNS} FROM credit_canaries c
    WHERE c.status = 'consumed' AND ${GRANT_CANARY_SQL} ORDER BY c.consumed_at, c.approval_id`).all() as GrantCanaryRow[]
}

/** The newest grant canary of any status (the status endpoint), or null. */
export function newestGrantCanary(db: Database.Database): GrantCanaryRow | null {
  return (db.prepare(`SELECT ${GRANT_CANARY_COLUMNS} FROM credit_canaries c
    WHERE ${GRANT_CANARY_SQL} ORDER BY c.consumed_at DESC, c.rowid DESC LIMIT 1`).get() as GrantCanaryRow | undefined) ?? null
}

/** When the run's window starts: the runner took the hash (the run started), else the button. */
export function grantCanaryStart(c: GrantCanaryRow): number {
  return c.hash_taken_at ?? c.consumed_at
}

/** The ledger rows from `fromMs` on (the run's rows carry the run's end time). */
export function windowSince(db: Database.Database, fromMs: number): WindowRow[] {
  return db.prepare(`SELECT source, run_id, batch_id, est_micro, cli_micro FROM credit_ledger_entries
    WHERE ts >= ? ORDER BY id`).all(Math.floor(fromMs / 1000)) as WindowRow[]
}

/** A credit_balance_too_low or 401 signal the gate recorded since `sinceMs`; the first one. */
export function signalSince(db: Database.Database, sinceMs: number): GrantCanarySignal | null {
  const r = db.prepare(`SELECT reason FROM credit_gate_events
    WHERE kind = 'signal' AND reason IN ('credit_balance_too_low', 'auth_401') AND at >= ? ORDER BY id LIMIT 1`).get(sinceMs) as
    { reason: GrantCanarySignal } | undefined
  return r?.reason ?? null
}
