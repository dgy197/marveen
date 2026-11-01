// The status endpoint's grant_model block (card 40e03382, node N3): what the
// grant model would hand the gate, read-only and shown in every mode (shadow
// too), so the owner can see the model before the one button.
//
// Names, ISO times, hashes of the config and USD strings only -- never a path,
// the reconstructed file's own hash, a key or a token. The r_est preview is
// the gate's formula on this model's numbers (the grant less the prior charge,
// less what the ledger booked since the period began, less the open
// reservations); the gate's own r_est_usd stays the word of the gate.

import type Database from 'better-sqlite3'
import type { ConfigLoadResult } from './config.js'
import { formatUsd, type PricingFileResult } from './gate.js'
import { newestGrantCanary, rowCost, windowSince } from './grant-canary.js'
import { currentPeriod, grantRemaining, priorCharge } from './grant-model.js'
import { measureGrantInputs, readChain } from './grant-period.js'
import type { Micro, PricingTable } from './types.js'

export interface GrantModelStatus {
  readonly source: 'grant_model'
  /** grantModelHash of the config as it is now (the reconstructed file measured); null when the file is not good. */
  readonly config_hash: string | null
  readonly inputs: { readonly ok: boolean; readonly why: string | null }
  readonly period: { readonly label: string; readonly lb: string; readonly expires: string }
  readonly prior_charge_usd: string | null
  readonly remaining_usd: string | null
  readonly ledger_since_lb_usd: string | null
  readonly unpriced_rows: number | null
  readonly open_reservations_usd: string | null
  readonly r_est_preview_usd: string | null
  readonly chain: { readonly state: 'unknown' | 'none' | 'ok' | 'stale' | 'invalid'; readonly period_id: number | null }
  readonly canary: { readonly status: string; readonly run_bound: boolean } | null
}

function iso(ms: number): string {
  return new Date(ms).toISOString()
}

/** The block, or null when the config does not select the grant model (or cannot be read). */
export function grantModelStatus(
  db: Database.Database | null,
  cfgR: ConfigLoadResult,
  loadPricing: (nowMs: number) => PricingFileResult,
  nowMs: number,
): GrantModelStatus | null {
  if (!cfgR.ok || cfgR.config.calibrationSource !== 'grant_model' || cfgR.config.grantModel === null) return null
  const cfg = cfgR.config
  const gm = cfg.grantModel as NonNullable<typeof cfg.grantModel>
  const inputs = measureGrantInputs(cfg)
  const period = currentPeriod(gm, nowMs)
  const base = {
    source: 'grant_model' as const,
    config_hash: inputs.ok ? inputs.hash : null,
    inputs: { ok: inputs.ok, why: inputs.ok ? null : inputs.why },
    period: { label: period.key, lb: iso(period.lbMs), expires: iso(period.expiresMs) },
  }
  let prior: Micro | null = null
  if (inputs.ok) {
    let table: PricingTable | null = null
    let skip = false
    if (gm.reconstructed !== null) {
      try {
        const p = loadPricing(nowMs)
        if (p.ok) table = p.table
        else skip = true
      } catch {
        skip = true
      }
    }
    if (!skip) prior = priorCharge(inputs.rows, gm, period.lbMs, table as PricingTable)
  }
  const remaining = prior === null ? null : grantRemaining(gm, prior)

  let ledger: number | null = null
  let unpriced: number | null = null
  let open: number | null = null
  let chain: GrantModelStatus['chain'] = { state: 'unknown', period_id: null }
  let canary: GrantModelStatus['canary'] = null
  if (db !== null) {
    try {
      const rows = windowSince(db, period.lbMs)
      ledger = rows.reduce((t, r) => t + rowCost(r), 0)
      unpriced = rows.filter((r) => r.est_micro === null).length
      open = (db.prepare("SELECT COALESCE(SUM(amount_micro), 0) AS n FROM credit_reservations WHERE status IN ('open', 'unknown')").get() as { n: number }).n
    } catch {
      ledger = null
      unpriced = null
      open = null
    }
    if (inputs.ok) {
      try {
        const read = readChain(db, cfg, inputs.hash)
        chain = read.kind === 'none' ? { state: 'none', period_id: null } : { state: read.kind, period_id: read.row.id }
      } catch {
        chain = { state: 'invalid', period_id: null }
      }
    }
    try {
      const c = newestGrantCanary(db)
      canary = c === null ? null : { status: c.status, run_bound: c.run_id !== null }
    } catch {
      canary = null
    }
  }
  const preview = remaining === null || ledger === null || open === null ? null : remaining - ledger - open
  return {
    ...base,
    prior_charge_usd: prior === null ? null : formatUsd(prior),
    remaining_usd: remaining === null ? null : formatUsd(remaining),
    ledger_since_lb_usd: ledger === null ? null : formatUsd(ledger),
    unpriced_rows: unpriced,
    open_reservations_usd: open === null ? null : formatUsd(open),
    r_est_preview_usd: preview === null ? null : formatUsd(preview),
    chain,
    canary,
  }
}
