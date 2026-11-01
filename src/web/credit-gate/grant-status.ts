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
import type { EnforceConfigView } from '../approval-telegram-text.js'
import type { Factor, Micro, PricingTable } from './types.js'

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

/** A multiplier as a decimal (4 places, trailing zeros trimmed); "~" marks a rounded-down figure. */
function formatFactor(f: Factor): string {
  const whole = f.num / f.den
  const rem = f.num % f.den
  const scaled = (rem * 10000n) / f.den
  const frac = scaled.toString().padStart(4, '0').replace(/0+$/, '')
  const exact = scaled * f.den === rem * 10000n
  return `${exact ? '' : '~'}${whole.toString()}${frac === '' ? '' : `.${frac}`}`
}

/**
 * Card 40e03382, R2 MED-1: the grant-model figures the enforce button's text
 * shows, from the config as it is NOW. `match` only when that config hashes
 * (the reconstructed file measured) to `expectedHash`, the payload's
 * grant_model_hash; a config that cannot be read, is not grant_model, or whose
 * file is not good is `unreadable`; any other hash is `mismatch`. The remaining
 * is grantModelStatus's remaining_usd (the grant less the prior charge at the
 * period's start) -- no formula of its own.
 */
export function enforceConfigView(
  cfgR: ConfigLoadResult,
  expectedHash: string,
  loadPricing: (nowMs: number) => PricingFileResult,
  nowMs: number,
): EnforceConfigView {
  const status = grantModelStatus(null, cfgR, loadPricing, nowMs)
  if (status === null || !cfgR.ok || status.config_hash === null) return { state: 'unreadable' }
  if (status.config_hash !== expectedHash) return { state: 'mismatch' }
  const gm = cfgR.config.grantModel as NonNullable<typeof cfgR.config.grantModel>
  const period = currentPeriod(gm, nowMs)
  const rc = gm.reconstructed
  return {
    state: 'match',
    grantUsd: formatUsd(gm.grantUsd),
    grantDays: [...gm.grantDays],
    periodLbMs: period.lbMs,
    periodExpiresMs: period.expiresMs,
    boundaryLeadH: gm.boundaryLeadH,
    multiplier: rc === null ? null : formatFactor(rc.multiplier),
    gapChargeUsd: rc === null ? null : formatUsd(rc.gap.chargeUsd),
    remainingUsd: status.remaining_usd,
  }
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
