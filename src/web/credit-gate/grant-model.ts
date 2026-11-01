// The grant model's pure core (card 40e03382, node N1): the calibration the
// gate takes from the config instead of a Console reading. No database, no
// clock, no network; the gate, the processor and the status read these.
//
// The model (spec 2): a grant of `grantUsd` arrives on one of the candidate
// days of the month. Its exact hour is unknown, so a period runs from
// `00:00Z of the grant day - boundaryLeadH` to the same point of the next
// grant. For each candidate day the current period is the latest one that has
// started; across candidates the EARLIEST start and the EARLIEST expiry win.
// Both choices lean strict: more of the past counts as spent, and the grant
// ends no later than it might. The gate gets ONE synthetic grant from this:
// granted = lb, expires = the earliest next grant, remaining = grant - the
// prior charge of everything the ledger cannot show since lb.
//
// The prior charge (spec 3) is the reconstructed rows' cost since lb, times a
// multiplier, plus the fixed gap charge while lb is before the gap's end. All
// money is whole micro-USD; the one division rounds UP.

import { createHash } from 'node:crypto'
import { canonicalJson } from '../../approval-envelope.js'
import { readProtectedFile, type CreditGateConfig, type GrantModelConfig } from './config.js'
import { ceilDiv, microFromBigInt, subMicro } from './money.js'
import { parseUsageLine, type UsageRow } from './ledger-usage-jsonl.js'
import { estimate } from './pricing.js'
import type { Micro, PricingTable } from './types.js'

const HOUR_MS = 3_600_000
/** The version of the hashed shape; bump it if the hashed parts change. */
const HASH_VERSION = 2
const SHA256_HEX_RE = /^[0-9a-f]{64}$/

export interface GrantPeriod {
  /** The synthetic grant's start: the earliest period start across the candidate days. */
  readonly lbMs: number
  /** The earliest next grant across the candidate days. */
  readonly expiresMs: number
  /** Identifies the (lb, expires) pair; a new key is a new period. */
  readonly key: string
}

/**
 * The current period at `nowMs`. For a candidate day D, the occurrence of D in
 * month m starts at Date.UTC(y, m, D) - lead; the current one is the latest
 * occurrence that has started (lb <= now), and the next occurrence's start is
 * its expiry. Always lb <= now < expires.
 */
export function currentPeriod(cfg: GrantModelConfig, nowMs: number): GrantPeriod {
  if (!Number.isFinite(nowMs)) throw new RangeError('currentPeriod: now must be a finite time')
  const lead = cfg.boundaryLeadH * HOUR_MS
  const base = new Date(nowMs)
  const y = base.getUTCFullYear()
  const mo = base.getUTCMonth()
  let lbMs = Number.POSITIVE_INFINITY
  let expiresMs = Number.POSITIVE_INFINITY
  for (const day of cfg.grantDays) {
    // The lead is at most 48 h and the day at most 28, so the current
    // occurrence is in the previous, this or the next month; look one wider.
    let current = Number.NEGATIVE_INFINITY
    let next = Number.POSITIVE_INFINITY
    for (let m = mo - 2; m <= mo + 2; m++) {
      const start = Date.UTC(y, m, day) - lead
      if (start <= nowMs) current = Math.max(current, start)
      else next = Math.min(next, start)
    }
    lbMs = Math.min(lbMs, current)
    expiresMs = Math.min(expiresMs, next)
  }
  return { lbMs, expiresMs, key: `${new Date(lbMs).toISOString()}/${new Date(expiresMs).toISOString()}` }
}

/**
 * The cost of the recovered rows since `lbMs` times the multiplier (rounded up
 * once, on the sum), plus the fixed gap charge while `lbMs` is before the
 * gap's end. A row counts when ts >= lb. Each row's cost is L = max(estimate,
 * the CLI's own figure). Null when any row cannot be priced -- the whole
 * answer, whatever lb, because the file is one measurement -- or when the sum
 * leaves the safe-integer range. Without a `reconstructed` block: 0.
 */
export function priorCharge(
  rows: readonly UsageRow[],
  cfg: GrantModelConfig,
  lbMs: number,
  table: PricingTable,
): Micro | null {
  const rc = cfg.reconstructed
  if (rc === null) return 0 as Micro
  let sum = 0n
  for (const r of rows) {
    const est = estimate(
      {
        model: r.model,
        input_tokens: r.input_tokens,
        output_tokens: r.output_tokens,
        cache_write_tokens: r.cache_write_tokens,
        cache_read_tokens: r.cache_read_tokens,
        batch_id: r.batch_id,
      },
      { table },
    )
    if (est === null) return null
    if (r.ts * 1000 >= lbMs) sum += BigInt(r.cli_micro !== null && r.cli_micro > est ? r.cli_micro : est)
  }
  let total = ceilDiv(sum * rc.multiplier.num, rc.multiplier.den)
  if (lbMs < rc.gap.toMs) total += BigInt(rc.gap.chargeUsd)
  return microFromBigInt(total)
}

/** The synthetic grant's remaining: the grant less the prior charge, never below zero (A4). */
export function grantRemaining(cfg: GrantModelConfig, prior: Micro): Micro {
  const left = subMicro(cfg.grantUsd, prior)
  return (left < 0 ? 0 : left) as Micro
}

/**
 * sha256 of everything the grant model's calibration rests on (spec 4): the
 * grantModel block, the thresholds, the expiry margin, the batch horizon, the
 * ledger sources, the reservation factor, the ledger age limit, and the
 * reconstructed file's sha256 as MEASURED (`fileSha`, null when the config has
 * no reconstructed block). A change to any of them is a different hash, so the
 * approval that bound the old one stops matching.
 * The spec keeps refreshS, calibrationMaxAgeH, canaryCloseMaxH, stopFile and
 * protected outside the button binding (they are not hashed on purpose).
 */
export function grantModelHash(config: CreditGateConfig, fileSha: string | null): string {
  const gm = config.grantModel
  if (gm === null) throw new Error('grantModelHash: the config has no grantModel')
  const rc = gm.reconstructed
  const t = config.thresholds
  const doc = {
    v: HASH_VERSION,
    grantModel: {
      grantUsd: gm.grantUsd,
      grantDays: [...gm.grantDays],
      boundaryLeadH: gm.boundaryLeadH,
      ...(rc === null
        ? {}
        : {
            reconstructed: {
              path: rc.path,
              sha256: rc.sha256,
              multiplier: { num: rc.multiplier.num.toString(), den: rc.multiplier.den.toString() },
              gap: { fromMs: rc.gap.fromMs, toMs: rc.gap.toMs, chargeUsd: rc.gap.chargeUsd },
            },
          }),
    },
    thresholds: {
      tClose: t.tClose,
      tLowcal: t.tLowcal,
      tReopen: t.tReopen,
      tCloseLowcalFallback: t.tCloseLowcalFallback,
      lowcalWaitH: t.lowcalWaitH,
    },
    expiryMarginH: config.expiryMarginH,
    batchHorizonH: config.batchHorizonH,
    // R2 LOW-2: the reserve's inflation and the ledger's staleness limit move what the gate admits.
    reservationFactor: { num: config.reservationFactor.num.toString(), den: config.reservationFactor.den.toString() },
    maxLedgerAgeS: config.maxLedgerAgeS,
    ledgerSources: config.ledgerSources.map((s) => ({ id: s.id, path: s.path, format: s.format })),
    reconstructedFileSha256: fileSha ?? '',
  }
  const text = canonicalJson(doc)
  if (text === null) throw new Error('grantModelHash: the hashed document is not canonical')
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

export type ReconstructedReadResult =
  | { readonly ok: true; readonly rows: readonly UsageRow[]; readonly sha256: string }
  | {
      readonly ok: false
      readonly reason: 'missing' | 'unreadable' | 'permissions' | 'sha_mismatch' | 'empty' | 'bad_row'
      /** Never carries file content: only a line number and the parser's reason. */
      readonly detail: string
    }

/**
 * The recovered usage file as data: read like a gate data file (regular file,
 * no symlink, owner, 0600 in a 0700 folder), its bytes pinned to `sha256`, and
 * EVERY line parsed by the usage-jsonl-v1 line parser. One line the parser
 * rejects, a missing final newline, a blank line or an empty file fails the
 * whole file -- a skipped line would be spend nobody counts.
 */
export function readReconstructed(path: string, sha256: string): ReconstructedReadResult {
  const r = readProtectedFile(path)
  if (!r.ok) return { ok: false, reason: r.reason, detail: r.detail }
  const actual = createHash('sha256').update(r.text, 'utf8').digest('hex')
  if (!SHA256_HEX_RE.test(sha256) || actual !== sha256) {
    return { ok: false, reason: 'sha_mismatch', detail: 'the file does not match the pinned sha256' }
  }
  const lines = r.text.split('\n')
  if (lines.pop() !== '') return { ok: false, reason: 'bad_row', detail: `line ${lines.length + 1}: not terminated by a newline` }
  if (lines.length === 0) return { ok: false, reason: 'empty', detail: 'the file has no row' }
  const rows: UsageRow[] = []
  for (const [i, text] of lines.entries()) {
    const p = parseUsageLine(text)
    if (!p.ok) return { ok: false, reason: 'bad_row', detail: `line ${i + 1}: ${p.reason}` }
    rows.push(p.row)
  }
  return { ok: true, rows, sha256: actual }
}
