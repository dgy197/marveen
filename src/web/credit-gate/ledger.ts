// The credit gate's ledger (card fec6335f, spec B-01..B-04 and A-02, blueprint
// 3.3, 3.4 and N1b): every usage.jsonl line and every headless run, each
// counted exactly once, priced as an overestimate.
//
//  - refresh(now, table) reads the configured usage.jsonl sources from their
//    cursors (ledger-usage-jsonl.ts). A damaged source -- truncated, replaced,
//    rewritten, a symlink, an unreadable line, a line half-written for more
//    than 120 s -- turns `broken` and STAYS broken (the gate goes to HOLD)
//    until resetSource() is called; nothing after the damage is read.
//  - recordHeadless(run) books a headless run as ONE row: the estimate from
//    its JSON usage and the CLI's own total_cost_usd side by side; without
//    JSON, the estimate from its transcript (ledger-transcript.ts); without a
//    usable transcript, its full reservation (B-04).
//  - ledgerSum(captured_at_lb) is L(t): per row max(est, cli), summed over the
//    rows stamped at or after the calibration's lower bound.
//
// No input makes the ledger throw: a token field at or above 10^9 breaks the
// source (usage.jsonl) or makes a headless result or transcript unusable (the
// run then books its full reservation), and ledgerSum / ingestedForBatch
// SATURATE at 100 000 USD (`saturated: true`) instead of leaving the safe
// range -- an overstated L only closes the gate.
//
// A row whose model has no price is stored with est_micro NULL: it never
// counts as zero silently, ledgerSum reports it (`unpriced`), and that is the
// A-02 "no price for a model" signal. A later refresh with a price table
// prices such usage rows (a table that was stale for a while must not leave
// the gate shut forever).
//
// Everything is synchronous (fs + better-sqlite3), so one refresh never
// interleaves with another call in the dashboard process.

import type Database from 'better-sqlite3'
import { isAbsolute } from 'node:path'
import { readTranscriptUsage } from './ledger-transcript.js'
import {
  MAX_TOKENS_PER_FIELD,
  parseUsageLine,
  scanUsageFile,
  usageDedupeKey,
  USAGE_JSONL_V1,
  type FileCursor,
} from './ledger-usage-jsonl.js'
import { asMicro, ceilDiv, MAX_USD_AMOUNT_MICRO, microFromBigInt } from './money.js'
import { estimate } from './pricing.js'
import type { Micro, PricingTable } from './types.js'

/** A half-written last line older than this breaks the source (blueprint N1b). */
export const PARTIAL_LINE_MAX_MS = 120_000
/** The writer (usage_log.py) never lets usage.jsonl grow past 64 MiB. */
export const MAX_USAGE_FILE_BYTES = 64 * 1024 * 1024
/** ledgerSum and ingestedForBatch report at most this (100 000 USD). */
export const L_SATURATION_MICRO = MAX_USD_AMOUNT_MICRO
/** The source name of headless-run rows; no configured source may use it. */
export const HEADLESS_SOURCE = 'headless'

export interface LedgerSource {
  readonly id: string
  /** Absolute path of the usage.jsonl file. */
  readonly path: string
  readonly format: typeof USAGE_JSONL_V1
}

export interface LedgerOptions {
  readonly sources: readonly LedgerSource[]
  readonly partialMaxMs?: number
  readonly maxFileBytes?: number
}

export type CursorStatus = 'ok' | 'partial' | 'broken'
export type LedgerBasis = 'usage' | 'headless_json' | 'headless_transcript' | 'headless_reservation'

export interface SourceRefresh {
  readonly id: string
  readonly status: CursorStatus
  /** Why the source is broken; null otherwise. */
  readonly reason: string | null
  readonly ingested: number
  /** Lines this refresh already had (same dedupe key or same batch request). */
  readonly duplicates: number
}

export interface RefreshResult {
  readonly sources: readonly SourceRefresh[]
  readonly ingested: number
  /** Earlier unpriced usage rows that this refresh could price. */
  readonly repriced: number
  /** Models of the rows ingested by THIS refresh without a price (A-02). The
   *  gate's own A-02 test is ledgerSum(lb).unpriced. */
  readonly unpriced_models: readonly string[]
  /** Ids of the sources that are broken after this refresh (HOLD). */
  readonly broken: readonly string[]
}

export interface LedgerSum {
  /** L(t): per row max(est, cli); a row with neither counts 0 and is unpriced. */
  readonly l_micro: Micro
  readonly rows: number
  /** Rows without an estimate (A-02 while > 0). */
  readonly unpriced: number
  readonly unpriced_models: readonly string[]
  /** The true sum is above 100 000 USD (or beyond the safe range); l_micro
   *  is then exactly 100 000 USD. Never thrown, only reported. */
  readonly saturated: boolean
}

export interface BatchIngested {
  readonly l_micro: Micro
  /** Requests of the batch in the ledger (one per custom_id). */
  readonly count: number
  readonly unpriced: number
  /** As in LedgerSum. */
  readonly saturated: boolean
}

/** The token counts of one model in a headless run's JSON result. */
export interface HeadlessModelUsage {
  readonly model: string
  readonly input_tokens: number
  readonly output_tokens: number
  readonly cache_write_tokens: number
  readonly cache_read_tokens: number
}

export interface HeadlessRun {
  readonly run_id: string
  /** When the run ended, epoch seconds: the row's `ts` (a run that straddles
   *  the calibration's lower bound counts in full -- the safe direction). */
  readonly ended_at_s: number
  /** The run's model (from the allowlist). */
  readonly model: string
  /** The run's reservation (budget x factor); booked in full when neither the
   *  JSON result nor a transcript tells the cost (B-04). */
  readonly reservation_micro: Micro
  /** The CLI's JSON result, reduced to cost and usage; null = missing. */
  readonly result: {
    readonly total_cost_usd: number | null
    readonly usage: readonly HeadlessModelUsage[]
  } | null
  /** The run's `<run>/config/projects` directory; null = none. */
  readonly transcript_dir: string | null
}

export interface HeadlessRecordResult {
  /** false: the run was already booked; the values are the stored ones. */
  readonly inserted: boolean
  readonly basis: LedgerBasis
  readonly est_micro: Micro | null
  readonly cli_micro: Micro | null
}

interface CursorRow {
  source: string
  dev: string | null
  ino: string | null
  offset: number
  tail_sha256: string | null
  status: CursorStatus
  reason: string | null
  partial_since: number | null
  checked_at: number | null
  updated_at: number
}

interface PriceableUsage {
  readonly model: string
  readonly input_tokens: number
  readonly output_tokens: number
  readonly cache_write_tokens: number
  readonly cache_read_tokens: number
  readonly batch_id?: string | null
}

const SOURCE_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/
const RUN_ID_RE = /^[A-Za-z0-9_-]{1,128}$/
const MODEL_RE = /^[A-Za-z0-9_.-]{1,128}$/

// L(t)'s per-row term. SQLite's two-argument max() is NULL when either side
// is NULL, so the cases are spelled out: est only, cli only, the larger one.
const ROW_COST_SQL = `CASE
  WHEN est_micro IS NULL THEN COALESCE(cli_micro, 0)
  WHEN cli_micro IS NULL OR est_micro >= cli_micro THEN est_micro
  ELSE cli_micro END`

function pricingTag(table: PricingTable): string {
  return `${table.schema}@${table.verified_at}`
}

function isCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
}

/** One token field of one request: 0 <= n < 10^9, as in usage.jsonl. */
function isTokenCount(v: unknown): v is number {
  return isCount(v) && v < MAX_TOKENS_PER_FIELD
}

/**
 * The CLI's total_cost_usd (a JSON number) as micro-USD, rounded UP; null when
 * it is not a finite, non-negative number of at most 100 000 USD. Exact: the
 * number's shortest decimal form is converted with integer arithmetic.
 */
export function usdNumberToMicroCeil(v: unknown): Micro | null {
  if (typeof v !== 'number' || !Number.isFinite(v) || v < 0) return null
  const m = /^([0-9]+)(?:\.([0-9]+))?(?:e([+-][0-9]+))?$/.exec(String(v))
  if (!m) return null
  const frac = m[2] ?? ''
  const digits = BigInt(m[1] + frac)
  // v x 10^6 = digits x 10^exp
  const exp = Number(m[3] ?? '0') - frac.length + 6
  const micro = exp >= 0 ? digits * 10n ** BigInt(exp) : ceilDiv(digits, 10n ** BigInt(-exp))
  if (micro > BigInt(MAX_USD_AMOUNT_MICRO)) return null
  return microFromBigInt(micro)
}

/**
 * The summed estimate of several requests (est null when any of them has no
 * price); null when the sum leaves the safe-integer range -- the caller then
 * treats the source as unusable, it never throws.
 */
function priceAll(items: readonly PriceableUsage[], table: PricingTable | null): { est: Micro | null; unpriced: string[] } | null {
  const unpriced = new Set<string>()
  let total = 0n
  for (const u of items) {
    if (u.input_tokens + u.output_tokens + u.cache_write_tokens + u.cache_read_tokens === 0) continue
    const e = table ? estimate(u, { table }) : null
    if (e === null) unpriced.add(u.model)
    else total += BigInt(e)
  }
  if (unpriced.size > 0) return { est: null, unpriced: [...unpriced].sort() }
  const est = microFromBigInt(total)
  return est === null ? null : { est, unpriced: [] }
}

/**
 * The JSON result when it tells something about the cost, else null (=
 * missing). It tells something when it carries a valid total_cost_usd (0
 * included: the CLI says nothing was spent) or at least one usage entry with
 * a non-zero token count. `{total_cost_usd: null, usage: []}` or all-zero
 * usage would otherwise book a killed run at 0 USD; as "missing" it goes to
 * the transcript and then to the full reservation (B-04).
 */
function validResult(r: HeadlessRun['result']): NonNullable<HeadlessRun['result']> | null {
  if (r === null || typeof r !== 'object' || !Array.isArray(r.usage)) return null
  let anyTokens = false
  for (const u of r.usage) {
    if (typeof u !== 'object' || u === null) return null
    if (typeof u.model !== 'string' || !MODEL_RE.test(u.model)) return null
    if (!isTokenCount(u.input_tokens) || !isTokenCount(u.output_tokens)
      || !isTokenCount(u.cache_write_tokens) || !isTokenCount(u.cache_read_tokens)) {
      return null
    }
    if (u.input_tokens + u.output_tokens + u.cache_write_tokens + u.cache_read_tokens > 0) anyTokens = true
  }
  if (!anyTokens && usdNumberToMicroCeil(r.total_cost_usd) === null) return null
  return r
}

/** Per-category token totals; null when one leaves the safe-integer range. */
function sumTokens(items: readonly PriceableUsage[]): [number, number, number, number] | null {
  let i = 0
  let o = 0
  let w = 0
  let c = 0
  for (const u of items) {
    i += u.input_tokens
    o += u.output_tokens
    w += u.cache_write_tokens
    c += u.cache_read_tokens
  }
  return [i, o, w, c].every((n) => Number.isSafeInteger(n)) ? [i, o, w, c] : null
}

export class CreditLedger {
  private readonly sources: readonly LedgerSource[]
  private readonly partialMaxMs: number
  private readonly maxFileBytes: number
  private readonly st: ReturnType<CreditLedger['prepare']>

  constructor(private readonly db: Database.Database, opts: LedgerOptions) {
    const ids = new Set<string>()
    for (const s of opts.sources) {
      if (typeof s.id !== 'string' || !SOURCE_ID_RE.test(s.id) || s.id === HEADLESS_SOURCE) {
        throw new Error(`ledger source id ${JSON.stringify(s.id)} is not allowed`)
      }
      if (ids.has(s.id)) throw new Error(`ledger source id ${JSON.stringify(s.id)} is duplicated`)
      ids.add(s.id)
      if (typeof s.path !== 'string' || !isAbsolute(s.path)) throw new Error(`ledger source ${s.id}: path must be absolute`)
      if (s.format !== USAGE_JSONL_V1) throw new Error(`ledger source ${s.id}: unsupported format ${JSON.stringify(s.format)}`)
    }
    this.sources = Object.freeze(opts.sources.map((s) => Object.freeze({ ...s })))
    this.partialMaxMs = opts.partialMaxMs ?? PARTIAL_LINE_MAX_MS
    this.maxFileBytes = opts.maxFileBytes ?? MAX_USAGE_FILE_BYTES
    if (!Number.isSafeInteger(this.partialMaxMs) || this.partialMaxMs <= 0) throw new Error('partialMaxMs must be a positive integer')
    if (!Number.isSafeInteger(this.maxFileBytes) || this.maxFileBytes <= 0) throw new Error('maxFileBytes must be a positive integer')
    this.st = this.prepare()
  }

  private prepare() {
    const db = this.db
    return {
      cursor: db.prepare('SELECT * FROM credit_ledger_cursors WHERE source = ?'),
      upsertCursor: db.prepare(`INSERT INTO credit_ledger_cursors
          (source, dev, ino, offset, tail_sha256, status, reason, partial_since, checked_at, updated_at)
        VALUES (@source, @dev, @ino, @offset, @tail_sha256, @status, @reason, @partial_since, @checked_at, @updated_at)
        ON CONFLICT(source) DO UPDATE SET dev = excluded.dev, ino = excluded.ino, offset = excluded.offset,
          tail_sha256 = excluded.tail_sha256, status = excluded.status, reason = excluded.reason,
          partial_since = excluded.partial_since, checked_at = excluded.checked_at, updated_at = excluded.updated_at`),
      deleteCursor: db.prepare('DELETE FROM credit_ledger_cursors WHERE source = ?'),
      batchRequest: db.prepare(`SELECT model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens
        FROM credit_ledger_entries WHERE batch_id = ? AND custom_id = ?`),
      insert: db.prepare(`INSERT INTO credit_ledger_entries
          (source, dedupe_key, ts, model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens,
           batch_id, custom_id, run_id, est_micro, cli_micro, priced_with, basis, ingested_at)
        VALUES (@source, @dedupe_key, @ts, @model, @input_tokens, @output_tokens, @cache_write_tokens, @cache_read_tokens,
           @batch_id, @custom_id, @run_id, @est_micro, @cli_micro, @priced_with, @basis, @ingested_at)
        ON CONFLICT(dedupe_key) DO NOTHING`),
      byDedupeKey: db.prepare('SELECT basis, est_micro, cli_micro FROM credit_ledger_entries WHERE dedupe_key = ?'),
      unpricedUsage: db.prepare(`SELECT id, model, input_tokens, output_tokens, cache_write_tokens, cache_read_tokens, batch_id
        FROM credit_ledger_entries WHERE est_micro IS NULL AND basis = 'usage'`),
      setPrice: db.prepare('UPDATE credit_ledger_entries SET est_micro = ?, priced_with = ? WHERE id = ? AND est_micro IS NULL'),
      // TOTAL() is a float and never overflows; the exact integer SUM() runs
      // only when TOTAL says the sum is in range (see sumOf).
      totalSince: db.prepare(`SELECT COUNT(*) AS rows, TOTAL(${ROW_COST_SQL}) AS total,
          COALESCE(SUM(CASE WHEN est_micro IS NULL THEN 1 ELSE 0 END), 0) AS unpriced
        FROM credit_ledger_entries WHERE ts >= ?`),
      sumSince: db.prepare(`SELECT COALESCE(SUM(${ROW_COST_SQL}), 0) AS l FROM credit_ledger_entries WHERE ts >= ?`),
      unpricedModelsSince: db.prepare(`SELECT DISTINCT model FROM credit_ledger_entries
        WHERE ts >= ? AND est_micro IS NULL ORDER BY model`),
      totalBatch: db.prepare(`SELECT COUNT(*) AS rows, TOTAL(${ROW_COST_SQL}) AS total,
          COALESCE(SUM(CASE WHEN est_micro IS NULL THEN 1 ELSE 0 END), 0) AS unpriced
        FROM credit_ledger_entries WHERE batch_id = ?`),
      sumBatch: db.prepare(`SELECT COALESCE(SUM(${ROW_COST_SQL}), 0) AS l FROM credit_ledger_entries WHERE batch_id = ?`),
    }
  }

  /**
   * A cost sum that cannot throw: above 100 000 USD it is reported as exactly
   * 100 000 USD with `saturated` (the gate then simply sees no credit left).
   */
  private sumOf(
    total: Database.Statement,
    exact: Database.Statement,
    arg: number | string,
  ): { l_micro: Micro; rows: number; unpriced: number; saturated: boolean } {
    const t = total.get(arg) as { rows: number; total: number; unpriced: number }
    let l = L_SATURATION_MICRO
    let saturated = true
    if (t.total <= L_SATURATION_MICRO) {
      const e = (exact.get(arg) as { l: number }).l
      // TOTAL rounds; the exact sum may sit a hair above the cap.
      if (Number.isSafeInteger(e) && e <= L_SATURATION_MICRO) {
        l = e
        saturated = false
      }
    }
    return { l_micro: asMicro(l), rows: t.rows, unpriced: t.unpriced, saturated }
  }

  private getCursor(source: string): CursorRow | undefined {
    return this.st.cursor.get(source) as CursorRow | undefined
  }

  /** Read every source from its cursor, and price earlier unpriced rows. */
  refresh(nowMs: number, table: PricingTable | null): RefreshResult {
    if (!Number.isSafeInteger(nowMs)) throw new RangeError('refresh: now must be epoch milliseconds')
    const repriced = table ? this.reprice(table) : 0
    const unpriced = new Set<string>()
    const sources = this.sources.map((s) => this.refreshSource(s, nowMs, table, unpriced))
    return {
      sources,
      ingested: sources.reduce((n, s) => n + s.ingested, 0),
      repriced,
      unpriced_models: [...unpriced].sort(),
      broken: sources.filter((s) => s.status === 'broken').map((s) => s.id),
    }
  }

  private reprice(table: PricingTable): number {
    const rows = this.st.unpricedUsage.all() as Array<PriceableUsage & { id: number }>
    if (rows.length === 0) return 0
    let n = 0
    this.db.transaction(() => {
      for (const r of rows) {
        const est = estimate(r, { table })
        if (est !== null) n += this.st.setPrice.run(est, pricingTag(table), r.id).changes
      }
    })()
    return n
  }

  private markBroken(source: string, cur: CursorRow | undefined, reason: string, nowMs: number): SourceRefresh {
    this.st.upsertCursor.run({
      source,
      dev: cur?.dev ?? null,
      ino: cur?.ino ?? null,
      offset: cur?.offset ?? 0,
      tail_sha256: cur?.tail_sha256 ?? null,
      status: 'broken',
      reason,
      partial_since: null,
      // The last complete read stays where it was: the age keeps growing.
      checked_at: cur?.checked_at ?? null,
      updated_at: nowMs,
    })
    return { id: source, status: 'broken', reason, ingested: 0, duplicates: 0 }
  }

  private refreshSource(src: LedgerSource, nowMs: number, table: PricingTable | null, unpriced: Set<string>): SourceRefresh {
    const cur = this.getCursor(src.id)
    // Broken is sticky: nothing is read until the source is reset.
    if (cur?.status === 'broken') return { id: src.id, status: 'broken', reason: cur.reason, ingested: 0, duplicates: 0 }

    const from: FileCursor | null = cur && cur.dev !== null && cur.ino !== null
      ? { dev: cur.dev, ino: cur.ino, offset: cur.offset, tail_sha256: cur.tail_sha256 }
      : null
    const scan = scanUsageFile(src.path, from, this.maxFileBytes)
    if (!scan.ok) return this.markBroken(src.id, cur, scan.reason, nowMs)

    return this.db.transaction((): SourceRefresh => {
      let offset = from?.offset ?? 0
      let ingested = 0
      let duplicates = 0
      let broken: string | null = null

      for (const line of scan.lines) {
        if (line.text === null) {
          broken = 'invalid_utf8'
          break
        }
        const parsed = parseUsageLine(line.text)
        if (!parsed.ok) {
          broken = parsed.reason
          break
        }
        const row = parsed.row
        if (row.batch_id !== null) {
          // One batch request is one (batch_id, custom_id), wherever it shows
          // up. The same request with other counts is a damaged log.
          const prev = this.st.batchRequest.get(row.batch_id, row.custom_id) as PriceableUsage | undefined
          if (prev) {
            const same = prev.model === row.model
              && prev.input_tokens === row.input_tokens
              && prev.output_tokens === row.output_tokens
              && prev.cache_write_tokens === row.cache_write_tokens
              && prev.cache_read_tokens === row.cache_read_tokens
            if (!same) {
              broken = 'batch_conflict'
              break
            }
            duplicates++
            offset = line.end
            continue
          }
        }
        const est = table ? estimate(row, { table }) : null
        const info = this.st.insert.run({
          source: src.id,
          dedupe_key: usageDedupeKey({ source: src.id, dev: scan.dev, ino: scan.ino, offset: line.offset, lineSha256: line.sha256 }),
          ts: row.ts,
          model: row.model,
          input_tokens: row.input_tokens,
          output_tokens: row.output_tokens,
          cache_write_tokens: row.cache_write_tokens,
          cache_read_tokens: row.cache_read_tokens,
          batch_id: row.batch_id,
          custom_id: row.custom_id,
          run_id: null,
          est_micro: est,
          cli_micro: row.cli_micro,
          priced_with: est === null ? null : pricingTag(table as PricingTable),
          basis: 'usage',
          ingested_at: nowMs,
        })
        if (info.changes === 1) {
          ingested++
          if (est === null) unpriced.add(row.model)
        } else {
          duplicates++
        }
        offset = line.end
      }

      const cursorBase = {
        source: src.id,
        dev: scan.dev,
        ino: scan.ino,
        offset,
        tail_sha256: scan.tailShaAt(offset),
        updated_at: nowMs,
      }
      if (broken !== null) {
        this.st.upsertCursor.run({ ...cursorBase, status: 'broken', reason: broken, partial_since: null, checked_at: cur?.checked_at ?? null })
        return { id: src.id, status: 'broken', reason: broken, ingested, duplicates }
      }

      // Bytes after the last newline: a line still being written. Its clock
      // starts when it is first seen at this cursor position.
      const partial = scan.partialBytes > 0
      let since: number | null = null
      if (partial) {
        since = cur?.status === 'partial' && cur.offset === offset && cur.partial_since !== null ? cur.partial_since : nowMs
        if (nowMs - since > this.partialMaxMs) {
          this.st.upsertCursor.run({ ...cursorBase, status: 'broken', reason: 'partial_timeout', partial_since: since, checked_at: cur?.checked_at ?? null })
          return { id: src.id, status: 'broken', reason: 'partial_timeout', ingested, duplicates }
        }
      }
      const status: CursorStatus = partial ? 'partial' : 'ok'
      this.st.upsertCursor.run({ ...cursorBase, status, reason: null, partial_since: since, checked_at: nowMs })
      return { id: src.id, status, reason: null, ingested, duplicates }
    })()
  }

  /**
   * Forget a source's cursor so the next refresh reads the file from its first
   * byte (the dedupe key keeps already-booked lines out). For the calibration
   * step that clears a HOLD; false when there was no cursor.
   */
  resetSource(id: string): boolean {
    if (!this.sources.some((s) => s.id === id)) return false
    return this.st.deleteCursor.run(id).changes > 0
  }

  /**
   * L(t) since the calibration's lower bound (epoch ms). The writers stamp
   * whole seconds (int(time.time()) truncates), so a row stamped in the
   * bound's own second may be later than the bound and counts: the overlap
   * overcounts, the safe direction (blueprint 3.4).
   */
  ledgerSum(sinceLbMs: number): LedgerSum {
    if (!Number.isFinite(sinceLbMs)) throw new RangeError('ledgerSum: the lower bound must be epoch milliseconds')
    const lbS = Math.floor(sinceLbMs / 1000)
    const r = this.sumOf(this.st.totalSince, this.st.sumSince, lbS)
    const models = (this.st.unpricedModelsSince.all(lbS) as Array<{ model: string }>).map((m) => m.model)
    return { l_micro: r.l_micro, rows: r.rows, unpriced: r.unpriced, unpriced_models: models, saturated: r.saturated }
  }

  /**
   * Seconds since the OLDEST configured source was last read to its end; null
   * when a source has never been read completely (no sources: null as well).
   * A broken source is not read, so its age keeps growing (A-02 at 120 s).
   */
  ageS(nowMs: number): number | null {
    if (this.sources.length === 0) return null
    let oldest = Number.POSITIVE_INFINITY
    for (const s of this.sources) {
      const c = this.getCursor(s.id)
      if (!c || c.checked_at === null) return null
      oldest = Math.min(oldest, c.checked_at)
    }
    return Math.max(0, nowMs - oldest) / 1000
  }

  /** What the ledger holds for one batch: for the batch reservation's open part. */
  ingestedForBatch(batchId: string): BatchIngested {
    const r = this.sumOf(this.st.totalBatch, this.st.sumBatch, batchId)
    return { l_micro: r.l_micro, count: r.rows, unpriced: r.unpriced, saturated: r.saturated }
  }

  /** Book one headless run, once (the first record of a run_id wins). */
  recordHeadless(run: HeadlessRun, table: PricingTable | null, nowMs: number): HeadlessRecordResult {
    if (typeof run.run_id !== 'string' || !RUN_ID_RE.test(run.run_id)) throw new Error('recordHeadless: invalid run_id')
    if (!Number.isSafeInteger(run.ended_at_s) || run.ended_at_s <= 0) throw new Error('recordHeadless: invalid ended_at_s')
    if (typeof run.model !== 'string' || !MODEL_RE.test(run.model)) throw new Error('recordHeadless: invalid model')
    if (!isCount(run.reservation_micro)) throw new Error('recordHeadless: invalid reservation_micro')
    if (run.transcript_dir !== null && (typeof run.transcript_dir !== 'string' || !isAbsolute(run.transcript_dir))) {
      throw new Error('recordHeadless: transcript_dir must be an absolute path or null')
    }
    if (!Number.isSafeInteger(nowMs)) throw new RangeError('recordHeadless: now must be epoch milliseconds')

    interface Booking {
      basis: LedgerBasis
      est: Micro | null
      cli: Micro | null
      model: string
      tokens: [number, number, number, number]
    }
    // Usage that cannot be summed inside the safe range is not a usable
    // source: null, and the next fallback takes over.
    const fromUsage = (basis: LedgerBasis, items: readonly PriceableUsage[], cli: Micro | null): Booking | null => {
      const p = priceAll(items, table)
      const tokens = sumTokens(items)
      if (p === null || tokens === null) return null
      // For an unpriced run the model column names the model(s) without a
      // price, so the A-02 reason points at the culprit.
      return { basis, est: p.est, cli, model: p.est === null ? p.unpriced.join(',') : run.model, tokens }
    }

    // The order of B-04: the JSON result; without a usable one the
    // transcript; without a usable transcript (missing, damaged, or without
    // a single response) the cost is unknown and the whole reservation is
    // spent. A result that does not validate counts as missing: the
    // fallbacks only ever book more, never less.
    let booking: Booking | null = null
    const result = validResult(run.result)
    if (result !== null) booking = fromUsage('headless_json', result.usage, usdNumberToMicroCeil(result.total_cost_usd))
    if (booking === null && run.transcript_dir !== null) {
      const transcript = readTranscriptUsage(run.transcript_dir)
      if (transcript.ok && transcript.messages.length > 0) booking = fromUsage('headless_transcript', transcript.messages, null)
    }
    booking ??= { basis: 'headless_reservation', est: asMicro(run.reservation_micro), cli: null, model: run.model, tokens: [0, 0, 0, 0] }
    const { basis, est, cli, model, tokens } = booking

    const dedupeKey = `${HEADLESS_SOURCE}:${run.run_id}`
    const info = this.st.insert.run({
      source: HEADLESS_SOURCE,
      dedupe_key: dedupeKey,
      ts: run.ended_at_s,
      model,
      input_tokens: tokens[0],
      output_tokens: tokens[1],
      cache_write_tokens: tokens[2],
      cache_read_tokens: tokens[3],
      batch_id: null,
      custom_id: null,
      run_id: run.run_id,
      est_micro: est,
      cli_micro: cli,
      priced_with: basis !== 'headless_reservation' && est !== null && table ? pricingTag(table) : null,
      basis,
      ingested_at: nowMs,
    })
    if (info.changes === 1) return { inserted: true, basis, est_micro: est, cli_micro: cli }
    const prev = this.st.byDedupeKey.get(dedupeKey) as { basis: LedgerBasis; est_micro: number | null; cli_micro: number | null }
    return {
      inserted: false,
      basis: prev.basis,
      est_micro: prev.est_micro === null ? null : asMicro(prev.est_micro),
      cli_micro: prev.cli_micro === null ? null : asMicro(prev.cli_micro),
    }
  }
}
