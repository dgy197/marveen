// The credit gate's price table (`credit-pricing/v1`, blueprint 3.2) and the
// per-request cost estimate (spec 6.1, B-03; card fec6335f, node N1a).
//
// The estimate is an OVERESTIMATE by construction:
//  - every cache write is priced at the 1-hour price, whatever its TTL;
//  - a long-context band applies when the prompt is above its threshold;
//  - the batch discount applies only to a row with a batch_id, only when the
//    table carries a (verified) batch_discount_pct, and only to input and
//    output tokens -- cache tokens keep the full price;
//  - the exact total is rounded UP to a whole micro-USD.
// An unknown model or an unusable token count gives null, never a guess: the
// caller treats null as "no price" (A-02), which closes the gate.
//
// Measured N0 facts that overrule the blueprint text (n0-kulso-tenyek.md, 1.6
// and 1.7, 2026-10-16): Opus 5.5 and Sonnet 5.5 have no long-context surcharge
// (long_context: null); Haiku 5.5 switches band when the prompt -- input +
// cache write + cache read tokens -- is STRICTLY above 100 000, and the upper
// band then prices ALL tokens of the request, output included. Unit prices
// may have up to six decimals (parseRate), not exactly two.
//
// The loader is fail-closed: an unknown key, a missing field, a duplicated key
// (JSON.parse would silently keep the last one), a malformed price, or a table
// whose own numbers contradict the overestimation rules (a zero price of any
// kind, a 1-hour cache write cheaper than the 5-minute one, a long-context
// price below the base price), a batch discount other than the 50% the N0
// sources state, or a long-context threshold above 10 000 000 tokens rejects
// the whole table (BE-2 review, 2026-10-16).

import { findDuplicateJsonKeys } from '../json-dup-keys.js'
import { ceilDiv, microFromBigInt, parseRate } from './money.js'
import type {
  LongContextBand,
  Micro,
  ModelPricing,
  PriceBand,
  PricingLoadResult,
  PricingSource,
  PricingTable,
  PromptTokenCategory,
  UsageForPricing,
} from './types.js'

export const PRICING_SCHEMA = 'credit-pricing/v1'
const DAY_MS = 24 * 60 * 60 * 1000
/** The only batch discount the N0 sources state (n0-kulso-tenyek.md 1.7). */
export const N0_BATCH_DISCOUNT_PCT = 50
/** A long-context threshold above this is not a real price band. */
export const MAX_LONG_CONTEXT_THRESHOLD = 10_000_000
/** A table verified more than this long ago is stale (A-02). Exactly 30 days is still fresh. */
export const STALE_AFTER_MS = 30 * DAY_MS
/** How far ahead of now a verified_at may lie: a date-only value means 00:00Z,
 *  and a local calendar day can begin up to ~14 h before that UTC midnight. */
export const VERIFIED_AT_MAX_AHEAD_MS = DAY_MS

const PRICE_KEYS = ['input', 'output', 'cache_write_5m', 'cache_write_1h', 'cache_read'] as const
const PROMPT_CATEGORIES: readonly PromptTokenCategory[] = ['input', 'cache_write', 'cache_read']
const TOP_KEYS = ['schema', 'verified_at', 'sources', 'batch_discount_pct', 'models'] as const
const MODEL_KEYS = ['ids', ...PRICE_KEYS, 'long_context'] as const
const LONG_CONTEXT_KEYS = ['threshold_input_tokens', ...PRICE_KEYS] as const
const SOURCE_KEYS = ['url', 'retrieved_at'] as const

// A table id: lowercase model-id characters, at most 128 (the batch writer's
// own limit for the usage `model` field).
const MODEL_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/
// The only tolerated variant of a table id: the id + "-YYYYMMDD".
const DATED_ID_RE = /^(.+)-([0-9]{4})([0-9]{2})([0-9]{2})$/
const DATE_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/
const STAMP_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/

class PricingInvalid extends Error {}

function fail(detail: string): never {
  throw new PricingInvalid(detail)
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function at(path: string, key: string): string {
  return path ? `${path}.${key}` : key
}

function checkKeys(
  o: Record<string, unknown>,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) fail(`${path || 'top level'}: unknown key ${JSON.stringify(k)}`)
  }
  for (const k of required) {
    if (!Object.hasOwn(o, k)) fail(`${at(path, k)}: missing`)
  }
}

/** Epoch ms of a valid calendar day (00:00Z), or null. */
function utcDay(y: number, mo: number, d: number): number | null {
  const ms = Date.UTC(y, mo - 1, d)
  const dt = new Date(ms)
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d ? ms : null
}

/** "YYYY-MM-DD" (00:00Z) or "YYYY-MM-DDTHH:MM:SSZ" as epoch ms, or null. */
function parseUtcTime(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const d = DATE_RE.exec(s)
  if (d) return utcDay(Number(d[1]), Number(d[2]), Number(d[3]))
  const t = STAMP_RE.exec(s)
  if (!t) return null
  const day = utcDay(Number(t[1]), Number(t[2]), Number(t[3]))
  const [h, mi, se] = [Number(t[4]), Number(t[5]), Number(t[6])]
  if (day === null || h > 23 || mi > 59 || se > 59) return null
  return day + ((h * 60 + mi) * 60 + se) * 1000
}

function readBand(o: Record<string, unknown>, path: string): PriceBand {
  const band: Record<string, number> = {}
  for (const k of PRICE_KEYS) {
    const r = parseRate(o[k])
    if (r === null) fail(`${at(path, k)}: not a USD/MTok price string (up to 6 decimals, 0..1000)`)
    // A zero price would book real tokens at 0 USD.
    if (r === 0) fail(`${at(path, k)}: must be above 0`)
    band[k] = r
  }
  const b = band as unknown as PriceBand
  // Every cache write is priced at the 1-hour price; that is an overestimate
  // only while the 1-hour price is the higher one.
  if (b.cache_write_1h < b.cache_write_5m) fail(`${path}: cache_write_1h is below cache_write_5m`)
  return Object.freeze(b)
}

function readLongContext(v: unknown, path: string, base: PriceBand): LongContextBand | null {
  if (v === null) return null
  if (!isPlainObject(v)) fail(`${path}: must be null or an object`)
  checkKeys(v, path, LONG_CONTEXT_KEYS, ['counts'])
  const threshold = v.threshold_input_tokens
  if (typeof threshold !== 'number' || !Number.isSafeInteger(threshold) || threshold <= 0 || threshold > MAX_LONG_CONTEXT_THRESHOLD) {
    fail(`${path}.threshold_input_tokens: must be an integer 1..${MAX_LONG_CONTEXT_THRESHOLD}`)
  }
  // The prompt length counts input, cache write AND cache read tokens (N0 1.6).
  // `counts` documents that rule in the data; a file that claims any other
  // rule is rejected rather than silently priced lower.
  let counts = PROMPT_CATEGORIES
  if (Object.hasOwn(v, 'counts')) {
    const c = v.counts
    const ok = Array.isArray(c)
      && c.length === PROMPT_CATEGORIES.length
      && new Set(c).size === c.length
      && c.every((x) => PROMPT_CATEGORIES.includes(x as PromptTokenCategory))
    if (!ok) fail(`${path}.counts: must name exactly input, cache_write and cache_read`)
    counts = c as PromptTokenCategory[]
  }
  const band = readBand(v, path)
  for (const k of PRICE_KEYS) {
    if (band[k] < base[k]) fail(`${path}: ${k} is below the base price`)
  }
  return Object.freeze({ ...band, threshold_input_tokens: threshold, counts: Object.freeze([...counts]) })
}

function readModels(v: unknown, byId: Map<string, ModelPricing>): ModelPricing[] {
  if (!Array.isArray(v) || v.length === 0) fail('models: must be a non-empty array')
  return v.map((m, i) => {
    const path = `models[${i}]`
    if (!isPlainObject(m)) fail(`${path}: must be an object`)
    checkKeys(m, path, MODEL_KEYS)
    const ids = m.ids
    if (!Array.isArray(ids) || ids.length === 0) fail(`${path}.ids: must be a non-empty array`)
    for (const id of ids) {
      if (typeof id !== 'string' || !MODEL_ID_RE.test(id)) fail(`${path}.ids: invalid model id ${JSON.stringify(id)}`)
    }
    const base = readBand(m, path)
    const entry: ModelPricing = Object.freeze({
      ids: Object.freeze([...(ids as string[])]),
      base,
      long_context: readLongContext(m.long_context, `${path}.long_context`, base),
    })
    for (const id of entry.ids) {
      if (byId.has(id)) fail(`${path}.ids: duplicate model id ${JSON.stringify(id)}`)
      byId.set(id, entry)
    }
    return entry
  })
}

function readSources(v: unknown): PricingSource[] {
  if (!Array.isArray(v) || v.length === 0) fail('sources: must be a non-empty array')
  return v.map((s, i) => {
    const path = `sources[${i}]`
    if (!isPlainObject(s)) fail(`${path}: must be an object`)
    checkKeys(s, path, SOURCE_KEYS)
    if (typeof s.url !== 'string' || !/^https:\/\/\S+$/.test(s.url)) fail(`${path}.url: must be an https URL`)
    if (parseUtcTime(s.retrieved_at) === null) fail(`${path}.retrieved_at: must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ`)
    return Object.freeze({ url: s.url, retrieved_at: s.retrieved_at as string })
  })
}

function readBatchDiscount(v: unknown): number | null {
  if (v === null) return null
  if (v !== N0_BATCH_DISCOUNT_PCT) fail(`batch_discount_pct: must be null or ${N0_BATCH_DISCOUNT_PCT} (the N0-verified discount)`)
  return v
}

/** True when the table was verified more than 30 days before `now` (A-02). */
export function isPricingStale(table: Pick<PricingTable, 'verified_at_ms'>, now: Date | number): boolean {
  const nowMs = typeof now === 'number' ? now : now.getTime()
  // A non-finite now cannot prove freshness.
  if (!Number.isFinite(nowMs)) return true
  return nowMs - table.verified_at_ms > STALE_AFTER_MS
}

/**
 * Parse and validate a `credit-pricing/v1` file. Fail-closed: any doubt is a
 * rejection with a reason (`stale` when verified_at is older than 30 days).
 */
export function loadPricing(text: string, now: Date | number): PricingLoadResult {
  const nowMs = typeof now === 'number' ? now : now instanceof Date ? now.getTime() : Number.NaN
  if (!Number.isFinite(nowMs)) return { ok: false, reason: 'invalid', detail: 'now: not a valid time' }

  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    return { ok: false, reason: 'invalid_json', detail: 'not valid JSON' }
  }
  const dups = findDuplicateJsonKeys(text)
  if (dups.length > 0) return { ok: false, reason: 'duplicate_key', detail: `duplicated key: ${dups.join(', ')}` }
  if (!isPlainObject(doc)) return { ok: false, reason: 'invalid', detail: 'top level: must be an object' }
  if (doc.schema !== PRICING_SCHEMA) {
    return { ok: false, reason: 'schema', detail: `schema: expected ${PRICING_SCHEMA}` }
  }

  let table: PricingTable
  try {
    checkKeys(doc, '', TOP_KEYS)
    const verifiedMs = parseUtcTime(doc.verified_at)
    if (verifiedMs === null) fail('verified_at: must be YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ')
    if (verifiedMs > nowMs + VERIFIED_AT_MAX_AHEAD_MS) fail('verified_at: lies in the future')
    const byId = new Map<string, ModelPricing>()
    table = Object.freeze({
      schema: PRICING_SCHEMA,
      verified_at: doc.verified_at as string,
      verified_at_ms: verifiedMs,
      sources: Object.freeze(readSources(doc.sources)),
      batch_discount_pct: readBatchDiscount(doc.batch_discount_pct),
      models: Object.freeze(readModels(doc.models, byId)),
      byId,
    })
  } catch (err) {
    if (err instanceof PricingInvalid) return { ok: false, reason: 'invalid', detail: err.message }
    throw err
  }

  if (isPricingStale(table, nowMs)) {
    return { ok: false, reason: 'stale', detail: `verified_at ${table.verified_at} is older than 30 days` }
  }
  return { ok: true, table }
}

/**
 * The price entry for a model id: the exact id, or the exact id followed by
 * "-YYYYMMDD" (a real calendar date). No other prefix or suffix guessing.
 */
export function matchModel(table: PricingTable, id: unknown): ModelPricing | null {
  if (typeof id !== 'string') return null
  const exact = table.byId.get(id)
  if (exact) return exact
  const m = DATED_ID_RE.exec(id)
  if (!m || utcDay(Number(m[2]), Number(m[3]), Number(m[4])) === null) return null
  return table.byId.get(m[1]) ?? null
}

function tokenCount(v: unknown): bigint | null {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? BigInt(v) : null
}

/** 100 x 10^6: the batch percentage scale times the per-MTok scale. */
const SCALE = 100n * 1_000_000n

/**
 * Overestimated cost of ONE request in micro-USD, or null when it cannot be
 * priced (unknown model, unusable token count, or a cost outside the
 * safe-integer range).
 */
export function estimate(usage: UsageForPricing, opts: { table: PricingTable }): Micro | null {
  const { table } = opts
  if (!isPlainObject(usage)) return null
  const pricing = matchModel(table, usage.model)
  if (!pricing) return null

  const input = tokenCount(usage.input_tokens)
  const output = tokenCount(usage.output_tokens)
  const cacheWrite = tokenCount(usage.cache_write_tokens)
  const cacheRead = tokenCount(usage.cache_read_tokens)
  if (input === null || output === null || cacheWrite === null || cacheRead === null) return null

  let band: PriceBand = pricing.base
  const lc = pricing.long_context
  if (lc) {
    const byCategory: Record<PromptTokenCategory, bigint> = { input, cache_write: cacheWrite, cache_read: cacheRead }
    const prompt = lc.counts.reduce((sum, c) => sum + byCategory[c], 0n)
    if (prompt > BigInt(lc.threshold_input_tokens)) band = lc
  }

  const isBatchRow = typeof usage.batch_id === 'string' && usage.batch_id.length > 0
  const pct = isBatchRow && table.batch_discount_pct !== null ? table.batch_discount_pct : 0
  const keep = BigInt(100 - pct)

  // tokens x (micro-USD per MTok) x percent = the exact cost x 10^8 micro-USD.
  const scaled =
    input * BigInt(band.input) * keep
    + output * BigInt(band.output) * keep
    + cacheWrite * BigInt(band.cache_write_1h) * 100n
    + cacheRead * BigInt(band.cache_read) * 100n
  return microFromBigInt(ceilDiv(scaled, SCALE))
}
