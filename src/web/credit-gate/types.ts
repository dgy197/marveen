// Shared types of the credit gate's money and pricing layer (card fec6335f, N1a).
//
// Money is an INTEGER count of micro-USD (1 USD = 1 000 000) everywhere. The
// brands below exist so that a plain float can never be handed to a function
// that expects money: a value only becomes `Micro` through money.ts, which
// checks that it is a safe integer. See money.ts for why this is a branded
// `number` and not a `bigint`.

/** An amount of money in micro-USD. Always a safe integer. */
export type Micro = number & { readonly __unit: 'micro-usd' }

/**
 * A unit price in micro-USD per million tokens (= the USD/MTok price x 10^6).
 * Always a non-negative safe integer; the cost of n tokens is n x rate / 10^6.
 */
export type RateMicroPerMTok = number & { readonly __unit: 'micro-usd-per-mtok' }

/** An exact multiplier >= 1 (e.g. the reservation factor "1.5"), as num/den. */
export interface Factor {
  readonly num: bigint
  readonly den: bigint
}

/** One price band of a model: every token category has its own unit price. */
export interface PriceBand {
  readonly input: RateMicroPerMTok
  readonly output: RateMicroPerMTok
  /** Validated and kept for reference, but NEVER used: every cache write is
   *  priced at `cache_write_1h` (spec 6.1, overestimation). */
  readonly cache_write_5m: RateMicroPerMTok
  readonly cache_write_1h: RateMicroPerMTok
  readonly cache_read: RateMicroPerMTok
}

/** Token categories whose sum is the "prompt length" a price band keys on. */
export type PromptTokenCategory = 'input' | 'cache_write' | 'cache_read'

/**
 * A higher price band for long prompts. A request whose prompt length
 * (input + cache write + cache read tokens) is STRICTLY above the threshold
 * pays the band prices on ALL of its tokens, output included.
 */
export interface LongContextBand extends PriceBand {
  readonly threshold_input_tokens: number
  readonly counts: readonly PromptTokenCategory[]
}

export interface ModelPricing {
  readonly ids: readonly string[]
  readonly base: PriceBand
  readonly long_context: LongContextBand | null
}

export interface PricingSource {
  readonly url: string
  readonly retrieved_at: string
}

/** A loaded, validated `credit-pricing/v1` table. */
export interface PricingTable {
  readonly schema: 'credit-pricing/v1'
  /** The `verified_at` string exactly as written in the file. */
  readonly verified_at: string
  /** `verified_at` as epoch ms (a date-only value means 00:00:00Z). */
  readonly verified_at_ms: number
  readonly sources: readonly PricingSource[]
  /** Percent off input and output tokens of a batch row; null = no discount. */
  readonly batch_discount_pct: number | null
  readonly models: readonly ModelPricing[]
  /** Exact id -> entry; a Map, so ids like `__proto__` cannot collide with
   *  object internals. */
  readonly byId: ReadonlyMap<string, ModelPricing>
}

export type PricingRejectReason =
  | 'invalid_json'
  | 'duplicate_key'
  | 'schema'
  | 'invalid'
  | 'stale'

export type PricingLoadResult =
  | { readonly ok: true; readonly table: PricingTable }
  | { readonly ok: false; readonly reason: PricingRejectReason; readonly detail: string }

/**
 * The token counts of ONE request (one ledger row). `cache_write_tokens` is
 * every cache write regardless of its TTL. A row is a batch row exactly when
 * `batch_id` is a non-empty string.
 */
export interface UsageForPricing {
  readonly model: string
  readonly input_tokens: number
  readonly output_tokens: number
  readonly cache_write_tokens: number
  readonly cache_read_tokens: number
  readonly batch_id?: string | null
}
