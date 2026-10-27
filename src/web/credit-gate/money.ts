// Money for the credit gate: whole micro-USD (1 USD = 1 000 000), no floating
// point anywhere (card fec6335f, blueprint 1 and N1a).
//
// Decision -- a branded safe-integer `number`, not a `bigint`:
//  - better-sqlite3 hands INTEGER columns back as `number` unless every
//    statement opts into safeIntegers(). A bigint/number mix then compares
//    wrongly and silently (`1n === 1` is false), which is a worse failure than
//    an overflow check that throws.
//  - JSON.stringify throws on a bigint, and the status and route answers all
//    carry money.
//  - The range is small: the largest accepted amount is 100 000 USD = 10^11
//    micro-USD, about 90 000 times below Number.MAX_SAFE_INTEGER.
// BigInt is used only INSIDE a computation that multiplies or divides (where
// the intermediate product can leave the safe range), and every result is
// range-checked on the way out. What keeps floats out: the `Micro` brand (a
// plain number does not type-check as money), asMicro()'s runtime
// Number.isSafeInteger check, and helpers that re-check inputs and results.
//
// Two parsers on purpose: an AMOUNT (config threshold, budget, Console
// reading) is exactly two decimals -- parseUsd; a UNIT PRICE in the price table
// may carry more (Haiku 5.5's cache write is 0.125 USD/MTok, N0 1.3) --
// parseRate.

import type { Factor, Micro, RateMicroPerMTok } from './types.js'

export const MICRO_PER_USD = 1_000_000
/** parseUsd's upper bound: 100 000.00 USD. */
export const MAX_USD_AMOUNT_MICRO = 100_000 * MICRO_PER_USD
/** parseRate's upper bound: 1000 USD/MTok. */
export const MAX_RATE_MICRO_PER_MTOK = 1_000 * MICRO_PER_USD
/** parseFactor's bounds: a factor only ever inflates (overestimation), up to 100x. */
const FACTOR_SCALE = 1_000_000n
const MAX_FACTOR = 100n

const MAX_SAFE_BIG = BigInt(Number.MAX_SAFE_INTEGER)
const MIN_SAFE_BIG = BigInt(Number.MIN_SAFE_INTEGER)

// The patterns are anchored at both ends. In JavaScript `$` without the m flag
// matches only at the very end of the input, so a trailing "\n" fails too.
// [0-9], not \d: only ASCII digits, never a look-alike.
const USD_RE = /^(0|[1-9][0-9]{0,5})\.([0-9]{2})$/
const RATE_RE = /^(0|[1-9][0-9]{0,3})(?:\.([0-9]{1,6}))?$/
const FACTOR_RE = /^(0|[1-9][0-9]{0,2})(?:\.([0-9]{1,6}))?$/

/** A number as money; throws unless it is a safe integer. */
export function asMicro(n: number): Micro {
  if (!Number.isSafeInteger(n)) throw new RangeError(`not a whole micro-USD amount: ${String(n)}`)
  return n as Micro
}

/** A bigint as money, or null when it does not fit the safe-integer range. */
export function microFromBigInt(x: bigint): Micro | null {
  if (x > MAX_SAFE_BIG || x < MIN_SAFE_BIG) return null
  return Number(x) as Micro
}

/**
 * An amount: exactly two decimals, no sign, exponent, whitespace or leading
 * zero, 0.00..100000.00. Anything else -- including a non-string -- is null.
 */
export function parseUsd(s: unknown): Micro | null {
  if (typeof s !== 'string') return null
  const m = USD_RE.exec(s)
  if (!m) return null
  // Integer arithmetic only, far inside the safe range (< 10^12).
  const micro = Number(m[1]) * MICRO_PER_USD + Number(m[2]) * 10_000
  return micro <= MAX_USD_AMOUNT_MICRO ? (micro as Micro) : null
}

/**
 * A unit price in USD/MTok: up to six decimals (the micro-USD resolution), no
 * sign, exponent, whitespace or leading zero, 0..1000. Returned as micro-USD
 * per million tokens, so "0.125" is 125 000.
 */
export function parseRate(s: unknown): RateMicroPerMTok | null {
  if (typeof s !== 'string') return null
  const m = RATE_RE.exec(s)
  if (!m) return null
  const rate = Number(m[1]) * MICRO_PER_USD + Number((m[2] ?? '').padEnd(6, '0'))
  return rate <= MAX_RATE_MICRO_PER_MTOK ? (rate as RateMicroPerMTok) : null
}

/** A multiplier such as the reservation factor "1.5": up to six decimals, 1..100. */
export function parseFactor(s: unknown): Factor | null {
  if (typeof s !== 'string') return null
  const m = FACTOR_RE.exec(s)
  if (!m) return null
  const num = BigInt(m[1]) * FACTOR_SCALE + BigInt((m[2] ?? '').padEnd(6, '0'))
  if (num < FACTOR_SCALE || num > MAX_FACTOR * FACTOR_SCALE) return null
  return { num, den: FACTOR_SCALE }
}

/** ceil(a / b) for a >= 0, b > 0. */
export function ceilDiv(a: bigint, b: bigint): bigint {
  if (a < 0n || b <= 0n) throw new RangeError('ceilDiv needs a >= 0 and b > 0')
  return (a + b - 1n) / b
}

/** amount x factor, rounded UP to a whole micro-USD. The amount must be >= 0. */
export function applyFactorCeil(amount: Micro, factor: Factor): Micro {
  const a = asMicro(amount)
  if (a < 0) throw new RangeError('a factor applies to a non-negative amount only')
  if (factor.den <= 0n || factor.num < factor.den) throw new RangeError('not a factor >= 1')
  const out = microFromBigInt(ceilDiv(BigInt(a) * factor.num, factor.den))
  if (out === null) throw new RangeError('amount x factor leaves the safe-integer range')
  return out
}

export function addMicro(a: Micro, b: Micro): Micro {
  return asMicro(asMicro(a) + asMicro(b))
}

/** a - b; may be negative (R_est can go below zero). */
export function subMicro(a: Micro, b: Micro): Micro {
  return asMicro(asMicro(a) - asMicro(b))
}

export function sumMicro(xs: Iterable<Micro>): Micro {
  let total = asMicro(0)
  for (const x of xs) total = addMicro(total, x)
  return total
}
