import { describe, it, expect, beforeAll, afterAll, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  MICRO_PER_USD,
  addMicro,
  applyFactorCeil,
  asMicro,
  parseFactor,
  parseRate,
  parseUsd,
  subMicro,
  sumMicro,
} from '../web/credit-gate/money.js'
import { STALE_AFTER_MS, estimate, isPricingStale, loadPricing, matchModel } from '../web/credit-gate/pricing.js'
import type { Micro, PricingTable, UsageForPricing } from '../web/credit-gate/types.js'

// Credit gate, node N1a: money and pricing (card fec6335f).
//
// Written from the spec (6.1, B-03, A-02), the blueprint (3.2, N1a) and the
// measured N0 facts (n0-kulso-tenyek.md 1.1-1.8), NOT from the code. Three of
// the N0 facts overrule the blueprint text on purpose:
//  - Opus 5.5 and Sonnet 5.5 have NO long-context surcharge and no 200k
//    threshold. Haiku 5.5 has a band: a request whose prompt (input + cache
//    write + cache read tokens) is STRICTLY above 100 000 tokens pays the higher
//    prices on all of its tokens. So the boundary cases are 99 999 / 100 000
//    (lower band) and 100 001 (upper band), cache tokens included.
//  - Unit prices may carry three or more decimals (0.125, 0.625), so the price
//    table has its own parser (parseRate); parseUsd stays the exactly-two-
//    decimals AMOUNT parser of the blueprint.
//  - The batch discount is 50% on input and output; it applies only when the
//    table's batch_discount_pct is not null, and only to a row with a batch_id.
//    Cache tokens keep the full price on a batch row: that is the
//    overestimating reading of "50% input+output" (spec 6.1, B-03).
//
// Every expected amount below is computed by hand from the N0 USD/MTok prices:
// cost in micro-USD = tokens x price / 1 000 000 x 1 000 000 = tokens x price,
// rounded UP to a whole micro-USD once, on the exact total of the request.

// Verbatim copy of the N0 output docs/pricing.draft.json (sha256
// 9acf8f6007613060df36714cac304ff78f221fca95a89750a31f1bba29050420, 2026-10-16).
// A fixture, not the live file: the test never reads the project folder.
const DRAFT_TEXT = `{
  "schema": "credit-pricing/v1",
  "verified_at": "2026-10-16",
  "sources": [
    {"url": "https://platform.claude.com/docs/en/about-claude/pricing", "retrieved_at": "2026-10-16"},
    {"url": "https://platform.claude.com/docs/en/about-claude/models/overview", "retrieved_at": "2026-10-16"},
    {"url": "https://platform.claude.com/docs/en/build-with-claude/batch-processing", "retrieved_at": "2026-10-16"},
    {"url": "https://platform.claude.com/docs/en/about-claude/models/model-ids-and-versions", "retrieved_at": "2026-10-16"}
  ],
  "batch_discount_pct": 50,
  "models": [
    {
      "ids": ["claude-opus-5-5"],
      "input": "4.00",
      "output": "20.00",
      "cache_write_5m": "5.00",
      "cache_write_1h": "8.00",
      "cache_read": "0.20",
      "long_context": null
    },
    {
      "ids": ["claude-sonnet-5-5"],
      "input": "2.00",
      "output": "10.00",
      "cache_write_5m": "2.50",
      "cache_write_1h": "4.00",
      "cache_read": "0.10",
      "long_context": null
    },
    {
      "ids": ["claude-haiku-5-5"],
      "input": "0.10",
      "output": "0.50",
      "cache_write_5m": "0.125",
      "cache_write_1h": "0.20",
      "cache_read": "0.01",
      "long_context": {
        "threshold_input_tokens": 100000,
        "input": "0.50",
        "output": "2.50",
        "cache_write_5m": "0.625",
        "cache_write_1h": "1.00",
        "cache_read": "0.05"
      }
    }
  ]
}
`

const DAY_MS = 24 * 60 * 60 * 1000
const VERIFIED_MS = Date.UTC(2026, 9, 16) // "2026-10-16" = 2026-10-16T00:00:00Z
const NOW = Date.UTC(2026, 9, 16, 12, 0, 0)

type Json = Record<string, any>

/** The draft as an object, changed by `mutate`, serialized back. */
function draftWith(mutate: (d: Json) => void): string {
  const d = JSON.parse(DRAFT_TEXT) as Json
  mutate(d)
  return JSON.stringify(d)
}

function loadOk(text: string, now: number = NOW): PricingTable {
  const r = loadPricing(text, now)
  if (!r.ok) throw new Error(`expected ok, got ${r.reason}: ${r.detail}`)
  return r.table
}

function rejectOf(text: string, now: number = NOW): { reason: string; detail: string } {
  const r = loadPricing(text, now)
  if (r.ok) throw new Error('expected a rejection, the table loaded')
  return { reason: r.reason, detail: r.detail }
}

function usage(model: string, t: Partial<Omit<UsageForPricing, 'model'>> = {}): UsageForPricing {
  return {
    model,
    input_tokens: 0,
    output_tokens: 0,
    cache_write_tokens: 0,
    cache_read_tokens: 0,
    ...t,
  }
}

const OPUS = 'claude-opus-5-5'
const SONNET = 'claude-sonnet-5-5'
const HAIKU = 'claude-haiku-5-5'

// Loaded on first use (not in beforeAll), so a broken loader fails each test
// on its own instead of skipping the whole file.
let cachedTable: PricingTable | undefined
function draftTable(): PricingTable {
  cachedTable ??= loadOk(DRAFT_TEXT)
  return cachedTable
}

beforeAll(() => {
  // Blueprint 6.1: no test may reach a real API. Nothing in N1a does network
  // I/O; this makes an accidental fetch fail loudly instead of leaving the box.
  vi.stubGlobal('fetch', () => {
    throw new Error('network is disabled in the credit-gate tests')
  })
})

afterAll(() => {
  vi.unstubAllGlobals()
})

describe('parseUsd: an amount is exactly two decimals, 0..100 000 USD', () => {
  it('turns valid amounts into whole micro-USD', () => {
    expect(parseUsd('0.00')).toBe(0)
    expect(parseUsd('0.01')).toBe(10_000)
    expect(parseUsd('3.63')).toBe(3_630_000)
    expect(parseUsd('20.00')).toBe(20_000_000)
    expect(parseUsd('195.64')).toBe(195_640_000)
    expect(parseUsd('100000.00')).toBe(100_000 * MICRO_PER_USD)
  })

  it.each([
    ['0.1'], ['1e2'], ['-1.00'], [' 1.00'], ['1.00 '], ['1.000'], ['1.00\n'], ['\n1.00'],
    ['+1.00'], ['01.00'], ['.50'], ['1.'], ['1'], ['100000.01'], ['1000000.00'],
    ['NaN'], ['Infinity'], ['-0.00'], [''], ['1,00'], ['1.0O'], ['１.００'], ['0x1.00'],
    ['1_000.00'], ['1.00e0'],
  ])('rejects %j', (s) => {
    expect(parseUsd(s)).toBeNull()
  })

  it.each<[string, unknown]>([
    ['1', 1], ['1.5', 1.5], ['NaN', Number.NaN], ['Infinity', Infinity], ['null', null],
    ['undefined', undefined], ['{}', {}], ['[]', []], ['10n', 10n],
  ])('rejects the non-string %s', (_name, v) => {
    expect(parseUsd(v)).toBeNull()
  })
})

describe('parseRate: a unit price is <= 6 decimals, 0..1000 USD/MTok', () => {
  it('accepts the N0 prices, three-decimal ones included', () => {
    expect(parseRate('0.125')).toBe(125_000)
    expect(parseRate('0.625')).toBe(625_000)
    expect(parseRate('0.01')).toBe(10_000)
    expect(parseRate('4.00')).toBe(4_000_000)
    expect(parseRate('20.00')).toBe(20_000_000)
  })

  it('accepts the edges: no decimals, six decimals, 0 and 1000', () => {
    expect(parseRate('4')).toBe(4_000_000)
    expect(parseRate('0.000001')).toBe(1)
    expect(parseRate('0')).toBe(0)
    expect(parseRate('1000')).toBe(1_000_000_000)
    expect(parseRate('1000.000000')).toBe(1_000_000_000)
  })

  it.each([
    ['0.0000001'], ['1000.000001'], ['1001'], ['-0.10'], ['+0.10'], [' 0.10'], ['0.10 '],
    ['0.10\n'], ['1e2'], ['1E2'], ['.5'], ['5.'], ['NaN'], ['Infinity'], [''], ['0x10'],
    ['01.00'], ['0,125'], ['０.125'],
  ])('rejects %j', (s) => {
    expect(parseRate(s)).toBeNull()
  })

  it.each([[0.125], [4], [null], [undefined], [Number.NaN]])('rejects the non-string %j', (v) => {
    expect(parseRate(v)).toBeNull()
  })
})

describe('money arithmetic stays in whole micro-USD', () => {
  it('the 1.5 reservation factor is exact on whole amounts', () => {
    const f = parseFactor('1.5')!
    expect(f).not.toBeNull()
    expect(applyFactorCeil(parseUsd('5.00')!, f)).toBe(parseUsd('7.50'))
    expect(applyFactorCeil(parseUsd('0.90')!, f)).toBe(1_350_000)
    expect(applyFactorCeil(asMicro(0), f)).toBe(0)
  })

  it('the 1.5 factor rounds a half micro-USD UP, never down', () => {
    const f = parseFactor('1.5')!
    expect(applyFactorCeil(asMicro(1), f)).toBe(2) // 1.5
    expect(applyFactorCeil(asMicro(3), f)).toBe(5) // 4.5
    expect(applyFactorCeil(asMicro(4), f)).toBe(6) // exact
    for (let m = 0; m <= 2_000; m++) {
      const out = applyFactorCeil(asMicro(m), f)
      expect(Number.isSafeInteger(out)).toBe(true)
      // out is the smallest whole micro-USD >= 1.5 x m
      expect(2 * out).toBeGreaterThanOrEqual(3 * m)
      expect(2 * (out - 1)).toBeLessThan(3 * m)
    }
  })

  it('factor 1 is the identity; a factor below 1 or malformed is rejected', () => {
    expect(applyFactorCeil(asMicro(1_234_567), parseFactor('1')!)).toBe(1_234_567)
    expect(applyFactorCeil(asMicro(10), parseFactor('1.000001')!)).toBe(11)
    for (const bad of ['0.5', '0.999999', '0', '1e0', '-1.5', ' 1.5', '1.5 ', '1,5', '', '1.', '.5',
      '1.1234567', '101', 'NaN']) {
      expect(parseFactor(bad), JSON.stringify(bad)).toBeNull()
    }
    expect(parseFactor(1.5)).toBeNull()
  })

  it('add, sub and sum are exact and refuse non-integers and overflow', () => {
    expect(addMicro(asMicro(195_640_000), asMicro(200_000_000))).toBe(395_640_000)
    expect(subMicro(asMicro(200_000_000), asMicro(200_000_001))).toBe(-1)
    expect(sumMicro([])).toBe(0)
    expect(sumMicro([asMicro(1), asMicro(2), asMicro(3)])).toBe(6)
    expect(() => asMicro(0.5)).toThrow()
    expect(() => asMicro(Number.NaN)).toThrow()
    expect(() => asMicro(2 ** 53)).toThrow()
    expect(() => addMicro(0.5 as Micro, asMicro(1))).toThrow()
    expect(() => addMicro(asMicro(Number.MAX_SAFE_INTEGER), asMicro(1))).toThrow()
    expect(() => subMicro(asMicro(-Number.MAX_SAFE_INTEGER), asMicro(1))).toThrow()
    expect(() => sumMicro([asMicro(1), 0.25 as Micro])).toThrow()
  })
})

describe('loadPricing: the N0 draft', () => {
  it('loads and keeps every price as whole micro-USD per MTok', () => {
    const table = draftTable()
    expect(table.schema).toBe('credit-pricing/v1')
    expect(table.verified_at).toBe('2026-10-16')
    expect(table.verified_at_ms).toBe(VERIFIED_MS)
    expect(table.batch_discount_pct).toBe(50)
    expect(table.models).toHaveLength(3)
    const opus = matchModel(draftTable(), OPUS)!
    expect(opus.base).toEqual({
      input: 4_000_000, output: 20_000_000, cache_write_5m: 5_000_000, cache_write_1h: 8_000_000,
      cache_read: 200_000,
    })
    expect(opus.long_context).toBeNull()
    expect(matchModel(draftTable(), SONNET)!.long_context).toBeNull()
    const haiku = matchModel(draftTable(), HAIKU)!
    expect(haiku.base.cache_write_5m).toBe(125_000)
    expect(haiku.long_context).toMatchObject({
      threshold_input_tokens: 100_000,
      input: 500_000, output: 2_500_000, cache_write_5m: 625_000, cache_write_1h: 1_000_000,
      cache_read: 50_000,
    })
    // `counts` is absent in the draft: the default counts every prompt category.
    expect([...haiku.long_context!.counts].sort()).toEqual(['cache_read', 'cache_write', 'input'])
  })

  it('accepts an explicit counts list that names all three prompt categories', () => {
    const t = loadOk(draftWith((d) => {
      d.models[2].long_context.counts = ['cache_read', 'input', 'cache_write']
    }))
    expect(matchModel(t, HAIKU)!.long_context!.threshold_input_tokens).toBe(100_000)
  })

  it('accepts a long-context threshold of exactly 10 000 000 tokens', () => {
    const t = loadOk(draftWith((d) => { d.models[2].long_context.threshold_input_tokens = 10_000_000 }))
    expect(matchModel(t, HAIKU)!.long_context!.threshold_input_tokens).toBe(10_000_000)
  })

  it('accepts batch_discount_pct = null', () => {
    const t = loadOk(draftWith((d) => { d.batch_discount_pct = null }))
    expect(t.batch_discount_pct).toBeNull()
  })

  it('accepts a full UTC timestamp as verified_at', () => {
    const t = loadOk(draftWith((d) => { d.verified_at = '2026-10-16T09:30:00Z' }))
    expect(t.verified_at_ms).toBe(Date.UTC(2026, 9, 16, 9, 30, 0))
  })
})

describe('loadPricing: staleness (A-02: verified_at older than 30 days)', () => {
  it('is fresh at exactly 30 days and stale one millisecond later', () => {
    expect(STALE_AFTER_MS).toBe(30 * DAY_MS)
    expect(loadPricing(DRAFT_TEXT, VERIFIED_MS + 30 * DAY_MS).ok).toBe(true)
    expect(rejectOf(DRAFT_TEXT, VERIFIED_MS + 30 * DAY_MS + 1).reason).toBe('stale')
  })

  it('isPricingStale applies the same rule to an already loaded table', () => {
    const t = draftTable()
    expect(isPricingStale(t, VERIFIED_MS + 30 * DAY_MS)).toBe(false)
    expect(isPricingStale(t, VERIFIED_MS + 30 * DAY_MS + 1)).toBe(true)
    expect(isPricingStale(t, new Date(VERIFIED_MS + 31 * DAY_MS))).toBe(true)
    expect(isPricingStale(t, Number.NaN)).toBe(true)
  })

  it('an old table is stale', () => {
    const text = draftWith((d) => { d.verified_at = '2026-09-01' })
    expect(rejectOf(text).reason).toBe('stale')
  })

  it('accepts a Date as now', () => {
    expect(loadPricing(DRAFT_TEXT, new Date(NOW)).ok).toBe(true)
    expect(loadPricing(DRAFT_TEXT, new Date(VERIFIED_MS + 31 * DAY_MS)).ok).toBe(false)
  })

  it('tolerates a date-only verified_at up to one day ahead (time zones), not more', () => {
    const tomorrow = draftWith((d) => { d.verified_at = '2026-10-17' })
    expect(loadPricing(tomorrow, Date.UTC(2026, 9, 16, 22, 30)).ok).toBe(true)
    const farAhead = draftWith((d) => { d.verified_at = '2026-10-18' })
    expect(rejectOf(farAhead).reason).toBe('invalid')
  })

  it('refuses an unusable now', () => {
    expect(rejectOf(DRAFT_TEXT, Number.NaN).reason).toBe('invalid')
  })
})

describe('loadPricing: rejections', () => {
  it('broken JSON', () => {
    expect(rejectOf('{').reason).toBe('invalid_json')
    expect(rejectOf('').reason).toBe('invalid_json')
    expect(rejectOf('null').reason).toBe('invalid')
    expect(rejectOf('[]').reason).toBe('invalid')
  })

  it('a duplicated key, which JSON.parse would silently resolve to the last value', () => {
    const text = DRAFT_TEXT.replace('"input": "4.00",', '"input": "0.01", "input": "4.00",')
    expect((JSON.parse(text) as Json).models[0].input).toBe('4.00')
    expect(rejectOf(text).reason).toBe('duplicate_key')
  })

  it('a \\u-escaped duplicated key ("\\u0069nput" is "input") is a duplicate too (BE-2 p1)', () => {
    const text = DRAFT_TEXT.replace('"input": "4.00",', '"input": "4.00", "\\u0069nput": "0.000001",')
    expect((JSON.parse(text) as Json).models[0].input).toBe('0.000001')
    expect(rejectOf(text).reason).toBe('duplicate_key')
  })

  it('a wrong or missing schema id', () => {
    expect(rejectOf(draftWith((d) => { d.schema = 'credit-pricing/v2' })).reason).toBe('schema')
    expect(rejectOf(draftWith((d) => { delete d.schema })).reason).toBe('schema')
  })

  it.each<[string, (d: Json) => void, string]>([
    ['unknown top-level key', (d) => { d.note = 'x' }, 'note'],
    ['unknown model key', (d) => { d.models[0].cache_wirte_1h = '8.00' }, 'models[0]'],
    ['unknown long_context key', (d) => { d.models[2].long_context.output_x = '1.00' }, 'models[2].long_context'],
    ['missing long_context', (d) => { delete d.models[0].long_context }, 'models[0].long_context'],
    ['missing price', (d) => { delete d.models[1].cache_read }, 'models[1].cache_read'],
    ['numeric price', (d) => { d.models[0].input = 4 }, 'models[0].input'],
    ['seven-decimal price', (d) => { d.models[2].cache_read = '0.0100001' }, 'models[2].cache_read'],
    ['price above 1000', (d) => { d.models[0].output = '1000.01' }, 'models[0].output'],
    ['negative price', (d) => { d.models[0].input = '-4.00' }, 'models[0].input'],
    ['zero input price "0"', (d) => { d.models[0].input = '0' }, 'models[0].input'],
    ['zero input price "0.00"', (d) => { d.models[1].input = '0.00' }, 'models[1].input'],
    ['zero output price "0"', (d) => { d.models[0].output = '0' }, 'models[0].output'],
    ['zero output price "0.000000"', (d) => { d.models[1].output = '0.000000' }, 'models[1].output'],
    ['zero long-context input price', (d) => { d.models[2].long_context.input = '0.00' }, 'models[2].long_context.input'],
    ['zero long-context output price', (d) => { d.models[2].long_context.output = '0' }, 'models[2].long_context.output'],
    ['exponent price', (d) => { d.models[2].long_context.input = '5e-1' }, 'models[2].long_context.input'],
    ['empty models', (d) => { d.models = [] }, 'models'],
    ['empty ids', (d) => { d.models[0].ids = [] }, 'models[0].ids'],
    ['non-string id', (d) => { d.models[0].ids = [42] }, 'models[0].ids'],
    ['id with a space', (d) => { d.models[0].ids = ['claude opus'] }, 'models[0].ids'],
    ['id with a bracket', (d) => { d.models[0].ids = ['claude-opus-5-5[1m]'] }, 'models[0].ids'],
    ['duplicate id across models', (d) => { d.models[1].ids = ['claude-opus-5-5'] }, 'claude-opus-5-5'],
    ['duplicate id in one model', (d) => { d.models[0].ids = ['claude-opus-5-5', 'claude-opus-5-5'] }, 'claude-opus-5-5'],
    ['batch_discount_pct as string', (d) => { d.batch_discount_pct = '50' }, 'batch_discount_pct'],
    ['batch_discount_pct 100', (d) => { d.batch_discount_pct = 100 }, 'batch_discount_pct'],
    ['batch_discount_pct negative', (d) => { d.batch_discount_pct = -1 }, 'batch_discount_pct'],
    ['batch_discount_pct fractional', (d) => { d.batch_discount_pct = 12.5 }, 'batch_discount_pct'],
    ['batch_discount_pct missing', (d) => { delete d.batch_discount_pct }, 'batch_discount_pct'],
    ['batch_discount_pct 0 (only 50 from N0, or null)', (d) => { d.batch_discount_pct = 0 }, 'batch_discount_pct'],
    ['batch_discount_pct 25', (d) => { d.batch_discount_pct = 25 }, 'batch_discount_pct'],
    ['batch_discount_pct 49', (d) => { d.batch_discount_pct = 49 }, 'batch_discount_pct'],
    ['batch_discount_pct 51', (d) => { d.batch_discount_pct = 51 }, 'batch_discount_pct'],
    ['batch_discount_pct 99', (d) => { d.batch_discount_pct = 99 }, 'batch_discount_pct'],
    ['zero cache read price', (d) => { d.models[0].cache_read = '0' }, 'models[0].cache_read'],
    ['zero 5m cache write price', (d) => { d.models[0].cache_write_5m = '0.00' }, 'models[0].cache_write_5m'],
    ['zero 1h cache write price', (d) => { d.models[1].cache_write_1h = '0' }, 'models[1].cache_write_1h'],
    ['zero long-context cache read price', (d) => { d.models[2].long_context.cache_read = '0.000000' }, 'models[2].long_context.cache_read'],
    ['threshold above 10 000 000', (d) => { d.models[2].long_context.threshold_input_tokens = 10_000_001 }, 'threshold_input_tokens'],
    ['threshold at the safe-integer maximum', (d) => { d.models[2].long_context.threshold_input_tokens = Number.MAX_SAFE_INTEGER }, 'threshold_input_tokens'],
    ['1h cache write cheaper than 5m', (d) => { d.models[0].cache_write_1h = '4.99' }, 'models[0]'],
    ['long-context price below the base price', (d) => { d.models[2].long_context.input = '0.05' }, 'models[2].long_context'],
    ['threshold 0', (d) => { d.models[2].long_context.threshold_input_tokens = 0 }, 'threshold_input_tokens'],
    ['threshold fractional', (d) => { d.models[2].long_context.threshold_input_tokens = 1.5 }, 'threshold_input_tokens'],
    ['threshold as string', (d) => { d.models[2].long_context.threshold_input_tokens = '100000' }, 'threshold_input_tokens'],
    ['counts missing a category', (d) => { d.models[2].long_context.counts = ['input'] }, 'counts'],
    ['counts with a duplicate', (d) => { d.models[2].long_context.counts = ['input', 'input', 'cache_read'] }, 'counts'],
    ['counts with output', (d) => {
      d.models[2].long_context.counts = ['input', 'cache_write', 'cache_read', 'output']
    }, 'counts'],
    ['no sources', (d) => { d.sources = [] }, 'sources'],
    ['http source', (d) => { d.sources[0].url = 'http://platform.claude.com/docs' }, 'sources[0].url'],
    ['source without retrieved_at', (d) => { delete d.sources[1].retrieved_at }, 'sources[1]'],
    ['impossible verified_at', (d) => { d.verified_at = '2026-02-30' }, 'verified_at'],
    ['verified_at with offset', (d) => { d.verified_at = '2026-10-16T00:00:00+02:00' }, 'verified_at'],
    ['numeric verified_at', (d) => { d.verified_at = VERIFIED_MS }, 'verified_at'],
  ])('%s', (_name, mutate, where) => {
    const r = rejectOf(draftWith(mutate))
    expect(r.reason).toBe('invalid')
    expect(r.detail).toContain(where)
  })
})

describe('matchModel: exact id, or exact id + "-YYYYMMDD", nothing else', () => {
  it('matches the exact id', () => {
    expect(matchModel(draftTable(), OPUS)!.base.input).toBe(4_000_000)
    expect(matchModel(draftTable(), SONNET)!.base.input).toBe(2_000_000)
    expect(matchModel(draftTable(), HAIKU)!.base.input).toBe(100_000)
  })

  it('matches the exact id with a date suffix', () => {
    expect(matchModel(draftTable(), 'claude-opus-5-5-20261016')!.base.input).toBe(4_000_000)
    expect(matchModel(draftTable(), 'claude-haiku-5-5-20251231')!.base.input).toBe(100_000)
  })

  it.each([
    ['claude-opus-5-5-x'], ['claude-opus-5-5x'], ['xclaude-opus-5-5'], ['claude-opus-5'],
    ['claude-opus'], ['claude'], ['claude-opus-5-5-2026101'], ['claude-opus-5-5-202610161'],
    ['claude-opus-5-5-20261340'], ['claude-opus-5-5-20260230'], ['claude-opus-5-5-20261016x'],
    ['claude-opus-5-5-20261016-20261016'], ['claude-opus-5-520261016'], ['claude-opus-5-5[1m]'],
    ['Claude-Opus-5-5'], [' claude-opus-5-5'], ['claude-opus-5-5 '], ['claude-opus-5-5\n'],
    ['claude-opus-5-5-２０２６１０１６'], [''], ['__proto__'], ['constructor'], ['toString'],
  ])('does not match %j', (id) => {
    expect(matchModel(draftTable(), id)).toBeNull()
  })

  it.each([[undefined], [null], [42], [{}], [['claude-opus-5-5']]])('does not match the non-string %j', (id) => {
    expect(matchModel(draftTable(), id)).toBeNull()
  })

  it('an exact dated id wins over the suffix rule', () => {
    const t = loadOk(draftWith((d) => {
      d.models[0].ids = ['claude-x']
      d.models[1].ids = ['claude-x-20261001']
    }))
    expect(matchModel(t, 'claude-x-20261001')!.base.input).toBe(2_000_000)
    expect(matchModel(t, 'claude-x-20261002')!.base.input).toBe(4_000_000)
  })
})

describe('estimate: overestimating micro-USD cost of one request (spec 6.1, B-03)', () => {
  const est = (u: UsageForPricing, t: PricingTable = draftTable()): number | null => estimate(u, { table: t })

  it('an unknown model has no price (A-02), not zero', () => {
    expect(est(usage('claude-opus-4-1', { input_tokens: 10 }))).toBeNull()
    expect(est(usage('claude-opus-5-5-x', { input_tokens: 10 }))).toBeNull()
    expect(est(usage('', { input_tokens: 10 }))).toBeNull()
  })

  it('prices each token category with its own unit price', () => {
    expect(est(usage(OPUS, { input_tokens: 1_000_000 }))).toBe(4_000_000)
    expect(est(usage(OPUS, { output_tokens: 1_000_000 }))).toBe(20_000_000)
    expect(est(usage(OPUS, { cache_read_tokens: 1_000_000 }))).toBe(200_000)
    expect(est(usage(SONNET, { input_tokens: 1_000_000, output_tokens: 1_000_000 }))).toBe(12_000_000)
    expect(est(usage(OPUS, { output_tokens: 1 }))).toBe(20)
    expect(est(usage(OPUS))).toBe(0)
  })

  it('every cache write is priced at the 1-hour price, never the 5-minute one', () => {
    expect(est(usage(OPUS, { cache_write_tokens: 1_000_000 }))).toBe(8_000_000) // not 5_000_000
    expect(est(usage(SONNET, { cache_write_tokens: 1_000_000 }))).toBe(4_000_000) // not 2_500_000
    expect(est(usage(HAIKU, { cache_write_tokens: 10_000 }))).toBe(2_000) // not 1_250
  })

  it('rounds the exact total of the request UP to a whole micro-USD, once', () => {
    expect(est(usage(HAIKU, { input_tokens: 1 }))).toBe(1) // 0.1
    expect(est(usage(HAIKU, { input_tokens: 10 }))).toBe(1) // exactly 1, not 2
    expect(est(usage(HAIKU, { input_tokens: 11 }))).toBe(2) // 1.1
    expect(est(usage(OPUS, { cache_read_tokens: 1 }))).toBe(1) // 0.2
    // 0.1 + 0.01 + 0.5 = 0.61 -> 1 (rounding each category would give 3)
    expect(est(usage(HAIKU, { input_tokens: 1, cache_read_tokens: 1, output_tokens: 1 }))).toBe(1)
    // 3 x 0.1 + 3 x 0.01 = 0.33 -> 1
    expect(est(usage(HAIKU, { input_tokens: 3, cache_read_tokens: 3 }))).toBe(1)
  })

  it('Opus 5.5 and Sonnet 5.5 have no long-context band', () => {
    expect(est(usage(OPUS, { input_tokens: 900_000 }))).toBe(3_600_000)
    expect(est(usage(OPUS, { input_tokens: 200_001 }))).toBe(800_004)
    expect(est(usage(SONNET, { input_tokens: 2_000_000, output_tokens: 1 }))).toBe(4_000_010)
  })

  describe('Haiku 5.5 band: prompt STRICTLY above 100 000 tokens, cache tokens counted', () => {
    it('input only: 99 999 and 100 000 lower, 100 001 upper', () => {
      expect(est(usage(HAIKU, { input_tokens: 99_999 }))).toBe(10_000) // 9 999.9
      expect(est(usage(HAIKU, { input_tokens: 100_000 }))).toBe(10_000) // exactly
      expect(est(usage(HAIKU, { input_tokens: 100_001 }))).toBe(50_001) // 50 000.5
    })

    it('input + cache write + cache read is the prompt length', () => {
      const base = { input_tokens: 40_000, cache_write_tokens: 30_000, output_tokens: 1_000 }
      // 4 000 + 6 000 + 299.99 + 500
      expect(est(usage(HAIKU, { ...base, cache_read_tokens: 29_999 }))).toBe(10_800)
      // 4 000 + 6 000 + 300 + 500
      expect(est(usage(HAIKU, { ...base, cache_read_tokens: 30_000 }))).toBe(10_800)
      // upper band on ALL tokens, output included: 20 000 + 30 000 + 1 500.05 + 2 500
      expect(est(usage(HAIKU, { ...base, cache_read_tokens: 30_001 }))).toBe(54_001)
    })

    it('cache writes or cache reads alone can cross the threshold', () => {
      expect(est(usage(HAIKU, { input_tokens: 1, cache_write_tokens: 99_999 }))).toBe(20_000) // 0.1 + 19 999.8
      expect(est(usage(HAIKU, { input_tokens: 1, cache_write_tokens: 100_000 }))).toBe(100_001) // 0.5 + 100 000
      expect(est(usage(HAIKU, { input_tokens: 1, cache_read_tokens: 99_999 }))).toBe(1_001) // 0.1 + 999.99
      expect(est(usage(HAIKU, { input_tokens: 1, cache_read_tokens: 100_000 }))).toBe(5_001) // 0.5 + 5 000
    })

    it('output tokens do not count toward the prompt length', () => {
      // 9 999.9 + 5 000 (the upper band would be 74 999.5 -> 75 000)
      expect(est(usage(HAIKU, { input_tokens: 99_999, output_tokens: 10_000 }))).toBe(15_000)
    })
  })

  describe('batch discount: only with a non-null batch_discount_pct, only on a batch_id row', () => {
    const big = { input_tokens: 1_000_000, output_tokens: 1_000_000 }

    it('halves input and output of a batch row', () => {
      expect(est(usage(OPUS, { ...big, batch_id: 'msgbatch_01' }))).toBe(12_000_000) // 2 + 10 USD
      expect(est(usage(SONNET, { ...big, batch_id: 'msgbatch_01' }))).toBe(6_000_000)
    })

    it('a row without a batch_id pays the full price', () => {
      expect(est(usage(OPUS, big))).toBe(24_000_000)
      expect(est(usage(OPUS, { ...big, batch_id: null }))).toBe(24_000_000)
      expect(est(usage(OPUS, { ...big, batch_id: '' }))).toBe(24_000_000)
    })

    it('no discount when the table has batch_discount_pct = null', () => {
      const noDiscount = loadOk(draftWith((d) => { d.batch_discount_pct = null }))
      expect(est(usage(OPUS, { ...big, batch_id: 'msgbatch_01' }), noDiscount)).toBe(24_000_000)
    })

    it('cache tokens of a batch row keep the full price (the overestimating reading)', () => {
      expect(est(usage(OPUS, {
        cache_write_tokens: 1_000_000, cache_read_tokens: 1_000_000, batch_id: 'msgbatch_01',
      }))).toBe(8_200_000)
    })

    it('rounds the discounted total up once', () => {
      expect(est(usage(HAIKU, { input_tokens: 1, batch_id: 'b' }))).toBe(1) // 0.05
      expect(est(usage(HAIKU, { input_tokens: 20, batch_id: 'b' }))).toBe(1) // exactly 1
      expect(est(usage(HAIKU, { input_tokens: 21, batch_id: 'b' }))).toBe(2) // 1.05
      expect(est(usage(HAIKU, { input_tokens: 100_001, batch_id: 'b' }))).toBe(25_001) // 25 000.25
    })

  })

  it.each<[string, Partial<UsageForPricing>]>([
    ['negative tokens', { input_tokens: -1 }],
    ['fractional tokens', { output_tokens: 1.5 }],
    ['NaN tokens', { cache_read_tokens: Number.NaN }],
    ['infinite tokens', { cache_write_tokens: Infinity }],
    ['string tokens', { input_tokens: '10' as unknown as number }],
    ['missing tokens', { output_tokens: undefined as unknown as number }],
    ['unsafe tokens', { input_tokens: 2 ** 53 }],
  ])('an unpriceable request (%s) gives null, never a guess', (_name, t) => {
    expect(est(usage(OPUS, t))).toBeNull()
  })

  it('a cost beyond the safe-integer range gives null instead of a wrong number', () => {
    expect(est(usage(OPUS, { output_tokens: Number.MAX_SAFE_INTEGER }))).toBeNull()
  })

  it('a non-string model gives null', () => {
    expect(est({ ...usage(OPUS), model: 42 as unknown as string })).toBeNull()
  })

  it('always returns a whole micro-USD that is >= the exact cost and < exact + 1', () => {
    // Exact cost x 10^8 from the N0 prices (USD/MTok x 10^6, x 100 for the
    // batch percentage), worked out here independently of the module.
    const price = {
      [OPUS]: [4_000_000n, 20_000_000n, 8_000_000n, 200_000n],
      [SONNET]: [2_000_000n, 10_000_000n, 4_000_000n, 100_000n],
    } as const
    const counts = [0, 1, 7, 999, 123_457, 1_000_003]
    for (const model of [OPUS, SONNET] as const) {
      for (const i of counts) for (const o of counts) for (const w of [0, 3, 50_001]) {
        for (const batch of [false, true]) {
          const [pi, po, pw, pr] = price[model]
          const disc = batch ? 50n : 100n
          const exact = BigInt(i) * pi * disc + BigInt(o) * po * disc + BigInt(w) * pw * 100n + 5n * pr * 100n
          const got = est(usage(model, {
            input_tokens: i, output_tokens: o, cache_write_tokens: w, cache_read_tokens: 5,
            batch_id: batch ? 'b' : null,
          }))
          expect(got).not.toBeNull()
          expect(Number.isSafeInteger(got)).toBe(true)
          const g = BigInt(got!)
          expect(g * 100_000_000n >= exact).toBe(true)
          expect((g - 1n) * 100_000_000n < exact).toBe(true)
        }
      }
    }
  })
})

describe('no floating point and no network in the money and pricing modules', () => {
  const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'credit-gate')
  it.each([['money.ts'], ['pricing.ts'], ['types.ts']])('%s', (file) => {
    const src = readFileSync(join(dir, file), 'utf8')
    for (const banned of ['parseFloat', 'toFixed', 'Math.round', 'Math.floor', 'Math.ceil',
      'fetch(', "'node:net'", "'node:http'", "'node:https'", "'node:child_process'"]) {
      expect(src.includes(banned), `${file} contains ${banned}`).toBe(false)
    }
  })
})
