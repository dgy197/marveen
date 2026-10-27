import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import {
  appendFileSync,
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  truncateSync,
  writeFileSync,
  writeSync,
} from 'node:fs'
import { execFileSync, spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { parseUsageLine, usageDedupeKey } from '../web/credit-gate/ledger-usage-jsonl.js'
import { readTranscriptUsage } from '../web/credit-gate/ledger-transcript.js'
import { CreditLedger, usdNumberToMicroCeil, type HeadlessRun } from '../web/credit-gate/ledger.js'
import { asMicro, MAX_USD_AMOUNT_MICRO } from '../web/credit-gate/money.js'
import { loadPricing } from '../web/credit-gate/pricing.js'
import type { PricingTable } from '../web/credit-gate/types.js'

// Credit gate, node N1b: the ledger (card fec6335f).
//
// Written from the spec (B-01..B-04, A-02) and the blueprint (3.3, 3.4, N1b),
// not from the code. The input format is the one the two real writers produce
// (~/Brainy/main/projects/anthropic-batch): a synchronous row
// {ts, month, caller, model, in, out} (batch_client.py) and a batch row with
// cache_creation_input_tokens, cache_read_input_tokens, batch_id, custom_id and
// api (message_batches.py), both appended through usage_log.append_usage as
// json.dumps(...) + "\n". Every fixture here is SYNTHETIC and lives in a tmp
// directory: the real usage.jsonl is never read.
//
// Expected amounts are computed by hand from the N0 prices (USD/MTok):
//   Opus 5.5   4.00 in, 20.00 out, 8.00 cache write (1h), 0.20 cache read
//   Sonnet 5.5 2.00 in, 10.00 out, 4.00 cache write (1h), 0.10 cache read
//   Haiku 5.5  0.10 in,  0.50 out, 0.20 cache write (1h), 0.01 cache read
// cost in micro-USD = tokens x price, rounded up once per request; a batch row
// pays 50% on input and output.

const PRICING_TEXT = `{
  "schema": "credit-pricing/v1",
  "verified_at": "2026-10-16",
  "sources": [{"url": "https://platform.claude.com/docs/en/about-claude/pricing", "retrieved_at": "2026-10-16"}],
  "batch_discount_pct": 50,
  "models": [
    {"ids": ["claude-opus-5-5"], "input": "4.00", "output": "20.00", "cache_write_5m": "5.00", "cache_write_1h": "8.00", "cache_read": "0.20", "long_context": null},
    {"ids": ["claude-sonnet-5-5"], "input": "2.00", "output": "10.00", "cache_write_5m": "2.50", "cache_write_1h": "4.00", "cache_read": "0.10", "long_context": null},
    {"ids": ["claude-haiku-5-5"], "input": "0.10", "output": "0.50", "cache_write_5m": "0.125", "cache_write_1h": "0.20", "cache_read": "0.01",
     "long_context": {"threshold_input_tokens": 100000, "input": "0.50", "output": "2.50", "cache_write_5m": "0.625", "cache_write_1h": "1.00", "cache_read": "0.05"}}
  ]
}`

const T0 = Date.UTC(2026, 9, 16, 8, 0, 0) // epoch ms, the fake "now" of every test
const TS = Math.floor(T0 / 1000) - 3600 // a row timestamp (epoch s) one hour before T0
const BATCH = 'msgbatch_01FPjz5ebTAmg8DeCAQ2DEfr'
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

let table: PricingTable
{
  const r = loadPricing(PRICING_TEXT, T0)
  if (!r.ok) throw new Error(`pricing fixture rejected: ${r.reason} ${r.detail}`)
  table = r.table
}

/** One line the way Python's json.dumps writes it (", " and ": " separators). */
function pyLine(o: Record<string, unknown>): string {
  return '{' + Object.entries(o).map(([k, v]) => `${JSON.stringify(k)}: ${JSON.stringify(v)}`).join(', ') + '}\n'
}

function syncRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { ts: TS, month: '2026-10', caller: 'hajcsar-triazs', model: 'claude-sonnet-5-5', in: 1000, out: 1000, ...over }
}

function batchRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ts: TS,
    month: '2026-10',
    caller: 'rag-gold-label',
    model: 'claude-opus-5-5',
    in: 45909,
    out: 4333,
    cache_creation_input_tokens: 2815,
    cache_read_input_tokens: 0,
    batch_id: BATCH,
    custom_id: 'q-1',
    api: 'message_batches',
    ...over,
  }
}

// The shape of the two real canary `claude -p` rows in usage.jsonl (key order
// and value types as written; BE-2 p4, read-only): cost_usd_reported is the
// CLI's total_cost_usd as a decimal string.
function canaryHeadlessRow(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    ts: TS,
    month: '2026-10',
    caller: 'ezermester-kanari-headless',
    api: 'claude-p',
    model: 'claude-sonnet-5-5',
    in: 8,
    out: 647,
    cache_creation_input_tokens: 26368,
    cache_read_input_tokens: 25761,
    cost_usd_reported: '0.0749821',
    ...over,
  }
}

// Sonnet, 1000 in + 1000 out: 1000 x 2 + 1000 x 10 = 12 000 micro-USD.
const SONNET_1K_1K = 12_000
// The real batch row: 45909 x 4 x 0.5 + 4333 x 20 x 0.5 + 2815 x 8 = 91 818 + 43 330 + 22 520.
const OPUS_BATCH = 157_668

let dir: string
let db: Database.Database
let usagePath: string

function ledger(over: Partial<ConstructorParameters<typeof CreditLedger>[1]> = {}): CreditLedger {
  return new CreditLedger(db, {
    sources: [{ id: 'anthropic-batch', path: usagePath, format: 'usage-jsonl-v1' }],
    ...over,
  })
}

function entries(): Array<Record<string, unknown>> {
  return db.prepare('SELECT * FROM credit_ledger_entries ORDER BY id').all() as Array<Record<string, unknown>>
}

function cursor(source = 'anthropic-batch'): Record<string, unknown> | undefined {
  return db.prepare('SELECT * FROM credit_ledger_cursors WHERE source = ?').get(source) as Record<string, unknown> | undefined
}

/**
 * Run a few lines of TypeScript in a child (tsx) and return the JSON its last
 * output line carries. For the FIFO cases: a blocking open() would hang the
 * test worker itself for good; a hung child is killed after 20 s instead.
 */
function inChild(lines: string[]): { value: unknown; ms: number } {
  const child = join(dir, `child-${Math.random().toString(36).slice(2)}.ts`)
  writeFileSync(child, lines.join('\n'))
  const out = spawnSync(join(REPO, 'node_modules', '.bin', 'tsx'), [child], { encoding: 'utf8', timeout: 20_000 })
  expect(out.error).toBeUndefined() // ETIMEDOUT = the open blocked
  return JSON.parse(out.stdout.trim().split('\n').pop() ?? '{}') as { value: unknown; ms: number }
}

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'credit-ledger-'))
  usagePath = join(dir, 'usage.jsonl')
  db = new Database(':memory:')
  applyCreditGateSchema(db)
})

afterEach(() => {
  db.close()
  rmSync(dir, { recursive: true, force: true })
})

describe('schema', () => {
  it('creates the ledger tables and is idempotent', () => {
    applyCreditGateSchema(db)
    applyCreditGateSchema(db)
    const cols = (t: string) => (db.prepare(`PRAGMA table_info(${t})`).all() as Array<{ name: string }>).map((c) => c.name)
    expect(cols('credit_ledger_entries')).toEqual(expect.arrayContaining([
      'id', 'source', 'dedupe_key', 'ts', 'model', 'input_tokens', 'output_tokens', 'cache_write_tokens',
      'cache_read_tokens', 'batch_id', 'custom_id', 'run_id', 'est_micro', 'cli_micro', 'priced_with', 'ingested_at',
    ]))
    expect(cols('credit_ledger_cursors')).toEqual(expect.arrayContaining([
      'source', 'dev', 'ino', 'offset', 'tail_sha256', 'status', 'updated_at',
    ]))
  })

  it('refuses a second row with the same dedupe_key at the database level', () => {
    const ins = db.prepare(`INSERT INTO credit_ledger_entries (source, dedupe_key, ts, model, input_tokens, output_tokens,
      cache_write_tokens, cache_read_tokens, basis, ingested_at) VALUES ('s', 'k', 1, 'm', 0, 0, 0, 0, 'usage', 1)`)
    ins.run()
    expect(() => ins.run()).toThrow(/UNIQUE/)
  })

  it('refuses a second row for the same (batch_id, custom_id) at the database level', () => {
    const ins = db.prepare(`INSERT INTO credit_ledger_entries (source, dedupe_key, ts, model, input_tokens, output_tokens,
      cache_write_tokens, cache_read_tokens, batch_id, custom_id, basis, ingested_at)
      VALUES ('s', ?, 1, 'm', 0, 0, 0, 0, 'b', 'c', 'usage', 1)`)
    ins.run('k1')
    expect(() => ins.run('k2')).toThrow(/UNIQUE/)
  })
})

describe('parseUsageLine (usage-jsonl-v1)', () => {
  it('reads the synchronous row of batch_client.py', () => {
    const r = parseUsageLine(pyLine(syncRow()).trimEnd())
    expect(r).toEqual({
      ok: true,
      row: {
        ts: TS, caller: 'hajcsar-triazs', model: 'claude-sonnet-5-5',
        input_tokens: 1000, output_tokens: 1000, cache_write_tokens: 0, cache_read_tokens: 0,
        batch_id: null, custom_id: null, cli_micro: null,
      },
    })
  })

  it('reads the batch row of message_batches.py', () => {
    const r = parseUsageLine(pyLine(batchRow()).trimEnd())
    expect(r.ok && r.row).toEqual({
      ts: TS, caller: 'rag-gold-label', model: 'claude-opus-5-5',
      input_tokens: 45909, output_tokens: 4333, cache_write_tokens: 2815, cache_read_tokens: 0,
      batch_id: BATCH, custom_id: 'q-1', cli_micro: null,
    })
  })

  it('reads the canary rows: a messages row and a claude -p row with cache tokens, no batch_id', () => {
    const m = parseUsageLine(pyLine(syncRow({ caller: 'ezermester-kanari-messages', in: 100, out: 50 })).trimEnd())
    expect(m.ok).toBe(true)
    const h = parseUsageLine(pyLine(syncRow({
      caller: 'ezermester-kanari-headless', in: 10, out: 200,
      cache_creation_input_tokens: 5000, cache_read_input_tokens: 20000,
    })).trimEnd())
    expect(h.ok && h.row).toMatchObject({ cache_write_tokens: 5000, cache_read_tokens: 20000, batch_id: null })
  })

  it('reads the real canary claude -p rows: cost_usd_reported is the CLI cost, rounded UP to micro-USD', () => {
    const a = parseUsageLine(pyLine(canaryHeadlessRow()).trimEnd())
    expect(a.ok && a.row).toMatchObject({ caller: 'ezermester-kanari-headless', cache_write_tokens: 26368, cli_micro: 74_983 })
    const b = parseUsageLine(pyLine(canaryHeadlessRow({
      in: 1, out: 1, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, cost_usd_reported: '0.1',
    })).trimEnd())
    expect(b.ok && b.row).toMatchObject({ cli_micro: 100_000 })
    const c = parseUsageLine(pyLine(canaryHeadlessRow({ cost_usd_reported: '12.5' })).trimEnd())
    expect(c.ok && c.row).toMatchObject({ cli_micro: 12_500_000 })
  })

  it('accepts a token count just under the per-field cap (999 999 999)', () => {
    const r = parseUsageLine(pyLine(syncRow({ in: 999_999_999, out: 999_999_999 })).trimEnd())
    expect(r.ok && r.row).toMatchObject({ input_tokens: 999_999_999, output_tokens: 999_999_999 })
  })

  const bad: Array<[string, string, string]> = [
    ['not JSON', '{"ts": 1, "month"', 'invalid_json'],
    ['an empty line', '', 'invalid_json'],
    ['an array', '[1, 2]', 'not_object'],
    ['a duplicated key', '{"ts": 1, "ts": 2, "month": "2026-10", "caller": "c", "model": "m", "in": 1, "out": 1}', 'duplicate_key'],
    ['an unknown key', pyLine(syncRow({ cost_usd: 1 })).trimEnd(), 'unknown_key'],
    ['a missing model', pyLine((({ model: _m, ...r }) => r)(syncRow())).trimEnd(), 'bad_model'],
    ['a null model (resp.get("model") was None)', pyLine(syncRow({ model: null })).trimEnd(), 'bad_model'],
    ['an empty model', pyLine(syncRow({ model: '' })).trimEnd(), 'bad_model'],
    ['a negative input count', pyLine(syncRow({ in: -1 })).trimEnd(), 'bad_tokens'],
    ['a negative output count', pyLine(syncRow({ out: -5 })).trimEnd(), 'bad_tokens'],
    ['a negative cache count', pyLine(batchRow({ cache_read_input_tokens: -1 })).trimEnd(), 'bad_tokens'],
    ['a null cache write count', pyLine(batchRow({ cache_creation_input_tokens: null })).trimEnd(), 'bad_tokens'],
    ['a null cache read count', pyLine(batchRow({ cache_read_input_tokens: null })).trimEnd(), 'bad_tokens'],
    ['a null cache write count on a synchronous row', pyLine(syncRow({ cache_creation_input_tokens: null })).trimEnd(), 'bad_tokens'],
    ['a fractional count', pyLine(syncRow({ in: 1.5 })).trimEnd(), 'bad_tokens'],
    ['a string count', pyLine(syncRow({ out: '5' })).trimEnd(), 'bad_tokens'],
    ['a boolean count', pyLine(syncRow({ in: true })).trimEnd(), 'bad_tokens'],
    ['a count beyond 2^53', '{"ts": 1, "month": "2026-10", "caller": "c", "model": "m", "in": 9007199254740993, "out": 1}', 'bad_tokens'],
    ['a missing output count', pyLine((({ out: _o, ...r }) => r)(syncRow())).trimEnd(), 'bad_tokens'],
    ['a missing ts', pyLine((({ ts: _t, ...r }) => r)(syncRow())).trimEnd(), 'bad_ts'],
    ['a fractional ts', pyLine(syncRow({ ts: 1.5 })).trimEnd(), 'bad_ts'],
    ['a bad month', pyLine(syncRow({ month: '2026/10' })).trimEnd(), 'bad_month'],
    ['a missing caller', pyLine((({ caller: _c, ...r }) => r)(syncRow())).trimEnd(), 'bad_caller'],
    ['a batch_id without custom_id', pyLine((({ custom_id: _c, ...r }) => r)(batchRow())).trimEnd(), 'bad_batch'],
    ['a custom_id without batch_id', pyLine(syncRow({ custom_id: 'q-1' })).trimEnd(), 'bad_batch'],
    ['a malformed batch_id', pyLine(batchRow({ batch_id: 'batch 1' })).trimEnd(), 'bad_batch'],
    ['a null batch_id', pyLine(batchRow({ batch_id: null })).trimEnd(), 'bad_batch'],
    ['an escaped duplicate key (\\u0069n is "in")', '{"ts": 1, "month": "2026-10", "caller": "c", "model": "m", "in": 500000, "\\u0069n": 1, "out": 1}', 'duplicate_key'],
    ['an input count of 1e9 (the per-field cap)', pyLine(syncRow({ in: 1_000_000_000 })).trimEnd(), 'bad_tokens'],
    ['an output count of 4e14 (BE-2 p3)', pyLine(syncRow({ out: 400_000_000_000_000 })).trimEnd(), 'bad_tokens'],
    ['a cache count of 1e9', pyLine(batchRow({ cache_read_input_tokens: 1_000_000_000 })).trimEnd(), 'bad_tokens'],
    ['a cost in exponent form', pyLine(canaryHeadlessRow({ cost_usd_reported: '7.49821e-05' })).trimEnd(), 'bad_cost'],
    ['a negative cost', pyLine(canaryHeadlessRow({ cost_usd_reported: '-0.1' })).trimEnd(), 'bad_cost'],
    ['a cost with a leading space', pyLine(canaryHeadlessRow({ cost_usd_reported: ' 0.1' })).trimEnd(), 'bad_cost'],
    ['a cost with a trailing space', pyLine(canaryHeadlessRow({ cost_usd_reported: '0.1 ' })).trimEnd(), 'bad_cost'],
    ['a cost without the leading digit', pyLine(canaryHeadlessRow({ cost_usd_reported: '.1' })).trimEnd(), 'bad_cost'],
    ['a cost with a leading zero', pyLine(canaryHeadlessRow({ cost_usd_reported: '01.5' })).trimEnd(), 'bad_cost'],
    ['a cost ending in a point', pyLine(canaryHeadlessRow({ cost_usd_reported: '1.' })).trimEnd(), 'bad_cost'],
    ['an empty cost', pyLine(canaryHeadlessRow({ cost_usd_reported: '' })).trimEnd(), 'bad_cost'],
    ['a numeric cost', pyLine(canaryHeadlessRow({ cost_usd_reported: 0.1 })).trimEnd(), 'bad_cost'],
    ['a null cost', pyLine(canaryHeadlessRow({ cost_usd_reported: null })).trimEnd(), 'bad_cost'],
    ['a cost above 100 000 USD', pyLine(canaryHeadlessRow({ cost_usd_reported: '100000.01' })).trimEnd(), 'bad_cost'],
    ['a cost on a batch row', pyLine(batchRow({ cost_usd_reported: '0.1' })).trimEnd(), 'bad_cost'],
  ]
  for (const [what, text, reason] of bad) {
    it(`rejects ${what} (${reason}), never skips it silently`, () => {
      expect(parseUsageLine(text)).toEqual({ ok: false, reason })
    })
  }
})

describe('usageDedupeKey', () => {
  it('changes with every component: source, dev, ino, offset and the line sha256', () => {
    const base = { source: 's', dev: '1', ino: '2', offset: 3, lineSha256: 'a'.repeat(64) }
    const k = usageDedupeKey(base)
    const variants = [
      { ...base, source: 't' },
      { ...base, dev: '9' },
      { ...base, ino: '9' },
      { ...base, offset: 4 },
      { ...base, lineSha256: 'b'.repeat(64) },
    ]
    const keys = new Set([k, ...variants.map(usageDedupeKey)])
    expect(keys.size).toBe(6)
  })
})

describe('refresh: reading usage.jsonl', () => {
  it('ingests synchronous and batch rows once, with the overestimate per row', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(syncRow({ model: 'claude-haiku-5-5', in: 22, out: 5 })) + pyLine(batchRow()))
    const l = ledger()
    const r = l.refresh(T0, table)
    expect(r.ingested).toBe(3)
    expect(r.sources).toEqual([{ id: 'anthropic-batch', status: 'ok', reason: null, ingested: 3, duplicates: 0 }])
    // Haiku 22 in + 5 out: 2.2 + 2.5 = 4.7 micro-USD, rounded up to 5.
    expect(entries().map((e) => e.est_micro)).toEqual([SONNET_1K_1K, 5, OPUS_BATCH])
    expect(entries().map((e) => e.cli_micro)).toEqual([null, null, null])
    expect(entries()[2]).toMatchObject({ batch_id: BATCH, custom_id: 'q-1', cache_write_tokens: 2815, source: 'anthropic-batch' })
    expect(entries()[0].priced_with).toBe('credit-pricing/v1@2026-10-16')
    expect(l.ledgerSum(0).l_micro).toBe(SONNET_1K_1K + 5 + OPUS_BATCH)
  })

  it('the same file read twice gives no new row', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(batchRow()))
    const l = ledger()
    expect(l.refresh(T0, table).ingested).toBe(2)
    const second = l.refresh(T0 + 30_000, table)
    expect(second.ingested).toBe(0)
    expect(entries()).toHaveLength(2)
    expect(cursor()).toMatchObject({ status: 'ok', offset: statSync(usagePath).size })
  })

  it('a fresh ledger object on the same database continues from the stored cursor', () => {
    writeFileSync(usagePath, pyLine(syncRow()))
    ledger().refresh(T0, table)
    appendFileSync(usagePath, pyLine(syncRow({ ts: TS + 1 })))
    expect(ledger().refresh(T0 + 30_000, table).ingested).toBe(1)
    expect(entries()).toHaveLength(2)
  })

  it('1000 rows appended in arbitrary pieces give exactly 1000 entries', () => {
    let content = ''
    for (let i = 0; i < 1000; i++) content += pyLine(syncRow({ ts: TS + i, in: 1000, out: 100 }))
    // Deterministic pseudo-random cut points, many of them inside a line.
    let seed = 12345
    const rnd = () => ((seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff)
    const l = ledger()
    let pos = 0
    let now = T0
    while (pos < content.length) {
      const n = 1 + Math.floor(rnd() * 400)
      appendFileSync(usagePath, content.slice(pos, pos + n))
      pos += n
      now += 1000
      const r = l.refresh(now, table)
      expect(r.sources[0].status).not.toBe('broken')
    }
    expect(entries()).toHaveLength(1000)
    // Sonnet 1000 in + 100 out: 2000 + 1000 = 3000 micro-USD a row.
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: 3_000_000, rows: 1000, unpriced: 0 })
    expect(cursor()).toMatchObject({ status: 'ok', offset: Buffer.byteLength(content) })
  })

  it('two byte-identical lines at different offsets are two requests', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(syncRow()))
    expect(ledger().refresh(T0, table).ingested).toBe(2)
  })

  it('a half-written last line is not read and the cursor does not move past it', () => {
    const full = pyLine(syncRow()) + pyLine(syncRow({ ts: TS + 1 }))
    const third = pyLine(syncRow({ ts: TS + 2 }))
    writeFileSync(usagePath, full + third.slice(0, 20))
    const l = ledger()
    const r = l.refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'partial', ingested: 2 })
    expect(cursor()).toMatchObject({ status: 'partial', offset: Buffer.byteLength(full) })
    expect(entries()).toHaveLength(2)
    appendFileSync(usagePath, third.slice(20))
    const r2 = l.refresh(T0 + 30_000, table)
    expect(r2.sources[0]).toMatchObject({ status: 'ok', ingested: 1 })
    expect(entries()).toHaveLength(3)
  })

  it('a final line without its newline (complete JSON) is still partial', () => {
    writeFileSync(usagePath, pyLine(syncRow()).trimEnd())
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'partial', ingested: 0 })
    expect(entries()).toHaveLength(0)
  })

  it('a partial line is broken only after MORE than 120 s', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + '{"ts": 1')
    const l = ledger()
    expect(l.refresh(T0, table).sources[0].status).toBe('partial')
    expect(l.refresh(T0 + 60_000, table).sources[0].status).toBe('partial')
    expect(l.refresh(T0 + 120_000, table).sources[0].status).toBe('partial')
    const r = l.refresh(T0 + 120_001, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'partial_timeout' })
    expect(r.broken).toEqual(['anthropic-batch'])
  })

  it('broken stays broken when the damage goes away (HOLD clears only through a reset)', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + '{"ts": 1')
    const l = ledger()
    l.refresh(T0, table)
    expect(l.refresh(T0 + 120_001, table).sources[0].reason).toBe('partial_timeout')
    // The writer finally finishes the line: still broken, nothing read.
    appendFileSync(usagePath, ', "month": "2026-10", "caller": "c", "model": "claude-sonnet-5-5", "in": 1, "out": 1}\n')
    expect(l.refresh(T0 + 150_000, table).sources[0]).toMatchObject({ status: 'broken', reason: 'partial_timeout', ingested: 0 })
    expect(entries()).toHaveLength(1)
    l.resetSource('anthropic-batch')
    expect(l.refresh(T0 + 180_000, table).sources[0]).toMatchObject({ status: 'ok', ingested: 1, duplicates: 1 })
  })

  it('a missing file that appears later stays broken until reset', () => {
    const l = ledger()
    expect(l.refresh(T0, table).sources[0].reason).toBe('missing')
    writeFileSync(usagePath, pyLine(syncRow()))
    expect(l.refresh(T0 + 30_000, table).sources[0]).toMatchObject({ status: 'broken', reason: 'missing', ingested: 0 })
    expect(l.ageS(T0 + 30_000)).toBeNull()
    l.resetSource('anthropic-batch')
    expect(l.refresh(T0 + 60_000, table).sources[0]).toMatchObject({ status: 'ok', ingested: 1 })
  })

  it('the partial clock restarts when the cursor moves on', () => {
    const l = ledger()
    writeFileSync(usagePath, pyLine(syncRow()) + '{"ts": 1')
    l.refresh(T0, table)
    // At +100 s the partial line is completed and a NEW partial line starts.
    appendFileSync(usagePath, ', "month": "2026-10", "caller": "c", "model": "claude-sonnet-5-5", "in": 1, "out": 1}\n{"ts": 2')
    expect(l.refresh(T0 + 100_000, table).sources[0]).toMatchObject({ status: 'partial', ingested: 1 })
    // 150 s after the first partial line, but only 50 s after the second one.
    expect(l.refresh(T0 + 150_000, table).sources[0].status).toBe('partial')
    expect(l.refresh(T0 + 220_001, table).sources[0]).toMatchObject({ status: 'broken', reason: 'partial_timeout' })
  })

  it('a truncated file (smaller than the cursor) is broken', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(syncRow({ ts: TS + 1 })) + pyLine(syncRow({ ts: TS + 2 })))
    const l = ledger()
    l.refresh(T0, table)
    truncateSync(usagePath, Buffer.byteLength(pyLine(syncRow())))
    const r = l.refresh(T0 + 30_000, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'truncated' })
  })

  it('a file replaced by another inode (rotation, copy-and-rename) is broken', () => {
    const content = pyLine(syncRow()) + pyLine(syncRow({ ts: TS + 1 }))
    writeFileSync(usagePath, content)
    const l = ledger()
    l.refresh(T0, table)
    const other = join(dir, 'usage.jsonl.new')
    writeFileSync(other, content + pyLine(syncRow({ ts: TS + 2 })))
    renameSync(other, usagePath)
    const r = l.refresh(T0 + 30_000, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'replaced' })
    expect(entries()).toHaveLength(2)
  })

  it('an in-place rewrite of the already-read tail is broken', () => {
    writeFileSync(usagePath, pyLine(syncRow({ in: 1000 })) + pyLine(syncRow({ ts: TS + 1 })))
    const l = ledger()
    l.refresh(T0, table)
    // Same length, same inode, different bytes: "1000" -> "9000".
    const text = readFileSync(usagePath, 'utf8')
    const at = text.indexOf('"in": 1000') + '"in": '.length
    const fd = openSync(usagePath, 'r+')
    writeSync(fd, '9', at)
    closeSync(fd)
    appendFileSync(usagePath, pyLine(syncRow({ ts: TS + 2 })))
    const r = l.refresh(T0 + 30_000, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'rewritten' })
    expect(entries()).toHaveLength(2)
  })

  it('a symlink in place of the file is broken (O_NOFOLLOW, like the writer)', () => {
    const real = join(dir, 'real.jsonl')
    writeFileSync(real, pyLine(syncRow()))
    symlinkSync(real, usagePath)
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'symlink' })
    expect(entries()).toHaveLength(0)
  })

  it('a missing file is broken, not an empty ledger', () => {
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'missing' })
  })

  it('a directory in place of the file is broken', () => {
    mkdirSync(usagePath)
    expect(ledger().refresh(T0, table).sources[0]).toMatchObject({ status: 'broken', reason: 'not_regular' })
  })

  it('a file above the size limit is broken', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(syncRow()))
    const r = ledger({ maxFileBytes: 100 }).refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'too_large' })
  })

  it('a line that is not UTF-8 is broken', () => {
    writeFileSync(usagePath, Buffer.concat([Buffer.from(pyLine(syncRow())), Buffer.from([0xff, 0xfe, 0x0a])]))
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'invalid_utf8', ingested: 1 })
  })

  const corrupt: Array<[string, string, string]> = [
    ['an unparseable JSON line', '{"ts": 17916', 'invalid_json'],
    ['a negative token count', pyLine(syncRow({ out: -3 })).trimEnd(), 'bad_tokens'],
    ['a row without model', pyLine((({ model: _m, ...r }) => r)(syncRow())).trimEnd(), 'bad_model'],
  ]
  for (const [what, line, reason] of corrupt) {
    it(`${what} makes the source broken (${reason}); the rows before it stay, nothing after it is read`, () => {
      const first = pyLine(syncRow())
      writeFileSync(usagePath, first + line + '\n' + pyLine(syncRow({ ts: TS + 5 })))
      const l = ledger()
      const r = l.refresh(T0, table)
      expect(r.sources[0]).toMatchObject({ status: 'broken', reason, ingested: 1 })
      expect(cursor()).toMatchObject({ status: 'broken', offset: Buffer.byteLength(first) })
      // Broken is sticky: later valid rows are not read until the source is reset.
      appendFileSync(usagePath, pyLine(syncRow({ ts: TS + 6 })))
      const r2 = l.refresh(T0 + 30_000, table)
      expect(r2.sources[0]).toMatchObject({ status: 'broken', reason, ingested: 0 })
      expect(entries()).toHaveLength(1)
    })
  }

  it('a model without a price is ingested with est NULL and raises the A-02 signal', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(syncRow({ model: 'claude-mystery-9' })))
    const l = ledger()
    const r = l.refresh(T0, table)
    expect(r.ingested).toBe(2)
    expect(r.unpriced_models).toEqual(['claude-mystery-9'])
    expect(entries()[1]).toMatchObject({ model: 'claude-mystery-9', est_micro: null, priced_with: null })
    const sum = l.ledgerSum(0)
    expect(sum).toEqual({ l_micro: SONNET_1K_1K, rows: 2, unpriced: 1, unpriced_models: ['claude-mystery-9'], saturated: false })
  })

  it('without a price table every row is unpriced, and a later refresh with a table prices it', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(batchRow()))
    const l = ledger()
    const r = l.refresh(T0, null)
    expect(r.unpriced_models).toEqual(['claude-opus-5-5', 'claude-sonnet-5-5'])
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: 0, unpriced: 2 })
    const r2 = l.refresh(T0 + 30_000, table)
    expect(r2.repriced).toBe(2)
    expect(r2.unpriced_models).toEqual([])
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: SONNET_1K_1K + OPUS_BATCH, unpriced: 0 })
  })

  it('a batch row duplicated in the log (same batch_id + custom_id) counts once', () => {
    writeFileSync(usagePath, pyLine(batchRow()) + pyLine(batchRow({ ts: TS + 60, month: '2026-10' })))
    const l = ledger()
    const r = l.refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'ok', ingested: 1, duplicates: 1 })
    expect(l.ledgerSum(0).l_micro).toBe(OPUS_BATCH)
  })

  it('a batch duplicate in a SECOND source counts once too', () => {
    const other = join(dir, 'other.jsonl')
    writeFileSync(usagePath, pyLine(batchRow()))
    writeFileSync(other, pyLine(batchRow()))
    const l = ledger({
      sources: [
        { id: 'a', path: usagePath, format: 'usage-jsonl-v1' },
        { id: 'b', path: other, format: 'usage-jsonl-v1' },
      ],
    })
    const r = l.refresh(T0, table)
    expect(r.ingested).toBe(1)
    expect(entries()).toHaveLength(1)
  })

  it('rows of the same batch with different custom_ids are separate requests', () => {
    writeFileSync(usagePath, pyLine(batchRow({ custom_id: 'q-1' })) + pyLine(batchRow({ custom_id: 'q-2' })))
    const l = ledger()
    expect(l.refresh(T0, table).ingested).toBe(2)
    expect(l.ingestedForBatch(BATCH)).toEqual({ l_micro: 2 * OPUS_BATCH, count: 2, unpriced: 0, saturated: false })
  })

  it('a conflicting batch duplicate (same ids, other tokens) is broken', () => {
    writeFileSync(usagePath, pyLine(batchRow()) + pyLine(batchRow({ out: 4334 })))
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'batch_conflict', ingested: 1 })
  })

  it('the same batch request with another cache WRITE count is a conflict, not a duplicate', () => {
    writeFileSync(usagePath, pyLine(batchRow()) + pyLine(batchRow({ cache_creation_input_tokens: 2816 })))
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'batch_conflict', ingested: 1, duplicates: 0 })
  })

  it('the same batch request with another cache READ count is a conflict, not a duplicate', () => {
    writeFileSync(usagePath, pyLine(batchRow()) + pyLine(batchRow({ cache_read_input_tokens: 1 })))
    const r = ledger().refresh(T0, table)
    expect(r.sources[0]).toMatchObject({ status: 'broken', reason: 'batch_conflict', ingested: 1, duplicates: 0 })
  })

  it('the real canary rows are booked with est AND cli; L takes the larger per row', () => {
    writeFileSync(usagePath,
      pyLine(canaryHeadlessRow())
      + pyLine(canaryHeadlessRow({ ts: TS + 1, in: 1, out: 1, cache_creation_input_tokens: 0, cache_read_input_tokens: 0, cost_usd_reported: '0.1' }))
      + pyLine(syncRow({ ts: TS + 2, caller: 'ezermester-kanari-messages', in: 100, out: 50 })))
    const l = ledger()
    expect(l.refresh(T0, table).ingested).toBe(3)
    // Row 1: 8 x 2 + 647 x 10 + 26 368 x 4 (1h cache write) + 25 761 x 0.10 = 114 534.1 -> 114 535.
    // The CLI's 0.0749821 is the same row at the 5-minute cache-write price
    // (26 368 x 2.50): est > cli, the overestimate wins. Row 2: est 12, cli 100 000.
    expect(entries().map((e) => [e.est_micro, e.cli_micro])).toEqual([[114_535, 74_983], [12, 100_000], [700, null]])
    expect(l.ledgerSum(0).l_micro).toBe(114_535 + 100_000 + 700)
    expect(l.refresh(T0 + 30_000, table).ingested).toBe(0)
  })

  it('an out-of-range usage row breaks the source and ledgerSum does not throw (BE-2 p3 c)', () => {
    const big = pyLine(syncRow({ model: 'claude-opus-5-5', in: 0, out: 400_000_000_000_000 }))
    writeFileSync(usagePath, big + big)
    const l = ledger()
    expect(l.refresh(T0, table).sources[0]).toMatchObject({ status: 'broken', reason: 'bad_tokens', ingested: 0 })
    expect(() => l.ledgerSum(T0 - 3_600_000)).not.toThrow()
  })

  it('a FIFO in place of usage.jsonl is broken (not_regular) at once; the open does not block', () => {
    execFileSync('mkfifo', [usagePath])
    const res = inChild([
      `import { createRequire } from 'node:module'`,
      `import { applyLedgerSchema } from ${JSON.stringify(join(REPO, 'src/web/credit-gate/schema-ledger.ts'))}`,
      `import { CreditLedger } from ${JSON.stringify(join(REPO, 'src/web/credit-gate/ledger.ts'))}`,
      `const Database = createRequire(${JSON.stringify(join(REPO, 'package.json'))})('better-sqlite3')`,
      `const db = new Database(':memory:')`,
      `applyLedgerSchema(db)`,
      `const l = new CreditLedger(db, { sources: [{ id: 'u', path: ${JSON.stringify(usagePath)}, format: 'usage-jsonl-v1' }] })`,
      `const t0 = Date.now()`,
      `const r = l.refresh(${T0}, null)`,
      `console.log(JSON.stringify({ value: r.sources[0], ms: Date.now() - t0 }))`,
    ])
    expect(res.value).toMatchObject({ status: 'broken', reason: 'not_regular' })
    expect(res.ms).toBeLessThan(1000)
  })

  it('the two canary callers are read like every other row, exactly once', () => {
    writeFileSync(usagePath,
      pyLine(syncRow({ caller: 'ezermester-kanari-messages', in: 100, out: 50 }))
      + pyLine(syncRow({
        caller: 'ezermester-kanari-headless', in: 10, out: 200,
        cache_creation_input_tokens: 5000, cache_read_input_tokens: 20000,
      })))
    const l = ledger()
    expect(l.refresh(T0, table).ingested).toBe(2)
    expect(l.refresh(T0 + 30_000, table).ingested).toBe(0)
    expect(l.resetSource('anthropic-batch')).toBe(true)
    expect(l.refresh(T0 + 60_000, table).ingested).toBe(0)
    // 100 x 2 + 50 x 10 = 700; 10 x 2 + 200 x 10 + 5000 x 4 + 20000 x 0.10 = 24 020.
    expect(entries().map((e) => [e.est_micro, e.batch_id])).toEqual([[700, null], [24_020, null]])
    expect(l.ledgerSum(0).l_micro).toBe(24_720)
  })

  it('after a reset the same bytes are not ingested again (dedupe key), and the source is ok again', () => {
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(batchRow()))
    const l = ledger()
    l.refresh(T0, table)
    truncateSync(usagePath, 10)
    expect(l.refresh(T0 + 30_000, table).sources[0].status).toBe('broken')
    writeFileSync(usagePath, pyLine(syncRow()) + pyLine(batchRow()))
    expect(l.resetSource('anthropic-batch')).toBe(true)
    const r = l.refresh(T0 + 60_000, table)
    expect(r.sources[0]).toMatchObject({ status: 'ok', ingested: 0, duplicates: 2 })
    expect(entries()).toHaveLength(2)
  })

  it('after a reset a line rewritten at the same offset is a new row (the line sha256 is in the key)', () => {
    writeFileSync(usagePath, pyLine(syncRow({ in: 1000 })))
    const l = ledger()
    l.refresh(T0, table)
    const fd = openSync(usagePath, 'r+')
    writeSync(fd, '9', readFileSync(usagePath, 'utf8').indexOf('"in": 1000') + '"in": '.length)
    closeSync(fd)
    expect(l.refresh(T0 + 30_000, table).sources[0].reason).toBe('rewritten')
    l.resetSource('anthropic-batch')
    expect(l.refresh(T0 + 60_000, table).ingested).toBe(1)
    expect(entries().map((e) => e.input_tokens)).toEqual([1000, 9000])
  })

  it('resetSource of an unknown or never-read source is false', () => {
    const l = ledger()
    expect(l.resetSource('nope')).toBe(false)
    expect(l.resetSource('anthropic-batch')).toBe(false)
  })

  it('rejects the reserved source id of headless rows', () => {
    expect(() => ledger({ sources: [{ id: 'headless', path: usagePath, format: 'usage-jsonl-v1' }] })).toThrow()
  })

  it('rejects an unsupported format, a relative path and a duplicated source id', () => {
    expect(() => ledger({ sources: [{ id: 'a', path: usagePath, format: 'csv' as 'usage-jsonl-v1' }] })).toThrow()
    expect(() => ledger({ sources: [{ id: 'a', path: 'usage.jsonl', format: 'usage-jsonl-v1' }] })).toThrow()
    expect(() => ledger({
      sources: [
        { id: 'a', path: usagePath, format: 'usage-jsonl-v1' },
        { id: 'a', path: join(dir, 'x'), format: 'usage-jsonl-v1' },
      ],
    })).toThrow()
  })
})

describe('ledgerSum: L(t) from captured_at_lb', () => {
  it('counts the row ON the boundary second and not the one before it', () => {
    const lbS = TS
    writeFileSync(usagePath,
      pyLine(syncRow({ ts: lbS - 1, in: 1, out: 0 })) // 2 micro-USD
      + pyLine(syncRow({ ts: lbS, in: 10, out: 0 })) // 20
      + pyLine(syncRow({ ts: lbS + 1, in: 100, out: 0 }))) // 200
    const l = ledger()
    l.refresh(T0, table)
    expect(l.ledgerSum(lbS * 1000)).toMatchObject({ l_micro: 220, rows: 2 })
    expect(l.ledgerSum(lbS * 1000 + 1000)).toMatchObject({ l_micro: 200, rows: 1 })
    expect(l.ledgerSum(lbS * 1000 - 1000)).toMatchObject({ l_micro: 222, rows: 3 })
  })

  it('a boundary inside a second still counts the row of that second (the writer truncates to whole seconds)', () => {
    writeFileSync(usagePath, pyLine(syncRow({ ts: TS, in: 10, out: 0 })))
    const l = ledger()
    l.refresh(T0, table)
    expect(l.ledgerSum(TS * 1000 + 999).l_micro).toBe(20)
  })

  it('an empty ledger sums to zero', () => {
    expect(ledger().ledgerSum(0)).toEqual({ l_micro: 0, rows: 0, unpriced: 0, unpriced_models: [], saturated: false })
  })

  function rawRow(key: string, est: number | bigint, batch: string | null = null) {
    db.prepare(`INSERT INTO credit_ledger_entries (source, dedupe_key, ts, model, input_tokens, output_tokens,
      cache_write_tokens, cache_read_tokens, batch_id, custom_id, est_micro, basis, ingested_at)
      VALUES ('x', ?, ?, 'claude-opus-5-5', 0, 0, 0, 0, ?, ?, ?, 'usage', 1)`).run(key, TS, batch, batch ? key : null, est)
  }

  it('saturates at 100 000 USD instead of throwing when the sum leaves the safe range', () => {
    for (const k of ['a', 'b', 'c']) rawRow(k, 4_000_000_000_000_000) // 3 x 4e15 > 2^53
    const l = ledger()
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: MAX_USD_AMOUNT_MICRO, rows: 3, saturated: true })
  })

  it('saturates instead of throwing when the sum leaves even SQLite\'s 64-bit range', () => {
    for (const k of ['a', 'b', 'c']) rawRow(k, 4_000_000_000_000_000_000n) // 3 x 4e18 > 2^63
    const l = ledger()
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: MAX_USD_AMOUNT_MICRO, saturated: true })
  })

  it('a sum just above 100 000 USD is saturated, a sum at it is not', () => {
    rawRow('a', MAX_USD_AMOUNT_MICRO)
    expect(ledger().ledgerSum(0)).toMatchObject({ l_micro: MAX_USD_AMOUNT_MICRO, saturated: false })
    rawRow('b', 1)
    expect(ledger().ledgerSum(0)).toMatchObject({ l_micro: MAX_USD_AMOUNT_MICRO, saturated: true })
  })

  it('ingestedForBatch saturates too', () => {
    for (const k of ['a', 'b', 'c']) rawRow(k, 4_000_000_000_000_000, BATCH)
    expect(ledger().ingestedForBatch(BATCH)).toMatchObject({ l_micro: MAX_USD_AMOUNT_MICRO, count: 3, saturated: true })
  })
})

describe('ageS', () => {
  it('is null before the first successful read, then the time since the last complete read', () => {
    writeFileSync(usagePath, pyLine(syncRow()))
    const l = ledger()
    expect(l.ageS(T0)).toBeNull()
    l.refresh(T0, table)
    expect(l.ageS(T0 + 30_000)).toBe(30)
    l.refresh(T0 + 60_000, table)
    expect(l.ageS(T0 + 90_500)).toBe(30.5)
  })

  it('a broken source stops refreshing the age, so it grows past 120 s', () => {
    writeFileSync(usagePath, pyLine(syncRow()))
    const l = ledger()
    l.refresh(T0, table)
    truncateSync(usagePath, 3)
    l.refresh(T0 + 30_000, table)
    expect(l.ageS(T0 + 121_000)).toBe(121)
  })

  it('takes the OLDEST source, and a source never read makes it null', () => {
    const other = join(dir, 'other.jsonl')
    writeFileSync(usagePath, pyLine(syncRow()))
    const l = ledger({
      sources: [
        { id: 'a', path: usagePath, format: 'usage-jsonl-v1' },
        { id: 'b', path: other, format: 'usage-jsonl-v1' },
      ],
    })
    l.refresh(T0, table) // b is missing -> broken, never checked
    expect(l.ageS(T0 + 1000)).toBeNull()
    writeFileSync(other, pyLine(syncRow({ ts: TS + 9 })))
    l.resetSource('b')
    l.refresh(T0 + 10_000, table)
    writeFileSync(other, 'garbage that is not the old file at all\n')
    l.refresh(T0 + 40_000, table) // b broken again, last good read at T0 + 10 s
    expect(l.ageS(T0 + 50_000)).toBe(40)
  })
})

describe('recordHeadless', () => {
  const base = (over: Partial<HeadlessRun> = {}): HeadlessRun => ({
    run_id: 'run-1',
    ended_at_s: TS,
    model: 'claude-sonnet-5-5',
    reservation_micro: asMicro(7_500_000),
    result: null,
    transcript_dir: null,
    ...over,
  })
  const sonnetUsage = { model: 'claude-sonnet-5-5', input_tokens: 1000, output_tokens: 1000, cache_write_tokens: 0, cache_read_tokens: 0 }

  it('a run with its JSON result keeps est and cli apart; L takes the larger (cli larger)', () => {
    const l = ledger()
    const r = l.recordHeadless(base({ result: { total_cost_usd: 0.5, usage: [sonnetUsage] } }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_json', est_micro: SONNET_1K_1K, cli_micro: 500_000 })
    expect(entries()[0]).toMatchObject({ source: 'headless', run_id: 'run-1', est_micro: SONNET_1K_1K, cli_micro: 500_000, ts: TS })
    expect(l.ledgerSum(0).l_micro).toBe(500_000)
  })

  it('L takes the larger (est larger)', () => {
    const l = ledger()
    l.recordHeadless(base({ result: { total_cost_usd: 0.001, usage: [sonnetUsage] } }), table, T0)
    expect(l.ledgerSum(0).l_micro).toBe(SONNET_1K_1K)
  })

  it('L = max(est, cli) row by row, not max of the sums', () => {
    const l = ledger()
    l.recordHeadless(base({ run_id: 'a', result: { total_cost_usd: 0.5, usage: [sonnetUsage] } }), table, T0)
    l.recordHeadless(base({ run_id: 'b', result: { total_cost_usd: 0.001, usage: [sonnetUsage] } }), table, T0)
    expect(l.ledgerSum(0).l_micro).toBe(500_000 + SONNET_1K_1K)
  })

  it('the same run recorded twice is one row (first record wins)', () => {
    const l = ledger()
    expect(l.recordHeadless(base({ result: { total_cost_usd: 0.5, usage: [sonnetUsage] } }), table, T0).inserted).toBe(true)
    expect(l.recordHeadless(base({ result: { total_cost_usd: 9, usage: [sonnetUsage] } }), table, T0).inserted).toBe(false)
    expect(entries()).toHaveLength(1)
    expect(l.ledgerSum(0).l_micro).toBe(500_000)
  })

  it('a JSON result with a model without a price: est NULL, cli counts, A-02 signal', () => {
    const l = ledger()
    const r = l.recordHeadless(base({
      result: { total_cost_usd: 0.25, usage: [sonnetUsage, { ...sonnetUsage, model: 'claude-mystery-9' }] },
    }), table, T0)
    expect(r).toMatchObject({ est_micro: null, cli_micro: 250_000 })
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: 250_000, unpriced: 1, unpriced_models: ['claude-mystery-9'] })
  })

  it('a JSON result without a usable total_cost_usd keeps cli NULL and L = est', () => {
    const l = ledger()
    const r = l.recordHeadless(base({ result: { total_cost_usd: null, usage: [sonnetUsage] } }), table, T0)
    expect(r).toMatchObject({ basis: 'headless_json', est_micro: SONNET_1K_1K, cli_micro: null })
    expect(l.ledgerSum(0).l_micro).toBe(SONNET_1K_1K)
  })

  it('a JSON result with no cost and no usage is a MISSING result: the full reservation', () => {
    const l = ledger()
    const r = l.recordHeadless(base({ result: { total_cost_usd: null, usage: [] } }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_reservation', est_micro: 7_500_000, cli_micro: null })
    expect(l.ledgerSum(0).l_micro).toBe(7_500_000)
  })

  it('a JSON result with no cost and all-zero usage is a MISSING result: the full reservation', () => {
    const zero = { ...sonnetUsage, input_tokens: 0, output_tokens: 0 }
    const r = ledger().recordHeadless(base({ result: { total_cost_usd: null, usage: [zero] } }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_reservation', est_micro: 7_500_000, cli_micro: null })
  })

  it('a JSON result with an unusable cost and no usage is a MISSING result too', () => {
    for (const [i, cost] of [-1, Number.NaN].entries()) {
      const r = ledger().recordHeadless(base({ run_id: `bad-${i}`, result: { total_cost_usd: cost, usage: [] } }), table, T0)
      expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000 })
    }
  })

  it('an empty JSON result falls back to the transcript first, the reservation only after it', () => {
    const root = join(dir, 'run', 'config', 'projects', '-wt')
    mkdirSync(root, { recursive: true })
    writeFileSync(join(root, 's.jsonl'),
      JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 1000, output_tokens: 1000 } } }) + '\n')
    const r = ledger().recordHeadless(base({
      result: { total_cost_usd: null, usage: [] },
      transcript_dir: join(dir, 'run', 'config', 'projects'),
    }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_transcript', est_micro: SONNET_1K_1K, cli_micro: null })
  })

  it('a JSON result with a valid cost of 0 and no usage is a real result (the CLI says: nothing spent)', () => {
    const r = ledger().recordHeadless(base({ result: { total_cost_usd: 0, usage: [] } }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_json', est_micro: 0, cli_micro: 0 })
  })

  it('an invalid JSON usage (negative tokens) falls back like a missing result', () => {
    const l = ledger()
    const r = l.recordHeadless(base({ result: { total_cost_usd: 0.1, usage: [{ ...sonnetUsage, output_tokens: -1 }] } }), table, T0)
    expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000, cli_micro: null })
  })

  function writeTranscript(lines: string[], rel = join('projects', '-wt', 'session-1.jsonl')): string {
    const root = join(dir, 'run', 'config')
    const file = join(root, rel)
    mkdirSync(join(file, '..'), { recursive: true })
    writeFileSync(file, lines.join(''))
    return join(root, 'projects')
  }
  const asst = (id: string | null, model: string, u: Record<string, number>) =>
    JSON.stringify({
      type: 'assistant',
      timestamp: '2026-10-16T07:00:00.000Z',
      message: { ...(id ? { id } : {}), model, role: 'assistant', content: [], usage: u },
    }) + '\n'

  it('without JSON: the transcript, each message id once; zero-usage synthetic lines ignored', () => {
    const projects = writeTranscript([
      JSON.stringify({ type: 'user', message: { role: 'user', content: 'x' } }) + '\n',
      // One tool-calling turn written as two lines with the same id and the same usage.
      asst('msg_A', 'claude-sonnet-5-5', { input_tokens: 1000, output_tokens: 100, cache_creation_input_tokens: 2000, cache_read_input_tokens: 0 }),
      asst('msg_A', 'claude-sonnet-5-5', { input_tokens: 1000, output_tokens: 100, cache_creation_input_tokens: 2000, cache_read_input_tokens: 0 }),
      asst('msg_B', 'claude-sonnet-5-5', { input_tokens: 10, output_tokens: 500, cache_read_input_tokens: 3000 }),
      asst(null, '<synthetic>', { input_tokens: 0, output_tokens: 0 }),
    ])
    // A sub-agent transcript one level down.
    const sub = join(projects, '-wt', 'session-1', 'subagents')
    mkdirSync(sub, { recursive: true })
    writeFileSync(join(sub, 'agent-1.jsonl'), asst('msg_C', 'claude-haiku-5-5', { input_tokens: 100, output_tokens: 100 }))
    const l = ledger()
    const r = l.recordHeadless(base({ transcript_dir: projects }), table, T0)
    // msg_A: 1000 x 2 + 100 x 10 + 2000 x 4 = 11 000; msg_B: 20 + 5000 + 300 = 5320;
    // msg_C: 100 x 0.10 + 100 x 0.50 = 60.
    expect(r).toEqual({ inserted: true, basis: 'headless_transcript', est_micro: 16_380, cli_micro: null })
    expect(l.ledgerSum(0).l_micro).toBe(16_380)
  })

  it('without JSON and without a transcript: the full reservation is spent', () => {
    const l = ledger()
    const r = l.recordHeadless(base({ transcript_dir: join(dir, 'no-such-dir') }), table, T0)
    expect(r).toEqual({ inserted: true, basis: 'headless_reservation', est_micro: 7_500_000, cli_micro: null })
    expect(l.ledgerSum(0).l_micro).toBe(7_500_000)
    expect(entries()[0]).toMatchObject({ basis: 'headless_reservation', priced_with: null })
  })

  it('a transcript with no usage line counts as no transcript (the request in flight is unknown)', () => {
    const projects = writeTranscript([JSON.stringify({ type: 'user', message: { role: 'user', content: 'x' } }) + '\n'])
    const r = ledger().recordHeadless(base({ transcript_dir: projects }), table, T0)
    expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000 })
  })

  it('a damaged transcript (bad JSON or a half-written last line) falls back to the reservation', () => {
    const good = asst('msg_A', 'claude-sonnet-5-5', { input_tokens: 1, output_tokens: 1 })
    const p1 = writeTranscript([good, '{"type": "assist\n'])
    expect(ledger().recordHeadless(base({ run_id: 'r1', transcript_dir: p1 }), table, T0).basis).toBe('headless_reservation')
    rmSync(join(dir, 'run'), { recursive: true, force: true })
    const p2 = writeTranscript([good, good.slice(0, 30)])
    expect(ledger().recordHeadless(base({ run_id: 'r2', transcript_dir: p2 }), table, T0).basis).toBe('headless_reservation')
  })

  it('a JSON usage entry above the per-field cap is not a result: no throw, the reservation (BE-2 p3 a)', () => {
    const big = { model: 'claude-opus-5-5', input_tokens: 0, output_tokens: 250_000_000_000_000, cache_write_tokens: 0, cache_read_tokens: 0 }
    const l = ledger()
    let r: unknown
    expect(() => { r = l.recordHeadless(base({ result: { total_cost_usd: null, usage: [big, { ...big }] } }), table, T0) }).not.toThrow()
    expect(r).toMatchObject({ inserted: true, basis: 'headless_reservation', est_micro: 7_500_000 })
  })

  it('a JSON usage entry AT the per-field cap (1e9) is not a result even when its sum is small', () => {
    const at = { ...sonnetUsage, input_tokens: 0, output_tokens: 1_000_000_000 }
    const r = ledger().recordHeadless(base({ result: { total_cost_usd: null, usage: [at] } }), table, T0)
    expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000 })
    // Just below the cap it is a result: 999 999 999 x 10 USD/MTok = 9 999 999 990 micro-USD.
    const below = { ...sonnetUsage, input_tokens: 0, output_tokens: 999_999_999 }
    const r2 = ledger().recordHeadless(base({ run_id: 'run-2', result: { total_cost_usd: null, usage: [below] } }), table, T0)
    expect(r2).toMatchObject({ basis: 'headless_json', est_micro: 9_999_999_990 })
  })

  it('a transcript count above the per-field cap: no throw, the reservation (BE-2 p3 b)', () => {
    const big = JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-opus-5-5', usage: { input_tokens: 0, output_tokens: 250_000_000_000_000 } } }) + '\n'
    const projects = writeTranscript([big, big.replace('"m1"', '"m2"')])
    const l = ledger()
    let r: unknown
    expect(() => { r = l.recordHeadless(base({ transcript_dir: projects }), table, T0) }).not.toThrow()
    expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000 })
  })

  it('a JSON result whose estimate leaves the safe range is not a result: no throw, the reservation', () => {
    // 1000 USD/MTok: each entry ~2e12 micro-USD, 5000 entries ~1e16 > 2^53.
    const pr = loadPricing(PRICING_TEXT.replace('"ids": ["claude-opus-5-5"], "input": "4.00", "output": "20.00"',
      '"ids": ["claude-opus-5-5"], "input": "1000.00", "output": "1000.00"'), T0)
    if (!pr.ok) throw new Error(pr.detail)
    const e = { model: 'claude-opus-5-5', input_tokens: 999_999_999, output_tokens: 999_999_999, cache_write_tokens: 0, cache_read_tokens: 0 }
    const l = ledger()
    let r: unknown
    expect(() => { r = l.recordHeadless(base({ result: { total_cost_usd: null, usage: Array.from({ length: 5000 }, () => e) } }), pr.table, T0) }).not.toThrow()
    expect(r).toMatchObject({ basis: 'headless_reservation', est_micro: 7_500_000 })
  })

  it('a transcript with an escaped duplicate key falls back to the reservation', () => {
    const projects = writeTranscript([
      '{"type": "assistant", "message": {"id": "m1", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 1000, "output_tokens": 5000, "\\u006futput_tokens": 1}}}\n',
    ])
    expect(ledger().recordHeadless(base({ transcript_dir: projects }), table, T0)).toMatchObject({ basis: 'headless_reservation' })
  })

  it('rejects a malformed run record (programming error, not data)', () => {
    const l = ledger()
    expect(() => l.recordHeadless(base({ run_id: '' }), table, T0)).toThrow()
    expect(() => l.recordHeadless(base({ run_id: 'a b' }), table, T0)).toThrow()
    expect(() => l.recordHeadless(base({ ended_at_s: 1.5 }), table, T0)).toThrow()
    expect(() => l.recordHeadless(base({ reservation_micro: -1 as never }), table, T0)).toThrow()
    expect(() => l.recordHeadless(base({ transcript_dir: 'run/config/projects' }), table, T0)).toThrow()
    expect(entries()).toHaveLength(0)
  })

  it('headless rows do not collide with usage rows and both count', () => {
    writeFileSync(usagePath, pyLine(syncRow()))
    const l = ledger()
    l.refresh(T0, table)
    l.recordHeadless(base(), table, T0)
    expect(l.ledgerSum(0)).toMatchObject({ l_micro: SONNET_1K_1K + 7_500_000, rows: 2 })
  })
})

describe('readTranscriptUsage', () => {
  it('collapses the lines of one message id by the max of each field', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    writeFileSync(join(root, 's.jsonl'),
      JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 5, output_tokens: 1 } } }) + '\n'
      + JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 5, output_tokens: 9, cache_read_input_tokens: 2 } } }) + '\n')
    const r = readTranscriptUsage(root)
    expect(r).toEqual({
      ok: true,
      messages: [{ model: 'claude-sonnet-5-5', input_tokens: 5, output_tokens: 9, cache_write_tokens: 0, cache_read_tokens: 2 }],
    })
  })

  it('collapses by the max even when the LAST line of a message id is the smaller one', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    writeFileSync(join(root, 's.jsonl'),
      JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 7, output_tokens: 9, cache_creation_input_tokens: 3, cache_read_input_tokens: 4 } } }) + '\n'
      + JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 5, output_tokens: 1, cache_creation_input_tokens: 0, cache_read_input_tokens: 0 } } }) + '\n')
    expect(readTranscriptUsage(root)).toEqual({
      ok: true,
      messages: [{ model: 'claude-sonnet-5-5', input_tokens: 7, output_tokens: 9, cache_write_tokens: 3, cache_read_tokens: 4 }],
    })
  })

  it('a usage line without a model is unusable (the price is unknown)', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    writeFileSync(join(root, 's.jsonl'), JSON.stringify({ type: 'assistant', message: { id: 'm1', usage: { input_tokens: 5, output_tokens: 1 } } }) + '\n')
    expect(readTranscriptUsage(root)).toEqual({ ok: false, reason: 'bad_model' })
  })

  it('a symlink inside the transcript tree is unusable', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    writeFileSync(join(dir, 'elsewhere.jsonl'), '')
    symlinkSync(join(dir, 'elsewhere.jsonl'), join(root, 's.jsonl'))
    expect(readTranscriptUsage(root)).toEqual({ ok: false, reason: 'symlink' })
  })

  it('a duplicated key, plain or \\u-escaped, makes the transcript unusable', () => {
    const cases = [
      '{"type": "assistant", "message": {"id": "m1", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 5, "output_tokens": 900, "\\u006futput_tokens": 1}}}',
      '{"type": "assistant", "message": {"id": "m1", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 5, "output_tokens": 900, "output_tokens": 1}}}',
      // A second "type" would hide the whole assistant line from the parser.
      '{"type": "assistant", "message": {"id": "m1", "model": "claude-sonnet-5-5", "usage": {"input_tokens": 5, "output_tokens": 900}}, "\\u0074ype": "user"}',
    ]
    for (const [i, line] of cases.entries()) {
      const root = join(dir, `dup-${i}`)
      mkdirSync(root)
      writeFileSync(join(root, 's.jsonl'), line + '\n')
      expect(readTranscriptUsage(root)).toEqual({ ok: false, reason: 'duplicate_key' })
    }
  })

  it('a count at the per-field cap (1e9) makes the transcript unusable', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    writeFileSync(join(root, 's.jsonl'), JSON.stringify({ type: 'assistant', message: { id: 'm1', model: 'claude-sonnet-5-5', usage: { input_tokens: 1_000_000_000, output_tokens: 1 } } }) + '\n')
    expect(readTranscriptUsage(root)).toEqual({ ok: false, reason: 'bad_tokens' })
  })

  it('a FIFO named *.jsonl in the tree makes the transcript unusable at once; the open does not block', () => {
    const root = join(dir, 'p')
    mkdirSync(root)
    execFileSync('mkfifo', [join(root, 'a.jsonl')])
    const res = inChild([
      `import { readTranscriptUsage } from ${JSON.stringify(join(REPO, 'src/web/credit-gate/ledger-transcript.ts'))}`,
      `const t0 = Date.now()`,
      `const r = readTranscriptUsage(${JSON.stringify(root)})`,
      `console.log(JSON.stringify({ value: r, ms: Date.now() - t0 }))`,
    ])
    expect(res.value).toEqual({ ok: false, reason: 'not_regular' })
    expect(res.ms).toBeLessThan(1000)
  })

  it('a missing directory is unusable', () => {
    expect(readTranscriptUsage(join(dir, 'nope'))).toEqual({ ok: false, reason: 'missing' })
  })
})

describe('usdNumberToMicroCeil (the CLI total_cost_usd)', () => {
  const cases: Array<[unknown, number | null]> = [
    [0, 0],
    [0.5, 500_000],
    [2.5, 2_500_000],
    [0.0123451, 12_346],
    [0.012345, 12_345],
    [1e-7, 1],
    [1.23e-5, 13],
    [-0.01, null],
    [Number.NaN, null],
    [Number.POSITIVE_INFINITY, null],
    ['0.5', null],
    [null, null],
    [100_001, null],
  ]
  for (const [v, want] of cases) {
    it(`${String(v)} -> ${String(want)}`, () => {
      expect(usdNumberToMicroCeil(v)).toBe(want)
    })
  }
})
