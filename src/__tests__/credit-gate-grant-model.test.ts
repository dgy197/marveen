import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { parseCreditGateConfig, type CreditGateConfig, type GrantModelConfig } from '../web/credit-gate/config.js'
import {
  currentPeriod,
  grantModelHash,
  grantRemaining,
  priorCharge,
  readReconstructed,
} from '../web/credit-gate/grant-model.js'
import type { UsageRow } from '../web/credit-gate/ledger-usage-jsonl.js'
import { loadPricing } from '../web/credit-gate/pricing.js'
import type { Micro, PricingTable } from '../web/credit-gate/types.js'
import { configObject, pricingText, T0 } from './fixtures/credit-gate/gate-harness.js'

// Credit gate grant_model, node N1 (card 40e03382): the pure core -- the
// period, the prior charge, the hash, the reconstructed-file reader -- and the
// config branch. Written from the spec (2, 3, A5, A6) and the blueprint (N1),
// not from the code. Every file lives in this test's own mkdtemp; the real
// reconstructed file and the live store are never read.

const USD = 1_000_000
const Z = (s: string): number => Date.parse(s)
const sha = (text: string): string => createHash('sha256').update(text, 'utf8').digest('hex')

const GAP = { from: '2026-10-23T05:41:23Z', to: '2026-10-24T15:42:00Z', chargeUsd: '10.52' }

function reconstructedBlock(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { path: '/tmp/x/reconstructed.jsonl', sha256: 'b'.repeat(64), multiplier: '3', gap: { ...GAP }, ...over }
}

function grantBlock(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { grantUsd: '200.00', grantDays: [1, 15], boundaryLeadH: 24, reconstructed: reconstructedBlock(), ...over }
}

/** A full config object with calibrationSource grant_model and the given grantModel block. */
function cfgObject(grantModel: Record<string, unknown> | null = grantBlock(), over: Record<string, unknown> = {}) {
  const o: Record<string, unknown> = { ...configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP'), calibrationSource: 'grant_model' }
  if (grantModel !== null) o.grantModel = grantModel
  return { ...o, ...over }
}

function parse(o: unknown) {
  return parseCreditGateConfig(JSON.stringify(o))
}

function configOf(o: Record<string, unknown>): CreditGateConfig {
  const r = parse(o)
  if (!r.ok) throw new Error(`expected ok, got ${r.reason}: ${r.detail}`)
  return r.config
}

function gmOf(grantModel: Record<string, unknown> = grantBlock()): GrantModelConfig {
  const gm = configOf(cfgObject(grantModel)).grantModel
  if (gm === null) throw new Error('grantModel missing')
  return gm
}

function table(): PricingTable {
  const r = loadPricing(pricingText(), T0)
  if (!r.ok) throw new Error(`pricing: ${r.detail}`)
  return r.table
}

function row(tsMs: number, model: string, input: number, output: number, extra: Partial<UsageRow> = {}): UsageRow {
  return {
    ts: Math.floor(tsMs / 1000),
    caller: 'test',
    model,
    input_tokens: input,
    output_tokens: output,
    cache_write_tokens: 0,
    cache_read_tokens: 0,
    batch_id: null,
    custom_id: null,
    cli_micro: null,
    ...extra,
  }
}

/** One Sonnet 5.5 row of exactly 2.00 USD (1M input tokens at 2.00/MTok). */
const sonnet2 = (tsMs: number, extra: Partial<UsageRow> = {}): UsageRow => row(tsMs, 'claude-sonnet-5-5', 1_000_000, 0, extra)

describe('currentPeriod: the A5 date table (grant days 1 and 15)', () => {
  const iso = (ms: number): string => new Date(ms).toISOString().replace('.000Z', 'Z')
  const period = (lead: number, now: string, days: number[] = [1, 15]) => {
    const p = currentPeriod(gmOf(grantBlock({ boundaryLeadH: lead, grantDays: days })), Z(now))
    return [iso(p.lbMs), iso(p.expiresMs)]
  }

  it('lead 24: the earlier lb and the earlier next grant win while both candidates are alive', () => {
    const table24: Array<[string, string, string]> = [
      ['2026-11-01T00:00:00Z', '2026-10-14T00:00:00Z', '2026-11-14T00:00:00Z'],
      ['2026-11-01T12:00:00Z', '2026-10-14T00:00:00Z', '2026-11-14T00:00:00Z'],
      ['2026-11-13T23:59:59Z', '2026-10-14T00:00:00Z', '2026-11-14T00:00:00Z'],
      ['2026-11-14T00:00:00Z', '2026-10-31T00:00:00Z', '2026-11-30T00:00:00Z'],
      ['2026-11-14T23:59:59Z', '2026-10-31T00:00:00Z', '2026-11-30T00:00:00Z'],
      ['2026-11-15T00:00:00Z', '2026-10-31T00:00:00Z', '2026-11-30T00:00:00Z'],
      ['2026-11-29T23:59:59Z', '2026-10-31T00:00:00Z', '2026-11-30T00:00:00Z'],
      ['2026-11-30T00:00:00Z', '2026-11-14T00:00:00Z', '2026-12-14T00:00:00Z'],
      ['2026-12-01T00:00:00Z', '2026-11-14T00:00:00Z', '2026-12-14T00:00:00Z'],
      ['2026-12-14T00:00:00Z', '2026-11-30T00:00:00Z', '2026-12-31T00:00:00Z'],
      // Month and year turn: the 1st of January minus 24 h is 12-31.
      ['2026-12-31T00:00:00Z', '2026-12-14T00:00:00Z', '2027-01-14T00:00:00Z'],
      ['2027-01-01T00:00:00Z', '2026-12-14T00:00:00Z', '2027-01-14T00:00:00Z'],
      ['2027-01-14T00:00:00Z', '2026-12-31T00:00:00Z', '2027-01-31T00:00:00Z'],
    ]
    for (const [now, lb, exp] of table24) expect(period(24, now), now).toEqual([lb, exp])
  })

  it('lead 0: 11-14 23:59:59Z is still the old period, 11-15 00:00Z the next', () => {
    const table0: Array<[string, string, string]> = [
      ['2026-11-01T00:00:00Z', '2026-10-15T00:00:00Z', '2026-11-15T00:00:00Z'],
      ['2026-11-14T23:59:59Z', '2026-10-15T00:00:00Z', '2026-11-15T00:00:00Z'],
      ['2026-11-15T00:00:00Z', '2026-11-01T00:00:00Z', '2026-12-01T00:00:00Z'],
      ['2026-11-30T23:59:59Z', '2026-11-01T00:00:00Z', '2026-12-01T00:00:00Z'],
      ['2026-12-01T00:00:00Z', '2026-11-15T00:00:00Z', '2026-12-15T00:00:00Z'],
      ['2026-12-31T23:59:59Z', '2026-12-01T00:00:00Z', '2027-01-01T00:00:00Z'],
      ['2027-01-01T00:00:00Z', '2026-12-15T00:00:00Z', '2027-01-15T00:00:00Z'],
    ]
    for (const [now, lb, exp] of table0) expect(period(0, now), now).toEqual([lb, exp])
  })

  it('a single grant day: its own month, year rollover included', () => {
    expect(period(0, '2026-12-31T12:00:00Z', [15])).toEqual(['2026-12-15T00:00:00Z', '2027-01-15T00:00:00Z'])
    expect(period(24, '2026-11-14T00:00:00Z', [15])).toEqual(['2026-11-14T00:00:00Z', '2026-12-14T00:00:00Z'])
    expect(period(24, '2026-11-13T23:59:59Z', [15])).toEqual(['2026-10-14T00:00:00Z', '2026-11-14T00:00:00Z'])
  })

  it('invariants over a sweep: lb <= now < expires, the key follows the pair', () => {
    const gm = gmOf()
    let prevKey = ''
    let changes = 0
    for (let t = Z('2026-10-01T00:00:00Z'); t < Z('2027-03-01T00:00:00Z'); t += 3_600_000) {
      const p = currentPeriod(gm, t)
      expect(p.lbMs <= t && t < p.expiresMs).toBe(true)
      if (p.key !== prevKey) changes++
      prevKey = p.key
    }
    // Two candidates flip once a month each: about ten flips over five months.
    expect(changes).toBeGreaterThan(5)
    expect(changes).toBeLessThan(30)
    const a = currentPeriod(gm, Z('2026-11-13T23:59:59Z'))
    const b = currentPeriod(gm, Z('2026-11-14T00:00:00Z'))
    const c = currentPeriod(gm, Z('2026-11-14T12:00:00Z'))
    expect(a.key).not.toBe(b.key)
    expect(b.key).toBe(c.key)
  })

  it('a non-finite now is refused', () => {
    expect(() => currentPeriod(gmOf(), Number.NaN)).toThrow()
    expect(() => currentPeriod(gmOf(), Number.POSITIVE_INFINITY)).toThrow()
  })
})

describe('priorCharge (spec 3): multiplier x rows from lb on, plus the gap charge while lb is before the gap end', () => {
  const A = Z('2026-10-10T13:15:32Z')
  const B = Z('2026-10-15T00:00:00Z')
  const C = Z('2026-10-23T05:41:23Z')
  const rows = (): UsageRow[] => [sonnet2(A), sonnet2(B), sonnet2(C)]
  const gm = (mult: string, gap: Record<string, unknown> = {}) =>
    gmOf(grantBlock({ reconstructed: reconstructedBlock({ multiplier: mult, gap: { ...GAP, ...gap } }) }))

  it('before the gap: all rows from lb on, x3, plus the fixed gap charge', () => {
    expect(priorCharge(rows(), gm('3'), Z('2026-10-10T00:00:00Z'), table())).toBe(18 * USD + 10_520_000)
    expect(priorCharge(rows(), gm('3'), Z('2026-10-14T00:00:00Z'), table())).toBe(12 * USD + 10_520_000)
  })

  it('the multiplier 1 and 2', () => {
    const lb = Z('2026-10-10T00:00:00Z')
    expect(priorCharge(rows(), gm('1'), lb, table())).toBe(6 * USD + 10_520_000)
    expect(priorCharge(rows(), gm('2'), lb, table())).toBe(12 * USD + 10_520_000)
  })

  it('inside the gap: no row is left, the gap charge still counts', () => {
    expect(priorCharge(rows(), gm('3'), Z('2026-10-23T06:00:00Z'), table())).toBe(10_520_000)
  })

  it('the gap end is exclusive: lb at the end counts nothing, one ms before it counts the gap', () => {
    const end = Z(GAP.to)
    expect(priorCharge(rows(), gm('3'), end, table())).toBe(0)
    expect(priorCharge(rows(), gm('3'), end - 1, table())).toBe(10_520_000)
    expect(priorCharge(rows(), gm('3'), end + 5 * 86_400_000, table())).toBe(0)
  })

  it('a row exactly at lb counts, one ms later it does not (ts is in whole seconds)', () => {
    const g = gm('1', { chargeUsd: '0.00' })
    expect(priorCharge(rows(), g, B, table())).toBe(4 * USD)
    expect(priorCharge(rows(), g, B + 1, table())).toBe(2 * USD)
  })

  it('rounds UP to a whole micro-USD, once, on the multiplied sum', () => {
    const g = gm('1.5', { chargeUsd: '0.00' })
    const micro1 = (ms: number) => row(ms, 'claude-sonnet-5-5', 0, 0, { cli_micro: 1 as Micro })
    expect(priorCharge([micro1(A)], g, A, table())).toBe(2) // 1.5 -> 2
    expect(priorCharge([micro1(A), micro1(B), micro1(C)], g, A, table())).toBe(5) // 4.5 -> 5, not 3 x 2
    expect(priorCharge([micro1(A), micro1(B)], g, A, table())).toBe(3) // exactly 3, no extra micro
  })

  it('L is max(estimate, cli); a batch row gets the 50% batch discount', () => {
    const g = gm('1', { chargeUsd: '0.00' })
    expect(priorCharge([sonnet2(A, { cli_micro: 3 * USD as Micro })], g, A, table())).toBe(3 * USD)
    expect(priorCharge([sonnet2(A, { cli_micro: 1 as Micro })], g, A, table())).toBe(2 * USD)
    expect(priorCharge([sonnet2(A, { batch_id: 'msgbatch_x', custom_id: 'c1' })], g, A, table())).toBe(1 * USD)
  })

  it('an unpriceable row (unknown model) makes the whole answer null, whatever lb', () => {
    const bad = row(A, 'claude-mystery-9', 10, 10)
    expect(priorCharge([bad], gm('3'), Z('2026-10-10T00:00:00Z'), table())).toBeNull()
    expect(priorCharge([bad, sonnet2(B)], gm('3'), Z('2026-10-14T00:00:00Z'), table())).toBeNull()
    expect(priorCharge([bad], gm('3'), Z('2026-10-30T00:00:00Z'), table())).toBeNull()
  })

  it('no reconstructed block: nothing prior', () => {
    const g = gmOf(grantBlock({ reconstructed: undefined }))
    expect(g.reconstructed).toBeNull()
    expect(priorCharge(rows(), g, Z('2026-10-10T00:00:00Z'), table())).toBe(0)
  })
})

describe('grantRemaining: grant - prior, clipped at 0 (A4)', () => {
  const g = gmOf()
  it('subtracts, and never goes below zero', () => {
    expect(grantRemaining(g, 0 as Micro)).toBe(200 * USD)
    expect(grantRemaining(g, 20_850_000 as Micro)).toBe(200 * USD - 20_850_000)
    expect(grantRemaining(g, 200 * USD as Micro)).toBe(0)
    expect(grantRemaining(g, 250 * USD as Micro)).toBe(0)
  })
})

describe('grantModelHash (spec 4: binds the model, the thresholds, the margins, the sources, the file)', () => {
  const FILE = 'c'.repeat(64)
  const h = (o: Record<string, unknown>, file: string | null = FILE) => grantModelHash(configOf(o), file)

  it('is a 64-hex sha256, deterministic, and independent of the key order in the config text', () => {
    const a = h(cfgObject())
    expect(a).toMatch(/^[0-9a-f]{64}$/)
    expect(h(cfgObject())).toBe(a)
    const base = cfgObject()
    const reordered = Object.fromEntries(Object.entries(base).reverse())
    expect(h(reordered)).toBe(a)
  })

  it('changes with each bound part', () => {
    const base = h(cfgObject())
    const changed: Array<[string, string]> = [
      ['grantUsd', h(cfgObject(grantBlock({ grantUsd: '150.00' })))],
      ['grantDays', h(cfgObject(grantBlock({ grantDays: [15] })))],
      ['boundaryLeadH', h(cfgObject(grantBlock({ boundaryLeadH: 0 })))],
      ['multiplier', h(cfgObject(grantBlock({ reconstructed: reconstructedBlock({ multiplier: '2' }) })))],
      ['gap charge', h(cfgObject(grantBlock({ reconstructed: reconstructedBlock({ gap: { ...GAP, chargeUsd: '7.02' } }) })))],
      ['gap from', h(cfgObject(grantBlock({ reconstructed: reconstructedBlock({ gap: { ...GAP, from: '2026-10-23T05:41:24Z' } }) })))],
      ['configured sha', h(cfgObject(grantBlock({ reconstructed: reconstructedBlock({ sha256: 'd'.repeat(64) }) })))],
      ['no reconstructed', h(cfgObject(grantBlock({ reconstructed: undefined })), null)],
      ['tClose', h({ ...cfgObject(), thresholds: { tClose: '25.00', tLowcal: '60.00', tReopen: '50.00', tCloseLowcalFallback: '40.00', lowcalWaitH: 12 } })],
      ['lowcalWaitH', h({ ...cfgObject(), thresholds: { tClose: '20.00', tLowcal: '60.00', tReopen: '50.00', tCloseLowcalFallback: '40.00', lowcalWaitH: 6 } })],
      ['expiryMarginH', h({ ...cfgObject(), expiryMarginH: 3 })],
      ['batchHorizonH', h({ ...cfgObject(), batchHorizonH: 36 })],
      ['ledger source path', h({ ...cfgObject(), ledgerSources: [{ id: 'anthropic-batch', path: '/tmp/y/usage.jsonl', format: 'usage-jsonl-v1' }] })],
      ['ledger source id', h({ ...cfgObject(), ledgerSources: [{ id: 'other', path: '/tmp/x/usage.jsonl', format: 'usage-jsonl-v1' }] })],
      ['file sha', h(cfgObject(), 'e'.repeat(64))],
    ]
    for (const [name, v] of changed) {
      expect(v, name).toMatch(/^[0-9a-f]{64}$/)
      expect(v, name).not.toBe(base)
    }
    expect(new Set(changed.map(([, v]) => v)).size).toBe(changed.length)
  })

  it('a part the grant model does not rest on does not move it', () => {
    const base = h(cfgObject())
    expect(h({ ...cfgObject(), refreshS: 20 })).toBe(base)
    expect(h({ ...cfgObject(), vaultKeyId: 'OTHER_KEY' })).toBe(base)
  })

  it('refuses a config that has no grantModel', () => {
    expect(() => grantModelHash(configOf(cfgObject(null, { calibrationSource: 'console' })), null)).toThrow()
  })
})

describe('readReconstructed: the recovered file as data (A6)', () => {
  let dir: string
  let path: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'grant-model-reconstructed-'))
    chmodSync(dir, 0o700)
    path = join(dir, 'reconstructed.jsonl')
  })
  afterEach(() => rmSync(dir, { recursive: true, force: true }))

  const line = (o: Record<string, unknown>): string => JSON.stringify({ month: '2026-10', caller: 'test', model: 'claude-sonnet-5-5', in: 10, out: 5, ...o }) + '\n'
  const GOOD = line({ ts: 1_760_000_000 }) + line({ ts: 1_760_000_100, in: 20 })
  const write = (text: string, mode = 0o600): string => {
    writeFileSync(path, text, { mode })
    chmodSync(path, mode)
    return sha(text)
  }

  it('reads the rows when the sha256 matches', () => {
    const s = write(GOOD)
    const r = readReconstructed(path, s)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.rows.length).toBe(2)
    expect(r.rows[1].input_tokens).toBe(20)
    expect(r.sha256).toBe(s)
  })

  it('a sha256 mismatch is a failure, and so is a malformed expected sha', () => {
    write(GOOD)
    expect(readReconstructed(path, 'a'.repeat(64))).toMatchObject({ ok: false })
    expect(readReconstructed(path, sha(GOOD).toUpperCase())).toMatchObject({ ok: false })
    expect(readReconstructed(path, 'nothex')).toMatchObject({ ok: false })
  })

  it('one changed byte after the sha was pinned is a failure', () => {
    const s = write(GOOD)
    write(GOOD.replace('"in":20', '"in":21'))
    expect(readReconstructed(path, s)).toMatchObject({ ok: false })
  })

  it('a missing file, a relative path, a symlink, an open-permission file: failures', () => {
    expect(readReconstructed(join(dir, 'nope.jsonl'), 'a'.repeat(64))).toMatchObject({ ok: false })
    expect(readReconstructed('reconstructed.jsonl', 'a'.repeat(64))).toMatchObject({ ok: false })
    const s = write(GOOD)
    const link = join(dir, 'link.jsonl')
    symlinkSync(path, link)
    expect(readReconstructed(link, s)).toMatchObject({ ok: false })
    write(GOOD, 0o644)
    expect(readReconstructed(path, s)).toMatchObject({ ok: false })
  })

  it('a folder open to others is a failure', () => {
    const s = write(GOOD)
    chmodSync(dir, 0o755)
    expect(readReconstructed(path, s)).toMatchObject({ ok: false })
    chmodSync(dir, 0o700)
  })

  it('a line the v1 parser rejects fails the whole file, with the line number, never a skip', () => {
    const bad: Array<[string, string]> = [
      ['unknown key', line({ ts: 1_760_000_000, surprise: 1 })],
      ['not JSON', 'not json\n'],
      ['negative tokens', line({ ts: 1_760_000_000, in: -1 })],
      ['missing model', JSON.stringify({ ts: 1_760_000_000, month: '2026-10', caller: 'test', in: 1, out: 1 }) + '\n'],
      ['duplicate key', '{"ts":1760000000,"month":"2026-10","caller":"t","model":"claude-sonnet-5-5","in":1,"in":2,"out":1}\n'],
      ['blank line', '\n'],
    ]
    for (const [name, badLine] of bad) {
      const s = write(GOOD + badLine + GOOD)
      const r = readReconstructed(path, s)
      expect(r.ok, name).toBe(false)
      if (!r.ok) expect(r.detail, name).toContain('line 3')
    }
  })

  it('an empty file is a failure (a reconstruction without a row is not one)', () => {
    const s = write('')
    expect(readReconstructed(path, s)).toMatchObject({ ok: false })
  })

  it('a failure never echoes the file content', () => {
    const secret = 'SUPERSECRETCALLERNAME'
    const s = write(line({ ts: 1_760_000_000, caller: secret, surprise: 1 }))
    const r = readReconstructed(path, s)
    expect(r.ok).toBe(false)
    expect(JSON.stringify(r)).not.toContain(secret)
  })
})

describe('config: calibrationSource and grantModel', () => {
  it('absent: console, no grantModel (the default stays what it was)', () => {
    const c = configOf(configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP'))
    expect(c.calibrationSource).toBe('console')
    expect(c.grantModel).toBeNull()
  })

  it('"console" is accepted, with or without a grantModel block next to it (a rollback is one key)', () => {
    expect(configOf({ ...configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP'), calibrationSource: 'console' }).calibrationSource).toBe('console')
    const withBlock = configOf(cfgObject(grantBlock(), { calibrationSource: 'console' }))
    expect(withBlock.calibrationSource).toBe('console')
    expect(withBlock.grantModel).not.toBeNull()
  })

  it('grant_model with a full block: every value parsed to money, UTC ms and an exact factor', () => {
    const c = configOf(cfgObject())
    expect(c.calibrationSource).toBe('grant_model')
    const gm = c.grantModel
    expect(gm).not.toBeNull()
    if (gm === null) return
    expect(gm.grantUsd).toBe(200 * USD)
    expect(gm.grantDays).toEqual([1, 15])
    expect(gm.boundaryLeadH).toBe(24)
    expect(gm.reconstructed).not.toBeNull()
    const rc = gm.reconstructed
    if (rc === null) return
    expect(rc.path).toBe('/tmp/x/reconstructed.jsonl')
    expect(rc.sha256).toBe('b'.repeat(64))
    expect(rc.multiplier).toEqual({ num: 3_000_000n, den: 1_000_000n })
    expect(rc.gap).toEqual({ fromMs: Z(GAP.from), toMs: Z(GAP.to), chargeUsd: 10_520_000 })
  })

  it('boundaryLeadH defaults to 24; grantDays are a sorted set; reconstructed is optional', () => {
    const { boundaryLeadH: _b, ...noLead } = grantBlock({ grantDays: [15, 1] })
    const gm = configOf(cfgObject(noLead)).grantModel
    expect(gm?.boundaryLeadH).toBe(24)
    expect(gm?.grantDays).toEqual([1, 15])
    expect(configOf(cfgObject(grantBlock({ boundaryLeadH: 0 }))).grantModel?.boundaryLeadH).toBe(0)
    expect(configOf(cfgObject(grantBlock({ reconstructed: undefined }))).grantModel?.reconstructed).toBeNull()
  })

  it('grant_model selected without a grantModel block is invalid', () => {
    expect(parse(cfgObject(null))).toMatchObject({ ok: false, reason: 'invalid' })
  })

  it('every malformed value or unknown key rejects the whole config', () => {
    const rec = (over: Record<string, unknown>) => grantBlock({ reconstructed: reconstructedBlock(over) })
    const gap = (over: Record<string, unknown>) => rec({ gap: { ...GAP, ...over } })
    const bad: Array<[string, Record<string, unknown>]> = [
      ['unknown calibrationSource', cfgObject(grantBlock(), { calibrationSource: 'Console' })],
      ['calibrationSource none', cfgObject(grantBlock(), { calibrationSource: 'none' })],
      ['calibrationSource not a string', cfgObject(grantBlock(), { calibrationSource: 1 })],
      ['grantModel not an object', cfgObject(grantBlock(), { grantModel: [] })],
      ['grantModel null', cfgObject(grantBlock(), { grantModel: null })],
      ['unknown key in grantModel', cfgObject(grantBlock({ surprise: 1 }))],
      ['unknown key in reconstructed', cfgObject(rec({ surprise: 1 }))],
      ['unknown key in gap', cfgObject(gap({ surprise: 1 }))],
      ['grantUsd missing', cfgObject((({ grantUsd: _g, ...r }) => r)(grantBlock()))],
      ['grantUsd one decimal', cfgObject(grantBlock({ grantUsd: '200.0' }))],
      ['grantUsd no decimals', cfgObject(grantBlock({ grantUsd: '200' }))],
      ['grantUsd zero', cfgObject(grantBlock({ grantUsd: '0.00' }))],
      ['grantDays missing', cfgObject((({ grantDays: _g, ...r }) => r)(grantBlock()))],
      ['grantDays empty', cfgObject(grantBlock({ grantDays: [] }))],
      ['grantDays zero', cfgObject(grantBlock({ grantDays: [0] }))],
      ['grantDays 29', cfgObject(grantBlock({ grantDays: [29] }))],
      ['grantDays duplicate', cfgObject(grantBlock({ grantDays: [15, 15] }))],
      ['grantDays five entries', cfgObject(grantBlock({ grantDays: [1, 5, 10, 15, 20] }))],
      ['grantDays fractional', cfgObject(grantBlock({ grantDays: [1.5] }))],
      ['grantDays strings', cfgObject(grantBlock({ grantDays: ['1', '15'] }))],
      ['grantDays not a list', cfgObject(grantBlock({ grantDays: 15 }))],
      ['boundaryLeadH negative', cfgObject(grantBlock({ boundaryLeadH: -1 }))],
      ['boundaryLeadH 49', cfgObject(grantBlock({ boundaryLeadH: 49 }))],
      ['boundaryLeadH fractional', cfgObject(grantBlock({ boundaryLeadH: 1.5 }))],
      ['reconstructed path relative', cfgObject(rec({ path: 'reconstructed.jsonl' }))],
      ['reconstructed path unnormalised', cfgObject(rec({ path: '/tmp/x/../y.jsonl' }))],
      ['sha256 short', cfgObject(rec({ sha256: 'b'.repeat(63) }))],
      ['sha256 uppercase', cfgObject(rec({ sha256: 'B'.repeat(64) }))],
      ['sha256 missing', cfgObject(grantBlock({ reconstructed: (({ sha256: _s, ...r }) => r)(reconstructedBlock()) }))],
      ['multiplier below 1', cfgObject(rec({ multiplier: '0.99' }))],
      ['multiplier above 10', cfgObject(rec({ multiplier: '10.01' }))],
      ['multiplier junk', cfgObject(rec({ multiplier: '3x' }))],
      ['multiplier a number', cfgObject(rec({ multiplier: 3 }))],
      ['multiplier missing', cfgObject(grantBlock({ reconstructed: (({ multiplier: _m, ...r }) => r)(reconstructedBlock()) }))],
      ['gap missing', cfgObject(grantBlock({ reconstructed: (({ gap: _g, ...r }) => r)(reconstructedBlock()) }))],
      ['gap from not a UTC instant', cfgObject(gap({ from: '2026-10-23 05:41:23' }))],
      ['gap to impossible date', cfgObject(gap({ to: '2026-02-30T00:00:00Z' }))],
      ['gap from after to', cfgObject(gap({ from: '2026-10-25T00:00:00Z' }))],
      ['gap from equals to', cfgObject(gap({ from: GAP.to }))],
      ['gap chargeUsd one decimal', cfgObject(gap({ chargeUsd: '10.5' }))],
      ['gap chargeUsd negative', cfgObject(gap({ chargeUsd: '-1.00' }))],
    ]
    for (const [name, o] of bad) {
      const r = parse(o)
      expect(r.ok, name).toBe(false)
    }
  })

  it('the Console config (no new keys) is untouched: same limits as before', () => {
    const base = configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP')
    expect(parse({ ...base, surprise: 1 }).ok).toBe(false)
    expect(parse(base).ok).toBe(true)
  })
})
