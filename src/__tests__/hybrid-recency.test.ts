// Card 94f8d99f, wave 2, node R2 (point 5): a created_at recency term in the
// hybrid fusion, score = RRF + WEIGHT * exp(-age / TAU). Weight 0 (the
// default) must leave the fusion exactly as it was; above 0, of two
// near-equal rows the newer one ranks first. MEMORY_HYBRID_FTS_RECENCY=off
// keeps the hybrid's keyword branch in plain bm25 order.
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const recencyState = vi.hoisted(() => ({ weight: 0, tauDays: 30, ftsRecency: true }))
const recencyInvalid = vi.hoisted(() => [] as string[])
vi.mock('../config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../config.js')>()
  return { ...orig, MEMORY_HYBRID_RECENCY: recencyState, MEMORY_HYBRID_RECENCY_INVALID: recencyInvalid }
})

import { resolveHybridRecencyConfig, HYBRID_RECENCY_DEFAULT, type HybridRecencyConfig } from '../config.js'
import {
  initDatabase, getDb, hybridSearchWith, searchAgentMemories, fuseRanked, hybridRecencyBonus, clearMemoryCache,
  HYBRID_RRF_K, type Memory, type VectorHit,
} from '../db.js'
import { logger } from '../logger.js'

const NOW = 1_790_000_000
const DAY = 86400
const AGENT = 'r2-agent'
const OFF: HybridRecencyConfig = { weight: 0, tauDays: 30, ftsRecency: true }

describe('resolveHybridRecencyConfig: MEMORY_HYBRID_RECENCY_* parsing', () => {
  const from = (env: Record<string, string>) => resolveHybridRecencyConfig(k => env[k])

  it('unset = weight 0, tau 30 days, the keyword branch keeps its re-rank', () => {
    expect(HYBRID_RECENCY_DEFAULT).toEqual(OFF)
    expect(from({})).toEqual({ config: OFF, invalid: [] })
    expect(from({ MEMORY_HYBRID_RECENCY_WEIGHT: ' ' })).toEqual({ config: OFF, invalid: [] })
  })

  it('reads the three keys', () => {
    expect(from({ MEMORY_HYBRID_RECENCY_WEIGHT: '0.005', MEMORY_HYBRID_RECENCY_TAU_DAYS: '90', MEMORY_HYBRID_FTS_RECENCY: 'off' }))
      .toEqual({ config: { weight: 0.005, tauDays: 90, ftsRecency: false }, invalid: [] })
    expect(from({ MEMORY_HYBRID_RECENCY_WEIGHT: '1' }).config.weight).toBe(1)
    expect(from({ MEMORY_HYBRID_RECENCY_TAU_DAYS: '0.5' }).config.tauDays).toBe(0.5)
    for (const on of ['on', 'ON', '1', 'true', 'yes']) expect(from({ MEMORY_HYBRID_FTS_RECENCY: on }).config.ftsRecency, on).toBe(true)
    for (const off of ['off', 'Off', '0', 'false', 'no']) expect(from({ MEMORY_HYBRID_FTS_RECENCY: off }).config.ftsRecency, off).toBe(false)
  })

  it('a bad value falls back to its default and is named (never a negative weight, never a zero tau)', () => {
    for (const bad of ['-0.1', '1.5', 'abc', '1e-3', 'NaN', 'Infinity', '.5', '0,5']) {
      const r = from({ MEMORY_HYBRID_RECENCY_WEIGHT: bad })
      expect(r.config, bad).toEqual(OFF)
      expect(r.invalid, bad).toEqual(['MEMORY_HYBRID_RECENCY_WEIGHT'])
    }
    for (const bad of ['0', '0.0', '-7', '3651', 'x']) {
      const r = from({ MEMORY_HYBRID_RECENCY_TAU_DAYS: bad })
      expect(r.config.tauDays, bad).toBe(30)
      expect(r.invalid, bad).toEqual(['MEMORY_HYBRID_RECENCY_TAU_DAYS'])
    }
    expect(from({ MEMORY_HYBRID_FTS_RECENCY: 'maybe' })).toEqual({ config: OFF, invalid: ['MEMORY_HYBRID_FTS_RECENCY'] })
  })
})

describe('hybridRecencyBonus', () => {
  const term = { weight: 0.01, tauSec: 30 * DAY, nowSec: NOW }

  it('weight * exp(-age / tau); a future created_at counts as brand new (age 0), not above the weight', () => {
    expect(hybridRecencyBonus(NOW, term)).toBe(0.01)
    expect(hybridRecencyBonus(NOW - 30 * DAY, term)).toBeCloseTo(0.01 * Math.exp(-1), 15)
    expect(hybridRecencyBonus(NOW + 5 * DAY, term)).toBe(0.01)
  })

  it('0 for anything unusable: weight 0 / negative / NaN, tau 0 / NaN / Infinity, created_at NaN / missing, clock NaN', () => {
    for (const w of [0, -0.01, Number.NaN, Number.POSITIVE_INFINITY]) expect(hybridRecencyBonus(NOW, { ...term, weight: w }), String(w)).toBe(0)
    for (const t of [0, -1, Number.NaN, Number.POSITIVE_INFINITY]) expect(hybridRecencyBonus(NOW, { ...term, tauSec: t }), String(t)).toBe(0)
    for (const c of [Number.NaN, Number.POSITIVE_INFINITY, undefined as unknown as number, null as unknown as number, '1790000000' as unknown as number]) {
      expect(hybridRecencyBonus(c, term), String(c)).toBe(0)
    }
    expect(hybridRecencyBonus(NOW, { ...term, nowSec: Number.NaN })).toBe(0)
  })

  it('monotone: newer never gets less, and the term stays within [0, weight]', () => {
    let prev = Number.POSITIVE_INFINITY
    for (let age = 0; age <= 3650 * DAY; age += 7 * DAY) {
      const b = hybridRecencyBonus(NOW - age, term)
      expect(b).toBeLessThanOrEqual(prev)
      expect(b).toBeGreaterThanOrEqual(0)
      expect(b).toBeLessThanOrEqual(term.weight)
      prev = b
    }
  })
})

// ---------------------------------------------------------------------------
// fuseRanked: parity at weight 0, order and monotonicity above it
// ---------------------------------------------------------------------------
function mulberry32(seed: number): () => number {
  let a = seed >>> 0
  return () => {
    a = (a + 0x6D2B79F5) >>> 0
    let t = a
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

const mem = (id: number, createdAt: number): Memory => ({
  id, chat_id: '0', topic_key: null, content: `m${id}`, sector: 'semantic', salience: 1, created_at: createdAt,
  accessed_at: createdAt, agent_id: 'x', category: 'warm', auto_generated: 0, keywords: null, embedding: null,
})

/** Random branch lists over a shared id pool, with ties in created_at and overlapping rows. */
function randomBranches(r: () => number): { fts: Memory[]; vec: VectorHit[] } {
  const pool = Array.from({ length: 30 }, (_, i) => mem(i + 1, NOW - Math.floor(r() * 4) * 90 * DAY - Math.floor(r() * 10) * DAY))
  const shuffled = (): Memory[] => [...pool].sort(() => r() - 0.5)
  const fts = shuffled().slice(0, Math.floor(r() * 20))
  const vec = shuffled().slice(0, Math.floor(r() * 20)).map(m => ({ memory: m, score: Math.round(r() * 1000) / 1000 }))
  return { fts, vec }
}

describe('fuseRanked with a recency term', () => {
  it('weight 0, NaN or omitted: the very same result as before, scores bit for bit', () => {
    const r = mulberry32(5)
    for (let i = 0; i < 300; i++) {
      const { fts, vec } = randomBranches(r)
      const limit = 1 + Math.floor(r() * 25)
      const base = fuseRanked(fts, vec, limit)
      for (const w of [0, Number.NaN, -0.01]) {
        expect(fuseRanked(fts, vec, limit, HYBRID_RRF_K, { weight: w, tauSec: 30 * DAY, nowSec: NOW })).toEqual(base)
      }
      expect(fuseRanked(fts, vec, limit, HYBRID_RRF_K, undefined)).toEqual(base)
    }
  })

  it('above 0: score = RRF + bonus, sorted by it', () => {
    const term = { weight: 0.005, tauSec: 30 * DAY, nowSec: NOW }
    const out = fuseRanked([mem(1, NOW - 400 * DAY), mem(2, NOW)], [], 10, HYBRID_RRF_K, term)
    expect(out.map(h => h.memory.id)).toEqual([2, 1])
    expect(out[0].score).toBe(1 / 62 + 0.005)
    expect(out[1].score).toBe(1 / 61 + hybridRecencyBonus(NOW - 400 * DAY, term))
  })

  it('two rows tied on RRF: the newer one first above 0; at 0 the old first-seen order', () => {
    const older = mem(1, NOW - 200 * DAY)
    const newer = mem(2, NOW - 10 * DAY)
    // Same RRF: older is first in FTS, newer is first in the vector branch.
    const fts = [older, newer]
    const vec = [{ memory: newer, score: 0.9 }, { memory: older, score: 0.8 }]
    expect(fuseRanked(fts, vec, 10).map(h => h.memory.id)).toEqual([1, 2])
    expect(fuseRanked(fts, vec, 10, HYBRID_RRF_K, { weight: 0.0001, tauSec: 30 * DAY, nowSec: NOW }).map(h => h.memory.id)).toEqual([2, 1])
  })

  it('monotone in the weight: once a newer row is ahead of an older one, a larger weight keeps it ahead', () => {
    const r = mulberry32(17)
    const weights = [0, 0.001, 0.002, 0.005, 0.01, 0.02, 0.05]
    let moved = 0
    for (let i = 0; i < 200; i++) {
      const { fts, vec } = randomBranches(r)
      const tauSec = [7, 30, 90][i % 3] * DAY
      const orders = weights.map(w => fuseRanked(fts, vec, 100, HYBRID_RRF_K, { weight: w, tauSec, nowSec: NOW }))
      for (let k = 1; k < orders.length; k++) {
        const prevPos = new Map(orders[k - 1].map((h, p) => [h.memory.id, p]))
        const pos = new Map(orders[k].map((h, p) => [h.memory.id, p]))
        const rows = orders[k].map(h => h.memory)
        for (const a of rows) for (const b of rows) {
          if (a.created_at <= b.created_at) continue // a strictly newer than b
          if (prevPos.get(a.id)! < prevPos.get(b.id)!) expect(pos.get(a.id)!).toBeLessThan(pos.get(b.id)!)
          else if (pos.get(a.id)! < pos.get(b.id)!) moved++
        }
      }
    }
    // The weights really reorder rows, so the property above is not vacuous.
    expect(moved).toBeGreaterThan(0)
  })
})

// ---------------------------------------------------------------------------
// hybridSearchWith on a seeded store: the synthetic staleness pair
// ---------------------------------------------------------------------------
const ids: Record<string, number> = {}
const Q_VEC = [1, 0, 0, 0]

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(join(mkdtempSync(join(tmpdir(), 'r2-recency-')), 'r2.db'))
  const insert = getDb().prepare(
    `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
     VALUES ('0', ?, 'semantic', 1.0, ?, ?, ?, 'warm', NULL, ?)`,
  )
  const add = (name: string, content: string, createdAt: number, emb: number[]) => {
    ids[name] = Number(insert.run(content, createdAt, createdAt, AGENT, JSON.stringify(emb)).lastInsertRowid)
  }
  // An exact duplicate pair: the older copy written first, so every tie favours it.
  add('dupOld', 'szivattyu nyomas beallitas hat bar', NOW - 400 * DAY, [0, 1, 0, 0])
  add('dupNew', 'szivattyu nyomas beallitas hat bar', NOW - 200 * DAY, [0, 1, 0, 0])
  // A near-duplicate pair: the older one is slightly better in BOTH branches
  // (the keyword twice, a closer vector), so without recency it ranks first.
  add('nearOld', 'sprinkler tartaly sprinkler meret', NOW - 400 * DAY, [1, 0.05, 0, 0])
  add('nearNew', 'sprinkler tartaly ujabb meret', NOW - 200 * DAY, [1, 0.1, 0, 0])
  // Unrelated rows, so the branches are not trivially two long.
  add('other1', 'kanban oszlop', NOW - 5 * DAY, [0, 0, 1, 0])
  add('other2', 'telegram gomb', NOW - 1 * DAY, [0, 0, 0, 1])
  add('other3', 'billingo szamla', NOW - 50 * DAY, [0.3, 0.3, 0.3, 0.3])
  // Keyword-branch pair: the old row is the better bm25 match (the word twice,
  // a short text), the one-day-old row the worse one.
  add('ftsOld', 'riaszto riaszto', NOW - 400 * DAY, [0, 0, 0.5, 0.5])
  add('ftsNew', 'riaszto kozponti egyseg cserejenek ideje es helye', NOW - 1 * DAY, [0, 0.5, 0.5, 0])
})

afterAll(() => {
  initDatabase(':memory:')
})

afterEach(() => {
  Object.assign(recencyState, OFF)
  recencyInvalid.length = 0
  clearMemoryCache()
  vi.restoreAllMocks()
})

const order = async (query: string, vec: number[], recency?: HybridRecencyConfig) =>
  (await hybridSearchWith(getDb(), AGENT, query, 10, undefined, undefined, { queryEmbedding: vec, nowSec: NOW, recency })).map(h => h.memory.id)

const before = (list: number[], a: string, b: string) => {
  expect(list).toContain(ids[a])
  expect(list).toContain(ids[b])
  return list.indexOf(ids[a]) < list.indexOf(ids[b])
}

describe('hybridSearchWith: a newer duplicate ranks above the older one when the weight is above 0', () => {
  it('near-duplicate: older first at weight 0, newer first at 0.02 / 90 days', async () => {
    expect(before(await order('sprinkler', Q_VEC, OFF), 'nearOld', 'nearNew')).toBe(true)
    expect(before(await order('sprinkler', Q_VEC, { weight: 0.02, tauDays: 90, ftsRecency: true }), 'nearNew', 'nearOld')).toBe(true)
  })

  it('exact duplicate (keyword re-rank off, so every tie is the table order): older first at 0, newer first above 0', async () => {
    const vec = [0, 1, 0, 0]
    expect(before(await order('szivattyu', vec, { ...OFF, ftsRecency: false }), 'dupOld', 'dupNew')).toBe(true)
    // The older copy leads both branches by one place: 2 * (1/61 - 1/62) ~ 0.00053
    // of RRF. The term has to beat that between ages 400 and 200 days.
    for (const [w, tau] of [[0.005, 365], [0.01, 365], [0.02, 90]]) {
      expect(before(await order('szivattyu', vec, { weight: w, tauDays: tau, ftsRecency: false }), 'dupNew', 'dupOld'), `${w}/${tau}`).toBe(true)
    }
    // A term too small for that lead changes nothing: it breaks near-ties, it does not override relevance.
    expect(before(await order('szivattyu', vec, { weight: 0.002, tauDays: 30, ftsRecency: false }), 'dupOld', 'dupNew')).toBe(true)
  })

  it('the dashboard config is the default: MEMORY_HYBRID_RECENCY reaches the search without opts.recency', async () => {
    const plain = await order('sprinkler', Q_VEC)
    expect(plain).toEqual(await order('sprinkler', Q_VEC, OFF))
    expect(before(plain, 'nearOld', 'nearNew')).toBe(true)
    Object.assign(recencyState, { weight: 0.02, tauDays: 90 })
    expect(before(await order('sprinkler', Q_VEC), 'nearNew', 'nearOld')).toBe(true)
  })

  it('weight 0 leaves every hit, score and rank exactly as without the term', async () => {
    for (const q of ['sprinkler', 'szivattyu', 'kanban', 'nincsilyen', '']) {
      for (const vec of [Q_VEC, [0, 1, 0, 0], [0.2, 0.2, 0.9, 0.1]]) {
        const a = await hybridSearchWith(getDb(), AGENT, q, 5, undefined, undefined, { queryEmbedding: vec, nowSec: NOW })
        const b = await hybridSearchWith(getDb(), AGENT, q, 5, undefined, undefined, { queryEmbedding: vec, nowSec: NOW, recency: OFF })
        expect(b).toEqual(a)
      }
    }
  })

  it('an invalid config value: one WARN per process naming the keys, the search still answers', async () => {
    recencyInvalid.push('MEMORY_HYBRID_RECENCY_WEIGHT')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    await order('sprinkler', Q_VEC)
    const list = await order('sprinkler', Q_VEC)
    const ours = warn.mock.calls.filter(c => String(c[1]).startsWith('memory search: invalid MEMORY_HYBRID_RECENCY'))
    expect(ours.length).toBe(1)
    expect((ours[0][0] as { keys: string[] }).keys).toEqual(['MEMORY_HYBRID_RECENCY_WEIGHT'])
    expect(list.length).toBeGreaterThan(0)
  })
})

describe('MEMORY_HYBRID_FTS_RECENCY: the hybrid keyword branch with or without its own re-rank', () => {
  it('off: the keyword branch keeps bm25 order; on: its 7-day re-rank applies; the keyword-only search is untouched', async () => {
    // No vector branch (a zero query vector, MR3), so the fused order is the keyword branch's.
    const none = [0, 0, 0, 0]
    expect(await order('riaszto', none, { ...OFF, ftsRecency: true })).toEqual([ids.ftsNew, ids.ftsOld])
    expect(await order('riaszto', none, { ...OFF, ftsRecency: false })).toEqual([ids.ftsOld, ids.ftsNew])
    // The dashboard switch reaches the search.
    Object.assign(recencyState, { ftsRecency: false })
    expect(await order('riaszto', none)).toEqual([ids.ftsOld, ids.ftsNew])
    // The keyword-only search keeps its re-rank whatever the hybrid switch says
    // (it reads the wall clock, so pin it to the seed's).
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(NOW * 1000)
    try {
      expect(searchAgentMemories(AGENT, 'riaszto', 10).map(m => m.id)).toEqual([ids.ftsNew, ids.ftsOld])
    } finally {
      vi.useRealTimers()
    }
  })
})
