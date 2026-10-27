// Card 94f8d99f, memory program w3, node DW2 (kanban 6a2827da): explain=1 on a
// hybrid search puts a `search` object {rrf, fts_rank, vec_rank, cos} on every
// row. Opt-in; any other branch ignores it; the rows, their order and their
// count are the ones the same search returns without it.
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

const recencyState = vi.hoisted(() => ({ weight: 0, tauDays: 30, ftsRecency: true }))
vi.mock('../config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../config.js')>()
  return { ...orig, MEMORY_HYBRID_RECENCY: recencyState }
})
// The accessed_at stamp goes through this one function: spy on it, behaviour kept.
vi.mock('../db.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../db.js')>()
  return { ...orig, touchMemoriesAccessed: vi.fn(orig.touchMemoriesAccessed) }
})

import {
  initDatabase, getDb, hybridSearchWith, clearMemoryCache, touchMemoriesAccessed, type HybridHit,
} from '../db.js'
import { logger } from '../logger.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import { explainHit } from '../web/memory-explain.js'
import type { RouteContext } from '../web/routes/types.js'

const AGENT = 'explainagent'
const Q_VEC = [1, 0, 0, 0]
const NOW = Math.floor(Date.now() / 1000)
const DAY = 86400

// content, embedding (null = no vector), category, age in days.
const ROWS: { content: string; emb: number[] | null; category: string; ageDays: number }[] = [
  { content: 'sprinkler szivattyu', emb: [0.5, 0.5, 0, 0], category: 'warm', ageDays: 400 },
  { content: 'sprinkler tartaly', emb: [0.9, 0.1, 0, 0], category: 'warm', ageDays: 1 },
  { content: 'sprinkler csak kulcsszo', emb: null, category: 'warm', ageDays: 200 },
  { content: 'kanban oszlop', emb: [0.8, 0.6, 0, 0], category: 'warm', ageDays: 100 },
  { content: 'sprinkler fej', emb: [0.7, 0.3, 0.1, 0], category: 'warm', ageDays: 50 },
  { content: 'sprinkler archiv', emb: [0.6, 0.4, 0, 0], category: 'cold', ageDays: 300 },
]
const ids: number[] = []

function stubEmbedder(mode: 'ok' | 'down') {
  vi.stubGlobal('fetch', vi.fn(async () => {
    if (mode === 'down') throw new Error('stub: embedding backend down')
    return { json: async () => ({ embedding: Q_VEC }) }
  }))
}

function fakeCtx(pathAndQuery: string) {
  const out: { status: number; body: any; raw: string; headers: Record<string, string> } = { status: 200, body: null, raw: '', headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, string>) {
      out.status = status
      if (headers) for (const [k, v] of Object.entries(headers)) out.headers[k.toLowerCase()] = String(v)
      return res
    },
    setHeader(k: string, v: string) { out.headers[k.toLowerCase()] = String(v) },
    end(chunk?: any) { if (chunk) { out.raw = chunk.toString(); try { out.body = JSON.parse(out.raw) } catch { out.body = out.raw } } },
  }
  const req: any = Readable.from([])
  req.headers = {}
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  return { ctx: { req, res, path: url.pathname, method: 'GET', url } as RouteContext, out }
}

async function get(pathAndQuery: string) {
  const { ctx, out } = fakeCtx(pathAndQuery)
  expect(await tryHandleMemories(ctx)).toBe(true)
  expect(out.status).toBe(200)
  return out
}

/** The row without the stamp a search itself makes (accessed_at and its label). */
const stable = (rows: any[]) => rows.map(r => {
  const { accessed_at: _a, accessed_label: _l, ...rest } = r
  return rest
})
const withoutSearch = (rows: any[]) => rows.map(r => {
  const { search: _s, ...rest } = r
  return rest
})
const idsOf = (rows: any[]) => rows.map(r => r.id)

const Q = `agent=${AGENT}&q=sprinkler&mode=hybrid&limit=10`
const KEYS = ['cos', 'fts_rank', 'rrf', 'vec_rank']

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(join(mkdtempSync(join(tmpdir(), 'w3-explain-')), 'explain.db'))
  const insert = getDb().prepare(
    `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
     VALUES ('0', ?, 'semantic', 1.0, ?, 1790000000, ?, ?, NULL, ?)`,
  )
  for (const r of ROWS) {
    ids.push(Number(insert.run(r.content, NOW - r.ageDays * DAY, AGENT, r.category, r.emb ? JSON.stringify(r.emb) : null).lastInsertRowid))
  }
})

afterAll(() => {
  initDatabase(':memory:')
})

afterEach(() => {
  recencyState.weight = 0
  clearMemoryCache()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
  vi.mocked(touchMemoriesAccessed).mockClear()
})

describe('explainHit: the pure shape', () => {
  const memory = {} as HybridHit['memory']
  it('6 decimals for the score, 4 for the cosine, ranks as integers, a missing branch is null', () => {
    expect(explainHit({ memory, score: 0.0327868852459, ftsRank: 1, vecRank: 2, cosine: 0.99391234 }))
      .toEqual({ rrf: 0.032787, fts_rank: 1, vec_rank: 2, cos: 0.9939 })
    expect(explainHit({ memory, score: 1 / 61, ftsRank: 3, vecRank: null, cosine: null }))
      .toEqual({ rrf: 0.016393, fts_rank: 3, vec_rank: null, cos: null })
    expect(explainHit({ memory, score: 1 / 61, ftsRank: null, vecRank: 7, cosine: -0.12346 }))
      .toEqual({ rrf: 0.016393, fts_rank: null, vec_rank: 7, cos: -0.1235 })
  })

  it('no NaN or Infinity ever reaches the answer: null (0 for the score) instead', () => {
    expect(explainHit({ memory, score: Number.NaN, ftsRank: 0, vecRank: 1.5, cosine: Number.NaN }))
      .toEqual({ rrf: 0, fts_rank: null, vec_rank: null, cos: null })
    expect(explainHit({ memory, score: Number.POSITIVE_INFINITY, ftsRank: -1, vecRank: 1, cosine: Number.NEGATIVE_INFINITY }))
      .toEqual({ rrf: 0, fts_rank: null, vec_rank: 1, cos: null })
    // A cosine that rounds to -0 is a plain 0 in the JSON, not "-0".
    expect(Object.is(explainHit({ memory, score: 0.5, ftsRank: 1, vecRank: 1, cosine: -0.00001 }).cos, 0)).toBe(true)
  })
})

describe('GET /api/memories explain=1 (hybrid)', () => {
  it('(a) without explain=1 the body is the old one: no `search` key, whatever else is on the URL', async () => {
    stubEmbedder('ok')
    const plain = await get(`/api/memories?${Q}`)
    expect(plain.body.length).toBeGreaterThan(0)
    expect(plain.raw).not.toContain('"search"')
    for (const r of plain.body) expect(Object.keys(r)).not.toContain('search')
    for (const extra of ['&explain=0', '&explain=true', '&explain=yes', '&explain=', '&explain=11']) {
      const out = await get(`/api/memories?${Q}${extra}`)
      expect(out.raw, extra).not.toContain('"search"')
      expect(stable(out.body), extra).toEqual(stable(plain.body))
      expect(out.headers, extra).toEqual(plain.headers)
    }
  })

  it('(b) every row gets exactly {rrf, fts_rank, vec_rank, cos}, typed and rounded as documented, equal to the search\'s own numbers', async () => {
    stubEmbedder('ok')
    const out = await get(`/api/memories?${Q}&explain=1`)
    // All six rows: five match the keyword, the sixth only the vector branch.
    expect(out.body.length).toBe(6)
    const reference = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 10)
    expect(idsOf(out.body)).toEqual(reference.map(h => h.memory.id))
    out.body.forEach((row: any, i: number) => {
      const hit = reference[i]
      const s = row.search
      expect(Object.keys(s).sort(), `row ${i}`).toEqual(KEYS)
      expect(s.rrf, `rrf ${i}`).toBe(Math.round(hit.score * 1e6) / 1e6)
      expect(s.fts_rank, `fts_rank ${i}`).toBe(hit.ftsRank)
      expect(s.vec_rank, `vec_rank ${i}`).toBe(hit.vecRank)
      expect(s.cos, `cos ${i}`).toBe(hit.cosine === null ? null : Math.round(hit.cosine * 1e4) / 1e4)
      expect(typeof s.rrf).toBe('number')
      expect(Math.round(s.rrf * 1e6) / 1e6).toBe(s.rrf)
      if (s.cos !== null) {
        expect(Number.isFinite(s.cos)).toBe(true)
        expect(s.cos).toBeGreaterThanOrEqual(-1)
        expect(s.cos).toBeLessThanOrEqual(1)
        expect(Math.round(s.cos * 1e4) / 1e4).toBe(s.cos)
      }
      for (const k of ['fts_rank', 'vec_rank'] as const) {
        if (s[k] !== null) {
          expect(Number.isInteger(s[k])).toBe(true)
          expect(s[k]).toBeGreaterThanOrEqual(1)
        }
      }
    })
  })

  it('(b2) the three kinds of row: both branches, keyword only (cos and vec_rank null), vector only (fts_rank null)', async () => {
    stubEmbedder('ok')
    const out = await get(`/api/memories?${Q}&explain=1`)
    const byContent = (c: string) => out.body.find((r: any) => r.content === c).search
    const both = byContent('sprinkler tartaly')
    expect(both.fts_rank).not.toBeNull()
    expect(both.vec_rank).toBe(1)
    expect(both.cos).toBe(Math.round((0.9 / Math.sqrt(0.82)) * 1e4) / 1e4)
    const ftsOnly = byContent('sprinkler csak kulcsszo')
    expect(ftsOnly.fts_rank).not.toBeNull()
    expect(ftsOnly.vec_rank).toBeNull()
    expect(ftsOnly.cos).toBeNull()
    const vecOnly = byContent('kanban oszlop')
    expect(vecOnly.fts_rank).toBeNull()
    expect(vecOnly.vec_rank).not.toBeNull()
    expect(vecOnly.cos).not.toBeNull()
    // The fusion arithmetic: a row both branches returned outscores either alone at the same ranks.
    expect(both.rrf).toBeGreaterThan(ftsOnly.rrf)
  })

  it('(c) the order, the count and the rows are those of the same search without explain=1', async () => {
    stubEmbedder('ok')
    for (const limit of [1, 2, 3, 10]) {
      const plain = await get(`/api/memories?agent=${AGENT}&q=sprinkler&mode=hybrid&limit=${limit}`)
      const explained = await get(`/api/memories?agent=${AGENT}&q=sprinkler&mode=hybrid&limit=${limit}&explain=1`)
      expect(explained.body.length, `limit ${limit}`).toBe(plain.body.length)
      expect(idsOf(explained.body), `limit ${limit}`).toEqual(idsOf(plain.body))
      expect(stable(withoutSearch(explained.body)), `limit ${limit}`).toEqual(stable(plain.body))
      expect(explained.headers['x-memory-search'], `limit ${limit}`).toBe(plain.headers['x-memory-search'])
    }
  })

  it('(d) explain=1 on any other branch is ignored: 200, no `search`, the body of the same URL without it', async () => {
    stubEmbedder('ok')
    for (const q of [
      `agent=${AGENT}&q=sprinkler`, // keyword search with an agent
      `agent=${AGENT}&q=nincsilyenszoegyaltalan`, // keyword, LIKE fallback, nothing
      'q=sprinkler', // keyword search without an agent
      `agent=${AGENT}&q=sprinkler&strict=1`,
      `agent=${AGENT}`, // listing
      `agent=${AGENT}&mode=hybrid`, // hybrid mode without q is a listing
      'limit=3',
    ]) {
      const plain = await get(`/api/memories?${q}`)
      const out = await get(`/api/memories?${q}&explain=1`)
      expect(out.raw, q).not.toContain('"search"')
      expect(stable(out.body), q).toEqual(stable(plain.body))
      expect(out.headers, q).toEqual(plain.headers)
    }
  })

  it('(e) abstain=1, timing=1 and explain=1 together: all three answers, the rows unchanged', async () => {
    stubEmbedder('ok')
    const base = `/api/memories?${Q}&abstain=1`
    const plain = await get(base)
    const all = await get(`${base}&timing=1&explain=1`)
    expect(all.headers['x-memory-search']).toBe(plain.headers['x-memory-search'])
    expect(all.headers['x-memory-search']).toMatch(/; top-cos=\d\.\d\d; overlap=\d+; relevance=(low|ok|unknown)$/)
    expect(all.headers['server-timing']).toMatch(/^fts;dur=[0-9.]+, embed;dur=/)
    expect(idsOf(all.body)).toEqual(idsOf(plain.body))
    for (const r of all.body) expect(Object.keys(r.search).sort()).toEqual(KEYS)
  })

  it('(f) with a tier filter the numbers are the filtered search\'s, rows of other tiers are absent', async () => {
    stubEmbedder('ok')
    const warm = await get(`/api/memories?${Q}&category=warm&explain=1`)
    expect(warm.body.every((r: any) => r.category === 'warm')).toBe(true)
    expect(warm.body.map((r: any) => r.content)).not.toContain('sprinkler archiv')
    const refWarm = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 10, undefined, 'warm')
    expect(idsOf(warm.body)).toEqual(refWarm.map(h => h.memory.id))
    warm.body.forEach((r: any, i: number) => expect(r.search.fts_rank).toBe(refWarm[i].ftsRank))
    const cold = await get(`/api/memories?${Q}&tier=cold&explain=1`)
    expect(cold.body.map((r: any) => r.content)).toEqual(['sprinkler archiv'])
    expect(cold.body[0].search).toMatchObject({ fts_rank: 1, vec_rank: 1 })
  })

  it('(g) the vector never leaves: no embedding key, no stored vector in the text of the answer', async () => {
    stubEmbedder('ok')
    const out = await get(`/api/memories?${Q}&explain=1`)
    expect(out.raw).not.toContain('"embedding"')
    for (const r of out.body) expect(r.embedding).toBeUndefined()
    for (const frag of ['0.9,0.1', '0.5,0.5', '0.8,0.6', '0.7,0.3']) expect(out.raw).not.toContain(frag)
  })

  it('(h) the accessed_at stamp goes to the same ids as without explain=1, and lands in the DB', async () => {
    stubEmbedder('ok')
    const touch = vi.mocked(touchMemoriesAccessed)
    getDb().prepare('UPDATE memories SET accessed_at = 1790000000').run()
    await get(`/api/memories?${Q}`)
    const plainIds = touch.mock.calls.at(-1)![0]
    touch.mockClear()
    getDb().prepare('UPDATE memories SET accessed_at = 1790000000').run()
    const out = await get(`/api/memories?${Q}&explain=1`)
    expect(touch).toHaveBeenCalledTimes(1)
    expect(touch.mock.calls[0][0]).toEqual(plainIds)
    expect(touch.mock.calls[0][0]).toEqual(idsOf(out.body))
    const stamped = getDb().prepare(`SELECT COUNT(*) AS c FROM memories WHERE id IN (${plainIds.map(() => '?').join(',')}) AND accessed_at > 1790000000`).get(...plainIds) as { c: number }
    expect(stamped.c).toBe(plainIds.length)
  })

  it('(i) embedding backend down: the rows come from the keyword branch, so cos and vec_rank are null on every one', async () => {
    stubEmbedder('down')
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
    const out = await get(`/api/memories?${Q}&explain=1`)
    expect(out.body.length).toBeGreaterThan(0)
    out.body.forEach((r: any, i: number) => {
      expect(r.search.cos).toBeNull()
      expect(r.search.vec_rank).toBeNull()
      expect(r.search.fts_rank).toBe(i + 1)
    })
    expect(out.headers['x-memory-search']).toMatch(/vector=0;/)
  })

  it('(j) the recency term is in rrf: the route\'s number is the search\'s own, and it moves with the weight', async () => {
    stubEmbedder('ok')
    const off = await get(`/api/memories?${Q}&explain=1`)
    recencyState.weight = 0.01
    const on = await get(`/api/memories?${Q}&explain=1`)
    const ref = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 10)
    expect(on.body.map((r: any) => r.search.rrf)).toEqual(ref.map(h => Math.round(h.score * 1e6) / 1e6))
    const offById = new Map(off.body.map((r: any) => [r.id, r.search.rrf]))
    const fresh = on.body.find((r: any) => r.content === 'sprinkler tartaly')
    expect(fresh.search.rrf).toBeGreaterThan(offById.get(fresh.id) as number)
  })
})
