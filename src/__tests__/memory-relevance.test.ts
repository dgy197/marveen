// Card 94f8d99f, wave 2, node R1 (point 3): the relevance label of the hybrid
// search. abstain=1 adds `top-cos`, `overlap` and `relevance=low|ok|unknown` to
// X-Memory-Search; it is a label, the rows never change. Also MR1: a
// non-finite cosine (zero-norm stored vector) counts as 0 before the vector
// sort; MR3: a zero-norm or non-finite query vector empties the vector branch.
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

const abstainState = vi.hoisted(() => ({ minCos: null as number | null, wGap: 0, wOverlap: 0, wFts: 0 }))
const abstainInvalid = vi.hoisted(() => [] as string[])
vi.mock('../config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../config.js')>()
  return { ...orig, MEMORY_ABSTAIN_CONFIG: abstainState, MEMORY_ABSTAIN_INVALID: abstainInvalid }
})

import { resolveAbstainConfig, type AbstainConfig } from '../config.js'
import {
  initDatabase, getDb, hybridSearch, hybridSearchWith, clearMemoryCache, classifyRelevance, relevanceHeaderFields,
  RELEVANCE_OVERLAP_CAP, type HybridSearchTrace,
} from '../db.js'
import { logger } from '../logger.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import type { RouteContext } from '../web/routes/types.js'

// The recall hook's own check of the header value (elohivas_core._HEADER_VALUE_RE, used with fullmatch).
const MODA_HEADER_RE = /^[a-z0-9=;. -]{1,200}$/

const OFF: AbstainConfig = { minCos: null, wGap: 0, wOverlap: 0, wFts: 0 }
const cfgOf = (over: Partial<AbstainConfig>): AbstainConfig => ({ ...OFF, ...over })

function trace(over: Partial<HybridSearchTrace>): HybridSearchTrace {
  return { ftsHits: 10, vectorHits: 10, ftsRelaxed: true, vectorOnly: false, topCos: 0.5, secondCos: 0.5, overlap: 0, ...over }
}

describe('resolveAbstainConfig: MEMORY_ABSTAIN_* parsing', () => {
  const from = (env: Record<string, string>) => resolveAbstainConfig(k => env[k])

  it('unset = off: no threshold, every weight 0, nothing invalid', () => {
    expect(from({})).toEqual({ config: OFF, invalid: [] })
    expect(from({ MEMORY_ABSTAIN_MIN_COS: '  ' })).toEqual({ config: OFF, invalid: [] })
  })

  it('reads the threshold and the three weights', () => {
    const r = from({ MEMORY_ABSTAIN_MIN_COS: '0.53', MEMORY_ABSTAIN_W_GAP: '0.5', MEMORY_ABSTAIN_W_OVERLAP: '0.01', MEMORY_ABSTAIN_W_FTS: '0.02' })
    expect(r).toEqual({ config: { minCos: 0.53, wGap: 0.5, wOverlap: 0.01, wFts: 0.02 }, invalid: [] })
    expect(from({ MEMORY_ABSTAIN_MIN_COS: '1' }).config.minCos).toBe(1)
    expect(from({ MEMORY_ABSTAIN_MIN_COS: '0' }).config.minCos).toBe(0)
  })

  it('a bad threshold turns the label off; a bad weight counts as 0 (never negative: the rule stays monotone)', () => {
    for (const bad of ['-0.1', '11', 'abc', '1e-1', 'NaN', 'Infinity', '.5', '0,5']) {
      const r = from({ MEMORY_ABSTAIN_MIN_COS: bad, MEMORY_ABSTAIN_W_GAP: bad })
      expect(r.config.minCos, bad).toBeNull()
      expect(r.config.wGap, bad).toBe(0)
      expect(r.invalid, bad).toEqual(['MEMORY_ABSTAIN_MIN_COS', 'MEMORY_ABSTAIN_W_GAP'])
    }
    expect(from({ MEMORY_ABSTAIN_MIN_COS: '1.5' })).toEqual({ config: OFF, invalid: ['MEMORY_ABSTAIN_MIN_COS'] })
    expect(from({ MEMORY_ABSTAIN_W_OVERLAP: '2' }).invalid).toEqual(['MEMORY_ABSTAIN_W_OVERLAP'])
    expect(from({ MEMORY_ABSTAIN_W_FTS: '-1' }).invalid).toEqual(['MEMORY_ABSTAIN_W_FTS'])
  })
})

describe('classifyRelevance: the label decision', () => {
  it('unknown, never low, when the vector branch gave nothing (embedding failure / timeout / no vectors)', () => {
    const strict = cfgOf({ minCos: 0.99, wFts: 1 })
    for (const t of [
      trace({ topCos: null, secondCos: null, vectorHits: 0 }),
      trace({ topCos: undefined, secondCos: undefined }),
      trace({ topCos: 0.2, vectorHits: 0 }),
      trace({ topCos: Number.NaN }),
      trace({ topCos: null, ftsHits: 0, vectorHits: 0 }),
    ]) {
      expect(classifyRelevance(t, strict)).toEqual({ relevance: 'unknown', score: null })
    }
  })

  it('unknown when no threshold is configured (the default), the score is still reported', () => {
    expect(classifyRelevance(trace({ topCos: 0.1 }), OFF)).toEqual({ relevance: 'unknown', score: 0.1 })
  })

  it('topCos alone: below the threshold low, at or above it ok', () => {
    const c = cfgOf({ minCos: 0.53 })
    expect(classifyRelevance(trace({ topCos: 0.5299 }), c).relevance).toBe('low')
    expect(classifyRelevance(trace({ topCos: 0.53 }), c).relevance).toBe('ok')
    expect(classifyRelevance(trace({ topCos: 0.7 }), c).relevance).toBe('ok')
    // With every weight 0 the other signals do not matter.
    expect(classifyRelevance(trace({ topCos: 0.52, secondCos: 0.1, overlap: 9, ftsRelaxed: false }), c).relevance).toBe('low')
  })

  it('the gap (topCos - secondCos) lifts the score by its weight; no second row or a negative gap adds nothing', () => {
    const c = cfgOf({ minCos: 0.53, wGap: 0.5 })
    expect(classifyRelevance(trace({ topCos: 0.52, secondCos: 0.5 }), c)).toEqual({ relevance: 'ok', score: 0.52 + 0.5 * (0.52 - 0.5) })
    expect(classifyRelevance(trace({ topCos: 0.52, secondCos: 0.515 }), c).relevance).toBe('low')
    expect(classifyRelevance(trace({ topCos: 0.52, secondCos: null }), c)).toEqual({ relevance: 'low', score: 0.52 })
    expect(classifyRelevance(trace({ topCos: 0.52, secondCos: 0.6 }), c)).toEqual({ relevance: 'low', score: 0.52 })
  })

  it('the overlap lifts the score by its weight, counted up to RELEVANCE_OVERLAP_CAP shared rows', () => {
    const c = cfgOf({ minCos: 0.53, wOverlap: 0.01 })
    expect(RELEVANCE_OVERLAP_CAP).toBe(2)
    expect(classifyRelevance(trace({ topCos: 0.515, overlap: 1 }), c).relevance).toBe('low')
    expect(classifyRelevance(trace({ topCos: 0.515, overlap: 2 }), c).relevance).toBe('ok')
    expect(classifyRelevance(trace({ topCos: 0.505, overlap: 9 }), c)).toEqual({ relevance: 'low', score: 0.505 + 0.02 })
    expect(classifyRelevance(trace({ topCos: 0.52, overlap: undefined }), c)).toEqual({ relevance: 'low', score: 0.52 })
  })

  it('the keyword branch counts only when it matched without relaxing', () => {
    const c = cfgOf({ minCos: 0.53, wFts: 0.02 })
    expect(classifyRelevance(trace({ topCos: 0.52, ftsHits: 3, ftsRelaxed: false }), c)).toEqual({ relevance: 'ok', score: 0.54 })
    expect(classifyRelevance(trace({ topCos: 0.52, ftsHits: 3, ftsRelaxed: true }), c).relevance).toBe('low')
    expect(classifyRelevance(trace({ topCos: 0.52, ftsHits: 0, ftsRelaxed: false }), c).relevance).toBe('low')
  })

  it('monotone: raising any one signal never turns ok into low', () => {
    const c = cfgOf({ minCos: 0.53, wGap: 0.5, wOverlap: 0.01, wFts: 0.02 })
    let seed = 7
    const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648 }
    const rank = (r: string) => (r === 'ok' ? 1 : 0)
    for (let i = 0; i < 500; i++) {
      const top = 0.4 + rnd() * 0.25
      const t = trace({ topCos: top, secondCos: top - rnd() * 0.05, overlap: Math.floor(rnd() * 4), ftsRelaxed: rnd() < 0.5 })
      const base = classifyRelevance(t, c)
      const ups = [
        trace({ ...t, topCos: top + 0.01, secondCos: t.secondCos }),
        trace({ ...t, secondCos: t.secondCos! - 0.01 }),
        trace({ ...t, overlap: t.overlap! + 1 }),
        trace({ ...t, ftsRelaxed: false }),
      ]
      for (const u of ups) {
        const r = classifyRelevance(u, c)
        expect(r.score!).toBeGreaterThanOrEqual(base.score! - 1e-12)
        expect(rank(r.relevance)).toBeGreaterThanOrEqual(rank(base.relevance))
      }
    }
  })
})

describe('relevanceHeaderFields: the X-Memory-Search tail', () => {
  it('two-decimal cosine clamped to 0..1, "none" without a vector answer, raw overlap', () => {
    expect(relevanceHeaderFields(trace({ topCos: 0.5268, overlap: 3 }), 'low')).toBe('; top-cos=0.53; overlap=3; relevance=low')
    expect(relevanceHeaderFields(trace({ topCos: 1.0000001 }), 'ok')).toBe('; top-cos=1.00; overlap=0; relevance=ok')
    expect(relevanceHeaderFields(trace({ topCos: -0.2 }), 'low')).toBe('; top-cos=0.00; overlap=0; relevance=low')
    expect(relevanceHeaderFields(trace({ topCos: null, overlap: undefined }), 'unknown')).toBe('; top-cos=none; overlap=0; relevance=unknown')
  })

  it('a full header still fits the recall hook\'s value check', () => {
    const longest = 'fts=400; vector=400; relaxed=false; vector-only=false' + relevanceHeaderFields(trace({ topCos: 0.9, overlap: 10 }), 'unknown')
    expect(longest).toMatch(MODA_HEADER_RE)
  })
})

// ---------------------------------------------------------------------------
// A small store: the route and MR1 run on it
// ---------------------------------------------------------------------------
const AGENT = 'relagent'
const Q_VEC = [1, 0, 0, 0]

function cos(a: number[], b: number[]): number {
  let d = 0, na = 0, nb = 0
  for (let i = 0; i < a.length; i++) { d += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i] }
  return d / (Math.sqrt(na) * Math.sqrt(nb))
}

// Insertion order matters for MR1: the zero vector comes FIRST, where the old
// NaN comparator left it on top.
const ROWS: { content: string; emb: number[] | string }[] = [
  { content: 'nulla vektor sprinkler', emb: [0, 0, 0, 0] },
  { content: 'sprinkler szivattyu', emb: [0.5, 0.5, 0, 0] },
  { content: 'sprinkler tartaly', emb: [0.9, 0.1, 0, 0] },
  { content: 'kanban oszlop', emb: [0, 1, 0, 0] },
  { content: 'telegram gomb', emb: [0.2, 0.9, 0.3, 0] },
  { content: 'sprinkler fej', emb: [0.7, 0.3, 0.1, 0] },
]
const ids: number[] = []

type StubMode = 'ok' | 'down'
function stubEmbedder(mode: StubMode) {
  const fetchMock = vi.fn(async () => {
    if (mode === 'down') throw new Error('stub: embedding backend down')
    return { json: async () => ({ embedding: Q_VEC }) }
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function fakeCtx(pathAndQuery: string) {
  const out: { status: number; body: any; headers: Record<string, string> } = { status: 200, body: null, headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, string>) {
      out.status = status
      if (headers) for (const [k, v] of Object.entries(headers)) out.headers[k.toLowerCase()] = String(v)
      return res
    },
    setHeader(k: string, v: string) { out.headers[k.toLowerCase()] = String(v) },
    end(chunk?: any) { if (chunk) { try { out.body = JSON.parse(chunk.toString()) } catch { out.body = chunk.toString() } } },
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

/** What a row carries apart from the accessed_at stamp a search itself makes. */
const stable = (rows: any[]) => rows.map(r => ({ id: r.id, content: r.content, category: r.category }))

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(join(mkdtempSync(join(tmpdir(), 'r1-relevance-')), 'r1.db'))
  const insert = getDb().prepare(
    `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
     VALUES ('0', ?, 'semantic', 1.0, 1790000000, 1790000000, ?, 'warm', NULL, ?)`,
  )
  for (const r of ROWS) ids.push(Number(insert.run(r.content, AGENT, typeof r.emb === 'string' ? r.emb : JSON.stringify(r.emb)).lastInsertRowid))
})

afterAll(() => {
  initDatabase(':memory:')
})

afterEach(() => {
  Object.assign(abstainState, OFF)
  abstainInvalid.length = 0
  clearMemoryCache()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('MR1: a zero-norm vector counts as cosine 0 before the sort', () => {
  it('vector order by cosine, the zero row behind every positive one with cosine 0, topCos/secondCos finite', async () => {
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
    // A query with no keyword match, so the answer is the vector branch alone.
    const hits = await hybridSearchWith(getDb(), AGENT, 'qqqxyz', 10, t, undefined, { queryEmbedding: Q_VEC })
    expect(t.ftsHits).toBe(0)
    const expected = ROWS.map((r, i) => ({ id: ids[i], c: cos(Q_VEC, r.emb as number[]) }))
      .map(x => ({ ...x, c: Number.isFinite(x.c) ? x.c : 0 }))
      .sort((a, b) => b.c - a.c)
    expect(hits.map(h => h.memory.id)).toEqual(expected.map(x => x.id))
    const zero = hits.find(h => h.memory.id === ids[0])!
    expect(zero.cosine).toBe(0)
    expect(hits.every(h => Number.isFinite(h.cosine!))).toBe(true)
    expect(t.topCos).toBe(cos(Q_VEC, [0.9, 0.1, 0, 0]))
    expect(t.secondCos).toBe(cos(Q_VEC, [0.7, 0.3, 0.1, 0]))
    expect(hits[0].memory.id).toBe(ids[2])
  })

})

describe('MR3: a zero-norm or non-finite QUERY vector is an embedding failure, not "nothing similar"', () => {
  const BROKEN: [string, number[]][] = [
    ['zero', [0, 0, 0, 0]],
    ['NaN', [0.9, Number.NaN, 0, 0]],
    ['Infinity', [Number.POSITIVE_INFINITY, 0, 0, 0]],
    ['-Infinity', [0, 0, Number.NEGATIVE_INFINITY, 0]],
    ['overflowing norm', [1e200, 1e200, 0, 0]],
  ]

  for (const [name, vec] of BROKEN) {
    it(`${name}: the vector branch returns nothing, topCos null, relevance unknown even with a threshold`, async () => {
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
      const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
      // 'qqqxyz' matches no keyword: without the guard every row would come back at cosine 0.
      const none = await hybridSearchWith(getDb(), AGENT, 'qqqxyz', 10, t, undefined, { queryEmbedding: vec })
      expect(none).toEqual([])
      expect(t).toMatchObject({ vectorHits: 0, topCos: null, secondCos: null, overlap: 0, vectorOnly: false })
      expect(classifyRelevance(t, cfgOf({ minCos: 0.99 })).relevance).toBe('unknown')
      expect(classifyRelevance(t, cfgOf({ minCos: 0.0001, wFts: 1 })).relevance).toBe('unknown')

      // With a keyword match the rows still come, from the keyword branch only.
      const t2: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
      const kw = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 10, t2, undefined, { queryEmbedding: vec })
      expect(kw.length).toBeGreaterThan(0)
      expect(kw.every(h => h.vecRank === null && h.cosine === null)).toBe(true)
      expect(t2.topCos).toBeNull()
      expect(classifyRelevance(t2, cfgOf({ minCos: 0.99 })).relevance).toBe('unknown')
    })
  }

  it('a healthy query vector still scores (the guard is not a blanket refusal)', async () => {
    const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
    await hybridSearchWith(getDb(), AGENT, 'qqqxyz', 10, t, undefined, { queryEmbedding: [1e-150, 0, 0, 0] })
    expect(t.vectorHits).toBe(ROWS.length)
    expect(t.topCos).not.toBeNull()
  })

  it('the route: an embedder answering a zero vector gives top-cos=none and relevance=unknown, never low', async () => {
    abstainState.minCos = 0.999
    vi.stubGlobal('fetch', vi.fn(async () => ({ json: async () => ({ embedding: [0, 0, 0, 0] }) })))
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    const out = await get(`/api/memories?agent=${AGENT}&q=sprinkler&mode=hybrid&limit=4&abstain=1`)
    expect(out.headers['x-memory-search']).toMatch(/^fts=\d+; vector=0; relaxed=false; vector-only=false; top-cos=none; overlap=0; relevance=unknown$/)
    expect(out.body.length).toBeGreaterThan(0)
  })
})

describe('GET /api/memories abstain=1: a label in the header, the rows unchanged', () => {
  const Q = `agent=${AGENT}&q=sprinkler&mode=hybrid&limit=4`

  it('without abstain=1 the header is the old one, byte for byte, even with a threshold set', async () => {
    abstainState.minCos = 0.99
    stubEmbedder('ok')
    const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
    await hybridSearch(AGENT, 'sprinkler', 4, t)
    for (const extra of ['', '&abstain=0', '&abstain=true', '&abstain=yes']) {
      const out = await get(`/api/memories?${Q}${extra}`)
      expect(out.headers['x-memory-search'], extra).toBe(`fts=${t.ftsHits}; vector=${t.vectorHits}; relaxed=${t.ftsRelaxed}; vector-only=${t.vectorOnly}`)
    }
  })

  it('abstain=1 appends top-cos, overlap and relevance; the body is the same rows in the same order', async () => {
    stubEmbedder('ok')
    const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
    await hybridSearch(AGENT, 'sprinkler', 4, t)
    const base = `fts=${t.ftsHits}; vector=${t.vectorHits}; relaxed=${t.ftsRelaxed}; vector-only=${t.vectorOnly}`
    const plain = await get(`/api/memories?${Q}`)
    for (const [minCos, rel] of [[0.999, 'low'], [0.5, 'ok'], [null, 'unknown']] as const) {
      abstainState.minCos = minCos
      const out = await get(`/api/memories?${Q}&abstain=1`)
      const h = out.headers['x-memory-search']
      expect(h).toBe(`${base}; top-cos=0.99; overlap=${t.overlap}; relevance=${rel}`)
      expect(h).toMatch(MODA_HEADER_RE)
      expect(stable(out.body)).toEqual(stable(plain.body))
      expect(out.body.length).toBeGreaterThan(0)
    }
  })

  it('the weights reach the route: a strict keyword match lifts a low answer to ok', async () => {
    stubEmbedder('ok')
    abstainState.minCos = 0.999
    expect((await get(`/api/memories?${Q}&abstain=1`)).headers['x-memory-search']).toMatch(/relaxed=false; .*relevance=low$/)
    abstainState.wFts = 0.01
    expect((await get(`/api/memories?${Q}&abstain=1`)).headers['x-memory-search']).toMatch(/relevance=ok$/)
  })

  it('embedding backend down: relevance=unknown and top-cos=none, never low; rows still come (keyword branch)', async () => {
    abstainState.minCos = 0.999
    stubEmbedder('down')
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
    const out = await get(`/api/memories?${Q}&abstain=1`)
    expect(out.headers['x-memory-search']).toMatch(/^fts=\d+; vector=0; relaxed=false; vector-only=false; top-cos=none; overlap=0; relevance=unknown$/)
    expect(out.body.length).toBeGreaterThan(0)
  })

  it('an invalid MEMORY_ABSTAIN_* value: one WARN per process, the label still answers', async () => {
    stubEmbedder('ok')
    abstainInvalid.push('MEMORY_ABSTAIN_W_GAP')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    await get(`/api/memories?${Q}&abstain=1`)
    const out = await get(`/api/memories?${Q}&abstain=1`)
    const ours = warn.mock.calls.filter(c => String(c[1]).startsWith('memory relevance:'))
    expect(ours.length).toBe(1)
    expect(ours[0][0]).toEqual({ keys: ['MEMORY_ABSTAIN_W_GAP'] })
    expect(out.headers['x-memory-search']).toMatch(/relevance=unknown$/)
  })

  it('the strict=1 absence path ignores abstain=1: same header, same rows', async () => {
    abstainState.minCos = 0.999
    stubEmbedder('ok')
    for (const q of ['sprinkler', 'nincsilyenszo']) {
      const plain = await get(`/api/memories?agent=${AGENT}&q=${q}&strict=1`)
      const withAbstain = await get(`/api/memories?agent=${AGENT}&q=${q}&strict=1&abstain=1`)
      expect(withAbstain.headers['x-memory-search']).toBe(plain.headers['x-memory-search'])
      expect(withAbstain.headers['x-memory-search']).toMatch(/^strict=true; relaxed=false; hits=\d+$/)
      expect(stable(withAbstain.body)).toEqual(stable(plain.body))
    }
    // The keyword (non-hybrid) answer without strict ignores it too.
    const kw = await get(`/api/memories?agent=${AGENT}&q=sprinkler&abstain=1`)
    expect(kw.headers['x-memory-search']).toMatch(/^strict=false; relaxed=false; hits=\d+$/)
  })
})
