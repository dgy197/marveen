// Card 94f8d99f, memory program w3, node DW1: GET /api/memories?q=...&timing=1
// answers with a Server-Timing header (stage times in ms, numbers only). It is
// opt-in: without timing=1, or without q, the answer is the one it always was.
import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'

import {
  initDatabase, getDb, hybridSearch, hybridSearchWith, clearMemoryCache,
  type HybridSearchTrace, type SearchStageTimes,
} from '../db.js'
import { logger } from '../logger.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import {
  SERVER_TIMING_HYBRID, SERVER_TIMING_KEYWORD, formatTimingMs, serverTimingHeader,
} from '../web/server-timing.js'
import type { RouteContext } from '../web/routes/types.js'

// The recall hook's grammar for the whole header value (blueprint 4.2, used with fullmatch).
const HOOK_GRAMMAR = /^[a-z]{2,8};dur=[0-9]{1,6}(?:\.[0-9]{1,3})?(?:, [a-z]{2,8};dur=[0-9]{1,6}(?:\.[0-9]{1,3})?){0,11}$/
const ITEM = /^([a-z]+);dur=([0-9]+(?:\.[0-9])?)$/

const AGENT = 'timingagent'
const Q_VEC = [1, 0, 0, 0]
const ROWS: { content: string; emb: number[] }[] = [
  { content: 'sprinkler szivattyu', emb: [0.5, 0.5, 0, 0] },
  { content: 'sprinkler tartaly', emb: [0.9, 0.1, 0, 0] },
  { content: 'kanban oszlop', emb: [0, 1, 0, 0] },
  { content: 'telegram gomb', emb: [0.2, 0.9, 0.3, 0] },
  { content: 'sprinkler fej', emb: [0.7, 0.3, 0.1, 0] },
]

type StubMode = 'ok' | 'down'
function stubEmbedder(mode: StubMode, delayMs = 0) {
  const fetchMock = vi.fn(async () => {
    if (delayMs > 0) await new Promise(r => setTimeout(r, delayMs))
    if (mode === 'down') throw new Error('stub: embedding backend down')
    return { json: async () => ({ embedding: Q_VEC }) }
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function fakeCtx(pathAndQuery: string) {
  const out: { status: number; body: any; headers: Record<string, string>; setHeaderCalls: string[] } =
    { status: 200, body: null, headers: {}, setHeaderCalls: [] }
  const res: any = {
    writeHead(status: number, headers?: Record<string, string>) {
      out.status = status
      if (headers) for (const [k, v] of Object.entries(headers)) out.headers[k.toLowerCase()] = String(v)
      return res
    },
    setHeader(k: string, v: string) { out.setHeaderCalls.push(k.toLowerCase()); out.headers[k.toLowerCase()] = String(v) },
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

/** The body without the stamp a search itself makes (accessed_at and its label). */
const stable = (rows: any[]) => rows.map(r => {
  const { accessed_at: _a, accessed_label: _l, ...rest } = r
  return rest
})

/** Parse a header value into [name, number][] (asserting the hook's grammar). */
function parseTiming(value: string | undefined): [string, number][] {
  expect(value).toBeDefined()
  expect(value!).toMatch(HOOK_GRAMMAR)
  return value!.split(', ').map(item => {
    const m = ITEM.exec(item)
    expect(m, item).not.toBeNull()
    return [m![1], Number(m![2])] as [string, number]
  })
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(join(mkdtempSync(join(tmpdir(), 'w3-timing-')), 'timing.db'))
  const insert = getDb().prepare(
    `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
     VALUES ('0', ?, 'semantic', 1.0, 1790000000, 1790000000, ?, 'warm', NULL, ?)`,
  )
  for (const r of ROWS) insert.run(r.content, AGENT, JSON.stringify(r.emb))
})

afterAll(() => {
  initDatabase(':memory:')
})

afterEach(() => {
  clearMemoryCache()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('formatTimingMs / serverTimingHeader: the value grammar', () => {
  it('finite, non-negative, at most one decimal; anything else is 0', () => {
    expect(formatTimingMs(12)).toBe('12')
    expect(formatTimingMs(12.345)).toBe('12.3')
    expect(formatTimingMs(12.35)).toBe('12.4')
    expect(formatTimingMs(0.04)).toBe('0')
    expect(formatTimingMs(0.06)).toBe('0.1')
    for (const bad of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, -1, -0.0001, 0]) {
      expect(formatTimingMs(bad)).toBe('0')
    }
    expect(formatTimingMs('12' as unknown as number)).toBe('0')
    expect(formatTimingMs(undefined as unknown as number)).toBe('0')
  })

  it('clamped to six integer digits so the hook grammar always fits', () => {
    expect(formatTimingMs(1e9)).toBe('999999.9')
    expect(formatTimingMs(999999.94)).toBe('999999.9')
    expect(formatTimingMs(Number.MAX_VALUE)).toBe('999999.9')
  })

  it('every value, however odd, renders as a grammar-conforming item', () => {
    let seed = 11
    const rnd = () => { seed = (seed * 1103515245 + 12345) % 2147483648; return seed / 2147483648 }
    const odd = [0, 1e-9, 0.05, 0.95, 5e-324, 1e21, 123456.78, 999999.95, -5]
    for (let i = 0; i < 300; i++) odd.push(rnd() * Math.pow(10, Math.floor(rnd() * 9) - 3))
    for (const v of odd) {
      const header = serverTimingHeader(SERVER_TIMING_KEYWORD, { fts: v, touch: v, fmt: v, total: v })
      expect(header, String(v)).toMatch(HOOK_GRAMMAR)
    }
  })

  it('names in the fixed order, a missing stage is dur=0, no desc and no letters beyond names and dur', () => {
    expect(SERVER_TIMING_HYBRID).toEqual(['fts', 'embed', 'vecsql', 'vecscore', 'fuse', 'touch', 'fmt', 'total'])
    expect(SERVER_TIMING_KEYWORD).toEqual(['fts', 'touch', 'fmt', 'total'])
    expect(serverTimingHeader(SERVER_TIMING_HYBRID, { total: 3.14, fts: 1 }))
      .toBe('fts;dur=1, embed;dur=0, vecsql;dur=0, vecscore;dur=0, fuse;dur=0, touch;dur=0, fmt;dur=0, total;dur=3.1')
  })
})

describe('hybridSearchWith: HybridSearchOptions.timing', () => {
  const T0: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
  const fresh = (): SearchStageTimes => ({ fts: -1, embed: -1, vecsql: -1, vecscore: -1, fuse: -1 })

  it('fills all five stages (each a real elapsed time, > 0) and the answer is the one without timing', async () => {
    stubEmbedder('ok', 15)
    const timing = fresh()
    const t1 = { ...T0 }
    const t2 = { ...T0 }
    const withTiming = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, t1, undefined, { timing })
    const without = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, t2)
    expect(withTiming.map(h => [h.memory.id, h.score, h.ftsRank, h.vecRank, h.cosine]))
      .toEqual(without.map(h => [h.memory.id, h.score, h.ftsRank, h.vecRank, h.cosine]))
    expect(t1).toEqual(t2)
    for (const k of ['fts', 'embed', 'vecsql', 'vecscore', 'fuse'] as const) {
      expect(Number.isFinite(timing[k]), k).toBe(true)
      expect(timing[k], k).toBeGreaterThan(0)
    }
    // The embedding stage is the wait for the (15 ms) embedder, nothing else.
    expect(timing.embed).toBeGreaterThanOrEqual(10)
    expect(timing.fts).toBeLessThan(timing.embed)
  })

  it('a caller-supplied query vector: embed is ~0, the vector stages still run', async () => {
    const timing = fresh()
    await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, undefined, undefined, { timing, queryEmbedding: Q_VEC })
    expect(timing.embed).toBeGreaterThanOrEqual(0)
    expect(timing.embed).toBeLessThan(5)
    expect(timing.vecsql).toBeGreaterThan(0)
    expect(timing.vecscore).toBeGreaterThan(0)
  })

  it('embedding failure: embed > 0, vecsql and vecscore stay 0, fuse still runs', async () => {
    stubEmbedder('down', 15)
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
    const timing = fresh()
    const hits = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, undefined, undefined, { timing })
    expect(hits.length).toBeGreaterThan(0)
    expect(timing.embed).toBeGreaterThanOrEqual(10)
    expect(timing.vecsql).toBe(0)
    expect(timing.vecscore).toBe(0)
    expect(timing.fts).toBeGreaterThan(0)
    expect(timing.fuse).toBeGreaterThan(0)
  })

  it('an unusable (zero-norm) query vector never reaches the SQL stage', async () => {
    const timing = fresh()
    await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, undefined, undefined, { timing, queryEmbedding: [0, 0, 0, 0] })
    expect(timing.vecsql).toBe(0)
    expect(timing.vecscore).toBe(0)
  })

  it('a reused object is reset first: stale values never leak into a search that skipped a stage', async () => {
    const timing: SearchStageTimes = { fts: 9e6, embed: 9e6, vecsql: 9e6, vecscore: 9e6, fuse: 9e6 }
    await hybridSearchWith(getDb(), AGENT, 'sprinkler', 4, undefined, undefined, { timing, queryEmbedding: null })
    expect(timing.vecsql).toBe(0)
    expect(timing.vecscore).toBe(0)
    expect(timing.fts).toBeLessThan(1e6)
    expect(timing.embed).toBeLessThan(1e6)
  })

  it('the category filter and the cut are the same with timing', async () => {
    stubEmbedder('ok')
    const a = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 2, undefined, 'warm', { timing: fresh() })
    const b = await hybridSearchWith(getDb(), AGENT, 'sprinkler', 2, undefined, 'warm')
    expect(a.map(h => h.memory.id)).toEqual(b.map(h => h.memory.id))
    expect(a.length).toBe(2)
  })
})

describe('GET /api/memories: Server-Timing is opt-in', () => {
  const HYB = `agent=${AGENT}&q=sprinkler&mode=hybrid&limit=4`

  it('(a) without timing=1 there is no Server-Timing and the answer is the old one: same header set, same X-Memory-Search, same body', async () => {
    stubEmbedder('ok')
    const t: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
    await hybridSearch(AGENT, 'sprinkler', 4, t)
    const plain = await get(`/api/memories?${HYB}`)
    expect(plain.setHeaderCalls).toEqual(['x-memory-search'])
    expect(Object.keys(plain.headers).sort()).toEqual(['cache-control', 'content-type', 'vary', 'x-memory-search'])
    expect(plain.headers['x-memory-search']).toBe(`fts=${t.ftsHits}; vector=${t.vectorHits}; relaxed=${t.ftsRelaxed}; vector-only=${t.vectorOnly}`)
    for (const extra of ['&timing=0', '&timing=true', '&timing=yes', '&timing=', '&timing=11']) {
      const out = await get(`/api/memories?${HYB}${extra}`)
      expect(out.headers['server-timing'], extra).toBeUndefined()
      expect(out.headers, extra).toEqual(plain.headers)
      expect(stable(out.body), extra).toEqual(stable(plain.body))
    }
  })

  it('(a2) with timing=1 everything else is untouched: the other headers and the body match the plain answer', async () => {
    stubEmbedder('ok')
    const plain = await get(`/api/memories?${HYB}`)
    const timed = await get(`/api/memories?${HYB}&timing=1`)
    const { 'server-timing': st, ...others } = timed.headers
    expect(st).toBeDefined()
    expect(others).toEqual(plain.headers)
    expect(timed.setHeaderCalls.filter(h => h === 'server-timing').length).toBe(1)
    expect(stable(timed.body)).toEqual(stable(plain.body))
    expect(timed.body.length).toBeGreaterThan(0)
  })

  it('(b) hybrid + timing=1: one header on the hook grammar, the 8 names in order, finite, >= 0, total covers every stage', async () => {
    stubEmbedder('ok', 15)
    const out = await get(`/api/memories?${HYB}&timing=1`)
    const items = parseTiming(out.headers['server-timing'])
    expect(items.map(([n]) => n)).toEqual([...SERVER_TIMING_HYBRID])
    const byName = Object.fromEntries(items)
    for (const [n, v] of items) {
      expect(Number.isFinite(v), n).toBe(true)
      expect(v, n).toBeGreaterThanOrEqual(0)
      expect(byName.total, n).toBeGreaterThanOrEqual(v)
    }
    // The 15 ms embedder shows up in `embed` and so in `total`.
    expect(byName.embed).toBeGreaterThanOrEqual(10)
    expect(byName.total).toBeGreaterThanOrEqual(byName.embed)
    // ...and the stages add up to no more than the total (rounding: 0.1 per item).
    const sum = ['fts', 'embed', 'vecsql', 'vecscore', 'fuse', 'touch', 'fmt'].reduce((s, n) => s + byName[n], 0)
    expect(sum).toBeLessThanOrEqual(byName.total + 0.8)
  })

  it('(c) keyword search (with an agent, and without one): the 4 names, the LIKE fallback inside fts', async () => {
    for (const q of [`agent=${AGENT}&q=sprinkler`, `agent=${AGENT}&q=nincsilyenszoegyaltalan`, 'q=sprinkler']) {
      const out = await get(`/api/memories?${q}&timing=1`)
      const items = parseTiming(out.headers['server-timing'])
      expect(items.map(([n]) => n), q).toEqual([...SERVER_TIMING_KEYWORD])
      for (const [n, v] of items) {
        expect(v, `${q} ${n}`).toBeGreaterThanOrEqual(0)
        expect(Object.fromEntries(items).total, `${q} ${n}`).toBeGreaterThanOrEqual(v)
      }
      expect(out.headers['x-memory-search'], q).toMatch(/^strict=(true|false); relaxed=(true|false); hits=\d+$/)
    }
  })

  it('(d) a listing, with or without timing=1, never carries Server-Timing; mode=hybrid without q is a listing', async () => {
    for (const q of [`agent=${AGENT}`, `agent=${AGENT}&mode=hybrid`, 'limit=3', `agent=${AGENT}&q=`, `agent=${AGENT}&q=%20%20`]) {
      const out = await get(`/api/memories?${q}&timing=1`)
      expect(out.headers['server-timing'], q).toBeUndefined()
      expect(out.setHeaderCalls, q).toEqual(['x-memory-search'])
      expect(out.headers['x-memory-search'], q).toMatch(/^listing=true; /)
    }
  })

  it('(e) embedding backend down: still 200 with the header; the dead embed wait shows in embed, the vector stages are 0', async () => {
    stubEmbedder('down', 15)
    vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
    const out = await get(`/api/memories?${HYB}&timing=1`)
    const byName = Object.fromEntries(parseTiming(out.headers['server-timing']))
    expect(byName.embed).toBeGreaterThanOrEqual(10)
    expect(byName.vecsql).toBe(0)
    expect(byName.vecscore).toBe(0)
    expect(out.headers['x-memory-search']).toMatch(/vector=0;/)
    expect(out.body.length).toBeGreaterThan(0)
  })

  it('(g) the value holds nothing but the fixed names, "dur=" and numbers: no desc, no query text, no agent', async () => {
    stubEmbedder('ok')
    const out = await get(`/api/memories?agent=${AGENT}&q=sprinkler%20szivattyu&mode=hybrid&limit=4&timing=1`)
    const value = out.headers['server-timing']
    const letters = value.replace(/dur=/g, '').replace(/[^a-z]/g, '')
    expect(letters).toBe(SERVER_TIMING_HYBRID.join(''))
    expect(value).not.toContain(AGENT)
    expect(value).not.toContain('sprinkler')
    expect(value).not.toContain('desc')
  })

  it('timing=1 beside abstain=1 and tier: both headers, rows unchanged', async () => {
    stubEmbedder('ok')
    const base = `/api/memories?${HYB}&abstain=1&category=warm`
    const plain = await get(base)
    const timed = await get(`${base}&timing=1`)
    expect(timed.headers['x-memory-search']).toBe(plain.headers['x-memory-search'])
    expect(timed.headers['server-timing']).toMatch(HOOK_GRAMMAR)
    expect(stable(timed.body)).toEqual(stable(plain.body))
  })

  it('the stages are what the clock says: every stage one interval of a scripted clock, total from the handler start to the header', async () => {
    stubEmbedder('ok')
    let t = 0
    // 10 ms per read. The route and hybridSearchWith read the clock 13 times in a hybrid answer:
    // handler start, search start, search mark, fts, embed, vecsql start, vecsql end, vecscore end, fuse mark, fuse end, touch start, fmt start, done.
    const spy = vi.spyOn(performance, 'now').mockImplementation(() => { t += 10; return t })
    const hybrid = await get(`/api/memories?${HYB}&timing=1`)
    const hybridReads = spy.mock.calls.length
    expect(parseTiming(hybrid.headers['server-timing'])).toEqual([
      ['fts', 10], ['embed', 10], ['vecsql', 10], ['vecscore', 10], ['fuse', 10], ['touch', 10], ['fmt', 10], ['total', (hybridReads - 1) * 10],
    ])
    expect(hybridReads).toBe(13)

    t = 0
    spy.mockClear()
    const kw = await get(`/api/memories?agent=${AGENT}&q=sprinkler&timing=1`)
    expect(parseTiming(kw.headers['server-timing'])).toEqual([
      ['fts', 10], ['touch', 10], ['fmt', 10], ['total', (spy.mock.calls.length - 1) * 10],
    ])
    expect(spy.mock.calls.length).toBe(6)
  })

  it('a clock that steps backwards cannot make the header invalid', async () => {
    stubEmbedder('ok')
    let t = 1000
    vi.spyOn(performance, 'now').mockImplementation(() => { t -= 7; return t })
    const out = await get(`/api/memories?${HYB}&timing=1`)
    const items = parseTiming(out.headers['server-timing'])
    for (const [, v] of items) expect(v).toBe(0)
  })
})
