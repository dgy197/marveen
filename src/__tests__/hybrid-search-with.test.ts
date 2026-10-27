// Card 94f8d99f, wave 2, node R0: hybridSearch was split into hybridSearchWith
// (injectable DB handle, per-row scores) plus a thin hybridSearch wrapper, so a
// read-only measurement harness can run the production ranking on a read-only
// handle. The refactor must not change what the existing callers get.
//
// The reference below is a FROZEN copy of the pre-R0 hybrid search (db.ts at
// c55269f8: hybridSearch, vectorSearch, cosineSimilarity, searchAgentMemories,
// ftsWithOrFallback, reRankByRecency), parameterised only on the DB handle. The
// equivalence suite ran green against the unrefactored code first, which pins
// the copy to the real old behaviour; it then has to stay green on the new code.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import Database from 'better-sqlite3'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import {
  initDatabase, getDb, hybridSearch, hybridSearchWith, fuseRanked, clearMemoryCache, generateEmbedding,
  queryLogFields, buildFtsMatchExpression, HYBRID_RRF_K, HYBRID_OVERLAP_TOP,
  type Memory, type HybridSearchTrace,
} from '../db.js'
import { logger } from '../logger.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import type { RouteContext } from '../web/routes/types.js'

// ---------------------------------------------------------------------------
// Frozen pre-R0 reference (do not "fix" it: it is the old behaviour on purpose)
// ---------------------------------------------------------------------------
const LEGACY_RECENCY_LAMBDA = 0.7
const LEGACY_RECENCY_TAU_SEC = 7 * 86400
const LEGACY_RECENCY_OVERSAMPLE = 4

function legacyFtsWithOrFallback<T>(query: string, run: (terms: string) => T[], allowRelaxed = true): { rows: T[]; relaxed: boolean } {
  const strict = buildFtsMatchExpression(query)
  if (!strict) return { rows: [], relaxed: false }
  const rows = run(strict)
  if (rows.length > 0) return { rows, relaxed: false }
  if (!allowRelaxed) return { rows, relaxed: false }
  const relaxedTerms = buildFtsMatchExpression(query, 'OR')
  if (relaxedTerms === strict) return { rows, relaxed: false }
  return { rows: run(relaxedTerms), relaxed: true }
}

function legacyReRankByRecency<T extends { rank: number; created_at: number }>(rows: T[], limit: number, nowSec: number = Math.floor(Date.now() / 1000)): T[] {
  return rows
    .map((row) => {
      const relevance = row.rank < 0 ? -row.rank / (1 - row.rank) : 0
      const ageSec = Math.max(0, nowSec - row.created_at)
      const recency = Math.exp(-ageSec / LEGACY_RECENCY_TAU_SEC)
      return { row, score: LEGACY_RECENCY_LAMBDA * relevance + (1 - LEGACY_RECENCY_LAMBDA) * recency }
    })
    .sort((a, b) => b.score - a.score)
    .slice(0, limit)
    .map((x) => x.row)
}

function legacySearchAgentMemories(db: Database.Database, agentId: string, query: string, limit: number, trace: { relaxed: boolean }, allowRelaxed: boolean, category?: string): Memory[] {
  try {
    const { rows, relaxed } = legacyFtsWithOrFallback(query, (terms) =>
      (category
        ? db.prepare(
            `SELECT m.*, f.rank AS rank FROM memories m
             JOIN memories_fts f ON m.id = f.rowid
             WHERE f.memories_fts MATCH ? AND (m.agent_id = ? OR m.category = 'shared')
               AND m.category = ?
             ORDER BY rank LIMIT ?`
          ).all(terms, agentId, category, limit * LEGACY_RECENCY_OVERSAMPLE)
        : db.prepare(
            `SELECT m.*, f.rank AS rank FROM memories m
             JOIN memories_fts f ON m.id = f.rowid
             WHERE f.memories_fts MATCH ? AND (m.agent_id = ? OR m.category = 'shared')
             ORDER BY rank LIMIT ?`
          ).all(terms, agentId, limit * LEGACY_RECENCY_OVERSAMPLE)) as (Memory & { rank: number })[]
    , allowRelaxed)
    trace.relaxed = relaxed
    return legacyReRankByRecency(rows, limit).map(({ rank: _rank, ...rest }) => rest) as Memory[]
  } catch {
    return (category
      ? db.prepare(
          "SELECT * FROM memories WHERE (agent_id = ? OR category = 'shared') AND category = ? AND (content LIKE ? OR keywords LIKE ?) ORDER BY accessed_at DESC LIMIT ?"
        ).all(agentId, category, `%${query}%`, `%${query}%`, limit)
      : db.prepare(
          "SELECT * FROM memories WHERE (agent_id = ? OR category = 'shared') AND (content LIKE ? OR keywords LIKE ?) ORDER BY accessed_at DESC LIMIT ?"
        ).all(agentId, `%${query}%`, `%${query}%`, limit)) as Memory[]
  }
}

function legacyCosine(a: number[], b: number[]): number {
  let dotProduct = 0, normA = 0, normB = 0
  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i]
    normA += a[i] * a[i]
    normB += b[i] * b[i]
  }
  return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB))
}

function legacyVectorSearch(db: Database.Database, agentId: string, queryEmbedding: number[], limit: number, category?: string): Memory[] {
  const rows = (category
    ? db.prepare(
        "SELECT * FROM memories WHERE embedding IS NOT NULL AND (agent_id = ? OR category = 'shared') AND category = ?"
      ).all(agentId, category)
    : db.prepare(
        "SELECT * FROM memories WHERE embedding IS NOT NULL AND (agent_id = ? OR category = 'shared')"
      ).all(agentId)) as Memory[]
  const scored = rows.flatMap(m => {
    try {
      const emb = JSON.parse(m.embedding!) as number[]
      if (emb.length !== queryEmbedding.length) return []
      return [{ memory: m, score: legacyCosine(queryEmbedding, emb) }]
    } catch {
      return [{ memory: m, score: 0 }]
    }
  })
  scored.sort((a, b) => b.score - a.score)
  return scored.slice(0, limit).map(s => s.memory)
}

async function legacyHybridSearch(db: Database.Database, agentId: string, query: string, limit = 10, trace?: HybridSearchTrace, category?: string): Promise<Memory[]> {
  const k = 60
  const ftsTrace = { relaxed: false }
  const ftsResults = legacySearchAgentMemories(db, agentId, query, limit * 2, ftsTrace, true, category)
  const queryEmbedding = await generateEmbedding(query)
  const vecResults = queryEmbedding ? legacyVectorSearch(db, agentId, queryEmbedding, limit * 2, category) : []
  if (trace) {
    trace.ftsHits = ftsResults.length
    trace.vectorHits = vecResults.length
    trace.ftsRelaxed = ftsTrace.relaxed
    trace.vectorOnly = ftsResults.length === 0 && vecResults.length > 0
  }
  if (ftsResults.length === 0 && vecResults.length > 0) {
    logger.warn(
      { agentId, ...queryLogFields(query), vectorHits: vecResults.length },
      'hybrid search: the keyword branch found nothing, the answer comes from the vector branch alone',
    )
  }
  const scores: Map<number, number> = new Map()
  const byId: Map<number, Memory> = new Map()
  ftsResults.forEach((m, rank) => {
    scores.set(m.id, (scores.get(m.id) || 0) + 1 / (k + rank + 1))
    byId.set(m.id, m)
  })
  vecResults.forEach((m, rank) => {
    scores.set(m.id, (scores.get(m.id) || 0) + 1 / (k + rank + 1))
    byId.set(m.id, m)
  })
  const ranked = [...scores.entries()].sort((a, b) => b[1] - a[1])
  return ranked.slice(0, limit).map(([id]) => byId.get(id)!)
}

// ---------------------------------------------------------------------------
// Deterministic seed: words with fixed vectors, a seeded PRNG, fixed clock
// ---------------------------------------------------------------------------
const DIMS = 8
const NOW_SEC = 1_790_000_000
const VOCAB = [
  'tuzjelzo', 'sprinkler', 'szamla', 'billingo', 'kanban', 'telegram', 'ollama', 'vektor',
  'memoria', 'hatarido', 'projekt', 'szerzodes', 'engedely', 'gomb', 'session', 'token',
  'vault', 'napló', 'árvíztűrő', 'tükörfúrógép',
]

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

function hashVec(word: string): number[] {
  let h = 2166136261
  for (const ch of word) h = Math.imul(h ^ ch.codePointAt(0)!, 16777619) >>> 0
  const r = mulberry32(h)
  return Array.from({ length: DIMS }, () => Math.round((r() * 2 - 1) * 1000) / 1000)
}

const WORD_VEC = new Map(VOCAB.map(w => [w, hashVec(w)]))

/** Sum of the word vectors of the text (unknown words get their own hash vector). */
function embedText(text: string): number[] {
  const out = new Array(DIMS).fill(0)
  const words = text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean)
  for (const w of words) {
    const v = WORD_VEC.get(w) ?? hashVec(w).map(x => x * 0.3)
    for (let i = 0; i < DIMS; i++) out[i] += v[i]
  }
  return out.map(x => Math.round(x * 1000) / 1000)
}

type EmbedMode = 'hybrid' | 'fts-only' | 'embedder-error'

function stubEmbedder(mode: EmbedMode) {
  const fetchMock = vi.fn(async (_url: string, init?: { body?: string }) => {
    if (mode === 'embedder-error') throw new Error('stub: embedding backend down')
    if (mode === 'fts-only') return { json: async () => ({ embedding: [] }) }
    const prompt = String(JSON.parse(init?.body ?? '{}').prompt ?? '')
    return { json: async () => ({ embedding: embedText(prompt) }) }
  })
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

let dbPath = ''

function seed(db: Database.Database): void {
  const r = mulberry32(20261017)
  const insert = db.prepare(
    `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
     VALUES ('0', ?, 'semantic', 1.0, ?, ?, ?, ?, ?, ?)`
  )
  const agents = ['eqa', 'eqb', 'eqc']
  const cats = ['hot', 'warm', 'cold', 'shared']
  const pick = <T>(xs: T[]): T => xs[Math.floor(r() * xs.length)]
  for (let i = 0; i < 64; i++) {
    const n = 2 + Math.floor(r() * 5)
    const words = Array.from({ length: n }, () => pick(VOCAB))
    const content = `${words.join(' ')} sor ${i}`
    const keywords = i % 5 === 0 ? null : Array.from({ length: 1 + Math.floor(r() * 2) }, () => pick(VOCAB)).join(', ')
    // A few rows share a creation second, so FTS recency ties exist too.
    const createdAt = NOW_SEC - (i % 7 === 0 ? 3600 : Math.floor(r() * 90 * 86400))
    let embedding: string | null = JSON.stringify(embedText(`${content} ${keywords ?? ''}`))
    if (i % 9 === 4) embedding = null                                         // not embedded yet
    if (i === 10) embedding = JSON.stringify([1, 0, 0, 0, 0, 0])              // another model's length
    if (i === 11) embedding = 'not-json'                                      // malformed: scores 0
    if (i === 12 || i === 13) embedding = JSON.stringify(embedText('tuzjelzo sprinkler'))  // exact cosine tie
    insert.run(content, createdAt, createdAt - (i % 3), pick(agents), pick(cats), keywords, embedding)
  }
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  dbPath = join(mkdtempSync(join(tmpdir(), 'r0-hybrid-')), 'seed.db')
  initDatabase(dbPath)
  seed(getDb())
})

afterAll(() => {
  // Leave the module on a private in-memory handle, not on the temp file.
  initDatabase(':memory:')
})

beforeEach(() => {
  clearMemoryCache()
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(NOW_SEC * 1000)
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

const QUERIES = [
  'tuzjelzo', 'tuzjelzo sprinkler', 'szamla billingo hatarido', 'kanban', 'telegram gomb session',
  'ollama vektor memoria', 'projekt', 'szerzodes engedely', 'token vault', 'árvíztűrő',
  'tükörfúrógép napló', 'zzzznincsilyenszo', 'xqxq yqyq', 'tuzjelzo zzzznincs',
  'sprinkler kanban telegram ollama', 'sor', 'sor 1', '"tuzjelzo"', 'tuzjelzo*', 'memoria OR kanban',
  'NOT kanban', '-kanban', 'a', '', 'billingo; DROP TABLE memories', 'hatarido projekt szerzodes token',
]
const AGENTS = ['eqa', 'eqb', 'nincs-ilyen']
const LIMITS = [3, 5, 10]
const CATEGORIES: (string | undefined)[] = [undefined, 'warm', 'shared']
const MODES: EmbedMode[] = ['hybrid', 'fts-only', 'embedder-error']

function freshTrace(): HybridSearchTrace {
  return { ftsHits: -1, vectorHits: -1, ftsRelaxed: true, vectorOnly: true }
}

function isZeroNorm(v: number[]): boolean {
  return v.every(x => x === 0)
}

function hybridWarns(spy: { mock: { calls: unknown[][] } }): unknown[] {
  return spy.mock.calls.filter((c: unknown[]) => String(c[1]).startsWith('hybrid search:'))
}

describe('R0 equivalence: hybridSearch returns exactly what the pre-R0 code returned', () => {
  for (const mode of MODES) {
    it(`${mode}: same rows, same order, same trace, same WARN, same embedder calls`, async () => {
      const db = getDb()
      let combos = 0
      let zeroQueries = 0
      let nonEmpty = 0
      let vectorOnly = 0
      for (const q of QUERIES) for (const agent of AGENTS) for (const limit of LIMITS) for (const cat of CATEGORIES) {
        const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
        vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)

        // MR3, the one intended change: a zero-norm query vector (here the empty
        // query) no longer yields a vector branch of all-cosine-0 rows; the new
        // code answers what the old one answered when the embedder gave nothing.
        const legacyMode: EmbedMode = mode === 'hybrid' && isZeroNorm(embedText(q)) ? 'fts-only' : mode
        if (legacyMode !== mode) zeroQueries++
        const fetchOld = stubEmbedder(legacyMode)
        const oldTrace = freshTrace()
        const oldRows = await legacyHybridSearch(db, agent, q, limit, oldTrace, cat)
        const oldWarns = hybridWarns(warn)
        const oldFetches = fetchOld.mock.calls.length
        warn.mockClear()

        const fetchNew = stubEmbedder(mode)
        const newTrace = freshTrace()
        const newRows = await hybridSearch(agent, q, limit, newTrace, cat)
        const newWarns = hybridWarns(warn)

        const where = JSON.stringify({ mode, q, agent, limit, cat })
        expect(newRows.map(m => m.id), where).toEqual(oldRows.map(m => m.id))
        // Whole rows, not only ids: the same object shape (no stray rank or score keys).
        expect(newRows, where).toEqual(oldRows)
        expect(newRows.map(m => Object.keys(m)), where).toEqual(oldRows.map(m => Object.keys(m)))
        expect({ ...newTrace, topCos: undefined, secondCos: undefined, overlap: undefined }, where)
          .toEqual({ ...oldTrace, topCos: undefined, secondCos: undefined, overlap: undefined })
        expect(newWarns, where).toEqual(oldWarns)
        expect(fetchNew.mock.calls.length, where).toBe(oldFetches)
        vi.restoreAllMocks()

        combos++
        if (oldRows.length > 0) nonEmpty++
        if (oldTrace.vectorOnly) vectorOnly++
      }
      expect(combos).toBe(QUERIES.length * AGENTS.length * LIMITS.length * CATEGORIES.length)
      // The seed has to exercise the paths, not just agree on empty answers.
      expect(nonEmpty).toBeGreaterThan(combos / 3)
      if (mode === 'hybrid') expect(vectorOnly).toBeGreaterThan(0)
      else expect(vectorOnly).toBe(0)
      // The MR3 exception covers exactly the empty query, nothing else.
      expect(zeroQueries).toBe(mode === 'hybrid' ? AGENTS.length * LIMITS.length * CATEGORIES.length : 0)
    })
  }

  it('the seed really contains an exact cosine tie, a wrong-length and a malformed vector', async () => {
    stubEmbedder('hybrid')
    const rows = await legacyHybridSearch(getDb(), 'eqa', 'tuzjelzo sprinkler', 64)
    expect(rows.length).toBeGreaterThan(0)
    const db = getDb()
    expect((db.prepare("SELECT COUNT(*) AS c FROM memories WHERE embedding = 'not-json'").get() as { c: number }).c).toBe(1)
    expect((db.prepare('SELECT COUNT(*) AS c FROM memories WHERE embedding IS NULL').get() as { c: number }).c).toBeGreaterThan(0)
  })

  it('hybridSearchWith on the module handle gives the same rows as hybridSearch', async () => {
    for (const mode of MODES) for (const q of QUERIES) {
      stubEmbedder(mode)
      const viaWrapper = await hybridSearch('eqa', q, 8)
      stubEmbedder(mode)
      const viaWith = await hybridSearchWith(getDb(), 'eqa', q, 8)
      expect(viaWith.map(h => h.memory), JSON.stringify({ mode, q })).toEqual(viaWrapper)
    }
  })
})

/** A handle that records every SQL text it is asked to prepare. */
function recordingHandle(inner: Database.Database, statements: string[]): Database.Database {
  return new Proxy(inner, {
    get(target, prop) {
      if (prop === 'prepare') {
        return (sql: string) => { statements.push(sql); return target.prepare(sql) }
      }
      const v = Reflect.get(target, prop, target)
      return typeof v === 'function' ? v.bind(target) : v
    },
  })
}

function snapshotRows(db: Database.Database): unknown[] {
  return db.prepare('SELECT id, content, keywords, embedding, accessed_at, created_at, salience, category FROM memories ORDER BY id').all()
}

describe('R0 read-only: hybridSearchWith runs on a read-only handle and never writes', () => {
  it('the read-only handle really refuses writes (the proof below is not vacuous)', () => {
    const ro = new Database(dbPath, { readonly: true, fileMustExist: true })
    try {
      expect(() => ro.prepare('UPDATE memories SET accessed_at = accessed_at + 1').run()).toThrow(/readonly/i)
      expect(() => ro.prepare("INSERT INTO memories (chat_id, content) VALUES ('0', 'x')").run()).toThrow(/readonly/i)
    } finally {
      ro.close()
    }
  })

  it('same rows as the pre-R0 code on the writable handle; only SELECTs; the store unchanged', async () => {
    // A clock no seed row carries: an accessed_at stamp (touchMemoriesAccessed)
    // made during the run would show up in the row snapshot below (MR2).
    vi.setSystemTime((NOW_SEC + 777) * 1000)
    const ro = new Database(dbPath, { readonly: true, fileMustExist: true })
    const statements: string[] = []
    const handle = recordingHandle(ro, statements)
    const main = getDb()
    try {
      const versionBefore = main.pragma('data_version', { simple: true })
      const before = snapshotRows(main)
      let compared = 0
      for (const mode of MODES) for (const q of QUERIES) for (const agent of AGENTS) for (const cat of [undefined, 'warm']) {
        // MR3: a zero-norm query vector answers like "no vector" (see the equivalence suite).
        stubEmbedder(mode === 'hybrid' && isZeroNorm(embedText(q)) ? 'fts-only' : mode)
        const legacy = await legacyHybridSearch(main, agent, q, 8, undefined, cat)
        stubEmbedder(mode)
        const hits = await hybridSearchWith(handle, agent, q, 8, undefined, cat)
        expect(hits.map(h => h.memory), JSON.stringify({ mode, q, agent, cat })).toEqual(legacy)
        compared++
      }
      expect(compared).toBe(MODES.length * QUERIES.length * AGENTS.length * 2)
      // Both branches ran on the given handle, not on the module one.
      expect(statements.some(s => s.includes('memories_fts MATCH'))).toBe(true)
      expect(statements.some(s => s.includes('embedding IS NOT NULL'))).toBe(true)
      const nonSelect = statements.filter(s => !/^\s*SELECT\b/i.test(s))
      expect(nonSelect).toEqual([])
      // No other connection committed anything, and no row changed.
      expect(main.pragma('data_version', { simple: true })).toBe(versionBefore)
      expect(snapshotRows(main)).toEqual(before)
    } finally {
      ro.close()
    }
  })
})

describe('R0 scores: hybridSearchWith exposes the numbers behind the order', () => {
  function eligibleCosines(agent: string, queryVec: number[]): { id: number; cos: number }[] {
    // MR3: a zero-norm query vector (the empty query's) gives no vector branch at all.
    if (isZeroNorm(queryVec)) return []
    const rows = getDb().prepare(
      "SELECT id, embedding FROM memories WHERE embedding IS NOT NULL AND (agent_id = ? OR category = 'shared')"
    ).all(agent) as { id: number; embedding: string }[]
    return rows.flatMap(r => {
      try {
        const emb = JSON.parse(r.embedding) as number[]
        // MR1: a non-finite cosine (a zero-norm stored vector) counts as 0.
        const c = legacyCosine(queryVec, emb)
        return emb.length === queryVec.length ? [{ id: r.id, cos: Number.isFinite(c) ? c : 0 }] : []
      } catch {
        return [{ id: r.id, cos: 0 }]
      }
    }).sort((a, b) => b.cos - a.cos)
  }

  it('score = RRF of the branch ranks, cosine = the row\'s cosine, order by score', async () => {
    let both = 0, ftsOnly = 0, vecOnly = 0
    for (const q of QUERIES) for (const agent of ['eqa', 'eqb']) {
      stubEmbedder('hybrid')
      const trace = freshTrace()
      const hits = await hybridSearchWith(getDb(), agent, q, 10, trace)
      const qv = embedText(q)
      const cosById = new Map(eligibleCosines(agent, qv).map(x => [x.id, x.cos]))
      for (let i = 0; i < hits.length; i++) {
        const h = hits[i]
        if (i > 0) expect(h.score).toBeLessThanOrEqual(hits[i - 1].score)
        expect(h.ftsRank !== null || h.vecRank !== null).toBe(true)
        const expected = (h.ftsRank !== null ? 0 + 1 / (HYBRID_RRF_K + h.ftsRank) : 0) + (h.vecRank !== null ? 1 / (HYBRID_RRF_K + h.vecRank) : 0)
        expect(h.score).toBeCloseTo(expected, 15)
        if (h.vecRank !== null) {
          expect(h.cosine).toBe(cosById.get(h.memory.id))
        } else {
          expect(h.cosine).toBeNull()
        }
        if (h.ftsRank !== null && h.vecRank !== null) both++
        else if (h.ftsRank !== null) ftsOnly++
        else vecOnly++
      }
      // Trace: best and second cosine of the vector branch, top-10 overlap.
      const ranked = eligibleCosines(agent, qv)
      expect(trace.topCos).toBe(ranked.length > 0 ? ranked[0].cos : null)
      expect(trace.secondCos).toBe(ranked.length > 1 ? ranked[1].cos : null)
      const fts = legacySearchAgentMemories(getDb(), agent, q, 20, { relaxed: false }, true)
      stubEmbedder('hybrid')
      const ftsTop = new Set(fts.slice(0, HYBRID_OVERLAP_TOP).map(m => m.id))
      const vecTop = legacyVectorSearch(getDb(), agent, qv, 20).slice(0, HYBRID_OVERLAP_TOP)
      expect(trace.overlap).toBe(vecTop.filter(m => ftsTop.has(m.id)).length)
    }
    // Every kind of row occurs, so the checks above are not vacuous.
    expect(both).toBeGreaterThan(0)
    expect(ftsOnly).toBeGreaterThan(0)
    expect(vecOnly).toBeGreaterThan(0)
  })

  it('the ranks are the branch positions: rows sorted by ftsRank / vecRank reproduce each branch', async () => {
    stubEmbedder('hybrid')
    const hits = await hybridSearchWith(getDb(), 'eqa', 'tuzjelzo sprinkler', 100)
    const fts = legacySearchAgentMemories(getDb(), 'eqa', 'tuzjelzo sprinkler', 200, { relaxed: false }, true)
    const vec = legacyVectorSearch(getDb(), 'eqa', embedText('tuzjelzo sprinkler'), 200)
    const byFts = hits.filter(h => h.ftsRank !== null).sort((a, b) => a.ftsRank! - b.ftsRank!).map(h => h.memory.id)
    const byVec = hits.filter(h => h.vecRank !== null).sort((a, b) => a.vecRank! - b.vecRank!).map(h => h.memory.id)
    expect(byFts).toEqual(fts.map(m => m.id))
    expect(byVec).toEqual(vec.map(m => m.id))
  })

  it('embedder failure: no cosine anywhere, topCos/secondCos null, overlap 0', async () => {
    for (const mode of ['fts-only', 'embedder-error'] as const) {
      stubEmbedder(mode)
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
      const trace = freshTrace()
      const hits = await hybridSearchWith(getDb(), 'eqa', 'tuzjelzo', 10, trace)
      expect(hits.length).toBeGreaterThan(0)
      expect(hits.every(h => h.cosine === null && h.vecRank === null && h.ftsRank !== null)).toBe(true)
      expect(trace).toMatchObject({ topCos: null, secondCos: null, overlap: 0, vectorHits: 0 })
    }
  })
})

describe('R0 options: a caller-supplied query vector and clock', () => {
  it('queryEmbedding: used as given, no embedding call, same answer as computing it', async () => {
    for (const q of QUERIES) {
      stubEmbedder('hybrid')
      const computed = await hybridSearchWith(getDb(), 'eqa', q, 8)
      const fetchMock = stubEmbedder('hybrid')
      const given = await hybridSearchWith(getDb(), 'eqa', q, 8, undefined, undefined, { queryEmbedding: embedText(q) })
      expect(fetchMock).not.toHaveBeenCalled()
      expect(given).toEqual(computed)
    }
  })

  it('queryEmbedding: null means no vector branch and no embedding call (= the embedder-failure answer)', async () => {
    for (const q of QUERIES) {
      stubEmbedder('embedder-error')
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
      vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
      const failed = await hybridSearchWith(getDb(), 'eqa', q, 8)
      const fetchMock = stubEmbedder('hybrid')
      const none = await hybridSearchWith(getDb(), 'eqa', q, 8, undefined, undefined, { queryEmbedding: null })
      expect(fetchMock).not.toHaveBeenCalled()
      expect(none).toEqual(failed)
    }
  })

  it('nowSec pins the FTS recency clock: same answer at another wall-clock time, and it is really used', async () => {
    const later = NOW_SEC + 365 * 86400
    let differs = 0
    for (const q of QUERIES) {
      const atNow = await hybridSearchWith(getDb(), 'eqa', q, 5, undefined, undefined, { queryEmbedding: null })
      vi.setSystemTime(later * 1000)
      const pinned = await hybridSearchWith(getDb(), 'eqa', q, 5, undefined, undefined, { queryEmbedding: null, nowSec: NOW_SEC })
      const unpinned = await hybridSearchWith(getDb(), 'eqa', q, 5, undefined, undefined, { queryEmbedding: null })
      vi.setSystemTime(NOW_SEC * 1000)
      expect(pinned).toEqual(atNow)
      if (JSON.stringify(unpinned.map(h => h.memory.id)) !== JSON.stringify(atNow.map(h => h.memory.id))) differs++
    }
    expect(differs).toBeGreaterThan(0)
  })
})

describe('R0 fuseRanked: the pure fusion keeps the old arithmetic and tie order', () => {
  const mem = (id: number, tag = ''): Memory => ({
    id, chat_id: '0', topic_key: null, content: `m${id}${tag}`, sector: 'semantic', salience: 1, created_at: 0,
    accessed_at: 0, agent_id: 'x', category: 'warm', auto_generated: 0, keywords: null, embedding: null,
  })

  it('sums both branches, ranks 1-based, cosine from the vector branch', () => {
    const out = fuseRanked([mem(1), mem(2)], [{ memory: mem(3), score: 0.9 }, { memory: mem(1), score: 0.5 }], 10)
    expect(out.map(h => h.memory.id)).toEqual([1, 3, 2])
    expect(out[0]).toMatchObject({ ftsRank: 1, vecRank: 2, cosine: 0.5 })
    expect(out[0].score).toBe(0 + 1 / 61 + 1 / 62)
    expect(out[1]).toMatchObject({ ftsRank: null, vecRank: 1, cosine: 0.9, score: 1 / 61 })
    expect(out[2]).toMatchObject({ ftsRank: 2, vecRank: null, cosine: null, score: 1 / 62 })
  })

  it('equal scores keep first-seen order (FTS rows before vector-only rows)', () => {
    const out = fuseRanked([mem(5)], [{ memory: mem(4), score: 0.99 }], 10)
    expect(out.map(h => h.memory.id)).toEqual([5, 4])
  })

  it('a row in both branches carries the vector branch\'s row object, as before', () => {
    const vecRow = mem(7, '-vec')
    const out = fuseRanked([mem(7, '-fts')], [{ memory: vecRow, score: 0.1 }], 10)
    expect(out[0].memory).toBe(vecRow)
  })

  it('cuts to limit and honours k', () => {
    const out = fuseRanked([mem(1), mem(2), mem(3)], [], 2, 10)
    expect(out.map(h => h.memory.id)).toEqual([1, 2])
    expect(out[0].score).toBe(1 / 11)
    expect(fuseRanked([], [], 5)).toEqual([])
  })
})

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

// Runs last: the route stamps accessed_at, which the LIKE fallback orders by.
describe('R0 route: GET /api/memories?mode=hybrid answers and stamps exactly as before', () => {
  for (const mode of ['hybrid', 'embedder-error'] as const) {
    it(`${mode}: same body ids and X-Memory-Search; the returned rows (only those) get accessed_at`, async () => {
      vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
      vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
      const stampAt = NOW_SEC + (mode === 'hybrid' ? 100 : 200)
      vi.setSystemTime(stampAt * 1000)
      const main = getDb()
      stubEmbedder(mode)
      const trace = freshTrace()
      const legacy = await legacyHybridSearch(main, 'eqa', 'tuzjelzo sprinkler', 5, trace)
      expect(legacy.length).toBeGreaterThan(0)
      const before = new Map((main.prepare('SELECT id, accessed_at FROM memories').all() as { id: number; accessed_at: number }[]).map(r => [r.id, r.accessed_at]))

      stubEmbedder(mode)
      const { ctx, out } = fakeCtx(`/api/memories?agent=eqa&q=${encodeURIComponent('tuzjelzo sprinkler')}&mode=hybrid&limit=5`)
      expect(await tryHandleMemories(ctx)).toBe(true)
      expect(out.status).toBe(200)
      expect((out.body as { id: number }[]).map(r => r.id)).toEqual(legacy.map(m => m.id))
      expect(out.headers['x-memory-search']).toBe(
        `fts=${trace.ftsHits}; vector=${trace.vectorHits}; relaxed=${trace.ftsRelaxed}; vector-only=${trace.vectorOnly}`,
      )
      const returned = new Set(legacy.map(m => m.id))
      const after = main.prepare('SELECT id, accessed_at FROM memories').all() as { id: number; accessed_at: number }[]
      for (const r of after) {
        expect(r.accessed_at, `id ${r.id}`).toBe(returned.has(r.id) ? stampAt : before.get(r.id))
      }
    })
  }
})
