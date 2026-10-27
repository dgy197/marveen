/**
 * Card d4e7fea7 (node T2): the claim on the card is that an edited memory drops
 * out of the VECTOR search. The other tests look at the `embedding` column; this
 * one asks the hybrid search itself, and reads "came from the vector branch"
 * off the per-branch fields (`vecRank`, `cosine`, `trace.vectorOnly`), never off
 * the fused order.
 *
 * The question is a word that appears in no row. The fake embedder maps it to
 * the vector of the edited row's NEW text (a synonym table), so the only way
 * the edited row can come back is through its vector. The FTS branch is
 * permissive (it drops words that match nothing and relaxes AND to OR), so
 * every case asserts `trace.ftsHits === 0` explicitly: without that, a hit
 * could be a keyword hit that merely looks vector-made.
 *
 * Vectors are one-hot sums over a word list: two texts that share no word have
 * cosine exactly 0, a text and a question mapped to it have cosine 1.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'

// Upstream's vector similarity floor (v1.45.0) drops weak vector hits. This suite's seeded
// vectors are not about the floor, so it is switched off here (a baseline no corpus reaches, an
// absolute small-corpus threshold of 0); the floor itself is pinned in memory-search-precision.test.ts.
vi.mock('../settings-store.js', async (orig) => {
  const actual = await orig<typeof import('../settings-store.js')>()
  const off: Record<string, string> = { MEMORY_VECTOR_BASELINE_MIN_ROWS: '1000000', MEMORY_VECTOR_SMALL_CORPUS_MIN_SIMILARITY: '0' }
  return { ...actual, getEffectiveSettingValue: (key: string) => (key in off ? off[key] : actual.getEffectiveSettingValue(key)) }
})
import {
  initDatabase, getDb, updateMemory, hybridSearchWith, type HybridHit, type HybridSearchTrace,
} from '../db.js'
import { HYBRID_RECENCY_DEFAULT } from '../config.js'
import { startEmbeddingRefreshRunner, stopEmbeddingRefreshRunner } from '../web/embedding-refresh-runner.js'

vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

const AGENT = 'vector-branch-agent'
const QUESTION = 'qxzlvenyhe' // appears in no row
const OLD_TEXT = 'regi alairasi szabalyzat'
const NEW_TEXT = 'hatosagi tuzoltokeszulek ellenorzes'
const NEAR_TEXT = 'hatosagi tuzoltokeszulek' // two of the three words of NEW_TEXT: cosine 0.816 to the question
const FAR_TEXTS = ['kerti locsolorendszer terv', 'csapat etterem foglalas', 'nyari szabadsag tervezes']

// The question is a synonym of the whole new text.
const SYNONYMS: Record<string, string> = { [QUESTION]: NEW_TEXT }

const VOCAB = [
  ...OLD_TEXT.split(' '), ...NEW_TEXT.split(' '), ...FAR_TEXTS.flatMap(t => t.split(' ')),
]
const AXES = [...new Set(VOCAB)]
const DIMS = AXES.length + 8

function embedText(text: string): number[] {
  const out = new Array(DIMS).fill(0)
  const words = text.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean)
  for (const raw of words) {
    for (const w of (SYNONYMS[raw] ?? raw).split(' ')) {
      const axis = AXES.indexOf(w)
      if (axis === -1) throw new Error(`fake embedder: "${w}" is not in the test vocabulary`)
      out[axis] += 1
    }
  }
  return out
}

interface FakeEmbedder { prompts: string[]; fail: boolean }
let fake: FakeEmbedder

function installFakeEmbedder(): FakeEmbedder {
  const f: FakeEmbedder = { prompts: [], fail: false }
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
    const prompt = JSON.parse(init.body).prompt as string
    f.prompts.push(prompt)
    if (f.fail) throw new Error('connect ECONNREFUSED (fake)')
    return { json: async () => ({ embedding: embedText(prompt) }) }
  }))
  return f
}

function seedRow(content: string, withVector = true): number {
  const now = Math.floor(Date.now() / 1000)
  const info = getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience,
     created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
     VALUES ('test-chat', NULL, ?, 'semantic', 1.0, ?, ?, ?, 'warm', 0, NULL, ?)`
  ).run(content, now, now, AGENT, withVector ? JSON.stringify(embedText(content)) : null)
  return Number(info.lastInsertRowid)
}

async function search(query: string): Promise<{ hits: HybridHit[]; trace: HybridSearchTrace }> {
  const trace: HybridSearchTrace = { ftsHits: 0, vectorHits: 0, ftsRelaxed: false, vectorOnly: false }
  // The recency config is passed in, so the ranking does not depend on a .env.
  const hits = await hybridSearchWith(getDb(), AGENT, query, 10, trace, undefined, { recency: HYBRID_RECENCY_DEFAULT })
  return { hits, trace }
}

const advance = (ms: number) => vi.advanceTimersByTimeAsync(ms)

let target = 0
let near = 0

beforeEach(() => {
  initDatabase(':memory:')
  vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'Date'] })
  fake = installFakeEmbedder()
  target = seedRow(OLD_TEXT)
  near = seedRow(NEAR_TEXT)
  for (const t of FAR_TEXTS) seedRow(t)
})

afterEach(async () => {
  // The single-flight slot and the nudge timer are module state: leave neither behind.
  stopEmbeddingRefreshRunner()
  fake.fail = false
  await advance(20_000)
  expect(vi.getTimerCount()).toBe(0)
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('an edited memory and the vector branch of the hybrid search', () => {
  it('the fake embedder is sane: the question is the new text, and the old text shares nothing with it', () => {
    const q = embedText(QUESTION)
    expect(q).toEqual(embedText(NEW_TEXT))
    expect(embedText(OLD_TEXT).some((x, i) => x > 0 && q[i] > 0)).toBe(false)
    expect(embedText(NEAR_TEXT).some((x, i) => x > 0 && q[i] > 0)).toBe(true)
  })

  it('before the edit: no keyword hit, and the row sits in the vector branch with the OLD vector, far from the question and not first', async () => {
    const { hits, trace } = await search(QUESTION)
    expect(trace.ftsHits).toBe(0) // otherwise a keyword hit could pass for a vector one
    expect(trace.vectorHits).toBeGreaterThan(0)
    const row = hits.find(h => h.memory.id === target)
    expect(row).toBeDefined()
    expect(row!.ftsRank).toBeNull()
    expect(row!.vecRank).not.toBeNull()
    expect(row!.vecRank).toBeGreaterThan(1)
    expect(row!.cosine).toBe(0)
    expect(hits[0].memory.id).toBe(near)
    expect(hits[0].cosine).toBeGreaterThan(0.8)
    expect(hits[0].cosine).toBeLessThan(0.82)
  })

  it('after the edit, before the re-embedding: the row is NOT in the vector branch (the old vector does not live on)', async () => {
    startEmbeddingRefreshRunner()
    expect(updateMemory(target, NEW_TEXT)).toBe(true)
    expect(getDb().prepare('SELECT embedding FROM memories WHERE id = ?').get(target)).toEqual({ embedding: null })

    const { hits, trace } = await search(QUESTION)
    expect(trace.ftsHits).toBe(0)
    expect(trace.vectorHits).toBeGreaterThan(0) // the branch works, it just has no vector for this row
    const row = hits.find(h => h.memory.id === target)
    expect(row?.vecRank ?? null).toBeNull()
    expect(row?.cosine ?? null).toBeNull()
    expect(hits.some(h => h.memory.id === target)).toBe(false) // no keyword hit either: absent altogether
    expect(fake.prompts.filter(p => p !== QUESTION)).toEqual([]) // only the question was embedded, not the edited row
  })

  it('about 2 s after the edit the row is rank 1 of the vector branch with cosine ~1, and the answer is vector-only', async () => {
    startEmbeddingRefreshRunner()
    expect(updateMemory(target, NEW_TEXT)).toBe(true)
    await advance(2_300)
    expect(fake.prompts).toEqual([NEW_TEXT])

    const { hits, trace } = await search(QUESTION)
    expect(trace.ftsHits).toBe(0) // the question is in no row: this is the vector branch alone
    expect(trace.vectorOnly).toBe(true)
    expect(trace.vectorHits).toBeGreaterThan(0)
    const row = hits.find(h => h.memory.id === target)
    expect(row).toBeDefined()
    expect(row!.ftsRank).toBeNull()
    expect(row!.vecRank).toBe(1)
    expect(row!.cosine).toBeGreaterThanOrEqual(0.999)
    expect(hits[0].memory.id).toBe(target)
    // The row that was first before the edit is now second.
    expect(hits.find(h => h.memory.id === near)!.vecRank).toBe(2)
  })

  it('control: without the runner the edited row stays out of the vector branch (so the re-embedding above is what brought it back)', async () => {
    expect(updateMemory(target, NEW_TEXT)).toBe(true)
    await advance(5_000)
    expect(fake.prompts).toEqual([])
    const { hits, trace } = await search(QUESTION)
    expect(trace.ftsHits).toBe(0)
    expect(hits.some(h => h.memory.id === target)).toBe(false)
  })

  it('backend down during the edit: the row is found by a word of the new text through the keyword branch alone, the vector branch is empty', async () => {
    startEmbeddingRefreshRunner()
    fake.fail = true
    expect(updateMemory(target, NEW_TEXT)).toBe(true)
    await advance(2_300) // the nudge round: the backend refuses
    expect(getDb().prepare('SELECT embedding FROM memories WHERE id = ?').get(target)).toEqual({ embedding: null })

    const { hits, trace } = await search('ellenorzes') // a word only the new text has
    expect(trace.ftsHits).toBeGreaterThanOrEqual(1)
    expect(trace.vectorHits).toBe(0)
    expect(trace.topCos).toBeNull()
    expect(trace.vectorOnly).toBe(false)
    const row = hits.find(h => h.memory.id === target)
    expect(row).toBeDefined()
    expect(row!.ftsRank).not.toBeNull()
    expect(row!.vecRank).toBeNull()
    expect(row!.cosine).toBeNull()
  })
})
