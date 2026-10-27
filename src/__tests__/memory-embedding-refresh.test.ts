import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import {
  initDatabase, getDb, updateMemory, backfillEmbeddings, storeEmbeddingIfUnchanged,
  requestEmbeddingRefresh, EMBEDDING_REFRESH_MAX_ROWS, embeddingBackoffDelayMs, EMBEDDING_BACKOFF_MAX_MS,
} from '../db.js'
import { startEmbeddingRefreshRunner, stopEmbeddingRefreshRunner } from '../web/embedding-refresh-runner.js'
import { logger } from '../logger.js'

// Card d4e7fea7: an edited memory must get the vector of its NEW text within a
// minute, without a dashboard restart. The runner (60 s, first tick at 30 s)
// is the floor, updateMemory's nudge (~2 s) the fast path; both go through the
// single-flight, compare-and-set backfill. Fake timers drive the clock, and a
// fake embedder answers with a vector derived from the prompt, so a test can
// tell which text a stored vector belongs to. Ollama is never contacted.

const AGENT = 'embedding-refresh-agent'
const OLD_VECTOR = JSON.stringify([9, 9, 9])

function vectorFor(text: string): number[] {
  let h = 0
  for (const ch of text) h = (h * 31 + ch.codePointAt(0)!) % 1_000_003
  return [text.length, h, 1]
}

interface FakeEmbedder {
  prompts: string[]
  /** When each prompt was asked (Date.now(), fake clock). */
  askedAt: Array<{ prompt: string; at: number }>
  held: Array<() => void>
  hold: boolean
  /** Hold only the prompts this matches (released by release(), like hold). */
  holdIf: (prompt: string) => boolean
  fail: boolean
  /** Per-prompt refusal while the backend is otherwise up: 'empty' = answers without a vector, 'throw' = the call fails. */
  refuse: (prompt: string) => 'empty' | 'throw' | null
  inFlight: number
  maxInFlight: number
  release(): void
}

let fake: FakeEmbedder

function installFakeEmbedder(): FakeEmbedder {
  const f: FakeEmbedder = {
    prompts: [], askedAt: [], held: [], hold: false, holdIf: () => false, fail: false, refuse: () => null, inFlight: 0, maxInFlight: 0,
    release() { for (const r of f.held.splice(0)) r() },
  }
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
    const prompt = JSON.parse(init.body).prompt as string
    f.prompts.push(prompt)
    f.askedAt.push({ prompt, at: Date.now() })
    f.inFlight++
    f.maxInFlight = Math.max(f.maxInFlight, f.inFlight)
    try {
      if (f.hold || f.holdIf(prompt)) await new Promise<void>(r => f.held.push(r))
      if (f.fail) throw new Error('connect ECONNREFUSED (fake)')
      const refusal = f.refuse(prompt)
      if (refusal === 'throw') throw new Error('this input breaks the model (fake)')
      if (refusal === 'empty') return { json: async () => ({ error: 'cannot embed this input (fake)' }) }
      return { json: async () => ({ embedding: vectorFor(prompt) }) }
    } finally {
      f.inFlight--
    }
  }))
  return f
}

function seedRow(content: string, keywords: string | null, embedding: string | null = null, createdAt?: number): number {
  const now = Math.floor(Date.now() / 1000)
  const info = getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience,
     created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
     VALUES ('test-chat', NULL, ?, 'semantic', 1.0, ?, ?, ?, 'warm', 0, ?, ?)`
  ).run(content, createdAt ?? now, now, AGENT, keywords, embedding)
  return Number(info.lastInsertRowid)
}

function readEmbedding(id: number): string | null {
  return (getDb().prepare('SELECT embedding FROM memories WHERE id = ?').get(id) as { embedding: string | null }).embedding
}

// An edit by a writer that does not nudge (another process, raw SQL).
function rawEdit(id: number, content: string): void {
  getDb().prepare('UPDATE memories SET content = ?, embedding = NULL, updated_at = ? WHERE id = ?')
    .run(content, Math.floor(Date.now() / 1000), id)
}

const advance = (ms: number) => vi.advanceTimersByTimeAsync(ms)

beforeEach(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  vi.useFakeTimers()
  fake = installFakeEmbedder()
})

afterEach(async () => {
  // Leave no pass in flight for the next test: the single-flight slot is
  // module state and outlives a test.
  stopEmbeddingRefreshRunner()
  fake.hold = false
  fake.holdIf = () => false
  fake.fail = false
  fake.release()
  await advance(20_000)
  vi.useRealTimers()
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('storeEmbeddingIfUnchanged (the compare-and-set write)', () => {
  it('writes only while content AND keywords still match; NULL keywords are not the empty string', () => {
    const bare = seedRow('Body', null)
    expect(storeEmbeddingIfUnchanged(bare, 'Body', '', [1])).toBe(false)
    expect(storeEmbeddingIfUnchanged(bare, 'Other body', null, [1])).toBe(false)
    expect(readEmbedding(bare)).toBeNull()
    expect(storeEmbeddingIfUnchanged(bare, 'Body', null, [1, 2])).toBe(true)
    expect(readEmbedding(bare)).toBe('[1,2]')

    const tagged = seedRow('Body', 'kw')
    expect(storeEmbeddingIfUnchanged(tagged, 'Body', null, [1])).toBe(false)
    expect(storeEmbeddingIfUnchanged(tagged, 'Body', 'kw', [3])).toBe(true)
    expect(readEmbedding(tagged)).toBe('[3]')
  })

  it('is a maintenance write: it does not stamp updated_at', () => {
    const id = seedRow('Body', 'kw')
    expect(storeEmbeddingIfUnchanged(id, 'Body', 'kw', [1])).toBe(true)
    const row = getDb().prepare('SELECT updated_at FROM memories WHERE id = ?').get(id) as { updated_at: number | null }
    expect(row.updated_at).toBeNull()
  })

  it('an unknown id is a miss, not an error', () => {
    expect(storeEmbeddingIfUnchanged(999_999, 'x', null, [1])).toBe(false)
  })
})

describe('the nudge after an edit', () => {
  it('brings the NEW text\'s vector about 2 s after the edit, long before the first runner tick', async () => {
    const id = seedRow('Before edit', 'kw', OLD_VECTOR)
    startEmbeddingRefreshRunner()
    expect(updateMemory(id, 'After edit')).toBe(true)
    expect(readEmbedding(id)).toBeNull()
    await advance(1_999)
    expect(fake.prompts).toEqual([])
    await advance(300)
    expect(fake.prompts).toEqual(['After edit kw'])
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('After edit kw')))
  })

  it('is debounced: three edits inside the window cost one pass and one call per row', async () => {
    const ids = [seedRow('A', null, OLD_VECTOR), seedRow('B', null, OLD_VECTOR), seedRow('C', null, OLD_VECTOR)]
    startEmbeddingRefreshRunner()
    const timersBefore = vi.getTimerCount()
    updateMemory(ids[0], 'A2')
    await advance(500)
    updateMemory(ids[1], 'B2')
    await advance(500)
    updateMemory(ids[2], 'C2')
    expect(vi.getTimerCount()).toBe(timersBefore + 1) // one pending nudge, not three
    await advance(1_500)
    expect(fake.prompts.slice().sort()).toEqual(['A2', 'B2', 'C2'])
    for (const id of ids) expect(readEmbedding(id)).not.toBeNull()
  })

  it('a category-only edit does not nudge (the vector stays, nothing to re-embed)', async () => {
    const id = seedRow('Stable', null, OLD_VECTOR)
    startEmbeddingRefreshRunner()
    const timersBefore = vi.getTimerCount()
    expect(updateMemory(id, 'Stable', 'cold')).toBe(true)
    expect(vi.getTimerCount()).toBe(timersBefore)
    await advance(5_000)
    expect(fake.prompts).toEqual([])
    expect(readEmbedding(id)).toBe(OLD_VECTOR)
  })

  it('is inert while the runner is not running (tests, CLI processes): no timer, no call', async () => {
    const id = seedRow('Quiet', null, OLD_VECTOR)
    expect(updateMemory(id, 'Quiet edit')).toBe(true)
    requestEmbeddingRefresh()
    expect(vi.getTimerCount()).toBe(0)
    await advance(120_000)
    expect(fake.prompts).toEqual([])
    expect(readEmbedding(id)).toBeNull()
  })

  it('an edit while a pass is in flight is embedded right after that pass, not a tick later', async () => {
    const a = seedRow('Row A', null)
    const b = seedRow('Row B', null, OLD_VECTOR)
    fake.hold = true
    startEmbeddingRefreshRunner()
    await advance(30_000)
    expect(fake.prompts).toEqual(['Row A'])
    expect(updateMemory(b, 'Row B edited')).toBe(true)
    await advance(2_000) // the nudge fires while Row A's call is still held
    expect(fake.prompts).toEqual(['Row A'])
    fake.hold = false
    fake.release()
    await advance(500) // t ~ 32.5 s, the next tick is at 90 s
    expect(fake.prompts).toEqual(['Row A', 'Row B edited'])
    expect(readEmbedding(a)).toBe(JSON.stringify(vectorFor('Row A')))
    expect(readEmbedding(b)).toBe(JSON.stringify(vectorFor('Row B edited')))
  })
})

describe('the runner', () => {
  it('first tick at 30 s; a row NULLed by a non-nudging writer gets its vector within one 60 s tick', async () => {
    const id = seedRow('Original', null, OLD_VECTOR)
    rawEdit(id, 'Raw edit one')
    startEmbeddingRefreshRunner()
    await advance(29_999)
    expect(fake.prompts).toEqual([])
    await advance(300)
    expect(fake.prompts).toEqual(['Raw edit one'])
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Raw edit one')))

    // t ~ 30.3 s: a second raw edit; the next tick is at 90 s.
    await advance(1_000)
    rawEdit(id, 'Raw edit two')
    await advance(58_000) // t ~ 89.3 s
    expect(readEmbedding(id)).toBeNull()
    await advance(1_000) // t ~ 90.3 s, less than 60 s after the edit
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Raw edit two')))
  })

  it('single-flight: overlapping ticks never run together, a held row is asked for once', async () => {
    const id = seedRow('Slow row', null)
    fake.hold = true
    startEmbeddingRefreshRunner()
    await advance(30_000)
    await advance(60_000)
    await advance(60_000)
    expect(fake.prompts).toEqual(['Slow row'])
    expect(fake.maxInFlight).toBe(1)
    fake.hold = false
    fake.release()
    await advance(500)
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Slow row')))
    expect(fake.prompts).toEqual(['Slow row'])
  })

  it(`caps a tick at ${EMBEDDING_REFRESH_MAX_ROWS} rows, most recently written first; the rest follow next tick`, async () => {
    expect(EMBEDDING_REFRESH_MAX_ROWS).toBe(50)
    const old = Math.floor(Date.now() / 1000) - 30 * 86_400
    const ids = Array.from({ length: 120 }, (_, i) => seedRow(`Backlog ${i}`, null, null, old))
    // A middle id is edited now. It is outside the first 50 by id in EITHER
    // direction, so only recency ordering puts it into the first tick.
    rawEdit(ids[60], 'Fresh edit')
    startEmbeddingRefreshRunner()
    await advance(30_000 + 50 * 100 + 1_000)
    expect(fake.prompts).toHaveLength(50)
    expect(fake.prompts[0]).toBe('Fresh edit')
    await advance(60_000)
    expect(fake.prompts).toHaveLength(100)
    await advance(60_000)
    expect(fake.prompts).toHaveLength(120)
    expect(new Set(fake.prompts).size).toBe(120)
    for (const id of ids) expect(readEmbedding(id)).not.toBeNull()
  })

  it('a row that got its vector from another writer, or was deleted, before its turn is skipped (no call, no warn)', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    const a = seedRow('Row A', null)
    const b = seedRow('Row B', null)
    const c = seedRow('Row C', null)
    fake.hold = true
    const pass = backfillEmbeddings()
    await advance(1)
    expect(fake.prompts).toEqual(['Row C']) // newest first: same created_at, id DESC
    const elsewhere = JSON.stringify(vectorFor('Row B'))
    getDb().prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(elsewhere, b)
    getDb().prepare('DELETE FROM memories WHERE id = ?').run(a)
    fake.hold = false
    fake.release()
    await advance(1_000)
    expect((await pass).embedded).toBe(1)
    expect(fake.prompts).toEqual(['Row C'])
    expect(readEmbedding(b)).toBe(elsewhere)
    expect(readEmbedding(c)).toBe(JSON.stringify(vectorFor('Row C')))
    expect(warn.mock.calls.filter(call => String(call[1]).startsWith('Embedding backfill embedded 0'))).toHaveLength(0)
  })

  it('without maxRows (boot, route, fleet import) a pass still takes every pending row', async () => {
    for (let i = 0; i < 60; i++) seedRow(`Row ${i}`, null)
    const pass = backfillEmbeddings()
    await advance(60 * 100 + 1_000)
    expect((await pass).embedded).toBe(60)
    expect(fake.prompts).toHaveLength(60)
  })

  it('survives an embedder outage: rows stay NULL, ONE warn per outage, and the next tick after recovery embeds them', async () => {
    // Start from a healthy backend so both once-per-outage latches are re-armed.
    seedRow('Healthy', null)
    const warm = backfillEmbeddings()
    await advance(500)
    expect((await warm).embedded).toBe(1)

    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    const backfillWarns = () => warn.mock.calls.filter(c => String(c[1]).startsWith('Embedding backfill embedded 0')).length
    const embedWarns = () => warn.mock.calls.filter(c => String(c[1]).startsWith('Embedding generation failed --')).length

    fake.fail = true
    const a = seedRow('Outage A', null)
    const b = seedRow('Outage B', 'kw')
    startEmbeddingRefreshRunner()
    await advance(30_500)
    await advance(60_000)
    await advance(60_000)
    expect(fake.prompts.filter(p => p.startsWith('Outage'))).toHaveLength(6) // retried every tick
    expect(readEmbedding(a)).toBeNull()
    expect(readEmbedding(b)).toBeNull()
    expect(backfillWarns()).toBe(1)
    expect(embedWarns()).toBe(1)

    fake.fail = false
    await advance(60_000)
    expect(readEmbedding(a)).toBe(JSON.stringify(vectorFor('Outage A')))
    expect(readEmbedding(b)).toBe(JSON.stringify(vectorFor('Outage B kw')))

    // A second outage warns again: the latch was re-armed by the recovery.
    fake.fail = true
    rawEdit(a, 'Outage A again')
    await advance(60_000)
    expect(backfillWarns()).toBe(2)
    expect(embedWarns()).toBe(2)
  })

  it('a pass that throws is logged and the next tick runs normally (the process is not taken down)', async () => {
    const error = vi.spyOn(logger, 'error').mockImplementation(() => undefined as never)
    const unhandled = vi.fn()
    process.on('unhandledRejection', unhandled)
    try {
      const id = seedRow('After the fault', null)
      const prepare = vi.spyOn(getDb(), 'prepare').mockImplementationOnce(() => {
        throw new Error('disk I/O error (fake)')
      })
      startEmbeddingRefreshRunner()
      await advance(30_500)
      expect(error).toHaveBeenCalledTimes(1)
      expect(String(error.mock.calls[0][1])).toBe('Embedding refresh failed')
      expect(readEmbedding(id)).toBeNull()
      prepare.mockRestore()
      await advance(60_000)
      expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('After the fault')))
      expect(unhandled).not.toHaveBeenCalled()
    } finally {
      process.off('unhandledRejection', unhandled)
    }
  })

  it('start is idempotent; stop clears every timer and disarms the nudge; a restart works', async () => {
    startEmbeddingRefreshRunner()
    startEmbeddingRefreshRunner()
    expect(vi.getTimerCount()).toBe(1)
    await advance(30_000)
    expect(vi.getTimerCount()).toBe(1) // the 60 s interval, nothing else

    const id = seedRow('Before stop', null, OLD_VECTOR)
    updateMemory(id, 'Edited before stop') // nudge timer pending
    expect(vi.getTimerCount()).toBe(2)
    stopEmbeddingRefreshRunner()
    expect(vi.getTimerCount()).toBe(0)

    updateMemory(id, 'Edited after stop')
    expect(vi.getTimerCount()).toBe(0)
    await advance(300_000)
    expect(fake.prompts).toEqual([])

    startEmbeddingRefreshRunner()
    await advance(30_300)
    expect(fake.prompts).toEqual(['Edited after stop'])
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Edited after stop')))
  })

  it('stop before the first tick: nothing ever runs', async () => {
    seedRow('Never', null)
    startEmbeddingRefreshRunner()
    stopEmbeddingRefreshRunner()
    expect(vi.getTimerCount()).toBe(0)
    await advance(300_000)
    expect(fake.prompts).toEqual([])
  })
})

// MN4: "backfill everything" (POST /api/memories/backfill, fleet import) must
// not come back with only a capped pass's rows done.
describe('an uncapped caller behind a capped pass', () => {
  const allEmbedded = (ids: number[]) => ids.every(id => readEmbedding(id) !== null)

  it('queues behind it, then embeds EVERY remaining NULL row (no row asked for twice, never two passes at once)', async () => {
    const ids = Array.from({ length: 120 }, (_, i) => seedRow(`Row ${i}`, null))
    fake.hold = true
    const capped = backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })
    await advance(1)
    expect(fake.prompts).toHaveLength(1)
    const full = backfillEmbeddings()
    await advance(1)
    expect(fake.prompts).toHaveLength(1) // queued, not a second pass
    fake.hold = false
    fake.release()
    await advance(120 * 100 + 1_000)
    expect((await capped).embedded).toBe(EMBEDDING_REFRESH_MAX_ROWS)
    expect((await full).embedded).toBe(120 - EMBEDDING_REFRESH_MAX_ROWS)
    expect(allEmbedded(ids)).toBe(true)
    expect(new Set(fake.prompts).size).toBe(120)
    expect(fake.prompts).toHaveLength(120)
    expect(fake.maxInFlight).toBe(1)
  })

  it('two uncapped callers behind the same capped pass share ONE follow-up pass', async () => {
    const ids = Array.from({ length: 80 }, (_, i) => seedRow(`Row ${i}`, null))
    fake.hold = true
    const capped = backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })
    await advance(1)
    const first = backfillEmbeddings()
    const second = backfillEmbeddings()
    fake.hold = false
    fake.release()
    await advance(80 * 100 + 1_000)
    expect((await capped).embedded).toBe(EMBEDDING_REFRESH_MAX_ROWS)
    expect((await first).embedded).toBe(30)
    expect((await second).embedded).toBe(30)
    expect(fake.prompts).toHaveLength(80)
    expect(allEmbedded(ids)).toBe(true)
  })

  it('a capped caller still joins an uncapped pass (it covers more than the cap asked for)', async () => {
    for (let i = 0; i < 60; i++) seedRow(`Row ${i}`, null)
    fake.hold = true
    const full = backfillEmbeddings()
    await advance(1)
    const capped = backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })
    fake.hold = false
    fake.release()
    await advance(60 * 100 + 1_000)
    expect((await full).embedded).toBe(60)
    expect((await capped).embedded).toBe(60)
    expect(fake.prompts).toHaveLength(60)
  })

  it('a queued uncapped caller still gets its pass when the capped pass throws', async () => {
    const id = seedRow('After the fault', null)
    const prepare = vi.spyOn(getDb(), 'prepare').mockImplementationOnce(() => {
      throw new Error('disk I/O error (fake)')
    })
    const capped = backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })
    const full = backfillEmbeddings()
    await expect(capped).rejects.toThrow(/disk I\/O error/)
    prepare.mockRestore()
    await advance(1_000)
    expect((await full).embedded).toBe(1)
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('After the fault')))
  })
})

// MN5: rows the backend refuses every time must not starve the runner, and
// must not read as "the backend is down".
describe('rows the backend refuses (per-row backoff)', () => {
  const POISON = 'Poison'
  const isPoison = (p: string) => p.startsWith(POISON)
  const PROBE = 'embedding backend health probe'
  const asked = (pred: (p: string) => boolean) => fake.prompts.filter(pred).length
  const warnsStarting = (warn: { mock: { calls: unknown[][] } }, prefix: string) =>
    warn.mock.calls.filter((c: unknown[]) => String(c[1]).startsWith(prefix)).length
  const OLD = () => Math.floor(Date.now() / 1000) - 30 * 86_400

  it('the delay doubles from 1 min and stops at 1 h', () => {
    expect(embeddingBackoffDelayMs(1)).toBe(60_000)
    expect(embeddingBackoffDelayMs(2)).toBe(120_000)
    expect(embeddingBackoffDelayMs(3)).toBe(240_000)
    expect(embeddingBackoffDelayMs(6)).toBe(1_920_000)
    expect(embeddingBackoffDelayMs(7)).toBe(EMBEDDING_BACKOFF_MAX_MS)
    expect(embeddingBackoffDelayMs(5_000)).toBe(EMBEDDING_BACKOFF_MAX_MS)
    expect(EMBEDDING_BACKOFF_MAX_MS).toBe(3_600_000)
  })

  it.each(['empty', 'throw'] as const)(
    '%s: a full window of refused rows does not starve the older rows behind it',
    async (how) => {
      const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
      fake.refuse = p => (isPoison(p) ? how : null)
      const good = Array.from({ length: 30 }, (_, i) => seedRow(`Good ${i}`, null, null, OLD()))
      for (let i = 0; i < EMBEDDING_REFRESH_MAX_ROWS; i++) seedRow(`${POISON} ${i}`, null) // newer: first in the window
      startEmbeddingRefreshRunner()
      await advance(30_000 + 50 * 100 + 1_000)
      expect(asked(isPoison)).toBe(50)
      expect(asked(p => p === PROBE)).toBe(1)
      expect(asked(p => p.startsWith('Good'))).toBe(0)
      await advance(60_000) // second tick: the refused rows are in backoff, the window moves on
      expect(asked(isPoison)).toBe(50)
      for (const id of good) expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor(getContent(id))))
      // Not an outage, so neither outage WARN; ONE line names the refused rows.
      expect(warnsStarting(warn, 'Embedding generation failed --')).toBe(0)
      expect(warnsStarting(warn, 'Embedding backfill embedded 0')).toBe(0)
      expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(1)
      const named = warn.mock.calls.find(c => String(c[1]).startsWith('Embedding backfill: the backend is up'))![0] as { refused: number; ids: number[] }
      expect(named.refused).toBe(50)
      expect(named.ids).toHaveLength(20)
    },
  )

  it('a refused row is retried on an exponential schedule, never more than 1 h (plus a tick) apart, and announced once', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    fake.refuse = p => (isPoison(p) ? 'throw' : null)
    seedRow(`${POISON} row`, null)
    startEmbeddingRefreshRunner()
    await advance(8 * 3_600_000)
    const times = fake.askedAt.filter(a => isPoison(a.prompt)).map(a => a.at)
    const gaps = times.slice(1).map((t, i) => t - times[i])
    // 1, 2, 4, 8, 16, 32 min, then the 1 h cap; each rounded up to the next 60 s tick.
    expect(gaps.slice(0, 6).map(g => Math.round(g / 60_000))).toEqual([2, 3, 5, 9, 17, 33])
    for (const g of gaps) expect(g).toBeLessThanOrEqual(EMBEDDING_BACKOFF_MAX_MS + 60_000)
    expect(gaps.slice(6).every(g => g >= EMBEDDING_BACKOFF_MAX_MS)).toBe(true)
    expect(times.length).toBeLessThan(15) // not 480 ticks' worth
    expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(1)
    expect(warnsStarting(warn, 'Embedding generation failed --')).toBe(0)
  })

  it('an edit drops the backoff: the new text is embedded by the nudge right away', async () => {
    fake.refuse = p => (isPoison(p) ? 'empty' : null)
    const id = seedRow(`${POISON} text`, null)
    startEmbeddingRefreshRunner()
    await advance(30_500)
    expect(readEmbedding(id)).toBeNull()
    expect(updateMemory(id, 'Fixed text')).toBe(true)
    await advance(2_300)
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Fixed text')))
  })

  it('a landed vector drops the backoff: a later refusal of the same row starts over at 1 min', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    let refuseNow = true
    fake.refuse = p => (refuseNow && isPoison(p) ? 'empty' : null)
    const id = seedRow(`${POISON} flaky`, null)
    startEmbeddingRefreshRunner()
    await advance(30_500) // refused once: fails = 1
    refuseNow = false
    await advance(120_000) // retried after the backoff, lands
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor(`${POISON} flaky`)))
    refuseNow = true
    rawEdit(id, `${POISON} flaky again`) // a non-nudging writer: only the landed vector cleared the entry
    const before = asked(isPoison)
    await advance(60_000)
    expect(asked(isPoison)).toBe(before + 1)
    // fails restarted at 1: a fresh refusal, announced again.
    expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(2)
  })

  it('an outage puts nothing into backoff: the first tick after recovery embeds every row', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    fake.fail = true
    const ids = Array.from({ length: 5 }, (_, i) => seedRow(`Outage ${i}`, null))
    startEmbeddingRefreshRunner()
    await advance(30_500)
    await advance(60_000 * 5)
    expect(asked(p => p === PROBE)).toBe(6) // the probe asked once per failed pass
    expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(0)
    expect(warnsStarting(warn, 'Embedding backfill embedded 0')).toBe(1)
    fake.fail = false
    await advance(60_000)
    for (const id of ids) expect(readEmbedding(id)).not.toBeNull()
  })

  it('a missing model (every row AND the probe answered without a vector) is the outage WARN, not a backoff', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    fake.refuse = () => 'empty'
    seedRow('Any row', null)
    startEmbeddingRefreshRunner()
    await advance(30_500)
    await advance(60_000)
    expect(asked(p => p === 'Any row')).toBe(2) // not skipped: no backoff
    expect(warnsStarting(warn, 'Embedding backfill embedded 0')).toBe(1)
    expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(0)
  })

  // MN7: the backoff must land on the text that was refused, not on the id.
  it('a row edited between its refusal and the probe gets no backoff: the nudge embeds the new text well within 60 s', async () => {
    fake.refuse = p => (isPoison(p) ? 'empty' : null)
    fake.holdIf = p => p === PROBE // the edit lands while the round waits on the probe
    const id = seedRow(`${POISON} text`, null)
    startEmbeddingRefreshRunner()
    await advance(30_000 + 200) // tick at 30 s: refused, the probe is held
    expect(asked(isPoison)).toBe(1)
    expect(asked(p => p === PROBE)).toBe(1)
    const editedAt = Date.now()
    expect(updateMemory(id, 'Fixed text')).toBe(true)
    fake.holdIf = () => false
    fake.release() // the probe answers: the backend is up
    await advance(2_000 + 500) // the nudge, ~2 s after the edit
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Fixed text')))
    expect(Date.now() - editedAt).toBeLessThan(60_000)
  })

  it('an edit by a writer that clears nothing (another process, raw SQL) releases a row in backoff on the next tick', async () => {
    fake.refuse = p => (isPoison(p) ? 'empty' : null)
    const id = seedRow(`${POISON} text`, null)
    startEmbeddingRefreshRunner()
    await advance(30_500) // refused: in backoff until ~90.1 s
    rawEdit(id, 'Fixed elsewhere')
    await advance(60_000) // tick at 90 s: the refused text is gone, so the row is not skipped
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Fixed elsewhere')))
  })

  it('an uncapped pass (boot, route, fleet import) ignores the backoff', async () => {
    fake.refuse = p => (isPoison(p) ? 'empty' : null)
    seedRow(`${POISON} row`, null)
    startEmbeddingRefreshRunner()
    await advance(30_500)
    expect(asked(isPoison)).toBe(1)
    const full = backfillEmbeddings()
    await advance(1_000)
    expect((await full).embedded).toBe(0)
    expect(asked(isPoison)).toBe(2)
  })

  it('refused rows mixed with good ones raise no "backend unreachable" WARN per row, even when the call throws', async () => {
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    fake.refuse = p => (isPoison(p) ? 'throw' : null)
    for (let i = 0; i < 3; i++) {
      seedRow(`${POISON} ${i}`, null)
      seedRow(`Good ${i}`, null)
    }
    startEmbeddingRefreshRunner()
    await advance(30_500)
    for (let t = 0; t < 10; t++) await advance(60_000)
    expect(warnsStarting(warn, 'Embedding generation failed --')).toBe(0)
    expect(warnsStarting(warn, 'Embedding backfill embedded 0')).toBe(0)
    expect(warnsStarting(warn, 'Embedding backfill: the backend is up')).toBe(1)
  })
})

function getContent(id: number): string {
  return (getDb().prepare('SELECT content FROM memories WHERE id = ?').get(id) as { content: string }).content
}

describe('wiring (a runner that is never started is a silent no-op)', () => {
  const root = join(__dirname, '..', '..')
  const read = (rel: string) => readFileSync(join(root, rel), 'utf-8')

  it('index.ts starts the runner after initDatabase() in main() and stops it in shutdown()', () => {
    const src = read('src/index.ts')
    expect(src).toContain("import { startEmbeddingRefreshRunner, stopEmbeddingRefreshRunner } from './web/embedding-refresh-runner.js'")
    const shutdown = src.slice(src.indexOf('const shutdown = (): void => {'), src.indexOf('async function main()'))
    expect(shutdown).toContain('stopEmbeddingRefreshRunner()')
    const main = src.slice(src.indexOf('async function main()'))
    expect(main.indexOf('initDatabase()')).toBeGreaterThan(-1)
    expect(main.indexOf('startEmbeddingRefreshRunner()')).toBeGreaterThan(main.indexOf('initDatabase()'))
  })

  it('the runner drives the capped single-flight backfill and arms the nudge', () => {
    const src = read('src/web/embedding-refresh-runner.ts')
    expect(src).toContain('backfillEmbeddings({ maxRows: EMBEDDING_REFRESH_MAX_ROWS })')
    expect(src).toContain('setEmbeddingRefreshArmed(true)')
    expect(src).toContain('setEmbeddingRefreshArmed(false)')
    expect(src).toMatch(/INITIAL_DELAY_MS = 30_000/)
    expect(src).toMatch(/INTERVAL_MS = 60_000/)
  })

  it('db.ts has no unconditional vector write left, and updateMemory nudges', () => {
    const src = read('src/db.ts')
    const writes = src.match(/SET embedding = \?[^'"`]*/g) ?? []
    expect(writes).toEqual(['SET embedding = ? WHERE id = ? AND content = ? AND keywords IS ?'])
    const update = src.slice(src.indexOf('export function updateMemory('), src.indexOf('// --- Daily logs ---'))
    expect(update).toContain('if (embeddedTextChanged) requestEmbeddingRefresh()')
  })
})
