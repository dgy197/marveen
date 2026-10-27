// Card ada44194: the hybridSearch WARN ("keyword branch found nothing") used to
// log the raw search query. A query is the user's own words, so only its length
// and a short hash may reach the log. Negative control: the marker text must be
// absent from everything the logger was handed; the length and the hash present.
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { initDatabase, getDb, hybridSearch, clearMemoryCache, queryLogFields } from '../db.js'
import { logger } from '../logger.js'

const MARKER = 'TITKOS-LEKERDEZES-123'

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

beforeEach(() => clearMemoryCache())
afterEach(() => vi.restoreAllMocks())

describe('hybridSearch WARN carries no query text', () => {
  it('logs queryLen and queryHash, never the query itself', async () => {
    const db = getDb()
    const now = Math.floor(Date.now() / 1000)
    db.prepare(
      `INSERT INTO memories (chat_id, content, sector, salience, created_at, accessed_at, agent_id, category, keywords, embedding)
       VALUES ('0', ?, 'semantic', 1.0, ?, ?, 'logtest', 'warm', ?, ?)`
    ).run('vektor-only sor', now, now, 'alpha', JSON.stringify([1, 0, 0, 0]))

    vi.stubGlobal('fetch', vi.fn(async () => ({ json: async () => ({ embedding: [1, 0, 0, 0] }) })))
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    const anyOther = [
      vi.spyOn(logger, 'info').mockImplementation(() => undefined as never),
      vi.spyOn(logger, 'error').mockImplementation(() => undefined as never),
      vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never),
    ]

    const query = `${MARKER} zzzznincsilyenszo`
    const hits = await hybridSearch('logtest', query, 10)
    vi.unstubAllGlobals()

    // The WARN branch really fired (vector-only answer).
    expect(hits.map(h => h.content)).toContain('vektor-only sor')
    const call = warn.mock.calls.find(c => String(c[1]).includes('keyword branch found nothing'))
    expect(call).toBeDefined()

    const everything = JSON.stringify([warn, ...anyOther].flatMap(s => s.mock.calls))
    expect(everything).not.toContain(MARKER)
    expect(everything).not.toContain('zzzznincsilyenszo')

    const fields = call![0] as Record<string, unknown>
    expect(fields.queryLen).toBe(query.length)
    expect(fields.queryHash).toMatch(/^[0-9a-f]{12}$/)
    // Same value as the in-process helper, but not the unsalted sha256.
    expect(fields.queryHash).toBe(queryLogFields(query).queryHash)
    expect(fields.queryHash).not.toBe(createHash('sha256').update(query).digest('hex').slice(0, 12))
    expect(fields).not.toHaveProperty('query')
  })

  it('queryLogFields: 12 hex chars, deterministic in-process, salted, length in characters', () => {
    const a = queryLogFields(MARKER)
    expect(a.queryHash).toMatch(/^[0-9a-f]{12}$/)
    expect(a).toEqual(queryLogFields(MARKER))
    expect(queryLogFields(MARKER + 'x').queryHash).not.toBe(a.queryHash)
    // Not the unsalted sha256 prefix: a dictionary of plain hashes cannot match it.
    expect(a.queryHash).not.toBe(createHash('sha256').update(MARKER).digest('hex').slice(0, 12))
    expect(JSON.stringify(a)).not.toContain(MARKER)
    expect(a.queryLen).toBe(MARKER.length)
    expect(queryLogFields('árvíztűrő').queryLen).toBe(9)
  })

  it('queryLogFields: the HMAC key is random per module load, not a fixed key in code', async () => {
    const first = queryLogFields(MARKER).queryHash
    vi.resetModules()
    const reloaded = await import('../db.js')
    // A fresh module instance (new load), not the one imported at the top.
    expect(reloaded.queryLogFields).not.toBe(queryLogFields)
    const second = reloaded.queryLogFields(MARKER).queryHash
    expect(second).toMatch(/^[0-9a-f]{12}$/)
    expect(second).not.toBe(first)
  })
})
