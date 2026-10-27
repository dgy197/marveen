/**
 * Contract test for GET /api/memories/:id.
 *
 * Until 2026-09-14 the id-addressed routes were PUT/PATCH/DELETE only: a memory
 * could be referenced by id, edited by id and deleted by id, but never READ by
 * id. The shared tier is full of such pointers ("see shared <id>"), and the only
 * way to follow one was keyword search -- which silently fails when the keywords
 * do not match.
 *
 * A sub-agent hit exactly that and read the 404 as "the record does not exist",
 * when what did not exist was the route. An absent route and an absent row must
 * not look alike, so both cases are pinned here.
 */
import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import { initDatabase, getDb, saveAgentMemory, updateMemory } from '../db.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import type { RouteContext } from '../web/routes/types.js'

vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  return { ...actual, MAIN_AGENT_ID: 'agent-a', ALLOWED_CHAT_ID: 'test-chat', OLLAMA_URL: '' }
})

vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

function makeCtx(path: string, method = 'GET'): { ctx: RouteContext; getBody: () => any; status: () => number } {
  const url = new URL(`http://localhost:3420${path}`)
  let responseBody = ''
  let statusCode = 200
  const res = {
    writeHead: (code: number) => { statusCode = code },
    end: (body?: string) => { responseBody = body || '' },
  }
  return {
    ctx: { req: {} as any, res: res as any, path, method, url },
    getBody: () => (responseBody ? JSON.parse(responseBody) : null),
    status: () => statusCode,
  }
}

let seededId = 0

beforeAll(() => {
  // saveAgentMemory fires an embedding request in the background; never let a test reach a real Ollama.
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  initDatabase(':memory:')
  seededId = saveAgentMemory('agent-a', 'a pointer target the keyword search would miss', 'shared', 'zzz-unrelated').id
})

afterAll(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('GET /api/memories/:id', () => {
  it('returns the row for an existing id, without needing a matching keyword', async () => {
    const { ctx, getBody } = makeCtx(`/api/memories/${seededId}`)
    const handled = await tryHandleMemories(ctx)
    expect(handled).toBe(true)
    const body = getBody()
    expect(body.id).toBe(seededId)
    expect(body.agent_id).toBe('agent-a')
    expect(body.category).toBe('shared')
    expect(body.content).toContain('pointer target')
  })

  it('404s for an id that does not exist -- distinct from the route being absent', async () => {
    const { ctx, status } = makeCtx('/api/memories/99999999')
    const handled = await tryHandleMemories(ctx)
    // handled=true is the point: the ROUTE exists and answers. Before the fix
    // this returned false and the caller saw a generic "Not found" from the
    // router, which is indistinguishable from a missing record.
    expect(handled).toBe(true)
    expect(status()).toBe(404)
  })
})

describe('GET /api/memories/:id: has_embedding', () => {
  function seedRow(content: string, embedding: string | null): number {
    const now = Math.floor(Date.now() / 1000)
    return Number(getDb().prepare(
      `INSERT INTO memories (chat_id, topic_key, content, sector, salience, created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
       VALUES ('0', NULL, ?, 'semantic', 1.0, ?, ?, 'agent-a', 'warm', 0, 'has-embedding-test', ?)`,
    ).run(content, now, now, embedding).lastInsertRowid)
  }

  it('is true for a row that has a vector, and the vector itself is not in the response', async () => {
    const id = seedRow('indexed row', JSON.stringify([0.1, 0.2, 0.3]))
    const { ctx, getBody } = makeCtx(`/api/memories/${id}`)
    await tryHandleMemories(ctx)
    const body = getBody()
    expect(body.has_embedding).toBe(true)
    expect(body).not.toHaveProperty('embedding')
    expect(JSON.stringify(body)).not.toContain('0.2')
  })

  it('is false for a row without a vector (strictly the boolean false, not 0 or null)', async () => {
    const id = seedRow('row waiting for re-embedding', null)
    const { ctx, getBody } = makeCtx(`/api/memories/${id}`)
    await tryHandleMemories(ctx)
    const body = getBody()
    expect(body.has_embedding).toBe(false)
    expect(body).not.toHaveProperty('embedding')
  })

  it('flips to false when updateMemory invalidates the vector', async () => {
    const id = seedRow('before edit', JSON.stringify([1, 0]))
    updateMemory(id, 'after edit')
    const { ctx, getBody } = makeCtx(`/api/memories/${id}`)
    await tryHandleMemories(ctx)
    expect(getBody().has_embedding).toBe(false)
  })

  it('keeps every other field unchanged', async () => {
    const { ctx, getBody } = makeCtx(`/api/memories/${seededId}`)
    await tryHandleMemories(ctx)
    expect(Object.keys(getBody()).sort()).toEqual([
      'accessed_at', 'agent_id', 'category', 'content', 'created_at', 'has_embedding',
      'id', 'keywords', 'length', 'updated_at', 'updated_by', 'version',
    ])
  })

  it('still 404s for a missing id', async () => {
    const { ctx, status, getBody } = makeCtx('/api/memories/99999998')
    await tryHandleMemories(ctx)
    expect(status()).toBe(404)
    expect(getBody()).toEqual({ error: 'Memory not found' })
  })
})
