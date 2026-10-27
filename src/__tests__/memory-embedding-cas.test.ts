import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { initDatabase, getDb, saveAgentMemory, saveMemory, updateMemory, backfillEmbeddings } from '../db.js'

// The vector of a memory row must describe the row's CURRENT text
// (`content + ' ' + keywords`). Both writers of the vector -- the save path's
// fire-and-forget and backfillEmbeddings -- call Ollama first and write later,
// so the text can change in between. Before card d4e7fea7 both wrote the vector
// back unconditionally, and an edit that landed while the embedding was in
// flight ended up with the OLD text's vector next to the NEW text: wrong
// ranking, no error, and nothing NULL left for a later backfill to fix.
//
// The fake embedder below answers with a vector derived from the prompt, so a
// test can tell WHICH text a stored vector belongs to, and it can hold the
// answer to put an edit inside the window. Ollama is never contacted.

const AGENT = 'embedding-cas-agent'

function vectorFor(text: string): number[] {
  let h = 0
  for (const ch of text) h = (h * 31 + ch.codePointAt(0)!) % 1_000_003
  return [text.length, h, 1]
}

interface FakeEmbedder {
  prompts: string[]
  held: Array<() => void>
  hold: boolean
  release(): void
}

function installFakeEmbedder(): FakeEmbedder {
  const fake: FakeEmbedder = {
    prompts: [],
    held: [],
    hold: false,
    release() { for (const r of fake.held.splice(0)) r() },
  }
  vi.stubGlobal('fetch', vi.fn(async (_url: string, init: { body: string }) => {
    const prompt = JSON.parse(init.body).prompt as string
    fake.prompts.push(prompt)
    if (fake.hold) await new Promise<void>(r => fake.held.push(r))
    return { json: async () => ({ embedding: vectorFor(prompt) }) }
  }))
  return fake
}

// One macrotask turn: every microtask queued by a released fetch (the fake's
// continuation, resp.json(), generateEmbedding's return, the save path's
// .then) has run by then.
const settle = () => new Promise<void>(r => setImmediate(r))

function seedRow(content: string, keywords: string | null, embedding: string | null = null): number {
  const now = Math.floor(Date.now() / 1000)
  const info = getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience,
     created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
     VALUES ('test-chat', NULL, ?, 'semantic', 1.0, ?, ?, ?, 'warm', 0, ?, ?)`
  ).run(content, now, now, AGENT, keywords, embedding)
  return Number(info.lastInsertRowid)
}

function readEmbedding(id: number): string | null {
  return (getDb().prepare('SELECT embedding FROM memories WHERE id = ?').get(id) as { embedding: string | null }).embedding
}

beforeEach(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('backfillEmbeddings: compare-and-set write', () => {
  it('an edit while the backfill is embedding does NOT get the old text\'s vector, and the next pass embeds the new text', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    const id = seedRow('Old text', 'kw')
    const pass = backfillEmbeddings()
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(fake.prompts).toEqual(['Old text kw'])

    expect(updateMemory(id, 'New text')).toBe(true)
    fake.hold = false
    fake.release()
    await pass
    expect(readEmbedding(id)).toBeNull()

    await backfillEmbeddings()
    expect(fake.prompts.at(-1)).toBe('New text kw')
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('New text kw')))
  })

  it('a keywords-only edit inside the window counts as a change too', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    const id = seedRow('Body stays', 'old-kw')
    const pass = backfillEmbeddings()
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(updateMemory(id, 'Body stays', undefined, undefined, 'new-kw')).toBe(true)
    fake.release()
    await pass
    expect(readEmbedding(id)).toBeNull()
  })

  it('never overwrites the vector of a NEWER text that landed while the stale answer was in flight', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    const id = seedRow('Version one', null)
    const pass = backfillEmbeddings()
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(updateMemory(id, 'Version two')).toBe(true)
    // The newer text got its vector by another writer in the meantime.
    const newer = JSON.stringify(vectorFor('Version two'))
    getDb().prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(newer, id)
    fake.release()
    await pass
    expect(readEmbedding(id)).toBe(newer)
  })

  it('two overlapping backfills embed every row once, and both callers get the same count', async () => {
    const fake = installFakeEmbedder()
    const ids = [seedRow('Row a', null), seedRow('Row b', 'kw'), seedRow('Row c', null)]
    const [first, second] = await Promise.all([backfillEmbeddings(), backfillEmbeddings()])
    expect(fake.prompts.slice().sort()).toEqual(['Row a', 'Row b kw', 'Row c'])
    expect(first.embedded).toBe(3)
    expect(second.embedded).toBe(3)
    for (const id of ids) expect(readEmbedding(id)).not.toBeNull()
  })

  it('positive control: without an edit the backfill still writes the vector of the text it embedded', async () => {
    const fake = installFakeEmbedder()
    const id = seedRow('Untouched', 'kw')
    expect((await backfillEmbeddings()).embedded).toBe(1)
    expect(fake.prompts).toEqual(['Untouched kw'])
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Untouched kw')))
  })
})

describe('save path: the fire-and-forget embedding is compare-and-set too', () => {
  it('saveAgentMemory + an immediate edit before the embedding returns: no stale vector', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    const { id } = saveAgentMemory(AGENT, 'Draft body', 'warm', 'kw')
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(fake.prompts).toEqual(['Draft body kw'])
    expect(updateMemory(id, 'Final body')).toBe(true)
    fake.release()
    await settle()
    expect(readEmbedding(id)).toBeNull()
  })

  it('saveMemory (chat path) + an immediate edit: no stale vector', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    saveMemory('test-chat', 'Chat draft', 'semantic', undefined, AGENT)
    const id = (getDb().prepare('SELECT id FROM memories WHERE content = ?').get('Chat draft') as { id: number }).id
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(updateMemory(id, 'Chat final')).toBe(true)
    fake.release()
    await settle()
    expect(readEmbedding(id)).toBeNull()
  })

  it('a category-only edit inside the window keeps the vector (the embedded text did not change)', async () => {
    const fake = installFakeEmbedder()
    fake.hold = true
    const { id } = saveAgentMemory(AGENT, 'Stable body', 'warm', 'kw')
    await vi.waitFor(() => expect(fake.held).toHaveLength(1))
    expect(updateMemory(id, 'Stable body', 'cold')).toBe(true)
    fake.release()
    await settle()
    expect(readEmbedding(id)).toBe(JSON.stringify(vectorFor('Stable body kw')))
  })

  it('new saves still get their vector (old behaviour), with and without keywords', async () => {
    const fake = installFakeEmbedder()
    const withKw = saveAgentMemory(AGENT, 'Fresh body', 'warm', 'kw1, kw2').id
    const withoutKw = saveAgentMemory(AGENT, 'Bare body', 'hot').id
    saveMemory('test-chat', 'Chat body', 'episodic', undefined, AGENT)
    const chatId = (getDb().prepare('SELECT id FROM memories WHERE content = ?').get('Chat body') as { id: number }).id
    await settle()
    expect(fake.prompts.slice().sort()).toEqual(['Bare body', 'Chat body', 'Fresh body kw1, kw2'])
    expect(readEmbedding(withKw)).toBe(JSON.stringify(vectorFor('Fresh body kw1, kw2')))
    expect(readEmbedding(withoutKw)).toBe(JSON.stringify(vectorFor('Bare body')))
    expect(readEmbedding(chatId)).toBe(JSON.stringify(vectorFor('Chat body')))
  })
})
