/**
 * Memory write gate b1 (card 3e9f6c28, node B1-S): even if migrateMemoryGate itself
 * THROWS (it is written not to), initDatabase() must return and the dashboard DB
 * must keep working. This is the belt-and-braces try/catch in db.ts (GB4).
 */
import { describe, it, expect, vi } from 'vitest'

vi.mock('../memory-gate/schema.js', () => ({
  migrateMemoryGate: () => { throw new Error('migration blew up') },
  gateTablesReady: () => false,
  gateMigrationFailure: () => null,
}))
vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

import { initDatabase, getDb, saveAgentMemory } from '../db.js'

describe('initDatabase with a throwing gate migration', () => {
  it('returns normally and the memories table still works', () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
    expect(() => initDatabase(':memory:')).not.toThrow()
    const { id } = saveAgentMemory('agent-a', 'saved despite the gate', 'warm', 'kw')
    expect(getDb().prepare('SELECT content FROM memories WHERE id = ?').get(id)).toEqual({ content: 'saved despite the gate' })
    vi.unstubAllGlobals()
  })
})
