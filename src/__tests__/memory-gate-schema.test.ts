/**
 * Memory write gate b1 (card 3e9f6c28, node B1-S): migration contract.
 *  - additive, idempotent, PRAGMA-verified;
 *  - no `memory_gate_state` table and no `memories.origin` column in b1;
 *  - a failed migration (SQLITE_BUSY / SQLITE_FULL / half-built table) never stops
 *    initDatabase(), leaves the rest of the dashboard DB usable and the gate inert.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { mkdtempSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDatabase, getDb, saveAgentMemory } from '../db.js'
import {
  migrateMemoryGate, gateTablesReady, gateMigrationFailure, verifyGateTables, GATE_TABLES, resetGateSchemaFlags,
} from '../memory-gate/schema.js'

vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

function tableNames(): string[] {
  return (getDb().prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'memory_gate_%' ORDER BY name").all() as Array<{ name: string }>).map(r => r.name)
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  resetGateSchemaFlags()
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('migrateMemoryGate', () => {
  it('a fresh database gets exactly the five b1 tables and the flag turns true', () => {
    initDatabase(':memory:')
    expect(gateTablesReady()).toBe(true)
    expect(gateMigrationFailure()).toBeNull()
    expect(tableNames()).toEqual([...GATE_TABLES].sort())
    expect(GATE_TABLES).toEqual(['memory_gate_origin', 'memory_gate_decisions', 'memory_gate_candidates', 'memory_gate_daily', 'memory_gate_kv'])
  })

  it('b1 creates no memory_gate_state table and adds no column to memories', () => {
    initDatabase(':memory:')
    expect(tableNames()).not.toContain('memory_gate_state')
    const cols = (getDb().prepare('PRAGMA table_info(memories)').all() as Array<{ name: string }>).map(c => c.name)
    expect(cols).not.toContain('origin')
    expect(cols).not.toContain('valid_to')
    expect(cols).not.toContain('superseded_by')
  })

  it('is idempotent and keeps the data (old DB, second boot)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'gate-schema-'))
    const file = join(dir, 'old.db')
    initDatabase(file)
    getDb().prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (7, 'api', 1)").run()
    // A DB from before the gate: drop every gate table, then boot again.
    for (const t of GATE_TABLES) getDb().exec(`DROP TABLE ${t}`)
    expect(tableNames()).toEqual([])
    initDatabase(file)
    expect(gateTablesReady()).toBe(true)
    getDb().prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (9, 'api', 1)").run()
    initDatabase(file)
    expect(migrateMemoryGate(getDb())).toEqual({ ok: true })
    expect(migrateMemoryGate(getDb())).toEqual({ ok: true })
    expect(getDb().prepare('SELECT memory_id FROM memory_gate_origin').all()).toEqual([{ memory_id: 9 }])
  })

  it('the origin CHECK admits only api; op admits UNKNOWN but not garbage', () => {
    initDatabase(':memory:')
    const db = getDb()
    expect(() => db.prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (1, 'import', 1)").run()).toThrow()
    const ins = (op: string | null) => db.prepare(
      "INSERT INTO memory_gate_decisions (source_id, source_version, rubric, state, op, created_at) VALUES (?, ?, 'g1', 'decided', ?, 1)",
    ).run(Math.floor(Math.random() * 1e9), 1, op)
    expect(() => ins('UNKNOWN')).not.toThrow()
    expect(() => ins('CREATE')).not.toThrow()
    expect(() => ins('DROP')).toThrow()
  })

  it('the decision row is unique per (source_id, source_version, rubric)', () => {
    initDatabase(':memory:')
    const ins = () => getDb().prepare("INSERT INTO memory_gate_decisions (source_id, source_version, rubric, created_at) VALUES (5, 1, 'g1', 1)").run()
    ins()
    expect(ins).toThrow()
  })

  it('reason is capped at 200 characters by the schema', () => {
    initDatabase(':memory:')
    const ins = (reason: string) => getDb().prepare("INSERT INTO memory_gate_decisions (source_id, source_version, rubric, reason, created_at) VALUES (?, 1, 'g1', ?, 1)").run(Math.floor(Math.random() * 1e9), reason)
    expect(() => ins('x'.repeat(200))).not.toThrow()
    expect(() => ins('x'.repeat(201))).toThrow()
  })
})

describe('a failing migration never stops the boot (GB4)', () => {
  for (const code of ['SQLITE_BUSY', 'SQLITE_FULL']) {
    it(`${code}: initDatabase returns, the rest of the DB works, the gate is inert`, () => {
      const realExec = Database.prototype.exec
      const spy = vi.spyOn(Database.prototype, 'exec').mockImplementation(function (this: Database.Database, sql: string) {
        if (sql.includes('memory_gate_origin')) throw Object.assign(new Error('simulated failure with SQL: ' + sql.slice(0, 20)), { code })
        return realExec.call(this, sql)
      })
      expect(() => initDatabase(':memory:')).not.toThrow()
      spy.mockRestore()
      expect(gateTablesReady()).toBe(false)
      expect(gateMigrationFailure()).toBe(code)
      expect(tableNames()).toEqual([]) // no half-built schema
      // the dashboard's own tables are fine
      const { id } = saveAgentMemory('agent-a', 'still saves', 'warm', 'kw')
      expect(id).toBeGreaterThan(0)
    })
  }

  it('the failure record holds the error class only, not the message', () => {
    const realExec = Database.prototype.exec
    const spy = vi.spyOn(Database.prototype, 'exec').mockImplementation(function (this: Database.Database, sql: string) {
      if (sql.includes('memory_gate_origin')) throw new Error('secret-looking text in message')
      return realExec.call(this, sql)
    })
    initDatabase(':memory:')
    spy.mockRestore()
    expect(gateMigrationFailure()).toBe('Error')
    expect(JSON.stringify(gateMigrationFailure())).not.toContain('secret')
  })

  it('a pre-existing table of the wrong shape fails the PRAGMA proof (verify_failed), the flag stays false', () => {
    const db = new Database(':memory:')
    db.exec('CREATE TABLE memory_gate_kv (key TEXT)') // IF NOT EXISTS will skip it
    expect(migrateMemoryGate(db)).toEqual({ ok: false, reason: 'verify_failed' })
    expect(gateTablesReady()).toBe(false)
    expect(verifyGateTables(db)).toBe(false)
    db.close()
  })
})
