import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import {
  mintAgentSendKey,
  resolveAgentSendKey,
  revokeAgentSendKey,
  AGENT_SEND_KEY_MAX_LEN,
  AGENT_SEND_KEY_GRACE_SEC,
} from '../web/agent-send-keys.js'

// Card 0d7e2c04 N1 -- per-agent send keys. Contract under test:
//   - mint returns a raw key once; only sha256(key) reaches the DB;
//   - resolve maps a key back to its agent through the hash lookup;
//   - rotation keeps the old key as 'prev' for the grace window, then null;
//   - revoke kills current and prev at once;
//   - the length cap runs before any hashing or DB access;
//   - the migration is additive and idempotent.

function sha256hex(v: string): string {
  return createHash('sha256').update(v).digest('hex')
}

beforeEach(() => {
  initDatabase(':memory:')
})

afterEach(() => {
  vi.useRealTimers()
  vi.restoreAllMocks()
})

describe('mint / resolve', () => {
  it('a minted key resolves to its agent as current', () => {
    const raw = mintAgentSendKey('feszek')
    expect(raw.startsWith('mvak_')).toBe(true)
    expect(raw.length).toBeLessThanOrEqual(AGENT_SEND_KEY_MAX_LEN)
    expect(resolveAgentSendKey(raw)).toEqual({ agentId: 'feszek', which: 'current' })
  })

  it('keys of two agents are distinct and each resolves to its own agent', () => {
    const a = mintAgentSendKey('feszek')
    const b = mintAgentSendKey('iroda')
    expect(a).not.toBe(b)
    expect(resolveAgentSendKey(a)?.agentId).toBe('feszek')
    expect(resolveAgentSendKey(b)?.agentId).toBe('iroda')
  })

  it('unknown, empty, wrong-prefix and non-string inputs resolve to null', () => {
    mintAgentSendKey('feszek')
    expect(resolveAgentSendKey('mvak_' + 'x'.repeat(43))).toBeNull()
    expect(resolveAgentSendKey('')).toBeNull()
    expect(resolveAgentSendKey('nope')).toBeNull()
    expect(resolveAgentSendKey(undefined)).toBeNull()
    expect(resolveAgentSendKey(['mvak_a'])).toBeNull()
    expect(resolveAgentSendKey(42)).toBeNull()
  })

  it('refuses a bad agent id on mint and revoke', () => {
    expect(() => mintAgentSendKey('')).toThrow('invalid agent id')
    expect(() => mintAgentSendKey('a'.repeat(65))).toThrow('invalid agent id')
    expect(() => revokeAgentSendKey('')).toThrow('invalid agent id')
  })

  it('stamps last_used_at on first use', () => {
    const raw = mintAgentSendKey('feszek')
    const before = getDb().prepare('SELECT last_used_at FROM agent_send_keys WHERE agent_id = ?').get('feszek') as { last_used_at: number | null }
    expect(before.last_used_at).toBeNull()
    resolveAgentSendKey(raw)
    const after = getDb().prepare('SELECT last_used_at FROM agent_send_keys WHERE agent_id = ?').get('feszek') as { last_used_at: number | null }
    expect(after.last_used_at).not.toBeNull()
  })
})

describe('rotation and grace window', () => {
  it('after a rotation the old key is prev within 10 minutes and the new one is current', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-31T10:00:00Z'))
    const oldKey = mintAgentSendKey('feszek')
    const newKey = mintAgentSendKey('feszek')
    expect(newKey).not.toBe(oldKey)
    expect(resolveAgentSendKey(newKey)).toEqual({ agentId: 'feszek', which: 'current' })
    expect(resolveAgentSendKey(oldKey)).toEqual({ agentId: 'feszek', which: 'prev' })
    vi.setSystemTime(new Date('2026-10-31T10:00:00Z').getTime() + (AGENT_SEND_KEY_GRACE_SEC - 1) * 1000)
    expect(resolveAgentSendKey(oldKey)).toEqual({ agentId: 'feszek', which: 'prev' })
  })

  it('after the grace window the old key is null, the new one still works', () => {
    vi.useFakeTimers()
    vi.setSystemTime(new Date('2026-10-31T10:00:00Z'))
    const oldKey = mintAgentSendKey('feszek')
    const newKey = mintAgentSendKey('feszek')
    vi.setSystemTime(new Date('2026-10-31T10:00:00Z').getTime() + (AGENT_SEND_KEY_GRACE_SEC + 1) * 1000)
    expect(resolveAgentSendKey(oldKey)).toBeNull()
    expect(resolveAgentSendKey(newKey)?.which).toBe('current')
  })

  it('a second rotation drops the key two generations back immediately', () => {
    const k1 = mintAgentSendKey('feszek')
    const k2 = mintAgentSendKey('feszek')
    const k3 = mintAgentSendKey('feszek')
    expect(resolveAgentSendKey(k1)).toBeNull()
    expect(resolveAgentSendKey(k2)?.which).toBe('prev')
    expect(resolveAgentSendKey(k3)?.which).toBe('current')
  })

  it('rotating one agent does not touch another agent', () => {
    const other = mintAgentSendKey('iroda')
    mintAgentSendKey('feszek')
    mintAgentSendKey('feszek')
    expect(resolveAgentSendKey(other)).toEqual({ agentId: 'iroda', which: 'current' })
  })
})

describe('revoke', () => {
  it('kills the current and the prev key at once', () => {
    const oldKey = mintAgentSendKey('feszek')
    const newKey = mintAgentSendKey('feszek')
    expect(revokeAgentSendKey('feszek')).toBe(true)
    expect(resolveAgentSendKey(newKey)).toBeNull()
    expect(resolveAgentSendKey(oldKey)).toBeNull()
  })

  it('returns false when the agent has no key, and leaves other agents alone', () => {
    const other = mintAgentSendKey('iroda')
    expect(revokeAgentSendKey('feszek')).toBe(false)
    expect(resolveAgentSendKey(other)?.agentId).toBe('iroda')
  })
})

describe('input size cap', () => {
  it('an oversized key resolves to null without hashing or any DB call', () => {
    mintAgentSendKey('feszek')
    const prepare = vi.spyOn(getDb(), 'prepare')
    expect(resolveAgentSendKey('mvak_' + 'a'.repeat(AGENT_SEND_KEY_MAX_LEN))).toBeNull()
    expect(resolveAgentSendKey('a'.repeat(100_000))).toBeNull()
    expect(prepare).not.toHaveBeenCalled()
  })

  it('a key exactly at the cap still reaches the lookup (and misses)', () => {
    const prepare = vi.spyOn(getDb(), 'prepare')
    const atCap = 'mvak_' + 'a'.repeat(AGENT_SEND_KEY_MAX_LEN - 5)
    expect(atCap.length).toBe(AGENT_SEND_KEY_MAX_LEN)
    expect(resolveAgentSendKey(atCap)).toBeNull()
    expect(prepare).toHaveBeenCalled()
  })
})

describe('the raw key never reaches the DB', () => {
  it('rows hold sha256 hashes only; a full DB dump does not contain the raw key', () => {
    const oldKey = mintAgentSendKey('feszek')
    const newKey = mintAgentSendKey('feszek')
    resolveAgentSendKey(newKey)
    const rows = getDb().prepare('SELECT * FROM agent_send_keys').all() as Array<Record<string, unknown>>
    expect(rows).toHaveLength(1)
    const dump = JSON.stringify(rows)
    expect(dump).not.toContain(newKey)
    expect(dump).not.toContain(oldKey)
    expect(rows[0].key_hash).toBe(sha256hex(newKey))
    expect(rows[0].prev_hash).toBe(sha256hex(oldKey))
    const bytes = getDb().serialize()
    expect(bytes.includes(Buffer.from(newKey))).toBe(false)
    expect(bytes.includes(Buffer.from(oldKey))).toBe(false)
  })

  it('error messages never carry key material', () => {
    let msg = ''
    try { mintAgentSendKey('x'.repeat(200)) } catch (e) { msg = (e as Error).message }
    expect(msg).toBe('invalid agent id')
  })
})

describe('migration is additive and idempotent', () => {
  let dir = ''
  beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'agent-send-keys-mig-')) })
  afterEach(() => {
    initDatabase(':memory:') // closes the file handle before its directory goes
    rmSync(dir, { recursive: true, force: true })
  })

  it('re-running initDatabase on the same file keeps keys and message rows untouched', () => {
    const file = join(dir, 'm.db')
    initDatabase(file)
    const raw = mintAgentSendKey('feszek')
    getDb()
      .prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at) VALUES ('a', 'b', 'hello', 'pending', 1)")
      .run()
    const keysBefore = JSON.stringify(getDb().prepare('SELECT * FROM agent_send_keys').all())
    const msgsBefore = JSON.stringify(getDb().prepare('SELECT * FROM agent_messages').all())

    initDatabase(file)

    expect(JSON.stringify(getDb().prepare('SELECT * FROM agent_send_keys').all())).toBe(keysBefore)
    expect(JSON.stringify(getDb().prepare('SELECT * FROM agent_messages').all())).toBe(msgsBefore)
    expect(resolveAgentSendKey(raw)?.agentId).toBe('feszek')
  })

  it('an older database without the table and column gains both; old rows keep sender_auth NULL', () => {
    const file = join(dir, 'old.db')
    initDatabase(file)
    getDb()
      .prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at) VALUES ('a', 'b', 'old row', 'done', 1)")
      .run()
    // Simulate a pre-0d7e2c04 database.
    getDb().exec('DROP INDEX IF EXISTS idx_agent_send_keys_prev')
    getDb().exec('DROP TABLE agent_send_keys')
    getDb().exec('ALTER TABLE agent_messages DROP COLUMN sender_auth')
    const cols = (getDb().prepare("PRAGMA table_info('agent_messages')").all() as Array<{ name: string }>).map((c) => c.name)
    expect(cols).not.toContain('sender_auth')

    initDatabase(file)

    const after = (getDb().prepare("PRAGMA table_info('agent_messages')").all() as Array<{ name: string }>).map((c) => c.name)
    expect(after).toContain('sender_auth')
    const row = getDb().prepare("SELECT content, sender_auth FROM agent_messages WHERE content = 'old row'").get() as { content: string; sender_auth: string | null }
    expect(row).toEqual({ content: 'old row', sender_auth: null })
    expect(getDb().prepare('SELECT count(*) AS n FROM agent_send_keys').get()).toEqual({ n: 0 })
  })
})
