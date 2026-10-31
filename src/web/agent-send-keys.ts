// Per-agent send keys (card 0d7e2c04, inter-agent sender authentication).
//
// Every agent gets ONE key at launch; presenting it on POST /api/messages
// binds the row's `from` to that agent instead of to the self-declared body
// field. Modeled on auth-device-keys.ts: only sha256(key) is stored, so a DB
// leak yields no usable credential. The raw key exists only in the object
// mintAgentSendKey returns, and the caller writes it to a 0600 file.
//
// Scope is "send as <agentId>" and nothing else: the key is not a dashboard
// credential (the shared Bearer is still required), it only vouches for the
// sender name. Same-user threat model: an agent that reads another agent's key
// file can still impersonate it; this closes accidental and injected `from`
// forgery, not deliberate key theft (spec R1).
//
// Rotation keeps the replaced key valid for a grace window (R3), so a
// background process that still holds it across a restart resolves as 'prev'
// rather than failing.
//
// Lookups go through the hash (an indexed equality lookup in SQLite), never a
// string compare on raw keys, and the length cap runs before any hashing or DB
// access, so an oversized header costs nothing.

import { randomBytes, createHash } from 'node:crypto'
import { getDb } from '../db.js'

// Recognizable in logs/repos (secret scanners) and distinct from the device-key
// prefix (mvdk_) and the 64-hex dashboard token.
const KEY_PREFIX = 'mvak_'

/** A real key is 5 + 43 chars; anything longer than this is rejected unhashed. */
export const AGENT_SEND_KEY_MAX_LEN = 128

/** How long a rotated-out key keeps resolving (as 'prev'). */
export const AGENT_SEND_KEY_GRACE_SEC = 10 * 60

/** An agent id is a short slug; bounds the key per row and the DB write. */
const MAX_AGENT_ID_LEN = 64

const LAST_USED_DEBOUNCE_SEC = 60

export interface ResolvedAgentSendKey {
  agentId: string
  /** 'current' = the live key; 'prev' = the key before the last rotation, still inside its grace window. */
  which: 'current' | 'prev'
}

function sha256hex(value: string): string {
  return createHash('sha256').update(value).digest('hex')
}

function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

function assertAgentId(agentId: unknown): asserts agentId is string {
  if (typeof agentId !== 'string' || agentId.length === 0 || agentId.length > MAX_AGENT_ID_LEN) {
    throw new Error('invalid agent id')
  }
}

/**
 * Mint a fresh key for an agent, replacing its current one. The replaced key's
 * hash moves to prev_hash and stays valid for AGENT_SEND_KEY_GRACE_SEC. The raw
 * value is returned ONCE and never stored.
 */
export function mintAgentSendKey(agentId: string): string {
  assertAgentId(agentId)
  const raw = KEY_PREFIX + randomBytes(32).toString('base64url')
  const keyHash = sha256hex(raw)
  const now = nowSec()
  // One statement: in an UPDATE every right-hand side reads the pre-update row,
  // so prev_hash picks up the old key_hash atomically with the new one.
  getDb()
    .prepare(
      `INSERT INTO agent_send_keys (agent_id, key_hash, prev_hash, prev_valid_until, created_at, last_used_at)
       VALUES (?, ?, NULL, NULL, ?, NULL)
       ON CONFLICT(agent_id) DO UPDATE SET
         prev_hash = agent_send_keys.key_hash,
         prev_valid_until = ?,
         key_hash = excluded.key_hash,
         created_at = excluded.created_at,
         last_used_at = NULL`,
    )
    .run(agentId, keyHash, now, now + AGENT_SEND_KEY_GRACE_SEC)
  return raw
}

/**
 * Resolve a presented raw key to the agent it belongs to, or null. Null covers
 * every failure alike (not a string, too long, wrong shape, unknown, revoked,
 * expired grace window): the caller must not learn which.
 */
export function resolveAgentSendKey(raw: unknown): ResolvedAgentSendKey | null {
  if (typeof raw !== 'string') return null
  // Length cap BEFORE hashing and any DB access.
  if (raw.length === 0 || raw.length > AGENT_SEND_KEY_MAX_LEN) return null
  if (!raw.startsWith(KEY_PREFIX)) return null
  const hash = sha256hex(raw)
  const db = getDb()
  const now = nowSec()

  const cur = db
    .prepare('SELECT agent_id, last_used_at FROM agent_send_keys WHERE key_hash = ?')
    .get(hash) as { agent_id: string; last_used_at: number | null } | undefined
  if (cur) {
    if (cur.last_used_at === null || now - cur.last_used_at >= LAST_USED_DEBOUNCE_SEC) {
      db.prepare('UPDATE agent_send_keys SET last_used_at = ? WHERE agent_id = ?').run(now, cur.agent_id)
    }
    return { agentId: cur.agent_id, which: 'current' }
  }

  const prev = db
    .prepare('SELECT agent_id, prev_valid_until FROM agent_send_keys WHERE prev_hash = ?')
    .get(hash) as { agent_id: string; prev_valid_until: number | null } | undefined
  if (prev && prev.prev_valid_until !== null && now <= prev.prev_valid_until) {
    return { agentId: prev.agent_id, which: 'prev' }
  }
  return null
}

/** Revoke an agent's keys at once (current and prev). True if a row existed. */
export function revokeAgentSendKey(agentId: string): boolean {
  assertAgentId(agentId)
  return getDb().prepare('DELETE FROM agent_send_keys WHERE agent_id = ?').run(agentId).changes > 0
}
