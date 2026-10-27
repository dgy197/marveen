// Memory write gate, b1: origin marking (card 3e9f6c28, node B1-S).
//
// A row is a gate candidate only if it came in through POST /api/memories
// (the only writer that calls noteGateOrigin). Daily-log mirror rows, imports
// and migrations never get a marker, so the runner can never classify them.
// The marker lives in its own table, NOT in a `memories` column: a column would
// surface in every `SELECT * FROM memories` reader and change the GET output.
//
// The POST must stay byte- and latency-identical: noteGateOrigin() only
// schedules the write with setImmediate (the response is already out by then),
// is total (never throws, whatever the DB or .env does) and writes nothing
// unless the gate tables are verified AND the mode is not `off` AND at least
// one owner is configured.
import { getDb } from '../db.js'
import { logger } from '../logger.js'
import { gateTablesReady } from './schema.js'
import { gateActive, readGateEnv, type GateEnv } from './gate-env.js'

export interface OriginDeps {
  /** Defaults to the live DB handle. */
  getDb: () => import('better-sqlite3').Database
  readEnv: () => GateEnv
  tablesReady: () => boolean
  now: () => number
}

const defaultDeps: OriginDeps = {
  getDb,
  readEnv: () => readGateEnv(),
  tablesReady: gateTablesReady,
  now: () => Math.floor(Date.now() / 1000),
}

/**
 * Synchronous worker (exported for tests). Returns true when a marker row was
 * written. Throws on a DB error; noteGateOrigin() is the total wrapper.
 */
export function writeGateOrigin(memoryId: number, deps: OriginDeps = defaultDeps): boolean {
  if (!Number.isInteger(memoryId) || memoryId <= 0) return false
  if (!deps.tablesReady()) return false
  if (!gateActive(deps.readEnv())) return false
  deps.getDb()
    .prepare("INSERT OR IGNORE INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (?, 'api', ?)")
    .run(memoryId, deps.now())
  return true
}

/** Called once from the POST /api/memories handler, after saveAgentMemory(). Fire-and-forget, never throws. */
export function noteGateOrigin(memoryId: number, deps: OriginDeps = defaultDeps): void {
  try {
    setImmediate(() => {
      try {
        writeGateOrigin(memoryId, deps)
      } catch (err) {
        // Only the error class: SQLite messages can carry SQL text.
        try { logger.debug({ reason: (err as { code?: string } | null)?.code ?? 'error' }, 'memory-gate: origin marker not written') } catch { /* ignore */ }
      }
    })
  } catch { /* the save has already succeeded; marking is best effort */ }
}
