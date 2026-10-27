// Memory write gate, b1 (shadow mode): schema + migration (card 3e9f6c28, node B1-S).
//
// Additive DDL only: five new tables, no column is added to `memories` and no
// existing table is touched. The gate NEVER writes `memories`; every table here
// is written by the gate's own code, after the save, in its own statements.
// `memory_gate_state` (valid_to / superseded_by / last_confirmed_at) is NOT
// created in b1: it is an effect table and b1 produces no effect (b2 owns it).
//
// Failure contract (GB4): a failed migration must never stop the dashboard
// from booting. migrateMemoryGate() catches everything, records an error CLASS
// (never the message: SQLite messages can carry SQL text) and returns
// { ok: false }; gateTablesReady() then stays false, so every consumer
// (origin marking, the runner, the read-only routes) stays inert.
import type Database from 'better-sqlite3'
import { logger } from '../logger.js'

/** Table -> columns the migration must have produced (verified via PRAGMA table_info). */
const EXPECTED_COLUMNS: Record<string, string[]> = {
  memory_gate_origin: ['memory_id', 'origin', 'noted_at'],
  memory_gate_decisions: [
    'id', 'source_id', 'source_version', 'rubric', 'state', 'attempts', 'next_at', 'claimed_at',
    'op', 'target_id', 'target_version', 'target_owner', 'target_category', 'confidence',
    'model', 'prompt_bytes', 'reserved_usd_micro', 'reason', 'error_class', 'skip_reason',
    'apply_block', 'mode', 'would_apply', 'applied', 'applied_at', 'prev_state',
    'reverted_at', 'reverted_by', 'created_at', 'decided_at',
  ],
  memory_gate_candidates: ['decision_id', 'memory_id', 'label', 'version'],
  memory_gate_daily: ['day', 'calls', 'reserved_usd_micro', 'supersede_applied', 'contradict_applied', 'alerted'],
  memory_gate_kv: ['key', 'value'],
}

export const GATE_TABLES = Object.keys(EXPECTED_COLUMNS)

// `op` carries UNKNOWN on top of the six model operations: UNKNOWN is the
// gate's own marker for "no usable decision" (error, cap, pause, too old) and
// is never accepted from model output (the parser enforces that).
const DDL = `
  CREATE TABLE IF NOT EXISTS memory_gate_origin (
    memory_id INTEGER PRIMARY KEY,
    origin    TEXT NOT NULL CHECK(origin IN ('api')),
    noted_at  INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS memory_gate_decisions (
    id                 INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id          INTEGER NOT NULL,
    source_version     INTEGER NOT NULL,
    rubric             TEXT NOT NULL,
    state              TEXT NOT NULL DEFAULT 'pending'
                         CHECK(state IN ('pending','in_flight','decided','skipped','failed')),
    attempts           INTEGER NOT NULL DEFAULT 0,
    next_at            INTEGER,
    claimed_at         INTEGER,
    op                 TEXT CHECK(op IS NULL OR op IN ('CREATE','SUPERSEDE','REINFORCE','CONTRADICT','EXPIRE','MERGE','UNKNOWN')),
    target_id          INTEGER,
    target_version     INTEGER,
    target_owner       TEXT,
    target_category    TEXT,
    confidence         REAL,
    model              TEXT,
    prompt_bytes       INTEGER,
    reserved_usd_micro INTEGER,
    reason             TEXT CHECK(reason IS NULL OR length(reason) <= 200),
    error_class        TEXT,
    skip_reason        TEXT,
    apply_block        TEXT,
    mode               TEXT,
    would_apply        INTEGER NOT NULL DEFAULT 0,
    applied            INTEGER NOT NULL DEFAULT 0,
    applied_at         INTEGER,
    prev_state         TEXT,
    reverted_at        INTEGER,
    reverted_by        TEXT,
    created_at         INTEGER NOT NULL,
    decided_at         INTEGER,
    UNIQUE(source_id, source_version, rubric)
  );
  CREATE INDEX IF NOT EXISTS idx_memory_gate_decisions_state ON memory_gate_decisions(state, next_at);
  CREATE INDEX IF NOT EXISTS idx_memory_gate_decisions_target ON memory_gate_decisions(target_id);
  CREATE INDEX IF NOT EXISTS idx_memory_gate_decisions_source ON memory_gate_decisions(source_id);
  CREATE INDEX IF NOT EXISTS idx_memory_gate_decisions_decided ON memory_gate_decisions(decided_at);
  CREATE TABLE IF NOT EXISTS memory_gate_candidates (
    decision_id INTEGER NOT NULL,
    memory_id   INTEGER NOT NULL,
    label       TEXT NOT NULL,
    version     INTEGER,
    PRIMARY KEY (decision_id, memory_id)
  );
  CREATE INDEX IF NOT EXISTS idx_memory_gate_candidates_memory ON memory_gate_candidates(memory_id);
  CREATE TABLE IF NOT EXISTS memory_gate_daily (
    day                TEXT PRIMARY KEY,
    calls              INTEGER NOT NULL DEFAULT 0,
    reserved_usd_micro INTEGER NOT NULL DEFAULT 0,
    supersede_applied  INTEGER NOT NULL DEFAULT 0,
    contradict_applied INTEGER NOT NULL DEFAULT 0,
    alerted            INTEGER NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS memory_gate_kv (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
  );
`

export interface GateMigrationResult { ok: boolean; reason?: string }

// Module flags (GB4). Set by migrateMemoryGate(), read by every gate consumer.
let tablesReady = false
let migrationFailure: string | null = null

/** True only when the migration ran AND PRAGMA table_info confirmed every table and column. */
export function gateTablesReady(): boolean { return tablesReady }

/** Error class of the last failed migration, or null (also null before any run). */
export function gateMigrationFailure(): string | null { return migrationFailure }

function errorClass(err: unknown): string {
  const e = err as { code?: unknown; name?: unknown } | null
  const code = typeof e?.code === 'string' ? e.code : typeof e?.name === 'string' ? e.name : 'error'
  return code.replace(/[^A-Za-z0-9_]/g, '').slice(0, 40) || 'error'
}

/** PRAGMA-based proof that every gate table exists with every expected column. */
export function verifyGateTables(db: Database.Database): boolean {
  for (const [table, cols] of Object.entries(EXPECTED_COLUMNS)) {
    const have = new Set((db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>).map(r => r.name))
    if (have.size === 0) return false
    for (const c of cols) if (!have.has(c)) return false
  }
  return true
}

/**
 * Create the gate tables (idempotent). Never throws: any failure becomes
 * { ok: false, reason: <error class> } and leaves gateTablesReady() false.
 */
export function migrateMemoryGate(db: Database.Database): GateMigrationResult {
  tablesReady = false
  migrationFailure = null
  try {
    // One transaction: a failure part-way (SQLITE_BUSY, SQLITE_FULL) leaves no half-built gate schema.
    db.transaction(() => { db.exec(DDL) })()
    if (!verifyGateTables(db)) {
      migrationFailure = 'verify_failed'
    } else {
      tablesReady = true
    }
  } catch (err) {
    migrationFailure = errorClass(err)
  }
  if (migrationFailure) {
    try { logger.warn({ reason: migrationFailure }, 'memory-gate: migration failed, gate stays inert') } catch { /* logging must not matter */ }
    return { ok: false, reason: migrationFailure }
  }
  return { ok: true }
}

/** Test hook: forget the module flags. */
export function resetGateSchemaFlags(): void {
  tablesReady = false
  migrationFailure = null
}
