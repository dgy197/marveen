// Memory write gate, b1: read-only status and decision-log routes (card 3e9f6c28, node B1-S).
//
//   GET /api/memories/gate/status
//   GET /api/memories/gate/decisions?limit=&before_id=&op=&state=
//   GET /api/memories/gate/decisions/:id
//
// Bearer-token gated by the global auth gate in web.ts (every /api/* path).
// The gate's free-text `reason` column is NEVER selected, in any of the three
// routes (Brainy 4217 Q3 / SR-6a-r6 B3): it is a masked classifier sentence about
// company memory text, kept only for the later human labelling run, and a
// deleted source row must not leave it readable through the API. Every query
// below therefore names its columns; none uses `SELECT *`.
import { lstatSync } from 'node:fs'
import { join } from 'node:path'
import { getDb } from '../../db.js'
import { STORE_DIR, APP_TZ } from '../../config.js'
import { json } from '../http-helpers.js'
import { gateTablesReady, gateMigrationFailure } from '../../memory-gate/schema.js'
import { readGateEnv } from '../../memory-gate/gate-env.js'
import type { RouteContext } from './types.js'

const STATES = ['pending', 'in_flight', 'decided', 'skipped', 'failed'] as const
const OPS = ['CREATE', 'SUPERSEDE', 'REINFORCE', 'CONTRADICT', 'EXPIRE', 'MERGE', 'UNKNOWN'] as const
const DEFAULT_LIMIT = 50
const MAX_LIMIT = 200

// No `reason`, by construction.
const DECISION_COLUMNS = `id, source_id, source_version, rubric, state, attempts, next_at, op,
  target_id, target_version, confidence, model, prompt_bytes, error_class, skip_reason,
  apply_block, mode, would_apply, created_at, decided_at`

interface DecisionRow {
  id: number; source_id: number; source_version: number; rubric: string; state: string
  attempts: number; next_at: number | null; op: string | null; target_id: number | null
  target_version: number | null; confidence: number | null; model: string | null
  prompt_bytes: number | null; error_class: string | null; skip_reason: string | null
  apply_block: string | null; mode: string | null; would_apply: number
  created_at: number; decided_at: number | null
}

function shape(r: DecisionRow) {
  return { ...r, would_apply: r.would_apply === 1 }
}

function disabledSwitch(): boolean {
  try {
    lstatSync(join(STORE_DIR, 'iras-kapu', 'DISABLE'))
    return true
  } catch {
    return false
  }
}

function budapestDay(): string {
  return new Intl.DateTimeFormat('sv-SE', { timeZone: APP_TZ, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date())
}

function statusPayload() {
  const env = readGateEnv()
  const base = {
    mode: { configured: env.configuredMode, effective: env.effectiveMode, invalid: env.invalidMode },
    owners: env.owners.owners.length, // the count only, never the names
    owner_config_error: env.owners.configError,
    main_agent_excluded: env.owners.mainAgentExcluded,
    disabled: disabledSwitch(),
    tables_ready: gateTablesReady(),
    migration_failed: gateMigrationFailure() !== null,
    migration_failure: gateMigrationFailure(),
  }
  if (!gateTablesReady()) return { ...base, rows: {}, origin_marked: 0, today: null, cursor: null, first_shadow_at: null, shadow_count: 0 }
  const db = getDb()
  const rows: Record<string, number> = {}
  for (const s of STATES) rows[s] = 0
  for (const r of db.prepare('SELECT state, COUNT(*) AS n FROM memory_gate_decisions GROUP BY state').all() as Array<{ state: string; n: number }>) {
    rows[r.state] = r.n
  }
  const origin = (db.prepare('SELECT COUNT(*) AS n FROM memory_gate_origin').get() as { n: number }).n
  const day = budapestDay()
  const daily = db.prepare('SELECT calls, reserved_usd_micro FROM memory_gate_daily WHERE day = ?').get(day) as
    { calls: number; reserved_usd_micro: number } | undefined
  const kv = new Map((db.prepare("SELECT key, value FROM memory_gate_kv WHERE key IN ('cursor','first_shadow_at','shadow_count')").all() as Array<{ key: string; value: string }>)
    .map(r => [r.key, r.value]))
  const num = (k: string): number | null => { const v = kv.get(k); const n = v === undefined ? NaN : Number(v); return Number.isFinite(n) ? n : null }
  return {
    ...base,
    rows,
    origin_marked: origin,
    today: { day, calls: daily?.calls ?? 0, reserved_usd: (daily?.reserved_usd_micro ?? 0) / 1_000_000 },
    cursor: num('cursor'),
    first_shadow_at: num('first_shadow_at'),
    shadow_count: num('shadow_count') ?? 0,
  }
}

export async function tryHandleMemoryGate(ctx: RouteContext): Promise<boolean> {
  const { res, path, method, url } = ctx
  if (path !== '/api/memories/gate/status' && path !== '/api/memories/gate/decisions' && !/^\/api\/memories\/gate\/decisions\/[^/]+$/.test(path)) {
    return false
  }
  if (method !== 'GET') { json(res, { error: 'Method not allowed' }, 405); return true }

  if (path === '/api/memories/gate/status') {
    json(res, statusPayload())
    return true
  }

  if (!gateTablesReady()) { json(res, { error: 'Memory gate tables are not available' }, 503); return true }
  const db = getDb()

  if (path === '/api/memories/gate/decisions') {
    const q = url.searchParams
    const rawLimit = q.get('limit')
    let limit = DEFAULT_LIMIT
    if (rawLimit !== null) {
      if (!/^\d{1,6}$/.test(rawLimit)) { json(res, { error: 'Invalid limit' }, 400); return true }
      limit = Math.min(Math.max(parseInt(rawLimit, 10), 1), MAX_LIMIT)
    }
    const where: string[] = []
    const args: Array<string | number> = []
    const rawBefore = q.get('before_id')
    if (rawBefore !== null) {
      if (!/^\d{1,12}$/.test(rawBefore)) { json(res, { error: 'Invalid before_id' }, 400); return true }
      where.push('id < ?'); args.push(parseInt(rawBefore, 10))
    }
    const op = q.get('op')
    if (op !== null) {
      if (!(OPS as readonly string[]).includes(op)) { json(res, { error: 'Invalid op' }, 400); return true }
      where.push('op = ?'); args.push(op)
    }
    const state = q.get('state')
    if (state !== null) {
      if (!(STATES as readonly string[]).includes(state)) { json(res, { error: 'Invalid state' }, 400); return true }
      where.push('state = ?'); args.push(state)
    }
    const sql = `SELECT ${DECISION_COLUMNS} FROM memory_gate_decisions${where.length ? ' WHERE ' + where.join(' AND ') : ''} ORDER BY id DESC LIMIT ?`
    const rows = db.prepare(sql).all(...args, limit) as DecisionRow[]
    json(res, { decisions: rows.map(shape), limit })
    return true
  }

  const idRaw = path.slice('/api/memories/gate/decisions/'.length)
  if (!/^\d{1,12}$/.test(idRaw)) { json(res, { error: 'Not found' }, 404); return true }
  const row = db.prepare(`SELECT ${DECISION_COLUMNS} FROM memory_gate_decisions WHERE id = ?`).get(parseInt(idRaw, 10)) as DecisionRow | undefined
  if (!row) { json(res, { error: 'Not found' }, 404); return true }
  const candidates = db.prepare('SELECT label, memory_id, version FROM memory_gate_candidates WHERE decision_id = ? ORDER BY label').all(row.id)
  json(res, { ...shape(row), candidates })
  return true
}
