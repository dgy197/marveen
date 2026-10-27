// Reads of the shared batch key from the Vault, counted (card fec6335f, node N5, spec G-03).
//
// The key is the Team credit's door: anyone with the dashboard's Bearer token
// can read it through GET /api/vault/:id, and the Vault's own ACL only logs
// (VAULTSZELES826 F0). So the gate keeps a COUNTER of those reads per Budapest
// day and per principal -- the principal's name only, never a value -- and the
// notifier sums a finished day up into the main agent's daily log. A reader
// nobody expects shows up there, and the status shows today's count.
//
// The count is best effort and never in the Vault's way: whatever fails here
// is logged (without any value) and swallowed. With CREDIT_GATE_MODE off (the
// default) nothing is written -- not even a table -- so the route behaves
// exactly as before.

import { join } from 'node:path'
import type Database from 'better-sqlite3'
import { APP_TZ } from '../../config.js'
import { logger } from '../../logger.js'
import { principalOf } from '../vault-acl.js'
import type { RouteContext } from '../routes/types.js'
import { CONFIG_FILE, CREDIT_GATE_DIR, loadCreditGateConfigFile } from './config.js'
import type { CreditGateRuntime } from './runtime.js'

/** The key id when the config cannot be read: the count must not depend on a healthy config. */
export const DEFAULT_KEY_ID = 'ANTHROPIC_API_KEY_BATCH'

const PRINCIPAL_RE = /^[A-Za-z0-9_.:@-]{1,64}$/

/** The calendar day in the install's time zone (Europe/Budapest), YYYY-MM-DD. */
export function budapestDay(ms: number): string {
  return new Date(ms).toLocaleDateString('en-CA', { timeZone: APP_TZ })
}

export function recordKeyRead(db: Database.Database, principal: string, nowMs: number): void {
  const name = PRINCIPAL_RE.test(principal) ? principal : '?'
  db.prepare(`INSERT INTO credit_key_reads (day, principal, count) VALUES (?, ?, 1)
    ON CONFLICT(day, principal) DO UPDATE SET count = count + 1`).run(budapestDay(nowMs), name)
}

/**
 * Called by GET /api/vault/:id after a value was found. Counts only the key
 * the config names (vaultKeyId; the default id if the config is unusable), and
 * only when the gate runs in shadow or enforce mode on a database.
 */
export function noteCreditKeyRead(
  id: string,
  auth: RouteContext['auth'],
  rt: Pick<CreditGateRuntime, 'mode' | 'gate' | 'storeDir' | 'db'>,
  nowMs: number = Date.now(),
): void {
  try {
    if (rt.mode.mode === 'off' || rt.gate === null || rt.db === null) return
    const cfg = loadCreditGateConfigFile(join(rt.storeDir, CREDIT_GATE_DIR, CONFIG_FILE))
    const keyId = cfg.ok ? cfg.config.vaultKeyId : DEFAULT_KEY_ID
    if (id !== keyId) return
    recordKeyRead(rt.db, principalOf(auth).principal, nowMs)
  } catch (err) {
    logger.warn({ errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: a Vault key read could not be counted')
  }
}

export interface KeyReadsView {
  readonly day: string
  readonly total: number
  readonly by_principal: Record<string, number>
}

/** One day's reads; zeros for no database or no table. */
export function keyReadsView(db: Database.Database | null, day: string): KeyReadsView {
  const view: KeyReadsView = { day, total: 0, by_principal: {} }
  if (db === null) return view
  try {
    const rows = db.prepare('SELECT principal, count FROM credit_key_reads WHERE day = ? ORDER BY principal').all(day) as Array<{ principal: string; count: number }>
    const by: Record<string, number> = {}
    let total = 0
    for (const r of rows) {
      by[r.principal] = r.count
      total += r.count
    }
    return { day, total, by_principal: by }
  } catch {
    return view
  }
}

/**
 * Every finished day (before today) with reads and no summary yet becomes one
 * `key_reads_daily` event; the notifier writes it to the daily log. Idempotent.
 */
export function summariseKeyReads(db: Database.Database, nowMs: number): number {
  const today = budapestDay(nowMs)
  let days: Array<{ day: string }>
  try {
    days = db.prepare(`SELECT DISTINCT r.day FROM credit_key_reads r
        WHERE r.day < ? AND NOT EXISTS (SELECT 1 FROM credit_gate_events e
                                         WHERE e.kind = 'key_reads_daily' AND json_extract(e.detail_json, '$.day') = r.day)
        ORDER BY r.day LIMIT 31`).all(today) as typeof days
  } catch (err) {
    if (/no such table/i.test(String((err as Error)?.message))) return 0
    throw err
  }
  const ins = db.prepare(`INSERT INTO credit_gate_events (at, kind, reason, detail_json) VALUES (?, 'key_reads_daily', 'daily_summary', ?)`)
  let n = 0
  db.transaction(() => {
    for (const d of days) {
      const v = keyReadsView(db, d.day)
      ins.run(nowMs, JSON.stringify({ day: v.day, total: v.total, by_principal: v.by_principal }))
      n++
    }
  })()
  return n
}
