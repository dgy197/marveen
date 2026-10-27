// The audit tables of the credit gate (card fec6335f, node N5, blueprint 3.3).
//
// Additive only, like every migration in db.ts. Times are epoch MILLISECONDS.
//
// credit_gate_events (created by schema-gate.ts) gets the delivery state of its
// outbox role: notify_state (NULL = not tried yet; sending | retry | sent |
// failed | skipped | coalesced), notify_attempts, notify_first_at, notify_last_at.
// notified_msg_id and daily_logged were there from the start.
//
// credit_key_reads (G-03): reads of the shared batch key from the Vault, per
// Budapest day and principal NAME. A counter, never a value.

import type Database from 'better-sqlite3'

/** The delivery columns of credit_gate_events (additive; a table from before N5 gets them). */
export function applyAuditSchema(db: Database.Database): void {
  for (const sql of [
    'ALTER TABLE credit_gate_events ADD COLUMN notify_state TEXT',
    'ALTER TABLE credit_gate_events ADD COLUMN notify_attempts INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE credit_gate_events ADD COLUMN notify_first_at INTEGER',
    'ALTER TABLE credit_gate_events ADD COLUMN notify_last_at INTEGER',
  ]) {
    try {
      db.exec(sql)
    } catch (err) {
      if (!/duplicate column name/i.test(String((err as Error)?.message))) throw err
    }
  }
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_credit_gate_events_notify ON credit_gate_events(notify_state);
    CREATE INDEX IF NOT EXISTS idx_credit_gate_events_kind ON credit_gate_events(kind);
  `)
}

export function applyKeyReadsSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_key_reads (
      day TEXT NOT NULL,
      principal TEXT NOT NULL,
      count INTEGER NOT NULL DEFAULT 0,
      PRIMARY KEY (day, principal)
    );
  `)
}
