// The credit gate tables as they were BEFORE review round 1 (9bafd0ea): no
// max_calibration_id, no last_stop_file, no request_count. The migration test
// builds these and lets the current applyCreditGateSchema upgrade them.

import type Database from 'better-sqlite3'

export function applyPreRound1GateSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_reservations (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('headless', 'batch', 'canary')),
      ref TEXT,
      amount_micro INTEGER NOT NULL CHECK (amount_micro >= 0),
      expected_requests INTEGER CHECK (expected_requests IS NULL OR expected_requests > 0),
      status TEXT NOT NULL CHECK (status IN ('open', 'settled', 'released', 'unknown')),
      caller TEXT,
      model TEXT,
      calibration_id INTEGER,
      complete_requested_at INTEGER,
      overrun_at INTEGER,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL,
      reason TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_reservations_batch
      ON credit_reservations(ref) WHERE kind = 'batch' AND ref IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_credit_reservations_status ON credit_reservations(status);

    CREATE TABLE IF NOT EXISTS credit_gate_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      state TEXT NOT NULL CHECK (state IN ('CLOSED', 'OPEN', 'HOLD', 'INCIDENT')),
      reason TEXT NOT NULL,
      since INTEGER NOT NULL,
      calibration_id INTEGER,
      t_close_eff_micro INTEGER,
      lowcal_requested_at INTEGER,
      lowcal_fallback_at INTEGER,
      latch_cal_id INTEGER,
      latch_reason TEXT,
      stop_owner_json TEXT,
      guard_cursor_json TEXT,
      evaluated_at INTEGER,
      incident_event_id INTEGER,
      mode TEXT,
      version INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS credit_gate_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      at INTEGER NOT NULL,
      kind TEXT NOT NULL,
      from_state TEXT,
      to_state TEXT,
      reason TEXT,
      r_est_micro INTEGER,
      l_micro INTEGER,
      ledger_age_s INTEGER,
      open_res_micro INTEGER,
      calibration_id INTEGER,
      detail_json TEXT,
      notified_msg_id INTEGER,
      daily_logged INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX IF NOT EXISTS idx_credit_gate_events_at ON credit_gate_events(at);
  `)
}
