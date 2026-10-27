// The calibration and canary tables of the credit gate (card fec6335f,
// blueprint 3.3, node N2c).
//
// Additive only, like every migration in db.ts: CREATE ... IF NOT EXISTS.
// Times are epoch MILLISECONDS.
//
// credit_calibrations: one row per CONSUMED credit_gate_calibration approval
// (owner-verified, bound, consumed once), whatever came of it. `outcome`:
//   accepted  the gate may use it (the newest accepted row is the calibration);
//   incident  D-02, a protected store decreased (the gate is in INCIDENT);
//   hold      B-05 mismatch, or nothing could be decided (the gate is on HOLD);
//   rejected  the reading's time is impossible (future, too old, not newer).
// readings_json is the approved canonical payload itself, content_hash its
// sha256 (checked again on every read). AUTOINCREMENT: an id is never reused,
// so a newer calibration always has a larger id (the gate's latches rely on it).
//
// credit_canaries: one row per consumed credit_gate_canary approval. At most
// one canary per before-calibration. status `consumed` until the next reading
// is processed; then success / incident / undecidable. run_id is the headless
// run the canary was consumed for (bound at the consume, mandatory); the
// window's ledger row of that run is what the canary measured. hash_taken_at:
// the runner took the hash (once).
//
// credit_calibration_state: one row (id = 1). owner_id is the owner's Telegram
// id, pinned at the first accepted reading; while the configured owner differs
// the gate is on HOLD (owner_changed, the event's id and time here) and only a
// new incident-clear of the PINNED owner naming that event re-pins it.
// min_captured_at_lb: after an incident-clear (or an owner re-pin) only a
// reading captured at or after this instant counts (MED-2).

import type Database from 'better-sqlite3'

export function applyCalibrationSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_calibrations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      approval_id TEXT NOT NULL UNIQUE,
      captured_at_lb INTEGER NOT NULL,
      readings_json TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      accepted_at INTEGER NOT NULL,
      outcome TEXT NOT NULL CHECK (outcome IN ('accepted', 'incident', 'hold', 'rejected')),
      reason TEXT,
      reconcile_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_credit_calibrations_outcome ON credit_calibrations(outcome, id);

    CREATE TABLE IF NOT EXISTS credit_canaries (
      approval_id TEXT PRIMARY KEY,
      config_hash TEXT NOT NULL,
      model TEXT NOT NULL,
      budget_micro INTEGER NOT NULL CHECK (budget_micro > 0),
      min_expected_micro INTEGER NOT NULL CHECK (min_expected_micro > 0),
      before_calibration_id INTEGER NOT NULL UNIQUE,
      run_id TEXT,
      status TEXT NOT NULL CHECK (status IN ('consumed', 'success', 'incident', 'undecidable')),
      after_calibration_id INTEGER,
      result_json TEXT,
      consumed_at INTEGER NOT NULL,
      evaluated_at INTEGER,
      hash_taken_at INTEGER
    );

    CREATE TABLE IF NOT EXISTS credit_calibration_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      owner_id TEXT,
      owner_pinned_at INTEGER,
      owner_changed_event_id INTEGER,
      owner_changed_at INTEGER,
      min_captured_at_lb INTEGER
    );
  `)
  // Added in the review round; only "duplicate column" is expected.
  for (const sql of ['ALTER TABLE credit_canaries ADD COLUMN hash_taken_at INTEGER']) {
    try {
      db.exec(sql)
    } catch (err) {
      if (!/duplicate column name/i.test(String((err as Error)?.message))) throw err
    }
  }
  db.exec('INSERT OR IGNORE INTO credit_calibration_state (id) VALUES (1)')
}
