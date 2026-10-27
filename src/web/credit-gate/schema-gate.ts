// The credit gate's own tables (card fec6335f, blueprint 3.3, node N2a).
//
// Additive only, like every migration in db.ts: CREATE ... IF NOT EXISTS.
// Times are epoch MILLISECONDS throughout (the ledger's `ts` column is the
// only one in seconds).
//
// credit_reservations: one row per admitted job. Money the gate has promised
// but the ledger does not show yet. Columns beyond the blueprint's list:
// request_count (a batch's reserved request count: bind must name exactly
// this many), caller and model (who asked, for the audit), calibration_id (under which
// calibration it was admitted), complete_requested_at (the batch client said
// "done"; the row settles once the ledger has every request) and overrun_at
// (the ledger showed more than the reservation once: HOLD, reported once).
// A batch is bound to at most one reservation (the partial unique index).
//
// credit_gate_state: exactly one row (id = 1). latch_cal_id + latch_reason
// generalise the blueprint's threshold_closed_cal_id: every closure that only
// a NEWER calibration may lift (threshold C-05, disarm and human STOP A-05,
// 401, HOLD, a cleared INCIDENT) stores the calibration id current at that
// moment; 0 = there was none. max_calibration_id is the largest calibration id
// ever seen (never decreases; every latch binds to it, BE-3), last_stop_file
// the STOP path of the last valid config (a closure caused by an invalid
// config still puts the STOP down). evaluated_at is the last complete evaluation
// (a reservation needs one at most maxLedgerAgeS old); guard_cursor_json is
// where the PR-A guard-event file was read to; incident_event_id is the event
// of the newest open INCIDENT cause (an incident-clear approval names it), and
// incident_open_json lists every open cause with its own event (N2c MED-1).
// reported_state + reported_reason are what the last reported change said (the
// last `transition` row, or in INCIDENT its newest cause row): a change is
// reported against them, never against `reason`, which a signal may have
// written (B14). NULL on a row from before them: the row's own state and reason.
// canary_res_id + canary_opened_at: the canary window (K-01, N7B1). Set when a
// canary reservation is admitted, cleared only by the close step -- the
// recording of the after-reading (closeCanary). While it is set the gate's
// STOP stays down and every other reservation is refused, also after the
// canary's run was settled, so the canary's cost is the only one between its
// two Console readings. In the database, so a restart keeps it.
// stop_place_failed_at (CW1): the gate could not put its STOP down when it had
// to (or, after a canary's admission, found none down) at this moment, and has
// not managed to since. While it is set the gate holds (`stop_place_failed`, a
// HOLD condition); the episode is reported once, when it starts. Cleared when
// the gate's STOP is down again (placed, or found in place).
// stop_release_failed_at (CS1): the gate could not take its own STOP away when
// it was to open (or, OPEN, when a canary window closed) at this moment, and
// has not managed to since. While it lasts the gate stays CLOSED
// (`stop_release_failed`): every tick that would open it tries the release
// first and writes nothing while it still fails; the episode is logged once.
// Cleared by a release that goes through, or by an opening (the STOP is gone).
//
// credit_gate_events: the audit outbox. N5 delivers it (notified_msg_id,
// daily_logged); detail_json never carries a value, only names and reasons.

import type Database from 'better-sqlite3'

export function applyGateSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_reservations (
      id TEXT PRIMARY KEY,
      kind TEXT NOT NULL CHECK (kind IN ('headless', 'batch', 'canary')),
      ref TEXT,
      amount_micro INTEGER NOT NULL CHECK (amount_micro >= 0),
      request_count INTEGER CHECK (request_count IS NULL OR request_count > 0),
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
      max_calibration_id INTEGER NOT NULL DEFAULT 0,
      t_close_eff_micro INTEGER,
      lowcal_requested_at INTEGER,
      lowcal_fallback_at INTEGER,
      latch_cal_id INTEGER,
      latch_reason TEXT,
      stop_owner_json TEXT,
      last_stop_file TEXT,
      guard_cursor_json TEXT,
      evaluated_at INTEGER,
      incident_event_id INTEGER,
      incident_open_json TEXT,
      mode TEXT,
      reported_state TEXT,
      reported_reason TEXT,
      canary_res_id TEXT,
      canary_opened_at INTEGER,
      stop_place_failed_at INTEGER,
      stop_release_failed_at INTEGER,
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
  // Columns added after the first version of these tables (review round 1):
  // additive, like db.ts -- an existing table gets them, a new one has them.
  // Only "duplicate column" is expected and swallowed; any other error goes
  // up, and the gate does not start (start_failed) rather than run on a half
  // upgraded table.
  let canaryWindowAdded = false
  for (const sql of [
    'ALTER TABLE credit_reservations ADD COLUMN request_count INTEGER CHECK (request_count IS NULL OR request_count > 0)',
    'ALTER TABLE credit_gate_state ADD COLUMN max_calibration_id INTEGER NOT NULL DEFAULT 0',
    'ALTER TABLE credit_gate_state ADD COLUMN last_stop_file TEXT',
    'ALTER TABLE credit_gate_state ADD COLUMN incident_open_json TEXT',
    'ALTER TABLE credit_gate_state ADD COLUMN reported_state TEXT',
    'ALTER TABLE credit_gate_state ADD COLUMN reported_reason TEXT',
    'ALTER TABLE credit_gate_state ADD COLUMN canary_res_id TEXT',
    'ALTER TABLE credit_gate_state ADD COLUMN canary_opened_at INTEGER',
    'ALTER TABLE credit_gate_state ADD COLUMN stop_place_failed_at INTEGER',
    'ALTER TABLE credit_gate_state ADD COLUMN stop_release_failed_at INTEGER',
  ]) {
    try {
      db.exec(sql)
      if (sql.includes('ADD COLUMN canary_res_id')) canaryWindowAdded = true
    } catch (err) {
      if (!/duplicate column name/i.test(String((err as Error)?.message))) throw err
    }
  }
  // N7B1: a table from before the canary window gets one for a canary that is
  // running right now (once, when the column comes in): its STOP then stays
  // down until its after-reading, not only until its settle.
  if (canaryWindowAdded) {
    db.exec(`UPDATE credit_gate_state SET
        canary_res_id = (SELECT id FROM credit_reservations WHERE kind = 'canary' AND status = 'open' ORDER BY created_at DESC, id DESC LIMIT 1),
        canary_opened_at = (SELECT created_at FROM credit_reservations WHERE kind = 'canary' AND status = 'open' ORDER BY created_at DESC, id DESC LIMIT 1)
      WHERE id = 1 AND canary_res_id IS NULL`)
  }
  // A row from before max_calibration_id (it came in as 0) keeps the latch
  // base it already had: its calibration and its latch (BE-3 round 2). The
  // max never decreases, so running this on every start is harmless.
  db.exec(`UPDATE credit_gate_state
    SET max_calibration_id = MAX(max_calibration_id, COALESCE(calibration_id, 0), COALESCE(latch_cal_id, 0))`)
}
