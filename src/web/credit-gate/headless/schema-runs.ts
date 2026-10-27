// The headless runner's table (card fec6335f, blueprint 3.3, node N4a; spec
// E-03): one row per `claude -p` run -- what was asked, under which config
// hash, which process, how it ended, and what it cost. Never a secret, never
// the prompt or the model's answer: result_json keeps only the usage and cost
// fields of the CLI's JSON result.
//
// Additive only, like every migration in db.ts: CREATE ... IF NOT EXISTS.
// Times are epoch MILLISECONDS. Columns beyond the blueprint's list:
// key_mode (how the key reached the child), deadline_at (the wall clock, so a
// re-attached run is still stopped on time), pgid, run_dir, cli_version
// (logged per run; not part of the config hash, Brainy 2026-10-16), reason
// (why a run was refused or how it was lost), residue_json (the RELATIVE
// names of run-dir files that carried key material; never their content),
// basis (how the ledger booked it) and errors_json (which cleanup steps
// failed, by name).

import type Database from 'better-sqlite3'

export const RUN_STATUSES = [
  'starting', 'spawning', 'running',
  'succeeded', 'failed', 'timeout', 'cancelled', 'killed', 'lost', 'refused', 'spawn_failed', 'secret_residue',
] as const
export type RunStatus = typeof RUN_STATUSES[number]
/** A row in one of these is not finished: the restart reconcile looks at it. */
export const OPEN_RUN_STATUSES: readonly RunStatus[] = ['starting', 'spawning', 'running']

export function applyHeadlessRunsSchema(db: Database.Database): void {
  const statuses = RUN_STATUSES.map((s) => `'${s}'`).join(', ')
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_headless_runs (
      id TEXT PRIMARY KEY,
      node_id TEXT NOT NULL,
      caller TEXT NOT NULL,
      model TEXT NOT NULL,
      effort TEXT NOT NULL,
      budget_micro INTEGER NOT NULL CHECK (budget_micro > 0),
      reservation_id TEXT NOT NULL,
      mode TEXT NOT NULL CHECK (mode IN ('normal', 'canary')),
      cwd TEXT NOT NULL,
      config_hash TEXT NOT NULL,
      key_mode TEXT NOT NULL CHECK (key_mode IN ('helper', 'env')),
      pid INTEGER,
      pid_start TEXT,
      pgid INTEGER,
      status TEXT NOT NULL CHECK (status IN (${statuses})),
      started_at INTEGER NOT NULL,
      deadline_at INTEGER,
      ended_at INTEGER,
      exit_code INTEGER,
      signal TEXT,
      result_json TEXT,
      est_micro INTEGER,
      cli_micro INTEGER,
      basis TEXT,
      cli_version TEXT,
      run_dir TEXT NOT NULL,
      reason TEXT,
      residue_json TEXT,
      errors_json TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_credit_headless_runs_status ON credit_headless_runs(status);
  `)
}
