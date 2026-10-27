// The credit gate's ledger tables (card fec6335f, blueprint 3.3, node N1b).
//
// Additive only, like every migration in db.ts: CREATE ... IF NOT EXISTS, so
// running it on every start is a no-op once the tables exist.
//
// credit_ledger_entries: one row per accounted request (a usage.jsonl line) or
// per headless run. Two UNIQUE guards keep a request from counting twice:
//  - dedupe_key: for a usage line source + dev + ino + offset + sha256 of the
//    line, for a headless run "headless:<run_id>";
//  - (batch_id, custom_id) for batch rows: the same batch result appearing
//    twice (in the log or in a second source) is one request.
// est_micro NULL = the row could not be priced (A-02 closes the gate);
// cli_micro is what the CLI reported for a headless run. L(t) takes the larger
// of the two per row (blueprint 3.4). Times: `ts` is the writer's epoch
// SECONDS (the request's own time); ingested_at and the cursor's *_at columns
// are epoch MILLISECONDS (the ledger's bookkeeping).
//
// credit_ledger_cursors: one row per configured source. dev and ino are TEXT
// (decimal) because a 64-bit inode does not always fit a JS number. Columns
// beyond the blueprint's list: reason (why a source is broken), partial_since
// (when the current half-written last line was first seen, for the 120 s
// rule) and checked_at (the last time the source was read to its end; the
// ledger's age is measured from it).

import type Database from 'better-sqlite3'

export function applyLedgerSchema(db: Database.Database): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS credit_ledger_entries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source TEXT NOT NULL,
      dedupe_key TEXT NOT NULL UNIQUE,
      ts INTEGER NOT NULL,
      model TEXT NOT NULL,
      input_tokens INTEGER NOT NULL CHECK (input_tokens >= 0),
      output_tokens INTEGER NOT NULL CHECK (output_tokens >= 0),
      cache_write_tokens INTEGER NOT NULL CHECK (cache_write_tokens >= 0),
      cache_read_tokens INTEGER NOT NULL CHECK (cache_read_tokens >= 0),
      batch_id TEXT,
      custom_id TEXT,
      run_id TEXT,
      est_micro INTEGER CHECK (est_micro IS NULL OR est_micro >= 0),
      cli_micro INTEGER CHECK (cli_micro IS NULL OR cli_micro >= 0),
      priced_with TEXT,
      basis TEXT NOT NULL CHECK (basis IN ('usage', 'headless_json', 'headless_transcript', 'headless_reservation')),
      ingested_at INTEGER NOT NULL,
      CHECK ((batch_id IS NULL) = (custom_id IS NULL))
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_credit_ledger_batch_request
      ON credit_ledger_entries(batch_id, custom_id) WHERE batch_id IS NOT NULL;
    CREATE INDEX IF NOT EXISTS idx_credit_ledger_ts ON credit_ledger_entries(ts);

    CREATE TABLE IF NOT EXISTS credit_ledger_cursors (
      source TEXT PRIMARY KEY,
      dev TEXT,
      ino TEXT,
      offset INTEGER NOT NULL DEFAULT 0 CHECK (offset >= 0),
      tail_sha256 TEXT,
      status TEXT NOT NULL CHECK (status IN ('ok', 'partial', 'broken')),
      reason TEXT,
      partial_since INTEGER,
      checked_at INTEGER,
      updated_at INTEGER NOT NULL
    );
  `)
}
