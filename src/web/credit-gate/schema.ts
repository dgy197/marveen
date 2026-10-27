// Every SQLite table of the credit gate, applied in one call (card fec6335f,
// blueprint 3.3). Each node adds its own schema-*.ts module here; the
// dashboard calls this once at start, after the main database is open, and
// only when CREDIT_GATE_MODE is not `off`.

import type Database from 'better-sqlite3'
import { applyHeadlessRunsSchema } from './headless/schema-runs.js'
import { applyAuditSchema, applyKeyReadsSchema } from './schema-audit.js'
import { applyCalibrationSchema } from './schema-calibration.js'
import { applyGateSchema } from './schema-gate.js'
import { applyLedgerSchema } from './schema-ledger.js'

export function applyCreditGateSchema(db: Database.Database): void {
  applyLedgerSchema(db)
  applyGateSchema(db)
  applyCalibrationSchema(db)
  applyHeadlessRunsSchema(db)
  applyAuditSchema(db)
  applyKeyReadsSchema(db)
}
