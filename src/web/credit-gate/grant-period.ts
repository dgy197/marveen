// The grant_model calibration's stored side (card 40e03382, node N2): the
// credit_grant_periods rows, the check of the chain they belong to, and the
// source the gate reads them through.
//
// One owner button (credit_gate_enforce) starts a CHAIN: the transaction that
// consumes it writes the chain's first period row; the tick then adds one row
// per period change, all naming the same approval (calibration.ts). A row is
// the gate's calibration only while ALL of this holds, on every read:
//   - its content_hash is the sha256 of its row_json, and the record in it is
//     exactly the columns of the row (id, approval, hash, lb, expiry, remaining);
//   - the approval it names is a credit_gate_enforce, owner-verified, bound to
//     its canonical payload (content_hash), consumed by the gate at the very
//     second the record says, and its payload names the row's grant_model_hash;
//   - the record is what the config derives from its own creation time (the same
//     period, the same grant), and remaining never exceeds the grant;
//   - the row's grant_model_hash is the hash of the config as it is NOW, the
//     reconstructed file included (a changed config needs a new button);
//   - the chain's enforce time is not before the owner's last incident-clear or
//     owner re-pin (credit_calibration_state.min_captured_at_lb, the MED-2 floor
//     projected onto the enforce time): after an INCIDENT only a NEW enforce
//     approval opens (spec A9).
// A row or approval that does not verify THROWS (the gate reads that as
// calibration_invalid and stays closed); a chain that verifies but is not in
// force (changed config, before the floor, no row yet) is simply no calibration.
//
// Ids: the gate's latch lifts on a strictly larger calibration id, and it only
// ever sees the id the source hands over. credit_grant_periods is therefore not
// autoincremented: nextCalibrationId gives max(everything issued so far) + 1,
// in the transaction that inserts the row.

import { createHash } from 'node:crypto'
import type Database from 'better-sqlite3'
import { canonicalJson } from '../../approval-envelope.js'
import { getApproval, isOwnerVerified } from '../../db.js'
import { creditGateBinding, type EnforcePayload } from './approval-payload.js'
import type { ConfigLoadResult, CreditGateConfig } from './config.js'
import type { Calibration, CalibrationSource } from './gate.js'
import { currentPeriod, grantModelHash, readReconstructed, type GrantPeriod } from './grant-model.js'
import type { UsageRow } from './ledger-usage-jsonl.js'
import type { Micro } from './types.js'

/** The gate's consumer name on an approval (calibration.ts CONSUMER). */
export const GRANT_CONSUMER = 'credit-gate'

const SHA256_HEX_RE = /^[0-9a-f]{64}$/
const RECORD_KEYS = [
  'v', 'kind', 'id', 'approval_id', 'grant_model_hash', 'enforced_at_ms', 'lb_ms', 'expires_ms', 'original_micro', 'remaining_micro', 'key',
] as const

export interface GrantPeriodRow {
  readonly id: number
  readonly approval_id: string
  readonly grant_model_hash: string
  readonly lb: number
  readonly expires: number
  readonly remaining_micro: number
  readonly row_json: string
  readonly content_hash: string
  readonly created_at: number
}

/** What row_json carries (canonical). */
export interface GrantPeriodRecord {
  readonly v: 1
  readonly kind: 'grant_period'
  readonly id: number
  readonly approval_id: string
  readonly grant_model_hash: string
  /** When the chain's enforce approval was consumed (ms): the same for every row of the chain. */
  readonly enforced_at_ms: number
  readonly lb_ms: number
  readonly expires_ms: number
  readonly original_micro: number
  readonly remaining_micro: number
  readonly key: string
}

const COLUMNS = 'id, approval_id, grant_model_hash, lb, expires, remaining_micro, row_json, content_hash, created_at'

function sha256(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function stamp(ms: number): string {
  return new Date(ms).toISOString().replace(/\.[0-9]{3}Z$/, 'Z')
}

// ------------------------------------------------------------------ inputs

export type GrantInputs =
  | { readonly ok: true; readonly hash: string; readonly rows: readonly UsageRow[] }
  | { readonly ok: false; readonly why: string; readonly detail: string }

/**
 * The measured inputs of the grant model: the reconstructed file read and
 * pinned to its sha256 (A6), and grantModelHash of the config with that
 * measured sha256. Any fault in the file is `ok: false` -- never a partial answer.
 */
export function measureGrantInputs(cfg: CreditGateConfig): GrantInputs {
  const gm = cfg.grantModel
  if (gm === null) return { ok: false, why: 'no_grant_model', detail: 'the config has no grantModel' }
  const rc = gm.reconstructed
  if (rc === null) return { ok: true, hash: grantModelHash(cfg, null), rows: [] }
  const r = readReconstructed(rc.path, rc.sha256)
  if (!r.ok) return { ok: false, why: `reconstructed_${r.reason}`, detail: r.detail }
  return { ok: true, hash: grantModelHash(cfg, r.sha256), rows: r.rows }
}

// ------------------------------------------------------------------ rows

/**
 * One above every calibration id ever issued: both tables, the autoincrement
 * sequence of credit_calibrations (a deleted row's id is not reused) and what
 * the gate's state remembers. Call it inside the transaction that inserts.
 */
export function nextCalibrationId(db: Database.Database): number {
  const one = (sql: string): number => {
    const r = db.prepare(sql).get() as { n: number | null } | undefined
    return typeof r?.n === 'number' ? r.n : 0
  }
  const seq = db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'").get() === undefined
    ? 0
    : one("SELECT seq AS n FROM sqlite_sequence WHERE name = 'credit_calibrations'")
  const state = one('SELECT MAX(COALESCE(max_calibration_id, 0), COALESCE(calibration_id, 0), COALESCE(latch_cal_id, 0)) AS n FROM credit_gate_state WHERE id = 1')
  return 1 + Math.max(
    one('SELECT MAX(id) AS n FROM credit_calibrations'),
    one('SELECT MAX(id) AS n FROM credit_grant_periods'),
    seq,
    state,
  )
}

export function newestPeriod(db: Database.Database): GrantPeriodRow | null {
  return (db.prepare(`SELECT ${COLUMNS} FROM credit_grant_periods ORDER BY id DESC LIMIT 1`).get() as GrantPeriodRow | undefined) ?? null
}

export interface NewPeriod {
  readonly approvalId: string
  readonly hash: string
  readonly enforcedAtMs: number
  readonly period: GrantPeriod
  readonly original: Micro
  readonly remaining: Micro
  readonly nowMs: number
}

/** Insert the next period row of a chain (inside the caller's transaction). Returns its id. */
export function insertPeriod(db: Database.Database, p: NewPeriod): number {
  const id = nextCalibrationId(db)
  const rec: GrantPeriodRecord = {
    v: 1,
    kind: 'grant_period',
    id,
    approval_id: p.approvalId,
    grant_model_hash: p.hash,
    enforced_at_ms: p.enforcedAtMs,
    lb_ms: p.period.lbMs,
    expires_ms: p.period.expiresMs,
    original_micro: p.original,
    remaining_micro: p.remaining,
    key: p.period.key,
  }
  const text = canonicalJson(rec)
  if (text === null) throw new Error('credit gate: the grant period record is not canonical')
  db.prepare(`INSERT INTO credit_grant_periods
      (id, approval_id, grant_model_hash, lb, expires, remaining_micro, row_json, content_hash, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(id, p.approvalId, p.hash, p.period.lbMs, p.period.expiresMs, p.remaining, text, sha256(text), p.nowMs)
  // R1 B3: the Console's autoincrement continues above this id, so a later reading (the switch back) is above every period row.
  if (db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'sqlite_sequence'").get() !== undefined) {
    const seq = db.prepare("SELECT seq FROM sqlite_sequence WHERE name = 'credit_calibrations'").get() as { seq: number } | undefined
    if (seq === undefined) db.prepare("INSERT INTO sqlite_sequence (name, seq) VALUES ('credit_calibrations', ?)").run(id)
    else if (seq.seq < id) db.prepare("UPDATE sqlite_sequence SET seq = MAX(seq, ?) WHERE name = 'credit_calibrations'").run(id)
  }
  return id
}

// ------------------------------------------------------------------ verification

export type ChainRead =
  | { readonly kind: 'none' }
  | { readonly kind: 'stale'; readonly why: 'config_hash' | 'before_floor'; readonly row: GrantPeriodRow }
  | { readonly kind: 'ok'; readonly row: GrantPeriodRow; readonly record: GrantPeriodRecord }

function isInt(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v)
}

function parseRecord(row: GrantPeriodRow): GrantPeriodRecord {
  if (sha256(row.row_json) !== row.content_hash) throw new Error('credit gate: a grant period row does not match its hash')
  let o: unknown
  try {
    o = JSON.parse(row.row_json)
  } catch {
    throw new Error('credit gate: a grant period row is not JSON')
  }
  if (typeof o !== 'object' || o === null || Array.isArray(o)) throw new Error('credit gate: a grant period record is not an object')
  const r = o as Record<string, unknown>
  const keys = Object.keys(r)
  if (keys.length !== RECORD_KEYS.length || !RECORD_KEYS.every((k) => Object.hasOwn(r, k))) throw new Error('credit gate: a grant period record has other keys')
  if (canonicalJson(r) !== row.row_json) throw new Error('credit gate: a grant period record is not canonical')
  if (r['v'] !== 1 || r['kind'] !== 'grant_period') throw new Error('credit gate: a grant period record is of another kind')
  if (!isInt(r['id']) || !isInt(r['enforced_at_ms']) || !isInt(r['lb_ms']) || !isInt(r['expires_ms'])
    || !isInt(r['original_micro']) || !isInt(r['remaining_micro'])
    || typeof r['approval_id'] !== 'string' || typeof r['grant_model_hash'] !== 'string' || typeof r['key'] !== 'string') {
    throw new Error('credit gate: a grant period record has a bad field')
  }
  const rec = r as unknown as GrantPeriodRecord
  if (rec.id !== row.id || rec.approval_id !== row.approval_id || rec.grant_model_hash !== row.grant_model_hash
    || rec.lb_ms !== row.lb || rec.expires_ms !== row.expires || rec.remaining_micro !== row.remaining_micro) {
    throw new Error('credit gate: a grant period record differs from its row')
  }
  if (!SHA256_HEX_RE.test(rec.grant_model_hash)) throw new Error('credit gate: a grant period row has a bad grant model hash')
  return rec
}

interface CalStateRow {
  owner_id: string | null
  min_captured_at_lb: number | null
}

function calStateRow(db: Database.Database): CalStateRow {
  return (db.prepare('SELECT owner_id, min_captured_at_lb FROM credit_calibration_state WHERE id = 1').get() as CalStateRow | undefined)
    ?? { owner_id: null, min_captured_at_lb: null }
}

/** The approval a record names, re-checked as the gate's own consume left it. Throws when it does not verify. */
function checkApproval(rec: GrantPeriodRecord, ownerId: string | null): void {
  const a = getApproval(rec.approval_id)
  const bad = (why: string): never => {
    throw new Error(`credit gate: the enforce approval of a grant period does not verify (${why})`)
  }
  if (!a) return bad('missing')
  if (a.category !== 'credit_gate_enforce') return bad('category')
  if (a.status !== 'approved') return bad('status')
  if (a.consumed_at == null || a.consumed_by !== GRANT_CONSUMER || a.consumed_at !== Math.floor(rec.enforced_at_ms / 1000)) return bad('consume')
  const b = creditGateBinding(a)
  if (!b.bound || b.payload.kind !== 'credit_gate_enforce') return bad('binding')
  if ((b.payload as EnforcePayload).grant_model_hash !== rec.grant_model_hash || (b.payload as EnforcePayload).mode !== 'enforce') return bad('hash')
  if (!(ownerId === null ? isOwnerVerified(a.id) : isOwnerVerified(a.id, ownerId))) return bad('owner')
}

/**
 * The newest period row and whether it is in force. Throws when the row or its
 * approval does not verify (A10); `stale` when it verifies but is not the
 * calibration of this config now.
 */
export function readChain(db: Database.Database, cfg: CreditGateConfig, currentHash: string): ChainRead {
  const row = newestPeriod(db)
  if (row === null) return { kind: 'none' }
  const rec = parseRecord(row)
  const cs = calStateRow(db)
  checkApproval(rec, cs.owner_id)
  if (rec.grant_model_hash !== currentHash) return { kind: 'stale', why: 'config_hash', row }
  if (cs.min_captured_at_lb !== null && rec.enforced_at_ms < cs.min_captured_at_lb) return { kind: 'stale', why: 'before_floor', row }
  // Same hash = same grantModel: the record must be what that model derives from the row's own time.
  const gm = cfg.grantModel
  if (gm === null) throw new Error('credit gate: the grant period has no grantModel to be checked against')
  const p = currentPeriod(gm, row.created_at)
  if (p.key !== rec.key || p.lbMs !== rec.lb_ms || p.expiresMs !== rec.expires_ms) throw new Error('credit gate: a grant period is not the period of its time')
  if (rec.original_micro !== gm.grantUsd || rec.remaining_micro > rec.original_micro) throw new Error('credit gate: a grant period holds another grant')
  return { kind: 'ok', row, record: rec }
}

// ------------------------------------------------------------------ the gate's source

/** The ONE synthetic grant the gate gets from a verified period (spec 2): protected = the config baseline. */
export function calibrationOfPeriod(cfg: CreditGateConfig, rec: GrantPeriodRecord): Calibration {
  return {
    id: rec.id,
    captured_at_lb_ms: rec.lb_ms,
    grants: [{
      granted: stamp(rec.lb_ms),
      expires: stamp(rec.expires_ms),
      original_micro: rec.original_micro as Micro,
      remaining_micro: rec.remaining_micro as Micro,
    }],
    protected: { R_micro: cfg.protected.R, V_micro: cfg.protected.V },
  }
}

/**
 * The grant_model calibration for a config that selects it: the newest period
 * row, if it verifies and is in force (readChain); null when the reconstructed
 * file is not good (the processor holds the gate, A6) or nothing is in force;
 * a row or approval that does not verify throws.
 */
export function grantModelCalibration(db: Database.Database, cfg: CreditGateConfig): Calibration | null {
  if (cfg.calibrationSource !== 'grant_model' || cfg.grantModel === null) return null
  const inputs = measureGrantInputs(cfg)
  if (!inputs.ok) return null
  const read = readChain(db, cfg, inputs.hash)
  return read.kind === 'ok' ? calibrationOfPeriod(cfg, read.record) : null
}

/**
 * The gate's calibration source (runtime.ts): the Console source untouched
 * unless the config selects grant_model. A config that cannot be read is the
 * Console path's business, as before.
 */
export function dispatchCalibrationSource(
  consoleSource: CalibrationSource,
  db: Database.Database,
  loadConfig: () => ConfigLoadResult,
): CalibrationSource {
  return (): Calibration | null => {
    let cfg: CreditGateConfig | null = null
    try {
      const r = loadConfig()
      cfg = r.ok && r.config.calibrationSource === 'grant_model' ? r.config : null
    } catch {
      cfg = null
    }
    return cfg === null ? consoleSource() : grantModelCalibration(db, cfg)
  }
}
