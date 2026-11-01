// The credit gate inside the dashboard process (card fec6335f, node N2a).
//
// startCreditGateRuntime() is the one call web.ts makes. With
// CREDIT_GATE_MODE missing, empty or `off` (the default) it only remembers
// the mode and returns: no table is created, no file is read or written, no
// timer starts -- the dashboard behaves exactly as before, and the routes
// answer {enforced:false} / gate_off. In shadow or enforce mode it applies the
// gate's tables, builds the gate on the real files (store/credit-gate/,
// the PR-A guard-event file) and ticks it every refreshS seconds. The
// calibration is the newest accepted credit_calibrations row (N2c) -- or, when
// the config selects calibrationSource grant_model (card 40e03382), the newest
// verified credit_grant_periods row (grant-period.ts); between
// two ticks the processor takes the owner-approved calibration and
// incident-clear approvals (calibration.ts) -- only on the dashboard's own
// database, where the approvals are.
//
// A web-only (staging) instance never runs the gate: it must not touch the
// shared STOP file. Its routes then refuse reservations (gate_not_running)
// instead of waving them through.

import { join } from 'node:path'
import type Database from 'better-sqlite3'
import { STORE_DIR } from '../../config.js'
import { getDb } from '../../db.js'
import { readEnvFile } from '../../env.js'
import { logger } from '../../logger.js'
import {
  CONFIG_FILE,
  CREDIT_GATE_DIR,
  GUARD_EVENTS_FILE,
  loadCreditGateConfigFile,
  PRICING_FILE,
  readCreditGateMode,
  readProtectedFile,
  type ModeReading,
} from './config.js'
import { CalibrationProcessor, calibrationSource } from './calibration.js'
import { dispatchCalibrationSource } from './grant-period.js'
import { CreditGate, noCalibration, stopView, type CalibrationSource, type CreditGateDeps, type GateStatus, type PricingFileResult } from './gate.js'
import { AuditNotifier, defaultNotifyDeps, type NotifyDeps } from './notify.js'
import { loadPricing } from './pricing.js'
import { applyCreditGateSchema } from './schema.js'
import { inspectStopContent, nodeStopFs, parseStopOwner, type StopFs } from './stop-file.js'

export interface CreditGateRuntime {
  readonly mode: ModeReading
  readonly gate: CreditGate | null
  readonly storeDir: string
  readonly db: Database.Database | null
  readonly startError: string | null
  /** N2c: the approval processor (the canary consume too); null when none runs. */
  readonly calibrations?: CalibrationProcessor | null
}

export interface StartOptions {
  readonly webOnly: boolean
  /** The CREDIT_GATE_MODE value; omitted = read from .env. */
  readonly modeValue?: string | null
  readonly db?: Database.Database
  readonly storeDir?: string
  /** Tests: a fixed source; then no approval is processed. Default: the credit_calibrations table. */
  readonly calibration?: CalibrationSource
  readonly now?: () => number
  /** N5: the audit deliverers. Default: the dashboard's own queue and daily log (only on the dashboard database). */
  readonly notify?: NotifyDeps
}

const DEFAULT_REFRESH_MS = 30_000

function offRuntime(): CreditGateRuntime {
  return { mode: readCreditGateMode(undefined), gate: null, storeDir: STORE_DIR, db: null, startError: null }
}

let current: CreditGateRuntime = offRuntime()

export function getCreditGateRuntime(): CreditGateRuntime {
  return current
}

/** Tests (and only tests) swap the runtime; null = back to off. */
export function setCreditGateRuntime(rt: CreditGateRuntime | null): void {
  current = rt ?? offRuntime()
}

/** pricing.json through the same checks as the config (0600, no symlink). */
export function loadPricingFile(path: string, nowMs: number): PricingFileResult {
  const r = readProtectedFile(path)
  if (!r.ok) return r
  return loadPricing(r.text, nowMs)
}

export interface FileDepsOptions {
  readonly storeDir: string
  readonly db: Database.Database
  readonly mode: ModeReading
  readonly calibration?: CalibrationSource
  readonly now?: () => number
  readonly stopFs?: StopFs
}

/** The gate on the real files under `storeDir`. */
export function fileGateDeps(o: FileDepsOptions): CreditGateDeps {
  const dir = join(o.storeDir, CREDIT_GATE_DIR)
  return {
    db: o.db,
    mode: o.mode,
    loadConfig: () => loadCreditGateConfigFile(join(dir, CONFIG_FILE)),
    loadPricing: (nowMs) => loadPricingFile(join(dir, PRICING_FILE), nowMs),
    calibration: o.calibration ?? noCalibration,
    guardEventsPath: join(o.storeDir, GUARD_EVENTS_FILE),
    stopFs: o.stopFs,
    now: o.now,
  }
}

/**
 * Start the gate per CREDIT_GATE_MODE. Returns the tick interval, or
 * undefined when nothing runs (off mode, a web-only instance, a failed start).
 */
export function startCreditGateRuntime(opts: StartOptions): NodeJS.Timeout | undefined {
  const raw = opts.modeValue !== undefined ? opts.modeValue : readEnvFile(['CREDIT_GATE_MODE'])['CREDIT_GATE_MODE']
  const mode = readCreditGateMode(raw)
  const storeDir = opts.storeDir ?? STORE_DIR
  current = { mode, gate: null, storeDir, db: opts.db ?? null, startError: null }
  if (mode.mode === 'off') return undefined
  if (opts.webOnly) {
    logger.info({ mode: mode.mode }, 'Credit gate not started on a web-only instance')
    current = { ...current, startError: 'web_only' }
    return undefined
  }
  try {
    const db = opts.db ?? getDb()
    applyCreditGateSchema(db)
    const configPath = join(storeDir, CREDIT_GATE_DIR, CONFIG_FILE)
    const loadConfig = () => loadCreditGateConfigFile(configPath)
    // Card 40e03382: the Console source unless the config selects the grant model.
    const gate = new CreditGate(fileGateDeps({
      storeDir, db, mode, calibration: opts.calibration ?? dispatchCalibrationSource(calibrationSource(db), db, loadConfig), now: opts.now,
    }))
    // The approvals live in db.ts's database: on any other handle nothing is
    // processed, and the gate (without a calibration) never opens.
    const calibrations = opts.calibration === undefined && db === getDb()
      ? new CalibrationProcessor({
        db,
        gate,
        loadConfig,
        loadPricing: (nowMs) => loadPricingFile(join(storeDir, CREDIT_GATE_DIR, PRICING_FILE), nowMs),
        now: opts.now,
      })
      : null
    if (calibrations === null && opts.calibration === undefined) logger.warn('Credit gate: not on the dashboard database, no approval is processed')
    current = { mode, gate, storeDir, db, startError: null, calibrations }
    // N5: the audit rows reach the main agent (daily log, message, directive). The default
    // deliverers write to the dashboard's database, so they only run on it.
    const notifier = opts.notify !== undefined || db === getDb()
      ? new AuditNotifier(db, opts.notify ?? defaultNotifyDeps())
      : null
    if (notifier === null) logger.warn('Credit gate: not on the dashboard database, the audit rows are not delivered')
    const run = () => {
      try {
        gate.tick()
        // Processed right after a tick (a fresh ledger), and the result at once.
        if (calibrations?.process().changed) gate.tick()
      } catch (err) {
        logger.error({ err }, 'Credit gate tick failed')
      }
      // Never awaited, never throws: bounded tries per event, see notify.ts.
      void notifier?.deliver()
    }
    run()
    const cfg = loadCreditGateConfigFile(join(storeDir, CREDIT_GATE_DIR, CONFIG_FILE))
    const interval = setInterval(run, cfg.ok ? cfg.config.refreshS * 1000 : DEFAULT_REFRESH_MS)
    interval.unref?.()
    logger.info({ mode: mode.mode, unknown: mode.unknown }, 'Credit gate started')
    return interval
  } catch (err) {
    logger.error({ err }, 'Credit gate failed to start: it stays closed')
    current = { ...current, startError: 'start_failed' }
    return undefined
  }
}

function hasStateTable(db: Database.Database): boolean {
  return db.prepare(`SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'credit_gate_state'`).get() !== undefined
}

/**
 * The status when no gate runs (off mode, web-only, failed start). Read-only:
 * it creates no table and touches no file; it still says who owns the STOP
 * (blueprint 3.6: in off mode the STOP stays in hand, the status names its
 * owner). With the gate's record (a database handle and the state row) the
 * full check runs; without it -- off mode in production has no handle -- the
 * STOP's own content tells (BE-3: the gate's STOP must not read as human).
 */
export function inactiveStatus(rt: CreditGateRuntime): GateStatus {
  const cfg = loadCreditGateConfigFile(join(rt.storeDir, CREDIT_GATE_DIR, CONFIG_FILE))
  let ownerJson: string | null = null
  let lastStopFile: string | null = null
  try {
    if (rt.db && hasStateTable(rt.db)) {
      const row = rt.db.prepare('SELECT stop_owner_json, last_stop_file FROM credit_gate_state WHERE id = 1').get() as
        { stop_owner_json: string | null; last_stop_file: string | null } | undefined
      ownerJson = row?.stop_owner_json ?? null
      lastStopFile = row?.last_stop_file ?? null
    }
  } catch {
    ownerJson = null
  }
  const stopPath = cfg.ok ? cfg.config.stopFile : lastStopFile
  const rec = parseStopOwner(ownerJson)
  let stop: GateStatus['stop']
  if (stopPath === null) stop = { path: null, present: null, owner: 'unknown' }
  else if (rec !== null) stop = stopView(nodeStopFs, stopPath, rec)
  else {
    const i = inspectStopContent(nodeStopFs, stopPath)
    stop = i.kind === 'absent' ? { path: stopPath, present: false, owner: 'none' }
      : i.kind === 'gate' ? { path: stopPath, present: true, owner: 'gate' }
      : i.kind === 'human' ? { path: stopPath, present: true, owner: 'human' }
      : { path: stopPath, present: null, owner: 'unknown' }
  }
  return {
    mode: rt.mode.mode,
    mode_raw: rt.mode.raw,
    enforced: rt.mode.mode === 'enforce',
    state: 'CLOSED',
    reason: rt.mode.mode === 'off' ? 'gate_off' : 'gate_not_running',
    since: null,
    evaluated_at: null,
    r_est_usd: null,
    ledger: { l_usd: null, age_s: null, unpriced: 0, error: null, saturated: false, sources: [] },
    reservations: { open_count: 0, open_usd: '0.00' },
    thresholds: null,
    calibration: null,
    close_at: null,
    close_at_batch: null,
    next_expiry: null,
    latch: null,
    max_calibration_id: 0,
    lowcal: { requested_at: null, fallback_at: null },
    stop,
    canary_in_progress: false,
    canary_window: null,
  }
}
