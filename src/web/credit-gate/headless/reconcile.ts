// The headless runs a previous dashboard left behind (card fec6335f, spec
// B-04; blueprint 4.3, node N4a; BE-4 round 1, 6, 10).
//
// A run's process lives in its own session, so a dashboard that died without
// running any code (SIGKILL, a crash, a power cut) leaves it running; one that
// got SIGTERM/SIGINT/SIGHUP took it along (runner.ts). At the next start:
//  - with a running gate, every unfinished row is decided once
//    (runner.reconcileRow): a row that does not check out (id, run_dir,
//    pgid, reservation) is closed without touching any file or process and
//    the gate is told; `starting` is settled at zero; a live pid whose argv
//    names the run dir and whose start time is the recorded one is
//    re-attached; anything else is closed by B-04 after its processes (the
//    pinned CLI with the run dir in its place, and the env-carrying members
//    of its group; never a bare group id or a mere mention) are killed; when ps cannot run,
//    the row stays open and a later tick retries;
//  - then (BE-4b N1) every closed row whose own reservation is still open or
//    unknown -- a settle that failed before the restart, whose in-memory
//    retry is gone -- is settled (runner.settleClosedRows); one that fails
//    again goes to the tick's retry;
//  - in EVERY mode except a web-only instance (also off, also a gate that
//    failed to start: the rollback path), the runs dir is swept: every key
//    file is deleted and every process of a run is stopped -- except the runs
//    this dashboard has just re-attached.
//
// startHeadlessRuntime() is the one call web.ts makes. The runner it builds
// is the one the runs routes use (N4b). E-04: a normal run starts only under
// the config hash the newest evaluated canary approved (N2c approvedCanary);
// a canary only under the hash its own consumed approval's row binds to that
// very run id, handed out once (takeCanaryHash) -- never one from the request.

import { join } from 'node:path'
import { PROJECT_ROOT } from '../../../config.js'
import { logger } from '../../../logger.js'
import { getSecret } from '../../vault.js'
import { CONFIG_FILE, CREDIT_GATE_DIR, loadCreditGateConfigFile } from '../config.js'
import { approvedCanary, takeCanaryHash } from '../calibration.js'
import { getCreditGateRuntime, type CreditGateRuntime } from '../runtime.js'
import { defaultKill, HeadlessRunner, listProcessesPs, sweepRunsDir, type HeadlessRunnerDeps, type ProcInfo } from './runner.js'

export interface ReconcileReport {
  readonly reattached: readonly string[]
  readonly closed: readonly string[]
  /** ps (or the config) cannot be used now: the row stays open, a tick retries. */
  readonly pending: readonly string[]
  /** BE-4b N1: closed rows whose open reservation was settled now. */
  readonly settled: readonly string[]
  /** BE-4b N1: closed rows whose open reservation could not be settled now: the tick retries. */
  readonly retrying: readonly string[]
  readonly errors: readonly string[]
}

export function reconcileHeadlessRuns(runner: HeadlessRunner): ReconcileReport {
  const out = {
    reattached: [] as string[], closed: [] as string[], pending: [] as string[], settled: [] as string[], retrying: [] as string[], errors: [] as string[],
  }
  for (const row of runner.openRows()) {
    try {
      out[runner.reconcileRow(row)].push(row.id)
    } catch (err) {
      out.errors.push(row.id)
      logger.error({ err: err instanceof Error ? err.name : 'error', run_id: row.id }, 'credit gate: reconciling a headless run failed')
    }
  }
  try {
    const s = runner.settleClosedRows()
    out.settled.push(...s.settled)
    out.retrying.push(...s.retrying)
  } catch (err) {
    logger.error({ err: err instanceof Error ? err.name : 'error' }, 'credit gate: settling the closed headless runs\' open reservations failed')
  }
  if (out.reattached.length + out.closed.length + out.pending.length + out.settled.length + out.retrying.length + out.errors.length > 0) {
    logger.warn(out, 'credit gate: headless runs reconciled after a restart')
  }
  return out
}

export interface HeadlessRuntimeHandle {
  readonly runner: HeadlessRunner
  stop(): void
}

export interface HeadlessRuntimeOptions {
  /** Default: the credit gate's runtime (runtime.ts). */
  readonly runtime?: CreditGateRuntime
  /** Default: the Vault's config.vaultKeyId. Used here only for the residue scan. */
  readonly getKey?: () => string | null
  /** Default: this install's root (PROJECT_ROOT). */
  readonly installRoot?: string
  /** Default: `ps -A -wwE` (tests inject). */
  readonly listProcesses?: () => readonly ProcInfo[]
  /** Default: process.kill (tests inject). */
  readonly kill?: (pid: number, signal: NodeJS.Signals | 0) => void
  /** Tests: the runner's process seams. The hash sources are not among them. */
  readonly runnerDeps?: Partial<Pick<HeadlessRunnerDeps,
    'spawner' | 'now' | 'newRunId' | 'procStart' | 'wallClockMs' | 'killGraceMs' | 'pollMs' | 'psRetryLimit' | 'settleRetryLimit' | 'cwdTreeLimits' | 'installSignalHandlers'>>
}

let current: HeadlessRunner | null = null

/** The dashboard's runner (N4b's routes use it); null while the gate does not run. */
export function getHeadlessRunner(): HeadlessRunner | null {
  return current
}

export function startHeadlessRuntime(o: HeadlessRuntimeOptions = {}): HeadlessRuntimeHandle | undefined {
  const rt = o.runtime ?? getCreditGateRuntime()
  // A web-only (staging) instance shares nothing it may clean up.
  if (rt.startError === 'web_only') return undefined
  const configPath = join(rt.storeDir, CREDIT_GATE_DIR, CONFIG_FILE)
  const loadConfig = () => loadCreditGateConfigFile(configPath)
  const listProcesses = o.listProcesses ?? listProcessesPs
  const kill = o.kill ?? defaultKill
  const sweep = (keep: ReadonlySet<string>): void => {
    const c = loadConfig()
    if (!c.ok || c.config.headless === null) {
      if (!c.ok && c.reason !== 'missing') logger.warn({ reason: c.reason }, 'credit gate: no valid config; the headless runs dir is not swept')
      return
    }
    try {
      sweepRunsDir(c.config.headless.runsDir, { keep, claudeBin: c.config.headless.claudeBin, listProcesses, kill })
    } catch (err) {
      logger.error({ err: err instanceof Error ? err.name : 'error' }, 'credit gate: sweeping the headless runs dir failed')
    }
  }
  if (rt.gate === null || rt.db === null) {
    // Off mode, or a gate that did not start: nobody would watch a run.
    sweep(new Set())
    return undefined
  }
  const getKey = o.getKey ?? (() => {
    const c = loadConfig()
    return c.ok ? getSecret(c.config.vaultKeyId) : null
  })
  const db = rt.db
  try {
    const runner = new HeadlessRunner({
      ...o.runnerDeps,
      db,
      gate: rt.gate,
      loadConfig,
      getKey,
      approvedHash: () => approvedCanary(db)?.config_hash ?? null,
      canaryApprovedHash: (approvalId, runId) => takeCanaryHash(db, approvalId, runId),
      forbiddenRoots: [o.installRoot ?? PROJECT_ROOT, rt.storeDir],
      listProcesses,
      kill,
    })
    current = runner
    reconcileHeadlessRuns(runner)
    sweep(new Set(runner.activeIds()))
    return {
      runner,
      stop: () => {
        runner.stop()
        if (current === runner) current = null
      },
    }
  } catch (err) {
    logger.error({ err: err instanceof Error ? err.name : 'error' }, 'credit gate: the headless runner did not start')
    sweep(new Set())
    return undefined
  }
}
