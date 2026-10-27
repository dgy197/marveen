// Memory write gate runner, b1 shadow mode (card 3e9f6c28, node G2c).
//
// Started once from index.ts after the keep-warm runner. The .env keys are read
// ONCE here (a change needs a restart; the DISABLE file is the restart-free
// switch). Rounds: the first 90 s after boot, then every 60 s, single-flight.
// The reason sweep runs at start (before any round) and every 10 minutes, in any
// mode, as long as the gate tables are verified.
//
// With MEMORY_GATE_MODE unset/off or no owners the runner starts its timers but
// every round returns before touching the database: 0 rows, 0 calls.
import { join } from 'node:path'
import { logger } from '../logger.js'
import { STORE_DIR, MAIN_AGENT_ID } from '../config.js'
import { getDb, appendDailyLog, createAgentMessage } from '../db.js'
import { gateTablesReady } from '../memory-gate/schema.js'
import { readGateConfig, makeDisableCheck, type CreditView, type GateConfig } from '../memory-gate/state.js'
import { runGateTick, newWorkerState, singleFlight, sweepReasons, type WorkerDeps } from '../memory-gate/worker.js'
import { runGateCalls } from '../memory-gate/transport.js'
import { getCreditGateRuntime, loadPricingFile } from './credit-gate/runtime.js'
import { CREDIT_GATE_DIR, PRICING_FILE } from './credit-gate/config.js'
import { estimate } from './credit-gate/pricing.js'

export const FIRST_TICK_MS = 90_000
export const TICK_MS = 60_000
export const SWEEP_MS = 10 * 60_000

let firstTimer: NodeJS.Timeout | null = null
let tickTimer: NodeJS.Timeout | null = null
let sweepTimer: NodeJS.Timeout | null = null

/** The credit gate as the worker needs it (B2); status() only in enforce mode. */
export function liveCreditView(): CreditView {
  const rt = getCreditGateRuntime()
  const mode = rt.mode.mode
  let gate: { state: string } | null = null
  if (rt.gate) {
    // Only enforce mode looks at the state; an unreadable status is simply not OPEN.
    let state = 'n/a'
    if (mode === 'enforce') { try { state = rt.gate.status().state } catch { state = 'UNREADABLE' } }
    gate = { state }
  }
  return { mode, unknown: rt.mode.unknown, startError: rt.startError, gate }
}

/** Over-estimate of one call from the credit gate's verified pricing table (input tokens <= prompt bytes). */
export function livePriceEstimate(model: string, promptBytes: number, maxTokens: number, nowMs: number): number | null {
  const p = loadPricingFile(join(STORE_DIR, CREDIT_GATE_DIR, PRICING_FILE), nowMs)
  if (!p.ok) return null
  const micro = estimate({ model, input_tokens: promptBytes, output_tokens: maxTokens, cache_write_tokens: 0, cache_read_tokens: 0 }, { table: p.table })
  return micro === null ? null : Number(micro)
}

function liveAlert(_cause: string, text: string): void {
  // Fixed text, numbers only. mirror:false: the alert writes no memories row.
  try { appendDailyLog(MAIN_AGENT_ID, text, { mirror: false }) } catch { /* best effort */ }
  try { createAgentMessage('system', MAIN_AGENT_ID, text) } catch { /* best effort */ }
}

export function liveWorkerDeps(cfg: GateConfig): WorkerDeps {
  return {
    db: getDb,
    now: Date.now,
    config: cfg,
    tablesReady: gateTablesReady,
    disabled: makeDisableCheck(STORE_DIR),
    credit: liveCreditView,
    estimateMicro: livePriceEstimate,
    transport: (calls) => runGateCalls(calls, { batchDir: cfg.batchDir, storeDir: STORE_DIR }),
    alert: liveAlert,
  }
}

function sweep(): void {
  if (!gateTablesReady()) return
  try { sweepReasons(getDb()) } catch (err) {
    try { logger.warn({ reason: (err as { code?: string } | null)?.code ?? 'error' }, 'memory-gate: reason sweep failed') } catch { /* ignore */ }
  }
}

export function startMemoryGateRunner(): void {
  if (tickTimer || firstTimer) return
  let cfg: GateConfig
  try { cfg = readGateConfig() } catch { logger.warn('memory-gate: config unreadable, runner not started'); return }
  if (cfg.env.invalidMode) logger.warn('memory-gate: MEMORY_GATE_MODE is not off/shadow/active, treated as off')
  if (cfg.env.configuredMode === 'active') logger.warn('memory-gate: active mode is not available in b1, running as shadow')
  if (cfg.configError) logger.warn({ reason: cfg.configError }, 'memory-gate: config error, gate inert')
  logger.info({ mode: cfg.env.effectiveMode, owners: cfg.env.owners.owners.length }, 'memory-gate: runner started')

  sweep()
  const deps = liveWorkerDeps(cfg)
  const st = newWorkerState()
  const tick = singleFlight(async () => {
    try { return await runGateTick(deps, st) } catch (err) {
      try { logger.warn({ reason: (err as { code?: string; name?: string } | null)?.code ?? (err as { name?: string } | null)?.name ?? 'error' }, 'memory-gate: round failed') } catch { /* ignore */ }
      return null
    }
  })
  firstTimer = setTimeout(() => {
    firstTimer = null
    void tick()
    tickTimer = setInterval(() => { void tick() }, TICK_MS)
    tickTimer.unref?.()
  }, FIRST_TICK_MS)
  firstTimer.unref?.()
  sweepTimer = setInterval(sweep, SWEEP_MS)
  sweepTimer.unref?.()
}

export function stopMemoryGateRunner(): void {
  if (firstTimer) clearTimeout(firstTimer)
  if (tickTimer) clearInterval(tickTimer)
  if (sweepTimer) clearInterval(sweepTimer)
  firstTimer = null
  tickTimer = null
  sweepTimer = null
}
