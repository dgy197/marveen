// POST /api/agents/fleet-token/restart-stale (card acdb8045 K6).
//
// Restarts, one after the other, the running fleet-token sub-agents whose launch
// stamp no longer matches the token file (K5's detector). It is a "restart the
// whole fleet" button, so it is owner-session only (Brainy 6344 Q4): the shared
// Bearer token is every sub-agent's credential, a device key (full or not) and
// an operator key are not the owner at the keyboard. The per-agent restart route
// is unchanged and stays Bearer-capable (Q5).
//
// Auth decision (the only one): upgradeTokenToSession(auth, req).kind === 'session',
// i.e. a valid, unexpired, unrevoked mv_session cookie. Anything else is ONE
// uniform 403, decided BEFORE the request body is touched (this route never reads
// a body). 403, never 401: a 401 makes the SPA fetch wrapper drop its stored token.
//
// Output hygiene: names and fixed reason words only. No fingerprint, no token, no
// error text from the restart (the detector already keeps fingerprints inside its
// callbacks).
//
// IO-injected (RestartStaleDeps) so the sequence is tested without tmux or sleeps.
// The production binding is fleet-token-restart-live.ts.
import { logConfigChange } from '../db.js'
import { logger } from '../logger.js'
import { json } from './http-helpers.js'
import { fleetTokenDrift, fleetTokenFieldFor, type FleetTokenDriftDeps } from './fleet-token-drift.js'
import { upgradeTokenToSession } from './owner-session.js'
import type { RouteContext } from './routes/types.js'

export const RESTART_STALE_PATH = '/api/agents/fleet-token/restart-stale'
const AUDIT_KEY = 'fleet_token.restart_stale'

/** One body for every refused principal, so the response does not tell them apart. */
export const RESTART_STALE_FORBIDDEN_BODY = { error: 'owner session required', code: 'owner_session_required' } as const

export type StaleStepResult = 'restarted' | 'skipped' | 'failed'

export interface StaleStep {
  agent: string
  result: StaleStepResult
  /** Fixed word, never free text from a failure. */
  reason?: string
}

export interface RestartStaleDeps {
  /** The K5 detector's IO; re-read before every step. */
  drift: FleetTokenDriftDeps
  /** The main agent is never restarted by this route, whatever the registry says. */
  isMain(name: string): boolean
  /**
   * A fixed reason word when this agent must not be (re)started right now
   * (stopped on purpose, remote host unreachable), else null. restartAgentProcess
   * starts a non-running agent outright, so the guard lives here.
   */
  blockReason(name: string): string | null
  restart(name: string): Promise<{ ok: boolean }>
  sleep(ms: number): Promise<void>
  /** Pause between two restarts (FLEET_RESTART_GAP_MS), so the fleet does not boot at once. */
  gapMs: number
}

export interface RestartStaleOutcome {
  measurable: boolean
  steps: StaleStep[]
}

/**
 * Sequential sweep. The stale list is taken once up front; each step then
 * re-detects (a restart elsewhere, a stop or a token change in the meantime) and
 * only a still-stale agent is restarted. The gap is paid only between two real
 * restarts. A failing restart is recorded and the sweep goes on.
 */
export async function restartStaleAgents(
  deps: RestartStaleDeps,
  onStart?: (stale: string[]) => void,
): Promise<RestartStaleOutcome> {
  const drift = fleetTokenDrift(deps.drift)
  const steps: StaleStep[] = []
  onStart?.([...drift.stale])
  let restartedBefore = false
  for (const name of drift.stale) {
    if (deps.isMain(name)) { steps.push({ agent: name, result: 'skipped', reason: 'main-agent' }); continue }
    let block: string | null = null
    try { block = deps.blockReason(name) } catch { block = 'state-unreadable' }
    if (block) { steps.push({ agent: name, result: 'skipped', reason: block }); continue }
    if (restartedBefore) await deps.sleep(deps.gapMs)
    // Re-detect right before the step, after the gap: the state may have moved.
    if (fleetTokenFieldFor(name, deps.drift) !== 'stale') {
      steps.push({ agent: name, result: 'skipped', reason: 'no-longer-stale' })
      continue
    }
    restartedBefore = true
    try {
      const r = await deps.restart(name)
      steps.push(r.ok ? { agent: name, result: 'restarted' } : { agent: name, result: 'failed', reason: 'restart-failed' })
    } catch {
      steps.push({ agent: name, result: 'failed', reason: 'restart-threw' })
    }
  }
  return { measurable: drift.measurable, steps }
}

const namesOf = (steps: StaleStep[], result: StaleStepResult) => steps.filter((s) => s.result === result).map((s) => s.agent)

let sweepInFlight = false

/** Test seam: clear a sweep flag left by a test that threw. */
export function __resetRestartStaleSweep(): void {
  sweepInFlight = false
}

function audit(newValue: string, actor: string): void {
  try {
    logConfigChange(AUDIT_KEY, null, newValue, actor)
  } catch (err) {
    logger.error({ err }, 'Failed to write the fleet-token restart-stale audit row')
  }
}

/**
 * The route handler. `makeDeps` is called only after the auth and single-flight
 * checks, so a refused caller never builds (or touches) anything.
 */
export async function handleFleetTokenRestartStale(
  ctx: RouteContext,
  makeDeps: () => RestartStaleDeps,
): Promise<void> {
  const { req, res } = ctx
  const effective = upgradeTokenToSession(ctx.auth, req)
  if (effective?.kind !== 'session') {
    json(res, RESTART_STALE_FORBIDDEN_BODY, 403)
    return
  }
  if (sweepInFlight) {
    json(res, { error: 'a restart-stale sweep is already running', code: 'restart_stale_in_progress' }, 409)
    return
  }
  sweepInFlight = true
  const actor = 'session'
  try {
    const outcome = await restartStaleAgents(makeDeps(), (stale) => {
      // Recorded BEFORE the first restart, so a sweep that dies half way leaves a trace.
      audit(`start by=${effective.user} stale=${stale.join(',') || '-'}`, actor)
    })
    const restarted = namesOf(outcome.steps, 'restarted')
    const skipped = namesOf(outcome.steps, 'skipped')
    const failed = namesOf(outcome.steps, 'failed')
    audit(`done restarted=${restarted.join(',') || '-'} skipped=${skipped.join(',') || '-'} failed=${failed.join(',') || '-'}`, actor)
    json(res, { ok: failed.length === 0, measurable: outcome.measurable, steps: outcome.steps, restarted, skipped, failed }, 200)
  } catch (err) {
    logger.error({ err }, 'fleet-token restart-stale sweep failed')
    audit('error sweep-threw', actor)
    json(res, { error: 'restart-stale sweep failed' }, 500)
  } finally {
    sweepInFlight = false
  }
}
