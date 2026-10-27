import { logger } from '../logger.js'
import { EMBED_URL, EMBED_MODEL, EMBED_KEEPWARM_MINUTES, EMBED_KEEPWARM_MINUTES_INVALID } from '../config.js'
import { embeddingMonoMs, getEmbeddingActivity, type EmbeddingActivity } from '../db.js'
import {
  KEEPWARM_FIRST_TICK_MS, KEEPWARM_TICK_MS, decideKeepWarm, evaluatePs, fetchPs, inPingWindow,
  keepWarmBackoffMs, loopbackEndpoint, pingEmbedding, remainingSeconds,
  type KeepWarmCallError, type KeepWarmFetch, type KeepWarmSkip,
} from '../embedding-keepwarm.js'

// Keep-warm runner (card 94f8d99f, memory program w3, node DW3); the why and
// the rules are in ../embedding-keepwarm.ts. Every minute (first tick 2 min
// after boot) it asks decideKeepWarm whether Ollama may be asked at all; only
// after EMBED_KEEPWARM_MINUTES without any embedding call (a real one, or its
// own probe or ping) does it read GET /api/ps, and only a loaded model with
// more than a minute left gets the ping. So at most one /api/ps and one ping
// per interval: 288 a day at 5 minutes, none while searches keep the model
// busy, none during an outage.
//
// Shared state it only READS: the activity generateEmbedding leaves (calls in
// flight, the last finished call, the success count, the outage latch) and
// whether a backfill pass runs. It holds no lock a search or the backfill
// waits for, writes nothing to the DB, and never sets the outage latch: its
// failures go into its own backoff. A real embedding that succeeds after a
// failure ends the backoff (the backend is back).
//
// Logging: one INFO at start (on, or why off), one WARN per failure episode
// (debug after it), and one INFO per hour with numbers only, written only if
// the hour had a keep-warm call (a probe) at all.

const SUMMARY_MS = 3_600_000

interface Counters {
  probes: number
  pings_ok: number
  pings_failed: number
  ps_failed: number
  skip_recent: number
  skip_inflight: number
  skip_outage: number
  skip_backoff: number
  skip_not_loaded: number
  skip_window: number
  max_ms: number
  last_ms: number
}

function zeroCounters(): Counters {
  return {
    probes: 0, pings_ok: 0, pings_failed: 0, ps_failed: 0,
    skip_recent: 0, skip_inflight: 0, skip_outage: 0, skip_backoff: 0, skip_not_loaded: 0, skip_window: 0,
    max_ms: 0, last_ms: 0,
  }
}

export interface KeepWarmDeps {
  fetch: KeepWarmFetch
  /** Monotonic ms, the same clock as EmbeddingActivity.lastDoneMono. */
  monoMs: () => number
  /** Wall clock ms (expires_at is wall time). */
  wallMs: () => number
  activity: () => EmbeddingActivity
}

export interface KeepWarmConfig {
  minutes: number
  /** The rejected raw value when the configured one was invalid (the default applies). */
  invalid?: string
  embedUrl: string
  model: string
}

interface RunnerState {
  deps: KeepWarmDeps
  model: string
  intervalMs: number
  psUrl: string
  embeddingsUrl: string
  startedMono: number
  /** End of the keep-warm's own last call (probe or ping), monotonic ms. */
  lastOwnCallMono: number | null
  backoffFails: number
  backoffUntilMono: number | null
  /** EmbeddingActivity.successes when the backoff was set: a higher count ends it. */
  successesAtBackoff: number
  busy: boolean
  abort: AbortController
  counters: Counters
  windowStartMono: number
  initialTimer: ReturnType<typeof setTimeout> | null
  intervalTimer: ReturnType<typeof setInterval> | null
}

let started = false
let state: RunnerState | null = null

function defaultDeps(): KeepWarmDeps {
  return {
    fetch: (url, init) => fetch(url, init),
    monoMs: embeddingMonoMs,
    wallMs: () => Date.now(),
    activity: getEmbeddingActivity,
  }
}

function defaultConfig(): KeepWarmConfig {
  return { minutes: EMBED_KEEPWARM_MINUTES, invalid: EMBED_KEEPWARM_MINUTES_INVALID, embedUrl: EMBED_URL, model: EMBED_MODEL }
}

/**
 * Start the runner (idempotent: a second start is a no-op until stop). Tests
 * pass a fake fetch, clocks and activity; the dashboard passes nothing.
 */
export function startEmbeddingKeepWarmRunner(opts: { deps?: Partial<KeepWarmDeps>; config?: Partial<KeepWarmConfig> } = {}): void {
  if (started) return
  started = true
  const deps: KeepWarmDeps = { ...defaultDeps(), ...opts.deps }
  const config: KeepWarmConfig = { ...defaultConfig(), ...opts.config }
  if (config.invalid !== undefined) {
    logger.warn(
      { value: config.invalid.slice(0, 40), using: config.minutes },
      'EMBED_KEEPWARM_MINUTES must be 0 (off) or a whole number from 5 to 10 -- using the default',
    )
  }
  if (config.minutes <= 0) {
    logger.info({ minutes: 0 }, 'Embedding keep-warm off (EMBED_KEEPWARM_MINUTES=0)')
    return
  }
  const psUrl = loopbackEndpoint(config.embedUrl, '/api/ps')
  const embeddingsUrl = loopbackEndpoint(config.embedUrl, '/api/embeddings')
  if (psUrl === null || embeddingsUrl === null) {
    logger.info('Embedding keep-warm off: EMBED_URL is not a loopback address (127.0.0.1, ::1, localhost), and a remote embedding server is not kept warm')
    return
  }
  const now = deps.monoMs()
  const s: RunnerState = {
    deps,
    model: config.model,
    intervalMs: config.minutes * 60_000,
    psUrl,
    embeddingsUrl,
    startedMono: now,
    lastOwnCallMono: null,
    backoffFails: 0,
    backoffUntilMono: null,
    successesAtBackoff: 0,
    busy: false,
    abort: new AbortController(),
    counters: zeroCounters(),
    windowStartMono: now,
    initialTimer: null,
    intervalTimer: null,
  }
  state = s
  s.initialTimer = setTimeout(() => {
    s.initialTimer = null
    void runKeepWarmTick()
    s.intervalTimer = setInterval(() => { void runKeepWarmTick() }, KEEPWARM_TICK_MS)
    s.intervalTimer.unref?.()
  }, KEEPWARM_FIRST_TICK_MS)
  s.initialTimer.unref?.()
  logger.info({ minutes: config.minutes }, 'Embedding keep-warm on: the loaded embedding model is pinged after this many idle minutes, without extending its keep_alive window')
}

/** Stop the runner: timers cleared, a call in flight aborted, and nothing it returns is acted on. */
export function stopEmbeddingKeepWarmRunner(): void {
  started = false
  const s = state
  state = null
  if (!s) return
  if (s.initialTimer) clearTimeout(s.initialTimer)
  if (s.intervalTimer) clearInterval(s.intervalTimer)
  s.initialTimer = null
  s.intervalTimer = null
  s.abort.abort()
}

export type KeepWarmTickResult =
  | 'stopped' | 'busy' | 'ping_ok' | 'ping_failed' | 'ps_failed' | 'not_loaded' | 'window'
  | `skip_${Exclude<KeepWarmSkip, 'off' | 'not_loopback'>}`

/** One tick now (the timers call this; tests call it directly). */
export async function runKeepWarmTick(): Promise<KeepWarmTickResult> {
  const s = state
  if (!s) return 'stopped'
  if (s.busy) return 'busy'
  s.busy = true
  try {
    // The hour closes before this tick, so its events count in the next one.
    maybeSummary(s)
    return await tick(s)
  } finally {
    s.busy = false
  }
}

function lastActivity(s: RunnerState, act: EmbeddingActivity, includeOwn: boolean): number {
  // Never pinged before the interval has passed since the start: what ran
  // before this process is unknown.
  let last = s.startedMono
  if (act.lastDoneMono !== null && act.lastDoneMono > last) last = act.lastDoneMono
  if (includeOwn && s.lastOwnCallMono !== null && s.lastOwnCallMono > last) last = s.lastOwnCallMono
  return last
}

/**
 * decideKeepWarm on a fresh snapshot; a skip is counted and returned.
 * `includeOwn` false = the keep-warm's own last call does not count as recent
 * (the re-check right after its own probe).
 */
function gate(s: RunnerState, includeOwn = true): KeepWarmTickResult | null {
  const act = s.deps.activity()
  // A real embedding succeeded since the backoff was set: the backend is back.
  if (s.backoffFails > 0 && act.successes !== s.successesAtBackoff) {
    s.backoffFails = 0
    s.backoffUntilMono = null
  }
  const d = decideKeepWarm({
    enabled: true,
    loopback: true,
    nowMono: s.deps.monoMs(),
    lastDoneMono: lastActivity(s, act, includeOwn),
    inFlight: act.inFlight,
    backfillInFlight: act.backfillInFlight,
    outageLatched: act.outageLatched,
    backoffUntilMono: s.backoffUntilMono,
    intervalMs: s.intervalMs,
  })
  if (d.action === 'probe') return null
  switch (d.reason) {
    case 'inflight': s.counters.skip_inflight++; return 'skip_inflight'
    case 'outage': s.counters.skip_outage++; return 'skip_outage'
    case 'backoff': s.counters.skip_backoff++; return 'skip_backoff'
    case 'recent': s.counters.skip_recent++; return 'skip_recent'
    // enabled and loopback are settled at start; a runner never ticks without them.
    default: return 'stopped'
  }
}

function fail(s: RunnerState, stage: 'ps' | 'ping', error: KeepWarmCallError | 'bad_json', status?: number): void {
  s.backoffFails++
  const delayMs = keepWarmBackoffMs(s.backoffFails)
  s.backoffUntilMono = s.deps.monoMs() + delayMs
  s.successesAtBackoff = s.deps.activity().successes
  const fields = { stage, error, ...(status !== undefined ? { status } : {}), backoffMin: delayMs / 60_000 }
  if (s.backoffFails === 1) {
    logger.warn(fields, 'Embedding keep-warm: the call failed; no keep-warm call until the backoff ends (doubling to 4 h) or a real embedding succeeds')
  } else {
    logger.debug(fields, 'Embedding keep-warm: the call failed again')
  }
}

/** End a failure episode: no backoff, and the next failure WARNs again. */
function endEpisode(s: RunnerState): void {
  s.backoffFails = 0
  s.backoffUntilMono = null
}

async function tick(s: RunnerState): Promise<KeepWarmTickResult> {
  const skipped = gate(s)
  if (skipped) return skipped

  s.counters.probes++
  const ps = await fetchPs(s.deps.fetch, s.psUrl, s.abort.signal)
  if (state !== s) return 'stopped'
  s.lastOwnCallMono = s.deps.monoMs()
  if (!ps.ok) {
    s.counters.ps_failed++
    fail(s, 'ps', ps.error, ps.status)
    return 'ps_failed'
  }
  const verdict = evaluatePs(ps.body, s.model, s.deps.wallMs())
  if (verdict.kind === 'bad') {
    s.counters.ps_failed++
    fail(s, 'ps', 'bad_json')
    return 'ps_failed'
  }
  // A readable /api/ps that ends the round without a ping: Ollama is back, so
  // the failure episode (if any) is over, and the next outage WARNs again
  // and starts at 15 min (finding DE1). Not reset before a ping: a ping that
  // keeps failing behind a good /api/ps stays one episode and keeps doubling.
  if (verdict.kind === 'not_loaded') { s.counters.skip_not_loaded++; endEpisode(s); return 'not_loaded' }
  if (verdict.kind === 'window') { s.counters.skip_window++; endEpisode(s); return 'window' }

  // A real call may have started while /api/ps answered: it warms the model
  // itself, and a ping queued behind it would only shorten the window it sets.
  // (Its own probe a moment ago does not count as recent here.)
  const again = gate(s, false)
  if (again) return again
  // The time left NOW, rounded down: the ping never moves expires_at later.
  const remainingSec = remainingSeconds(verdict.expiresMs, s.deps.wallMs())
  if (!inPingWindow(remainingSec)) { s.counters.skip_window++; endEpisode(s); return 'window' }

  const t0 = s.deps.monoMs()
  const ping = await pingEmbedding(s.deps.fetch, s.embeddingsUrl, s.model, remainingSec, s.abort.signal)
  if (state !== s) return 'stopped'
  const t1 = s.deps.monoMs()
  s.lastOwnCallMono = t1
  if (!ping.ok) {
    s.counters.pings_failed++
    fail(s, 'ping', ping.error, ping.status)
    return 'ping_failed'
  }
  const ms = Math.max(0, Math.round(t1 - t0))
  s.counters.pings_ok++
  s.counters.last_ms = ms
  if (ms > s.counters.max_ms) s.counters.max_ms = ms
  // The whole round went through: the failure episode (if any) is over.
  endEpisode(s)
  logger.debug({ keepAliveSec: remainingSec, ms }, 'Embedding keep-warm ping')
  return 'ping_ok'
}

function maybeSummary(s: RunnerState): void {
  const now = s.deps.monoMs()
  if (now - s.windowStartMono < SUMMARY_MS) return
  if (s.counters.probes > 0) logger.info({ ...s.counters }, 'Embedding keep-warm, last hour')
  s.counters = zeroCounters()
  s.windowStartMono = now
}

/** Test seam: the live timers (to check that they are unref'ed) and the counters. */
export function keepWarmRunnerSnapshot(): { running: boolean; initialTimer: unknown; intervalTimer: unknown; counters: Counters | null; backoffFails: number } {
  const s = state
  return {
    running: s !== null,
    initialTimer: s?.initialTimer ?? null,
    intervalTimer: s?.intervalTimer ?? null,
    counters: s ? { ...s.counters } : null,
    backoffFails: s?.backoffFails ?? 0,
  }
}
