// Long-poll loop of the permission-bot relay (card d7f586bf, spec F2.3, F4, F5).
//
// The loop owns getUpdates, the offset file and the status file; what happens
// with a callback_query is the injected handler's business (N2: apv-handler via
// the prefix dispatcher). The handler answers the callback itself (toast) and
// resolves with an outcome; only AFTER it resolves is the offset advanced
// (F4.1), so a crash in between redelivers the update (F4.2).
//
// States: starting -> refused(webhook_set) | polling; polling <-> degraded
// (transient errors, 1 s .. 60 s exponential backoff); polling -> conflict on a
// 409 (another getUpdates consumer): no polling, one retry per conflictRetryMs
// (5 min), the alert is logged once per episode (K4: log + status file, read by
// the health round; the relay sends nothing itself). A 409 caused by a webhook,
// or a webhook seen at start, ends the loop as refused(webhook_set): the relay
// never deletes a webhook (F1.3). 401 / other 4xx end it as fatal.
//
// Backlog (K3): at start the updates already pending on the server are dropped
// (counted, logged, offset moved past them), EXCEPT the one recorded as
// `inflight` in the offset file, i.e. the update whose handler was running when
// the previous process died. That one is handed to the handler again.
//
// Stop (SIGTERM/SIGINT, F4.5): the pending long-poll and any backoff sleep are
// aborted at once; an update whose handler is already running is allowed to
// finish and its offset is committed; no new update is started. If the handler
// is still running when the grace period ends, its signal is aborted and stop()
// resolves with drained:false (the inflight marker makes it come again).
//
// Logging (F5): update_id, counts, state and reason codes only. Never the
// update body, the callback data, a user id, or a handler error message (only
// its name). Bot-API error messages are already token-masked by bot-api.ts.

import { BotApiError, type BotApi, type TelegramUpdate } from './bot-api.js'
import type { OffsetStore, RelayState, StatusFile } from './offset-store.js'
import type { RelayLock } from './lock.js'

export type HandlerOutcome = 'processed' | 'rejected'

export interface UpdateHandlerContext {
  api: BotApi
  // Aborted when the stop grace period runs out; cancel outbound work on it.
  signal: AbortSignal
}

// Called once per callback_query update (non-callback updates never reach it).
// Should not throw: a throw is retried up to maxHandlerAttempts, then skipped.
export type UpdateHandler = (update: TelegramUpdate, ctx: UpdateHandlerContext) => Promise<HandlerOutcome>

export interface RelayLog {
  info(obj: Record<string, unknown>, msg: string): void
  warn(obj: Record<string, unknown>, msg: string): void
  error(obj: Record<string, unknown>, msg: string): void
}

export interface Clock {
  now(): number
  // Resolves after ms, or early when signal aborts. Never rejects.
  sleep(ms: number, signal: AbortSignal): Promise<void>
}

export const realClock: Clock = {
  now: () => Date.now(),
  sleep: (ms, signal) =>
    new Promise<void>((resolve) => {
      if (signal.aborted) return resolve()
      const t = setTimeout(done, ms)
      function done(): void {
        clearTimeout(t)
        signal.removeEventListener('abort', done)
        resolve()
      }
      signal.addEventListener('abort', done, { once: true })
    }),
}

export interface PollLoopOptions {
  api: BotApi
  offsets: OffsetStore
  status: StatusFile
  handler: UpdateHandler
  log: RelayLog
  clock?: Clock
  longPollTimeoutSec?: number
  limit?: number
  conflictRetryMs?: number
  backoffBaseMs?: number
  backoffCapMs?: number
  dropBacklogAtStart?: boolean
  maxHandlerAttempts?: number
  checkWebhookAtStart?: boolean
}

export type PollLoopExit =
  | { kind: 'stopped' }
  | { kind: 'refused'; reason: 'webhook_set' }
  | { kind: 'fatal'; reason: 'api_unauthorized' | 'api_fatal' | 'offset_unreadable' }

export const CONFLICT_RETRY_MS = 5 * 60 * 1000
export const DEFAULT_STOP_GRACE_MS = 9000

const ALERT_CONFLICT = 'permission_bot_relay_conflict'
const ALERT_REFUSED = 'permission_bot_relay_refused'

function isUpdateId(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
}

function errName(err: unknown): string {
  return err instanceof Error ? err.name : typeof err
}

export class PollLoop {
  private readonly api: BotApi
  private readonly offsets: OffsetStore
  private readonly status: StatusFile
  private readonly handler: UpdateHandler
  private readonly log: RelayLog
  private readonly clock: Clock
  private readonly longPollTimeoutSec: number
  private readonly limit: number
  private readonly conflictRetryMs: number
  private readonly backoffBaseMs: number
  private readonly backoffCapMs: number
  private readonly dropBacklogAtStart: boolean
  private readonly maxHandlerAttempts: number
  private readonly checkWebhookAtStart: boolean

  private stopping = false
  private readonly stopController = new AbortController()
  private readonly handlerController = new AbortController()
  private runPromise: Promise<PollLoopExit> | null = null
  private finished = false
  private current: RelayState = 'starting'

  constructor(opts: PollLoopOptions) {
    this.api = opts.api
    this.offsets = opts.offsets
    this.status = opts.status
    this.handler = opts.handler
    this.log = opts.log
    this.clock = opts.clock ?? realClock
    this.longPollTimeoutSec = opts.longPollTimeoutSec ?? 30
    this.limit = opts.limit ?? 100
    this.conflictRetryMs = opts.conflictRetryMs ?? CONFLICT_RETRY_MS
    this.backoffBaseMs = opts.backoffBaseMs ?? 1000
    this.backoffCapMs = opts.backoffCapMs ?? 60_000
    this.dropBacklogAtStart = opts.dropBacklogAtStart ?? true
    this.maxHandlerAttempts = Math.max(1, opts.maxHandlerAttempts ?? 3)
    this.checkWebhookAtStart = opts.checkWebhookAtStart ?? true
  }

  get state(): RelayState {
    return this.current
  }

  get isStopping(): boolean {
    return this.stopping
  }

  run(): Promise<PollLoopExit> {
    if (!this.runPromise) {
      this.runPromise = this.loop().finally(() => { this.finished = true })
    }
    return this.runPromise
  }

  // Idempotent. Resolves when the loop has finished or the grace period ended.
  async stop(graceMs = DEFAULT_STOP_GRACE_MS): Promise<{ drained: boolean }> {
    if (!this.stopping) {
      this.stopping = true
      if (!this.finished) this.setState('stopping', null)
      this.stopController.abort()
    }
    if (!this.runPromise || this.finished) return { drained: true }
    let timer: NodeJS.Timeout | undefined
    const graceOver = new Promise<'grace'>((resolve) => { timer = setTimeout(() => resolve('grace'), graceMs) })
    const r = await Promise.race([this.runPromise.then(() => 'done' as const, () => 'done' as const), graceOver])
    clearTimeout(timer)
    if (r === 'grace') {
      this.handlerController.abort()
      this.log.warn({ grace_ms: graceMs }, 'permission-bot-relay: stop grace period ended with a handler still running')
      return { drained: false }
    }
    return { drained: true }
  }

  private setState(state: RelayState, reason: string | null): void {
    this.current = state
    this.status.setState(state, reason)
  }

  private sleep(ms: number): Promise<void> {
    return this.clock.sleep(ms, this.stopController.signal)
  }

  private async loop(): Promise<PollLoopExit> {
    this.setState('starting', null)
    let backoff = this.backoffBaseMs

    // F1.3: a webhook means someone else receives the updates. Never delete it.
    if (this.checkWebhookAtStart) {
      for (;;) {
        if (this.stopping) return this.finishStopped()
        try {
          const info = await this.api.getWebhookInfo(this.stopController.signal)
          if (info.url) return this.refuseWebhook()
          break
        } catch (err) {
          const exit = await this.handleApiError(err, backoff)
          if (exit) return exit
          backoff = Math.min(backoff * 2, this.backoffCapMs)
        }
      }
    }

    let rec
    try {
      rec = this.offsets.read()
    } catch (err) {
      this.setState('refused', 'offset_unreadable')
      this.log.error({ alert: ALERT_REFUSED, reason: 'offset_unreadable', code: (err as NodeJS.ErrnoException).code ?? 'unknown' }, 'permission-bot-relay: offset file unreadable')
      return { kind: 'fatal', reason: 'offset_unreadable' }
    }
    if (rec.corrupt) this.log.warn({ reason: 'offset_file_corrupt' }, 'permission-bot-relay: offset file corrupt, starting without an offset')

    let offset: number | undefined = rec.offset ?? undefined
    let inflight: number | null = rec.inflight
    let draining = this.dropBacklogAtStart
    let dropped = 0
    const attempts = new Map<number, number>()

    const commit = (next: number | undefined, inflightId: number | null): void => {
      this.offsets.write({ offset: next ?? null, inflight: inflightId })
    }

    while (!this.stopping) {
      let updates: TelegramUpdate[]
      try {
        updates = await this.api.getUpdates(
          { offset, timeout: draining ? 0 : this.longPollTimeoutSec, limit: this.limit },
          this.stopController.signal,
        )
      } catch (err) {
        const exit = await this.handleApiError(err, backoff)
        if (exit) return exit
        if (err instanceof BotApiError && err.kind === 'transient') backoff = Math.min(backoff * 2, this.backoffCapMs)
        continue
      }

      if (this.current === 'conflict') this.log.info({}, 'permission-bot-relay: conflict cleared, polling again')
      backoff = this.backoffBaseMs
      this.status.pollOk()
      if (this.current !== 'polling') this.setState('polling', null)

      const batch = updates.filter((u) => {
        if (isUpdateId(u.update_id)) return true
        this.log.warn({ reason: 'malformed_update' }, 'permission-bot-relay: update without a valid update_id skipped')
        return false
      }).sort((a, b) => a.update_id - b.update_id)

      if (draining && batch.length === 0) {
        draining = false
        if (inflight !== null) inflight = null
        try { commit(offset, null) } catch { /* retried on the next commit */ }
        this.log.info({ dropped }, 'permission-bot-relay: start-up backlog dropped (K3)')
        continue
      }

      let retryAfterBackoff = false
      try {
        for (const u of batch) {
          if (this.stopping) break
          const id = u.update_id
          if (offset !== undefined && id < offset) continue

          if (draining && id !== inflight) {
            dropped++
            this.status.bump('dropped')
            offset = id + 1
            continue
          }

          if (!u.callback_query || typeof u.callback_query !== 'object') {
            // F4.4: not ours to handle, but the offset moves past it.
            commit(id + 1, draining ? inflight : null)
            offset = id + 1
            this.status.bump('ignored')
            continue
          }

          commit(offset, id)
          let outcome: HandlerOutcome
          try {
            outcome = await this.handler(u, { api: this.api, signal: this.handlerController.signal })
          } catch (err) {
            const n = (attempts.get(id) ?? 0) + 1
            attempts.set(id, n)
            this.status.bump('errors')
            if (n < this.maxHandlerAttempts) {
              this.log.warn({ update_id: id, attempt: n, err_name: errName(err) }, 'permission-bot-relay: handler failed, will retry')
              this.setState('degraded', 'handler_error')
              retryAfterBackoff = true
              break
            }
            this.log.error({ update_id: id, attempt: n, err_name: errName(err) }, 'permission-bot-relay: handler failed repeatedly, update skipped')
            attempts.delete(id)
            commit(id + 1, null)
            offset = id + 1
            if (inflight === id) inflight = null
            continue
          }
          attempts.delete(id)
          commit(id + 1, null)
          offset = id + 1
          if (inflight === id) inflight = null
          this.status.bump(outcome === 'processed' ? 'processed' : 'rejected')
        }
        if (draining) commit(offset, inflight)
      } catch (err) {
        // Offset/inflight write failed: do not go on without a durable offset.
        this.status.bump('errors')
        this.log.error({ reason: 'offset_write_failed', code: (err as NodeJS.ErrnoException).code ?? errName(err) }, 'permission-bot-relay: offset write failed')
        this.setState('degraded', 'offset_write_failed')
        retryAfterBackoff = true
      }

      if (retryAfterBackoff && !this.stopping) {
        await this.sleep(backoff)
        backoff = Math.min(backoff * 2, this.backoffCapMs)
      }
    }
    return this.finishStopped()
  }

  // Returns an exit for terminal errors; otherwise waits (backoff / conflict
  // window / retry_after) and returns null so the caller retries.
  private async handleApiError(err: unknown, backoff: number): Promise<PollLoopExit | null> {
    if (this.stopping) return this.finishStopped()
    const e = err instanceof BotApiError ? err : new BotApiError('transient', 'unknown', 'unexpected error')
    switch (e.kind) {
      case 'aborted':
        return this.finishStopped()
      case 'webhook_active':
        return this.refuseWebhook()
      case 'conflict':
        if (this.current !== 'conflict') {
          this.setState('conflict', 'getupdates_conflict')
          this.log.error({ alert: ALERT_CONFLICT, reason: 'getupdates_conflict', retry_ms: this.conflictRetryMs }, 'permission-bot-relay: another getUpdates consumer holds the permission bot; polling paused')
        } else {
          this.log.info({ reason: 'getupdates_conflict' }, 'permission-bot-relay: conflict persists')
        }
        await this.sleep(this.conflictRetryMs)
        return null
      case 'rate_limit': {
        // In the conflict state a 429 keeps it (no new alert) and the next try is
        // still no sooner than the conflict interval.
        const inConflict = this.current === 'conflict'
        const wait = inConflict
          ? this.conflictRetryMs
          : Math.min(Math.max((e.retryAfterSec ?? 0) * 1000, this.backoffBaseMs), this.conflictRetryMs)
        this.status.bump('errors')
        if (!inConflict) this.setState('degraded', 'rate_limited')
        this.log.warn({ reason: 'rate_limited', wait_ms: wait }, 'permission-bot-relay: rate limited')
        await this.sleep(wait)
        return null
      }
      case 'fatal': {
        const reason = e.status === 401 ? 'api_unauthorized' : 'api_fatal'
        this.setState('refused', reason)
        this.log.error({ alert: ALERT_REFUSED, reason, method: e.method, status: e.status ?? null, msg_masked: e.message }, 'permission-bot-relay: Bot API refused the token, not polling')
        return { kind: 'fatal', reason }
      }
      case 'transient':
      default:
        // In the conflict state a transient error keeps it (no new alert) and the
        // next try is still no sooner than the conflict interval.
        const waitMs = this.current === 'conflict' ? Math.max(backoff, this.conflictRetryMs) : backoff
        this.status.bump('errors')
        if (this.current !== 'conflict') this.setState('degraded', 'api_transient')
        this.log.warn({ reason: 'api_transient', method: e.method, wait_ms: waitMs, msg_masked: e.message }, 'permission-bot-relay: Bot API call failed, backing off')
        await this.sleep(waitMs)
        return null
    }
  }

  private refuseWebhook(): PollLoopExit {
    this.setState('refused', 'webhook_set')
    this.log.error({ alert: ALERT_REFUSED, reason: 'webhook_set' }, 'permission-bot-relay: a webhook is set on the permission bot; not polling and not deleting it')
    return { kind: 'refused', reason: 'webhook_set' }
  }

  private finishStopped(): PollLoopExit {
    this.setState('stopped', null)
    return { kind: 'stopped' }
  }
}

export interface SignalSource {
  on(signal: 'SIGTERM' | 'SIGINT', listener: () => void): unknown
  off(signal: 'SIGTERM' | 'SIGINT', listener: () => void): unknown
}

export interface ShutdownOptions {
  log: RelayLog
  lock?: RelayLock
  graceMs?: number
  signals?: SignalSource
  exit?: (code: number) => void
}

// SIGTERM/SIGINT -> stop the loop (drain), release the lock, exit. A second
// signal while draining is ignored; the grace period bounds the wait (< 10 s).
// Returns a detach function.
export function attachShutdownSignals(loop: PollLoop, opts: ShutdownOptions): () => void {
  const signals: SignalSource = opts.signals ?? process
  const exit = opts.exit ?? ((code: number) => process.exit(code))
  let started = false
  const onSignal = (name: 'SIGTERM' | 'SIGINT') => (): void => {
    if (started) return
    started = true
    opts.log.info({ signal: name }, 'permission-bot-relay: shutdown requested, draining')
    void loop.stop(opts.graceMs ?? DEFAULT_STOP_GRACE_MS).then((r) => {
      const released = opts.lock ? opts.lock.release() : false
      opts.log.info({ drained: r.drained, lock_released: released }, 'permission-bot-relay: shut down')
      exit(r.drained ? 0 : 1)
    })
  }
  const term = onSignal('SIGTERM')
  const int = onSignal('SIGINT')
  signals.on('SIGTERM', term)
  signals.on('SIGINT', int)
  return () => {
    signals.off('SIGTERM', term)
    signals.off('SIGINT', int)
  }
}
