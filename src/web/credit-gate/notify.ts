// Delivery of the gate's audit events to the main agent (card fec6335f, node N5,
// spec L-01, L-02).
//
// For every row of credit_gate_events not yet delivered: a line in the main
// agent's daily log, and -- by the event's class (audit.ts) -- an info message
// (createAgentMessage) or, when it asks for an action, an authenticated system
// directive (sendSystemDirective: the main agent can verify the queue row by
// msg_id). A delivery COUNTS only when a message id came back. A failure is
// retried at most NOTIFY_MAX_RETRIES times inside NOTIFY_WINDOW_MS of the first
// try, with a gap between tries; after that the event is `failed`: counted in
// the status (notify.failed) and logged once as an error. There is no loop:
// every event has a bounded number of tries and a closed end state.
//
// A round takes the rows in four classes, most urgent first, each with its own
// quota (DELIVERY_TIERS, B10): a backlog of one class -- a flood of Bearer
// signals or refusals -- never holds back the next, so a genuine INCIDENT goes
// out in the first round, inside L-01's 5 minutes. The last class is the kinds
// that coalesce (B12): there the quota counts the rows tried as messages, and a
// repeat of what was reported inside the window is marked in bulk (its daily
// line, then one UPDATE), so a flood of repeats is done in one round and holds
// back nothing.
//
// The row is CLAIMED (state `sending`, attempt counted) in one UPDATE before
// anything is sent, so two notifiers on one database, or an overlapping call,
// cannot send the same event twice; a claim that never reported back (a crash
// mid-send) is retried after NOTIFY_STALE_SENDING_MS.
//
// Nothing secret passes through here: the texts come from audit.ts (fixed words,
// numbers from the row, whitelisted and scrubbed fields), and the logs below
// carry event ids, kinds and counts only.

import type Database from 'better-sqlite3'
import { MAIN_AGENT_ID } from '../../config.js'
import { appendDailyLog, createAgentMessage, getDb } from '../../db.js'
import { logger } from '../../logger.js'
import { MAIN_CHANNELS_SESSION } from '../main-agent.js'
import {
  classifyEvent,
  COALESCE_WINDOW_MS,
  COALESCED_ROW_SQL,
  DIRECTIVE_ROW_SQL,
  formatEvent,
  isCoalescedKind,
  NOTIFY_MAX_RETRIES,
  NOTIFY_RETRY_GAP_MS,
  NOTIFY_STALE_SENDING_MS,
  NOTIFY_WINDOW_MS,
  recordApprovalMismatches,
  type CalibrationRef,
  type EventRow,
} from './audit.js'
import { summariseKeyReads } from './key-reads.js'

export interface NotifyDeps {
  readonly now?: () => number
  /** Queue an info message for the main agent; the new row's id, or nothing. */
  sendInfo(text: string): number | null | undefined
  /** Deliver an authenticated directive; the anchor row's id when it was injected, else nothing. May throw. */
  sendDirective(text: string): Promise<number | null | undefined>
  /** Append to the main agent's daily log. May throw. */
  dailyLog(text: string): void
}

export interface DeliverResult {
  /** Delivered with a returned id. */
  readonly sent: number
  /** Failed this round, will be tried again. */
  readonly retrying: number
  /** Out of tries this round: now `failed`. */
  readonly failed: number
  /** Audit rows that need no message. */
  readonly skipped: number
  /** Repeats of a refusal already reported inside the window. */
  readonly coalesced: number
}

type Tally = { -readonly [K in keyof DeliverResult]: DeliverResult[K] }

/** Rows per class and round; in the last class, rows tried as messages (a coalesced repeat is free, B12). */
const BATCH = 50
/** Rows read per page when the last class looks for repeats. */
const REPEAT_PAGE = 500

/**
 * The classes of a round, in order, as SQL conditions (B10, B12): the
 * directives (an INCIDENT, the lowcal request), then every other state change,
 * then the rest, then the kinds that coalesce. Every row is in exactly one;
 * inside a class the order is the id.
 */
export const DELIVERY_TIERS: readonly string[] = [
  DIRECTIVE_ROW_SQL,
  `(NOT ${DIRECTIVE_ROW_SQL}) AND kind = 'transition'`,
  `(NOT ${DIRECTIVE_ROW_SQL}) AND kind <> 'transition' AND (NOT ${COALESCED_ROW_SQL})`,
  `(NOT ${DIRECTIVE_ROW_SQL}) AND ${COALESCED_ROW_SQL}`,
]
const COALESCED_TIER = DELIVERY_TIERS[DELIVERY_TIERS.length - 1] as string

/** Due for a try: new, waiting for a retry, or a claim that never reported back. */
const DUE_SQL = `(notify_state IS NULL OR notify_state = 'retry' OR (notify_state = 'sending' AND notify_last_at <= ?))`

/** The words that mark a coalesced repeat's daily line. */
const COALESCED_DAILY_MARK = 'osszevont ismetles'

/** A coalesced repeat's daily line: the event's own, marked as a repeat. */
function repeatLine(daily: string): string {
  return `${daily}\n(${COALESCED_DAILY_MARK}: az elozo jelentes ismetlese, uzenet nem ment)`
}

/** A usable message id: a positive integer. */
function validId(id: unknown): id is number {
  return typeof id === 'number' && Number.isSafeInteger(id) && id > 0
}

export class AuditNotifier {
  private running: Promise<DeliverResult> | null = null

  constructor(private readonly db: Database.Database, private readonly deps: NotifyDeps) {}

  /** One round; calls that overlap share it. Never throws. */
  deliver(): Promise<DeliverResult> {
    if (this.running === null) {
      this.running = this.round().finally(() => { this.running = null })
    }
    return this.running
  }

  private nowMs(): number {
    return (this.deps.now ?? Date.now)()
  }

  private async round(): Promise<DeliverResult> {
    const res: Tally = { sent: 0, retrying: 0, failed: 0, skipped: 0, coalesced: 0 }
    try {
      const now = this.nowMs()
      // New events first: the payload mismatches and the finished days of key reads.
      for (const sweep of [() => recordApprovalMismatches(this.db, now), () => summariseKeyReads(this.db, now)]) {
        try {
          sweep()
        } catch (err) {
          logger.error({ errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: an audit sweep failed')
        }
      }
      // The last class works up to the newest row of now: a flood arriving meanwhile waits for the next round.
      const top = (this.db.prepare('SELECT COALESCE(MAX(id), 0) AS id FROM credit_gate_events').get() as { id: number }).id
      const rows: EventRow[] = []
      for (const tier of DELIVERY_TIERS.slice(0, -1)) {
        rows.push(...this.db.prepare(`SELECT * FROM credit_gate_events WHERE ${DUE_SQL} AND ${tier} ORDER BY id LIMIT ?`)
          .all(now - NOTIFY_STALE_SENDING_MS, BATCH) as EventRow[])
      }
      for (const ev of rows) await this.oneSafely(ev, res)
      await this.coalescedClass(top, res)
    } catch (err) {
      logger.error({ errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: the audit delivery round failed')
    }
    return res
  }

  private async oneSafely(ev: EventRow, res: Tally): Promise<void> {
    try {
      await this.one(ev, res)
    } catch (err) {
      // The bookkeeping itself failed (a locked database): the row stays as it is and is looked at again next round.
      logger.error({ eventId: ev.id, errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: the audit delivery could not be recorded')
    }
  }

  /**
   * The last class (B12): the kinds that coalesce, up to `top`. The repeats of
   * what was reported before are marked first; then row by row in id order, and
   * after every message its own repeats. BATCH counts the rows tried as
   * messages, so the repeats -- however many -- take no share of the round.
   */
  private async coalescedClass(top: number, res: Tally): Promise<void> {
    this.coalesceRepeatsSafely(top, null, res)
    let cursor = 0
    let tried = 0
    while (tried < BATCH) {
      const ev = this.db.prepare(`SELECT * FROM credit_gate_events WHERE id > ? AND id <= ? AND ${DUE_SQL} AND ${COALESCED_TIER} ORDER BY id LIMIT 1`)
        .get(cursor, top, this.nowMs() - NOTIFY_STALE_SENDING_MS) as EventRow | undefined
      if (!ev) return
      cursor = ev.id
      const coalescedBefore = res.coalesced
      await this.oneSafely(ev, res)
      if (res.coalesced === coalescedBefore) tried++
      const after = this.db.prepare('SELECT notify_state FROM credit_gate_events WHERE id = ?').get(ev.id) as { notify_state: string | null } | undefined
      if (after?.notify_state === 'sent') this.coalesceRepeatsSafely(top, ev, res)
    }
  }

  private coalesceRepeatsSafely(top: number, of: EventRow | null, res: Tally): void {
    try {
      this.coalesceRepeats(top, of, res)
    } catch (err) {
      // A locked database: the rows go the one-by-one way, or wait for the next round.
      logger.error({ eventId: of?.id ?? null, errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: the coalesced repeats could not be recorded')
    }
  }

  /**
   * Every new row of the last class up to `top` that repeats a reported one --
   * coalesces(): the same kind and reason, inside the window of the newest one
   * sent before it -- after `of` and of its kind and reason, or all of them.
   * Read page by page in id order; the rows sent so far are read once per kind
   * and reason (they are few: one per window), so the pass is linear in the
   * rows it looks at. The repeats of a page are claimed in one UPDATE (two
   * notifiers never log one row twice), then each gets its daily line (L-01:
   * every rejection has one, marked as a repeat), then one UPDATE marks them.
   * A daily line that cannot be written ends the pass: that row and the rest of
   * the claim are failed attempts, retried one by one like any other.
   */
  private coalesceRepeats(top: number, of: EventRow | null, res: Tally): void {
    const group = of === null ? '' : ' AND kind = @kind AND reason IS @reason'
    const pageOf = this.db.prepare(`SELECT * FROM credit_gate_events
        WHERE notify_state IS NULL AND id > @cursor AND id <= @top AND ${COALESCED_TIER}${group}
        ORDER BY id LIMIT @page`)
    const sentOf = this.db.prepare(`SELECT id, at FROM credit_gate_events WHERE kind = ? AND reason IS ? AND notify_state = 'sent' ORDER BY id`)
    const claim = this.db.prepare(`UPDATE credit_gate_events
        SET notify_state = 'sending', notify_attempts = notify_attempts + 1, notify_first_at = COALESCE(notify_first_at, @now), notify_last_at = @now
        WHERE notify_state IS NULL AND id IN (SELECT value FROM json_each(@ids))
        RETURNING *`)
    const finish = this.db.prepare(`UPDATE credit_gate_events SET notify_state = 'coalesced', daily_logged = 1
        WHERE notify_state = 'sending' AND id IN (SELECT value FROM json_each(?))`)
    // Per kind and reason: the sent rows' ids, ascending, and the largest `at` up to each.
    const sent = new Map<string, { ids: number[]; maxAt: number[] }>()
    const lastSentBefore = (ev: EventRow): number | null => {
      const key = JSON.stringify([ev.kind, ev.reason])
      let ref = sent.get(key)
      if (!ref) {
        ref = { ids: [], maxAt: [] }
        for (const r of sentOf.all(ev.kind, ev.reason) as Array<{ id: number; at: number }>) {
          ref.ids.push(r.id)
          ref.maxAt.push(Math.max(r.at, ref.maxAt[ref.maxAt.length - 1] ?? r.at))
        }
        sent.set(key, ref)
      }
      let lo = 0
      let hi = ref.ids.length
      while (lo < hi) {
        const mid = (lo + hi) >> 1
        if ((ref.ids[mid] as number) < ev.id) lo = mid + 1
        else hi = mid
      }
      return lo === 0 ? null : (ref.maxAt[lo - 1] as number)
    }
    let cursor = of?.id ?? 0
    for (;;) {
      const page = pageOf.all({ cursor, top, page: REPEAT_PAGE, ...(of === null ? {} : { kind: of.kind, reason: of.reason }) }) as EventRow[]
      if (page.length === 0) return
      cursor = (page[page.length - 1] as EventRow).id
      const repeats = page.filter((ev) => {
        const last = lastSentBefore(ev)
        return last !== null && ev.at >= last && ev.at - last < COALESCE_WINDOW_MS
      }).map((ev) => ev.id)
      if (repeats.length > 0) {
        const claimed = (claim.all({ now: this.nowMs(), ids: JSON.stringify(repeats) }) as EventRow[]).sort((a, b) => a.id - b.id)
        const done: number[] = []
        let broken = -1
        for (let i = 0; i < claimed.length; i++) {
          const ev = claimed[i] as EventRow
          const plan = classifyEvent(ev)
          try {
            if (plan.daily && ev.daily_logged === 0) this.deps.dailyLog(repeatLine(formatEvent(ev, this.calibrationOf(ev.calibration_id), plan).daily))
            done.push(ev.id)
          } catch (err) {
            logger.warn({ eventId: ev.id, attempt: ev.notify_attempts, left: claimed.length - i, errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: the daily line of a coalesced audit event could not be written')
            broken = i
            break
          }
        }
        if (done.length > 0) res.coalesced += finish.run(JSON.stringify(done)).changes
        if (broken >= 0) {
          for (const ev of claimed.slice(broken)) this.retryOrFail(ev.id, ev.notify_attempts, res)
          return
        }
      }
      if (page.length < REPEAT_PAGE) return
    }
  }

  /** Claim the row for one try; false when it is not due, was taken, or ran out of tries. */
  private claim(ev: EventRow, now: number, res: { failed: number }): boolean {
    const state = ev.notify_state
    if (state === 'retry' || state === 'sending') {
      if (ev.notify_first_at !== null && now - ev.notify_first_at > NOTIFY_WINDOW_MS) {
        this.markFailed(ev.id, ev.notify_attempts, now)
        res.failed++
        return false
      }
      if (state === 'retry' && ev.notify_last_at !== null && now - ev.notify_last_at < NOTIFY_RETRY_GAP_MS) return false
    }
    const changes = this.db.prepare(`UPDATE credit_gate_events
        SET notify_state = 'sending', notify_attempts = notify_attempts + 1, notify_first_at = COALESCE(notify_first_at, ?), notify_last_at = ?
        WHERE id = ? AND notify_attempts = ? AND notify_state IS ?`)
      .run(now, now, ev.id, ev.notify_attempts, state).changes
    return changes === 1
  }

  private markFailed(id: number, attempts: number, now: number): void {
    this.db.prepare("UPDATE credit_gate_events SET notify_state = 'failed', notify_last_at = ? WHERE id = ?").run(now, id)
    const kind = (this.db.prepare('SELECT kind FROM credit_gate_events WHERE id = ?').get(id) as { kind: string } | undefined)?.kind
    logger.error({ eventId: id, kind, attempts }, 'credit gate: an audit event could not be delivered to the main agent (see notify.failed in the status)')
  }

  private calibrationOf(id: number | null): CalibrationRef | null {
    if (id === null) return null
    try {
      const c = this.db.prepare('SELECT id, captured_at_lb, approval_id FROM credit_calibrations WHERE id = ?').get(id) as CalibrationRef | undefined
      return c ?? null
    } catch {
      return null
    }
  }

  /** Reported already: an earlier event of the same kind and reason inside the window. */
  private coalesces(ev: EventRow): boolean {
    if (!isCoalescedKind(ev.kind)) return false
    const last = this.db.prepare(`SELECT MAX(at) AS at FROM credit_gate_events
        WHERE kind = ? AND reason IS ? AND notify_state = 'sent' AND id < ?`).get(ev.kind, ev.reason, ev.id) as { at: number | null }
    return last.at !== null && ev.at >= last.at && ev.at - last.at < COALESCE_WINDOW_MS
  }

  private async one(ev: EventRow, res: Tally): Promise<void> {
    const now = this.nowMs()
    if (!this.claim(ev, now, res)) return
    const attempts = ev.notify_attempts + 1
    const plan = classifyEvent(ev)

    const text = formatEvent(ev, this.calibrationOf(ev.calibration_id), plan)

    if (this.coalesces(ev)) {
      // No message, but L-01 wants a daily line for every rejection: one line per event, marked as a repeat.
      try {
        if (plan.daily && ev.daily_logged === 0) this.deps.dailyLog(repeatLine(text.daily))
        this.db.prepare("UPDATE credit_gate_events SET notify_state = 'coalesced', daily_logged = 1 WHERE id = ?").run(ev.id)
        res.coalesced++
        return
      } catch (err) {
        logger.warn({ eventId: ev.id, attempt: attempts, errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: the daily line of a coalesced audit event could not be written')
        this.retryOrFail(ev.id, attempts, res)
        return
      }
    }

    let id: unknown = null
    try {
      if (plan.daily && ev.daily_logged === 0) {
        this.deps.dailyLog(text.daily)
        this.db.prepare('UPDATE credit_gate_events SET daily_logged = 1 WHERE id = ?').run(ev.id)
      }
      if (plan.notify === 'none') {
        this.db.prepare("UPDATE credit_gate_events SET notify_state = 'skipped' WHERE id = ?").run(ev.id)
        res.skipped++
        return
      }
      id = plan.notify === 'directive' ? await this.deps.sendDirective(text.message) : this.deps.sendInfo(text.message)
    } catch (err) {
      logger.warn({ eventId: ev.id, attempt: attempts, errorName: err instanceof Error ? err.name : typeof err }, 'credit gate: an audit delivery attempt threw')
      id = null
    }

    if (validId(id)) {
      this.db.prepare("UPDATE credit_gate_events SET notify_state = 'sent', notified_msg_id = ? WHERE id = ?").run(id, ev.id)
      res.sent++
      return
    }
    this.retryOrFail(ev.id, attempts, res)
  }

  /** A failed attempt: another try later, or `failed` once the tries are used up. */
  private retryOrFail(id: number, attempts: number, res: { retrying: number; failed: number }): void {
    if (attempts >= 1 + NOTIFY_MAX_RETRIES) {
      this.markFailed(id, attempts, this.nowMs())
      res.failed++
      return
    }
    this.db.prepare("UPDATE credit_gate_events SET notify_state = 'retry', notify_last_at = ? WHERE id = ?").run(this.nowMs(), id)
    res.retrying++
  }
}

/**
 * The deliverers on the dashboard's own database and queue: an info message is
 * a queue row from `system` to the main agent; a directive is sendSystemDirective
 * into the main channels session, and counts only when its anchor row exists AND
 * the injection said `sent`. `sendSystemDirective` is loaded on first use (it
 * pulls the whole agent-process module) and can be replaced for tests.
 */
export function defaultNotifyDeps(over: { sendSystemDirective?: (to: string, session: string, text: string) => Promise<string> } = {}): NotifyDeps {
  const maxMessageId = (): number => (getDb().prepare('SELECT COALESCE(MAX(id), 0) AS id FROM agent_messages').get() as { id: number }).id
  return {
    now: Date.now,
    sendInfo: (text) => createAgentMessage('system', MAIN_AGENT_ID, text).id,
    sendDirective: async (text) => {
      const send = over.sendSystemDirective ?? (await import('../system-directive.js')).sendSystemDirective
      const before = maxMessageId()
      // The anchor row is written synchronously inside the call, before its first await.
      const pending = send(MAIN_AGENT_ID, MAIN_CHANNELS_SESSION, text)
      const row = getDb().prepare(`SELECT id FROM agent_messages WHERE id > ? AND from_agent = 'system' AND to_agent = ? AND content = ? ORDER BY id DESC LIMIT 1`)
        .get(before, MAIN_AGENT_ID, text) as { id: number } | undefined
      const outcome = await pending
      return outcome === 'sent' && row ? row.id : null
    },
    dailyLog: (text) => appendDailyLog(MAIN_AGENT_ID, text),
  }
}
