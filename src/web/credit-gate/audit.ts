// What the gate's audit rows say, and to whom (card fec6335f, node N5, spec L-01..L-03).
//
// credit_gate_events is the audit outbox: the gate (N2a) and the calibration
// processor (N2c) write a row for everything that matters; notify.ts delivers
// it. This module is the pure part: which event asks for what (classifyEvent),
// how it reads (formatEvent -- fixed words, numbers from the row, no value of
// any kind), the sweep that turns an approval the system closed as a payload
// mismatch into an event, and the read-only view the status endpoint and the
// /status row show.
//
// Nothing here sends anything. Text is plain ASCII Hungarian, like the other
// system messages to the main agent.

import type Database from 'better-sqlite3'
import { APP_TZ } from '../../config.js'
import { PAYLOAD_MISMATCH_RESOLVER } from '../../db.js'
import { logger } from '../../logger.js'
import { isCreditGateCategory } from './approval-payload.js'
import { formatUsd, isGuardName, scrubDetail } from './gate.js'
import { budapestDay, keyReadsView, type KeyReadsView } from './key-reads.js'
import type { CreditGateRuntime } from './runtime.js'

/** One try plus this many retries per event (L-02). */
export const NOTIFY_MAX_RETRIES = 3
/** Retries happen only inside this window after the first try (L-01: 5 minutes). */
export const NOTIFY_WINDOW_MS = 5 * 60_000
/** The least time between two tries of the same event. */
export const NOTIFY_RETRY_GAP_MS = 20_000
/** The same refusal, repeated inside this window of the last one reported, is an audit row only. */
export const COALESCE_WINDOW_MS = 10 * 60_000
/** A try that never reported back (a crash mid-send) is retried after this long. */
export const NOTIFY_STALE_SENDING_MS = 2 * 60_000

export type NotifyClass = 'none' | 'info' | 'directive'
export interface EventPlan {
  readonly notify: NotifyClass
  /** A line in the main agent's daily log. */
  readonly daily: boolean
}

const INFO: EventPlan = { notify: 'info', daily: true }
const DIRECTIVE: EventPlan = { notify: 'directive', daily: true }
/** Audit row and a daily line, no message. */
const QUIET: EventPlan = { notify: 'none', daily: true }
/** Audit row only (high volume bookkeeping). */
const SILENT: EventPlan = { notify: 'none', daily: false }

const KIND_PLANS: Readonly<Record<string, EventPlan>> = {
  incident_cause: DIRECTIVE,
  lowcal_request: DIRECTIVE,
  lowcal_fallback: INFO,
  fault: INFO,
  batch_overrun: INFO,
  reservation_unknown: INFO,
  guard_damage: INFO,
  guard_event: INFO,
  stop_race: INFO,
  stop_exists: INFO,
  stop_place_failed: INFO,
  reservation_rejected: INFO,
  signal: INFO,
  incident_clear_refused: INFO,
  owner_changed: INFO,
  owner_change_reverted: INFO,
  calibration_error: INFO,
  canary_evaluated: INFO,
  calibration_incident: INFO,
  calibration_hold: INFO,
  calibration_rejected: INFO,
  grant_model_bad: INFO,
  grant_button_required: INFO,
  approval_payload_mismatch: INFO,
  reservation_bound: SILENT,
  reservation_released: SILENT,
  reservation_settled: SILENT,
  stop_placed: QUIET,
  stop_released: QUIET,
  incident_cause_cleared: QUIET,
  incident_clear: QUIET,
  owner_change_cleared: QUIET,
  canary_consumed: QUIET,
  canary_window_opened: QUIET,
  canary_window_closed: QUIET,
  calibration: QUIET,
  grant_enforce: QUIET,
  grant_period: QUIET,
  guard_baseline: QUIET,
  key_reads_daily: QUIET,
}

/** Every kind classified on purpose (a test checks the gate's own kinds against it). */
export const CLASSIFIED_KINDS: ReadonlySet<string> = new Set([...Object.keys(KIND_PLANS), 'transition'])

/**
 * Kinds that can repeat every tick or every request: reported once per window
 * and reason. A `signal` is one row per POST of any Bearer caller (B10); its
 * reason is the signal kind, so the caller's source and detail do not make a
 * repeat news. A transition and an INCIDENT cause are never coalesced.
 */
const COALESCED_KINDS: ReadonlySet<string> = new Set(['reservation_rejected', 'fault', 'signal'])
export function isCoalescedKind(kind: string): boolean {
  return COALESCED_KINDS.has(kind)
}

/**
 * isCoalescedKind(row.kind) as an SQL condition: the notifier's last class
 * (B12), where a repeat costs no share of the round. Same inlining as
 * DIRECTIVE_ROW_SQL (this module's own [a-z_] literals).
 */
export const COALESCED_ROW_SQL = `(kind IN (${[...COALESCED_KINDS].map((k) => `'${k}'`).join(', ')}))`

export function classifyEvent(ev: { readonly kind: string; readonly to_state: string | null; readonly reason: string | null }): EventPlan {
  if (ev.kind === 'transition') return ev.to_state === 'INCIDENT' ? DIRECTIVE : INFO
  return KIND_PLANS[ev.kind] ?? INFO
}

/**
 * classifyEvent(row).notify === 'directive' as an SQL condition over a
 * credit_gate_events row (never NULL), for the notifier's order (B10, L-01).
 * The kinds are this module's own literals ([a-z_]), inlined; a test checks it
 * against classifyEvent for every classified kind.
 */
export const DIRECTIVE_ROW_SQL = `(kind IN (${Object.keys(KIND_PLANS).filter((k) => KIND_PLANS[k]?.notify === 'directive').map((k) => `'${k}'`).join(', ')})`
  + ` OR (kind = 'transition' AND to_state IS 'INCIDENT'))`

export interface EventRow {
  readonly id: number
  readonly at: number
  readonly kind: string
  readonly from_state: string | null
  readonly to_state: string | null
  readonly reason: string | null
  readonly r_est_micro: number | null
  readonly l_micro: number | null
  readonly ledger_age_s: number | null
  readonly open_res_micro: number | null
  readonly calibration_id: number | null
  readonly detail_json: string | null
  readonly notified_msg_id: number | null
  readonly daily_logged: number
  readonly notify_state: string | null
  readonly notify_attempts: number
  readonly notify_first_at: number | null
  readonly notify_last_at: number | null
}

export interface CalibrationRef {
  readonly id: number
  readonly captured_at_lb: number
  readonly approval_id: string | null
}

/** The fixed words for an approval the system rejected because its content changed after the button message. */
export const PAYLOAD_MISMATCH_TEXT =
  'A jovahagyasi kerelem tartalma a gombos uzenet kikuldese utan megvaltozott; a kapu automatikusan elutasitotta. A kapu allapota nem valtozott, nem nyitott.'

const TITLES: Readonly<Record<string, string>> = {
  transition: 'kapu-atmenet',
  incident_cause: 'uj INCIDENT-ok',
  lowcal_request: 'alacsony kredit, friss leolvasas kell',
  lowcal_fallback: 'a leolvasas elmaradt, szigorubb kuszob',
  fault: 'belso hiba (a kapu zarva tart)',
  batch_overrun: 'batch-tullepes',
  reservation_unknown: 'ismeretlen kimenetu foglalas',
  guard_damage: 'orzo-fajl serult',
  guard_event: 'orzo-riasztas',
  stop_race: 'STOP-verseny',
  stop_exists: 'mar volt STOP, a kapu nem tulajdonos',
  stop_place_failed: 'a STOP nem irhato',
  reservation_rejected: 'foglalas elutasitva',
  signal: 'jel a kapunak',
  incident_clear_refused: 'incident-clear elutasitva',
  owner_changed: 'a tulajdonos megvaltozott',
  owner_change_reverted: 'a tulajdonos-valtozas visszaallt',
  calibration_error: 'kalibracio-hiba',
  canary_evaluated: 'kanari kiertekelve',
  calibration: 'kalibracio elfogadva',
  calibration_incident: 'kalibracio: vedett tarolo csokkent',
  calibration_hold: 'kalibracio: nem eldontheto, HOLD',
  calibration_rejected: 'kalibracio elutasitva',
  grant_model_bad: 'grant-modell: a rekonstrualt fajl nem hasznalhato, HOLD',
  grant_button_required: 'grant-modell: a lanc all, csak uj enforce-gomb nyit (401, disarm, stop vagy fuggo HOLD)',
  grant_enforce: 'grant-modell: enforce-gomb felhasznalva, elso periodus',
  grant_period: 'grant-modell: uj periodus',
  approval_payload_mismatch: 'jovahagyas automatikusan elutasitva (a tartalom megvaltozott)',
  stop_placed: 'STOP lerakva',
  stop_released: 'STOP leszedve',
  incident_cause_cleared: 'INCIDENT-ok feloldva',
  incident_clear: 'incident-clear',
  owner_change_cleared: 'tulajdonos-valtozas feloldva',
  canary_consumed: 'kanari-jovahagyas felhasznalva',
  canary_window_opened: 'kanari-ablak nyitva (a batch-ut STOP-on, az utana-leolvasasig)',
  canary_window_closed: 'kanari-ablak lezarva (utana-leolvasas rogzitve)',
  guard_baseline: 'orzo alapallapot',
  key_reads_daily: 'kulcs-olvasasok napi osszesito',
  reservation_bound: 'foglalas kotve',
  reservation_released: 'foglalas felszabaditva',
  reservation_settled: 'foglalas elszamolva',
}

/** The action a directive asks for. */
function actionFor(ev: EventRow): string {
  if (ev.kind === 'lowcal_request') {
    return 'TEENDO: kerj Gyuritol friss Console-leolvasast (kalibracio) a keretrol; amig nincs, a kapu a szigorubb kuszobbel zar.'
  }
  return 'TEENDO: vizsgald meg az INCIDENT okat; nyitni csak a tulajdonos jovahagyasa (incident-clear, majd uj kalibracio) tud. Ne probald megkerulni.'
}

/**
 * Detail fields that may reach a message: names, ids and counts the gate itself
 * validated -- never a free text. A signal's `detail` is typed by whoever calls
 * the endpoint, and a directive is the main agent's authenticated channel: caller
 * text must not ride on it, so it stays in the audit row and out of the messages.
 * A signal's INCIDENT names that row by `signal_event_id` (B10).
 */
const DETAIL_KEYS = ['kind', 'caller', 'source', 'agent', 'reservation_id', 'approval_id', 'category', 'how', 'why', 'error', 'where', 'outcome', 'signal_event_id'] as const

/**
 * The signal sources the system itself uses (the headless runner's SIGNAL_SOURCE).
 * POST /api/credit-gate/signals takes any 64-character source from any Bearer
 * caller, so in a directive (the main agent's authenticated channel) a source
 * outside this list is the fixed word below; an info message keeps the raw one.
 */
const KNOWN_SIGNAL_SOURCES: ReadonlySet<string> = new Set(['headless-runner'])
const UNKNOWN_SOURCE_WORD = 'egyeb'

function safe(v: unknown, max = 120): string | null {
  if (typeof v === 'string') return scrubDetail(v, max)
  if (typeof v === 'number' && Number.isFinite(v)) return String(v)
  if (typeof v === 'boolean') return String(v)
  return null
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i

/** An approval or reservation id: a UUID as it is (the key scrub would eat its 36 characters), anything else scrubbed. */
function safeId(v: unknown): string | null {
  return typeof v === 'string' && UUID_RE.test(v) ? v : safe(v, 64)
}

function parseDetail(json: string | null): Record<string, unknown> {
  if (json === null) return {}
  try {
    const o: unknown = JSON.parse(json)
    return typeof o === 'object' && o !== null && !Array.isArray(o) ? (o as Record<string, unknown>) : {}
  } catch {
    return {}
  }
}

function usd(micro: number | null): string {
  if (micro === null || micro === undefined) return 'n/a'
  try {
    return `${formatUsd(micro)} USD`
  } catch {
    return 'n/a'
  }
}

function isoOf(ms: number): string {
  return new Date(ms).toISOString()
}

function clock(ms: number): string {
  return new Intl.DateTimeFormat('hu-HU', { timeZone: APP_TZ, hour: '2-digit', minute: '2-digit', hour12: false }).format(new Date(ms))
}

export interface FormattedEvent {
  /** The message to the main agent. */
  readonly message: string
  /** The daily-log entry. */
  readonly daily: string
}

/** The text of one event. Every dynamic piece is a number from the row or a scrubbed, whitelisted string. */
export function formatEvent(ev: EventRow, cal: CalibrationRef | null, plan: EventPlan = classifyEvent(ev)): FormattedEvent {
  const title = TITLES[ev.kind] ?? scrubDetail(ev.kind, 60) ?? 'esemeny'
  const detail = parseDetail(ev.detail_json)
  const lines: string[] = []

  if (ev.kind === 'key_reads_daily') {
    const day = safe(detail.day, 10) ?? '?'
    const total = typeof detail.total === 'number' && Number.isFinite(detail.total) ? detail.total : 0
    const by = typeof detail.by_principal === 'object' && detail.by_principal !== null ? detail.by_principal as Record<string, unknown> : {}
    const parts = Object.keys(by).sort().map((k) => `${scrubDetail(k, 64)}=${safe(by[k], 12)}`)
    const line = `kulcs-olvasasok ${day}: ${total} olvasas${parts.length > 0 ? ` (${parts.join(', ')})` : ''}`
    return { message: `[KREDIT-KAPU] ${line}`, daily: `## ${clock(ev.at)} -- kredit-kapu: ${title}\n${line}` }
  }

  if (ev.from_state !== null || ev.to_state !== null) {
    lines.push(`atmenet: ${scrubDetail(ev.from_state ?? '?', 20)} -> ${scrubDetail(ev.to_state ?? '?', 20)}`)
  }
  lines.push(`ok: ${ev.reason === null ? 'n/a' : scrubDetail(ev.reason, 80)}`)
  if (ev.kind === 'approval_payload_mismatch') {
    lines.push(PAYLOAD_MISMATCH_TEXT)
    lines.push(`approval: ${safeId(detail.approval_id) ?? '?'}`)
    lines.push(`kategoria: ${safe(detail.category, 64) ?? '?'}`)
  } else {
    const parts: string[] = []
    for (const k of DETAIL_KEYS) {
      let v = k === 'approval_id' || k === 'reservation_id' ? safeId(detail[k]) : safe(detail[k])
      if (k === 'source' && v !== null && plan.notify === 'directive' && !KNOWN_SIGNAL_SOURCES.has(v)) v = UNKNOWN_SOURCE_WORD
      if (v !== null && v !== '') parts.push(`${k}=${v}`)
    }
    // The guard's env names (never values): a short list of identifiers.
    if (Array.isArray(detail.names)) {
      const names = detail.names.filter((n): n is string => isGuardName(n) && !/sk-ant/i.test(n)).slice(0, 8)
      if (names.length > 0) parts.push(`names=${names.join(',')}`)
    }
    if (parts.length > 0) lines.push(`reszletek: ${parts.join(' ')}`)
  }
  lines.push([
    `R_est: ${usd(ev.r_est_micro)}`,
    `L: ${usd(ev.l_micro)}`,
    `ledger-kor: ${ev.ledger_age_s === null ? 'n/a' : `${ev.ledger_age_s} s`}`,
    `nyitott foglalas: ${usd(ev.open_res_micro)}`,
  ].join(' | '))
  if (ev.calibration_id === null) lines.push('kalibracio: nincs')
  else if (cal === null) lines.push(`kalibracio: #${ev.calibration_id}`)
  else {
    const src = cal.approval_id === null ? 'ismeretlen' : `approval ${(safeId(cal.approval_id) ?? '?').slice(0, 8)}`
    lines.push(`kalibracio: #${cal.id} (olvasas ideje, legkorabbi: ${isoOf(cal.captured_at_lb)}, forras: ${src})`)
  }
  lines.push(`esemeny: #${ev.id} ${scrubDetail(ev.kind, 60)} ${isoOf(ev.at)}`)
  if (plan.notify === 'directive') lines.push(actionFor(ev))

  const body = lines.join('\n')
  return {
    message: `[KREDIT-KAPU] ${title}\n${body}`,
    daily: `## ${clock(ev.at)} -- kredit-kapu: ${title}\n${body}`,
  }
}

// ------------------------------------------------- payload_mismatch sweep

/**
 * N2b closes a credit-gate approval whose payload no longer binds its hash
 * (resolved_by system:payload_mismatch) right at the owner's button press. The
 * owner sees only "changed, rejected" on the button; this makes it an audit
 * event so the main agent hears about it too. Idempotent: an approval is an
 * event once. The row's own closing time is the event's time. A database with
 * no approvals table (the gate on another handle) has nothing to sweep.
 */
export function recordApprovalMismatches(db: Database.Database, nowMs: number): number {
  let rows: Array<{ id: string; category: string; resolved_at: number | null }>
  try {
    rows = db.prepare(`SELECT a.id, a.category, a.resolved_at FROM approvals a
        WHERE a.resolved_by = ? AND a.category LIKE 'credit\\_gate\\_%' ESCAPE '\\'
          AND NOT EXISTS (SELECT 1 FROM credit_gate_events e
                           WHERE e.kind = 'approval_payload_mismatch' AND json_extract(e.detail_json, '$.approval_id') = a.id)
        ORDER BY a.resolved_at, a.id LIMIT 50`).all(PAYLOAD_MISMATCH_RESOLVER) as typeof rows
  } catch (err) {
    if (/no such table: approvals/i.test(String((err as Error)?.message))) return 0
    throw err
  }
  let n = 0
  const ins = db.prepare(`INSERT INTO credit_gate_events (at, kind, reason, detail_json) VALUES (?, 'approval_payload_mismatch', 'payload_mismatch', ?)`)
  db.transaction(() => {
    for (const r of rows) {
      if (!isCreditGateCategory(r.category)) continue
      const at = typeof r.resolved_at === 'number' && r.resolved_at > 0 ? r.resolved_at * 1000 : nowMs
      ins.run(at, JSON.stringify({ approval_id: r.id, category: r.category }))
      n++
    }
  })()
  if (n > 0) logger.warn({ count: n }, 'credit gate: approvals closed by the system for a changed payload were recorded')
  return n
}

// ------------------------------------------------------------ status view

export interface AuditView {
  readonly notify: { readonly failed: number; readonly pending: number; readonly last_failed_at: string | null }
  readonly approvals: { readonly payload_mismatch: { readonly count: number; readonly last_at: string | null } }
  readonly key_reads: KeyReadsView
  readonly last_event: { readonly id: number; readonly at: string; readonly kind: string; readonly reason: string | null; readonly notify_state: string | null } | null
}

function iso(ms: number | null | undefined): string | null {
  return typeof ms === 'number' && Number.isFinite(ms) ? new Date(ms).toISOString() : null
}

/** Read-only; never throws: no database, no tables, or an older table all read as zeros. */
export function auditStatus(db: Database.Database | null, nowMs: number): AuditView {
  const empty: AuditView = {
    notify: { failed: 0, pending: 0, last_failed_at: null },
    approvals: { payload_mismatch: { count: 0, last_at: null } },
    key_reads: keyReadsView(null, budapestDay(nowMs)),
    last_event: null,
  }
  if (db === null) return empty
  try {
    const key_reads = keyReadsView(db, budapestDay(nowMs))
    const n = db.prepare(`SELECT
        SUM(CASE WHEN notify_state = 'failed' THEN 1 ELSE 0 END) AS failed,
        SUM(CASE WHEN notify_state IS NULL OR notify_state IN ('retry', 'sending') THEN 1 ELSE 0 END) AS pending,
        MAX(CASE WHEN notify_state = 'failed' THEN notify_last_at END) AS last_failed_at,
        SUM(CASE WHEN kind = 'approval_payload_mismatch' THEN 1 ELSE 0 END) AS mismatch,
        MAX(CASE WHEN kind = 'approval_payload_mismatch' THEN at END) AS mismatch_at
      FROM credit_gate_events`).get() as { failed: number | null; pending: number | null; last_failed_at: number | null; mismatch: number | null; mismatch_at: number | null }
    const last = db.prepare('SELECT id, at, kind, reason, notify_state FROM credit_gate_events ORDER BY id DESC LIMIT 1').get() as
      { id: number; at: number; kind: string; reason: string | null; notify_state: string | null } | undefined
    return {
      notify: { failed: n.failed ?? 0, pending: n.pending ?? 0, last_failed_at: iso(n.last_failed_at) },
      approvals: { payload_mismatch: { count: n.mismatch ?? 0, last_at: iso(n.mismatch_at) } },
      key_reads,
      last_event: last ? { id: last.id, at: iso(last.at) as string, kind: last.kind, reason: last.reason === null ? null : scrubDetail(last.reason, 80), notify_state: last.notify_state } : null,
    }
  } catch {
    return empty
  }
}

/** The one line of the /status system block. */
export function creditGateStatusLine(rt: Pick<CreditGateRuntime, 'mode' | 'gate' | 'db' | 'startError'>): string {
  if (rt.mode.mode === 'off') return 'ki (CREDIT_GATE_MODE=off)'
  if (!rt.gate) return `${rt.mode.mode} · nem fut (${rt.startError ?? 'nincs kapu'})`
  const st = rt.gate.status()
  const failed = auditStatus(rt.db, Date.now()).notify.failed
  return `${st.mode} · ${st.state} (${st.reason}) · R_est ${st.r_est_usd === null ? 'n/a' : `${st.r_est_usd} USD`} · jelzes-hiba ${failed}`
}
