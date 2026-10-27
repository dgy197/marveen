// Memory write gate, b1 (shadow): one round of the worker (card 3e9f6c28, node G2c;
// blueprint r5 5., r6 2./4.2/6.).
//
// A round, in order:
//   0. inert unless the gate tables are verified, the config is clean, the mode is
//      not off, there is at least one owner, DISABLE is absent and no breaker is up
//      (off / no owners = not a single row written anywhere);
//   1. a stale in_flight row (claimed > 10 min ago) goes back to pending, as
//      maybe_billed (its outcome is unknown);
//   2. enqueue: memories rows above the cursor, ONLY rows at least 60 s old (so a
//      late origin marker is never lost); a decision row only for an origin-marked
//      row of an allowed owner that is not a daily-log mirror row; the cursor
//      steps over every row it saw;
//   3. pending rows older than 72 h close as UNKNOWN / too_old (with the class
//      they were waiting on);
//   4. credit-gate pause (SR-6a-r6 B2) and price checks: the round makes no call;
//   5. up to 5 pending rows: re-read and re-check the source, find candidates,
//      build and residue-check the prompt, reserve (calls + USD, Budapest day),
//      one transport child for the round, then record the outcome;
//   6. a decision is only EVALUATED (evaluateApply -> would_apply). b1 has no
//      effect: it writes its own tables and nothing else.
// Every error branch and every cap ends in op = 'UNKNOWN' with a named error_class
// (a wait reason stays on the pending row until it is decided or too old).
import type Database from 'better-sqlite3'
import { logger } from '../logger.js'
import { findGateCandidatesAsync, type CandidateResult, type GateSourceRow } from './candidates.js'
import { buildGatePrompt } from './prompt.js'
import { residueFindings } from './mask.js'
import { parseGateOutput } from './parse.js'
import { evaluateApply } from './evaluate.js'
import { RUBRIC } from './prompt.js'
import { FORBIDDEN_OWNERS } from './gate-env.js'
import type { GateCall, GateCallResult, GateErrorClass } from './transport.js'
import { creditPause, dayKey, dayStart, gateRuns, nextDayStart, type CreditView, type GateConfig } from './state.js'

export const MIN_AGE_S = 60
export const MAX_AGE_S = 72 * 3600
export const MIN_CHARS = 40
export const VECTOR_WAIT_S = 600
export const STALE_IN_FLIGHT_S = 600
export const ENQUEUE_BATCH = 200
export const CALLS_PER_ROUND = 5
export const MAX_TRANSIENT_ATTEMPTS = 5
/** Keyword the c) wave puts on its episode blocks (3e9f6c28 c-result: `epizod, episodic, ugynok:<id>`). */
export const EPISODE_KEYWORD = 'epizod'

/** Reasons a pending row may be waiting on; they never overwrite a maybe_billed mark. */
const WAIT_CLASSES = ['daily_cap', 'credit_paused', 'credit_unknown', 'unpriced']
/** Pre-call failures that stop the gate until the dashboard restarts. */
const RESTART_BREAKERS: readonly GateErrorClass[] = ['auth', 'contract_mismatch', 'untrusted_batch_dir', 'residue_check_unavailable', 'usage_log_failed']

export const ALERT_BITS = { daily_cap: 1, breaker: 2, maybe_billed: 4, bad_request: 8, error: 16 } as const
export type AlertCause = keyof typeof ALERT_BITS

export interface WorkerDeps {
  db: () => Database.Database
  /** Wall clock, ms. */
  now: () => number
  config: GateConfig
  tablesReady: () => boolean
  disabled: () => boolean
  credit: () => CreditView
  /** Over-estimated micro-USD of one call, null = no usable price (missing, stale, unknown model). */
  estimateMicro: (model: string, promptBytes: number, maxTokens: number, nowMs: number) => number | null
  transport: (calls: GateCall[]) => Promise<GateCallResult[]>
  /** Fixed text, numbers only; default: the main agent's daily log + an agent message. */
  alert: (cause: AlertCause, text: string) => void
  /** May be sync or async; the default yields to the event loop between its slices (B10). */
  findCandidates?: (db: Database.Database, source: GateSourceRow, opts: { limit: number }) => CandidateResult | Promise<CandidateResult>
  nonce?: () => string
  tz?: string
}

export interface WorkerState {
  /** until = null: until the dashboard restarts. */
  breaker: { reason: string; until: number | null } | null
}

export function newWorkerState(): WorkerState {
  return { breaker: null }
}

export interface TickReport {
  /** Why the round did nothing, or 'ran'. */
  outcome: string
  enqueued: number
  calls: number
  decided: number
}

interface DecisionRow { id: number; source_id: number; source_version: number; attempts: number; error_class: string | null }
interface SourceRow { id: number; agent_id: string; category: string; content: string; keywords: string | null; created_at: number; embedding: string | null }

function versionOf(db: Database.Database, memoryId: number): number {
  return (db.prepare('SELECT COUNT(*) AS n FROM memory_versions WHERE memory_id = ?').get(memoryId) as { n: number }).n
}

function kvGet(db: Database.Database, key: string): string | null {
  const r = db.prepare('SELECT value FROM memory_gate_kv WHERE key = ?').get(key) as { value: string } | undefined
  return r ? r.value : null
}

function kvSet(db: Database.Database, key: string, value: string): void {
  db.prepare('INSERT INTO memory_gate_kv (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').run(key, value)
}

function yieldToLoop(): Promise<void> {
  return new Promise<void>(resolve => setImmediate(resolve))
}

function hasTable(db: Database.Database, name: string): boolean {
  return db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name) !== undefined
}

export function isEpisode(keywords: string | null): boolean {
  return (keywords ?? '').toLowerCase().split(/[,;\s]+/).includes(EPISODE_KEYWORD)
}

/**
 * Null the stored reason of every decision whose source, target or any offered
 * candidate no longer exists (GB5 in b1: at boot and every 10 minutes; the API
 * never returns `reason` at all). Runs whenever the tables are verified, in any mode.
 */
export function sweepReasons(db: Database.Database): number {
  return db.prepare(`UPDATE memory_gate_decisions SET reason = NULL
    WHERE reason IS NOT NULL AND (
      NOT EXISTS (SELECT 1 FROM memories m WHERE m.id = memory_gate_decisions.source_id)
      OR (target_id IS NOT NULL AND NOT EXISTS (SELECT 1 FROM memories m WHERE m.id = memory_gate_decisions.target_id))
      OR EXISTS (SELECT 1 FROM memory_gate_candidates c WHERE c.decision_id = memory_gate_decisions.id
                 AND NOT EXISTS (SELECT 1 FROM memories m WHERE m.id = c.memory_id))
    )`).run().changes
}

/** Two overlapping rounds never run: the second caller gets 'busy'. */
export function singleFlight<T>(fn: () => Promise<T>): () => Promise<T | 'busy'> {
  let running = false
  return async () => {
    if (running) return 'busy'
    running = true
    try { return await fn() } finally { running = false }
  }
}

export async function runGateTick(deps: WorkerDeps, st: WorkerState): Promise<TickReport> {
  const report: TickReport = { outcome: 'ran', enqueued: 0, calls: 0, decided: 0 }
  const done = (outcome: string): TickReport => ({ ...report, outcome })
  const cfg = deps.config
  const tz = deps.tz
  if (!deps.tablesReady()) return done('migration_failed')
  if (cfg.configError !== null) return done('config_error')
  if (!gateRuns(cfg)) return done('off')
  if (deps.disabled()) return done('disabled')
  const nowMs = deps.now()
  if (st.breaker && (st.breaker.until === null || nowMs < st.breaker.until)) return done('breaker')
  st.breaker = null

  const db = deps.db()
  const nowS = Math.floor(nowMs / 1000)
  const owners = cfg.env.owners.owners.filter(o => !FORBIDDEN_OWNERS.includes(o))
  const mode = cfg.env.effectiveMode
  const tomorrowS = Math.floor(nextDayStart(nowMs, tz) / 1000) + 5 * 60

  // 1. stale in_flight
  db.prepare(`UPDATE memory_gate_decisions SET state = 'pending', claimed_at = NULL, error_class = 'maybe_billed', next_at = ?
    WHERE state = 'in_flight' AND claimed_at < ?`).run(tomorrowS, nowS - STALE_IN_FLIGHT_S)

  // 2. enqueue
  report.enqueued = enqueue(db, owners, nowS, mode)

  // 3. too old
  db.prepare(`UPDATE memory_gate_decisions SET state = 'skipped', op = 'UNKNOWN', skip_reason = 'too_old',
      error_class = COALESCE(error_class, 'too_old'), decided_at = ?
    WHERE state = 'pending' AND (created_at < ? OR source_id IN (SELECT id FROM memories WHERE created_at < ?))`)
    .run(nowS, nowS - MAX_AGE_S, nowS - MAX_AGE_S)

  const markWaiting = (cls: string) => {
    db.prepare(`UPDATE memory_gate_decisions SET error_class = ?
      WHERE state = 'pending' AND (error_class IS NULL OR error_class IN (${WAIT_CLASSES.map(() => '?').join(',')}))`).run(cls, ...WAIT_CLASSES)
  }

  // 4. credit gate (B2) and price
  let pause: string | null
  try { pause = creditPause(deps.credit()) } catch { pause = 'credit_unknown' }
  if (pause !== null) { markWaiting(pause); return done(pause) }
  const perCall = deps.estimateMicro(cfg.model, cfg.maxPromptBytes, cfg.maxTokens, nowMs)
  if (perCall === null) { markWaiting('unpriced'); return done('unpriced') }
  // Static ceiling (r5 4.1): the worst case of a full day must fit the daily USD cap.
  if (perCall * cfg.maxCallsPerDay > cfg.dailyUsdMicro) return done('static_cap')

  // 5. pick and prepare
  const finder = deps.findCandidates ?? findGateCandidatesAsync
  const pending = db.prepare(`SELECT id, source_id, source_version, attempts, error_class FROM memory_gate_decisions
    WHERE state = 'pending' AND (next_at IS NULL OR next_at <= ?) ORDER BY id LIMIT 20`).all(nowS) as DecisionRow[]
  const skip = db.prepare(`UPDATE memory_gate_decisions SET state = 'skipped', skip_reason = ?, op = ?, error_class = ?, decided_at = ? WHERE id = ?`)
  type Prepared = { dec: DecisionRow; src: SourceRow; call: GateCall; labels: Map<string, { id: number; version: number }>; nonce: string }
  const prepared: Prepared[] = []
  let capped = false
  for (const dec of pending) {
    if (prepared.length >= CALLS_PER_ROUND || capped) break
    // B10: give the event loop back between sources (the finder yields inside a source).
    await yieldToLoop()
    const src = db.prepare('SELECT id, agent_id, category, content, keywords, created_at, embedding FROM memories WHERE id = ?').get(dec.source_id) as SourceRow | undefined
    if (!src) { skip.run('deleted', null, null, nowS, dec.id); continue }
    if (versionOf(db, src.id) !== dec.source_version) { skip.run('edited', null, null, nowS, dec.id); continue }
    if (!owners.includes(src.agent_id)) { skip.run('owner_changed', null, null, nowS, dec.id); continue }
    if (src.category !== 'warm' && src.category !== 'cold') { skip.run('category', null, null, nowS, dec.id); continue }
    if (nowS - src.created_at < MIN_AGE_S) continue
    // No vector yet: wait up to 10 minutes for the embedder, then go keyword-only.
    if (!src.embedding && nowS - src.created_at < VECTOR_WAIT_S) continue

    const cand = await finder(db, src, { limit: cfg.candidates })
    if (cand.refused) { skip.run(cand.refused, null, null, nowS, dec.id); continue }
    const createNoCall = () => {
      db.prepare(`UPDATE memory_gate_decisions SET state = 'decided', op = 'CREATE', would_apply = 0, apply_block = NULL,
        error_class = NULL, mode = ?, decided_at = ? WHERE id = ?`).run(mode, nowS, dec.id)
      report.decided++
    }
    if (cand.hits.length === 0) { createNoCall(); continue }
    const nonce = deps.nonce ? deps.nonce() : undefined
    const gp = buildGatePrompt(
      { content: src.content, keywords: src.keywords, created_at: src.created_at },
      cand.hits.map(h => ({ id: h.memory.id, content: h.memory.content, keywords: h.memory.keywords, created_at: h.memory.created_at })),
      { maxPromptBytes: cfg.maxPromptBytes, maxCandidates: cfg.candidates, ...(nonce ? { nonce } : {}), ...(tz ? { tz } : {}) },
    )
    if (gp.labels.length === 0) { createNoCall(); continue }
    if (residueFindings(`${gp.system}\n${gp.prompt}`).length > 0) { skip.run('secret_residue', 'UNKNOWN', 'secret_residue', nowS, dec.id); continue }
    const est = deps.estimateMicro(cfg.model, gp.bytes, cfg.maxTokens, nowMs)
    if (est === null) { markWaiting('unpriced'); break }

    const labels = new Map<string, { id: number; version: number }>()
    for (const l of gp.labels) labels.set(l.label, { id: l.id, version: versionOf(db, l.id) })
    const day = dayKey(nowMs, tz)
    const reserved = db.transaction((): boolean => {
      db.prepare('INSERT OR IGNORE INTO memory_gate_daily (day) VALUES (?)').run(day)
      const d = db.prepare('SELECT calls, reserved_usd_micro FROM memory_gate_daily WHERE day = ?').get(day) as { calls: number; reserved_usd_micro: number }
      if (d.calls + 1 > cfg.maxCallsPerDay || d.reserved_usd_micro + est > cfg.dailyUsdMicro) {
        db.prepare(`UPDATE memory_gate_decisions SET next_at = ?,
          error_class = CASE WHEN error_class = 'maybe_billed' THEN error_class ELSE 'daily_cap' END WHERE id = ?`).run(tomorrowS, dec.id)
        return false
      }
      db.prepare('UPDATE memory_gate_daily SET calls = calls + 1, reserved_usd_micro = reserved_usd_micro + ? WHERE day = ?').run(est, day)
      db.prepare('DELETE FROM memory_gate_candidates WHERE decision_id = ?').run(dec.id)
      const ins = db.prepare('INSERT INTO memory_gate_candidates (decision_id, memory_id, label, version) VALUES (?, ?, ?, ?)')
      for (const [label, v] of labels) ins.run(dec.id, v.id, label, v.version)
      db.prepare(`UPDATE memory_gate_decisions SET state = 'in_flight', attempts = attempts + 1, claimed_at = ?, model = ?,
        prompt_bytes = ?, reserved_usd_micro = COALESCE(reserved_usd_micro, 0) + ?, mode = ? WHERE id = ?`)
        .run(nowS, cfg.model, gp.bytes, est, mode, dec.id)
      return true
    })()
    if (!reserved) {
      capped = true
      alertOnce(deps, db, nowMs, 'daily_cap', `[memory-gate] daily_cap: calls ${cfg.maxCallsPerDay}, usd_micro ${cfg.dailyUsdMicro}`)
      break
    }
    prepared.push({
      dec: { ...dec, attempts: dec.attempts + 1 }, src, nonce: gp.nonce, labels,
      call: { k: String(dec.id), model: cfg.model, max_tokens: cfg.maxTokens, system: gp.system, prompt: gp.prompt },
    })
  }
  if (prepared.length === 0) return done(capped ? 'daily_cap' : 'ran')

  // One child for the round.
  let results: GateCallResult[]
  try {
    results = await deps.transport(prepared.map(p => p.call))
  } catch {
    results = prepared.map(p => ({ k: p.call.k, ok: false as const, error: 'maybe_billed' as const }))
  }
  report.calls = prepared.length
  const byK = new Map(results.map(r => [r.k, r]))
  for (const p of prepared) {
    const r = byK.get(p.call.k) ?? { k: p.call.k, ok: false as const, error: 'maybe_billed' as const }
    if (recordOutcome(deps, db, st, p, r, nowMs, tomorrowS, mode)) report.decided++
  }
  return report
}

function enqueue(db: Database.Database, owners: string[], nowS: number, mode: string): number {
  const mirror = hasTable(db, 'daily_log_memory')
  return db.transaction((): number => {
    const raw = kvGet(db, 'cursor')
    if (raw === null || !/^[0-9]+$/.test(raw)) {
      // First run: everything already stored is history, not a write the gate saw.
      const max = (db.prepare('SELECT COALESCE(MAX(id), 0) AS m FROM memories').get() as { m: number }).m
      kvSet(db, 'cursor', String(max))
      return 0
    }
    let cursor = parseInt(raw, 10)
    const rows = db.prepare(`SELECT m.id, m.agent_id, m.category, m.content, m.keywords, m.created_at,
        (o.memory_id IS NOT NULL) AS marked,
        ${mirror ? 'EXISTS (SELECT 1 FROM daily_log_memory d WHERE d.memory_id = m.id)' : '0'} AS mirror
      FROM memories m LEFT JOIN memory_gate_origin o ON o.memory_id = m.id
      WHERE m.id > ? ORDER BY m.id LIMIT ?`).all(cursor, ENQUEUE_BATCH) as Array<SourceRow & { marked: number; mirror: number }>
    const ins = db.prepare(`INSERT OR IGNORE INTO memory_gate_decisions
      (source_id, source_version, rubric, state, skip_reason, op, mode, next_at, created_at, decided_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    let n = 0
    for (const r of rows) {
      // Younger than 60 s: stop here, so a late origin marker is still seen next round.
      if (r.created_at > nowS - MIN_AGE_S) break
      cursor = r.id
      if (r.marked !== 1 || r.mirror === 1 || !owners.includes(r.agent_id)) continue
      let state = 'pending'
      let skipReason: string | null = null
      let op: string | null = null
      if (r.category !== 'warm' && r.category !== 'cold') { state = 'skipped'; skipReason = 'category' }
      else if (Array.from(r.content ?? '').length < MIN_CHARS) { state = 'skipped'; skipReason = 'too_short' }
      else if (isEpisode(r.keywords)) { state = 'skipped'; skipReason = 'episode' }
      else if (nowS - r.created_at > MAX_AGE_S) { state = 'skipped'; skipReason = 'too_old'; op = 'UNKNOWN' }
      ins.run(r.id, versionOf(db, r.id), RUBRIC, state, skipReason, op, mode, state === 'pending' ? r.created_at + MIN_AGE_S : null,
        nowS, state === 'pending' ? null : nowS)
      n++
    }
    kvSet(db, 'cursor', String(cursor))
    return n
  })()
}

function alertOnce(deps: WorkerDeps, db: Database.Database, nowMs: number, cause: AlertCause, text: string): void {
  try {
    const day = dayKey(nowMs, deps.tz)
    const bit = ALERT_BITS[cause]
    const fresh = db.transaction((): boolean => {
      db.prepare('INSERT OR IGNORE INTO memory_gate_daily (day) VALUES (?)').run(day)
      const d = db.prepare('SELECT alerted FROM memory_gate_daily WHERE day = ?').get(day) as { alerted: number }
      if ((d.alerted & bit) !== 0) return false
      db.prepare('UPDATE memory_gate_daily SET alerted = alerted | ? WHERE day = ?').run(bit, day)
      return true
    })()
    if (fresh) deps.alert(cause, text)
  } catch (err) {
    try { logger.warn({ reason: (err as { code?: string } | null)?.code ?? 'error', cause }, 'memory-gate: alert not sent') } catch { /* ignore */ }
  }
}

/** Returns true when the row ended decided. */
function recordOutcome(
  deps: WorkerDeps, db: Database.Database, st: WorkerState,
  p: { dec: DecisionRow; src: SourceRow; labels: Map<string, { id: number; version: number }>; nonce: string },
  r: GateCallResult, nowMs: number, tomorrowS: number, mode: string,
): boolean {
  const nowS = Math.floor(nowMs / 1000)
  const id = p.dec.id
  const fail = (state: 'failed' | 'skipped', cls: string) =>
    db.prepare(`UPDATE memory_gate_decisions SET state = ?, op = 'UNKNOWN', error_class = ?, claimed_at = NULL, decided_at = ?,
      skip_reason = CASE WHEN ? = 'skipped' THEN ? ELSE skip_reason END WHERE id = ?`).run(state, cls, nowS, state, cls, id)
  const requeue = (cls: string, nextAt: number, refundAttempt: boolean) =>
    db.prepare(`UPDATE memory_gate_decisions SET state = 'pending', claimed_at = NULL, error_class = ?, next_at = ?,
      attempts = attempts - ? WHERE id = ?`).run(cls, nextAt, refundAttempt ? 1 : 0, id)

  if (r.ok) {
    const parsed = parseGateOutput(r.text, [...p.labels.keys()], p.nonce)
    if (!parsed.ok) { fail('failed', 'bad_output'); return false }
    const dcs = parsed.decision
    const offered = dcs.target ? p.labels.get(dcs.target) ?? null : null
    const t = offered ? db.prepare('SELECT id, agent_id, category FROM memories WHERE id = ?').get(offered.id) as { id: number; agent_id: string; category: string } | undefined : undefined
    const since = Math.floor(dayStart(nowMs, deps.tz) / 1000)
    const appliedToday = (db.prepare(`SELECT COUNT(*) AS n FROM memory_gate_decisions
      WHERE op = ? AND would_apply = 1 AND decided_at >= ?`).get(dcs.op, since) as { n: number }).n
    const cfg = deps.config
    const ev = evaluateApply({
      op: dcs.op, confidence: dcs.confidence, sourceId: p.src.id, sourceOwner: p.src.agent_id,
      offeredVersion: offered ? offered.version : null,
      target: t ? { id: t.id, agent_id: t.agent_id, category: t.category, version: versionOf(db, t.id) } : null,
      appliedToday,
    }, cfg)
    db.transaction(() => {
      db.prepare(`UPDATE memory_gate_decisions SET state = 'decided', op = ?, target_id = ?, target_version = ?, target_owner = ?,
          target_category = ?, confidence = ?, reason = ?, would_apply = ?, apply_block = ?, error_class = NULL, claimed_at = NULL,
          mode = ?, decided_at = ? WHERE id = ?`)
        .run(dcs.op, offered?.id ?? null, offered?.version ?? null, t?.agent_id ?? null, t?.category ?? null, dcs.confidence,
          dcs.reason === '' ? null : dcs.reason, ev.wouldApply ? 1 : 0, ev.block, mode, nowS, id)
      if (kvGet(db, 'first_shadow_at') === null) kvSet(db, 'first_shadow_at', String(nowS))
      kvSet(db, 'shadow_count', String((parseInt(kvGet(db, 'shadow_count') ?? '0', 10) || 0) + 1))
    })()
    return true
  }

  switch (r.error) {
    case 'transient':
      if (p.dec.attempts >= MAX_TRANSIENT_ATTEMPTS) fail('failed', 'transient')
      // E3: a transient retry must not erase an earlier maybe_billed mark (the second one is final).
      else requeue(p.dec.error_class === 'maybe_billed' ? 'maybe_billed' : 'transient', nowS + 60 * 2 ** p.dec.attempts, false)
      return false
    case 'maybe_billed':
      // GN4: it may have been billed. Never again today; the second time it is final.
      if (p.dec.error_class === 'maybe_billed') fail('failed', 'maybe_billed')
      else requeue('maybe_billed', tomorrowS, false)
      alertOnce(deps, db, nowMs, 'maybe_billed', `[memory-gate] maybe_billed: decision ${id}`)
      return false
    case 'stopped':
      requeue('stopped', nowS, true)
      return false
    case 'credit':
      st.breaker = { reason: 'credit', until: nextDayStart(nowMs, deps.tz) }
      requeue('credit', tomorrowS, true)
      alertOnce(deps, db, nowMs, 'breaker', '[memory-gate] breaker: credit')
      return false
    case 'secret_residue':
      fail('skipped', 'secret_residue')
      return false
    case 'bad_request':
    case 'error':
      fail('failed', r.error)
      alertOnce(deps, db, nowMs, r.error, `[memory-gate] ${r.error}: decision ${id}`)
      return false
    default:
      if ((RESTART_BREAKERS as readonly string[]).includes(r.error)) {
        st.breaker = { reason: r.error, until: null }
        // usage_log_failed: the call DID happen, so this row is final; the rest never reached the API.
        if (r.error === 'usage_log_failed') fail('failed', 'usage_log_failed')
        else requeue(r.error, nowS, true)
        alertOnce(deps, db, nowMs, 'breaker', `[memory-gate] breaker: ${r.error}`)
        return false
      }
      fail('failed', 'error')
      return false
  }
}
