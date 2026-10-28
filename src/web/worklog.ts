// Work log: read-only aggregation over data the system already records
// (card S4-B; SPEC 4.1 "no new data", 5.4).
//
// Sources, ONLY timestamp and identifier columns, named in every SELECT (never
// `*`), so no text column can reach a response:
//   me      conversation_log (direction 'in', the owner's chat; created_at)
//           function_decisions (recorded_via session/device; created_at)
//           open_questions (answered_via 'ui'; answered_at)
//   ai      token_usage (agent, timestamp) + tool_call_log (agent_id, created_at),
//           segmented PER AGENT, the daily AI minutes are the UNION of those
//   prompts owner = the owner's inbound messages; agent = agent_messages whose
//           from_agent is not 'system'
// A token-written decision (recorded_via 'token') is an agent's act, not the
// owner's: it is not "me" time. A table that does not exist (yet) is no events.
//
// Never read: conversation_log.text, token_usage.content_preview,
// tool_call_log.input_summary, agent_messages.content/result.

import type Database from 'better-sqlite3'
import {
  SESSION_GAP_SECONDS,
  addDays,
  buildSegments,
  localDate,
  localDayBounds,
  summarizeDay,
  unionIntervals,
  type Interval,
} from './worklog-intervals.js'

export const DEFAULT_RANGE_DAYS = 30
export const MAX_RANGE_DAYS = 92
export const MAX_PROMPTS = 2000
export const UNKNOWN_AGENT = '(ismeretlen)'

/** Exact key allowlists of the responses (snapshot-pinned in the tests). */
export const DAY_KEYS = [
  'date', 'me_minutes', 'me_segments', 'ai_minutes', 'ai_segments',
  'ai_by_agent', 'prompts_owner', 'prompts_agent', 'sources',
] as const
export const DETAIL_KEYS = [
  'date', 'tz', 'day_start', 'day_end', 'me', 'ai', 'ai_by_agent', 'prompts', 'truncated', 'sources',
] as const
export const RANGE_KEYS = ['tz', 'from', 'to', 'days'] as const
export const PROMPT_KEYS = ['ts', 'kind', 'agent', 'from_agent', 'to_agent'] as const

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/
const MIN_YEAR = 2000
const MAX_YEAR = 2100

export interface WorklogOptions {
  tz: string
  /** The owner's chat id; null = none configured (no "me" chat events). */
  ownerChatId: string | null
}

export interface DaySources {
  token_usage: boolean
  tool_call_log: boolean
}

export interface WorklogDay {
  date: string
  me_minutes: number
  me_segments: number
  ai_minutes: number
  ai_segments: number
  ai_by_agent: Array<{ agent: string; minutes: number }>
  prompts_owner: number
  prompts_agent: number
  sources: DaySources
}

export interface WorklogRange {
  tz: string
  from: string
  to: string
  days: WorklogDay[]
}

export interface WorklogPrompt {
  ts: number
  kind: 'owner' | 'agent'
  agent: string | null
  from_agent: string | null
  to_agent: string | null
}

export interface WorklogDetail {
  date: string
  tz: string
  day_start: number
  day_end: number
  me: Interval[]
  ai: Interval[]
  ai_by_agent: Array<{ agent: string; segments: number }>
  prompts: WorklogPrompt[]
  /** True when the day has more than MAX_PROMPTS prompts and the list is cut (chronological, first ones kept). */
  truncated: boolean
  sources: DaySources
}

/** True for a real calendar date `YYYY-MM-DD`, years 2000..2100 only. */
export function isValidDate(s: string): boolean {
  if (!DATE_RE.test(s)) return false
  const year = Number(s.slice(0, 4))
  if (year < MIN_YEAR || year > MAX_YEAR) return false
  const t = Date.parse(`${s}T00:00:00Z`)
  return Number.isFinite(t) && new Date(t).toISOString().slice(0, 10) === s
}

/** Inclusive number of calendar days from..to (both valid dates). */
export function daySpan(from: string, to: string): number {
  return Math.round((Date.parse(`${to}T00:00:00Z`) - Date.parse(`${from}T00:00:00Z`)) / 86_400_000) + 1
}

function tableExists(db: Database.Database, name: string): boolean {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(name)
}

/** A SELECT on an optional table: a missing table or column is "no events"; any other error propagates. */
function optionalTimes(db: Database.Database, table: string, sql: string, ...args: number[]): number[] {
  if (!tableExists(db, table)) return []
  try {
    return (db.prepare(sql).all(...args) as Array<{ t: number }>).map(r => r.t)
  } catch (err) {
    if (err instanceof Error && /no such (table|column)/i.test(err.message)) return []
    throw err
  }
}

interface Raw {
  meTimes: number[]
  ownerPrompts: Array<{ ts: number; agent: string }>
  agentPrompts: Array<{ ts: number; from: string; to: string }>
  /** agent -> event times */
  aiByAgent: Map<string, number[]>
  oldestToken: number | null
  oldestTool: number | null
}

function loadRaw(db: Database.Database, lo: number, hi: number, opts: WorklogOptions): Raw {
  const ownerPrompts = opts.ownerChatId
    ? (db.prepare(
        "SELECT created_at AS ts, agent_id AS agent FROM conversation_log WHERE direction = 'in' AND chat_id = ? AND created_at >= ? AND created_at < ? ORDER BY created_at",
      ).all(opts.ownerChatId, lo, hi) as Array<{ ts: number; agent: string }>)
    : []

  const agentPrompts = (db.prepare(
    "SELECT created_at AS ts, from_agent AS \"from\", to_agent AS \"to\" FROM agent_messages WHERE from_agent <> 'system' AND created_at >= ? AND created_at < ? ORDER BY created_at",
  ).all(lo, hi) as Array<{ ts: number; from: string; to: string }>)

  const meTimes: number[] = ownerPrompts.map(p => p.ts)
  meTimes.push(...optionalTimes(
    db, 'function_decisions',
    "SELECT created_at AS t FROM function_decisions WHERE recorded_via IN ('session','device') AND created_at >= ? AND created_at < ?",
    lo, hi,
  ))
  meTimes.push(...optionalTimes(
    db, 'open_questions',
    "SELECT answered_at AS t FROM open_questions WHERE answered_via = 'ui' AND answered_at >= ? AND answered_at < ?",
    lo, hi,
  ))

  const aiByAgent = new Map<string, number[]>()
  const push = (agent: string | null, t: number) => {
    const key = agent && agent.trim() ? agent : UNKNOWN_AGENT
    const arr = aiByAgent.get(key)
    if (arr) arr.push(t)
    else aiByAgent.set(key, [t])
  }
  for (const r of db.prepare('SELECT agent, timestamp AS t FROM token_usage WHERE timestamp >= ? AND timestamp < ?').all(lo, hi) as Array<{ agent: string | null; t: number }>) {
    push(r.agent, r.t)
  }
  for (const r of db.prepare('SELECT agent_id AS agent, created_at AS t FROM tool_call_log WHERE created_at >= ? AND created_at < ?').all(lo, hi) as Array<{ agent: string | null; t: number }>) {
    push(r.agent, r.t)
  }

  const oldest = (sql: string): number | null => {
    const r = db.prepare(sql).get() as { m: number | null } | undefined
    return r && typeof r.m === 'number' ? r.m : null
  }
  return {
    meTimes,
    ownerPrompts,
    agentPrompts,
    aiByAgent,
    oldestToken: oldest('SELECT MIN(timestamp) AS m FROM token_usage'),
    oldestTool: oldest('SELECT MIN(created_at) AS m FROM tool_call_log'),
  }
}

/** Number of values in [start, end) of an ascending array. */
function countIn(sorted: readonly number[], start: number, end: number): number {
  const lower = (x: number): number => {
    let lo = 0
    let hi = sorted.length
    while (lo < hi) {
      const mid = (lo + hi) >> 1
      if (sorted[mid] < x) lo = mid + 1
      else hi = mid
    }
    return lo
  }
  return lower(end) - lower(start)
}

function sourcesFor(raw: Raw, dayEnd: number): DaySources {
  return {
    token_usage: raw.oldestToken !== null && dayEnd > raw.oldestToken,
    tool_call_log: raw.oldestTool !== null && dayEnd > raw.oldestTool,
  }
}

interface Model {
  me: Interval[]
  perAgent: Array<{ agent: string; segs: Interval[] }>
  aiUnion: Interval[]
}

function model(raw: Raw): Model {
  const perAgent = [...raw.aiByAgent.entries()]
    .map(([agent, times]) => ({ agent, segs: buildSegments(times) }))
    .sort((a, b) => (a.agent < b.agent ? -1 : a.agent > b.agent ? 1 : 0))
  return {
    me: buildSegments(raw.meTimes),
    perAgent,
    aiUnion: unionIntervals(perAgent.flatMap(p => p.segs)),
  }
}

/** Closed local-date range, one aggregate per day. Dates must be valid and from <= to. */
export function buildWorklogRange(db: Database.Database, from: string, to: string, opts: WorklogOptions): WorklogRange {
  const first = localDayBounds(from, opts.tz)
  const last = localDayBounds(to, opts.tz)
  // The lookback lets a segment that starts before the first day begin correctly.
  const raw = loadRaw(db, first.start - SESSION_GAP_SECONDS, last.end, opts)
  const m = model(raw)
  const ownerTs = raw.ownerPrompts.map(p => p.ts)
  const agentTs = raw.agentPrompts.map(p => p.ts)

  const days: WorklogDay[] = []
  for (let n = daySpan(from, to), i = 0; i < n; i++) {
    const date = addDays(from, i)
    const me = summarizeDay(m.me, date, opts.tz)
    const ai = summarizeDay(m.aiUnion, date, opts.tz)
    const byAgent = m.perAgent
      .map(p => ({ agent: p.agent, minutes: summarizeDay(p.segs, date, opts.tz).minutes }))
      .filter(a => a.minutes > 0)
      .sort((a, b) => b.minutes - a.minutes || (a.agent < b.agent ? -1 : 1))
    days.push({
      date,
      me_minutes: me.minutes,
      me_segments: me.segments,
      ai_minutes: ai.minutes,
      ai_segments: ai.segments,
      ai_by_agent: byAgent,
      prompts_owner: countIn(ownerTs, me.start, me.end),
      prompts_agent: countIn(agentTs, me.start, me.end),
      sources: sourcesFor(raw, me.end),
    })
  }
  return { tz: opts.tz, from, to, days }
}

/** One day in detail: the clipped intervals, per-agent segment counts, the prompt list. */
export function buildWorklogDay(db: Database.Database, date: string, opts: WorklogOptions): WorklogDetail {
  const b = localDayBounds(date, opts.tz)
  const raw = loadRaw(db, b.start - SESSION_GAP_SECONDS, b.end, opts)
  const m = model(raw)
  const me = summarizeDay(m.me, date, opts.tz)
  const ai = summarizeDay(m.aiUnion, date, opts.tz)

  const allPrompts: WorklogPrompt[] = [
    ...raw.ownerPrompts
      .filter(p => p.ts >= b.start && p.ts < b.end)
      .map(p => ({ ts: p.ts, kind: 'owner' as const, agent: p.agent, from_agent: null, to_agent: p.agent })),
    ...raw.agentPrompts
      .filter(p => p.ts >= b.start && p.ts < b.end)
      .map(p => ({ ts: p.ts, kind: 'agent' as const, agent: p.from, from_agent: p.from, to_agent: p.to })),
  ].sort((a, b2) => a.ts - b2.ts)
  const truncated = allPrompts.length > MAX_PROMPTS
  const prompts = truncated ? allPrompts.slice(0, MAX_PROMPTS) : allPrompts

  return {
    date,
    tz: opts.tz,
    day_start: b.start,
    day_end: b.end,
    me: me.intervals,
    ai: ai.intervals,
    ai_by_agent: m.perAgent
      .map(p => ({ agent: p.agent, segments: summarizeDay(p.segs, date, opts.tz).segments }))
      .filter(a => a.segments > 0),
    prompts,
    truncated,
    sources: sourcesFor(raw, b.end),
  }
}

/** Default range: the last 30 local days up to and including `nowSec`'s local date. */
export function defaultRange(nowSec: number, tz: string): { from: string; to: string } {
  const to = localDate(nowSec, tz)
  return { from: addDays(to, -(DEFAULT_RANGE_DAYS - 1)), to }
}
