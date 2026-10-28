// Time-interval core for the work log (card d7b2d5c8, S4-A).
//
// Pure functions, no DB, no clock, no config import: the zone is always an
// explicit argument (callers pass APP_TZ). Events are unix SECONDS.
//
// Rules (blueprint S4-A, SPEC D6):
//  - events are cut into segments in time order; an event belongs to the
//    previous segment when `ts - lastTs <= SESSION_GAP_SECONDS` (closed bound),
//  - a segment spans `[firstTs, lastTs + EVENT_TAIL_SECONDS)`, so a lone event
//    counts as one minute,
//  - overlapping or touching intervals are merged (two agents working at the
//    same time are not counted twice),
//  - a day is the LOCAL calendar day in the zone, `[local midnight, next local
//    midnight)`, found with Intl (never `+ 86400`): a DST day has 23 or 25 hours,
//  - a segment crossing midnight is clipped into both days.

/** Max gap between two events of the same segment, inclusive (D6: 10 minutes). */
export const SESSION_GAP_SECONDS = 600

/** Length credited after the last event of a segment (a lone event = 1 minute). */
export const EVENT_TAIL_SECONDS = 60

/** Half-open interval `[start, end)` in unix seconds. */
export interface Interval {
  start: number
  end: number
}

export interface DayBounds {
  date: string
  /** Local midnight at the start of the day (unix seconds). */
  start: number
  /** Next local midnight (unix seconds, exclusive). */
  end: number
}

export interface DaySummary extends DayBounds {
  /** floor(seconds covered / 60) over the union of the intervals clipped to the day. */
  minutes: number
  /** Number of input intervals that reach into the day. */
  segments: number
  /** The union clipped to the day, ascending. */
  intervals: Interval[]
}

const DATE_RE = /^\d{4}-\d{2}-\d{2}$/

/**
 * Cut events into segments. Input need not be sorted and may hold duplicates;
 * non-finite values are ignored. Returns ascending, non-overlapping intervals.
 */
export function buildSegments(timestamps: readonly number[]): Interval[] {
  const sorted = timestamps.filter(t => Number.isFinite(t)).sort((a, b) => a - b)
  const out: Interval[] = []
  let first = 0
  let last = 0
  let open = false
  for (const ts of sorted) {
    if (open && ts - last <= SESSION_GAP_SECONDS) {
      last = ts
      continue
    }
    if (open) out.push({ start: first, end: last + EVENT_TAIL_SECONDS })
    first = ts
    last = ts
    open = true
  }
  if (open) out.push({ start: first, end: last + EVENT_TAIL_SECONDS })
  return out
}

/** Merge overlapping or touching intervals. Does not mutate the input. */
export function unionIntervals(intervals: readonly Interval[]): Interval[] {
  const sorted = intervals
    .filter(i => Number.isFinite(i.start) && Number.isFinite(i.end) && i.end > i.start)
    .map(i => ({ start: i.start, end: i.end }))
    .sort((a, b) => a.start - b.start || a.end - b.end)
  const out: Interval[] = []
  for (const cur of sorted) {
    const prev = out[out.length - 1]
    if (prev && cur.start <= prev.end) {
      if (cur.end > prev.end) prev.end = cur.end
    } else {
      out.push(cur)
    }
  }
  return out
}

/** Clip intervals to `[start, end)`, dropping the ones with nothing left. */
export function clipIntervals(intervals: readonly Interval[], start: number, end: number): Interval[] {
  const out: Interval[] = []
  for (const i of intervals) {
    const s = Math.max(i.start, start)
    const e = Math.min(i.end, end)
    if (e > s) out.push({ start: s, end: e })
  }
  return out
}

/** Total length in seconds of already-disjoint intervals. */
export function totalSeconds(intervals: readonly Interval[]): number {
  let sum = 0
  for (const i of intervals) sum += i.end - i.start
  return sum
}

const formatters = new Map<string, Intl.DateTimeFormat>()

function dateFormatter(tz: string): Intl.DateTimeFormat {
  let f = formatters.get(tz)
  if (!f) {
    f = new Intl.DateTimeFormat('en-CA', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' })
    formatters.set(tz, f)
  }
  return f
}

/** Local calendar date `YYYY-MM-DD` of an instant in the zone. */
export function localDate(unixSeconds: number, tz: string): string {
  let y = ''
  let m = ''
  let d = ''
  for (const p of dateFormatter(tz).formatToParts(new Date(unixSeconds * 1000))) {
    if (p.type === 'year') y = p.value
    else if (p.type === 'month') m = p.value
    else if (p.type === 'day') d = p.value
  }
  return `${y}-${m}-${d}`
}

/** Calendar arithmetic on a `YYYY-MM-DD` string (zone independent). */
export function addDays(date: string, days: number): string {
  assertDate(date)
  return new Date(Date.parse(`${date}T00:00:00Z`) + days * 86_400_000).toISOString().slice(0, 10)
}

function assertDate(date: string): void {
  if (!DATE_RE.test(date) || new Date(`${date}T00:00:00Z`).toISOString().slice(0, 10) !== date) {
    throw new RangeError(`invalid date: ${date}`)
  }
}

/**
 * The first instant (unix seconds) whose local date in the zone is >= `date`,
 * i.e. the local midnight. Binary search on the monotonic local date, so a
 * DST shift or a skipped midnight cannot break it.
 */
function localMidnight(date: string, tz: string): number {
  const utcMidnight = Date.parse(`${date}T00:00:00Z`) / 1000
  let lo = utcMidnight - 15 * 3600 // local date < date for every real zone offset
  let hi = utcMidnight + 15 * 3600 // local date >= date for every real zone offset
  while (hi - lo > 1) {
    const mid = Math.floor((lo + hi) / 2)
    if (localDate(mid, tz) >= date) hi = mid
    else lo = mid
  }
  return hi
}

/** `[local midnight, next local midnight)` of a local date in the zone. */
export function localDayBounds(date: string, tz: string): DayBounds {
  assertDate(date)
  return { date, start: localMidnight(date, tz), end: localMidnight(addDays(date, 1), tz) }
}

/**
 * Minutes and segment count of one local day. `intervals` are typically the
 * output of buildSegments (the user) or of unionIntervals over the per-agent
 * segments (the AI); they are merged here again for the minutes, so overlapping
 * input never counts twice.
 */
export function summarizeDay(intervals: readonly Interval[], date: string, tz: string): DaySummary {
  const bounds = localDayBounds(date, tz)
  const clippedUnion = unionIntervals(clipIntervals(intervals, bounds.start, bounds.end))
  const segments = clipIntervals(intervals, bounds.start, bounds.end).length
  return {
    ...bounds,
    minutes: Math.floor(totalSeconds(clippedUnion) / 60),
    segments,
    intervals: clippedUnion,
  }
}
