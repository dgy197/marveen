import { describe, it, expect } from 'vitest'
import {
  EVENT_TAIL_SECONDS, SESSION_GAP_SECONDS, addDays, buildSegments, clipIntervals, localDate,
  localDayBounds, summarizeDay, totalSeconds, unionIntervals, type Interval,
} from '../web/worklog-intervals.js'

// Card d7b2d5c8 (S4-A): the time-interval core. Fixed instants and explicit
// Europe/Budapest dates only, no wall clock. Acceptance S4-1 (hand-computed
// minutes) and S4-2 (overlapping agents are not counted twice).

const TZ = 'Europe/Budapest'

/** ISO instant -> unix seconds. */
const t = (iso: string): number => Date.parse(iso) / 1000

// A quiet mid-day instant (CET, UTC+1): 2026-10-28 12:00:00 local.
const T0 = t('2026-10-28T11:00:00Z')

describe('constants', () => {
  it('pins the D6 rules', () => {
    expect(SESSION_GAP_SECONDS).toBe(600)
    expect(EVENT_TAIL_SECONDS).toBe(60)
  })
})

describe('buildSegments', () => {
  it('returns no segments for no events', () => {
    expect(buildSegments([])).toEqual([])
  })

  it('credits a lone event with one minute', () => {
    const segs = buildSegments([T0])
    expect(segs).toEqual([{ start: T0, end: T0 + 60 }])
    expect(totalSeconds(segs)).toBe(60)
  })

  it('keeps a gap of exactly 600 s in one segment (closed bound)', () => {
    expect(buildSegments([T0, T0 + 600])).toEqual([{ start: T0, end: T0 + 660 }])
  })

  it('splits at a gap of 601 s', () => {
    expect(buildSegments([T0, T0 + 601])).toEqual([
      { start: T0, end: T0 + 60 },
      { start: T0 + 601, end: T0 + 661 },
    ])
  })

  it('chains events each within 600 s of the previous one', () => {
    // 0, 600, 1200, 1800: every step is 600, so one segment of 1860 s.
    expect(buildSegments([T0, T0 + 600, T0 + 1200, T0 + 1800])).toEqual([{ start: T0, end: T0 + 1860 }])
  })

  it('measures the gap from the last event, not from the segment start', () => {
    // 0, 500, 1100 -> 500 and 600 steps: one segment although 1100 > 600 from the start.
    expect(buildSegments([T0, T0 + 500, T0 + 1100])).toEqual([{ start: T0, end: T0 + 1160 }])
  })

  it('sorts unsorted input', () => {
    expect(buildSegments([T0 + 1300, T0, T0 + 100, T0 + 1200])).toEqual([
      { start: T0, end: T0 + 160 },
      { start: T0 + 1200, end: T0 + 1360 },
    ])
  })

  it('treats duplicate timestamps as one event', () => {
    expect(buildSegments([T0, T0, T0, T0 + 30, T0 + 30])).toEqual([{ start: T0, end: T0 + 90 }])
  })

  it('ignores non-finite values and does not mutate the input', () => {
    const input = [T0 + 10, Number.NaN, T0, Number.POSITIVE_INFINITY]
    const copy = [...input]
    expect(buildSegments(input)).toEqual([{ start: T0, end: T0 + 70 }])
    expect(input).toEqual(copy) // same order, nothing removed in place
  })
})

describe('unionIntervals', () => {
  it('returns an empty list for no intervals', () => {
    expect(unionIntervals([])).toEqual([])
  })

  it('keeps disjoint intervals apart and sorts them', () => {
    expect(unionIntervals([{ start: 200, end: 300 }, { start: 0, end: 100 }])).toEqual([
      { start: 0, end: 100 },
      { start: 200, end: 300 },
    ])
  })

  it('merges a fully contained interval', () => {
    expect(unionIntervals([{ start: 0, end: 500 }, { start: 100, end: 200 }])).toEqual([{ start: 0, end: 500 }])
  })

  it('merges a partial overlap', () => {
    expect(unionIntervals([{ start: 0, end: 300 }, { start: 200, end: 500 }])).toEqual([{ start: 0, end: 500 }])
  })

  it('merges touching intervals (end == next start)', () => {
    expect(unionIntervals([{ start: 0, end: 100 }, { start: 100, end: 200 }])).toEqual([{ start: 0, end: 200 }])
  })

  it('merges a chain through a bridging interval', () => {
    expect(unionIntervals([
      { start: 0, end: 100 }, { start: 300, end: 400 }, { start: 50, end: 350 },
    ])).toEqual([{ start: 0, end: 400 }])
  })

  it('drops empty and inverted intervals and does not mutate the input', () => {
    const input: Interval[] = [{ start: 5, end: 5 }, { start: 9, end: 3 }, { start: 10, end: 20 }]
    const snapshot = JSON.stringify(input)
    expect(unionIntervals(input)).toEqual([{ start: 10, end: 20 }])
    expect(JSON.stringify(input)).toBe(snapshot)
  })

  it('does not double-count two agents working at the same time (S4-2)', () => {
    // Agent A: events at +0 and +120 -> [0, 180). Agent B: +60 and +300 -> [60, 360).
    const a = buildSegments([T0, T0 + 120])
    const b = buildSegments([T0 + 60, T0 + 300])
    expect(totalSeconds(a) + totalSeconds(b)).toBe(180 + 300)
    const union = unionIntervals([...a, ...b])
    expect(union).toEqual([{ start: T0, end: T0 + 360 }])
    expect(totalSeconds(union)).toBe(360)
  })

  it('counts a full overlap once (S4-2)', () => {
    const a = buildSegments([T0, T0 + 300])
    const b = buildSegments([T0 + 60, T0 + 120])
    expect(totalSeconds(unionIntervals([...a, ...b]))).toBe(360)
  })
})

describe('clipIntervals', () => {
  it('clips both ends and drops what falls outside', () => {
    expect(clipIntervals([
      { start: 0, end: 50 }, { start: 40, end: 160 }, { start: 150, end: 400 }, { start: 200, end: 300 },
    ], 100, 200)).toEqual([{ start: 100, end: 160 }, { start: 150, end: 200 }])
  })

  it('treats the end bound as exclusive', () => {
    expect(clipIntervals([{ start: 200, end: 260 }], 100, 200)).toEqual([])
    expect(clipIntervals([{ start: 40, end: 100 }], 100, 200)).toEqual([])
  })
})

describe('calendar helpers', () => {
  it('addDays crosses month, year and leap-day borders', () => {
    expect(addDays('2026-10-31', 1)).toBe('2026-11-01')
    expect(addDays('2026-12-31', 1)).toBe('2027-01-01')
    expect(addDays('2028-02-28', 1)).toBe('2028-02-29')
    expect(addDays('2027-03-01', -1)).toBe('2027-02-28')
  })

  it('rejects malformed and impossible dates', () => {
    expect(() => addDays('2026-13-01', 1)).toThrow(RangeError)
    expect(() => addDays('2026-02-30', 1)).toThrow(RangeError)
    expect(() => localDayBounds('2026-10-2', TZ)).toThrow(RangeError)
    expect(() => localDayBounds('nap', TZ)).toThrow(RangeError)
  })

  it('localDate reads the zone, not UTC', () => {
    expect(localDate(t('2026-10-27T23:30:00Z'), TZ)).toBe('2026-10-28') // CET: 00:30 next day
    expect(localDate(t('2026-10-27T22:59:59Z'), TZ)).toBe('2026-10-27')
    expect(localDate(t('2026-07-31T22:30:00Z'), TZ)).toBe('2026-08-01') // CEST: 00:30
  })
})

describe('localDayBounds (Europe/Budapest)', () => {
  it('a normal CET day is 24 h from 23:00Z to 23:00Z', () => {
    const b = localDayBounds('2026-10-28', TZ)
    expect(b.start).toBe(t('2026-10-27T23:00:00Z'))
    expect(b.end).toBe(t('2026-10-28T23:00:00Z'))
    expect((b.end - b.start) / 3600).toBe(24)
  })

  it('a normal CEST day starts at 22:00Z', () => {
    const b = localDayBounds('2026-07-15', TZ)
    expect(b.start).toBe(t('2026-07-14T22:00:00Z'))
    expect(b.end).toBe(t('2026-07-15T22:00:00Z'))
  })

  it('2026-10-25 (DST ends) is 25 h long', () => {
    const b = localDayBounds('2026-10-25', TZ)
    expect(b.start).toBe(t('2026-10-24T22:00:00Z')) // midnight CEST
    expect(b.end).toBe(t('2026-10-25T23:00:00Z')) // midnight CET
    expect((b.end - b.start) / 3600).toBe(25)
  })

  it('2027-03-28 (DST starts) is 23 h long', () => {
    const b = localDayBounds('2027-03-28', TZ)
    expect(b.start).toBe(t('2027-03-27T23:00:00Z')) // midnight CET
    expect(b.end).toBe(t('2027-03-28T22:00:00Z')) // midnight CEST
    expect((b.end - b.start) / 3600).toBe(23)
  })

  it('consecutive days tile without gap or overlap across both DST changes', () => {
    for (const d of ['2026-10-24', '2026-10-25', '2027-03-27', '2027-03-28']) {
      expect(localDayBounds(d, TZ).end).toBe(localDayBounds(addDays(d, 1), TZ).start)
    }
  })

  it('works for UTC as well', () => {
    const b = localDayBounds('2026-10-28', 'UTC')
    expect(b.start).toBe(t('2026-10-28T00:00:00Z'))
    expect(b.end).toBe(t('2026-10-29T00:00:00Z'))
  })
})

describe('summarizeDay', () => {
  it('is zero for no intervals', () => {
    const s = summarizeDay([], '2026-10-28', TZ)
    expect(s.minutes).toBe(0)
    expect(s.segments).toBe(0)
    expect(s.intervals).toEqual([])
  })

  it('hand-computed day (S4-1): 3 segments, 1 + 11 + 31 minutes', () => {
    const events = [
      T0, // lone: 1 min
      T0 + 3600, T0 + 3600 + 600, // 600 s gap: [0, 660) = 11 min
      T0 + 7200, T0 + 7200 + 600, T0 + 7200 + 1200, T0 + 7200 + 1800, // chain: [0, 1860) = 31 min
    ]
    const s = summarizeDay(buildSegments(events), '2026-10-28', TZ)
    expect(s.segments).toBe(3)
    expect(s.minutes).toBe(1 + 11 + 31)
  })

  it('floors partial minutes', () => {
    const s = summarizeDay([{ start: T0, end: T0 + 119 }], '2026-10-28', TZ)
    expect(s.minutes).toBe(1)
  })

  it('splits a segment crossing local midnight into the two days', () => {
    // Events 22:55Z and 23:05Z (600 s apart) = [22:55Z, 23:06Z), midnight at 23:00Z:
    // 5 min on 10-27, 6 min on 10-28, one segment on each.
    const segs = buildSegments([t('2026-10-27T22:55:00Z'), t('2026-10-27T23:05:00Z')])
    expect(segs).toHaveLength(1)
    const before = summarizeDay(segs, '2026-10-27', TZ)
    const after = summarizeDay(segs, '2026-10-28', TZ)
    expect(before.minutes).toBe(5)
    expect(before.segments).toBe(1)
    expect(after.minutes).toBe(6)
    expect(after.segments).toBe(1)
    expect(before.minutes + after.minutes).toBe(11)
  })

  it('does not count a segment that ends exactly at midnight on the next day', () => {
    const segs: Interval[] = [{ start: t('2026-10-27T22:50:00Z'), end: t('2026-10-27T23:00:00Z') }]
    expect(summarizeDay(segs, '2026-10-27', TZ)).toMatchObject({ minutes: 10, segments: 1 })
    expect(summarizeDay(segs, '2026-10-28', TZ)).toMatchObject({ minutes: 0, segments: 0 })
  })

  it('merges overlapping agent intervals for the minutes (S4-2)', () => {
    const a = buildSegments([T0, T0 + 120])
    const b = buildSegments([T0 + 60, T0 + 300])
    const s = summarizeDay([...a, ...b], '2026-10-28', TZ)
    expect(s.minutes).toBe(6)
    expect(s.intervals).toEqual([{ start: T0, end: T0 + 360 }])
  })

  it('a segment covering the whole DST-end day yields 25 h = 1500 minutes', () => {
    const b = localDayBounds('2026-10-25', TZ)
    const s = summarizeDay([{ start: b.start - 3600, end: b.end + 3600 }], '2026-10-25', TZ)
    expect(s.minutes).toBe(1500)
    expect(s.segments).toBe(1)
  })

  it('a segment covering the whole DST-start day yields 23 h = 1380 minutes', () => {
    const b = localDayBounds('2027-03-28', TZ)
    const s = summarizeDay([{ start: b.start - 3600, end: b.end + 3600 }], '2027-03-28', TZ)
    expect(s.minutes).toBe(1380)
  })

  it('local midnight in the DST-end night is the CEST one: 00:30 local is 22:30Z the day before', () => {
    // 2026-10-24T22:30:00Z = 00:30 CEST on 10-25 -> belongs to 10-25, not 10-24.
    const seg: Interval[] = [{ start: t('2026-10-24T22:30:00Z'), end: t('2026-10-24T22:40:00Z') }]
    expect(summarizeDay(seg, '2026-10-25', TZ).minutes).toBe(10)
    expect(summarizeDay(seg, '2026-10-24', TZ).minutes).toBe(0)
  })

  it('the repeated DST hour (02:00-03:00 twice) is counted in full', () => {
    // 2026-10-25 00:30Z = 02:30 CEST (first pass); 01:30Z = 02:30 CET (second pass).
    const seg = buildSegments([t('2026-10-25T00:30:00Z'), t('2026-10-25T01:30:00Z')])
    expect(seg).toHaveLength(2) // 3600 s apart
    expect(summarizeDay(seg, '2026-10-25', TZ).minutes).toBe(2)
  })

  it('returns the day bounds with the summary', () => {
    const s = summarizeDay([], '2027-03-28', TZ)
    expect(s.date).toBe('2027-03-28')
    expect(s.end - s.start).toBe(23 * 3600)
  })
})
