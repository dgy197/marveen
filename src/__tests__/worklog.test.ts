import { describe, it, expect, beforeEach } from 'vitest'
import { initDatabase, getDb } from '../db.js'
import { localDayBounds } from '../web/worklog-intervals.js'
import {
  DAY_KEYS,
  DETAIL_KEYS,
  PROMPT_KEYS,
  RANGE_KEYS,
  buildWorklogDay,
  buildWorklogRange,
  isValidDate,
  type WorklogOptions,
} from '../web/worklog.js'

// Card (S4-B): the aggregation over the four sources, on an in-memory DB.
// Every text column carries a marker; none may reach an output.

const TZ = 'Europe/Budapest'
const OWNER = 'OWNER-CHAT'
const OPTS: WorklogOptions = { tz: TZ, ownerChatId: OWNER }
const MARK = 'TITOK-MARKER'
const DAY = '2026-10-20'
const t0 = localDayBounds(DAY, TZ).start

let mid = 0
function convIn(agent: string, chat: string, ts: number, direction: 'in' | 'out' = 'in'): void {
  getDb().prepare(
    'INSERT INTO conversation_log (agent_id, chat_id, direction, message_id, text, created_at) VALUES (?, ?, ?, ?, ?, ?)',
  ).run(agent, chat, direction, `m${++mid}`, MARK, ts)
}
function token(agent: string, ts: number): void {
  getDb().prepare('INSERT INTO token_usage (agent, session_id, timestamp, content_preview) VALUES (?, ?, ?, ?)').run(agent, 's', ts, MARK)
}
function tool(agent: string | null, ts: number): void {
  getDb().prepare('INSERT INTO tool_call_log (session_id, tool_name, input_summary, created_at, agent_id) VALUES (?, ?, ?, ?, ?)').run('s', 'Bash', MARK, ts, agent)
}
function agentMsg(from: string, to: string, ts: number): void {
  getDb().prepare('INSERT INTO agent_messages (from_agent, to_agent, content, result, created_at) VALUES (?, ?, ?, ?, ?)').run(from, to, MARK, MARK, ts)
}

beforeEach(() => {
  mid = 0
  initDatabase(':memory:')
})

function seedFullDay(): void {
  // Owner: 3 inbound in the owner chat -> segments [3600,3960) and [4600,4660)
  convIn('a1', OWNER, t0 + 3600)
  convIn('a2', OWNER, t0 + 3900)
  convIn('a1', OWNER, t0 + 4600) // gap 700 > 600 -> a new segment
  convIn('a1', 'OTHER-CHAT', t0 + 20000) // another chat: not the owner
  convIn('a1', OWNER, t0 + 21000, 'out') // outbound: not the owner
  // Decisions / answered questions (optional tables, created here)
  const db = getDb()
  db.exec('CREATE TABLE function_decisions (id INTEGER PRIMARY KEY, quote_short TEXT, recorded_via TEXT, created_at INTEGER)')
  db.exec('CREATE TABLE open_questions (id INTEGER PRIMARY KEY, body TEXT, answered_via TEXT, answered_at INTEGER)')
  const dec = db.prepare('INSERT INTO function_decisions (quote_short, recorded_via, created_at) VALUES (?, ?, ?)')
  dec.run(MARK, 'session', t0 + 30000) // owner: 1 minute
  dec.run(MARK, 'token', t0 + 40000) // an agent's act: not the owner
  const q = db.prepare('INSERT INTO open_questions (body, answered_via, answered_at) VALUES (?, ?, ?)')
  q.run(MARK, 'ui', t0 + 50000) // owner: 1 minute
  q.run(MARK, 'tg', t0 + 52000) // not the dashboard
  // AI: A [7200,7560) (6 min), B [7400,7860) (7 min), union [7200,7860) = 11 min
  token('A', t0 + 7200)
  token('A', t0 + 7260)
  tool('A', t0 + 7500)
  token('B', t0 + 7400)
  tool('B', t0 + 7800)
  tool(null, t0 + 60000) // unknown agent: 1 minute
  // Prompts between agents; 'system' does not count
  agentMsg('a1', 'a2', t0 + 100)
  agentMsg('system', 'a2', t0 + 200)
}

describe('buildWorklogRange: aggregation across the four sources', () => {
  it('counts me / ai minutes, segments, prompts and per-agent minutes (hand-computed)', () => {
    seedFullDay()
    const r = buildWorklogRange(getDb(), DAY, DAY, OPTS)
    expect(r.days).toHaveLength(1)
    const d = r.days[0]
    expect(d.date).toBe(DAY)
    // 360 s + 60 s + 60 s (decision) + 60 s (answered question) = 540 s = 9 min, 4 segments
    expect(d.me_minutes).toBe(9)
    expect(d.me_segments).toBe(4)
    // union [7200,7860) = 660 s + 60 s (unknown agent) = 720 s = 12 min, 2 merged blocks
    expect(d.ai_minutes).toBe(12)
    expect(d.ai_segments).toBe(2)
    expect(d.ai_by_agent).toEqual([
      { agent: 'B', minutes: 7 },
      { agent: 'A', minutes: 6 },
      { agent: '(ismeretlen)', minutes: 1 },
    ])
    expect(d.prompts_owner).toBe(3)
    expect(d.prompts_agent).toBe(1)
    expect(d.sources).toEqual({ token_usage: true, tool_call_log: true })
  })

  it('two agents working at the same time are not counted twice', () => {
    for (const a of ['A', 'B']) { token(a, t0 + 1000); token(a, t0 + 1100) }
    const d = buildWorklogRange(getDb(), DAY, DAY, OPTS).days[0]
    expect(d.ai_minutes).toBe(2) // [1000,1160) = 160 s -> 2 min, once
    expect(d.ai_by_agent.map(a => a.minutes)).toEqual([2, 2])
  })

  it('a segment that starts before the day (inside the 600 s lookback) is clipped into it', () => {
    token('A', t0 - 300)
    token('A', t0 + 200) // gap 500 <= 600: one segment [t0-300, t0+260)
    const d = buildWorklogRange(getDb(), DAY, DAY, OPTS).days[0]
    expect(d.ai_minutes).toBe(4) // 260 s
    expect(d.ai_segments).toBe(1)
  })

  it('a missing function_decisions / open_questions table is no events, not an error', () => {
    convIn('a1', OWNER, t0 + 100)
    const d = buildWorklogRange(getDb(), DAY, DAY, OPTS).days[0]
    expect(d.me_minutes).toBe(1)
  })

  it('a table with the wrong columns ("no such column") is no events, not an error', () => {
    getDb().exec('CREATE TABLE function_decisions (id INTEGER PRIMARY KEY)')
    convIn('a1', OWNER, t0 + 100)
    const d = buildWorklogRange(getDb(), DAY, DAY, OPTS).days[0]
    expect(d.me_minutes).toBe(1)
  })

  it('any other SQL error in an optional table propagates (S4-M4)', () => {
    // A generated column whose function fails once armed (after the insert): a SELECT-time error that is not "no such ...".
    let armed = false
    getDb().function('wl_boom', { deterministic: true }, (v: unknown) => { if (armed) throw new Error('wl_boom /secret/path'); return v as number })
    getDb().exec('CREATE TABLE function_decisions (id INTEGER PRIMARY KEY, recorded_via TEXT, x INTEGER, created_at INTEGER GENERATED ALWAYS AS (wl_boom(x)) VIRTUAL)')
    getDb().exec("INSERT INTO function_decisions (recorded_via, x) VALUES ('session', 1)")
    armed = true
    expect(() => buildWorklogRange(getDb(), DAY, DAY, OPTS)).toThrow(/wl_boom/)
    expect(() => buildWorklogDay(getDb(), DAY, OPTS)).toThrow(/wl_boom/)
  })

  it('no owner chat configured: no chat events, the rest still counts', () => {
    seedFullDay()
    const d = buildWorklogRange(getDb(), DAY, DAY, { tz: TZ, ownerChatId: null }).days[0]
    expect(d.prompts_owner).toBe(0)
    expect(d.me_minutes).toBe(2) // decision + answered question
    expect(d.ai_minutes).toBe(12)
  })

  it('source flags: false before the oldest row of the table (prune notice)', () => {
    seedFullDay()
    const r = buildWorklogRange(getDb(), '2026-10-18', DAY, OPTS)
    expect(r.days.map(d => d.date)).toEqual(['2026-10-18', '2026-10-19', DAY])
    expect(r.days[0].sources).toEqual({ token_usage: false, tool_call_log: false })
    expect(r.days[1].sources).toEqual({ token_usage: false, tool_call_log: false })
    expect(r.days[2].sources).toEqual({ token_usage: true, tool_call_log: true })
  })

  it('empty tables: all-zero days, sources false', () => {
    const d = buildWorklogRange(getDb(), DAY, DAY, OPTS).days[0]
    expect(d).toMatchObject({ me_minutes: 0, ai_minutes: 0, prompts_owner: 0, prompts_agent: 0, ai_by_agent: [] })
    expect(d.sources).toEqual({ token_usage: false, tool_call_log: false })
  })

  it('the DST-autumn day (25 h) is one day: an event after 02:00 local lands on it', () => {
    const day = '2026-10-25'
    const b = localDayBounds(day, TZ)
    expect(b.end - b.start).toBe(25 * 3600)
    token('A', b.start + 24 * 3600)
    const r = buildWorklogRange(getDb(), day, '2026-10-26', OPTS)
    expect(r.days[0].ai_minutes).toBe(1)
    expect(r.days[1].ai_minutes).toBe(0)
  })
})

describe('S4-3 / 5.4: no text ever reaches a response', () => {
  it('TITOK-MARKER in every text column is absent from both outputs', () => {
    seedFullDay()
    const range = JSON.stringify(buildWorklogRange(getDb(), '2026-10-01', '2026-10-31', OPTS))
    const day = JSON.stringify(buildWorklogDay(getDb(), DAY, OPTS))
    expect(range).not.toContain(MARK)
    expect(day).not.toContain(MARK)
    expect(day).not.toMatch(/"(text|content|content_preview|input_summary|result|quote_short|body)"/)
  })

  it('key allowlists are exact (snapshot)', () => {
    seedFullDay()
    const r = buildWorklogRange(getDb(), DAY, DAY, OPTS)
    expect(Object.keys(r)).toEqual([...RANGE_KEYS])
    expect(Object.keys(r.days[0])).toEqual([...DAY_KEYS])
    expect(Object.keys(r.days[0].sources)).toEqual(['token_usage', 'tool_call_log'])
    expect(Object.keys(r.days[0].ai_by_agent[0])).toEqual(['agent', 'minutes'])

    const d = buildWorklogDay(getDb(), DAY, OPTS)
    expect(Object.keys(d)).toEqual([...DETAIL_KEYS])
    expect([...DETAIL_KEYS]).toEqual(['date', 'tz', 'day_start', 'day_end', 'me', 'ai', 'ai_by_agent', 'prompts', 'truncated', 'sources'])
    expect(d.truncated).toBe(false)
    expect(Object.keys(d.prompts[0])).toEqual([...PROMPT_KEYS])
    expect(Object.keys(d.me[0])).toEqual(['start', 'end'])
    expect(Object.keys(d.ai_by_agent[0])).toEqual(['agent', 'segments'])
    expect([...DAY_KEYS]).toMatchInlineSnapshot(`
      [
        "date",
        "me_minutes",
        "me_segments",
        "ai_minutes",
        "ai_segments",
        "ai_by_agent",
        "prompts_owner",
        "prompts_agent",
        "sources",
      ]
    `)
  })
})

describe('buildWorklogDay', () => {
  it('returns clipped intervals, per-agent segments and the ordered prompt list', () => {
    seedFullDay()
    const d = buildWorklogDay(getDb(), DAY, OPTS)
    expect(d.tz).toBe(TZ)
    expect(d.day_start).toBe(t0)
    expect(d.day_end - d.day_start).toBe(24 * 3600)
    expect(d.me).toEqual([
      { start: t0 + 3600, end: t0 + 3960 },
      { start: t0 + 4600, end: t0 + 4660 },
      { start: t0 + 30000, end: t0 + 30060 },
      { start: t0 + 50000, end: t0 + 50060 },
    ])
    expect(d.ai).toEqual([
      { start: t0 + 7200, end: t0 + 7860 },
      { start: t0 + 60000, end: t0 + 60060 },
    ])
    expect(d.ai_by_agent).toEqual([ // by agent name
      { agent: '(ismeretlen)', segments: 1 },
      { agent: 'A', segments: 1 },
      { agent: 'B', segments: 1 },
    ])
    expect(d.prompts.map(p => [p.kind, p.ts - t0])).toEqual([['agent', 100], ['owner', 3600], ['owner', 3900], ['owner', 4600]])
    expect(d.prompts[0]).toEqual({ ts: t0 + 100, kind: 'agent', agent: 'a1', from_agent: 'a1', to_agent: 'a2' })
    expect(d.prompts[1]).toEqual({ ts: t0 + 3600, kind: 'owner', agent: 'a1', from_agent: null, to_agent: 'a1' })
  })

  it('caps the prompt list at 2000 rows, keeps the first ones in order and flags truncated (S4-M3)', () => {
    const ins = getDb().prepare('INSERT INTO agent_messages (from_agent, to_agent, content, created_at) VALUES (?, ?, ?, ?)')
    getDb().transaction(() => { for (let i = 0; i < 2100; i++) ins.run('a1', 'a2', 'x', t0 + i) })()
    const d = buildWorklogDay(getDb(), DAY, OPTS)
    expect(d.prompts).toHaveLength(2000)
    expect(d.truncated).toBe(true)
    expect(d.prompts[0].ts).toBe(t0)
    expect(d.prompts[1999].ts).toBe(t0 + 1999)
    expect(d.prompts.map(p => p.ts)).toEqual([...d.prompts.map(p => p.ts)].sort((a, b) => a - b))
  })

  it('exactly 2000 prompts is not truncated', () => {
    const ins = getDb().prepare('INSERT INTO agent_messages (from_agent, to_agent, content, created_at) VALUES (?, ?, ?, ?)')
    getDb().transaction(() => { for (let i = 0; i < 2000; i++) ins.run('a1', 'a2', 'x', t0 + i) })()
    const d = buildWorklogDay(getDb(), DAY, OPTS)
    expect(d.prompts).toHaveLength(2000)
    expect(d.truncated).toBe(false)
  })

  it('isValidDate accepts 2000..2100 only (S4-N2)', () => {
    for (const ok of ['2000-01-01', '2026-10-20', '2100-12-31']) expect(isValidDate(ok)).toBe(true)
    for (const bad of ['1999-12-31', '2101-01-01', '0000-01-01', '9999-12-31']) expect(isValidDate(bad)).toBe(false)
  })
})

describe('S4-4: volume', () => {
  it('30 days x 5 agents x 2000 token/tool events + 200 messages/day answers well under 2 s', () => {
    const db = getDb()
    const insT = db.prepare('INSERT INTO token_usage (agent, session_id, timestamp) VALUES (?, ?, ?)')
    const insL = db.prepare('INSERT INTO tool_call_log (session_id, tool_name, created_at, agent_id) VALUES (?, ?, ?, ?)')
    const insM = db.prepare('INSERT INTO agent_messages (from_agent, to_agent, content, created_at) VALUES (?, ?, ?, ?)')
    const insC = db.prepare('INSERT INTO conversation_log (agent_id, chat_id, direction, message_id, text, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    const from = '2026-09-21'
    const base = localDayBounds(from, TZ).start
    db.transaction(() => {
      for (let day = 0; day < 30; day++) {
        for (let a = 0; a < 5; a++) {
          for (let i = 0; i < 1000; i++) {
            const ts = base + day * 86400 + i * 80 + a * 7
            insT.run(`agent${a}`, 's', ts)
            insL.run('s', 'Bash', ts + 3, `agent${a}`)
            if (i % 5 === 0) {
              insM.run(`agent${a}`, `agent${(a + 1) % 5}`, 'x', ts + 5)
              insC.run(`agent${a}`, i % 2 ? OWNER : 'OTHER-CHAT', 'in', `v${day}-${a}-${i}`, 'x', ts + 6)
            }
          }
        }
      }
    })()
    const started = Date.now()
    const r = buildWorklogRange(db, from, '2026-10-20', OPTS)
    const ms = Date.now() - started
    expect(r.days).toHaveLength(30)
    expect(r.days[0].prompts_agent).toBeGreaterThan(0)
    expect(r.days[0].prompts_owner).toBeGreaterThan(0)
    expect(ms).toBeLessThan(2000)
  }, 60_000)
})
