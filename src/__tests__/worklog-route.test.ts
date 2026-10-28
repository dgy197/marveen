import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import { requiresAuth } from '../web/auth-gate.js'
import { operatorGateDecision } from '../web/operator-gate.js'
import { setWorklogOptionsForTest, tryHandleWorklog } from '../web/routes/worklog.js'
import { localDayBounds } from '../web/worklog-intervals.js'
import { DAY_KEYS, DETAIL_KEYS, RANGE_KEYS } from '../web/worklog.js'
import type { RouteContext } from '../web/routes/types.js'

// Card d7b2d5c8 (S4-B): the HTTP surface of the work log. Auth matrix, date
// validation, range cap, response keys, and the wiring pin in web.ts.

type Auth = RouteContext['auth']
const TZ = 'Europe/Budapest'
const MARK = 'TITOK-MARKER'
const DAY = '2026-10-20'
const t0 = localDayBounds(DAY, TZ).start

function call(pathAndQuery: string, opts: { method?: string; auth?: Auth | null } = {}): { ctx: RouteContext; out: { status: number; body: any; headers: Record<string, unknown> } } {
  const out: { status: number; body: any; headers: Record<string, unknown> } = { status: 0, body: null, headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  const auth = opts.auth === undefined ? ({ kind: 'token' } as Auth) : (opts.auth ?? undefined)
  return { ctx: { req: {} as any, res, path: url.pathname, method: opts.method ?? 'GET', url, auth } as RouteContext, out }
}

beforeEach(() => {
  initDatabase(':memory:')
  setWorklogOptionsForTest({ tz: TZ, ownerChatId: 'OWNER-CHAT' })
  const db = getDb()
  db.prepare('INSERT INTO conversation_log (agent_id, chat_id, direction, message_id, text, created_at) VALUES (?, ?, ?, ?, ?, ?)').run('a1', 'OWNER-CHAT', 'in', 'm1', MARK, t0 + 3600)
  db.prepare('INSERT INTO token_usage (agent, session_id, timestamp, content_preview) VALUES (?, ?, ?, ?)').run('A', 's', t0 + 7200, MARK)
  db.prepare('INSERT INTO tool_call_log (session_id, tool_name, input_summary, created_at, agent_id) VALUES (?, ?, ?, ?, ?)').run('s', 'Bash', MARK, t0 + 7300, 'A')
  db.prepare('INSERT INTO agent_messages (from_agent, to_agent, content, result, created_at) VALUES (?, ?, ?, ?, ?)').run('a1', 'a2', MARK, MARK, t0 + 100)
})
afterEach(() => { setWorklogOptionsForTest(null) })

describe('routing and shape', () => {
  it('GET /api/worklog?from&to answers the per-day aggregate with exactly the allowlisted keys', async () => {
    const r = call(`/api/worklog?from=${DAY}&to=${DAY}`)
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(Object.keys(r.out.body)).toEqual([...RANGE_KEYS])
    expect(r.out.body).toMatchObject({ tz: TZ, from: DAY, to: DAY })
    expect(Object.keys(r.out.body.days[0])).toEqual([...DAY_KEYS])
    expect(r.out.body.days[0]).toMatchObject({ me_minutes: 1, ai_minutes: 2, prompts_owner: 1, prompts_agent: 1 })
    expect(r.out.headers['Cache-Control']).toBe('private, no-store')
  })

  it('no query: the last 30 days', async () => {
    const r = call('/api/worklog')
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(r.out.body.days).toHaveLength(30)
  })

  it('only "to": 30 days ending there', async () => {
    const r = call(`/api/worklog?to=${DAY}`)
    await tryHandleWorklog(r.ctx)
    expect(r.out.body.days).toHaveLength(30)
    expect(r.out.body.to).toBe(DAY)
    expect(r.out.body.from).toBe('2026-09-21')
  })

  it('GET /api/worklog/:date answers the day detail with exactly the allowlisted keys', async () => {
    const r = call(`/api/worklog/${DAY}`)
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(Object.keys(r.out.body)).toEqual([...DETAIL_KEYS])
    expect(r.out.body.date).toBe(DAY)
    expect(r.out.body.prompts).toHaveLength(2)
  })

  it('TITOK-MARKER from every text column is in no response', async () => {
    for (const p of [`/api/worklog?from=${DAY}&to=${DAY}`, `/api/worklog/${DAY}`]) {
      const r = call(p)
      await tryHandleWorklog(r.ctx)
      expect(JSON.stringify(r.out.body)).not.toContain(MARK)
    }
  })

  it('does not claim other paths', async () => {
    for (const p of ['/api/worklogs', '/api/worklog/', `/api/worklog/${DAY}/x`, '/api/other']) {
      expect(await tryHandleWorklog(call(p).ctx)).toBe(false)
    }
  })
})

describe('validation', () => {
  it.each([
    ['from=abc'], ['from=2026-13-01'], ['from=2026-02-30'], ['to=2026-10-2'], ['from=2026-10-20&to=nope'],
    ['from=2026-10-20&to=2026-10-19'],
    ['from=2026-01-01&to=2026-04-03'], // 93 days
  ])('range ?%s -> 400', async (q) => {
    const r = call(`/api/worklog?${q}`)
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(400)
  })

  it('92 days is accepted, 93 is not', async () => {
    const ok = call('/api/worklog?from=2026-01-01&to=2026-04-02')
    await tryHandleWorklog(ok.ctx)
    expect(ok.out.status).toBe(200)
    expect(ok.out.body.days).toHaveLength(92)
  })

  it.each(['1999-12-31', '2101-01-01'])('year outside 2000..2100: range from=%s and detail -> 400 (S4-N2)', async (d) => {
    for (const p of [`/api/worklog?from=${d}&to=${d}`, `/api/worklog/${d}`]) {
      const r = call(p)
      expect(await tryHandleWorklog(r.ctx)).toBe(true)
      expect(r.out.status).toBe(400)
    }
  })

  it('an unexpected SQL error answers 500 with a generic body: no stack, path or SQL text (S4-M4)', async () => {
    // A generated column whose function fails once armed (after the insert): a SELECT-time error that is not "no such ...".
    let armed = false
    getDb().function('wl_boom', { deterministic: true }, (v: unknown) => { if (armed) throw new Error('wl_boom /secret/path'); return v as number })
    getDb().exec('CREATE TABLE function_decisions (id INTEGER PRIMARY KEY, recorded_via TEXT, x INTEGER, created_at INTEGER GENERATED ALWAYS AS (wl_boom(x)) VIRTUAL)')
    getDb().exec("INSERT INTO function_decisions (recorded_via, x) VALUES ('session', 1)")
    armed = true
    for (const p of [`/api/worklog?from=${DAY}&to=${DAY}`, `/api/worklog/${DAY}`]) {
      const r = call(p)
      expect(await tryHandleWorklog(r.ctx)).toBe(true)
      expect(r.out.status).toBe(500)
      expect(r.out.body).toEqual({ error: 'Internal error' })
      expect(JSON.stringify(r.out.body)).not.toMatch(/wl_boom|secret|SELECT|function_decisions|\/|stack/i)
    }
  })

  it.each(['2026-13-01', '2026-02-30', 'abc', '20261020', '2026-10-2', '%E0%A4%A', '..%2F..'])('detail date %s -> 400', async (d) => {
    const r = call(`/api/worklog/${d}`)
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(400)
  })
})

describe('auth matrix', () => {
  const paths = ['/api/worklog', `/api/worklog/${DAY}`]

  it.each(paths)('%s: no principal -> 401', async (p) => {
    const r = call(p, { auth: null })
    await tryHandleWorklog(r.ctx)
    expect(r.out.status).toBe(401)
  })

  it.each(paths)('%s: operator-scoped device -> 403, federation -> 403', async (p) => {
    for (const auth of [{ kind: 'device', scope: 'operator' }, { kind: 'federation', peer: 'x' }] as Auth[]) {
      const r = call(p, { auth })
      await tryHandleWorklog(r.ctx)
      expect(r.out.status).toBe(403)
      expect(JSON.stringify(r.out.body)).not.toContain(MARK)
    }
  })

  it.each(paths)('%s: token, session and full device are allowed', async (p) => {
    for (const auth of [{ kind: 'token' }, { kind: 'session', user: 'u' }, { kind: 'device', scope: 'full' }] as Auth[]) {
      const r = call(p, { auth })
      await tryHandleWorklog(r.ctx)
      expect(r.out.status).toBe(200)
    }
  })

  it.each(['POST', 'PUT', 'PATCH', 'DELETE'])('%s -> 405 with Allow: GET', async (method) => {
    const r = call('/api/worklog', { method })
    expect(await tryHandleWorklog(r.ctx)).toBe(true)
    expect(r.out.status).toBe(405)
    expect(r.out.headers.Allow).toBe('GET')
  })

  it('the dashboard gate requires auth and shuts the operator key out', () => {
    for (const p of paths) {
      expect(requiresAuth(p, 'GET')).toBe(true)
      expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, p, () => ({ enabled: true, capabilities: {} as never, commands: [] }))).toBe('operator credential: not an operator endpoint')
      expect(operatorGateDecision({ kind: 'token' }, p, () => { throw new Error('must not read access for a token') })).toBeNull()
    }
  })
})

describe('wiring in web.ts', () => {
  it('web.ts routes /api/worklog through tryHandleWorklog inside the route chain, after tryHandleFunkciok', () => {
    const web = readFileSync(join(__dirname, '..', 'web.ts'), 'utf-8')
    const code = web.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    expect(code).toMatch(/^\s*if \(await tryHandleWorklog\(routeCtx\)\) return$/m)
    expect(code).toMatch(/import \{[^}]*\btryHandleWorklog\b[^}]*\} from '\.\/web\/routes\/worklog\.js'/)
    const at = code.indexOf('if (await tryHandleWorklog(routeCtx)) return')
    expect(at).toBeGreaterThan(code.indexOf('if (await tryHandleAuth(routeCtx)) return'))
    expect(at).toBeGreaterThan(code.indexOf('if (await tryHandleFunkciok(routeCtx)) return'))
  })
})
