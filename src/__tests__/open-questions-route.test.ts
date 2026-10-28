import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { initDatabase, getDb } from '../db.js'
import { requiresAuth } from '../web/auth-gate.js'
import { operatorGateDecision } from '../web/operator-gate.js'
import { QUESTION_KEYS, QUESTION_OPEN_PER_AGENT_MAX } from '../web/open-questions.js'
import { setQuestionsClockForTest, tryHandleOpenQuestions } from '../web/routes/open-questions.js'
import type { RouteContext } from '../web/routes/types.js'

// Open questions S3-N1: the HTTP surface. Auth matrix of POST and GET (spec
// 5.1), validation answers (400 / 413 / 422 / 429), the GET filters with the
// lazy expiry, the response allowlist (spec 5.4) and the marker test.

vi.mock('../web/agent-config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/agent-config.js')>()),
  isKnownAgent: (n: string) => n === 'alfa' || n === 'beta',
}))

const MARKER = 'TITOK-MARKER'
const T0 = 1_760_000_000
const sorted = (a: readonly string[]) => [...a].sort()

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const TOKEN_ALFA: Auth = { kind: 'token', agent: 'alfa' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'full' }
const DEVICE_OP: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'operator' }
const SESSION: Auth = { kind: 'session', user: 'tulaj-teszt' }
const FEDERATION: Auth = { kind: 'federation', peer: 'teszt-peer' }

type Out = { status: number; body: any; headers: Record<string, unknown> }

function call(pathAndQuery: string, opts: { method?: string; auth?: Auth | null; body?: string; headers?: Record<string, string> } = {}): { ctx: RouteContext; out: Out } {
  const out: Out = { status: 0, body: null, headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const body = opts.body ?? ''
  const req: any = Object.assign(Readable.from([Buffer.from(body, 'utf8')]), {
    headers: { 'content-length': String(Buffer.byteLength(body)), ...(opts.headers ?? {}) },
  })
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  const auth = opts.auth === undefined ? TOKEN_ALFA : (opts.auth ?? undefined)
  return { ctx: { req, res, path: url.pathname, method: opts.method ?? 'GET', url, auth } as RouteContext, out }
}

async function post(body: unknown, auth: Auth | null = TOKEN_ALFA, headers?: Record<string, string>): Promise<Out> {
  const r = call('/api/questions', { method: 'POST', auth, body: typeof body === 'string' ? body : JSON.stringify(body), headers })
  expect(await tryHandleOpenQuestions(r.ctx)).toBe(true)
  return r.out
}

async function get(q = '', auth: Auth | null = TOKEN): Promise<Out> {
  const r = call(`/api/questions${q}`, { auth })
  expect(await tryHandleOpenQuestions(r.ctx)).toBe(true)
  return r.out
}

const good = { agent_id: 'alfa', kind: 'yesno', question_short: 'Mehet a teszt-kiadas?' }
const count = () => (getDb().prepare('SELECT COUNT(*) AS n FROM open_questions').get() as { n: number }).n

beforeEach(() => {
  initDatabase(':memory:')
  setQuestionsClockForTest(() => T0 * 1000)
})
afterEach(() => { setQuestionsClockForTest(null) })

describe('routing', () => {
  it('only /api/questions exactly; other paths (incl. the later answer path) fall through', async () => {
    for (const p of ['/api/questions/', '/api/questions/1', '/api/questions/1/answer', '/api/questionsx', '/api/question', '/api/other']) {
      expect(await tryHandleOpenQuestions(call(p).ctx)).toBe(false)
    }
  })

  it('other methods are 405 with an Allow header and write nothing', async () => {
    for (const method of ['PUT', 'PATCH', 'DELETE']) {
      const r = call('/api/questions', { method, body: JSON.stringify(good) })
      expect(await tryHandleOpenQuestions(r.ctx)).toBe(true)
      expect(r.out.status).toBe(405)
      expect(r.out.headers.Allow).toBe('GET, POST')
    }
    expect(count()).toBe(0)
  })

  it('responses are not cacheable', async () => {
    const r = call('/api/questions')
    await tryHandleOpenQuestions(r.ctx)
    expect(r.out.headers['Cache-Control']).toBe('private, no-store')
  })
})

describe('auth matrix (spec 5.1)', () => {
  it('POST: token 201; device full, session, operator, federation 403; no principal 401; nothing written for the refused', async () => {
    expect((await post(good, TOKEN_ALFA)).status).toBe(201)
    expect(count()).toBe(1)
    for (const auth of [DEVICE_FULL, SESSION, DEVICE_OP, FEDERATION]) {
      expect((await post(good, auth)).status).toBe(403)
    }
    expect((await post(good, null)).status).toBe(401)
    expect(count()).toBe(1)
  })

  it('GET: token, device full and session 200; operator and federation 403; no principal 401', async () => {
    for (const auth of [TOKEN, TOKEN_ALFA, DEVICE_FULL, SESSION]) expect((await get('', auth)).status).toBe(200)
    for (const auth of [DEVICE_OP, FEDERATION]) expect((await get('', auth)).status).toBe(403)
    expect((await get('', null)).status).toBe(401)
  })

  it('a token without an X-Agent-Id claim may post for a known agent (the claim attributes, it does not authorize)', async () => {
    expect((await post(good, TOKEN)).status).toBe(201)
  })

  it('a claim that differs from the body agent_id is 400', async () => {
    const r = await post({ ...good, agent_id: 'beta' }, TOKEN_ALFA)
    expect(r.status).toBe(400)
    expect(r.body.error).toMatch(/X-Agent-Id/)
    expect(count()).toBe(0)
  })

  it('the dashboard gate: both methods need auth, and an operator key is denied there', () => {
    expect(requiresAuth('/api/questions', 'GET')).toBe(true)
    expect(requiresAuth('/api/questions', 'POST')).toBe(true)
    expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, '/api/questions', () => ({ enabled: true, capabilities: {} as never, commands: [] })))
      .toBe('operator credential: not an operator endpoint')
    expect(operatorGateDecision({ kind: 'token' }, '/api/questions', () => { throw new Error('must not read access for a token') })).toBeNull()
    expect(operatorGateDecision({ kind: 'device', scope: 'full' }, '/api/questions', () => { throw new Error('must not read access') })).toBeNull()
  })
})

describe('POST validation', () => {
  it('201 answers the stored question with exactly the allowlisted keys', async () => {
    const r = await post(good)
    expect(r.status).toBe(201)
    expect(sorted(Object.keys(r.body))).toEqual(sorted(QUESTION_KEYS))
    expect(r.body).toMatchObject({ agent_id: 'alfa', kind: 'yesno', status: 'open', source: 'agent', created_at: T0, expires_at: T0 + 7 * 24 * 3600 })
  })

  it('every field: bad values are 400 and nothing is written', async () => {
    const bad: unknown[] = [
      {}, [], 'x', null,
      { ...good, agent_id: undefined }, { ...good, agent_id: 'Alfa' }, { ...good, agent_id: 'nincs-ilyen' },
      { ...good, kind: 'maybe' }, { ...good, kind: undefined },
      { ...good, question_short: '' }, { ...good, question_short: 'x'.repeat(401) }, { ...good, question_short: 5 },
      { ...good, card_id: 'XYZ' }, { ...good, msg_id: 0 }, { ...good, msg_id: '3' },
      { ...good, expires_in_s: 299 }, { ...good, expires_in_s: 30 * 24 * 3600 + 1 }, { ...good, expires_in_s: 1.5 },
      { ...good, source: 'extractor' }, { ...good, status: 'yes' }, { ...good, answer_short: 'igen' },
    ]
    for (const b of bad) {
      const r = await post(typeof b === 'string' || b === null ? JSON.stringify(b) : b)
      expect(r.status, JSON.stringify(b)).toBe(400)
    }
    expect((await post('{not json')).status).toBe(400)
    expect((await post('')).status).toBe(400)
    expect(count()).toBe(0)
  })

  it('limits: 400 characters pass, 401 do not; expiry 300 s and 30 days pass', async () => {
    expect((await post({ ...good, question_short: 'x'.repeat(400) })).status).toBe(201)
    expect((await post({ ...good, question_short: 'x'.repeat(401) })).status).toBe(400)
    expect((await post({ ...good, expires_in_s: 300 })).status).toBe(201)
    expect((await post({ ...good, expires_in_s: 30 * 24 * 3600 })).status).toBe(201)
    expect((await post({ ...good, expires_in_s: 30 * 24 * 3600 + 1 })).status).toBe(400)
  })

  it('hidden characters (ESC, bidi override, BOM, zero width, NUL) are 400', async () => {
    for (const cp of [0x1b, 0x202e, 0xfeff, 0x200b, 0x00]) {
      const r = await post({ ...good, question_short: `elo${String.fromCodePoint(cp)}utan` })
      expect(r.status, `U+${cp.toString(16)}`).toBe(400)
    }
    expect(count()).toBe(0)
  })

  it('a secret-shaped question is 400 and the marker never comes back', async () => {
    const r = await post({ ...good, question_short: `${MARKER} token=${'Q'.repeat(30)}` })
    expect(r.status).toBe(400)
    expect(JSON.stringify(r.body)).not.toContain(MARKER)
    expect(JSON.stringify(r.body)).not.toContain('QQQQ')
    expect(count()).toBe(0)
  })

  it('card_id and msg_id that do not exist are 422; existing ones are accepted', async () => {
    expect((await post({ ...good, card_id: '0a0b0c0d' })).status).toBe(422)
    expect((await post({ ...good, msg_id: 77 })).status).toBe(422)
    getDb().prepare(`INSERT INTO kanban_cards (id, title, description, test_steps, status, assignee, sort_order, created_at, updated_at)
                     VALUES ('0a0b0c0d', ?, ?, ?, 'planned', 'alfa', 0, ?, ?)`).run(`${MARKER} cim`, `${MARKER} leiras`, `${MARKER} lepesek`, T0, T0)
    const m = Number(getDb().prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at) VALUES ('alfa', 'beta', ?, 'done', ?)").run(`${MARKER} uzenet`, T0).lastInsertRowid)
    const r = await post({ ...good, card_id: '0a0b0c0d', msg_id: m })
    expect(r.status).toBe(201)
    expect(r.body).toMatchObject({ card_id: '0a0b0c0d', msg_id: m })
    expect(JSON.stringify(r.body)).not.toContain(MARKER)
  })

  it('the 20th open question per agent is 201, the 21st is 429; another agent still posts', async () => {
    for (let i = 0; i < QUESTION_OPEN_PER_AGENT_MAX; i++) expect((await post({ ...good, question_short: `k${i}` })).status).toBe(201)
    const r = await post({ ...good, question_short: 'huszonegyedik' })
    expect(r.status).toBe(429)
    expect(count()).toBe(20)
    expect((await post({ ...good, agent_id: 'beta' }, { kind: 'token', agent: 'beta' })).status).toBe(201)
  })

  it('body size: over 8 KB by Content-Length is 413 (not read); over 8 KB streamed without a length is 413; 8 KB exactly is read', async () => {
    const big = JSON.stringify({ ...good, question_short: 'x'.repeat(9000) })
    const declared = call('/api/questions', { method: 'POST', auth: TOKEN_ALFA, body: big })
    await tryHandleOpenQuestions(declared.ctx)
    expect(declared.out.status).toBe(413)

    const streamed = call('/api/questions', { method: 'POST', auth: TOKEN_ALFA, body: big, headers: {} })
    delete (streamed.ctx.req.headers as Record<string, unknown>)['content-length']
    await tryHandleOpenQuestions(streamed.ctx)
    expect(streamed.out.status).toBe(413)
    expect(count()).toBe(0)

    // exactly 8192 bytes passes the size fence (and then fails validation on length, not on size)
    const pad = JSON.stringify({ ...good, question_short: '' })
    const exact = JSON.stringify({ ...good, question_short: 'x'.repeat(8192 - Buffer.byteLength(pad)) })
    expect(Buffer.byteLength(exact)).toBe(8192)
    const r = await post(exact)
    expect(r.status).toBe(400)
    expect(r.body.error).toMatch(/longer than 400/)
  })
})

describe('GET: filters, lazy expiry, allowlist', () => {
  function seed(): { live: number; old: number; done: number } {
    const db = getDb()
    const ins = (over: Record<string, unknown>) => {
      const row = { agent_id: 'alfa', kind: 'yesno', question_short: 'k', status: 'open', answer_short: null, answered_via: null, answered_at: null, answered_by: null, answered_principal: null, created_at: T0 - 100, expires_at: T0 + 1000, source: 'agent', ...over }
      const cols = Object.keys(row)
      return Number(db.prepare(`INSERT INTO open_questions (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...Object.values(row) as never[]).lastInsertRowid)
    }
    return {
      live: ins({ question_short: 'elo', created_at: T0 - 10 }),
      old: ins({ question_short: 'lejart', created_at: T0 - 200, expires_at: T0 - 50 }),
      done: ins({ question_short: 'valaszolt', agent_id: 'beta', status: 'yes', answered_via: 'ui', answered_at: T0 - 5, answered_by: `session:${MARKER}`, answered_principal: 'session' }),
    }
  }

  it('default is open; status=open|answered|expired|all select the right rows; newest first', async () => {
    const { live, old, done } = seed()
    const ids = (r: Out) => r.body.questions.map((q: { id: number }) => q.id)
    expect(ids(await get())).toEqual([live])
    expect(ids(await get('?status=open'))).toEqual([live])
    expect(ids(await get('?status=answered'))).toEqual([done])
    expect(ids(await get('?status=expired'))).toEqual([old])
    expect(ids(await get('?status=all'))).toEqual([live, done, old])
  })

  it('lazy expiry in the view: the same row is open before and expired after the clock passes expires_at; the table is untouched', async () => {
    const { live } = seed()
    expect((await get('?status=open')).body.questions.map((q: { id: number }) => q.id)).toEqual([live])
    setQuestionsClockForTest(() => (T0 + 1000) * 1000)
    expect((await get('?status=open')).body.questions).toEqual([])
    const all = (await get('?status=all')).body.questions
    expect(all.find((q: { id: number }) => q.id === live).status).toBe('expired')
    expect((getDb().prepare('SELECT status FROM open_questions WHERE id = ?').get(live) as { status: string }).status).toBe('open')
  })

  it('an unknown status filter is 400', async () => {
    for (const q of ['?status=bogus', '?status=', '?status=OPEN', '?status=open%20OR%201=1']) expect((await get(q)).status).toBe(400)
  })

  it('every item has exactly the allowlisted keys (snapshot) and the table-only columns / marker never appear', async () => {
    seed()
    const r = await get('?status=all')
    expect(r.body.questions).toHaveLength(3)
    for (const q of r.body.questions) expect(sorted(Object.keys(q))).toEqual(sorted(QUESTION_KEYS))
    expect(sorted(Object.keys(r.body))).toEqual(['questions'])
    const text = JSON.stringify(r.body)
    expect(text).not.toContain(MARKER)
    expect(text).not.toMatch(/answered_by|answered_principal/)
  })

  it('a POSTed question shows up in the GET, with the agent breakdown intact', async () => {
    await post(good)
    await post({ ...good, agent_id: 'beta', kind: 'free', question_short: 'Melyik agon?' }, { kind: 'token', agent: 'beta' })
    const q = (await get()).body.questions
    expect(q.map((x: { agent_id: string }) => x.agent_id)).toEqual(['beta', 'alfa'])
    expect(q.every((x: { source: string }) => x.source === 'agent')).toBe(true)
  })
})

describe('wiring in web.ts', () => {
  it('web.ts routes /api/questions through tryHandleOpenQuestions inside the authenticated route chain', () => {
    const web = readFileSync(join(__dirname, '..', 'web.ts'), 'utf-8')
    const code = web.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    expect(code).toMatch(/^\s*if \(await tryHandleOpenQuestions\(routeCtx\)\) return$/m)
    expect(code).toMatch(/import \{[^}]*\btryHandleOpenQuestions\b[^}]*\} from '\.\/web\/routes\/open-questions\.js'/)
    expect(code.indexOf('if (await tryHandleOpenQuestions(routeCtx)) return')).toBeGreaterThan(code.indexOf('if (await tryHandleAuth(routeCtx)) return'))
  })
})
