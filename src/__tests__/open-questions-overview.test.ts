import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { initDatabase, getDb } from '../db.js'
import { requiresAuth } from '../web/auth-gate.js'
import { QUESTION_KEYS, createQuestion, type QuestionKind } from '../web/open-questions.js'
import { APPROVAL_KEYS, setOverviewDepsForTest } from '../web/open-questions-overview.js'
import { setQuestionsClockForTest, tryHandleOpenQuestions } from '../web/routes/open-questions.js'
import type { RouteContext } from '../web/routes/types.js'

// Open questions S3-N3: GET /api/questions/overview. Open questions per agent
// (agent_running, card_seq, funkcio_slug), the pending approvals shown with an
// allowlist of fields only, the auth matrix of the list GET, the marker test.

vi.mock('../web/agent-process.js', () => ({ isAgentRunning: () => false }))

const MARKER = 'TITOK-MARKER'
const T0 = 1_760_000_000
const sorted = (a: readonly string[]) => [...a].sort()

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'full' }
const DEVICE_OP: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'operator' }
const SESSION: Auth = { kind: 'session', user: 'tulaj-teszt' }
const FEDERATION: Auth = { kind: 'federation', peer: 'teszt-peer' }

type Out = { status: number; body: any; headers: Record<string, unknown> }

async function call(auth: Auth | null = TOKEN, method = 'GET', path = '/api/questions/overview'): Promise<{ handled: boolean; out: Out }> {
  const out: Out = { status: 0, body: null, headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const req: any = Object.assign(Readable.from([Buffer.from('', 'utf8')]), { headers: {} })
  const url = new URL(`http://localhost:3420${path}`)
  const ctx = { req, res, path: url.pathname, method, url, auth: auth ?? undefined } as RouteContext
  return { handled: await tryHandleOpenQuestions(ctx), out }
}

let regDir: string
let running: Set<string>

function addCard(id: string, title = 'teszt-kartya', parentId: string | null = null): void {
  getDb().prepare(`INSERT INTO kanban_cards (id, title, description, test_steps, status, assignee, sort_order, created_at, updated_at, parent_id)
                   VALUES (?, ?, ?, ?, 'planned', 'alfa', 0, ?, ?, ?)`).run(id, title, `${MARKER} leiras`, `${MARKER} lepesek`, T0, T0, parentId)
}

function ask(agent: string, kind: QuestionKind, text: string, cardId: string | null = null, expiresIn = 3600, createdAt = T0): void {
  const r = createQuestion({ agent_id: agent, kind, question_short: text, card_id: cardId, msg_id: null, expires_in_s: expiresIn }, createdAt)
  expect(r.kind).toBe('ok')
}

function addApproval(id: string, status: string, requestedAt: number): void {
  getDb().prepare(`INSERT INTO approvals (id, agent_id, category, action_description, action_payload, status, content_hash, requested_at)
                   VALUES (?, 'alfa', 'email_send', ?, ?, ?, ?, ?)`)
    .run(id, `${MARKER} action_description`, `${MARKER} payload`, status, `${MARKER}-hash`, requestedAt)
}

beforeEach(() => {
  initDatabase(':memory:')
  setQuestionsClockForTest(() => (T0 + 10) * 1000)
  regDir = mkdtempSync(join(tmpdir(), 'oq-overview-'))
  running = new Set(['alfa'])
  setOverviewDepsForTest({ registryDir: regDir, isRunning: (a) => running.has(a) })
})
afterEach(() => {
  setQuestionsClockForTest(null)
  setOverviewDepsForTest(null)
  rmSync(regDir, { recursive: true, force: true })
})

describe('routing and auth', () => {
  it('only GET on the exact path; the list path is untouched', async () => {
    for (const m of ['POST', 'PUT', 'DELETE']) {
      const r = await call(TOKEN, m)
      expect(r.handled).toBe(true)
      expect(r.out.status).toBe(405)
      expect(r.out.headers.Allow).toBe('GET')
    }
    expect((await call(TOKEN, 'GET', '/api/questions/overview/')).handled).toBe(false)
    expect((await call(TOKEN, 'GET', '/api/questions/overviewx')).handled).toBe(false)
    expect(Array.isArray((await call(TOKEN, 'GET', '/api/questions')).out.body.questions)).toBe(true)
  })

  it('token, device full and session 200; operator and federation 403; no principal 401; not cacheable', async () => {
    for (const a of [TOKEN, DEVICE_FULL, SESSION]) {
      const r = await call(a)
      expect(r.out.status).toBe(200)
      expect(r.out.headers['Cache-Control']).toBe('private, no-store')
    }
    for (const a of [DEVICE_OP, FEDERATION]) {
      const r = await call(a)
      expect(r.out.status).toBe(403)
      expect(r.out.body.agents).toBeUndefined()
    }
    expect((await call(null)).out.status).toBe(401)
  })

  it('the dashboard gate requires auth for the path', () => {
    expect(requiresAuth('/api/questions/overview', 'GET')).toBe(true)
  })
})

describe('open questions per agent', () => {
  it('groups by agent (sorted), newest first, with agent_running; expired and answered rows stay out', async () => {
    addCard('0a0b0c0d')
    ask('beta', 'info', 'beta kerdes')
    ask('alfa', 'yesno', 'alfa regebbi', null, 3600, T0 - 1)
    ask('alfa', 'free', 'alfa kartyas', '0a0b0c0d')
    ask('beta', 'info', 'beta rovid', null, 300) // expires at T0+300, the clock is T0+10: still open
    // a row that is already past its expiry at the clock
    getDb().prepare("INSERT INTO open_questions (agent_id, kind, question_short, status, created_at, expires_at, source) VALUES ('alfa', 'info', 'lejart sor', 'open', ?, ?, 'agent')")
      .run(T0 - 100, T0 - 1)
    getDb().prepare("UPDATE open_questions SET status = 'yes', answer_short = 'igen', answered_via = 'ui', answered_at = ? WHERE question_short = 'beta kerdes'").run(T0 + 5)

    const r = await call()
    expect(r.out.status).toBe(200)
    expect(r.out.body.agents.map((a: any) => a.agent_id)).toEqual(['alfa', 'beta'])
    const [alfa, beta] = r.out.body.agents
    expect(alfa.agent_running).toBe(true)
    expect(beta.agent_running).toBe(false)
    expect(alfa.questions.map((q: any) => q.question_short)).toEqual(['alfa kartyas', 'alfa regebbi'])
    expect(beta.questions.map((q: any) => q.question_short)).toEqual(['beta rovid'])
    for (const a of r.out.body.agents) for (const q of a.questions) expect(q.agent_id).toBe(a.agent_id)
  })

  it('a card row carries the card_seq of an existing card; a question without a card has null', async () => {
    addCard('0a0b0c0d')
    addCard('1a1b1c1d')
    ask('alfa', 'yesno', 'kartyas', '1a1b1c1d')
    ask('alfa', 'info', 'kartya nelkul')
    const seq = (getDb().prepare('SELECT rowid AS seq FROM kanban_cards WHERE id = ?').get('1a1b1c1d') as { seq: number }).seq

    const rows = (await call()).out.body.agents[0].questions
    const withCard = rows.find((q: any) => q.card_id === '1a1b1c1d')
    const without = rows.find((q: any) => q.card_id === null)
    expect(withCard.card_seq).toBe(seq)
    expect(without.card_seq).toBeNull()
    expect(without.funkcio_slug).toBeNull()
    // S3-7: every card row's card_seq belongs to an existing card
    for (const q of rows.filter((x: any) => x.card_id !== null)) {
      const found = getDb().prepare('SELECT 1 AS x FROM kanban_cards WHERE id = ? AND rowid = ?').get(q.card_id, q.card_seq)
      expect(found, q.card_id).toBeTruthy()
    }
  })

  it('funkcio_slug comes from the registry (first valid function listing the card); unknown or broken -> null', async () => {
    addCard('0a0b0c0d')
    addCard('1a1b1c1d')
    addCard('2a2b2c2d')
    const doc = (slug: string, kartyak: string[]) => JSON.stringify({ slug, nev: `Funkcio ${slug}`, kartyak })
    writeFileSync(join(regDir, 'beta-feature.json'), doc('beta-feature', ['0a0b0c0d']))
    writeFileSync(join(regDir, 'alfa-feature.json'), doc('alfa-feature', ['0a0b0c0d', '1a1b1c1d']))
    writeFileSync(join(regDir, 'torott.json'), '{nem json')
    ask('alfa', 'info', 'egy', '0a0b0c0d')
    ask('alfa', 'info', 'ketto', '1a1b1c1d')
    ask('alfa', 'info', 'harom', '2a2b2c2d')

    const rows = (await call()).out.body.agents[0].questions
    const slugOf = (card: string) => rows.find((q: any) => q.card_id === card).funkcio_slug
    expect(slugOf('0a0b0c0d')).toBe('alfa-feature')
    expect(slugOf('1a1b1c1d')).toBe('alfa-feature')
    expect(slugOf('2a2b2c2d')).toBeNull()
  })

  it('S3-R2: a subcard (parent_id is a registry card) carries its parent\'s funkcio_slug; a card whose parent is not in the registry stays null', () => {
    addCard('3a3b3c3d')
    addCard('4a4b4c4d', 'alkartya', '3a3b3c3d')
    addCard('5a5b5c5d')
    addCard('6a6b6c6d', 'arva alkartya', '5a5b5c5d')
    writeFileSync(join(regDir, 'gamma-feature.json'), JSON.stringify({ slug: 'gamma-feature', nev: 'Funkcio gamma', kartyak: ['3a3b3c3d'] }))
    ask('alfa', 'info', 'szulo', '3a3b3c3d')
    ask('alfa', 'info', 'gyerek', '4a4b4c4d')
    ask('alfa', 'info', 'arva', '6a6b6c6d')
    return call().then(({ out }) => {
      const rows = out.body.agents[0].questions
      const slugOf = (card: string) => rows.find((q: any) => q.card_id === card).funkcio_slug
      expect(slugOf('3a3b3c3d')).toBe('gamma-feature')
      expect(slugOf('4a4b4c4d')).toBe('gamma-feature')
      expect(slugOf('6a6b6c6d')).toBeNull()
    })
  })

  it('a missing registry dir and a throwing run-state probe do not break the answer', async () => {
    setOverviewDepsForTest({ registryDir: join(regDir, 'nincs-ilyen'), isRunning: () => { throw new Error('tmux') } })
    ask('alfa', 'info', 'egy')
    const r = await call()
    expect(r.out.status).toBe(200)
    expect(r.out.body.agents[0].agent_running).toBe(false)
    expect(r.out.body.agents[0].questions[0].funkcio_slug).toBeNull()
  })

  it('each question carries exactly the list keys plus card_seq and funkcio_slug', async () => {
    ask('alfa', 'info', 'egy')
    const q = (await call()).out.body.agents[0].questions[0]
    expect(sorted(Object.keys(q))).toEqual(sorted([...QUESTION_KEYS, 'card_seq', 'funkcio_slug']))
  })

  it('no questions: empty groups', async () => {
    const r = await call()
    expect(r.out.body).toEqual({ agents: [], pending_approvals: [], questions_truncated: false, approvals_truncated: false })
  })
})

describe('pending approvals (shown only, spec 5.3)', () => {
  it('lists only pending approvals, newest first, with exactly the allowlisted keys and a link', async () => {
    addApproval('aaaa0001', 'pending', T0 - 20)
    addApproval('aaaa0002', 'pending', T0 - 5)
    addApproval('aaaa0003', 'approved', T0 - 3)
    addApproval('aaaa0004', 'rejected', T0 - 2)
    addApproval('aaaa0005', 'timeout', T0 - 1)

    const rows = (await call()).out.body.pending_approvals
    expect(rows.map((a: any) => a.id)).toEqual(['aaaa0002', 'aaaa0001'])
    for (const a of rows) {
      expect(sorted(Object.keys(a))).toEqual(sorted(APPROVAL_KEYS))
      expect(sorted(Object.keys(a))).toEqual(sorted(['id', 'agent_id', 'category', 'status', 'requested_at', 'link']))
      expect(a).toMatchObject({ agent_id: 'alfa', category: 'email_send', status: 'pending', link: '#approvals' })
    }
    expect(rows[0].requested_at).toBe(T0 - 5)
  })

  it('the marker in action_description, payload and content_hash never appears anywhere in the response', async () => {
    addApproval('aaaa0001', 'pending', T0)
    addCard('0a0b0c0d')
    ask('alfa', 'info', 'rendes kerdes', '0a0b0c0d')
    const r = await call()
    const text = JSON.stringify(r.out.body)
    expect(text).not.toContain(MARKER)
    for (const k of ['action_description', 'action_payload', 'content_hash', 'consumed_at', 'telegram_message_id', 'resolved_by', 'timeout_at']) {
      expect(text).not.toContain(k)
    }
    expect(r.out.body.pending_approvals).toHaveLength(1)
  })

  it('a question never changes or reads the approvals: the approvals table is the same before and after', async () => {
    addApproval('aaaa0001', 'pending', T0)
    const snap = () => JSON.stringify(getDb().prepare('SELECT * FROM approvals ORDER BY id').all())
    const before = snap()
    ask('alfa', 'yesno', 'engedelyezed?')
    await call()
    expect(snap()).toBe(before)
  })

  it('the list is capped', async () => {
    for (let i = 0; i < 60; i++) addApproval(`bbbb${String(i).padStart(4, '0')}`, 'pending', T0 + i)
    const body = (await call()).out.body
    expect(body.pending_approvals).toHaveLength(50)
    expect(body.approvals_truncated).toBe(true) // S3-R4
  })

  it('S3-R4: exactly 50 pending approvals are not truncated', async () => {
    for (let i = 0; i < 50; i++) addApproval(`cccc${String(i).padStart(4, '0')}`, 'pending', T0 + i)
    const body = (await call()).out.body
    expect(body.pending_approvals).toHaveLength(50)
    expect(body.approvals_truncated).toBe(false)
  })

  it('S3-R4: questions_truncated is true when more than 200 open questions exist', async () => {
    const db = getDb()
    const ins = db.prepare("INSERT INTO open_questions (agent_id, kind, question_short, created_at, expires_at, source) VALUES ('alfa', 'info', 'x', ?, ?, 'agent')")
    db.transaction(() => { for (let i = 0; i < 201; i++) ins.run(T0 + i, T0 + 99999) })()
    const body = (await call()).out.body
    expect(body.questions_truncated).toBe(true)
    expect(body.agents[0].questions).toHaveLength(200)
    expect(sorted(Object.keys(body))).toEqual(sorted(['agents', 'pending_approvals', 'questions_truncated', 'approvals_truncated']))
  })
})
