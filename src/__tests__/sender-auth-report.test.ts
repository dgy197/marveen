import { describe, it, expect, beforeAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { initDatabase, getDb, createAgentMessage, closeOpenMessage } from '../db.js'
import { tryHandleMessages } from '../web/routes/messages.js'
import { mintAgentSendKey } from '../web/agent-send-keys.js'
import type { RouteContext } from '../web/routes/types.js'

// Card 0d7e2c04 N5 -- GET /api/messages/sender-auth-report: counts per (from, sender_auth) + last-seen, nothing else.

type Auth = RouteContext['auth']

async function get(query: string, auth: Auth | undefined): Promise<{ statusCode: number; raw: string; json: Record<string, unknown> }> {
  const req = new EventEmitter() as unknown as RouteContext['req']
  ;(req as unknown as { headers: Record<string, string> }).headers = {}
  const state = { statusCode: 0, body: '' }
  const res = {
    writeHead(code: number) { state.statusCode = code; return res },
    end(data?: unknown) { state.body = String(data ?? '') },
    setHeader() { /* unused */ },
    getHeader() { return undefined },
  } as unknown as RouteContext['res']
  const ctx = { req, res, path: '/api/messages/sender-auth-report', method: 'GET', url: new URL('http://localhost/api/messages/sender-auth-report' + query), fedPeer: null, auth } as RouteContext
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: state.statusCode, raw: state.body, json: JSON.parse(state.body) }
}

const TOKEN: Auth = { kind: 'token' } as Auth
type Row = { from: string; sender_auth: string; count: number; last_seen: number }
let rawKey = ''

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  rawKey = mintAgentSendKey('sar-agent-0d7e')
  createAgentMessage('sar-a', 'sar-b', 'x', null, null, { senderAuth: 'verified' })
  createAgentMessage('sar-a', 'sar-b', 'x', null, null, { senderAuth: 'verified' })
  createAgentMessage('sar-a', 'sar-b', 'x', null, null, { senderAuth: 'unsigned' })
  createAgentMessage('sar-c', 'sar-b', 'x', null, null, { senderAuth: 'mismatch' })
  createAgentMessage('sar-c', 'sar-b', 'x') // in-process default: internal
  const db = getDb()
  const now = Math.floor(Date.now() / 1000)
  // legacy: NULL column, recent; and an old row outside the window
  db.prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at, sender_auth) VALUES ('sar-d','sar-b','x','done',?,NULL)").run(now - 100)
  db.prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at, sender_auth) VALUES ('sar-old','sar-b','x','done',?,'unsigned')").run(now - 30 * 86400)
})

// Card f137f980 (E11, Q2): the same report also lists the closes, per (to, closer_auth).
type CloserRow = { to: string; closer_auth: string; count: number; last_seen: number }
const RESULT_TEXT = 'closer report secret result text'

function closeRow(to: string, verdict: string | null, status: 'done' | 'failed' = 'done'): void {
  const id = createAgentMessage('sarc-from', to, 'task').id
  expect(closeOpenMessage(id, status, RESULT_TEXT, verdict)).toBe(true)
}

describe('sender-auth report: closers (card f137f980)', () => {
  beforeAll(() => {
    closeRow('sarc-iroda', 'verified')
    closeRow('sarc-iroda', 'verified')
    closeRow('sarc-iroda', 'unsigned', 'failed')
    closeRow('sarc-feszek', 'mismatch')
    closeRow('sarc-sys', 'no_key_recipient')
    closeRow('sarc-iroda', null) // an old call / off mode: NULL = legacy
    const db = getDb()
    const now = Math.floor(Date.now() / 1000)
    db.prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at, completed_at, closer_auth) VALUES ('sarc-from','sarc-old','x','done',?,?,'unsigned')").run(now - 31 * 86400, now - 30 * 86400)
    // still open rows are not closes, whatever their column holds
    db.prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at, closer_auth) VALUES ('sarc-from','sarc-open','x','pending',?,'verified')").run(now - 10)
  })

  it('has a closers array next to rows, counted per (to, closer_auth) with last_seen; NULL is legacy; failed counts too', async () => {
    const r = await get('', TOKEN)
    expect(r.statusCode).toBe(200)
    expect(Array.isArray(r.json.rows)).toBe(true)
    const closers = (r.json.closers as CloserRow[]).filter((x) => x.to.startsWith('sarc-'))
    const by = (t: string, a: string) => closers.find((x) => x.to === t && x.closer_auth === a)
    expect(by('sarc-iroda', 'verified')?.count).toBe(2)
    expect(by('sarc-iroda', 'unsigned')?.count).toBe(1)
    expect(by('sarc-iroda', 'legacy')?.count).toBe(1)
    expect(by('sarc-feszek', 'mismatch')?.count).toBe(1)
    expect(by('sarc-sys', 'no_key_recipient')?.count).toBe(1)
    expect(typeof by('sarc-iroda', 'verified')?.last_seen).toBe('number')
    expect(closers.some((x) => x.to === 'sarc-old')).toBe(false) // outside the 7 day window
    expect(closers.some((x) => x.to === 'sarc-open')).toBe(false) // not closed
  })

  it('a wider window includes the old close', async () => {
    const r = await get('?days=60', TOKEN)
    expect((r.json.closers as CloserRow[]).find((x) => x.to === 'sarc-old')?.count).toBe(1)
  })

  it('exposes only to, closer_auth, count, last_seen: no key, hash, result or content', async () => {
    const r = await get('?days=60', TOKEN)
    for (const row of r.json.closers as CloserRow[]) expect(Object.keys(row).sort()).toEqual(['closer_auth', 'count', 'last_seen', 'to'])
    const hash = (getDb().prepare('SELECT key_hash FROM agent_send_keys WHERE agent_id = ?').get('sar-agent-0d7e') as { key_hash: string }).key_hash
    expect(r.raw).not.toContain(rawKey)
    expect(r.raw).not.toContain(hash)
    expect(r.raw).not.toContain(RESULT_TEXT)
    expect(r.raw).not.toContain('"content"')
    expect(r.raw).not.toContain('"result"')
  })

  it('the rows array keeps its exact shape (additive change only)', async () => {
    const r = await get('?days=60', TOKEN)
    for (const row of r.json.rows as Row[]) expect(Object.keys(row).sort()).toEqual(['count', 'from', 'last_seen', 'sender_auth'])
    expect(Object.keys(r.json).sort()).toEqual(['closers', 'days', 'mode', 'rows'])
  })

  it('refuses a request without a principal and bad days values, closers or not', async () => {
    expect((await get('', undefined)).statusCode).toBe(401)
    expect((await get('?days=0', TOKEN)).statusCode).toBe(400)
  })
})

describe('sender-auth report', () => {
  it('counts per (from, sender_auth) with last-seen, NULL is legacy, window applies', async () => {
    const r = await get('', TOKEN)
    expect(r.statusCode).toBe(200)
    const rows = (r.json.rows as Row[]).filter(x => x.from.startsWith('sar-'))
    const by = (f: string, a: string) => rows.find(x => x.from === f && x.sender_auth === a)
    expect(by('sar-a', 'verified')?.count).toBe(2)
    expect(by('sar-a', 'unsigned')?.count).toBe(1)
    expect(by('sar-c', 'mismatch')?.count).toBe(1)
    expect(by('sar-c', 'internal')?.count).toBe(1)
    expect(by('sar-d', 'legacy')?.count).toBe(1)
    expect(rows.some(x => x.from === 'sar-old')).toBe(false)
    expect(typeof by('sar-a', 'verified')?.last_seen).toBe('number')
    expect(r.json.days).toBe(7)
    expect(['off', 'shadow']).toContain(r.json.mode)
  })

  it('a wider window includes the old row', async () => {
    const r = await get('?days=60', TOKEN)
    const rows = r.json.rows as Row[]
    expect(rows.find(x => x.from === 'sar-old')?.count).toBe(1)
  })

  it('exposes only from, sender_auth, count, last_seen: no key, hash or content', async () => {
    const r = await get('?days=60', TOKEN)
    for (const row of r.json.rows as Row[]) expect(Object.keys(row).sort()).toEqual(['count', 'from', 'last_seen', 'sender_auth'])
    const hash = (getDb().prepare('SELECT key_hash FROM agent_send_keys WHERE agent_id = ?').get('sar-agent-0d7e') as { key_hash: string }).key_hash
    expect(hash.length).toBeGreaterThan(8)
    expect(r.raw).not.toContain(rawKey)
    expect(r.raw).not.toContain(hash)
    expect(r.raw).not.toContain('"content"')
  })

  it('refuses a request without a principal and bad days values', async () => {
    expect((await get('', undefined)).statusCode).toBe(401)
    for (const q of ['?days=0', '?days=91', '?days=abc', '?days=1.5']) expect((await get(q, TOKEN)).statusCode).toBe(400)
  })
})
