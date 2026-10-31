import { describe, it, expect, beforeAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { initDatabase, getDb, createAgentMessage, getAgentMessage, toServedMessage } from '../db.js'
import { tryHandleMessages } from '../web/routes/messages.js'
import type { RouteContext } from '../web/routes/types.js'

// Card 0d7e2c04 r1 (B1) -- sender_auth is STORED, never SERVED. No route that returns an agent_messages row may carry the
// column: a per-row verdict would be a free oracle for "does this stolen key still verify", and the bodies must keep the
// shape they had before the column existed. Only the aggregate report endpoint exposes the values (sender-auth-report.test.ts).

const FROM = 'ssr-feszek-0d7e'
const TO = 'ssr-iroda-0d7e'

type Auth = RouteContext['auth']

function call(method: string, path: string, body?: unknown): Promise<{ statusCode: number; raw: string }> {
  const req = new EventEmitter() as unknown as RouteContext['req'] & { destroy(): void }
  ;(req as unknown as { headers: Record<string, string> }).headers = {}
  ;(req as { destroy(): void }).destroy = () => { /* readBody over-limit hook */ }
  const state = { statusCode: 0, raw: '' }
  const res = {
    writeHead(code: number) { state.statusCode = code; return res },
    end(data?: unknown) { state.raw = String(data ?? '') },
    setHeader() { /* unused */ },
    getHeader() { return undefined },
  } as unknown as RouteContext['res']
  if (body !== undefined) {
    process.nextTick(() => {
      ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
      ;(req as unknown as EventEmitter).emit('end')
    })
  }
  const ctx = { req, res, path: path.split('?')[0], method, url: new URL('http://localhost' + path), fedPeer: null, auth: { kind: 'token' } as Auth } as RouteContext
  return tryHandleMessages(ctx).then((handled) => {
    expect(handled).toBe(true)
    return state
  })
}

const rowColumns = () =>
  (getDb().prepare('PRAGMA table_info(agent_messages)').all() as { name: string }[]).map((c) => c.name)

// Card f137f980: closer_auth is a stored-not-served verdict column too, so the served shape is every column but the two.
const servedColumns = () => rowColumns().filter((c) => c !== 'sender_auth' && c !== 'closer_auth')

let id = 0

beforeAll(() => {
  initDatabase(':memory:')
  // A row with a NON-null verdict, so a leak shows as a value and not only as a null key.
  id = createAgentMessage(FROM, TO, 'served-rows probe', null, null, { senderAuth: 'mismatch' }).id
})

describe('served message rows carry no sender_auth', () => {
  it('positive control: the verdict really is stored on the row', () => {
    expect(getAgentMessage(id)?.sender_auth).toBe('mismatch')
    expect(rowColumns()).toContain('sender_auth')
  })

  it('GET /api/messages/:id -> the pre-card shape (every column but sender_auth, plus freshness)', async () => {
    const r = await call('GET', `/api/messages/${id}`)
    expect(r.statusCode).toBe(200)
    expect(r.raw).not.toContain('sender_auth')
    expect(r.raw).not.toContain('mismatch')
    expect(Object.keys(JSON.parse(r.raw)).sort()).toEqual([...servedColumns(), 'freshness'].sort())
  })

  it('GET /api/messages (all, per-agent, pending) -> no row has the key', async () => {
    for (const q of ['', `?agent=${TO}`, `?agent=${TO}&status=pending`, '?status=pending']) {
      const r = await call('GET', `/api/messages${q}`)
      expect(r.statusCode, q).toBe(200)
      const rows = JSON.parse(r.raw) as Record<string, unknown>[]
      expect(rows.some((x) => x.id === id), q).toBe(true)
      expect(r.raw, q).not.toContain('sender_auth')
      for (const row of rows) expect(Object.keys(row).sort(), q).toEqual([...servedColumns(), 'freshness'].sort())
    }
  })

  it('GET /api/messages/threads -> lastMessage has no sender_auth', async () => {
    const r = await call('GET', '/api/messages/threads')
    expect(r.statusCode).toBe(200)
    expect(r.raw).toContain('served-rows probe') // positive control: the thread with our row is there
    expect(r.raw).not.toContain('sender_auth')
  })

  it('PUT /api/messages/:id (close, and the 409 repeat) -> no sender_auth in either answer', async () => {
    const first = await call('PUT', `/api/messages/${id}`, { status: 'done', result: 'ok', notify: false })
    expect(first.statusCode).toBe(200)
    expect(JSON.parse(first.raw)).toEqual({ ok: true })
    expect(first.raw).not.toContain('sender_auth')
    const again = await call('PUT', `/api/messages/${id}`, { status: 'done', result: 'ok', notify: false })
    expect(again.statusCode).toBe(409)
    expect(again.raw).not.toContain('sender_auth')
    // and the closed row, read back, is still clean while the stored verdict survived the close
    const get = await call('GET', `/api/messages/${id}`)
    expect(get.raw).not.toContain('sender_auth')
    expect(getAgentMessage(id)?.sender_auth).toBe('mismatch')
  })

  it('toServedMessage drops only sender_auth and keeps the rest byte for byte', () => {
    const row = { id: 1, content: 'x', sender_auth: 'verified', result: null }
    expect(toServedMessage(row)).toEqual({ id: 1, content: 'x', result: null })
    expect(row.sender_auth).toBe('verified') // the input is not mutated
  })
})
