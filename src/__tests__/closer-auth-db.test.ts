import { describe, it, expect, beforeAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdtempSync } from 'node:fs'
import { join } from 'node:path'
import {
  initDatabase, getDb, createAgentMessage, getAgentMessage, closeOpenMessage, toServedMessage, getCloserAuthReport,
} from '../db.js'
import { tryHandleMessages } from '../web/routes/messages.js'
import type { RouteContext } from '../web/routes/types.js'

// Card f137f980 (N1) -- closer_auth: how the CLOSER of a message (PUT /api/messages/:id) was authenticated. Stored in the
// same UPDATE that closes the row, never served. This node is DB plumbing only: the route (N2) decides the verdict.

const FROM = 'cad-feszek-f137'
const TO = 'cad-iroda-f137'

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

const columns = () =>
  (getDb().prepare('PRAGMA table_info(agent_messages)').all() as { name: string; type: string; notnull: number }[])

const raw = (id: number) =>
  getDb().prepare('SELECT status, result, closer_auth FROM agent_messages WHERE id = ?').get(id) as
    { status: string; result: string | null; closer_auth: string | null }

describe('closer_auth migration', () => {
  it('is additive and idempotent: a re-init keeps the column once and the old rows untouched', () => {
    const dir = mkdtempSync(join('/Volumes/8T/10_LOCAL/Brainy/_ezermester/f137f980/tmp', 'cad-mig-'))
    const file = join(dir, 'mig.db')
    initDatabase(file)
    const first = columns().map((c) => c.name)
    expect(first.filter((n) => n === 'closer_auth')).toHaveLength(1)
    const col = columns().find((c) => c.name === 'closer_auth')!
    expect(col.type).toBe('TEXT')
    expect(col.notnull).toBe(0)

    // A pre-card database: no closer_auth column, one open row and one closed row already in it.
    const keep = createAgentMessage(FROM, TO, 'legacy open').id
    const done = createAgentMessage(FROM, TO, 'legacy closed').id
    expect(closeOpenMessage(done, 'done', 'old result')).toBe(true)
    getDb().exec('ALTER TABLE agent_messages DROP COLUMN closer_auth')
    expect(columns().map((c) => c.name)).not.toContain('closer_auth')

    initDatabase(file)
    expect(columns().map((c) => c.name)).toEqual(first)
    initDatabase(file) // and again: still exactly one
    expect(columns().filter((c) => c.name === 'closer_auth')).toHaveLength(1)
    expect(columns().map((c) => c.name)).toEqual(first)

    expect(raw(keep)).toEqual({ status: 'pending', result: null, closer_auth: null })
    expect(raw(done)).toEqual({ status: 'done', result: 'old result', closer_auth: null })
  })
})

describe('closeOpenMessage with closerAuth', () => {
  beforeAll(() => {
    initDatabase(':memory:')
  })

  it('writes the status and the verdict in ONE UPDATE (done and failed)', () => {
    const d = getDb()
    d.exec('CREATE TEMP TABLE upd_log (seq INTEGER PRIMARY KEY AUTOINCREMENT, id INTEGER, status TEXT, closer_auth TEXT)')
    d.exec("CREATE TEMP TRIGGER upd_probe AFTER UPDATE ON agent_messages BEGIN INSERT INTO upd_log (id, status, closer_auth) VALUES (NEW.id, NEW.status, NEW.closer_auth); END")
    const a = createAgentMessage(FROM, TO, 'one update done').id
    const b = createAgentMessage(FROM, TO, 'one update failed').id
    expect(closeOpenMessage(a, 'done', 'r1', 'verified')).toBe(true)
    expect(closeOpenMessage(b, 'failed', 'r2', 'mismatch')).toBe(true)
    const log = d.prepare('SELECT id, status, closer_auth FROM upd_log ORDER BY seq').all()
    // Exactly one UPDATE per close, and the very first (only) write of the row already carries the verdict.
    expect(log).toEqual([
      { id: a, status: 'done', closer_auth: 'verified' },
      { id: b, status: 'failed', closer_auth: 'mismatch' },
    ])
    expect(raw(a)).toEqual({ status: 'done', result: 'r1', closer_auth: 'verified' })
    expect(raw(b)).toEqual({ status: 'failed', result: 'r2', closer_auth: 'mismatch' })
    d.exec('DROP TRIGGER upd_probe')
    d.exec('DROP TABLE upd_log')
  })

  it('an old caller (no closerAuth) and an explicit null write NULL', () => {
    const a = createAgentMessage(FROM, TO, 'old caller').id
    const b = createAgentMessage(FROM, TO, 'explicit null').id
    expect(closeOpenMessage(a, 'done', 'x')).toBe(true)
    expect(closeOpenMessage(b, 'failed', 'y', null)).toBe(true)
    expect(raw(a).closer_auth).toBeNull()
    expect(raw(b).closer_auth).toBeNull()
  })

  it('a second close of a closed row changes nothing: only the FIRST verdict stays (race loser)', () => {
    const id = createAgentMessage(FROM, TO, 'two closes').id
    expect(closeOpenMessage(id, 'done', 'first', 'verified')).toBe(true)
    const before = raw(id)
    expect(closeOpenMessage(id, 'done', 'second', 'unsigned')).toBe(false)
    expect(closeOpenMessage(id, 'failed', 'third', 'mismatch')).toBe(false)
    expect(raw(id)).toEqual(before)
    expect(before.closer_auth).toBe('verified')
  })

  it('the receipt label rides on createAgentMessage senderAuth and is stored on the receipt row', () => {
    const r = createAgentMessage(TO, FROM, '[Eredmeny] msg_id:1', null, null, { senderAuth: 'receipt_verified' })
    expect(getAgentMessage(r.id)?.sender_auth).toBe('receipt_verified')
    const m = createAgentMessage(TO, FROM, '[Eredmeny] msg_id:2', null, null, { senderAuth: 'receipt_mismatch' })
    expect(getAgentMessage(m.id)?.sender_auth).toBe('receipt_mismatch')
    const u = createAgentMessage(TO, FROM, '[Eredmeny] msg_id:3', null, null, { senderAuth: 'receipt_unsigned' })
    expect(getAgentMessage(u.id)?.sender_auth).toBe('receipt_unsigned')
  })
})

describe('closer_auth is stored, never served', () => {
  let id = 0
  beforeAll(() => {
    initDatabase(':memory:')
    id = createAgentMessage(FROM, TO, 'closer served-rows probe', null, null, { senderAuth: 'mismatch' }).id
    expect(closeOpenMessage(id, 'done', 'res', 'unsigned')).toBe(true)
  })

  it('positive control: both verdicts are really stored on the row', () => {
    expect(getAgentMessage(id)?.closer_auth).toBe('unsigned')
    expect(getAgentMessage(id)?.sender_auth).toBe('mismatch')
  })

  it('toServedMessage strips closer_auth and sender_auth, keeps the rest', () => {
    const served = toServedMessage(getAgentMessage(id)!) as Record<string, unknown>
    expect('closer_auth' in served).toBe(false)
    expect('sender_auth' in served).toBe(false)
    expect(served.id).toBe(id)
    expect(served.status).toBe('done')
    expect(served.result).toBe('res')
  })

  it('GET /api/messages/:id carries neither column nor value', async () => {
    const r = await call('GET', `/api/messages/${id}`)
    expect(r.statusCode).toBe(200)
    expect(r.raw).not.toContain('closer_auth')
    expect(r.raw).not.toContain('sender_auth')
    expect(r.raw).not.toContain('unsigned')
  })

  it('GET /api/messages (list) carries neither column nor value', async () => {
    const r = await call('GET', '/api/messages')
    expect(r.statusCode).toBe(200)
    expect(r.raw).not.toContain('closer_auth')
    expect(r.raw).not.toContain('sender_auth')
  })

  it('GET /api/messages/threads carries neither column nor value', async () => {
    const r = await call('GET', '/api/messages/threads')
    expect(r.statusCode).toBe(200)
    expect(r.raw).not.toContain('closer_auth')
    expect(r.raw).not.toContain('sender_auth')
  })

  it('POST /api/messages response carries neither column', async () => {
    const r = await call('POST', '/api/messages', { from: FROM, to: TO, content: 'post probe' })
    expect(r.statusCode).toBe(200)
    expect(r.raw).not.toContain('closer_auth')
    expect(r.raw).not.toContain('sender_auth')
  })

  it('the 409 on an already-closed row is unchanged and does not touch the stored verdict', async () => {
    const r = await call('PUT', `/api/messages/${id}`, { status: 'done', result: 'again' })
    expect(r.statusCode).toBe(409)
    expect(raw(id)).toEqual({ status: 'done', result: 'res', closer_auth: 'unsigned' })
  })

  it('the aggregate closer report counts by (to_agent, verdict), legacy for NULL, no content', () => {
    const legacy = createAgentMessage(FROM, TO, 'secret content xyz').id
    expect(closeOpenMessage(legacy, 'failed', 'secret result xyz')).toBe(true)
    const rows = getCloserAuthReport(7)
    expect(rows).toEqual(expect.arrayContaining([
      expect.objectContaining({ to: TO, closer_auth: 'unsigned', count: 1 }),
      expect.objectContaining({ to: TO, closer_auth: 'legacy', count: 1 }),
    ]))
    expect(JSON.stringify(rows)).not.toContain('xyz')
  })
})
