import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdirSync, rmSync } from 'node:fs'
import { agentDir } from '../web/agent-config.js'
import { initDatabase, getAgentMessage, listAgentMessages, createAgentMessage, COMPLETION_REPORT_PREFIX } from '../db.js'
import { logger } from '../logger.js'
import { tryHandleMessages, getCloserAuthCounters, getSenderAuthCounters } from '../web/routes/messages.js'
import { mintAgentSendKey, resolveAgentSendKey } from '../web/agent-send-keys.js'
import type { RouteContext } from '../web/routes/types.js'

// Card f137f980 N3 (E9) -- MESSAGE_SENDER_AUTH=off on PUT /api/messages/:id: the closer check is skipped entirely (the
// rollback). The close works as before, closer_auth stays NULL, no key is looked up, nothing is counted or logged, and
// the receipt keeps the 'internal' label it had before the card.

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  MESSAGE_SENDER_AUTH: 'off',
  MESSAGE_SENDER_AUTH_DOWNGRADED: undefined,
}))
vi.mock('../web/agent-send-keys.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../web/agent-send-keys.js')>()
  return { ...real, resolveAgentSendKey: vi.fn(real.resolveAgentSendKey) }
})

type Auth = RouteContext['auth']

const TOKEN: Auth = { kind: 'token' } as Auth
const A = 'cao-iroda-f137' // recipient (the legitimate closer)
const B = 'cao-feszek-f137' // sender of the rows

async function request(
  method: string,
  path: string,
  body: unknown,
  keyHeader?: string,
): Promise<{ statusCode: number; json: Record<string, unknown> }> {
  const req = new EventEmitter() as unknown as RouteContext['req'] & { destroy(): void }
  ;(req as unknown as { headers: Record<string, string> }).headers = keyHeader === undefined ? {} : { 'x-agent-key': keyHeader }
  ;(req as { destroy(): void }).destroy = () => { /* readBody over-limit hook */ }
  const state = { statusCode: 0, body: '' }
  const res = {
    writeHead(code: number) { state.statusCode = code; return res },
    end(data?: unknown) { state.body = String(data ?? '') },
    setHeader() { /* not used by json() */ },
    getHeader() { return undefined },
  } as unknown as RouteContext['res']
  if (body !== undefined) {
    process.nextTick(() => {
      ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
      ;(req as unknown as EventEmitter).emit('end')
    })
  }
  const ctx = { req, res, path, method, url: new URL('http://localhost' + path), fedPeer: null, auth: TOKEN } as RouteContext
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: state.statusCode, json: JSON.parse(state.body) }
}

const open = (): number => createAgentMessage(B, A, 'task for the closer test').id
const put = (id: number, body: unknown, keyHeader?: string) => request('PUT', `/api/messages/${id}`, body, keyHeader)
const receiptOf = (id: number) =>
  listAgentMessages(10_000).find((m) => m.from_agent === A && m.to_agent === B && m.content.startsWith(`${COMPLETION_REPORT_PREFIX} msg_id:${id} `))

const logged: string[] = []

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  mkdirSync(agentDir(A), { recursive: true })
  mkdirSync(agentDir(B), { recursive: true })
})
afterAll(() => {
  rmSync(agentDir(A), { recursive: true, force: true })
  rmSync(agentDir(B), { recursive: true, force: true })
})
beforeEach(() => {
  vi.restoreAllMocks()
  vi.mocked(resolveAgentSendKey).mockClear()
  logged.length = 0
  for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { logged.push(JSON.stringify(args)) }) as never)
  }
})

describe('MESSAGE_SENDER_AUTH=off, PUT /api/messages/:id', () => {
  it('closes as before: closer_auth NULL, no key lookup, no counter, no log line, receipt labelled internal', async () => {
    const keyA = mintAgentSendKey(A)
    const keyB = mintAgentSendKey(B)
    // The headers that would have earned every kind of verdict in shadow mode: none, the right key, another agent's key,
    // an unknown key, garbage. None of them may change anything.
    const headers: Array<string | undefined> = [undefined, keyA, keyB, 'mvak_' + 'q'.repeat(43), 'garbage']
    for (const header of headers) {
      const id = open()
      const r = await put(id, { status: 'done', result: 'off mode result' }, header)
      expect(r.statusCode).toBe(200)
      expect(r.json).toEqual({ ok: true })

      const row = getAgentMessage(id)
      expect(row?.status).toBe('done')
      expect(row?.result).toBe('off mode result')
      expect(row?.closer_auth ?? null).toBeNull()

      const receipt = receiptOf(id)
      expect(receipt).toBeDefined()
      expect(receipt?.sender_auth).toBe('internal')
    }
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(getCloserAuthCounters()).toEqual({})
    expect(getSenderAuthCounters()).toEqual({})
    expect(logged.filter((l) => l.includes('closer'))).toEqual([])
  })

  it('a failed close and a notify:false close are inert too', async () => {
    const failedId = open()
    expect((await put(failedId, { status: 'failed', result: 'nope' }, undefined)).statusCode).toBe(200)
    expect(getAgentMessage(failedId)?.status).toBe('failed')
    expect(getAgentMessage(failedId)?.closer_auth ?? null).toBeNull()
    expect(receiptOf(failedId)?.sender_auth).toBe('internal')

    const quietId = open()
    expect((await put(quietId, { status: 'done', notify: false }, 'garbage')).statusCode).toBe(200)
    expect(getAgentMessage(quietId)?.closer_auth ?? null).toBeNull()
    expect(receiptOf(quietId)).toBeUndefined()

    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(getCloserAuthCounters()).toEqual({})
  })

  it('a second close is still the 409 no-op, 404 for a missing row', async () => {
    const id = open()
    expect((await put(id, { status: 'done' })).statusCode).toBe(200)
    const again = await put(id, { status: 'done' })
    expect(again.statusCode).toBe(409)
    expect(again.json.error).toBe('Message already closed')
    expect((await put(999_999, { status: 'done' })).statusCode).toBe(404)
    expect(getCloserAuthCounters()).toEqual({})
  })
})

describe('MESSAGE_SENDER_AUTH=off, sender-auth-report', () => {
  it('still answers, mode off, with a closers array', async () => {
    const r = await request('GET', '/api/messages/sender-auth-report', undefined)
    expect(r.statusCode).toBe(200)
    expect(r.json.mode).toBe('off')
    expect(Array.isArray(r.json.closers)).toBe(true)
  })
})
