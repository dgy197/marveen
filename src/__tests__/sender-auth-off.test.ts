import { describe, it, expect, vi, beforeAll, afterAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdirSync, rmSync } from 'node:fs'
import { agentDir } from '../web/agent-config.js'
import { initDatabase, getAgentMessage } from '../db.js'
import { MAIN_AGENT_ID } from '../config.js'
import { tryHandleMessages, getSenderAuthCounters } from '../web/routes/messages.js'
import { mintAgentSendKey, resolveAgentSendKey } from '../web/agent-send-keys.js'
import type { RouteContext } from '../web/routes/types.js'

// Card 0d7e2c04 N3 -- MESSAGE_SENDER_AUTH=off: the check is skipped entirely (the rollback). The row is accepted as
// before, the sender_auth column stays empty, no key is looked up, nothing is counted.

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  MESSAGE_SENDER_AUTH: 'off',
  MESSAGE_SENDER_AUTH_DOWNGRADED: undefined,
}))
vi.mock('../web/agent-send-keys.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../web/agent-send-keys.js')>()
  return { ...real, resolveAgentSendKey: vi.fn(real.resolveAgentSendKey) }
})

const SENDER = 'sa-off-0d7e'

async function post(body: unknown, keyHeader?: string): Promise<{ statusCode: number; json: Record<string, unknown> }> {
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
  process.nextTick(() => {
    ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
    ;(req as unknown as EventEmitter).emit('end')
  })
  const ctx = { req, res, path: '/api/messages', method: 'POST', url: new URL('http://localhost/api/messages'), fedPeer: null, auth: { kind: 'token' } } as RouteContext
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: state.statusCode, json: JSON.parse(state.body) }
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  mkdirSync(agentDir(SENDER), { recursive: true })
})
afterAll(() => { rmSync(agentDir(SENDER), { recursive: true, force: true }) })

describe('MESSAGE_SENDER_AUTH=off', () => {
  it('accepts as before, writes no sender_auth, looks up no key, counts nothing', async () => {
    const key = mintAgentSendKey(SENDER)
    for (const header of [undefined, key, 'mvak_' + 'q'.repeat(43), 'garbage']) {
      const r = await post({ from: SENDER, to: MAIN_AGENT_ID, content: 'off mode' }, header)
      expect(r.statusCode).toBe(200)
      expect(r.json.status).toBe('pending')
      expect('sender_auth' in r.json).toBe(false)
      expect(getAgentMessage(Number(r.json.id))?.sender_auth).toBeNull()
    }
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(getSenderAuthCounters()).toEqual({})
  })
})
