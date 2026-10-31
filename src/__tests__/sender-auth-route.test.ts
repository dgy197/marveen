import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdirSync, rmSync } from 'node:fs'
import { agentDir } from '../web/agent-config.js'
import { initDatabase, getDb, getAgentMessage, listAgentMessages, createAgentMessage } from '../db.js'
import { MAIN_AGENT_ID, resolveMessageSenderAuthMode, MESSAGE_SENDER_AUTH } from '../config.js'
import { logger } from '../logger.js'
import { tryHandleMessages, getSenderAuthCounters } from '../web/routes/messages.js'
import { mintAgentSendKey, resolveAgentSendKey, AGENT_SEND_KEY_MAX_LEN, AGENT_SEND_KEY_GRACE_SEC } from '../web/agent-send-keys.js'
import { COORDINATOR_AGENT_ID, VOICE_CHANNEL_AGENT_ID } from '../channel-coordinator/ingest.js'
import { OWNER_UI_SENDER } from '../web/reserved-senders.js'
import type { RouteContext } from '../web/routes/types.js'

// Card 0d7e2c04 N3 -- POST /api/messages, shadow mode. Contract under test:
//   - the row is ALWAYS accepted exactly as before (status, response shape); sender_auth is only recorded;
//   - verdicts: verified / verified_prev / mismatch / invalid / unsigned / session / device;
//   - the check runs after every existing guard, so their 403s are untouched and do no key work;
//   - the raw key reaches no log line, response or DB column;
//   - MESSAGE_SENDER_AUTH: unset or unknown -> shadow, 'enforce' does not exist in this phase.

// Count the lookups the route makes, but keep the real behaviour.
vi.mock('../web/agent-send-keys.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../web/agent-send-keys.js')>()
  return { ...real, resolveAgentSendKey: vi.fn(real.resolveAgentSendKey) }
})

type Auth = RouteContext['auth']

interface Opts {
  auth?: Auth
  /** value of the x-agent-key header as Node would expose it (string, or an array to model a repeat) */
  keyHeader?: string | string[]
  /** the raw header list, to model a repeated header the way Node's parser records it */
  rawHeaders?: string[]
}

function fakeCtx(body: unknown, opts: Opts): { ctx: RouteContext; res: { statusCode: number; body: string } } {
  const req = new EventEmitter() as unknown as RouteContext['req'] & { destroy(): void }
  const headers: Record<string, string | string[]> = {}
  if (opts.keyHeader !== undefined) headers['x-agent-key'] = opts.keyHeader
  ;(req as unknown as { headers: Record<string, string | string[]> }).headers = headers
  if (opts.rawHeaders) (req as unknown as { rawHeaders: string[] }).rawHeaders = opts.rawHeaders
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
  return {
    ctx: { req, res, path: '/api/messages', method: 'POST', url: new URL('http://localhost/api/messages'), fedPeer: null, auth: opts.auth } as RouteContext,
    res: state,
  }
}

async function post(body: unknown, opts: Opts = { auth: { kind: 'token' } as Auth }): Promise<{ statusCode: number; json: Record<string, unknown>; raw: string }> {
  const { ctx, res } = fakeCtx(body, opts)
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: res.statusCode, json: JSON.parse(res.body), raw: res.body }
}

const TOKEN: Auth = { kind: 'token' } as Auth
const A = 'sa-feszek-0d7e'
const B = 'sa-iroda-0d7e'
const rowCount = () => listAgentMessages(10_000).length
const stored = (r: { json: Record<string, unknown> }) => getAgentMessage(Number(r.json.id))?.sender_auth

// Every logger call, stringified, to grep for key material.
const logged: string[] = []
function captureLogs(): void {
  for (const level of ['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { logged.push(JSON.stringify(args)) }) as never)
  }
}

let keyA = ''
let keyB = ''

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
  captureLogs()
  keyA = mintAgentSendKey(A)
  keyB = mintAgentSendKey(B)
})

describe('MESSAGE_SENDER_AUTH resolution', () => {
  it('unset, empty and shadow -> shadow; off -> off; nothing else is a mode of this build', () => {
    expect(resolveMessageSenderAuthMode(undefined)).toMatchObject({ mode: 'shadow', downgraded: false })
    expect(resolveMessageSenderAuthMode('')).toMatchObject({ mode: 'shadow', downgraded: false })
    expect(resolveMessageSenderAuthMode(' Shadow ')).toMatchObject({ mode: 'shadow', downgraded: false })
    expect(resolveMessageSenderAuthMode(' OFF ')).toMatchObject({ mode: 'off', downgraded: false })
    for (const v of ['enforce', 'ENFORCE', 'mark', 'on', 'true', '1', 'shadow2', 'of f']) {
      const r = resolveMessageSenderAuthMode(v)
      expect(r.mode, v).toBe('shadow')
      expect(r.downgraded, v).toBe(true)
    }
  })

  it('the shipped default of this suite is shadow', () => {
    expect(MESSAGE_SENDER_AUTH).toBe('shadow')
  })
})

describe('verdicts (always HTTP 200, row always stored)', () => {
  it('own current key -> verified', async () => {
    const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'hello' }, { auth: TOKEN, keyHeader: keyA })
    expect(r.statusCode).toBe(200)
    expect(stored(r)).toBe('verified')
  })

  it('forged-from: feszek key with from=iroda -> 200, mismatch, warn without the key', async () => {
    const r = await post({ from: B, to: MAIN_AGENT_ID, content: 'forged' }, { auth: TOKEN, keyHeader: keyA })
    expect(r.statusCode).toBe(200)
    expect(stored(r)).toBe('mismatch')
    const warns = logged.filter((l) => l.includes('mismatch'))
    expect(warns.length).toBeGreaterThan(0)
    expect(warns.join('\n')).toContain(A) // the key's agent is named...
    expect(logged.join('\n')).not.toContain(keyA) // ...the key itself never
  })

  it('wrong-key: a random mvak_ key -> 200, invalid', async () => {
    const wrong = 'mvak_' + 'x'.repeat(43)
    const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'wrong' }, { auth: TOKEN, keyHeader: wrong })
    expect(r.statusCode).toBe(200)
    expect(stored(r)).toBe('invalid')
    expect(logged.join('\n')).not.toContain(wrong)
  })

  it('a key without the prefix, and an empty header value -> invalid', async () => {
    expect(stored(await post({ from: A, to: MAIN_AGENT_ID, content: 'a' }, { auth: TOKEN, keyHeader: 'not-a-key' }))).toBe('invalid')
    expect(stored(await post({ from: A, to: MAIN_AGENT_ID, content: 'b' }, { auth: TOKEN, keyHeader: '' }))).toBe('invalid')
  })

  it('rotation / replay: the old key is verified_prev inside the grace window, invalid after it', async () => {
    const old = keyA
    const fresh = mintAgentSendKey(A)
    expect(stored(await post({ from: A, to: MAIN_AGENT_ID, content: 'new' }, { auth: TOKEN, keyHeader: fresh }))).toBe('verified')
    expect(stored(await post({ from: A, to: MAIN_AGENT_ID, content: 'old' }, { auth: TOKEN, keyHeader: old }))).toBe('verified_prev')
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      vi.setSystemTime(Date.now() + (AGENT_SEND_KEY_GRACE_SEC + 5) * 1000)
      const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'too late' }, { auth: TOKEN, keyHeader: old })
      expect(r.statusCode).toBe(200)
      expect(stored(r)).toBe('invalid')
    } finally {
      vi.useRealTimers()
    }
  })

  it('missing-key-in-shadow: no header -> 200, unsigned, counter grows, response shape is the pre-card one', async () => {
    const before = getSenderAuthCounters().unsigned ?? 0
    const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'no key' }, { auth: TOKEN })
    expect(r.statusCode).toBe(200)
    expect(stored(r)).toBe('unsigned')
    expect(getSenderAuthCounters().unsigned).toBe(before + 1)
    expect(r.json.status).toBe('pending')
    // Exactly the keys 9d75d5e0 returned for this row (the queue field rides along); sender_auth is stored, never served.
    expect(Object.keys(r.json).sort()).toEqual([
      'completed_at', 'content', 'created_at', 'delivered_at', 'from_agent', 'id', 'origin_note', 'parent_span_id', 'priority',
      'queue', 'result', 'seen_at', 'span_id', 'status', 'stop_authorized', 'to_agent', 'trace_id', 'urgent',
    ])
    expect(r.raw).not.toContain('sender_auth')
  })

  it('a signed and an unsigned send answer with the same shape', async () => {
    const signed = await post({ from: A, to: MAIN_AGENT_ID, content: 's' }, { auth: TOKEN, keyHeader: keyA })
    const unsigned = await post({ from: A, to: MAIN_AGENT_ID, content: 'u' }, { auth: TOKEN })
    expect(Object.keys(signed.json).sort()).toEqual(Object.keys(unsigned.json).sort())
  })

  it('owner session -> session, device key -> device (a key header does not change the lane label)', async () => {
    const sess = await post({ from: A, to: MAIN_AGENT_ID, content: 'o' }, { auth: { kind: 'session', user: 'gyuri' } as Auth })
    expect(stored(sess)).toBe('session')
    const dev = await post({ from: A, to: MAIN_AGENT_ID, content: 'd' }, { auth: { kind: 'device', device: 'x', deviceId: 3, scope: 'full' } as Auth, keyHeader: keyA })
    expect(stored(dev)).toBe('device')
  })

  it('an in-process writer is internal', () => {
    const m = createAgentMessage(A, MAIN_AGENT_ID, 'in-process')
    expect(getAgentMessage(m.id)?.sender_auth).toBe('internal')
    expect('sender_auth' in m).toBe(false)
  })
})

describe('header handling', () => {
  it('size: a 512-byte header -> invalid, and no lookup is made', async () => {
    const huge = 'mvak_' + 'a'.repeat(507)
    expect(huge.length).toBe(512)
    const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'big' }, { auth: TOKEN, keyHeader: huge })
    expect(r.statusCode).toBe(200)
    expect(stored(r)).toBe('invalid')
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    // the cap itself: a header exactly one over the cap is also refused unlooked
    const over = 'mvak_' + 'a'.repeat(AGENT_SEND_KEY_MAX_LEN - 4)
    expect(over.length).toBe(AGENT_SEND_KEY_MAX_LEN + 1)
    expect(stored(await post({ from: A, to: MAIN_AGENT_ID, content: 'over' }, { auth: TOKEN, keyHeader: over }))).toBe('invalid')
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
  })

  it('several X-Agent-Key headers -> invalid, even when each is a valid key (the sender\'s own twice, or a joined value)', async () => {
    const two = await post({ from: A, to: MAIN_AGENT_ID, content: 'two' }, {
      auth: TOKEN, keyHeader: `${keyA}, ${keyB}`, rawHeaders: ['X-Agent-Key', keyA, 'x-agent-key', keyB],
    })
    expect(two.statusCode).toBe(200)
    expect(stored(two)).toBe('invalid')
    const same = await post({ from: A, to: MAIN_AGENT_ID, content: 'same' }, {
      auth: TOKEN, keyHeader: keyA, rawHeaders: ['X-Agent-Key', keyA, 'X-AGENT-KEY', keyA],
    })
    expect(stored(same)).toBe('invalid')
    const arr = await post({ from: A, to: MAIN_AGENT_ID, content: 'arr' }, { auth: TOKEN, keyHeader: [keyA, keyA] })
    expect(stored(arr)).toBe('invalid')
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(logged.join('\n')).not.toContain(keyA)
    expect(logged.join('\n')).not.toContain(keyB)
  })

  it('a single header in rawHeaders is still verified', async () => {
    const r = await post({ from: A, to: MAIN_AGENT_ID, content: 'one' }, { auth: TOKEN, keyHeader: keyA, rawHeaders: ['Authorization', 'Bearer t', 'X-Agent-Key', keyA] })
    expect(stored(r)).toBe('verified')
  })
})

describe('existing guards keep their order and answers (a valid key changes nothing)', () => {
  const cases: Array<[string, Record<string, unknown>, number, RegExp]> = [
    ['system', { from: 'system', to: MAIN_AGENT_ID, content: 'x' }, 403, /reserved for in-process system directives/],
    ['owner-ui', { from: OWNER_UI_SENDER, to: MAIN_AGENT_ID, content: 'x' }, 403, /reserved for the dashboard owner answer/],
    ['coordinator', { from: COORDINATOR_AGENT_ID, to: MAIN_AGENT_ID, content: 'x' }, 403, /reserved for the in-process channel coordinator/],
    ['voice without a device key', { from: VOICE_CHANNEL_AGENT_ID, to: MAIN_AGENT_ID, content: 'x' }, 403, /requires an enrolled device key|reserved/],
    ['urgent without a listed device key', { from: A, to: MAIN_AGENT_ID, content: 'x', urgent: true }, 403, /urgent delivery requires/],
    ['qualified from', { from: 'peer/agent', to: MAIN_AGENT_ID, content: 'x' }, 403, /must be a local agent id without "\/"/],
    ['unknown agent', { from: 'no-such-agent-0d7e', to: MAIN_AGENT_ID, content: 'x' }, 403, /unknown agent/],
  ]
  for (const [name, body, status, re] of cases) {
    it(`${name}: ${status}, no row, no key work`, async () => {
      const rows = rowCount()
      const counters = JSON.stringify(getSenderAuthCounters())
      const r = await post(body, { auth: TOKEN, keyHeader: keyA })
      expect(r.statusCode).toBe(status)
      expect(String(r.json.error)).toMatch(re)
      expect(r.raw).not.toContain(keyA)
      expect(rowCount()).toBe(rows)
      expect(JSON.stringify(getSenderAuthCounters())).toBe(counters)
      expect(resolveAgentSendKey).not.toHaveBeenCalled()
    })
  }
})

describe('the key is never persisted, served or logged', () => {
  it('after wrong, forged, right and oversized sends, no raw key is in any log line, response or DB row', async () => {
    const wrong = 'mvak_' + 'y'.repeat(43)
    const huge = 'mvak_' + 'z'.repeat(507)
    const outputs: string[] = []
    for (const [from, key] of [[A, keyA], [B, keyA], [A, wrong], [A, huge], [B, keyB]] as const) {
      outputs.push((await post({ from, to: MAIN_AGENT_ID, content: 'leak check' }, { auth: TOKEN, keyHeader: key })).raw)
    }
    const db = getDb()
    const dump = JSON.stringify([
      db.prepare('SELECT * FROM agent_messages').all(),
      db.prepare('SELECT * FROM agent_send_keys').all(),
    ])
    const haystack = [...logged, ...outputs, dump].join('\n')
    for (const secret of [keyA, keyB, wrong, huge]) {
      expect(haystack.includes(secret), `leaked ${secret.slice(0, 7)}...`).toBe(false)
      // not even the body of the key (past the shared prefix)
      expect(haystack.includes(secret.slice(5, 25)), 'leaked a key fragment').toBe(false)
    }
  })
})
