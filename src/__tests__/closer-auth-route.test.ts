import { describe, it, expect, vi, beforeAll, afterAll, beforeEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdirSync, rmSync } from 'node:fs'
import { agentDir } from '../web/agent-config.js'
import { initDatabase, getDb, getAgentMessage, listAgentMessages, createAgentMessage, COMPLETION_REPORT_PREFIX } from '../db.js'
import { MAIN_AGENT_ID, OWNER_NAME } from '../config.js'
import { logger } from '../logger.js'
import { tryHandleMessages, getCloserAuthCounters, getSenderAuthCounters } from '../web/routes/messages.js'
import { mintAgentSendKey, resolveAgentSendKey, AGENT_SEND_KEY_MAX_LEN, AGENT_SEND_KEY_GRACE_SEC } from '../web/agent-send-keys.js'
import { VOICE_CHANNEL_AGENT_ID } from '../channel-coordinator/ingest.js'
import type { RouteContext } from '../web/routes/types.js'

// Card f137f980 N2 -- PUT /api/messages/:id, shadow mode. Contract under test:
//   - the answer, the delivery, `notify` and the receipt TEXT are exactly what they were; closer_auth is only recorded;
//   - verdicts against the row's recipient (to_agent, read from the stored row): verified / verified_prev / mismatch /
//     unsigned / invalid / session / device / no_key_recipient;
//   - the verdict is written by the same UPDATE as the close and counted only for the close that won;
//   - the receipt row is labelled 'receipt_<verdict>' (sender_auth), not 'internal';
//   - the raw key reaches no log line, response or DB column.

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

function fakeCtx(path: string, body: unknown, opts: Opts): { ctx: RouteContext; res: { statusCode: number; body: string } } {
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
    ctx: { req, res, path, method: 'PUT', url: new URL('http://localhost' + path), fedPeer: null, auth: opts.auth } as RouteContext,
    res: state,
  }
}

async function put(id: number | string, body: unknown, opts: Opts = { auth: { kind: 'token' } as Auth }): Promise<{ statusCode: number; json: Record<string, unknown>; raw: string }> {
  const { ctx, res } = fakeCtx(`/api/messages/${id}`, body, opts)
  expect(await tryHandleMessages(ctx)).toBe(true)
  return { statusCode: res.statusCode, json: JSON.parse(res.body), raw: res.body }
}

const TOKEN: Auth = { kind: 'token' } as Auth
const A = 'ca-iroda-f137' // the recipient of the rows under test (the legitimate closer)
const B = 'ca-feszek-f137' // the sender of the rows, and "another agent" for mismatch
const CLOSE = { status: 'done', result: 'the result' }

/** A fresh open row B -> to, as the in-process writer makes it. */
const open = (to: string = A, from: string = B): number => createAgentMessage(from, to, `task for ${to}`).id
const closerOf = (id: number): string | null | undefined => getAgentMessage(id)?.closer_auth
const receiptOf = (id: number, from: string = A, to: string = B) =>
  listAgentMessages(10_000).find((m) => m.from_agent === from && m.to_agent === to && m.content.startsWith(`${COMPLETION_REPORT_PREFIX} msg_id:${id} `))
const count = (v: string): number => getCloserAuthCounters()[v] ?? 0
const totalCount = (): number => Object.values(getCloserAuthCounters()).reduce((a, b) => a + b, 0)

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

describe('verdicts (always the same answer, the verdict only stored)', () => {
  it('the recipient\'s own current key -> verified', async () => {
    const id = open()
    const before = count('verified')
    const r = await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA })
    expect(r.statusCode).toBe(200)
    expect(r.json).toEqual({ ok: true })
    expect(getAgentMessage(id)?.status).toBe('done')
    expect(closerOf(id)).toBe('verified')
    expect(count('verified')).toBe(before + 1)
  })

  it('failed closes carry a verdict too', async () => {
    const id = open()
    expect((await put(id, { status: 'failed', result: 'nope' }, { auth: TOKEN, keyHeader: keyA })).statusCode).toBe(200)
    expect(getAgentMessage(id)?.status).toBe('failed')
    expect(closerOf(id)).toBe('verified')
  })

  it('rotation: the old key is verified_prev inside the grace window, invalid after it', async () => {
    const old = keyA
    const fresh = mintAgentSendKey(A)
    const a = open()
    const b = open()
    const c = open()
    expect((await put(a, CLOSE, { auth: TOKEN, keyHeader: fresh })).statusCode).toBe(200)
    expect(closerOf(a)).toBe('verified')
    expect((await put(b, CLOSE, { auth: TOKEN, keyHeader: old })).statusCode).toBe(200)
    expect(closerOf(b)).toBe('verified_prev')
    vi.useFakeTimers({ toFake: ['Date'] })
    try {
      vi.setSystemTime(Date.now() + (AGENT_SEND_KEY_GRACE_SEC + 5) * 1000)
      const r = await put(c, CLOSE, { auth: TOKEN, keyHeader: old })
      expect(r.statusCode).toBe(200)
      expect(closerOf(c)).toBe('invalid')
    } finally {
      vi.useRealTimers()
    }
  })

  it('another agent\'s valid key -> mismatch, warn names the key\'s owner and the row, never the key', async () => {
    const id = open()
    const before = count('mismatch')
    const r = await put(id, CLOSE, { auth: TOKEN, keyHeader: keyB })
    expect(r.statusCode).toBe(200)
    expect(r.json).toEqual({ ok: true })
    expect(closerOf(id)).toBe('mismatch')
    expect(count('mismatch')).toBe(before + 1)
    const warns = logged.filter((l) => l.includes('mismatch'))
    expect(warns.length).toBeGreaterThan(0)
    expect(warns.join('\n')).toContain(B) // the key's owner...
    expect(warns.join('\n')).toContain(A) // ...and the row's recipient are named
    expect(warns.join('\n')).toContain(String(id))
    expect(logged.join('\n')).not.toContain(keyA)
    expect(logged.join('\n')).not.toContain(keyB)
  })

  it('the recipient is read from the stored row, not from the request: a body that names another `to` changes nothing', async () => {
    const id = open(A)
    const r = await put(id, { ...CLOSE, to: B, to_agent: B, from_agent: A }, { auth: TOKEN, keyHeader: keyB })
    expect(r.statusCode).toBe(200)
    expect(closerOf(id)).toBe('mismatch')
    const own = open(B, A)
    expect((await put(own, { ...CLOSE, to_agent: A }, { auth: TOKEN, keyHeader: keyB })).statusCode).toBe(200)
    expect(closerOf(own)).toBe('verified')
  })

  it('no header -> unsigned, with a warn', async () => {
    const id = open()
    const before = count('unsigned')
    const r = await put(id, CLOSE, { auth: TOKEN })
    expect(r.statusCode).toBe(200)
    expect(closerOf(id)).toBe('unsigned')
    expect(count('unsigned')).toBe(before + 1)
    expect(logged.some((l) => l.includes('unsigned'))).toBe(true)
  })

  it('a random mvak_ key, a key without the prefix and an empty header -> invalid', async () => {
    const wrong = 'mvak_' + 'x'.repeat(43)
    const a = open()
    const b = open()
    const c = open()
    expect((await put(a, CLOSE, { auth: TOKEN, keyHeader: wrong })).statusCode).toBe(200)
    expect((await put(b, CLOSE, { auth: TOKEN, keyHeader: 'not-a-key' })).statusCode).toBe(200)
    expect((await put(c, CLOSE, { auth: TOKEN, keyHeader: '' })).statusCode).toBe(200)
    expect([closerOf(a), closerOf(b), closerOf(c)]).toEqual(['invalid', 'invalid', 'invalid'])
    expect(logged.join('\n')).not.toContain(wrong)
  })

  it('a too long header (over the cap) -> invalid, without hashing or a lookup', async () => {
    const over = 'mvak_' + 'a'.repeat(AGENT_SEND_KEY_MAX_LEN - 4)
    expect(over.length).toBe(AGENT_SEND_KEY_MAX_LEN + 1)
    const id = open()
    const r = await put(id, CLOSE, { auth: TOKEN, keyHeader: over })
    expect(r.statusCode).toBe(200)
    expect(closerOf(id)).toBe('invalid')
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
  })

  it('a repeated X-Agent-Key header -> invalid, even when each copy is the recipient\'s valid key; no lookup', async () => {
    const joined = open()
    const same = open()
    const arr = open()
    await put(joined, CLOSE, { auth: TOKEN, keyHeader: `${keyA}, ${keyB}`, rawHeaders: ['X-Agent-Key', keyA, 'x-agent-key', keyB] })
    await put(same, CLOSE, { auth: TOKEN, keyHeader: keyA, rawHeaders: ['X-Agent-Key', keyA, 'X-AGENT-KEY', keyA] })
    await put(arr, CLOSE, { auth: TOKEN, keyHeader: [keyA, keyA] })
    expect([closerOf(joined), closerOf(same), closerOf(arr)]).toEqual(['invalid', 'invalid', 'invalid'])
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(logged.join('\n')).not.toContain(keyA)
    expect(logged.join('\n')).not.toContain(keyB)
  })

  it('a single header in rawHeaders is still verified', async () => {
    const id = open()
    await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA, rawHeaders: ['Authorization', 'Bearer t', 'X-Agent-Key', keyA] })
    expect(closerOf(id)).toBe('verified')
  })

  it('owner session -> session, device key -> device; a key header does not change the lane label and is not looked up', async () => {
    const s = open()
    const d = open()
    expect((await put(s, CLOSE, { auth: { kind: 'session', user: 'gyuri' } as Auth, keyHeader: keyB })).statusCode).toBe(200)
    expect((await put(d, CLOSE, { auth: { kind: 'device', device: 'x', deviceId: 3, scope: 'full' } as Auth, keyHeader: keyB })).statusCode).toBe(200)
    expect(closerOf(s)).toBe('session')
    expect(closerOf(d)).toBe('device')
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
  })

  it('the MAIN agent is a key holder too: its own key on a row addressed to it -> verified', async () => {
    const mainKey = mintAgentSendKey(MAIN_AGENT_ID)
    const id = open(MAIN_AGENT_ID)
    await put(id, CLOSE, { auth: TOKEN, keyHeader: mainKey })
    expect(closerOf(id)).toBe('verified')
    const other = open(MAIN_AGENT_ID)
    await put(other, CLOSE, { auth: TOKEN, keyHeader: keyA })
    expect(closerOf(other)).toBe('mismatch')
  })
})

describe('no_key_recipient: a recipient that holds no send key, decided before any key work', () => {
  const recipients: Array<[string, string]> = [
    ['a system id', 'system'],
    ['the owner', OWNER_NAME],
    ['a federated address', 'peer-f137/someone'],
    ['the voice mailbox', VOICE_CHANNEL_AGENT_ID ?? 'voice-channel'],
  ]
  for (const [name, to] of recipients) {
    it(`${name} (${to}): no_key_recipient, even with a valid key header, and no lookup`, async () => {
      const id = open(to, A)
      const r = await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA })
      expect(r.statusCode).toBe(200)
      expect(r.json).toEqual({ ok: true })
      expect(closerOf(id)).toBe('no_key_recipient')
      expect(resolveAgentSendKey).not.toHaveBeenCalled()
    })
  }

  it('it opens no loophole for an agent-addressed row: an unsigned close of a row to a real agent stays unsigned', async () => {
    const id = open(A)
    await put(id, CLOSE, { auth: TOKEN })
    expect(closerOf(id)).toBe('unsigned')
  })
})

describe('the key store failing (E13)', () => {
  it('a throwing lookup -> invalid, and the close still succeeds with the usual answer', async () => {
    vi.mocked(resolveAgentSendKey).mockImplementationOnce(() => { throw new Error('key store down') })
    const id = open()
    const r = await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA })
    expect(r.statusCode).toBe(200)
    expect(r.json).toEqual({ ok: true })
    expect(getAgentMessage(id)?.status).toBe('done')
    expect(getAgentMessage(id)?.result).toBe('the result')
    expect(closerOf(id)).toBe('invalid')
    expect(logged.some((l) => l.includes('key store down'))).toBe(true) // the error text is logged...
    expect(logged.join('\n')).not.toContain(keyA) // ...the key is not
  })
})

describe('what must not change (E6)', () => {
  it('the answer is byte-identical for every verdict', async () => {
    const wrong = 'mvak_' + 'q'.repeat(43)
    const raws: string[] = []
    for (const o of [
      { auth: TOKEN, keyHeader: keyA }, { auth: TOKEN, keyHeader: keyB }, { auth: TOKEN }, { auth: TOKEN, keyHeader: wrong },
      { auth: { kind: 'session', user: 'g' } as Auth }, { auth: { kind: 'device', device: 'x', deviceId: 3, scope: 'full' } as Auth },
    ] as Opts[]) {
      const r = await put(open(), CLOSE, o)
      expect(r.statusCode).toBe(200)
      raws.push(r.raw)
    }
    raws.push((await put(open('system', A), CLOSE, { auth: TOKEN })).raw)
    expect(new Set(raws).size).toBe(1)
    expect(raws[0]).toBe(JSON.stringify({ ok: true }))
  })

  it('the receipt TEXT is identical for every verdict (only the label differs)', async () => {
    const texts = new Set<string>()
    for (const o of [{ auth: TOKEN, keyHeader: keyA }, { auth: TOKEN, keyHeader: keyB }, { auth: TOKEN }] as Opts[]) {
      const id = open()
      await put(id, CLOSE, o)
      const rec = receiptOf(id)
      expect(rec, 'a receipt exists').toBeDefined()
      texts.add(rec!.content.replace(/msg_id:\d+/, 'msg_id:N'))
      expect(rec!.status).toBe('pending')
    }
    expect([...texts]).toEqual([`${COMPLETION_REPORT_PREFIX} msg_id:N status:done\n\nthe result`])
  })

  it('the closer_auth and receipt label never leave over HTTP: the answers carry neither name', async () => {
    const id = open()
    const r = await put(id, CLOSE, { auth: TOKEN })
    expect(r.raw).not.toContain('closer_auth')
    expect(r.raw).not.toContain('sender_auth')
    expect(r.raw).not.toContain('receipt_')
  })
})

describe('receipt label (E7)', () => {
  it('the receipt row is receipt_<verdict>, not internal', async () => {
    const cases: Array<[Opts, string]> = [
      [{ auth: TOKEN, keyHeader: keyA }, 'receipt_verified'],
      [{ auth: TOKEN, keyHeader: keyB }, 'receipt_mismatch'],
      [{ auth: TOKEN }, 'receipt_unsigned'],
      [{ auth: TOKEN, keyHeader: 'junk' }, 'receipt_invalid'],
      [{ auth: { kind: 'session', user: 'g' } as Auth }, 'receipt_session'],
    ]
    for (const [o, label] of cases) {
      const id = open()
      await put(id, CLOSE, o)
      expect(getAgentMessage(receiptOf(id)!.id)?.sender_auth, label).toBe(label)
    }
    const sysId = open('system', A)
    await put(sysId, CLOSE, { auth: TOKEN })
    // a row to a recipient without a key: the verdict is stored and the (unchanged) receipt carries it
    expect(closerOf(sysId)).toBe('no_key_recipient')
    expect(getAgentMessage(receiptOf(sysId, 'system', A)!.id)?.sender_auth).toBe('receipt_no_key_recipient')
  })

  it('a row whose sender is not an addressable agent gets no receipt (unchanged), the verdict is stored', async () => {
    const id = open(A, 'system')
    await put(id, CLOSE, { auth: TOKEN })
    expect(receiptOf(id, A, 'system')).toBeUndefined()
    expect(closerOf(id)).toBe('unsigned')
  })

  it('notify:false -> no receipt, the verdict is stored anyway', async () => {
    const id = open()
    const r = await put(id, { ...CLOSE, notify: false }, { auth: TOKEN, keyHeader: keyA })
    expect(r.statusCode).toBe(200)
    expect(receiptOf(id)).toBeUndefined()
    expect(closerOf(id)).toBe('verified')
  })

  it('notify:true is the default spelled out: a receipt, labelled', async () => {
    const id = open()
    await put(id, { ...CLOSE, notify: true }, { auth: TOKEN, keyHeader: keyA })
    expect(getAgentMessage(receiptOf(id)!.id)?.sender_auth).toBe('receipt_verified')
  })
})

describe('no verdict, no count on the refused paths', () => {
  it('409: a second close of a closed row changes nothing, is not counted, does no key work', async () => {
    const id = open()
    await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA })
    const total = totalCount()
    const receipts = listAgentMessages(10_000).length
    vi.mocked(resolveAgentSendKey).mockClear()
    const again = await put(id, { status: 'done', result: 'second' }, { auth: TOKEN })
    expect(again.statusCode).toBe(409)
    expect(again.json.error).toBe('Message already closed')
    expect(closerOf(id)).toBe('verified') // only the first closer's verdict stays
    expect(getAgentMessage(id)?.result).toBe('the result')
    expect(totalCount()).toBe(total)
    expect(listAgentMessages(10_000).length).toBe(receipts)
    expect(resolveAgentSendKey).not.toHaveBeenCalled()
    expect(logged.some((l) => l.includes('Shadow closer check'))).toBe(false)
  })

  it('404: an unknown id -> the usual answer, no count, no log line', async () => {
    const total = totalCount()
    const r = await put(999_999, CLOSE, { auth: TOKEN })
    expect(r.statusCode).toBe(404)
    expect(r.json.error).toBe('Message not found or invalid status')
    expect(totalCount()).toBe(total)
    expect(logged.some((l) => l.includes('Shadow closer check'))).toBe(false)
  })

  it('404: an invalid status on an open row -> the row stays open with no verdict, nothing counted', async () => {
    const id = open()
    const total = totalCount()
    const r = await put(id, { status: 'bogus' }, { auth: TOKEN })
    expect(r.statusCode).toBe(404)
    expect(getAgentMessage(id)?.status).toBe('pending')
    expect(closerOf(id)).toBeNull()
    expect(totalCount()).toBe(total)
  })

  it('400: a non-boolean notify is refused before anything is read or written', async () => {
    const id = open()
    const total = totalCount()
    const r = await put(id, { ...CLOSE, notify: 'false' }, { auth: TOKEN })
    expect(r.statusCode).toBe(400)
    expect(getAgentMessage(id)?.status).toBe('pending')
    expect(closerOf(id)).toBeNull()
    expect(totalCount()).toBe(total)
  })

  it('two closes in a row with different verdicts: the winner\'s verdict stays, the loser gets the 409', async () => {
    const id = open()
    expect((await put(id, CLOSE, { auth: TOKEN })).statusCode).toBe(200) // unsigned wins
    expect((await put(id, CLOSE, { auth: TOKEN, keyHeader: keyA })).statusCode).toBe(409) // would have been verified
    expect(closerOf(id)).toBe('unsigned')
  })
})

describe('the POST side is untouched', () => {
  it('closing rows moves no sender-auth counter', async () => {
    const before = JSON.stringify(getSenderAuthCounters())
    await put(open(), CLOSE, { auth: TOKEN, keyHeader: keyA })
    await put(open(), CLOSE, { auth: TOKEN })
    expect(JSON.stringify(getSenderAuthCounters())).toBe(before)
  })
})

describe('the key is never persisted, served or logged', () => {
  it('after wrong, forged, right, oversized and repeated closes, no raw key is in any log line, response or DB row', async () => {
    const wrong = 'mvak_' + 'y'.repeat(43)
    const huge = 'mvak_' + 'z'.repeat(507)
    const outputs: string[] = []
    for (const key of [keyA, keyB, wrong, huge]) {
      outputs.push((await put(open(), CLOSE, { auth: TOKEN, keyHeader: key })).raw)
    }
    const db = getDb()
    const dump = JSON.stringify([
      db.prepare('SELECT * FROM agent_messages').all(),
      db.prepare('SELECT * FROM agent_send_keys').all(),
    ])
    const haystack = [...logged, ...outputs, dump].join('\n')
    for (const secret of [keyA, keyB, wrong, huge]) {
      expect(haystack.includes(secret), `leaked ${secret.slice(0, 7)}...`).toBe(false)
      expect(haystack.includes(secret.slice(5, 25)), 'leaked a key fragment').toBe(false)
    }
  })
})
