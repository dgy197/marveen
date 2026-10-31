// Bot-API client of the permission-bot relay (card d7f586bf): request shape,
// error classification, token masking (F5.1). Loopback only: a socket guard
// refuses every non-loopback connect and the blocklisted ports (self-tested).
// The token is a fixed fake; no Vault, no real Telegram.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import http from 'node:http'
import type { AddressInfo } from 'node:net'
import { BotApiError, createBotApi, maskSecrets, RELAY_ALLOWED_UPDATES } from '../permission-bot-relay/bot-api.js'
import { FakeBotApi } from './helpers/fake-bot-api.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'

const TOKEN = '424242424:FAKEtokenSECRETforRelayTests_0123456789ab'
const SECRET = TOKEN.split(':')[1]!

// Every 8-char window of the secret, plus the whole token.
function leaks(corpus: string): string[] {
  const hits: string[] = []
  if (corpus.includes(TOKEN)) hits.push('token')
  for (let i = 0; i + 8 <= SECRET.length; i++) {
    const w = SECRET.slice(i, i + 8)
    if (corpus.includes(w)) hits.push(w)
  }
  return hits
}

const corpus: string[] = []
async function capture(p: Promise<unknown>): Promise<BotApiError> {
  try {
    await p
  } catch (err) {
    corpus.push(String(err), (err as Error).message, (err as Error).stack ?? '', JSON.stringify(err))
    expect(err).toBeInstanceOf(BotApiError)
    return err as BotApiError
  }
  throw new Error('expected a rejection')
}

let guard: LoopbackGuard
let fake: FakeBotApi
beforeAll(async () => {
  guard = installLoopbackGuard()
  await selfTestLoopbackGuard(guard)
  fake = new FakeBotApi(TOKEN)
  await fake.start()
})
afterAll(async () => {
  await fake.close()
  expect(leaks(corpus.join('\n'))).toEqual([])
  guard.uninstall()
})

describe('requests', () => {
  it('getMe / getWebhookInfo parse the result', async () => {
    const api = createBotApi({ token: TOKEN, apiBase: fake.url })
    expect(await api.getMe()).toEqual({ id: 424242424, is_bot: true, username: 'fake_permission_bot' })
    fake.webhookUrl = ''
    expect((await api.getWebhookInfo()).url).toBe('')
  })

  it('getUpdates always sends allowed_updates=["callback_query"] and the offset', async () => {
    const api = createBotApi({ token: TOKEN, apiBase: fake.url })
    const id = fake.pushCallback('apv:a:x:y')
    const ups = await api.getUpdates({ offset: id, timeout: 0, limit: 5 })
    expect(ups.map((u) => u.update_id)).toEqual([id])
    const last = fake.callsOf('getUpdates').at(-1)!
    expect(last.body).toEqual({ offset: id, timeout: 0, limit: 5, allowed_updates: [...RELAY_ALLOWED_UPDATES] })
    expect(RELAY_ALLOWED_UPDATES).toEqual(['callback_query'])
    await api.getUpdates({ offset: id + 1, timeout: 0, limit: 5 })
  })

  it('answerCallbackQuery caps the text at 200 characters', async () => {
    const api = createBotApi({ token: TOKEN, apiBase: fake.url })
    await api.answerCallbackQuery('cbq-1', { text: 'x'.repeat(500) })
    const c = fake.callsOf('answerCallbackQuery').at(-1)!
    expect(c.body['callback_query_id']).toBe('cbq-1')
    expect(String(c.body['text']).length).toBe(200)
  })

  it('the client has no deleteWebhook and no message-editing method', () => {
    const api = createBotApi({ token: TOKEN, apiBase: fake.url }) as unknown as Record<string, unknown>
    expect(Object.keys(api).sort()).toEqual(['answerCallbackQuery', 'getMe', 'getUpdates', 'getWebhookInfo'])
  })
})

describe('error classification (token never in the message)', () => {
  const cases: Array<[mode: 'conflict' | 'webhook_conflict' | 'error5xx' | 'unauthorized' | 'fatal_echo', kind: string, status: number]> = [
    ['conflict', 'conflict', 409],
    ['webhook_conflict', 'webhook_active', 409],
    ['error5xx', 'transient', 502],
    ['unauthorized', 'fatal', 401],
    ['fatal_echo', 'fatal', 400],
  ]
  for (const [mode, kind, status] of cases) {
    it(`${mode} -> ${kind}`, async () => {
      const api = createBotApi({ token: TOKEN, apiBase: fake.url })
      fake.mode = mode
      fake.modeCalls = 1
      const e = await capture(api.getUpdates({ timeout: 0, limit: 1 }))
      expect(e.kind).toBe(kind)
      expect(e.status).toBe(status)
      expect(e.method).toBe('getUpdates')
      expect(leaks(e.message)).toEqual([])
      if (mode === 'fatal_echo') expect(e.message).toContain('<token>')
    })
  }

  it('wrong token -> fatal 401', async () => {
    const api = createBotApi({ token: '424242424:WRONGtokenWRONGtokenWRONGtoken_000000', apiBase: fake.url })
    const e = await capture(api.getMe())
    expect(e.kind).toBe('fatal')
    expect(e.status).toBe(401)
  })

  it('429 carries retry_after', async () => {
    const srv = http.createServer((_req, res) => {
      res.writeHead(429, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error_code: 429, description: 'Too Many Requests: retry after 7', parameters: { retry_after: 7 } }))
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const api = createBotApi({ token: TOKEN, apiBase: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` })
    const e = await capture(api.getMe())
    expect(e.kind).toBe('rate_limit')
    expect(e.retryAfterSec).toBe(7)
    await new Promise<void>((r) => srv.close(() => r()))
  })

  it('an error description is masked BEFORE it is cut to 300: a token straddling the cut leaves no fragment (F4)', async () => {
    const srv = http.createServer((_req, res) => {
      res.writeHead(400, { 'content-type': 'application/json' })
      res.end(JSON.stringify({ ok: false, error_code: 400, description: `${'x'.repeat(280)}${TOKEN}${'y'.repeat(50)}` }))
    })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const api = createBotApi({ token: TOKEN, apiBase: `http://127.0.0.1:${(srv.address() as AddressInfo).port}` })
    const e = await capture(api.getMe())
    expect(e.kind).toBe('fatal')
    expect(e.message).toContain('<token>')
    expect(e.message).not.toContain(SECRET.slice(0, 8))
    expect(e.message).not.toContain('FAKEtoken')
    await new Promise<void>((r) => srv.close(() => r()))
  })

  it('read timeout -> transient', async () => {
    const srv = http.createServer(() => { /* never answers */ })
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const api = createBotApi({ token: TOKEN, apiBase: `http://127.0.0.1:${(srv.address() as AddressInfo).port}`, shortCallTimeoutMs: 100 })
    const e = await capture(api.getMe())
    expect(e.kind).toBe('transient')
    expect(e.message).toMatch(/read timeout/)
    srv.closeAllConnections()
    await new Promise<void>((r) => srv.close(() => r()))
  })

  it('caller abort -> aborted (not an error)', async () => {
    const api = createBotApi({ token: TOKEN, apiBase: fake.url })
    fake.mode = 'hang'
    fake.modeCalls = 1
    const ac = new AbortController()
    const p = api.getUpdates({ timeout: 0, limit: 1 }, ac.signal)
    setTimeout(() => ac.abort(), 50)
    const e = await capture(p)
    expect(e.kind).toBe('aborted')
  })

  it('connection refused and an invalid base URL (which echoes the full URL) -> transient, masked', async () => {
    const srv = http.createServer()
    await new Promise<void>((r) => srv.listen(0, '127.0.0.1', r))
    const port = (srv.address() as AddressInfo).port
    await new Promise<void>((r) => srv.close(() => r()))
    const refused = await capture(createBotApi({ token: TOKEN, apiBase: `http://127.0.0.1:${port}` }).getMe())
    expect(refused.kind).toBe('transient')
    const invalid = await capture(createBotApi({ token: TOKEN, apiBase: 'http://127.0.0.1:99999' }).getMe())
    expect(invalid.kind).toBe('transient')
    for (const e of [refused, invalid]) expect(leaks(`${e.message}\n${e.stack}`)).toEqual([])
  })

  it('a non-loopback target is refused by the guard before any I/O, and the message is masked', async () => {
    const before = guard.blocked.length
    const e = await capture(createBotApi({ token: TOKEN, apiBase: 'http://192.0.2.1' }).getMe())
    expect(e.kind).toBe('transient')
    expect(guard.blocked.length).toBeGreaterThan(before)
    expect(leaks(e.message)).toEqual([])
  })
})

describe('maskSecrets', () => {
  it('masks the token, its secret part, the URL-encoded token and any token-shaped string', () => {
    // Fake, and deliberately not starting with 'A' (real token shape for scanners).
    const other = '555555555:xANOTHERtokenANOTHERtokenANOTHERtoken1'
    const text = `a ${TOKEN} b ${SECRET} c ${encodeURIComponent(TOKEN)} d ${other}`
    const out = maskSecrets(text, TOKEN)
    expect(leaks(out)).toEqual([])
    expect(out).not.toContain('ANOTHERtoken')
    expect(out).toContain('<token>')
  })
})
