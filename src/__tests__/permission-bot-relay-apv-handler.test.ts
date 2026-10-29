// apv: button handler and prefix dispatcher of the permission-bot relay (card
// d7f586bf, spec F3, F5). Every pre-filter refusal is its own case and never
// reaches the dashboard; every dashboard answer maps to its exact toast with
// exactly one request (no automatic retry); a dashboard that is down, slow or
// redirecting yields "nothing was decided"; the forward target is loopback only;
// the Bearer file is re-read per request; the nonce, the raw callback data, the
// approval id, the presser id and the Bearer never reach the log.
// Loopback only (socket guard, self-tested): a fake Bot API and a fake dashboard
// on 127.0.0.1, fake tokens, no Vault, no real Telegram.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import http from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { buildCallbackData, newCallbackNonce } from '../web/approval-callback-data.js'
import { createBotApi, type BotApi, type TelegramUpdate } from '../permission-bot-relay/bot-api.js'
import {
  createApvHandler, dashboardTokenFileReader, prefilterCallback, toastFor,
  TOAST_CLOSED, TOAST_DECIDED, TOAST_INVALID, TOAST_UNAVAILABLE, TOAST_UNKNOWN,
  type ApvHandlerOptions,
} from '../permission-bot-relay/apv-handler.js'
import { createDispatcher } from '../permission-bot-relay/dispatch.js'
import type { RelayLog, UpdateHandler } from '../permission-bot-relay/poll-loop.js'
import { FakeBotApi } from './helpers/fake-bot-api.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'

const PIN = '424242424'
const PIN_N = Number(PIN)
const TOKEN = `${PIN}:FAKEtokenSECRETforRelayTests_0123456789ab`
const OWNER = '1591000001'
const OWNER_N = Number(OWNER)
const STRANGER_N = 2002000002
const MAIN_BOT_N = 777777777
const BEARER_A = 'bearerAAAAfakeDashboardToken0001'
const BEARER_B = 'bearerBBBBfakeDashboardToken0002'

// ---- fake dashboard ---------------------------------------------------------

interface DashCall { url: string; auth: string | undefined; body: Record<string, unknown> }
type DashReply = { status: number; body?: unknown; raw?: string; headers?: Record<string, string> } | 'hang'

class FakeDashboard {
  calls: DashCall[] = []
  reply: DashReply = { status: 200, body: { ok: true, outcome_text: '✅ Jóváhagyva: 12:00 (Budapest).' } }
  port = 0
  private server: http.Server | null = null
  private sockets = new Set<Socket>()

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => { void this.on(req, res) })
    this.server.on('connection', (s) => { this.sockets.add(s); s.on('close', () => this.sockets.delete(s)) })
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r))
    this.port = (this.server.address() as AddressInfo).port
  }

  async close(): Promise<void> {
    for (const s of this.sockets) s.destroy()
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()))
    this.server = null
  }

  private async on(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown> } catch { body = {} }
    this.calls.push({ url: req.url ?? '', auth: req.headers['authorization'], body })
    const r = this.reply
    if (r === 'hang') return
    res.writeHead(r.status, { 'content-type': 'application/json', ...(r.headers ?? {}) })
    res.end(r.raw ?? JSON.stringify(r.body ?? {}))
  }
}

// ---- log capture ------------------------------------------------------------

const allLog: string[] = []
function captureLog(): RelayLog {
  const push = (level: string) => (obj: Record<string, unknown>, msg: string): void => {
    allLog.push(JSON.stringify({ level, obj, msg }))
  }
  return { info: push('info'), warn: push('warn'), error: push('error') }
}
// Everything that must never be logged; collected per press.
const secrets = new Set<string>([TOKEN, TOKEN.split(':')[1]!, BEARER_A, BEARER_B, OWNER, String(STRANGER_N)])

// ---- fixtures ---------------------------------------------------------------

let guard: LoopbackGuard
let bot: FakeBotApi
let api: BotApi
let dash: FakeDashboard
let dir: string
let bearerPath: string
let nextUpdate = 5000

beforeAll(async () => {
  guard = installLoopbackGuard()
  await selfTestLoopbackGuard(guard)
  bot = new FakeBotApi(TOKEN)
  await bot.start()
  api = createBotApi({ token: TOKEN, apiBase: bot.url })
  dash = new FakeDashboard()
  await dash.start()
})
afterAll(async () => {
  await bot.close()
  await dash.close()
  const text = allLog.join('\n')
  for (const s of secrets) expect(text.includes(s), 'a secret value reached the log').toBe(false)
  expect(text).not.toMatch(/apv:/)
  guard.uninstall()
})
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pbr-apv-'))
  bearerPath = join(dir, '.dashboard-token')
  writeFileSync(bearerPath, `${BEARER_A}\n`, { mode: 0o600 })
  dash.calls = []
  dash.reply = { status: 200, body: { ok: true, outcome_text: '✅ Jóváhagyva: 12:00 (Budapest).' } }
  bot.calls.length = 0
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function button(decision: 'approved' | 'rejected' = 'approved'): { data: string; id: string; id32: string; nonce: string } {
  const id = randomUUID()
  const nonce = newCallbackNonce()
  const data = buildCallbackData(decision, id, nonce)
  secrets.add(nonce)
  secrets.add(data)
  secrets.add(id)
  secrets.add(id.replace(/-/g, ''))
  return { data, id, id32: id.replace(/-/g, ''), nonce }
}

function update(data: string | undefined, over: Record<string, unknown> = {}): TelegramUpdate {
  const cbq: Record<string, unknown> = {
    id: `cbq-${nextUpdate}`,
    from: { id: OWNER_N, is_bot: false },
    message: { message_id: 7, chat: { id: OWNER_N, type: 'private' }, from: { id: PIN_N, is_bot: true } },
    ...over,
  }
  if (data !== undefined && !('data' in over)) cbq['data'] = data
  return { update_id: nextUpdate++, callback_query: cbq as unknown as TelegramUpdate['callback_query'] }
}

function handler(over: Partial<ApvHandlerOptions> = {}): UpdateHandler {
  const apv = createApvHandler({
    pinnedBotId: PIN,
    dashboardPort: dash.port,
    readBearer: dashboardTokenFileReader(bearerPath),
    resolveOwner: () => OWNER,
    log: captureLog(),
    timeoutMs: 2000,
    ...over,
  })
  return createDispatcher({ 'apv:': apv }, { log: captureLog() })
}

async function press(h: UpdateHandler, u: TelegramUpdate, botApi: BotApi = api) {
  const outcome = await h(u, { api: botApi, signal: new AbortController().signal })
  const answers = bot.callsOf('answerCallbackQuery')
  return { outcome, toast: answers.at(-1)?.body['text'], answers: answers.length }
}

// ---- happy path -------------------------------------------------------------

describe('forward', () => {
  it('a valid press is forwarded once to 127.0.0.1 with the exact body, the toast is outcome_text', async () => {
    const b = button('approved')
    const r = await press(handler(), update(b.data))
    expect(dash.calls).toHaveLength(1)
    const c = dash.calls[0]!
    expect(c.url).toBe(`/api/approvals/${b.id32}/permission-bot`)
    expect(c.auth).toBe(`Bearer ${BEARER_A}`)
    expect(c.body).toEqual({ decision: 'approved', nonce: b.nonce, from_id: OWNER, chat_id: OWNER, message_id: 7, bot_id: PIN })
    expect(r).toEqual({ outcome: 'processed', toast: '✅ Jóváhagyva: 12:00 (Budapest).', answers: 1 })
  })

  it('reject button forwards decision=rejected', async () => {
    const b = button('rejected')
    await press(handler(), update(b.data))
    expect(dash.calls[0]!.body['decision']).toBe('rejected')
  })

  it('the target is loopback only: fixed host 127.0.0.1, integer port, redirects refused', async () => {
    const seen: string[] = []
    const spy: typeof fetch = (input, init) => {
      seen.push(String(input))
      expect(init?.redirect).toBe('error')
      return fetch(input, init)
    }
    const b = button()
    await press(handler({ fetchImpl: spy }), update(b.data))
    expect(seen).toHaveLength(1)
    expect(new URL(seen[0]!).hostname).toBe('127.0.0.1')
    expect(new URL(seen[0]!).protocol).toBe('http:')
    for (const port of [0, -1, 65536, 1.5, Number.NaN]) {
      expect(() => createApvHandler({ pinnedBotId: PIN, dashboardPort: port, readBearer: () => BEARER_A, log: captureLog() })).toThrow(TypeError)
    }
    expect(() => createApvHandler({ pinnedBotId: 'x', dashboardPort: dash.port, readBearer: () => BEARER_A, log: captureLog() })).toThrow(TypeError)
  })

  it('a redirect to a non-loopback host is not followed -> nothing was decided', async () => {
    dash.reply = { status: 302, headers: { location: 'http://192.0.2.1/api/approvals/x/permission-bot' }, raw: '' }
    const blockedBefore = guard.blocked.length
    const r = await press(handler(), update(button().data))
    expect(r.toast).toBe(TOAST_UNAVAILABLE)
    expect(r.outcome).toBe('rejected')
    expect(dash.calls).toHaveLength(1)
    expect(guard.blocked.length).toBe(blockedBefore)
  })

  it('the Bearer file is re-read per request (rotation between two presses)', async () => {
    const h = handler()
    await press(h, update(button().data))
    writeFileSync(bearerPath, `${BEARER_B}\n`)
    await press(h, update(button().data))
    expect(dash.calls.map((c) => c.auth)).toEqual([`Bearer ${BEARER_A}`, `Bearer ${BEARER_B}`])
  })

  it('no Bearer file -> nothing was decided, no request', async () => {
    rmSync(bearerPath)
    const r = await press(handler(), update(button().data))
    expect(r.toast).toBe(TOAST_UNAVAILABLE)
    expect(dash.calls).toHaveLength(0)
  })

  it('a failing toast does not throw (no retry by the poll loop)', async () => {
    const badApi = createBotApi({ token: `${PIN}:WRONGsecretWRONGsecretWRONGsecret00`, apiBase: bot.url })
    const r = await press(handler(), update(button().data), badApi)
    expect(r.outcome).toBe('processed')
    expect(dash.calls).toHaveLength(1)
  })
})

// ---- forged callback_data ---------------------------------------------------

describe('forged callback_data -> invalid toast, never forwarded', () => {
  const b = (() => {
    const id = randomUUID()
    const nonce = newCallbackNonce()
    secrets.add(nonce)
    return { id32: id.replace(/-/g, ''), nonce }
  })()
  const cases: Array<[string, string | undefined]> = [
    ['wrong prefix', `apx:a:${b.id32}:${b.nonce}`],
    ['upper-case prefix', `APV:a:${b.id32}:${b.nonce}`],
    ['upper-case decision', `apv:A:${b.id32}:${b.nonce}`],
    ['upper-case hex id', `apv:a:${b.id32.toUpperCase().replace(/^[0-9]/, 'A')}:${b.nonce}`],
    ['leading space', ` apv:a:${b.id32}:${b.nonce}`],
    ['trailing space', `apv:a:${b.id32}:${b.nonce} `],
    ['trailing newline', `apv:a:${b.id32}:${b.nonce}\n`],
    ['short nonce (21)', `apv:a:${b.id32}:${b.nonce.slice(0, 21)}`],
    ['long nonce (23)', `apv:a:${b.id32}:${b.nonce}x`],
    ['31 hex id', `apv:a:${b.id32.slice(0, 31)}:${b.nonce}`],
    ['33 hex id', `apv:a:${b.id32}a:${b.nonce}`],
    ['dashed id', `apv:a:${b.id32.slice(0, 8)}-${b.id32.slice(8)}:${b.nonce}`],
    ['unknown decision', `apv:x:${b.id32}:${b.nonce}`],
    ['ppr: (no handler wired)', `ppr:a:${b.id32}:${b.nonce}`],
    ['empty data', ''],
    ['no data', undefined],
  ]
  for (const [name, data] of cases) {
    it(name, async () => {
      const r = await press(handler(), update(data))
      expect(r).toEqual({ outcome: 'rejected', toast: TOAST_INVALID, answers: 1 })
      expect(dash.calls).toHaveLength(0)
    })
  }
})

// ---- who pressed, where -----------------------------------------------------

describe('pre-filter: presser, chat, message', () => {
  const refused: Array<[string, Record<string, unknown>]> = [
    ['another user presses', { from: { id: STRANGER_N, is_bot: false }, message: { message_id: 7, chat: { id: STRANGER_N, type: 'private' }, from: { id: PIN_N, is_bot: true } } }],
    ['from.is_bot true', { from: { id: OWNER_N, is_bot: true } }],
    ['from.is_bot missing', { from: { id: OWNER_N } }],
    ['from missing', { from: undefined }],
    ['group chat', { message: { message_id: 7, chat: { id: -1001234567890, type: 'supergroup' }, from: { id: PIN_N, is_bot: true } } }],
    ['group type with the owner id as chat id', { message: { message_id: 7, chat: { id: OWNER_N, type: 'group' } , from: { id: PIN_N, is_bot: true } } }],
    ['chat.id != from.id (private)', { message: { message_id: 7, chat: { id: STRANGER_N, type: 'private' }, from: { id: PIN_N, is_bot: true } } }],
    ['inline_message_id instead of message', { message: undefined, inline_message_id: 'AAAinline' }],
    ['inline_message_id next to a message', { inline_message_id: 'AAAinline' }],
    ['no message', { message: undefined }],
    ['buttoned message sent by the main bot', { message: { message_id: 7, chat: { id: OWNER_N, type: 'private' }, from: { id: MAIN_BOT_N, is_bot: true } } }],
    ['buttoned message without a sender', { message: { message_id: 7, chat: { id: OWNER_N, type: 'private' } } }],
    ['message_id 0', { message: { message_id: 0, chat: { id: OWNER_N, type: 'private' }, from: { id: PIN_N, is_bot: true } } }],
  ]
  for (const [name, over] of refused) {
    it(name, async () => {
      const r = await press(handler(), update(button().data, over))
      expect(r).toEqual({ outcome: 'rejected', toast: TOAST_INVALID, answers: 1 })
      expect(dash.calls).toHaveLength(0)
    })
  }

  it('owner unresolved at press time -> nothing was decided, not forwarded', async () => {
    const r = await press(handler({ resolveOwner: () => null }), update(button().data))
    expect(r).toEqual({ outcome: 'rejected', toast: TOAST_UNAVAILABLE, answers: 1 })
    expect(dash.calls).toHaveLength(0)
  })

  it('owner resolver throwing -> same, fail-closed', async () => {
    const r = await press(handler({ resolveOwner: () => { throw new Error('boom') } }), update(button().data))
    expect(r.toast).toBe(TOAST_UNAVAILABLE)
    expect(dash.calls).toHaveLength(0)
  })

  it('prefilterCallback names the reason without values', () => {
    const u = update(button().data, { from: { id: STRANGER_N, is_bot: false } })
    expect(prefilterCallback(u.callback_query!, OWNER, PIN)).toEqual({ ok: false, reason: 'not_owner' })
  })
})

// ---- F3.4: every dashboard answer -------------------------------------------

describe('F3.4 dashboard answer -> exact toast, one request, no retry', () => {
  const table: Array<[string, DashReply, string, 'processed' | 'rejected']> = [
    ['200 outcome_text', { status: 200, body: { ok: true, outcome_text: '❌ Elutasítva: 12:01 (Budapest).' } }, '❌ Elutasítva: 12:01 (Budapest).', 'processed'],
    ['200 ok without outcome_text', { status: 200, body: { ok: true } }, TOAST_DECIDED, 'processed'],
    ['200 not the success shape', { status: 200, body: { ok: false } }, TOAST_UNKNOWN, 'rejected'],
    ['200 non-JSON', { status: 200, raw: '<html>' }, TOAST_UNKNOWN, 'rejected'],
    ['409 already_resolved', { status: 409, body: { ok: false, reason: 'already_resolved', status: 'approved' } }, TOAST_CLOSED, 'rejected'],
    ['409 expired', { status: 409, body: { ok: false, reason: 'expired' } }, TOAST_CLOSED, 'rejected'],
    ['409 wrong_category', { status: 409, body: { ok: false, reason: 'wrong_category' } }, TOAST_INVALID, 'rejected'],
    ['409 not_bound', { status: 409, body: { ok: false, reason: 'not_bound' } }, TOAST_INVALID, 'rejected'],
    ['409 payload_mismatch', { status: 409, body: { ok: false, reason: 'payload_mismatch' } }, TOAST_INVALID, 'rejected'],
    ['403 bad_nonce', { status: 403, body: { ok: false, reason: 'bad_nonce' } }, TOAST_INVALID, 'rejected'],
    ['403 owner_mismatch', { status: 403, body: { ok: false, reason: 'owner_mismatch' } }, TOAST_INVALID, 'rejected'],
    ['403 message_mismatch', { status: 403, body: { ok: false, reason: 'message_mismatch' } }, TOAST_INVALID, 'rejected'],
    ['403 bot_mismatch', { status: 403, body: { ok: false, reason: 'bot_mismatch' } }, TOAST_INVALID, 'rejected'],
    ['400 bad_request', { status: 400, body: { ok: false, reason: 'bad_request', field: 'nonce' } }, TOAST_INVALID, 'rejected'],
    ['404 not_found', { status: 404, body: { ok: false, reason: 'not_found' } }, TOAST_INVALID, 'rejected'],
    ['401 (Bearer refused)', { status: 401, body: { error: 'Unauthorized' } }, TOAST_UNAVAILABLE, 'rejected'],
    ['503 owner_unresolved', { status: 503, body: { ok: false, reason: 'owner_unresolved' } }, TOAST_UNAVAILABLE, 'rejected'],
    ['503 permission_bot_unavailable', { status: 503, body: { ok: false, reason: 'permission_bot_unavailable', why: 'same_as_main_bot' } }, TOAST_UNAVAILABLE, 'rejected'],
    ['500', { status: 500, raw: 'boom' }, TOAST_UNAVAILABLE, 'rejected'],
    ['502', { status: 502, raw: '<html>bad gateway</html>' }, TOAST_UNAVAILABLE, 'rejected'],
  ]
  for (const [name, reply, toast, outcome] of table) {
    it(name, async () => {
      dash.reply = reply
      const r = await press(handler(), update(button().data))
      expect(r).toEqual({ outcome, toast, answers: 1 })
      expect(dash.calls).toHaveLength(1)
    })
  }

  it('dashboard not running -> nothing was decided, no throw', async () => {
    const gone = new FakeDashboard()
    await gone.start()
    const port = gone.port
    await gone.close()
    const r = await press(handler({ dashboardPort: port }), update(button().data))
    expect(r).toEqual({ outcome: 'rejected', toast: TOAST_UNAVAILABLE, answers: 1 })
  })

  it('dashboard timeout -> nothing was decided, one request', async () => {
    dash.reply = 'hang'
    const t0 = Date.now()
    const r = await press(handler({ timeoutMs: 200 }), update(button().data))
    expect(Date.now() - t0).toBeLessThan(5000)
    expect(r).toEqual({ outcome: 'rejected', toast: TOAST_UNAVAILABLE, answers: 1 })
    expect(dash.calls).toHaveLength(1)
  })

  it('toastFor covers the unavailable kinds', () => {
    for (const why of ['no_bearer', 'timeout', 'network', 'aborted'] as const) expect(toastFor({ kind: 'unavailable', why })).toBe(TOAST_UNAVAILABLE)
  })
})

describe('dispatcher', () => {
  it('rejects a malformed prefix key at construction', () => {
    expect(() => createDispatcher({ APV: (async () => 'processed') as UpdateHandler }, { log: captureLog() })).toThrow(TypeError)
  })
  it('routes only the exact prefix to its handler', async () => {
    let apvSeen = 0
    let pprSeen = 0
    const d = createDispatcher({
      'apv:': async () => { apvSeen++; return 'processed' },
      'ppr:': async () => { pprSeen++; return 'processed' },
    }, { log: captureLog() })
    const ctx = { api, signal: new AbortController().signal }
    await d(update('ppr:x'), ctx)
    await d(update('apv:x'), ctx)
    await d(update('APV:x'), ctx)
    await d(update('constructor:x'), ctx)
    expect([apvSeen, pprSeen]).toEqual([1, 1])
  })
})
