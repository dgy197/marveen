// End-to-end of the permission-bot relay (card d7f586bf N4, spec F3 / F4 / F5):
// the REAL T1 approvals route (POST /api/approvals/:id/permission-bot, card
// 9a77b3e5) behind a loopback HTTP server, the REAL relay modules (poll loop,
// prefix dispatcher, apv handler) in front of it, and a fake Bot API on
// 127.0.0.1 in between. The button message is made by the real sender (fake
// Telegram for the route's own outbound calls), so every callback_data and nonce
// here is one the owner's chat actually carried.
//
// Cases: approve (row approved, outcome_text toast, the dashboard took the
// buttons off), the same press again (already_resolved toast, status unchanged),
// reject, expired, a forged nonce (403, nothing decided), a stopped dashboard
// (nothing decided, "not available" toast).
//
// Loopback only (socket guard, self-tested), fake tokens, no Vault, no real
// Telegram. The relay's own fetch is the fetch captured BEFORE the route
// tests' Telegram stub is installed.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import http from 'node:http'
import type { AddressInfo, Socket } from 'node:net'
import { chmodSync, mkdtempSync, rmSync, unlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const state = vi.hoisted(() => ({
  mainToken: '',
  allowedChatId: '',
  channelToken: null as string | null,
  permToken: null as string | null,
  pinnedId: '',
}))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return {
    ...real,
    MAIN_AGENT_ID: 'marveen',
    get PERMISSION_BOT_ID() { return state.pinnedId },
    get TELEGRAM_BOT_TOKEN() { return state.mainToken },
    get ALLOWED_CHAT_ID() { return state.allowedChatId },
  }
})

vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  const read = () => { throw new Error('ENOENT') }
  return {
    ...real,
    resolveOwnerChatId: vi.fn((_r?: unknown, configured?: string | null) => real.resolveOwnerChatId(read, configured)),
    resolveAlertOwnerChat: vi.fn((_r?: unknown, configured?: string | null) => real.resolveAlertOwnerChat(read, configured)),
  }
})

vi.mock('../channel-provider.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../channel-provider.js')>()
  return { ...real, readChannelToken: vi.fn(() => state.channelToken) }
})

vi.mock('../web/vault.js', () => ({
  getSecret: vi.fn((id: string) => (id === 'telegram-engedely-bot-token' ? state.permToken : null)),
  readPermissionBotToken: vi.fn(() => state.permToken),
}))

import { initDatabase, getApproval, getDb, listApprovalEvents } from '../db.js'
import { logger } from '../logger.js'
import { ownerNotificationsSettled, setPermissionBotResponseKeyPath } from '../web/routes/approvals.js'
import { RESPONSE_MAC_HEADER, loadOrCreateResponseKey, responseKeyPath, verifyResponseMac } from '../permission-bot-relay/response-mac.js'
import { buildCallbackData, newCallbackNonce } from '../web/approval-callback-data.js'
import { createBotApi } from '../permission-bot-relay/bot-api.js'
import { OffsetStore, StatusFile, relayPaths } from '../permission-bot-relay/offset-store.js'
import { PollLoop, type RelayLog } from '../permission-bot-relay/poll-loop.js'
import { createApvHandler, TOAST_CLOSED, TOAST_INVALID, TOAST_UNAVAILABLE, TOAST_UNKNOWN } from '../permission-bot-relay/apv-handler.js'
import { createDispatcher } from '../permission-bot-relay/dispatch.js'
import { FakeBotApi } from './helpers/fake-bot-api.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'
import {
  OWNER, PERM_BOT, MAIN_TOKEN, MAIN_CHANNEL_TOKEN, PERM_TOKEN, SECRET_PARTS,
  createFakeTelegram, route, canonical, requestBody, buttonsOf, dumpLogs, sha, type TgCall,
} from './helpers/rag-approval-route-harness.js'

// The fetch the relay uses: captured now, before beforeEach stubs the global one
// with the fake Telegram of the route.
const realFetch = globalThis.fetch

const OWNER_N = Number(OWNER)
const PERM_BOT_N = Number(PERM_BOT)
const BEARER = 'bearerE2EfakeDashboardToken0001'

// ---- the dashboard: the real route handler behind a loopback HTTP server ------

interface DashCall { url: string; auth: string | undefined; body: Record<string, unknown>; status: number; raw: string }

class LoopbackDashboard {
  calls: DashCall[] = []
  dropMac = false
  port = 0
  private server: http.Server | null = null
  private sockets = new Set<Socket>()

  async start(): Promise<void> {
    this.server = http.createServer((req, res) => { void this.on(req, res) })
    this.server.on('connection', (s) => { this.sockets.add(s); s.on('close', () => this.sockets.delete(s)) })
    await new Promise<void>((r) => this.server!.listen(0, '127.0.0.1', r))
    this.port = (this.server.address() as AddressInfo).port
  }

  async stop(): Promise<void> {
    for (const s of this.sockets) s.destroy()
    if (this.server) await new Promise<void>((r) => this.server!.close(() => r()))
    this.server = null
  }

  private async on(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const chunks: Buffer[] = []
    for await (const c of req) chunks.push(c as Buffer)
    let body: Record<string, unknown> = {}
    try { body = JSON.parse(Buffer.concat(chunks).toString('utf8')) as Record<string, unknown> } catch { body = {} }
    const url = req.url ?? ''
    const auth = req.headers['authorization']
    const send = (status: number, raw: string, extra: Record<string, string> = {}): void => {
      this.calls.push({ url, auth, body, status, raw })
      res.writeHead(status, { 'content-type': 'application/json', ...extra })
      res.end(raw)
    }
    if (auth !== `Bearer ${BEARER}`) return send(401, JSON.stringify({ ok: false, reason: 'unauthorized' }))
    if (req.method !== 'POST' || !/^\/api\/approvals\/[0-9a-f]{32}\/permission-bot$/.test(url)) {
      return send(404, JSON.stringify({ ok: false, reason: 'not_found' }))
    }
    try {
      const out = await route('POST', url, body)
      // Card 0c15f6f7 A1: pass the route's own MAC header on, as the real server does.
      const mac = out.headers[RESPONSE_MAC_HEADER]
      send(out.status, out.raw, mac === undefined || this.dropMac ? {} : { [RESPONSE_MAC_HEADER]: mac })
    } catch {
      send(500, JSON.stringify({ ok: false, reason: 'harness_error' }))
    }
  }
}

// ---- fixtures ----------------------------------------------------------------

const tg = createFakeTelegram()
let guard: LoopbackGuard
let blockedAfterSelfTest = 0
let bot: FakeBotApi
let dash: LoopbackDashboard
let loop: PollLoop
let offsets: OffsetStore
let dir: string
let loggedApp: unknown[][] = []
const relayLines: string[] = []
let responses: string[] = []
const secretsInFlight: string[] = []
const T0 = Math.floor(Date.now() / 1000)

interface Posted { id: string; approve: string; reject: string; approveData: string; rejectData: string; messageId: number }

async function postD(): Promise<Posted> {
  const payload = canonical({ start: T0 - 10, end: T0 + 3600 })
  const out = await route('POST', '/api/approvals', requestBody(payload, { timeout_seconds: 600 }))
  responses.push(out.raw)
  expect(out.status).toBe(201)
  await ownerNotificationsSettled()
  const send: TgCall = tg.sends().at(-1)!
  const { approve, reject } = buttonsOf(send, out.body.id)
  const [a, r] = send.body.reply_markup.inline_keyboard[0]
  const row = getApproval(out.body.id)!
  secretsInFlight.push(approve, reject, a.callback_data, r.callback_data)
  return { id: out.body.id, approve, reject, approveData: a.callback_data, rejectData: r.callback_data, messageId: row.telegram_message_id! }
}

async function waitFor(cond: () => boolean, what: string, ms = 8000): Promise<void> {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

/** The owner presses a button: the update goes through the fake Bot API, the real loop, dispatcher and handler. */
async function relayPress(p: Posted, data: string): Promise<{ toast: string; updateId: number }> {
  const answered = bot.callsOf('answerCallbackQuery').length
  const updateId = bot.pushCallback(data, {
    from: { id: OWNER_N, is_bot: false },
    message: { message_id: p.messageId, chat: { id: OWNER_N, type: 'private' }, from: { id: PERM_BOT_N, is_bot: true } },
  })
  await waitFor(() => bot.callsOf('answerCallbackQuery').length === answered + 1, 'the toast')
  // The offset moves only after the handler returned: the press is fully done.
  await waitFor(() => offsets.read().offset === updateId + 1, 'the offset commit')
  await ownerNotificationsSettled()
  const toast = String(bot.callsOf('answerCallbackQuery').at(-1)!.body['text'])
  return { toast, updateId }
}

const status = (id: string) => getApproval(id)!.status
const eventCount = (id: string) => listApprovalEvents(id).length

function captureLog(): RelayLog {
  const push = (level: string) => (obj: Record<string, unknown>, msg: string): void => {
    relayLines.push(JSON.stringify({ level, obj, msg }))
  }
  return { info: push('info'), warn: push('warn'), error: push('error') }
}

beforeAll(async () => {
  guard = installLoopbackGuard()
  await selfTestLoopbackGuard(guard)
  blockedAfterSelfTest = guard.blocked.length
})
afterAll(() => {
  // The guard refused only its own self-test connections: the relay and the route
  // never tried a non-loopback or blocklisted connect.
  expect(guard.blocked.slice(blockedAfterSelfTest)).toEqual([])
  guard.uninstall()
})

beforeEach(async () => {
  initDatabase(':memory:')
  state.mainToken = MAIN_TOKEN
  state.allowedChatId = OWNER
  state.channelToken = MAIN_CHANNEL_TOKEN
  state.permToken = PERM_TOKEN
  state.pinnedId = PERM_BOT
  tg.reset()
  vi.stubGlobal('fetch', tg.fetch)
  loggedApp = []
  responses = []
  relayLines.length = 0
  secretsInFlight.length = 0
  for (const level of ['info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { loggedApp.push([level, ...args]) }) as never)
  }

  bot = new FakeBotApi(PERM_TOKEN)
  await bot.start()
  dash = new LoopbackDashboard()
  await dash.start()
  dir = mkdtempSync(join(tmpdir(), 'pbr-e2e-'))
  const bearerPath = join(dir, '.dashboard-token')
  writeFileSync(bearerPath, `${BEARER}\n`, { mode: 0o600 })
  // Card 0c15f6f7 A1: the route and the relay resolve the response key from the same store dir.
  setPermissionBotResponseKeyPath(responseKeyPath(dir))

  const log = captureLog()
  const paths = relayPaths(dir)
  offsets = new OffsetStore(paths.offset)
  const statusFile = new StatusFile(paths.status, () => Date.now(), log)
  const api = createBotApi({ token: PERM_TOKEN, apiBase: bot.url, fetchImpl: realFetch })
  const apv = createApvHandler({
    pinnedBotId: PERM_BOT,
    dashboardPort: dash.port,
    readBearer: () => BEARER,
    log,
    resolveOwner: () => OWNER,
    fetchImpl: realFetch,
    responseKey: loadOrCreateResponseKey(responseKeyPath(dir)),
  })
  loop = new PollLoop({
    api, offsets, status: statusFile, log,
    handler: createDispatcher({ 'apv:': apv }, { log }),
    longPollTimeoutSec: 1,
    dropBacklogAtStart: false,
  })
  void loop.run()
})

afterEach(async () => {
  try {
    await loop.stop(3000)
    await ownerNotificationsSettled()
    // No relay call ever touched a webhook, and only the three relay methods were used.
    expect(bot.callsOf('deleteWebhook')).toHaveLength(0)
    for (const c of bot.calls) expect(['getWebhookInfo', 'getUpdates', 'answerCallbackQuery']).toContain(c.method)
    expect(bot.calls.every((c) => c.tokenOk)).toBe(true)

    // Nothing secret reached a log or a response: not the token, the Bearer, a
    // nonce, nor the raw callback data (the relay logs reason codes only).
    const logs = dumpLogs(loggedApp) + '\n' + relayLines.join('\n')
    expect(logs).not.toContain(PERM_TOKEN)
    expect(logs).not.toContain(BEARER)
    for (const part of SECRET_PARTS) {
      expect(logs).not.toContain(part)
      for (const r of responses) expect(r).not.toContain(part)
    }
    for (const s of secretsInFlight) {
      expect(logs).not.toContain(s)
      expect(logs).not.toContain(sha(s))
      for (const r of responses) expect(r).not.toContain(s)
    }
    expect(relayLines.join('\n')).not.toMatch(/apv:/)
  } finally {
    await dash.stop()
    await bot.close()
    setPermissionBotResponseKeyPath(null)
    rmSync(dir, { recursive: true, force: true })
    vi.useRealTimers()
    vi.unstubAllGlobals()
    vi.restoreAllMocks()
  }
})

describe('permission-bot relay, end to end through the real approvals route', () => {
  it('approve: the row is approved, the toast is the route\'s outcome_text, the dashboard took the buttons off', async () => {
    const p = await postD()
    const { toast } = await relayPress(p, p.approveData)

    expect(dash.calls).toHaveLength(1)
    const call = dash.calls[0]!
    expect(call.url).toBe(`/api/approvals/${p.id.replace(/-/g, '')}/permission-bot`)
    expect(call.auth).toBe(`Bearer ${BEARER}`)
    expect(call.body).toMatchObject({ decision: 'approved', nonce: p.approve, from_id: OWNER, chat_id: OWNER, message_id: p.messageId, bot_id: PERM_BOT })
    expect(call.status).toBe(200)
    const answer = JSON.parse(call.raw) as { ok: boolean; outcome_text: string; approval: { status: string } }
    expect(answer).toMatchObject({ ok: true, approval: { status: 'approved' } })

    expect(status(p.id)).toBe('approved')
    expect(getApproval(p.id)!.resolved_by).toBe(`owner:telegram:${OWNER}`)
    expect(toast).toBe(answer.outcome_text)
    expect(toast).toMatch(/^✅ Jóváhagyva: .+ \(Budapest\)\.$/)

    // The dashboard removed the button, through the permission bot, on THAT message.
    expect(tg.edits()).toHaveLength(1)
    expect(tg.edits()[0]!.url).toBe(`https://api.telegram.org/bot${PERM_TOKEN}/editMessageReplyMarkup`)
    expect(tg.edits()[0]!.body).toMatchObject({ chat_id: OWNER, message_id: p.messageId, reply_markup: { inline_keyboard: [] } })
    // The callback was answered exactly once, for exactly this callback_query.
    expect(bot.callsOf('answerCallbackQuery')).toHaveLength(1)
  })

  it('the same press again: already_resolved toast, status and events unchanged, no second edit', async () => {
    const p = await postD()
    await relayPress(p, p.approveData)
    const events = eventCount(p.id)
    const resolvedAt = getApproval(p.id)!.resolved_at

    const again = await relayPress(p, p.approveData)
    expect(again.toast).toBe(TOAST_CLOSED)
    expect(dash.calls).toHaveLength(2)
    expect(dash.calls[1]!.status).toBe(409)
    expect(JSON.parse(dash.calls[1]!.raw)).toMatchObject({ ok: false, reason: 'already_resolved', status: 'approved' })
    expect(status(p.id)).toBe('approved')
    expect(getApproval(p.id)!.resolved_at).toBe(resolvedAt)
    expect(eventCount(p.id)).toBe(events)
    expect(tg.edits()).toHaveLength(1)

    // The other button of the same message does not flip the closed request either.
    const other = await relayPress(p, p.rejectData)
    expect(other.toast).toBe(TOAST_CLOSED)
    expect(status(p.id)).toBe('approved')
  })

  it('reject: the row is rejected, the toast says so, the buttons come off', async () => {
    const p = await postD()
    const { toast } = await relayPress(p, p.rejectData)
    expect(status(p.id)).toBe('rejected')
    expect(toast).toMatch(/^❌ Elutasítva: .+ \(Budapest\)\.$/)
    expect(JSON.parse(dash.calls[0]!.raw).outcome_text).toBe(toast)
    expect(tg.edits()).toHaveLength(1)
    expect(tg.edits()[0]!.body).toMatchObject({ chat_id: OWNER, message_id: p.messageId, reply_markup: { inline_keyboard: [] } })
  })

  it('expired: the closed toast, nothing decided, the buttons stay (the route refused)', async () => {
    const p = await postD()
    getDb().prepare('UPDATE approvals SET timeout_at = ? WHERE id = ?').run(Math.floor(Date.now() / 1000) - 5, p.id)
    const { toast } = await relayPress(p, p.approveData)
    expect(toast).toBe(TOAST_CLOSED)
    expect(dash.calls).toHaveLength(1)
    expect(dash.calls[0]!.status).toBe(409)
    expect(JSON.parse(dash.calls[0]!.raw)).toMatchObject({ ok: false, reason: 'expired' })
    expect(status(p.id)).toBe('pending')
    expect(tg.edits()).toHaveLength(0)
  })

  it('forged nonce: 403, the invalid toast, nothing decided; the real button still works afterwards', async () => {
    const p = await postD()
    const forged = buildCallbackData('approved', p.id, newCallbackNonce())
    secretsInFlight.push(forged)
    const { toast } = await relayPress(p, forged)
    expect(toast).toBe(TOAST_INVALID)
    expect(dash.calls).toHaveLength(1)
    expect(dash.calls[0]!.status).toBe(403)
    expect(JSON.parse(dash.calls[0]!.raw)).toMatchObject({ ok: false, reason: 'bad_nonce' })
    expect(status(p.id)).toBe('pending')
    expect(getApproval(p.id)!.resolved_at ?? null).toBeNull()
    expect(tg.edits()).toHaveLength(0)

    // The reject button's nonce does not take the approve decision either: a
    // swapped decision/nonce pair is a forgery as well.
    const swapped = buildCallbackData('approved', p.id, p.reject)
    secretsInFlight.push(swapped)
    expect((await relayPress(p, swapped)).toast).toBe(TOAST_INVALID)
    // The route itself rejected the swapped pair (not a pre-filter drop).
    expect(dash.calls).toHaveLength(2)
    expect(dash.calls[1]!.status).toBe(403)
    expect(JSON.parse(dash.calls[1]!.raw)).toMatchObject({ ok: false, reason: 'bad_nonce' })
    expect(status(p.id)).toBe('pending')

    const real = await relayPress(p, p.approveData)
    expect(real.toast).toMatch(/^✅ Jóváhagyva/)
    expect(status(p.id)).toBe('approved')
  })

  it('dashboard stopped: nothing decided, the "not available" toast, no edit, the row is still pending', async () => {
    const p = await postD()
    await dash.stop()
    const { toast } = await relayPress(p, p.approveData)
    expect(toast).toBe(TOAST_UNAVAILABLE)
    expect(dash.calls).toHaveLength(0)
    expect(status(p.id)).toBe('pending')
    expect(tg.edits()).toHaveLength(0)
    const text = relayLines.join('\n')
    expect(text).toContain('dashboard_unavailable')
    expect(text).toContain('"why":"network"')
  })
})

// Card 0c15f6f7 A1: the route signs its answers, the relay trusts only signed ones.
describe('signed answers of the permission-bot route (card 0c15f6f7 A1)', () => {
  const forged = (): Record<string, unknown> => ({
    decision: 'approved', nonce: newCallbackNonce(), from_id: OWNER, chat_id: OWNER, message_id: 1001, bot_id: PERM_BOT,
  })

  it('a route answer carries a header that verifies with the key; the key is not in the body', async () => {
    const p = await postD()
    const id32 = p.id.replace(/-/g, '')
    const key = loadOrCreateResponseKey(responseKeyPath(dir))!
    const body = forged()
    const out = await route('POST', `/api/approvals/${id32}/permission-bot`, body)
    expect([403, 409]).toContain(out.status)
    expect(verifyResponseMac(key, out.headers[RESPONSE_MAC_HEADER], id32, body.nonce as string, out.status, out.raw)).toBe(true)
    // Another nonce or another id does not verify.
    expect(verifyResponseMac(key, out.headers[RESPONSE_MAC_HEADER], id32, newCallbackNonce(), out.status, out.raw)).toBe(false)
    expect(verifyResponseMac(key, out.headers[RESPONSE_MAC_HEADER], '0'.repeat(32), body.nonce as string, out.status, out.raw)).toBe(false)
    expect(out.raw).not.toContain(key.toString('hex'))
    expect(out.raw).not.toContain(key.toString('base64'))
    expect(JSON.stringify(out.headers)).not.toContain(key.toString('hex'))
  })

  it('an unreadable body is answered 400 with a header over the empty nonce', async () => {
    const p = await postD()
    const id32 = p.id.replace(/-/g, '')
    const key = loadOrCreateResponseKey(responseKeyPath(dir))!
    const out = await route('POST', `/api/approvals/${id32}/permission-bot`, {})
    expect(out.status).toBe(400)
    expect(verifyResponseMac(key, out.headers[RESPONSE_MAC_HEADER], id32, '', out.status, out.raw)).toBe(true)
  })

  it('a key file with mode 0644 is unusable: the route sends no header and does not rewrite it', async () => {
    const p = await postD()
    const keyFile = responseKeyPath(dir)
    loadOrCreateResponseKey(keyFile)
    chmodSync(keyFile, 0o644)
    const out = await route('POST', `/api/approvals/${p.id.replace(/-/g, '')}/permission-bot`, forged())
    expect([403, 409]).toContain(out.status)
    expect(out.headers[RESPONSE_MAC_HEADER]).toBeUndefined()
    expect(loadOrCreateResponseKey(keyFile)).toBeNull()
  })

  it('end to end: a signed answer gives the decision toast; the same answer without the header gives the unknown toast', async () => {
    const p = await postD()
    dash.dropMac = true
    const { toast } = await relayPress(p, p.approveData)
    expect(toast).toBe(TOAST_UNKNOWN)
    // The route did decide the row, but the relay could not tell who answered.
    expect(status(p.id)).toBe('approved')
    expect(relayLines.join('\n')).toContain('unsigned_response')
  })

  it('end to end: a route that signs with another key than the relay holds gives the unknown toast', async () => {
    const p = await postD()
    unlinkSync(responseKeyPath(dir))
    // The route now creates and uses a different key; the relay still holds the old one.
    setPermissionBotResponseKeyPath(responseKeyPath(`${dir}-other`))
    try {
      const { toast } = await relayPress(p, p.approveData)
      expect(toast).toBe(TOAST_UNKNOWN)
    } finally {
      rmSync(`${dir}-other`, { recursive: true, force: true })
    }
  })
})
