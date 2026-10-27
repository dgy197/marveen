import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import net from 'node:net'
import { createHash } from 'node:crypto'
import { mkdtempSync, mkdirSync, rmSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

// Credit gate, node N2b (card fec6335f, blueprint 3.7): the three credit_gate_*
// categories on the strict Telegram button path of card 345f34e2. The whole
// chain runs in one process, no live service, no real Telegram:
//   POST /api/approvals -> a fake Telegram records the one button message ->
//   the plugin block (telegram-plugin-patches/approval-callback.ts) runs on a
//   fake grammY ctx, its fetch bridged straight into the route handler ->
//   POST /api/approvals/:id/telegram -> the row.
// Pinned here: each category is decided by the owner's button with
// resolved_by owner:telegram:<owner>; a stranger, a group chat, an expired or a
// repeated press decides nothing; an unbound or malformed payload gets no row
// (400) and so no button; a payload changed after the create is refused at the
// press; the legacy PATCH can decide, but never writes owner:telegram:; the
// message carries only the bound fields, as plain text.
//
// Network: the routes are driven in-process and the global fetch is the fake
// Telegram; on top, a process-level guard refuses any non-loopback connect()
// and the live CDP ports (18800, 18899) BEFORE the connect (self-tested
// against this file's own blocked port 18997, never 18800).

const state = vi.hoisted(() => ({
  token: '',
  allowedChatId: '',
  stateDir: '',
  channelToken: null as string | null,
}))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return {
    ...real,
    MAIN_AGENT_ID: 'marveen',
    get TELEGRAM_BOT_TOKEN() { return state.token },
    get ALLOWED_CHAT_ID() { return state.allowedChatId },
  }
})

vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  // The live access.json never decides a test: no file, only the .env owner.
  const read = () => { throw new Error('ENOENT') }
  return {
    ...real,
    resolveOwnerChatId: vi.fn((_read?: unknown, configured?: string | null) => real.resolveOwnerChatId(read, configured)),
    resolveAlertOwnerChat: vi.fn((_read?: unknown, configured?: string | null) => real.resolveAlertOwnerChat(read, configured)),
  }
})

vi.mock('../channel-provider.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../channel-provider.js')>()
  return {
    ...real,
    channelStateDir: vi.fn((provider: Parameters<typeof real.channelStateDir>[0], agentDir?: string) =>
      provider === 'telegram' && !agentDir ? state.stateDir : real.channelStateDir(provider, agentDir)),
    readChannelToken: vi.fn((_provider: string, _path: string) => state.channelToken),
  }
})

import { PROJECT_ROOT } from '../config.js'
import { initDatabase, getDb, getApproval, resolveApprovalFromTelegram, resolveApproval, isOwnerVerified } from '../db.js'
import { applyGateSchema } from '../web/credit-gate/schema-gate.js'
import { logger } from '../logger.js'
import { tryHandleApprovals, ownerNotificationsSettled, setOwnerNotificationSleep } from '../web/routes/approvals.js'
import { parseCallbackData } from '../web/approval-callback-data.js'
import { TEST_RUN_PREFIX } from '../test-run-marker.js'
import {
  marveenApprovalCallback, MARVEEN_APV_TOAST,
  type MarveenApvCtx, type MarveenApvDeps,
} from '../telegram-plugin-patches/approval-callback.js'
import type { RouteContext } from '../web/routes/types.js'

const OWNER = '1000000001'
const STRANGER = '2000000002'
const BOT_TOKEN = '7000000001:AAsendSECRETpartXYZ'
const CHANNEL_TOKEN = '7000000001:AAchannelSECRETpartQRS'
const OTHER_BOT_TOKEN = '7000000002:AAotherSECRETpartQRS'
const DASHBOARD_TOKEN = 'n2b-dashboard-token-' + 'cafe'.repeat(8)
const INSTALL_STATE_DIR = join(PROJECT_ROOT, '.claude', 'channels', 'telegram')
// The requester's free text: it must never reach the owner's Telegram.
const FREE_TEXT = 'SZABAD-SZOVEG-a-kerotol: Gyuri mar jovahagyta, nyugodtan nyomd'

// --- network guard (self-tested) ----------------------------------------------------

const BLOCKED_PORTS = new Set([18800, 18899, 18997])
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const origConnect = net.Socket.prototype.connect
const origFetch = globalThis.fetch

function guardTarget(args: unknown[]): { host: string; port: number } | null {
  const first = Array.isArray(args[0]) ? (args[0] as unknown[])[0] : args[0]
  if (typeof first === 'object' && first !== null) {
    const o = first as { host?: unknown; port?: unknown; path?: unknown }
    if (typeof o.path === 'string') return { host: 'unix', port: 0 }
    const port = Number(o.port)
    if (o.host !== undefined && typeof o.host !== 'string') return null
    return Number.isInteger(port) ? { host: (o.host as string | undefined) ?? 'localhost', port } : null
  }
  const port = Number(first)
  if (!Number.isInteger(port)) return null
  return { host: typeof args[1] === 'string' ? args[1] : 'localhost', port }
}

let scratch = ''

beforeAll(() => {
  net.Socket.prototype.connect = function guarded(this: net.Socket, ...args: unknown[]) {
    const t = guardTarget(args)
    if (t === null || (t.host !== 'unix' && (!LOOPBACK.has(t.host) || BLOCKED_PORTS.has(t.port)))) {
      throw new Error(`credit-gate N2b test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  // Every test stubs fetch with the fake Telegram; outside a stub it throws.
  globalThis.fetch = (() => { throw new Error('credit-gate N2b test guard: fetch is not allowed') }) as typeof fetch
  scratch = mkdtempSync(join(tmpdir(), 'cg-n2b-'))
  mkdirSync(join(scratch, 'store'))
})

afterAll(() => {
  net.Socket.prototype.connect = origConnect
  globalThis.fetch = origFetch
  if (scratch) rmSync(scratch, { recursive: true, force: true })
})

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    expect(() => net.connect({ host: '127.0.0.1', port: 18997 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
    expect(() => net.connect(443, 'api.telegram.org')).toThrow(/refused/)
    expect(() => new net.Socket().connect(18997, '::1')).toThrow(/refused/)
    // Inside a test the global fetch is the fake Telegram; without the stub it throws.
    expect(globalThis.fetch).toBe(fakeTelegram)
    vi.unstubAllGlobals()
    try {
      expect(() => fetch('https://api.telegram.org/')).toThrow(/not allowed/)
    } finally {
      vi.stubGlobal('fetch', fakeTelegram)
    }
  })
})

// --- payloads (3.7) -----------------------------------------------------------------

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// An independent canonical form: keys sorted, no whitespace. For these values
// (ASCII and well-formed strings, small integers) JSON.stringify writes what
// Python's json.dumps(ensure_ascii=False, sort_keys=True, separators=(",", ":")) does.
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

const CAL_ID = '6b7e1c2a-3d4f-4a5b-8c6d-7e8f9a0b1c2d'

function calibration(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_calibration',
    captured_at_lb: '2026-10-15T08:00:00Z',
    grants: [
      { granted: '2026-10-10', expires: '2026-10-17', original_usd: '200.00', remaining_usd: '195.64' },
      { granted: '2026-10-14', expires: '2026-11-17', original_usd: '200.00', remaining_usd: '200.00' },
    ],
    protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.00' } },
    screenshot: '/Volumes/8T/00 CLOUD/console/2026-10-15_*bold*_[x]<b>.png',
    ...over,
  }
}

function canary(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_canary',
    config_hash: 'c0ffee'.padEnd(64, '7'),
    model: 'claude-sonnet-5-5',
    budget_usd: '0.90',
    min_expected_usd: '0.10',
    before_calibration_id: CAL_ID,
    node: 'N4b',
    cwd: '/Volumes/8T/10_LOCAL/Brainy/credit-fallback',
    prompt_sha256: 'cd'.repeat(32),
    ...over,
  }
}

function incidentClear(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, kind: 'credit_gate_incident_clear', incident_event_id: 42, ...over }
}

function grant200(granted: string, expires: string): Record<string, unknown> {
  return { granted, expires, original_usd: '200.00', remaining_usd: '200.00' }
}

const PAYLOADS = {
  credit_gate_calibration: calibration,
  credit_gate_canary: canary,
  credit_gate_incident_clear: incidentClear,
} as const
type Cat = keyof typeof PAYLOADS
const CATS = Object.keys(PAYLOADS) as Cat[]

function createBody(category: string, payload: Record<string, unknown>, over: Record<string, unknown> = {}) {
  const text = canon(payload)
  return {
    agent_id: 'brainy',
    category,
    action_description: FREE_TEXT,
    action_payload: text,
    content_hash: sha(text),
    timeout_seconds: 3600,
    ...over,
  }
}

// --- fake Telegram + route plumbing (as in approval-buttons-e2e.test.ts) -----------------

type TgCall = { url: string; rawBody: string; body: { chat_id: string; text: string; reply_markup?: any; parse_mode?: string } }
let tgCalls: TgCall[] = []
let nextMessageId = 7000

const fakeTelegram = vi.fn(async (url: string, init: { body: string }) => {
  tgCalls.push({ url, rawBody: init.body, body: JSON.parse(init.body) })
  const messageId = nextMessageId++
  return { ok: true, status: 200, text: async () => '', json: async () => ({ ok: true, result: { message_id: messageId } }) }
})

function fakeReq(raw: string) {
  return {
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(Buffer.from(raw))
      if (event === 'end') cb()
    },
  }
}

async function route(method: string, path: string, raw: string): Promise<{ status: number; raw: string; body: any }> {
  const out = { status: 0, raw: '', body: null as any }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) { out.raw = chunk; out.body = JSON.parse(chunk) } },
  }
  const url = new URL(`http://localhost:3420${path}`)
  // v1.45.0 (kanban 80d0e3c6): the legacy PATCH approve takes an owner credential, so the PATCH
  // cases here (which test the credit_gate_* rules behind it) run as the dashboard owner's session.
  // The button route (POST .../telegram) is not behind that rule and carries no credential.
  const auth = method === 'PATCH' ? { kind: 'session', user: 'owner' } : undefined
  expect(await tryHandleApprovals({ req: fakeReq(raw), res, path, method, url, auth } as unknown as RouteContext)).toBe(true)
  return out
}

type Bridged = { body: any; status: number; response: any }
let bridged: Bridged[] = []

const bridgeFetch = vi.fn(async (input: unknown, init?: RequestInit) => {
  const u = new URL(String(input))
  expect(u.origin).toBe('http://127.0.0.1:3420')
  expect(u.pathname).toMatch(/^\/api\/approvals\/[0-9a-f-]{36}\/telegram$/)
  const raw = String(init?.body)
  const out = await route('POST', u.pathname, raw)
  bridged.push({ body: JSON.parse(raw), status: out.status, response: out.body })
  return new Response(out.raw, { status: out.status, headers: { 'content-type': 'application/json' } })
})

function pluginDeps(allowFrom: string[] = [OWNER, STRANGER]): MarveenApvDeps {
  const files: Record<string, string> = {
    [`${PROJECT_ROOT}/store/.dashboard-token`]: `${DASHBOARD_TOKEN}\n`,
    [`${PROJECT_ROOT}/.env`]: 'WEB_PORT=3420\n',
  }
  return {
    stateDir: INSTALL_STATE_DIR,
    readFileSync: (p: string) => {
      const v = files[p]
      if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    fetch: bridgeFetch as unknown as typeof fetch,
    loadAccess: () => ({ allowFrom }),
    env: {},
    envAtLoad: {},
  }
}

type Shown = {
  messageId: number
  text: string
  keyboard: { inline_keyboard: { text: string; callback_data: string }[][] } | null
  answers: (string | undefined)[]
}

function pressCtx(shown: Shown, o: { fromId?: string; chatId?: string; chatType?: string } = {}): MarveenApvCtx {
  return {
    from: { id: Number(o.fromId ?? OWNER) },
    callbackQuery: {
      message: {
        message_id: shown.messageId,
        chat: { id: Number(o.chatId ?? o.fromId ?? OWNER), type: o.chatType ?? 'private' },
        text: shown.text,
      },
    },
    answerCallbackQuery: async (other?: { text?: string }) => { shown.answers.push(other?.text) },
    editMessageText: async (text: string, other?: { reply_markup?: any }) => {
      shown.text = text
      shown.keyboard = other?.reply_markup ?? null
    },
    editMessageReplyMarkup: async (other?: { reply_markup?: any }) => {
      shown.keyboard = other?.reply_markup?.inline_keyboard?.length ? other.reply_markup : null
    },
  }
}

// Press a button of the message; `data` replays a callback the message no longer shows.
async function press(shown: Shown, which: 'approve' | 'reject', o: Parameters<typeof pressCtx>[1] & { data?: string } = {}) {
  const data = o.data ?? shown.keyboard?.inline_keyboard[0]?.[which === 'approve' ? 0 : 1]?.callback_data
  if (!data) throw new Error('no button to press')
  await marveenApprovalCallback(pressCtx(shown, o), data, pluginDeps())
  return shown.answers[shown.answers.length - 1]
}

async function request(category: Cat, payload: Record<string, unknown> = PAYLOADS[category]()) {
  const body = createBody(category, payload)
  const created = await route('POST', '/api/approvals', JSON.stringify(body))
  expect(created.status).toBe(201)
  const id = created.body.id as string
  await ownerNotificationsSettled()
  expect(tgCalls).toHaveLength(1)
  const call = tgCalls[0]!
  expect(call.body.reply_markup).toBeTruthy()
  const row = getApproval(id)!
  expect(row.telegram_message_id).toBeGreaterThan(0)
  const shown: Shown = { messageId: row.telegram_message_id!, text: call.body.text, keyboard: call.body.reply_markup, answers: [] }
  return { id, body, shown, call }
}

const rowCount = () => (getDb().prepare('SELECT COUNT(*) AS n FROM approvals').get() as { n: number }).n

// The gate's own event row the incident-clear payloads name (#42), as N2a writes
// an INCIDENT transition, and one that is no INCIDENT (#44).
const INCIDENT_AT_MS = Date.UTC(2026, 9, 15, 6, 30, 0)
function seedGateEvents(): void {
  applyGateSchema(getDb())
  getDb().exec('DELETE FROM credit_gate_events')
  const ins = getDb().prepare('INSERT INTO credit_gate_events (id, at, kind, from_state, to_state, reason) VALUES (?, ?, ?, ?, ?, ?)')
  ins.run(42, INCIDENT_AT_MS, 'transition', 'CLOSED', 'INCIDENT', 'credit_balance_too_low')
  ins.run(44, INCIDENT_AT_MS + 1000, 'transition', 'OPEN', 'CLOSED', 'threshold')
}

// The press must leave the row rejected by the system, and tell the installed
// plugin so in a form it already knows (already_resolved + outcome_text).
const CHANGED_OUTCOME = '❌ A kérés tartalma megváltozott, elutasítva.'
function expectClosedAsChanged(id: string): void {
  expect(bridged.at(-1)!.status).toBe(409)
  expect(bridged.at(-1)!.response).toEqual({ ok: false, reason: 'already_resolved', status: 'rejected', outcome_text: CHANGED_OUTCOME })
  const row = getApproval(id)!
  expect(row.status).toBe('rejected')
  expect(row.resolved_by).toBe('system:payload_mismatch')
  expect(isOwnerVerified(id)).toBe(false)
}

let logged: unknown[][] = []

beforeEach(() => {
  initDatabase(join(scratch, 'store', 'claudeclaw.db'))
  getDb().exec('DELETE FROM approval_events; DELETE FROM approvals; DELETE FROM agent_messages')
  if (getDb().prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'approval_owner_resolutions'").get()) {
    getDb().exec('DELETE FROM approval_owner_resolutions')
  }
  seedGateEvents()
  state.token = BOT_TOKEN
  state.allowedChatId = OWNER
  state.stateDir = INSTALL_STATE_DIR
  state.channelToken = CHANNEL_TOKEN
  tgCalls = []
  bridged = []
  nextMessageId = 7000
  fakeTelegram.mockClear()
  bridgeFetch.mockClear()
  vi.stubGlobal('fetch', fakeTelegram)
  setOwnerNotificationSleep(async () => {})
  logged = []
  for (const level of ['info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { logged.push([level, ...args]) }) as never)
  }
})

afterEach(async () => {
  await ownerNotificationsSettled()
  // No nonce of any button message in a log line or an API answer.
  for (const c of tgCalls.filter((t) => t.body.reply_markup)) {
    for (const button of c.body.reply_markup.inline_keyboard[0]) {
      const nonce = parseCallbackData(button.callback_data)!.nonce
      expect(JSON.stringify(logged)).not.toContain(nonce)
      for (const b of bridged) expect(JSON.stringify(b.response)).not.toContain(nonce)
    }
  }
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

// --- the owner's button decides, and only the owner's ------------------------------------

describe('credit_gate_* approvals on the owner button path (N2b)', () => {
  it.each(CATS)('%s: the owner\'s approve button decides it, resolved_by owner:telegram:<owner>', async (category) => {
    const { id, shown, call } = await request(category)
    expect(call.body.chat_id).toBe(OWNER)
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    expect(bridged).toHaveLength(1)
    expect(bridged[0]!.status).toBe(200)
    const row = getApproval(id)!
    expect(row.status).toBe('approved')
    expect(row.resolved_by).toBe(`owner:telegram:${OWNER}`)
    expect(row.category).toBe(category)
    // The payload stays: the gate (N2c) re-hashes it when it consumes the approval.
    expect(row.action_payload).toBe(createBody(category, PAYLOADS[category]()).action_payload)
    expect(row.consumed_at).toBeNull()
    // The buttons are gone, and the outcome line is the credit gate's, not the letter's.
    expect(shown.keyboard).toBeNull()
    expect(shown.text).toMatch(/\n\n✅ Jóváhagyva: .+ \(Budapest\)\. A kredit-kapu dolgozza fel, egyszer\.$/)
    expect(shown.text).not.toContain('levél')
  })

  it.each(CATS)('%s: the owner\'s reject button rejects it, resolved_by owner:telegram:<owner>', async (category) => {
    const { id, shown } = await request(category)
    expect(await press(shown, 'reject')).toBe(MARVEEN_APV_TOAST.rejected)
    const row = getApproval(id)!
    expect(row.status).toBe('rejected')
    expect(row.resolved_by).toBe(`owner:telegram:${OWNER}`)
    expect(shown.text).toMatch(/\n\n❌ Elutasítva: .+ \(Budapest\)\.$/)
  })

  it.each(CATS)('%s: a stranger\'s press is refused with 403 and decides nothing', async (category) => {
    const { id, shown } = await request(category)
    expect(await press(shown, 'approve', { fromId: STRANGER })).toBe(MARVEEN_APV_TOAST.forbidden)
    expect(bridged.at(-1)!.status).toBe(403)
    expect(bridged.at(-1)!.response).toEqual({ ok: false, reason: 'not_owner' })
    expect(getApproval(id)!.status).toBe('pending')
    // The buttons stay for the owner, who can still decide.
    expect(shown.keyboard).not.toBeNull()
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    expect(getApproval(id)!.resolved_by).toBe(`owner:telegram:${OWNER}`)
  })

  it('the owner\'s press from a group chat decides nothing: the plugin refuses it, and so does the server (chat_mismatch)', async () => {
    const { id, shown } = await request('credit_gate_calibration')
    expect(await press(shown, 'approve', { chatId: '-1001234567890', chatType: 'supergroup' })).toBe(MARVEEN_APV_TOAST.forbidden)
    expect(bridged).toHaveLength(0)
    // The same callback posted straight to the endpoint, as from the group chat.
    const nonce = parseCallbackData(shown.keyboard!.inline_keyboard[0]![0]!.callback_data)!.nonce
    const direct = await route('POST', `/api/approvals/${id}/telegram`, JSON.stringify({
      status: 'approved', resolved_by: `owner:telegram:${OWNER}`, telegram_message_id: shown.messageId,
      telegram_chat_id: '-1001234567890', telegram_chat_type: 'supergroup', callback_nonce: nonce, callback_protocol: 1,
    }))
    expect(direct.status).toBe(403)
    expect(direct.body).toEqual({ ok: false, reason: 'chat_mismatch' })
    expect(getApproval(id)!.status).toBe('pending')
  })

  it.each(CATS)('%s: a repeated press (the same callback again) is refused, the first decision stands', async (category) => {
    const { id, shown } = await request(category)
    const approveData = shown.keyboard!.inline_keyboard[0]![0]!.callback_data
    const rejectData = shown.keyboard!.inline_keyboard[0]![1]!.callback_data
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    const first = getApproval(id)!
    // The same approve callback again, and the reject callback after it.
    expect(await press(shown, 'approve', { data: approveData })).toBe(MARVEEN_APV_TOAST.alreadyResolved)
    expect(await press(shown, 'reject', { data: rejectData })).toBe(MARVEEN_APV_TOAST.alreadyResolved)
    for (const b of bridged.slice(1)) {
      expect(b.status).toBe(409)
      expect(b.response.reason).toBe('already_resolved')
      expect(b.response.outcome_text).not.toContain('levél')
    }
    expect(getApproval(id)).toEqual(first)
  })

  it('the approve nonce of one request decides no other request (BE-3b P6)', async () => {
    const a = await request('credit_gate_calibration')
    tgCalls = []
    const b = await request('credit_gate_calibration')
    const nonceA = parseCallbackData(a.shown.keyboard!.inline_keyboard[0]![0]!.callback_data)!.nonce
    const cross = await route('POST', `/api/approvals/${b.id}/telegram`, JSON.stringify({
      status: 'approved', resolved_by: `owner:telegram:${OWNER}`, telegram_message_id: b.shown.messageId,
      telegram_chat_id: OWNER, telegram_chat_type: 'private', callback_nonce: nonceA, callback_protocol: 1,
    }))
    expect(cross.status).toBe(403)
    expect(cross.body).toEqual({ ok: false, reason: 'bad_nonce' })
    expect(getApproval(b.id)!.status).toBe('pending')
    expect(getApproval(a.id)!.status).toBe('pending')
  })

  it.each(CATS)('%s: an expired request cannot be decided by its button', async (category) => {
    const { id, shown } = await request(category)
    getDb().prepare('UPDATE approvals SET timeout_at = ? WHERE id = ?').run(Math.floor(Date.now() / 1000) - 1, id)
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.expired)
    expect(bridged.at(-1)!.status).toBe(409)
    expect(bridged.at(-1)!.response.reason).toBe('expired')
    expect(getApproval(id)!.status).toBe('pending')
    expect(getApproval(id)!.resolved_by).toBeNull()
  })
})

// --- the payload is bound: no row without it, no decision when it changed ------------------

describe('credit_gate_* payload binding (N2b)', () => {
  const badCreates: Array<[string, () => Record<string, unknown>]> = [
    ['no payload', () => { const b: Record<string, unknown> = createBody('credit_gate_calibration', calibration()); delete b.action_payload; return b }],
    ['no content_hash', () => { const b: Record<string, unknown> = createBody('credit_gate_calibration', calibration()); delete b.content_hash; return b }],
    ['a content_hash of another payload', () => createBody('credit_gate_calibration', calibration(), { content_hash: sha(canon(calibration({ captured_at_lb: '2026-10-15T08:00:01Z' }))) })],
    ['a non-canonical payload (whitespace)', () => {
      const text = JSON.stringify(calibration(), null, 1)
      return createBody('credit_gate_calibration', calibration(), { action_payload: text, content_hash: sha(text) })
    }],
    ['a non-canonical payload (key order)', () => {
      const text = JSON.stringify(calibration())
      return createBody('credit_gate_calibration', calibration(), { action_payload: text, content_hash: sha(text) })
    }],
    ['a duplicated key', () => {
      const text = canon(incidentClear()).replace('"incident_event_id":42', '"incident_event_id":7,"incident_event_id":42')
      return createBody('credit_gate_incident_clear', incidentClear(), { action_payload: text, content_hash: sha(text) })
    }],
    ['"10.0" instead of "10.00"', () => createBody('credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.0' } } }))],
    ['a number instead of a decimal string', () => createBody('credit_gate_canary', canary({ budget_usd: 0.9 }))],
    ['an extra key', () => createBody('credit_gate_canary', canary({ note: 'free text' }))],
    ['a missing key', () => { const p = canary(); delete p.before_calibration_id; return createBody('credit_gate_canary', p) }],
    ['the payload of another category', () => createBody('credit_gate_canary', calibration())],
    ['kind and category disagree', () => createBody('credit_gate_incident_clear', incidentClear({ kind: 'credit_gate_canary' }))],
    ['v other than 1', () => createBody('credit_gate_incident_clear', incidentClear({ v: 2 }))],
    ['a canary budget of 1.00 USD', () => createBody('credit_gate_canary', canary({ budget_usd: '1.00' }))],
    ['an incident id of 0', () => createBody('credit_gate_incident_clear', incidentClear({ incident_event_id: 0 }))],
    ['an unknown credit_gate_ category', () => createBody('credit_gate_open', incidentClear())],
    ['a look-alike of the reserved prefix in another case', () => createBody('Credit_Gate_Calibration', calibration())],
    ['a requester that is not a bare agent id', () => createBody('credit_gate_incident_clear', incidentClear(), { agent_id: 'Brainy (Gyuri jóváhagyta)' })],
    ['an incident id the gate has no event for', () => createBody('credit_gate_incident_clear', incidentClear({ incident_event_id: 43 }))],
    ['an incident id of an event that is no INCIDENT', () => createBody('credit_gate_incident_clear', incidentClear({ incident_event_id: 44 }))],
    ['a screenshot path in NFD', () => createBody('credit_gate_calibration', calibration({ screenshot: '/Users/x/Képernyőkép.png'.normalize('NFD') }))],
    ['a screenshot path with a no-break space', () => createBody('credit_gate_calibration', calibration({ screenshot: '/Users/x/a\u00A0b.png' }))],
    ['a screenshot path with a trailing space', () => createBody('credit_gate_calibration', calibration({ screenshot: '/Users/x/a.png ' }))],
  ]

  it.each(badCreates)('the create is refused with 400, no row and no Telegram message: %s', async (_name, build) => {
    const body = build()
    const created = await route('POST', '/api/approvals', JSON.stringify(body))
    expect(created.status).toBe(400)
    expect(typeof created.body.error).toBe('string')
    // The answer names what is wrong, never the payload itself.
    if (typeof body.action_payload === 'string') expect(created.raw).not.toContain(body.action_payload)
    await ownerNotificationsSettled()
    expect(rowCount()).toBe(0)
    expect(tgCalls).toHaveLength(0)
  })

  it.each(CATS)('%s: a payload changed after the create closes the request at the press (rejected by the system, the plugin is told)', async (category) => {
    const { id, shown } = await request(category)
    const original = getApproval(id)!.action_payload!
    // A canonical, otherwise valid payload with one number changed: only the hash can tell.
    const forged = category === 'credit_gate_calibration' ? canon(calibration({ grants: [{ granted: '2026-10-10', expires: '2026-10-17', original_usd: '200.00', remaining_usd: '199.64' }] }))
      : category === 'credit_gate_canary' ? canon(canary({ budget_usd: '0.99' }))
        : canon(incidentClear({ incident_event_id: 43 }))
    expect(forged).not.toBe(original)
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(forged, id)
    // The installed plugin settles the message with the server's line and takes the buttons off.
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.alreadyResolved)
    expectClosedAsChanged(id)
    expect(shown.keyboard).toBeNull()
    expect(shown.text.endsWith(`\n\n${CHANGED_OUTCOME}`)).toBe(true)
    // The dashboard cannot approve it afterwards, and a second press says the same.
    const patch = await route('PATCH', `/api/approvals/${id}`, JSON.stringify({ status: 'approved', resolved_by: 'dashboard' }))
    expect(patch.status).toBe(409)
    expect(getApproval(id)!.status).toBe('rejected')
    const nonce = parseCallbackData(tgCalls[0]!.body.reply_markup.inline_keyboard[0][0].callback_data)!.nonce
    const again = await route('POST', `/api/approvals/${id}/telegram`, JSON.stringify({
      status: 'approved', resolved_by: `owner:telegram:${OWNER}`, telegram_message_id: shown.messageId,
      telegram_chat_id: OWNER, telegram_chat_type: 'private', callback_nonce: nonce, callback_protocol: 1,
    }))
    expect(again.status).toBe(409)
    expect(again.body).toEqual({ ok: false, reason: 'already_resolved', status: 'rejected', outcome_text: CHANGED_OUTCOME })
  })

  it('a content_hash changed after the create closes the request too', async () => {
    const { id, shown } = await request('credit_gate_canary')
    getDb().prepare('UPDATE approvals SET content_hash = ? WHERE id = ?').run('0'.repeat(64), id)
    await press(shown, 'approve')
    expectClosedAsChanged(id)
  })

  it('a payload broken after the create (not JSON) closes the request, by either button', async () => {
    const { id, shown } = await request('credit_gate_incident_clear')
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run('{"v":1', id)
    await press(shown, 'reject')
    expectClosedAsChanged(id)
  })

  it('the DB decision itself checks the binding (a direct call closes the row the same way)', async () => {
    const { id, shown } = await request('credit_gate_incident_clear')
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(canon(incidentClear({ incident_event_id: 9 })), id)
    const nonce = parseCallbackData(shown.keyboard!.inline_keyboard[0]![0]!.callback_data)!.nonce
    const r = resolveApprovalFromTelegram({ id, status: 'approved', ownerId: OWNER, messageId: shown.messageId, nonceHash: sha(nonce) })
    expect(r).toMatchObject({ ok: false, reason: 'payload_mismatch' })
    expect(getApproval(id)).toMatchObject({ status: 'rejected', resolved_by: 'system:payload_mismatch' })
    expect(isOwnerVerified(id)).toBe(false)
  })

  it('an expired request with a changed payload is just expired (no system decision before the sweeper)', async () => {
    const { id, shown } = await request('credit_gate_canary')
    getDb().prepare('UPDATE approvals SET action_payload = ?, timeout_at = ? WHERE id = ?').run(canon(canary({ budget_usd: '0.99' })), Math.floor(Date.now() / 1000) - 1, id)
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.expired)
    expect(getApproval(id)).toMatchObject({ status: 'pending', resolved_by: null })
  })

  it.each(CATS)('%s: payload AND hash rewritten together (BE-3b P1): the button no longer matches, nothing is approved', async (category) => {
    const { id, shown } = await request(category)
    const original = getApproval(id)!
    const forged = category === 'credit_gate_calibration'
      ? canon(calibration({ grants: [grant200('2026-10-10', '2026-10-17'), grant200('2026-10-14', '2026-11-17')] }))
      : category === 'credit_gate_canary' ? canon(canary({ budget_usd: '0.99' }))
        : canon(incidentClear({ incident_event_id: 44 }))
    getDb().prepare('UPDATE approvals SET action_payload = ?, content_hash = ? WHERE id = ?').run(forged, sha(forged), id)
    for (const which of ['approve', 'reject'] as const) {
      expect(await press(shown, which)).toBe(MARVEEN_APV_TOAST.invalid)
      expect(bridged.at(-1)!.status).toBe(403)
      expect(bridged.at(-1)!.response).toEqual({ ok: false, reason: 'bad_nonce' })
    }
    expect(getApproval(id)).toMatchObject({ status: 'pending', resolved_by: null })
    expect(isOwnerVerified(id)).toBe(false)
    // Put back what the owner saw: the same button works again, so the binding is to the content.
    getDb().prepare('UPDATE approvals SET action_payload = ?, content_hash = ? WHERE id = ?').run(original.action_payload, original.content_hash, id)
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    expect(isOwnerVerified(id)).toBe(true)
  })
})

// --- the owner-verified trace (BE-3b MED-1) ---------------------------------------------------

describe('isOwnerVerified: only the owner\'s button press leaves the trace (N2b, BE-3b MED-1)', () => {
  it.each(CATS)('%s: true after the owner\'s approve button, for that owner only', async (category) => {
    const { id, shown } = await request(category)
    expect(isOwnerVerified(id)).toBe(false)
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    expect(isOwnerVerified(id)).toBe(true)
    expect(isOwnerVerified(id, OWNER)).toBe(true)
    expect(isOwnerVerified(id, STRANGER)).toBe(false)
    const trace = getDb().prepare('SELECT owner_id, status, content_hash, resolved_at FROM approval_owner_resolutions WHERE approval_id = ?').get(id)
    const row = getApproval(id)!
    expect(trace).toEqual({ owner_id: OWNER, status: 'approved', content_hash: row.content_hash, resolved_at: row.resolved_at })
  })

  it('false after the owner\'s reject button', async () => {
    const { id, shown } = await request('credit_gate_calibration')
    expect(await press(shown, 'reject')).toBe(MARVEEN_APV_TOAST.rejected)
    expect(isOwnerVerified(id)).toBe(false)
  })

  it('false after the legacy PATCH, whatever it claims', async () => {
    const { id } = await request('credit_gate_canary')
    const r = await route('PATCH', `/api/approvals/${id}`, JSON.stringify({ status: 'approved', resolved_by: 'dashboard' }))
    expect(r.status).toBe(200)
    expect(isOwnerVerified(id)).toBe(false)
  })

  it('resolveApproval (every legacy caller) refuses the owner:telegram: attribution in any spelling (BE-3b P2)', async () => {
    const { id } = await request('credit_gate_incident_clear')
    for (const forged of [`owner:telegram:${OWNER}`, ` Owner:Telegram:${OWNER}`, `OWNER : TELEGRAM : ${OWNER}`,
      `owner\uFF1Atelegram\uFF1A${OWNER}`, `owner:\u200Btelegram:${OWNER}`, 'owner:telegram:']) {
      expect(resolveApproval(id, 'approved', forged)).toBe(false)
      expect(getApproval(id)).toMatchObject({ status: 'pending', resolved_by: null })
    }
    expect(isOwnerVerified(id)).toBe(false)
    expect(resolveApproval(id, 'approved', 'dashboard')).toBe(true)
    expect(isOwnerVerified(id)).toBe(false)
  })

  it('a row approved as owner:telegram: before the trace existed (pre-migration) is never verified, and the button says so', async () => {
    const { id, shown } = await request('credit_gate_calibration')
    getDb().prepare("UPDATE approvals SET status = 'approved', resolved_by = ?, resolved_at = ? WHERE id = ?")
      .run(`owner:telegram:${OWNER}`, Math.floor(Date.now() / 1000), id)
    expect(isOwnerVerified(id)).toBe(false)
    expect(isOwnerVerified(id, OWNER)).toBe(false)
    await press(shown, 'approve')
    expect(bridged.at(-1)!.response.outcome_text).toMatch(/^Már eldöntve, nem gombbal: ✅ Jóváhagyva: .+ A kredit-kapu a nem gombos jóváhagyást nem fogadja el\.$/)
  })

  it('a verified approval whose content changes afterwards is no longer verified', async () => {
    const a = await request('credit_gate_canary')
    expect(await press(a.shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    expect(isOwnerVerified(a.id)).toBe(true)
    const forged = canon(canary({ budget_usd: '0.99' }))
    getDb().prepare('UPDATE approvals SET action_payload = ?, content_hash = ? WHERE id = ?').run(forged, sha(forged), a.id)
    expect(isOwnerVerified(a.id)).toBe(false)
    tgCalls = []
    const b = await request('credit_gate_incident_clear')
    expect(await press(b.shown, 'approve')).toBe(MARVEEN_APV_TOAST.approved)
    getDb().prepare('UPDATE approvals SET action_payload = ? WHERE id = ?').run(canon(incidentClear({ incident_event_id: 44 })), b.id)
    expect(isOwnerVerified(b.id)).toBe(false)
  })

  it('no route and no module but db.ts names the trace table (it is not writable over the API)', () => {
    const root = join(PROJECT_ROOT, 'src')
    const offenders: string[] = []
    const walk = (dir: string): void => {
      for (const name of readdirSync(dir)) {
        const p = join(dir, name)
        if (name === '__tests__' || name === 'node_modules') continue
        if (statSync(p).isDirectory()) walk(p)
        else if (/\.(ts|mjs|js)$/.test(name) && p !== join(root, 'db.ts') && readFileSync(p, 'utf-8').includes('approval_owner_resolutions')) offenders.push(p)
      }
    }
    walk(root)
    expect(offenders).toEqual([])
    const db = readFileSync(join(root, 'db.ts'), 'utf-8')
    expect(db.match(/INSERT INTO approval_owner_resolutions/g)).toHaveLength(1)
  })
})

// --- the legacy PATCH ----------------------------------------------------------------------

describe('the legacy PATCH on credit_gate_* approvals (N2b)', () => {
  it.each(CATS)('%s: it can decide, but never as owner:telegram: (the gate refuses it in N2c)', async (category) => {
    const { id, shown } = await request(category)
    for (const forged of [`owner:telegram:${OWNER}`, ` Owner:Telegram:${OWNER}`, `OWNER : TELEGRAM : ${OWNER}`, 'owner:telegram:']) {
      const r = await route('PATCH', `/api/approvals/${id}`, JSON.stringify({ status: 'approved', resolved_by: forged }))
      expect(r.status).toBe(400)
      expect(getApproval(id)!.status).toBe('pending')
    }
    const r = await route('PATCH', `/api/approvals/${id}`, JSON.stringify({ status: 'approved', resolved_by: 'dashboard' }))
    expect(r.status).toBe(200)
    const row = getApproval(id)!
    expect(row.status).toBe('approved')
    expect(row.resolved_by).toBe('dashboard')
    expect(row.resolved_by!.replace(/\s/g, '').toLowerCase().startsWith('owner:telegram:')).toBe(false)
    // The owner's button afterwards changes nothing, and says it was not a button decision.
    expect(await press(shown, 'approve')).toBe(MARVEEN_APV_TOAST.alreadyResolved)
    expect(bridged.at(-1)!.response.outcome_text).toMatch(/^Már eldöntve, nem gombbal: ✅ Jóváhagyva: /)
    expect(getApproval(id)!.resolved_by).toBe('dashboard')
  })
})

// --- what the owner sees ---------------------------------------------------------------

describe('the owner\'s Telegram message of a credit_gate_* approval (N2b)', () => {
  it('calibration: every reading, the short id and the hash prefix, as plain text, nothing else from the requester', async () => {
    const { id, body, call } = await request('credit_gate_calibration')
    const text = call.body.text
    expect(call.body.parse_mode).toBeUndefined()
    expect(text).not.toContain(FREE_TEXT)
    expect(text.startsWith(`${TEST_RUN_PREFIX}[JÓVÁHAGYÁS KELL] brainy | credit_gate_calibration\n`)).toBe(true)
    for (const line of [
      'Kredit-kapu: Console-leolvasás (kalibráció) jóváhagyása',
      `Kérés: ${id.slice(0, 8)}, tartalom-hash: ${body.content_hash.slice(0, 16)}`,
      'A képernyőkép legkorábbi ideje: 2026-10-15T08:00:00Z (Budapest: ',
      'Team-grantok (2 db):',
      '1. jóváírva 2026-10-10, lejár 2026-10-17: maradék 195.64 USD / eredeti 200.00 USD',
      '2. jóváírva 2026-10-14, lejár 2026-11-17: maradék 200.00 USD / eredeti 200.00 USD',
      'Védett R: maradék 3.63 USD, lejár 2027-01-31',
      'Védett V: maradék 10.00 USD',
      // Plain text: the markdown/HTML characters of the path arrive as they are.
      'Képernyőkép: /Volumes/8T/00 CLOUD/console/2026-10-15_*bold*_[x]<b>.png',
      'Jóváhagyás után a kredit-kapu dolgozza fel, egyszer.',
    ]) {
      expect(text).toContain(line)
    }
  })

  it('canary: model, ceiling, expected minimum, the full config hash and the before-calibration', async () => {
    const { id, body, call } = await request('credit_gate_canary')
    const text = call.body.text
    expect(call.body.parse_mode).toBeUndefined()
    expect(text).not.toContain(FREE_TEXT)
    for (const line of [
      '[JÓVÁHAGYÁS KELL] brainy | credit_gate_canary',
      'Kredit-kapu: kanári-futás jóváhagyása',
      `Kérés: ${id.slice(0, 8)}, tartalom-hash: ${body.content_hash.slice(0, 16)}`,
      'Modell: claude-sonnet-5-5',
      'Költségplafon: 0.90 USD',
      'Várt minimum költés: 0.10 USD',
      `Futtató-konfiguráció (hash): ${'c0ffee'.padEnd(64, '7')}`,
      `Előtte-kalibráció (jóváhagyás-azonosító): ${CAL_ID}`,
    ]) {
      expect(text).toContain(line)
    }
  })

  it('incident clear: the event id, and the INCIDENT\'s reason and time from the gate\'s own event row', async () => {
    const { call } = await request('credit_gate_incident_clear')
    const text = call.body.text
    expect(text).not.toContain(FREE_TEXT)
    expect(text).toContain('Kredit-kapu: INCIDENT feloldása')
    expect(text).toContain('\nINCIDENT esemény: #42\n')
    expect(text).toContain('\nAz INCIDENT oka: credit_balance_too_low\n')
    expect(text).toMatch(/\nAz INCIDENT kezdete: 2026-10-15T06:30:00Z \(Budapest: 2026\. 10\. 15\. 8:30:00\)\n/)
  })

  it('incident clear whose event row is gone by the notification: no buttons', async () => {
    const created = await route('POST', '/api/approvals', JSON.stringify(createBody('credit_gate_incident_clear', incidentClear())))
    expect(created.status).toBe(201)
    getDb().exec('DELETE FROM credit_gate_events WHERE id = 42')
    await ownerNotificationsSettled()
    expect(tgCalls).toHaveLength(1)
    expect(tgCalls[0]!.body.reply_markup).toBeUndefined()
    expect(logged.some((l) => l[0] === 'warn' && JSON.stringify(l).includes('incident_unknown'))).toBe(true)
  })

  it('a create while the gate has no event table at all is refused for incident clear', async () => {
    getDb().exec('DROP TABLE credit_gate_events')
    const created = await route('POST', '/api/approvals', JSON.stringify(createBody('credit_gate_incident_clear', incidentClear())))
    expect(created.status).toBe(400)
    expect(created.body.field).toBe('incident_event_id')
    expect(rowCount()).toBe(0)
  })

  it('a Hungarian screenshot path is shown, and its non-ASCII letters are flagged escaped', async () => {
    const path = '/Volumes/8T/00 CLOUD/Képernyőkép ŐŰ.png'
    const { call } = await request('credit_gate_calibration', calibration({ screenshot: path }))
    expect(call.body.text).toContain(`\nKépernyőkép: ${path}\n`)
    expect(call.body.text).toContain('\nFIGYELEM: nem-ASCII karakter az útvonalban: /Volumes/8T/00 CLOUD/K<U+00E9>perny<U+0151>k<U+00E9>p <U+0150><U+0170>.png\n')
  })

  it('no buttons (another bot polls the channel): the plain notice has no payload and no free text, and says why', async () => {
    state.channelToken = OTHER_BOT_TOKEN
    const created = await route('POST', '/api/approvals', JSON.stringify(createBody('credit_gate_calibration', calibration())))
    expect(created.status).toBe(201)
    await ownerNotificationsSettled()
    expect(tgCalls).toHaveLength(1)
    const call = tgCalls[0]!
    expect(call.body.reply_markup).toBeUndefined()
    expect(call.body.text).not.toContain(FREE_TEXT)
    expect(call.body.text).not.toContain('195.64')
    expect(call.body.text).toContain(`Kredit-kapu jóváhagyás (id: ${created.body.id}).`)
    expect(call.body.text).toContain('a kredit-kapu csak a Telegram-gombos döntést fogadja el')
    const warn = logged.find((l) => l[0] === 'warn' && JSON.stringify(l).includes('bot_mismatch'))
    expect(warn).toBeTruthy()
    // The log line does not send anyone to the dashboard: there is no valid decision there.
    expect(String(warn![2])).toBe('credit-gate approval notification goes out WITHOUT buttons -- it cannot be decided validly; request it again once the cause is fixed')
  })

  it('another category keeps its old plain notice, free text included (unchanged)', async () => {
    const created = await route('POST', '/api/approvals', JSON.stringify({
      agent_id: 'brainy', category: 'kanban_move', action_description: FREE_TEXT, timeout_seconds: 3600,
    }))
    expect(created.status).toBe(201)
    await ownerNotificationsSettled()
    expect(tgCalls).toHaveLength(1)
    expect(tgCalls[0]!.body.reply_markup).toBeUndefined()
    expect(tgCalls[0]!.body.text).toContain(FREE_TEXT)
    expect(tgCalls[0]!.body.text).toContain('Döntés: Dashboard -> Jóváhagyások')
  })
})
