// Card 89df7a00, node N4 (paths E, F, G, H): pairing a sender onto a SUB-agent's
// bot through the dashboard is a channel credential that outlives a rotation of
// the shared token. A gated caller (a bare shared token, or a FULL device key,
// execGateApplies) therefore goes through the bearer-credential-admin switch
// (credential-admin.ts, the same one that guards device-key minting):
//   E  POST /api/agents/<sub>/channels/<p>/invites
//   F  POST /api/agents/<sub>/channels/<p>/approve
//   G  POST /api/agents/<sub>/channel-requests/<n>/approve (Slack)
//   H  POST /api/agents/<sub>/channels/<p> (setup), Brainy K1=b: only when the
//      allowFrom is missing or is not a subset of the main agent's allowFrom for
//      the same provider (unreadable main access.json = not a subset). The
//      uj-csapattag skill (a new bot wired to Gyuri's id, already on the main
//      allowlist) keeps working. Google Chat setup is always gated for a gated
//      caller (its owner / allowDomain pair is not comparable).
// E, F, G refuse before the body is read, after the 404; H refuses before the
// token probe and every write. The main agent keeps its own gate
// (MAIN_CHANNEL_ADMIN_ENABLED), which decides first (G5). The owner's session and
// a token with a live session cookie are never gated (G7). GETs and the revoking
// routes are not gated (G9).
//
// Everything runs against a throwaway install under one mkdtemp directory. No
// network: the token probe, the busy probe and the welcome message are mocked,
// and a global fetch stub fails (and is counted) if anything still tries.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'subagent-channel-gate-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  const main = path.join(root, 'main-state')
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  for (const p of ['TELEGRAM', 'SLACK', 'DISCORD', 'GOOGLECHAT', 'TEAMS']) {
    process.env[`${p}_STATE_DIR`] = path.join(main, p.toLowerCase())
  }
  delete process.env.MAIN_CHANNEL_ADMIN_ENABLED
  delete process.env.BEARER_CREDENTIAL_ADMIN_ENABLED
  return { root, project, home, main, store: path.join(project, 'store') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
  MAIN_AGENT_ID: 'mainbot',
}))

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', () => ({ logger: log, PRETTY_OPTIONS: {} }))

const probes = vi.hoisted(() => ({ validate: 0, busy: 0, welcome: 0, notify: 0 }))
vi.mock('../channel-provider.js', async (importOriginal) => {
  const a = await importOriginal<typeof import('../channel-provider.js')>()
  return {
    ...a,
    getProvider: (p: Parameters<typeof a.getProvider>[0]) => ({
      ...a.getProvider(p),
      validateToken: async () => { probes.validate++; return { ok: true, botName: 'subby_bot' } },
    }),
    checkTelegramTokenBusy: async () => { probes.busy++; return { busy: false } },
  }
})
vi.mock('../web/telegram.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/telegram.js')>()),
  sendWelcomeMessage: async () => { probes.welcome++ },
}))
vi.mock('../web/agent-process.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/agent-process.js')>()),
  isAgentRunning: () => false,
}))
vi.mock('../notify.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../notify.js')>()),
  notifySecurityEvent: async () => { probes.notify++ },
}))

const fetchStub = vi.fn(async () => { throw new Error('network is disabled in this suite') })
vi.stubGlobal('fetch', fetchStub)

const { tryHandleAgents } = await import('../web/routes/agents.js')
const { initDatabase, createDashboardUser, getDb, upsertChannelRequest, listPendingChannelRequests } = await import('../db.js')
const { createSession } = await import('../web/auth-sessions.js')
const { SESSION_COOKIE_NAME } = await import('../web/auth-gate.js')

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }

const SWITCH = 'BEARER_CREDENTIAL_ADMIN_ENABLED'
const MAIN_SWITCH = 'MAIN_CHANNEL_ADMIN_ENABLED'
const OFF_BODY = { error: `Forbidden for the shared token (${SWITCH} is off)`, code: 'bearer_credential_admin_off' }
const REFUSED = /^Credential admin refused for the shared token/
const ADMITTED = /^Credential admin by the shared token/

const MAIN_TG = join(T.main, 'telegram')
const SUB = 'subby'
const SLACKY = 'slacky'
const AGENTS = join(T.project, 'agents')
const SUB_TG = join(AGENTS, SUB, '.claude', 'channels', 'telegram')
const SLACK_DIR = join(AGENTS, SLACKY, '.claude', 'channels', 'slack')
const FUTURE = Date.now() + 3_600_000

function access(allowFrom: string[], pending: Record<string, unknown> = {}) {
  return JSON.stringify({ dmPolicy: 'allowlist', allowFrom, groups: {}, pending }, null, 2)
}

let requestId = 0

function resetInstall(lines: string[] = []): void {
  for (const d of [T.project, T.home, T.main]) rmSync(d, { recursive: true, force: true })
  mkdirSync(T.store, { recursive: true })
  mkdirSync(MAIN_TG, { recursive: true })
  mkdirSync(SUB_TG, { recursive: true })
  mkdirSync(SLACK_DIR, { recursive: true })
  mkdirSync(T.home, { recursive: true })
  writeFileSync(join(T.project, '.env'), ['MAIN_AGENT_ID=mainbot', ...lines, ''].join('\n'))
  // The main agent allows Gyuri ('111'); the sub-agent has its own owner ('222')
  // and one pending pairing code.
  writeFileSync(join(MAIN_TG, 'access.json'), access(['111']))
  writeFileSync(join(SUB_TG, 'access.json'), access(['222'], { SUBCODE: { senderId: '777', chatId: '777', createdAt: 1, expiresAt: FUTURE } }))
  writeFileSync(join(SUB_TG, 'invites.json'), JSON.stringify({ invites: { subtok: { createdAt: 1, expiresAt: FUTURE, used: false } } }))
  writeFileSync(join(AGENTS, SUB, 'agent-config.json'), JSON.stringify({ name: SUB, channelProvider: 'telegram' }))
  writeFileSync(join(SLACK_DIR, 'access.json'), JSON.stringify({ dmPolicy: 'allowlist', allowFrom: ['U1'], groups: {} }, null, 2))
  writeFileSync(join(AGENTS, SLACKY, 'agent-config.json'), JSON.stringify({ name: SLACKY, channelProvider: 'slack' }))
  initDatabase(':memory:')
  createDashboardUser('owner', 'hash')
  upsertChannelRequest(SLACKY, 'C123', 'U9')
  requestId = listPendingChannelRequests(SLACKY)[0]!.id
}

function snapshot(dir: string): Record<string, string> {
  const out: Record<string, string> = {}
  if (!existsSync(dir)) return out
  const walk = (d: string) => {
    for (const n of readdirSync(d)) {
      const p = join(d, n)
      const st = statSync(p)
      if (st.isDirectory()) { out[`${relative(T.root, p)}/`] = 'dir'; walk(p); continue }
      out[relative(T.root, p)] = `${createHash('sha256').update(readFileSync(p)).digest('hex')}:${st.mtimeMs}`
    }
  }
  walk(dir)
  return out
}
const state = () => ({ main: snapshot(T.main), agents: snapshot(AGENTS), pending: listPendingChannelRequests(SLACKY).map(r => r.id) })
const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'))

function liveSessionCookie(): string {
  const u = getDb().prepare('SELECT id FROM dashboard_users WHERE username = ?').get('owner') as { id: number }
  return `${SESSION_COOKIE_NAME}=${createSession({ userId: u.id, username: 'owner' })}`
}

async function call(method: string, path: string, body: unknown, auth: Auth, extraHeaders: Record<string, string> = {}) {
  const out: { status: number; body: any; bodyRead: boolean } = { status: 0, body: null, bodyRead: false }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { return res },
    end(chunk?: string | Buffer) { if (chunk) { try { out.body = JSON.parse(String(chunk)) } catch { out.body = String(chunk) } } },
  }
  const raw = Buffer.from(JSON.stringify(body ?? {}))
  const req: any = {
    headers: { 'x-agent-id': 'ezermester', ...extraHeaders },
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') { out.bodyRead = true; cb(raw) }
      if (event === 'end') cb()
      return req
    },
  }
  const url = new URL(`http://localhost:3420${path}`)
  const handled = await tryHandleAgents({ req, res, path: url.pathname, method, url, auth } as RouteContext, '/nonexistent-web')
  expect(handled).toBe(true)
  return { ...out, status: out.status || 200 }
}

const warns = (re: RegExp) => log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))

beforeEach(() => {
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  for (const k of Object.keys(probes) as Array<keyof typeof probes>) probes[k] = 0
  fetchStub.mockClear()
  delete process.env[SWITCH]
  delete process.env[MAIN_SWITCH]
})

afterAll(() => {
  expect(fetchStub).not.toHaveBeenCalled()
  rmSync(T.root, { recursive: true, force: true })
})

const E = ['E', 'POST', `/api/agents/${SUB}/channels/telegram/invites`, {}, 'channel.invite.create'] as const
const E_LEGACY = ['E legacy', 'POST', `/api/agents/${SUB}/telegram/invites`, {}, 'channel.invite.create'] as const
const F = ['F', 'POST', `/api/agents/${SUB}/channels/telegram/approve`, { code: 'SUBCODE' }, 'channel.pairing.approve'] as const
const F_LEGACY = ['F legacy', 'POST', `/api/agents/${SUB}/telegram/approve`, { code: 'SUBCODE' }, 'channel.pairing.approve'] as const
const gPath = () => `/api/agents/${SLACKY}/channel-requests/${requestId}/approve`
const EFG_STATIC = [E, E_LEGACY, F, F_LEGACY]

describe('E, F, G on a sub-agent: a gated caller needs the credential switch (G4, G8, L1)', () => {
  it.each([...EFG_STATIC.map(r => [...r, TOKEN] as const), ...EFG_STATIC.map(r => [`${r[0]} device`, r[1], r[2], r[3], r[4], DEVICE_FULL] as const)])(
    '%s: switch off -> 403 before the body, nothing written, one WARN',
    async (_l, method, path, body, action, auth) => {
      resetInstall()
      const before = state()
      const r = await call(method, path, body, auth)
      expect(r.status).toBe(403)
      expect(r.body).toEqual(OFF_BODY)
      expect(r.bodyRead).toBe(false)
      expect(state()).toEqual(before)
      expect(existsSync(join(SUB_TG, 'approved'))).toBe(false)
      const w = warns(REFUSED)
      expect(w).toHaveLength(1)
      expect(w[0]![0]).toMatchObject({ caller: 'ezermester', action, reason: 'switch_off' })
      expect(Number.isNaN(Date.parse(w[0]![0].at))).toBe(false)
      expect(JSON.stringify(w[0]![0])).not.toContain('SUBCODE')
      expect(log.warn).toHaveBeenCalledTimes(1)
    },
  )

  it.each([['token', TOKEN], ['device full', DEVICE_FULL]] as const)('G (%s): switch off -> 403 before the body; the request stays pending, access.json unchanged', async (_l, auth) => {
    resetInstall()
    const before = state()
    const r = await call('POST', gPath(), { allowFromAll: true }, auth)
    expect(r.status).toBe(403)
    expect(r.body).toEqual(OFF_BODY)
    expect(r.bodyRead).toBe(false)
    expect(state()).toEqual(before)
    expect(warns(REFUSED)).toHaveLength(1)
    expect(warns(REFUSED)[0]![0].action).toBe('channel.request.approve')
  })

  it.each([['true'], ['yes'], ['" 1"'], [''], ['0']])('switch value %s keeps it closed', async (v) => {
    resetInstall([`${SWITCH}=${v}`])
    expect((await call('POST', F[2], F[3], TOKEN)).status).toBe(403)
  })

  it('a process-environment value does not open it', async () => {
    resetInstall()
    process.env[SWITCH] = '1'
    expect((await call('POST', E[2], {}, TOKEN)).status).toBe(403)
  })

  it('the code-exec switch does not open it (K3: two separate switches)', async () => {
    resetInstall(['BEARER_CODE_EXEC_ADMIN_ENABLED=1'])
    expect((await call('POST', E[2], {}, TOKEN)).status).toBe(403)
  })

  it('a non-existent agent is still 404 for a gated caller (the 404 comes first)', async () => {
    resetInstall()
    expect((await call('POST', '/api/agents/nobody/channels/telegram/invites', {}, TOKEN)).status).toBe(404)
    expect((await call('POST', '/api/agents/nobody/channels/telegram/approve', { code: 'x' }, TOKEN)).status).toBe(404)
    expect((await call('POST', '/api/agents/nobody/channel-requests/1/approve', {}, TOKEN)).status).toBe(404)
    expect(warns(REFUSED)).toHaveLength(0)
  })

  it('a token with a forged session cookie is still gated', async () => {
    resetInstall()
    const r = await call('POST', F[2], F[3], TOKEN, { cookie: `${SESSION_COOKIE_NAME}=forged` })
    expect(r.status).toBe(403)
  })
})

describe('E, F, G: switch open, session, token with a live session cookie (G6, G7)', () => {
  it('switch "1": token invite, approve and channel request work as before, one admitted WARN each', async () => {
    resetInstall([`${SWITCH}=1`])
    const inv = await call('POST', E[2], {}, TOKEN)
    expect(inv.status).toBe(200)
    expect(typeof inv.body?.token).toBe('string')
    const ap = await call('POST', F[2], F[3], TOKEN)
    expect(ap.status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual(['222', '777'])
    expect(existsSync(join(SUB_TG, 'approved', '777'))).toBe(true)
    const g = await call('POST', gPath(), {}, TOKEN)
    expect(g.status).toBe(200)
    expect(readJson(join(SLACK_DIR, 'access.json')).channels.C123).toEqual({ requireMention: true, allowFrom: ['U9'] })
    expect(listPendingChannelRequests(SLACKY)).toHaveLength(0)
    const w = warns(ADMITTED)
    expect(w.map((c: any[]) => c[0].action)).toEqual(['channel.invite.create', 'channel.pairing.approve', 'channel.request.approve'])
    for (const c of w) expect(c[0]).toMatchObject({ via: 'switch', mode: 'manual' })
    expect(warns(REFUSED)).toHaveLength(0)
  })

  it('switch "1": a full device key is admitted like the token', async () => {
    resetInstall([`${SWITCH}=1`])
    expect((await call('POST', F[2], F[3], DEVICE_FULL)).status).toBe(200)
    expect(warns(ADMITTED)).toHaveLength(1)
  })

  it.each([['session', SESSION, {}], ['token + live session cookie', TOKEN, null]] as const)('%s, switch off: E, F, G as before, no WARN', async (_l, auth, headers) => {
    resetInstall()
    const h = headers ?? { cookie: liveSessionCookie() }
    expect((await call('POST', E[2], {}, auth, h)).status).toBe(200)
    expect((await call('POST', F[2], F[3], auth, h)).status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual(['222', '777'])
    expect((await call('POST', gPath(), {}, auth, h)).status).toBe(200)
    expect(log.warn).not.toHaveBeenCalled()
  })
})

describe('the main agent: its own gate decides first (G5)', () => {
  it.each([
    ['POST', '/api/agents/mainbot/channels/telegram/invites', {}],
    ['POST', '/api/agents/mainbot/channels/telegram/approve', { code: 'X' }],
    ['POST', '/api/agents/mainbot/channel-requests/1/approve', {}],
    ['POST', '/api/agents/mainbot/channels/telegram', { botToken: '1:a', allowFrom: ['999'] }],
  ])('%s %s with both switches off -> the main-channel 403, not the credential one', async (method, path, body) => {
    resetInstall()
    const before = state()
    const r = await call(method, path, body, TOKEN)
    expect(r.status).toBe(403)
    expect(String(r.body?.error)).toContain(MAIN_SWITCH)
    expect(r.body?.code).toBeUndefined()
    expect(warns(REFUSED)).toHaveLength(0)
    expect(state()).toEqual(before)
  })

  it('main switch "1": the main agent is not behind the sub-agent gate (as designed, blueprint N4)', async () => {
    resetInstall([`${MAIN_SWITCH}=1`])
    expect((await call('POST', '/api/agents/mainbot/channels/telegram/invites', {}, TOKEN)).status).toBe(200)
    expect(warns(REFUSED)).toHaveLength(0)
  })
})

describe('H, the sub-agent setup (K1=b, H1)', () => {
  const setup = (body: unknown, auth: Auth, headers: Record<string, string> = {}) =>
    call('POST', `/api/agents/${SUB}/channels/telegram`, body, auth, headers)

  it('token, allowFrom within the main allowlist (the uj-csapattag call) -> 200 as today, no WARN', async () => {
    resetInstall()
    const r = await setup({ botToken: '123:abc', allowFrom: ['111'] }, TOKEN)
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ ok: true, botName: 'subby_bot' })
    expect(readJson(join(SUB_TG, 'access.json'))).toMatchObject({ dmPolicy: 'allowlist', allowFrom: ['111'] })
    expect(readFileSync(join(SUB_TG, '.env'), 'utf8')).toBe('TELEGRAM_BOT_TOKEN=123:abc\n')
    expect(probes.validate).toBe(1)
    expect(log.warn).not.toHaveBeenCalled()
  })

  it('the uj-csapattag call through the legacy /telegram path works the same', async () => {
    resetInstall()
    expect((await call('POST', `/api/agents/${SUB}/telegram`, { botToken: '123:abc', allowFrom: ['111', '111'] }, TOKEN)).status).toBe(200)
  })

  it.each([
    ['a foreign id', { botToken: '123:abc', allowFrom: ['999'] }],
    ['one foreign id next to the owner', { botToken: '123:abc', allowFrom: ['111', '999'] }],
    ['no allowFrom (pairing mode)', { botToken: '123:abc' }],
    ['the sub-agent owner only, not on the main list', { botToken: '123:abc', allowFrom: ['222'] }],
  ])('token, %s -> 403, no probe, nothing written', async (_l, body) => {
    resetInstall()
    const before = state()
    const r = await setup(body, TOKEN)
    expect(r.status).toBe(403)
    expect(r.body).toEqual(OFF_BODY)
    expect(state()).toEqual(before)
    expect(probes).toEqual({ validate: 0, busy: 0, welcome: 0, notify: 0 })
    const w = warns(REFUSED)
    expect(w).toHaveLength(1)
    expect(w[0]![0]).toMatchObject({ action: 'channel.setup.allow_from', reason: 'switch_off' })
    expect(JSON.stringify(log.warn.mock.calls)).not.toContain('123:abc')
  })

  it.each([
    ['unparsable', '{not json'],
    ['allowFrom not an array', JSON.stringify({ allowFrom: '111' })],
    ['JSON null', 'null'],
  ])('main access.json %s -> not a subset, 403 (fail closed)', async (_l, content) => {
    resetInstall()
    writeFileSync(join(MAIN_TG, 'access.json'), content)
    expect((await setup({ botToken: '123:abc', allowFrom: ['111'] }, TOKEN)).status).toBe(403)
  })

  it('main access.json missing -> 403', async () => {
    resetInstall()
    rmSync(join(MAIN_TG, 'access.json'))
    expect((await setup({ botToken: '123:abc', allowFrom: ['111'] }, TOKEN)).status).toBe(403)
  })

  it('the subset is per provider: a main Telegram id does not admit a Discord setup', async () => {
    resetInstall()
    const r = await call('POST', `/api/agents/${SUB}/channels/discord`, { botToken: 'x', allowFrom: ['111'], channelId: '123456789012345678' }, TOKEN)
    expect(r.status).toBe(403)
  })

  it('device full: subset passes, a foreign id is gated', async () => {
    resetInstall()
    expect((await setup({ botToken: '123:abc', allowFrom: ['111'] }, DEVICE_FULL)).status).toBe(200)
    resetInstall()
    expect((await setup({ botToken: '123:abc', allowFrom: ['999'] }, DEVICE_FULL)).status).toBe(403)
  })

  it('switch "1": token with a foreign id -> 200 as today, one admitted WARN', async () => {
    resetInstall([`${SWITCH}=1`])
    const r = await setup({ botToken: '123:abc', allowFrom: ['999'] }, TOKEN)
    expect(r.status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual(['999'])
    expect(warns(ADMITTED)).toHaveLength(1)
    expect(warns(ADMITTED)[0]![0].action).toBe('channel.setup.allow_from')
  })

  it.each([['session', SESSION, {}], ['token + live session cookie', TOKEN, null]] as const)('%s with a foreign id and no allowFrom -> 200, no WARN', async (_l, auth, headers) => {
    resetInstall()
    const h = headers ?? { cookie: liveSessionCookie() }
    expect((await setup({ botToken: '123:abc', allowFrom: ['999'] }, auth, h)).status).toBe(200)
    resetInstall()
    const h2 = headers ?? { cookie: liveSessionCookie() }
    expect((await setup({ botToken: '123:abc' }, auth, h2)).status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).dmPolicy).toBe('pairing')
    expect(log.warn).not.toHaveBeenCalled()
  })

  it('Google Chat setup: a gated caller is always gated (owner not comparable); the session is not', async () => {
    const gc = { saKeyPath: '/k.json', projectId: 'p', subscription: 's', owner: 'users/1' }
    resetInstall()
    const before = state()
    const r = await call('POST', `/api/agents/${SUB}/channels/googlechat`, gc, TOKEN)
    expect(r.status).toBe(403)
    expect(r.body).toEqual(OFF_BODY)
    expect(state()).toEqual(before)
    const s = await call('POST', `/api/agents/${SUB}/channels/googlechat`, gc, SESSION)
    expect(s.status).toBe(200)
    expect(readJson(join(AGENTS, SUB, '.claude', 'channels', 'googlechat', 'access.json')).owner).toBe('users/1')
  })
})

describe('not gated: reads and revoking routes (G9)', () => {
  it('token, switch off: GET invites/allowed/requests, DELETE invite, DELETE allowed user, deny -> not 403', async () => {
    resetInstall()
    expect((await call('GET', E[2], undefined, TOKEN)).status).toBe(200)
    expect((await call('GET', `/api/agents/${SUB}/channels/telegram/allowed`, undefined, TOKEN)).status).toBe(200)
    expect((await call('GET', `/api/agents/${SLACKY}/channel-requests`, undefined, TOKEN)).status).toBe(200)
    expect((await call('DELETE', `/api/agents/${SUB}/channels/telegram/invites/subtok`, undefined, TOKEN)).status).not.toBe(403)
    const del = await call('DELETE', `/api/agents/${SUB}/channels/telegram/allowed/user/222`, undefined, TOKEN)
    expect(del.status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual([])
    expect((await call('POST', `/api/agents/${SLACKY}/channel-requests/${requestId}/deny`, {}, TOKEN)).status).not.toBe(403)
    expect(warns(REFUSED)).toHaveLength(0)
  })
})
