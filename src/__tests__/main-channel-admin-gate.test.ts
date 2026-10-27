// Card 053f4e66 (Brainy 1954): every dashboard route that writes the MAIN
// agent's channel state (access.json, pairing, invites, channel .env) is 403
// unless the install's .env has MAIN_CHANNEL_ADMIN_ENABLED=1, and the invite
// monitor does not auto-approve onto the main agent's allowlist without it.
// Sub-agents' own bots keep working exactly as before.
//
// Everything runs against a throwaway install: PROJECT_ROOT, HOME and every
// provider's main state dir live under one mkdtemp directory.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'main-channel-gate-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  const main = path.join(root, 'main-state')
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  for (const p of ['TELEGRAM', 'SLACK', 'DISCORD', 'GOOGLECHAT', 'TEAMS']) {
    process.env[`${p}_STATE_DIR`] = path.join(main, p.toLowerCase())
  }
  delete process.env.MAIN_CHANNEL_ADMIN_ENABLED
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

const { tryHandleAgents } = await import('../web/routes/agents.js')
const { runInviteMonitorTick } = await import('../web/channel-invites.js')
const { initDatabase } = await import('../db.js')

const KEY = 'MAIN_CHANNEL_ADMIN_ENABLED'
const MAIN_TG = join(T.main, 'telegram')
const SUB = 'subby'
const SUB_TG = join(T.project, 'agents', SUB, '.claude', 'channels', 'telegram')
const AGENTS_ROOT = join(T.project, 'agents')
const FUTURE = Date.now() + 3_600_000

function access(allowFrom: string[], pending: Record<string, unknown> = {}) {
  return JSON.stringify({ dmPolicy: 'allowlist', allowFrom, groups: { '-100': { requireMention: true, allowFrom: [] } }, pending }, null, 2)
}

function resetInstall(switchLine: string | null): void {
  for (const d of [T.project, T.home, T.main]) rmSync(d, { recursive: true, force: true })
  mkdirSync(T.store, { recursive: true })
  mkdirSync(MAIN_TG, { recursive: true })
  mkdirSync(SUB_TG, { recursive: true })
  mkdirSync(T.home, { recursive: true })
  writeFileSync(join(T.project, '.env'), `MAIN_AGENT_ID=mainbot\n${switchLine === null ? '' : `${switchLine}\n`}`)
  writeFileSync(join(MAIN_TG, 'access.json'), access(['111'], { MAINCODE: { senderId: '666', chatId: '666', createdAt: 1, expiresAt: FUTURE } }))
  writeFileSync(join(MAIN_TG, 'invites.json'), JSON.stringify({ invites: { maintok: { createdAt: 1, expiresAt: FUTURE, used: false } } }))
  writeFileSync(join(SUB_TG, 'access.json'), access(['222'], { SUBCODE: { senderId: '777', chatId: '777', createdAt: 1, expiresAt: FUTURE } }))
  writeFileSync(join(T.project, 'agents', SUB, 'agent-config.json'), JSON.stringify({ name: SUB }))
  initDatabase(':memory:')
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

const readJson = (p: string) => JSON.parse(readFileSync(p, 'utf8'))

async function call(method: string, path: string, body: unknown = {}, agentId?: string) {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { return res },
    end(chunk?: string | Buffer) { if (chunk) { try { out.body = JSON.parse(String(chunk)) } catch { out.body = String(chunk) } } },
  }
  const raw = Buffer.from(JSON.stringify(body))
  const headers: Record<string, string> = {}
  if (agentId) headers['x-agent-id'] = agentId
  const req: any = {
    headers,
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(raw)
      if (event === 'end') cb()
      return req
    },
  }
  const url = new URL(`http://localhost:3420${path}`)
  const handled = await tryHandleAgents({ req, res, path: url.pathname, method, url } as RouteContext, '/nonexistent-web')
  return { handled, ...out }
}

const refusals = () => log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && /channel admin refused/i.test(c[1]))
const monitorRefusals = () => log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && /auto-approval refused/i.test(c[1]))

beforeEach(() => {
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  delete process.env[KEY]
})

afterAll(() => { rmSync(T.root, { recursive: true, force: true }) })

const GATED: Array<[string, string, unknown]> = [
  ['POST', '/api/agents/mainbot/channels/telegram/invites', {}],
  ['POST', '/api/agents/mainbot/telegram/invites', {}],
  ['POST', '/api/agents/%6Dainbot/channels/telegram/invites', {}],
  ['POST', '/api/agents/mainbot/channels/slack/invites', {}],
  ['POST', '/api/agents/mainbot/channels/telegram/approve', { code: 'MAINCODE' }],
  ['POST', '/api/agents/mainbot/telegram/approve', { code: 'MAINCODE' }],
  ['DELETE', '/api/agents/mainbot/channels/telegram/invites/maintok', {}],
  ['DELETE', '/api/agents/mainbot/telegram/invites/maintok', {}],
  ['DELETE', '/api/agents/mainbot/channels/telegram/allowed/user/111', {}],
  ['DELETE', '/api/agents/mainbot/channels/telegram/allowed/group/-100', {}],
  ['DELETE', '/api/agents/mainbot/telegram/allowed/user/111', {}],
  ['POST', '/api/agents/mainbot/channels/telegram', {}],
  ['POST', '/api/agents/mainbot/telegram', {}],
  ['DELETE', '/api/agents/mainbot/channels/telegram', {}],
  ['POST', '/api/agents/mainbot/channel-requests/1/approve', {}],
]

describe('main-agent channel writes are off by default (053f4e66)', () => {
  it.each(GATED)('%s %s -> 403, a log line with caller and time, nothing written', async (method, path, body) => {
    resetInstall(null)
    const before = { main: snapshot(T.main), sub: snapshot(join(T.project, 'agents')) }
    const r = await call(method, path, body, 'ezermester')
    expect(r.handled).toBe(true)
    expect(r.status).toBe(403)
    expect(String(r.body?.error ?? '')).toContain(KEY)
    const logs = refusals()
    expect(logs).toHaveLength(1)
    expect(logs[0]![0].caller).toBe('ezermester')
    expect(Number.isNaN(Date.parse(logs[0]![0].at))).toBe(false)
    expect(snapshot(T.main)).toEqual(before.main)
    expect(snapshot(join(T.project, 'agents'))).toEqual(before.sub)
  })

  it.each([['true'], ['yes'], ['" 1"'], [''], ['on']])('switch value %s keeps it off', async (v) => {
    resetInstall(`${KEY}=${v}`)
    const before = snapshot(T.main)
    const r = await call('POST', '/api/agents/mainbot/channels/telegram/approve', { code: 'MAINCODE' })
    expect(r.status).toBe(403)
    expect(snapshot(T.main)).toEqual(before)
  })

  it('a process-environment value does not turn it on', async () => {
    resetInstall(null)
    process.env[KEY] = '1'
    const r = await call('POST', '/api/agents/mainbot/channels/telegram/invites')
    expect(r.status).toBe(403)
  })

  it('read-only main routes keep working with the switch off', async () => {
    resetInstall(null)
    const before = snapshot(T.main)
    expect((await call('GET', '/api/agents/mainbot/channels/telegram/pending')).status).toBe(200)
    expect((await call('GET', '/api/agents/mainbot/channels/telegram/allowed')).body).toMatchObject({ users: ['111'] })
    expect((await call('GET', '/api/agents/mainbot/channels/telegram/invites')).status).toBe(200)
    expect(refusals()).toHaveLength(0)
    expect(snapshot(T.main)).toEqual(before)
  })

  it('switch "1": invites and approve on the main agent work as before (positive control)', async () => {
    resetInstall(`${KEY}=1`)
    const inv = await call('POST', '/api/agents/mainbot/channels/telegram/invites')
    expect(inv.status).toBe(200)
    expect(typeof inv.body?.token).toBe('string')
    const ap = await call('POST', '/api/agents/mainbot/channels/telegram/approve', { code: 'MAINCODE' })
    expect(ap.status).toBe(200)
    expect(readJson(join(MAIN_TG, 'access.json')).allowFrom).toEqual(['111', '666'])
    expect(refusals()).toHaveLength(0)
  })
})

describe('sub-agents keep their own bot routes (053f4e66)', () => {
  it('switch off: invite and approve on a sub-agent work; its allowFrom grows, the main one does not change', async () => {
    resetInstall(null)
    const mainBefore = snapshot(T.main)
    const inv = await call('POST', `/api/agents/${SUB}/channels/telegram/invites`)
    expect(inv.status).toBe(200)
    const ap = await call('POST', `/api/agents/${SUB}/channels/telegram/approve`, { code: 'SUBCODE' })
    expect(ap.status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual(['222', '777'])
    expect(refusals()).toHaveLength(0)
    expect(snapshot(T.main)).toEqual(mainBefore)
  })

  it('switch off: removing a user from a sub-agent still works', async () => {
    resetInstall(null)
    const r = await call('DELETE', `/api/agents/${SUB}/channels/telegram/allowed/user/222`)
    expect(r.status).toBe(200)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual([])
  })
})

describe('the invite monitor and the main agent (053f4e66)', () => {
  function seedSubInvite(): void {
    writeFileSync(join(SUB_TG, 'invites.json'), JSON.stringify({ invites: { subtok: { createdAt: 1, expiresAt: FUTURE, used: false } } }))
  }

  it('switch off: the main pending code is NOT auto-approved (one WARN), the sub-agent one is', () => {
    resetInstall(null)
    seedSubInvite()
    const mainAccess = readFileSync(join(MAIN_TG, 'access.json'), 'utf8')
    const mainInvites = readFileSync(join(MAIN_TG, 'invites.json'), 'utf8')
    runInviteMonitorTick('mainbot', AGENTS_ROOT)
    runInviteMonitorTick('mainbot', AGENTS_ROOT)
    expect(readFileSync(join(MAIN_TG, 'access.json'), 'utf8')).toBe(mainAccess)
    expect(readFileSync(join(MAIN_TG, 'invites.json'), 'utf8')).toBe(mainInvites)
    expect(existsSync(join(MAIN_TG, 'approved'))).toBe(false)
    expect(monitorRefusals()).toHaveLength(1)
    expect(readJson(join(SUB_TG, 'access.json')).allowFrom).toEqual(['222', '777'])
  })

  it('switch "1": the main pending code is auto-approved as before', () => {
    resetInstall(`${KEY}=1`)
    runInviteMonitorTick('mainbot', AGENTS_ROOT)
    expect(readJson(join(MAIN_TG, 'access.json')).allowFrom).toEqual(['111', '666'])
    expect(existsSync(join(MAIN_TG, 'approved', '666'))).toBe(true)
  })

  it('a hand pairing in the /telegram:access skill style (direct file edit) stays as written', () => {
    resetInstall(null)
    // The skill: read access.json, move pending[code].senderId into allowFrom,
    // drop the pending row, write approved/<senderId>. No dashboard call.
    const a = readJson(join(MAIN_TG, 'access.json'))
    a.allowFrom.push(a.pending.MAINCODE.senderId)
    delete a.pending.MAINCODE
    writeFileSync(join(MAIN_TG, 'access.json'), JSON.stringify(a, null, 2))
    mkdirSync(join(MAIN_TG, 'approved'), { recursive: true })
    writeFileSync(join(MAIN_TG, 'approved', '666'), '666')
    runInviteMonitorTick('mainbot', AGENTS_ROOT)
    expect(readJson(join(MAIN_TG, 'access.json')).allowFrom).toEqual(['111', '666'])
    expect(existsSync(join(MAIN_TG, 'approved', '666'))).toBe(true)
  })
})

describe('mainChannelWriteAction (053f4e66)', () => {
  it('names the main-agent writes and nothing else', async () => {
    const { mainChannelWriteAction } = await import('../web/main-channel-admin.js')
    expect(mainChannelWriteAction('/api/agents/mainbot/channels/teams/invites', 'POST', 'mainbot')).toBe('invite-create')
    expect(mainChannelWriteAction('/api/agents/mainbot/channels/telegram/invites', 'GET', 'mainbot')).toBeNull()
    expect(mainChannelWriteAction('/api/agents/subby/channels/telegram/invites', 'POST', 'mainbot')).toBeNull()
    expect(mainChannelWriteAction('/api/agents/mainbot/channels/telegram/test', 'POST', 'mainbot')).toBeNull()
    expect(mainChannelWriteAction('/api/agents/%E0%A4%A/channels/telegram/invites', 'POST', 'mainbot')).toBe('invite-create')
  })
})
