// Card 24e137ef, nodes N1 + N3: the shared dashboard Bearer (bare token or a full
// device key) must not widen an agent's privileges in a way that outlives a token
// rotation. PUT /api/agents/<n>/security, PUT /api/agents/<n>/capabilities,
// POST /api/skills/<n>/assign and POST /api/fleet/import?apply=true go through the
// code-exec gate BEFORE the body is read; the session (and a token with a live
// session cookie) is never gated. An agent import never takes the bundle's
// securityProfile: an overwrite keeps the existing one, a new agent gets none.
//
// Driven through the real route handlers against a scratch PROJECT_ROOT.

import { describe, it, expect, vi, beforeAll, beforeEach, afterAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, readdirSync, statSync, rmSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const H = vi.hoisted(() => ({ root: '', tmp: '' }))

vi.mock('node:os', async (orig) => {
  const a = await orig<typeof import('node:os')>()
  return { ...a, homedir: () => `${H.root}/home`, tmpdir: () => H.tmp || a.tmpdir() }
})
vi.mock('../config.js', async (orig) => {
  const a = await orig<typeof import('../config.js')>()
  return { ...a, PROJECT_ROOT: H.root, STORE_DIR: `${H.root}/store` }
})
vi.mock('../web/vault.js', async (orig) => {
  const a = await orig<typeof import('../web/vault.js')>()
  return { ...a, getSecret: () => null, setSecret: () => {}, deleteSecret: () => {} }
})
vi.mock('../web/claude-cli-version.js', async (orig) => {
  const a = await orig<typeof import('../web/claude-cli-version.js')>()
  const v = { version: '9.9.999', measuredAt: 0, error: null, source: 'env' as const }
  return { ...a, measureClaudeCliVersion: async () => v, measureClaudeCliVersionSync: () => v }
})

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', async (importOriginal) => ({ ...(await importOriginal<typeof import('../logger.js')>()), logger: log }))

vi.mock('../notify.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../notify.js')>()),
  notifySecurityEvent: async () => {},
}))

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
H.root = mkdtempSync(join(tmpdir(), 'code-exec-privilege-'))
H.tmp = join(H.root, 'tmp')
process.env.CLAUDECLAW_ENV_DIR = join(H.root, 'envdir')
delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
mkdirSync(join(H.root, 'envdir'), { recursive: true })
mkdirSync(H.tmp, { recursive: true })
for (const d of ['templates', 'scripts', '.claude', 'plugins', 'config-examples', 'seed-config', 'web']) {
  if (existsSync(join(REPO, d))) symlinkSync(join(REPO, d), join(H.root, d))
}
mkdirSync(join(H.root, 'store'), { recursive: true })
mkdirSync(join(H.root, 'home', '.claude', 'skills'), { recursive: true })

const { tryHandleAgents } = await import('../web/routes/agents.js')
const { tryHandleFleetQ } = await import('../web/routes/fleet-q.js')
const { tryHandleSkills } = await import('../web/routes/skills.js')
const { tryHandleFleet } = await import('../web/routes/fleet.js')
const { importAgentBundle } = await import('../web/agent-bundle.js')
const { initDatabase, getDb, createDashboardUser } = await import('../db.js')
const { createSession } = await import('../web/auth-sessions.js')
const { SESSION_COOKIE_NAME } = await import('../web/auth-gate.js')
type Ctx = Parameters<typeof tryHandleAgents>[0]
type Auth = Ctx['auth']

const ENV_PATH = join(H.root, 'envdir', '.env')
const EXEC_OFF_BODY = { error: 'Forbidden for this credential (BEARER_CODE_EXEC_ADMIN_ENABLED is off)', code: 'bearer_code_exec_admin_off' }
const AUDIT_KEY = 'security.bearer_code_exec_admin'

const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }

const NAME = 'priv-agent'
const SKILL = 'priv-skill'
const agentDirPath = (n = NAME) => join(H.root, 'agents', n)
const globalSkillDir = join(H.root, 'home', '.claude', 'skills', SKILL)

function seed(): void {
  rmSync(agentDirPath(), { recursive: true, force: true })
  mkdirSync(join(agentDirPath(), '.claude'), { recursive: true })
  writeFileSync(join(agentDirPath(), 'agent-config.json'), JSON.stringify({ model: 'claude-opus-5-5', securityProfile: 'default', capabilities: ['a'] }))
  writeFileSync(join(agentDirPath(), '.claude', 'settings.json'), '{"permissions":{"allow":[]}}\n')
  rmSync(globalSkillDir, { recursive: true, force: true })
  mkdirSync(globalSkillDir, { recursive: true })
  writeFileSync(join(globalSkillDir, 'SKILL.md'), '---\nname: priv-skill\ndescription: x\n---\nbody\n')
}

function tree(dir: string, base = dir): Record<string, string> {
  const out: Record<string, string> = {}
  if (!existsSync(dir)) return out
  for (const n of readdirSync(dir)) {
    const p = join(dir, n)
    if (statSync(p).isDirectory()) Object.assign(out, tree(p, base))
    else out[p.slice(base.length)] = readFileSync(p, 'utf8')
  }
  return out
}
const snapshot = () => ({ agent: tree(agentDirPath()), skillsDir: tree(join(agentDirPath(), '.claude', 'skills')) })

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, 'MAIN_AGENT_ID=mainbot\n' + (lines === null ? '' : `${lines}\n`))
}
const EXEC_ON = 'BEARER_CODE_EXEC_ADMIN_ENABLED=1'

type Handler = 'agents' | 'fleetq' | 'skills' | 'fleet'
async function call(handler: Handler, method: string, fullUrl: string, auth: Auth, body: unknown, headers: Record<string, string> = {}) {
  const req = new EventEmitter() as unknown as Ctx['req']
  const url = new URL(`http://localhost:3420${fullUrl}`)
  ;(req as unknown as { headers: Record<string, string> }).headers = { 'content-type': 'application/json', ...headers }
  ;(req as unknown as { url: string }).url = url.pathname + url.search
  const out = { status: 0, raw: '' }
  const res = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.raw += String(chunk) },
    setHeader() {},
  }
  process.nextTick(() => {
    ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
    ;(req as unknown as EventEmitter).emit('end')
  })
  const ctx = { req, res, path: url.pathname, method, url, auth } as unknown as Ctx
  const handled =
    handler === 'agents' ? await tryHandleAgents(ctx, join(H.root, 'web'))
    : handler === 'fleetq' ? await tryHandleFleetQ(ctx)
    : handler === 'skills' ? await tryHandleSkills(ctx)
    : await tryHandleFleet(ctx)
  expect(handled).toBe(true)
  return {
    status: out.status || 200,
    json: () => (out.raw ? JSON.parse(out.raw) : {}),
    bodyRead: (req as unknown as EventEmitter).listenerCount('data') > 0,
  }
}

function liveSessionCookie(): string {
  const u = getDb().prepare('SELECT id FROM dashboard_users WHERE username = ?').get('owner') as { id: number }
  return `${SESSION_COOKIE_NAME}=${createSession({ userId: u.id, username: 'owner' })}`
}
function auditRows(): Array<{ actor: string; new_value: string }> {
  return getDb().prepare('SELECT actor, new_value FROM config_change_log WHERE key = ? ORDER BY id').all(AUDIT_KEY) as Array<{ actor: string; new_value: string }>
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  createDashboardUser('owner', 'hash')
})
beforeEach(() => {
  getDb().exec('DELETE FROM config_change_log')
  seed()
  setEnv(null)
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
})
afterAll(() => rmSync(H.root, { recursive: true, force: true }))

interface Route { action: string; handler: Handler; method: string; url: string; body: unknown; extraEnv?: string }
const ROUTES: Route[] = [
  { action: 'agents.security', handler: 'agents', method: 'PUT', url: `/api/agents/${NAME}/security`, body: { profile: 'default' } },
  { action: 'agents.capabilities', handler: 'fleetq', method: 'PUT', url: `/api/agents/${NAME}/capabilities`, body: { capabilities: ['x', 'y'] } },
  { action: 'skills.assign', handler: 'skills', method: 'POST', url: `/api/skills/${SKILL}/assign`, body: { agents: [NAME] } },
  { action: 'fleet.import', handler: 'fleet', method: 'POST', url: '/api/fleet/import?apply=true', body: { not: 'a fleet' }, extraEnv: 'FLEET_IMPORT_APPLY_ENABLED=1' },
]
const GATED: Array<[string, Auth]> = [['token', TOKEN], ['full device key', DEVICE_FULL]]

describe('switch off: 403 before the body is read, target files byte-identical', () => {
  for (const r of ROUTES) {
    for (const [who, auth] of GATED) {
      it(`${r.action}: ${who} -> 403 bearer_code_exec_admin_off`, async () => {
        if (r.extraEnv) setEnv(r.extraEnv)
        const before = snapshot()
        const skillBefore = tree(globalSkillDir)
        const res = await call(r.handler, r.method, r.url, auth, r.body)
        expect(res.status).toBe(403)
        expect(res.json()).toEqual(EXEC_OFF_BODY)
        expect(res.bodyRead).toBe(false)
        expect(snapshot()).toEqual(before)
        expect(tree(globalSkillDir)).toEqual(skillBefore)
        expect(auditRows()).toEqual([])
      })
    }
    it(`${r.action}: a token with a forged session cookie is still gated`, async () => {
      if (r.extraEnv) setEnv(r.extraEnv)
      const res = await call(r.handler, r.method, r.url, TOKEN, r.body, { cookie: `${SESSION_COOKIE_NAME}=forged` })
      expect(res.status).toBe(403)
      expect(res.bodyRead).toBe(false)
    })
  }
})

describe('switch on: today\'s response, audited', () => {
  it('agents.security: token -> 200, profile and settings written, start + outcome rows', async () => {
    setEnv(EXEC_ON)
    const res = await call('agents', 'PUT', `/api/agents/${NAME}/security`, TOKEN, { profile: 'default' })
    expect(res.status).toBe(200)
    expect(res.json()).toMatchObject({ ok: true })
    expect(res.bodyRead).toBe(true)
    expect(JSON.parse(readFileSync(join(agentDirPath(), 'agent-config.json'), 'utf8')).securityProfile).toBe('default')
    expect(auditRows()).toEqual([
      { actor: 'token', new_value: `agents.security ${NAME}` },
      { actor: 'token', new_value: `agents.security ${NAME} -> ok` },
    ])
  })

  it('agents.capabilities: token -> 200, tags written, audited', async () => {
    setEnv(EXEC_ON)
    const res = await call('fleetq', 'PUT', `/api/agents/${NAME}/capabilities`, TOKEN, { capabilities: ['x', 'y'] })
    expect(res.status).toBe(200)
    expect(res.json()).toEqual({ ok: true, capabilities: ['x', 'y'] })
    expect(JSON.parse(readFileSync(join(agentDirPath(), 'agent-config.json'), 'utf8')).capabilities).toEqual(['x', 'y'])
    expect(auditRows()).toEqual([
      { actor: 'token', new_value: `agents.capabilities ${NAME}` },
      { actor: 'token', new_value: `agents.capabilities ${NAME} -> ok` },
    ])
  })

  it('skills.assign: full device key -> 200, skill copied into the agent, audited', async () => {
    setEnv(EXEC_ON)
    const res = await call('skills', 'POST', `/api/skills/${SKILL}/assign`, DEVICE_FULL, { agents: [NAME] })
    expect(res.status).toBe(200)
    expect(res.json()).toEqual({ ok: true })
    expect(existsSync(join(agentDirPath(), '.claude', 'skills', SKILL, 'SKILL.md'))).toBe(true)
    expect(auditRows()).toEqual([
      { actor: 'device', new_value: `skills.assign ${SKILL}` },
      { actor: 'device', new_value: `skills.assign ${SKILL} -> ok` },
    ])
  })

  it('fleet.import apply: token with the apply switch and the code-exec switch -> not 403 on the gate', async () => {
    setEnv(`${EXEC_ON}\nFLEET_IMPORT_APPLY_ENABLED=1`)
    const res = await call('fleet', 'POST', '/api/fleet/import?apply=true', TOKEN, { not: 'a fleet' })
    expect(res.status).not.toBe(403)
    expect(res.bodyRead).toBe(true)
    expect(auditRows()[0]).toEqual({ actor: 'token', new_value: 'fleet.import fleet' })
  })
})

describe('session: never gated, no audit rows', () => {
  for (const r of ROUTES) {
    it(`${r.action}: session -> today's response`, async () => {
      setEnv(r.extraEnv ?? null)
      const res = await call(r.handler, r.method, r.url, SESSION, r.body)
      expect(res.status).not.toBe(403)
      expect(res.bodyRead).toBe(true)
      expect(auditRows()).toEqual([])
    })
    it(`${r.action}: token carrying a live session cookie -> not gated`, async () => {
      setEnv(r.extraEnv ?? null)
      const res = await call(r.handler, r.method, r.url, TOKEN, r.body, { cookie: liveSessionCookie() })
      expect(res.status).not.toBe(403)
      expect(auditRows()).toEqual([])
    })
  }
})

describe('fleet import dry-run stays open for the token', () => {
  it('apply absent -> not 403, body read, no audit row', async () => {
    const res = await call('fleet', 'POST', '/api/fleet/import', TOKEN, { not: 'a fleet' })
    expect(res.status).not.toBe(403)
    expect(res.bodyRead).toBe(true)
    expect(auditRows()).toEqual([])
  })
})

describe('N3b: a bundle never chooses the securityProfile', () => {
  let seq = 0
  function bundle(profile: string): Buffer {
    const stage = join(H.root, 'bundles', `b${++seq}`)
    mkdirSync(join(stage, 'agent', '.claude'), { recursive: true })
    writeFileSync(join(stage, 'manifest.json'), JSON.stringify({ schemaVersion: 1, agentName: 'imp', includesSecrets: false }))
    writeFileSync(join(stage, 'agent', 'agent-config.json'), JSON.stringify({ model: 'm', securityProfile: profile }))
    writeFileSync(join(stage, 'agent', '.claude', 'settings.json'), '{"permissions":{"allow":["Bash(*)"]}}\n')
    const out = join(H.root, 'bundles', `b${seq}.tar.gz`)
    execFileSync('tar', ['-czf', out, '-C', stage, 'manifest.json', 'agent'])
    return readFileSync(out)
  }
  const dest = (n: string) => join(H.root, 'imp-dest', n)

  it('overwrite of an existing developer-junior agent keeps developer-junior and its settings.json', () => {
    rmSync(join(H.root, 'imp-dest'), { recursive: true, force: true })
    mkdirSync(join(dest('imp'), '.claude'), { recursive: true })
    writeFileSync(join(dest('imp'), 'agent-config.json'), JSON.stringify({ securityProfile: 'developer-junior' }))
    writeFileSync(join(dest('imp'), '.claude', 'settings.json'), '{"permissions":{"allow":[]}}\n')
    const r = importAgentBundle(bundle('applier'), { overwrite: true, resolveDest: dest })
    expect(r.overwritten).toBe(true)
    expect(JSON.parse(readFileSync(join(dest('imp'), 'agent-config.json'), 'utf8')).securityProfile).toBe('developer-junior')
    expect(readFileSync(join(dest('imp'), '.claude', 'settings.json'), 'utf8')).toBe('{"permissions":{"allow":[]}}\n')
  })

  it('a new agent gets no securityProfile from the bundle (falls back to default)', () => {
    rmSync(join(H.root, 'imp-dest'), { recursive: true, force: true })
    const r = importAgentBundle(bundle('applier'), { resolveDest: dest })
    expect(r.overwritten).toBe(false)
    const cfg = JSON.parse(readFileSync(join(dest('imp'), 'agent-config.json'), 'utf8'))
    expect('securityProfile' in cfg).toBe(false)
    expect(cfg.model).toBe('m')
  })

  it('overwrite of an existing agent WITHOUT a profile -> still none from the bundle', () => {
    rmSync(join(H.root, 'imp-dest'), { recursive: true, force: true })
    mkdirSync(dest('imp'), { recursive: true })
    writeFileSync(join(dest('imp'), 'agent-config.json'), JSON.stringify({ model: 'old' }))
    importAgentBundle(bundle('applier'), { overwrite: true, resolveDest: dest })
    expect('securityProfile' in JSON.parse(readFileSync(join(dest('imp'), 'agent-config.json'), 'utf8'))).toBe(false)
  })
})
