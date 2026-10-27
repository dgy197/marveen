// Card 053f4e66 B, node N1: the one shared dashboard Bearer (auth kind 'token',
// held by every agent of the fleet) must not issue a new long-lived credential:
// a dashboard user, a device key, a password reset (the take-over of an existing
// user) or a Bridge pairing. These four POSTs are refused with 403 unless the
// install's .env opens the bearer-credential-admin switch (credential-admin.ts),
// and the refusal happens BEFORE the request body is read. A logged-in owner
// ('session') works exactly as before; device keys, federation tokens and a
// missing principal keep their old 403.
//
// Window mode (S6-S9): with ENABLED=1 plus UNTIL and NONCE in the same .env the
// switch admits a token caller only before UNTIL (at most 900 s ahead) and only
// with an X-Credential-Window header equal to NONCE (constant-time compare).
//
// The suite runs the REAL handlers (routes/auth.ts, routes/security.ts) against
// a throwaway install: the .env, store/config-overrides.json and the
// authorized_keys file live under one mkdtemp directory, the DB is in memory.
// bridgeEnroll is replaced by a stand-in that writes the temp authorized_keys
// and mints a real device key, so the "nothing written" assertions of the
// refused cases are not vacuous: the admitted cases write through the same
// fixture.

import { describe, it, expect, beforeAll, beforeEach, afterEach, afterAll, vi } from 'vitest'
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'cred-admin-gate-')))
  const project = path.join(root, 'project')
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import.
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  for (const k of ['BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE']) delete process.env[k]
  return { root, project, store: path.join(project, 'store'), sshDir: path.join(root, 'ssh') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
}))

// Every log call is recorded in order, next to the body reads (seq), so the
// suite can show the decision was taken before the body was touched.
const seq = vi.hoisted(() => [] as string[])
const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) {
    l[k] = vi.fn((_obj: unknown, msg?: unknown) => { seq.push(`${k}:${String(msg)}`) })
  }
  l.child = () => l
  return l
})
vi.mock('../logger.js', () => ({ logger: log, PRETTY_OPTIONS: {} }))

// No real notification ever leaves the suite; the texts are kept for asserts.
const notified = vi.hoisted(() => [] as string[])
vi.mock('../notify.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../notify.js')>()),
  notifySecurityEvent: async (text: string) => { notified.push(text) },
}))

// Bridge stand-in: no keyscan, no real ~/.ssh. It writes the temp
// authorized_keys and mints a real device key, as bridgeEnroll does.
const bridge = vi.hoisted(() => ({ calls: 0 }))
vi.mock('../web/bridge-enroll.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/bridge-enroll.js')>()),
  bridgeEnroll: async (input: { name: string }) => {
    bridge.calls++
    const fs = await import('node:fs')
    const { randomUUID } = await import('node:crypto')
    const { createDeviceKey } = await import('../web/auth-device-keys.js')
    const installId = randomUUID()
    fs.appendFileSync(`${T.sshDir}/authorized_keys`, `ssh-ed25519 AAAAtest marveen-remote:${installId}\n`)
    const minted = createDeviceKey(input.name, { installId })
    return { action: 'added', warnings: [], installId, deviceKeyId: minted.id, replacedDeviceKey: false, host: '100.64.0.1', hostKeySource: 'test', bundle: `BUNDLE:${minted.key}` }
  },
}))

// Every .env read through env.ts, with the keys asked for (S9: one read).
const envReads = vi.hoisted(() => [] as Array<string[] | undefined>)
vi.mock('../env.js', async (importOriginal) => {
  const m = await importOriginal<typeof import('../env.js')>()
  return { ...m, readEnvFile: (keys?: string[]) => { envReads.push(keys ? [...keys] : undefined); return m.readEnvFile(keys) } }
})

// timingSafeEqual is wrapped, so the suite can show the nonce verdict IS its
// verdict (override) and not an === next to it.
const ct = vi.hoisted(() => ({ lengths: [] as number[], override: null as null | ((a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView) => boolean) }))
vi.mock('node:crypto', async (importOriginal) => {
  const m = await importOriginal<typeof import('node:crypto')>()
  const timingSafeEqual = (a: NodeJS.ArrayBufferView, b: NodeJS.ArrayBufferView): boolean => {
    ct.lengths.push(a.byteLength)
    return ct.override ? ct.override(a, b) : m.timingSafeEqual(a, b)
  }
  return { ...m, default: { ...m, timingSafeEqual }, timingSafeEqual }
})

const { tryHandleAuth } = await import('../web/routes/auth.js')
const { tryHandleSecurity } = await import('../web/routes/security.js')
const { operatorGateDecision } = await import('../web/operator-gate.js')
const { initDatabase, getDb, createDashboardUser, getDashboardUser } = await import('../db.js')
const { hashPassword, verifyPassword } = await import('../web/password-hash.js')
const { createDeviceKey, resolveDeviceKey, _clearDeviceKeyCacheForTest } = await import('../web/auth-device-keys.js')
const { _clearSessionCacheForTest } = await import('../web/auth-sessions.js')
const { _resetThrottleForTest } = await import('../web/login-throttle.js')

const ENABLED = 'BEARER_CREDENTIAL_ADMIN_ENABLED'
const UNTIL = 'BEARER_CREDENTIAL_ADMIN_UNTIL'
const NONCE = 'BEARER_CREDENTIAL_ADMIN_NONCE'
const HEADER = 'x-credential-window'
const OFF_BODY = { error: 'Forbidden for the shared token (BEARER_CREDENTIAL_ADMIN_ENABLED is off)', code: 'bearer_credential_admin_off' }
const FORBIDDEN_KIND = { error: 'Forbidden for this credential type' }
const FORBIDDEN_CREDENTIAL = { error: 'Forbidden for this credential type', code: 'forbidden_credential' }
const REFUSED = /^Credential admin refused for the shared token/
const ADMITTED = /^Credential admin by the shared token/

const ENV_PATH = join(T.project, '.env')
const OVERRIDES = join(T.store, 'config-overrides.json')
const AUTH_KEYS = join(T.sshDir, 'authorized_keys')
const BASE_ENV = 'MAIN_AGENT_ID=mainbot\nBOT_NAME=Brainy\n'

const OWNER = 'owner'
const OWNER_PW = 'owner-secret-pw-1'
const NEW_PW = 'brand-new-secret-pw-2'
let OWNER_HASH = ''

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: OWNER }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }
const DEVICE_OPERATOR: Auth = { kind: 'device', device: 'it-op', deviceId: 901, scope: 'operator' }
const FEDERATION: Auth = { kind: 'federation', peer: 'peer-a' }

interface Route { action: string; path: string; ok: number; body: () => Record<string, unknown> }
const ROUTES: Route[] = [
  { action: 'auth.users.create', path: '/api/auth/users', ok: 201, body: () => ({ username: 'newuser', password: NEW_PW }) },
  { action: 'auth.device_keys.create', path: '/api/auth/device-keys', ok: 201, body: () => ({ name: 'gate-test', expires_in_days: 30 }) },
  { action: 'auth.password.break_glass', path: '/api/auth/password', ok: 200, body: () => ({ username: OWNER, new_password: NEW_PW }) },
  { action: 'security.bridge_enroll', path: '/api/security/bridge-enroll', ok: 201, body: () => ({ key_line: 'ssh-ed25519 AAAAtest marveen-remote:x', name: 'Gate Phone' }) },
]
const DEVICE_KEYS = ROUTES[1]!

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, BASE_ENV + (lines === null ? '' : `${lines}\n`))
}

async function call(method: string, path: string, opts: { auth?: Auth; body?: unknown; headers?: Record<string, string | string[]> } = {}) {
  const out = { status: 0, raw: '' }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() {},
    end(chunk?: string) { if (chunk !== undefined) out.raw += chunk },
  }
  const raw = opts.body === undefined ? '' : typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)
  let bodyRead = false
  const req: any = {
    headers: { ...(opts.headers ?? {}) },
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (!bodyRead) { bodyRead = true; seq.push('body') }
      if (event === 'data' && raw) cb(Buffer.from(raw))
      if (event === 'end') cb()
      return req
    },
    destroy() {},
  }
  const ctx = { req, res, path, method, url: new URL(`http://127.0.0.1:3420${path}`), auth: opts.auth } as RouteContext
  const handled = path.startsWith('/api/security/') ? await tryHandleSecurity(ctx) : await tryHandleAuth(ctx)
  return { handled, status: out.status, raw: out.raw, json: () => (out.raw ? JSON.parse(out.raw) : {}), bodyRead }
}

function warns(re: RegExp): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))
}

function gateEnvReads(): Array<string[] | undefined> {
  return envReads.filter(k => k?.includes(ENABLED))
}

const TABLES = ['dashboard_users', 'device_keys', 'auth_sessions', 'config_change_log']
function snapshot() {
  const db = getDb()
  return {
    tables: Object.fromEntries(TABLES.map(t => [t, JSON.stringify(db.prepare(`SELECT * FROM ${t} ORDER BY rowid`).all())])),
    files: Object.fromEntries([ENV_PATH, OVERRIDES, AUTH_KEYS].map(p => [p, existsSync(p) ? readFileSync(p, 'utf8') : null])),
  }
}

function auditRows(key: string): Array<{ new_value: string; actor: string }> {
  return getDb().prepare('SELECT new_value, actor FROM config_change_log WHERE key = ? ORDER BY id').all(key) as Array<{ new_value: string; actor: string }>
}

/** Everything the suite could have leaked a secret into: logs, notifications, audit rows. */
function trail(): string {
  const logs = Object.entries(log).filter(([, fn]) => typeof fn === 'function' && 'mock' in fn).map(([, fn]) => JSON.stringify((fn as any).mock.calls))
  const audit = JSON.stringify(getDb().prepare('SELECT * FROM config_change_log').all())
  return [...logs, JSON.stringify(notified), audit].join('\n')
}

beforeAll(async () => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
  OWNER_HASH = await hashPassword(OWNER_PW)
})

beforeEach(() => {
  getDb().exec('DELETE FROM auth_sessions; DELETE FROM dashboard_users; DELETE FROM device_keys; DELETE FROM config_change_log')
  _clearSessionCacheForTest()
  _clearDeviceKeyCacheForTest()
  _resetThrottleForTest()
  createDashboardUser(OWNER, OWNER_HASH)
  mkdirSync(T.store, { recursive: true })
  mkdirSync(T.sshDir, { recursive: true })
  setEnv(null)
  writeFileSync(OVERRIDES, '{}\n')
  writeFileSync(AUTH_KEYS, 'ssh-ed25519 AAAAexisting existing@host\n')
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  seq.length = 0
  notified.length = 0
  envReads.length = 0
  bridge.calls = 0
  ct.lengths.length = 0
  ct.override = null
  for (const k of [ENABLED, UNTIL, NONCE]) delete process.env[k]
})

afterAll(() => {
  for (const k of [ENABLED, UNTIL, NONCE]) delete process.env[k]
  try { getDb().close() } catch { /* already closed */ }
  rmSync(T.root, { recursive: true, force: true })
})

describe('token caller, switch off: 403 before the body, one WARN, nothing written (G1, L1)', () => {
  it.each(ROUTES.map(r => [r.action, r] as const))('%s', async (_action, route) => {
    for (const body of [route.body(), '{']) {
      const before = snapshot()
      log.warn.mockClear()
      const r = await call('POST', route.path, { auth: TOKEN, body, headers: { 'x-agent-id': 'ezermester' } })
      expect(r.handled).toBe(true)
      expect(r.status).toBe(403)
      expect(r.json()).toEqual(OFF_BODY)
      expect(r.bodyRead).toBe(false)
      expect(snapshot()).toEqual(before)
      expect(log.warn).toHaveBeenCalledTimes(1)
      const [w] = warns(REFUSED)
      expect(w?.[0]).toEqual({ caller: 'ezermester', at: expect.any(String), action: route.action, reason: 'switch_off' })
      expect(new Date(w![0].at).toISOString()).toBe(w![0].at)
    }
    expect(bridge.calls).toBe(0)
    expect(notified).toEqual([])
  })
})

describe('token caller, switch "1" (manual mode): today\'s answer plus the trail (G2, L2)', () => {
  beforeEach(() => setEnv(`${ENABLED}=1`))

  it('POST /api/auth/users: 201, one admission WARN before the body, one audit row, one notification, no password anywhere', async () => {
    const r = await call('POST', '/api/auth/users', { auth: TOKEN, body: ROUTES[0]!.body(), headers: { 'x-agent-id': 'brainy' } })
    expect(r.status).toBe(201)
    expect(r.json()).toMatchObject({ ok: true, user: { username: 'newuser' } })
    expect(getDashboardUser('newuser')).toBeDefined()
    const w = warns(ADMITTED)
    expect(w).toHaveLength(1)
    expect(w[0]![0]).toEqual({ caller: 'brainy', at: expect.any(String), action: 'auth.users.create', via: 'switch', mode: 'manual' })
    expect(seq.findIndex(s => /Credential admin by the shared token/.test(s))).toBeLessThan(seq.indexOf('body'))
    const rows = auditRows('security.bearer_credential_admin')
    expect(rows).toHaveLength(1)
    expect(rows[0]!.actor).toBe('token')
    expect(rows[0]!.new_value).toContain('newuser')
    expect(notified).toHaveLength(1)
    expect(notified[0]).toContain('newuser')
    expect(trail()).not.toContain(NEW_PW)
  })

  it('POST /api/auth/device-keys: 201, one admission WARN, one audit row (name, id, expiry), one notification, no raw key anywhere', async () => {
    const r = await call('POST', '/api/auth/device-keys', { auth: TOKEN, body: DEVICE_KEYS.body() })
    expect(r.status).toBe(201)
    const body = r.json()
    expect(String(body.key)).toMatch(/^mvdk_/)
    const w = warns(ADMITTED)
    expect(w).toHaveLength(1)
    expect(w[0]![0]).toMatchObject({ caller: 'unknown', action: 'auth.device_keys.create', via: 'switch', mode: 'manual' })
    const rows = auditRows('security.bearer_credential_admin')
    expect(rows).toHaveLength(1)
    expect(rows[0]!.actor).toBe('token')
    expect(rows[0]!.new_value).toContain('gate-test')
    expect(rows[0]!.new_value).toContain(`id=${body.id}`)
    expect(rows[0]!.new_value).toContain(new Date(Number(body.expires_at) * 1000).toISOString())
    expect(notified).toHaveLength(1)
    expect(notified[0]).toContain('gate-test')
    expect(trail()).not.toContain(String(body.key))
  })

  it('POST /api/auth/password (token break-glass): 200, the existing audit and notification, one admission WARN, no password anywhere', async () => {
    const r = await call('POST', '/api/auth/password', { auth: TOKEN, body: ROUTES[2]!.body() })
    expect(r.status).toBe(200)
    expect(await verifyPassword(NEW_PW, getDashboardUser(OWNER)!.password_hash)).toBe(true)
    expect(warns(ADMITTED)).toHaveLength(1)
    expect(warns(ADMITTED)[0]![0]).toMatchObject({ action: 'auth.password.break_glass', via: 'switch', mode: 'manual' })
    expect(auditRows('security.break_glass_password_reset')).toHaveLength(1)
    expect(auditRows('security.bearer_credential_admin')).toHaveLength(0)
    expect(notified).toHaveLength(1)
    expect(trail()).not.toContain(NEW_PW)
  })

  it('POST /api/security/bridge-enroll: 201 (stand-in enroll), the existing audit and notification, one admission WARN', async () => {
    const before = readFileSync(AUTH_KEYS, 'utf8')
    const r = await call('POST', '/api/security/bridge-enroll', { auth: TOKEN, body: ROUTES[3]!.body() })
    expect(r.status).toBe(201)
    expect(bridge.calls).toBe(1)
    expect(readFileSync(AUTH_KEYS, 'utf8')).not.toBe(before)
    expect(warns(ADMITTED)).toHaveLength(1)
    expect(warns(ADMITTED)[0]![0]).toMatchObject({ action: 'security.bridge_enroll', via: 'switch', mode: 'manual' })
    expect(auditRows('security.bridge_enroll')).toHaveLength(1)
    expect(notified).toHaveLength(1)
  })

  it('a "{" body is parsed only after the gate: 400 on all four, nothing written (D10)', async () => {
    for (const route of ROUTES) {
      const before = snapshot()
      const r = await call('POST', route.path, { auth: TOKEN, body: '{' })
      expect(r.status, route.path).toBe(400)
      expect(snapshot()).toEqual(before)
    }
    expect(bridge.calls).toBe(0)
  })

  it('the decision precedes the first body read on every gated route', async () => {
    for (const route of ROUTES) {
      seq.length = 0
      await call('POST', route.path, { auth: TOKEN, body: route.body() })
      const decided = seq.findIndex(s => /Credential admin by the shared token/.test(s))
      expect(decided, route.path).toBeGreaterThanOrEqual(0)
      expect(seq.indexOf('body'), route.path).toBeGreaterThan(decided)
    }
  })
})

describe('session caller: unchanged whatever the switch says, no gate WARN, no gate notification (G3)', () => {
  it.each([['off', null], ['on', `${ENABLED}=1`]] as const)('switch %s', async (_label, line) => {
    setEnv(line)
    const users = await call('POST', '/api/auth/users', { auth: SESSION, body: ROUTES[0]!.body() })
    expect(users.status).toBe(201)
    const keys = await call('POST', '/api/auth/device-keys', { auth: SESSION, body: DEVICE_KEYS.body() })
    expect(keys.status).toBe(201)
    const wrong = await call('POST', '/api/auth/password', { auth: SESSION, body: { current_password: 'not-the-password', new_password: NEW_PW } })
    expect(wrong.status).toBe(401)
    const pw = await call('POST', '/api/auth/password', { auth: SESSION, body: { current_password: OWNER_PW, new_password: NEW_PW } })
    expect(pw.status).toBe(200)
    expect(await verifyPassword(NEW_PW, getDashboardUser(OWNER)!.password_hash)).toBe(true)
    const br = await call('POST', '/api/security/bridge-enroll', { auth: SESSION, body: ROUTES[3]!.body() })
    expect(br.status).toBe(201)
    expect(bridge.calls).toBe(1)
    expect(warns(REFUSED)).toEqual([])
    expect(warns(ADMITTED)).toEqual([])
    expect(gateEnvReads()).toEqual([])
    expect(auditRows('security.bearer_credential_admin')).toEqual([])
    // Only the Bridge pairing's own, existing notification.
    expect(notified).toHaveLength(1)
  })

  it('a password login still works and mints a session, switch off', async () => {
    const r = await call('POST', '/api/auth/login', { body: { username: OWNER, password: OWNER_PW } })
    expect(r.status).toBe(200)
    expect(r.json()).toMatchObject({ ok: true, user: OWNER })
    expect((getDb().prepare('SELECT COUNT(*) AS n FROM auth_sessions').get() as { n: number }).n).toBe(1)
  })
})

describe('device, federation and no principal: the old 403, body unread, switch on or off (G4, G5)', () => {
  it.each([
    ['device full', DEVICE_FULL],
    ['device operator', DEVICE_OPERATOR],
    ['federation', FEDERATION],
    ['no principal', undefined],
  ] as const)('%s', async (_label, auth) => {
    for (const line of [null, `${ENABLED}=1`]) {
      setEnv(line)
      for (const route of ROUTES) {
        const before = snapshot()
        const r = await call('POST', route.path, { auth, body: route.body() })
        expect(r.status, route.path).toBe(403)
        expect(r.json()).toEqual(route.path.startsWith('/api/security/') ? FORBIDDEN_CREDENTIAL : FORBIDDEN_KIND)
        expect(r.bodyRead, route.path).toBe(false)
        expect(snapshot()).toEqual(before)
      }
    }
    expect(bridge.calls).toBe(0)
    expect(warns(REFUSED)).toEqual([])
    expect(warns(ADMITTED)).toEqual([])
    expect(gateEnvReads()).toEqual([])
    expect(notified).toEqual([])
  })

  it('an operator key is stopped by the web.ts operator gate before any of the four handlers (G5)', () => {
    const access = (enabled: boolean) => () => ({ enabled, capabilities: {} as any, commands: [] })
    for (const route of ROUTES) {
      expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, route.path, access(true)), route.path).not.toBeNull()
      expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, route.path, access(false)), route.path).not.toBeNull()
    }
  })
})

describe('switch values: only an exact "1" in the .env opens (S1-S3)', () => {
  it.each([
    ['no line', null, false],
    ['empty value', `${ENABLED}=`, false],
    ['true', `${ENABLED}=true`, false],
    ['yes', `${ENABLED}=yes`, false],
    ['on', `${ENABLED}=on`, false],
    ['01', `${ENABLED}=01`, false],
    ['0', `${ENABLED}=0`, false],
    ['quoted " 1"', `${ENABLED}=" 1"`, false],
    ["quoted '1 '", `${ENABLED}='1 '`, false],
    ['lower-case key', `${ENABLED.toLowerCase()}=1`, false],
    ['commented out', `#${ENABLED}=1`, false],
    ['export prefix', `export ${ENABLED}=1`, false],
    ['similar key', `${ENABLED}_X=1`, false],
    ['1', `${ENABLED}=1`, true],
    ['"1"', `${ENABLED}="1"`, true],
    ["'1'", `${ENABLED}='1'`, true],
    ['unquoted " 1" (the line is trimmed)', `${ENABLED}= 1`, true],
    ['unquoted "1 " (the line is trimmed)', `${ENABLED}=1 `, true],
    ['=1 then =0 (the last wins)', `${ENABLED}=1\n${ENABLED}=0`, false],
    ['=0 then =1 (the last wins)', `${ENABLED}=0\n${ENABLED}=1`, true],
  ] as const)('%s -> open: %s', async (_label, line, open) => {
    setEnv(line)
    const r = await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })
    expect(r.status).toBe(open ? 201 : 403)
    if (!open) expect(r.json()).toEqual(OFF_BODY)
  })

  it('the process environment does not count (S2)', async () => {
    process.env[ENABLED] = '1'
    const r = await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })
    expect(r.status).toBe(403)
    expect(warns(REFUSED)[0]![0]).toMatchObject({ reason: 'switch_off' })
  })

  it('store/config-overrides.json does not count (S2)', async () => {
    writeFileSync(OVERRIDES, JSON.stringify({ [ENABLED]: '1' }))
    const r = await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })
    expect(r.status).toBe(403)
  })

  it('a change of the .env between two requests is followed without a restart (S3)', async () => {
    setEnv(`${ENABLED}=1`)
    expect((await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })).status).toBe(201)
    setEnv(null)
    expect((await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })).status).toBe(403)
    setEnv(`${ENABLED}=1`)
    expect((await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })).status).toBe(201)
  })
})

describe('window mode: UNTIL and NONCE next to ENABLED=1 (S6-S9)', () => {
  const NOW = 1_800_000_000
  const GOOD = 'Ab3_-'.repeat(8) + 'xyz'
  const flip = (s: string) => (s[0] === 'A' ? 'B' : 'A') + s.slice(1)

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] })
    vi.setSystemTime(NOW * 1000)
  })
  afterEach(() => { vi.useRealTimers() })

  function windowEnv(until: string | null, nonce: string | null, enabled: string | null = '1'): string {
    return [
      enabled === null ? null : `${ENABLED}=${enabled}`,
      until === null ? null : `${UNTIL}=${until}`,
      nonce === null ? null : `${NONCE}=${nonce}`,
    ].filter(Boolean).join('\n')
  }

  async function mint(header: string | string[] | undefined) {
    const headers: Record<string, string | string[]> = { 'x-agent-id': 'credential-window' }
    if (header !== undefined) headers[HEADER] = header
    return call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body(), headers })
  }

  const S = (n: number) => String(n)
  it.each([
    ['now+60, header matches', S(NOW + 60), GOOD, GOOD, 'window'],
    ['header missing', S(NOW + 60), GOOD, undefined, 'window_nonce_missing'],
    ['header empty', S(NOW + 60), GOOD, '', 'window_nonce_missing'],
    ['header one character off, same length', S(NOW + 60), GOOD, flip(GOOD), 'window_nonce_mismatch'],
    ['header shorter', S(NOW + 60), GOOD, GOOD.slice(0, -1), 'window_nonce_mismatch'],
    ['header longer', S(NOW + 60), GOOD, `${GOOD}A`, 'window_nonce_mismatch'],
    ['header sent twice (array)', S(NOW + 60), GOOD, [GOOD, GOOD], 'window_nonce_mismatch'],
    ['header sent twice (joined)', S(NOW + 60), GOOD, `${GOOD}, ${GOOD}`, 'window_nonce_mismatch'],
    ['header with a multi-byte character, same string length', S(NOW + 60), GOOD, `é${GOOD.slice(1)}`, 'window_nonce_mismatch'],
    ['UNTIL = now (the boundary)', S(NOW), GOOD, GOOD, 'window_expired'],
    ['UNTIL = now-1', S(NOW - 1), GOOD, GOOD, 'window_expired'],
    ['UNTIL = now+900 (the boundary)', S(NOW + 900), GOOD, GOOD, 'window'],
    ['UNTIL = now+901', S(NOW + 901), GOOD, GOOD, 'window_too_long'],
    ['UNTIL quoted (the parser strips one pair)', `"${NOW + 60}"`, GOOD, GOOD, 'window'],
    ['UNTIL abc', 'abc', GOOD, GOOD, 'window_malformed'],
    ['UNTIL 9 digits', '180000000', GOOD, GOOD, 'window_malformed'],
    ['UNTIL 11 digits', S((NOW + 60) * 10), GOOD, GOOD, 'window_malformed'],
    ['UNTIL -1', '-1', GOOD, GOOD, 'window_malformed'],
    ['UNTIL 1e9', '1e9', GOOD, GOOD, 'window_malformed'],
    ['UNTIL with a + sign', `+${NOW + 60}`, GOOD, GOOD, 'window_malformed'],
    ['UNTIL empty', '', GOOD, GOOD, 'window_malformed'],
    ['NONCE 42 characters', S(NOW + 60), GOOD.slice(0, 42), GOOD.slice(0, 42), 'window_malformed'],
    ['NONCE 44 characters', S(NOW + 60), `${GOOD}A`, `${GOOD}A`, 'window_malformed'],
    ['NONCE not base64url', S(NOW + 60), `${GOOD.slice(0, 42)}+`, `${GOOD.slice(0, 42)}+`, 'window_malformed'],
    ['NONCE empty', S(NOW + 60), '', '', 'window_malformed'],
    ['NONCE missing', S(NOW + 60), null, GOOD, 'window_malformed'],
    ['UNTIL missing', null, GOOD, GOOD, 'window_malformed'],
    ['both missing, header sent (manual mode, S8)', null, null, GOOD, 'manual'],
    ['both missing, no header (manual mode, S8)', null, null, undefined, 'manual'],
  ] as const)('%s', async (_label, until, nonce, header, expected) => {
    setEnv(windowEnv(until, nonce))
    const before = snapshot()
    const r = await mint(header as string | string[] | undefined)
    if (expected === 'window' || expected === 'manual') {
      expect(r.status).toBe(201)
      expect(warns(ADMITTED)).toHaveLength(1)
      expect(warns(ADMITTED)[0]![0]).toMatchObject({ caller: 'credential-window', action: 'auth.device_keys.create', via: 'switch', mode: expected })
      expect(auditRows('security.bearer_credential_admin')[0]!.new_value).toContain(`mode=${expected}`)
    } else {
      expect(r.status).toBe(403)
      expect(r.json()).toEqual(OFF_BODY)
      expect(r.bodyRead).toBe(false)
      expect(snapshot()).toEqual(before)
      expect(log.warn).toHaveBeenCalledTimes(1)
      expect(warns(REFUSED)[0]![0]).toEqual({ caller: 'credential-window', at: expect.any(String), action: 'auth.device_keys.create', reason: expected })
    }
  })

  it.each([['ENABLED=0', '0'], ['ENABLED missing', null]] as const)('%s with a valid window and a matching header: switch_off', async (_label, enabled) => {
    setEnv(windowEnv(S(NOW + 60), GOOD, enabled))
    const r = await mint(GOOD)
    expect(r.status).toBe(403)
    expect(warns(REFUSED)[0]![0]).toMatchObject({ reason: 'switch_off' })
  })

  it('UNTIL and NONCE only in the process environment or the overrides: manual mode, the .env alone counts (S2, S9)', async () => {
    setEnv(`${ENABLED}=1`)
    process.env[UNTIL] = S(NOW - 100)
    process.env[NONCE] = GOOD
    writeFileSync(OVERRIDES, JSON.stringify({ [UNTIL]: S(NOW - 100), [NONCE]: GOOD }))
    const r = await mint(undefined)
    expect(r.status).toBe(201)
    expect(warns(ADMITTED)[0]![0]).toMatchObject({ mode: 'manual' })
  })

  it('the three keys come from ONE .env read per request (S9)', async () => {
    setEnv(windowEnv(S(NOW + 60), GOOD))
    for (const header of [GOOD, undefined]) {
      envReads.length = 0
      await mint(header)
      expect(envReads).toHaveLength(1)
      expect([...envReads[0]!].sort()).toEqual([ENABLED, NONCE, UNTIL].sort())
    }
  })

  it('the nonce never shows up in a response or in any log line', async () => {
    setEnv(windowEnv(S(NOW + 60), GOOD))
    const raws: string[] = []
    for (const header of [GOOD, flip(GOOD), undefined, `${GOOD}, ${GOOD}`]) raws.push((await mint(header)).raw)
    setEnv(windowEnv(S(NOW - 1), GOOD))
    raws.push((await mint(GOOD)).raw)
    expect(warns(ADMITTED)).toHaveLength(1)
    expect(warns(REFUSED)).toHaveLength(4)
    expect(raws.join('\n')).not.toContain(GOOD.slice(0, 20))
    expect(trail()).not.toContain(GOOD.slice(0, 20))
    expect(trail()).not.toContain(flip(GOOD).slice(0, 20))
  })

  it('the nonce verdict is timingSafeEqual\'s: forced false refuses an exact match, forced true admits a same-length miss', async () => {
    setEnv(windowEnv(S(NOW + 60), GOOD))
    expect((await mint(GOOD)).status).toBe(201)
    expect(ct.lengths).toContain(43)

    ct.override = () => false
    const refused = await mint(GOOD)
    expect(refused.status).toBe(403)
    expect(warns(REFUSED).at(-1)![0]).toMatchObject({ reason: 'window_nonce_mismatch' })

    ct.override = () => true
    expect((await mint(flip(GOOD))).status).toBe(201)
  })
})

describe('the caller label in the WARN line (L1)', () => {
  it.each([
    ['ezermester', 'ezermester'],
    [undefined, 'unknown'],
    ['  ', 'unknown'],
    ['evil\r\nINJECTED {"x":1}', 'evil__INJECTED___x__1_'],
    ['x'.repeat(200), 'x'.repeat(64)],
  ] as const)('X-Agent-Id %j -> %j', async (agent, expected) => {
    const headers: Record<string, string> = agent === undefined ? {} : { 'x-agent-id': agent }
    await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body(), headers })
    const caller = warns(REFUSED)[0]![0].caller as string
    expect(caller).toBe(expected)
    expect(caller.length).toBeLessThanOrEqual(64)
  })
})

describe('not gated: listing and revoking keep today\'s answers, no gate WARN (G6)', () => {
  it.each([['off', null], ['on', `${ENABLED}=1`]] as const)('switch %s', async (_label, line) => {
    setEnv(line)
    for (const auth of [TOKEN, SESSION]) {
      const users = await call('GET', '/api/auth/users', { auth })
      expect(users.status).toBe(200)
      expect((users.json().users as Array<{ username: string }>).map(u => u.username)).toContain(OWNER)
      const keys = await call('GET', '/api/auth/device-keys', { auth })
      expect(keys.status).toBe(200)
      expect(Array.isArray(keys.json().keys)).toBe(true)

      const key = createDeviceKey('to-revoke', { expiresInDays: 30 })
      expect((await call('DELETE', `/api/auth/device-keys/${key.id}`, { auth })).status).toBe(200)
      expect((await call('DELETE', `/api/auth/device-keys/${key.id}`, { auth })).status).toBe(404)

      createDashboardUser('to-delete', OWNER_HASH)
      expect((await call('DELETE', '/api/auth/users/to-delete', { auth })).status).toBe(200)
      expect((await call('DELETE', '/api/auth/users/to-delete', { auth })).status).toBe(404)
    }
    const key = createDeviceKey('kept', { expiresInDays: 30 })
    for (const auth of [DEVICE_FULL, DEVICE_OPERATOR, FEDERATION, undefined]) {
      for (const [method, path] of [
        ['GET', '/api/auth/users'],
        ['GET', '/api/auth/device-keys'],
        ['DELETE', `/api/auth/device-keys/${key.id}`],
        ['DELETE', `/api/auth/users/${OWNER}`],
      ] as const) {
        const r = await call(method, path, { auth })
        expect(r.status, `${method} ${path}`).toBe(403)
        expect(r.json()).toEqual(FORBIDDEN_KIND)
      }
    }
    expect(resolveDeviceKey(key.key)).not.toBeNull()
    expect(getDashboardUser(OWNER)).toBeDefined()
    expect(warns(REFUSED)).toEqual([])
    expect(warns(ADMITTED)).toEqual([])
    expect(gateEnvReads()).toEqual([])
  })
})

describe('existing credentials are untouched by the gate (R1 for N1)', () => {
  it('a key and a user from before keep working after refused and admitted calls', async () => {
    const bridgeKey = createDeviceKey('GYURI WINDOWS', { installId: '11111111-2222-4333-8444-555555555555' })
    const apiKey = createDeviceKey('api-key', { expiresInDays: 7 })
    for (const route of ROUTES) await call('POST', route.path, { auth: TOKEN, body: route.body() })
    setEnv(`${ENABLED}=1`)
    await call('POST', '/api/auth/users', { auth: TOKEN, body: ROUTES[0]!.body() })
    await call('POST', DEVICE_KEYS.path, { auth: TOKEN, body: DEVICE_KEYS.body() })
    expect(resolveDeviceKey(bridgeKey.key)).toMatchObject({ id: bridgeKey.id, scope: 'full' })
    expect(resolveDeviceKey(apiKey.key)).toMatchObject({ id: apiKey.id })
    const login = await call('POST', '/api/auth/login', { body: { username: OWNER, password: OWNER_PW } })
    expect(login.status).toBe(200)
  })
})
