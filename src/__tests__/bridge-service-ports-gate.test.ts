// Card 053f4e66 B (Brainy 2097): PUT /api/bridge/service-ports rewrites an
// enrolled Bridge key's permitopen list in authorized_keys -- it widens what an
// existing credential reaches. So the one shared dashboard Bearer (auth kind
// 'token') gets the same bearer-credential-admin gate as the four issuing
// POSTs (credential-admin.ts): 403 bearer_credential_admin_off unless the
// install's .env opens the switch, decided BEFORE the body is read, one WARN
// with the caller label, nothing written. A logged-in owner ('session') and the
// Bridge itself (a device key bound to its own enrollment) work as before. The
// GET (a read) is not gated.
//
// The suite runs the REAL handler and the REAL authorized_keys rewrite against
// a throwaway install: the .env, the ssh dir and the DB live under one mkdtemp
// directory / in memory, so the "nothing written" assertions of the refused
// cases are not vacuous: the admitted cases write through the same fixture.

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { readFileSync, rmSync, writeFileSync, mkdirSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'svc-ports-gate-')))
  const project = path.join(root, 'project')
  const sshDir = path.join(root, 'ssh')
  fs.mkdirSync(project, { recursive: true })
  fs.mkdirSync(sshDir, { recursive: true, mode: 0o700 })
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import,
  // and the route resolves the ssh dir through the MARVEEN_SSH_DIR test seam.
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  process.env.MARVEEN_SSH_DIR = sshDir
  for (const k of ['BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE']) delete process.env[k]
  return { root, project, sshDir }
})

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

const { tryHandleBridgeServicePorts } = await import('../web/routes/bridge-service-ports.js')
const { initDatabase, getDb } = await import('../db.js')
const { createDeviceKey, _clearDeviceKeyCacheForTest } = await import('../web/auth-device-keys.js')
const { restrictOptions, restrictOptionsWithServices } = await import('../remote-enroll-core.js')
const { WEB_PORT } = await import('../config.js')

const ENABLED = 'BEARER_CREDENTIAL_ADMIN_ENABLED'
const UNTIL = 'BEARER_CREDENTIAL_ADMIN_UNTIL'
const NONCE = 'BEARER_CREDENTIAL_ADMIN_NONCE'
const OFF_BODY = { error: 'Forbidden for the shared token (BEARER_CREDENTIAL_ADMIN_ENABLED is off)', code: 'bearer_credential_admin_off' }
const REFUSED = /^Credential admin refused for the shared token/
const ADMITTED = /^Credential admin by the shared token/
const ACTION = 'bridge.service_ports.update'
const PATH = '/api/bridge/service-ports'

const ENV_PATH = join(T.project, '.env')
const AUTH_KEYS = join(T.sshDir, 'authorized_keys')
const ID = '0f81a9a2-08d6-4f4c-9a09-93e35ad27182'
const B64 = 'AAAAC3NzaC1lZDI1NTE5AAAAIFakefakefakefakefakefakefakefakefakefake'
const FOREIGN_LINE = 'ssh-ed25519 AAAAexisting existing@host'
const ENROLLED = `${FOREIGN_LINE}\n${restrictOptions(WEB_PORT)} ssh-ed25519 ${B64} marveen-remote:${ID}\n`
const WIDENED = `${FOREIGN_LINE}\n${restrictOptionsWithServices(WEB_PORT, [4007])} ssh-ed25519 ${B64} marveen-remote:${ID}\n`

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, 'MAIN_AGENT_ID=mainbot\n' + (lines === null ? '' : `${lines}\n`))
}

async function call(method: 'GET' | 'PUT', opts: { auth?: Auth; body?: unknown; headers?: Record<string, string>; query?: string } = {}) {
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
  const ctx = { req, res, path: PATH, method, url: new URL(`http://127.0.0.1:3420${PATH}${opts.query ?? ''}`), auth: opts.auth } as RouteContext
  const handled = await tryHandleBridgeServicePorts(ctx)
  return { handled, status: out.status, json: () => (out.raw ? JSON.parse(out.raw) : {}), bodyRead }
}

function warns(re: RegExp): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))
}

function snapshot() {
  return {
    authorizedKeys: readFileSync(AUTH_KEYS, 'utf8'),
    env: readFileSync(ENV_PATH, 'utf8'),
    ledger: JSON.stringify(getDb().prepare('SELECT * FROM config_change_log ORDER BY id').all()),
    keys: JSON.stringify(getDb().prepare('SELECT * FROM device_keys ORDER BY id').all()),
  }
}

function ledgerRows(): Array<{ key: string; actor: string; new_value: string }> {
  return getDb().prepare("SELECT key, actor, new_value FROM config_change_log WHERE key = 'security.bridge_service_ports' ORDER BY id").all() as Array<{ key: string; actor: string; new_value: string }>
}

const WIDEN_BODY = { install_id: ID, ports: [{ name: 'svc', port: 4007 }] }

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

beforeEach(() => {
  getDb().exec('DELETE FROM device_keys; DELETE FROM config_change_log')
  _clearDeviceKeyCacheForTest()
  mkdirSync(T.sshDir, { recursive: true, mode: 0o700 })
  writeFileSync(AUTH_KEYS, ENROLLED, { mode: 0o600 })
  setEnv(null)
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  seq.length = 0
  notified.length = 0
  for (const k of [ENABLED, UNTIL, NONCE]) delete process.env[k]
})

afterAll(() => {
  try { getDb().close() } catch { /* already closed */ }
  rmSync(T.root, { recursive: true, force: true })
})

describe('PUT /api/bridge/service-ports, token caller, switch off: 403 before the body, one WARN, nothing written', () => {
  it('a widening body and an unparseable one alike', async () => {
    for (const body of [WIDEN_BODY, '{']) {
      const before = snapshot()
      log.warn.mockClear()
      const r = await call('PUT', { auth: TOKEN, body, headers: { 'x-agent-id': 'ezermester' } })
      expect(r.handled).toBe(true)
      expect(r.status).toBe(403)
      expect(r.json()).toEqual(OFF_BODY)
      expect(r.bodyRead).toBe(false)
      expect(snapshot()).toEqual(before)
      expect(log.warn).toHaveBeenCalledTimes(1)
      const [w] = warns(REFUSED)
      expect(w?.[0]).toEqual({ caller: 'ezermester', at: expect.any(String), action: ACTION, reason: 'switch_off' })
    }
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(ENROLLED)
    expect(notified).toEqual([])
  })

  it('a process-environment ENABLED=1 does not open it (S2)', async () => {
    process.env[ENABLED] = '1'
    const r = await call('PUT', { auth: TOKEN, body: WIDEN_BODY })
    expect(r.status).toBe(403)
    expect(r.bodyRead).toBe(false)
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(ENROLLED)
  })

  it('window mode without the nonce header stays closed (S6)', async () => {
    const until = Math.floor(Date.now() / 1000) + 120
    setEnv(`${ENABLED}=1\n${UNTIL}=${until}\n${NONCE}=${'a'.repeat(43)}`)
    const r = await call('PUT', { auth: TOKEN, body: WIDEN_BODY })
    expect(r.status).toBe(403)
    expect(r.json()).toEqual(OFF_BODY)
    expect(r.bodyRead).toBe(false)
    expect(warns(REFUSED)[0]?.[0]).toMatchObject({ action: ACTION, reason: 'window_nonce_missing' })
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(ENROLLED)
  })
})

describe('PUT /api/bridge/service-ports, token caller, switch "1": today\'s answer plus the admission WARN', () => {
  beforeEach(() => setEnv(`${ENABLED}=1`))

  it('200, the permitopen list widened, one ledger row and one notification, the WARN before the body', async () => {
    const r = await call('PUT', { auth: TOKEN, body: WIDEN_BODY, headers: { 'x-agent-id': 'ezermester' } })
    expect(r.status).toBe(200)
    expect(r.json()).toEqual({ ok: true, install_id: ID, web_port: WEB_PORT, ports: [4007], reconnect_required: true })
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(WIDENED)
    expect(ledgerRows()).toEqual([expect.objectContaining({ actor: 'token' })])
    expect(notified).toHaveLength(1)
    const [w] = warns(ADMITTED)
    expect(w?.[0]).toEqual({ caller: 'ezermester', at: expect.any(String), action: ACTION, via: 'switch', mode: 'manual' })
    expect(seq.indexOf(`warn:${w![1]}`)).toBeLessThan(seq.indexOf('body'))
    expect(warns(REFUSED)).toEqual([])
  })

  it('the old validation answers are unchanged behind the open switch', async () => {
    expect((await call('PUT', { auth: TOKEN, body: '{' })).status).toBe(400)
    expect((await call('PUT', { auth: TOKEN, body: { ports: [4007] } })).status).toBe(400) // no install_id
    expect((await call('PUT', { auth: TOKEN, body: { install_id: ID, ports: [22] } })).status).toBe(400)
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(ENROLLED)
  })
})

describe('PUT /api/bridge/service-ports, other callers: unchanged whatever the switch says, no gate WARN', () => {
  for (const sw of [null, `${ENABLED}=1`]) {
    it(`session (switch ${sw ? 'on' : 'off'}): 200 and written`, async () => {
      setEnv(sw)
      const r = await call('PUT', { auth: SESSION, body: WIDEN_BODY })
      expect(r.status).toBe(200)
      expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(WIDENED)
      expect(ledgerRows()).toEqual([expect.objectContaining({ actor: 'session' })])
      expect(warns(REFUSED)).toEqual([])
      expect(warns(ADMITTED)).toEqual([])
    })

    it(`the Bridge's own bound device key (switch ${sw ? 'on' : 'off'}): 200 and written`, async () => {
      setEnv(sw)
      const minted = createDeviceKey('Bridge laptop', { installId: ID })
      const device: Auth = { kind: 'device', device: 'Bridge laptop', deviceId: minted.id, scope: 'full' }
      const r = await call('PUT', { auth: device, body: { ports: [4007] } })
      expect(r.status).toBe(200)
      expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(WIDENED)
      expect(warns(REFUSED)).toEqual([])
      expect(warns(ADMITTED)).toEqual([])
    })
  }

  it('federation and no principal keep the old 403', async () => {
    for (const auth of [{ kind: 'federation', peer: 'peer-a' } as Auth, undefined]) {
      const r = await call('PUT', { auth, body: WIDEN_BODY })
      expect(r.status).toBe(403)
      expect(r.json()).toEqual({ error: 'Forbidden for this credential type' })
    }
    expect(readFileSync(AUTH_KEYS, 'utf8')).toBe(ENROLLED)
    expect(warns(REFUSED)).toEqual([])
  })
})

describe('GET /api/bridge/service-ports is a read: not gated', () => {
  it('token caller, switch off: 200 with the current list, no gate WARN', async () => {
    const r = await call('GET', { auth: TOKEN, query: `?install_id=${ID}` })
    expect(r.status).toBe(200)
    expect(r.json()).toEqual({ ok: true, install_id: ID, web_port: WEB_PORT, ports: [] })
    expect(warns(REFUSED)).toEqual([])
  })
})
