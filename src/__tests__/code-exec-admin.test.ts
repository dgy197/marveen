// Card 89df7a00, node N1: the code-exec gate module (web/code-exec-admin.ts) and
// its install switch BEARER_CODE_EXEC_ADMIN_ENABLED. The shared Bearer (auth kind
// 'token') and a FULL device key must not create state that runs code after a
// token rotation unless the install's .env opens the switch. This file pins the
// module on its own (no route is wired yet): the switch semantics (exactly "1" in
// the .env, per request, nothing else opens it), who the gate applies to, the
// 403 body and the single WARN per decision, the audit row and the notification
// text. The route call sites are pinned in the N2-N4 suites.

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'code-exec-admin-')))
  const project = path.join(root, 'project')
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import.
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
  return { root, project, store: path.join(project, 'store') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
}))

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
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

const { admitCodeExecAdmin, execGateApplies, recordCodeExecAdmin, recordCodeExecOutcome, codeExecAuditTrail, BEARER_CODE_EXEC_ADMIN_OFF } = await import('../web/code-exec-admin.js')
const { BEARER_CODE_EXEC_ADMIN_ENV, isAdminSwitchOn, ADMIN_SWITCH_KEYS, isAdminSwitchKey } = await import('../web/admin-switch.js')
const { initDatabase, getDb, createDashboardUser } = await import('../db.js')
const { createSession, revokeSession, _clearSessionCacheForTest } = await import('../web/auth-sessions.js')
const { SESSION_COOKIE_NAME } = await import('../web/auth-gate.js')
const { formatForTelegram } = await import('../format.js')

const KEY = 'BEARER_CODE_EXEC_ADMIN_ENABLED'
const ENV_PATH = join(T.project, '.env')
const OVERRIDES = join(T.store, 'config-overrides.json')
const BASE_ENV = 'MAIN_AGENT_ID=mainbot\nBOT_NAME=Brainy\n'
const OFF_BODY = { error: 'Forbidden for this credential (BEARER_CODE_EXEC_ADMIN_ENABLED is off)', code: 'bearer_code_exec_admin_off' }
const REFUSED = /^Code-exec admin refused/
const ADMITTED = /^Code-exec admin by a gated credential/

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }
const DEVICE_OPERATOR: Auth = { kind: 'device', device: 'it-op', deviceId: 901, scope: 'operator' }
const FEDERATION: Auth = { kind: 'federation', peer: 'peer-a' }

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, BASE_ENV + (lines === null ? '' : `${lines}\n`))
}

function mkReq(headers: Record<string, string> = {}): any {
  return { headers: { ...headers } }
}

function admit(auth: Auth, headers: Record<string, string> = {}, action: Parameters<typeof admitCodeExecAdmin>[1] = 'connectors.add') {
  const out = { status: 0, raw: '', headers: {} as Record<string, string> }
  const res: any = {
    writeHead(status: number, h?: Record<string, string>) { out.status = status; out.headers = h ?? {}; return res },
    setHeader() {},
    end(chunk?: string) { if (chunk !== undefined) out.raw += chunk },
  }
  const ctx = { req: mkReq(headers), res, path: '/x', method: 'POST', url: new URL('http://127.0.0.1:3420/x'), auth } as RouteContext
  const admitted = admitCodeExecAdmin(ctx, action)
  return { admitted, status: out.status, raw: out.raw, json: () => (out.raw ? JSON.parse(out.raw) : {}) }
}

function warns(re: RegExp): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

beforeEach(() => {
  getDb().exec('DELETE FROM auth_sessions; DELETE FROM dashboard_users; DELETE FROM config_change_log')
  _clearSessionCacheForTest()
  mkdirSync(T.store, { recursive: true })
  setEnv(null)
  writeFileSync(OVERRIDES, '{}\n')
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  notified.length = 0
  delete process.env[KEY]
})

afterAll(() => {
  delete process.env[KEY]
  try { getDb().close() } catch { /* already closed */ }
  rmSync(T.root, { recursive: true, force: true })
})

describe('SW1: the switch is open only on exactly "1" in the .env', () => {
  it('the key name is the one the spec names', () => {
    expect(BEARER_CODE_EXEC_ADMIN_ENV).toBe(KEY)
    expect(BEARER_CODE_EXEC_ADMIN_OFF).toBe('bearer_code_exec_admin_off')
  })

  it.each([
    [`${KEY}=1`, true],
    [`${KEY}="1"`, true],
    [`${KEY}='1'`, true],
    [`${KEY}=1 `, true], // trailing space is trimmed by the .env parser, as for every other switch
    [null, false], // key missing
    [`${KEY}=`, false],
    [`${KEY}=true`, false],
    [`${KEY}=yes`, false],
    [`${KEY}=on`, false],
    [`${KEY}=01`, false],
    [`${KEY}=0`, false],
    [`${KEY}=" 1"`, false],
    [`${KEY.toLowerCase()}=1`, false],
    [`${KEY}_X=1`, false],
    [`# ${KEY}=1`, false],
  ] as const)('.env line %j -> open: %s', (line, open) => {
    setEnv(line)
    expect(isAdminSwitchOn(KEY)).toBe(open)
    const r = admit(TOKEN)
    expect(r.admitted).toBe(open)
    expect(r.status).toBe(open ? 0 : 403)
  })

  it('the process environment does not open it', () => {
    process.env[KEY] = '1'
    expect(isAdminSwitchOn(KEY)).toBe(false)
    expect(admit(TOKEN).admitted).toBe(false)
  })

  it('store/config-overrides.json (the Settings page writes it) does not open it', () => {
    writeFileSync(OVERRIDES, JSON.stringify({ [KEY]: '1', [KEY.toLowerCase()]: '1', bearer_code_exec_admin_enabled: true }))
    expect(isAdminSwitchOn(KEY)).toBe(false)
    expect(admit(TOKEN).admitted).toBe(false)
  })

  it('the credential switch is a different key and does not open this one', () => {
    setEnv('BEARER_CREDENTIAL_ADMIN_ENABLED=1')
    expect(admit(TOKEN).admitted).toBe(false)
  })

  it('there is no window mode: UNTIL and NONCE lines change nothing', () => {
    setEnv(`${KEY}=1\n${KEY}_UNTIL=1\n${KEY}_NONCE=x`)
    expect(admit(TOKEN, { 'x-credential-window': 'x' }).admitted).toBe(true)
    setEnv(`${KEY}_UNTIL=9999999999\n${KEY}_NONCE=${'a'.repeat(43)}`)
    expect(admit(TOKEN, { 'x-credential-window': 'a'.repeat(43) }).admitted).toBe(false)
  })

  it('a change of the .env between two requests is followed by the second one', () => {
    setEnv(null)
    expect(admit(TOKEN).admitted).toBe(false)
    setEnv(`${KEY}=1`)
    expect(admit(TOKEN).admitted).toBe(true)
    setEnv(`${KEY}=0`)
    expect(admit(TOKEN).admitted).toBe(false)
    rmSync(ENV_PATH)
    expect(admit(TOKEN).admitted).toBe(false)
  })
})

describe('SW2: the key is a protected install key', () => {
  it('is in ADMIN_SWITCH_KEYS, also in lower case or with spaces', () => {
    expect(ADMIN_SWITCH_KEYS.has(KEY)).toBe(true)
    for (const k of [KEY, KEY.toLowerCase(), ` ${KEY} `, `${KEY}\t`, 'Bearer_Code_Exec_Admin_Enabled']) {
      expect(isAdminSwitchKey(k), JSON.stringify(k)).toBe(true)
    }
    expect(isAdminSwitchKey(`${KEY}_X`)).toBe(false)
  })
})

describe('execGateApplies: who the gate stands in front of', () => {
  function liveSessionCookie(): string {
    createDashboardUser('owner', 'hash')
    const u = getDb().prepare('SELECT id FROM dashboard_users WHERE username = ?').get('owner') as { id: number }
    return `${SESSION_COOKIE_NAME}=${createSession({ userId: u.id, username: 'owner' })}`
  }

  it('a bare token: applies', () => {
    expect(execGateApplies(TOKEN, mkReq())).toBe(true)
    expect(execGateApplies(TOKEN, undefined)).toBe(true)
  })

  it('a token that also carries a live session cookie is the owner: does not apply', () => {
    const cookie = liveSessionCookie()
    expect(execGateApplies(TOKEN, mkReq({ cookie }))).toBe(false)
  })

  it('a token with an expired or revoked session cookie: applies', () => {
    const cookie = liveSessionCookie()
    revokeSession(cookie.slice(SESSION_COOKIE_NAME.length + 1))
    expect(execGateApplies(TOKEN, mkReq({ cookie }))).toBe(true)
  })

  it('a token with a forged session cookie: applies', () => {
    expect(execGateApplies(TOKEN, mkReq({ cookie: `${SESSION_COOKIE_NAME}=forged` }))).toBe(true)
  })

  it('a full device key (K2): applies, with or without a cookie', () => {
    expect(execGateApplies(DEVICE_FULL, mkReq())).toBe(true)
    expect(execGateApplies(DEVICE_FULL, undefined)).toBe(true)
    expect(execGateApplies(DEVICE_FULL, mkReq({ cookie: liveSessionCookie() }))).toBe(true)
  })

  it('a device key without a scope is treated as full: applies', () => {
    expect(execGateApplies({ kind: 'device', device: 'old', deviceId: 5 }, mkReq())).toBe(true)
  })

  it('a session, an operator-scoped key, federation and no principal: do not apply', () => {
    expect(execGateApplies(SESSION, mkReq())).toBe(false)
    expect(execGateApplies(DEVICE_OPERATOR, mkReq())).toBe(false)
    expect(execGateApplies(FEDERATION, mkReq())).toBe(false)
    expect(execGateApplies(undefined, mkReq())).toBe(false)
  })
})

describe('admitCodeExecAdmin: the decision, the 403 and the log', () => {
  it('closed: false, the exact 403 body, exactly one WARN, no admitted WARN', () => {
    const r = admit(TOKEN, { 'x-agent-id': 'brainy' }, 'mcp_catalog.install')
    expect(r.admitted).toBe(false)
    expect(r.status).toBe(403)
    expect(r.raw).toBe(JSON.stringify(OFF_BODY))
    expect(r.json()).toEqual(OFF_BODY)
    expect(warns(REFUSED)).toHaveLength(1)
    expect(warns(ADMITTED)).toEqual([])
    const [fields, msg] = warns(REFUSED)[0]!
    expect(msg).toBe('Code-exec admin refused (BEARER_CODE_EXEC_ADMIN_ENABLED off)')
    expect(fields).toMatchObject({ caller: 'brainy', action: 'mcp_catalog.install', kind: 'token', reason: 'switch_off' })
    expect(typeof fields.at).toBe('string')
    expect(Number.isNaN(Date.parse(fields.at))).toBe(false)
    expect(Object.keys(fields).sort()).toEqual(['action', 'at', 'caller', 'kind', 'reason'])
    expect(log.warn).toHaveBeenCalledTimes(1)
  })

  it('open: true, nothing written to the response, exactly one WARN with via:"switch"', () => {
    setEnv(`${KEY}=1`)
    const r = admit(DEVICE_FULL, {}, 'schedules.exec_fields')
    expect(r.admitted).toBe(true)
    expect(r.status).toBe(0)
    expect(r.raw).toBe('')
    expect(warns(ADMITTED)).toHaveLength(1)
    expect(warns(REFUSED)).toEqual([])
    const [fields, msg] = warns(ADMITTED)[0]!
    expect(msg).toBe('Code-exec admin by a gated credential (BEARER_CODE_EXEC_ADMIN_ENABLED=1)')
    expect(fields).toMatchObject({ caller: 'unknown', action: 'schedules.exec_fields', kind: 'device', via: 'switch' })
    expect(Object.keys(fields).sort()).toEqual(['action', 'at', 'caller', 'kind', 'via'])
    expect(log.warn).toHaveBeenCalledTimes(1)
  })

  it.each([
    'connectors.add', 'mcp_catalog.install', 'connectors.github_repo.add',
    'connectors.github_repo.update', 'schedules.exec_fields', 'agents.mcp_json',
  ] as const)('action %s is logged as given', (action) => {
    admit(TOKEN, {}, action)
    expect(warns(REFUSED)[0]![0].action).toBe(action)
  })

  it('the WARN carries no request body, command, URL or env value', () => {
    // The module never receives them; the check is that nothing but the five
    // fixed fields is logged, even with a hostile header set.
    const r = admit(TOKEN, { 'x-agent-id': 'brainy', authorization: 'Bearer sekret-token', cookie: 'a=b', 'content-length': '99' })
    expect(r.admitted).toBe(false)
    const logged = JSON.stringify(log.warn.mock.calls)
    expect(logged).not.toContain('sekret-token')
    expect(logged).not.toContain('a=b')
  })

  it('the caller label is the capped, charset-reduced X-Agent-Id (log only)', () => {
    admit(TOKEN, { 'x-agent-id': 'x'.repeat(200) })
    expect(warns(REFUSED)[0]![0].caller).toBe('x'.repeat(64))
    log.warn.mockClear()
    admit(TOKEN, { 'x-agent-id': 'a b\u0007"c' })
    expect(warns(REFUSED)[0]![0].caller).toBe('a_b__c')
    log.warn.mockClear()
    admit(TOKEN, {})
    expect(warns(REFUSED)[0]![0].caller).toBe('unknown')
  })

  it('every refusal answers the same body whatever the reason for the closed switch', () => {
    const bodies = new Set<string>()
    for (const line of [null, `${KEY}=`, `${KEY}=true`, `${KEY}=0`, `${KEY}=01`]) {
      setEnv(line)
      bodies.add(admit(TOKEN).raw)
    }
    expect([...bodies]).toEqual([JSON.stringify(OFF_BODY)])
  })
})

describe('recordCodeExecAdmin: one audit row, one notification', () => {
  function auditRows(): Array<{ new_value: string; actor: string }> {
    return getDb().prepare("SELECT new_value, actor FROM config_change_log WHERE key = 'security.bearer_code_exec_admin' ORDER BY id").all() as Array<{ new_value: string; actor: string }>
  }

  it('token: actor "token", the action and subject in the row, one notification naming the switch', () => {
    recordCodeExecAdmin('connectors.add', 'my_server', TOKEN)
    expect(auditRows()).toEqual([{ new_value: 'connectors.add my_server', actor: 'token' }])
    expect(notified).toHaveLength(1)
    expect(notified[0]).toContain('BEARER_CODE_EXEC_ADMIN_ENABLED')
    expect(notified[0]).toContain('my_server')
  })

  it('no auth argument: actor "token" too; a full device key: actor "device"', () => {
    recordCodeExecAdmin('agents.mcp_json', 'sub1')
    recordCodeExecAdmin('agents.mcp_json', 'sub2', DEVICE_FULL)
    expect(auditRows().map(r => r.actor)).toEqual(['token', 'device'])
    expect(notified).toHaveLength(2)
  })

  it('underscores stay literal after formatForTelegram, no <i> tag', () => {
    recordCodeExecAdmin('mcp_catalog.install', 'my_key_name', TOKEN)
    const html = formatForTelegram(notified[0]!)
    expect(html).toContain('BEARER_CODE_EXEC_ADMIN_ENABLED')
    expect(html).toContain('mcp_catalog.install')
    expect(html).toContain('my_key_name')
    expect(html).not.toMatch(/<\/?i>/)
  })

  it('a subject with <, > and &: escaped and literal', () => {
    recordCodeExecAdmin('connectors.add', 'a_b_c<x>&y', TOKEN)
    const html = formatForTelegram(notified[0]!)
    expect(html).toContain('a_b_c&lt;x&gt;&amp;y')
    expect(html).not.toContain('<x>')
    expect(html).not.toMatch(/<\/?i>/)
  })

  it('a backtick or newline in the subject cannot break out of the code span', () => {
    recordCodeExecAdmin('connectors.add', 'ev`il\nline_two', TOKEN)
    const html = formatForTelegram(notified[0]!)
    expect(html).not.toMatch(/<\/?i>/)
    expect(html).toContain('line_two')
    // Exactly the three intended code spans (action, subject, switch name).
    expect(html.match(/<code>/g)).toHaveLength(3)
  })
})

// Card 89df7a00 N6 (BE B2 / E3): the start is recorded before the first write, the
// outcome (ok / failed) after it.
describe('recordCodeExecOutcome / codeExecAuditTrail: start before the write, outcome after', () => {
  function auditRows(): Array<{ new_value: string; actor: string }> {
    return getDb().prepare("SELECT new_value, actor FROM config_change_log WHERE key = 'security.bearer_code_exec_admin' ORDER BY id").all() as Array<{ new_value: string; actor: string }>
  }

  it('ok: one row, NO notification', () => {
    recordCodeExecOutcome('agents.import', 'sub1', 'ok', TOKEN)
    expect(auditRows()).toEqual([{ new_value: 'agents.import sub1 -> ok', actor: 'token' }])
    expect(notified).toEqual([])
  })

  it('failed: one row with the error CLASS and one notification; a full device key is actor "device"', () => {
    class BoomError extends Error { constructor(m: string) { super(m); this.name = 'BoomError' } }
    recordCodeExecOutcome('agents.import', 'sub1', 'failed', DEVICE_FULL, new BoomError('/secret/path curl evil.example'))
    expect(auditRows()).toEqual([{ new_value: 'agents.import sub1 -> failed (BoomError)', actor: 'device' }])
    expect(notified).toHaveLength(1)
    expect(notified[0]).toContain('BoomError')
    expect(notified[0]).toContain('agents.import')
    expect(notified[0]).not.toMatch(/secret|curl|evil/)
  })

  it('the error class is a plain identifier: a hostile or missing name collapses to "Error"', () => {
    const odd = new Error('x'); odd.name = 'bad name; rm -rf /'
    recordCodeExecOutcome('agents.import', 'a', 'failed', TOKEN, odd)
    recordCodeExecOutcome('agents.import', 'b', 'failed', TOKEN, 'a thrown string with a path /etc/x')
    recordCodeExecOutcome('agents.import', 'c', 'failed', TOKEN)
    expect(auditRows().map(r => r.new_value)).toEqual([
      'agents.import a -> failed (Error)',
      'agents.import b -> failed (Error)',
      'agents.import c -> failed (Error)',
    ])
    expect(notified.join('\n')).not.toMatch(/rm -rf|\/etc\/x|bad name/)
  })

  it('the failed text keeps the underscore-safe code spans (formatForTelegram: no <i>)', () => {
    recordCodeExecOutcome('mcp_catalog.install', 'my_key_name', 'failed', TOKEN, new TypeError('x'))
    const html = formatForTelegram(notified[0]!)
    expect(html).toContain('mcp_catalog.install')
    expect(html).toContain('my_key_name')
    expect(html).toContain('TypeError')
    expect(html).not.toMatch(/<\/?i>/)
  })

  it('trail: start, then ok -> two rows, one notification; the ok subject may differ from the start subject', () => {
    const t = codeExecAuditTrail(true, 'agents.import', TOKEN)
    t.start('fleet a,b')
    t.ok('fleet a')
    expect(auditRows().map(r => r.new_value)).toEqual(['agents.import fleet a,b', 'agents.import fleet a -> ok'])
    expect(notified).toHaveLength(1)
  })

  it('trail: start, then failed -> two rows, two notifications', () => {
    const t = codeExecAuditTrail(true, 'connectors.add', TOKEN)
    t.start('srv')
    t.failed(new RangeError('boom'))
    expect(auditRows().map(r => r.new_value)).toEqual(['connectors.add srv', 'connectors.add srv -> failed (RangeError)'])
    expect(notified).toHaveLength(2)
  })

  it('trail: start and the close each count once (a second start, ok or failed is a no-op)', () => {
    const t = codeExecAuditTrail(true, 'connectors.add', TOKEN)
    t.start('srv')
    t.start('srv-again')
    t.ok()
    t.failed(new Error('late'))
    t.ok()
    expect(auditRows().map(r => r.new_value)).toEqual(['connectors.add srv', 'connectors.add srv -> ok'])
    expect(notified).toHaveLength(1)
  })

  it('trail: an operation that never started records nothing on close (e.g. refused by a later gate)', () => {
    const t = codeExecAuditTrail(true, 'agents.import', TOKEN)
    t.failed(new Error('x'))
    t.ok()
    expect(auditRows()).toEqual([])
    expect(notified).toEqual([])
  })

  it('trail: an ungated caller records nothing at all', () => {
    const t = codeExecAuditTrail(false, 'agents.import', SESSION)
    t.start('sub1')
    t.ok()
    t.failed(new Error('x'))
    expect(auditRows()).toEqual([])
    expect(notified).toEqual([])
  })

  it('trail: a recording failure is logged, never thrown, and the outcome is still tried', () => {
    getDb().exec("CREATE TRIGGER n6_unit_fail BEFORE INSERT ON config_change_log BEGIN SELECT RAISE(ABORT, 'audit down'); END")
    try {
      const t = codeExecAuditTrail(true, 'connectors.add', TOKEN)
      expect(() => { t.start('srv'); t.failed(new Error('x')) }).not.toThrow()
      expect(log.error).toHaveBeenCalledTimes(2)
    } finally {
      getDb().exec('DROP TRIGGER IF EXISTS n6_unit_fail')
    }
  })
})
