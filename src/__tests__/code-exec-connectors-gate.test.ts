// Card 89df7a00, node N2: the code-exec gate on the connector routes. The four
// routes that leave a rotation-surviving, code-running entry behind are
//   A  POST  /api/connectors                      (stdio, http, sse)
//   B  POST  /api/mcp-catalog/<id>/install        (local, remote)
//   C  POST  /api/connectors/github-repos         (with and without runScripts)
//   D  PATCH /api/connectors/github-repos/<name>  (with and without a body)
// A bare shared token and a FULL device key get 403 bearer_code_exec_admin_off
// unless the install's .env opens BEARER_CODE_EXEC_ADMIN_ENABLED; the decision is
// taken BEFORE the body is read and before the catalog is looked at, so a refused
// request runs no `claude mcp`, clones nothing and writes nothing. The owner's
// session (and a token that carries a live session cookie) is never gated.
//
// The handlers run for real against a throwaway install (HOME, .env, project root
// under one mkdtemp dir, a fake `claude` first on PATH). The git clone / pull / npm
// side of C and D lives in dashboard-settings.ts and is covered by
// connector-install-scripts.test.ts; here installGitHubRepo / updateGitHubRepo are
// recording stubs, so "the stub was never called" is the proof that nothing was cloned.

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'code-exec-connectors-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  const bin = path.join(root, 'bin')
  const calls = path.join(root, 'claude-calls')
  for (const d of [project, home, bin, calls, path.join(project, 'store')]) fs.mkdirSync(d, { recursive: true })
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import, and the
  // fake claude must win on PATH before connectors.js / mcp-list.ts are imported.
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  process.env.FAKE_CLAUDE_DIR = calls
  process.env.PATH = `${bin}:${process.env.PATH}`
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
  return { root, project, home, bin, calls }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: join(T.project, 'store'),
}))

// Every log call is recorded in order next to the body reads (seq), so the suite can
// show the gate decided before the body was touched.
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

vi.mock('../web/vault.js', () => ({
  listSecrets: vi.fn(() => []),
  setSecret: vi.fn(),
  deleteSecret: vi.fn(),
  getSecret: vi.fn(() => null),
  getSecretsForEnv: vi.fn(() => ({})),
}))

vi.mock('../web/dashboard-settings.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/dashboard-settings.js')>()),
  installGitHubRepo: vi.fn(async () => ({ repo: { name: 'gate-repo' }, requiredEnvVars: [], scriptsSkipped: [] })),
  updateGitHubRepo: vi.fn(() => ({ scriptsSkipped: [] })),
  removeGitHubRepo: vi.fn(() => ({})),
}))

writeFileSync(join(T.project, 'mcp-catalog.json'), JSON.stringify([
  { id: 'fake-local', name: 'Fake local', type: 'local', command: 'npx', args: ['-y', 'pkg@1'], env: {} },
  { id: 'fake-remote', name: 'Fake remote', type: 'remote', url: 'https://example.test/mcp', transport: 'http' },
]))
writeFileSync(join(T.bin, 'claude'), `#!/bin/sh
d="$FAKE_CLAUDE_DIR"
n=$(cat "$d/n" 2>/dev/null || echo 0); n=$((n+1)); echo "$n" > "$d/n"
for a in "$@"; do printf '%s\\n' "$a"; done > "$d/argv.$n"
cat > /dev/null
exit 0
`)
chmodSync(join(T.bin, 'claude'), 0o755)

const { tryHandleConnectors } = await import('../web/routes/connectors.js')
const ds = await import('../web/dashboard-settings.js')
const { initDatabase, getDb, createDashboardUser } = await import('../db.js')
const { createSession } = await import('../web/auth-sessions.js')
const { SESSION_COOKIE_NAME } = await import('../web/auth-gate.js')

const ENV_PATH = join(T.project, '.env')
const LOCAL_CATALOG = join(T.project, 'mcp-catalog.local.json')
const CLAUDE_JSON = join(T.home, '.claude.json')
const OFF_BODY = { error: 'Forbidden for this credential (BEARER_CODE_EXEC_ADMIN_ENABLED is off)', code: 'bearer_code_exec_admin_off' }
const REFUSED = /^Code-exec admin refused/
const ADMITTED = /^Code-exec admin by a gated credential/
const AUDIT_KEY = 'security.bearer_code_exec_admin'

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }

interface Route {
  label: string
  method: 'POST' | 'PATCH'
  path: string
  body?: unknown
  action: string
  // The subject the audit row and the notification carry (metadata only).
  subject: string
}

const ROUTES: Route[] = [
  { label: 'A stdio', method: 'POST', path: '/api/connectors', body: { name: 'gate-a', type: 'stdio', command: 'node', args: 'secret-arg.js' }, action: 'connectors.add', subject: 'gate-a' },
  { label: 'A http', method: 'POST', path: '/api/connectors', body: { name: 'gate-h', type: 'http', url: 'https://example.test/secret-path' }, action: 'connectors.add', subject: 'gate-h' },
  { label: 'A sse', method: 'POST', path: '/api/connectors', body: { name: 'gate-s', type: 'sse', url: 'https://example.test/sse-secret' }, action: 'connectors.add', subject: 'gate-s' },
  { label: 'B local', method: 'POST', path: '/api/mcp-catalog/fake-local/install', body: {}, action: 'mcp_catalog.install', subject: 'fake-local' },
  { label: 'B remote', method: 'POST', path: '/api/mcp-catalog/fake-remote/install', body: {}, action: 'mcp_catalog.install', subject: 'fake-remote' },
  { label: 'C no runScripts', method: 'POST', path: '/api/connectors/github-repos', body: { url: 'https://github.com/o/gate-repo' }, action: 'connectors.github_repo.add', subject: 'gate-repo runScripts=false' },
  { label: 'C runScripts', method: 'POST', path: '/api/connectors/github-repos', body: { url: 'https://github.com/o/gate-repo', runScripts: true }, action: 'connectors.github_repo.add', subject: 'gate-repo runScripts=true' },
  { label: 'D with body', method: 'PATCH', path: '/api/connectors/github-repos/gate-repo', body: { runScripts: true }, action: 'connectors.github_repo.update', subject: 'gate-repo' },
  { label: 'D no body', method: 'PATCH', path: '/api/connectors/github-repos/gate-repo', action: 'connectors.github_repo.update', subject: 'gate-repo' },
]

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
  const handled = await tryHandleConnectors(ctx)
  return { handled, status: out.status, json: () => (out.raw ? JSON.parse(out.raw) : {}), bodyRead }
}

const callRoute = (r: Route, auth: Auth, headers?: Record<string, string>) => call(r.method, r.path, { auth, body: r.body, headers })

function warns(re: RegExp): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && re.test(c[1]))
}

function claudeCalls(): number {
  try { return Number(readFileSync(join(T.calls, 'n'), 'utf8').trim()) } catch { return 0 }
}

function auditRows(): Array<{ actor: string; new_value: string }> {
  return getDb().prepare('SELECT actor, new_value FROM config_change_log WHERE key = ? ORDER BY id').all(AUDIT_KEY) as Array<{ actor: string; new_value: string }>
}

// Everything a refused request must leave byte-identical (null = absent).
function snapshot() {
  const f = (p: string) => (existsSync(p) ? readFileSync(p, 'utf8') : null)
  return { claudeJson: f(CLAUDE_JSON), localCatalog: f(LOCAL_CATALOG), settings: f(join(T.project, 'store', 'dashboard-settings.json')), env: f(ENV_PATH) }
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
  rmSync(T.calls, { recursive: true, force: true })
  mkdirSync(T.calls, { recursive: true })
  rmSync(LOCAL_CATALOG, { force: true })
  rmSync(CLAUDE_JSON, { force: true })
  setEnv(null)
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  for (const fn of [ds.installGitHubRepo, ds.updateGitHubRepo, ds.removeGitHubRepo]) vi.mocked(fn).mockClear()
  seq.length = 0
  notified.length = 0
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
})

afterAll(() => {
  rmSync(T.root, { recursive: true, force: true })
})

describe('G1/G8: switch closed, the shared token and a full device key are refused on A-D', () => {
  for (const [who, auth] of [['token', TOKEN], ['full device key', DEVICE_FULL]] as const) {
    for (const r of ROUTES) {
      it(`${who}: ${r.label} -> 403, body unread, nothing run or written`, async () => {
        const before = snapshot()
        const res = await callRoute(r, auth)
        expect(res.handled).toBe(true)
        expect(res.status).toBe(403)
        expect(res.json()).toEqual(OFF_BODY)
        expect(res.bodyRead).toBe(false)
        expect(seq).not.toContain('body')
        expect(claudeCalls()).toBe(0)
        expect(ds.installGitHubRepo).not.toHaveBeenCalled()
        expect(ds.updateGitHubRepo).not.toHaveBeenCalled()
        expect(snapshot()).toEqual(before)
        expect(auditRows()).toEqual([])
        expect(notified).toEqual([])
        // L1: exactly one WARN for the refusal, with the action and no body content.
        const w = warns(REFUSED)
        expect(w).toHaveLength(1)
        expect(w[0][0]).toMatchObject({ action: r.action, kind: auth!.kind, reason: 'switch_off' })
        expect(JSON.stringify(w[0][0])).not.toMatch(/secret|example\.test/)
        expect(warns(ADMITTED)).toHaveLength(0)
      })
    }
  }

  it('B: an unknown catalog id gets the same 403 as a known one (no 404 oracle for the catalog)', async () => {
    const known = await call('POST', '/api/mcp-catalog/fake-local/install', { auth: TOKEN, body: {} })
    const unknown = await call('POST', '/api/mcp-catalog/does-not-exist/install', { auth: TOKEN, body: {} })
    expect(unknown.status).toBe(403)
    expect(unknown.json()).toEqual(known.json())
    expect(claudeCalls()).toBe(0)
  })

  it('the credential switch does not open the code-exec routes', async () => {
    setEnv('BEARER_CREDENTIAL_ADMIN_ENABLED=1')
    const res = await callRoute(ROUTES[0], TOKEN)
    expect(res.status).toBe(403)
    expect(res.json().code).toBe('bearer_code_exec_admin_off')
  })

  it('process.env does not open it (only the .env does)', async () => {
    process.env.BEARER_CODE_EXEC_ADMIN_ENABLED = '1'
    const res = await callRoute(ROUTES[0], TOKEN)
    expect(res.status).toBe(403)
  })
})

describe('G6/G8: switch open, the gated caller gets today\'s answer plus one WARN, one audit row, one notification', () => {
  for (const [who, auth, actor] of [['token', TOKEN, 'token'], ['full device key', DEVICE_FULL, 'device']] as const) {
    for (const r of ROUTES) {
      it(`${who}: ${r.label} -> success`, async () => {
        setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
        const res = await callRoute(r, auth)
        expect(res.status).toBe(200)
        expect(res.json().ok).toBe(true)
        const w = warns(ADMITTED)
        expect(w).toHaveLength(1)
        expect(w[0][0]).toMatchObject({ action: r.action, kind: auth!.kind, via: 'switch' })
        expect(warns(REFUSED)).toHaveLength(0)
        // N6: the start row (before the first write) and the outcome row; only the start notifies.
        expect(auditRows()).toEqual([
          { actor, new_value: `${r.action} ${r.subject}` },
          { actor, new_value: `${r.action} ${r.subject} -> ok` },
        ])
        expect(notified).toHaveLength(1)
        expect(notified[0]).toContain(r.action)
        // The subject is metadata only: no command, argument or URL path in the text.
        expect(notified[0]).not.toMatch(/secret|example\.test|node/)
        expect(log.error).not.toHaveBeenCalled()
      })
    }
  }

  it('the effect really happens when admitted (A stdio runs claude mcp add and persists the catalog entry)', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    await callRoute(ROUTES[0], TOKEN)
    expect(claudeCalls()).toBe(1)
    expect(readFileSync(join(T.calls, 'argv.1'), 'utf8')).toContain('gate-a')
    expect(existsSync(LOCAL_CATALOG)).toBe(true)
  })

  it('C/D reach the install functions only when admitted', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    await callRoute(ROUTES[5], TOKEN)
    await callRoute(ROUTES[7], TOKEN)
    expect(ds.installGitHubRepo).toHaveBeenCalledTimes(1)
    expect(ds.updateGitHubRepo).toHaveBeenCalledTimes(1)
  })

  it('N6: a failing install by a gated caller keeps its start row and ends with a failed row and a second notification', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    vi.mocked(ds.installGitHubRepo).mockResolvedValueOnce({ error: 'clone failed MARKER-CLONE-ERR' } as any)
    const res = await callRoute(ROUTES[5], TOKEN)
    expect(res.status).toBe(400)
    expect(auditRows().map(r => r.new_value)).toEqual([
      'connectors.github_repo.add gate-repo runScripts=false',
      'connectors.github_repo.add gate-repo runScripts=false -> failed (Error)',
    ])
    expect(notified).toHaveLength(2)
    expect(notified.join('\n')).not.toContain('MARKER-CLONE-ERR')
  })

  it('the switch is read per request: closing the .env again refuses the next call', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    expect((await callRoute(ROUTES[1], TOKEN)).status).toBe(200)
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=true')
    expect((await callRoute(ROUTES[1], TOKEN)).status).toBe(403)
  })
})

// N6 (BE E3, B2 class): the audit row and the notification come BEFORE the first write; the
// outcome closes the pair in a catch/finally path. Error messages, commands, env values
// and URLs never reach a row or a notification.
describe('N6: start before the first write, outcome after (ok / failed)', () => {
  const MARK = 'MARKER-ERR-7f3a'
  const ENV_VALUE = 'env-value-9c1e'
  const rows = () => auditRows().map(r => r.new_value)
  const noLeak = () => {
    const all = JSON.stringify(auditRows()) + notified.join('\n')
    for (const bad of [MARK, ENV_VALUE, 'secret-arg', 'example.test', 'node']) expect(all, bad).not.toContain(bad)
  }

  it('A stdio: the env vaulting throws after `claude mcp add` -> start + failed, 2 notifications, 500 stays', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const vault = await import('../web/vault.js')
    vi.mocked(vault.setSecret).mockImplementationOnce(() => { throw new Error(`vault write failed ${MARK} ${ENV_VALUE}`) })
    const res = await call('POST', '/api/connectors', {
      auth: TOKEN,
      body: { name: 'gate-a', type: 'stdio', command: 'node', args: 'secret-arg.js', env: { API_KEY: ENV_VALUE } },
    })
    expect(res.status).toBe(500)
    expect(claudeCalls()).toBe(1) // the write really happened before the throw
    expect(rows()).toEqual(['connectors.add gate-a', 'connectors.add gate-a -> failed (Error)'])
    expect(notified).toHaveLength(2)
    expect(notified[1]).toContain('connectors.add')
    noLeak()
  })

  it('B local: the env vaulting throws -> start + failed, 2 notifications, 500 stays', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const vault = await import('../web/vault.js')
    vi.mocked(vault.setSecret).mockImplementationOnce(() => { throw new Error(`vault write failed ${MARK} ${ENV_VALUE}`) })
    const res = await call('POST', '/api/mcp-catalog/fake-local/install', { auth: TOKEN, body: { env: { API_KEY: ENV_VALUE } } })
    expect(res.status).toBe(500)
    expect(rows()).toEqual(['mcp_catalog.install fake-local', 'mcp_catalog.install fake-local -> failed (Error)'])
    expect(notified).toHaveLength(2)
    noLeak()
  })

  it('A stdio, no secrets: success -> start + ok, one notification', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const res = await call('POST', '/api/connectors', { auth: TOKEN, body: { name: 'gate-a', type: 'stdio', command: 'node', args: 'secret-arg.js' } })
    expect(res.status).toBe(200)
    expect(rows()).toEqual(['connectors.add gate-a', 'connectors.add gate-a -> ok'])
    expect(notified).toHaveLength(1)
    noLeak()
  })

  it('A: a body that is refused as invalid (400) before any write leaves no row and no notification', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const res = await call('POST', '/api/connectors', { auth: TOKEN, body: { name: 'gate-x', type: 'stdio' } })
    expect(res.status).toBe(400)
    expect(claudeCalls()).toBe(0)
    expect(auditRows()).toEqual([])
    expect(notified).toEqual([])
  })

  it('C: the start row is already there when the clone runs; a throw is recorded and still propagates', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    let rowsAtClone = -1
    vi.mocked(ds.installGitHubRepo).mockImplementationOnce(async () => {
      rowsAtClone = auditRows().length
      const e = new Error(`clone exploded ${MARK}`)
      e.name = 'CloneBoomError'
      throw e
    })
    await expect(callRoute(ROUTES[5], TOKEN)).rejects.toThrow('clone exploded')
    expect(rowsAtClone).toBe(1)
    expect(rows()).toEqual([
      'connectors.github_repo.add gate-repo runScripts=false',
      'connectors.github_repo.add gate-repo runScripts=false -> failed (CloneBoomError)',
    ])
    expect(notified).toHaveLength(2)
    noLeak()
  })

  it('C: the audit subject comes from the URL\'s last segment, never the URL (no user, host or token)', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    vi.mocked(ds.installGitHubRepo).mockResolvedValueOnce({ error: 'x' } as any)
    await call('POST', '/api/connectors/github-repos', { auth: TOKEN, body: { url: 'https://user:tok-secret@example.test/o/my-repo.git?x=1' } })
    expect(rows()[0]).toBe('connectors.github_repo.add my-repo runScripts=false')
    expect(notified.join('\n')).not.toMatch(/tok-secret|example\.test/)
  })

  it('D: the start row is already there when the pull runs; a throw is recorded and still propagates', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    let rowsAtPull = -1
    vi.mocked(ds.updateGitHubRepo).mockImplementationOnce(() => {
      rowsAtPull = auditRows().length
      throw new Error(`pull exploded ${MARK}`)
    })
    await expect(callRoute(ROUTES[7], TOKEN)).rejects.toThrow('pull exploded')
    expect(rowsAtPull).toBe(1)
    expect(rows()).toEqual(['connectors.github_repo.update gate-repo', 'connectors.github_repo.update gate-repo -> failed (Error)'])
    expect(notified).toHaveLength(2)
    noLeak()
  })

  it('a recording failure is logged and does not change the answer', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    getDb().exec("CREATE TRIGGER n6_fail_insert BEFORE INSERT ON config_change_log BEGIN SELECT RAISE(ABORT, 'n6 audit down'); END")
    try {
      const res = await callRoute(ROUTES[1], TOKEN)
      expect(res.status).toBe(200)
      expect(res.json().ok).toBe(true)
      expect(log.error).toHaveBeenCalled()
    } finally {
      getDb().exec('DROP TRIGGER IF EXISTS n6_fail_insert')
    }
  })
})

describe('G7: the owner\'s session is never gated, whatever the switch says', () => {
  for (const r of ROUTES) {
    it(`session: ${r.label} -> success, no gate WARN, no audit, no notification`, async () => {
      const res = await callRoute(r, SESSION)
      expect(res.status).toBe(200)
      expect(warns(REFUSED)).toHaveLength(0)
      expect(warns(ADMITTED)).toHaveLength(0)
      expect(auditRows()).toEqual([])
      expect(notified).toEqual([])
    })

    it(`token carrying a live session cookie: ${r.label} -> same as the session`, async () => {
      const res = await callRoute(r, TOKEN, { cookie: liveSessionCookie() })
      expect(res.status).toBe(200)
      expect(warns(REFUSED)).toHaveLength(0)
      expect(warns(ADMITTED)).toHaveLength(0)
      expect(auditRows()).toEqual([])
      expect(notified).toEqual([])
    })
  }

  it('a token with a forged session cookie is still gated', async () => {
    const res = await callRoute(ROUTES[0], TOKEN, { cookie: `${SESSION_COOKIE_NAME}=forged` })
    expect(res.status).toBe(403)
  })
})

describe('G9: what takes entries away, or reads, stays open to the shared token with the switch closed', () => {
  it('DELETE github-repos/<name> is not gated', async () => {
    const res = await call('DELETE', '/api/connectors/github-repos/gate-repo', { auth: TOKEN })
    expect(res.status).toBe(200)
    expect(ds.removeGitHubRepo).toHaveBeenCalledTimes(1)
    expect(warns(REFUSED)).toHaveLength(0)
  })

  it('DELETE mcp-catalog/<id>/uninstall is not gated', async () => {
    const res = await call('DELETE', '/api/mcp-catalog/fake-local/uninstall', { auth: TOKEN })
    expect(res.status).not.toBe(403)
    expect(warns(REFUSED)).toHaveLength(0)
  })

  it('DELETE connectors/<name> is not gated', async () => {
    const res = await call('DELETE', '/api/connectors/gate-a', { auth: TOKEN })
    expect(res.status).not.toBe(403)
    expect(warns(REFUSED)).toHaveLength(0)
  })
})
