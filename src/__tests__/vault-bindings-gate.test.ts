// Card 24e137ef, node N2 (CX1): POST /api/vault/bindings.
//  - gate: a bare shared token and a FULL device key get 403 bearer_code_exec_admin_off
//    unless the install's .env opens BEARER_CODE_EXEC_ADMIN_ENABLED; decided BEFORE the body
//    is read, so a refused request writes neither store/vault-bindings.json nor any .mcp.json.
//    The owner's session is never gated.
//  - validation, for EVERY caller: the binding key (no process-start env names such as
//    NODE_OPTIONS / LD_PRELOAD), the header scheme, and every target file (must be one of the
//    known MCP config files, not a symlink, not a stranger JSON file) are checked before any write.
// The handler runs for real against a throwaway install (HOME, .env, project root under one
// mkdtemp dir); the vault itself is a stub that holds one secret.

import { describe, it, expect, beforeAll, beforeEach, afterAll, vi } from 'vitest'
import { existsSync, mkdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'vault-bindings-gate-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  const outside = path.join(root, 'outside')
  for (const d of [project, home, outside, path.join(project, 'store'), path.join(project, 'agents', 'alpha')]) {
    fs.mkdirSync(d, { recursive: true })
  }
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import.
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
  return { root, project, home, outside }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: join(T.project, 'store'),
}))

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

const notified = vi.hoisted(() => [] as string[])
vi.mock('../notify.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../notify.js')>()),
  notifySecurityEvent: async (text: string) => { notified.push(text) },
}))

const SECRET_VALUE = 'SECRET-VALUE-never-logged-5d21'
vi.mock('../web/vault.js', () => ({
  listSecrets: vi.fn(() => []),
  setSecret: vi.fn(),
  deleteSecret: vi.fn(),
  getSecret: vi.fn((id: string) => (id === 'minicrm' ? SECRET_VALUE : null)),
  getSecretsForEnv: vi.fn(() => ({})),
}))

const { tryHandleConnectors } = await import('../web/routes/connectors.js')
const vb = await import('../web/vault-bindings.js')
const { initDatabase, getDb } = await import('../db.js')

const ENV_PATH = join(T.project, '.env')
const BINDINGS = join(T.project, 'store', 'vault-bindings.json')
const PROJECT_MCP = join(T.project, '.mcp.json')
const AGENT_MCP = join(T.project, 'agents', 'alpha', '.mcp.json')
const STRANGER = join(T.outside, 'stranger.json')
const OFF_BODY = { error: 'Forbidden for this credential (BEARER_CODE_EXEC_ADMIN_ENABLED is off)', code: 'bearer_code_exec_admin_off' }
const AUDIT_KEY = 'security.bearer_code_exec_admin'
const MCP_FIXTURE = JSON.stringify({ mcpServers: { srv: { command: 'node', args: ['srv.js'] } } }, null, 2)

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const SESSION: Auth = { kind: 'session', user: 'owner' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'phone', deviceId: 900, scope: 'full' }

function setEnv(lines: string | null): void {
  writeFileSync(ENV_PATH, 'MAIN_AGENT_ID=mainbot\n' + (lines === null ? '' : `${lines}\n`))
}

async function post(auth: Auth, body: unknown) {
  const out = { status: 0, raw: '' }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() {},
    end(chunk?: string) { if (chunk !== undefined) out.raw += chunk },
  }
  const raw = JSON.stringify(body)
  let bodyRead = false
  const req: any = {
    headers: {},
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (!bodyRead) { bodyRead = true; seq.push('body') }
      if (event === 'data') cb(Buffer.from(raw))
      if (event === 'end') cb()
      return req
    },
    destroy() {},
  }
  const path = '/api/vault/bindings'
  const ctx = { req, res, path, method: 'POST', url: new URL(`http://127.0.0.1:3420${path}`), auth } as RouteContext
  const handled = await tryHandleConnectors(ctx)
  return { handled, status: out.status, json: () => (out.raw ? JSON.parse(out.raw) : {}), bodyRead }
}

const read = (p: string) => (existsSync(p) ? readFileSync(p, 'utf8') : null)
// Everything a refused request must leave byte-identical (null = absent).
const snapshot = () => ({ bindings: read(BINDINGS), project: read(PROJECT_MCP), agent: read(AGENT_MCP), stranger: read(STRANGER) })
const auditRows = () => getDb().prepare('SELECT actor, new_value FROM config_change_log WHERE key = ? ORDER BY id').all(AUDIT_KEY) as Array<{ actor: string; new_value: string }>
const GOOD = { vaultSecretId: 'minicrm', envVar: 'MINICRM_API_KEY', targets: [{ mcpFilePath: PROJECT_MCP, serverName: 'srv' }] }

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

beforeEach(() => {
  getDb().exec('DELETE FROM config_change_log')
  rmSync(BINDINGS, { force: true })
  rmSync(join(T.home, '.claude.json'), { force: true })
  rmSync(join(T.project, 'agents', 'linky'), { recursive: true, force: true })
  writeFileSync(PROJECT_MCP, MCP_FIXTURE)
  writeFileSync(AGENT_MCP, MCP_FIXTURE)
  writeFileSync(STRANGER, MCP_FIXTURE)
  setEnv(null)
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  seq.length = 0
  notified.length = 0
  delete process.env.BEARER_CODE_EXEC_ADMIN_ENABLED
})

afterAll(() => {
  rmSync(T.root, { recursive: true, force: true })
})

describe('gate: switch closed, the shared token and a full device key are refused', () => {
  for (const [who, auth] of [['token', TOKEN], ['full device key', DEVICE_FULL]] as const) {
    it(`${who}: 403, body unread, no binding file and no .mcp.json touched`, async () => {
      const before = snapshot()
      const res = await post(auth, GOOD)
      expect(res.handled).toBe(true)
      expect(res.status).toBe(403)
      expect(res.json()).toEqual(OFF_BODY)
      expect(res.bodyRead).toBe(false)
      expect(seq).not.toContain('body')
      expect(snapshot()).toEqual(before)
      expect(before.bindings).toBeNull()
      expect(auditRows()).toEqual([])
      expect(notified).toEqual([])
    })
  }

  it('the refusal beats the validation: a bad body from a gated caller is 403, not 400', async () => {
    const res = await post(TOKEN, { ...GOOD, envVar: 'NODE_OPTIONS' })
    expect(res.status).toBe(403)
  })
})

describe('gate: switch open, session', () => {
  it('token with the switch open -> 200, the binding and the vault reference are written, one start and one ok row', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const res = await post(TOKEN, GOOD)
    expect(res.status).toBe(200)
    expect(res.json()).toMatchObject({ ok: true, synced: 1, errors: [] })
    expect(JSON.parse(read(BINDINGS)!).bindings).toHaveLength(1)
    expect(JSON.parse(read(PROJECT_MCP)!).mcpServers.srv.env.MINICRM_API_KEY).toBe('vault:minicrm')
    expect(auditRows()).toEqual([
      { actor: 'token', new_value: 'vault.bindings.add minicrm srv' },
      { actor: 'token', new_value: 'vault.bindings.add minicrm srv -> ok' },
    ])
    expect(notified).toHaveLength(1)
    // metadata only: ids, never the secret value
    expect(JSON.stringify([...notified, ...log.warn.mock.calls, ...log.info.mock.calls])).not.toContain(SECRET_VALUE)
  })

  it('a refused validation of an admitted gated caller leaves no start row and no file change', async () => {
    setEnv('BEARER_CODE_EXEC_ADMIN_ENABLED=1')
    const before = snapshot()
    const res = await post(TOKEN, { ...GOOD, envVar: 'NODE_OPTIONS' })
    expect(res.status).toBe(400)
    expect(snapshot()).toEqual(before)
    expect(auditRows()).toEqual([])
  })

  it('session -> 200 without the switch, no audit row, no code-exec WARN', async () => {
    const res = await post(SESSION, GOOD)
    expect(res.status).toBe(200)
    expect(res.json().ok).toBe(true)
    expect(JSON.parse(read(PROJECT_MCP)!).mcpServers.srv.env.MINICRM_API_KEY).toBe('vault:minicrm')
    expect(auditRows()).toEqual([])
    expect(log.warn.mock.calls.filter((c: any[]) => /Code-exec admin/.test(String(c[1])))).toHaveLength(0)
  })

  it('session: server-name discovery (no explicit targets) still binds into the known files', async () => {
    const res = await post(SESSION, { vaultSecretId: 'minicrm', envVar: 'MINICRM_API_KEY', serverName: 'srv' })
    expect(res.status).toBe(200)
    expect(res.json().synced).toBe(2)
    expect(JSON.parse(read(AGENT_MCP)!).mcpServers.srv.env.MINICRM_API_KEY).toBe('vault:minicrm')
  })

  it('session: a header binding with a clean name and scheme still works', async () => {
    const res = await post(SESSION, { vaultSecretId: 'minicrm', headerName: 'Authorization', headerScheme: 'Bearer', targets: GOOD.targets })
    expect(res.status).toBe(200)
    expect(JSON.parse(read(PROJECT_MCP)!).mcpServers.srv.headersHelper).toContain('Authorization=Bearer:::minicrm')
  })
})

describe('validation (session caller): refused before any write', () => {
  const LONG = 'A'.repeat(129)
  for (const bad of ['NODE_OPTIONS', 'ld_preload', 'DYLD_INSERT_LIBRARIES', 'PATH', 'lower-case', LONG, 'PYTHONSTARTUP', 'GIT_SSH_COMMAND', 'NPM_CONFIG_REGISTRY', 'BASH_ENV']) {
    it(`envVar ${bad.length > 40 ? `(${bad.length} chars)` : bad} -> 400, files byte-identical`, async () => {
      const before = snapshot()
      const res = await post(SESSION, { ...GOOD, envVar: bad })
      expect(res.status).toBe(400)
      expect(snapshot()).toEqual(before)
    })
  }

  it('MINICRM_API_KEY is accepted', async () => {
    expect((await post(SESSION, GOOD)).status).toBe(200)
  })

  it('a bad headerName and a bad headerScheme -> 400', async () => {
    const before = snapshot()
    expect((await post(SESSION, { vaultSecretId: 'minicrm', headerName: 'Bad Header', targets: GOOD.targets })).status).toBe(400)
    expect((await post(SESSION, { vaultSecretId: 'minicrm', headerName: 'Authorization', headerScheme: 'Bear er;x', targets: GOOD.targets })).status).toBe(400)
    expect(snapshot()).toEqual(before)
  })

  it('non-string fields -> 400, not a 500', async () => {
    const res = await post(SESSION, { ...GOOD, envVar: 42 })
    expect(res.status).toBe(400)
  })

  it('an mcpFilePath outside the known list (a stranger JSON file with mcpServers) -> 400, file byte-identical', async () => {
    const before = snapshot()
    const res = await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: STRANGER, serverName: 'srv' }] })
    expect(res.status).toBe(400)
    expect(snapshot()).toEqual(before)
    expect(before.bindings).toBeNull()
  })

  it('a non-existing file and a path with a NUL -> 400', async () => {
    const missing = join(T.project, 'agents', 'alpha', 'projects', 'nope', '.mcp.json')
    expect((await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: missing, serverName: 'srv' }] })).status).toBe(400)
    expect((await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: PROJECT_MCP + '\0x', serverName: 'srv' }] })).status).toBe(400)
  })

  it('a symlink planted in a known directory pointing elsewhere -> 400, the real target untouched', async () => {
    const linkDir = join(T.project, 'agents', 'linky')
    mkdirSync(linkDir, { recursive: true })
    const link = join(linkDir, '.mcp.json')
    symlinkSync(STRANGER, link)
    const before = snapshot()
    const res = await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: link, serverName: 'srv' }] })
    expect(res.status).toBe(400)
    expect(snapshot()).toEqual(before)
    // discovery by server name must not follow the planted link either
    const viaName = await post(SESSION, { vaultSecretId: 'minicrm', envVar: 'MINICRM_API_KEY', serverName: 'srv' })
    expect(viaName.status).toBe(400)
    expect(read(STRANGER)).toBe(MCP_FIXTURE)
  })

  it('a symlink pointing AT a known file is refused too (the listed path is the only way in)', async () => {
    const link = join(T.outside, 'to-project-mcp.json')
    rmSync(link, { force: true })
    symlinkSync(PROJECT_MCP, link)
    const res = await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: link, serverName: 'srv' }] })
    expect(res.status).toBe(400)
    expect(read(PROJECT_MCP)).toBe(MCP_FIXTURE)
  })

  it('serverName __proto__ -> 400 (no prototype write)', async () => {
    const res = await post(SESSION, { ...GOOD, targets: [{ mcpFilePath: PROJECT_MCP, serverName: '__proto__' }] })
    expect(res.status).toBe(400)
    expect(({} as any).env).toBeUndefined()
  })
})

describe('pure validators', () => {
  it('validateBindingKey(env): allowed and denied names, case-insensitive', () => {
    expect(vb.validateBindingKey('env', 'MINICRM_API_KEY')).toBeNull()
    expect(vb.validateBindingKey('env', '_X1')).toBeNull()
    expect(vb.validateBindingKey('env', 'A'.repeat(128))).toBeNull()
    expect(vb.validateBindingKey('env', 'A'.repeat(129))).not.toBeNull()
    for (const bad of ['', '1ABC', 'lower', 'A-B', 'A B', 'A\nB']) expect(vb.validateBindingKey('env', bad), bad).not.toBeNull()
    for (const denied of ['PATH', 'path', 'Node_Options', 'NODE_PATH', 'BASH_ENV', 'ENV', 'SHELL', 'HOME', 'IFS', 'PROMPT_COMMAND',
      'LD_PRELOAD', 'ld_library_path', 'DYLD_INSERT_LIBRARIES', 'PYTHONPATH', 'PYTHONSTARTUP', 'PERL5LIB', 'PERL5OPT',
      'RUBYOPT', 'RUBYLIB', 'GIT_SSH_COMMAND', 'GIT_ASKPASS', 'NPM_CONFIG_REGISTRY', 'npm_config_prefix']) {
      expect(vb.validateBindingKey('env', denied), denied).toMatch(/not allowed/)
    }
    // look-alikes that are not on the list
    for (const fine of ['PATHS', 'MY_PATH', 'HOMEPAGE_URL', 'ENVIRONMENT', 'GITHUB_TOKEN', 'NPM_TOKEN', 'LDAP_PASSWORD']) {
      expect(vb.validateBindingKey('env', fine), fine).toBeNull()
    }
    expect(vb.validateBindingKey('env', 5)).not.toBeNull()
  })

  // Card 24e137ef B2: interpreter / runtime injection, proxy and CA redirection,
  // shell and config-root relocation. Asserts the rejection, not its message: the
  // lower-case forms may be refused by the name regex instead of the denylist.
  it('validateBindingKey(env): the widened denylist refuses every injection name, in any case', () => {
    const exact = [
      'PERLLIB', 'JAVA_TOOL_OPTIONS', '_JAVA_OPTIONS', 'JDK_JAVA_OPTIONS', 'CLASSPATH', 'ZDOTDIR',
      'HTTPS_PROXY', 'HTTP_PROXY', 'ALL_PROXY', 'NO_PROXY',
      'SSL_CERT_FILE', 'SSL_CERT_DIR', 'REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE',
      'GEM_HOME', 'GEM_PATH', 'ELECTRON_RUN_AS_NODE', 'TMPDIR', 'CLAUDE_CONFIG_DIR', 'ANTHROPIC_BASE_URL',
    ]
    const prefixed = [
      'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_ANYTHING',
      'RUBY', 'RUBYOPT', 'RUBYLIB', 'RUBY_ANYTHING', 'PIP_INDEX_URL', 'PIP_EXTRA_INDEX_URL', 'UV_INDEX_URL', 'UV_PYTHON', 'XDG_CONFIG_HOME', 'XDG_DATA_DIRS',
    ]
    for (const name of [...exact, ...prefixed]) {
      for (const variant of [name, name.toLowerCase(), name[0] + name.slice(1).toLowerCase()]) {
        expect(vb.validateBindingKey('env', variant), variant).not.toBeNull()
      }
    }
    // the exact names are refused by the denylist itself in their canonical case
    for (const name of [...exact, ...prefixed]) expect(vb.validateBindingKey('env', name), name).toMatch(/not allowed/)
    // look-alikes that must stay usable
    for (const fine of ['TMPDIR_NAME', 'MY_CLASSPATH', 'PROXY_URL', 'HTTPS_PROXY_USER', 'SSL_CERT_PASSWORD', 'UVICORN_PORT', 'PIPELINE_TOKEN', 'NODEMAILER_KEY', 'XDGTOKEN', 'GEM_API_KEY']) {
      expect(vb.validateBindingKey('env', fine), fine).toBeNull()
    }
  })

  it('validateBindingKey(header)', () => {
    for (const ok of ['Authorization', 'X-Api-Key', 'x', 'A'.repeat(128)]) expect(vb.validateBindingKey('header', ok), ok).toBeNull()
    for (const bad of ['', 'Bad Header', 'A_B', 'A:B', 'A\r\nB', 'A'.repeat(129)]) expect(vb.validateBindingKey('header', bad), bad).not.toBeNull()
    // env-name denials do not apply to a header name
    expect(vb.validateBindingKey('header', 'Path')).toBeNull()
  })

  it('validateHeaderScheme', () => {
    for (const ok of [undefined, null, '', 'Bearer', 'Token', 'A'.repeat(32)]) expect(vb.validateHeaderScheme(ok), String(ok)).toBeNull()
    for (const bad of ['A'.repeat(33), 'Bear er', 'Bearer;', 'B3arer', '$(x)', 7]) expect(vb.validateHeaderScheme(bad), String(bad)).not.toBeNull()
  })

  it('validateServerName', () => {
    expect(vb.validateServerName('minicrm')).toBeNull()
    for (const bad of ['', '__proto__', 'constructor', 'prototype', 3, undefined, 'x'.repeat(257)]) expect(vb.validateServerName(bad), String(bad)).not.toBeNull()
  })

  it('resolveKnownMcpFile / validateBindingTargets work off the injected known list', () => {
    const known = [{ path: PROJECT_MCP }, { path: join(T.project, 'agents', 'alpha', 'missing.json') }]
    expect(vb.resolveKnownMcpFile(PROJECT_MCP, known)).toBe(PROJECT_MCP)
    // a different spelling of the same real file resolves to the listed spelling
    expect(vb.resolveKnownMcpFile(join(T.project, 'agents', '..', '.mcp.json'), known)).toBe(PROJECT_MCP)
    expect(vb.resolveKnownMcpFile(STRANGER, known)).toBeNull()
    expect(vb.resolveKnownMcpFile(join(T.project, 'agents', 'alpha', 'missing.json'), known)).toBeNull()
    expect(vb.resolveKnownMcpFile(undefined, known)).toBeNull()
    expect(vb.resolveKnownMcpFile('', known)).toBeNull()

    expect(vb.validateBindingTargets([{ mcpFilePath: PROJECT_MCP, serverName: 'srv' }], known))
      .toEqual({ targets: [{ mcpFilePath: PROJECT_MCP, serverName: 'srv' }] })
    expect(vb.validateBindingTargets([{ mcpFilePath: STRANGER, serverName: 'srv' }], known).error).toMatch(/known MCP config file/)
    expect(vb.validateBindingTargets('nope', known).error).toMatch(/array/)
    expect(vb.validateBindingTargets([null], known).error).toBeTruthy()
    // one bad target refuses the whole request
    expect(vb.validateBindingTargets([{ mcpFilePath: PROJECT_MCP, serverName: 'srv' }, { mcpFilePath: STRANGER, serverName: 'srv' }], known).targets).toBeUndefined()
  })
})
