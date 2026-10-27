// Card 053f4e66: the protected install keys FLEET_IMPORT_APPLY_ENABLED,
// MAIN_CHANNEL_ADMIN_ENABLED, MIGRATE_ROOTS and (053f4e66 B) the
// bearer-credential-admin trio BEARER_CREDENTIAL_ADMIN_ENABLED / _UNTIL / _NONCE
// live in the .env and are read from there per request. So no .env writer
// reachable with the shared Bearer may be able to write them. The writers of the install .env (PROJECT_ROOT/.env):
//   1. env.ts updateEnvFile -- callers: fleet import identity (fleet-transfer.ts,
//      covered in fleet-import-apply-gate.test.ts) and main-model.ts (/model keep,
//      MAIN_AGENT_MODEL from store/model-choices.json);
//   2. routes/onboarding.ts setEnvKey -- /api/onboarding/claude-auth and
//      /api/onboarding/identity;
//   3. model-fallback-runner.ts writeMainEnvModel -- MAIN_AGENT_MODEL only,
//      value gated by isValidModelId.
// Each is pinned here: a forged line (LF, CR, NUL, other control characters)
// or a key that is not a plain variable name is refused and nothing is written.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'switch-writers-')))
  const project = path.join(root, 'project')
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  for (const p of ['TELEGRAM', 'SLACK', 'DISCORD', 'GOOGLECHAT', 'TEAMS']) {
    process.env[`${p}_STATE_DIR`] = path.join(root, 'main-state', p.toLowerCase())
  }
  return { root, project, store: path.join(project, 'store') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
  MAIN_AGENT_ID: 'mainbot',
}))

const probe = vi.hoisted(() => ({ calls: 0 }))
vi.mock('../web/claude-credentials-guard.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/claude-credentials-guard.js')>()),
  liveProbeAuth: async () => { probe.calls++; return 'ok' },
  stampTokenVerified: () => {},
}))
vi.mock('../web/agent-process.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../web/agent-process.js')>()),
  sessionExistsOnHost: () => false,
}))
// The Keychain presence probe would shell out to /usr/bin/security.
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  execFileSync: () => { throw new Error('blocked in test') },
}))
vi.mock('../logger.js', () => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = () => {}
  l.child = () => l
  return { logger: l, PRETTY_OPTIONS: {} }
})

const { updateEnvFile, readEnvFile, InvalidEnvEntryError } = await import('../env.js')
const { setEnvKey, tryHandleOnboarding } = await import('../web/routes/onboarding.js')
const { isValidModelId } = await import('../model-id.js')
const { ADMIN_SWITCH_KEYS, isAdminSwitchKey } = await import('../web/admin-switch.js')

const ENV = join(T.project, '.env')
const BASE = 'MAIN_AGENT_ID=mainbot\nBOT_NAME=Brainy\n'
const SWITCHES = [
  'FLEET_IMPORT_APPLY_ENABLED', 'MAIN_CHANNEL_ADMIN_ENABLED', 'MIGRATE_ROOTS',
  'BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE',
]
const OAT = 'sk-ant-oat01-' + 'Ab_9-'.repeat(20)
const API = 'sk-ant-api03-' + 'Zz0_-'.repeat(19) + 'AA'

function switchesOff(): void {
  const env = readEnvFile()
  for (const k of SWITCHES) expect(env[k], k).toBeUndefined()
}

async function post(path: string, body: unknown) {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const raw = Buffer.from(JSON.stringify(body))
  const req: any = {
    headers: {},
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(raw)
      if (event === 'end') cb()
      return req
    },
  }
  const url = new URL(`http://localhost:3420${path}`)
  await tryHandleOnboarding({ req, res, path, method: 'POST', url } as RouteContext)
  return out
}

const INJECTIONS = SWITCHES.flatMap(k => [`\n${k}=1`, `\r\n${k}=1`, `\r${k}=1`, `\u0000\n${k}=1`])

beforeEach(() => {
  rmSync(T.project, { recursive: true, force: true })
  mkdirSync(T.store, { recursive: true })
  writeFileSync(ENV, BASE)
  probe.calls = 0
})

afterAll(() => { rmSync(T.root, { recursive: true, force: true }) })

describe('updateEnvFile refuses a forged line (053f4e66, from fec6335f)', () => {
  it('a value with CR, LF or NUL, or a key that is not ^[A-Z_][A-Z0-9_]*$: throws, the file is untouched', () => {
    const bad: Array<Record<string, string>> = [
      ...INJECTIONS.map(v => ({ BOT_NAME: `x${v}` })),
      { 'MAIN_CHANNEL_ADMIN_ENABLED ': '1' },
      { BOT_NAME: 'x\nMIGRATE_ROOTS=/' },
      { ' MIGRATE_ROOTS': '/' },
      { ' FLEET_IMPORT_APPLY_ENABLED': '1' },
      { main_channel_admin_enabled: '1' },
      { ' BEARER_CREDENTIAL_ADMIN_ENABLED': '1' },
      { 'BEARER_CREDENTIAL_ADMIN_NONCE ': 'x' },
      { bearer_credential_admin_until: '1800000000' },
      { BOT_NAME: 'x\nBEARER_CREDENTIAL_ADMIN_ENABLED=1' },
      { 'A-B': 'x' },
      { '1ABC': 'x' },
      { 'A=B': 'x' },
      { MAIN_AGENT_ID: 'ok', BOT_NAME: 'x\nFLEET_IMPORT_APPLY_ENABLED=1' },
    ]
    for (const updates of bad) {
      expect(() => updateEnvFile(updates), JSON.stringify(updates)).toThrow(InvalidEnvEntryError)
      expect(readFileSync(ENV, 'utf8')).toBe(BASE)
    }
    switchesOff()
  })

  it('the error names the key, never the value', () => {
    let msg = ''
    try { updateEnvFile({ BOT_NAME: 'secret-value\nX=1' }) } catch (e) { msg = (e as Error).message }
    expect(msg).toContain('BOT_NAME')
    expect(msg).not.toContain('secret-value')
  })

  it('a valid entry is still written as before', () => {
    updateEnvFile({ MAIN_AGENT_MODEL: 'claude-sonnet-5-5', _X1: 'a=b c' })
    const text = readFileSync(ENV, 'utf8')
    expect(text).toContain('MAIN_AGENT_MODEL=claude-sonnet-5-5')
    expect(text).toContain('_X1=a=b c')
  })
})

describe('onboarding setEnvKey refuses control characters (053f4e66)', () => {
  it.each([...INJECTIONS, '\t', '\u001b[2J', '\u007f', '\u0000'])('value %j: throws, nothing written', (v) => {
    expect(() => setEnvKey('BOT_NAME', `x${v}`)).toThrow(InvalidEnvEntryError)
    expect(readFileSync(ENV, 'utf8')).toBe(BASE)
  })

  it.each(['bot_name', 'A B', 'A\nFLEET_IMPORT_APPLY_ENABLED', ''])('key %j: throws, nothing written', (k) => {
    expect(() => setEnvKey(k, 'v')).toThrow(InvalidEnvEntryError)
    expect(readFileSync(ENV, 'utf8')).toBe(BASE)
  })

  it('a plain value is written as before', () => {
    setEnvKey('OWNER_NAME', 'Decsi György')
    expect(readEnvFile().OWNER_NAME).toBe('Decsi György')
  })
})

describe('POST /api/onboarding/claude-auth: whole-value format (053f4e66)', () => {
  it.each([
    ...INJECTIONS.map(v => ({ apiKey: `sk-ant-x${v}` })),
    ...INJECTIONS.map(v => ({ apiKey: `${API}${v}` })),
    ...INJECTIONS.map(v => ({ token: `${OAT}${v}` })),
    { apiKey: 'sk-ant-x' },
    { apiKey: `${API} trailing-words` },
    { apiKey: `sk-ant-oat01-${'A'.repeat(50)}` },
    { token: 'sk-ant-oat01-short' },
    { token: `sk-ant-oat01-${'A'.repeat(50)}\u001b` },
    { token: `sk-ant-api03-${'A'.repeat(50)}` },
  ])('%j -> 400, no probe, .env untouched', async (body) => {
    const r = await post('/api/onboarding/claude-auth', body)
    expect(r.status).toBe(400)
    expect(['bad-key', 'bad-token']).toContain(r.body?.reason)
    expect(probe.calls).toBe(0)
    expect(readFileSync(ENV, 'utf8')).toBe(BASE)
    switchesOff()
  })

  it('a well-formed setup-token (surrounding whitespace trimmed, as before) is stored as one line', async () => {
    const r = await post('/api/onboarding/claude-auth', { token: `  ${OAT}\n` })
    expect(r.status).toBe(200)
    expect(readFileSync(ENV, 'utf8')).toBe(`${BASE}CLAUDE_CODE_OAUTH_TOKEN=${OAT}\n`)
    switchesOff()
  })

  it('a well-formed API key is stored as one line', async () => {
    const r = await post('/api/onboarding/claude-auth', { apiKey: API })
    expect(r.status).toBe(200)
    expect(readFileSync(ENV, 'utf8')).toBe(`${BASE}ANTHROPIC_API_KEY=${API}\n`)
    switchesOff()
  })
})

describe('POST /api/onboarding/identity: control characters (053f4e66)', () => {
  it.each([
    { agentName: 'Brainy', ownerName: 'Gyuri\u000bFLEET_IMPORT_APPLY_ENABLED' },
    { agentName: 'Bra\u001bny', ownerName: 'Gyuri' },
    { agentName: 'Brainy\tX', ownerName: 'Gyuri' },
    { agentName: 'Brainy', ownerName: 'Gyuri\nMAIN_CHANNEL_ADMIN_ENABLED=1' },
    { agentName: 'Brainy', ownerName: 'Gyuri\u000bMIGRATE_ROOTS' },
  ])('%j -> 400, .env untouched', async (body) => {
    const r = await post('/api/onboarding/identity', body)
    expect(r.status).toBe(400)
    expect(readFileSync(ENV, 'utf8')).toBe(BASE)
    switchesOff()
  })
})

describe('model-fallback-runner writes only a valid model id (053f4e66)', () => {
  it('isValidModelId (the gate in front of writeMainEnvModel) refuses a forged line', () => {
    for (const k of SWITCHES) {
      expect(isValidModelId(`claude-opus-5\n${k}=1`)).toBe(false)
      expect(isValidModelId(`claude-opus-5\r${k}=1`)).toBe(false)
    }
    expect(isValidModelId('claude-opus-5-5[1m]')).toBe(true)
  })
})

describe('the bearer-credential-admin keys are protected install keys (053f4e66 B, S4)', () => {
  it('all three are in ADMIN_SWITCH_KEYS', () => {
    for (const k of ['BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE']) {
      expect(ADMIN_SWITCH_KEYS.has(k), k).toBe(true)
    }
  })

  it.each([
    'BEARER_CREDENTIAL_ADMIN_ENABLED', 'bearer_credential_admin_enabled', ' BEARER_CREDENTIAL_ADMIN_ENABLED ',
    'Bearer_Credential_Admin_Until', 'bearer_credential_admin_nonce\t',
  ])('isAdminSwitchKey(%j) is true', (k) => {
    expect(isAdminSwitchKey(k)).toBe(true)
  })

  it('a similar but different key is not one', () => {
    expect(isAdminSwitchKey('BEARER_CREDENTIAL_ADMIN_ENABLED_X')).toBe(false)
  })
})
