// fec6335f N3a (I-02): the dashboard write paths refuse a change that would put
// a first-party Claude agent on an API key, BEFORE any write. Driven through
// the real route handler against a scratch PROJECT_ROOT/STORE_DIR; the Vault
// is a recorder, no key is read or stored.
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const H = vi.hoisted(() => ({
  root: '',
  vault: [] as string[],
  providers: {} as Record<string, { id: string; label: string; baseUrl: string; authHeader: 'x-api-key' | 'Bearer' | 'none'; vaultKey: string | null }>,
}))

vi.mock('node:os', async (orig) => {
  const a = await orig<typeof import('node:os')>()
  return { ...a, homedir: () => `${H.root}/home` }
})
vi.mock('../config.js', async (orig) => {
  const a = await orig<typeof import('../config.js')>()
  return { ...a, PROJECT_ROOT: H.root, STORE_DIR: `${H.root}/store` }
})
vi.mock('../web/vault.js', async (orig) => {
  const a = await orig<typeof import('../web/vault.js')>()
  return {
    ...a,
    getSecret: (id: string) => { H.vault.push(`get:${id}`); return null },
    setSecret: (id: string) => { H.vault.push(`set:${id}`) },
    deleteSecret: (id: string) => { H.vault.push(`del:${id}`) },
  }
})
vi.mock('../web/custom-providers.js', async (orig) => {
  const a = await orig<typeof import('../web/custom-providers.js')>()
  return { ...a, loadCustomProvider: (id: string) => H.providers[id] ?? null, listCustomProviders: () => Object.values(H.providers) }
})
vi.mock('../web/claude-cli-version.js', async (orig) => {
  const a = await orig<typeof import('../web/claude-cli-version.js')>()
  const v = { version: '9.9.999', measuredAt: 0, error: null, source: 'env' as const }
  return { ...a, measureClaudeCliVersion: async () => v, measureClaudeCliVersionSync: () => v }
})

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
H.root = mkdtempSync(join(tmpdir(), 'ikg-route-'))
process.env.CLAUDECLAW_ENV_DIR = join(H.root, 'envdir')
mkdirSync(join(H.root, 'envdir'), { recursive: true })
for (const d of ['templates', 'scripts', '.claude', 'plugins', 'config-examples', 'seed-config', 'web']) {
  if (existsSync(join(REPO, d))) symlinkSync(join(REPO, d), join(H.root, d))
}
mkdirSync(join(H.root, 'store'), { recursive: true })
mkdirSync(join(H.root, 'home', '.claude'), { recursive: true })

const { tryHandleAgents } = await import('../web/routes/agents.js')
const G = await import('../web/interactive-key-guard.js')
type Ctx = Parameters<typeof tryHandleAgents>[0]

const DUMMY = ['sk', 'ant', 'TEST', 'DUMMY', randomBytes(6).toString('hex')].join('-')

async function call(method: 'PUT' | 'POST', path: string, body: unknown): Promise<{ status: number; body: any; raw: string }> {
  const req = new EventEmitter() as unknown as Ctx['req']
  ;(req as unknown as { headers: Record<string, string> }).headers = { 'content-type': 'application/json' }
  const out = { status: 0, body: null as any, raw: '' }
  const res = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) { out.raw = String(chunk); out.body = JSON.parse(String(chunk)) } },
    setHeader() {},
  }
  const url = new URL(`http://localhost:3420${path}`)
  process.nextTick(() => {
    ;(req as unknown as EventEmitter).emit('data', Buffer.from(JSON.stringify(body)))
    ;(req as unknown as EventEmitter).emit('end')
  })
  const handled = await tryHandleAgents({ req, res, path: url.pathname, method, url } as unknown as Ctx, join(H.root, 'web'))
  expect(handled).toBe(true)
  return { status: out.status || 200, body: out.body, raw: out.raw }
}

function agent(name: string, cfg: Record<string, unknown>): { dir: string; cfgPath: string } {
  const dir = join(H.root, 'agents', name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'agent-config.json'), JSON.stringify(cfg))
  writeFileSync(join(dir, 'CLAUDE.md'), 'original\n')
  return { dir, cfgPath: join(dir, 'agent-config.json') }
}

beforeEach(() => {
  H.vault.length = 0
  H.providers = {}
})
afterEach(() => G.setInteractiveKeyPolicyForTest(null))
afterAll(() => rmSync(H.root, { recursive: true, force: true }))

describe('forbid: PUT /api/agents/:name refuses a key route for a first-party agent (422, nothing written)', () => {
  it('{authMode:"api", apiKey} on a Claude agent: 422, no Vault write, config and CLAUDE.md untouched', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const a = agent('r1', { model: 'claude-opus-5-5' })
    const before = readFileSync(a.cfgPath, 'utf-8')
    const r = await call('PUT', '/api/agents/r1', { authMode: 'api', apiKey: DUMMY, claudeMd: 'overwritten' })
    expect(r.status).toBe(422)
    expect(r.body.reason).toBe('auth-mode-api')
    expect(H.vault).toEqual([])
    expect(readFileSync(a.cfgPath, 'utf-8')).toBe(before)
    expect(readFileSync(join(a.dir, 'CLAUDE.md'), 'utf-8')).toBe('original\n')
    expect(r.raw).not.toContain(DUMMY)
  })

  it('{model:"claude-…"} onto an existing api-mode GPT agent: 422 (judged on the config AFTER the change)', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const a = agent('r2', { model: 'openai/gpt-5.5', authMode: 'api' })
    const before = readFileSync(a.cfgPath, 'utf-8')
    const r = await call('PUT', '/api/agents/r2', { model: 'claude-opus-5-5' })
    expect(r.status).toBe(422)
    expect(readFileSync(a.cfgPath, 'utf-8')).toBe(before)
    expect(H.vault).toEqual([])
  })

  it('{customProvider:null} that would turn an api-mode litellm agent back into a Claude one: 422', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    H.providers.litellm = { id: 'litellm', label: 'l', baseUrl: 'http://127.0.0.1:4010', authHeader: 'Bearer', vaultKey: 'lk' }
    const a = agent('r3', { model: 'claude-opus-5-5', customProvider: 'litellm', authMode: 'api' })
    const before = readFileSync(a.cfgPath, 'utf-8')
    expect((await call('PUT', '/api/agents/r3', { customProvider: null })).status).toBe(422)
    expect(readFileSync(a.cfgPath, 'utf-8')).toBe(before)
  })

  it('{customProvider} pointing at Anthropic itself: 422', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    H.providers.direct = { id: 'direct', label: 'd', baseUrl: 'https://api.anthropic.com', authHeader: 'x-api-key', vaultKey: 'k' }
    agent('r4', { model: 'gpt-x' })
    const r = await call('PUT', '/api/agents/r4', { customProvider: 'direct' })
    expect(r.status).toBe(422)
    expect(r.body.reason).toBe('first-party-custom-provider')
  })

  it('{authMode:"api"} on a GPT agent: 200 (not first-party)', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const a = agent('r5', { model: 'openai/gpt-5.5' })
    const r = await call('PUT', '/api/agents/r5', { authMode: 'api', apiKey: DUMMY })
    expect(r.status).toBe(200)
    expect(JSON.parse(readFileSync(a.cfgPath, 'utf-8')).authMode).toBe('api')
    expect(H.vault).toEqual(['set:agent-r5-api-key'])
  })

  it('a write that does not touch the key route passes, and authMode:"shared" is the way out', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const a = agent('r6', { model: 'claude-opus-5-5', authMode: 'api' })
    expect((await call('PUT', '/api/agents/r6', { claudeMd: 'edited' })).status).toBe(200)
    expect(readFileSync(join(a.dir, 'CLAUDE.md'), 'utf-8')).toBe('edited')
    expect((await call('PUT', '/api/agents/r6', { authMode: 'shared' })).status).toBe(200)
    expect(JSON.parse(readFileSync(a.cfgPath, 'utf-8')).authMode).toBe('shared')
    expect(H.vault).toEqual(['del:agent-r6-api-key'])
  })
})

describe('allow: the PUT behaves exactly as today', () => {
  it('{authMode:"api", apiKey} on a Claude agent: 200, the key goes to the Vault', async () => {
    G.setInteractiveKeyPolicyForTest('allow')
    const a = agent('r7', { model: 'claude-opus-5-5' })
    const r = await call('PUT', '/api/agents/r7', { authMode: 'api', apiKey: DUMMY })
    expect(r.status).toBe(200)
    expect(JSON.parse(readFileSync(a.cfgPath, 'utf-8')).authMode).toBe('api')
    expect(H.vault).toEqual(['set:agent-r7-api-key'])
  })
})

describe('forbid: POST /api/agents (create) refuses an api-mode Claude agent before creating anything', () => {
  it('422 and no agent directory', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const r = await call('POST', '/api/agents', { name: 'newapi', description: 'x', model: 'claude-opus-5-5', authMode: 'api', apiKey: DUMMY })
    expect(r.status).toBe(422)
    expect(existsSync(join(H.root, 'agents', 'newapi'))).toBe(false)
    expect(H.vault).toEqual([])
    expect(r.raw).not.toContain(DUMMY)
  })
})
