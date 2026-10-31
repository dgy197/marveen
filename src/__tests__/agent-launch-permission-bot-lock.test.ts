import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import { readFileSync, writeFileSync, readdirSync, existsSync } from 'node:fs'
import { join } from 'node:path'

// Card 8e9f4670 (N2, B1): a custom provider config that already references the
// permission bot's Vault token (written before the lock, or by hand) must not
// inject it into an agent's environment at launch. The launch stops like it does
// for a missing key, the token is never decrypted, and nothing lands in the
// launch-secrets dir. A separate file from vault-permission-bot-read-lock.test.ts
// because it loads agent-process.

const h = vi.hoisted(() => ({ root: '', reads: [] as string[] }))

vi.mock('../config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../config.js')>()
  const { mkdtempSync, mkdirSync } = await import('node:fs')
  const { join } = await import('node:path')
  const { tmpdir } = await import('node:os')
  h.root = mkdtempSync(join(tmpdir(), 'launch-lock-test-'))
  mkdirSync(join(h.root, 'store'), { recursive: true })
  return { ...orig, PROJECT_ROOT: h.root, STORE_DIR: join(h.root, 'store') }
})
vi.mock('../web/keychain.js', () => ({
  isKeychainAvailable: () => false,
  keychainStore: () => { throw new Error('no keychain in tests') },
  keychainRetrieveStatus: () => ({ status: 'empty' }),
  keychainRetrieve: () => null,
  keychainDelete: () => true,
}))
vi.mock('../web/vault.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../web/vault.js')>()
  return { ...orig, getSecret: (id: string) => { h.reads.push(id); return orig.getSecret(id) } }
})
vi.mock('../web/agent-config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../web/agent-config.js')>()
  return { ...orig, readAgentCustomProvider: () => 'lockprov', readAgentModel: () => 'some-model' }
})

const { setSecret } = await import('../web/vault.js')
const { buildCustomProviderLaunchEnv } = await import('../web/agent-process.js')
const { PERMISSION_BOT_VAULT_ID } = await import('../web/permission-bot-vault.js')

const TOKEN = '7000000004:AAlaunchLockPermissionBotToken'
const VAULT_FILE = () => join(h.root, 'store', 'vault.json')
const PROVIDERS_FILE = () => join(h.root, 'store', 'custom-providers.json')

function useProvider(vaultKey: string, authHeader: string): void {
  writeFileSync(PROVIDERS_FILE(), JSON.stringify({
    providers: [{ id: 'lockprov', label: 'L', baseUrl: 'https://provider.example/api', authHeader, vaultKey }],
  }))
}

beforeAll(() => {
  setSecret('seed-entry', 'seed', TOKEN)
  const store = JSON.parse(readFileSync(VAULT_FILE(), 'utf-8'))
  store.entries[0].id = PERMISSION_BOT_VAULT_ID
  writeFileSync(VAULT_FILE(), JSON.stringify(store, null, 2))
  setSecret('provider-key', 'ok', 'provider-key-value-1')
})

beforeEach(() => { h.reads.length = 0 })

function launchSecretFiles(): string[] {
  const dirs = readdirSync(h.root, { recursive: true, encoding: 'utf-8' }) as string[]
  return dirs.filter(p => /launch-secret/i.test(p) && existsSync(join(h.root, p)))
}

describe('buildCustomProviderLaunchEnv with the locked id as vaultKey', () => {
  for (const authHeader of ['x-api-key', 'Bearer']) {
    for (const vk of [PERMISSION_BOT_VAULT_ID, PERMISSION_BOT_VAULT_ID.toUpperCase()]) {
      it(`${authHeader}, ${vk === PERMISSION_BOT_VAULT_ID ? 'exact' : 'upper case'}: launch stops, no decrypt, no token anywhere`, () => {
        useProvider(vk, authHeader)
        let thrown: unknown
        try { buildCustomProviderLaunchEnv('probe-agent') } catch (err) { thrown = err }
        expect(thrown).toBeInstanceOf(Error)
        expect((thrown as Error).message).not.toContain(TOKEN)
        expect(h.reads).toEqual([])
        for (const f of launchSecretFiles()) {
          expect(readFileSync(join(h.root, f), 'utf-8')).not.toContain(TOKEN)
        }
      })
    }
  }

  it('a normal vaultKey still builds the env', () => {
    useProvider('provider-key', 'x-api-key')
    const env = buildCustomProviderLaunchEnv('probe-agent')
    expect(env).not.toBeNull()
    expect(env!.envPrefix).toContain('ANTHROPIC_API_KEY=')
    expect(env!.envPrefix).not.toContain(TOKEN)
    expect(h.reads).toContain('provider-key')
  })
})
