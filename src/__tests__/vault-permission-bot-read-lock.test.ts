import { describe, it, expect, vi, beforeAll, beforeEach } from 'vitest'
import { readFileSync, writeFileSync, existsSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { join } from 'node:path'
import type http from 'node:http'
import type { RouteContext } from '../web/routes/types.js'

// Card 8e9f4670 (N2): the permission bot's Vault token is never READ through the API.
//  - GET /api/vault/<id> answers 403 (also for a row that does not exist), without
//    decrypting, with an audit row that carries no value;
//  - POST /api/vault/bindings refuses the id and writes nothing;
//  - a fleet export leaves the row (and bindings naming it) out, with a warning;
//  - in-process getSecret still returns it (the relay needs it).
// The real vault runs against a throw-away project root.

const h = vi.hoisted(() => ({ root: '', reads: [] as string[] }))

vi.mock('../config.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../config.js')>()
  const { mkdtempSync, mkdirSync } = await import('node:fs')
  const { join } = await import('node:path')
  const { tmpdir } = await import('node:os')
  h.root = mkdtempSync(join(tmpdir(), 'vault-readlock-test-'))
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
// Wrap getSecret so the test can see that the locked route never decrypts.
vi.mock('../web/vault.js', async (importOriginal) => {
  const orig = await importOriginal<typeof import('../web/vault.js')>()
  return { ...orig, getSecret: (id: string) => { h.reads.push(id); return orig.getSecret(id) } }
})
vi.mock('../db.js', () => ({
  getDb: () => ({}),
  backfillEmbeddings: () => Promise.resolve(),
  initDatabase: () => {},
  logConfigChange: () => undefined,
}))
vi.mock('../store-watcher.js', () => ({ setStoreWriteActor: () => undefined }))

const { setSecret, getSecret } = await import('../web/vault.js')
const { tryHandleConnectors } = await import('../web/routes/connectors.js')
const { _exportVaultForTest } = await import('../web/fleet-transfer.js')
const { PERMISSION_BOT_VAULT_ID } = await import('../web/permission-bot-vault.js')
const { logger } = await import('../logger.js')

const TOKEN = '7000000003:AAreadLockPermissionBotToken'
const OTHER_VALUE = 'other-secret-value-1'
const VAULT_FILE = () => join(h.root, 'store', 'vault.json')
const BINDINGS_FILE = () => join(h.root, 'store', 'vault-bindings.json')
const MCP_FILE = () => join(h.root, '.mcp.json')

const infoSpy = vi.spyOn(logger, 'info').mockImplementation(() => undefined)
const warnSpy = vi.spyOn(logger, 'warn').mockImplementation(() => undefined)

function sha(path: string): string {
  return existsSync(path) ? createHash('sha256').update(readFileSync(path)).digest('hex') : 'absent'
}

function allLogPayloads(): string {
  return JSON.stringify([...infoSpy.mock.calls, ...warnSpy.mock.calls])
}

function mkRes() {
  const out = { status: 0, body: null as any, raw: '' }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { return res },
    end(chunk?: string) { if (chunk) { out.raw = chunk; out.body = JSON.parse(chunk) } },
  }
  return { out, res }
}

function fakeReq(body: unknown) {
  const bodyStr = JSON.stringify(body ?? {})
  return {
    headers: {},
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(Buffer.from(bodyStr))
      if (event === 'end') cb()
    },
  }
}

async function call(method: 'GET' | 'POST', path: string, body?: unknown) {
  const { out, res } = mkRes()
  const ctx = {
    req: fakeReq(body) as unknown as http.IncomingMessage, res: res as http.ServerResponse,
    path, method, url: new URL(`http://localhost${path}`), auth: { kind: 'token' },
  } as unknown as RouteContext
  expect(await tryHandleConnectors(ctx)).toBe(true)
  return out
}

beforeAll(() => {
  // The locked id cannot be written through setSecret: provision it the way the
  // operator does, out-of-band (write a normal entry, then relabel its id).
  setSecret('seed-entry', 'seed', TOKEN)
  const store = JSON.parse(readFileSync(VAULT_FILE(), 'utf-8'))
  store.entries[0].id = PERMISSION_BOT_VAULT_ID
  writeFileSync(VAULT_FILE(), JSON.stringify(store, null, 2))
  setSecret('other-secret', 'other', OTHER_VALUE)
})

beforeEach(() => {
  h.reads.length = 0
  infoSpy.mockClear()
  warnSpy.mockClear()
})

describe('GET /api/vault/<locked id>', () => {
  const variants = [
    ['exact id', PERMISSION_BOT_VAULT_ID],
    ['upper case', PERMISSION_BOT_VAULT_ID.toUpperCase()],
    ['trailing space (encoded)', `${PERMISSION_BOT_VAULT_ID}%20`],
    ['leading space (encoded)', `%20${PERMISSION_BOT_VAULT_ID}`],
    ['url-encoded first letter', `%74elegram-engedely-bot-token`],
    ['url-encoded upper case first letter', `%54elegram-engedely-bot-token`],
  ] as const

  for (const [name, seg] of variants) {
    it(`${name}: 403, no decrypt, audit row without the value`, async () => {
      const out = await call('GET', `/api/vault/${seg}`)
      expect(out.status).toBe(403)
      expect(out.body.error).toContain('locked')
      expect(out.raw).not.toContain(TOKEN)
      expect(out.body.value).toBeUndefined()
      expect(h.reads).toEqual([])
      const rows = infoSpy.mock.calls.filter(c => (c[0] as { event?: string })?.event === 'vault-read')
      expect(rows).toHaveLength(1)
      expect(rows[0][0]).toMatchObject({ id: PERMISSION_BOT_VAULT_ID, kind: 'token', found: true })
      expect(allLogPayloads()).not.toContain(TOKEN)
    })
  }

  it('a locked id with no row is still 403, not 404 (no existence leak)', async () => {
    const original = readFileSync(VAULT_FILE(), 'utf-8')
    const store = JSON.parse(original)
    store.entries = store.entries.filter((e: { id: string }) => e.id !== PERMISSION_BOT_VAULT_ID)
    writeFileSync(VAULT_FILE(), JSON.stringify(store, null, 2))
    try {
      const out = await call('GET', `/api/vault/${PERMISSION_BOT_VAULT_ID}`)
      expect(out.status).toBe(403)
      expect(h.reads).toEqual([])
      const rows = infoSpy.mock.calls.filter(c => (c[0] as { event?: string })?.event === 'vault-read')
      expect(rows[0][0]).toMatchObject({ id: PERMISSION_BOT_VAULT_ID, found: false })
    } finally {
      writeFileSync(VAULT_FILE(), original)
    }
  })

  it('another id is still served (the lock is not a blanket)', async () => {
    const out = await call('GET', '/api/vault/other-secret')
    expect(out.status).toBe(200)
    expect(out.body).toEqual({ id: 'other-secret', value: OTHER_VALUE })
  })

  it('in-process getSecret still returns the token (the relay reads it this way)', () => {
    expect(getSecret(PERMISSION_BOT_VAULT_ID)).toBe(TOKEN)
  })
})

describe('POST /api/vault/bindings with the locked id', () => {
  it('is refused (403) for env and header bindings and every id variant; no file changes', async () => {
    writeFileSync(BINDINGS_FILE(), JSON.stringify({ bindings: [] }, null, 2))
    writeFileSync(MCP_FILE(), JSON.stringify({ mcpServers: { srv: { command: 'node', args: ['x.js'] } } }, null, 2))
    const before = { bindings: sha(BINDINGS_FILE()), mcp: sha(MCP_FILE()), vault: sha(VAULT_FILE()) }
    const targets = [{ mcpFilePath: MCP_FILE(), serverName: 'srv' }]
    for (const vaultSecretId of [PERMISSION_BOT_VAULT_ID, PERMISSION_BOT_VAULT_ID.toUpperCase(), `  ${PERMISSION_BOT_VAULT_ID}  `]) {
      const env = await call('POST', '/api/vault/bindings', { vaultSecretId, envVar: 'TOKEN', serverName: 'srv', targets })
      expect(env.status).toBe(403)
      expect(env.body.error).toContain('locked')
      const header = await call('POST', '/api/vault/bindings', { vaultSecretId, headerName: 'Authorization', serverName: 'srv' })
      expect(header.status).toBe(403)
    }
    expect({ bindings: sha(BINDINGS_FILE()), mcp: sha(MCP_FILE()), vault: sha(VAULT_FILE()) }).toEqual(before)
    const refusals = warnSpy.mock.calls.filter(c => (c[0] as { event?: string })?.event === 'vault-binding-refused')
    expect(refusals.length).toBe(6)
    expect(allLogPayloads()).not.toContain(TOKEN)
  })
})

describe('fleet export', () => {
  it('skips the locked row and bindings that name it, warns, and keeps the other rows', () => {
    writeFileSync(BINDINGS_FILE(), JSON.stringify({
      bindings: [
        { vaultSecretId: PERMISSION_BOT_VAULT_ID, envVar: 'TOKEN', targets: [] },
        { vaultSecretId: 'other-secret', envVar: 'OTHER', targets: [] },
      ],
    }))
    const out = _exportVaultForTest()
    expect(out).not.toBeNull()
    expect(out!.entries.map(e => (e as { id: string }).id)).toEqual(['other-secret'])
    expect(out!.bindings.map(b => (b as { vaultSecretId: string }).vaultSecretId)).toEqual(['other-secret'])
    expect(JSON.stringify(out)).not.toContain(PERMISSION_BOT_VAULT_ID)
    const skipped = warnSpy.mock.calls.filter(c => (c[0] as { event?: string })?.event === 'fleet-export-vault-row-skipped')
    expect(skipped).toHaveLength(1)
    expect(allLogPayloads()).not.toContain(TOKEN)
  })

  it('an export with no locked row logs no skip warning', async () => {
    const original = readFileSync(VAULT_FILE(), 'utf-8')
    const store = JSON.parse(original)
    store.entries = store.entries.filter((e: { id: string }) => e.id !== PERMISSION_BOT_VAULT_ID)
    writeFileSync(VAULT_FILE(), JSON.stringify(store, null, 2))
    try {
      writeFileSync(BINDINGS_FILE(), JSON.stringify({ bindings: [] }))
      expect(_exportVaultForTest()).not.toBeNull()
      expect(warnSpy.mock.calls.filter(c => (c[0] as { event?: string })?.event === 'fleet-export-vault-row-skipped')).toHaveLength(0)
    } finally {
      writeFileSync(VAULT_FILE(), original)
    }
  })
})
