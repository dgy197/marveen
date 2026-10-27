// fec6335f (blueprint 3.1): INTERACTIVE_ANTHROPIC_KEY_POLICY is writable from
// the .env file only. The fleet import's identity takeover used to copy ANY key
// of mainAgent.identity into config-overrides.json and .env, so one Bearer call
// (POST /api/fleet/import?apply=true) could switch the guard back to allow. It
// now takes exactly the keys an export writes (FLEET_IDENTITY_KEYS), and refuses
// the whole import -- dry-run or apply, 400 at the route -- on anything else,
// before a single write. Same mock set as fleet-transfer.test.ts: no real DB,
// store, .env or filesystem write.
import { describe, it, expect, vi, beforeEach } from 'vitest'
import { EventEmitter } from 'node:events'

vi.mock('../db.js', () => ({
  getDb: () => ({
    prepare: () => ({ all: () => [], get: () => null, run: () => ({ changes: 0 }) }),
    transaction: (fn: Function) => fn,
  }),
  backfillEmbeddings: () => Promise.resolve(),
  initDatabase: () => {},
}))
vi.mock('../web/agent-config.js', () => ({
  AGENTS_BASE_DIR: '/mock/agents',
  listAgentNames: () => [],
  readJsonObjectForWrite: () => ({}),
}))
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>()
  return { ...real, existsSync: () => false, mkdirSync: () => undefined, unlinkSync: () => undefined, rmSync: () => undefined, readdirSync: () => [] }
})
vi.mock('../web/atomic-write.js', () => ({ atomicWriteFileSync: vi.fn() }))
vi.mock('../web/scheduled-tasks-io.js', () => ({ SCHEDULED_TASKS_DIR: '/mock/tasks' }))
vi.mock('../config.js', () => ({
  PROJECT_ROOT: '/mock/project',
  STORE_DIR: '/mock/store',
  MAIN_AGENT_ID: 'marveen',
  BOT_NAME: 'Marveen',
  BRAND_NAME: 'Marveen',
  OWNER_NAME: 'Szabolcs',
  CHANNEL_PROVIDER: 'telegram',
  // fleet-transfer.ts reads it since v1.45.0 (the voice channel id); the fixed list, as in fleet-transfer.test.ts.
  RESERVED_AGENT_IDS: ['system', 'heartbeat', 'telegram-coordinator', 'channel-coordinator'],
}))
vi.mock('../web/vault-bindings.js', () => ({ getBindings: () => [] }))
// readEnvFile: the 053f4e66 apply switch (admin-switch.ts) reads the .env per
// request; off unless a test opens it.
vi.mock('../env.js', () => ({ updateEnvFile: vi.fn(), readEnvFile: vi.fn(() => ({})) }))
vi.mock('../logger.js', () => ({ logger: { info: () => {}, warn: () => {}, error: () => {} } }))

const { importFleet, FLEET_IDENTITY_KEYS } = await import('../web/fleet-transfer.js')
const { tryHandleFleet } = await import('../web/routes/fleet.js')
const { updateEnvFile, readEnvFile } = await import('../env.js')
const { atomicWriteFileSync } = await import('../web/atomic-write.js')

const IDENTITY = { MAIN_AGENT_ID: 'atlas', BOT_NAME: 'Atlas', BRAND_NAME: 'Atlas', OWNER_NAME: 'Norbert', CHANNEL_PROVIDER: 'telegram' }
const fleet = (mainAgent: Record<string, unknown>) => JSON.stringify({
  schemaVersion: 1, exportedAt: '2026-01-01T00:00:00.000Z', sourceHost: 'source',
  mainAgent: { claudeMd: '', soulMd: '', config: {}, mcp: {}, settings: {}, channelsAccess: {}, ...mainAgent },
  agents: [], skills: [], scheduledTasks: [], memories: [], dailyLogs: [],
  kanban: { cards: [], comments: [], cardEvents: [], labels: [], cardLabels: [] },
  ideaBox: { ideas: [], comments: [], statusLog: [] },
  dashboardSettings: { autonomy: {}, autoRestart: {}, agentsDesired: {}, norbertPersonal: {} },
})
const overrideWrites = () => (atomicWriteFileSync as any).mock.calls.filter((c: string[]) => String(c[0]).includes('config-overrides.json'))

beforeEach(() => {
  ;(updateEnvFile as any).mockClear()
  ;(atomicWriteFileSync as any).mockClear()
})

describe('the identity allowlist is exactly what the export writes', () => {
  it('FLEET_IDENTITY_KEYS', () => {
    expect([...FLEET_IDENTITY_KEYS]).toEqual(['MAIN_AGENT_ID', 'BOT_NAME', 'BRAND_NAME', 'OWNER_NAME', 'CHANNEL_PROVIDER'])
  })

  it('a legitimate export still takes over, into config-overrides.json AND .env', () => {
    const r = importFleet(fleet({ agentId: 'atlas', identity: IDENTITY }), { apply: true }) as any
    expect(r.ok).toBe(true)
    expect((updateEnvFile as any).mock.calls.at(-1)[0]).toEqual(IDENTITY)
    expect(overrideWrites()).toHaveLength(1)
  })

  it('an old export without identity still writes MAIN_AGENT_ID only', () => {
    const r = importFleet(fleet({ agentId: 'atlas' }), { apply: true }) as any
    expect(r.ok).toBe(true)
    expect((updateEnvFile as any).mock.calls.at(-1)[0]).toEqual({ MAIN_AGENT_ID: 'atlas' })
  })
})

describe('anything else in the identity refuses the WHOLE import, before any write', () => {
  const smuggled: Array<[string, Record<string, unknown>]> = [
    ['INTERACTIVE_ANTHROPIC_KEY_POLICY', { INTERACTIVE_ANTHROPIC_KEY_POLICY: 'allow' }],
    ['CREDIT_GATE_MODE', { CREDIT_GATE_MODE: 'off' }],
    ['a *_KEY_POLICY name', { SOME_KEY_POLICY: 'allow' }],
    ['a *_GATE_* name', { EMAIL_GATE_LEVEL: '3' }],
    ['an ordinary setting', { WEB_PORT: '1' }],
    ['a lower-case look-alike', { main_agent_id: 'x' }],
  ]
  for (const [label, extra] of smuggled) {
    for (const apply of [true, false]) {
      it(`${label} (${apply ? 'apply' : 'dry-run'})`, () => {
        const r = importFleet(fleet({ agentId: 'atlas', identity: { ...IDENTITY, ...extra } }), { apply }) as any
        expect(r.dryRun).toBe(true)
        expect(r.errors).toHaveLength(1)
        expect(r.errors[0]).toContain(Object.keys(extra)[0])
        expect(updateEnvFile as any).not.toHaveBeenCalled()
        expect(atomicWriteFileSync as any).not.toHaveBeenCalled()
      })
    }
  }

  it('a control character in a value (a .env line injection) refuses; so does one in the legacy agentId', () => {
    for (const bad of [
      { agentId: 'atlas', identity: { ...IDENTITY, BOT_NAME: 'Atlas\nINTERACTIVE_ANTHROPIC_KEY_POLICY=allow' } },
      { agentId: 'atlas', identity: { ...IDENTITY, OWNER_NAME: 'N\r' } },
      { agentId: 'atlas\nINTERACTIVE_ANTHROPIC_KEY_POLICY=allow' },
    ]) {
      const r = importFleet(fleet(bad), { apply: true }) as any
      expect(r.dryRun).toBe(true)
      expect(r.errors.length).toBeGreaterThan(0)
      expect(updateEnvFile as any).not.toHaveBeenCalled()
      expect(atomicWriteFileSync as any).not.toHaveBeenCalled()
    }
  })

  it('an identity that is not an object refuses', () => {
    const r = importFleet(fleet({ agentId: 'atlas', identity: ['INTERACTIVE_ANTHROPIC_KEY_POLICY'] }), { apply: true }) as any
    expect(r.errors).toEqual(['Érvénytelen mainAgent.identity: objektum kell.'])
    expect(updateEnvFile as any).not.toHaveBeenCalled()
  })
})

// On an install with the 053f4e66 package, the apply switch
// (FLEET_IMPORT_APPLY_ENABLED) answers first: 403 while it is off, before the
// body is read. The identity allowlist is the wall behind an open switch.
describe('POST /api/fleet/import?apply=true with the policy key in the identity writes nothing', () => {
  const post = async () => {
    const req = new EventEmitter() as any
    req.headers = {}
    const out = { status: 0, body: null as any }
    const res = {
      writeHead(s: number) { out.status = s; return res },
      end(chunk?: string) { if (chunk) out.body = JSON.parse(String(chunk)) },
      setHeader() {},
    }
    const url = new URL('http://localhost:3420/api/fleet/import?apply=true')
    process.nextTick(() => {
      req.emit('data', Buffer.from(fleet({ agentId: 'atlas', identity: { ...IDENTITY, INTERACTIVE_ANTHROPIC_KEY_POLICY: 'allow' } })))
      req.emit('end')
    })
    expect(await tryHandleFleet({ req, res, path: url.pathname, method: 'POST', url } as any)).toBe(true)
    return out
  }

  it('apply switch off: 403 from the 053f4e66 gate', async () => {
    ;(readEnvFile as any).mockImplementation(() => ({}))
    const out = await post()
    expect(out.status).toBe(403)
    expect(updateEnvFile as any).not.toHaveBeenCalled()
    expect(atomicWriteFileSync as any).not.toHaveBeenCalled()
  })

  it('apply switch on: 400 from the identity allowlist', async () => {
    ;(readEnvFile as any).mockImplementation(() => ({ FLEET_IMPORT_APPLY_ENABLED: '1' }))
    try {
      const out = await post()
      expect(out.status).toBe(400)
      expect(out.body.errors[0]).toContain('INTERACTIVE_ANTHROPIC_KEY_POLICY')
      expect(updateEnvFile as any).not.toHaveBeenCalled()
      expect(atomicWriteFileSync as any).not.toHaveBeenCalled()
    } finally {
      ;(readEnvFile as any).mockImplementation(() => ({}))
    }
  })
})
