/**
 * Memory write gate b1 (card 3e9f6c28, node B1-S): origin marking and the
 * "b1 changes nothing observable" golden tests.
 *
 *  - noteGateOrigin writes only when tables are verified AND mode != off AND an owner exists;
 *  - the POST /api/memories response and the stored `memories` row are identical in every
 *    gate state (off, shadow, no owners, migration failed, DB error while marking);
 *  - GET /api/memories (every branch) and GET /api/memories/:id are byte-identical with empty
 *    and filled gate tables;
 *  - POST /api/daily-log (mirror rows) never gets an origin marker;
 *  - nothing under src/memory-gate/ writes `memories` (source-level).
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { Readable } from 'node:stream'
import { readdirSync, readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { initDatabase, getDb } from '../db.js'
import { tryHandleMemories } from '../web/routes/memories.js'
import { tryHandleDailyLog } from '../web/routes/daily-log.js'
import { noteGateOrigin, writeGateOrigin, type OriginDeps } from '../memory-gate/origin.js'
import { gateTablesReady } from '../memory-gate/schema.js'
import type { GateEnv } from '../memory-gate/gate-env.js'
import type { RouteContext } from '../web/routes/types.js'

const envState = vi.hoisted(() => ({ values: {} as Record<string, string> }))

vi.mock('../env.js', async () => {
  const actual = await vi.importActual<typeof import('../env.js')>('../env.js')
  return {
    ...actual,
    readEnvFile: (keys?: string[]) =>
      keys && keys.every(k => k.startsWith('MEMORY_GATE_'))
        ? Object.fromEntries(Object.entries(envState.values).filter(([k]) => keys.includes(k)))
        : actual.readEnvFile(keys),
  }
})
vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  return { ...actual, MAIN_AGENT_ID: 'brainy', ALLOWED_CHAT_ID: 'test-chat', OLLAMA_URL: '' }
})
vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))

interface Captured { status: number; body: string }

async function call(
  handler: (ctx: RouteContext) => Promise<boolean>,
  method: string, path: string, payload?: unknown,
): Promise<Captured> {
  const url = new URL(`http://localhost:3420${path}`)
  let status = 200
  let body = ''
  const res = {
    writeHead: (code: number) => { status = code },
    setHeader: () => {},
    end: (b?: string) => { body = b || '' },
  }
  const req = Readable.from(payload === undefined ? [] : [Buffer.from(JSON.stringify(payload))]) as any
  req.headers = {}
  const handled = await handler({ req, res: res as any, path: url.pathname, method, url })
  expect(handled, `${method} ${path} handled`).toBe(true)
  return { status, body }
}

const flush = async () => { await new Promise(r => setImmediate(r)); await new Promise(r => setImmediate(r)) }
const originCount = () => (getDb().prepare('SELECT COUNT(*) AS n FROM memory_gate_origin').get() as { n: number }).n

function memRows(): Array<Record<string, unknown>> {
  return (getDb().prepare('SELECT * FROM memories ORDER BY id').all() as Array<Record<string, unknown>>)
    .map(({ id: _id, ...rest }) => rest)
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  vi.useFakeTimers({ toFake: ['Date'] })
  vi.setSystemTime(new Date('2026-10-23T12:00:00Z'))
  envState.values = {}
})
afterEach(async () => { await flush(); vi.useRealTimers(); vi.restoreAllMocks(); vi.unstubAllGlobals() })

const POSTS = [
  { agent_id: 'iroda', content: 'A Billingo kulcs rotacioja negyedevente tortenik, felelos: Garas.', category: 'warm', keywords: 'billingo, rotacio' },
  { agent_id: 'iroda', content: 'Cyrillic look-alike: \u0430dmin account note, long enough to count.', category: 'cold' },
]

describe('noteGateOrigin writes only when the gate is genuinely on', () => {
  const deps = (over: Partial<OriginDeps> = {}): OriginDeps => ({
    getDb: () => getDb(),
    readEnv: () => ({
      configuredMode: 'shadow', effectiveMode: 'shadow', invalidMode: false,
      owners: { owners: ['iroda'], configError: null, mainAgentExcluded: false },
    }),
    tablesReady: () => true,
    now: () => 1_700_000_000,
    ...over,
  })

  beforeEach(() => { initDatabase(':memory:') })

  it('writes an api marker in shadow mode with an owner', () => {
    expect(writeGateOrigin(41, deps())).toBe(true)
    expect(getDb().prepare('SELECT * FROM memory_gate_origin').all()).toEqual([{ memory_id: 41, origin: 'api', noted_at: 1_700_000_000 }])
  })

  it('writes the same id once (INSERT OR IGNORE)', () => {
    writeGateOrigin(41, deps()); writeGateOrigin(41, deps())
    expect(originCount()).toBe(1)
  })

  it('off mode, no owners, a config error or unverified tables: zero writes', () => {
    const off: GateEnv = { configuredMode: 'off', effectiveMode: 'off', invalidMode: false, owners: { owners: ['iroda'], configError: null, mainAgentExcluded: false } }
    expect(writeGateOrigin(1, deps({ readEnv: () => off }))).toBe(false)
    const none: GateEnv = { configuredMode: 'shadow', effectiveMode: 'shadow', invalidMode: false, owners: { owners: [], configError: null, mainAgentExcluded: false } }
    expect(writeGateOrigin(2, deps({ readEnv: () => none }))).toBe(false)
    const bad: GateEnv = { configuredMode: 'shadow', effectiveMode: 'shadow', invalidMode: false, owners: { owners: [], configError: 'forbidden_owner', mainAgentExcluded: false } }
    expect(writeGateOrigin(3, deps({ readEnv: () => bad }))).toBe(false)
    expect(writeGateOrigin(4, deps({ tablesReady: () => false }))).toBe(false)
    expect(originCount()).toBe(0)
  })

  it('rejects non-positive or non-integer ids', () => {
    for (const id of [0, -1, 1.5, NaN, Infinity]) expect(writeGateOrigin(id, deps())).toBe(false)
    expect(originCount()).toBe(0)
  })

  it('noteGateOrigin never throws and defers the write past the current tick', async () => {
    const throwing = deps({ getDb: () => { throw new Error('db gone') } })
    expect(() => noteGateOrigin(5, throwing)).not.toThrow()
    noteGateOrigin(6, deps())
    expect(originCount()).toBe(0) // not written synchronously
    await flush()
    expect(originCount()).toBe(1)
    const broken = deps({ readEnv: () => { throw new Error('env unreadable') } })
    expect(() => noteGateOrigin(7, broken)).not.toThrow()
    await flush()
    expect(originCount()).toBe(1)
  })
})

describe('POST /api/memories: response and stored row are identical in every gate state', () => {
  async function scenario(prepare: () => void): Promise<{ results: Captured[]; rows: Array<Record<string, unknown>>; origin: number }> {
    prepare()
    const results: Captured[] = []
    for (const p of POSTS) results.push(await call(tryHandleMemories, 'POST', '/api/memories', p))
    await flush()
    const origin = gateTablesReady() ? originCount() : -1
    return { results, rows: memRows(), origin }
  }
  const norm = (c: Captured) => c.body.replace(/"id":\d+/, '"id":N')

  it('off / shadow / no owners / migration failed / marking DB error all answer and store the same', async () => {
    const off = await scenario(() => { initDatabase(':memory:'); envState.values = { MEMORY_GATE_MODE: 'off', MEMORY_GATE_OWNERS: 'iroda' } })
    const shadow = await scenario(() => { initDatabase(':memory:'); envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' } })
    const noOwners = await scenario(() => { initDatabase(':memory:'); envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: '' } })
    const migFailed = await scenario(() => {
      const realExec = Database.prototype.exec
      const spy = vi.spyOn(Database.prototype, 'exec').mockImplementation(function (this: Database.Database, sql: string) {
        if (sql.includes('memory_gate_origin')) throw Object.assign(new Error('x'), { code: 'SQLITE_BUSY' })
        return realExec.call(this, sql)
      })
      initDatabase(':memory:')
      spy.mockRestore()
      envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' }
    })
    const markError = await scenario(() => {
      initDatabase(':memory:')
      envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' }
      const realPrepare = Database.prototype.prepare
      vi.spyOn(Database.prototype, 'prepare').mockImplementation(function (this: Database.Database, sql: string) {
        if (sql.includes('INTO memory_gate_origin')) throw Object.assign(new Error('x'), { code: 'SQLITE_FULL' })
        return realPrepare.call(this, sql)
      } as never)
    })

    expect(off.results.map(r => r.status)).toEqual([200, 200])
    expect(off.results[0].body).toMatch(/^\{"ok":true,"id":\d+\}$/)
    expect(off.results[1].body).toContain('homoglyph_warning')
    for (const s of [shadow, noOwners, migFailed, markError]) {
      expect(s.results.map(r => [r.status, norm(r)])).toEqual(off.results.map(r => [r.status, norm(r)]))
      expect(s.rows).toEqual(off.rows)
    }
    // ...while the marker side differs exactly as designed
    expect(off.origin).toBe(0)
    expect(shadow.origin).toBe(2)
    expect(noOwners.origin).toBe(0)
    expect(migFailed.origin).toBe(-1)
    expect(markError.origin).toBe(0)
  })

  it('rejected requests (400s) do not reach the marker', async () => {
    initDatabase(':memory:')
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' }
    const empty = await call(tryHandleMemories, 'POST', '/api/memories', { agent_id: 'iroda', content: '   ' })
    const badCat = await call(tryHandleMemories, 'POST', '/api/memories', { agent_id: 'iroda', content: 'valid text for the test', category: 'nope' })
    await flush()
    expect([empty.status, badCat.status]).toEqual([400, 400])
    expect(originCount()).toBe(0)
  })
})

describe('GET /api/memories and GET /api/memories/:id do not see the gate tables', () => {
  it('every branch is byte-identical with empty and with filled gate tables', async () => {
    initDatabase(':memory:')
    envState.values = {}
    const ids: number[] = []
    for (const [i, c] of ['alma kulcs a masodik projektben', 'alma szolgaltatas hatarido penteken', 'korte megjegyzes a szamlazasrol'].entries()) {
      const r = await call(tryHandleMemories, 'POST', '/api/memories', { agent_id: 'iroda', content: c, category: i === 2 ? 'cold' : 'warm', keywords: 'alma, teszt' })
      ids.push(JSON.parse(r.body).id)
    }
    const paths = [
      '/api/memories?agent=iroda',
      '/api/memories?agent=iroda&category=warm',
      '/api/memories?agent=iroda&q=alma',
      '/api/memories?agent=iroda&q=alma&mode=hybrid',
      '/api/memories?agent=iroda&q=alma&mode=hybrid&explain=1',
      '/api/memories?agent=iroda&date=2026-10-23',
      `/api/memories/${ids[0]}`,
      `/api/memories/${ids[2]}`,
    ]
    const run = async () => {
      const out: Array<[number, string]> = []
      for (const p of paths) { const r = await call(tryHandleMemories, 'GET', p); out.push([r.status, r.body]) }
      return out
    }
    const before = await run()
    expect(before.every(([s]) => s === 200)).toBe(true)

    const db = getDb()
    for (const id of ids) db.prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (?, 'api', 1)").run(id)
    db.prepare("INSERT INTO memory_gate_decisions (id, source_id, source_version, rubric, state, op, target_id, would_apply, created_at) VALUES (1, ?, 1, 'g1', 'decided', 'SUPERSEDE', ?, 1, 1)").run(ids[1], ids[0])
    db.prepare("INSERT INTO memory_gate_candidates (decision_id, memory_id, label, version) VALUES (1, ?, 'C1', 1)").run(ids[0])
    db.prepare("INSERT INTO memory_gate_kv (key, value) VALUES ('cursor', '99')").run()

    const after = await run()
    expect(after).toEqual(before)
    expect(JSON.stringify(after)).not.toContain('origin')
  })
})

describe('the daily-log mirror is never marked', () => {
  it('POST /api/daily-log writes a mirror row and no origin marker, even with the gate on', async () => {
    initDatabase(':memory:')
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' }
    const r = await call(tryHandleDailyLog, 'POST', '/api/daily-log', { agent_id: 'iroda', content: '## 10:00 -- Teszt\nMi tortent a napon, eleg hosszu szoveg.' })
    await flush()
    expect(r.status).toBe(200)
    expect(JSON.parse(r.body).memory_mirror).toEqual(expect.any(Number))
    expect(originCount()).toBe(0)
  })
})

describe('source-level guard: the gate never writes memories', () => {
  it('no memories write, no accessed_at assignment, no touchMemoriesAccessed under src/memory-gate/', () => {
    const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'memory-gate')
    const forbidden = /INSERT\s+(?:OR\s+\w+\s+)?INTO\s+memories\b|UPDATE\s+memories\b|DELETE\s+FROM\s+memories\b|touchMemoriesAccessed|accessed_at\s*=(?!=)/i
    const files = readdirSync(dir).filter(f => f.endsWith('.ts'))
    expect(files.length).toBeGreaterThan(0)
    for (const f of files) {
      expect(readFileSync(join(dir, f), 'utf8'), f).not.toMatch(forbidden)
    }
  })
})
