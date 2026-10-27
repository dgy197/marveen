/**
 * Memory write gate b1 (card 3e9f6c28, node B1-S): the three read-only routes.
 *  - Bearer gate (requiresAuth) covers them; web.ts routes them before tryHandleMemories;
 *  - 404 / 400 / 405 / 503 and limit bounds;
 *  - SR-6a-r6 B3: NO route ever returns a `reason` key or the stored reason text.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import Database from 'better-sqlite3'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { initDatabase, getDb } from '../db.js'
import { tryHandleMemoryGate } from '../web/routes/memory-gate.js'
import { requiresAuth } from '../web/auth-gate.js'
import { resetGateSchemaFlags } from '../memory-gate/schema.js'
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

const REASON_TEXT = 'masked classifier sentence about the budget memory'

async function get(pathAndQuery: string, method = 'GET') {
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  let status = 200
  let raw = ''
  const res = { writeHead: (c: number) => { status = c }, setHeader: () => {}, end: (b?: string) => { raw = b || '' } }
  const handled = await tryHandleMemoryGate({ req: {} as any, res: res as any, path: url.pathname, method, url })
  return { handled, status, raw, body: raw ? JSON.parse(raw) : null }
}

function keysDeep(v: unknown, out: string[] = []): string[] {
  if (Array.isArray(v)) v.forEach(x => keysDeep(x, out))
  else if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { out.push(k); keysDeep(x, out) }
  return out
}

function seed(): void {
  const db = getDb()
  const ins = db.prepare(`INSERT INTO memory_gate_decisions
    (id, source_id, source_version, rubric, state, op, target_id, target_version, confidence, reason, model, would_apply, error_class, skip_reason, mode, created_at, decided_at)
    VALUES (?, ?, 1, 'g1', ?, ?, ?, 1, 0.9, ?, 'claude-haiku-5-5', ?, ?, ?, 'shadow', 1000, 1001)`)
  ins.run(1, 101, 'decided', 'SUPERSEDE', 100, REASON_TEXT, 1, null, null)
  ins.run(2, 102, 'decided', 'CREATE', null, REASON_TEXT, 0, null, null)
  ins.run(3, 103, 'decided', 'UNKNOWN', null, null, 0, 'daily_cap', null)
  ins.run(4, 104, 'skipped', null, null, null, 0, null, 'too_short')
  ins.run(5, 105, 'pending', null, null, null, 0, null, null)
  db.prepare("INSERT INTO memory_gate_candidates (decision_id, memory_id, label, version) VALUES (1, 100, 'C1', 1), (1, 99, 'C2', 1)").run()
  db.prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (101, 'api', 1), (102, 'api', 1)").run()
  db.prepare("INSERT INTO memory_gate_kv (key, value) VALUES ('cursor', '102'), ('first_shadow_at', '1000'), ('shadow_count', '3')").run()
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda,hajcsar' }
  resetGateSchemaFlags()
  initDatabase(':memory:')
  seed()
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('auth and wiring', () => {
  it('the global Bearer gate covers all three paths', () => {
    for (const p of ['/api/memories/gate/status', '/api/memories/gate/decisions', '/api/memories/gate/decisions/1']) {
      expect(requiresAuth(p, 'GET'), p).toBe(true)
    }
  })

  it('web.ts mounts the gate router before tryHandleMemories', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'web.ts'), 'utf8')
    const gate = src.indexOf('tryHandleMemoryGate(routeCtx)')
    const mem = src.indexOf('tryHandleMemories(routeCtx)')
    expect(gate).toBeGreaterThan(0)
    expect(mem).toBeGreaterThan(gate)
  })

  it('unrelated paths fall through', async () => {
    expect((await get('/api/memories')).handled).toBe(false)
    expect((await get('/api/memories/12')).handled).toBe(false)
    expect((await get('/api/memories/gate')).handled).toBe(false)
    expect((await get('/api/memories/gate/decisions/1/revert', 'POST')).handled).toBe(false)
  })

  it('a non-GET on a gate path is 405, not a fall-through to the memory routes', async () => {
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const r = await get('/api/memories/gate/decisions/1', m)
      expect([r.handled, r.status]).toEqual([true, 405])
    }
  })
})

describe('GET /api/memories/gate/status', () => {
  it('reports mode, owner count (not names), tables, rows and the kv counters', async () => {
    const r = await get('/api/memories/gate/status')
    expect(r.status).toBe(200)
    expect(r.body.mode).toEqual({ configured: 'shadow', effective: 'shadow', invalid: false })
    expect(r.body.owners).toBe(2)
    expect(r.raw).not.toContain('hajcsar')
    expect(r.raw).not.toContain('iroda')
    expect(r.body.tables_ready).toBe(true)
    expect(r.body.migration_failed).toBe(false)
    expect(r.body.rows).toEqual({ pending: 1, in_flight: 0, decided: 3, skipped: 1, failed: 0 })
    expect(r.body.origin_marked).toBe(2)
    expect(r.body.cursor).toBe(102)
    expect(r.body.first_shadow_at).toBe(1000)
    expect(r.body.shadow_count).toBe(3)
    expect(r.body.today.calls).toBe(0)
  })

  it('active is reported as configured=active, effective=shadow (b1 has no effect)', async () => {
    envState.values = { MEMORY_GATE_MODE: 'active', MEMORY_GATE_OWNERS: 'iroda' }
    expect((await get('/api/memories/gate/status')).body.mode).toEqual({ configured: 'active', effective: 'shadow', invalid: false })
  })

  it('with a failed migration it says so and still answers 200', async () => {
    const realExec = Database.prototype.exec
    const spy = vi.spyOn(Database.prototype, 'exec').mockImplementation(function (this: Database.Database, sql: string) {
      if (sql.includes('memory_gate_origin')) throw Object.assign(new Error('x'), { code: 'SQLITE_FULL' })
      return realExec.call(this, sql)
    })
    resetGateSchemaFlags()
    initDatabase(':memory:')
    spy.mockRestore()
    const r = await get('/api/memories/gate/status')
    expect(r.status).toBe(200)
    expect(r.body.tables_ready).toBe(false)
    expect(r.body.migration_failed).toBe(true)
    expect(r.body.migration_failure).toBe('SQLITE_FULL')
    expect(r.body.rows).toEqual({})
  })

  it('a forbidden owner shows as a config error with zero owners', async () => {
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda,feszek' }
    const r = await get('/api/memories/gate/status')
    expect(r.body.owners).toBe(0)
    expect(r.body.owner_config_error).toBe('forbidden_owner')
  })
})

describe('GET /api/memories/gate/decisions', () => {
  it('lists newest first and shapes would_apply as a boolean', async () => {
    const r = await get('/api/memories/gate/decisions')
    expect(r.body.decisions.map((d: any) => d.id)).toEqual([5, 4, 3, 2, 1])
    expect(r.body.decisions.find((d: any) => d.id === 1).would_apply).toBe(true)
    expect(r.body.decisions.find((d: any) => d.id === 2).would_apply).toBe(false)
    expect(r.body.limit).toBe(50)
  })

  it('limit is clamped to 1..200 and must be digits', async () => {
    expect((await get('/api/memories/gate/decisions?limit=2')).body.decisions).toHaveLength(2)
    expect((await get('/api/memories/gate/decisions?limit=0')).body.limit).toBe(1)
    expect((await get('/api/memories/gate/decisions?limit=100000')).body.limit).toBe(200)
    for (const bad of ['-1', 'abc', '1.5', '1e3', '9999999']) {
      expect((await get(`/api/memories/gate/decisions?limit=${bad}`)).status, bad).toBe(400)
    }
  })

  it('before_id, op and state filter; garbage is a 400, never SQL', async () => {
    expect((await get('/api/memories/gate/decisions?before_id=3')).body.decisions.map((d: any) => d.id)).toEqual([2, 1])
    expect((await get('/api/memories/gate/decisions?op=SUPERSEDE')).body.decisions.map((d: any) => d.id)).toEqual([1])
    expect((await get('/api/memories/gate/decisions?state=skipped')).body.decisions.map((d: any) => d.id)).toEqual([4])
    expect((await get('/api/memories/gate/decisions?op=UNKNOWN&state=decided')).body.decisions.map((d: any) => d.id)).toEqual([3])
    for (const q of ['before_id=x', "op=CREATE'%20OR%201=1", 'op=create', 'state=done', 'before_id=-5']) {
      expect((await get(`/api/memories/gate/decisions?${q}`)).status, q).toBe(400)
    }
  })

  it('503 when the gate tables are not available', async () => {
    resetGateSchemaFlags()
    expect((await get('/api/memories/gate/decisions')).status).toBe(503)
    expect((await get('/api/memories/gate/decisions/1')).status).toBe(503)
  })
})

describe('GET /api/memories/gate/decisions/:id', () => {
  it('returns the decision with its candidates', async () => {
    const r = await get('/api/memories/gate/decisions/1')
    expect(r.status).toBe(200)
    expect(r.body).toMatchObject({ id: 1, source_id: 101, op: 'SUPERSEDE', target_id: 100, would_apply: true, state: 'decided' })
    expect(r.body.candidates).toEqual([{ label: 'C1', memory_id: 100, version: 1 }, { label: 'C2', memory_id: 99, version: 1 }])
  })

  it('404 for a missing id and for a malformed id', async () => {
    expect((await get('/api/memories/gate/decisions/999')).status).toBe(404)
    for (const bad of ['abc', '1abc', '-1', '1.5', '0x10', '99999999999999']) {
      expect((await get(`/api/memories/gate/decisions/${bad}`)).status, bad).toBe(404)
    }
  })
})

describe('SR-6a-r6 B3: no route ever exposes `reason`', () => {
  it('status, list and /:id carry no reason key and not the stored text', async () => {
    const all = [
      await get('/api/memories/gate/status'),
      await get('/api/memories/gate/decisions'),
      await get('/api/memories/gate/decisions?op=SUPERSEDE&limit=200'),
      await get('/api/memories/gate/decisions/1'),
      await get('/api/memories/gate/decisions/2'),
      await get('/api/memories/gate/decisions/3'),
    ]
    // sanity: the text really is in the table, so the absence below is the routes' doing
    expect((getDb().prepare('SELECT reason FROM memory_gate_decisions WHERE id = 1').get() as { reason: string }).reason).toBe(REASON_TEXT)
    for (const r of all) {
      expect(r.status).toBe(200)
      expect(keysDeep(r.body)).not.toContain('reason')
      expect(r.raw).not.toContain(REASON_TEXT)
    }
  })

  it('no SELECT * and no reason column anywhere in the route source', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'routes', 'memory-gate.ts'), 'utf8')
    const code = src.split('\n').filter(l => !l.trim().startsWith('//')).join('\n')
    expect(code).not.toMatch(/SELECT\s+\*/i)
    expect(code).not.toMatch(/\breason\b\s*[,)]|,\s*reason\b/)
  })
})
