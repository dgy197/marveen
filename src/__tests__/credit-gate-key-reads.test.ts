import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type http from 'node:http'
import type { RouteContext } from '../web/routes/types.js'

// Credit gate, node N5, G-03: the reads of the shared batch key from the Vault
// are counted per day and principal (a counter, never a value), summed up into
// the daily log once the day is over, and shown in the status. The count lives
// on GET /api/vault/:id -- the one door every Bearer caller uses to read a
// value. A broken counter never touches the Vault's answer.

const logSpy = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }))
vi.mock('../logger.js', () => ({ logger: logSpy, PRETTY_OPTIONS: {} }))

const DUMMY_KEY = `sk-ant-TEST-DUMMY-${Math.random().toString(36).slice(2)}`
const KEY_ID = 'ANTHROPIC_API_KEY_BATCH'
vi.mock('../web/vault.js', () => ({
  listSecrets: () => [],
  setSecret: () => undefined,
  deleteSecret: () => false,
  getSecret: (id: string) => (id === 'ANTHROPIC_API_KEY_BATCH' || id === 'OTHER_KEY' ? `${DUMMY_KEY}-${id}` : null),
  getSecretsForEnv: () => ({}),
}))

const keyReads = await import('../web/credit-gate/key-reads.js')
const audit = await import('../web/credit-gate/audit.js')
const { AuditNotifier } = await import('../web/credit-gate/notify.js')
const { setCreditGateRuntime } = await import('../web/credit-gate/runtime.js')
const { tryHandleConnectors } = await import('../web/routes/connectors.js')
const { Harness, T0 } = await import('./fixtures/credit-gate/gate-harness.js')
type Harness = InstanceType<typeof Harness>

const origFetch = globalThis.fetch
let h: Harness | undefined
beforeEach(() => {
  globalThis.fetch = (() => { throw new Error('credit-gate test guard: fetch is not allowed') }) as typeof fetch
  for (const f of Object.values(logSpy)) f.mockClear()
})
afterEach(() => {
  globalThis.fetch = origFetch
  setCreditGateRuntime(null)
  h?.cleanup()
  h = undefined
})

function runtimeOf(x: Harness) {
  return { mode: x.mode, gate: x.gate, storeDir: x.storeDir, db: x.db, startError: null }
}
function harness(o: ConstructorParameters<typeof Harness>[0] = { cal: null }): Harness {
  h = new Harness(o)
  setCreditGateRuntime(runtimeOf(h))
  return h
}

const counts = (x: Harness) => x.db.prepare('SELECT day, principal, count FROM credit_key_reads ORDER BY day, principal').all()
const agent = (name: string) => ({ kind: 'agent', agent: name } as unknown as RouteContext['auth'])

describe('the day', () => {
  it('is the Budapest calendar day, not the UTC one', () => {
    expect(keyReads.budapestDay(Date.UTC(2026, 9, 16, 21, 59, 59))).toBe('2026-10-16')
    expect(keyReads.budapestDay(Date.UTC(2026, 9, 16, 22, 0, 0))).toBe('2026-10-17')
    expect(keyReads.budapestDay(Date.UTC(2026, 0, 15, 23, 30, 0))).toBe('2026-01-16')
  })
})

describe('noteCreditKeyRead', () => {
  it('counts the configured key per day and principal', () => {
    const x = harness()
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0 + 1000)
    keyReads.noteCreditKeyRead(KEY_ID, agent('dani'), runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0 + 86_400_000)
    expect(counts(x)).toEqual([
      { day: '2026-10-16', principal: 'dani', count: 1 },
      { day: '2026-10-16', principal: 'token', count: 2 },
      { day: '2026-10-17', principal: 'token', count: 1 },
    ])
  })

  it('counts only the key named in the config (vaultKeyId), other secrets never', () => {
    const x = harness()
    keyReads.noteCreditKeyRead('SOMETHING_ELSE', { kind: 'token' }, runtimeOf(x), T0)
    keyReads.noteCreditKeyRead('anthropic_api_key_batch', { kind: 'token' }, runtimeOf(x), T0)
    expect(counts(x)).toEqual([])
    x.writeConfig({ vaultKeyId: 'OTHER_KEY' })
    keyReads.noteCreditKeyRead('OTHER_KEY', { kind: 'token' }, runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0)
    expect(counts(x)).toEqual([{ day: '2026-10-16', principal: 'token', count: 1 }])
  })

  it('without a usable config it still counts the default key id (the count must not depend on a healthy config)', () => {
    const x = harness()
    x.writeConfig({ ledgerSources: 'broken' })
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0)
    expect(counts(x)).toEqual([{ day: '2026-10-16', principal: 'token', count: 1 }])
  })

  it('off mode and a gate that does not run write nothing (no table, no side effect)', () => {
    const x = harness()
    const off = { ...runtimeOf(x), mode: { mode: 'off' as const, raw: null, unknown: false }, gate: null }
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, off, T0)
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, { ...runtimeOf(x), db: null }, T0)
    expect(counts(x)).toEqual([])
  })

  it('a hostile principal name is stored as "?", the counter table never grows without bound per name length', () => {
    const x = harness()
    keyReads.noteCreditKeyRead(KEY_ID, agent('x'.repeat(500)), runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, agent("a'; DROP TABLE credit_key_reads;--"), runtimeOf(x), T0)
    expect(counts(x)).toEqual([{ day: '2026-10-16', principal: '?', count: 2 }])
  })

  it('never throws: a closed database is swallowed and logged without any value', () => {
    const x = harness()
    const rt = runtimeOf(x)
    x.db.close()
    expect(() => keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, rt, T0)).not.toThrow()
    expect(logSpy.warn.mock.calls.length + logSpy.error.mock.calls.length).toBeGreaterThan(0)
    expect(JSON.stringify([logSpy.warn.mock.calls, logSpy.error.mock.calls])).not.toContain('TEST-DUMMY')
  })
})

describe('GET /api/vault/:id', () => {
  function get(path: string, auth: RouteContext['auth']) {
    const out = { status: 0, body: '' }
    const res: any = { writeHead(c: number) { out.status = c }, setHeader() { /* unused */ }, getHeader() { return undefined }, end(b?: string) { out.body = b ?? '' } }
    const ctx: RouteContext = {
      req: { headers: {}, method: 'GET', url: path } as unknown as http.IncomingMessage,
      res: res as http.ServerResponse, path, method: 'GET', url: new URL(`http://127.0.0.1:3420${path}`), auth,
    }
    return tryHandleConnectors(ctx).then((handled) => ({ handled, out }))
  }

  it('a read of the shared key is counted and the answer is unchanged; the value is nowhere but in the answer', async () => {
    const x = harness()
    const a = await get(`/api/vault/${KEY_ID}`, { kind: 'token' })
    expect(a.out.status).toBe(200)
    expect(JSON.parse(a.out.body)).toEqual({ id: KEY_ID, value: `${DUMMY_KEY}-${KEY_ID}` })
    await get(`/api/vault/${KEY_ID}`, agent('dani'))
    expect(counts(x)).toEqual([
      { day: keyReads.budapestDay(Date.now()), principal: 'dani', count: 1 },
      { day: keyReads.budapestDay(Date.now()), principal: 'token', count: 1 },
    ])
    const stored = JSON.stringify(x.db.prepare('SELECT * FROM credit_key_reads').all()) + JSON.stringify(x.db.prepare('SELECT * FROM credit_gate_events').all())
    expect(stored).not.toContain('TEST-DUMMY')
    expect(JSON.stringify([logSpy.info.mock.calls, logSpy.warn.mock.calls, logSpy.error.mock.calls])).not.toContain('TEST-DUMMY')
  })

  it('a read of another secret, or of a missing one, is not counted', async () => {
    const x = harness()
    expect((await get('/api/vault/OTHER_KEY', { kind: 'token' })).out.status).toBe(200)
    expect((await get('/api/vault/MISSING', { kind: 'token' })).out.status).toBe(404)
    expect(counts(x)).toEqual([])
  })

  it('a counter that cannot write does not change the Vault\'s answer', async () => {
    const x = harness()
    x.db.exec('DROP TABLE credit_key_reads')
    const a = await get(`/api/vault/${KEY_ID}`, { kind: 'token' })
    expect(a.out.status).toBe(200)
    expect(JSON.parse(a.out.body).value).toBe(`${DUMMY_KEY}-${KEY_ID}`)
  })

  it('with the gate off the route behaves exactly as before and creates nothing', async () => {
    setCreditGateRuntime(null)
    const a = await get(`/api/vault/${KEY_ID}`, { kind: 'token' })
    expect(a.out.status).toBe(200)
  })
})

describe('the daily summary and the status', () => {
  it('a finished day is summed up once, into the daily log only (no message), by principal', async () => {
    const x = harness()
    for (const [who, n] of [['token', 3], ['dani', 2]] as const) {
      for (let i = 0; i < n; i++) keyReads.noteCreditKeyRead(KEY_ID, who === 'token' ? { kind: 'token' } : agent(who), runtimeOf(x), T0)
    }
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0 + 86_400_000)
    const sent = { info: [] as string[], directive: [] as string[], daily: [] as string[] }
    const clock = { now: T0 + 86_400_000 + 1000 } // the next Budapest day
    const n = new AuditNotifier(x.db, {
      now: () => clock.now,
      sendInfo: (t) => { sent.info.push(t); return 1 },
      sendDirective: async (t) => { sent.directive.push(t); return 1 },
      dailyLog: (t) => { sent.daily.push(t) },
    })
    await n.deliver()
    await n.deliver()
    expect(sent.info).toEqual([])
    expect(sent.directive).toEqual([])
    expect(sent.daily).toHaveLength(1)
    expect(sent.daily[0]).toContain('2026-10-16')
    expect(sent.daily[0]).toMatch(/5 olvasas/)
    expect(sent.daily[0]).toContain('token=3')
    expect(sent.daily[0]).toContain('dani=2')
    expect(sent.daily[0]).not.toContain('2026-10-17')
    const ev = x.db.prepare("SELECT kind, daily_logged, notify_state FROM credit_gate_events WHERE kind = 'key_reads_daily'").all()
    expect(ev).toEqual([{ kind: 'key_reads_daily', daily_logged: 1, notify_state: 'skipped' }])
    // The day after tomorrow the second day follows, the first is not repeated.
    clock.now += 86_400_000
    await n.deliver()
    expect(sent.daily).toHaveLength(2)
    expect(sent.daily[1]).toContain('2026-10-17')
  })

  it('the status shows today\'s reads by principal', () => {
    const x = harness()
    keyReads.noteCreditKeyRead(KEY_ID, { kind: 'token' }, runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, agent('dani'), runtimeOf(x), T0)
    keyReads.noteCreditKeyRead(KEY_ID, agent('dani'), runtimeOf(x), T0 - 86_400_000)
    const v = audit.auditStatus(x.db, T0)
    expect(v.key_reads).toEqual({ day: '2026-10-16', total: 2, by_principal: { dani: 1, token: 1 } })
  })

  it('no reads, no table: an empty view', () => {
    expect(audit.auditStatus(null, T0).key_reads).toEqual({ day: '2026-10-16', total: 0, by_principal: {} })
  })
})
