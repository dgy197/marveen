/**
 * Memory write gate b1 (card 3e9f6c28, node G2c): the worker round, the .env-only config,
 * the credit-gate pause (SR-6a-r6 B2), the caps, the kill switch, the reason sweep and the
 * runner wiring. Fake clock, fake transport (a spy), in-memory DB: no child process, no network.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { readFileSync, readdirSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

const envState = vi.hoisted(() => ({ values: {} as Record<string, string> }))
vi.mock('../logger.js', () => ({ logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() } }))
vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  return { ...actual, MAIN_AGENT_ID: 'brainy', OLLAMA_URL: '' }
})
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

import { initDatabase, getDb, appendDailyLog } from '../db.js'
import { gateTablesReady } from '../memory-gate/schema.js'
import {
  resolveGateConfig, readGateConfig, creditPause, makeDisableCheck, nextDayStart, dayStart, dayKey,
  DAILY_USD_CEILING_MICRO, type CreditView,
} from '../memory-gate/state.js'
import { runGateTick, newWorkerState, singleFlight, sweepReasons, type WorkerDeps, type AlertCause } from '../memory-gate/worker.js'
import { evaluateApply } from '../memory-gate/evaluate.js'
import type { GateCall, GateCallResult, GateErrorClass } from '../memory-gate/transport.js'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')
const clock = { now: 0 }
const nowS = () => Math.floor(clock.now / 1000)

function put(agent: string, category: string, content: string, o: { age?: number; keywords?: string | null; embedding?: string | null; origin?: boolean } = {}): number {
  const created = nowS() - (o.age ?? 3600)
  const id = Number(getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience, created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
     VALUES ('0', NULL, ?, 'semantic', 1.0, ?, ?, ?, ?, 0, ?, ?)`,
  ).run(content, created, created, agent, category, o.keywords ?? null, o.embedding ?? null).lastInsertRowid)
  if (o.origin !== false) getDb().prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (?, 'api', ?)").run(id, created)
  return id
}

const ANSWER = (op: string, target: string | null, conf: number) => JSON.stringify({ op, target, confidence: conf, reason: 'same item' })

interface Spy { calls: GateCall[]; rounds: number; answer: (c: GateCall) => GateCallResult }
function spy(): Spy {
  return { calls: [], rounds: 0, answer: (c) => ({ k: c.k, ok: true, text: ANSWER('REINFORCE', 'C1', 0.9) }) }
}

function cfgOf(over: Record<string, string> = {}) {
  return resolveGateConfig({ MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'hajcsar', MEMORY_GATE_BATCH_DIR: '/tmp/fake-batch', ...over }, 'brainy')
}

const CREDIT_OFF: CreditView = { mode: 'off', unknown: false, startError: null, gate: null }
const alerts: Array<{ cause: AlertCause; text: string }> = []

function deps(s: Spy, over: Partial<WorkerDeps> = {}, cfg = cfgOf()): WorkerDeps {
  return {
    db: getDb,
    now: () => clock.now,
    config: cfg,
    tablesReady: gateTablesReady,
    disabled: () => false,
    credit: () => CREDIT_OFF,
    estimateMicro: () => 1350,
    transport: async (calls) => { s.rounds++; s.calls.push(...calls); return calls.map(s.answer) },
    alert: (cause, text) => { alerts.push({ cause, text }) },
    nonce: () => '0123456789abcdef',
    ...over,
  }
}

const count = (table: string) => (getDb().prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n
const decisions = () => getDb().prepare('SELECT * FROM memory_gate_decisions ORDER BY id').all() as Array<Record<string, any>>
const decisionFor = (sourceId: number) => getDb().prepare('SELECT * FROM memory_gate_decisions WHERE source_id = ?').get(sourceId) as Record<string, any> | undefined
const setCursor = (v: number) => getDb().prepare("INSERT INTO memory_gate_kv (key, value) VALUES ('cursor', ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value").run(String(v))

/** One candidate and one source of hajcsar, sharing words; returns ids. */
function pair(owner = 'hajcsar', tag = 'zorvalux'): { cand: number; src: number } {
  const cand = put(owner, 'warm', `${tag} projekt tervezes hatarido egyeztetes kesz allapot`, { origin: false })
  const src = put(owner, 'warm', `${tag} projekt tervezes hatarido modositva uj datummal mostantol`)
  return { cand, src }
}

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  initDatabase(':memory:')
  clock.now = Date.now()
  alerts.length = 0
  envState.values = {}
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('(b) off mode or no owners: nothing at all', () => {
  it('writes no row into any gate table and calls nothing', async () => {
    pair()
    for (const over of [{ MEMORY_GATE_MODE: 'off' }, { MEMORY_GATE_OWNERS: '' }, { MEMORY_GATE_MODE: 'bogus' }] as Array<Record<string, string>>) {
      const s = spy()
      const r = await runGateTick(deps(s, {}, cfgOf(over)), newWorkerState())
      expect(r.outcome).toBe('off')
      expect(s.calls).toHaveLength(0)
    }
    for (const t of ['memory_gate_decisions', 'memory_gate_candidates', 'memory_gate_daily', 'memory_gate_kv']) expect(count(t)).toBe(0)
  })
})

describe('(c) transport spy (GB1): only the allowed owner\'s warm/cold rows ever reach a prompt', () => {
  it('across several rounds no other marker appears in any system or prompt text', async () => {
    setCursor(0)
    const common = 'projekt tervezes hatarido kerekgyarto ajanlat'
    const allowed = {
      a1: put('hajcsar', 'warm', `alfaquin ${common} egy`, { origin: false }),
      a2: put('hajcsar', 'cold', `betorvix ${common} ketto`, { origin: false }),
    }
    const denied: Record<string, number> = {
      hot: put('hajcsar', 'hot', `frestagon ${common} harom`),
      shared: put('hajcsar', 'shared', `dolmerix ${common} negy`),
      otherWarm: put('iroda', 'warm', `velkandra ${common} ot`),
      otherShared: put('iroda', 'shared', `tarnopell ${common} hat`),
      feszek: put('feszek', 'warm', `ombrelix ${common} het`),
      main: put('brainy', 'warm', `kastrovian ${common} nyolc`),
    }
    appendDailyLog('hajcsar', `plenthorix ${common} naplo bejegyzes tukor`)
    const src1 = put('hajcsar', 'warm', `cinderwal ${common} uj forras egy`)
    const src2 = put('hajcsar', 'cold', `dravenmo ${common} uj forras ketto`)
    clock.now += 120_000
    const s = spy()
    const st = newWorkerState()
    for (let i = 0; i < 3; i++) { await runGateTick(deps(s), st); clock.now += 60_000 }
    expect(s.calls.length).toBeGreaterThanOrEqual(2)
    const all = s.calls.map(c => `${c.system}\n${c.prompt}`).join('\n')
    for (const w of ['frestagon', 'dolmerix', 'velkandra', 'tarnopell', 'ombrelix', 'kastrovian', 'plenthorix']) expect(all).not.toContain(w)
    for (const w of ['alfaquin', 'betorvix', 'cinderwal', 'dravenmo']) expect(all).toContain(w)
    // hot / shared / foreign rows never become a source either
    for (const id of Object.values(denied)) {
      const d = decisionFor(id)
      if (d) expect(d.state).toBe('skipped')
    }
    expect(decisionFor(denied.otherWarm)).toBeUndefined()
    expect(decisionFor(denied.feszek)).toBeUndefined()
    expect(decisionFor(denied.main)).toBeUndefined()
    expect(decisionFor(allowed.a1)).toBeUndefined()
    expect(decisionFor(src1)?.state).toBe('decided')
    expect(decisionFor(src2)?.state).toBe('decided')
  })
})

describe('(d) owner list: feszek forbidden in code, brainy only with MEMORY_GATE_MAIN_AGENT_OK=tg-<n>', () => {
  it('feszek in the list is a config error whatever else is set: 0 calls, 0 rows', async () => {
    pair()
    for (const over of [{ MEMORY_GATE_OWNERS: 'hajcsar,feszek' }, { MEMORY_GATE_OWNERS: 'feszek', MEMORY_GATE_MAIN_AGENT_OK: 'tg-3341' }] as Array<Record<string, string>>) {
      const s = spy()
      const cfg = cfgOf(over)
      expect(cfg.configError).toBe('forbidden_owner')
      expect((await runGateTick(deps(s, {}, cfg), newWorkerState())).outcome).toBe('config_error')
      expect(s.calls).toHaveLength(0)
    }
    expect(count('memory_gate_decisions') + count('memory_gate_kv')).toBe(0)
  })

  it('brainy rows are classified only with a well-formed approval reference', async () => {
    for (const [ok, expected] of [[undefined, 0], ['', 0], ['tg-abc', 0], ['3341', 0], ['tg-3341', 1]] as const) {
      initDatabase(':memory:')
      setCursor(0)
      pair('brainy')
      clock.now += 120_000
      const s = spy()
      const cfg = cfgOf({ MEMORY_GATE_OWNERS: 'brainy,hajcsar', ...(ok === undefined ? {} : { MEMORY_GATE_MAIN_AGENT_OK: ok }) })
      await runGateTick(deps(s, {}, cfg), newWorkerState())
      expect(s.calls.length).toBe(expected)
    }
  })
})

describe('(e) GN1: .env only, nothing in the registry or the overrides', () => {
  it('readGateConfig takes every key from readEnvFile', () => {
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'hajcsar', MEMORY_GATE_BATCH_DIR: '/x', MEMORY_GATE_MAX_CALLS_PER_DAY: '7' }
    const c = readGateConfig('brainy')
    expect(c.env.owners.owners).toEqual(['hajcsar'])
    expect(c.maxCallsPerDay).toBe(7)
    expect(c.configError).toBeNull()
  })
  it('state.ts never reads cfg()/overrides and no MEMORY_GATE_ key is in the config registry', () => {
    const code = (f: string) => readFileSync(join(SRC, 'memory-gate', f), 'utf8').split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l)).join('\n')
    for (const f of ['state.ts', 'gate-env.ts', 'worker.ts']) {
      expect(code(f), f).not.toMatch(/\bcfg\(|config-overrides|import\s*\{[^}]*\bcfg\b/)
    }
    expect(readFileSync(join(SRC, 'config-registry.ts'), 'utf8')).not.toContain('MEMORY_GATE_')
  })
  it('the daily USD ceiling is 0.50 in code: a higher .env value is a config error', () => {
    expect(cfgOf().dailyUsdMicro).toBe(DAILY_USD_CEILING_MICRO)
    expect(DAILY_USD_CEILING_MICRO).toBe(500_000)
    expect(cfgOf({ MEMORY_GATE_DAILY_USD: '0.51' }).configError).toBe('bad_daily_usd')
    expect(cfgOf({ MEMORY_GATE_DAILY_USD: '0.20' }).dailyUsdMicro).toBe(200_000)
    expect(cfgOf({ MEMORY_GATE_BATCH_DIR: 'relative' }).configError).toBe('bad_batch_dir')
  })
})

describe('(f)(u)(v) cursor', () => {
  it('first run sets the cursor to max(id) and classifies nothing already stored', async () => {
    pair()
    const s = spy()
    await runGateTick(deps(s), newWorkerState())
    expect(count('memory_gate_decisions')).toBe(0)
    expect(s.calls).toHaveLength(0)
    const max = (getDb().prepare('SELECT MAX(id) AS m FROM memories').get() as { m: number }).m
    expect(getDb().prepare("SELECT value FROM memory_gate_kv WHERE key = 'cursor'").get()).toEqual({ value: String(max) })
  })

  it('(u) unmarked, mirror and foreign rows: 0 calls, 0 decision rows, the cursor steps over them; a restart continues', async () => {
    setCursor(0)
    put('hajcsar', 'warm', 'import sor projekt tervezes hatarido negyven karakter felett', { origin: false })
    appendDailyLog('hajcsar', 'naplo tukor projekt tervezes hatarido negyven karakter felett')
    const foreign = put('iroda', 'warm', 'idegen sor projekt tervezes hatarido negyven karakter felett')
    clock.now += 120_000
    const s = spy()
    await runGateTick(deps(s), newWorkerState())
    expect(s.calls).toHaveLength(0)
    expect(count('memory_gate_decisions')).toBe(0)
    const cur = Number((getDb().prepare("SELECT value FROM memory_gate_kv WHERE key = 'cursor'").get() as { value: string }).value)
    expect(cur).toBeGreaterThanOrEqual(foreign)
    const { src } = pair()
    clock.now += 120_000
    await runGateTick(deps(s), newWorkerState()) // fresh state = restart
    expect(decisionFor(src)?.state).toBe('decided')
  })

  it('(v) a row younger than 60 s holds the cursor, so a late origin marker is not lost', async () => {
    setCursor(0)
    const cand = put('hajcsar', 'warm', 'zorvalux projekt tervezes hatarido egyeztetes kesz', { origin: false })
    const young = put('hajcsar', 'warm', 'zorvalux projekt tervezes hatarido modositva most', { age: 10, origin: false })
    const s = spy()
    await runGateTick(deps(s), newWorkerState())
    expect(Number((getDb().prepare("SELECT value FROM memory_gate_kv WHERE key = 'cursor'").get() as { value: string }).value)).toBe(cand)
    getDb().prepare("INSERT INTO memory_gate_origin (memory_id, origin, noted_at) VALUES (?, 'api', ?)").run(young, nowS())
    clock.now += 11 * 60_000
    await runGateTick(deps(s), newWorkerState())
    expect(decisionFor(young)?.state).toBe('decided')
    expect(s.calls).toHaveLength(1)
  })
})

describe('(g)(h)(i) skip reasons, vector wait, zero candidates', () => {
  it('(g) category, too_short, episode and too_old', async () => {
    setCursor(0)
    const hot = put('hajcsar', 'hot', 'forro sor projekt tervezes hatarido negyven karakter felett')
    const short = put('hajcsar', 'warm', 'rovid sor')
    const ep = put('hajcsar', 'cold', 'epizod blokk projekt tervezes hatarido negyven karakter felett', { keywords: 'epizod, episodic, ugynok:hajcsar' })
    const old = put('hajcsar', 'warm', 'regi sor projekt tervezes hatarido negyven karakter felett', { age: 73 * 3600 })
    await runGateTick(deps(spy()), newWorkerState())
    expect(decisionFor(hot)).toMatchObject({ state: 'skipped', skip_reason: 'category' })
    expect(decisionFor(short)).toMatchObject({ state: 'skipped', skip_reason: 'too_short' })
    expect(decisionFor(ep)).toMatchObject({ state: 'skipped', skip_reason: 'episode' })
    expect(decisionFor(old)).toMatchObject({ state: 'skipped', skip_reason: 'too_old', op: 'UNKNOWN' })
  })

  it('(h) no vector and younger than 10 minutes: no attempt; afterwards keyword-only', async () => {
    setCursor(0)
    put('hajcsar', 'warm', 'zorvalux projekt tervezes hatarido egyeztetes kesz', { origin: false })
    const src = put('hajcsar', 'warm', 'zorvalux projekt tervezes hatarido modositva most', { age: 5 * 60 })
    const s = spy()
    await runGateTick(deps(s), newWorkerState())
    expect(s.calls).toHaveLength(0)
    expect(decisionFor(src)).toMatchObject({ state: 'pending', attempts: 0 })
    clock.now += 6 * 60_000
    await runGateTick(deps(s), newWorkerState())
    expect(s.calls).toHaveLength(1)
  })

  it('(i) no candidate: CREATE without a call', async () => {
    setCursor(0)
    const src = put('hajcsar', 'warm', 'teljesen egyedi szoveg semmi kozos a tobbivel itt van')
    const s = spy()
    await runGateTick(deps(s), newWorkerState())
    expect(s.calls).toHaveLength(0)
    expect(decisionFor(src)).toMatchObject({ state: 'decided', op: 'CREATE', would_apply: 0 })
  })
})

describe('(j) single flight', () => {
  it('a second round while one runs returns busy', async () => {
    let release!: () => void
    const gate = new Promise<void>(r => { release = r })
    const run = singleFlight(async () => { await gate; return 'done' })
    const a = run()
    expect(await run()).toBe('busy')
    release()
    expect(await a).toBe('done')
    expect(await run()).toBe('done')
  })
})

describe('(k)(l) caps, Budapest day, static ceiling, price', () => {
  it('Budapest midnight on DST days (25 h and 23 h days)', () => {
    const tz = 'Europe/Budapest'
    expect(new Date(nextDayStart(Date.UTC(2026, 9, 24, 12), tz)).toISOString()).toBe('2026-10-24T22:00:00.000Z')
    expect(new Date(nextDayStart(Date.UTC(2026, 9, 25, 10), tz)).toISOString()).toBe('2026-10-25T23:00:00.000Z')
    expect(new Date(dayStart(Date.UTC(2026, 9, 25, 10), tz)).toISOString()).toBe('2026-10-24T22:00:00.000Z')
    expect(new Date(nextDayStart(Date.UTC(2026, 2, 29, 10), tz)).toISOString()).toBe('2026-03-29T22:00:00.000Z')
    expect(new Date(dayStart(Date.UTC(2026, 2, 29, 10), tz)).toISOString()).toBe('2026-03-28T23:00:00.000Z')
    expect(dayKey(Date.UTC(2026, 9, 24, 22, 30), tz)).toBe('2026-10-25')
  })

  it('daily call cap: the next row waits until tomorrow 00:05 as daily_cap; one alert per day', async () => {
    setCursor(0)
    const a = pair('hajcsar', 'zorvalux')
    const b = pair('hajcsar', 'quimbleton')
    const s = spy()
    const d = deps(s, {}, cfgOf({ MEMORY_GATE_MAX_CALLS_PER_DAY: '1' }))
    await runGateTick(d, newWorkerState())
    await runGateTick(d, newWorkerState())
    expect(s.calls).toHaveLength(1)
    expect(decisionFor(a.src)?.state).toBe('decided')
    expect(decisionFor(b.src)).toMatchObject({ state: 'pending', error_class: 'daily_cap', next_at: Math.floor(nextDayStart(clock.now) / 1000) + 300 })
    expect(alerts.filter(x => x.cause === 'daily_cap')).toHaveLength(1)
    // 73 hours later still capped -> too_old closes it as UNKNOWN with the reason it waited on
    clock.now += 73 * 3600_000
    await runGateTick(deps(s, { estimateMicro: () => null }, cfgOf({ MEMORY_GATE_MAX_CALLS_PER_DAY: '1' })), newWorkerState())
    expect(decisionFor(b.src)).toMatchObject({ state: 'skipped', op: 'UNKNOWN', skip_reason: 'too_old', error_class: 'daily_cap' })
  })

  it('daily USD cap by reservation', async () => {
    setCursor(0)
    pair('hajcsar', 'zorvalux'); pair('hajcsar', 'quimbleton'); const c = pair('hajcsar', 'brimoleon')
    const s = spy()
    const cfg = cfgOf({ MEMORY_GATE_DAILY_USD: '0.01', MEMORY_GATE_MAX_CALLS_PER_DAY: '5' })
    await runGateTick(deps(s, { estimateMicro: (_m, bytes) => (bytes === cfg.maxPromptBytes ? 1350 : 4000) }, cfg), newWorkerState())
    expect(s.calls).toHaveLength(2)
    expect(decisionFor(c.src)?.error_class).toBe('daily_cap')
    const day = getDb().prepare('SELECT calls, reserved_usd_micro FROM memory_gate_daily').get() as { calls: number; reserved_usd_micro: number }
    expect(day).toEqual({ calls: 2, reserved_usd_micro: 8000 })
  })

  it('(l) static ceiling exceeded or no usable price: no call', async () => {
    setCursor(0)
    const { src } = pair()
    const s = spy()
    expect((await runGateTick(deps(s, { estimateMicro: () => 2000 }), newWorkerState())).outcome).toBe('static_cap') // 300 x 2000 > 500000
    expect((await runGateTick(deps(s, { estimateMicro: () => null }), newWorkerState())).outcome).toBe('unpriced')
    expect(s.calls).toHaveLength(0)
    expect(decisionFor(src)).toMatchObject({ state: 'pending', error_class: 'unpriced' })
  })
})

describe('(m)(w) every error branch ends in UNKNOWN with a named class', () => {
  async function one(error: GateErrorClass | 'bad_output', prev: string | null = null) {
    initDatabase(':memory:')
    setCursor(0)
    const { src } = pair()
    if (prev) {
      await runGateTick(deps(spy(), { estimateMicro: () => null }), newWorkerState())
      getDb().prepare('UPDATE memory_gate_decisions SET error_class = ? WHERE source_id = ?').run(prev, src)
    }
    const s = spy()
    s.answer = (c) => (error === 'bad_output' ? { k: c.k, ok: true, text: 'not json' } : { k: c.k, ok: false, error })
    const st = newWorkerState()
    await runGateTick(deps(s), st)
    return { d: decisionFor(src)!, st, s }
  }

  it('final classes', async () => {
    for (const [cls, state] of [['bad_output', 'failed'], ['bad_request', 'failed'], ['error', 'failed'], ['secret_residue', 'skipped'], ['usage_log_failed', 'failed']] as const) {
      const { d } = await one(cls)
      expect(d, cls).toMatchObject({ state, op: 'UNKNOWN', error_class: cls })
    }
  })

  it('maybe_billed: not again today, final the second time', async () => {
    const first = await one('maybe_billed')
    expect(first.d).toMatchObject({ state: 'pending', error_class: 'maybe_billed', next_at: Math.floor(nextDayStart(clock.now) / 1000) + 300 })
    const second = await one('maybe_billed', 'maybe_billed')
    expect(second.d).toMatchObject({ state: 'failed', op: 'UNKNOWN', error_class: 'maybe_billed' })
  })

  it('transient backs off; stopped keeps the attempt; restart breakers stop the gate', async () => {
    const t = await one('transient')
    expect(t.d).toMatchObject({ state: 'pending', error_class: 'transient', attempts: 1, next_at: nowS() + 120 })
    const st = await one('stopped')
    expect(st.d).toMatchObject({ state: 'pending', attempts: 0 })
    for (const cls of ['auth', 'contract_mismatch', 'untrusted_batch_dir', 'residue_check_unavailable', 'usage_log_failed'] as const) {
      const r = await one(cls)
      expect(r.st.breaker, cls).toEqual({ reason: cls, until: null })
      const again = spy()
      expect((await runGateTick(deps(again), r.st)).outcome).toBe('breaker')
      expect(again.calls).toHaveLength(0)
    }
    const credit = await one('credit')
    expect(credit.st.breaker).toEqual({ reason: 'credit', until: nextDayStart(clock.now) })
  })

  it('E3: a transient failure keeps an earlier maybe_billed mark, so the second maybe_billed is still final', async () => {
    const t = await one('transient', 'maybe_billed')
    expect(t.d).toMatchObject({ state: 'pending', error_class: 'maybe_billed', attempts: 1, next_at: nowS() + 120 })
    // after the back-off the row is picked again; a second maybe_billed now ends it
    clock.now += 121_000
    const s = spy()
    s.answer = (c) => ({ k: c.k, ok: false, error: 'maybe_billed' })
    await runGateTick(deps(s), newWorkerState())
    expect(decisionFor(t.d.source_id)).toMatchObject({ state: 'failed', op: 'UNKNOWN', error_class: 'maybe_billed' })
  })

  it('B10: a timer queued before the tick runs while a long tick is still going (the tick yields)', async () => {
    setCursor(0)
    for (let i = 0; i < 6; i++) pair('hajcsar', `yieldtag${i}x`)
    let timerRan = false
    let foundAfterTimer = 0
    const t = setTimeout(() => { timerRan = true }, 0)
    const s = spy()
    const r = await runGateTick(deps(s, {
      findCandidates: (_db, _src) => { if (timerRan) foundAfterTimer++; return { hits: [], rejected: 0, ftsTerms: 0, vectorUsed: false } },
    }), newWorkerState())
    clearTimeout(t)
    expect(r.outcome).toBe('ran')
    expect(timerRan).toBe(true)
    expect(foundAfterTimer).toBeGreaterThan(0) // the timer fired while sources were still being processed
  })

  it('a stale in_flight row goes back to pending as maybe_billed', async () => {
    setCursor(0)
    const { src } = pair()
    await runGateTick(deps(spy(), { estimateMicro: () => null }), newWorkerState())
    getDb().prepare("UPDATE memory_gate_decisions SET state = 'in_flight', claimed_at = ? WHERE source_id = ?").run(nowS() - 601, src)
    await runGateTick(deps(spy(), { estimateMicro: () => null }), newWorkerState())
    expect(decisionFor(src)).toMatchObject({ state: 'pending', error_class: 'maybe_billed' })
  })
})

describe('(n) SR-6a-r6 B2: the credit gate pause', () => {
  const v = (o: Partial<CreditView>): CreditView => ({ mode: 'enforce', unknown: false, startError: null, gate: { state: 'OPEN' }, ...o })
  it('enforce runs ONLY with a gate object in state OPEN', () => {
    expect(creditPause(v({}))).toBeNull()
    expect(creditPause(v({ gate: null }))).toBe('credit_unknown')
    expect(creditPause(v({ startError: 'boom' }))).toBe('credit_unknown')
    expect(creditPause(v({ unknown: true }))).toBe('credit_unknown')
    for (const state of ['CLOSED', 'HOLD', 'INCIDENT', 'UNREADABLE']) expect(creditPause(v({ gate: { state } }))).toBe('credit_paused')
    expect(creditPause(v({ mode: 'shadow', gate: { state: 'CLOSED' } }))).toBeNull()
    expect(creditPause(v({ mode: 'off', gate: null }))).toBeNull()
  })

  it('a round under each pause makes no call and marks the waiting rows; shadow+CLOSED runs', async () => {
    const cases: Array<[Partial<CreditView>, string | null]> = [
      [{ gate: { state: 'CLOSED' } }, 'credit_paused'], [{ gate: null }, 'credit_unknown'],
      [{ startError: 'x' }, 'credit_unknown'], [{ unknown: true }, 'credit_unknown'], [{ mode: 'shadow', gate: { state: 'CLOSED' } }, null],
    ]
    for (const [o, pause] of cases) {
      initDatabase(':memory:')
      setCursor(0)
      const { src } = pair()
      const s = spy()
      await runGateTick(deps(s, { credit: () => v(o) }), newWorkerState())
      if (pause) {
        expect(s.calls).toHaveLength(0)
        expect(decisionFor(src)).toMatchObject({ state: 'pending', error_class: pause })
      } else {
        expect(s.calls).toHaveLength(1)
      }
    }
  })
})

describe('(o) DISABLE within 5 s, without restart', () => {
  it('lstat-based, cached at most 5 s, fail-closed on an odd error', async () => {
    const t = { now: 1_000_000 }
    let present = false
    const lstat = () => { if (present) return {}; const e = new Error('x') as Error & { code: string }; e.code = 'ENOENT'; throw e }
    const check = makeDisableCheck('/store', () => t.now, lstat)
    expect(check()).toBe(false)
    present = true
    t.now += 4_999
    expect(check()).toBe(false)
    t.now += 1
    expect(check()).toBe(true)
    const odd = makeDisableCheck('/store', () => 0, () => { const e = new Error('x') as Error & { code: string }; e.code = 'EACCES'; throw e })
    expect(odd()).toBe(true)
    setCursor(0)
    pair()
    const s = spy()
    expect((await runGateTick(deps(s, { disabled: () => true }), newWorkerState())).outcome).toBe('disabled')
    expect(s.calls).toHaveLength(0)
  })
})

describe('(q) would_apply is exactly evaluateApply', () => {
  const lim = { supersedeMinConf: 0.85, otherMinConf: 0.7, maxSupersedePerDay: 20, maxContradictPerDay: 20 }
  const base = { op: 'SUPERSEDE' as const, confidence: 0.9, sourceId: 10, sourceOwner: 'hajcsar', offeredVersion: 0, target: { id: 5, agent_id: 'hajcsar', category: 'warm', version: 0 }, appliedToday: 0 }
  it('each SUPERSEDE condition broken alone gives a named block', () => {
    expect(evaluateApply(base, lim)).toEqual({ wouldApply: true, block: null })
    expect(evaluateApply({ ...base, confidence: 0.84 }, lim).block).toBe('low_confidence')
    expect(evaluateApply({ ...base, target: null }, lim).block).toBe('target_missing')
    expect(evaluateApply({ ...base, target: { ...base.target, id: 10 } }, lim).block).toBe('self_target')
    expect(evaluateApply({ ...base, target: { ...base.target, id: 11 } }, lim).block).toBe('target_newer')
    expect(evaluateApply({ ...base, target: { ...base.target, agent_id: 'iroda' } }, lim).block).toBe('other_owner')
    expect(evaluateApply({ ...base, target: { ...base.target, category: 'shared' } }, lim).block).toBe('target_category')
    expect(evaluateApply({ ...base, target: { ...base.target, version: 1 } }, lim).block).toBe('target_changed')
    expect(evaluateApply({ ...base, appliedToday: 20 }, lim).block).toBe('daily_cap')
    expect(evaluateApply({ ...base, op: 'CONTRADICT', appliedToday: 20 }, lim).block).toBe('daily_cap')
    expect(evaluateApply({ ...base, op: 'MERGE' }, lim).block).toBe('proposal_only')
    expect(evaluateApply({ ...base, op: 'CREATE' }, lim)).toEqual({ wouldApply: false, block: null })
  })

  it('the round records what evaluateApply says, with the masked reason and the offered target', async () => {
    setCursor(0)
    const { cand, src } = pair()
    const s = spy()
    s.answer = (c) => ({ k: c.k, ok: true, text: ANSWER('SUPERSEDE', 'C1', 0.9) })
    await runGateTick(deps(s), newWorkerState())
    expect(decisionFor(src)).toMatchObject({ state: 'decided', op: 'SUPERSEDE', target_id: cand, target_version: 0, would_apply: 1, apply_block: null, reason: 'same item', mode: 'shadow' })
    expect(getDb().prepare("SELECT value FROM memory_gate_kv WHERE key = 'shadow_count'").get()).toEqual({ value: '1' })
    const low = pair('hajcsar', 'quimbleton')
    s.answer = (c) => ({ k: c.k, ok: true, text: ANSWER('SUPERSEDE', 'C1', 0.8) })
    clock.now += 60_000
    await runGateTick(deps(s), newWorkerState())
    expect(decisionFor(low.src)).toMatchObject({ would_apply: 0, apply_block: 'low_confidence' })
  })
})

describe('(r) inert without verified tables; (s) alerts; sweep', () => {
  it('migration_failed: no call', async () => {
    setCursor(0)
    pair()
    const s = spy()
    expect((await runGateTick(deps(s, { tablesReady: () => false }), newWorkerState())).outcome).toBe('migration_failed')
    expect(s.calls).toHaveLength(0)
  })

  it('(s) one alert per cause per day', async () => {
    for (let i = 0; i < 3; i++) {
      initDatabase(':memory:')
      setCursor(0)
      pair()
      const s = spy()
      s.answer = (c) => ({ k: c.k, ok: false, error: 'error' })
      await runGateTick(deps(s), newWorkerState())
    }
    // three separate DBs = three "first" alerts; within one DB the bit holds:
    const s = spy()
    s.answer = (c) => ({ k: c.k, ok: false, error: 'error' })
    pair('hajcsar', 'quimbleton')
    clock.now += 60_000
    await runGateTick(deps(s), newWorkerState())
    expect(alerts.filter(a => a.cause === 'error')).toHaveLength(3)
  })

  it('the sweep nulls the reason when the source, the target or any candidate is gone', async () => {
    setCursor(0)
    const a = pair('hajcsar', 'zorvalux')
    const s = spy()
    s.answer = (c) => ({ k: c.k, ok: true, text: ANSWER('REINFORCE', 'C1', 0.9) })
    await runGateTick(deps(s), newWorkerState())
    expect(decisionFor(a.src)?.reason).toBe('same item')
    expect(sweepReasons(getDb())).toBe(0)
    getDb().prepare('DELETE FROM memories WHERE id = ?').run(a.cand)
    expect(sweepReasons(getDb())).toBe(1)
    expect(decisionFor(a.src)?.reason).toBeNull()
  })
})

describe('(t)(x) wiring and the b1 boundary (source level)', () => {
  it('(t) index.ts starts the runner after the keep-warm runner and stops it on shutdown', () => {
    const idx = readFileSync(join(SRC, 'index.ts'), 'utf8')
    expect(idx).toMatch(/startEmbeddingKeepWarmRunner\(\)\n\s*try \{ startMemoryGateRunner\(\) \}/)
    expect(idx).toMatch(/try \{ stopMemoryGateRunner\(\) \}/)
  })

  it('(x) b1 never applies a decision and never writes the effect table', () => {
    const files = [
      ...readdirSync(join(SRC, 'memory-gate')).filter(f => f.endsWith('.ts')).map(f => join(SRC, 'memory-gate', f)),
      join(SRC, 'web', 'memory-gate-runner.ts'),
      join(SRC, 'web', 'routes', 'memory-gate.ts'),
    ]
    expect(files.length).toBeGreaterThanOrEqual(11)
    for (const f of files) {
      const text = readFileSync(f, 'utf8')
      expect(text, f).not.toMatch(/\bapplyDecision\s*\(/)
      expect(text, f).not.toMatch(/(INSERT\s+(OR\s+\w+\s+)?INTO|UPDATE|DELETE\s+FROM|REPLACE\s+INTO|CREATE\s+TABLE(\s+IF\s+NOT\s+EXISTS)?)\s+memory_gate_state\b/i)
    }
  })
})
