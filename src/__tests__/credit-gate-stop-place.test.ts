import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { appendFileSync, chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync } from 'node:fs'
import { join } from 'node:path'

// Credit gate, finding CW1 (card fec6335f, spec A-03, K-01): a STOP the gate
// must put down but cannot -- an unwritable directory (EACCES), a missing one
// (ENOENT), a read-only file system (EROFS, injected through StopFs) -- used
// to be one `stop_place_failed` row per tick, and the gate stayed OPEN without
// a STOP, also with a canary window open. Now it is a HOLD
// (`stop_place_failed`), never OPEN, and the same after a canary's admission
// when no STOP is down. The episode is reported ONCE (B14): one report row
// (one message, one daily line) and one error log line, however many ticks
// try the STOP again. The HOLD lifts by the existing HOLD rule: the condition
// gone (the STOP is down again) AND a calibration newer than the latch.
// Written from the finding and the brief (Brainy 2148). Nothing here sends a
// thing: the deliverers are injected, and fetch throws if anything tries.

const logSpy = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }))
vi.mock('../logger.js', () => ({ logger: logSpy, PRETTY_OPTIONS: {} }))

const { AuditNotifier } = await import('../web/credit-gate/notify.js')
const { applyCreditGateSchema } = await import('../web/credit-gate/schema.js')
const { nodeStopFs } = await import('../web/credit-gate/stop-file.js')
const { applyPreRound1GateSchema } = await import('./fixtures/credit-gate/old-schema-gate.js')
const { Harness, simpleCal, T0 } = await import('./fixtures/credit-gate/gate-harness.js')
type Harness = InstanceType<typeof Harness>
type HarnessOptions = import('./fixtures/credit-gate/gate-harness.js').HarnessOptions
type NotifyDeps = import('../web/credit-gate/notify.js').NotifyDeps
type StopFs = import('../web/credit-gate/stop-file.js').StopFs

const origFetch = globalThis.fetch
beforeEach(() => {
  globalThis.fetch = (() => { throw new Error('credit-gate test guard: fetch is not allowed') }) as typeof fetch
  for (const f of Object.values(logSpy)) f.mockClear()
})

let harnesses: Harness[] = []
/** Directories a test made unwritable: writable again before the cleanup. */
let lockedDirs: string[] = []
afterEach(() => {
  globalThis.fetch = origFetch
  for (const d of lockedDirs) {
    try { chmodSync(d, 0o700) } catch { /* gone */ }
  }
  lockedDirs = []
  for (const x of harnesses) x.cleanup()
  harnesses = []
})

function harness(o: HarnessOptions = {}): Harness {
  const x = new Harness(o)
  harnesses.push(x)
  return x
}

const PLACE_FAILED_LOG = 'could not put the STOP down'
const ABOUT_IT = /stop_place_failed|a STOP nem irhato/

const canaryReq = (ref: string) => ({ kind: 'canary' as const, budget_micro: 900_000 as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
const headlessReq = { kind: 'headless' as const, budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-other', caller: 'ezermester' }

function errno(code: string): Error {
  return Object.assign(new Error(`${code}: injected`), { code })
}

/** A StopFs on a read-only file system: nothing can be created. */
const erofsFs: StopFs = { ...nodeStopFs, openExclusive: () => { throw errno('EROFS') } }

/** The notifier's view: every message and daily line, delivered after each step. */
function outbox(h: Harness) {
  const sent = { info: [] as string[], directive: [] as string[], daily: [] as string[] }
  let nextId = 900
  const deps: NotifyDeps = {
    now: () => h.now,
    sendInfo: (text) => { sent.info.push(text); return nextId++ },
    sendDirective: async (text) => { sent.directive.push(text); return nextId++ },
    dailyLog: (text) => { sent.daily.push(text) },
  }
  const n = new AuditNotifier(h.db, deps)
  return {
    sent,
    deliver: () => n.deliver(),
    messages: () => [...sent.info, ...sent.directive],
  }
}

function placeFailedLogs(): number {
  return logSpy.error.mock.calls.filter((c) => typeof c[1] === 'string' && c[1].includes(PLACE_FAILED_LOG)).length
}

function stopIsTheGates(h: Harness): boolean {
  return existsSync(h.stopPath) && readFileSync(h.stopPath, 'utf8').startsWith('credit-gate v1 ')
}

/** The three ways the STOP cannot be put down, each with its fault and its repair. */
const FAULTS: Array<{ name: string; detail: string; inject: (h: Harness) => void; repair: (h: Harness) => void }> = [
  {
    name: 'EACCES (an unwritable directory)',
    detail: 'create:EACCES',
    inject: (h) => { chmodSync(h.batchDir, 0o500); lockedDirs.push(h.batchDir) },
    repair: (h) => chmodSync(h.batchDir, 0o700),
  },
  {
    name: 'ENOENT (the directory is missing)',
    detail: 'create:ENOENT',
    inject: (h) => h.writeConfig({ stopFile: join(h.dir, 'missing', 'STOP') }),
    repair: (h) => mkdirSync(join(h.dir, 'missing')),
  },
  {
    name: 'EROFS (a read-only file system, injected through StopFs)',
    detail: 'create:EROFS',
    inject: (h) => { h.stopFs = erofsFs; h.gate = h.makeGate() },
    repair: (h) => { h.stopFs = undefined; h.gate = h.makeGate() },
  },
]

describe('CW1: a STOP that cannot be put down is a HOLD, never OPEN, reported once', () => {
  for (const f of FAULTS) {
    it(`${f.name}: HOLD stop_place_failed; 30 minutes of ticks (a calibration that would open it arrives) -> still HOLD, 1 log line, 1 message, 1 daily line`, async () => {
      const h = harness({ cal: null })
      f.inject(h)
      const box = outbox(h)
      // Closed (no calibration), so the STOP must go down -- and cannot.
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
      await box.deliver()
      const hold = h.events('transition').filter((e) => e.to_state === 'HOLD')
      expect(hold).toHaveLength(1)
      expect(hold[0]).toMatchObject({ reason: 'stop_place_failed' })
      expect(JSON.parse(String(hold[0].detail_json))).toEqual({ why: 'error', detail: f.detail })
      expect(h.state()).toMatchObject({ state: 'HOLD', latch_reason: 'stop_place_failed', latch_cal_id: 0, stop_owner_json: null })
      expect(h.state().stop_place_failed_at).toBe(h.now)
      const afterStart = { messages: box.messages().length, daily: box.sent.daily.length, events: h.events().length }

      // A calibration that would open the gate on its own.
      h.cal = simpleCal(1, '100.00')
      for (let i = 0; i < 60; i++) {
        h.now += 30_000
        expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
        await box.deliver()
      }
      expect(h.events('transition').some((e) => e.to_state === 'OPEN')).toBe(false)
      expect(h.gate.reserve(headlessReq)).toMatchObject({ enforced: true, ok: false, reason: 'gate_closed', detail: 'stop_place_failed' })
      // Once, not per tick: the 60 ticks wrote no row, sent no message, logged nothing.
      expect(h.events().filter((e) => e.kind !== 'reservation_rejected')).toHaveLength(afterStart.events)
      expect(placeFailedLogs()).toBe(1)
      expect(box.messages().filter((t) => ABOUT_IT.test(t))).toHaveLength(1)
      expect(box.sent.daily.filter((t) => ABOUT_IT.test(t))).toHaveLength(1)
      expect(box.messages().slice(afterStart.messages).filter((t) => !t.includes('foglalas elutasitva'))).toEqual([])
      expect(h.events('stop_place_failed')).toEqual([])

      // Lifting: the STOP goes down on the first tick after the repair (still HOLD)...
      f.repair(h)
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
      expect(h.state().stop_place_failed_at).toBeNull()
      expect(h.events('stop_placed')).toHaveLength(1)
      // ...and with the condition gone, the calibration newer than the latch (1 > 0) opens it.
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
      expect(h.events('stop_released')).toHaveLength(1)
      expect(placeFailedLogs()).toBe(1)
    })
  }

  it('the STOP down again but no calibration newer than the latch: the HOLD stays; a newer one lifts it', () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    FAULTS[0].inject(h)
    // The disarm closes it; its STOP cannot go down.
    h.gate.signal('disarm', 'operator', null)
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed', latch_cal_id: 1 })
    expect(h.gate.tick().state).toBe('HOLD')
    FAULTS[0].repair(h)
    for (let i = 0; i < 5; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
      expect(stopIsTheGates(h)).toBe(true)
    }
    expect(h.state().stop_place_failed_at).toBeNull()
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    expect(placeFailedLogs()).toBe(1)
  })

  it('a failure on a gate already in HOLD (a broken ledger source): one HOLD -> HOLD report, then no flapping between the two reasons', () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    appendFileSync(h.usagePath, '{"ts": not json}\n')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_broken:anthropic-batch' })
    expect(stopIsTheGates(h)).toBe(true)
    // Someone removes the STOP and the directory becomes unwritable.
    unlinkSync(h.stopPath)
    FAULTS[0].inject(h)
    const before = h.events('transition').length
    for (let i = 0; i < 30; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    }
    expect(h.events('transition').slice(before).map((e) => [e.from_state, e.to_state, e.reason])).toEqual([['HOLD', 'HOLD', 'stop_place_failed']])
    expect(placeFailedLogs()).toBe(1)
  })

  it('in INCIDENT the state does not change: the episode is one stop_place_failed row (and one log line), not one per tick', () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    FAULTS[2].inject(h)
    h.gate.raiseIncident('guard_event', { where: 'test' })
    expect(h.state().state).toBe('INCIDENT')
    for (let i = 0; i < 20; i++) {
      h.now += 30_000
      expect(h.gate.tick().state).toBe('INCIDENT')
    }
    const rows = h.events('stop_place_failed')
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ reason: 'error' })
    expect(JSON.parse(String(rows[0].detail_json))).toEqual({ why: 'error', detail: 'create:EROFS' })
    expect(h.events('transition').filter((e) => e.reason === 'stop_place_failed')).toEqual([])
    expect(placeFailedLogs()).toBe(1)
  })
})

describe('CW1 + K-01: after a canary\'s admission the STOP must be down, else HOLD', () => {
  for (const f of [FAULTS[0], FAULTS[2]]) {
    it(`${f.name} at the canary's STOP step: HOLD (not OPEN) with the window open; reported once; the close and a newer calibration lift it only once the STOP is down`, async () => {
      const h = harness({ cal: simpleCal(1, '95.00') })
      expect(h.gate.tick().state).toBe('OPEN')
      f.inject(h)
      const box = outbox(h)
      await box.deliver()
      const startMessages = box.messages().length
      const c = h.gate.reserve(canaryReq('hr-canary'))
      if (!c.enforced || !c.ok) throw new Error(`the canary was not admitted: ${JSON.stringify(c)}`)
      expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed', canary_res_id: c.reservation_id })
      expect(existsSync(h.stopPath)).toBe(false)
      for (let i = 0; i < 60; i++) {
        h.now += 30_000
        expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
        await box.deliver()
      }
      expect(h.events('transition').filter((e) => e.to_state === 'OPEN')).toHaveLength(1)
      expect(h.gate.reserve(headlessReq)).toMatchObject({ ok: false, reason: 'gate_closed' })
      expect(placeFailedLogs()).toBe(1)
      expect(box.messages().slice(startMessages).filter((t) => ABOUT_IT.test(t))).toHaveLength(1)
      expect(box.sent.daily.filter((t) => ABOUT_IT.test(t))).toHaveLength(1)
      // The run ends, the after-reading closes the window: still held, the STOP still cannot go down.
      expect(h.gate.settleHeadless(c.reservation_id, null)).toMatchObject({ ok: true })
      expect(h.gate.closeCanary(2)).toMatchObject({ ok: true })
      h.cal = simpleCal(2, '94.00')
      h.now += 30_000
      expect(h.gate.tick().state).toBe('HOLD')
      // Repaired: the STOP goes down (still HOLD), then the newer calibration lifts it.
      f.repair(h)
      h.now += 30_000
      expect(h.gate.tick().state).toBe('HOLD')
      expect(stopIsTheGates(h)).toBe(true)
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
      expect(existsSync(h.stopPath)).toBe(false)
      expect(placeFailedLogs()).toBe(1)
    })
  }

  it('the STOP cannot be checked at the canary\'s STOP step (lstat EIO, nothing placed): HOLD, reported once', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    const fault = { on: false }
    h.stopFs = {
      ...nodeStopFs,
      lstat: (p) => {
        if (fault.on && p === h.stopPath) throw errno('EIO')
        return nodeStopFs.lstat(p)
      },
    }
    h.gate = h.makeGate()
    expect(h.gate.tick().state).toBe('OPEN')
    fault.on = true
    expect(h.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    const hold = h.events('transition').filter((e) => e.to_state === 'HOLD')
    expect(hold).toHaveLength(1)
    expect(JSON.parse(String(hold[0].detail_json))).toEqual({ why: 'not_down', detail: 'lstat:EIO' })
    for (let i = 0; i < 20; i++) {
      h.now += 30_000
      expect(h.gate.tick().state).toBe('HOLD')
    }
    expect(h.events('transition').filter((e) => e.to_state === 'HOLD')).toHaveLength(1)
    expect(placeFailedLogs()).toBe(1)
    // Readable again: the STOP goes down, the condition is gone, the latch (cal 1) holds.
    fault.on = false
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    expect(stopIsTheGates(h)).toBe(true)
    expect(h.state().stop_place_failed_at).toBeNull()
  })

  it('CR1: the canary\'s own STOP is down but cannot be checked afterwards (lstat EIO from the 3rd call): HOLD keeps the owner record; after the repair the STOP is the gate\'s, not a human\'s', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    // Counts lstat calls on the STOP path from the canary's admission on.
    const probe = { on: false, calls: 0 }
    h.stopFs = {
      ...nodeStopFs,
      lstat: (p) => {
        if (probe.on && p === h.stopPath && ++probe.calls >= 3) throw errno('EIO')
        return nodeStopFs.lstat(p)
      },
    }
    h.gate = h.makeGate()
    expect(h.gate.tick().state).toBe('OPEN')
    probe.on = true
    expect(h.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    // The gate's STOP is physically down; only the check after the admission failed.
    expect(stopIsTheGates(h)).toBe(true)
    expect(h.events('stop_placed')).toHaveLength(1)
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    const hold = h.events('transition').filter((e) => e.to_state === 'HOLD')
    expect(hold).toHaveLength(1)
    expect(JSON.parse(String(hold[0].detail_json))).toEqual({ why: 'not_down', detail: 'lstat:EIO' })
    // keepOwner: the record of the gate's own STOP survives the error branch.
    const owner = h.state().stop_owner_json
    expect(owner).not.toBeNull()
    for (let i = 0; i < 5; i++) {
      h.now += 30_000
      expect(h.gate.tick().state).toBe('HOLD')
      expect(h.state().stop_owner_json).toBe(owner)
    }
    // The fault is gone: the STOP is found as the gate's, and no human_stop latch appears.
    probe.on = false
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    expect(h.state()).toMatchObject({ stop_place_failed_at: null, stop_owner_json: owner })
    expect(h.gate.status().stop).toMatchObject({ present: true, owner: 'gate' })
    expect(h.state().latch_reason).not.toBe('human_stop')
    expect(h.events('transition').some((e) => e.reason === 'human_stop')).toBe(false)
    expect(placeFailedLogs()).toBe(1)
  })

  it('the canary\'s STOP placed and gone again before the check: HOLD; the next tick puts it back, and the HOLD stays latched', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    let linked = false
    let lstatsAfterLink = 0
    h.stopFs = {
      ...nodeStopFs,
      link: (a, b) => { nodeStopFs.link(a, b); if (b === h.stopPath) linked = true },
      lstat: (p) => {
        // placeStop's own check after the link sees the STOP; the next look finds it removed.
        if (linked && p === h.stopPath && ++lstatsAfterLink === 2) unlinkSync(h.stopPath)
        return nodeStopFs.lstat(p)
      },
    }
    h.gate = h.makeGate()
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    expect(h.events('stop_placed')).toHaveLength(1)
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed', stop_owner_json: null })
    const hold = h.events('transition').filter((e) => e.to_state === 'HOLD')
    expect(JSON.parse(String(hold[0].detail_json))).toEqual({ why: 'not_down', detail: 'absent' })
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    expect(stopIsTheGates(h)).toBe(true)
    expect(h.state().stop_place_failed_at).toBeNull()
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    expect(placeFailedLogs()).toBe(1)
  })

  it('a canary whose STOP goes down is not affected: OPEN, the window holds the STOP, nothing logged', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    expect(h.state()).toMatchObject({ state: 'OPEN', stop_place_failed_at: null })
    expect(stopIsTheGates(h)).toBe(true)
    expect(placeFailedLogs()).toBe(0)
  })
})

describe('CW1: the schema upgrade', () => {
  it('a state table from before the column gets it empty, and the gate runs on it', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    h.db.exec('DROP TABLE credit_gate_state; DROP TABLE credit_reservations; DROP TABLE credit_gate_events')
    applyPreRound1GateSchema(h.db)
    h.db.prepare(`INSERT INTO credit_gate_state (id, state, reason, since, calibration_id, evaluated_at, version)
      VALUES (1, 'OPEN', 'open', ?, 1, ?, 3)`).run(T0, T0)
    applyCreditGateSchema(h.db)
    applyCreditGateSchema(h.db)
    expect(h.state()).toMatchObject({ stop_place_failed_at: null })
    h.gate = h.makeGate()
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })
})
