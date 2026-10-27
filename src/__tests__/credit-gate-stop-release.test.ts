import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { chmodSync, existsSync, readFileSync } from 'node:fs'

// Credit gate, findings CS1 and CS2 (card fec6335f, spec A-03, K-01; Brainy
// 2148, 2154).
//
// CS1: the gate's own STOP cannot be taken away (an r-x directory: rename
// EACCES; a read-only file system: EROFS). Every tick used to decide OPEN,
// fail the release and close again as a transient `stop_release_failed`: two
// transitions and two messages per tick. Now a tick that would open the gate
// takes its STOP away FIRST, on the non-OPEN side, and decides the opening on
// the outcome: a release that fails is one CLOSED `stop_release_failed`
// (stop_release_failed_at marks the episode), reported once against the last
// reported (state, reason) pair (B14), and every later tick retries the
// release and writes nothing while it still fails. The gate is never OPEN
// while its STOP is down.
//
// CS2: a STOP directory with mode 000 (lstat EACCES) hides whether the STOP
// is down. In enforce mode that is the CW1 episode (HOLD `stop_place_failed`,
// latched), not a transient CLOSED `stop_unverifiable`: repairing the
// permissions does not open the gate on the same calibration; the STOP must be
// shown down AND a newer calibration must come (the HOLD rule).
//
// Written from the findings and the brief. Nothing here sends a thing: the
// deliverers are injected, and fetch throws if anything tries.

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
/** Directories a test locked: writable and searchable again before the cleanup. */
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

const RELEASE_FAILED_LOG = 'could not take its own STOP away'
const PLACE_FAILED_LOG = 'could not put the STOP down'
const ABOUT_RELEASE = /stop_release_failed/
const ABOUT_PLACE = /stop_place_failed|a STOP nem irhato/

const canaryReq = (ref: string) => ({ kind: 'canary' as const, budget_micro: 900_000 as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
const headlessReq = { kind: 'headless' as const, budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-other', caller: 'ezermester' }

function errno(code: string): Error {
  return Object.assign(new Error(`${code}: injected`), { code })
}

/** A StopFs on a read-only file system: nothing can be created, renamed, linked or removed. */
const erofsFs: StopFs = {
  ...nodeStopFs,
  openExclusive: () => { throw errno('EROFS') },
  rename: () => { throw errno('EROFS') },
  link: () => { throw errno('EROFS') },
  unlink: () => { throw errno('EROFS') },
}

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

function logs(text: string): number {
  return logSpy.error.mock.calls.filter((c) => typeof c[1] === 'string' && c[1].includes(text)).length
}

function stopIsTheGates(h: Harness): boolean {
  return existsSync(h.stopPath) && readFileSync(h.stopPath, 'utf8').startsWith('credit-gate v1 ')
}

/** The two ways the gate's own STOP cannot be taken away, each with its repair. */
const RELEASE_FAULTS: Array<{ name: string; detail: string; inject: (h: Harness) => void; repair: (h: Harness) => void }> = [
  {
    name: '0500 (an r-x directory: rename EACCES)',
    detail: 'rename:EACCES',
    inject: (h) => { chmodSync(h.batchDir, 0o500); lockedDirs.push(h.batchDir) },
    repair: (h) => chmodSync(h.batchDir, 0o700),
  },
  {
    name: 'EROFS (a read-only file system, injected through StopFs)',
    detail: 'rename:EROFS',
    inject: (h) => { h.stopFs = erofsFs; h.gate = h.makeGate() },
    repair: (h) => { h.stopFs = undefined; h.gate = h.makeGate() },
  },
]

describe('CS1: a STOP the gate cannot take away is one CLOSED stop_release_failed, never OPEN, reported once', () => {
  for (const f of RELEASE_FAULTS) {
    it(`${f.name}: a calibration that would open it -> 20 ticks: at most 1 message, never OPEN, the STOP stays down; repaired -> OPEN in that tick`, async () => {
      const h = harness({ cal: null })
      const box = outbox(h)
      // Closed (no calibration): the gate's STOP is down.
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
      expect(stopIsTheGates(h)).toBe(true)
      await box.deliver()
      f.inject(h)
      const start = { messages: box.messages().length, daily: box.sent.daily.length, events: h.events().length }

      // A calibration that would open the gate on its own.
      h.cal = simpleCal(1, '100.00')
      for (let i = 0; i < 20; i++) {
        h.now += 30_000
        expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'stop_release_failed' })
        await box.deliver()
        // Never OPEN, and never without the STOP: it is the gate's, and it is down.
        expect(h.state().state).toBe('CLOSED')
        expect(stopIsTheGates(h)).toBe(true)
      }
      const msgs = box.messages().slice(start.messages)
      expect(msgs).toHaveLength(1)
      expect(msgs[0]).toMatch(ABOUT_RELEASE)
      expect(box.sent.daily.slice(start.daily)).toHaveLength(1)
      // The one report row: CLOSED no_calibration -> CLOSED stop_release_failed, with why.
      const rows = h.events().slice(start.events)
      expect(rows.map((e) => [e.kind, e.from_state, e.to_state, e.reason])).toEqual([['transition', 'CLOSED', 'CLOSED', 'stop_release_failed']])
      expect(JSON.parse(String(rows[0].detail_json))).toEqual({ why: 'error', detail: f.detail })
      expect(h.events('transition').some((e) => e.to_state === 'OPEN')).toBe(false)
      expect(logs(RELEASE_FAILED_LOG)).toBe(1)
      expect(h.state().stop_release_failed_at).toBe(T0 + 30_000)
      expect(h.state().stop_owner_json).not.toBeNull()
      expect(h.gate.reserve(headlessReq)).toMatchObject({ enforced: true, ok: false, reason: 'gate_closed', detail: 'stop_release_failed' })

      // Repaired: the next tick takes the STOP away and opens in that same tick.
      f.repair(h)
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
      expect(existsSync(h.stopPath)).toBe(false)
      expect(h.batchDirEntries()).toEqual([])
      expect(h.state()).toMatchObject({ state: 'OPEN', stop_release_failed_at: null, stop_owner_json: null })
      expect(h.events('stop_released')).toHaveLength(1)
      expect(h.events('transition').filter((e) => e.to_state === 'OPEN')).toHaveLength(1)
      expect(logs(RELEASE_FAILED_LOG)).toBe(1)
    })
  }

  it('after the repair the STOP works as before: a disarm puts it down, a newer calibration takes it away, nothing more is logged', async () => {
    const h = harness({ cal: null })
    h.gate.tick()
    RELEASE_FAULTS[0].inject(h)
    h.cal = simpleCal(1, '100.00')
    for (let i = 0; i < 3; i++) {
      h.now += 30_000
      h.gate.tick()
    }
    RELEASE_FAULTS[0].repair(h)
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    const box = outbox(h)
    await box.deliver()
    const start = box.messages().length
    expect(h.gate.signal('disarm', 'operator', null)).toMatchObject({ state: 'CLOSED' })
    expect(stopIsTheGates(h)).toBe(true)
    for (let i = 0; i < 5; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
      expect(stopIsTheGates(h)).toBe(true)
    }
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    await box.deliver()
    expect(box.messages().slice(start).filter((t) => ABOUT_RELEASE.test(t))).toEqual([])
    expect(h.events('stop_released')).toHaveLength(2)
    expect(h.state().stop_release_failed_at).toBeNull()
    expect(logs(RELEASE_FAILED_LOG)).toBe(1)
  })

  it('another closing reason during the episode: the STOP is not taken away even once the directory is repaired, until nothing else closes the gate', () => {
    const h = harness({ cal: null })
    h.gate.tick()
    RELEASE_FAULTS[0].inject(h)
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'stop_release_failed' })
    // A disarm latches it under calibration 1.
    h.gate.signal('disarm', 'operator', null)
    RELEASE_FAULTS[0].repair(h)
    for (let i = 0; i < 5; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
      expect(stopIsTheGates(h)).toBe(true)
    }
    expect(h.events('stop_released')).toEqual([])
    // A newer calibration lifts the latch: the release goes through and it opens.
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    expect(h.state().stop_release_failed_at).toBeNull()
    // The episode was reported once: no stop_release_failed report besides the first.
    expect(h.events('transition').filter((e) => e.reason === 'stop_release_failed')).toHaveLength(1)
  })

  it('a latch lifted while the release still fails: one report for the new reason, no opening, the STOP stays', async () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.gate.signal('disarm', 'operator', null)
    expect(stopIsTheGates(h)).toBe(true)
    RELEASE_FAULTS[1].inject(h)
    const box = outbox(h)
    await box.deliver()
    const start = box.messages().length
    h.cal = simpleCal(2, '100.00')
    for (let i = 0; i < 20; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'stop_release_failed' })
      await box.deliver()
      expect(stopIsTheGates(h)).toBe(true)
    }
    expect(box.messages().slice(start)).toHaveLength(1)
    expect(h.events('transition').map((e) => [e.from_state, e.to_state, e.reason]).slice(-1)).toEqual([['CLOSED', 'CLOSED', 'stop_release_failed']])
    expect(logs(RELEASE_FAILED_LOG)).toBe(1)
  })

  for (const f of RELEASE_FAULTS) {
    it(`${f.name} when a canary window closes on an OPEN gate: one CLOSED stop_release_failed, then 20 ticks: no message, never OPEN; repaired -> OPEN`, async () => {
      const h = harness({ cal: simpleCal(1, '95.00') })
      expect(h.gate.tick().state).toBe('OPEN')
      const c = h.gate.reserve(canaryReq('hr-canary'))
      if (!c.enforced || !c.ok) throw new Error(`the canary was not admitted: ${JSON.stringify(c)}`)
      expect(stopIsTheGates(h)).toBe(true)
      expect(h.gate.settleHeadless(c.reservation_id, null)).toMatchObject({ ok: true })
      f.inject(h)
      const box = outbox(h)
      await box.deliver()
      const start = { messages: box.messages().length, transitions: h.events('transition').length }
      // The close step takes the STOP away right away (an OPEN gate): it cannot.
      expect(h.gate.closeCanary(2)).toMatchObject({ ok: true })
      expect(h.state()).toMatchObject({ state: 'CLOSED', reason: 'stop_release_failed' })
      expect(stopIsTheGates(h)).toBe(true)
      h.cal = simpleCal(2, '94.00')
      for (let i = 0; i < 20; i++) {
        h.now += 30_000
        expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'stop_release_failed' })
        await box.deliver()
        expect(stopIsTheGates(h)).toBe(true)
      }
      const msgs = box.messages().slice(start.messages)
      expect(msgs).toHaveLength(1)
      expect(msgs[0]).toMatch(ABOUT_RELEASE)
      expect(h.events('transition').slice(start.transitions).map((e) => [e.from_state, e.to_state, e.reason])).toEqual([['OPEN', 'CLOSED', 'stop_release_failed']])
      expect(logs(RELEASE_FAILED_LOG)).toBe(1)
      f.repair(h)
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
      expect(existsSync(h.stopPath)).toBe(false)
      expect(h.state().stop_release_failed_at).toBeNull()
    })
  }

  it('an ordinary opening takes the STOP away before the gate is OPEN: stop_released is written before the OPEN transition', () => {
    const h = harness({ cal: null })
    h.gate.tick()
    expect(stopIsTheGates(h)).toBe(true)
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    const kinds = h.events().filter((e) => e.kind === 'stop_released' || (e.kind === 'transition' && e.to_state === 'OPEN')).map((e) => e.kind)
    expect(kinds).toEqual(['stop_released', 'transition'])
    expect(existsSync(h.stopPath)).toBe(false)
    expect(logs(RELEASE_FAILED_LOG)).toBe(0)
  })
})

describe('CS2: a STOP directory with mode 000 (lstat EACCES) is a HOLD, not a transient CLOSED', () => {
  it('an OPEN gate: HOLD stop_place_failed, reported once in 20 ticks; repaired, the same calibration does not open it; a newer one does, once the STOP is shown down', async () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    const box = outbox(h)
    await box.deliver()
    const start = { messages: box.messages().length, events: h.events().length }
    chmodSync(h.batchDir, 0o000)
    lockedDirs.push(h.batchDir)
    for (let i = 0; i < 20; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
      await box.deliver()
    }
    const rows = h.events().slice(start.events)
    expect(rows.map((e) => [e.kind, e.from_state, e.to_state, e.reason])).toEqual([['transition', 'OPEN', 'HOLD', 'stop_place_failed']])
    expect(JSON.parse(String(rows[0].detail_json))).toEqual({ why: 'not_down', detail: 'lstat:EACCES' })
    expect(box.messages().slice(start.messages)).toHaveLength(1)
    expect(box.messages().slice(start.messages)[0]).toMatch(ABOUT_PLACE)
    expect(h.state()).toMatchObject({ latch_reason: 'stop_place_failed', latch_cal_id: 1 })
    expect(logs(PLACE_FAILED_LOG)).toBe(1)
    expect(h.events('transition').some((e) => e.reason === 'stop_unverifiable')).toBe(false)

    // Repaired: the STOP goes down, the condition is gone -- and the same calibration still holds it.
    chmodSync(h.batchDir, 0o700)
    for (let i = 0; i < 10; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
      expect(stopIsTheGates(h)).toBe(true)
    }
    expect(h.state().stop_place_failed_at).toBeNull()
    expect(h.events('transition').some((e) => e.to_state === 'OPEN' && Number(e.id) > Number(rows[0].id))).toBe(false)
    expect(h.gate.reserve(headlessReq)).toMatchObject({ enforced: true, ok: false, reason: 'gate_closed' })
    // A newer calibration lifts it, and the gate's own STOP comes off.
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    expect(logs(PLACE_FAILED_LOG)).toBe(1)
  })

  it('the gate\'s own STOP hidden by mode 000 keeps its owner record: after the repair it is found as the gate\'s, not a human\'s, and taken away by a newer calibration', () => {
    const h = harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.gate.signal('disarm', 'operator', null)
    expect(stopIsTheGates(h)).toBe(true)
    const owner = h.state().stop_owner_json
    expect(owner).not.toBeNull()
    chmodSync(h.batchDir, 0o000)
    lockedDirs.push(h.batchDir)
    for (let i = 0; i < 5; i++) {
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    }
    expect(h.state().stop_owner_json).toBe(owner)
    chmodSync(h.batchDir, 0o700)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'stop_place_failed' })
    expect(h.state()).toMatchObject({ stop_place_failed_at: null, stop_owner_json: owner })
    expect(h.gate.status().stop).toMatchObject({ present: true, owner: 'gate' })
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    expect(h.events('transition').some((e) => e.reason === 'human_stop')).toBe(false)
  })

  it('shadow mode keeps the transient stop_unverifiable: no STOP duty, nothing latched', () => {
    const h = harness({ cal: simpleCal(1, '100.00'), mode: 'shadow' })
    chmodSync(h.batchDir, 0o000)
    lockedDirs.push(h.batchDir)
    h.gate.tick()
    // shadow_mode comes first in the close reasons; the STOP problem is a close reason, not a HOLD.
    expect(h.state()).toMatchObject({ state: 'CLOSED', stop_place_failed_at: null, latch_cal_id: null })
    expect(logs(PLACE_FAILED_LOG)).toBe(0)
  })
})

describe('CS1: the schema upgrade', () => {
  it('a state table from before the column gets it empty, and the gate runs on it', () => {
    const h = harness({ cal: simpleCal(1, '95.00') })
    h.db.exec('DROP TABLE credit_gate_state; DROP TABLE credit_reservations; DROP TABLE credit_gate_events')
    applyPreRound1GateSchema(h.db)
    h.db.prepare(`INSERT INTO credit_gate_state (id, state, reason, since, calibration_id, evaluated_at, version)
      VALUES (1, 'OPEN', 'open', ?, 1, ?, 3)`).run(T0, T0)
    applyCreditGateSchema(h.db)
    applyCreditGateSchema(h.db)
    expect(h.state()).toMatchObject({ stop_release_failed_at: null })
    h.gate = h.makeGate()
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })
})
