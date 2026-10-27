import { describe, it, expect, afterEach } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { parseCreditGateConfig, DEFAULT_CANARY_CLOSE_H, MAX_CANARY_CLOSE_H } from '../web/credit-gate/config.js'
import type { CreditGate } from '../web/credit-gate/gate.js'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { applyPreRound1GateSchema } from './fixtures/credit-gate/old-schema-gate.js'
import { configObject, Harness, HOUR, simpleCal, T0, type HarnessOptions } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, finding N7B1 (card fec6335f, spec K-01): the canary's cost must
// be the only one between its two Console readings. The gate's STOP therefore
// stays down -- and nothing else is admitted -- from the canary's admission
// until an EXPLICIT close step, the recording of the after-reading
// (closeCanary), not only until the canary's reservation is settled at the end
// of its run. If the close does not come within canaryCloseMaxH hours of the
// settle (config, at most 24 in the code), the gate goes on HOLD
// (`canary_close_timeout`), never OPEN, and the STOP stays down. The window is
// in the database, so a dashboard restart between the two steps keeps it.
// Written from the finding and the brief (Brainy 2137), not from the code:
//  (a) between the settle and the close: the STOP stays down, no other
//      reservation (batch, headless, a second canary) is admitted;
//  (b) the deadline passes without the close: HOLD, not OPEN, the STOP down;
//  (c) after the close: the old behaviour -- in OPEN the STOP goes;
//  (d) a restart (a new gate on a new connection) between the two steps;
//  (e) a repeated close, or one with no canary: refused, nothing changes.

let h: Harness
function harness(o: HarnessOptions = {}): Harness {
  h = new Harness(o)
  return h
}
afterEach(() => h?.cleanup())

const canaryReq = (ref: string) => ({ kind: 'canary' as const, budget_micro: 900_000 as never, model: 'claude-sonnet-5-5', ref, caller: 'ezermester' })
const headlessReq = { kind: 'headless' as const, budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-other', caller: 'ezermester' }
const batchReq = { kind: 'batch' as const, model: 'claude-haiku-5-5', input_tokens_total: 1000, max_output_tokens_total: 0, request_count: 1, caller: 'rag' }

/** OPEN under calibration 1, the canary admitted and its run settled: the window's middle. */
function settledCanary(o: HarnessOptions = {}): { g: Harness; reservationId: string } {
  const g = harness({ cal: simpleCal(1, '95.00'), ...o })
  expect(g.gate.tick().state).toBe('OPEN')
  const c = g.gate.reserve(canaryReq('hr-canary'))
  if (!c.enforced || !c.ok) throw new Error(`the canary was not admitted: ${JSON.stringify(c)}`)
  expect(existsSync(g.stopPath)).toBe(true)
  expect(g.gate.settleHeadless(c.reservation_id, null)).toMatchObject({ ok: true, status: 'settled' })
  return { g, reservationId: c.reservation_id }
}

function stopIsTheGates(g: Harness): boolean {
  return existsSync(g.stopPath) && readFileSync(g.stopPath, 'utf8').startsWith('credit-gate v1 ')
}

describe('(a) between the canary\'s settle and the close: the STOP stays down, nothing else is admitted', () => {
  it('the settle does not lift the STOP; ticks keep it; batch, headless and a second canary get canary_window_open', () => {
    const { g, reservationId } = settledCanary()
    // The run is over (no canary in progress), the window is not.
    expect(g.gate.canaryInProgress()).toBe(false)
    expect(g.gate.canaryBlock()).toBe('canary_window_open')
    expect(stopIsTheGates(g)).toBe(true)
    expect(g.state()).toMatchObject({ state: 'OPEN', canary_res_id: reservationId })
    for (let i = 0; i < 3; i++) {
      g.now += 30_000
      expect(g.gate.tick().state).toBe('OPEN')
      expect(stopIsTheGates(g)).toBe(true)
    }
    const before = g.reservations().length
    expect(g.gate.reserve(batchReq)).toMatchObject({ enforced: true, ok: false, reason: 'canary_window_open' })
    expect(g.gate.reserve(headlessReq)).toMatchObject({ enforced: true, ok: false, reason: 'canary_window_open' })
    expect(g.gate.reserve(canaryReq('hr-canary-2'))).toMatchObject({ enforced: true, ok: false, reason: 'canary_window_open' })
    // No other spending got in: no new reservation, the STOP still the gate's.
    expect(g.reservations()).toHaveLength(before)
    expect(g.events('reservation_rejected').map((e) => e.reason)).toEqual(['canary_window_open', 'canary_window_open', 'canary_window_open'])
    expect(stopIsTheGates(g)).toBe(true)
    const st = g.gate.status()
    expect(st).toMatchObject({ state: 'OPEN', canary_in_progress: false, stop: { present: true, owner: 'gate' } })
    expect(st.canary_window).toMatchObject({
      reservation_id: reservationId,
      run_id: 'hr-canary',
      opened_at: new Date(T0).toISOString(),
      run_ended_at: new Date(T0).toISOString(),
      close_by: new Date(T0 + DEFAULT_CANARY_CLOSE_H * HOUR).toISOString(),
    })
    expect(g.events('canary_window_opened')).toHaveLength(1)
    expect(g.events('canary_window_closed')).toHaveLength(0)
  })

  it('while the canary still runs the reason is canary_in_progress, and the window is already open', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    g.gate.tick()
    const c = g.gate.reserve(canaryReq('hr-canary')) as { ok: true; reservation_id: string }
    expect(g.gate.canaryBlock()).toBe('canary_in_progress')
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'canary_in_progress' })
    expect(g.gate.status().canary_window).toMatchObject({ reservation_id: c.reservation_id, run_ended_at: null, close_by: null })
  })
})

describe('(b) the close does not come in time: HOLD canary_close_timeout, never OPEN, the STOP down', () => {
  it('canaryCloseMaxH after the settle the tick holds; it stays held; the late close and a newer calibration lift it', () => {
    const { g } = settledCanary({ config: { canaryCloseMaxH: 2 } })
    g.now = T0 + 2 * HOUR - 1
    expect(g.gate.tick().state).toBe('OPEN')
    expect(stopIsTheGates(g)).toBe(true)
    g.now = T0 + 2 * HOUR
    expect(g.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
    expect(stopIsTheGates(g)).toBe(true)
    expect(g.events('transition').filter((e) => e.reason === 'canary_close_timeout')).toHaveLength(1)
    for (let i = 0; i < 3; i++) {
      g.now += 30_000
      expect(g.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
      expect(stopIsTheGates(g)).toBe(true)
    }
    // Reported once, not on every tick.
    expect(g.events('transition').filter((e) => e.reason === 'canary_close_timeout')).toHaveLength(1)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'gate_closed', detail: 'canary_close_timeout' })
    // The after-reading comes late: the window closes, the HOLD is latched and stays...
    expect(g.gate.closeCanary(2)).toMatchObject({ ok: true })
    g.now += 30_000
    expect(g.gate.tick().state).toBe('HOLD')
    expect(stopIsTheGates(g)).toBe(true)
    // ...until the gate sees that newer calibration.
    g.cal = simpleCal(2, '94.00', { captured_at_lb_ms: T0 + HOUR })
    g.now += 30_000
    expect(g.gate.tick().state).toBe('OPEN')
    expect(existsSync(g.stopPath)).toBe(false)
  })

  it('a newer calibration without the close does not lift it: the condition stays', () => {
    const { g } = settledCanary({ config: { canaryCloseMaxH: 1 } })
    g.now = T0 + HOUR
    expect(g.gate.tick().state).toBe('HOLD')
    g.cal = simpleCal(2, '94.00', { captured_at_lb_ms: T0 + 30 * 60_000 })
    g.now += 30_000
    expect(g.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
    expect(stopIsTheGates(g)).toBe(true)
  })

  it('without a valid config the code\'s ceiling (24 h) applies, and the gate holds then', () => {
    const { g } = settledCanary({ config: { canaryCloseMaxH: 2 } })
    g.writeConfig({ canaryCloseMaxH: 25 })
    g.now = T0 + 3 * HOUR
    expect(g.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'config_invalid' })
    expect(stopIsTheGates(g)).toBe(true)
    g.now = T0 + MAX_CANARY_CLOSE_H * HOUR
    expect(g.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
    expect(stopIsTheGates(g)).toBe(true)
  })

  it('the deadline does not run while the canary is still running', () => {
    const g = harness({ cal: simpleCal(1, '95.00'), config: { canaryCloseMaxH: 1 } })
    g.gate.tick()
    expect(g.gate.reserve(canaryReq('hr-canary'))).toMatchObject({ ok: true })
    g.now = T0 + 3 * HOUR
    expect(g.gate.tick().state).toBe('OPEN')
    expect(stopIsTheGates(g)).toBe(true)
  })
})

describe('(c) after the close: the old behaviour', () => {
  it('in OPEN the STOP goes, and a batch is admitted again', () => {
    const { g, reservationId } = settledCanary()
    const r = g.gate.closeCanary(2)
    expect(r).toEqual({ ok: true, reservation_id: reservationId })
    expect(existsSync(g.stopPath)).toBe(false)
    expect(g.gate.canaryBlock()).toBeNull()
    expect(g.state()).toMatchObject({ state: 'OPEN', canary_res_id: null, canary_opened_at: null })
    expect(g.gate.status()).toMatchObject({ canary_in_progress: false, canary_window: null, stop: { present: false, owner: 'none' } })
    g.now += 30_000
    g.gate.tick()
    expect(existsSync(g.stopPath)).toBe(false)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: true })
    const closed = g.events('canary_window_closed')
    expect(closed).toHaveLength(1)
    expect(closed[0]).toMatchObject({ reason: 'after_reading', calibration_id: 2 })
    expect(JSON.parse(String(closed[0]!.detail_json))).toMatchObject({ reservation_id: reservationId, run_id: 'hr-canary' })
  })

  it('a close inside the caller\'s transaction (syncStop false) leaves the STOP to the caller\'s sync', () => {
    const { g } = settledCanary()
    expect(g.gate.closeCanary(2, g.now, false)).toMatchObject({ ok: true })
    expect(stopIsTheGates(g)).toBe(true)
    g.gate.syncStopFile()
    expect(existsSync(g.stopPath)).toBe(false)
  })

  it('a close while the canary still runs: its open reservation keeps the STOP until the settle', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    g.gate.tick()
    const c = g.gate.reserve(canaryReq('hr-canary')) as { ok: true; reservation_id: string }
    expect(g.gate.closeCanary(2)).toMatchObject({ ok: true })
    expect(stopIsTheGates(g)).toBe(true)
    expect(g.gate.reserve(batchReq)).toMatchObject({ ok: false, reason: 'canary_in_progress' })
    g.gate.settleHeadless(c.reservation_id, null)
    expect(existsSync(g.stopPath)).toBe(false)
  })
})

describe('(d) a dashboard restart between the settle and the close keeps the window', () => {
  it('a new gate on a new connection: the STOP stays, nothing is admitted, the status shows it; its close works', () => {
    const { g, reservationId } = settledCanary()
    const g2: CreditGate = g.makeGate(g.openDb())
    expect(g2.canaryBlock()).toBe('canary_window_open')
    g.now += 30_000
    expect(g2.tick().state).toBe('OPEN')
    expect(stopIsTheGates(g)).toBe(true)
    expect(g2.reserve(batchReq)).toMatchObject({ ok: false, reason: 'canary_window_open' })
    expect(g2.status().canary_window).toMatchObject({ reservation_id: reservationId, run_ended_at: new Date(T0).toISOString() })
    // The deadline counts from the settle, across the restart.
    g.now = T0 + DEFAULT_CANARY_CLOSE_H * HOUR
    expect(g2.tick()).toMatchObject({ state: 'HOLD', reason: 'canary_close_timeout' })
    expect(g2.closeCanary(2)).toMatchObject({ ok: true })
    expect(g.gate.canaryBlock()).toBeNull()
  })

  it('the close after the restart releases the STOP in OPEN', () => {
    const { g } = settledCanary()
    const g2 = g.makeGate(g.openDb())
    g.now += 30_000
    g2.tick()
    expect(stopIsTheGates(g)).toBe(true)
    expect(g2.closeCanary(2)).toMatchObject({ ok: true })
    expect(existsSync(g.stopPath)).toBe(false)
    expect(g2.reserve(batchReq)).toMatchObject({ ok: true })
  })
})

describe('(e) a repeated close, or one without a canary: refused, nothing changes', () => {
  function snapshot(g: Harness): { state: Record<string, unknown>; events: number; stop: boolean } {
    return { state: g.state(), events: g.events().length, stop: existsSync(g.stopPath) }
  }

  it('no canary ever: no_canary_window, the state row (version too), the events and the STOP are as they were', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    g.gate.tick()
    const before = snapshot(g)
    expect(g.gate.closeCanary(2)).toEqual({ ok: false, reason: 'no_canary_window' })
    expect(snapshot(g)).toEqual(before)
  })

  it('no state row yet (no tick): refused, and no row is created', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    expect(g.gate.closeCanary(2)).toEqual({ ok: false, reason: 'no_canary_window' })
    expect(g.db.prepare('SELECT COUNT(*) AS n FROM credit_gate_state').get()).toEqual({ n: 0 })
  })

  it('the second close of the same window: refused, nothing changes', () => {
    const { g } = settledCanary()
    expect(g.gate.closeCanary(2)).toMatchObject({ ok: true })
    const before = snapshot(g)
    expect(g.gate.closeCanary(2)).toEqual({ ok: false, reason: 'no_canary_window' })
    expect(g.gate.closeCanary(3)).toEqual({ ok: false, reason: 'no_canary_window' })
    expect(snapshot(g)).toEqual(before)
    expect(g.events('canary_window_closed')).toHaveLength(1)
  })

  it('a reading not newer than the canary\'s own calibration is no after-reading: refused, the window stays', () => {
    const { g } = settledCanary()
    const before = snapshot(g)
    expect(g.gate.closeCanary(1)).toEqual({ ok: false, reason: 'not_an_after_reading' })
    expect(snapshot(g)).toEqual(before)
    expect(g.gate.canaryBlock()).toBe('canary_window_open')
  })

  it('a malformed calibration id: invalid_request, nothing changes', () => {
    const { g } = settledCanary()
    const before = snapshot(g)
    for (const bad of [0, -1, 1.5, Number.NaN, Number.MAX_SAFE_INTEGER + 2]) {
      expect(g.gate.closeCanary(bad), String(bad)).toEqual({ ok: false, reason: 'invalid_request' })
    }
    expect(snapshot(g)).toEqual(before)
  })
})

describe('canaryCloseMaxH in config.json', () => {
  const base = () => configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP')
  const parse = (o: unknown) => parseCreditGateConfig(JSON.stringify(o))

  it('optional, default 6; 1..24 accepted; anything else rejects the config', () => {
    const d = parse(base())
    expect(d.ok && d.config.canaryCloseMaxH).toBe(DEFAULT_CANARY_CLOSE_H)
    expect(DEFAULT_CANARY_CLOSE_H).toBe(6)
    expect(MAX_CANARY_CLOSE_H).toBe(24)
    for (const v of [1, 12, 24]) {
      const r = parse({ ...base(), canaryCloseMaxH: v })
      expect(r.ok && r.config.canaryCloseMaxH, String(v)).toBe(v)
    }
    for (const v of [0, 25, -1, 1.5, '6', null]) expect(parse({ ...base(), canaryCloseMaxH: v }).ok, String(v)).toBe(false)
  })
})

describe('the schema upgrade: a canary running across it keeps its window', () => {
  function oldTables(g: Harness): void {
    g.db.exec('DROP TABLE credit_gate_state; DROP TABLE credit_reservations; DROP TABLE credit_gate_events')
    applyPreRound1GateSchema(g.db)
    g.db.prepare(`INSERT INTO credit_gate_state (id, state, reason, since, calibration_id, evaluated_at, version)
      VALUES (1, 'OPEN', 'open', ?, 1, ?, 3)`).run(T0, T0)
  }

  it('an open canary reservation at the upgrade becomes the window (the STOP then waits for its after-reading)', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    oldTables(g)
    g.db.prepare(`INSERT INTO credit_reservations (id, kind, ref, amount_micro, status, caller, model, calibration_id, created_at, updated_at)
      VALUES ('res-old-canary', 'canary', 'hr-old', 1350000, 'open', 'ezermester', 'claude-sonnet-5-5', 1, ?, ?)`).run(T0 - 60_000, T0 - 60_000)
    applyCreditGateSchema(g.db)
    expect(g.state()).toMatchObject({ canary_res_id: 'res-old-canary', canary_opened_at: T0 - 60_000 })
    // A second start does not move it.
    applyCreditGateSchema(g.db)
    expect(g.state()).toMatchObject({ canary_res_id: 'res-old-canary' })
    g.gate = g.makeGate()
    g.gate.settleHeadless('res-old-canary', null)
    expect(g.gate.canaryBlock()).toBe('canary_window_open')
  })

  it('no open canary at the upgrade: no window', () => {
    const g = harness({ cal: simpleCal(1, '95.00') })
    oldTables(g)
    applyCreditGateSchema(g.db)
    expect(g.state()).toMatchObject({ canary_res_id: null, canary_opened_at: null })
  })
})
