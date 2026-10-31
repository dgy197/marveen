import { describe, it, expect, afterEach } from 'vitest'
import { createHash } from 'node:crypto'
import { appendFileSync, chmodSync, existsSync, readFileSync, renameSync, symlinkSync, truncateSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { readCreditGateMode } from '../web/credit-gate/config.js'
import { batchReservationAmount, formatUsd, type HeadlessReserveRequest } from '../web/credit-gate/gate.js'
import type { HeadlessRun } from '../web/credit-gate/ledger.js'
import { asMicro } from '../web/credit-gate/money.js'
import { loadPricing } from '../web/credit-gate/pricing.js'
import {
  calibration,
  grant,
  Harness,
  HOUR,
  pricingText,
  simpleCal,
  T0,
  USD,
  type HarnessOptions,
} from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a: the gate core (card fec6335f).
//
// Written from the spec (A-01..A-06, B-06, C-01..C-06, D-04, D-05) and the
// blueprint (3.4-3.6, N2a test list, 8, 14), not from the code. The money is
// computed by hand from the N0 prices in the harness (USD/MTok):
//   Sonnet 5.5  2.00 in, 10.00 out, 4.00 cache write 1h
//   Haiku 5.5   0.10 in, 0.50 out, 0.20 cache write 1h; above 100k prompt
//               0.50 in, 2.50 out, 1.00 cache write 1h
// A batch reservation is priced at the worst input rate of every band,
// max(input x 50%, cache_write_1h), and the worst output rate x 50%: for Haiku
// that is 1.00 USD/MTok in (= 1 micro-USD per token) and 1.25 out.

let h: Harness
function harness(o: HarnessOptions = {}): Harness {
  h = new Harness(o)
  return h
}
afterEach(() => h?.cleanup())

function headless(budgetUsd: number, over: Partial<HeadlessReserveRequest> = {}): HeadlessReserveRequest {
  return { kind: 'headless', budget_micro: asMicro(Math.round(budgetUsd * USD)), model: 'claude-opus-5-5', ref: 'node-1', caller: 'ezermester', ...over }
}

function batch(model: string, input: number, output = 0, requests = 1) {
  return { kind: 'batch' as const, model, input_tokens_total: input, max_output_tokens_total: output, request_count: requests, caller: 'rag-gold-label' }
}

function stateOf(x: Harness) {
  const s = x.state()
  return { state: s.state, reason: s.reason }
}

describe('helpers', () => {
  it('formatUsd is exact and keeps at least two decimals', () => {
    expect(formatUsd(0)).toBe('0.00')
    expect(formatUsd(20 * USD)).toBe('20.00')
    expect(formatUsd(19_999_999)).toBe('19.999999')
    expect(formatUsd(395_640_000)).toBe('395.64')
    expect(formatUsd(-1)).toBe('-0.000001')
  })

  it('the batch upper estimate takes the worst input and output rate of every band (blueprint 3.4)', () => {
    const r = loadPricing(pricingText(), T0)
    if (!r.ok) throw new Error('fixture')
    // Haiku: 1 micro per input token (long-context cache write), 1.25 per output token.
    expect(batchReservationAmount(r.table, 'claude-haiku-5-5', 1_000_000, 0)).toBe(1 * USD)
    expect(batchReservationAmount(r.table, 'claude-haiku-5-5', 0, 1_000_000)).toBe(1_250_000)
    // Sonnet: max(2.00 x 50%, 4.00) = 4.00 in, 10.00 x 50% = 5.00 out.
    expect(batchReservationAmount(r.table, 'claude-sonnet-5-5', 1_000_000, 1_000_000)).toBe(9 * USD)
    // Rounded up: 1 input token of Sonnet is 4 micro-USD; 1 output token 5.
    expect(batchReservationAmount(r.table, 'claude-sonnet-5-5', 1, 1)).toBe(9)
    expect(batchReservationAmount(r.table, 'claude-unknown-9', 1, 1)).toBeNull()
  })
})

describe('K1: the threshold (C-02, C-04, C-05)', () => {
  it('a headless reservation that leaves R_est == T_close is admitted, and the gate closes behind it', () => {
    harness({ cal: simpleCal(1, '50.00') })
    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 50 * USD })
    // 20.00 x 1.5 = 30.00 -> R_est after = 20.00 = T_close.
    const r = h.gate.reserve(headless(20))
    expect(r).toMatchObject({ enforced: true, ok: true, amount_micro: 30 * USD, r_est_after_micro: 20 * USD, closed: true })
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'threshold' })
    // A-03: the closed gate stops the batch path at once.
    expect(readFileSync(h.stopPath, 'utf8')).toMatch(/^credit-gate v1 [0-9a-f]{32}$/)
    // Nothing more fits.
    expect(h.gate.reserve(headless(0.01))).toMatchObject({ enforced: true, ok: false, reason: 'gate_closed' })
  })

  it('one micro-USD below T_close is refused, and the gate stays open; exactly T_close is admitted', () => {
    harness({ cal: simpleCal(1, '61.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    // Haiku: 1 micro-USD per input token. 41.000001 USD would leave 19.999999.
    const below = h.gate.reserve(batch('claude-haiku-5-5', 41_000_001))
    expect(below).toMatchObject({ enforced: true, ok: false, reason: 'below_threshold' })
    expect(h.reservations()).toHaveLength(0)
    expect(stateOf(h).state).toBe('OPEN')
    expect(h.events('reservation_rejected')).toHaveLength(1)
    const exact = h.gate.reserve(batch('claude-haiku-5-5', 41_000_000))
    expect(exact).toMatchObject({ ok: true, amount_micro: 41 * USD, r_est_after_micro: 20 * USD, closed: true })
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'threshold' })
  })

  it('C-05: after a threshold closure the same calibration does not reopen, even when R_est recovers', () => {
    harness({ cal: simpleCal(1, '61.00') })
    h.gate.tick()
    const r = h.gate.reserve(batch('claude-haiku-5-5', 41_000_000))
    if (!('ok' in r) || !r.ok) throw new Error('reserve failed')
    // The batch was refused by the API: the reservation is given back.
    expect(h.gate.release(r.reservation_id, 'rejected_4xx')).toMatchObject({ ok: true, status: 'released' })
    h.now += 30_000
    const t = h.gate.tick()
    expect(t.r_est_micro).toBe(61 * USD)
    expect(t).toMatchObject({ state: 'CLOSED', reason: 'threshold' })
    h.now += 30_000
    expect(h.gate.tick().state).toBe('CLOSED')
    // A newer, approved calibration lifts it.
    h.cal = simpleCal(2, '61.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('C-04 in the tick: R_est at T_close + 1 micro stays open, at T_close it closes', () => {
    harness({ cal: simpleCal(1, '50.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    // 2 999 999 Sonnet output tokens = 29.99999 USD; 90 Haiku input tokens = 9 micro.
    h.usage('claude-sonnet-5-5', 0, 2_999_999)
    h.usage('claude-haiku-5-5', 90, 0)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 20 * USD + 1 })
    h.usage('claude-haiku-5-5', 10, 0)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'threshold', r_est_micro: 20 * USD })
  })

  it('opening needs R_est >= T_reopen: 49.999999 stays closed, 50.00 opens', () => {
    harness({ cal: simpleCal(1, '50.00') })
    h.usage('claude-haiku-5-5', 10, 0) // 1 micro
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'below_reopen' })
    h.cal = simpleCal(2, '50.01')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })
})

describe('K2: missing or doubtful measurement closes the gate (A-02)', () => {
  it('a ledger older than 120 s: the reservation gets 409 and the gate closes; 120 s exactly is still fine', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.now = T0 + 120_000
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: true })
    h.now = T0 + 120_001
    expect(h.gate.reserve(headless(1))).toMatchObject({ enforced: true, ok: false, reason: 'ledger_stale' })
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'ledger_stale' })
    expect(existsSync(h.stopPath)).toBe(true)
    // Transient: a fresh tick with the same calibration reopens, and the STOP goes.
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
  })

  it('a broken ledger source puts the gate on HOLD; a newer calibration alone does not lift it', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    appendFileSync(h.usagePath, '{"ts": not json}\n')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_broken:anthropic-batch' })
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'gate_closed' })
    expect(existsSync(h.stopPath)).toBe(true)
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
  })

  it('a source file that goes missing holds the gate; when it is back the ledger heals, the HOLD latch lifts only with a newer calibration', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    unlinkSync(h.usagePath)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_broken:anthropic-batch' })
    // Still missing: the next polls change nothing, the gate never opens by itself.
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'gate_closed' })
    // The file is back: the source reads ok again, but the latched HOLD stays.
    writeFileSync(h.usagePath, '')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
    // The latch follows the normal rule: a newer calibration lifts it.
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('a row that cannot be priced (est NULL) closes the gate', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.usage('claude-unknown-9', 1000, 1000)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'unpriced_rows' })
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false })
  })

  it('a missing, unreadable or stale price table closes the gate', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    unlinkSync(join(h.gateDir, 'pricing.json'))
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'pricing_missing' })
    h.writePricing('2026-10-16')
    chmodSync(join(h.gateDir, 'pricing.json'), 0o644)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'pricing_permissions' })
    h.writePricing('2026-09-15')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'pricing_stale' })
    h.writePricing('2026-10-16')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('the price table turning stale between the tick and the reservation: 409 and closed', () => {
    // Verified 30 days minus one minute before T0: fresh at T0, stale at T0 + 2 min.
    harness({ cal: simpleCal(1, '100.00'), pricingVerifiedAt: '2026-09-16T08:01:00Z' })
    expect(h.gate.tick().state).toBe('OPEN')
    h.now = T0 + 120_000
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'pricing_stale' })
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'pricing_stale' })
  })

  it('no calibration: CLOSED, and the gate puts its STOP down', () => {
    harness({ cal: null })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'no_calibration' })
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'gate_closed' })
    expect(existsSync(h.stopPath)).toBe(true)
  })

  it('an invalid calibration (future lower bound, remaining above original, no grant) closes the gate', () => {
    for (const cal of [
      simpleCal(1, '100.00', { captured_at_lb_ms: T0 + 1 }),
      calibration(1, [grant('2026-10-14', '2026-11-17', '100.00', '100.01')]),
      calibration(1, []),
      calibration(1, [grant('2026-10-14', '2026-11-31', '100.00', '100.00')]),
    ]) {
      harness({ cal })
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
      h.cleanup()
    }
  })

  it('D-01: R or V off its baseline in the calibration: the gate does not open', () => {
    harness({ cal: simpleCal(1, '100.00', { protected: { R_micro: asMicro(3_620_000), V_micro: asMicro(10 * USD) } }) })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'protected_mismatch' })
    h.cleanup()
    harness({ cal: simpleCal(1, '100.00', { protected: { R_micro: asMicro(3_630_000), V_micro: asMicro(9_990_000) } }) })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'protected_mismatch' })
  })

  it('a newer calibration than the one the tick decided on: the reservation waits for the tick (calibration_changed)', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.cal = simpleCal(2, '100.00')
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'calibration_changed' })
    expect(h.reservations()).toHaveLength(0)
    expect(stateOf(h).state).toBe('OPEN')
    h.now += 30_000
    h.gate.tick()
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: true })
  })

  it('an invalid or missing config closes the gate', () => {
    harness({ cal: simpleCal(1, '100.00'), config: { maxLedgerAgeS: 600 } })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'config_invalid' })
    unlinkSync(join(h.gateDir, 'config.json'))
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'config_missing' })
  })

  it('an unknown mode is enforce and CLOSED: it never opens, and the STOP is still managed', () => {
    harness({ cal: simpleCal(1, '100.00'), mode: 'enforced' })
    expect(h.gate.mode).toMatchObject({ mode: 'enforce', unknown: true })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'mode_unknown' })
    expect(existsSync(h.stopPath)).toBe(true)
    expect(h.gate.reserve(headless(1))).toMatchObject({ enforced: true, ok: false })
  })

  it('a gate state older than 120 s (the tick stopped) admits nothing', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    // Only the evaluation is old (the tick stopped); the ledger is fresh.
    h.db.prepare('UPDATE credit_gate_state SET evaluated_at = ? WHERE id = 1').run(T0 - 121_000)
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'gate_state_stale' })
    expect(stateOf(h).state).toBe('CLOSED')
  })
})

describe('K3: one decision at a time (C-01)', () => {
  it('two connections to one file (two processes): seven fit, seven are admitted, never more', () => {
    // R_est 95 and T_close 20: 75 USD of room; each reservation is 10.00 (Haiku 10M input tokens).
    harness({ cal: simpleCal(1, '95.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    const other = h.makeGate(h.openDb())
    const results = []
    for (let i = 0; i < 20; i++) {
      const g = i % 2 === 0 ? h.gate : other
      results.push(g.reserve(batch('claude-haiku-5-5', 10_000_000)))
    }
    const ok = results.filter((r) => 'ok' in r && r.ok)
    expect(ok).toHaveLength(7)
    const total = h.reservations().reduce((s, r) => s + (r.amount_micro as number), 0)
    expect(total).toBe(70 * USD)
    expect(total).toBeLessThanOrEqual(75 * USD)
    expect(h.gate.status().r_est_usd).toBe('25.00')
    expect(other.status().r_est_usd).toBe('25.00')
  })

  it('a write lock held by the other process: the reservation is refused (gate_busy), not doubled', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const lockDb = h.openDb()
    const other = h.makeGate(h.openDb(50))
    lockDb.exec('BEGIN IMMEDIATE')
    try {
      expect(other.reserve(headless(1))).toMatchObject({ enforced: true, ok: false, reason: 'gate_busy' })
    } finally {
      lockDb.exec('COMMIT')
    }
    expect(h.reservations()).toHaveLength(0)
    expect(other.reserve(headless(1))).toMatchObject({ ok: true })
    expect(h.reservations()).toHaveLength(1)
  })

  it('a reservation made by another process while a tick gathers its inputs is counted by that tick', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    const other = h.makeGate(h.openDb())
    let fired = false
    // The tick reads the calibration source before its transaction: the
    // other process reserves exactly then.
    h.onCalibrationRead = () => {
      if (fired) return
      fired = true
      const r = other.reserve(headless(20)) // 30.00
      if (!('ok' in r) || !r.ok) throw new Error(`reserve during tick failed: ${JSON.stringify(r)}`)
    }
    h.now += 30_000
    const t = h.gate.tick()
    expect(fired).toBe(true)
    expect(t.r_est_micro).toBe(70 * USD)
    expect(h.reservations()).toHaveLength(1)
    expect(h.gate.status().r_est_usd).toBe('70.00')
  })

  it('a double complete or settle books once', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const r = h.gate.reserve(batch('claude-sonnet-5-5', 1000, 1000, 2))
    if (!('ok' in r) || !r.ok) throw new Error('reserve')
    expect(h.gate.bind(r.reservation_id, 'msgbatch_01ABC', 2)).toMatchObject({ ok: true, changed: true })
    expect(h.gate.bind(r.reservation_id, 'msgbatch_01ABC', 2)).toMatchObject({ ok: true, changed: false })
    h.batchUsage('msgbatch_01ABC', 'q-1', 'claude-sonnet-5-5', 500, 500)
    h.batchUsage('msgbatch_01ABC', 'q-2', 'claude-sonnet-5-5', 500, 500)
    h.now += 30_000
    h.gate.tick()
    expect(h.gate.complete(r.reservation_id)).toMatchObject({ ok: true, status: 'settled', changed: true })
    expect(h.gate.complete(r.reservation_id)).toMatchObject({ ok: true, status: 'settled', changed: false })
    expect(h.events('reservation_settled')).toHaveLength(1)

    const hr = h.gate.reserve(headless(1))
    if (!('ok' in hr) || !hr.ok) throw new Error('reserve')
    expect(h.gate.settleHeadless(hr.reservation_id)).toMatchObject({ ok: true, status: 'settled', changed: true })
    expect(h.gate.settleHeadless(hr.reservation_id)).toMatchObject({ ok: true, status: 'settled', changed: false })
    expect(h.events('reservation_settled')).toHaveLength(2)
  })
})

describe('K4: expiry (C-06, D-04, D-05) with the P1/P2 test vector', () => {
  const P1P2 = () => calibration(1, [
    grant('2026-10-10', '2026-10-17', '200.00', '195.64'),
    grant('2026-10-14', '2026-11-17', '200.00', '200.00'),
  ], { captured_at_lb_ms: Date.UTC(2026, 9, 15, 6, 0, 0) })

  it('R_est = 395.64 - L before 10-17 00:00Z, 200.00 - L from it; close_at = 11-17 00:00Z - 2 h', () => {
    harness({ cal: P1P2() })
    // L = 1.00 USD: 100 000 Sonnet output tokens, stamped after the lower bound.
    h.usage('claude-sonnet-5-5', 0, 100_000, Math.floor(Date.UTC(2026, 9, 15, 7) / 1000))
    // A row stamped before the lower bound does not count.
    h.usage('claude-sonnet-5-5', 0, 100_000, Math.floor(Date.UTC(2026, 9, 15, 5, 59, 59) / 1000))

    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 394_640_000 })
    const st = h.gate.status()
    expect(st.close_at).toBe('2026-11-16T22:00:00.000Z')
    expect(st.next_expiry).toBe('2026-10-17T00:00:00.000Z')
    expect(st.r_est_usd).toBe('394.64')

    h.now = Date.UTC(2026, 9, 16, 23, 59, 59, 999)
    expect(h.gate.tick().r_est_micro).toBe(394_640_000)
    h.now = Date.UTC(2026, 9, 17, 0, 0, 0, 0)
    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 199 * USD })
    expect(h.gate.status().next_expiry).toBe('2026-11-17T00:00:00.000Z')

    h.writePricing('2026-11-16')
    h.now = Date.UTC(2026, 10, 16, 21, 59, 59, 999)
    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 199 * USD })
    h.now = Date.UTC(2026, 10, 16, 22, 0, 0, 0)
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'expired' })
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false })
  })

  it('a reservation at close_at itself is refused and closes the gate, even before the next tick', () => {
    harness({ cal: P1P2(), pricingVerifiedAt: '2026-11-16' , now: Date.UTC(2026, 10, 16, 21, 59, 30) })
    expect(h.gate.tick().state).toBe('OPEN')
    h.now = Date.UTC(2026, 10, 16, 22, 0, 0)
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'expired' })
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'expired' })
  })

  it('an expiry with a time of day counts from that instant; a spent grant does not set close_at', () => {
    harness({
      cal: calibration(1, [
        grant('2026-10-14', '2026-11-17T12:00:00Z', '200.00', '100.00'),
        grant('2026-10-14', '2026-12-31', '200.00', '0.00'),
      ]),
    })
    h.gate.tick()
    expect(h.gate.status().close_at).toBe('2026-11-17T10:00:00.000Z')
  })
})

describe('B-06: the low-calibration timer', () => {
  it('asks once at 60, falls back to T_close 40 after 12 h, and a new calibration resets it', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    // Spend 40.00: 4 000 000 Sonnet output tokens.
    h.usage('claude-sonnet-5-5', 0, 4_000_000)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'OPEN', r_est_micro: 60 * USD })
    expect(h.events('lowcal_request')).toHaveLength(1)
    h.now += 30_000
    h.gate.tick()
    expect(h.events('lowcal_request')).toHaveLength(1)
    expect(h.gate.status().thresholds?.t_close_eff_usd).toBe('20.00')

    // 12 hours later (the ledger and the price table still fresh).
    h.now += 12 * HOUR
    h.writePricing('2026-10-16')
    // Spend 20.00 more: R_est 40 = the fallback threshold.
    h.usage('claude-sonnet-5-5', 0, 2_000_000)
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'threshold' })
    expect(h.events('lowcal_fallback')).toHaveLength(1)
    expect(h.gate.status().thresholds?.t_close_eff_usd).toBe('40.00')

    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    h.gate.tick()
    expect(h.gate.status().thresholds?.t_close_eff_usd).toBe('20.00')
  })

  it('before 12 h the threshold is still 20', () => {
    harness({ cal: simpleCal(1, '60.00') })
    h.gate.tick()
    expect(h.events('lowcal_request')).toHaveLength(1)
    h.now += 12 * HOUR - 1
    h.gate.tick()
    expect(h.gate.status().thresholds?.t_close_eff_usd).toBe('20.00')
    h.now += 1
    h.gate.tick()
    expect(h.gate.status().thresholds?.t_close_eff_usd).toBe('40.00')
  })
})

describe('signals: only ever toward closing (A-05, D-03, blueprint 14)', () => {
  it('disarm closes and latches; a later tick with the same calibration does not reopen', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    expect(h.gate.signal('disarm', 'operator', 'manual')).toMatchObject({ enforced: true, state: 'CLOSED' })
    expect(existsSync(h.stopPath)).toBe(true)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('credit_balance_too_low is an INCIDENT; only clearIncident and then a newer calibration open again', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    expect(h.gate.signal('credit_balance_too_low', 'batch_client', null).state).toBe('INCIDENT')
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('INCIDENT')
    const ev = h.events('transition').find((e) => e.to_state === 'INCIDENT')
    expect(ev).toBeTruthy()
    expect(h.gate.clearIncident(ev!.id as number)).toBe(true)
    h.now += 30_000
    expect(h.gate.tick().state).toBe('CLOSED')
    h.cal = simpleCal(3, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('auth_401 closes (latched); usage_log_failed holds', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    expect(h.gate.signal('auth_401', 'batch_client', null).state).toBe('CLOSED')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'auth_401' })
    expect(h.gate.signal('usage_log_failed', 'batch_client', null).state).toBe('HOLD')
  })

  it('no signal opens a closed gate', () => {
    harness({ cal: null })
    h.gate.tick()
    h.cal = simpleCal(1, '100.00') // would open on the next tick, but no tick runs
    expect(h.gate.signal('disarm', 'x', null).state).toBe('CLOSED')
    // The disarm latched under the calibration that is current NOW, so the
    // next tick does not open with it.
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
    for (const k of ['auth_401', 'usage_log_failed', 'credit_balance_too_low'] as const) {
      expect(h.gate.signal(k, 'x', null).state).not.toBe('OPEN')
      expect(stateOf(h).state).not.toBe('OPEN')
      h.now += 30_000
      expect(h.gate.tick().state).not.toBe('OPEN')
    }
  })

  it('a signal detail never stores a key-like value', () => {
    harness({ cal: simpleCal(1, '100.00') })
    const dummy = `sk-ant-TEST-DUMMY-${Math.random().toString(36).slice(2)}abcdefghijklmnop`
    h.gate.signal('auth_401', 'batch_client', `401 with key ${dummy} rejected`)
    const all = JSON.stringify(h.events())
    expect(all).not.toContain(dummy)
    expect(all).not.toContain('sk-ant-')
  })
})

describe('PR-A guard events (I-03, I-04): a line after the baseline, or damage, is an INCIDENT', () => {
  const ev = (over: Record<string, unknown> = {}) =>
    JSON.stringify({ ts: '2026-10-16T08:00:00Z', source: 'guard-runner', where: 'tmux:global', names: ['ANTHROPIC_API_KEY'], agent: 'brainy', ...over }) + '\n'
  const sha256 = (b: Buffer) => createHash('sha256').update(b).digest('hex')

  it('first init with lines already in the file: a baseline (count + sha256) AND an INCIDENT; after the owner clears it, the next line is one', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, ev() + ev({ names: ['apiKeyHelper'] }) + 'garbage\n')
    const content = readFileSync(h.guardPath)
    expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason: 'guard_backlog' })
    const base = h.events('guard_baseline')
    expect(base).toHaveLength(1)
    expect(JSON.parse(base[0].detail_json as string)).toEqual({ lines: 3, bytes: content.length, sha256: sha256(content), why: 'init' })
    expect(h.events('guard_event')).toHaveLength(0)
    const inc = h.events('transition').find((e) => e.to_state === 'INCIDENT')!
    expect(h.gate.clearIncident(inc.id as number)).toBe(true)
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.events('guard_baseline')).toHaveLength(1)
    appendFileSync(h.guardPath, ev())
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason: 'guard_event' })
    const g = h.events('guard_event')
    expect(g).toHaveLength(1)
    expect(JSON.parse(g[0].detail_json as string)).toMatchObject({ source: 'guard-runner', names: ['ANTHROPIC_API_KEY'] })
    expect(existsSync(h.stopPath)).toBe(true)
  })

  it('no file at init: a file that appears later is read from its first line', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    expect(JSON.parse(h.events('guard_baseline')[0].detail_json as string)).toMatchObject({ lines: 0, sha256: null })
    writeFileSync(h.guardPath, ev())
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason: 'guard_event' })
  })

  it('an event seen once is not counted again; a cleared incident is not re-raised by the old line', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, '')
    h.gate.tick()
    appendFileSync(h.guardPath, ev())
    h.now += 30_000
    expect(h.gate.tick().state).toBe('INCIDENT')
    const inc = h.events('transition').find((e) => e.to_state === 'INCIDENT')!
    expect(h.gate.clearIncident(inc.id as number)).toBe(true)
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.events('guard_event')).toHaveLength(1)
    appendFileSync(h.guardPath, ev({ where: 'settings:~/.claude/settings.json', names: ['apiKeyHelper'] }))
    h.now += 30_000
    expect(h.gate.tick().state).toBe('INCIDENT')
  })

  it('an unparseable line is an event too; a value smuggled into names is not stored', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, '')
    h.gate.tick()
    appendFileSync(h.guardPath, 'garbage line\n' + ev({ names: ['ANTHROPIC_API_KEY', 'sk-ant-TEST-DUMMY-zzz=secretvalue'] }))
    h.now += 30_000
    h.gate.tick()
    expect(stateOf(h).state).toBe('INCIDENT')
    expect(h.events('guard_event')).toHaveLength(2)
    expect(JSON.stringify(h.events())).not.toContain('sk-ant-')
  })

  it('the allow-mode audit file is not an incident source', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    writeFileSync(join(h.storeDir, 'interactive-key-guard-audit.jsonl'), ev())
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  const damages: Array<[string, string, (x: Harness) => void]> = [
    ['truncated (smaller than the cursor)', 'guard_events_truncated', (x) => truncateSync(x.guardPath, 0)],
    ['replaced by another inode of the same size', 'guard_events_replaced', (x) => {
      const same = readFileSync(x.guardPath)
      const tmp = join(x.storeDir, 'guard.new')
      writeFileSync(tmp, same)
      renameSync(tmp, x.guardPath)
    }],
    ['rewritten in place', 'guard_events_rewritten', (x) => {
      const b = readFileSync(x.guardPath)
      b[0] = 0x78
      writeFileSync(x.guardPath, b)
    }],
    ['removed', 'guard_events_missing', (x) => unlinkSync(x.guardPath)],
  ]
  for (const [name, reason, damage] of damages) {
    it(`a file already read and then ${name}: INCIDENT (an event may have been hidden), raised once`, () => {
      harness({ cal: simpleCal(1, '100.00') })
      // Blank lines: content to damage, but no event and no backlog.
      writeFileSync(h.guardPath, '\n\n')
      expect(h.gate.tick().state).toBe('OPEN')
      damage(h)
      h.now += 30_000
      expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason })
      expect(h.events('guard_damage').map((e) => e.reason)).toEqual([reason])
      // Cleared by the owner and a newer calibration: the same damage is not raised again.
      const inc = h.events('transition').find((e) => e.to_state === 'INCIDENT')!
      expect(h.gate.clearIncident(inc.id as number)).toBe(true)
      h.cal = simpleCal(2, '100.00')
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
      expect(h.events('guard_damage')).toHaveLength(1)
    })
  }

  it('an unreadable file (a symlink) stays an INCIDENT until resetGuardCursor', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, '\n')
    h.gate.tick()
    const real = join(h.storeDir, 'elsewhere.jsonl')
    renameSync(h.guardPath, real)
    symlinkSync(real, h.guardPath)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason: 'guard_events_symlink' })
    const inc = h.events('transition').find((e) => e.to_state === 'INCIDENT')!
    h.gate.clearIncident(inc.id as number)
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('INCIDENT')
    unlinkSync(h.guardPath)
    renameSync(real, h.guardPath)
    h.gate.resetGuardCursor()
    const inc2 = h.events('transition').filter((e) => e.to_state === 'INCIDENT').pop()!
    h.gate.clearIncident(inc2.id as number)
    h.cal = simpleCal(3, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.events('guard_baseline').map((e) => e.reason)).toEqual(['init', 'reset'])
  })
})
describe('reservations', () => {
  it('a bound batch counts max(0, amount - ingested) and settles when every request is in', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    // Sonnet, 1 000 000 in + 1 000 000 out: 4.00 + 5.00 = 9.00 reserved.
    const r = h.gate.reserve(batch('claude-sonnet-5-5', 1_000_000, 1_000_000, 2))
    if (!('ok' in r) || !r.ok) throw new Error('reserve')
    expect(r.amount_micro).toBe(9 * USD)
    expect(h.gate.bind(r.reservation_id, 'msgbatch_01X', 2).ok).toBe(true)
    // One result in: 500k in + 500k out at the batch price = 0.50 + 2.50 = 3.00.
    h.batchUsage('msgbatch_01X', 'q-1', 'claude-sonnet-5-5', 500_000, 500_000)
    h.now += 30_000
    // R_est = 100 - 3.00 (ledger) - (9.00 - 3.00) (open part) = 91.00.
    expect(h.gate.tick().r_est_micro).toBe(91 * USD)
    expect(h.gate.complete(r.reservation_id)).toMatchObject({ ok: true, status: 'open' })
    h.batchUsage('msgbatch_01X', 'q-2', 'claude-sonnet-5-5', 500_000, 500_000)
    h.now += 30_000
    expect(h.gate.tick().r_est_micro).toBe(94 * USD)
    expect(h.reservations()[0].status).toBe('settled')
  })

  it('a batch that costs more than its reservation is a HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const r = h.gate.reserve(batch('claude-sonnet-5-5', 1000, 0, 1)) // 0.004
    if (!('ok' in r) || !r.ok) throw new Error('reserve')
    h.gate.bind(r.reservation_id, 'msgbatch_01Y', 1)
    h.batchUsage('msgbatch_01Y', 'q-1', 'claude-sonnet-5-5', 1000, 1000)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'batch_overrun' })
    h.now += 30_000
    h.gate.tick()
    expect(h.events('batch_overrun')).toHaveLength(1)
  })

  it('release: only an unbound reservation, only for a proven 4xx; an unknown outcome is a HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const a = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    const b = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    if (!('ok' in a) || !a.ok || !('ok' in b) || !b.ok) throw new Error('reserve')
    h.gate.bind(a.reservation_id, 'msgbatch_01Z', 1)
    expect(h.gate.release(a.reservation_id, 'rejected_4xx')).toMatchObject({ ok: false, code: 409, reason: 'bound' })
    expect(h.gate.release('nope', 'rejected_4xx')).toMatchObject({ ok: false, code: 404 })
    expect(h.gate.release(b.reservation_id, 'unknown_outcome')).toMatchObject({ ok: true, status: 'unknown' })
    expect(stateOf(h)).toEqual({ state: 'HOLD', reason: 'reservation_unknown' })
    // An unknown reservation still counts in full.
    expect(h.gate.status().reservations.open_count).toBe(2)
  })

  it('bind: another batch for the same reservation, or the same batch twice, is refused', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const a = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    const b = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    if (!('ok' in a) || !a.ok || !('ok' in b) || !b.ok) throw new Error('reserve')
    expect(h.gate.bind(a.reservation_id, 'msgbatch_01A', 1).ok).toBe(true)
    expect(h.gate.bind(a.reservation_id, 'msgbatch_01B', 1)).toMatchObject({ ok: false, code: 409 })
    expect(h.gate.bind(b.reservation_id, 'msgbatch_01A', 1)).toMatchObject({ ok: false, code: 409 })
    expect(h.gate.bind('nope', 'msgbatch_01C', 1)).toMatchObject({ ok: false, code: 404 })
  })

  it('a headless reservation never settled within 24 h turns unknown (HOLD); one millisecond earlier it is still open', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    h.gate.reserve(headless(1))
    h.now = T0 + 24 * HOUR - 1
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.reservations()[0].status).toBe('open')
    h.now = T0 + 24 * HOUR
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'reservation_unknown' })
    expect(h.reservations()[0].status).toBe('unknown')
  })

  it('an unbound batch reservation older than an hour turns unknown (HOLD)', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    h.now += HOUR + 1
    h.writePricing('2026-10-16')
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'reservation_unknown' })
    expect(h.reservations()[0].status).toBe('unknown')
  })
})

describe('BE-2: a ledger or pricing fault fails closed, with a reason, never silently', () => {
  const run = (over: Partial<HeadlessRun> = {}): HeadlessRun => ({
    run_id: 'run-1',
    ended_at_s: Math.floor((T0 - 60_000) / 1000),
    model: 'claude-opus-5-5',
    reservation_micro: asMicro(0),
    // 1000 in + 1000 out of Opus = 24 000 micro; the CLI says 0.50 USD: L takes the larger.
    result: { total_cost_usd: 0.5, usage: [{ model: 'claude-opus-5-5', input_tokens: 1000, output_tokens: 1000, cache_write_tokens: 0, cache_read_tokens: 0 }] },
    transcript_dir: null,
    ...over,
  })
  const faults = () => h.events('fault').map((e) => [e.reason, JSON.parse(e.detail_json as string).where])
  const neverOpened = () => !h.events('transition').some((e) => e.to_state === 'OPEN')

  for (const method of ['refresh', 'ledgerSum', 'ageS'] as const) {
    it(`tick: ${method} throws -> HOLD ledger_error, recorded, the STOP goes down; it never opens`, () => {
      harness({ cal: simpleCal(1, '100.00') })
      h.ledgerThrows.add(method)
      expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_error', r_est_micro: null })
      expect(neverOpened()).toBe(true)
      expect(faults()).toContainEqual(['ledger_error', method])
      expect(existsSync(h.stopPath)).toBe(true)
      // The fault gone: the HOLD stays until a newer calibration.
      h.ledgerThrows.clear()
      h.now += 30_000
      expect(h.gate.tick().state).toBe('HOLD')
      h.cal = simpleCal(2, '100.00')
      h.now += 30_000
      expect(h.gate.tick().state).toBe('OPEN')
    })
  }

  it('tick: an OPEN gate whose ledger starts throwing goes to HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.ledgerThrows.add('ledgerSum')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_error' })
  })

  it('tick: ingestedForBatch throws for a bound batch -> HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const r = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    if (!('ok' in r) || !r.ok) throw new Error('reserve')
    h.gate.bind(r.reservation_id, 'msgbatch_01F', 1)
    h.ledgerThrows.add('ingestedForBatch')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_error' })
    expect(faults().length).toBeGreaterThan(0)
  })

  it('tick: building the ledger throws -> HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.ledgerInitThrows = true
    h.gate = h.makeGate()
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'ledger_error' })
    expect(faults()).toContainEqual(['ledger_error', 'ledger_init'])
  })

  it('tick: the price table loader throws -> CLOSED pricing_error, recorded', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.pricingThrows = true
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'pricing_error' })
    expect(neverOpened()).toBe(true)
    expect(faults()).toContainEqual(['pricing_error', 'loadPricing'])
  })

  for (const method of ['ledgerSum', 'ageS', 'ingestedForBatch'] as const) {
    it(`reserve: ${method} throws -> 409 ledger_error, nothing reserved, HOLD`, () => {
      harness({ cal: simpleCal(1, '100.00') })
      h.gate.tick()
      if (method === 'ingestedForBatch') {
        const r0 = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
        if (!('ok' in r0) || !r0.ok) throw new Error('reserve')
        h.gate.bind(r0.reservation_id, 'msgbatch_01G', 1)
      }
      const before = h.reservations().length
      h.ledgerThrows.add(method)
      expect(h.gate.reserve(headless(1))).toMatchObject({ enforced: true, ok: false, reason: 'ledger_error' })
      expect(h.reservations()).toHaveLength(before)
      expect(stateOf(h)).toEqual({ state: 'HOLD', reason: 'ledger_error' })
      expect(faults().length).toBeGreaterThan(0)
      expect(existsSync(h.stopPath)).toBe(true)
    })
  }

  it('reserve: building the ledger throws -> 409 ledger_error, HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    h.ledgerInitThrows = true
    const fresh = h.makeGate()
    expect(fresh.reserve(headless(1))).toMatchObject({ ok: false, reason: 'ledger_error' })
    expect(stateOf(h)).toEqual({ state: 'HOLD', reason: 'ledger_error' })
  })

  it('reserve: pricing the request throws -> 409 pricing_error, nothing reserved, CLOSED', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    h.tableThrows = true
    expect(h.gate.reserve(batch('claude-sonnet-5-5', 1000))).toMatchObject({ ok: false, reason: 'pricing_error' })
    expect(h.reservations()).toHaveLength(0)
    expect(stateOf(h)).toEqual({ state: 'CLOSED', reason: 'pricing_error' })
    expect(faults()).toContainEqual(['pricing_error', 'amount'])
  })

  it('complete: ingestedForBatch throws -> 409 ledger_error, not settled, HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const r = h.gate.reserve(batch('claude-sonnet-5-5', 1000))
    if (!('ok' in r) || !r.ok) throw new Error('reserve')
    h.gate.bind(r.reservation_id, 'msgbatch_01H', 1)
    h.ledgerThrows.add('ingestedForBatch')
    expect(h.gate.complete(r.reservation_id)).toMatchObject({ ok: false, code: 409, reason: 'ledger_error' })
    expect(h.reservations()[0].status).toBe('open')
    expect(stateOf(h)).toEqual({ state: 'HOLD', reason: 'ledger_error' })
  })

  it('settleHeadless with the run: books it once and settles; recordHeadless throwing -> not settled, HOLD', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const a = h.gate.reserve(headless(1))
    if (!('ok' in a) || !a.ok) throw new Error('reserve')
    expect(h.gate.settleHeadless(a.reservation_id, run())).toMatchObject({ ok: true, status: 'settled', changed: true })
    // The reservation (1.50) is gone, the run's 0.50 is in the ledger.
    expect(h.gate.status().r_est_usd).toBe('99.50')

    const b = h.gate.reserve(headless(2))
    if (!('ok' in b) || !b.ok) throw new Error('reserve')
    h.ledgerThrows.add('recordHeadless')
    expect(h.gate.settleHeadless(b.reservation_id, run({ run_id: 'run-2' }))).toMatchObject({ ok: false, code: 409, reason: 'ledger_error' })
    expect(h.reservations().find((x) => x.id === b.reservation_id)?.status).toBe('open')
    expect(stateOf(h)).toEqual({ state: 'HOLD', reason: 'ledger_error' })
    expect(faults()).toContainEqual(['ledger_error', 'recordHeadless'])
  })

  it('tick: any other exception (here a broken gate table) -> HOLD tick_error, recorded', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.db.exec('DROP TABLE credit_reservations')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'HOLD', reason: 'tick_error' })
    expect(faults()).toContainEqual(['tick_error', 'tick'])
    expect(existsSync(h.stopPath)).toBe(true)
  })

  it('status: a throwing ledger is shown, not hidden and not thrown', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    h.ledgerThrows.add('ledgerSum')
    const st = h.gate.status()
    expect(st.ledger.error).toBe('ledger_error')
    expect(st.r_est_usd).toBeNull()
  })
})

describe('modes', () => {
  it('shadow: computes R_est and writes events, never opens, never touches the STOP, reservations are not enforced', () => {
    harness({ cal: simpleCal(1, '100.00'), mode: 'shadow' })
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'shadow_mode', r_est_micro: 100 * USD })
    expect(existsSync(h.stopPath)).toBe(false)
    expect(h.gate.reserve(headless(1))).toEqual({ enforced: false })
    expect(h.reservations()).toHaveLength(0)
    expect(h.gate.signal('disarm', 'operator', null)).toMatchObject({ enforced: false })
    expect(h.events().length).toBeGreaterThan(0)
    expect(existsSync(h.stopPath)).toBe(false)
    expect(h.batchDirEntries()).toEqual([])
  })

  it('the mode flag reading is the one the gate reports', () => {
    harness({ mode: 'shadow' })
    expect(h.gate.mode).toEqual(readCreditGateMode('shadow'))
  })
})
