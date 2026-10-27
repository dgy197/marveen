import { describe, it, expect, afterEach } from 'vitest'
import type Database from 'better-sqlite3'
import { chmodSync, existsSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { readCreditGateMode } from '../web/credit-gate/config.js'
import type { HeadlessReserveRequest } from '../web/credit-gate/gate.js'
import { asMicro } from '../web/credit-gate/money.js'
import { getCreditGateRuntime, inactiveStatus, setCreditGateRuntime, startCreditGateRuntime } from '../web/credit-gate/runtime.js'
import { applyGateSchema } from '../web/credit-gate/schema-gate.js'
import { applyCreditGateSchema } from '../web/credit-gate/schema.js'
import { applyPreRound1GateSchema } from './fixtures/credit-gate/old-schema-gate.js'
import { calibration, grant, Harness, HOUR, simpleCal, T0, USD, type HarnessOptions } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a, review round 1 (card fec6335f): the findings of the
// reviewer and of the BE-3 security review, kept as regression tests. Each
// exploit of the proofs (scratchpad be3-proof.test.ts, ell-n2a probe) is here
// with the expectation the spec demands; they all failed before the fix.

let h: Harness
function harness(o: HarnessOptions = {}): Harness {
  h = new Harness(o)
  return h
}
afterEach(() => {
  setCreditGateRuntime(null)
  h?.cleanup()
})

const st = () => {
  const s = h.state()
  return { state: s.state, reason: s.reason, latch: s.latch_cal_id }
}
const haikuBatch = (input: number, requests: number) => ({
  kind: 'batch' as const, model: 'claude-haiku-5-5', input_tokens_total: input, max_output_tokens_total: 0, request_count: requests, caller: 'x',
})
const headless = (budgetUsd: number): HeadlessReserveRequest => ({
  kind: 'headless', budget_micro: asMicro(Math.round(budgetUsd * USD)), model: 'claude-opus-5-5', ref: 'node-1', caller: 'ezermester',
})
const P1P2 = () => calibration(1, [grant('2026-10-10', '2026-10-17', '200.00', '195.64'), grant('2026-10-14', '2026-11-17', '200.00', '200.00')])

describe('finding 1 (HIGH): a grant may expire before the reserved work is done', () => {
  it('BE-3 A: a 350 USD batch at 10-16 23:30Z is refused (P1 expires within the 24 h batch horizon)', () => {
    harness({ cal: P1P2() })
    h.now = Date.UTC(2026, 9, 16, 23, 30)
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.gate.reserve(haikuBatch(350_000_000, 1000))).toMatchObject({ enforced: true, ok: false, reason: 'below_threshold' })
    expect(h.reservations()).toHaveLength(0)
    // What fits the horizon (P2 only: 200 - 20) is still admitted.
    expect(h.gate.reserve(haikuBatch(180_000_000, 1000))).toMatchObject({ ok: true })
  })

  it('BE-3 B: a 150 USD batch at 11-16 21:59Z is refused (the last grant expires within the horizon)', () => {
    harness({ cal: calibration(1, [grant('2026-10-14', '2026-11-17', '200.00', '200.00')]), pricingVerifiedAt: '2026-11-10' })
    h.now = Date.UTC(2026, 10, 16, 21, 59)
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.gate.reserve(haikuBatch(150_000_000, 1000))).toMatchObject({ ok: false, reason: 'expiry_horizon' })
    // The batch cut-off is the last expiry - max(margin, 24 h) = 11-16 00:00Z.
    expect(h.gate.status().close_at_batch).toBe('2026-11-16T00:00:00.000Z')
  })

  it('a batch is admitted up to the instant before the batch cut-off, not at it', () => {
    harness({ cal: calibration(1, [grant('2026-10-14', '2026-11-17', '200.00', '200.00')]), pricingVerifiedAt: '2026-11-10' })
    h.now = Date.UTC(2026, 10, 15, 23, 59, 59, 999)
    h.gate.tick()
    expect(h.gate.reserve(haikuBatch(1_000_000, 1))).toMatchObject({ ok: true })
    h.now = Date.UTC(2026, 10, 16, 0, 0, 0)
    expect(h.gate.reserve(haikuBatch(1_000_000, 1))).toMatchObject({ ok: false, reason: 'expiry_horizon' })
  })

  it('headless: the horizon is wallClockMin (here 180 min, longer than the 2 h margin)', () => {
    harness({ cal: calibration(1, [grant('2026-10-14', '2026-11-17', '200.00', '200.00')]), pricingVerifiedAt: '2026-11-10' })
    // Two reservations at once: maxConcurrent 2 (BE-4b's default is 1).
    h.writeConfig({ headless: { ...headlessBlock(), wallClockMin: 180, maxConcurrent: 2 } })
    h.now = Date.UTC(2026, 10, 16, 20, 59)
    h.gate.tick()
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: true })
    h.now = Date.UTC(2026, 10, 16, 21, 0)
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'expiry_horizon' })
  })

  it('headless: a grant that expires within wallClockMin does not count', () => {
    harness({ cal: P1P2() })
    // Two reservations at once: maxConcurrent 2 (BE-4b's default is 1).
    h.writeConfig({ headless: { ...headlessBlock(), maxConcurrent: 2 } })
    // P1 (195.64) expires at 10-17 00:00Z, 60 min after now; wallClockMin is 90.
    h.now = Date.UTC(2026, 9, 16, 23, 0)
    expect(h.gate.tick().state).toBe('OPEN')
    // 120 x 1.5 = 180 = 200 - 20: fits on P2 alone.
    expect(h.gate.reserve(headless(120))).toMatchObject({ ok: true })
    expect(h.gate.reserve(headless(0.01))).toMatchObject({ ok: false, reason: 'below_threshold' })
  })

  it('without a headless block a headless reservation is refused', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.writeConfig({ headless: undefined })
    h.gate.tick()
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'headless_disabled' })
  })
})

describe('finding 2 (MED): a latch must not fall back to 0 during a calibration outage', () => {
  it('OPEN (cal 5) -> outage + human STOP -> STOP removed -> cal 5 back: does NOT open', () => {
    harness({ cal: simpleCal(5, '200.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    const keep = h.cal
    writeFileSync(h.stopPath, 'ember\n')
    h.cal = null
    h.now += 30_000
    h.gate.tick()
    expect(st()).toMatchObject({ state: 'CLOSED', latch: 5 })
    unlinkSync(h.stopPath)
    h.cal = keep
    h.now += 30_000
    h.gate.tick()
    h.now += 30_000
    expect(h.gate.tick().state).not.toBe('OPEN')
    h.cal = simpleCal(6, '200.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('a HOLD signal during the outage is not lifted by the same calibration', () => {
    harness({ cal: simpleCal(5, '200.00') })
    h.gate.tick()
    const keep = h.cal
    h.cal = null
    h.now += 30_000
    h.gate.tick()
    h.gate.signal('usage_log_failed', 'batch', null)
    expect(st()).toMatchObject({ state: 'HOLD', latch: 5 })
    h.cal = keep
    h.now += 30_000
    expect(h.gate.tick().state).toBe('HOLD')
  })

  it('a disarm during the outage is not lifted by the same calibration (reviewer probe)', () => {
    harness({ cal: simpleCal(7, '100.00') })
    h.gate.tick()
    h.cal = null
    h.now += 30_000
    h.gate.tick()
    h.gate.signal('disarm', 'human', null)
    h.cal = simpleCal(7, '100.00')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })

  it('a C-05 threshold latch is not downgraded by a new cause during the outage', () => {
    harness({ cal: simpleCal(5, '100.00') })
    h.gate.tick()
    const r = h.gate.reserve(haikuBatch(80_000_000, 10))
    if (!('ok' in r) || !r.ok) throw new Error(JSON.stringify(r))
    expect(r.closed).toBe(true)
    h.gate.release(r.reservation_id, 'rejected_4xx')
    const keep = h.cal
    h.cal = null
    writeFileSync(h.stopPath, 'ember\n')
    h.now += 30_000
    h.gate.tick()
    unlinkSync(h.stopPath)
    h.cal = keep
    h.now += 30_000
    expect(h.gate.tick().state).not.toBe('OPEN')
  })

  it('the lowcal threshold (40) is not reset to 20 by an outage tick and the same calibration', () => {
    harness({ cal: simpleCal(5, '55.00') })
    h.gate.tick()
    h.now += 12 * HOUR + 60_000
    h.gate.tick()
    expect(h.state().t_close_eff_micro).toBe(40 * USD)
    const keep = h.cal
    h.cal = null
    h.now += 30_000
    h.gate.tick()
    h.cal = keep
    h.now += 30_000
    h.gate.tick()
    expect(h.state().t_close_eff_micro).toBe(40 * USD)
    // A newer calibration does reset it.
    h.cal = simpleCal(6, '55.00')
    h.now += 30_000
    h.gate.tick()
    expect(h.state().t_close_eff_micro).toBe(20 * USD)
  })

  it('the largest calibration id ever seen is stored and never decreases', () => {
    harness({ cal: simpleCal(5, '100.00') })
    h.gate.tick()
    h.cal = null
    h.now += 30_000
    h.gate.tick()
    expect(h.state()).toMatchObject({ calibration_id: null, max_calibration_id: 5 })
    h.cal = simpleCal(3, '100.00')
    h.now += 30_000
    h.gate.tick()
    expect(h.state().max_calibration_id).toBe(5)
  })
})

describe('finding 3 (MED): a batch reservation released early through the binding', () => {
  it('BE-3 P2: bind must name the reserved request count; expected_requests=1 for 1000 requests is refused', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.gate.tick()
    const r1 = h.gate.reserve(haikuBatch(60_000_000, 1000))
    if (!('ok' in r1) || !r1.ok) throw new Error(JSON.stringify(r1))
    expect(h.gate.bind(r1.reservation_id, 'msgbatch_abc', 1)).toMatchObject({ ok: false, code: 409, reason: 'expected_mismatch' })
    expect(h.gate.bind(r1.reservation_id, 'msgbatch_abc', 1000)).toMatchObject({ ok: true })
    h.batchUsage('msgbatch_abc', 'c0', 'claude-haiku-5-5', 100, 10, Math.floor(T0 / 1000))
    h.now += 1000
    h.gate.tick()
    h.gate.complete(r1.reservation_id)
    h.now += 1000
    h.gate.tick()
    // One result of 1000 does not settle it: a second 60 USD batch does not fit.
    expect(h.gate.reserve(haikuBatch(60_000_000, 1000))).toMatchObject({ ok: false })
    expect(h.reservations()[0]).toMatchObject({ status: 'open', request_count: 1000 })
  })

  it('BE-3 P2b: a batch_id that already has ledger rows cannot be bound', () => {
    harness({ cal: simpleCal(1, '100.00') })
    h.batchUsage('msgbatch_old', 'o1', 'claude-sonnet-5-5', 50_000_000, 0, Math.floor((T0 - 3 * HOUR) / 1000))
    expect(h.gate.tick().state).toBe('OPEN')
    const r1 = h.gate.reserve(haikuBatch(60_000_000, 1000))
    if (!('ok' in r1) || !r1.ok) throw new Error(JSON.stringify(r1))
    expect(h.gate.bind(r1.reservation_id, 'msgbatch_old', 1000)).toMatchObject({ ok: false, code: 409, reason: 'batch_has_rows' })
    expect(h.gate.reserve(haikuBatch(60_000_000, 1000))).toMatchObject({ ok: false })
  })
})

describe('finding 4: saturation and implausible calibrations', () => {
  it('two grants of 100 000 USD are refused; above 10 000 per grant or 20 000 in total too', () => {
    for (const cal of [
      calibration(1, [grant('2026-10-14', '2026-11-17', '100000.00', '100000.00'), grant('2026-10-14', '2026-11-17', '100000.00', '100000.00')]),
      calibration(1, [grant('2026-10-14', '2026-11-17', '10000.01', '200.00')]),
      calibration(1, [
        grant('2026-10-14', '2026-11-17', '7000.00', '7000.00'),
        grant('2026-10-14', '2026-11-17', '7000.00', '7000.00'),
        grant('2026-10-14', '2026-11-17', '6000.01', '6000.01'),
      ]),
    ]) {
      harness({ cal })
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'calibration_invalid' })
      h.cleanup()
    }
    harness({ cal: calibration(1, [grant('2026-10-14', '2026-11-17', '10000.00', '10000.00'), grant('2026-10-14', '2026-11-17', '10000.00', '10000.00')]) })
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('a saturated ledger (L above 100 000 USD) closes with its own reason in the tick', () => {
    harness({ cal: simpleCal(1, '200.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    // 6 x 999 999 999 Opus output tokens: about 120 000 USD.
    for (let i = 0; i < 6; i++) h.usage('claude-opus-5-5', 0, 999_999_999)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'ledger_saturated' })
    expect(h.gate.status().ledger.saturated).toBe(true)
  })

  it('a ledger that saturates between the tick and a reservation: 409 ledger_saturated', () => {
    harness({ cal: simpleCal(1, '200.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    // Booked by another process after the tick (the state still says OPEN).
    h.db.prepare(`INSERT INTO credit_ledger_entries (source, dedupe_key, ts, model, input_tokens, output_tokens,
      cache_write_tokens, cache_read_tokens, est_micro, basis, ingested_at)
      VALUES ('anthropic-batch', 'x-sat', ?, 'claude-opus-5-5', 0, 0, 0, 0, ?, 'usage', ?)`).run(Math.floor(T0 / 1000), 200_000 * USD, T0)
    expect(h.gate.reserve(headless(1))).toMatchObject({ ok: false, reason: 'ledger_saturated' })
    expect(h.state()).toMatchObject({ state: 'CLOSED', reason: 'ledger_saturated' })
  })
})

describe('finding 5: guard-event lines already there at the first init are an INCIDENT', () => {
  const ev = JSON.stringify({ ts: '2026-10-16T08:00:00Z', source: 'guard-runner', where: 'tmux:global', names: ['ANTHROPIC_API_KEY'] }) + '\n'

  it('lines > 0 at init: INCIDENT guard_backlog (baseline recorded); only clearIncident lifts it', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, ev + ev)
    expect(h.gate.tick()).toMatchObject({ state: 'INCIDENT', reason: 'guard_backlog' })
    expect(JSON.parse(h.events('guard_baseline')[0].detail_json as string)).toMatchObject({ lines: 2, why: 'init' })
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('INCIDENT')
    const inc = h.events('transition').find((e) => e.to_state === 'INCIDENT')!
    expect(h.gate.clearIncident(inc.id as number)).toBe(true)
    h.cal = simpleCal(3, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
  })

  it('an empty or a missing file at init is no INCIDENT', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.guardPath, '')
    expect(h.gate.tick().state).toBe('OPEN')
    h.cleanup()
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
  })
})

describe('finding 6: a closure caused by the config itself still puts the STOP down', () => {
  it('BE-3 P4: OPEN -> config.json 0644 -> CLOSED config_invalid, and the STOP is out (last valid stopFile)', () => {
    harness({ cal: simpleCal(1, '200.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
    chmodSync(join(h.gateDir, 'config.json'), 0o644)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'config_invalid' })
    expect(readFileSync(h.stopPath, 'utf8')).toMatch(/^credit-gate v1 [0-9a-f]{32}$/)
  })

  it('a signal while the config is invalid also puts the STOP down', () => {
    harness({ cal: simpleCal(1, '200.00') })
    h.gate.tick()
    unlinkSync(join(h.gateDir, 'config.json'))
    h.gate.signal('disarm', 'operator', null)
    expect(existsSync(h.stopPath)).toBe(true)
  })
})

describe('finding 7: off mode in production (no db) names the gate\'s own STOP by its content', () => {
  it('BE-3 P3: the gate\'s STOP is "gate", a human one "human"', () => {
    harness({ cal: null })
    h.gate.tick()
    expect(startCreditGateRuntime({ webOnly: false, modeValue: 'off', storeDir: h.storeDir })).toBeUndefined()
    expect(getCreditGateRuntime().db).toBeNull()
    expect(inactiveStatus(getCreditGateRuntime()).stop).toMatchObject({ present: true, owner: 'gate' })
    unlinkSync(h.stopPath)
    writeFileSync(h.stopPath, 'STOP\n')
    expect(inactiveStatus({ mode: readCreditGateMode('off'), gate: null, storeDir: h.storeDir, db: null, startError: null }).stop)
      .toMatchObject({ present: true, owner: 'human' })
  })
})

function headlessBlock(): Record<string, unknown> {
  return {
    allowedCallers: ['ezermester'], cwdRoots: ['/Volumes/8T/10_LOCAL/Brainy'], forbiddenCwds: ['/Users/x/marveen'],
    runsDir: '/tmp/credit-gate-runs', claudeBin: '/opt/homebrew/bin/claude', claudeBinSha256: 'a'.repeat(64), models: ['claude-opus-5-5', 'claude-sonnet-5-5'],
    maxBudgetUsd: '5.00', wallClockMin: 90,
  }
}

describe('round 2, LOW 2: migrating a pre-round-1 state row keeps its calibration as the latch base', () => {
  /** Drop the gate tables, build them the old way with an OPEN row under calibration 5, upgrade. */
  function migrateOldOpenRow(): void {
    h.db.exec('DROP TABLE credit_gate_state; DROP TABLE credit_reservations; DROP TABLE credit_gate_events')
    applyPreRound1GateSchema(h.db)
    h.db.prepare(`INSERT INTO credit_gate_state (id, state, reason, since, calibration_id, evaluated_at, version)
      VALUES (1, 'OPEN', 'open', ?, 5, ?, 3)`).run(T0, T0)
    applyCreditGateSchema(h.db)
    h.gate = h.makeGate()
  }

  it('the upgrade fills max_calibration_id from calibration_id / latch_cal_id', () => {
    harness({ cal: simpleCal(5, '200.00') })
    migrateOldOpenRow()
    expect(h.state().max_calibration_id).toBe(5)
    const rcols = (h.db.prepare('PRAGMA table_info(credit_reservations)').all() as Array<{ name: string }>).map((c) => c.name)
    expect(rcols).toContain('request_count')
    // B14: the reported pair arrives empty; the old row's own state stands for it until the first write.
    expect(h.state()).toMatchObject({ reported_state: null, reported_reason: null })
    h.now += 30_000
    h.gate.tick()
    expect(h.events('transition')).toEqual([])
    expect(h.state()).toMatchObject({ state: 'OPEN', reported_state: 'OPEN', reported_reason: 'open' })
  })

  it('BE-3 R1: old OPEN row under cal 5 -> outage + human STOP -> STOP removed, cal 5 back: does NOT open', () => {
    harness({ cal: simpleCal(5, '200.00') })
    migrateOldOpenRow()
    const keep = h.cal
    h.cal = null
    writeFileSync(h.stopPath, 'ember\n')
    h.now += 30_000
    h.gate.tick()
    expect(st()).toMatchObject({ state: 'CLOSED', latch: 5 })
    unlinkSync(h.stopPath)
    h.cal = keep
    h.now += 30_000
    expect(h.gate.tick().state).not.toBe('OPEN')
  })

  it('a row whose stored max lags its own calibration_id (written by an older process): the tick still latches on 5', () => {
    harness({ cal: simpleCal(5, '200.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    h.db.prepare('UPDATE credit_gate_state SET max_calibration_id = 0 WHERE id = 1').run()
    const keep = h.cal
    h.cal = null
    writeFileSync(h.stopPath, 'ember\n')
    h.now += 30_000
    h.gate.tick()
    expect(st().latch).toBe(5)
    unlinkSync(h.stopPath)
    h.cal = keep
    h.now += 30_000
    expect(h.gate.tick().state).not.toBe('OPEN')
  })
})

describe('round 2, LOW 3: the schema upgrade swallows only "duplicate column"', () => {
  /** The real database, except that every ALTER fails with another error. */
  function failingAlterDb(db: Database.Database): Database.Database {
    return new Proxy(db, {
      get(target, prop, receiver) {
        if (prop === 'exec') {
          return (sql: string) => {
            if (/^\s*ALTER TABLE/i.test(sql)) throw Object.assign(new Error('disk I/O error'), { code: 'SQLITE_IOERR' })
            return target.exec(sql)
          }
        }
        const v = Reflect.get(target, prop, receiver)
        return typeof v === 'function' ? v.bind(target) : v
      },
    })
  }

  it('applying twice is fine (the duplicate columns are swallowed)', () => {
    harness()
    expect(() => {
      applyGateSchema(h.db)
      applyGateSchema(h.db)
    }).not.toThrow()
  })

  it('any other ALTER error is thrown, and the gate does not start (start_failed)', () => {
    harness()
    h.db.exec('DROP TABLE credit_gate_state; DROP TABLE credit_reservations; DROP TABLE credit_gate_events')
    applyPreRound1GateSchema(h.db)
    const bad = failingAlterDb(h.db)
    expect(() => applyGateSchema(bad)).toThrow(/disk I\/O error/)
    expect(startCreditGateRuntime({ webOnly: false, modeValue: 'enforce', db: bad, storeDir: h.storeDir })).toBeUndefined()
    expect(getCreditGateRuntime()).toMatchObject({ gate: null, startError: 'start_failed' })
    expect(inactiveStatus(getCreditGateRuntime())).toMatchObject({ state: 'CLOSED', reason: 'gate_not_running' })
  })
})
