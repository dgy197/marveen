import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  loadCreditGateConfigFile,
  parseCreditGateConfig,
  parseUtcInstant,
  readCreditGateMode,
  readProtectedFile,
} from '../web/credit-gate/config.js'
import {
  applyCause,
  applySignal,
  clearIncident,
  decide,
  latchLifted,
  STATE_SEVERITY,
  type DecideInput,
  type GateState,
  type StateSnapshot,
} from '../web/credit-gate/gate-state.js'
import { configObject } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a: the mode flag, the config file and the pure state
// machine (card fec6335f). Written from the spec (A-01..A-06, C-04, C-05) and
// the blueprint (3.1, 3.2, 3.5, 14), not from the code.

describe('CREDIT_GATE_MODE (blueprint 3.1)', () => {
  it('missing or empty is off: today\'s behaviour', () => {
    for (const v of [undefined, null, '', '   ']) {
      expect(readCreditGateMode(v)).toEqual({ mode: 'off', raw: null, unknown: false })
    }
  })

  it('the three known values, surrounding whitespace ignored', () => {
    expect(readCreditGateMode('off')).toEqual({ mode: 'off', raw: 'off', unknown: false })
    expect(readCreditGateMode('shadow')).toEqual({ mode: 'shadow', raw: 'shadow', unknown: false })
    expect(readCreditGateMode(' enforce ')).toEqual({ mode: 'enforce', raw: 'enforce', unknown: false })
  })

  it('K2: an unknown value is enforce, flagged unknown (fail-closed), never off', () => {
    for (const v of ['Enforce', 'OFF', 'of', 'disabled', 'true', '0', 'enforced']) {
      const r = readCreditGateMode(v)
      expect(r.mode).toBe('enforce')
      expect(r.unknown).toBe(true)
      expect(r.raw).toBe(v)
    }
  })
})

describe('config.json (blueprint 3.2)', () => {
  const base = () => configObject('/tmp/x/usage.jsonl', '/tmp/x/batch/STOP')
  const parse = (o: unknown) => parseCreditGateConfig(JSON.stringify(o))

  it('the blueprint\'s default config is accepted', () => {
    const r = parse(base())
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.config.thresholds.tClose).toBe(20_000_000)
    expect(r.config.thresholds.tReopen).toBe(50_000_000)
    expect(r.config.reservationFactor).toEqual({ num: 1_500_000n, den: 1_000_000n })
    expect(r.config.batchHorizonH).toBe(24)
    expect(r.config.headless?.wallClockMin).toBe(90)
    // Without the headless block the headless path stays off.
    const { headless: _h, ...noHeadless } = base()
    const r2 = parse(noHeadless)
    expect(r2.ok && r2.config.headless).toBeNull()
  })

  it('batchHorizonH is required, at least 24 (spec C-06b), at most 168', () => {
    const { batchHorizonH: _b, ...without } = base()
    expect(parse(without).ok).toBe(false)
    for (const v of [0, 1, 23, 169]) expect(parse({ ...base(), batchHorizonH: v }).ok, String(v)).toBe(false)
    expect(parse({ ...base(), batchHorizonH: 24 }).ok).toBe(true)
    expect(parse({ ...base(), batchHorizonH: 168 }).ok).toBe(true)
  })

  it('accepts a full headless block and rejects a relative path in it', () => {
    const headless = {
      allowedCallers: ['ezermester'], cwdRoots: ['/Volumes/8T/10_LOCAL/Brainy'], forbiddenCwds: ['/Users/x/marveen'],
      runsDir: '/tmp/runs', claudeBin: '/opt/homebrew/bin/claude', claudeBinSha256: 'a'.repeat(64), models: ['claude-opus-5-5', 'claude-sonnet-5-5'],
      maxBudgetUsd: '5.00', wallClockMin: 90,
    }
    const ok = parse({ ...base(), headless })
    expect(ok.ok).toBe(true)
    if (ok.ok) expect(ok.config.headless?.maxBudget).toBe(5_000_000)
    expect(parse({ ...base(), headless: { ...headless, cwdRoots: ['relative/dir'] } }).ok).toBe(false)
    expect(parse({ ...base(), headless: { ...headless, extra: 1 } }).ok).toBe(false)
  })

  it('rejects every out-of-bounds or malformed value, with a reason', () => {
    const bad: Array<[string, Record<string, unknown>]> = [
      ['unknown key', { ...base(), surprise: 1 }],
      ['tClose below 20.00', { ...base(), thresholds: { ...(base().thresholds as object), tClose: '19.99' } }],
      ['tClose not two decimals', { ...base(), thresholds: { ...(base().thresholds as object), tClose: '20.0' } }],
      ['reopen not above the lowcal close', { ...base(), thresholds: { ...(base().thresholds as object), tReopen: '40.00' } }],
      ['lowcal ask below reopen', { ...base(), thresholds: { ...(base().thresholds as object), tLowcal: '49.99' } }],
      ['factor below 1.5', { ...base(), reservationFactor: '1.49' }],
      ['ledger age above 120 s', { ...base(), maxLedgerAgeS: 121 }],
      ['expiry margin below 2 h', { ...base(), expiryMarginH: 1 }],
      ['relative STOP path', { ...base(), stopFile: 'batch/STOP' }],
      ['unnormalised STOP path', { ...base(), stopFile: '/tmp/x/../STOP' }],
      ['reserved ledger source id', { ...base(), ledgerSources: [{ id: 'headless', path: '/tmp/u.jsonl', format: 'usage-jsonl-v1' }] }],
      ['unknown ledger format', { ...base(), ledgerSources: [{ id: 'a', path: '/tmp/u.jsonl', format: 'csv' }] }],
      ['protected not two decimals', { ...base(), protected: { R: '3.6', V: '10.00' } }],
      ['refresh slower than half the max age', { ...base(), refreshS: 61 }],
    ]
    for (const [name, o] of bad) {
      const r = parse(o)
      expect(r.ok, name).toBe(false)
    }
    expect(parse({ ...base(), schema: 'credit-gate-config/v2' })).toMatchObject({ ok: false, reason: 'schema' })
    expect(parseCreditGateConfig('{"schema": "credit-gate-config/v1", "schema": "x"}')).toMatchObject({ ok: false, reason: 'duplicate_key' })
    expect(parseCreditGateConfig('{nope')).toMatchObject({ ok: false, reason: 'invalid_json' })
  })

  describe('the file itself', () => {
    let dir: string
    beforeEach(() => {
      dir = mkdtempSync(join(tmpdir(), 'credit-gate-config-'))
      chmodSync(dir, 0o700)
    })
    afterEach(() => rmSync(dir, { recursive: true, force: true }))

    it('0600 in a 0700 folder: accepted', () => {
      const p = join(dir, 'config.json')
      writeFileSync(p, JSON.stringify(configObject('/tmp/u.jsonl', '/tmp/STOP')), { mode: 0o600 })
      expect(loadCreditGateConfigFile(p).ok).toBe(true)
    })

    it('a file open to others, a symlink, a folder open to others, a missing file: rejected', () => {
      const p = join(dir, 'config.json')
      writeFileSync(p, JSON.stringify(configObject('/tmp/u.jsonl', '/tmp/STOP')), { mode: 0o600 })
      chmodSync(p, 0o644)
      expect(readProtectedFile(p)).toMatchObject({ ok: false, reason: 'permissions' })
      chmodSync(p, 0o600)
      const link = join(dir, 'link.json')
      symlinkSync(p, link)
      expect(readProtectedFile(link)).toMatchObject({ ok: false, reason: 'permissions' })
      expect(readProtectedFile(join(dir, 'nope.json'))).toMatchObject({ ok: false, reason: 'missing' })
      const open = join(dir, 'open')
      mkdirSync(open)
      chmodSync(open, 0o755)
      writeFileSync(join(open, 'c.json'), '{}', { mode: 0o600 })
      expect(readProtectedFile(join(open, 'c.json'))).toMatchObject({ ok: false, reason: 'permissions' })
    })
  })

  it('expiry instants: a date is that day 00:00:00Z (C-06), a stamp is exact, nonsense is null', () => {
    expect(parseUtcInstant('2026-10-17')).toBe(Date.UTC(2026, 9, 17))
    expect(parseUtcInstant('2026-11-17T12:30:00Z')).toBe(Date.UTC(2026, 10, 17, 12, 30))
    for (const s of ['2026-02-30', '2026-10-17T24:00:00Z', '2026-10-17 00:00', '17/10/2026', 20261017, null]) {
      expect(parseUtcInstant(s)).toBeNull()
    }
  })
})

const CLOSED: StateSnapshot = { state: 'CLOSED', reason: 'initial', latchCalId: null, latchReason: null }
const OPEN: StateSnapshot = { state: 'OPEN', reason: 'open', latchCalId: null, latchReason: null }

function input(prev: StateSnapshot, over: Partial<DecideInput> = {}): DecideInput {
  const calibrationId = over.calibrationId === undefined ? 1 : over.calibrationId
  return {
    prev,
    calibrationId,
    latchBase: Math.max(calibrationId ?? 0, prev.latchCalId ?? 0),
    incidents: [],
    holdEvents: [],
    holdConditions: [],
    latchCauses: [],
    closeReasons: [],
    reopenBlockers: [],
    ...over,
  }
}

describe('the state machine (blueprint 3.5)', () => {
  it('CLOSED opens only when nothing at all speaks against it', () => {
    expect(decide(input(CLOSED)).state).toBe('OPEN')
    expect(decide(input(CLOSED, { reopenBlockers: ['below_reopen'] }))).toMatchObject({ state: 'CLOSED', reason: 'below_reopen' })
    expect(decide(input(CLOSED, { closeReasons: ['ledger_stale'] }))).toMatchObject({ state: 'CLOSED', reason: 'ledger_stale' })
    expect(decide(input(CLOSED, { calibrationId: null, closeReasons: ['no_calibration'] }))).toMatchObject({ state: 'CLOSED' })
  })

  it('hysteresis: an OPEN gate below T_reopen (but above T_close) stays OPEN', () => {
    expect(decide(input(OPEN, { reopenBlockers: ['below_reopen'] })).state).toBe('OPEN')
  })

  it('a transient closure lifts when its cause is gone, with the same calibration', () => {
    const closed = decide(input(OPEN, { closeReasons: ['ledger_stale'] }))
    expect(closed).toMatchObject({ state: 'CLOSED', reason: 'ledger_stale', latchCalId: null })
    expect(decide(input(closed)).state).toBe('OPEN')
  })

  it('C-05: a threshold closure does not reopen under the same calibration, a newer one lifts it', () => {
    const closed = decide(input(OPEN, { latchCauses: ['threshold'] }))
    expect(closed).toMatchObject({ state: 'CLOSED', reason: 'threshold', latchCalId: 1, latchReason: 'threshold' })
    const again = decide(input(closed))
    expect(again).toMatchObject({ state: 'CLOSED', reason: 'threshold', latchCalId: 1 })
    expect(decide(input(again, { calibrationId: 2 })).state).toBe('OPEN')
    // An older id (a stale source) does not lift it either.
    expect(decide(input(again, { calibrationId: 0 })).state).toBe('CLOSED')
  })

  it('a latch set while there was no calibration ever (0) is lifted by the first calibration', () => {
    const closed = decide(input(CLOSED, { calibrationId: null, latchCauses: ['disarm'], closeReasons: ['no_calibration'] }))
    expect(closed.latchCalId).toBe(0)
    expect(decide(input(closed, { calibrationId: 1 })).state).toBe('OPEN')
    expect(latchLifted(0, null)).toBe(false)
    expect(latchLifted(null, null)).toBe(true)
    expect(latchLifted(3, 3)).toBe(false)
    expect(latchLifted(3, 4)).toBe(true)
  })

  it('BE-3: a latch set during a calibration outage binds to the largest id ever seen, not to 0', () => {
    // The gate saw calibration 5, then the source went empty: calibrationId null, latchBase 5.
    const closed = decide(input(OPEN, { calibrationId: null, latchBase: 5, latchCauses: ['human_stop'], closeReasons: ['no_calibration'] }))
    expect(closed).toMatchObject({ state: 'CLOSED', latchCalId: 5 })
    // The SAME calibration 5 comes back: still closed. Only 6 lifts it.
    expect(decide(input(closed, { calibrationId: 5, latchBase: 5 })).state).toBe('CLOSED')
    expect(decide(input(closed, { calibrationId: 6, latchBase: 6 })).state).toBe('OPEN')
    const held = applyCause(OPEN, { kind: 'hold', reason: 'usage_log_failed' }, 5)
    expect(held.latchCalId).toBe(5)
    expect(decide(input(held, { calibrationId: 5, latchBase: 5 })).state).toBe('HOLD')
    expect(clearIncident({ state: 'INCIDENT', reason: 'x', latchCalId: 5, latchReason: 'x' }, 7).latchCalId).toBe(7)
  })

  it('HOLD needs a newer calibration AND every HOLD condition gone', () => {
    const held = decide(input(OPEN, { holdConditions: ['ledger_broken:a'] }))
    expect(held).toMatchObject({ state: 'HOLD', reason: 'ledger_broken:a', latchCalId: 1 })
    // The condition is gone, but the calibration is the same: still HOLD.
    expect(decide(input(held)).state).toBe('HOLD')
    // A newer calibration, but the condition is still there: still HOLD.
    expect(decide(input(held, { calibrationId: 2, holdConditions: ['ledger_broken:a'] })).state).toBe('HOLD')
    // Both: it leaves HOLD, and opens if nothing else speaks against it.
    expect(decide(input(held, { calibrationId: 2 })).state).toBe('OPEN')
    expect(decide(input(held, { calibrationId: 2, reopenBlockers: ['below_reopen'] })).state).toBe('CLOSED')
  })

  it('INCIDENT is left only through clearIncident, and then a newer calibration is still needed', () => {
    const inc = decide(input(OPEN, { incidents: ['guard_event'] }))
    expect(inc).toMatchObject({ state: 'INCIDENT', reason: 'guard_event' })
    expect(decide(input(inc, { calibrationId: 5 })).state).toBe('INCIDENT')
    const cleared = clearIncident(inc, 1)
    expect(cleared).toMatchObject({ state: 'CLOSED', latchCalId: 1 })
    expect(decide(input(cleared)).state).toBe('CLOSED')
    expect(decide(input(cleared, { calibrationId: 2 })).state).toBe('OPEN')
    // clearIncident on anything else changes nothing.
    expect(clearIncident(OPEN, 1)).toEqual(OPEN)
  })

  it('severity order: incident > hold > latched closure > transient closure', () => {
    const all = input(OPEN, {
      incidents: ['credit_balance_too_low'], holdEvents: ['stop_race'], latchCauses: ['disarm'], closeReasons: ['ledger_stale'],
    })
    expect(decide(all).state).toBe('INCIDENT')
    expect(decide({ ...all, incidents: [] }).state).toBe('HOLD')
    expect(decide({ ...all, incidents: [], holdEvents: [] })).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })

  it('applyCause never opens and never lowers the severity, for every state and every cause', () => {
    const prevs: StateSnapshot[] = [
      OPEN,
      CLOSED,
      { state: 'CLOSED', reason: 'threshold', latchCalId: 1, latchReason: 'threshold' },
      { state: 'HOLD', reason: 'stop_race', latchCalId: 1, latchReason: 'stop_race' },
      { state: 'INCIDENT', reason: 'guard_event', latchCalId: 1, latchReason: 'guard_event' },
    ]
    for (const prev of prevs) {
      for (const kind of ['incident', 'hold', 'latch', 'transient'] as const) {
        for (const cal of [0, 1, 2]) {
          const r = applyCause(prev, { kind, reason: `x_${kind}` }, cal)
          expect(r.state).not.toBe('OPEN')
          expect(STATE_SEVERITY[r.state as GateState]).toBeGreaterThanOrEqual(STATE_SEVERITY[prev.state])
        }
      }
    }
    expect(applyCause(OPEN, { kind: 'latch', reason: 'disarm' }, 3)).toMatchObject({ state: 'CLOSED', latchCalId: 3, latchReason: 'disarm' })
    expect(applyCause(OPEN, { kind: 'transient', reason: 'ledger_stale' }, 3)).toMatchObject({ state: 'CLOSED', latchCalId: null })
    expect(applyCause(CLOSED, { kind: 'hold', reason: 'usage_log_failed' }, 0)).toMatchObject({ state: 'HOLD', latchCalId: 0 })
    expect(applyCause(OPEN, { kind: 'incident', reason: 'credit_balance_too_low' }, 1).state).toBe('INCIDENT')
  })

  it('B14: a signal on a gate already latched at least as hard, under the latch base, changes nothing; otherwise it is applyCause', () => {
    const threshold: StateSnapshot = { state: 'CLOSED', reason: 'threshold', latchCalId: 2, latchReason: 'threshold' }
    const held: StateSnapshot = { state: 'HOLD', reason: 'ledger_broken:a', latchCalId: 2, latchReason: 'ledger_broken:a' }
    const disarm = { kind: 'latch', reason: 'disarm' } as const
    const usage = { kind: 'hold', reason: 'usage_log_failed' } as const
    // Latched under the latch base: the very same snapshot, no new reason or latch reason.
    expect(applySignal(threshold, disarm, 2)).toBe(threshold)
    expect(applySignal(threshold, { kind: 'latch', reason: 'auth_401' }, 2)).toBe(threshold)
    expect(applySignal(held, usage, 2)).toBe(held)
    expect(applySignal(held, disarm, 2)).toBe(held)
    // A newer calibration seen since the latch: re-latched under it, as before.
    expect(applySignal(threshold, disarm, 3)).toEqual({ state: 'CLOSED', reason: 'disarm', latchCalId: 3, latchReason: 'disarm' })
    expect(applySignal(held, usage, 3)).toEqual({ state: 'HOLD', reason: 'usage_log_failed', latchCalId: 3, latchReason: 'usage_log_failed' })
    // Never weaker than applyCause: a severity raise, a first latch, an opening's end.
    expect(applySignal(threshold, usage, 2)).toMatchObject({ state: 'HOLD', latchCalId: 2 })
    expect(applySignal(CLOSED, disarm, 2)).toMatchObject({ state: 'CLOSED', reason: 'disarm', latchCalId: 2 })
    expect(applySignal(OPEN, disarm, 2)).toMatchObject({ state: 'CLOSED', latchCalId: 2 })
    expect(applySignal(threshold, { kind: 'incident', reason: 'credit_balance_too_low' }, 2).state).toBe('INCIDENT')
    const prevs: StateSnapshot[] = [OPEN, CLOSED, threshold, held, { state: 'INCIDENT', reason: 'guard_event', latchCalId: 2, latchReason: 'guard_event' }]
    for (const prev of prevs) {
      for (const kind of ['incident', 'hold', 'latch', 'transient'] as const) {
        for (const cal of [0, 1, 2, 3]) {
          const r = applySignal(prev, { kind, reason: `x_${kind}` }, cal)
          const c = applyCause(prev, { kind, reason: `x_${kind}` }, cal)
          expect(STATE_SEVERITY[r.state]).toBe(STATE_SEVERITY[c.state])
          // The same severity, and a latch never lower than applyCause would leave it.
          expect(r.latchCalId ?? -1).toBeGreaterThanOrEqual(c.latchCalId ?? -1)
        }
      }
    }
  })
})
