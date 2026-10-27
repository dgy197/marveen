// The credit gate's state machine as pure functions (card fec6335f, blueprint
// 3.5, spec 8 and A-01..A-06, node N2a). No I/O, no clock: gate.ts gathers
// the inputs and stores the result.
//
// States, by severity: OPEN < CLOSED < HOLD < INCIDENT.
//  - CLOSED is the default. A transient closure (stale ledger or price table,
//    an unpriced row, no or invalid calibration, expiry, shadow or unknown
//    mode) lifts as soon as its cause is gone. A LATCHED closure (threshold
//    C-05; disarm, a human STOP and a 401 under A-05) lifts only with a
//    calibration NEWER than the one current when it latched.
//  - HOLD (measurement uncertain): latched like the above, and in addition
//    every HOLD condition that is still present (a broken ledger source, a
//    damaged guard-event file) must be gone.
//  - INCIDENT: only clearIncident() leaves it (N2c, after an owner approval),
//    into a latched CLOSED: a new calibration is still needed (blueprint 3.5).
// A latch always binds to `latchBase`, the LARGEST calibration id the gate has
// ever seen (stored, never decreasing) -- not to the current one, which may be
// missing for a moment. Otherwise a closure that happens while the source is
// empty would latch at 0 and the same old calibration would lift it (BE-3).
// OPEN is reached only from decide(), only in enforce mode, and only when no
// closure reason of any kind is present. applyCause() -- every signal and
// every in-transaction closure -- can only keep or raise the severity: no
// unapproved signal ever opens the gate (blueprint 14).

export type GateState = 'CLOSED' | 'OPEN' | 'HOLD' | 'INCIDENT'

export const STATE_SEVERITY: Readonly<Record<GateState, number>> = Object.freeze({
  OPEN: 0,
  CLOSED: 1,
  HOLD: 2,
  INCIDENT: 3,
})

export interface StateSnapshot {
  readonly state: GateState
  readonly reason: string
  /** null: no latch; 0: latched when there was no calibration at all. */
  readonly latchCalId: number | null
  readonly latchReason: string | null
}

export interface DecideInput {
  readonly prev: StateSnapshot
  /** The current calibration's id (null: none or invalid). */
  readonly calibrationId: number | null
  /** The largest calibration id ever seen (>= calibrationId; 0 = never one). New latches bind to it. */
  readonly latchBase: number
  /** New INCIDENT causes found by this evaluation. */
  readonly incidents: readonly string[]
  /** New HOLD causes that are events (they happened once). */
  readonly holdEvents: readonly string[]
  /** HOLD causes that are conditions (still present now). */
  readonly holdConditions: readonly string[]
  /** New causes of a latched closure (threshold, human_stop, ...). */
  readonly latchCauses: readonly string[]
  /** Transient closure reasons present now, most important first. */
  readonly closeReasons: readonly string[]
  /** Reasons that keep a CLOSED gate closed but do not close an OPEN one (R_est < T_reopen). */
  readonly reopenBlockers: readonly string[]
}

export type CauseKind = 'incident' | 'hold' | 'latch' | 'transient'

export interface Cause {
  readonly kind: CauseKind
  readonly reason: string
}

/** True when a latch set at `latchCalId` no longer holds under `calibrationId`. */
export function latchLifted(latchCalId: number | null, calibrationId: number | null): boolean {
  if (latchCalId === null) return true
  return calibrationId !== null && calibrationId > latchCalId
}

function closed(reason: string, latchCalId: number | null, latchReason: string | null): StateSnapshot {
  return { state: 'CLOSED', reason, latchCalId, latchReason }
}

/** The full evaluation of one tick: may open, close, hold or keep. */
export function decide(input: DecideInput): StateSnapshot {
  const { prev } = input
  const cal = input.latchBase

  // INCIDENT: nothing in a tick leaves it (clearIncident does).
  if (prev.state === 'INCIDENT') return prev
  if (input.incidents.length > 0) {
    return { state: 'INCIDENT', reason: input.incidents[0], latchCalId: cal, latchReason: input.incidents[0] }
  }

  // HOLD: a new HOLD event latches (again) under the current calibration.
  if (input.holdEvents.length > 0) {
    return { state: 'HOLD', reason: input.holdEvents[0], latchCalId: cal, latchReason: input.holdEvents[0] }
  }
  let latch: number | null
  let latchReason: string | null
  if (prev.state === 'HOLD') {
    if (!latchLifted(prev.latchCalId, input.calibrationId) || input.holdConditions.length > 0) {
      return { ...prev, reason: input.holdConditions[0] ?? prev.reason }
    }
    // Lifted: a newer calibration and no HOLD condition left.
    latch = null
    latchReason = null
  } else if (input.holdConditions.length > 0) {
    return { state: 'HOLD', reason: input.holdConditions[0], latchCalId: cal, latchReason: input.holdConditions[0] }
  } else {
    latch = prev.latchCalId
    latchReason = prev.latchReason
  }

  // Latched closures.
  if (input.latchCauses.length > 0) return closed(input.latchCauses[0], cal, input.latchCauses[0])
  if (!latchLifted(latch, input.calibrationId)) return closed(latchReason ?? 'latched', latch, latchReason)

  // Transient closures.
  if (input.closeReasons.length > 0) return closed(input.closeReasons[0], null, null)

  // Nothing closes it. An OPEN gate stays open (hysteresis: below T_reopen is
  // fine once open); a closed one opens only when nothing blocks a reopening.
  if (prev.state === 'OPEN') return { state: 'OPEN', reason: 'open', latchCalId: null, latchReason: null }
  if (input.reopenBlockers.length > 0) return closed(input.reopenBlockers[0], null, null)
  return { state: 'OPEN', reason: 'opened', latchCalId: null, latchReason: null }
}

/**
 * One closing cause applied to a state (a signal, or a closure found inside a
 * reservation). Never lowers the severity, never opens.
 */
export function applyCause(prev: StateSnapshot, cause: Cause, latchBase: number): StateSnapshot {
  const cal = latchBase
  switch (cause.kind) {
    case 'incident':
      if (prev.state === 'INCIDENT') return prev
      return { state: 'INCIDENT', reason: cause.reason, latchCalId: cal, latchReason: cause.reason }
    case 'hold':
      if (prev.state === 'INCIDENT') return prev
      // A new HOLD event re-latches under the current calibration, in HOLD too.
      return { state: 'HOLD', reason: cause.reason, latchCalId: cal, latchReason: cause.reason }
    case 'latch':
      if (prev.state === 'HOLD' || prev.state === 'INCIDENT') return prev
      return closed(cause.reason, cal, cause.reason)
    case 'transient':
      if (prev.state !== 'OPEN') return prev
      return closed(cause.reason, null, null)
  }
}

/**
 * A Bearer signal's cause (B14). As applyCause, except on a gate that is
 * already latched at least as hard as the signal would latch it -- a CLOSED
 * or higher for a latch signal, a HOLD or higher for a hold signal, bound to
 * `latchBase` already: it is returned unchanged. The signal would not move
 * the latch, only rewrite the reason and the latch reason, and the next tick,
 * giving the latch's own reason back, would be one more change per signal.
 * The signal's own audit row records it. A latch below `latchBase` (a newer
 * calibration was seen since) is re-latched as before, and an incident signal
 * is applyCause's (its cause is coalesced per kind by the gate, B10).
 */
export function applySignal(prev: StateSnapshot, cause: Cause, latchBase: number): StateSnapshot {
  if (cause.kind === 'latch' || cause.kind === 'hold') {
    const floor = cause.kind === 'latch' ? STATE_SEVERITY.CLOSED : STATE_SEVERITY.HOLD
    if (STATE_SEVERITY[prev.state] >= floor && prev.latchCalId !== null && prev.latchCalId >= latchBase) return prev
  }
  return applyCause(prev, cause, latchBase)
}

/**
 * INCIDENT -> CLOSED after an owner's incident-clear approval (N2c checks the
 * approval). The result is latched: only a calibration newer than the current
 * one opens. Any other state is returned unchanged.
 */
export function clearIncident(prev: StateSnapshot, latchBase: number): StateSnapshot {
  if (prev.state !== 'INCIDENT') return prev
  return closed('incident_cleared', latchBase, 'incident_cleared')
}
