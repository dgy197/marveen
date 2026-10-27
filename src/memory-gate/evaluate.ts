// Memory write gate, b1: would the decision be applied? (card 3e9f6c28, node G2c).
//
// A pure function over the decision and a fresh read of its target. b1 only
// LOGS the answer (`would_apply`, `apply_block`); nothing is applied, no effect
// table exists, and no memory row is touched. b2 applies exactly what this
// returns, so the rules live here once.
import type { ModelOp } from './parse.js'

export interface EvalTarget {
  id: number
  agent_id: string
  category: string
  /** memory_versions count at the time of the read. */
  version: number
}

export interface EvalInput {
  op: ModelOp
  confidence: number
  sourceId: number
  sourceOwner: string
  /** The target's version recorded when the candidate was offered (CAS). */
  offeredVersion: number | null
  /** Fresh read of the target, null when it no longer exists or none was named. */
  target: EvalTarget | null
  /** Decisions of this op already marked would_apply today (Budapest day). */
  appliedToday: number
}

export interface EvalLimits {
  supersedeMinConf: number
  otherMinConf: number
  maxSupersedePerDay: number
  maxContradictPerDay: number
}

export interface EvalResult { wouldApply: boolean; block: string | null }

const no = (block: string): EvalResult => ({ wouldApply: false, block })

export function evaluateApply(d: EvalInput, lim: EvalLimits): EvalResult {
  if (d.op === 'CREATE') return { wouldApply: false, block: null }
  if (d.op === 'EXPIRE' || d.op === 'MERGE') return no('proposal_only')
  const t = d.target
  if (t === null) return no('target_missing')
  if (t.id === d.sourceId) return no('self_target')
  if (t.id > d.sourceId) return no('target_newer')
  if (t.agent_id !== d.sourceOwner) return no('other_owner')
  if (t.category !== 'warm' && t.category !== 'cold') return no('target_category')
  if (d.offeredVersion === null || t.version !== d.offeredVersion) return no('target_changed')
  const min = d.op === 'SUPERSEDE' ? lim.supersedeMinConf : lim.otherMinConf
  if (!(d.confidence >= min)) return no('low_confidence')
  if (d.op === 'SUPERSEDE' && d.appliedToday >= lim.maxSupersedePerDay) return no('daily_cap')
  if (d.op === 'CONTRADICT' && d.appliedToday >= lim.maxContradictPerDay) return no('daily_cap')
  return { wouldApply: true, block: null }
}
