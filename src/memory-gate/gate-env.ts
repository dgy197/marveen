// Memory write gate: the two .env keys every gate consumer needs first
// (MEMORY_GATE_MODE, MEMORY_GATE_OWNERS) plus the main-agent guard
// (MEMORY_GATE_MAIN_AGENT_OK). Card 3e9f6c28.
//
// ALL MEMORY_GATE_* keys are read from the .env file ONLY (readEnvFile), never
// through cfg()/config-overrides.json and never through the config registry
// (GN1): the dashboard Settings page must not be able to widen the gate's data
// scope. The pure resolvers below take the raw values so they are testable
// without touching the file system.
import { readEnvFile } from '../env.js'
import { MAIN_AGENT_ID } from '../config.js'

export type GateMode = 'off' | 'shadow' | 'active'

/** Agents whose memories may NEVER reach the classifier, whatever .env says (family-private; Brainy 4217 / spec D6). */
export const FORBIDDEN_OWNERS: readonly string[] = ['feszek']

const OWNER_RE = /^[a-z0-9_-]{1,32}$/
const MAIN_AGENT_OK_RE = /^tg-[0-9]{1,8}$/

export interface GateOwners {
  /** Effective owner list (already minus the main agent when it is not approved). */
  owners: string[]
  /** Non-null = the whole gate is off for this config ('bad_owner' | 'forbidden_owner'). */
  configError: string | null
  /** True when the main agent was named but dropped for want of a valid MEMORY_GATE_MAIN_AGENT_OK. */
  mainAgentExcluded: boolean
}

/**
 * Parse MEMORY_GATE_OWNERS. Rules (blueprint r5 4.1 + Brainy 4217 Q1):
 *  - empty / missing = no owners = the gate does nothing;
 *  - an element that is not [a-z0-9_-]{1,32} = config_error (bad_owner);
 *  - a forbidden owner (feszek) = config_error (forbidden_owner), never silently dropped;
 *  - the main agent is dropped unless MEMORY_GATE_MAIN_AGENT_OK is exactly `tg-<digits>`
 *    (missing, empty or malformed = excluded, the other owners keep working).
 */
export function resolveGateOwners(rawOwners: string | undefined, rawMainOk: string | undefined, mainAgentId: string): GateOwners {
  const parts = (rawOwners ?? '').split(',').map(s => s.trim()).filter(s => s.length > 0)
  if (parts.length === 0) return { owners: [], configError: null, mainAgentExcluded: false }
  for (const p of parts) {
    if (!OWNER_RE.test(p)) return { owners: [], configError: 'bad_owner', mainAgentExcluded: false }
    if (FORBIDDEN_OWNERS.includes(p)) return { owners: [], configError: 'forbidden_owner', mainAgentExcluded: false }
  }
  const mainOk = MAIN_AGENT_OK_RE.test((rawMainOk ?? '').trim())
  let mainAgentExcluded = false
  const owners: string[] = []
  for (const p of parts) {
    if (p === mainAgentId && !mainOk) { mainAgentExcluded = true; continue }
    if (!owners.includes(p)) owners.push(p)
  }
  return { owners, configError: null, mainAgentExcluded }
}

/** MEMORY_GATE_MODE: off / shadow / active; anything else (and unset) = off. */
export function parseGateMode(raw: string | undefined): { mode: GateMode; invalid: boolean } {
  const v = (raw ?? '').trim().toLowerCase()
  if (v === '') return { mode: 'off', invalid: false }
  if (v === 'off' || v === 'shadow' || v === 'active') return { mode: v, invalid: false }
  return { mode: 'off', invalid: true }
}

export interface GateEnv {
  configuredMode: GateMode
  /** b1 has no `active`: it runs as shadow. b2 lifts this. */
  effectiveMode: GateMode
  invalidMode: boolean
  owners: GateOwners
}

/** Read the gate keys from .env (fresh read, so a restart is the only thing a change needs). */
export function readGateEnv(mainAgentId: string = MAIN_AGENT_ID): GateEnv {
  return gateEnvFromValues(readEnvFile(['MEMORY_GATE_MODE', 'MEMORY_GATE_OWNERS', 'MEMORY_GATE_MAIN_AGENT_OK']), mainAgentId)
}

/** The same resolution over values already read from .env (state.ts reads every key in one go). */
export function gateEnvFromValues(e: Record<string, string | undefined>, mainAgentId: string = MAIN_AGENT_ID): GateEnv {
  const { mode, invalid } = parseGateMode(e.MEMORY_GATE_MODE)
  const owners = resolveGateOwners(e.MEMORY_GATE_OWNERS, e.MEMORY_GATE_MAIN_AGENT_OK, mainAgentId)
  return {
    configuredMode: mode,
    effectiveMode: mode === 'active' ? 'shadow' : mode,
    invalidMode: invalid,
    owners,
  }
}

/** The gate does anything at all only for a non-off mode, a clean config and at least one owner. */
export function gateActive(env: GateEnv): boolean {
  return env.effectiveMode !== 'off' && env.owners.configError === null && env.owners.owners.length > 0
}
