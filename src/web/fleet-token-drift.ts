// Fleet-token drift detector (card acdb8045 K5).
//
// Read-only: it compares each running fleet-token sub-agent's launch stamp with
// the token file as it is now and REPORTS. It never restarts anything and has no
// restart dependency at all (the restart-all route is K6, owner session only).
//
// Output hygiene: the only things that leave this module are agent names and the
// state words below. The fingerprints stay inside FleetTokenDriftDeps callbacks
// and are compared in memory; they are not returned, logged or put in a string.
//
// IO-injected (FleetTokenDriftDeps) so the state machine is unit-tested without
// tmux, the vault or the real store. The production binding is
// fleet-token-drift-live.ts.
import { createdAfterTokenChange, fleetTokenState, type LaunchRegistry } from './fleet-token-fingerprint.js'

/**
 * What the API / system-status shows per agent. Values only, no fingerprint.
 *  - current:           stamp equals the token file now
 *  - stale:             stamp differs from the token file now
 *  - unknown:           no stamp (session predates stamping) or the file cannot be read
 *  - current-estimated: no stamp, but the session was created after the token file's last change (label only)
 *  - n/a:               not a running fleet-token sub-agent (main, own token, remote, GPT/LiteLLM, stopped)
 */
export type FleetTokenField = 'current' | 'stale' | 'unknown' | 'current-estimated' | 'n/a'

export interface FleetTokenDriftDeps {
  /** Candidate agent names (sub-agents; the main agent may be listed, it is n/a). */
  listAgents(): string[]
  /** agentUsesFleetToken for this agent (main / remote / own token / non-Claude -> false). */
  usesFleetToken(name: string): boolean
  isRunning(name: string): boolean
  /** Fingerprint of the token file now, or null when missing / empty / unreadable. In-memory only. */
  currentFingerprint(): string | null
  /** The launch registry. In-memory only. */
  registry(): LaunchRegistry
  /** tmux session_created of the agent in ms, or null. Called only for stamp-less agents. */
  sessionCreatedMs(name: string): number | null
  /** mtime of the token file in ms, or null. Called only for stamp-less agents. */
  tokenMtimeMs(): number | null
}

interface Snapshot {
  current: string | null
  registry: LaunchRegistry
}

function snapshot(deps: FleetTokenDriftDeps): Snapshot {
  let current: string | null = null
  let registry: LaunchRegistry = Object.create(null)
  try { current = deps.currentFingerprint() } catch { current = null }
  try { registry = deps.registry() } catch { registry = Object.create(null) }
  return { current, registry }
}

function fieldWith(name: string, deps: FleetTokenDriftDeps, snap: Snapshot): FleetTokenField {
  try {
    if (!deps.usesFleetToken(name)) return 'n/a'
    if (!deps.isRunning(name)) return 'n/a'
    const launchFp = snap.registry[`agent:${name}`]?.fp ?? null
    const state = fleetTokenState(launchFp, snap.current)
    if (state !== 'unknown') return state
    // Label only, never a decision: no stamp but the file is readable and the
    // session was born after the file last changed.
    if (launchFp === null && snap.current !== null && createdAfterTokenChange(deps.sessionCreatedMs(name), deps.tokenMtimeMs())) {
      return 'current-estimated'
    }
    return 'unknown'
  } catch {
    // A failing probe must not turn into a false `stale`.
    return 'unknown'
  }
}

/** The `fleetToken` field of GET /api/agents/:name/status. */
export function fleetTokenFieldFor(name: string, deps: FleetTokenDriftDeps): FleetTokenField {
  return fieldWith(name, deps, snapshot(deps))
}

export interface FleetTokenDrift {
  /** false when the current token cannot be fingerprinted (file missing / empty / unreadable). */
  measurable: boolean
  /** Running fleet-token agents whose stamp differs from the token file now (sorted). */
  stale: string[]
  /** Running fleet-token agents with no verdict (no stamp / unreadable), sorted. */
  unknown: string[]
  /** Running fleet-token agents that are current (stamped or estimated). */
  current: number
}

/** Drift over the running fleet-token agents. Read-only; never restarts anything. */
export function fleetTokenDrift(deps: FleetTokenDriftDeps): FleetTokenDrift {
  const snap = snapshot(deps)
  const out: FleetTokenDrift = { measurable: snap.current !== null, stale: [], unknown: [], current: 0 }
  let names: string[] = []
  try { names = [...deps.listAgents()].sort() } catch { names = [] }
  for (const name of names) {
    const f = fieldWith(name, deps, snap)
    if (f === 'stale') out.stale.push(name)
    else if (f === 'unknown') out.unknown.push(name)
    else if (f === 'current' || f === 'current-estimated') out.current += 1
  }
  return out
}

/** The system-status row value (label `Flotta-token`). Names and counts only. */
export function fleetTokenStatusLine(d: FleetTokenDrift): string {
  if (!d.measurable) return 'nem mérhető (a flotta-token fájl hiányzik, üres vagy nem olvasható)'
  if (d.stale.length) return `${d.stale.length} ügynök a régi tokennel: ${d.stale.join(', ')}`
  // Not "mind az aktuálison" when some agents simply have no launch stamp yet
  // (sessions started before the stamping deploy): that would be a false all-clear.
  if (d.unknown.length) return `nincs bizonyítottan régi tokenes ügynök, ${d.unknown.length} nem megállapítható (nincs indítási jegyzék): ${d.unknown.join(', ')}`
  return 'mind az aktuálison'
}
