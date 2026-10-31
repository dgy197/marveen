// Production binding of the fleet-token drift detector (card acdb8045 K5).
// The logic and its tests live in fleet-token-drift.ts; this only plugs in the
// real agent registry, tmux liveness and the fleet token files. Read-only: no
// restart primitive is imported here.
import { statSync } from 'node:fs'
import { listAllAgentNames } from './agent-config.js'
import { getAgentRunningSince, isAgentRunning } from './agent-process.js'
import { usesFleetToken } from './claude-plan-fleet-wiring.js'
import {
  fingerprintFleetToken,
  fleetTokenFilePath,
  readLaunchRegistry,
} from './fleet-token-fingerprint.js'
import { fleetTokenDrift, fleetTokenFieldFor, type FleetTokenDriftDeps } from './fleet-token-drift.js'

export function liveFleetTokenDriftDeps(): FleetTokenDriftDeps {
  return {
    listAgents: listAllAgentNames,
    usesFleetToken,
    isRunning: isAgentRunning,
    currentFingerprint: () => fingerprintFleetToken(),
    registry: () => readLaunchRegistry(),
    sessionCreatedMs: (name) => {
      const sec = getAgentRunningSince(name)
      return sec === null ? null : sec * 1000
    },
    tokenMtimeMs: () => {
      try { return statSync(fleetTokenFilePath()).mtimeMs } catch { return null }
    },
  }
}

export function liveFleetTokenDrift() {
  return fleetTokenDrift(liveFleetTokenDriftDeps())
}

/**
 * Field for one agent whose liveness the caller already knows (the status route
 * just called getAgentProcessInfo): avoids a second tmux probe.
 */
export function liveFleetTokenField(name: string, running: boolean) {
  const deps = liveFleetTokenDriftDeps()
  return fleetTokenFieldFor(name, { ...deps, isRunning: () => running })
}
