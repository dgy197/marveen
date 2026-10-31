// Production binding of the fleet-token restart-stale sweep (card acdb8045 K6).
// The sequence and its tests live in fleet-token-restart.ts; this plugs in the
// real detector, run state, desired state and restart primitive.
import { FLEET_RESTART_GAP_MS } from '../claude-plan-fleet-rotation.js'
import { getDesiredAgents } from './agent-desired-state.js'
import { agentRunState, restartAgentProcess } from './agent-process.js'
import { liveFleetTokenDriftDeps } from './fleet-token-drift-live.js'
import type { RestartStaleDeps } from './fleet-token-restart.js'
import { isMainChannelsAgent } from './main-agent.js'

export function liveRestartStaleDeps(): RestartStaleDeps {
  return {
    drift: liveFleetTokenDriftDeps(),
    isMain: isMainChannelsAgent,
    // Same guard as the per-agent restart route (RESTARTSTOPPED1005): a stopped
    // agent that is not in the desired run-state stays stopped.
    blockReason: (name) => {
      const state = agentRunState(name)
      if (state === 'unreachable') return 'host-unreachable'
      if (state !== 'running' && !getDesiredAgents().has(name)) return 'stopped-not-desired'
      return null
    },
    restart: (name) => restartAgentProcess(name, { wake: { reason: 'fleet-token-swap' } }),
    sleep: (ms) => new Promise<void>((resolve) => setTimeout(resolve, ms)),
    gapMs: FLEET_RESTART_GAP_MS,
  }
}
