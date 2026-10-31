// Card acdb8045 K5: the stale-token detector and its two surfaces. Tokens are
// assembled at runtime (never a literal token-shaped string in the source).
import { describe, it, expect, afterAll, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import { liveFleetTokenDriftDeps } from '../web/fleet-token-drift-live.js'
import { agentUsesFleetToken } from '../claude-plan-fleet-rotation.js'
import {
  fingerprintFleetToken,
  readLaunchRegistry,
  recordLaunch,
  type LaunchRegistry,
} from '../web/fleet-token-fingerprint.js'
import {
  fleetTokenDrift,
  fleetTokenFieldFor,
  fleetTokenStatusLine,
  type FleetTokenDriftDeps,
} from '../web/fleet-token-drift.js'

// Spies on every restart/start/stop primitive the detector could reach. The
// detector must call none of them (K5: it only reports).
const spies = vi.hoisted(() => ({
  restartAgentProcess: vi.fn(),
  startAgentProcess: vi.fn(),
  stopAgentProcess: vi.fn(),
}))
vi.mock('../web/agent-process.js', async (orig) => ({
  ...(await orig<typeof import('../web/agent-process.js')>()),
  ...spies,
  isAgentRunning: () => true,
  getAgentRunningSince: () => null,
}))
vi.mock('../web/agent-config.js', async (orig) => ({
  ...(await orig<typeof import('../web/agent-config.js')>()),
  listAllAgentNames: () => ['levente', 'own'],
}))
vi.mock('../web/claude-plan-fleet-wiring.js', () => ({
  usesFleetToken: (n: string) => n === 'levente',
}))

const __dirname = dirname(fileURLToPath(import.meta.url))
const tmpRoot = mkdtempSync(join(tmpdir(), 'marveen-fleet-drift-test-'))
afterAll(() => rmSync(tmpRoot, { recursive: true, force: true }))

const canary = (tag: string) => ['canary', 'drift', 'tok', tag, 'k5z7p1'].join('-')

interface AgentSpec {
  main?: boolean
  remote?: boolean
  ownTokenFile?: boolean
  model?: string
  running?: boolean
  createdMs?: number | null
}

/** Real files in a temp dir + the real agentUsesFleetToken rule; only the agent facts are faked. */
function fixture(agents: Record<string, AgentSpec>) {
  const dir = mkdtempSync(join(tmpRoot, 'f-'))
  const tokenPath = join(dir, '.claude-oauth-token')
  const registryPath = join(dir, 'fleet-token-launch.json')
  const tokenA = canary('a')
  const tokenB = canary('b')
  writeFileSync(tokenPath, tokenA)
  let mtime = 1_000
  const deps: FleetTokenDriftDeps = {
    listAgents: () => Object.keys(agents),
    usesFleetToken: (name) => {
      const a = agents[name]
      return agentUsesFleetToken({
        name,
        mainAgentId: 'brainy',
        model: a.model ?? 'claude-sonnet-5-5',
        authMode: 'shared',
        configuredConfigDir: null,
        remote: a.remote === true,
        ownTokenFile: a.ownTokenFile === true,
      })
    },
    isRunning: (name) => agents[name].running !== false,
    currentFingerprint: () => fingerprintFleetToken(tokenPath),
    registry: () => readLaunchRegistry(registryPath),
    sessionCreatedMs: (name) => agents[name].createdMs ?? null,
    tokenMtimeMs: () => mtime,
  }
  return {
    dir, tokenPath, registryPath, tokenA, tokenB, deps,
    setMtime: (ms: number) => { mtime = ms },
    stamp: (name: string, token = tokenA) => {
      const fp = fingerprintFleetToken(tokenPath)
      // stamp the fingerprint of `token` regardless of the file now
      const w = join(dir, `.stamp-${name}`)
      writeFileSync(w, token)
      return recordLaunch(`agent:${name}`, fingerprintFleetToken(w) ?? fp ?? '', 5_000, registryPath)
    },
    swap: () => writeFileSync(tokenPath, tokenB),
  }
}

describe('fleetTokenDrift / fleetTokenFieldFor (K5)', () => {
  it('after a swap a running fleet-token agent is stale; before it is current', () => {
    const f = fixture({ levente: {} })
    f.stamp('levente')
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('current')
    f.swap()
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('stale')
    const d = fleetTokenDrift(f.deps)
    expect(d.stale).toEqual(['levente'])
    expect(fleetTokenStatusLine(d)).toBe('1 ügynök a régi tokennel: levente')
  })

  it('after the restart (new stamp with the new token) the agent is current again', () => {
    const f = fixture({ levente: {} })
    f.stamp('levente')
    f.swap()
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('stale')
    f.stamp('levente', f.tokenB)
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('current')
    expect(fleetTokenStatusLine(fleetTokenDrift(f.deps))).toBe('mind az aktuálison')
  })

  it('main, own-token, remote and GPT/LiteLLM agents are n/a, never stale, whatever the registry says', () => {
    const f = fixture({
      brainy: { main: true },
      own: { ownTokenFile: true },
      far: { remote: true },
      gpt: { model: 'chatgpt/gpt-6-astra' },
    })
    for (const n of ['brainy', 'own', 'far', 'gpt']) f.stamp(n)
    f.swap()
    for (const n of ['brainy', 'own', 'far', 'gpt']) expect(fleetTokenFieldFor(n, f.deps), n).toBe('n/a')
    const d = fleetTokenDrift(f.deps)
    expect(d.stale).toEqual([])
    expect(d.unknown).toEqual([])
    expect(fleetTokenStatusLine(d)).toBe('mind az aktuálison')
  })

  it('a stopped agent is n/a even with a stale stamp', () => {
    const f = fixture({ levente: { running: false } })
    f.stamp('levente')
    f.swap()
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('n/a')
    expect(fleetTokenDrift(f.deps).stale).toEqual([])
  })

  it('no stamp: unknown, never stale; created after the token file changed: current-estimated', () => {
    const f = fixture({ old: { createdMs: 500 }, fresh: { createdMs: 2_000 }, nocreated: { createdMs: null } })
    f.setMtime(1_000)
    expect(fleetTokenFieldFor('old', f.deps)).toBe('unknown')
    expect(fleetTokenFieldFor('fresh', f.deps)).toBe('current-estimated')
    expect(fleetTokenFieldFor('nocreated', f.deps)).toBe('unknown')
    const d = fleetTokenDrift(f.deps)
    expect(d.stale).toEqual([])
    expect(d.unknown).toEqual(['nocreated', 'old'])
    expect(d.current).toBe(1)
  })

  it('a stamped agent is never relabelled by the mtime estimate', () => {
    const f = fixture({ levente: { createdMs: 9_999 } })
    f.stamp('levente')
    f.swap()
    f.setMtime(1_000)
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('stale')
  })

  it('unreadable or empty token file: nothing is stale, the status says it cannot be measured', () => {
    const f = fixture({ levente: {} })
    f.stamp('levente')
    writeFileSync(f.tokenPath, '  \n')
    expect(fleetTokenFieldFor('levente', f.deps)).toBe('unknown')
    const d = fleetTokenDrift(f.deps)
    expect(d.measurable).toBe(false)
    expect(d.stale).toEqual([])
    expect(fleetTokenStatusLine(d)).toMatch(/^nem mérhető \(/)
  })

  it('unstamped agents are not reported as "mind az aktuálison"', () => {
    const f = fixture({ a: {}, b: {} })
    const line = fleetTokenStatusLine(fleetTokenDrift(f.deps))
    expect(line).not.toBe('mind az aktuálison')
    expect(line).toContain('2 nem megállapítható')
  })

  it('lists several stale agents sorted, with the count', () => {
    const f = fixture({ zed: {}, alma: {}, ok: {} })
    f.stamp('zed'); f.stamp('alma')
    f.swap()
    f.stamp('ok', f.tokenB)
    expect(fleetTokenStatusLine(fleetTokenDrift(f.deps))).toBe('2 ügynök a régi tokennel: alma, zed')
  })

  it('a throwing probe gives unknown, not a false stale', () => {
    const f = fixture({ levente: {} })
    f.stamp('levente')
    f.swap()
    const deps: FleetTokenDriftDeps = { ...f.deps, isRunning: () => { throw new Error('tmux gone') } }
    expect(fleetTokenFieldFor('levente', deps)).toBe('unknown')
  })

  it('the detector never restarts: spies on restart/start/stop see 0 calls through the live wiring', () => {
    const f = fixture({ levente: {} })
    f.stamp('levente')
    f.swap()
    const live: FleetTokenDriftDeps = {
      ...liveFleetTokenDriftDeps(),
      // fixture files instead of the live store; the rest is the production wiring
      currentFingerprint: f.deps.currentFingerprint,
      registry: f.deps.registry,
      tokenMtimeMs: f.deps.tokenMtimeMs,
    }
    const d = fleetTokenDrift(live)
    expect(d.stale).toEqual(['levente'])
    expect(fleetTokenFieldFor('levente', live)).toBe('stale')
    expect(fleetTokenFieldFor('own', live)).toBe('n/a')
    fleetTokenStatusLine(d)
    expect(spies.restartAgentProcess).toHaveBeenCalledTimes(0)
    expect(spies.startAgentProcess).toHaveBeenCalledTimes(0)
    expect(spies.stopAgentProcess).toHaveBeenCalledTimes(0)
    expect(Object.keys(live).some((k) => /restart|start|stop/i.test(k))).toBe(false)
    for (const file of ['fleet-token-drift.ts', 'fleet-token-drift-live.ts']) {
      const src = readFileSync(join(__dirname, '..', 'web', file), 'utf-8').replace(/\/\/.*$/gm, '')
      expect(src, file).not.toMatch(/restartAgentProcess|startAgentProcess|stopAgentProcess|restartWorkerSession/)
    }
  })

  it('no token and no fingerprint in any output (marker test)', () => {
    const f = fixture({ levente: {}, other: {}, fresh: { createdMs: 9_000 } })
    f.stamp('levente')
    f.swap()
    const fpA = fingerprintFleetToken((() => { const p = join(f.dir, 'a'); writeFileSync(p, f.tokenA); return p })())!
    const fpB = fingerprintFleetToken(f.tokenPath)!
    const out = JSON.stringify([
      fleetTokenDrift(f.deps),
      fleetTokenFieldFor('levente', f.deps),
      fleetTokenFieldFor('other', f.deps),
      fleetTokenStatusLine(fleetTokenDrift(f.deps)),
    ])
    for (const secret of [f.tokenA, f.tokenB, fpA, fpB]) expect(out).not.toContain(secret)
    // the field is one of the fixed words
    for (const n of ['levente', 'other', 'fresh']) {
      expect(['current', 'stale', 'unknown', 'current-estimated', 'n/a']).toContain(fleetTokenFieldFor(n, f.deps))
    }
  })

  it('registry stays the only holder of fingerprints: tolerant of an empty registry object', () => {
    const f = fixture({ levente: {} })
    const empty: LaunchRegistry = Object.create(null)
    expect(fleetTokenFieldFor('levente', { ...f.deps, registry: () => empty })).toBe('unknown')
  })
})

describe('wiring (K5)', () => {
  const read = (rel: string) => readFileSync(join(__dirname, '..', rel), 'utf-8')

  it('system-status has the Flotta-token row in RENDSZER, built from the drift line', () => {
    const src = read('web/system-status.ts')
    expect(src).toContain("label: 'Flotta-token'")
    expect(src).toContain('fleetTokenStatusLine(liveFleetTokenDrift())')
  })

  it('GET /api/agents/:name/status adds a fleetToken field next to the process info', () => {
    const src = read('web/routes/agents.ts')
    expect(src).toContain('fleetToken: liveFleetTokenField(name, info.running)')
    expect(src).toContain("from '../fleet-token-drift-live.js'")
  })
})
