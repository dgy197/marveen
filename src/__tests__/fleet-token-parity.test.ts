// Card acdb8045 K1: the stale-token detector (agentUsesFleetToken) and the
// launcher's decision to export CLAUDE_CODE_OAUTH_TOKEN (launchExportsFleetToken,
// the one rule behind both export sites in agent-process.ts) must never disagree.
// Pure tests plus a source guard that no export site bypasses the shared rule.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { agentUsesFleetToken, launchExportsFleetToken } from '../claude-plan-fleet-rotation.js'

const __dirname = dirname(fileURLToPath(import.meta.url))

interface Row {
  label: string
  /** Agent facts. */
  name?: string
  model?: string
  authMode?: string
  configuredConfigDir?: string | null
  ownTokenFile?: boolean
  customProvider?: boolean
  remote?: boolean
  /** The launcher's expectation when the fleet token file exists. */
  launcherWithToken: boolean
}

const MAIN = 'main'
const rows: Row[] = [
  { label: 'plain Claude sub-agent', launcherWithToken: true },
  { label: 'authMode api (own API key)', authMode: 'api', launcherWithToken: false },
  { label: 'authMode own_team (own /login)', authMode: 'own_team', launcherWithToken: false },
  { label: 'operator-configured plan / config dir', configuredConfigDir: '/opt/claude-x', launcherWithToken: false },
  { label: 'own setup-token file (set or invalid)', ownTokenFile: true, launcherWithToken: false },
  { label: 'non-Claude model', model: 'deepseek-v4-pro', launcherWithToken: false },
  { label: 'custom provider with a claude- model id', customProvider: true, launcherWithToken: false },
  { label: 'custom provider with a foreign model id', customProvider: true, model: 'mistral:7b', launcherWithToken: false },
  { label: 'own token file AND configured dir', ownTokenFile: true, configuredConfigDir: '/opt/x', launcherWithToken: false },
  { label: 'api mode with a configured dir', authMode: 'api', configuredConfigDir: '/opt/x', launcherWithToken: false },
]

function agentInput(r: Row) {
  return {
    name: r.name ?? 'dev',
    mainAgentId: MAIN,
    model: r.model ?? 'claude-opus-5',
    authMode: r.authMode ?? 'shared',
    configuredConfigDir: r.configuredConfigDir ?? null,
    remote: r.remote ?? false,
    ownTokenFile: r.ownTokenFile ?? false,
    customProvider: r.customProvider ?? false,
  }
}

function launcherInput(r: Row, fleetTokenPresent: boolean) {
  const a = agentInput(r)
  return {
    isClaudeModel: a.model.startsWith('claude-'),
    customProvider: a.customProvider,
    authMode: a.authMode,
    configuredConfigDir: a.configuredConfigDir !== null,
    ownTokenFile: a.ownTokenFile,
    fleetTokenPresent,
  }
}

describe('fleet token parity: detector vs launcher decision', () => {
  it.each(rows.map((r) => [r.label, r] as const))('%s: both agree and match the expected launcher outcome', (_l, r) => {
    const detector = agentUsesFleetToken(agentInput(r))
    const launcher = launchExportsFleetToken(launcherInput(r, true))
    expect(launcher).toBe(r.launcherWithToken)
    expect(detector).toBe(launcher)
  })

  it.each(rows.map((r) => [r.label, r] as const))('%s: no fleet token file means no export (detector reads the agent, not the store)', (_l, r) => {
    expect(launchExportsFleetToken(launcherInput(r, false))).toBe(false)
  })

  it('the detector is exactly "launcher exports, given the token file exists" for every flag combination', () => {
    const bools = [false, true]
    const models = ['claude-opus-5', 'gpt-x']
    const modes = ['shared', 'api', 'own_team']
    let n = 0
    for (const custom of bools) for (const own of bools) for (const dir of bools) for (const model of models) for (const authMode of modes) {
      const r: Row = { label: 'combo', model, authMode, customProvider: custom, ownTokenFile: own, configuredConfigDir: dir ? '/d' : null, launcherWithToken: false }
      expect(agentUsesFleetToken(agentInput(r))).toBe(launchExportsFleetToken(launcherInput(r, true)))
      n++
    }
    expect(n).toBe(48)
  })

  it('an empty-string configured dir is "not configured" (matches the launcher truthiness)', () => {
    const r: Row = { label: 'empty dir', configuredConfigDir: '', launcherWithToken: true }
    expect(agentUsesFleetToken(agentInput(r))).toBe(true)
  })

  it('the main agent and remote agents are never fleet-token agents (the launcher never reaches this rule for them)', () => {
    expect(agentUsesFleetToken(agentInput({ label: 'main', name: MAIN, launcherWithToken: false }))).toBe(false)
    expect(agentUsesFleetToken(agentInput({ label: 'remote', remote: true, launcherWithToken: false }))).toBe(false)
  })
})

describe('fleet token parity: no export site bypasses the shared rule', () => {
  const src = readFileSync(join(__dirname, '..', 'web', 'agent-process.ts'), 'utf-8')
  const exportLiteral = 'export CLAUDE_CODE_OAUTH_TOKEN="$(cat \'${FLEET_OAUTH_TOKEN_PATH}\')"'

  it('agent-process.ts: every fleet-token export is guarded by launchExportsFleetToken', () => {
    const idxs: number[] = []
    let from = 0
    for (;;) {
      const i = src.indexOf(exportLiteral, from)
      if (i < 0) break
      idxs.push(i)
      from = i + 1
    }
    expect(idxs.length).toBe(2)
    for (const i of idxs) {
      const before = src.slice(Math.max(0, i - 700), i)
      expect(before).toContain('launchExportsFleetToken(')
    }
  })

  it('the launch string keeps $(cat file), never a token value (the value is never JS-side)', () => {
    expect(src).not.toMatch(/CLAUDE_CODE_OAUTH_TOKEN=["']?\$\{/)
  })
})
