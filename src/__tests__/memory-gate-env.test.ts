/**
 * Memory write gate b1 (card 3e9f6c28, node B1-S): the .env-only keys that decide
 * whether the gate does anything at all. Pure resolvers, no file system.
 */
import { describe, it, expect, vi } from 'vitest'

const envState = vi.hoisted(() => ({ values: {} as Record<string, string> }))

vi.mock('../env.js', async () => {
  const actual = await vi.importActual<typeof import('../env.js')>('../env.js')
  return {
    ...actual,
    readEnvFile: (keys?: string[]) =>
      keys && keys.every(k => k.startsWith('MEMORY_GATE_'))
        ? Object.fromEntries(Object.entries(envState.values).filter(([k]) => keys.includes(k)))
        : actual.readEnvFile(keys),
  }
})

import { resolveGateOwners, parseGateMode, readGateEnv, gateActive, FORBIDDEN_OWNERS } from '../memory-gate/gate-env.js'

describe('MEMORY_GATE_OWNERS resolution', () => {
  it('empty or missing means no owners and no config error (the gate does nothing)', () => {
    expect(resolveGateOwners(undefined, undefined, 'brainy')).toEqual({ owners: [], configError: null, mainAgentExcluded: false })
    expect(resolveGateOwners('', undefined, 'brainy').owners).toEqual([])
    expect(resolveGateOwners(' , ,', undefined, 'brainy').owners).toEqual([])
  })

  it('hajcsar is a normal owner (Brainy 4217 Q1)', () => {
    expect(resolveGateOwners('hajcsar,iroda', undefined, 'brainy').owners).toEqual(['hajcsar', 'iroda'])
  })

  it('feszek is a config error, never silently dropped, and it switches the whole list off', () => {
    expect(FORBIDDEN_OWNERS).toContain('feszek')
    const r = resolveGateOwners('iroda,feszek', 'tg-5938', 'brainy')
    expect(r.configError).toBe('forbidden_owner')
    expect(r.owners).toEqual([])
  })

  it('a malformed element is a config error', () => {
    for (const bad of ['Iroda', 'a b', 'x;y', 'a'.repeat(33), 'iroda,../etc']) {
      expect(resolveGateOwners(bad, undefined, 'brainy').configError).toBe('bad_owner')
    }
  })

  it('the main agent is excluded unless MEMORY_GATE_MAIN_AGENT_OK is exactly tg-<digits> (Brainy 4217 Q1)', () => {
    const missing = resolveGateOwners('brainy,hajcsar', undefined, 'brainy')
    expect(missing).toEqual({ owners: ['hajcsar'], configError: null, mainAgentExcluded: true })
    for (const bad of ['', 'tg-', 'tg-abc', 'tg-123456789', 'TG-5938', 'tg-5938 x', '5938', 'tg--1']) {
      const r = resolveGateOwners('brainy,hajcsar', bad, 'brainy')
      expect(r.owners, `OK=${JSON.stringify(bad)}`).toEqual(['hajcsar'])
      expect(r.mainAgentExcluded).toBe(true)
    }
    const ok = resolveGateOwners('brainy,hajcsar', 'tg-5938', 'brainy')
    expect(ok).toEqual({ owners: ['brainy', 'hajcsar'], configError: null, mainAgentExcluded: false })
  })

  it('the main agent rule follows MAIN_AGENT_ID, not the literal name', () => {
    expect(resolveGateOwners('marveen,iroda', undefined, 'marveen').owners).toEqual(['iroda'])
    expect(resolveGateOwners('brainy,iroda', undefined, 'marveen').owners).toEqual(['brainy', 'iroda'])
  })

  it('duplicates collapse', () => {
    expect(resolveGateOwners('iroda,iroda', undefined, 'brainy').owners).toEqual(['iroda'])
  })
})

describe('MEMORY_GATE_MODE', () => {
  it('only off/shadow/active are accepted, anything else is off and flagged', () => {
    expect(parseGateMode(undefined)).toEqual({ mode: 'off', invalid: false })
    expect(parseGateMode('')).toEqual({ mode: 'off', invalid: false })
    expect(parseGateMode('shadow')).toEqual({ mode: 'shadow', invalid: false })
    expect(parseGateMode(' Shadow ')).toEqual({ mode: 'shadow', invalid: false })
    expect(parseGateMode('active')).toEqual({ mode: 'active', invalid: false })
    expect(parseGateMode('on')).toEqual({ mode: 'off', invalid: true })
  })

  it('b1 runs active as shadow (there is no effect to apply yet)', () => {
    envState.values = { MEMORY_GATE_MODE: 'active', MEMORY_GATE_OWNERS: 'iroda' }
    const env = readGateEnv('brainy')
    expect(env.configuredMode).toBe('active')
    expect(env.effectiveMode).toBe('shadow')
    expect(gateActive(env)).toBe(true)
  })
})

describe('gateActive', () => {
  it('needs a non-off mode AND a clean config AND at least one owner', () => {
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'iroda' }
    expect(gateActive(readGateEnv('brainy'))).toBe(true)
    envState.values = { MEMORY_GATE_MODE: 'off', MEMORY_GATE_OWNERS: 'iroda' }
    expect(gateActive(readGateEnv('brainy'))).toBe(false)
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: '' }
    expect(gateActive(readGateEnv('brainy'))).toBe(false)
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'feszek' }
    expect(gateActive(readGateEnv('brainy'))).toBe(false)
    envState.values = { MEMORY_GATE_MODE: 'shadow', MEMORY_GATE_OWNERS: 'brainy' }
    expect(gateActive(readGateEnv('brainy'))).toBe(false) // only the unapproved main agent
    envState.values = { MEMORY_GATE_MODE: 'shadow' }
    expect(gateActive(readGateEnv('brainy'))).toBe(false)
  })

  it('a config-overrides style value never reaches the gate: only readEnvFile is consulted', () => {
    // The gate reads the .env file through readEnvFile(['MEMORY_GATE_*']) and nothing else.
    envState.values = {}
    expect(readGateEnv('brainy').owners.owners).toEqual([])
  })
})
