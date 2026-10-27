/**
 * Memory write gate b1 (card 3e9f6c28, node G5): the docs and the code must agree on the
 * MEMORY_GATE_* key list, the `.env`-only marking, the documented defaults, the kill-switch
 * path and the reason length. A new key, a changed default or a renamed switch fails here
 * until the three docs follow.
 */
import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'

vi.mock('../env.js', async () => {
  const actual = await vi.importActual<typeof import('../env.js')>('../env.js')
  return {
    ...actual,
    readEnvFile: (keys?: string[]) =>
      keys && keys.every(k => k.startsWith('MEMORY_GATE_')) ? {} : actual.readEnvFile(keys),
  }
})

import { MEMORY_GATE_KEYS, resolveGateConfig, disablePath } from '../memory-gate/state.js'
import { MAX_REASON_CHARS } from '../memory-gate/parse.js'
import { FORBIDDEN_OWNERS } from '../memory-gate/gate-env.js'

const DOCS = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'docs')
const read = (rel: string): string => readFileSync(join(DOCS, rel), 'utf-8')

const HU = read('config-reference.md')
const EN = read('en/config-reference.md')
const MEMORY_SYSTEM = read('memory-system.md')
const GATE_DOC = read('memory-write-gate.md')

const rowOf = (doc: string, key: string): string[] =>
  doc.split('\n').filter(l => l.startsWith(`| \`${key}\` |`))

describe('config-reference rows (hu and en)', () => {
  for (const key of MEMORY_GATE_KEYS) {
    it(`${key} has exactly one row per language, marked .env-only`, () => {
      const hu = rowOf(HU, key)
      const en = rowOf(EN, key)
      expect(hu).toHaveLength(1)
      expect(en).toHaveLength(1)
      expect(hu[0]).toContain('Csak a `.env`-ből olvassa')
      expect(en[0]).toContain('`.env` only')
    })
  }

  it('the docs name no MEMORY_GATE_ key that the code does not read', () => {
    const known = new Set<string>(MEMORY_GATE_KEYS)
    for (const doc of [HU, EN, MEMORY_SYSTEM, GATE_DOC]) {
      const named = new Set(doc.match(/MEMORY_GATE_[A-Z_]+/g) ?? [])
      for (const n of named) expect(known.has(n), n).toBe(true)
    }
  })
})

describe('docs/memory-write-gate.md', () => {
  it('has one table row per key', () => {
    for (const key of MEMORY_GATE_KEYS) expect(rowOf(GATE_DOC, key), key).toHaveLength(1)
  })

  it('documents the defaults the code resolves to', () => {
    const d = resolveGateConfig({}, 'brainy')
    const expected: Record<string, string> = {
      MEMORY_GATE_MODEL: d.model,
      MEMORY_GATE_MAX_CALLS_PER_DAY: String(d.maxCallsPerDay),
      MEMORY_GATE_DAILY_USD: (d.dailyUsdMicro / 1_000_000).toFixed(2),
      MEMORY_GATE_MAX_PROMPT_BYTES: String(d.maxPromptBytes),
      MEMORY_GATE_MAX_TOKENS: String(d.maxTokens),
      MEMORY_GATE_CANDIDATES: String(d.candidates),
      MEMORY_GATE_SUPERSEDE_MIN_CONF: d.supersedeMinConf.toFixed(2),
      MEMORY_GATE_OTHER_MIN_CONF: d.otherMinConf.toFixed(2),
      MEMORY_GATE_MAX_SUPERSEDE_PER_DAY: String(d.maxSupersedePerDay),
      MEMORY_GATE_MAX_CONTRADICT_PER_DAY: String(d.maxContradictPerDay),
    }
    for (const [key, value] of Object.entries(expected)) {
      const cells = rowOf(GATE_DOC, key)[0].split('|').map(c => c.trim())
      expect(cells[2], key).toBe(`\`${value}\``)
    }
  })

  it('names the kill-switch file the code checks, and the forbidden owner', () => {
    expect(GATE_DOC).toContain(disablePath('store'))
    for (const o of FORBIDDEN_OWNERS) expect(GATE_DOC).toContain(`\`${o}\``)
  })

  it('states the reason length cap and that the API never returns the reason', () => {
    expect(GATE_DOC).toContain(`${MAX_REASON_CHARS} characters`)
    expect(GATE_DOC).toContain('NEVER returned by the API')
    expect(GATE_DOC).toContain('No route returns the `reason` column')
  })

  it('states the main-agent condition (tg-<digits>) in the docs', () => {
    expect(GATE_DOC).toContain('MEMORY_GATE_MAIN_AGENT_OK=tg-<digits>')
    expect(rowOf(HU, 'MEMORY_GATE_MAIN_AGENT_OK')[0]).toContain('tg-<szám>')
  })

  it('is linked from memory-system.md and from both config references', () => {
    expect(MEMORY_SYSTEM).toContain('memory-write-gate.md')
    expect(HU).toContain('memory-write-gate.md')
    expect(EN).toContain('memory-write-gate.md')
  })
})
