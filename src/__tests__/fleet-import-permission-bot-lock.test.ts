// Card 8e9f4670 (B5): the fleet import writes vault.json as a whole file and
// never calls setSecret, so the storage-layer lock on the permission bot's
// token (vault.ts) does not cover it. importFleet carries its own check
// (validateVaultLock): a locked row in the bundle's vault section, or in the
// live vault the section would replace, refuses the WHOLE import before the
// first write of any kind.
//
// Real file system and a real SQLite (:memory:) under a temp root: STORE_DIR,
// PROJECT_ROOT (main agent files), the agents dir, the scheduled-tasks dir and
// $HOME (global skills) all point into it, so a snapshot of the whole tree
// (sha256 of every file, every directory) before and after proves "nothing
// was written anywhere".
import { describe, it, expect, vi, beforeAll, beforeEach, afterAll } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-import-lock-'))
  return {
    root,
    store: path.join(root, 'store'),
    home: path.join(root, 'home'),
    agents: path.join(root, 'agents'),
    tasks: path.join(root, 'tasks'),
  }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.root,
  STORE_DIR: T.store,
}))

vi.mock('node:os', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:os')>()
  return { ...real, homedir: () => T.home }
})

vi.mock('../web/agent-config.js', () => ({
  AGENTS_BASE_DIR: T.agents,
  listAgentNames: () => [],
  readJsonObjectForWrite: () => ({}),
}))

vi.mock('../web/scheduled-tasks-io.js', () => ({ SCHEDULED_TASKS_DIR: T.tasks }))
vi.mock('../web/vault-bindings.js', () => ({ getBindings: () => [] }))

vi.mock('../env.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../env.js')>()),
  updateEnvFile: () => { throw new Error('fleet-import-permission-bot-lock: unexpected .env write') },
}))

vi.mock('../logger.js', () => ({
  logger: { info: () => {}, warn: () => {}, error: () => {}, debug: () => {} },
}))

vi.mock('../db.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../db.js')>()
  return { ...real, backfillEmbeddings: async () => 0 }
})

import { initDatabase } from '../db.js'
import { importFleet } from '../web/fleet-transfer.js'
import { PERMISSION_BOT_VAULT_ID, PERMISSION_BOT_VAULT_LOCKED_ERROR } from '../web/permission-bot-vault.js'

const LIVE_VAULT = join(T.store, 'vault.json')

// path -> sha256 for files, path -> 'dir' for directories, the whole temp tree.
function snapshot(): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir).sort()) {
      const p = join(dir, name)
      const rel = relative(T.root, p)
      if (statSync(p).isDirectory()) { out[rel] = 'dir'; walk(p) }
      else out[rel] = createHash('sha256').update(readFileSync(p)).digest('hex')
    }
  }
  walk(T.root)
  return out
}

// Never throws, whatever `id` is (String() throws on a hostile toString).
const labelOf = (id: unknown): string =>
  typeof id === 'string' || typeof id === 'number' ? String(id) : `<${typeof id}>`

const row = (id: unknown) => ({ id, label: `label-${labelOf(id)}`, encrypted: 'x', createdAt: 't', updatedAt: 't' })

// A bundle that would write in EVERY phase if it were accepted: an agent dir, a
// global skill, a scheduled task, a memory row, a kanban card, the vault files.
function bundle(vault?: unknown, extra: Record<string, unknown> = {}): string {
  return JSON.stringify({
    schemaVersion: 1,
    exportedAt: '2026-01-01T00:00:00.000Z',
    sourceHost: 'test-host',
    agents: [{
      name: 'lockprobe', config: { id: 'lockprobe' }, claudeMd: '# c', soulMd: '# s', mcp: {}, settings: {},
      channelsAccess: {}, avatar: null, avatarExt: 'png', agentSkills: [],
    }],
    skills: [{ name: 'lockprobe-skill', skillMd: '# skill' }],
    scheduledTasks: [],
    memories: [],
    dailyLogs: [],
    kanban: { cards: [], comments: [], cardEvents: [], labels: [], cardLabels: [] },
    ideaBox: { ideas: [], comments: [], statusLog: [] },
    dashboardSettings: { autonomy: { a: 1 }, autoRestart: {}, agentsDesired: {}, norbertPersonal: {} },
    ...(vault === undefined ? {} : { vault }),
    ...extra,
  })
}

const vaultOf = (entries: unknown[]) => ({ vaultKey: 'a2V5', entries, bindings: [] })

const asDiff = (r: unknown) => r as { dryRun?: true; errors: string[] }

// The refusal has the same shape for the preview and the apply, so the dry-run
// never promises an import that apply would refuse.
function expectRefused(result: unknown): void {
  const r = asDiff(result)
  expect(r.dryRun).toBe(true)
  expect(r.errors.length).toBeGreaterThan(0)
  expect(r.errors[0]).toContain(PERMISSION_BOT_VAULT_LOCKED_ERROR)
}

beforeAll(() => { initDatabase(':memory:') })
afterAll(() => { rmSync(T.root, { recursive: true, force: true }) })

beforeEach(() => {
  rmSync(T.root, { recursive: true, force: true })
  for (const d of [T.store, T.home, T.agents, T.tasks]) mkdirSync(d, { recursive: true })
})

describe('B5: a locked Vault row in the bundle refuses the whole import', () => {
  for (const [label, id] of [
    ['exact id', PERMISSION_BOT_VAULT_ID],
    ['upper case', PERMISSION_BOT_VAULT_ID.toUpperCase()],
    ['padded with spaces', `  ${PERMISSION_BOT_VAULT_ID}  `],
  ] as const) {
    it(`apply: ${label} -> refused, nothing written anywhere, live vault byte-identical`, () => {
      writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row('other')] }))
      const before = snapshot()
      expect(Object.keys(before)).toContain('store/vault.json') // positive control: the snapshot sees files

      const result = importFleet(bundle(vaultOf([row('other'), row(id)])), { apply: true })

      expectRefused(result)
      expect(snapshot()).toEqual(before)
    })
  }

  it('dry-run: the same bundle reports the refusal in errors and writes nothing', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row('other')] }))
    const before = snapshot()

    const result = importFleet(bundle(vaultOf([row(PERMISSION_BOT_VAULT_ID)])), { apply: false })

    expectRefused(result)
    expect(snapshot()).toEqual(before)
  })

  it('a locked row refuses even when it is the only vault entry and the live vault is empty', () => {
    const before = snapshot()
    const result = importFleet(bundle(vaultOf([row(PERMISSION_BOT_VAULT_ID)])), { apply: true })
    expectRefused(result)
    expect(snapshot()).toEqual(before)
  })

  for (const [label, bad] of [
    ['number id', row(42)],
    ['object id', row({ toString: 'telegram-engedely-bot-token' })],
    ['array id', row([PERMISSION_BOT_VAULT_ID])],
    ['missing id', { label: 'no id' }],
    ['null entry', null],
    ['string entry', PERMISSION_BOT_VAULT_ID],
  ] as const) {
    it(`a malformed vault entry (${label}) does not crash, is refused, and nothing is written`, () => {
      writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row('other')] }))
      const before = snapshot()

      let result: unknown
      expect(() => { result = importFleet(bundle(vaultOf([row('fine'), bad])), { apply: true }) }).not.toThrow()

      const r = asDiff(result)
      expect(r.dryRun).toBe(true)
      expect(r.errors.length).toBeGreaterThan(0)
      expect(snapshot()).toEqual(before)
    })
  }

  it('a vault section without an entries array is refused', () => {
    const before = snapshot()
    const result = importFleet(bundle({ vaultKey: 'a2V5', bindings: [] }), { apply: true })
    expect(asDiff(result).dryRun).toBe(true)
    expect(asDiff(result).errors.length).toBeGreaterThan(0)
    expect(snapshot()).toEqual(before)
  })
})

describe('B5: a locked row in the LIVE vault refuses a vault-carrying bundle (A2)', () => {
  it('apply: live locked row + bundle vault section without it -> refused, live vault byte-identical', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row(PERMISSION_BOT_VAULT_ID), row('other')] }))
    const before = snapshot()

    const result = importFleet(bundle(vaultOf([row('imported')])), { apply: true })

    expectRefused(result)
    expect(snapshot()).toEqual(before)
  })

  it('dry-run: the same case reports the refusal in errors', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row(PERMISSION_BOT_VAULT_ID)] }))
    const before = snapshot()
    expectRefused(importFleet(bundle(vaultOf([row('imported')])), { apply: false }))
    expect(snapshot()).toEqual(before)
  })

  it('live locked row with a differently-cased id is still found', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row(` ${PERMISSION_BOT_VAULT_ID.toUpperCase()}`)] }))
    const before = snapshot()
    expectRefused(importFleet(bundle(vaultOf([])), { apply: true }))
    expect(snapshot()).toEqual(before)
  })

  it('an unreadable live vault.json refuses a vault-carrying bundle (fail-closed)', () => {
    writeFileSync(LIVE_VAULT, '{not json')
    const before = snapshot()
    const result = asDiff(importFleet(bundle(vaultOf([row('imported')])), { apply: true }))
    expect(result.dryRun).toBe(true)
    expect(result.errors.length).toBeGreaterThan(0)
    expect(snapshot()).toEqual(before)
  })

  it('live locked row + a bundle WITHOUT a vault section: the import runs, vault files byte-identical', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row(PERMISSION_BOT_VAULT_ID)] }))
    const vaultBefore = readFileSync(LIVE_VAULT)

    const result = importFleet(bundle(undefined), { apply: true }) as { ok?: true; dryRun?: true }

    expect(result.dryRun).toBeUndefined()
    expect(result.ok).toBe(true)
    expect(readFileSync(LIVE_VAULT).equals(vaultBefore)).toBe(true)
    // positive control: the rest of the bundle really was written
    expect(readFileSync(join(T.agents, 'lockprobe', 'agent-config.json'), 'utf-8')).toContain('lockprobe')
  })
})

describe('B5: no locked row anywhere -> the import behaves as before (A4)', () => {
  it('apply: unlocked rows are written to vault.json, the agent and the skill land', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row('old')] }))

    const result = importFleet(bundle(vaultOf([row('alpha'), row('beta')])), { apply: true }) as { ok?: true; dryRun?: true }

    expect(result.dryRun).toBeUndefined()
    expect(result.ok).toBe(true)
    const written = JSON.parse(readFileSync(LIVE_VAULT, 'utf-8')) as { entries: { id: string }[] }
    expect(written.entries.map(e => e.id)).toEqual(['alpha', 'beta'])
    expect(readFileSync(join(T.store, '.vault-key'), 'utf-8')).toBe('a2V5')
    expect(readFileSync(join(T.agents, 'lockprobe', 'agent-config.json'), 'utf-8')).toContain('lockprobe')
    expect(readFileSync(join(T.home, '.claude', 'skills', 'lockprobe-skill', 'SKILL.md'), 'utf-8')).toBe('# skill')
  })

  it('dry-run: unlocked rows report no errors and write nothing', () => {
    writeFileSync(LIVE_VAULT, JSON.stringify({ entries: [row('old')] }))
    const before = snapshot()

    const result = asDiff(importFleet(bundle(vaultOf([row('alpha')])), { apply: false }))

    expect(result.dryRun).toBe(true)
    expect(result.errors).toEqual([])
    expect(snapshot()).toEqual(before)
  })

  it('a bundle without a vault section and no live vault imports normally', () => {
    const result = importFleet(bundle(undefined), { apply: true }) as { ok?: true }
    expect(result.ok).toBe(true)
  })
})
