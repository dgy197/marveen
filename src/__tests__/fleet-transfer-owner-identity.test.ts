// Fleet import and the owner's identity (card fec6335f, BE-3c P5 on 642f697d).
//
// The credit gate trusts the owner's Telegram id: ALLOWED_CHAT_ID in .env, or
// the one DM entry of the main access.json (resolveAlertOwnerChat). The fleet
// import is reachable with the shared Bearer token, so it must not be a way to
// rewrite either. Pinned here: the identity block is an allow-list (the five
// keys the export writes), so no *_CHAT_ID, *_BOT_TOKEN, TELEGRAM_* or
// ALLOWED_* key reaches .env or config-overrides.json; an existing main
// access.json keeps its access-control fields (allowFrom, groups, channels,
// pending, dmPolicy, owner*) and takes only the others; a fresh target (no
// access.json yet) is written as exported, as before.
//
// Everything is mocked: no real file, DB or network.

import { describe, it, expect, vi, beforeEach } from 'vitest'

const fsState = vi.hoisted(() => ({ files: new Map<string, string>() }))

vi.mock('../db.js', () => ({
  getDb: () => ({ prepare: () => ({ all: () => [], get: () => null, run: () => ({ changes: 0 }) }), transaction: (fn: Function) => fn }),
  backfillEmbeddings: () => Promise.resolve(),
  initDatabase: () => {},
}))
vi.mock('../web/agent-config.js', () => ({ AGENTS_BASE_DIR: '/mock/agents', listAgentNames: () => [], readJsonObjectForWrite: () => ({}) }))
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>()
  return {
    ...real,
    existsSync: (p: string) => fsState.files.has(String(p)),
    readFileSync: (p: unknown, ...rest: unknown[]) => {
      const v = fsState.files.get(String(p))
      if (v !== undefined) return v
      if (String(p).startsWith('/mock/')) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return (real.readFileSync as (...a: unknown[]) => unknown)(p, ...rest)
    },
    mkdirSync: () => undefined,
    unlinkSync: () => undefined,
    rmSync: () => undefined,
    readdirSync: () => [],
  }
})
vi.mock('../web/atomic-write.js', () => ({ atomicWriteFileSync: vi.fn() }))
vi.mock('../web/scheduled-tasks-io.js', () => ({ SCHEDULED_TASKS_DIR: '/mock/tasks' }))
// RESERVED_AGENT_IDS: fleet-transfer.ts reads it since v1.45.0 (the voice channel id); the fixed list is enough here.
vi.mock('../config.js', async () => ({
  PROJECT_ROOT: '/mock/project', STORE_DIR: '/mock/store', MAIN_AGENT_ID: 'marveen', BOT_NAME: 'Marveen', BRAND_NAME: 'Marveen', OWNER_NAME: 'X', CHANNEL_PROVIDER: 'telegram',
  RESERVED_AGENT_IDS: (await import('../web/sanitize.js')).FIXED_RESERVED_AGENT_IDS,
}))
vi.mock('../channel-provider.js', () => ({ channelStateDir: (p: string) => `/mock/channels/${p}` }))
vi.mock('../web/vault-bindings.js', () => ({ getBindings: () => [] }))
vi.mock('../env.js', () => ({ updateEnvFile: vi.fn() }))
vi.mock('../logger.js', () => ({ logger: { info: () => {}, warn: () => {}, error: () => {} } }))

import { importFleet, isDeniedIdentityKey, isImportableIdentityKey } from '../web/fleet-transfer.js'
import { updateEnvFile } from '../env.js'
import { atomicWriteFileSync } from '../web/atomic-write.js'

const MAIN_ACCESS = '/mock/channels/telegram/access.json'
const ATTACKER = '6666666666'
const OWNER = '1000000001'

function fleet(identity: Record<string, string>, access: Record<string, unknown>): string {
  return JSON.stringify({
    schemaVersion: 1, exportedAt: '2026-01-01T00:00:00.000Z', sourceHost: 'x',
    mainAgent: {
      agentId: 'marveen', identity, claudeMd: '', soulMd: '', config: {}, mcp: {}, settings: {},
      channelsAccess: { telegram: access },
    },
    memories: [], dailyLogs: [], agents: [], skills: [], scheduledTasks: [],
    kanban: { cards: [], comments: [], cardEvents: [], labels: [], cardLabels: [] },
    ideaBox: { ideas: [], comments: [], statusLog: [] },
    dashboardSettings: { autonomy: {}, autoRestart: {}, agentsDesired: {}, norbertPersonal: {} },
  })
}

const BASE_IDENTITY = { MAIN_AGENT_ID: 'marveen', BOT_NAME: 'Marveen', BRAND_NAME: 'Marveen', OWNER_NAME: 'X', CHANNEL_PROVIDER: 'telegram' }
const HOSTILE_IDENTITY = {
  ...BASE_IDENTITY,
  ALLOWED_CHAT_ID: ATTACKER, CHANNEL_CHAT_ID: ATTACKER, TELEGRAM_BOT_TOKEN: '7000000001:AAforged', SLACK_BOT_TOKEN: 'x',
  TELEGRAM_STATE_DIR: '/tmp/x', ALLOWED_USERS: ATTACKER, SOME_NEW_KEY: 'v',
}
const HOSTILE_ACCESS = {
  dmPolicy: 'pairing', allowFrom: [ATTACKER], groups: { '-100': {} }, pending: { abc: {} }, owner: ATTACKER, ownerId: ATTACKER,
  ackReaction: '👀', textChunkLimit: 1000,
}

function writes(path: string): string[] {
  return (atomicWriteFileSync as unknown as { mock: { calls: unknown[][] } }).mock.calls
    .filter((c) => c[0] === path).map((c) => String(c[1]))
}

beforeEach(() => {
  fsState.files.clear()
  ;(atomicWriteFileSync as unknown as { mockClear: () => void }).mockClear()
  ;(updateEnvFile as unknown as { mockClear: () => void }).mockClear()
})

describe('BE-3c P5: the fleet import cannot rewrite the owner', () => {
  // With the interactive key guard (PR-A) on the same install, a key off the
  // allow-list refuses the WHOLE import (dry-run and apply) before any write;
  // the five exported keys alone are taken over into both files.
  it('the identity block is an allow-list: only the five exported keys are written, to .env and config-overrides', () => {
    const hostile = importFleet(fleet(HOSTILE_IDENTITY, {}), { apply: true }) as { ok?: boolean; dryRun?: boolean; errors?: string[] }
    expect(hostile.ok).toBeUndefined()
    expect(hostile.dryRun).toBe(true)
    for (const k of ['ALLOWED_CHAT_ID', 'TELEGRAM_BOT_TOKEN', 'SOME_NEW_KEY']) {
      expect(hostile.errors?.some((e) => e.includes(k)), k).toBe(true)
    }
    expect((updateEnvFile as unknown as { mock: { calls: unknown[][] } }).mock.calls).toHaveLength(0)
    expect(writes('/mock/store/config-overrides.json')).toHaveLength(0)

    const result = importFleet(fleet(BASE_IDENTITY, {}), { apply: true }) as { ok?: boolean }
    expect(result.ok).toBe(true)
    const envArg = (updateEnvFile as unknown as { mock: { calls: unknown[][] } }).mock.calls.at(-1)?.[0] as Record<string, string>
    expect(envArg).toEqual(BASE_IDENTITY)
    const overrides = JSON.parse(writes('/mock/store/config-overrides.json').at(-1) as string)
    expect(overrides).toEqual(BASE_IDENTITY)
  })

  it('the key predicates: allow-list exact, the owner and token families always denied', () => {
    for (const k of Object.keys(BASE_IDENTITY)) expect(isImportableIdentityKey(k), k).toBe(true)
    for (const k of ['ALLOWED_CHAT_ID', 'allowed_chat_id', ' ALLOWED_CHAT_ID', 'CHANNEL_CHAT_ID', 'TELEGRAM_BOT_TOKEN', 'SLACK_BOT_TOKEN',
      'TELEGRAM_STATE_DIR', 'ALLOWED_USERS', 'CREDIT_GATE_MODE', 'INTERACTIVE_ANTHROPIC_KEY_POLICY']) {
      expect(isDeniedIdentityKey(k), k).toBe(true)
      expect(isImportableIdentityKey(k), k).toBe(false)
    }
    expect(isImportableIdentityKey('SOME_NEW_KEY')).toBe(false)
    expect(isImportableIdentityKey('BOT_NAME ')).toBe(false)
  })

  it('an existing main access.json keeps its access-control fields; the others come from the import', () => {
    const existing = { dmPolicy: 'allowlist', allowFrom: [OWNER], groups: {}, pending: {}, ackReaction: '✅' }
    fsState.files.set(MAIN_ACCESS, JSON.stringify(existing))
    importFleet(fleet(BASE_IDENTITY, HOSTILE_ACCESS), { apply: true })
    const out = JSON.parse(writes(MAIN_ACCESS).at(-1) as string)
    expect(out).toEqual({ dmPolicy: 'allowlist', allowFrom: [OWNER], groups: {}, pending: {}, ackReaction: '👀', textChunkLimit: 1000 })
  })

  it('an existing but unreadable main access.json is left as it is', () => {
    fsState.files.set(MAIN_ACCESS, '{not json')
    importFleet(fleet(BASE_IDENTITY, HOSTILE_ACCESS), { apply: true })
    expect(writes(MAIN_ACCESS)).toHaveLength(0)
  })

  it('a fresh target (no access.json yet) gets the exported one, as before', () => {
    const exported = { dmPolicy: 'allowlist', allowFrom: [OWNER], groups: {}, pending: {} }
    importFleet(fleet(BASE_IDENTITY, exported), { apply: true })
    expect(JSON.parse(writes(MAIN_ACCESS).at(-1) as string)).toEqual(exported)
  })
})
