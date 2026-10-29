// Card 053f4e66: POST /api/fleet/import?apply=true is OFF unless the install's
// .env carries FLEET_IMPORT_APPLY_ENABLED=1 (exactly "1"). A refused apply is a
// 403 plus one log line naming the caller (X-Agent-Id or "unknown") and the
// time, and it writes NOTHING: the route answers before importFleet runs. The
// dry run (no apply) stays available and is pinned here as write-free too.
//
// The suite runs the REAL route and the REAL importFleet against a throwaway
// install: PROJECT_ROOT, HOME, the main Telegram state dir and the .env all
// live under one mkdtemp directory, and the DB is a temp file. The switch="1"
// case is the positive control: it proves the same fixture DOES get written
// when the gate lets the call through, so the "unchanged" assertions of the
// refused cases are not vacuous.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { join, relative } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'fleet-apply-gate-')))
  const project = path.join(root, 'project')
  const home = path.join(root, 'home')
  const tgState = path.join(root, 'tg-state')
  // Set BEFORE any app module loads: env.ts reads CLAUDECLAW_ENV_DIR at import,
  // scheduled-tasks-io.ts resolves homedir() at import.
  process.env.HOME = home
  process.env.CLAUDECLAW_ENV_DIR = project
  process.env.TELEGRAM_STATE_DIR = tgState
  delete process.env.FLEET_IMPORT_APPLY_ENABLED
  return { root, project, home, tgState, store: path.join(project, 'store') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
}))

// No embedding backfill: it would try the embedder over the network.
vi.mock('../db.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../db.js')>()),
  backfillEmbeddings: () => Promise.resolve(),
}))

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', () => ({ logger: log, PRETTY_OPTIONS: {} }))

const { tryHandleFleet } = await import('../web/routes/fleet.js')
const { initDatabase, getDb } = await import('../db.js')

const DB_PATH = join(T.store, 'claudeclaw.db')
const KEY = 'FLEET_IMPORT_APPLY_ENABLED'

const ORIGINAL = {
  env: 'MAIN_AGENT_ID=oldmain\nBOT_NAME=Old\n',
  claudeMd: '# original main CLAUDE.md\n',
  config: '{\n  "displayName": "Original"\n}',
  settings: '{\n  "permissions": {}\n}',
  access: '{\n  "allowFrom": ["111"]\n}',
  alphaConfig: '{\n  "name": "alpha"\n}',
}

const FLEET = JSON.stringify({
  schemaVersion: 1,
  exportedAt: '2026-10-16T00:00:00.000Z',
  sourceHost: 'source-host',
  mainAgent: {
    agentId: 'importedmain',
    identity: { MAIN_AGENT_ID: 'importedmain', BOT_NAME: 'Imported', BRAND_NAME: 'Imported', OWNER_NAME: 'Someone', CHANNEL_PROVIDER: 'telegram' },
    claudeMd: '# IMPORTED main\n',
    soulMd: '# IMPORTED soul\n',
    config: { displayName: 'Imported' },
    mcp: {},
    settings: { permissions: { allow: ['Bash'] } },
    channelsAccess: { telegram: { allowFrom: ['999'] } },
  },
  agents: [{
    name: 'alpha', config: { name: 'alpha', imported: true }, claudeMd: '# IMPORTED alpha\n', soulMd: '',
    mcp: {}, settings: {}, channelsAccess: {}, avatar: null, avatarExt: 'png', agentSkills: [],
  }],
  skills: [{ name: 'imported-skill', skillMd: '# skill\n' }],
  scheduledTasks: [],
  memories: [{
    agent_id: 'importedmain', content: 'imported memory row', sector: 'semantic', salience: 1,
    created_at: 1760000000, accessed_at: 1760000000, category: 'warm', auto_generated: 0, keywords: null,
  }],
  dailyLogs: [{ agent_id: 'importedmain', date: '2026-10-15', content: 'imported log', created_at: 1760000000 }],
  kanban: {
    cards: [{ id: 'card-imported', title: 'Imported', status: 'planned', priority: 'normal', sort_order: 0, created_at: 1760000000, updated_at: 1760000000 }],
    comments: [], cardEvents: [], labels: [], cardLabels: [],
  },
  ideaBox: { ideas: [], comments: [], statusLog: [] },
  dashboardSettings: { autonomy: { imported: 1 }, autoRestart: {}, agentsDesired: {}, norbertPersonal: {} },
})

function writeEnv(switchLine: string | null): void {
  writeFileSync(join(T.project, '.env'), ORIGINAL.env + (switchLine === null ? '' : `${switchLine}\n`))
}

function resetInstall(switchLine: string | null): void {
  rmSync(T.project, { recursive: true, force: true })
  rmSync(T.home, { recursive: true, force: true })
  rmSync(T.tgState, { recursive: true, force: true })
  mkdirSync(join(T.project, '.claude'), { recursive: true })
  mkdirSync(join(T.project, 'agents', 'alpha'), { recursive: true })
  mkdirSync(T.store, { recursive: true })
  mkdirSync(join(T.home, '.claude', 'skills'), { recursive: true })
  mkdirSync(T.tgState, { recursive: true })
  writeEnv(switchLine)
  writeFileSync(join(T.project, 'CLAUDE.md'), ORIGINAL.claudeMd)
  writeFileSync(join(T.project, 'agent-config.json'), ORIGINAL.config)
  writeFileSync(join(T.project, '.claude', 'settings.json'), ORIGINAL.settings)
  writeFileSync(join(T.tgState, 'access.json'), ORIGINAL.access)
  writeFileSync(join(T.project, 'agents', 'alpha', 'agent-config.json'), ORIGINAL.alphaConfig)
  initDatabase(DB_PATH)
  getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience, created_at, accessed_at, agent_id, category, auto_generated, keywords)
     VALUES ('', NULL, 'pre-existing row', 'semantic', 1, 1, 1, 'oldmain', 'warm', 0, NULL)`,
  ).run()
}

const isDbFile = (p: string) => /claudeclaw\.db(-wal|-shm|-journal)?$/.test(p)

// Every file under the throwaway install except the SQLite files (those are
// compared by content below): path -> sha256, size, mtime.
function fileSnapshot(): Record<string, string> {
  const out: Record<string, string> = {}
  const walk = (dir: string) => {
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      const st = statSync(p)
      if (st.isDirectory()) { out[`${relative(T.root, p)}/`] = 'dir'; walk(p); continue }
      if (isDbFile(p)) continue
      const sha = createHash('sha256').update(readFileSync(p)).digest('hex')
      out[relative(T.root, p)] = `${sha}:${st.size}:${st.mtimeMs}`
    }
  }
  walk(T.root)
  return out
}

// Every table: row count + a hash of all rows.
function dbSnapshot(): Record<string, string> {
  const db = getDb()
  const tables = db.prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name").all() as { name: string }[]
  const out: Record<string, string> = {}
  for (const { name } of tables) {
    let rows: unknown[]
    try { rows = db.prepare(`SELECT * FROM "${name.replace(/"/g, '""')}"`).all() } catch { continue }
    const h = createHash('sha256').update(JSON.stringify(rows, (_k, v) => (typeof v === 'bigint' ? v.toString() : Buffer.isBuffer(v) ? v.toString('hex') : v))).digest('hex')
    out[name] = `${rows.length}:${h}`
  }
  return out
}

function countRows(table: string): number {
  return (getDb().prepare(`SELECT COUNT(*) AS n FROM ${table}`).get() as { n: number }).n
}

async function callImport(opts: { apply?: string | null; agentId?: string; body?: string; vaultPassword?: string } = {}) {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const qs = opts.apply === undefined ? '?apply=true' : opts.apply === null ? '' : `?apply=${opts.apply}`
  const url = new URL(`http://localhost:3420/api/fleet/import${qs}`)
  const headers: Record<string, string> = {}
  if (opts.agentId !== undefined) headers['x-agent-id'] = opts.agentId
  if (opts.vaultPassword !== undefined) headers['x-vault-password'] = opts.vaultPassword
  let bodyRead = false
  const bodyStr = opts.body ?? FLEET
  const req: any = {
    headers,
    on(event: string, cb: (chunk?: Buffer) => void) {
      bodyRead = true
      if (event === 'data') cb(Buffer.from(bodyStr))
      if (event === 'end') cb()
      return req
    },
  }
  const ctx = { req, res, path: '/api/fleet/import', method: 'POST', url } as RouteContext
  const handled = await tryHandleFleet(ctx)
  return { handled, ...out, bodyRead: () => bodyRead }
}

function refusalLogs(): any[][] {
  return log.warn.mock.calls.filter((c: any[]) => typeof c[1] === 'string' && /fleet import apply refused/i.test(c[1]))
}

beforeEach(() => {
  for (const fn of Object.values(log)) if (typeof fn === 'function' && 'mockClear' in fn) (fn as any).mockClear()
  delete process.env[KEY]
})

afterAll(() => {
  try { getDb().close() } catch { /* already closed */ }
  rmSync(T.root, { recursive: true, force: true })
})

describe('POST /api/fleet/import?apply=true is off by default (053f4e66)', () => {
  it('without the switch: 403, a log line with the caller and the time, nothing written', async () => {
    resetInstall(null)
    const files = fileSnapshot()
    const db = dbSnapshot()
    const before = Date.now()

    const r = await callImport({ agentId: 'ezermester' })

    expect(r.handled).toBe(true)
    expect(r.status).toBe(403)
    expect(String(r.body?.error ?? '')).toContain(KEY)
    expect(r.bodyRead()).toBe(false)
    const logs = refusalLogs()
    expect(logs).toHaveLength(1)
    const fields = logs[0]![0]
    expect(fields.caller).toBe('ezermester')
    const at = Date.parse(fields.at)
    expect(Number.isNaN(at)).toBe(false)
    expect(at).toBeGreaterThanOrEqual(before - 1000)
    expect(at).toBeLessThanOrEqual(Date.now() + 1000)

    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
    expect(readFileSync(join(T.project, '.env'), 'utf8')).toBe(ORIGINAL.env)
    expect(readFileSync(join(T.tgState, 'access.json'), 'utf8')).toBe(ORIGINAL.access)
    expect(readFileSync(join(T.project, '.claude', 'settings.json'), 'utf8')).toBe(ORIGINAL.settings)
    expect(readFileSync(join(T.project, 'CLAUDE.md'), 'utf8')).toBe(ORIGINAL.claudeMd)
    expect(readFileSync(join(T.project, 'agent-config.json'), 'utf8')).toBe(ORIGINAL.config)
  })

  it('without X-Agent-Id the caller is logged as "unknown"', async () => {
    resetInstall(null)
    const r = await callImport()
    expect(r.status).toBe(403)
    const logs = refusalLogs()
    expect(logs).toHaveLength(1)
    expect(logs[0]![0].caller).toBe('unknown')
  })

  it('an X-Agent-Id with control characters or excess length is logged neutralised and capped', async () => {
    resetInstall(null)
    const r = await callImport({ agentId: `evil\n{"x":1}${'a'.repeat(200)}` })
    expect(r.status).toBe(403)
    const caller = refusalLogs()[0]![0].caller as string
    expect(caller.length).toBeLessThanOrEqual(64)
    expect(caller).toMatch(/^[A-Za-z0-9_.@-]+$/)
  })

  it.each([
    ['true', `${KEY}=true`],
    ['yes', `${KEY}=yes`],
    ['" 1" (quoted, keeps the space)', `${KEY}=" 1"`],
    ['empty', `${KEY}=`],
    ['on', `${KEY}=on`],
    ['01', `${KEY}=01`],
  ])('switch value %s keeps it off: 403, nothing written', async (_label, line) => {
    resetInstall(line)
    const files = fileSnapshot()
    const db = dbSnapshot()
    const r = await callImport({ agentId: 'ezermester' })
    expect(r.status).toBe(403)
    expect(refusalLogs()).toHaveLength(1)
    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
  })

  it('a process-environment FLEET_IMPORT_APPLY_ENABLED=1 does not turn it on: the .env is the only source', async () => {
    resetInstall(null)
    process.env[KEY] = '1'
    const files = fileSnapshot()
    const db = dbSnapshot()
    const r = await callImport()
    expect(r.status).toBe(403)
    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
  })

  it('the refusal comes first: a too-short vault password or a broken body still gets 403, not 400', async () => {
    resetInstall(null)
    const r1 = await callImport({ vaultPassword: 'x' })
    expect(r1.status).toBe(403)
    const r2 = await callImport({ body: 'not json' })
    expect(r2.status).toBe(403)
  })

  it('switch "1": the previous behaviour, the import is applied (positive control for the fixture)', async () => {
    resetInstall(`${KEY}=1`)
    const memBefore = countRows('memories')
    const cardsBefore = countRows('kanban_cards')

    const r = await callImport({ agentId: 'ezermester' })

    expect(r.status).toBe(200)
    expect(r.body?.ok).toBe(true)
    expect(refusalLogs()).toHaveLength(0)
    expect(readFileSync(join(T.project, 'CLAUDE.md'), 'utf8')).toBe('# IMPORTED main\n')
    expect(readFileSync(join(T.tgState, 'access.json'), 'utf8')).not.toBe(ORIGINAL.access)
    expect(readFileSync(join(T.project, '.claude', 'settings.json'), 'utf8')).not.toBe(ORIGINAL.settings)
    expect(readFileSync(join(T.project, 'agent-config.json'), 'utf8')).not.toBe(ORIGINAL.config)
    expect(readFileSync(join(T.project, '.env'), 'utf8')).toContain('MAIN_AGENT_ID=importedmain')
    expect(readFileSync(join(T.project, 'agents', 'alpha', 'CLAUDE.md'), 'utf8')).toBe('# IMPORTED alpha\n')
    expect(countRows('memories')).toBe(memBefore + 1)
    expect(countRows('kanban_cards')).toBe(cardsBefore + 1)
  })

  it('switch "1" written as KEY = 1 (the .env grammar trims the value) is on', async () => {
    resetInstall(`${KEY} = 1`)
    const r = await callImport()
    expect(r.status).toBe(200)
    expect(r.body?.ok).toBe(true)
  })
})

describe('POST /api/fleet/import dry run (no apply) writes nothing (053f4e66)', () => {
  it.each([
    ['switch off', null],
    ['switch "1"', `${KEY}=1`],
  ])('%s: 200 dry-run report, files byte- and mtime-identical, DB identical', async (_label, line) => {
    resetInstall(line)
    const files = fileSnapshot()
    const db = dbSnapshot()
    const memBefore = countRows('memories')

    const r = await callImport({ apply: null, agentId: 'ezermester' })

    expect(r.status).toBe(200)
    expect(r.body?.dryRun).toBe(true)
    expect(r.body?.wouldCreate?.memories).toBe(1)
    expect(refusalLogs()).toHaveLength(0)
    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
    expect(countRows('memories')).toBe(memBefore)
  })

  it('apply=false and apply=1 are dry runs, not applies, and write nothing', async () => {
    resetInstall(null)
    const files = fileSnapshot()
    const db = dbSnapshot()
    for (const v of ['false', '1']) {
      const r = await callImport({ apply: v })
      expect(r.status).toBe(200)
      expect(r.body?.dryRun).toBe(true)
    }
    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
  })
})

describe('fleet import identity cannot write the protected install keys or forge .env lines (053f4e66)', () => {
  const withIdentity = (extra: Record<string, unknown>) => {
    const f = JSON.parse(FLEET)
    Object.assign(f.mainAgent.identity, extra)
    return JSON.stringify(f)
  }
  const overridesPath = () => join(T.store, 'config-overrides.json')

  it('switch keys in the identity block are skipped (with a warning), never written to .env or config-overrides', async () => {
    resetInstall(`${KEY}=1`)
    const r = await callImport({
      body: withIdentity({
        MAIN_CHANNEL_ADMIN_ENABLED: '1', ' main_channel_admin_enabled ': '1', FLEET_IMPORT_APPLY_ENABLED: '1', MIGRATE_ROOTS: '/', 'migrate_roots ': '/',
        // 053f4e66 B: the bearer-credential-admin trio, and its case/space variants.
        BEARER_CREDENTIAL_ADMIN_ENABLED: '1', ' bearer_credential_admin_enabled ': '1',
        BEARER_CREDENTIAL_ADMIN_UNTIL: '1800000000', BEARER_CREDENTIAL_ADMIN_NONCE: 'Ab3_-'.repeat(8) + 'xyz',
        // 89df7a00: the code-exec switch, and its case/space variants.
        BEARER_CODE_EXEC_ADMIN_ENABLED: '1', ' bearer_code_exec_admin_enabled ': '1',
      }),
    })
    expect(r.status).toBe(200)
    expect(r.body?.ok).toBe(true)
    const env = readFileSync(join(T.project, '.env'), 'utf8')
    expect(env).not.toMatch(/MAIN_CHANNEL_ADMIN_ENABLED/i)
    expect(env).not.toMatch(/MIGRATE_ROOTS/i)
    expect(env).not.toMatch(/BEARER_CREDENTIAL_ADMIN/i)
    expect(env).not.toMatch(/BEARER_CODE_EXEC_ADMIN/i)
    expect(env.match(/FLEET_IMPORT_APPLY_ENABLED/g)).toHaveLength(1)
    const ov = JSON.parse(readFileSync(overridesPath(), 'utf8'))
    expect(Object.keys(ov).filter(k => /admin|apply_enabled|migrate_roots|bearer_credential|bearer_code_exec/i.test(k))).toEqual([])
    expect((r.body?.warnings ?? []).join(' ')).toMatch(/MAIN_CHANNEL_ADMIN_ENABLED/)
    expect((r.body?.warnings ?? []).join(' ')).toMatch(/MIGRATE_ROOTS/)
    for (const k of ['BEARER_CREDENTIAL_ADMIN_ENABLED', 'bearer_credential_admin_enabled', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE', 'BEARER_CODE_EXEC_ADMIN_ENABLED', 'bearer_code_exec_admin_enabled']) {
      expect((r.body?.warnings ?? []).join(' ')).toContain(k)
    }
  })

  it.each([
    ['a value with LF', { BOT_NAME: 'x\nMAIN_CHANNEL_ADMIN_ENABLED=1' }],
    ['a value with CR', { BOT_NAME: 'x\rMAIN_CHANNEL_ADMIN_ENABLED=1' }],
    ['a key that is not a variable name', { 'BOT NAME': 'x' }],
  ])('%s: an import error (400) on apply and on dry run, nothing written', async (_label, extra) => {
    resetInstall(`${KEY}=1`)
    const files = fileSnapshot()
    const db = dbSnapshot()
    for (const apply of [undefined, null]) {
      const r = await callImport({ apply, body: withIdentity(extra) })
      expect(r.status).toBe(400)
      expect(r.body?.errors?.length).toBeGreaterThan(0)
    }
    expect(fileSnapshot()).toEqual(files)
    expect(dbSnapshot()).toEqual(db)
  })
})
