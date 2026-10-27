// Card 053f4e66 (Brainy 1954): POST /api/migrate/run used to read any path in
// its body into memory rows -- through the shared Bearer, any file the
// dashboard user can read. A run may now read only a file a recent scan
// listed, compared by realpath: "../", an absolute path elsewhere and a symlink
// out of the scanned folder are refused (403) before anything is read.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

// One throwaway tree: HOME, the install (PROJECT_ROOT, store), a main channel
// state dir outside both, the allowlisted folder and a folder outside it.
const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'migrate-guard-')))
  const project = path.join(root, 'project')
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  for (const p of ['TELEGRAM', 'SLACK', 'DISCORD', 'GOOGLECHAT', 'TEAMS']) {
    process.env[`${p}_STATE_DIR`] = path.join(root, 'state', p.toLowerCase())
  }
  return { root, project, home: path.join(root, 'home'), store: path.join(project, 'store'), state: path.join(root, 'state') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
}))

const saved = vi.hoisted(() => [] as Array<{ agent: string; content: string }>)
vi.mock('../db.js', () => ({
  saveAgentMemory: (agent: string, content: string) => { saved.push({ agent, content }) },
}))
const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', () => ({ logger: log, PRETTY_OPTIONS: {} }))

const fsReads = vi.hoisted(() => [] as string[])
vi.mock('node:fs', async (importOriginal) => {
  const real = await importOriginal<typeof import('node:fs')>()
  return {
    ...real,
    readFileSync: ((p: any, ...rest: any[]) => { fsReads.push(String(p)); return (real.readFileSync as any)(p, ...rest) }) as typeof real.readFileSync,
  }
})

const { tryHandleMigrate, _resetMigrateScansForTest } = await import('../web/routes/migrate.js')

const ROOT = T.root
const ALLOWED = join(ROOT, 'allowed')
const WS = join(ALLOWED, 'workspace')
const OUTSIDE = join(ROOT, 'outside')
const SECRET = join(OUTSIDE, 'secret.md')
const SOUL = join(WS, 'SOUL.md')
const ENV = join(T.project, '.env')
const setRoots = (v: string | null) => writeFileSync(ENV, v === null ? 'MAIN_AGENT_ID=x\n' : `MIGRATE_ROOTS=${v}\n`)

async function call(path: string, body: unknown) {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const raw = Buffer.from(JSON.stringify(body))
  const req: any = {
    headers: { 'x-agent-id': 'ezermester' },
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(raw)
      if (event === 'end') cb()
      return req
    },
  }
  const url = new URL(`http://localhost:3420${path}`)
  await tryHandleMigrate({ req, res, path, method: 'POST', url } as RouteContext)
  return out
}

const run = (paths: string[]) => call('/api/migrate/run', { agentId: 'target', findings: paths.map(p => ({ type: 'personality', path: p, name: 'x.md' })) })

beforeEach(() => {
  for (const d of [ALLOWED, OUTSIDE, T.home, T.project, T.state]) rmSync(d, { recursive: true, force: true })
  mkdirSync(join(WS, 'memory'), { recursive: true })
  mkdirSync(OUTSIDE, { recursive: true })
  mkdirSync(T.store, { recursive: true })
  writeFileSync(SOUL, '# soul of the old assistant, long enough to be imported\n')
  writeFileSync(SECRET, '# TOP SECRET outside the workspace, long enough\n')
  writeFileSync(join(WS, '.credentials.json'), '{"token":"x-not-a-real-secret-but-long"}')
  symlinkSync(SECRET, join(WS, 'memory', 'link-out.md'))
  setRoots(ALLOWED)
  _resetMigrateScansForTest()
  saved.length = 0
  fsReads.length = 0
  log.warn.mockClear()
})

afterAll(() => { rmSync(ROOT, { recursive: true, force: true }) })

describe('POST /api/migrate/run reads only scanned files (053f4e66)', () => {
  it('legit: scan, then run with the listed path imports it', async () => {
    const scan = await call('/api/migrate/scan', { sourcePath: WS })
    expect(scan.status).toBe(200)
    const listed = scan.body.findings.map((f: any) => f.path)
    expect(listed).toContain(SOUL)
    const r = await run([SOUL])
    expect(r.status).toBe(200)
    expect(saved.some(s => s.content.includes('soul of the old assistant'))).toBe(true)
  })

  it('the scan does not list a symlink pointing out of the folder, nor a dotfile', async () => {
    const scan = await call('/api/migrate/scan', { sourcePath: WS })
    const listed = scan.body.findings.map((f: any) => f.path)
    expect(listed).not.toContain(join(WS, 'memory', 'link-out.md'))
    expect(listed).not.toContain(join(WS, '.credentials.json'))
  })

  it.each([
    ['an absolute path elsewhere', () => SECRET],
    ['a ../ escape from the scanned root', () => join(WS, '..', 'outside', 'secret.md')],
    ['a symlink inside the root pointing out', () => join(WS, 'memory', 'link-out.md')],
    ['a dotfile under the root the scan did not list', () => join(WS, '.credentials.json')],
    ['a nonexistent escaping path', () => join(WS, '..', '..', 'nonexistent-053f4e66', 'x.md')],
  ])('%s -> 403, nothing read, nothing saved', async (_label, p) => {
    await call('/api/migrate/scan', { sourcePath: WS })
    fsReads.length = 0
    const r = await run([SOUL, p()])
    expect(r.status).toBe(403)
    expect(fsReads).toEqual([])
    expect(saved).toEqual([])
    const w = log.warn.mock.calls.find((c: any[]) => /Migrate run refused/.test(String(c[1])))
    expect(w?.[0]).toMatchObject({ caller: 'ezermester', refused: 1 })
  })

  it('without a scan, even a file under a would-be root is refused', async () => {
    const r = await run([SOUL])
    expect(r.status).toBe(403)
    expect(fsReads).toEqual([])
    expect(saved).toEqual([])
  })

  it('a scan of another folder does not open this one', async () => {
    await call('/api/migrate/scan', { sourcePath: OUTSIDE })
    const r = await run([SOUL])
    expect(r.status).toBe(403)
    expect(saved).toEqual([])
  })
})

describe('POST /api/migrate/scan: only MIGRATE_ROOTS, never a protected or dot folder (053f4e66 M1)', () => {
  const scan = (p: string) => call('/api/migrate/scan', { sourcePath: p })
  const scanRefusals = () => log.warn.mock.calls.filter((c: any[]) => /Migrate scan refused/.test(String(c[1])))

  it('without MIGRATE_ROOTS in the .env every scan is 403, even of a fine folder', async () => {
    setRoots(null)
    const r = await scan(WS)
    expect(r.status).toBe(403)
    expect(r.body?.reason).toBe('migrate_roots_missing')
    expect(scanRefusals()[0]?.[0]).toMatchObject({ caller: 'ezermester', reason: 'migrate_roots_missing' })
    expect((await run([SOUL])).status).toBe(403)
  })

  it('a folder outside MIGRATE_ROOTS is 403, and does not even learn whether it exists', async () => {
    expect((await scan(OUTSIDE)).status).toBe(403)
    expect((await scan(join(ROOT, 'no-such-folder'))).status).toBe(403)
  })

  it('a nonexistent folder inside MIGRATE_ROOTS is still a plain 404', async () => {
    expect((await scan(join(ALLOWED, 'missing'))).status).toBe(404)
  })

  // The BE round-2 proof cases, with MIGRATE_ROOTS opened as wide as the whole
  // tree (HOME, the install and the channel dir are all under it).
  describe('with MIGRATE_ROOTS covering everything', () => {
    function seed(): Record<string, string> {
      const tg = join(T.home, '.claude', 'channels', 'telegram')
      mkdirSync(tg, { recursive: true })
      writeFileSync(join(tg, 'access.json'), '{"allowFrom":["111"],"dmPolicy":"allowlist"}')
      writeFileSync(join(tg, 'invites.json'), '{"invites":{"tok":{"used":false}}}')
      writeFileSync(join(T.store, 'federation.json'), '{"peers":[{"token":"x-not-real-but-long"}]}')
      mkdirSync(join(T.home, '.config', 'x'), { recursive: true })
      writeFileSync(join(T.home, '.config', 'x', 'token.json'), '{"token":"x-not-real-but-long"}')
      const mainTg = join(T.state, 'telegram')
      mkdirSync(mainTg, { recursive: true })
      writeFileSync(join(mainTg, 'access.json'), '{"allowFrom":["111"]}')
      mkdirSync(join(T.project, 'agents', 'subby'), { recursive: true })
      writeFileSync(join(T.project, 'agents', 'subby', 'notes.md'), '# a sub-agent note, long enough\n')
      mkdirSync(join(ALLOWED, '.hidden'), { recursive: true })
      writeFileSync(join(ALLOWED, '.hidden', 'x.md'), '# hidden, long enough to list\n')
      symlinkSync(join(T.home, '.config', 'x'), join(ALLOWED, 'config-link'))
      return {
        'access.json': join(tg, 'access.json'),
        'invites.json': join(tg, 'invites.json'),
        'federation.json': join(T.store, 'federation.json'),
        '~/.config/x/token.json': join(T.home, '.config', 'x', 'token.json'),
      }
    }

    it.each([
      ['~/.claude/channels/telegram (access.json, invites.json)', () => join(T.home, '.claude', 'channels', 'telegram')],
      ['~/.claude', () => join(T.home, '.claude')],
      ['the store (federation.json)', () => T.store],
      ['~/.config/x (token.json)', () => join(T.home, '.config', 'x')],
      ['~/.config', () => join(T.home, '.config')],
      ['the install root', () => T.project],
      ['a folder below the install root', () => join(T.project, 'agents', 'subby')],
      ['a main channel state dir outside HOME', () => join(T.state, 'telegram')],
      ['a dot-folder inside an allowed root', () => join(ALLOWED, '.hidden')],
      ['a symlink inside an allowed root pointing into ~/.config', () => join(ALLOWED, 'config-link')],
      ['a ../ walk from an allowed root into ~/.config', () => join(ALLOWED, '..', 'home', '.config', 'x')],
    ])('%s -> 403', async (_label, p) => {
      seed()
      setRoots(ROOT)
      const r = await scan(p())
      expect(r.status).toBe(403)
      expect(r.body?.findings).toBeUndefined()
    })

    it('access.json, invites.json, federation.json, ~/.config/x/token.json: run is 403 and reads nothing', async () => {
      const files = seed()
      setRoots(ROOT)
      await scan(ROOT)
      fsReads.length = 0
      for (const [name, p] of Object.entries(files)) {
        const r = await run([p])
        expect(r.status, name).toBe(403)
      }
      expect(fsReads).toEqual([])
      expect(saved).toEqual([])
    })

    it('a protected folder listed in MIGRATE_ROOTS is dropped from the list', async () => {
      seed()
      setRoots(`${T.store}:${join(T.home, '.config')}`)
      const r = await scan(join(T.home, '.config', 'x'))
      expect(r.status).toBe(403)
      expect(r.body?.reason).toBe('migrate_roots_missing')
    })
  })
})

// BE round 3 (B1): on a case-insensitive volume the JS realpathSync returns the
// letter case it was given, so a differently cased protected path slipped past
// the relative() comparison. Only meaningful where the tmp volume really is
// case-insensitive (the default APFS on macOS); measured here, else skipped.
const CASE_INSENSITIVE = await (async () => {
  const fs = await vi.importActual<typeof import('node:fs')>('node:fs')
  const probe = join(T.root, 'CaseProbe-053f4e66')
  fs.writeFileSync(probe, '')
  const insensitive = fs.existsSync(join(T.root, 'caseprobe-053f4e66'))
  fs.rmSync(probe, { force: true })
  return insensitive
})()

describe('a differently cased protected path is still protected (053f4e66 B1)', () => {
  it.skipIf(!CASE_INSENSITIVE)('MIGRATE_ROOTS = a parent; .../PROJECT/STORE in upper case: scan 403, run 403, nothing saved', async () => {
    writeFileSync(join(T.store, 'federation.json'), '{"peers":[{"token":"x-not-real-but-long"}]}')
    setRoots(ROOT)
    const upperStore = join(ROOT, 'PROJECT', 'STORE')
    const s = await call('/api/migrate/scan', { sourcePath: upperStore })
    expect(s.status).toBe(403)
    expect(s.body?.findings).toBeUndefined()
    const r = await call('/api/migrate/run', { agentId: 'target', findings: [{ type: 'config', path: join(upperStore, 'federation.json'), name: 'federation.json' }] })
    expect(r.status).toBe(403)
    expect(saved).toEqual([])
    // and a mixed-case walk into ~/.config as well
    mkdirSync(join(T.home, '.config', 'x'), { recursive: true })
    expect((await call('/api/migrate/scan', { sourcePath: join(ROOT, 'Home', '.Config', 'X') })).status).toBe(403)
  })

  it.runIf(!CASE_INSENSITIVE)('skipped above: the tmp volume is case-sensitive, the case-folding escape cannot happen here', () => {
    expect(CASE_INSENSITIVE).toBe(false)
  })
})
