// Card 053f4e66 (M2): with a local patch package under store/local-patches/,
// POST /api/updates/apply { autoStash: true } is refused with 409
// local_patches_present and a WARN line, before the update lock or any git
// or update.sh call. The stash-pull-build-pop path would build a dist without
// the patch and, on a pop conflict, leave every gate of it silently gone.

import { describe, it, expect, beforeEach, afterAll, vi } from 'vitest'
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import type { RouteContext } from '../web/routes/types.js'

const T = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'update-lp-gate-')))
  const project = path.join(root, 'project')
  process.env.HOME = path.join(root, 'home')
  process.env.CLAUDECLAW_ENV_DIR = project
  return { root, project, store: path.join(project, 'store') }
})

vi.mock('../config.js', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../config.js')>()),
  PROJECT_ROOT: T.project,
  STORE_DIR: T.store,
}))

// No git and no update.sh may ever run from this suite.
const proc = vi.hoisted(() => ({ spawn: 0, execFile: 0 }))
vi.mock('node:child_process', async (importOriginal) => ({
  ...(await importOriginal<typeof import('node:child_process')>()),
  spawn: () => { proc.spawn++; throw new Error('spawn blocked in test') },
  execFileSync: () => { proc.execFile++; throw new Error('execFileSync blocked in test') },
}))

const log = vi.hoisted(() => {
  const l: Record<string, any> = {}
  for (const k of ['info', 'warn', 'error', 'debug', 'trace', 'fatal']) l[k] = vi.fn()
  l.child = () => l
  return l
})
vi.mock('../logger.js', () => ({ logger: log, PRETTY_OPTIONS: {} }))

const updates = await import('../web/routes/updates.js')

const LP = join(T.store, 'local-patches')
const PIDFILE = join(T.store, 'update.pid')

async function apply(body: unknown, agentId = 'ezermester') {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const raw = Buffer.from(body === undefined ? '' : JSON.stringify(body))
  const req: any = {
    headers: { 'x-agent-id': agentId },
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data' && raw.length) cb(raw)
      if (event === 'end') cb()
      return req
    },
  }
  const path = '/api/updates/apply'
  const url = new URL(`http://localhost:3420${path}`)
  await updates.tryHandleUpdates({ req, res, path, method: 'POST', url } as RouteContext)
  return out
}

const refusals = () => log.warn.mock.calls.filter((c: any[]) => /local patches present/i.test(String(c[1])))

beforeEach(() => {
  rmSync(T.project, { recursive: true, force: true })
  mkdirSync(T.store, { recursive: true })
  proc.spawn = 0
  proc.execFile = 0
  log.warn.mockClear()
})

afterAll(() => { rmSync(T.root, { recursive: true, force: true }) })

describe('POST /api/updates/apply autoStash with local patches (053f4e66 M2)', () => {
  it('a package present + autoStash:true -> 409 local_patches_present, a WARN, no lock, no git, no update.sh', async () => {
    mkdirSync(join(LP, '053f4e66'), { recursive: true })
    writeFileSync(join(LP, '053f4e66', 'README.md'), '# x\n')
    const r = await apply({ autoStash: true })
    expect(r.status).toBe(409)
    expect(r.body?.reason).toBe('local_patches_present')
    expect(refusals()).toHaveLength(1)
    expect(refusals()[0]![0]).toMatchObject({ caller: 'ezermester' })
    expect(Number.isNaN(Date.parse(refusals()[0]![0].at))).toBe(false)
    expect(proc.spawn).toBe(0)
    expect(proc.execFile).toBe(0)
    expect(existsSync(PIDFILE)).toBe(false)
  })

  it('a plain file named local-patches also counts (fail closed)', async () => {
    writeFileSync(LP, 'x')
    const r = await apply({ autoStash: true })
    expect(r.body?.reason).toBe('local_patches_present')
  })

  it('without autoStash the request goes on to the usual checks (not this refusal)', async () => {
    mkdirSync(join(LP, '053f4e66'), { recursive: true })
    const r = await apply({ autoStash: false })
    expect(r.body?.reason).not.toBe('local_patches_present')
    expect(refusals()).toHaveLength(0)
  })

  it.each([
    ['no local-patches folder', () => {}],
    ['an empty local-patches folder', () => mkdirSync(LP, { recursive: true })],
    ['only dotfiles in it', () => { mkdirSync(LP, { recursive: true }); writeFileSync(join(LP, '.DS_Store'), '') }],
  ])('%s + autoStash:true -> not refused for local patches', async (_label, prep) => {
    prep()
    const r = await apply({ autoStash: true })
    expect(r.body?.reason).not.toBe('local_patches_present')
    expect(refusals()).toHaveLength(0)
  })
})

describe('localPatchesPresent (053f4e66 M2)', () => {
  it('present iff the folder holds a non-dot entry, or is not a readable folder', () => {
    expect(updates.localPatchesPresent(T.store)).toBe(false)
    mkdirSync(LP, { recursive: true })
    expect(updates.localPatchesPresent(T.store)).toBe(false)
    writeFileSync(join(LP, '.keep'), '')
    expect(updates.localPatchesPresent(T.store)).toBe(false)
    mkdirSync(join(LP, '345f34e2'))
    expect(updates.localPatchesPresent(T.store)).toBe(true)
  })
})
