import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import { requiresAuth } from '../web/auth-gate.js'
import { operatorGateDecision } from '../web/operator-gate.js'
import { createGitLogReader, type ExecFileFn } from '../web/funkciok-git.js'
import { NO_SIGNALS, createIvekService, defaultIvekDeps, derivePhase, type IvekDeps, type IvekService } from '../web/ivek.js'
import { setIvekServiceForTest, tryHandleIvek } from '../web/routes/ivek.js'
import type { RouteContext } from '../web/routes/types.js'

// "Ivek" view (card 46e935d6, N2): service + HTTP surface. Fixtures live in a
// temp dir; the real 8T folders and the real repo are never touched.

type Auth = RouteContext['auth']
const MARKER = 'ZQ-MARKER-n2-55c1'
const NOW_MS = Date.UTC(2026, 9, 31, 12, 0, 0)
const NOW_S = NOW_MS / 1000
const DAY = 86400

function call(pathAndQuery: string, opts: { method?: string; auth?: Auth | null } = {}): { ctx: RouteContext; out: { status: number; body: any; raw: string; headers: Record<string, unknown> } } {
  const out: { status: number; body: any; raw: string; headers: Record<string, unknown> } = { status: 0, body: null, raw: '', headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    end(chunk?: string) { if (chunk) { out.raw = chunk; out.body = JSON.parse(chunk) } },
  }
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  const auth = opts.auth === undefined ? ({ kind: 'token' } as Auth) : (opts.auth ?? undefined)
  return { ctx: { req: {} as any, res, path: url.pathname, method: opts.method ?? 'GET', url, auth } as RouteContext, out }
}

let base: string
let ezRoot: string
let depRoot: string
let gitCalls: number
let gitStdout: string | Error

function gitRow(hash: string, ct: number, subject: string, body = ''): string {
  return `\x00${hash.padEnd(40, '0')}\x00${hash.slice(0, 8)}\x00${ct}\x00Ez\x00${subject}\x00${body}\x00\n\nsrc/a.ts\n`
}

const fakeExec: ExecFileFn = async () => {
  gitCalls++
  if (gitStdout instanceof Error) throw gitStdout
  return { stdout: gitStdout }
}

function makeService(over: Partial<IvekDeps> = {}): IvekService {
  return createIvekService({
    ...defaultIvekDeps(),
    git: createGitLogReader({ exec: fakeExec, now: () => 0 }),
    repo: () => '/nonexistent-test-repo',
    ezermesterRoot: ezRoot,
    deployRoot: depRoot,
    now: () => NOW_MS,
    ...over,
  })
}

function addCard(id: string, o: { title?: string; status?: string; assignee?: string | null; updated?: number; archived?: number | null; parent?: string | null } = {}): void {
  getDb().prepare(
    `INSERT INTO kanban_cards (id, title, status, assignee, priority, parent_id, created_at, updated_at, archived_at)
     VALUES (?, ?, ?, ?, 'normal', ?, ?, ?, ?)`,
  ).run(id, o.title ?? `Card ${id}`, o.status ?? 'in_progress', o.assignee === undefined ? 'ezermester' : o.assignee, o.parent ?? null, NOW_S - 30 * DAY, o.updated ?? NOW_S - DAY, o.archived ?? null)
}

function addEvent(id: string, from: string | null, to: string, at: number, actor = 'brainy'): void {
  getDb().prepare('INSERT INTO kanban_card_events (card_id, from_status, to_status, actor, created_at) VALUES (?, ?, ?, ?, ?)').run(id, from, to, actor, at)
}

function putFile(dir: string, name: string, content: string): void {
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, name), content)
}

function jl(rows: Record<string, unknown>[]): string {
  return rows.map((r) => JSON.stringify(r)).join('\n') + '\n'
}

/** The 51538ebc shape: 3 findings rows, briefs, 2 check + 1 apply deploy logs, commits. */
function seedArc(id = '51538ebc'): void {
  putFile(join(ezRoot, id), 'findings-log.jsonl', jl([
    { event: 'add', id: 'B1', round: 1, reviewer: 'be-opus-high', severity: 'HIGH', summary: MARKER, reason: MARKER, location: MARKER, ts: '2026-10-31T19:20:00+01:00' },
    { event: 'add', id: 'B2', round: 1, reviewer: 'be-opus-high', severity: 'LOW', summary: 'x', ts: '2026-10-31T19:21:00+01:00' },
    { event: 'close', id: 'B1', ts: '2026-10-31T20:00:00+01:00' },
  ]))
  putFile(join(ezRoot, id), 'brief-r3.md', `# brief ${MARKER}\n`)
  putFile(join(ezRoot, id), 'brief-r4.md', 'x')
  const dir = join(depRoot, id)
  putFile(dir, 'deploy-20261031-200000-check.log', `base=4617a805aaaa tip=9d75d5e0bbbb files=6 branch=b head=h\nsrc/${MARKER}.ts\nCHECK OK: ${MARKER}\n`)
  putFile(dir, 'deploy-20261031-203000-check.log', 'base=4617a805aaaa tip=9d75d5e0bbbb files=6 branch=b head=h\nCHECK OK: fine\n')
  putFile(dir, 'deploy-20261031-210000-apply.log', 'base=4617a805aaaa tip=9d75d5e0bbbb files=6 branch=b head=h\nAPPLY OK: done\n')
}

beforeEach(() => {
  initDatabase(':memory:')
  base = mkdtempSync(join(tmpdir(), 'ivek-route-'))
  ezRoot = join(base, 'ez')
  depRoot = join(base, 'dep')
  mkdirSync(ezRoot)
  mkdirSync(depRoot)
  gitCalls = 0
  gitStdout = ''
  setIvekServiceForTest(makeService())
})
afterEach(() => {
  setIvekServiceForTest(null)
  rmSync(base, { recursive: true, force: true })
})

describe('derivePhase', () => {
  it('no signal: nincs_jel', () => {
    expect(derivePhase(NO_SIGNALS)).toEqual({ phase: 'nincs_jel', round: null, since: null })
  })
  it('every branch, furthest wins, since is the trigger time', () => {
    expect(derivePhase({ ...NO_SIGNALS, briefAt: 10 })).toEqual({ phase: 'brief', round: null, since: 10 })
    expect(derivePhase({ ...NO_SIGNALS, briefAt: 10, commitAt: 20 })).toEqual({ phase: 'vegrehajtas', round: null, since: 20 })
    expect(derivePhase({ ...NO_SIGNALS, commitAt: 20, reviewRound: 2, reviewAt: 30 })).toEqual({ phase: 'review', round: 2, since: 30 })
    expect(derivePhase({ ...NO_SIGNALS, reviewRound: 2, reviewAt: 30, checkAt: 40 })).toEqual({ phase: 'deploy_jelolt', round: null, since: 40 })
    expect(derivePhase({ ...NO_SIGNALS, checkAt: 40, applyAt: 50 })).toEqual({ phase: 'elesitve', round: null, since: 50 })
  })
})

describe('list', () => {
  it('filters: three assignees in, others out, archived out, done 14 days in / 15 days out, case-insensitive assignee', async () => {
    addCard('aaaaaaa1', { assignee: 'ezermester' })
    addCard('aaaaaaa2', { assignee: 'Fejleszto' })
    addCard('aaaaaaa3', { assignee: 'lapszabasz', status: 'waiting' })
    addCard('aaaaaaa4', { assignee: 'iroda' })
    addCard('aaaaaaa5', { assignee: null })
    addCard('aaaaaaa6', { archived: NOW_S - DAY })
    addCard('aaaaaaa7', { status: 'done', updated: NOW_S - 13 * DAY })
    addCard('aaaaaaa8', { status: 'done', updated: NOW_S - 15 * DAY })
    const r = call('/api/ivek')
    expect(await tryHandleIvek(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    const ids = r.out.body.ivek.map((i: any) => i.id).sort()
    expect(ids).toEqual(['aaaaaaa1', 'aaaaaaa2', 'aaaaaaa3', 'aaaaaaa7'])
    expect(Object.keys(r.out.body.ivek[0]).sort()).toEqual(['assignee', 'id', 'phase', 'status', 'title'])
    expect(Object.keys(r.out.body.ivek[0].phase).sort()).toEqual(['phase', 'round', 'since'])
  })

  it('one git read for the whole list, however many cards (exec-spy)', async () => {
    for (let i = 1; i <= 5; i++) addCard(`bbbbbbb${i}`)
    gitStdout = gitRow('c0ffee01', NOW_S - 100, 'feat: x (card bbbbbbb1)')
    const r = call('/api/ivek')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
    expect(gitCalls).toBe(1)
    const withCommit = r.out.body.ivek.find((i: any) => i.id === 'bbbbbbb1')
    expect(withCommit.phase.phase).toBe('vegrehajtas')
  })

  it('the phase comes from the files: 51538ebc-shaped arc is elesitve; a card without any signal is nincs_jel', async () => {
    addCard('51538ebc')
    addCard('dddddddd')
    seedArc()
    const r = call('/api/ivek')
    await tryHandleIvek(r.ctx)
    const arc = r.out.body.ivek.find((i: any) => i.id === '51538ebc')
    expect(arc.phase.phase).toBe('elesitve')
    expect(arc.phase.since).toBe(Date.parse('2026-10-31T21:00:00') / 1000)
    expect(r.out.body.ivek.find((i: any) => i.id === 'dddddddd').phase.phase).toBe('nincs_jel')
  })

  it('K4: an upper-case kanban id is listed, its file and git signals are nincs adat (nincs_jel)', async () => {
    addCard('ABCDEF12')
    mkdirSync(join(ezRoot, 'abcdef12'))
    writeFileSync(join(ezRoot, 'abcdef12', 'brief-x.md'), 'x')
    gitStdout = gitRow('c0ffee02', NOW_S - 100, 'feat: y (card abcdef12)')
    const r = call('/api/ivek')
    await tryHandleIvek(r.ctx)
    expect(r.out.body.ivek[0]).toMatchObject({ id: 'ABCDEF12', phase: { phase: 'nincs_jel' } })
  })

  it('git failure does not break the list', async () => {
    addCard('eeeeeee1')
    gitStdout = new Error('boom /Users/x')
    const r = call('/api/ivek')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
    expect(r.out.body.ivek).toHaveLength(1)
  })
})

describe('detail', () => {
  it('51538ebc-shaped arc: events, briefs, reviews (close joins its round), commits, deploys, children, phase', async () => {
    addCard('51538ebc', { title: 'Import gate' })
    addCard('11111111', { parent: '51538ebc', status: 'done', title: 'child a' })
    addCard('22222222', { parent: '51538ebc', status: 'planned', title: 'child b' })
    addEvent('51538ebc', null, 'planned', NOW_S - 5 * DAY)
    addEvent('51538ebc', 'planned', 'in_progress', NOW_S - 4 * DAY, 'ezermester')
    gitStdout = gitRow('aaaa1111', NOW_S - 3 * DAY, 'feat(x): first (card 51538ebc)') + gitRow('bbbb2222', NOW_S - 2 * DAY, 'fix: second', 'card 51538ebc r2') + gitRow('cccc3333', NOW_S - DAY, 'chore: other (card 99999999)')
    seedArc()
    const r = call('/api/ivek/51538ebc')
    expect(await tryHandleIvek(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    const b = r.out.body
    expect(b).toMatchObject({ id: '51538ebc', title: 'Import gate', status: 'in_progress', assignee: 'ezermester', phase: { phase: 'elesitve' } })
    expect(b.events.map((e: any) => e.to_status)).toEqual(['planned', 'in_progress'])
    expect(Object.keys(b.events[0]).sort()).toEqual(['actor', 'created_at', 'from_status', 'to_status'])
    expect(b.briefs.ok).toBe(true)
    expect(b.briefs.files.map((f: any) => f.name)).toEqual(['brief-r3.md', 'brief-r4.md'])
    expect(b.reviews.ok).toBe(true)
    expect(b.reviews.events).toEqual({ add: 2, close: 1, reject: 0 })
    expect(b.reviews.rounds).toHaveLength(1)
    expect(b.reviews.rounds[0]).toMatchObject({ round: 1, reviewer: 'be-opus-high', add: 2, close: 1 })
    expect(b.commits).toEqual({ ok: true, commits: [
      { hash: 'aaaa1111', date: NOW_S - 3 * DAY, subject: 'feat(x): first (card 51538ebc)' },
      { hash: 'bbbb2222', date: NOW_S - 2 * DAY, subject: 'fix: second' },
    ] })
    expect(b.deploys.ok).toBe(true)
    expect(b.deploys.runs.map((x: any) => x.mode)).toEqual(['check', 'check', 'apply'])
    expect(b.deploys.runs[2]).toMatchObject({ base: '4617a805', tip: '9d75d5e0', files: 6, result: 'ok' })
    expect(b.children.map((c: any) => c.id).sort()).toEqual(['11111111', '22222222'])
  })

  it('markers in summary/reason/location, deploy file list and status line, and a brief body never reach the response', async () => {
    addCard('51538ebc')
    seedArc()
    const r = call('/api/ivek/51538ebc')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
    expect(r.out.raw).not.toContain(MARKER)
    const l = call('/api/ivek')
    await tryHandleIvek(l.ctx)
    expect(l.out.raw).not.toContain(MARKER)
  })

  it('no absolute path or root name anywhere in a success answer', async () => {
    addCard('51538ebc')
    seedArc()
    const r = call('/api/ivek/51538ebc')
    await tryHandleIvek(r.ctx)
    expect(r.out.raw).not.toContain(base)
    for (const s of ['/Volumes', '/Users', '_ezermester', '_brainy-deploy', tmpdir()]) expect(r.out.raw).not.toContain(s)
  })

  it('E5: missing folders and logs -> 200, those blocks are { ok: false, reason }, the card and the other blocks work', async () => {
    addCard('51538ebc', { title: 'Alone' })
    addEvent('51538ebc', null, 'planned', NOW_S - DAY)
    rmSync(ezRoot, { recursive: true })
    rmSync(depRoot, { recursive: true })
    gitStdout = gitRow('aaaa1111', NOW_S - DAY, 'feat: z (card 51538ebc)')
    const r = call('/api/ivek/51538ebc')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
    for (const k of ['briefs', 'reviews', 'deploys']) {
      expect(r.out.body[k].ok).toBe(false)
      expect(r.out.body[k].reason).toMatch(/^[a-z_]+$/)
    }
    expect(r.out.body.commits.ok).toBe(true)
    expect(r.out.body.events).toHaveLength(1)
    expect(r.out.body.phase.phase).toBe('vegrehajtas')
  })

  it('git failure and git timeout -> commits block is a gap, the rest stays', async () => {
    addCard('51538ebc')
    seedArc()
    for (const err of [new Error('boom'), Object.assign(new Error('t'), { killed: true, signal: 'SIGTERM' })]) {
      setIvekServiceForTest(makeService({ git: createGitLogReader({ exec: fakeExec, now: () => 0 }) }))
      gitStdout = err
      const r = call('/api/ivek/51538ebc')
      await tryHandleIvek(r.ctx)
      expect(r.out.status).toBe(200)
      expect(r.out.body.commits.ok).toBe(false)
      expect(r.out.body.commits.reason).toMatch(/^git_(failed|timeout)$/)
      expect(r.out.raw).not.toContain('boom')
      expect(r.out.body.briefs.ok).toBe(true)
      expect(r.out.body.reviews.ok).toBe(true)
      expect(r.out.body.phase.phase).toBe('elesitve')
    }
  })

  it('a throwing source or an unresolved repo is a gap, not a 500', async () => {
    addCard('51538ebc')
    const thrower = () => { throw new Error('/Volumes/secret') }
    setIvekServiceForTest(makeService({ repo: () => null, sources: { findings: thrower, briefs: thrower, deploys: thrower } }))
    const r = call('/api/ivek/51538ebc')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
    expect(r.out.body.commits).toEqual({ ok: false, reason: 'repo_missing' })
    expect(r.out.body.reviews).toEqual({ ok: false, reason: 'unreadable' })
    expect(r.out.raw).not.toContain('/Volumes')
  })

  it('a rollback after the apply takes the card back to deploy_jelolt', async () => {
    addCard('51538ebc')
    seedArc()
    putFile(join(depRoot, '51538ebc'), 'deploy-20261031-220000-rollback.log', 'base=4617a805aaaa tip=9d75d5e0bbbb files=6 branch=b head=h\nROLLBACK OK: back\n')
    const r = call('/api/ivek/51538ebc')
    await tryHandleIvek(r.ctx)
    expect(r.out.body.phase.phase).toBe('deploy_jelolt')
  })

  it('unknown kanban card -> 404', async () => {
    const r = call('/api/ivek/deadbeef')
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(404)
  })

  it('reading writes nothing to the board', async () => {
    addCard('51538ebc')
    addCard('aaaaaaa1')
    addEvent('51538ebc', null, 'planned', NOW_S - DAY)
    seedArc()
    const snap = () => JSON.stringify([
      getDb().prepare('SELECT * FROM kanban_cards ORDER BY id').all(),
      getDb().prepare('SELECT * FROM kanban_card_events ORDER BY id').all(),
    ])
    const before = snap()
    for (const p of ['/api/ivek', '/api/ivek/51538ebc']) await tryHandleIvek(call(p).ctx)
    expect(snap()).toBe(before)
  })
})

describe('id fences (E6): 404 with no file system access', () => {
  it.each([
    '/api/ivek/..',
    '/api/ivek/%2e%2e',
    '/api/ivek/%2E%2E',
    '/api/ivek/51538ebc%2f..',
    '/api/ivek/..%2f..%2fetc',
    '/api/ivek/ABCDEF12',
    '/api/ivek/51538EBC',
    '/api/ivek/1234567',
    '/api/ivek/123456789',
    '/api/ivek/%00',
    '/api/ivek/5153%008ebc',
    '/api/ivek/%E0%A4%A',
    '/api/ivek/51538ebg',
  ])('%s', async (p) => {
    const card = vi.fn()
    const sources = { findings: vi.fn(), briefs: vi.fn(), deploys: vi.fn() }
    setIvekServiceForTest(makeService({ card, sources: sources as never }))
    const r = call('/api/ivek')
    r.ctx.path = p
    expect(await tryHandleIvek(r.ctx)).toBe(true)
    expect(r.out.status).toBe(404)
    expect(r.out.body).toEqual({ error: 'Not found' })
    expect(card).not.toHaveBeenCalled()
    expect(sources.findings).not.toHaveBeenCalled()
    expect(sources.briefs).not.toHaveBeenCalled()
    expect(sources.deploys).not.toHaveBeenCalled()
  })
})

describe('routing', () => {
  it('other paths fall through', async () => {
    for (const p of ['/api/ivek-x', '/api/ivekx', '/api/ivek/a/b', '/api/ivek/', '/api/other', '/api/funkciok']) {
      const r = call(p)
      r.ctx.path = p
      expect(await tryHandleIvek(r.ctx)).toBe(false)
    }
  })

  it('responses are not cacheable', async () => {
    const r = call('/api/ivek')
    await tryHandleIvek(r.ctx)
    expect(r.out.headers['Cache-Control']).toBe('private, no-store')
  })

  it('an internal failure is a 500 with a fixed body, no message, no path', async () => {
    const failing: IvekService = { list: async () => { throw new Error('/Users/x/secret') }, detail: async () => { throw new Error('/Volumes/y') } }
    setIvekServiceForTest(failing)
    for (const p of ['/api/ivek', '/api/ivek/51538ebc']) {
      const r = call(p)
      await tryHandleIvek(r.ctx)
      expect(r.out.status).toBe(500)
      expect(r.out.body).toEqual({ error: 'Internal error' })
    }
  })
})

describe('E9: authentication, method, scope', () => {
  const paths = ['/api/ivek', '/api/ivek/51538ebc']

  it('only GET: POST, PUT, PATCH, DELETE are 405 with Allow, and the service is not reached', async () => {
    const stub = { list: vi.fn(), detail: vi.fn() }
    setIvekServiceForTest(stub as unknown as IvekService)
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      for (const p of paths) {
        const r = call(p, { method })
        expect(await tryHandleIvek(r.ctx)).toBe(true)
        expect(r.out.status).toBe(405)
        expect(r.out.headers.Allow).toBe('GET')
      }
    }
    expect(stub.list).not.toHaveBeenCalled()
    expect(stub.detail).not.toHaveBeenCalled()
  })

  it('no principal: 401; operator-scoped device key: 403; federation peer: 403; service not reached', async () => {
    const stub = { list: vi.fn(), detail: vi.fn() }
    setIvekServiceForTest(stub as unknown as IvekService)
    for (const p of paths) {
      let r = call(p, { auth: null })
      expect(await tryHandleIvek(r.ctx)).toBe(true)
      expect(r.out.status).toBe(401)
      r = call(p, { auth: { kind: 'device', device: 'op', deviceId: 1, scope: 'operator' } })
      await tryHandleIvek(r.ctx)
      expect(r.out.status).toBe(403)
      r = call(p, { auth: { kind: 'federation', peer: 'p' } })
      await tryHandleIvek(r.ctx)
      expect(r.out.status).toBe(403)
    }
    expect(stub.list).not.toHaveBeenCalled()
    expect(stub.detail).not.toHaveBeenCalled()
  })

  it.each([
    ['dashboard token', { kind: 'token' }],
    ['browser session', { kind: 'session', user: 'owner' }],
    ['full-scope device key', { kind: 'device', device: 'phone', deviceId: 2, scope: 'full' }],
  ] as [string, Auth][])('allowed: %s', async (_l, auth) => {
    const r = call('/api/ivek', { auth })
    await tryHandleIvek(r.ctx)
    expect(r.out.status).toBe(200)
  })

  it('the dashboard gate needs auth on /api/ivek*, the operator gate refuses an operator key there', () => {
    for (const p of ['/api/ivek', '/api/ivek/51538ebc']) {
      expect(requiresAuth(p, 'GET')).toBe(true)
      expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, p, () => ({ enabled: true, capabilities: {} as never, commands: [] }))).toBe('operator credential: not an operator endpoint')
      expect(operatorGateDecision({ kind: 'token' }, p, () => { throw new Error('must not read access for a token') })).toBeNull()
    }
  })

  it('wiring pin: web.ts routes /api/ivek through tryHandleIvek', () => {
    const src = readFileSync(join(__dirname, '..', 'web.ts'), 'utf8')
    expect(src).toContain("import { tryHandleIvek } from './web/routes/ivek.js'")
    expect(src).toContain('if (await tryHandleIvek(routeCtx)) return')
  })
})
