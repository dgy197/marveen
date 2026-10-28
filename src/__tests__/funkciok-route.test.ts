import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { requiresAuth } from '../web/auth-gate.js'
import { operatorGateDecision } from '../web/operator-gate.js'
import { setFunkciokServiceForTest, tryHandleFunkciok } from '../web/routes/funkciok.js'
import type { FunkciokService } from '../web/funkciok-page.js'
import type { RouteContext } from '../web/routes/types.js'

// Function page (S1): the HTTP surface of the function page. Routing, method,
// slug and id fences, and the auth answers (S1-6): 401 without a principal,
// 403 for an operator-scoped key. The service behind is a stub here; its own
// behaviour is covered in funkciok-page.test.ts.

type Auth = RouteContext['auth']

function call(pathAndQuery: string, opts: { method?: string; auth?: Auth | null } = {}): { ctx: RouteContext; out: { status: number; body: any; headers: Record<string, unknown> } } {
  const out: { status: number; body: any; headers: Record<string, unknown> } = { status: 0, body: null, headers: {} }
  const res: any = {
    writeHead(status: number, headers?: Record<string, unknown>) { out.status = status; out.headers = headers ?? {}; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const url = new URL(`http://localhost:3420${pathAndQuery}`)
  const auth = opts.auth === undefined ? ({ kind: 'token' } as Auth) : (opts.auth ?? undefined)
  return { ctx: { req: {} as any, res, path: url.pathname, method: opts.method ?? 'GET', url, auth } as RouteContext, out }
}

let stub: { list: ReturnType<typeof vi.fn>; page: ReturnType<typeof vi.fn>; message: ReturnType<typeof vi.fn> }

beforeEach(() => {
  stub = {
    list: vi.fn(async () => [{ slug: 'charlie-feature', nev: 'Charlie feature', last_change: 1, open_cards: 0 }]),
    page: vi.fn(async (slug: string) => (slug === 'charlie-feature'
      ? { kind: 'ok', page: { slug } }
      : slug === 'broken' ? { kind: 'invalid', slug, error: 'invalid JSON' } : { kind: 'not_found' })),
    message: vi.fn(async (_slug: string, id: number) => (id === 7 ? { kind: 'ok', message: { id: 7 } } : { kind: 'not_found' })),
  }
  setFunkciokServiceForTest(stub as unknown as FunkciokService)
})
afterEach(() => { setFunkciokServiceForTest(null) })

describe('routing', () => {
  it('GET /api/funkciok lists, GET /api/funkciok/:slug answers the page, GET .../messages/:id the D3 text', async () => {
    let r = call('/api/funkciok')
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(r.out.body.funkciok[0].slug).toBe('charlie-feature')

    r = call('/api/funkciok/charlie-feature')
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(r.out.body.slug).toBe('charlie-feature')

    r = call('/api/funkciok/charlie-feature/messages/7')
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(200)
    expect(stub.message).toHaveBeenCalledWith('charlie-feature', 7)
  })

  it('responses are not cacheable', async () => {
    const r = call('/api/funkciok')
    await tryHandleFunkciok(r.ctx)
    expect(r.out.headers['Cache-Control']).toBe('private, no-store')
  })

  it('unknown slug and unknown message id are 404; an invalid registry file is 422 with the reason', async () => {
    let r = call('/api/funkciok/nincs-ilyen')
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(404)
    r = call('/api/funkciok/charlie-feature/messages/8')
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(404)
    r = call('/api/funkciok/broken')
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(422)
    expect(r.out.body).toMatchObject({ slug: 'broken', reason: 'invalid JSON' })
  })

  it('other paths fall through (return false)', async () => {
    for (const p of ['/api/funkciok-x', '/api/funkciokok', '/api/other', '/api/funkciok/a/b', '/api/funkciok/a/messages', '/api/funkciok/a/messages/1/2']) {
      expect(await tryHandleFunkciok(call(p).ctx)).toBe(false)
    }
  })

  it('only GET: POST, PUT and DELETE are 405 with an Allow header, and reach no service', async () => {
    for (const method of ['POST', 'PUT', 'DELETE', 'PATCH']) {
      for (const p of ['/api/funkciok', '/api/funkciok/charlie-feature', '/api/funkciok/charlie-feature/messages/7']) {
        const r = call(p, { method })
        expect(await tryHandleFunkciok(r.ctx)).toBe(true)
        expect(r.out.status).toBe(405)
        expect(r.out.headers.Allow).toBe('GET')
      }
    }
    expect(stub.list).not.toHaveBeenCalled()
    expect(stub.page).not.toHaveBeenCalled()
    expect(stub.message).not.toHaveBeenCalled()
  })
})

describe('slug and id fences', () => {
  it.each([
    '/api/funkciok/..',
    '/api/funkciok/%2e%2e',
    '/api/funkciok/%2E%2E',
    '/api/funkciok/..%2fetc',
    '/api/funkciok/%2e%2e%2f%2e%2e%2fetc%2fpasswd',
    '/api/funkciok/UPPER',
    '/api/funkciok/a%20b',
    '/api/funkciok/%00',
    '/api/funkciok/%E0%A4%A',
    '/api/funkciok/-start',
    `/api/funkciok/${'a'.repeat(65)}`,
  ])('page: %s is a 404 and never reaches the service', async (p) => {
    const r = call(p)
    // `new URL` may normalise dot segments; build the context path by hand too.
    r.ctx.path = p
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(404)
    expect(stub.page).not.toHaveBeenCalled()
  })

  it.each([
    '/api/funkciok/charlie-feature/messages/abc',
    '/api/funkciok/charlie-feature/messages/-1',
    '/api/funkciok/charlie-feature/messages/1.5',
    '/api/funkciok/charlie-feature/messages/1e3',
    '/api/funkciok/charlie-feature/messages/0x10',
    '/api/funkciok/charlie-feature/messages/1%20OR%201=1',
    '/api/funkciok/charlie-feature/messages/12345678901234567890',
    '/api/funkciok/..%2f/messages/7',
    '/api/funkciok/%2e%2e/messages/7',
  ])('message: %s is a 404 and never reaches the service', async (p) => {
    const r = call('/api/funkciok')
    r.ctx.path = p
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(404)
    expect(stub.message).not.toHaveBeenCalled()
  })
})

describe('S1-6: authentication and credential scope', () => {
  const paths = ['/api/funkciok', '/api/funkciok/charlie-feature', '/api/funkciok/charlie-feature/messages/7']

  it('no principal: 401 on every route, and the service is not reached', async () => {
    for (const p of paths) {
      const r = call(p, { auth: null })
      expect(await tryHandleFunkciok(r.ctx)).toBe(true)
      expect(r.out.status).toBe(401)
    }
    expect(stub.list).not.toHaveBeenCalled()
    expect(stub.page).not.toHaveBeenCalled()
    expect(stub.message).not.toHaveBeenCalled()
  })

  it('an operator-scoped device key: 403 on every route', async () => {
    for (const p of paths) {
      const r = call(p, { auth: { kind: 'device', device: 'op', deviceId: 1, scope: 'operator' } })
      expect(await tryHandleFunkciok(r.ctx)).toBe(true)
      expect(r.out.status).toBe(403)
    }
    expect(stub.list).not.toHaveBeenCalled()
    expect(stub.page).not.toHaveBeenCalled()
  })

  it('a federation peer token is refused too (it is valid on two wire endpoints only)', async () => {
    const r = call('/api/funkciok', { auth: { kind: 'federation', peer: 'p' } })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(403)
  })

  it.each([
    ['dashboard token', { kind: 'token' }],
    ['token with an agent claim', { kind: 'token', agent: 'agent-b' }],
    ['browser session', { kind: 'session', user: 'owner' }],
    ['full-scope device key', { kind: 'device', device: 'phone', deviceId: 2, scope: 'full' }],
  ] as [string, Auth][])('allowed: %s', async (_label, auth) => {
    const r = call('/api/funkciok', { auth })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(200)
  })

  it('the dashboard gate itself: /api/funkciok* needs auth, and the operator gate denies an operator key there', () => {
    for (const p of ['/api/funkciok', '/api/funkciok/x', '/api/funkciok/x/messages/1']) {
      expect(requiresAuth(p, 'GET')).toBe(true)
      expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, p, () => ({ enabled: true, capabilities: {} as never, commands: [] }))).toBe('operator credential: not an operator endpoint')
      // every other credential passes the operator gate untouched
      expect(operatorGateDecision({ kind: 'token' }, p, () => { throw new Error('must not read access for a token') })).toBeNull()
      expect(operatorGateDecision({ kind: 'device', scope: 'full' }, p, () => { throw new Error('must not read access') })).toBeNull()
    }
  })
})

describe('R1-6: wiring in web.ts', () => {
  it('web.ts routes /api/funkciok through tryHandleFunkciok inside the route chain', () => {
    // Source pin, like commands-dispatch-route: the dispatcher lives inside
    // startWebServer, which a unit test cannot drive.
    const web = readFileSync(join(__dirname, '..', 'web.ts'), 'utf-8')
    const code = web.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')
    expect(code).toMatch(/^\s*if \(await tryHandleFunkciok\(routeCtx\)\) return$/m)
    expect(code).toMatch(/import \{[^}]*\btryHandleFunkciok\b[^}]*\} from '\.\/web\/routes\/funkciok\.js'/)
    // after the auth handler resolved, i.e. inside the authenticated chain
    expect(code.indexOf('if (await tryHandleFunkciok(routeCtx)) return')).toBeGreaterThan(code.indexOf('if (await tryHandleAuth(routeCtx)) return'))
  })
})
