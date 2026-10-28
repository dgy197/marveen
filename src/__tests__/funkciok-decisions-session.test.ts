import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { Readable } from 'node:stream'
import { initDatabase, createDashboardUser } from '../db.js'
import { createSession, revokeSession, _clearSessionCacheForTest } from '../web/auth-sessions.js'
import { setFunkciokServiceForTest, tryHandleFunkciok } from '../web/routes/funkciok.js'
import { upgradeTokenToSession } from '../web/owner-session.js'
import type { FunkciokService } from '../web/funkciok-page.js'
import type { RouteContext } from '../web/routes/types.js'

// S2-M1: a browser decision write carries the stored Bearer token AND the
// session cookie. The gate resolves the Bearer first (kind:'token'), so the
// write used to be recorded as recorded_via='token'. The route now resolves
// the cookie itself: a valid owner session makes it recorded_via='session'.

type Auth = RouteContext['auth']
const P = '/api/funkciok/charlie-feature/decisions'
const goodBody = JSON.stringify({ quote_short: 'igen', tg_msg_id: '1' })

let recordDecision: ReturnType<typeof vi.fn>

function reqWith(cookie?: string) {
  return Object.assign(Readable.from([Buffer.from(goodBody)]), { headers: cookie ? { cookie } : {} as Record<string, string> })
}

async function post(auth: Auth | null, cookie?: string): Promise<number> {
  let status = 0
  const res: any = { writeHead(s: number) { status = s; return res }, end() { /* body not needed */ } }
  const url = new URL(`http://localhost:3420${P}`)
  const ctx = { req: reqWith(cookie) as any, res, path: url.pathname, method: 'POST', url, auth: auth ?? undefined } as RouteContext
  expect(await tryHandleFunkciok(ctx)).toBe(true)
  return status
}

function login(name = 'tulaj-teszt'): string {
  const u = createDashboardUser(name, '$scrypt$ln=16,r=8,p=1$c2FsdA==$a2V5')
  return createSession({ userId: u.id, username: u.username })
}

beforeEach(() => {
  initDatabase(':memory:')
  _clearSessionCacheForTest()
  recordDecision = vi.fn(async () => ({ kind: 'ok', decision: { id: 2 } }))
  setFunkciokServiceForTest({ recordDecision } as unknown as FunkciokService)
})
afterEach(() => { setFunkciokServiceForTest(null) })

describe('S2-M1: token + session cookie is recorded as a session write', () => {
  it('token + valid session cookie -> actor via session (by session:<user>), the X-Agent-Id claim is not used', async () => {
    const cookie = login()
    expect(await post({ kind: 'token', agent: 'agent-b' }, `mv_session=${cookie}`)).toBe(201)
    expect(recordDecision).toHaveBeenCalledWith('charlie-feature', goodBody, { via: 'session', by: 'session:tulaj-teszt' })
  })

  it('the bare token (no cookie, or a bad / revoked / foreign-named cookie) stays a token write', async () => {
    const live = login('tulaj-teszt')
    const revoked = login('masik-teszt')
    revokeSession(revoked)
    expect(await post({ kind: 'token', agent: 'agent-b' })).toBe(201)
    expect(await post({ kind: 'token' }, 'mv_session=nincs-ilyen')).toBe(201)
    expect(await post({ kind: 'token' }, `mv_session=${revoked}`)).toBe(201)
    expect(await post({ kind: 'token' }, `mv_operator=${live}`)).toBe(201)
    expect(recordDecision.mock.calls.map((c) => c[2])).toEqual([
      { via: 'token', by: 'agent-b' }, { via: 'token', by: 'token' }, { via: 'token', by: 'token' }, { via: 'token', by: 'token' },
    ])
  })

  it('device full and a gate-resolved session are unchanged; a cookie never upgrades operator or federation', async () => {
    const cookie = login()
    expect(await post({ kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'full' }, `mv_session=${cookie}`)).toBe(201)
    expect(await post({ kind: 'session', user: 'tulaj-teszt' })).toBe(201)
    expect(await post({ kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'operator' }, `mv_session=${cookie}`)).toBe(403)
    expect(await post({ kind: 'federation', peer: 'teszt-peer' }, `mv_session=${cookie}`)).toBe(403)
    expect(await post(null, `mv_session=${cookie}`)).toBe(401)
    expect(recordDecision.mock.calls.map((c) => c[2])).toEqual([
      { via: 'device', by: 'device:teszt-telefon' }, { via: 'session', by: 'session:tulaj-teszt' },
    ])
  })

  it('upgradeTokenToSession returns a token without a cookie, no principal and a non-token auth unchanged', () => {
    expect(upgradeTokenToSession({ kind: 'token' }, { headers: {} } as any)).toEqual({ kind: 'token' })
    expect(upgradeTokenToSession(undefined, { headers: { cookie: 'mv_session=x' } } as any)).toBeUndefined()
    const s: Auth = { kind: 'session', user: 'u' }
    expect(upgradeTokenToSession(s, { headers: { cookie: 'mv_session=x' } } as any)).toBe(s)
  })
})
