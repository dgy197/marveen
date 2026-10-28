import type http from 'node:http'
import { parseCookies, SESSION_COOKIE_NAME } from './auth-gate.js'
import { resolveSession } from './auth-sessions.js'
import type { RouteContext } from './routes/types.js'

// Browser writes carry BOTH the stored Bearer token (the SPA fetch wrapper adds
// it to every /api/ call) and, after a dashboard login, the mv_session cookie.
// The auth gate resolves the Bearer first, so such a request arrives as
// kind:'token' and the session is invisible to a route (the S2-M1 finding).
//
// This helper looks at the owner session cookie ONLY (never the operator
// cookie, never a first-run exception -- unlike mayIssueCredentials, which
// accepts the bare token while no dashboard user exists). A valid, unexpired,
// unrevoked session is the proof; the token and its self-asserted X-Agent-Id
// claim are irrelevant once it is present.

type Auth = RouteContext['auth']

/** The valid owner session behind the request's cookie, or null. */
export function ownerSessionFromCookie(req: http.IncomingMessage | undefined): { username: string } | null {
  const cookie = req ? parseCookies(req.headers?.cookie)[SESSION_COOKIE_NAME] : undefined
  if (!cookie) return null
  const s = resolveSession(cookie)
  return s ? { username: s.username } : null
}

/**
 * kind:'token' + a valid session cookie becomes kind:'session' (the browser
 * write of the logged-in owner); everything else is returned unchanged. No
 * cookie means no DB access.
 */
export function upgradeTokenToSession(auth: Auth, req: http.IncomingMessage | undefined): Auth {
  if (auth?.kind !== 'token') return auth
  const s = ownerSessionFromCookie(req)
  return s ? { kind: 'session', user: s.username } : auth
}
