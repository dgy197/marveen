import { join } from 'node:path'
import { PROJECT_ROOT, STORE_DIR } from '../../config.js'
import { getEffectiveSettingValue } from '../../settings-store.js'
import { RequestBodyTooLargeError, json, methodNotAllowed, readBody } from '../http-helpers.js'
import { DECISION_BODY_MAX_BYTES, decisionActor } from '../funkciok-decisions.js'
import { createGitLogReader } from '../funkciok-git.js'
import { createFunkciokService, type FunkciokService } from '../funkciok-page.js'
import { SLUG_RE, resolveAllowedRepos } from '../funkciok-registry.js'
import type { RouteContext } from './types.js'

// Function page (S1): GET-only, read-only function pages for the dashboard tab
// "Fejlesztes > Funkciok".
//
//   GET /api/funkciok                       list
//   GET /api/funkciok/:slug                 the assembled page
//   GET /api/funkciok/:slug/messages/:id    full text of one inter-agent message
//                                           that is on THAT function's page (D3)
//   GET  /api/funkciok/:slug/decisions      (S2-A) the append-only decision log
//   POST /api/funkciok/:slug/decisions      (S2-A) append one decision; no PUT/PATCH/DELETE
//
// Auth is the dashboard gate's (web.ts: 401 without a principal, 403 for an
// operator-scoped key, which reaches /api/operator/* only). The handler repeats
// the two checks: a route added to this module later stays closed even if the
// gate's wiring changes.

/** Name of the setting that extends the repo allowlist beyond the install root. */
export const FUNKCIO_ALLOWLIST_SETTING = 'FUNKCIO_REPO_ALLOWLIST'

function readAllowlistSetting(): string {
  try {
    return String(getEffectiveSettingValue(FUNKCIO_ALLOWLIST_SETTING) ?? '')
  } catch {
    return '' // unreadable setting -> install root only (narrow)
  }
}

let service: FunkciokService | null = null

function getService(): FunkciokService {
  if (!service) {
    service = createFunkciokService({
      registryDir: join(STORE_DIR, 'funkciok'),
      // Resolved per request: the setting is hot-reloadable and a repo may be
      // swapped for a symlink between two requests.
      getAllowedRepos: () => resolveAllowedRepos(PROJECT_ROOT, readAllowlistSetting()),
      git: createGitLogReader(),
    })
  }
  return service
}

/** Test seam: swap the service (temp registry dir, fake execFile). null restores the default. */
export function setFunkciokServiceForTest(s: FunkciokService | null): void {
  service = s
}

const LIST_PATH = '/api/funkciok'
const PAGE_RE = /^\/api\/funkciok\/([^/]+)$/
const MSG_RE = /^\/api\/funkciok\/([^/]+)\/messages\/([^/]+)$/
const DECISIONS_RE = /^\/api\/funkciok\/([^/]+)\/decisions$/

function decodeSlug(raw: string): string | null {
  let s: string
  try { s = decodeURIComponent(raw) } catch { return null }
  return SLUG_RE.test(s) ? s : null
}

/** null = let the request through, else the status to answer with. */
function denied(ctx: RouteContext): number | null {
  const a = ctx.auth
  if (!a) return 401
  if (a.kind === 'device' && a.scope === 'operator') return 403
  if (a.kind === 'federation') return 403
  return null
}

export async function tryHandleFunkciok(ctx: RouteContext): Promise<boolean> {
  const { res, path, method } = ctx
  if (path !== LIST_PATH && !path.startsWith(`${LIST_PATH}/`)) return false

  const msgMatch = MSG_RE.exec(path)
  const pageMatch = PAGE_RE.exec(path)
  const decMatch = DECISIONS_RE.exec(path)
  if (path !== LIST_PATH && !msgMatch && !pageMatch && !decMatch) return false

  // The decision log is the only write surface here, and only POST appends.
  const allowed = decMatch ? ['GET', 'POST'] : ['GET']
  if (!allowed.includes(method)) {
    methodNotAllowed(res, method, allowed)
    return true
  }
  const status = denied(ctx)
  if (status !== null) {
    json(res, { error: status === 401 ? 'Unauthorized' : 'Forbidden for this credential' }, status)
    return true
  }

  const svc = getService()

  if (decMatch) {
    const slug = decodeSlug(decMatch[1])
    if (!slug) { json(res, { error: 'Not found' }, 404); return true }

    if (method === 'GET') {
      const r = await svc.decisions(slug)
      if (r.kind === 'ok') json(res, { decisions: r.decisions })
      else if (r.kind === 'invalid') json(res, { error: 'Invalid registry file', slug: r.slug, reason: r.error }, 422)
      else json(res, { error: 'Not found' }, 404)
      return true
    }

    // POST. Spec 5.1: token (attributed to X-Agent-Id), device full and session
    // write; operator and federation were refused above. A cross-origin browser
    // write never gets here (web.ts: isBlockedCrossOriginWrite, before routing).
    const actor = decisionActor(ctx.auth)
    if (!actor) { json(res, { error: 'Forbidden for this credential' }, 403); return true }
    const declared = Number(ctx.req.headers?.['content-length'])
    if (Number.isFinite(declared) && declared > DECISION_BODY_MAX_BYTES) { json(res, { error: 'body_too_large' }, 413); return true }
    let text: string
    try {
      text = (await readBody(ctx.req, { maxBytes: DECISION_BODY_MAX_BYTES })).toString('utf8')
    } catch (err) {
      if (err instanceof RequestBodyTooLargeError) { json(res, { error: 'body_too_large' }, 413); return true }
      json(res, { error: 'Bad request' }, 400)
      return true
    }
    const r = await svc.recordDecision(slug, text, actor)
    switch (r.kind) {
      case 'ok': json(res, r.decision, 201); break
      case 'bad_request': json(res, { error: r.error }, 400); break
      case 'unprocessable': json(res, { error: r.error }, 422); break
      case 'conflict': json(res, { error: r.error }, 409); break
      case 'invalid': json(res, { error: 'Invalid registry file', slug: r.slug, reason: r.error }, 422); break
      default: json(res, { error: 'Not found' }, 404)
    }
    return true
  }

  if (path === LIST_PATH) {
    json(res, { funkciok: await svc.list() })
    return true
  }

  if (msgMatch) {
    const slug = decodeSlug(msgMatch[1])
    const idRaw = msgMatch[2]
    if (!slug || !/^\d{1,15}$/.test(idRaw)) { json(res, { error: 'Not found' }, 404); return true }
    const r = await svc.message(slug, Number(idRaw))
    if (r.kind === 'ok') json(res, r.message)
    else if (r.kind === 'invalid') json(res, { error: 'Invalid registry file', slug: r.slug, reason: r.error }, 422)
    else json(res, { error: 'Not found' }, 404)
    return true
  }

  const slug = decodeSlug(pageMatch![1])
  if (!slug) { json(res, { error: 'Not found' }, 404); return true }
  const r = await svc.page(slug)
  if (r.kind === 'ok') json(res, r.page)
  else if (r.kind === 'invalid') json(res, { error: 'Invalid registry file', slug: r.slug, reason: r.error }, 422)
  else json(res, { error: 'Not found' }, 404)
  return true
}
