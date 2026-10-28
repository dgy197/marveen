import { join } from 'node:path'
import { PROJECT_ROOT, STORE_DIR } from '../../config.js'
import { getEffectiveSettingValue } from '../../settings-store.js'
import { json, methodNotAllowed } from '../http-helpers.js'
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
  if (path !== LIST_PATH && !msgMatch && !pageMatch) return false

  if (method !== 'GET') {
    methodNotAllowed(res, method, ['GET'])
    return true
  }
  const status = denied(ctx)
  if (status !== null) {
    json(res, { error: status === 401 ? 'Unauthorized' : 'Forbidden for this credential' }, status)
    return true
  }

  const svc = getService()

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
