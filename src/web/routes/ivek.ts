import { json, methodNotAllowed } from '../http-helpers.js'
import { HEX8_RE } from '../ivek-sources.js'
import { createIvekService, type IvekService } from '../ivek.js'
import type { RouteContext } from './types.js'

// "Ivek" view (card 46e935d6): GET-only, read-only arc view for the dashboard
// tab "Fejlesztes > Ivek".
//
//   GET /api/ivek        list of the open (and recently done) dev cards, with the derived phase
//   GET /api/ivek/:id    the life of one card: status events, briefs, review rounds,
//                        commits, deploy runs, child cards
//
// Auth is the dashboard gate's (web.ts: 401 without a principal, 403 for an
// operator-scoped key). Like routes/funkciok.ts the handler repeats the two
// checks. The only request datum is the card id, validated as lower-case hex8
// before it reaches the service; it becomes a path component only inside
// ivek-sources.ts, behind the same check. Errors carry a fixed code, never a
// path or a message.

let service: IvekService | null = null

function getService(): IvekService {
  if (!service) service = createIvekService()
  return service
}

/** Test seam: swap the service (temp roots, fake git). null restores the default. */
export function setIvekServiceForTest(s: IvekService | null): void {
  service = s
}

const LIST_PATH = '/api/ivek'
const DETAIL_RE = /^\/api\/ivek\/([^/]+)$/

function decodeId(raw: string): string | null {
  let s: string
  try { s = decodeURIComponent(raw) } catch { return null }
  return HEX8_RE.test(s) ? s : null
}

/** null = let the request through, else the status to answer with. */
function denied(ctx: RouteContext): number | null {
  const a = ctx.auth
  if (!a) return 401
  if (a.kind === 'device' && a.scope === 'operator') return 403
  if (a.kind === 'federation') return 403
  return null
}

export async function tryHandleIvek(ctx: RouteContext): Promise<boolean> {
  const { res, path, method } = ctx
  const detailMatch = DETAIL_RE.exec(path)
  if (path !== LIST_PATH && !detailMatch) return false

  if (method !== 'GET') {
    methodNotAllowed(res, method, ['GET'])
    return true
  }
  const status = denied(ctx)
  if (status !== null) {
    json(res, { error: status === 401 ? 'Unauthorized' : 'Forbidden for this credential' }, status)
    return true
  }

  try {
    if (!detailMatch) {
      json(res, { ivek: await getService().list() })
      return true
    }
    const id = decodeId(detailMatch[1])
    if (!id) { json(res, { error: 'Not found' }, 404); return true }
    const detail = await getService().detail(id)
    if (!detail) { json(res, { error: 'Not found' }, 404); return true }
    json(res, detail)
  } catch {
    json(res, { error: 'Internal error' }, 500)
  }
  return true
}
