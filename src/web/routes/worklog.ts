import { APP_TZ } from '../../config.js'
import { getDb } from '../../db.js'
import { resolveOwnerChatId } from '../../owner-chat.js'
import { json, methodNotAllowed } from '../http-helpers.js'
import { addDays } from '../worklog-intervals.js'
import {
  DEFAULT_RANGE_DAYS,
  MAX_RANGE_DAYS,
  buildWorklogDay,
  buildWorklogRange,
  daySpan,
  defaultRange,
  isValidDate,
  type WorklogOptions,
} from '../worklog.js'
import type { RouteContext } from './types.js'

// Card (S4-B): GET-only work log for "Fejlesztes > Munkanaplo".
//
//   GET /api/worklog?from=YYYY-MM-DD&to=YYYY-MM-DD   per-day aggregate (default last 30 days, max 92)
//   GET /api/worklog/:date                           one day in detail
//
// Reads only timestamps and identifiers (see web/worklog.ts). Auth is the
// dashboard gate's; like routes/funkciok.ts the handler repeats it: 401 without
// a principal, 403 for an operator-scoped key and for a federation peer.

const RANGE_PATH = '/api/worklog'
const DAY_RE = /^\/api\/worklog\/([^/]+)$/

/** Test seam: replaces the options (zone, owner chat). null restores the default. */
let optionsOverride: WorklogOptions | null = null
export function setWorklogOptionsForTest(o: WorklogOptions | null): void {
  optionsOverride = o
}

function options(): WorklogOptions {
  if (optionsOverride) return optionsOverride
  let ownerChatId: string | null = null
  try { ownerChatId = resolveOwnerChatId() } catch { ownerChatId = null }
  return { tz: APP_TZ, ownerChatId }
}

/** null = let the request through, else the status to answer with. */
function denied(ctx: RouteContext): number | null {
  const a = ctx.auth
  if (!a) return 401
  if (a.kind === 'device' && a.scope === 'operator') return 403
  if (a.kind === 'federation') return 403
  return null
}

export async function tryHandleWorklog(ctx: RouteContext): Promise<boolean> {
  const { res, path, method } = ctx
  const dayMatch = DAY_RE.exec(path)
  if (path !== RANGE_PATH && !dayMatch) return false

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
    return handle(ctx, dayMatch)
  } catch (err) {
    // Generic body: no stack, path or SQL text reaches the client.
    console.error('[worklog] request failed:', err instanceof Error ? err.name : 'error')
    json(res, { error: 'Internal error' }, 500)
    return true
  }
}

function handle(ctx: RouteContext, dayMatch: RegExpExecArray | null): boolean {
  const { res } = ctx
  const opts = options()

  if (dayMatch) {
    let date: string
    try { date = decodeURIComponent(dayMatch[1]) } catch { date = '' }
    if (!isValidDate(date)) { json(res, { error: 'Invalid date, expected YYYY-MM-DD' }, 400); return true }
    json(res, buildWorklogDay(getDb(), date, opts))
    return true
  }

  const fromQ = ctx.url.searchParams.get('from')
  const toQ = ctx.url.searchParams.get('to')
  if ((fromQ !== null && !isValidDate(fromQ)) || (toQ !== null && !isValidDate(toQ))) {
    json(res, { error: 'Invalid date, expected YYYY-MM-DD' }, 400)
    return true
  }
  const dflt = defaultRange(Math.floor(Date.now() / 1000), opts.tz)
  const to = toQ ?? dflt.to
  const from = fromQ ?? (toQ !== null ? addDays(toQ, -(DEFAULT_RANGE_DAYS - 1)) : dflt.from)
  if (from > to) { json(res, { error: '"from" is after "to"' }, 400); return true }
  if (daySpan(from, to) > MAX_RANGE_DAYS) {
    json(res, { error: `Range too long, max ${MAX_RANGE_DAYS} days` }, 400)
    return true
  }
  json(res, buildWorklogRange(getDb(), from, to, opts))
  return true
}
