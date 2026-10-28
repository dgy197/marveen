import { RequestBodyTooLargeError, json, methodNotAllowed, readBody } from '../http-helpers.js'
import { isKnownAgent } from '../agent-config.js'
import {
  QUESTION_BODY_MAX_BYTES, createQuestion, isQuestionFilter, listQuestions, validateQuestionInput,
} from '../open-questions.js'
import { buildOverview } from '../open-questions-overview.js'
import { answerQuestion, getQuestionKind, ownerAnswerPrincipal, validateAnswerInput } from '../open-questions-answer.js'
import { logger } from '../../logger.js'
import type { RouteContext } from './types.js'

// Open questions (S3-N1): the agents' questions for the owner.
//
//   GET  /api/questions?status=open|answered|expired|all   list (default open), newest first, max 200
//   POST /api/questions                                    an AGENT raises a question
//
//   POST /api/questions/:id/answer                         the OWNER answers (S3-N2, see handleAnswer)
//
// Auth (spec 5.1) is the dashboard gate's (web.ts: 401 without a principal, 403
// for an operator-scoped key). The handler repeats the checks, so a route added
// later stays closed even if the gate's wiring changes:
//   GET : token, device full, session. operator and federation: 403.
//   POST: the shared token ONLY (it is the agents' credential). device, session,
//         operator, federation: 403 -- the owner never raises a question.
// The token's X-Agent-Id claim is self-asserted: it can contradict the body
// (400), it never authorizes anything.

const PATH = '/api/questions'
const ANSWER_RE = /^\/api\/questions\/([^/]+)\/answer$/

let nowMs: () => number = () => Date.now()

/** Test seam: a fake clock (ms). null restores the real one. */
export function setQuestionsClockForTest(fn: (() => number) | null): void {
  nowMs = fn ?? (() => Date.now())
}

/** null = let the request through, else the status to answer with. */
function deniedRead(ctx: RouteContext): number | null {
  const a = ctx.auth
  if (!a) return 401
  if (a.kind === 'device' && a.scope === 'operator') return 403
  if (a.kind === 'federation') return 403
  return null
}

/**
 * POST /api/questions/:id/answer. Owner only (blueprint section 1): a session,
 * a full device key, or the token WITH a valid session cookie (the browser).
 * The shared token alone is 403 (never 401), also with zero dashboard users.
 * A cross-origin browser write never gets here (web.ts runs the origin gate
 * before routing).
 */
async function handleAnswer(ctx: RouteContext, rawId: string): Promise<void> {
  const { res, method } = ctx
  if (method !== 'POST') { methodNotAllowed(res, method, ['POST']); return }
  const verdict = ownerAnswerPrincipal(ctx.auth, ctx.req)
  if (!verdict.ok) { json(res, verdict.body, verdict.status); return }

  if (!/^\d{1,15}$/.test(rawId)) { json(res, { error: 'Not found' }, 404); return }
  const id = Number(rawId)
  const declared = Number(ctx.req.headers?.['content-length'])
  if (Number.isFinite(declared) && declared > QUESTION_BODY_MAX_BYTES) { json(res, { error: 'body_too_large' }, 413); return }
  let text: string
  try {
    text = (await readBody(ctx.req, { maxBytes: QUESTION_BODY_MAX_BYTES })).toString('utf8')
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) { json(res, { error: 'body_too_large' }, 413); return }
    json(res, { error: 'Bad request' }, 400)
    return
  }
  let raw: unknown
  try { raw = JSON.parse(text) } catch { json(res, { error: 'Body must be valid JSON' }, 400); return }

  const kind = getQuestionKind(id)
  if (!kind) { json(res, { error: 'Not found' }, 404); return }
  const v = validateAnswerInput(kind, raw)
  if (!v.ok) { json(res, { error: v.error }, 400); return }

  let r: ReturnType<typeof answerQuestion>
  try {
    r = answerQuestion(id, v.value, kind, verdict.principal, Math.floor(nowMs() / 1000))
  } catch (err) {
    // The answer and its message are ONE transaction: nothing was recorded, the owner may retry.
    logger.error({ err, id }, 'open question answer failed; rolled back')
    json(res, { error: 'The answer could not be recorded' }, 500)
    return
  }
  switch (r.kind) {
    case 'ok': json(res, r.question, 200); break
    case 'not_found': json(res, { error: 'Not found' }, 404); break
    case 'expired': json(res, { error: r.error }, 410); break
    default: json(res, { error: r.error }, 409)
  }
}

export async function tryHandleOpenQuestions(ctx: RouteContext): Promise<boolean> {
  const { res, path, method } = ctx
  if (path === OVERVIEW_PATH) return handleOverview(ctx)
  const answerMatch = ANSWER_RE.exec(path)
  if (answerMatch) {
    await handleAnswer(ctx, answerMatch[1])
    return true
  }
  if (path !== PATH) return false

  const allowed = ['GET', 'POST']
  if (!allowed.includes(method)) {
    methodNotAllowed(res, method, allowed)
    return true
  }
  const status = deniedRead(ctx)
  if (status !== null) {
    json(res, { error: status === 401 ? 'Unauthorized' : 'Forbidden for this credential' }, status)
    return true
  }
  const nowSec = Math.floor(nowMs() / 1000)

  if (method === 'GET') {
    const raw = ctx.url.searchParams.get('status') ?? 'open'
    if (!isQuestionFilter(raw)) { json(res, { error: 'status must be open, answered, expired or all' }, 400); return true }
    json(res, { questions: listQuestions(raw, nowSec) })
    return true
  }

  // POST: the shared token only.
  if (ctx.auth?.kind !== 'token') { json(res, { error: 'Forbidden for this credential' }, 403); return true }
  const declared = Number(ctx.req.headers?.['content-length'])
  if (Number.isFinite(declared) && declared > QUESTION_BODY_MAX_BYTES) { json(res, { error: 'body_too_large' }, 413); return true }
  let text: string
  try {
    text = (await readBody(ctx.req, { maxBytes: QUESTION_BODY_MAX_BYTES })).toString('utf8')
  } catch (err) {
    if (err instanceof RequestBodyTooLargeError) { json(res, { error: 'body_too_large' }, 413); return true }
    json(res, { error: 'Bad request' }, 400)
    return true
  }
  let raw: unknown
  try { raw = JSON.parse(text) } catch { json(res, { error: 'Body must be valid JSON' }, 400); return true }

  const v = validateQuestionInput(raw)
  if (!v.ok) { json(res, { error: v.error }, 400); return true }
  if (!isKnownAgent(v.value.agent_id)) { json(res, { error: 'agent_id is not a known fleet agent' }, 400); return true }
  const claim = ctx.auth.agent
  if (claim && claim !== v.value.agent_id) { json(res, { error: 'agent_id differs from the X-Agent-Id claim' }, 400); return true }

  const r = createQuestion(v.value, nowSec)
  switch (r.kind) {
    case 'ok': json(res, r.question, 201); break
    case 'unprocessable': json(res, { error: r.error }, 422); break
    default: json(res, { error: r.error }, 429)
  }
  return true
}

// ---------------------------------------------------------------------------
// S3-N3: GET /api/questions/overview -- open questions grouped per agent
// (agent_running, card_seq, funkcio_slug) plus the pending approvals, shown
// read-only with allowlisted fields. Same auth as the list GET.
// ---------------------------------------------------------------------------

const OVERVIEW_PATH = '/api/questions/overview'

function handleOverview(ctx: RouteContext): boolean {
  const { res, method } = ctx
  if (method !== 'GET') { methodNotAllowed(res, method, ['GET']); return true }
  const status = deniedRead(ctx)
  if (status !== null) {
    json(res, { error: status === 401 ? 'Unauthorized' : 'Forbidden for this credential' }, status)
    return true
  }
  json(res, buildOverview(Math.floor(nowMs() / 1000)))
  return true
}
