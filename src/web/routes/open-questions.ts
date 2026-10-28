import { RequestBodyTooLargeError, json, methodNotAllowed, readBody } from '../http-helpers.js'
import { isKnownAgent } from '../agent-config.js'
import {
  QUESTION_BODY_MAX_BYTES, createQuestion, isQuestionFilter, listQuestions, validateQuestionInput,
} from '../open-questions.js'
import type { RouteContext } from './types.js'

// Open questions (S3-N1): the agents' questions for the owner.
//
//   GET  /api/questions?status=open|answered|expired|all   list (default open), newest first, max 200
//   POST /api/questions                                    an AGENT raises a question
//
// POST /api/questions/:id/answer (the owner's answer) is a later node and is
// NOT handled here: the path falls through to the next module.
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

export async function tryHandleOpenQuestions(ctx: RouteContext): Promise<boolean> {
  const { res, path, method } = ctx
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
