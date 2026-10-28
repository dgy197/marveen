import type http from 'node:http'
import { createAgentMessage, getDb } from '../db.js'
import { maskSecrets } from './agent-transcript.js'
import { isHiddenChar } from './funkciok-text.js'
import { ownerSessionFromCookie } from './owner-session.js'
import { OWNER_UI_SENDER, toQuestionOut, type QuestionKind, type QuestionOut } from './open-questions.js'
import type { RouteContext } from './routes/types.js'

// Open questions S3-N2: the OWNER's answer to an agent's question.
//
// A question authorizes NOTHING (spec 5.3): the answer is information for the
// asking agent. No approval gate, credit gate or send-authorize path reads
// open_questions, and the message below says so in its own text.

export const ANSWER_MAX_CODEPOINTS = 1000
export const QUESTION_ECHO_MAX_CODEPOINTS = 200

type Auth = RouteContext['auth']

// ---------------------------------------------------------------------------
// Who may answer (blueprint section 1)
// ---------------------------------------------------------------------------

export interface OwnerPrincipal {
  via: 'session' | 'device'
  by: string
}

export const OWNER_SESSION_REQUIRED_BODY = {
  error: 'Answering needs the dashboard login (an owner session) or a full Bridge device key. The shared access token cannot answer.',
  code: 'owner_session_required',
}

export type PrincipalVerdict =
  | { ok: true; principal: OwnerPrincipal }
  | { ok: false; status: 401 | 403; body: Record<string, unknown> }

const cut = (s: string) => Array.from(s).slice(0, 80).join('')

/**
 * Spec 5.1 for the answer: the owner only.
 *   none                  -> 401 (the gate does it first; repeated here)
 *   session               -> yes
 *   device, scope full    -> yes
 *   device, other scope   -> 403 (operator)
 *   federation            -> 403
 *   token                 -> yes ONLY with a valid owner session cookie
 *                            (browser: token + cookie); else 403. There is NO
 *                            first-run exception (unlike mayIssueCredentials),
 *                            so a bare token never answers, with zero dashboard
 *                            users either. The token and its X-Agent-Id claim
 *                            are never part of the recorded principal.
 * A token caller never gets 401: the SPA's fetch wrapper drops its stored token
 * on a 401, and the browser would lose it for nothing.
 */
export function ownerAnswerPrincipal(auth: Auth, req: http.IncomingMessage | undefined): PrincipalVerdict {
  if (!auth) return { ok: false, status: 401, body: { error: 'Unauthorized' } }
  switch (auth.kind) {
    case 'session':
      return { ok: true, principal: { via: 'session', by: cut(`session:${auth.user ?? 'unknown'}`) } }
    case 'device':
      if (auth.scope === 'full') return { ok: true, principal: { via: 'device', by: cut(`device:${auth.device ?? 'unknown'}`) } }
      return { ok: false, status: 403, body: { error: 'Forbidden for this credential' } }
    case 'token': {
      const s = ownerSessionFromCookie(req)
      if (s) return { ok: true, principal: { via: 'session', by: cut(`session:${s.username}`) } }
      return { ok: false, status: 403, body: OWNER_SESSION_REQUIRED_BODY }
    }
    default:
      return { ok: false, status: 403, body: { error: 'Forbidden for this credential' } }
  }
}

// ---------------------------------------------------------------------------
// The answer (pure validation)
// ---------------------------------------------------------------------------

export type AnswerStatus = 'ack' | 'yes' | 'no' | 'answered'

export interface AnswerInput {
  status: AnswerStatus
  /** Stored in answer_short: only the free text; ack / yes / no carry none. */
  text: string | null
}

export type AnswerValidation = { ok: true; value: AnswerInput } | { ok: false; error: string }

const ANSWER_KEYS = ['answer', 'text']

function hasForbiddenChar(s: string): boolean {
  for (const ch of s) {
    if (isHiddenChar(ch, true)) return true
  }
  return false
}

/** Which answer fits which kind: info -> ack, yesno -> yes|no, free -> text. */
export function validateAnswerInput(kind: QuestionKind, raw: unknown): AnswerValidation {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false, error: 'Body must be a JSON object' }
  const o = raw as Record<string, unknown>
  for (const k of Object.keys(o)) {
    if (!ANSWER_KEYS.includes(k)) return { ok: false, error: `Unknown field: ${k.slice(0, 40)}` }
  }
  if (typeof o.answer !== 'string') return { ok: false, error: 'answer is required (ack, yes, no or text)' }

  if (kind === 'free') {
    if (o.answer !== 'text') return { ok: false, error: 'a free question takes answer "text"' }
    if (typeof o.text !== 'string') return { ok: false, error: 'text is required (string)' }
    const text = o.text.replace(/\r\n?/g, '\n').trim()
    const len = Array.from(text).length
    if (len < 1) return { ok: false, error: 'text is empty' }
    if (len > ANSWER_MAX_CODEPOINTS) return { ok: false, error: `text is longer than ${ANSWER_MAX_CODEPOINTS} characters` }
    if (hasForbiddenChar(text)) return { ok: false, error: 'text contains a control, invisible or direction-override character' }
    if (maskSecrets(text) !== text) return { ok: false, error: 'text contains a secret-shaped string' }
    return { ok: true, value: { status: 'answered', text } }
  }

  if (o.text !== undefined) return { ok: false, error: 'text is only for a free question' }
  if (kind === 'info') {
    if (o.answer !== 'ack') return { ok: false, error: 'an info question takes answer "ack"' }
    return { ok: true, value: { status: 'ack', text: null } }
  }
  if (o.answer !== 'yes' && o.answer !== 'no') return { ok: false, error: 'a yes/no question takes answer "yes" or "no"' }
  return { ok: true, value: { status: o.answer, text: null } }
}

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

export type AnswerOutcome =
  | { kind: 'ok'; question: QuestionOut; message_id: number }
  | { kind: 'not_found' }
  | { kind: 'conflict'; error: string }
  | { kind: 'expired'; error: string }

/** One line, no control characters: the text ends up in the asking agent's terminal. */
function oneLine(s: string): string {
  return Array.from(s.replace(/\s+/g, ' ')).filter((ch) => !isHiddenChar(ch)).join('').trim()
}

function answerLabel(a: AnswerInput): string {
  if (a.status === 'ack') return 'tudomásul vette'
  if (a.status === 'yes') return 'IGEN'
  if (a.status === 'no') return 'NEM'
  return oneLine(a.text ?? '')
}

/**
 * The text of the bus message to the asking agent. It states in its own words
 * that it is information, not an approval.
 */
export function buildAnswerMessage(id: number, questionShort: string, a: AnswerInput): string {
  const q = Array.from(oneLine(maskSecrets(questionShort))).slice(0, QUESTION_ECHO_MAX_CODEPOINTS).join('')
  return `[Válasz kérdésre #q${id}] A gazda válasza: ${answerLabel(a)} -- kérdés: ${q} -- `
    + 'Ez tájékoztatás, NEM jóváhagyás: semmilyen kaput, engedélyt vagy küldést nem nyit meg. Valódi engedélyhez approval kell.'
}

interface StateRow { id: number; agent_id: string; kind: QuestionKind; question_short: string; status: string; expires_at: number }

/**
 * Open -> ack|yes|no|answered, exactly once. The conditional UPDATE and the
 * message to the asker run in ONE immediate transaction:
 *   - `WHERE status = 'open' AND expires_at > now` makes the transition itself
 *     the guard, so of two racing answers exactly one gets changes === 1 and
 *     only that one writes a message;
 *   - if the message insert fails, the answer rolls back with it (the owner
 *     can retry; the agent never misses an answer the owner thinks was given).
 * The kind must be read to validate the body, so the route calls
 * getQuestionKind() first; the UPDATE also pins `kind` so a stale read cannot
 * store a mismatching answer.
 */
export function answerQuestion(id: number, answer: AnswerInput, kind: QuestionKind, principal: OwnerPrincipal, nowSec: number): AnswerOutcome {
  const db = getDb()
  return db.transaction((): AnswerOutcome => {
    const info = db.prepare(`UPDATE open_questions
      SET status = ?, answer_short = ?, answered_via = 'ui', answered_at = ?, answered_by = ?, answered_principal = ?
      WHERE id = ? AND kind = ? AND status = 'open' AND expires_at > ?`)
      .run(answer.status, answer.text, nowSec, principal.by, principal.via, id, kind, nowSec)
    if (info.changes === 1) {
      const row = db.prepare('SELECT agent_id, question_short FROM open_questions WHERE id = ?').get(id) as { agent_id: string; question_short: string }
      const msg = createAgentMessage(OWNER_UI_SENDER, row.agent_id, buildAnswerMessage(id, row.question_short, answer))
      const out = db.prepare(`SELECT id, agent_id, card_id, msg_id, kind, question_short, status, answer_short,
        answered_via, answered_at, created_at, expires_at, source FROM open_questions WHERE id = ?`).get(id) as Parameters<typeof toQuestionOut>[0]
      return { kind: 'ok', question: toQuestionOut(out, nowSec), message_id: msg.id }
    }
    const cur = db.prepare('SELECT id, agent_id, kind, question_short, status, expires_at FROM open_questions WHERE id = ?').get(id) as StateRow | undefined
    if (!cur) return { kind: 'not_found' }
    if (cur.status === 'expired' || (cur.status === 'open' && cur.expires_at <= nowSec)) return { kind: 'expired', error: 'The question has expired' }
    if (cur.status !== 'open') return { kind: 'conflict', error: 'The question is already answered' }
    // open and not expired but the UPDATE did not match: the kind changed under us (cannot happen: the trigger pins it).
    return { kind: 'conflict', error: 'The question changed; reload it' }
  }).immediate()
}

/** The kind of a question, to pick the right body validation; null when there is no such row. */
export function getQuestionKind(id: number): QuestionKind | null {
  const r = getDb().prepare('SELECT kind FROM open_questions WHERE id = ?').get(id) as { kind: QuestionKind } | undefined
  return r ? r.kind : null
}
