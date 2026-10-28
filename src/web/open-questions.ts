import { getDb } from '../db.js'
import { maskSecrets } from './agent-transcript.js'
import { isHiddenChar } from './funkciok-text.js'

// Open questions S3-N1: the agents' questions for the owner ("Fejlesztes >
// Kerdesek"). A question authorizes NOTHING: no approval gate reads this table
// (spec 5.3), the owner's later answer is information for the asking agent.
//
//   - spec 5.4: every response is built by toQuestionOut() from the explicit
//     column list below (QUESTION_KEYS pins it in the snapshot test). The
//     answered_by / answered_principal columns stay in the table (work log) and
//     are never selected for a response.
//   - expiry is LAZY: the stored status stays 'open'; the view reports
//     'expired' once expires_at <= now. No background job.

export { OWNER_UI_SENDER } from './reserved-senders.js'

export const QUESTION_MAX_CODEPOINTS = 400
export const QUESTION_BODY_MAX_BYTES = 8 * 1024
export const QUESTION_LIST_MAX_ROWS = 200
export const QUESTION_OPEN_PER_AGENT_MAX = 20
export const QUESTION_DEFAULT_EXPIRY_S = 7 * 24 * 3600
export const QUESTION_MIN_EXPIRY_S = 300
export const QUESTION_MAX_EXPIRY_S = 7 * 24 * 3600
/** All agents together: the table is append-only, so a runaway poster must hit a ceiling. */
export const QUESTION_OPEN_GLOBAL_MAX = 200

export const QUESTION_KEYS = [
  'id', 'agent_id', 'card_id', 'msg_id', 'kind', 'question_short', 'status',
  'answer_short', 'answered_via', 'answered_at', 'created_at', 'expires_at', 'source',
] as const

export type QuestionKind = 'info' | 'yesno' | 'free'
export type QuestionViewStatus = 'open' | 'ack' | 'yes' | 'no' | 'answered' | 'expired'

export interface QuestionOut {
  id: number
  agent_id: string
  card_id: string | null
  msg_id: number | null
  kind: QuestionKind
  question_short: string
  status: QuestionViewStatus
  answer_short: string | null
  answered_via: 'ui' | 'telegram' | null
  answered_at: number | null
  created_at: number
  expires_at: number
  source: 'extractor' | 'agent'
}

export interface QuestionInput {
  agent_id: string
  kind: QuestionKind
  question_short: string
  card_id: string | null
  msg_id: number | null
  expires_in_s: number
}

const INPUT_KEYS: readonly string[] = ['agent_id', 'kind', 'question_short', 'card_id', 'msg_id', 'expires_in_s']
const KINDS: readonly string[] = ['info', 'yesno', 'free']
const AGENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/

// ---------------------------------------------------------------------------
// Input validation (pure)
// ---------------------------------------------------------------------------

export type ValidateResult = { ok: true; value: QuestionInput } | { ok: false; error: string }

// Same shared check as the decision log (funkciok-text.ts): controls except
// \n, line/paragraph separators, every format / default-ignorable character.
function hasForbiddenChar(s: string): boolean {
  for (const ch of s) {
    if (isHiddenChar(ch, true)) return true
  }
  return false
}

/** Shape and range checks only; whether card_id / msg_id / agent_id exist is a DB / roster question. */
export function validateQuestionInput(raw: unknown): ValidateResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false, error: 'Body must be a JSON object' }
  const o = raw as Record<string, unknown>
  for (const k of Object.keys(o)) {
    if (!INPUT_KEYS.includes(k)) return { ok: false, error: `Unknown field: ${k.slice(0, 40)}` }
  }

  if (typeof o.agent_id !== 'string' || !AGENT_ID_RE.test(o.agent_id)) return { ok: false, error: 'agent_id is required (a fleet agent id)' }
  if (typeof o.kind !== 'string' || !KINDS.includes(o.kind)) return { ok: false, error: 'kind must be info, yesno or free' }

  if (typeof o.question_short !== 'string') return { ok: false, error: 'question_short is required (string)' }
  const question = o.question_short.replace(/\r\n?/g, '\n').trim()
  const len = Array.from(question).length
  if (len < 1) return { ok: false, error: 'question_short is empty' }
  if (len > QUESTION_MAX_CODEPOINTS) return { ok: false, error: `question_short is longer than ${QUESTION_MAX_CODEPOINTS} characters` }
  if (hasForbiddenChar(question)) return { ok: false, error: 'question_short contains a control, invisible or direction-override character' }
  // The row is never edited or deleted, and it reaches the owner's screen: no secret may get in.
  if (maskSecrets(question) !== question) return { ok: false, error: 'question_short contains a secret-shaped string' }

  let cardId: string | null = null
  if (o.card_id !== undefined && o.card_id !== null) {
    if (typeof o.card_id !== 'string' || !/^[0-9a-f]{8}$/.test(o.card_id)) return { ok: false, error: 'card_id must be 8 lowercase hex characters' }
    cardId = o.card_id
  }

  let msgId: number | null = null
  if (o.msg_id !== undefined && o.msg_id !== null) {
    if (typeof o.msg_id !== 'number' || !Number.isSafeInteger(o.msg_id) || o.msg_id < 1) return { ok: false, error: 'msg_id must be a positive integer' }
    msgId = o.msg_id
  }

  let expiresIn = QUESTION_DEFAULT_EXPIRY_S
  if (o.expires_in_s !== undefined && o.expires_in_s !== null) {
    if (typeof o.expires_in_s !== 'number' || !Number.isSafeInteger(o.expires_in_s)) return { ok: false, error: 'expires_in_s must be an integer (seconds)' }
    if (o.expires_in_s < QUESTION_MIN_EXPIRY_S || o.expires_in_s > QUESTION_MAX_EXPIRY_S) {
      return { ok: false, error: `expires_in_s must be between ${QUESTION_MIN_EXPIRY_S} and ${QUESTION_MAX_EXPIRY_S}` }
    }
    expiresIn = o.expires_in_s
  }

  return { ok: true, value: { agent_id: o.agent_id, kind: o.kind as QuestionKind, question_short: question, card_id: cardId, msg_id: msgId, expires_in_s: expiresIn } }
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

interface QuestionRow {
  id: number
  agent_id: string
  card_id: string | null
  msg_id: number | null
  kind: QuestionKind
  question_short: string
  status: QuestionViewStatus
  answer_short: string | null
  answered_via: 'ui' | 'telegram' | null
  answered_at: number | null
  created_at: number
  expires_at: number
  source: 'extractor' | 'agent'
}

// Named columns, never `*` (spec 5.4).
const SELECT_ROWS = `SELECT id, agent_id, card_id, msg_id, kind, question_short, status, answer_short,
  answered_via, answered_at, created_at, expires_at, source FROM open_questions`

export function toQuestionOut(r: QuestionRow, nowSec: number): QuestionOut {
  return {
    id: r.id,
    agent_id: r.agent_id,
    card_id: r.card_id,
    msg_id: r.msg_id,
    kind: r.kind,
    question_short: maskSecrets(r.question_short),
    status: r.status === 'open' && r.expires_at <= nowSec ? 'expired' : r.status,
    answer_short: r.answer_short === null ? null : maskSecrets(r.answer_short),
    answered_via: r.answered_via,
    answered_at: r.answered_at,
    created_at: r.created_at,
    expires_at: r.expires_at,
    source: r.source,
  }
}

export type QuestionFilter = 'open' | 'answered' | 'expired' | 'all'

export function isQuestionFilter(v: string): v is QuestionFilter {
  return v === 'open' || v === 'answered' || v === 'expired' || v === 'all'
}

export interface QuestionPage {
  questions: QuestionOut[]
  /** More rows matched than QUESTION_LIST_MAX_ROWS: the list is cut. */
  truncated: boolean
}

/** Newest first, at most QUESTION_LIST_MAX_ROWS. `open` and `expired` apply the lazy expiry. */
export function listQuestions(filter: QuestionFilter, nowSec: number): QuestionOut[] {
  return listQuestionsPage(filter, nowSec).questions
}

/** Same rows as listQuestions, plus whether the cap cut the list (one extra row is read to know). */
export function listQuestionsPage(filter: QuestionFilter, nowSec: number): QuestionPage {
  let where = ''
  const params: number[] = []
  if (filter === 'open') { where = "WHERE status = 'open' AND expires_at > ?"; params.push(nowSec) }
  else if (filter === 'expired') { where = "WHERE (status = 'open' AND expires_at <= ?) OR status = 'expired'"; params.push(nowSec) }
  else if (filter === 'answered') where = "WHERE status IN ('ack','yes','no','answered')"
  const rows = getDb()
    .prepare(`${SELECT_ROWS} ${where} ORDER BY created_at DESC, id DESC LIMIT ${QUESTION_LIST_MAX_ROWS + 1}`)
    .all(...params) as QuestionRow[]
  return { questions: rows.slice(0, QUESTION_LIST_MAX_ROWS).map((r) => toQuestionOut(r, nowSec)), truncated: rows.length > QUESTION_LIST_MAX_ROWS }
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

export type CreateOutcome =
  | { kind: 'ok'; question: QuestionOut }
  | { kind: 'unprocessable'; error: string }
  /** code: which cap refused (agent_cap or global_cap); the route logs it on every 429. */
  | { kind: 'too_many'; error: string; code: 'agent_cap' | 'global_cap' }

/**
 * Appends one agent question. The existence checks, the per-agent cap and the
 * insert run in ONE immediate transaction, so two racing writers cannot both
 * slip under the cap. `source` is always 'agent' here.
 */
export function createQuestion(input: QuestionInput, nowSec: number): CreateOutcome {
  const db = getDb()
  const outcome = db.transaction((): CreateOutcome | number => {
    if (input.card_id !== null && !db.prepare('SELECT 1 FROM kanban_cards WHERE id = ?').get(input.card_id)) {
      return { kind: 'unprocessable', error: 'card_id does not exist' }
    }
    if (input.msg_id !== null && !db.prepare('SELECT 1 FROM agent_messages WHERE id = ?').get(input.msg_id)) {
      return { kind: 'unprocessable', error: 'msg_id does not exist' }
    }
    const open = db.prepare("SELECT COUNT(*) AS n FROM open_questions WHERE agent_id = ? AND status = 'open' AND expires_at > ?")
      .get(input.agent_id, nowSec) as { n: number }
    if (open.n >= QUESTION_OPEN_PER_AGENT_MAX) {
      return { kind: 'too_many', error: `At most ${QUESTION_OPEN_PER_AGENT_MAX} open questions per agent`, code: 'agent_cap' }
    }
    const all = db.prepare("SELECT COUNT(*) AS n FROM open_questions WHERE status = 'open' AND expires_at > ?").get(nowSec) as { n: number }
    if (all.n >= QUESTION_OPEN_GLOBAL_MAX) {
      return { kind: 'too_many', error: `At most ${QUESTION_OPEN_GLOBAL_MAX} open questions in total`, code: 'global_cap' }
    }
    const info = db.prepare(`INSERT INTO open_questions (agent_id, card_id, msg_id, kind, question_short, status, created_at, expires_at, source)
      VALUES (?, ?, ?, ?, ?, 'open', ?, ?, 'agent')`).run(
      input.agent_id, input.card_id, input.msg_id, input.kind, input.question_short, nowSec, nowSec + input.expires_in_s,
    )
    return Number(info.lastInsertRowid)
  }).immediate()
  if (typeof outcome !== 'number') return outcome
  const row = db.prepare(`${SELECT_ROWS} WHERE id = ?`).get(outcome) as QuestionRow
  return { kind: 'ok', question: toQuestionOut(row, nowSec) }
}
