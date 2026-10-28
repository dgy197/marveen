import { getDb } from '../db.js'
import { maskSecrets } from './agent-transcript.js'

// Function page S2-A: the append-only decision log of the function pages.
//
//   - rows are written by recordDecision() and read by the two list functions;
//     there is no UPDATE and no DELETE path (and the table has triggers that abort
//     both, see db.ts). A correction is a NEW row whose `supersedes` points at an
//     existing row of the same slug.
//   - spec 5.1: the log is NOT proof of what the owner said. The only check it
//     makes is "is there an inbound conversation_log row with this message id in
//     the OWNER's chat", and it reveals that as found / not found, never the text.
//     The result is stored at write time too (source_found), so a later
//     conversation_log retention purge reads "verified at record time" instead of
//     flipping to "not found".
//   - spec 5.4: every response is built by toDecisionOut() from the explicit
//     column list below (DECISION_KEYS pins it in the snapshot test).

export const QUOTE_MAX_CODEPOINTS = 280
export const DECISION_BODY_MAX_BYTES = 16 * 1024
export const DECISION_LIST_MAX_ROWS = 500
export const DECISION_PAGE_MAX_ROWS = 50
/** Rows older than 2020-01-01 are a typo, not a decision date. */
const MIN_DECIDED_AT = 1_577_836_800
/** Clock skew tolerated on `decided_at` (seconds). */
const FUTURE_SKEW_SECONDS = 60
const ACTOR_MAX_CHARS = 100

export const DECISION_KEYS = [
  'id', 'slug', 'quote_short', 'tg_chat', 'tg_msg_id', 'msg_id', 'card_id', 'decided_at',
  'recorded_by', 'supersedes', 'superseded_by', 'source_status', 'created_at',
] as const

export type SourceStatus = 'verified' | 'verified_at_record' | 'not_found' | 'none'

export interface DecisionOut {
  id: number
  slug: string
  quote_short: string
  tg_chat: string | null
  tg_msg_id: string | null
  msg_id: number | null
  card_id: string | null
  decided_at: number
  recorded_by: string
  supersedes: number | null
  superseded_by: number | null
  source_status: SourceStatus
  created_at: number
}

export type DecisionVia = 'token' | 'device' | 'session'
export interface DecisionActor { via: DecisionVia; by: string }

export interface DecisionInput {
  quote_short: string
  tg_chat: string | null
  tg_msg_id: string | null
  msg_id: number | null
  card_id: string | null
  decided_at: number | null
  supersedes: number | null
}

const INPUT_KEYS: readonly string[] = ['quote_short', 'tg_chat', 'tg_msg_id', 'msg_id', 'card_id', 'decided_at', 'supersedes']

// ---------------------------------------------------------------------------
// Who is writing
// ---------------------------------------------------------------------------

type AuthLike = {
  kind: 'token' | 'session' | 'federation' | 'device'
  user?: string
  device?: string
  agent?: string
  scope?: 'full' | 'operator'
} | undefined | null

/**
 * The write principal, or null when this credential may not write decisions
 * (spec 5.1: token, device `full` and session may; operator scope, federation
 * and "no principal" may not). The token's `agent` is the self-asserted
 * X-Agent-Id: it attributes, it does not authorize.
 */
export function decisionActor(auth: AuthLike): DecisionActor | null {
  if (!auth) return null
  const cut = (s: string) => Array.from(s).slice(0, ACTOR_MAX_CHARS).join('')
  if (auth.kind === 'token') return { via: 'token', by: cut(auth.agent || 'token') }
  if (auth.kind === 'device' && auth.scope !== 'operator') return { via: 'device', by: cut(`device:${auth.device ?? 'unknown'}`) }
  if (auth.kind === 'session') return { via: 'session', by: cut(`session:${auth.user ?? 'unknown'}`) }
  return null
}

// ---------------------------------------------------------------------------
// Input validation (pure)
// ---------------------------------------------------------------------------

export type ValidateResult = { ok: true; value: DecisionInput } | { ok: false; error: string }

// Control characters except \n, line/paragraph separators, bidi overrides/isolates, BOM,
// invisible format characters (zero width, word joiner, Arabic letter mark) and Unicode tag characters.
// Code points, not a regex literal: the separators would sit unescaped in the source.
function hasForbiddenChar(s: string): boolean {
  for (const ch of s) {
    const c = ch.codePointAt(0) as number
    if (c <= 0x09 || (c >= 0x0b && c <= 0x1f) || (c >= 0x7f && c <= 0x9f)) return true
    if (c === 0x2028 || c === 0x2029 || (c >= 0x202a && c <= 0x202e) || (c >= 0x2066 && c <= 0x2069) || c === 0xfeff) return true
    if ((c >= 0xe0000 && c <= 0xe007f) || (c >= 0x200b && c <= 0x200f) || c === 0x061c || (c >= 0x2060 && c <= 0x2064)) return true
  }
  return false
}

function idString(v: unknown, re: RegExp): string | null | undefined {
  if (v === undefined || v === null) return null
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) return undefined
    v = String(v)
  }
  return typeof v === 'string' && re.test(v) ? v : undefined
}

/** Shape and range checks only; whether msg_id / supersedes exist is a DB question (recordDecision). */
export function validateDecisionInput(raw: unknown, nowSec: number): ValidateResult {
  if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) return { ok: false, error: 'Body must be a JSON object' }
  const o = raw as Record<string, unknown>
  for (const k of Object.keys(o)) {
    if (!INPUT_KEYS.includes(k)) return { ok: false, error: `Unknown field: ${k.slice(0, 40)}` }
  }

  if (typeof o.quote_short !== 'string') return { ok: false, error: 'quote_short is required (string)' }
  const quote = o.quote_short.replace(/\r\n?/g, '\n').trim()
  const len = Array.from(quote).length
  if (len < 1) return { ok: false, error: 'quote_short is empty' }
  if (len > QUOTE_MAX_CODEPOINTS) return { ok: false, error: `quote_short is longer than ${QUOTE_MAX_CODEPOINTS} characters` }
  if (hasForbiddenChar(quote)) return { ok: false, error: 'quote_short contains a control, invisible or direction-override character' }
  // The log cannot be edited or deleted, so a secret must not get in at all.
  if (maskSecrets(quote) !== quote) return { ok: false, error: 'quote_short contains a secret-shaped string' }

  const tgMsgId = idString(o.tg_msg_id, /^\d{1,20}$/)
  if (tgMsgId === undefined) return { ok: false, error: 'tg_msg_id must be digits (max 20)' }
  const tgChat = idString(o.tg_chat, /^-?\d{1,20}$/)
  if (tgChat === undefined) return { ok: false, error: 'tg_chat must be an integer string' }
  if (tgChat !== null && tgMsgId === null) return { ok: false, error: 'tg_chat needs tg_msg_id' }

  let msgId: number | null = null
  if (o.msg_id !== undefined && o.msg_id !== null) {
    if (typeof o.msg_id !== 'number' || !Number.isSafeInteger(o.msg_id) || o.msg_id < 1) return { ok: false, error: 'msg_id must be a positive integer' }
    msgId = o.msg_id
  }
  if (tgMsgId === null && msgId === null) return { ok: false, error: 'A source is required: tg_msg_id or msg_id' }

  let cardId: string | null = null
  if (o.card_id !== undefined && o.card_id !== null) {
    if (typeof o.card_id !== 'string' || !/^[0-9a-f]{8}$/.test(o.card_id)) return { ok: false, error: 'card_id must be 8 lowercase hex characters' }
    cardId = o.card_id
  }

  let decidedAt: number | null = null
  if (o.decided_at !== undefined && o.decided_at !== null) {
    if (typeof o.decided_at !== 'number' || !Number.isSafeInteger(o.decided_at)) return { ok: false, error: 'decided_at must be unix seconds (integer)' }
    if (o.decided_at < MIN_DECIDED_AT) return { ok: false, error: 'decided_at is before 2020' }
    if (o.decided_at > nowSec + FUTURE_SKEW_SECONDS) return { ok: false, error: 'decided_at is in the future' }
    decidedAt = o.decided_at
  }

  let supersedes: number | null = null
  if (o.supersedes !== undefined && o.supersedes !== null) {
    if (typeof o.supersedes !== 'number' || !Number.isSafeInteger(o.supersedes) || o.supersedes < 1) return { ok: false, error: 'supersedes must be a positive integer' }
    supersedes = o.supersedes
  }

  return { ok: true, value: { quote_short: quote, tg_chat: tgChat, tg_msg_id: tgMsgId, msg_id: msgId, card_id: cardId, decided_at: decidedAt, supersedes } }
}

// ---------------------------------------------------------------------------
// Source check (found / not found, nothing else)
// ---------------------------------------------------------------------------

/**
 * Message ids (of `chat`) that have an inbound conversation_log row. One scan
 * for the whole batch. Only the id column is read: conversation_log.text never
 * leaves the table. Only the OWNER's chat is looked up, so this cannot be used
 * to probe whether a message exists in some other chat.
 */
function foundInboundIds(chat: string, ids: readonly string[]): Set<string> {
  const found = new Set<string>()
  if (ids.length === 0) return found
  const unique = [...new Set(ids)]
  for (let i = 0; i < unique.length; i += 500) {
    const part = unique.slice(i, i + 500)
    const rows = getDb()
      .prepare(`SELECT DISTINCT message_id FROM conversation_log WHERE direction = 'in' AND chat_id = ? AND message_id IN (${part.map(() => '?').join(',')})`)
      .all(chat, ...part) as { message_id: string }[]
    for (const r of rows) found.add(String(r.message_id))
  }
  return found
}

// ---------------------------------------------------------------------------
// Reading
// ---------------------------------------------------------------------------

interface DecisionRow {
  id: number
  slug: string
  quote_short: string
  tg_chat: string | null
  tg_msg_id: string | null
  msg_id: number | null
  card_id: string | null
  decided_at: number
  recorded_by: string
  supersedes: number | null
  source_found: number | null
  created_at: number
  superseded_by: number | null
}

// Named columns, never `*` (spec 5.4). recorded_via and source_checked_at stay
// in the table for the work log and audits; they are not part of the response.
const SELECT_ROWS = `SELECT d.id, d.slug, d.quote_short, d.tg_chat, d.tg_msg_id, d.msg_id, d.card_id, d.decided_at,
  d.recorded_by, d.supersedes, d.source_found, d.created_at,
  (SELECT s.id FROM function_decisions s WHERE s.supersedes = d.id) AS superseded_by
  FROM function_decisions d`

function serialize(rows: readonly DecisionRow[], ownerChat: string | null): DecisionOut[] {
  const live = ownerChat === null
    ? new Set<string>()
    : foundInboundIds(ownerChat, rows.filter((r) => r.tg_msg_id !== null && r.tg_chat === ownerChat).map((r) => r.tg_msg_id as string))
  return rows.map((r): DecisionOut => {
    let status: SourceStatus
    if (r.tg_msg_id === null) status = 'none'
    else if (ownerChat !== null && r.tg_chat === ownerChat && live.has(r.tg_msg_id)) status = 'verified'
    else status = r.source_found === 1 ? 'verified_at_record' : 'not_found'
    return {
      id: r.id,
      slug: r.slug,
      quote_short: maskSecrets(r.quote_short),
      tg_chat: r.tg_chat,
      tg_msg_id: r.tg_msg_id,
      msg_id: r.msg_id,
      card_id: r.card_id,
      decided_at: r.decided_at,
      recorded_by: r.recorded_by,
      supersedes: r.supersedes,
      superseded_by: r.superseded_by,
      source_status: status,
      created_at: r.created_at,
    }
  })
}

/** Every row of the slug (corrected ones too), newest first, at most DECISION_LIST_MAX_ROWS. */
export function listDecisions(slug: string, ownerChat: () => string | null): DecisionOut[] {
  const rows = getDb()
    .prepare(`${SELECT_ROWS} WHERE d.slug = ? ORDER BY d.created_at DESC, d.id DESC LIMIT ${DECISION_LIST_MAX_ROWS}`)
    .all(slug) as DecisionRow[]
  return serialize(rows, rows.some((r) => r.tg_msg_id !== null) ? ownerChat() : null)
}

/** The page block: only rows that nothing corrected (the newer row is shown instead), at most DECISION_PAGE_MAX_ROWS. */
export function pageDecisions(slug: string, ownerChat: () => string | null): DecisionOut[] {
  const rows = getDb()
    .prepare(`${SELECT_ROWS} WHERE d.slug = ? AND NOT EXISTS (SELECT 1 FROM function_decisions s WHERE s.supersedes = d.id)
              ORDER BY d.created_at DESC, d.id DESC LIMIT ${DECISION_PAGE_MAX_ROWS}`)
    .all(slug) as DecisionRow[]
  return serialize(rows, rows.some((r) => r.tg_msg_id !== null) ? ownerChat() : null)
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------

export type RecordOutcome =
  | { kind: 'ok'; decision: DecisionOut }
  | { kind: 'bad_request'; error: string }
  | { kind: 'unprocessable'; error: string }
  | { kind: 'conflict'; error: string }

function isUniqueViolation(err: unknown): boolean {
  const e = err as { code?: unknown; message?: unknown } | null
  // Only UNIQUE(supersedes) can race here; CHECK / FOREIGN KEY / trigger aborts stay 500s.
  return e?.code === 'SQLITE_CONSTRAINT_UNIQUE' && typeof e.message === 'string' && e.message.includes('function_decisions.supersedes')
}

/**
 * Appends one row. The existence checks and the insert run in ONE immediate
 * transaction; UNIQUE(supersedes) is the final arbiter if two writers race
 * (a constraint error is a 409, never a 500).
 */
export function recordDecision(
  slug: string,
  input: DecisionInput,
  actor: DecisionActor,
  nowSec: number,
  ownerChat: () => string | null,
): RecordOutcome {
  const db = getDb()

  let tgChat = input.tg_chat
  let sourceFound: number | null = null
  if (input.tg_msg_id !== null) {
    const owner = ownerChat()
    if (tgChat === null) {
      if (owner === null) return { kind: 'bad_request', error: 'tg_chat is required: this install has no owner chat configured' }
      tgChat = owner
    }
    sourceFound = owner !== null && tgChat === owner && foundInboundIds(owner, [input.tg_msg_id]).has(input.tg_msg_id) ? 1 : 0
  }

  let id: number
  try {
    const outcome = db.transaction((): RecordOutcome | number => {
      if (input.msg_id !== null && !db.prepare('SELECT 1 FROM agent_messages WHERE id = ?').get(input.msg_id)) {
        return { kind: 'unprocessable', error: 'msg_id does not exist' }
      }
      if (input.supersedes !== null) {
        const target = db.prepare('SELECT slug FROM function_decisions WHERE id = ?').get(input.supersedes) as { slug: string } | undefined
        if (!target || target.slug !== slug) return { kind: 'conflict', error: 'supersedes must point at an existing decision of the same function' }
        if (db.prepare('SELECT 1 FROM function_decisions WHERE supersedes = ?').get(input.supersedes)) {
          return { kind: 'conflict', error: 'That decision has already been corrected' }
        }
      }
      const info = db.prepare(`INSERT INTO function_decisions
        (slug, quote_short, tg_chat, tg_msg_id, msg_id, card_id, decided_at, recorded_by, recorded_via, supersedes, source_checked_at, source_found, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
        slug, input.quote_short, tgChat, input.tg_msg_id, input.msg_id, input.card_id, input.decided_at ?? nowSec,
        actor.by, actor.via, input.supersedes, input.tg_msg_id !== null ? nowSec : null, sourceFound, nowSec,
      )
      return Number(info.lastInsertRowid)
    }).immediate()
    if (typeof outcome !== 'number') return outcome
    id = outcome
  } catch (err) {
    if (isUniqueViolation(err)) return { kind: 'conflict', error: 'That decision has already been corrected' }
    throw err
  }

  const row = db.prepare(`${SELECT_ROWS} WHERE d.id = ?`).get(id) as DecisionRow
  return { kind: 'ok', decision: serialize([row], row.tg_msg_id !== null ? ownerChat() : null)[0] }
}
