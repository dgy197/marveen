// The apv: button handler of the permission-bot relay (card d7f586bf, spec F3, F5).
//
// The relay decides NOTHING. It pre-filters a callback_query (F3.1), forwards a
// press that passes to the dashboard over loopback (F3.3), and turns the answer
// into the toast (F3.4). The dashboard route (POST /api/approvals/:id/
// permission-bot, card 9a77b3e5) re-checks everything and is the only place a
// decision is made; this filter only keeps junk away from it.
//
// Pre-filter (all must hold, else the generic "not valid" toast, F3.2):
//   - data is EXACTLY an apv callback (parseCallbackData: no trim, no case fold)
//   - from.is_bot is false, from.id is the owner (resolved per press, the
//     dashboard's strict rule; unresolved = "system unavailable", fail-closed)
//   - the press came on a message (no inline_message_id), in a private chat
//     whose id is the presser's own id
//   - the buttoned message was sent by the pinned permission bot
//
// Forwarding: only to http://127.0.0.1:<port> (the host is fixed here, the port
// is an integer, redirects are refused). The Bearer is read from its file for
// EVERY request, so a rotation is picked up without a restart. One request per
// press, no automatic retry: a dashboard that is down, slow (10 s) or answers 5xx
// gets the "nothing was decided" toast, and the owner presses again.
//
// Logging (F3.2, F5): update_id, a short hash of the presser id, the reason code
// and the HTTP status. Never the callback data, the nonce, the approval id, the
// raw presser id, the Bearer or a response body.

import { createHmac, randomBytes } from 'node:crypto'
import { closeSync, constants as fsConstants, fchmodSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, writeSync } from 'node:fs'
import { dirname } from 'node:path'
import { parseCallbackData } from '../web/approval-callback-data.js'
import { BotApiError, type BotApi, type TelegramCallbackQuery } from './bot-api.js'
import { REASON_CODE_RE } from './offset-store.js'
import type { HandlerOutcome, RelayLog, UpdateHandler } from './poll-loop.js'
import { TELEGRAM_USER_ID_RE, PINNED_BOT_ID_RE, strictOwnerUserId } from './startup.js'

export const TOAST_INVALID = 'Ez a gomb nem érvényes.'
export const TOAST_CLOSED = 'Ez a kérés már lezárult.'
export const TOAST_UNAVAILABLE = 'A rendszer most nem érhető el, semmi nem dőlt el. Nyomd meg újra később.'
// 200 with ok:true but no outcome_text (the route always sends one; defensive).
export const TOAST_DECIDED = 'A döntés rögzítve.'
// 200 whose body is not the route's success shape: the outcome is unknown, so
// the toast must not claim that nothing was decided.
export const TOAST_UNKNOWN = 'A válasz nem értelmezhető. Nézd meg a dashboardon, mi lett a kérés sorsa.'

export const FORWARD_TIMEOUT_MS = 10_000
const RESPONSE_BODY_MAX = 16 * 1024
const BEARER_RE = /^[\x21-\x7e]{1,512}$/

export type PrefilterRefusal =
  | 'bad_data'
  | 'bad_from'
  | 'from_is_bot'
  | 'owner_unresolved'
  | 'not_owner'
  | 'inline_message'
  | 'no_message'
  | 'not_private'
  | 'chat_mismatch'
  | 'not_permission_bot_message'
  | 'bad_message_id'

export interface PrefilterPass {
  ok: true
  body: {
    decision: 'approved' | 'rejected'
    nonce: string
    from_id: string
    chat_id: string
    message_id: number
    bot_id: string
  }
  id32: string
}

export type PrefilterResult = PrefilterPass | { ok: false; reason: PrefilterRefusal }

function isPositiveId(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v > 0
}

/** F3.1. `owner` is the resolved owner user id, or null when unresolved. */
export function prefilterCallback(cbq: TelegramCallbackQuery, owner: string | null, pinnedBotId: string): PrefilterResult {
  const parsed = parseCallbackData(cbq.data)
  if (!parsed) return { ok: false, reason: 'bad_data' }
  const from = cbq.from
  if (!from || typeof from !== 'object' || !isPositiveId(from.id)) return { ok: false, reason: 'bad_from' }
  if (from.is_bot !== false) return { ok: false, reason: 'from_is_bot' }
  if (owner == null || !TELEGRAM_USER_ID_RE.test(owner)) return { ok: false, reason: 'owner_unresolved' }
  if (String(from.id) !== owner) return { ok: false, reason: 'not_owner' }
  if (cbq.inline_message_id !== undefined) return { ok: false, reason: 'inline_message' }
  const msg = cbq.message
  if (!msg || typeof msg !== 'object' || !msg.chat || typeof msg.chat !== 'object') return { ok: false, reason: 'no_message' }
  if (msg.chat.type !== 'private') return { ok: false, reason: 'not_private' }
  if (!isPositiveId(msg.chat.id) || msg.chat.id !== from.id) return { ok: false, reason: 'chat_mismatch' }
  const sender = msg.from
  if (!sender || typeof sender !== 'object' || !isPositiveId(sender.id) || String(sender.id) !== pinnedBotId) {
    return { ok: false, reason: 'not_permission_bot_message' }
  }
  if (!isPositiveId(msg.message_id)) return { ok: false, reason: 'bad_message_id' }
  return {
    ok: true,
    id32: parsed.approvalId.replace(/-/g, ''),
    body: {
      decision: parsed.decision,
      nonce: parsed.nonce,
      from_id: String(from.id),
      chat_id: String(msg.chat.id),
      message_id: msg.message_id,
      bot_id: pinnedBotId,
    },
  }
}

export const PRESSER_KEY_FILE_NAME = 'permission-bot-relay.presser-key'
const PRESSER_KEY_BYTES = 32
// Telegram rejects answerCallbackQuery with a text over 200 characters.
export const TOAST_MAX_CODE_POINTS = 200

/** Cuts a toast to at most 200 code points; an empty result is null. */
export function cutToast(text: string): string | null {
  const cut = Array.from(text).slice(0, TOAST_MAX_CODE_POINTS).join('').trim()
  return cut === '' ? null : cut
}

function readPresserKey(path: string): Buffer | null {
  let fd: number | null = null
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o777) !== 0o600 || st.size !== PRESSER_KEY_BYTES) return null
    const buf = Buffer.alloc(PRESSER_KEY_BYTES)
    if (readSync(fd, buf, 0, PRESSER_KEY_BYTES, 0) !== PRESSER_KEY_BYTES) return null
    return buf
  } catch {
    return null
  } finally {
    if (fd !== null) { try { closeSync(fd) } catch { /* best effort */ } }
  }
}

/**
 * The per-install secret that keys the presser tag: 32 random bytes, 0600, in the
 * relay's store directory. Created with exclusive create, read back on later runs.
 * Missing and not creatable, or wrong mode/size: null (no tag, fail closed). Never
 * throws and never reports the secret.
 */
export function loadOrCreatePresserKey(path: string): Buffer | null {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const fd = openSync(path, 'wx', 0o600)
    try {
      fchmodSync(fd, 0o600)
      if (writeSync(fd, randomBytes(PRESSER_KEY_BYTES)) !== PRESSER_KEY_BYTES) return null
    } finally {
      closeSync(fd)
    }
  } catch {
    // EEXIST (already created) or not creatable: fall through to the read-back.
  }
  return readPresserKey(path)
}

/** A short HMAC-SHA256 tag of the presser for the log; null without a valid key. */
export function presserTag(id: unknown, key: Buffer | null | undefined): string | null {
  if (!isPositiveId(id)) return null
  if (!Buffer.isBuffer(key) || key.length !== PRESSER_KEY_BYTES) return null
  return createHmac('sha256', key).update(`permission-bot-relay:${id}`, 'utf8').digest('hex').slice(0, 12)
}

/** Reads the dashboard Bearer from its file on every call; null when unusable. */
export function dashboardTokenFileReader(path: string): () => string | null {
  return () => {
    try {
      const t = readFileSync(path, 'utf8').trim()
      return BEARER_RE.test(t) ? t : null
    } catch {
      return null
    }
  }
}

/** Answers the callback with a toast. Never throws; logs the error name only. */
export async function answerToast(
  api: BotApi,
  cbq: TelegramCallbackQuery,
  text: string,
  log: RelayLog,
  updateId: number,
  signal?: AbortSignal,
): Promise<void> {
  if (typeof cbq.id !== 'string' || cbq.id === '') return
  try {
    await api.answerCallbackQuery(cbq.id, { text }, signal)
  } catch (err) {
    const kind = err instanceof BotApiError ? err.kind : err instanceof Error ? err.name : typeof err
    log.warn({ update_id: updateId, reason: 'answer_failed', kind }, 'permission-bot-relay: toast could not be sent')
  }
}

export type ForwardResult =
  | { kind: 'answered'; status: number; reason: string | null; ok: boolean; outcomeText: string | null }
  | { kind: 'unavailable'; why: 'no_bearer' | 'timeout' | 'network' | 'aborted' }

export interface ApvHandlerOptions {
  pinnedBotId: string
  dashboardPort: number
  readBearer: () => string | null
  log: RelayLog
  resolveOwner?: () => string | null
  // Key of the presser log tag (loadOrCreatePresserKey); absent or invalid: no tag.
  presserKey?: Buffer | null
  timeoutMs?: number
  fetchImpl?: typeof fetch
}

function safeReason(v: unknown): string | null {
  return typeof v === 'string' && REASON_CODE_RE.test(v) ? v : null
}

/** F3.4: the toast for a dashboard answer. */
export function toastFor(r: ForwardResult): string {
  if (r.kind === 'unavailable') return TOAST_UNAVAILABLE
  if (r.status === 200) {
    if (!r.ok) return TOAST_UNKNOWN
    return r.outcomeText ?? TOAST_DECIDED
  }
  if (r.status === 409 && (r.reason === 'already_resolved' || r.reason === 'expired')) return TOAST_CLOSED
  if (r.status === 400 || r.status === 403 || r.status === 404 || r.status === 409) return TOAST_INVALID
  // 401 (Bearer), 503 (owner / bot unavailable), any other 5xx or odd status.
  return TOAST_UNAVAILABLE
}

export function createApvHandler(opts: ApvHandlerOptions): UpdateHandler {
  if (!PINNED_BOT_ID_RE.test(opts.pinnedBotId)) throw new TypeError('apv handler: pinned bot id is not a bot id')
  if (!Number.isInteger(opts.dashboardPort) || opts.dashboardPort < 1 || opts.dashboardPort > 65535) {
    throw new TypeError('apv handler: dashboard port is not a TCP port')
  }
  const origin = `http://127.0.0.1:${opts.dashboardPort}`
  const doFetch = opts.fetchImpl ?? fetch
  const timeoutMs = opts.timeoutMs ?? FORWARD_TIMEOUT_MS
  const resolveOwner = opts.resolveOwner ?? strictOwnerUserId
  const { log, pinnedBotId } = opts
  const tag = (id: unknown): string | null => presserTag(id, opts.presserKey)

  async function forward(pass: PrefilterPass, signal: AbortSignal): Promise<ForwardResult> {
    const bearer = opts.readBearer()
    if (bearer == null) return { kind: 'unavailable', why: 'no_bearer' }
    if (signal.aborted) return { kind: 'unavailable', why: 'aborted' }
    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; controller.abort() }, timeoutMs)
    const onOuter = (): void => controller.abort()
    signal.addEventListener('abort', onOuter, { once: true })
    try {
      const res = await doFetch(`${origin}/api/approvals/${pass.id32}/permission-bot`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${bearer}` },
        body: JSON.stringify(pass.body),
        redirect: 'error',
        signal: controller.signal,
      })
      const text = (await res.text()).slice(0, RESPONSE_BODY_MAX)
      let parsed: Record<string, unknown> | null = null
      try {
        const j: unknown = JSON.parse(text)
        parsed = j !== null && typeof j === 'object' && !Array.isArray(j) ? j as Record<string, unknown> : null
      } catch { parsed = null }
      const rawOutcome = parsed?.['outcome_text']
      const outcome = typeof rawOutcome === 'string' ? cutToast(rawOutcome.trim()) : null
      return { kind: 'answered', status: res.status, reason: safeReason(parsed?.['reason']), ok: parsed?.['ok'] === true, outcomeText: outcome }
    } catch {
      if (timedOut) return { kind: 'unavailable', why: 'timeout' }
      if (signal.aborted) return { kind: 'unavailable', why: 'aborted' }
      return { kind: 'unavailable', why: 'network' }
    } finally {
      clearTimeout(timer)
      signal.removeEventListener('abort', onOuter)
    }
  }

  return async (update, ctx): Promise<HandlerOutcome> => {
    const cbq = update.callback_query
    const updateId = update.update_id
    if (!cbq || typeof cbq !== 'object') return 'rejected'
    let owner: string | null = null
    try { owner = resolveOwner() } catch { owner = null }
    const pre = prefilterCallback(cbq, owner, pinnedBotId)
    if (!pre.ok) {
      log.warn({ update_id: updateId, reason: pre.reason, presser: tag(cbq.from?.id) }, 'permission-bot-relay: press refused by the pre-filter, not forwarded')
      await answerToast(ctx.api, cbq, pre.reason === 'owner_unresolved' ? TOAST_UNAVAILABLE : TOAST_INVALID, log, updateId, ctx.signal)
      return 'rejected'
    }
    const r = await forward(pre, ctx.signal)
    const toast = toastFor(r)
    if (r.kind === 'answered') {
      log.info({ update_id: updateId, presser: tag(cbq.from?.id), status: r.status, reason: r.reason }, 'permission-bot-relay: press forwarded, dashboard answered')
    } else {
      log.warn({ update_id: updateId, presser: tag(cbq.from?.id), reason: 'dashboard_unavailable', why: r.why }, 'permission-bot-relay: press NOT decided, the dashboard was not reachable')
    }
    await answerToast(ctx.api, cbq, toast, log, updateId, ctx.signal)
    return r.kind === 'answered' && r.status === 200 && r.ok ? 'processed' : 'rejected'
  }
}
