// Minimal Telegram Bot-API client for the permission-bot relay (card d7f586bf).
//
// Deliberately separate from channel-coordinator/telegram-client.ts: Telegram
// REMEMBERS the allowed_updates list per token, and the relay must only ever
// ask for callback_query on the permission bot's token. The coordinator's list
// would be wrong here, and that file stays untouched.
//
// Surface: getMe, getWebhookInfo, getUpdates, answerCallbackQuery. There is no
// deleteWebhook, no sendMessage, no editMessage: the relay never removes a
// webhook (F1.3) and never edits a message (F3.5, the dashboard does that).
//
// Secrets: the token is part of every request URL (/bot<token>/<method>), so any
// error that echoes the URL (an invalid base URL, a proxy error page, an undici
// message) could carry it. Every message this module produces passes through
// maskSecrets() before it leaves, and the original error object (with its cause
// chain) is never attached.

export const DEFAULT_API_BASE = 'https://api.telegram.org'

// The only update kind the relay consumes. Sent on EVERY getUpdates call.
export const RELAY_ALLOWED_UPDATES = ['callback_query'] as const

// Read timeout for the short calls; getUpdates uses long-poll seconds + 10.
const SHORT_CALL_TIMEOUT_MS = 10_000

// Telegram caps a callback answer text at 200 characters.
const ANSWER_TEXT_MAX = 200

export interface TelegramUser {
  id: number
  is_bot?: boolean
  username?: string
  first_name?: string
}

export interface TelegramChat {
  id: number
  type?: string
}

export interface TelegramMessage {
  message_id: number
  date?: number
  chat: TelegramChat
  from?: TelegramUser
}

export interface TelegramCallbackQuery {
  id: string
  from?: TelegramUser
  message?: TelegramMessage
  inline_message_id?: string
  chat_instance?: string
  data?: string
}

export interface TelegramUpdate {
  update_id: number
  callback_query?: TelegramCallbackQuery
  [key: string]: unknown
}

export interface BotIdentity {
  id: number
  is_bot: boolean
  username?: string
}

export interface WebhookInfo {
  url: string
  pending_update_count?: number
}

//   fatal          -> 401 / other 4xx: configuration or token problem, retrying is pointless
//   conflict       -> 409 from another getUpdates consumer
//   webhook_active -> 409 because a webhook is set (never deleted by us)
//   rate_limit     -> 429, wait retryAfterSec
//   transient      -> 5xx, network error, read timeout, malformed response
//   aborted        -> the caller's own stop signal fired (not an error)
export type BotApiErrorKind = 'fatal' | 'conflict' | 'webhook_active' | 'rate_limit' | 'transient' | 'aborted'

export class BotApiError extends Error {
  constructor(
    public readonly kind: BotApiErrorKind,
    public readonly method: string,
    message: string,
    public readonly status?: number,
    public readonly retryAfterSec?: number,
  ) {
    super(message)
    this.name = 'BotApiError'
  }
}

// Generic Bot-API token shape, masked even when it is not OUR token (a proxy
// page could echo another one). Bot id 5+ digits, secret 30+ url-safe chars.
const TOKEN_SHAPE_RE = /\d{5,}:[A-Za-z0-9_-]{30,}/g

export function maskSecrets(text: string, token: string): string {
  let out = String(text)
  if (token) {
    out = out.split(token).join('<token>')
    const colon = token.indexOf(':')
    const secret = colon >= 0 ? token.slice(colon + 1) : token
    if (secret.length >= 8) out = out.split(secret).join('<token-secret>')
    // A URL-encoded copy (':' -> %3A) of the token or the secret.
    const enc = encodeURIComponent(token)
    if (enc !== token) out = out.split(enc).join('<token>')
  }
  return out.replace(TOKEN_SHAPE_RE, '<token>')
}

export interface BotApiOptions {
  token: string
  apiBase?: string
  fetchImpl?: typeof fetch
  shortCallTimeoutMs?: number
}

export interface GetUpdatesParams {
  offset?: number
  timeout: number
  limit: number
}

export interface BotApi {
  getMe(signal?: AbortSignal): Promise<BotIdentity>
  getWebhookInfo(signal?: AbortSignal): Promise<WebhookInfo>
  getUpdates(params: GetUpdatesParams, signal?: AbortSignal): Promise<TelegramUpdate[]>
  answerCallbackQuery(callbackQueryId: string, opts?: { text?: string; showAlert?: boolean }, signal?: AbortSignal): Promise<void>
}

interface BotApiEnvelope {
  ok?: boolean
  result?: unknown
  error_code?: number
  description?: string
  parameters?: { retry_after?: number }
}

export function createBotApi(opts: BotApiOptions): BotApi {
  const token = opts.token
  const base = (opts.apiBase ?? DEFAULT_API_BASE).replace(/\/+$/, '')
  const doFetch = opts.fetchImpl ?? fetch
  const shortTimeout = opts.shortCallTimeoutMs ?? SHORT_CALL_TIMEOUT_MS
  const mask = (s: string): string => maskSecrets(s, token)

  async function call(method: string, body: Record<string, unknown>, timeoutMs: number, signal?: AbortSignal): Promise<unknown> {
    if (signal?.aborted) throw new BotApiError('aborted', method, `${method}: aborted`)
    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => { timedOut = true; controller.abort() }, timeoutMs)
    const onOuterAbort = (): void => controller.abort()
    signal?.addEventListener('abort', onOuterAbort, { once: true })
    let res: Response
    let raw: string
    try {
      try {
        res = await doFetch(`${base}/bot${token}/${method}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(body),
          signal: controller.signal,
        })
        raw = await res.text()
      } catch (err) {
        if (signal?.aborted && !timedOut) throw new BotApiError('aborted', method, `${method}: aborted`)
        if (timedOut) throw new BotApiError('transient', method, `${method}: read timeout after ${timeoutMs} ms`)
        const msg = err instanceof Error ? err.message : String(err)
        const code = (err as { cause?: { code?: unknown } } | null)?.cause?.code
        const codePart = typeof code === 'string' ? ` (${code})` : ''
        throw new BotApiError('transient', method, mask(`${method}: network error: ${msg}${codePart}`))
      }
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', onOuterAbort)
    }

    let env: BotApiEnvelope | null = null
    try { env = JSON.parse(raw) as BotApiEnvelope } catch { env = null }
    const errorCode = typeof env?.error_code === 'number' ? env.error_code : res.status
    const description = mask(typeof env?.description === 'string' ? env.description.slice(0, 300) : `HTTP ${res.status}`)

    if (!res.ok || env?.ok === false) {
      if (errorCode === 409) {
        const kind: BotApiErrorKind = /webhook/i.test(description) ? 'webhook_active' : 'conflict'
        throw new BotApiError(kind, method, `${method}: 409 ${description}`, 409)
      }
      if (errorCode === 429) {
        const ra = env?.parameters?.retry_after
        throw new BotApiError('rate_limit', method, `${method}: 429 ${description}`, 429, typeof ra === 'number' && ra > 0 ? ra : undefined)
      }
      // 5xx, or an ok:false body without a 4xx code: retryable.
      if (errorCode >= 500 || errorCode < 400) throw new BotApiError('transient', method, `${method}: ${errorCode} ${description}`, errorCode)
      throw new BotApiError('fatal', method, `${method}: ${errorCode} ${description}`, errorCode)
    }
    if (!env || env.ok !== true) throw new BotApiError('transient', method, `${method}: malformed response`, res.status)
    return env.result
  }

  return {
    async getMe(signal) {
      const r = await call('getMe', {}, shortTimeout, signal) as Partial<BotIdentity> | null
      if (!r || typeof r.id !== 'number' || !Number.isSafeInteger(r.id)) throw new BotApiError('transient', 'getMe', 'getMe: malformed result')
      return { id: r.id, is_bot: r.is_bot === true, username: typeof r.username === 'string' ? r.username : undefined }
    },
    async getWebhookInfo(signal) {
      const r = await call('getWebhookInfo', {}, shortTimeout, signal) as Partial<WebhookInfo> | null
      if (!r || typeof r.url !== 'string') throw new BotApiError('transient', 'getWebhookInfo', 'getWebhookInfo: malformed result')
      return { url: r.url, pending_update_count: typeof r.pending_update_count === 'number' ? r.pending_update_count : undefined }
    },
    async getUpdates(params, signal) {
      const body: Record<string, unknown> = {
        timeout: params.timeout,
        limit: params.limit,
        allowed_updates: RELAY_ALLOWED_UPDATES,
      }
      if (params.offset !== undefined) body['offset'] = params.offset
      const r = await call('getUpdates', body, (params.timeout + 10) * 1000, signal)
      if (!Array.isArray(r)) throw new BotApiError('transient', 'getUpdates', 'getUpdates: malformed result')
      return r.filter((u): u is TelegramUpdate => typeof u === 'object' && u !== null)
    },
    async answerCallbackQuery(callbackQueryId, answer, signal) {
      const body: Record<string, unknown> = { callback_query_id: callbackQueryId }
      if (answer?.text) body['text'] = answer.text.slice(0, ANSWER_TEXT_MAX)
      if (answer?.showAlert) body['show_alert'] = true
      await call('answerCallbackQuery', body, shortTimeout, signal)
    },
  }
}
