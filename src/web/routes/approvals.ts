import { randomUUID } from 'node:crypto'
import { readFileSync, existsSync } from 'node:fs'
import { join } from 'node:path'
import { PROJECT_ROOT, MAIN_AGENT_ID, TELEGRAM_BOT_TOKEN, CHANNEL_PROVIDER, APP_TZ, DASHBOARD_PUBLIC_URL, WEB_PORT, PERMISSION_BOT_ID } from '../../config.js'
import {
  consumeApproval, consumeCategoryApproval,
  CATEGORY_CONSUME_DEFAULT_WINDOW_S, CATEGORY_CONSUME_MAX_WINDOW_S,
  createApproval, getApproval, resolveApproval, listApprovals, expireTimedOutApprovals,
  createAgentMessage, setApprovalTelegramMessageId, setPermissionBotNonceHashes,
  type Approval,
} from '../../db.js'
import { logger } from '../../logger.js'
import { readBody, json } from '../http-helpers.js'
import { approvalGranteeOf, approvalNotGrantedReason, identityDenialBody } from '../auth-gate.js'
import { resolveOwnerChatId, resolveAlertOwnerChat } from '../../owner-chat.js'
import { sendOwnerMessage, sendOwnerSlackDm, slackTargetFor, noticeTargetDrift } from '../../notify.js'
import { getEffectiveSettingValue } from '../../settings-store.js'
import { mainBotToken, ownerDmVerdict, SLACK_CHUNK } from '../../slack-notify.js'
import { reactionRoute, reactionsOn, repliesOn, dashboardOnlyLine, postReactionPrompt, startApprovalSlackSweeper, type RouteDeps } from '../approval-slack-route.js'
import { sendTelegramMessage, type TelegramInlineKeyboard } from '../telegram.js'
import { channelStateDir, readChannelToken } from '../../channel-provider.js'
import { getSecret } from '../vault.js'
import { PERMISSION_BOT_VAULT_ID } from '../permission-bot-vault.js'
import { isPermissionBotCategory, parseRagApprovalPayload, type RagApprovalPayload } from '../rag-approval-payload.js'
import { buildCallbackData, newCallbackNonce, nonceHash } from '../approval-callback-data.js'
import { mayActAsOwner, OWNER_SESSION_REQUIRED, refuseOwner } from './auth.js'
import type { RouteContext } from './types.js'

// Kanban 80d0e3c6: APPROVING is the owner's decision, so the two routes that make a row approved
// (the born-approved POST and PATCH status=approved) take an owner credential. Measured before:
// a caller with the shared token (every agent holds it) got an approved row on both routes, and
// the real email-approval-gate then let its letter through; through STANDING_CATEGORY the same
// row made every later letter to an address approval-free. The self-declared agent_id and
// resolved_by checks below stay, but they were never what stopped this.
// Who counts as the owner is the owner gate (mayActAsOwner, #2163): the owner's session, also when
// the browser sends the stored token alongside it; the bare token never, not even before the first
// dashboard login exists (OWNERGATE4-1104: every agent holds it, and could approve its own request).
// With no login yet, refuseOwner answers setup_required and says to create one.
const OWNER_ONLY = {
  ...OWNER_SESSION_REQUIRED,
  error: 'Approving needs the dashboard login (an owner session); the shared dashboard token can file, reject or time out a request, not approve one.',
}

const AUTONOMY_CONFIG_PATH = join(PROJECT_ROOT, 'store', 'autonomy-config.json')

// APPROVALVAK821: a pending approval with timeout_at NULL can never reach the
// 'timeout' status -- the sweeper's WHERE clause skips it forever, so an
// unanswered request leaves the asking agent polling into eternity. No
// category carried timeout_minutes in any real install, which made the state
// STRUCTURALLY unreachable. Every request therefore gets a timeout: the
// caller's explicit timeout_seconds wins, then the category's
// timeout_minutes, then this default.
export const DEFAULT_TIMEOUT_MINUTES = 1440
// Cap: a timeout past a week is indistinguishable from the old "never".
export const MAX_TIMEOUT_SECONDS = 7 * 24 * 3600

function readCategoryTimeoutMinutes(category: string): number | null {
  try {
    if (!existsSync(AUTONOMY_CONFIG_PATH)) return null
    const config = JSON.parse(readFileSync(AUTONOMY_CONFIG_PATH, 'utf-8')) as {
      categories: { key: string; timeout_minutes?: number | null }[]
    }
    const cat = config.categories.find(c => c.key === category)
    if (!cat || cat.timeout_minutes == null) return null
    return cat.timeout_minutes
  } catch {
    return null
  }
}

// Pure + exported for tests. `timeoutSeconds` is the request-body value as
// received (unknown): the scaffolded agent instructions have always told
// agents to send timeout_seconds, but the old handler never read it.
export function computeTimeoutAt(category: string, timeoutSeconds: unknown, nowMs: number = Date.now()): number {
  const now = Math.floor(nowMs / 1000)
  if (typeof timeoutSeconds === 'number' && Number.isFinite(timeoutSeconds) && timeoutSeconds > 0) {
    return now + Math.min(Math.floor(timeoutSeconds), MAX_TIMEOUT_SECONDS)
  }
  const catMinutes = readCategoryTimeoutMinutes(category)
  if (catMinutes != null && catMinutes > 0) return now + catMinutes * 60
  return now + DEFAULT_TIMEOUT_MINUTES * 60
}

// f2c5edb0: the window inside which an approved letter may still be consumed,
// counted from resolved_at. The SAME fixed value as the gate (APPROVAL_WINDOW_S
// in scripts/hooks/email-approval-gate.py; a test pins the two), so the two
// consume paths agree on when an approval has gone stale. No environment
// override on either side (ENVRELAXGATE1104): the hook cannot see the
// dashboard's launch environment, so an override here would split the two.
export const APPROVAL_WINDOW_S = 1800
export function approvalWindowSeconds(): number {
  return APPROVAL_WINDOW_S
}

// The consumer names the sending tool in the audit trail. Printable only (no
// control characters, checked by code point so the source carries no escape),
// 1-120 characters after trimming.
export function isConsumerName(v: unknown): v is string {
  if (typeof v !== 'string') return false
  const t = v.trim()
  if (t.length < 1 || t.length > 120) return false
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i)
    if (c < 32 || c === 127) return false
  }
  return true
}

// One RFC 5322 msg-id, angle brackets included: the sender generates it BEFORE
// the send and hands the same value to its mailer, so the approval row names the
// letter that used it.
export function isMessageId(v: unknown): v is string {
  return typeof v === 'string' && v.length <= 250 && /^<[^<>\s@]+@[^<>\s@]+>$/.test(v)
}

// A category key as the autonomy config spells them (email_send, data_delete,
// external_message): lower-case ASCII letter first, then letters, digits, underscore.
export function isCategoryKey(v: unknown): v is string {
  return typeof v === 'string' && /^[a-z][a-z0-9_]{0,63}$/.test(v)
}

// What the acting tool names as the thing that used the approval (a plan id,
// a change-list id). Printable, 1-250 characters after trimming.
export function isConsumeRef(v: unknown): v is string {
  if (typeof v !== 'string') return false
  const t = v.trim()
  if (t.length < 1 || t.length > 250) return false
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i)
    if (c < 32 || c === 127) return false
  }
  return true
}

// for_agent names one fleet agent. Same alphabet as sanitizeAgentIdent
// (prompt-safety.ts) and the 64-char cap of the X-Agent-Id claim, so the stored
// value is exactly what an agent token resolves to.
export function isForAgentName(v: unknown): v is string {
  return typeof v === 'string' && /^[A-Za-z0-9_-]{1,64}$/.test(v)
}

// The window the acting tool asks for, in seconds. Absent = the default;
// anything else must be a whole number inside 1..cap, or the call is refused
// (400) rather than silently clamped, so a tool learns its policy is not what
// it thinks.
export function categoryWindowSeconds(v: unknown): number | null {
  if (v === undefined || v === null) return CATEGORY_CONSUME_DEFAULT_WINDOW_S
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < 1 || v > CATEGORY_CONSUME_MAX_WINDOW_S) return null
  return v
}

// The dashboard's Approvals page as the BROWSER reaches it (DASHBOARD_PUBLIC_URL, else this host's port), for the
// owner's message (APPROVALSLACK1030: the decision is one tap away). Exported for tests.
export function approvalsPageUrl(publicUrl: string = DASHBOARD_PUBLIC_URL, port: number = WEB_PORT): string {
  return `${publicUrl.trim().replace(/\/+$/, '') || `http://localhost:${port}`}/#approvals`
}

// Owner-facing text (Slack DM or the channel provider). Pure + exported for
// tests. Plain text (no markdown escaping concerns), proper accents: this is
// outgoing copy.
export function buildOwnerApprovalText(approval: Approval): string {
  const expires = approval.timeout_at
    ? new Date(approval.timeout_at * 1000).toLocaleString('hu-HU', { timeZone: APP_TZ })
    : 'nincs'
  return [
    `[JÓVÁHAGYÁS KELL] ${approval.agent_id} | ${approval.category}`,
    approval.action_description,
    `Lejárat: ${expires}`,
    `Döntés: Dashboard -> Jóváhagyások (id: ${approval.id})`,
    approvalsPageUrl(),
  ].join('\n')
}

// The informative variant, for a row the owner already approved in the chat
// before it was filed. Pure + exported for tests. It must NOT read as a
// question -- the owner answering "mehet" a second time to a done deal is
// exactly the noise this replaces -- but it keeps the action visible in the
// owner's chat.
export function buildOwnerChatApprovedText(approval: Approval, ownerMessageId: number | string): string {
  return [
    `[JÓVÁHAGYVA A CHATBEN] ${approval.agent_id} | ${approval.category}`,
    approval.action_description,
    `Jóváhagyás: a chat-üzeneted (üzenet-azonosító: ${ownerMessageId})`,
    `Nincs további teendőd, ez csak tájékoztatás.`,
    `Napló: Dashboard -> Jóváhagyások (id: ${approval.id})`,
  ].join('\n')
}

// When the owner send is suppressed or fails AND the requester is the main
// agent, there is no in-band signal left at all: the leg-2 short-circuit
// below skips the main-agent message unconditionally. The old self-notify was
// useless but VISIBLE -- losing even that would rebuild the closed loop this
// card documents, one layer deeper (Marveen's review finding on #1026).
// Everyone else already got the normal main-agent notify, so the fallback is
// main-requester-only. The marker names the reason so the reader knows this
// is a degraded delivery, not the normal path.
function fallbackInBand(approval: Approval, reason: string): void {
  if (approval.agent_id !== MAIN_AGENT_ID) return
  try {
    const content = [
      `[APPROVAL_REQUEST][OWNER_UNREACHED ${reason}]`,
      `id=${approval.id}`,
      `agent=${approval.agent_id}`,
      `category=${approval.category}`,
      `action=${approval.action_description}`,
      `timeout_at=${approval.timeout_at ?? 'null'}`,
    ].join(' ')
    createAgentMessage('system', MAIN_AGENT_ID, content)
  } catch (err) {
    logger.warn({ err, approvalId: approval.id }, 'approval in-band fallback failed too -- the request is only visible on the dashboard')
  }
}

// APPROVALVAK821 (a) -- the request must reach the OWNER, not only the main
// agent's inter-agent queue. Fire-and-forget on purpose: the POST response
// must not wait on the Telegram round-trip, and a failed send must not fail
// the request -- but it must be LOUD in the logs, because a silently
// undelivered approval is exactly the closed loop this fixes.
//
// With `chatApprovedMessageId` set, the row is already approved (the owner said
// yes in that chat message) and the owner gets the informative note instead of
// the question. Two things differ on that path: the note's own message id is
// NOT stamped (telegram_message_id already names the owner's approving
// message), and a failed note does NOT fall back in-band -- the only requester
// allowed on this path is the main agent, which already knows the action is
// approved; an [APPROVAL_REQUEST] marker would mislead it.
// APPROVALSLACK1030 (2): what the reaction path reads, in one place (tests replace it).
export const reactionDeps: RouteDeps = {
  setting: (key) => String(getEffectiveSettingValue(key) ?? ''),
  token: () => mainBotToken(),
  ownerTarget: async () => (await slackTargetFor('owner')) || '',
  verdict: (channel, owner) => ownerDmVerdict(channel, owner),
  drift: (current) => noticeTargetDrift(current),
  chunk: SLACK_CHUNK,
}

function notifyOwner(approval: Approval, chatApprovedMessageId: number | string | null = null, serverFiled = false): void {
  // Card 9a77b3e5: a permission-bot category goes out through the permission
  // bot ONLY, never through the main bot's token below.
  if (isPermissionBotCategory(approval.category)) {
    notifyPermissionBot(approval)
    return
  }
  const informative = chatApprovedMessageId != null
  let text = informative
    ? buildOwnerChatApprovedText(approval, chatApprovedMessageId)
    : buildOwnerApprovalText(approval)
  void (async () => {
    // APPROVALSLACK1030 (2): the owner decides with a Slack reaction the server itself checks, when this request may
    // (approval-slack-route.ts); otherwise the normal DM below, saying the decision is on the dashboard.
    // APPROVALSLACK1030 B: with APPROVAL_SLACK_REPLIES on, the same one-message path, and the owner's typed reply decides.
    if (!informative && (reactionsOn(reactionDeps.setting) || repliesOn(reactionDeps.setting))) {
      const expires = approval.timeout_at ? new Date(approval.timeout_at * 1000).toLocaleString('hu-HU', { timeZone: APP_TZ }) : 'nincs'
      const route = await reactionRoute(approval, serverFiled, reactionDeps, expires, approvalsPageUrl())
      if (route.ok && await postReactionPrompt(approval, route)) return
      text += '\n' + dashboardOnlyLine(route.ok ? 'slack_post_failed' : route.reason)
    }
    // APPROVALSLACK1030: an owner who moved to Slack (NOTIFY_SLACK_TARGET set) while the channel provider stays
    // Telegram got the request on Telegram (measured 2026-10-30: both of the day's requests logged this function's
    // Telegram branch, its messageId and no provider). The owner asked for Slack only: the request goes to the owner's
    // Slack DM, and a miss falls back in-band, never to Telegram.
    const slack = await sendOwnerSlackDm(text)
    if (slack.attempted) {
      if (slack.sent) {
        logger.info({ approvalId: approval.id, provider: 'slack', informative }, 'approval owner notification sent')
        return
      }
      if (slack.error === 'no_slack_token') {
        logger.warn({ approvalId: approval.id, provider: 'slack', informative }, 'approval owner notification suppressed: no channel token')
        if (!informative) fallbackInBand(approval, 'no-token')
        return
      }
      if (slack.error?.startsWith('unresolved_target')) {
        logger.warn({ approvalId: approval.id, provider: 'slack', informative }, 'approval owner notification suppressed: no owner chat')
        if (!informative) fallbackInBand(approval, 'no-owner-chat')
        return
      }
      logger.warn({ approvalId: approval.id, provider: 'slack', error: slack.error, informative },
        'approval owner notification FAILED -- the request is only visible on the dashboard')
      if (!informative) fallbackInBand(approval, 'send-failed')
      return
    }

    // APPROVALVAK821 fixed this path so the request reaches the OWNER and not
    // only the main agent's queue -- but the fix went out Telegram-only, so on
    // any install that speaks another provider the old silence came straight
    // back. Measured on a Discord install 2026-09-26: every approval request
    // logged `owner notification suppressed: no TELEGRAM_BOT_TOKEN`, the owner
    // was told nothing, and the only notification went to the main agent, i.e.
    // to the very agent whose request it was. An approval gate whose owner
    // never hears about it is not a gate.
    //
    // The Telegram branch is kept for Telegram installs ONLY because it also
    // records the message id (setApprovalTelegramMessageId); every other
    // provider goes through sendOwnerMessage, which resolves provider, token
    // and owner chat the same way every other owner message does.
    if (CHANNEL_PROVIDER === 'telegram' && TELEGRAM_BOT_TOKEN) {
      const ownerChat = resolveOwnerChatId()
      if (!ownerChat) {
        logger.warn({ approvalId: approval.id, informative }, 'approval owner notification suppressed: no owner chat')
        if (!informative) fallbackInBand(approval, 'no-owner-chat')
        return
      }
      try {
        const messageId = await sendTelegramMessage(TELEGRAM_BOT_TOKEN, ownerChat, text)
        if (!informative && messageId != null) setApprovalTelegramMessageId(approval.id, messageId)
        logger.info({ approvalId: approval.id, messageId, informative }, 'approval owner notification sent')
      } catch (err) {
        logger.warn({ err, approvalId: approval.id, informative }, 'approval owner notification FAILED -- the request is only visible on the dashboard')
        if (!informative) fallbackInBand(approval, 'send-failed')
      }
      return
    }

    // sendOwnerMessage REPORTS whether it went out (PR1655 review, ask 2). The
    // funnel it wraps swallows every provider exception, so a `catch` here
    // would be unreachable and a failed Discord send would be recorded as a
    // delivered notification. The result is read instead.
    // The literals below are deliberate, not a computed reason string: the
    // delivery contract test (approvals-delivery.test.ts) reads this function's
    // SOURCE and requires every failure path to name its fallback explicitly.
    // That test exists so a refactor cannot quietly drop a fallback -- and it
    // caught exactly that when this branch first used a template string.
    const r = await sendOwnerMessage(text)
    if (r.sent) {
      logger.info({ approvalId: approval.id, provider: CHANNEL_PROVIDER, informative }, 'approval owner notification sent')
      return
    }
    if (r.reason === 'no-token') {
      logger.warn({ approvalId: approval.id, provider: CHANNEL_PROVIDER, informative },
        'approval owner notification suppressed: no channel token')
      if (!informative) fallbackInBand(approval, 'no-token')
      return
    }
    if (r.reason === 'no-owner-chat') {
      logger.warn({ approvalId: approval.id, provider: CHANNEL_PROVIDER, informative },
        'approval owner notification suppressed: no owner chat')
      if (!informative) fallbackInBand(approval, 'no-owner-chat')
      return
    }
    logger.warn({ approvalId: approval.id, provider: CHANNEL_PROVIDER, reason: r.reason, informative },
      'approval owner notification FAILED -- the request is only visible on the dashboard')
    if (!informative) fallbackInBand(approval, 'send-failed')
  })()
}

// Approval notifications go out one at a time, in arrival order (an
// in-process promise chain), so the messages of two notifications (a failed
// button message and its plain notice, say) never interleave in the owner's
// chat. A failed notification never breaks the chain. Other messages of the
// same bot are not ordered against these (accepted trade-off).
let ownerNotificationQueue: Promise<void> = Promise.resolve()

function enqueueOwnerNotification(approvalId: string, task: () => Promise<void>): void {
  // Each task starts on its own macrotask, after the POST's response is out:
  // even its synchronous part (hashing, file reads) never delays the reply.
  ownerNotificationQueue = ownerNotificationQueue
    .then(() => new Promise<void>(r => setImmediate(r)))
    .then(task)
    .catch(() => {
    // The task catches its own failures; this is only the backstop that keeps
    // the chain alive. The error is not logged: it could carry the nonce.
      logger.warn({ approvalId }, 'approval owner notification aborted unexpectedly -- the request is only visible on the dashboard')
    })
}

/** Test seam: settles once every owner notification queued so far is done. */
export function ownerNotificationsSettled(): Promise<void> {
  return ownerNotificationQueue
}

// Pause before the plain notice that follows a failed button message, and the
// cap on a 429 wait.
export const APPROVAL_PART_PAUSE_MS = 1000
export const APPROVAL_RETRY_AFTER_CAP_S = 30
// A 429 without a readable retry_after (Telegram always sends one).
const APPROVAL_RETRY_AFTER_DEFAULT_S = 3

type Sleep = (ms: number) => Promise<void>
let ownerNotificationSleep: Sleep = ms => new Promise(r => setTimeout(r, ms))

/** Test seam: replace the pause/429 sleep; returns the previous one. */
export function setOwnerNotificationSleep(sleep: Sleep): Sleep {
  const prev = ownerNotificationSleep
  ownerNotificationSleep = sleep
  return prev
}

const APPROVE_BUTTON_TEXT = '✅ Jóváhagyom'
const REJECT_BUTTON_TEXT = '❌ Elutasítom'

// A Telegram bot id: the part of a bot token before the colon.
const TELEGRAM_BOT_ID_RE = /^[1-9][0-9]{0,19}$/
// A Telegram user id: a positive decimal integer, no sign, no leading zero.
const TELEGRAM_USER_ID_RE = /^[1-9][0-9]{0,15}$/

export function telegramBotId(token: string | null | undefined): string | null {
  if (typeof token !== 'string') return null
  const t = token.trim()
  const colon = t.indexOf(':')
  if (colon <= 0 || colon === t.length - 1) return null
  const id = t.slice(0, colon)
  return TELEGRAM_BOT_ID_RE.test(id) ? id : null
}

/** True when both tokens belong to the same bot (equal bot ids, both well-formed). */
export function sameTelegramBot(a: string | null | undefined, b: string | null | undefined): boolean {
  const ia = telegramBotId(a)
  return ia != null && ia === telegramBotId(b)
}

function approvalButtons(approvalId: string, approveNonce: string, rejectNonce: string): TelegramInlineKeyboard {
  return {
    inline_keyboard: [[
      { text: APPROVE_BUTTON_TEXT, callback_data: buildCallbackData('approved', approvalId, approveNonce) },
      { text: REJECT_BUTTON_TEXT, callback_data: buildCallbackData('rejected', approvalId, rejectNonce) },
    ]],
  }
}

// The message of an error, with every occurrence of each secret cut out.
function scrubbedErrorText(err: unknown, secrets: string[]): string {
  let text = err instanceof Error ? err.message : String(err)
  for (const secret of secrets) text = text.split(secret).join('<redacted>')
  return text
}

// Epoch seconds as Budapest local time (APP_TZ), the owner-facing format.
function budapestTime(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString('hu-HU', { timeZone: 'Europe/Budapest' })
}

/**
 * Seconds to wait before the one retry of a send Telegram refused with 429
 * (an HTTP 429, or ok:false with error_code 429), capped at
 * APPROVAL_RETRY_AFTER_CAP_S; null for any other error.
 */
export function telegramRetryAfterSeconds(err: unknown): number | null {
  const text = err instanceof Error ? err.message : ''
  if (!/^Telegram API 429\b/.test(text)) return null
  const m = /"retry_after"\s*:\s*(\d{1,6})/.exec(text) ?? /retry after (\d{1,6})/i.exec(text)
  const s = m ? Number(m[1]) : APPROVAL_RETRY_AFTER_DEFAULT_S
  return Math.min(Math.max(s, 1), APPROVAL_RETRY_AFTER_CAP_S)
}

// The button message: one retry after a 429, none otherwise (a timed-out send
// may have landed; repeating it would duplicate the message). The error travels
// on unchanged; the caller scrubs it. Nothing here logs it.
async function sendButtonMessage(
  token: string, chatId: string, text: string, approvalId: string, keyboard: TelegramInlineKeyboard,
): Promise<number | null> {
  try {
    return await sendTelegramMessage(token, chatId, text, keyboard)
  } catch (err) {
    const waitS = telegramRetryAfterSeconds(err)
    if (waitS == null) throw err
    logger.warn({ approvalId, waitS }, 'approval notification hit the Telegram rate limit (429): one retry after the wait')
    await ownerNotificationSleep(waitS * 1000)
    return await sendTelegramMessage(token, chatId, text, keyboard)
  }
}

// --- Card 9a77b3e5: the permission bot (rag_production_d, permission_bot_probe) ---
//
// The owner's buttons for these rows are sent by the permission bot,
// whose token the dashboard reads in-process from the
// Vault entry below. The token is never logged, returned or put in a message;
// only its bot id (the part before the colon) is ever used outside the send
// call itself. The callback comes back through the relay (POST
// /api/approvals/:id/permission-bot); this process only SENDS, it never polls.
export { PERMISSION_BOT_VAULT_ID }

type PermissionBotTokenReader = () => string | null
const vaultPermissionBotToken: PermissionBotTokenReader = () => {
  try { return getSecret(PERMISSION_BOT_VAULT_ID) } catch { return null }
}
let permissionBotTokenReader: PermissionBotTokenReader = vaultPermissionBotToken

/** Test seam: replace the Vault read of the permission-bot token (null = the real one); returns the previous reader. */
export function setPermissionBotTokenReader(reader: PermissionBotTokenReader | null): PermissionBotTokenReader {
  const prev = permissionBotTokenReader
  permissionBotTokenReader = reader ?? vaultPermissionBotToken
  return prev
}

// The tokens of the main bot as far as this install knows it: the one the main
// channel plugin polls, then the one the dashboard's own sends use.
function mainBotTokens(): string[] {
  const tokens: string[] = []
  try {
    const channel = readChannelToken('telegram', join(channelStateDir('telegram'), '.env'))
    if (telegramBotId(channel) != null && channel) tokens.push(channel)
  } catch { /* unreadable: the other source decides */ }
  if (telegramBotId(TELEGRAM_BOT_TOKEN) != null) tokens.push(TELEGRAM_BOT_TOKEN)
  return tokens
}

export type PermissionBotUnavailable =
  | 'bot_id_unpinned' | 'token_missing' | 'token_malformed' | 'token_bot_mismatch'
  | 'main_bot_unresolved' | 'same_as_main_bot'

type PermissionBot =
  | { ok: true; token: string; botId: string }
  | { ok: false; reason: PermissionBotUnavailable }

type PermissionBotWithMain =
  | { ok: true; token: string; botId: string; mainBotId: string }
  | { ok: false; reason: PermissionBotUnavailable }

// The permission bot as configured NOW. Its id is the PINNED PERMISSION_BOT_ID
// (process env / install .env at startup, outside the Bearer's reach); the Vault
// token is only the credential to SEND with, and only while its bot id (the part
// before the colon) IS the pinned id. A missing or malformed pin, no token, a
// malformed token, or a token of another bot is no bot (fail-closed): a token
// swapped into the Vault is never used and never defines who may approve.
function resolvePermissionBot(): PermissionBot {
  const pinned = PERMISSION_BOT_ID
  if (typeof pinned !== 'string' || !TELEGRAM_BOT_ID_RE.test(pinned)) return { ok: false, reason: 'bot_id_unpinned' }
  let raw: string | null = null
  try { raw = permissionBotTokenReader() } catch { raw = null }
  const token = typeof raw === 'string' ? raw.trim() : ''
  if (token === '') return { ok: false, reason: 'token_missing' }
  const tokenBotId = telegramBotId(token)
  if (tokenBotId == null) return { ok: false, reason: 'token_malformed' }
  if (tokenBotId !== pinned) return { ok: false, reason: 'token_bot_mismatch' }
  return { ok: true, token, botId: pinned }
}

// The same, plus the main bot's id: the SEND and the decision paths need it (the
// permission bot must not be the main bot, and a main-bot press must never
// decide). The consume path does not: it only compares against the pinned id.
function resolvePermissionBotWithMain(): PermissionBotWithMain {
  const bot = resolvePermissionBot()
  if (!bot.ok) return bot
  const mains = mainBotTokens()
  const mainBotId = mains.length > 0 ? telegramBotId(mains[0]) : null
  if (mainBotId == null) return { ok: false, reason: 'main_bot_unresolved' }
  if (mainBotId === bot.botId || mains.some(m => sameTelegramBot(m, bot.token))) return { ok: false, reason: 'same_as_main_bot' }
  return { ok: true, token: bot.token, botId: bot.botId, mainBotId }
}

// The owner-facing text of a permission-bot request. Built from the stored,
// validated payload -- never from the requester's action_description -- so
// the owner reads the package, run and window he is approving.
export function buildPermissionBotText(approval: Approval, payload: RagApprovalPayload): string {
  const title = approval.category === 'permission_bot_probe'
    ? 'Engedély-bot próba (nem engedélyez semmit)'
    : 'RAG éles futás (D) jóváhagyása'
  return [
    title,
    `Kérő ügynök: ${approval.agent_id}`,
    `Azonosító: ${approval.id.slice(0, 8)}`,
    `Csomag (sha256 első 16 jele): ${payload.package_sha256.slice(0, 16)}`,
    `Futás (run_id): ${payload.run_id}`,
    `Írási ablak: ${budapestTime(payload.write_window_start)} - ${budapestTime(payload.write_window_end)} (Budapest)`,
    `Lejárat: ${approval.timeout_at ? budapestTime(approval.timeout_at) : 'nincs'}`,
  ].join('\n')
}

function telegramOwnerUserId(): string | null {
  try {
    const owner = resolveAlertOwnerChat()
    return owner.chatId != null && TELEGRAM_USER_ID_RE.test(owner.chatId) ? owner.chatId : null
  } catch {
    return null
  }
}

function notifyPermissionBot(approval: Approval): void {
  const bot = resolvePermissionBotWithMain()
  if (!bot.ok) {
    logger.warn({ approvalId: approval.id, reason: bot.reason }, 'permission-bot approval NOT sent: the permission bot is unavailable -- the owner was not asked')
    fallbackInBand(approval, 'permission-bot-unavailable')
    return
  }
  const ownerChat = telegramOwnerUserId()
  if (ownerChat == null) {
    logger.warn({ approvalId: approval.id, reason: 'owner_unresolved' }, 'permission-bot approval NOT sent: the strict owner is unresolved -- the owner was not asked')
    fallbackInBand(approval, 'no-owner-chat')
    return
  }
  enqueueOwnerNotification(approval.id, async () => {
    const secretPart = bot.token.slice(bot.token.indexOf(':') + 1)
    try {
      const current = getApproval(approval.id)
      const nowS = Math.floor(Date.now() / 1000)
      if (!current || current.status !== 'pending' || (current.timeout_at != null && current.timeout_at <= nowS)) {
        logger.info({ approvalId: approval.id, status: current?.status ?? null }, 'permission-bot approval notification skipped: decided, expired or gone while it waited in the queue')
        return
      }
      const parsed = parseRagApprovalPayload(current.action_payload, current.category)
      if (!parsed.ok) {
        logger.warn({ approvalId: approval.id, field: parsed.field }, 'permission-bot approval NOT sent: the stored payload is not the canonical one')
        return
      }
      const approveNonce = newCallbackNonce()
      const rejectNonce = newCallbackNonce()
      // The hashes go onto the row BEFORE the message: a press can only ever
      // match a button that exists.
      if (!setPermissionBotNonceHashes(approval.id, { approved: nonceHash(approveNonce), rejected: nonceHash(rejectNonce) })) {
        logger.warn({ approvalId: approval.id, reason: 'nonce_not_bound' }, 'permission-bot approval NOT sent: the buttons could not be bound to the row')
        return
      }
      const keyboard = approvalButtons(approval.id, approveNonce, rejectNonce)
      let messageId: number | null
      try {
        messageId = await sendButtonMessage(bot.token, ownerChat, buildPermissionBotText(current, parsed.payload), approval.id, keyboard)
      } catch (err) {
        throw new Error(`permission-bot message failed: ${scrubbedErrorText(err, [bot.token, secretPart, approveNonce, rejectNonce])}`)
      }
      if (messageId != null && !setApprovalTelegramMessageId(approval.id, messageId)) {
        logger.warn({ approvalId: approval.id }, 'permission-bot message sent, but its message id was NOT stamped onto the row')
      }
      if (messageId == null) {
        logger.warn({ approvalId: approval.id }, 'permission-bot message sent without a message_id: NOT bound, every press will be refused (not_bound)')
      }
      logger.info({ approvalId: approval.id, messageId, botId: bot.botId }, 'permission-bot approval notification sent')
    } catch (err) {
      logger.warn({ err, approvalId: approval.id }, 'permission-bot approval notification FAILED -- the owner was not asked')
      fallbackInBand(approval, 'send-failed')
    }
  })
}

function notifyMainAgent(approval: Approval): void {
  // APPROVALVAK821 (b): when the requester IS the main agent, this used to
  // deliver the notification back to the requester itself -- which counted as
  // "notified" while no human ever saw it. The owner Telegram above is the
  // real notification; a self-addressed message is noise that hides the gap.
  if (approval.agent_id === MAIN_AGENT_ID) {
    logger.info({ approvalId: approval.id }, 'approval main-agent notify skipped: requester is the main agent (owner is notified on Telegram)')
    return
  }
  try {
    const content = [
      `[APPROVAL_REQUEST]`,
      `id=${approval.id}`,
      `agent=${approval.agent_id}`,
      `category=${approval.category}`,
      `action=${approval.action_description}`,
      `timeout_at=${approval.timeout_at ?? 'null'}`,
    ].join(' ')
    createAgentMessage('system', MAIN_AGENT_ID, content)
  } catch (err) {
    // Non-fatal: the approval is created regardless; main-agent notification is best-effort
    logger.warn({ err, approvalId: approval.id }, 'Failed to notify main agent of approval request')
  }
}

// MARVEENGAPS1020 (a): a route that needs an approval files it itself, with a
// description it built from the real object, on the same path as POST
// /api/approvals: same row, same timeout rule, same owner and main-agent
// notification. The requester cannot word the request the owner reads.
export function fileServerApproval(params: {
  agent_id: string
  category: string
  action_description: string
  action_payload?: string | null
  content_hash: string
}): Approval {
  const approval = createApproval({
    id: randomUUID(),
    agent_id: params.agent_id,
    category: params.category,
    action_description: params.action_description,
    action_payload: params.action_payload ?? null,
    timeout_at: computeTimeoutAt(params.category, undefined),
    content_hash: params.content_hash,
  })
  // serverFiled: the description is the server's own words, so the reaction path may show it (APPROVALSLACK1030 (2)).
  notifyOwner(approval, null, true)
  notifyMainAgent(approval)
  logger.info({ id: approval.id, agent_id: approval.agent_id, category: approval.category }, 'Approval request filed by the server')
  return approval
}

/** APPROVALSLACK1030 (2) and B: the owner's Slack reactions and typed replies, read by the server (idle while both switches are off). */
export function startApprovalReactionSweeper(): NodeJS.Timeout {
  return startApprovalSlackSweeper({
    setting: reactionDeps.setting,
    token: reactionDeps.token,
    pageUrl: approvalsPageUrl(),
    alert: (t) => { void sendOwnerSlackDm(t).catch(() => {}) },
  })
}

export function startApprovalTimeoutSweeper(): NodeJS.Timeout {
  return setInterval(() => {
    try {
      const expired = expireTimedOutApprovals()
      if (expired > 0) logger.info({ expired }, 'Approval timeout sweep: expired pending approvals')
    } catch (err) {
      logger.warn({ err }, 'Approval timeout sweep failed')
    }
  }, 60_000)
}

// POST /api/approvals/:id/consume with a category other than email_send. The
// acting tool calls it right BEFORE its first irreversible write and acts only
// on 200; 409 means do NOT act (used, unapproved, another plan, another
// category, stale). Same answer shapes as the letter path. email_send and
// data_delete rows are refused here (wrong_category): the server consumes
// those on their own paths.
function handleCategoryConsume(ctx: RouteContext, id: string, body: Record<string, unknown>): void {
  const { res } = ctx
  const { category, content_hash, consumer, ref, max_age_seconds } = body
  if (!isCategoryKey(category)) {
    json(res, { error: 'category must be a category key (lower-case letters, digits, underscore; max 64)' }, 400)
    return
  }
  if (content_hash !== undefined && content_hash !== null && (typeof content_hash !== 'string' || !/^[0-9a-f]{64}$/.test(content_hash))) {
    json(res, { error: 'content_hash, if given, must be the 64-char lowercase sha256 hex anchor the approval was requested with' }, 400)
    return
  }
  if (!isConsumerName(consumer)) {
    json(res, { error: 'consumer is required: 1-120 printable characters naming the acting tool' }, 400)
    return
  }
  if (ref !== undefined && ref !== null && !isConsumeRef(ref)) {
    json(res, { error: 'ref, if given, must be 1-250 printable characters' }, 400)
    return
  }
  const windowSeconds = categoryWindowSeconds(max_age_seconds)
  if (windowSeconds === null) {
    json(res, { error: `max_age_seconds, if given, must be a whole number of seconds between 1 and ${CATEGORY_CONSUME_MAX_WINDOW_S}` }, 400)
    return
  }
  const result = consumeCategoryApproval({
    id,
    category,
    contentHash: typeof content_hash === 'string' ? content_hash : null,
    consumer: consumer.trim(),
    ref: typeof ref === 'string' ? ref.trim() : null,
    windowSeconds,
  })
  if (result.ok) {
    logger.info({ id, category, consumer: consumer.trim(), ref: ref ?? null }, 'Approval consumed by the acting tool')
    json(res, { ok: true, approval: result.approval })
    return
  }
  if (result.reason === 'not_found') {
    json(res, { ok: false, reason: 'not_found' }, 404)
    return
  }
  const a = result.approval
  logger.warn({ id, category, consumer: consumer.trim(), reason: result.reason }, 'Approval consume refused')
  json(res, {
    ok: false,
    reason: result.reason,
    approval: a ? { id: a.id, status: a.status, consumed_at: a.consumed_at, consumed_by: a.consumed_by, consumed_ref: a.consumed_ref } : null,
  }, 409)
}

export async function tryHandleApprovals(ctx: RouteContext): Promise<boolean> {
  const { req, res, path, method, url } = ctx

  // POST /api/approvals -- create new approval request
  if (path === '/api/approvals' && method === 'POST') {
    let body: { agent_id?: unknown; category?: unknown; action_description?: unknown; action_payload?: unknown; timeout_seconds?: unknown; content_hash?: unknown; owner_approved_message_id?: unknown; for_agent?: unknown }
    try {
      body = JSON.parse((await readBody(req)).toString())
    } catch {
      json(res, { error: 'Invalid JSON' }, 400)
      return true
    }

    const { agent_id, category, action_description, action_payload, timeout_seconds, content_hash, owner_approved_message_id, for_agent } = body
    if (typeof agent_id !== 'string' || !agent_id.trim()) {
      json(res, { error: 'agent_id is required' }, 400)
      return true
    }
    if (typeof category !== 'string' || !category.trim()) {
      json(res, { error: 'category is required' }, 400)
      return true
    }
    // D3(b): second_review rows are filed by the server only (routes/review-action.ts), with the
    // exact call as payload. A caller-filed row could carry a call's hash under a harmless text.
    if (category.trim() === 'second_review') {
      json(res, { error: 'category second_review is reserved for the server' }, 403)
      return true
    }
    if (typeof action_description !== 'string' || !action_description.trim()) {
      json(res, { error: 'action_description is required' }, 400)
      return true
    }
    if (action_payload !== undefined && typeof action_payload !== 'string') {
      json(res, { error: 'action_payload must be a string (JSON) if provided' }, 400)
      return true
    }
    // EMAILKAPU901 PR2: the email-approval-gate hook hands the requesting
    // agent this exact sha256 anchor (to+cc+subject+body); a malformed value
    // could never match the gate's recomputation, so reject it loudly here
    // instead of storing a row that silently authorizes nothing.
    if (content_hash !== undefined && (typeof content_hash !== 'string' || !/^[0-9a-f]{64}$/.test(content_hash))) {
      json(res, { error: 'content_hash must be a 64-char lowercase sha256 hex string if provided' }, 400)
      return true
    }

    // for_agent grants the row to ONE sub-agent, whose own token (AGENT_TOKENS)
    // may then consume it (auth-gate.ts binding on POST /api/approvals/:id/consume).
    // Granting is the main agent's lane: the gate already refuses the field from
    // a sub-agent token (owner-lane field, 403); this repeats it at the route so
    // the grant never rests on the gate table alone.
    let forAgent: string | null = null
    if (for_agent !== undefined && for_agent !== null) {
      if (ctx.auth?.kind === 'token' && ctx.auth.tokenAgent) {
        json(res, { error: 'for_agent is set only by the main agent; a sub-agent token cannot grant an approval' }, 403)
        return true
      }
      if (!isForAgentName(for_agent)) {
        json(res, { error: 'for_agent, if given, must be one agent name (1-64 chars: letters, digits, _ or -)' }, 400)
        return true
      }
      forAgent = for_agent
    }

    // The main agent may file an approval for an action the
    // owner ALREADY approved in the chat, naming the owner's approving
    // message. Such a row is born approved and the owner is told, not asked.
    // Only the main agent: it is the one reading the owner's chat. Any other
    // requester sending the field is refused outright (not silently ignored),
    // so a caller relying on the field learns at once that it does not apply.
    // A sub-agent that declares its own name is refused; the check rests on
    // the self-declared agent_id, and any holder of the shared dashboard token
    // can send the main agent's name and get a row born approved.
    //
    // The server does not verify the id: it does not check that the message
    // exists, came from the owner, is recent, or refers to this action. Any
    // value of the right shape passes. Whether the owner approved this action
    // in the chat is the main agent's judgement, not a server check.
    //
    // The id is the owner's approving chat message: a positive integer
    // (Telegram), or a short id string for providers whose message ids are not
    // safe integers (a Slack ts, a Discord snowflake). Only an integer id is
    // stored in the row's telegram_message_id column (INTEGER, the same column
    // PATCH writes); a string id is kept in the owner note and the log line.
    let chatApprovedMessageId: number | string | null = null
    if (owner_approved_message_id !== undefined && owner_approved_message_id !== null) {
      if (!mayActAsOwner(ctx.auth, req)) {
        logger.warn({ agent_id, category, auth: ctx.auth?.kind, agent: ctx.auth?.agent }, 'born-approved approval refused: no owner session')
        refuseOwner(res, OWNER_ONLY.error)
        return true
      }
      if (agent_id.trim() !== MAIN_AGENT_ID) {
        json(res, { error: 'owner_approved_message_id is only accepted from the main agent; a requesting agent cannot pre-approve its own request' }, 400)
        return true
      }
      const okInt = typeof owner_approved_message_id === 'number' && Number.isSafeInteger(owner_approved_message_id) && owner_approved_message_id > 0
      const okStr = typeof owner_approved_message_id === 'string' && /^[A-Za-z0-9._:-]{1,64}$/.test(owner_approved_message_id)
      if (!okInt && !okStr) {
        json(res, { error: 'owner_approved_message_id must be the owner\'s approving chat message id (a positive integer, or an id string of 1-64 [A-Za-z0-9._:-] characters) if provided' }, 400)
        return true
      }
      chatApprovedMessageId = owner_approved_message_id as number | string
    }

    const id = randomUUID()
    const timeout_at = computeTimeoutAt(category, timeout_seconds)
    let approval = createApproval({
      id,
      agent_id: agent_id.trim(),
      category: category.trim(),
      action_description: action_description.trim(),
      action_payload: typeof action_payload === 'string' ? action_payload : null,
      timeout_at,
      content_hash: typeof content_hash === 'string' ? content_hash : null,
      for_agent: forAgent,
    })
    if (chatApprovedMessageId != null) {
      // Same resolve path as PATCH, so the row is indistinguishable from a
      // PATCH-approved one for every reader (e.g. the email-approval-gate).
      resolveApproval(id, 'approved', `${CHANNEL_PROVIDER}_text`,
        typeof chatApprovedMessageId === 'number' ? chatApprovedMessageId : null)
      approval = getApproval(id) ?? approval
    }

    notifyOwner(approval, chatApprovedMessageId)
    notifyMainAgent(approval)
    logger.info({ id, agent_id, category, chatApprovedMessageId, forAgent }, chatApprovedMessageId != null ? 'Approval created as already approved in chat' : 'Approval request created')
    json(res, approval, 201)
    return true
  }

  // GET /api/approvals -- list with filters
  if (path === '/api/approvals' && method === 'GET') {
    const agent_id = url.searchParams.get('agent') ?? undefined
    const category = url.searchParams.get('category') ?? undefined
    const status = url.searchParams.get('status') ?? undefined
    const limitRaw = url.searchParams.get('limit')
    const limit = limitRaw ? Math.min(parseInt(limitRaw, 10) || 100, 500) : 100

    const items = listApprovals({ agent_id, category, status, limit })
    json(res, items)
    return true
  }

  // POST /api/approvals/:id/consume -- f2c5edb0: one-shot consumption on the
  // SEND path. A sender the gate cannot see (a script that mails from another
  // host) calls this right BEFORE the letter goes out and sends only on 200.
  // 409 means do NOT send: the approval is used, unapproved, for another letter,
  // or stale -- and a second attempt on a used approval is the double send this
  // exists to stop.
  // With "category": "<key>" (anything but email_send) the same route consumes
  // an approval of that category once, for the tool about to act on it
  // (handleCategoryConsume above).
  const consumeMatch = path.match(/^\/api\/approvals\/([^/]+)\/consume$/)
  if (consumeMatch && method === 'POST') {
    // A sub-agent's own token (AGENT_TOKENS) reaches this route only for its
    // own request or a row the main agent granted to it with for_agent (the
    // gate's identity binding). The route repeats the check so the rule never
    // rests on the gate table alone; agent_id and for_agent are written once at
    // creation and never updated. Same uniform 403 as the gate: no consume,
    // and nothing said about whether the id exists.
    const caller = ctx.auth?.kind === 'token' ? ctx.auth.tokenAgent : undefined
    if (caller && approvalGranteeOf(getApproval(consumeMatch[1])) !== caller) {
      json(res, identityDenialBody(caller, MAIN_AGENT_ID, approvalNotGrantedReason(caller)), 403)
      return true
    }
    let body: { content_hash?: unknown; consumer?: unknown; message_id?: unknown; category?: unknown }
    try {
      body = JSON.parse((await readBody(req)).toString())
    } catch {
      json(res, { error: 'Invalid JSON' }, 400)
      return true
    }
    if (body === null || typeof body !== 'object' || Array.isArray(body)) {
      json(res, { error: 'body must be a JSON object' }, 400)
      return true
    }
    // A body naming any category other than email_send is the generic one-shot
    // path. No category (or email_send, or null) is the letter path below,
    // exactly as before.
    if (body.category !== undefined && body.category !== null && body.category !== 'email_send') {
      handleCategoryConsume(ctx, consumeMatch[1], body as Record<string, unknown>)
      return true
    }
    const { content_hash, consumer, message_id } = body
    if (typeof content_hash !== 'string' || !/^[0-9a-f]{64}$/.test(content_hash)) {
      json(res, { error: 'content_hash must be the 64-char lowercase sha256 hex anchor of the letter being sent' }, 400)
      return true
    }
    if (!isConsumerName(consumer)) {
      json(res, { error: 'consumer is required: 1-120 printable characters naming the sending tool' }, 400)
      return true
    }
    if (message_id !== undefined && message_id !== null && !isMessageId(message_id)) {
      json(res, { error: 'message_id, if given, must be one RFC 5322 id like <local@domain> (max 250 chars)' }, 400)
      return true
    }
    const result = consumeApproval({
      id: consumeMatch[1],
      contentHash: content_hash,
      consumer: consumer.trim(),
      messageId: typeof message_id === 'string' ? message_id : null,
      windowSeconds: approvalWindowSeconds(),
    })
    if (result.ok) {
      logger.info({ id: consumeMatch[1], consumer: consumer.trim(), ref: message_id ?? null }, 'Approval consumed by the send path')
      json(res, { ok: true, approval: result.approval })
      return true
    }
    if (result.reason === 'not_found') {
      json(res, { ok: false, reason: 'not_found' }, 404)
      return true
    }
    const a = result.approval
    logger.warn({ id: consumeMatch[1], consumer: consumer.trim(), reason: result.reason }, 'Approval consume refused')
    json(res, {
      ok: false,
      reason: result.reason,
      approval: a ? { id: a.id, status: a.status, consumed_at: a.consumed_at, consumed_by: a.consumed_by, consumed_ref: a.consumed_ref } : null,
    }, 409)
    return true
  }

  // GET /api/approvals/:id -- status poll
  const idMatch = path.match(/^\/api\/approvals\/([^/]+)$/)
  if (idMatch && method === 'GET') {
    const approval = getApproval(idMatch[1])
    if (!approval) {
      json(res, { error: 'Not found' }, 404)
      return true
    }
    json(res, approval)
    return true
  }

  // PATCH /api/approvals/:id -- resolve (approve/reject/timeout)
  if (idMatch && method === 'PATCH') {
    let body: { status?: unknown; resolved_by?: unknown; telegram_message_id?: unknown }
    try {
      body = JSON.parse((await readBody(req)).toString())
    } catch {
      json(res, { error: 'Invalid JSON' }, 400)
      return true
    }

    const { status, resolved_by, telegram_message_id } = body
    if (status !== 'approved' && status !== 'rejected' && status !== 'timeout') {
      json(res, { error: 'status must be approved, rejected, or timeout' }, 400)
      return true
    }
    if (typeof resolved_by !== 'string' || !resolved_by.trim()) {
      json(res, { error: 'resolved_by is required' }, 400)
      return true
    }
    const msgId = typeof telegram_message_id === 'number' ? telegram_message_id : null

    // Approving takes the owner (see OWNER_ONLY); rejecting or timing out does not, since
    // an agent that cancels a request gains nothing by it.
    if (status === 'approved' && !mayActAsOwner(ctx.auth, req)) {
      logger.warn({ id: idMatch[1], resolved_by, auth: ctx.auth?.kind, agent: ctx.auth?.agent }, 'approval approve refused: no owner session')
      refuseOwner(res, OWNER_ONLY.error)
      return true
    }

    // Self-approval guard: the requesting agent cannot approve its own request.
    // This is a best-effort check on the self-declared resolved_by value (all fleet
    // agents share the same bearer token, so server-side identity is not enforceable).
    // It catches naive/accidental self-approvals; the real control lives on the
    // main-agent side (approval-request-handling skill).
    const target = getApproval(idMatch[1])
    if (target && resolved_by.trim() === target.agent_id) {
      json(res, { error: 'The requesting agent cannot approve its own request' }, 403)
      return true
    }

    const updated = resolveApproval(idMatch[1], status, resolved_by.trim(), msgId)
    if (!updated) {
      // Either not found or already resolved
      const existing = getApproval(idMatch[1])
      if (!existing) {
        json(res, { error: 'Not found' }, 404)
      } else {
        json(res, { error: `Already resolved as ${existing.status}` }, 409)
      }
      return true
    }

    const approval = getApproval(idMatch[1])
    logger.info({ id: idMatch[1], status, resolved_by }, 'Approval resolved')
    json(res, approval)
    return true
  }

  return false
}
