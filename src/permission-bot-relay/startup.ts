// Start-up gates of the permission-bot relay (card d7f586bf, spec F1, F5).
//
// Every gate is fail-closed: the relay polls only when ALL of these hold, in
// this order:
//   1. the switch is on (PERMISSION_BOT_RELAY_ENABLED=1)      else disabled
//   2. the pinned PERMISSION_BOT_ID is present and well formed
//   3. the owner resolves (the dashboard's strict rule)      F1.5
//   4. the Vault holds a token for the permission bot         F1.1
//   5. the token's bot id (before the colon) is the pin
//   6. the pin is not the main bot's id
//   7. getMe answers with the pinned id and is_bot
// A refusal writes refused:<reason> to the status file, logs the reason BY NAME
// (never a value: no id, no token part), and returns a non-zero exit code. The
// webhook check (F1.3) is the poll loop's own first step (checkWebhookAtStart).
//
// Every input is injected (N3 wires the real ones), so the tests never touch the
// Keychain, the real Vault item, the install .env or the real bot token. The
// defaults below are the production sources: the Vault entry for the token, and
// the same owner rule the dashboard decides with (resolveAlertOwnerChat plus the
// Telegram user-id shape, null on any error).

import { resolveAlertOwnerChat } from '../owner-chat.js'
import { readPermissionBotToken } from '../web/vault.js'
import { BotApiError, createBotApi, type BotApi } from './bot-api.js'
import type { StatusFile } from './offset-store.js'
import type { RelayLog } from './poll-loop.js'

// Same shapes as the dashboard (approvals.ts / config.ts), copied, not imported:
// importing the route module would pull the database layer into the relay.
export const TELEGRAM_USER_ID_RE = /^[1-9][0-9]{0,15}$/
export const PINNED_BOT_ID_RE = /^[1-9][0-9]{0,15}$/
const TOKEN_BOT_ID_RE = /^[1-9][0-9]{0,19}$/
const TOKEN_SECRET_RE = /^[A-Za-z0-9_-]+$/

export type StartupRefusal =
  | 'bot_id_missing'
  | 'bot_id_invalid'
  | 'owner_unresolved'
  | 'token_missing'
  | 'token_malformed'
  | 'token_bot_mismatch'
  | 'main_bot_unresolved'
  | 'same_as_main_bot'
  | 'getme_mismatch'
  | 'getme_unauthorized'
  | 'getme_unavailable'

export const REFUSED_EXIT_CODE = 2

export type StartupResult =
  | { kind: 'ready'; botId: string; api: BotApi }
  | { kind: 'disabled' }
  | { kind: 'refused'; reason: StartupRefusal; exitCode: number }

export interface StartupDeps {
  // Raw value of the switch (the install .env); only '1' turns the relay on.
  enabled: string | undefined
  // Raw pinned bot id (process environment / install .env, read once by N3).
  pinnedBotId: string | undefined
  // The main bot's token-derived ids (digits only), as far as the install knows.
  mainBotIds: () => string[]
  readToken?: () => string | null
  resolveOwner?: () => string | null
  status: StatusFile
  log: RelayLog
  apiBase?: string
  fetchImpl?: typeof fetch
  shortCallTimeoutMs?: number
  signal?: AbortSignal
}

/** The token from the Vault entry, or null (missing, locked Keychain, any error). */
function vaultPermissionBotToken(): string | null {
  try {
    return readPermissionBotToken()
  } catch {
    return null
  }
}

/** The owner's Telegram user id by the dashboard's strict rule, or null. */
export function strictOwnerUserId(): string | null {
  try {
    const owner = resolveAlertOwnerChat()
    return owner.chatId != null && TELEGRAM_USER_ID_RE.test(owner.chatId) ? owner.chatId : null
  } catch {
    return null
  }
}

/** The bot id of a Bot-API token (the part before the colon), or null. */
export function tokenBotId(token: string | null | undefined): string | null {
  if (typeof token !== 'string') return null
  const t = token.trim()
  const colon = t.indexOf(':')
  if (colon <= 0 || colon === t.length - 1) return null
  const id = t.slice(0, colon)
  if (!TOKEN_BOT_ID_RE.test(id) || !TOKEN_SECRET_RE.test(t.slice(colon + 1))) return null
  return id
}

export async function runStartupGates(deps: StartupDeps): Promise<StartupResult> {
  const { status, log } = deps
  const refuse = (reason: StartupRefusal): StartupResult => {
    status.setState('refused', reason)
    log.error({ alert: 'permission_bot_relay_refused', reason }, 'permission-bot-relay: start-up gate refused, not polling')
    return { kind: 'refused', reason, exitCode: REFUSED_EXIT_CODE }
  }

  // 1. Switch (F1.4): anything but exactly "1" is off.
  if ((deps.enabled ?? '').trim() !== '1') {
    status.setState('disabled', null)
    log.info({ state: 'disabled' }, 'permission-bot-relay: switch is off, not polling')
    return { kind: 'disabled' }
  }

  // 2. Pin (F1.2).
  const pin = (deps.pinnedBotId ?? '').trim()
  if (pin === '') return refuse('bot_id_missing')
  if (!PINNED_BOT_ID_RE.test(pin)) return refuse('bot_id_invalid')

  // 3. Owner (F1.5): the same strict rule the dashboard decides with.
  let owner: string | null = null
  try { owner = (deps.resolveOwner ?? strictOwnerUserId)() } catch { owner = null }
  if (typeof owner !== 'string' || !TELEGRAM_USER_ID_RE.test(owner)) return refuse('owner_unresolved')

  // 4-5. Token from the Vault only (F1.1), and it must be the pinned bot's.
  let raw: string | null = null
  try { raw = (deps.readToken ?? vaultPermissionBotToken)() } catch { raw = null }
  const token = typeof raw === 'string' ? raw.trim() : ''
  if (token === '') return refuse('token_missing')
  const idOfToken = tokenBotId(token)
  if (idOfToken == null) return refuse('token_malformed')
  if (idOfToken !== pin) return refuse('token_bot_mismatch')

  // 6. Never the main bot: a main-bot press must never decide, and polling the
  // main bot here would steal its updates from the channel plugin.
  let mains: string[] = []
  try { mains = deps.mainBotIds().filter((m) => typeof m === 'string' && TOKEN_BOT_ID_RE.test(m)) } catch { mains = [] }
  if (mains.length === 0) return refuse('main_bot_unresolved')
  if (mains.includes(pin)) return refuse('same_as_main_bot')

  // 7. getMe: the token really is the pinned bot.
  const api = createBotApi({ token, apiBase: deps.apiBase, fetchImpl: deps.fetchImpl, shortCallTimeoutMs: deps.shortCallTimeoutMs })
  try {
    const me = await api.getMe(deps.signal)
    if (String(me.id) !== pin || me.is_bot !== true) return refuse('getme_mismatch')
  } catch (err) {
    const kind = err instanceof BotApiError ? err.kind : 'unknown'
    if (err instanceof BotApiError && err.kind === 'fatal' && err.status === 401) return refuse('getme_unauthorized')
    // The masked message stays out: the reason code says enough, and a refused
    // start is retried by the supervisor anyway.
    log.warn({ reason: 'getme_unavailable', kind }, 'permission-bot-relay: getMe failed at start-up')
    return refuse('getme_unavailable')
  }

  log.info({ state: 'starting' }, 'permission-bot-relay: start-up gates passed')
  return { kind: 'ready', botId: pin, api }
}
