import type http from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { readEnvFile } from '../env.js'
import { logger } from '../logger.js'
import { logConfigChange } from '../db.js'
import { notifySecurityEvent } from '../notify.js'
import { json } from './http-helpers.js'
import {
  BEARER_CREDENTIAL_ADMIN_ENV,
  BEARER_CREDENTIAL_ADMIN_UNTIL_ENV,
  BEARER_CREDENTIAL_ADMIN_NONCE_ENV,
  callerLabel,
} from './admin-switch.js'
import type { RouteContext } from './routes/types.js'

// Card 053f4e66 B: the one shared dashboard Bearer (auth kind 'token', held by
// every agent of the fleet) must not issue a new long-lived credential. If it
// leaks, or an agent is prompt-injected, rotating the token is not enough when
// the token could meanwhile mint a device key or a user that outlives the
// rotation. So the four issuing paths -- POST /api/auth/users, POST
// /api/auth/device-keys, the token branch of POST /api/auth/password (it takes
// over an existing user) and POST /api/security/bridge-enroll -- refuse a
// token caller with 403 unless the install's .env opens the switch. So does
// PUT /api/bridge/service-ports (Brainy 2097): it widens an enrolled Bridge
// key's permitopen list, an access widening of an existing credential.
//
// The handlers call admitBearerCredentialAdmin ONLY for a token caller, after
// their kind allowlist and BEFORE the body is read: a refused request writes
// nothing and parses nothing. A 'session' caller (the logged-in owner) never
// reaches it.
//
// The switch, read per request from the .env only (admin-switch.ts rule; the
// process environment and store/config-overrides.json do not count), in ONE
// read of the three keys:
//   - ENABLED is not exactly "1"                -> closed
//   - ENABLED=1, no UNTIL and no NONCE          -> open (manual mode: the owner
//                                                  added the line by hand)
//   - ENABLED=1, UNTIL and NONCE both present   -> window mode: open only while
//       now < UNTIL <= now + 900 (UNTIL is 10-digit epoch seconds) and only for
//       a request whose X-Credential-Window header equals NONCE (43 base64url
//       characters, constant-time compare). The 900 s ceiling is a property of
//       this gate: it closes even if whatever opened the window has died.
//   - anything else (one of the two, or malformed) -> closed
// Every closed case answers the same 403 body; the reason is only in the WARN
// line. The nonce value is never logged and never answered.
// In v4 nothing in the code writes UNTIL or NONCE (the window CLI does not
// ship; the owner opens the switch by hand). Window mode is reachable only by
// the owner adding both lines manually, and it can only narrow: every request
// it admits, ENABLED=1 alone would admit too.
const ENABLED = BEARER_CREDENTIAL_ADMIN_ENV
const UNTIL = BEARER_CREDENTIAL_ADMIN_UNTIL_ENV
const NONCE = BEARER_CREDENTIAL_ADMIN_NONCE_ENV

export type CredentialAdminAction =
  | 'auth.users.create'
  | 'auth.device_keys.create'
  | 'auth.password.break_glass'
  | 'security.bridge_enroll'
  | 'bridge.service_ports.update'
  // Card 89df7a00 N4: a sub-agent's channel pairing (invite, pairing approve,
  // Slack channel request, setup with a foreign allowFrom), routes/agents.ts.
  | 'channel.invite.create'
  | 'channel.pairing.approve'
  | 'channel.request.approve'
  | 'channel.setup.allow_from'

export const BEARER_CREDENTIAL_ADMIN_OFF = 'bearer_credential_admin_off'
export const CREDENTIAL_WINDOW_HEADER = 'x-credential-window'
export const CREDENTIAL_WINDOW_MAX_SECONDS = 900

export type CredentialAdminMode = 'manual' | 'window'
export type CredentialAdminRefusal =
  | 'switch_off'
  | 'window_expired'
  | 'window_too_long'
  | 'window_malformed'
  | 'window_nonce_missing'
  | 'window_nonce_mismatch'

export type SwitchDecision =
  | { open: true; mode: CredentialAdminMode }
  | { open: false; reason: CredentialAdminRefusal }

const REFUSAL_BODY = {
  error: `Forbidden for the shared token (${ENABLED} is off)`,
  code: BEARER_CREDENTIAL_ADMIN_OFF,
} as const

const UNTIL_RE = /^[0-9]{10}$/
const NONCE_RE = /^[A-Za-z0-9_-]{43}$/

function has(env: Readonly<Record<string, string>>, key: string): boolean {
  return Object.prototype.hasOwnProperty.call(env, key)
}

/**
 * K6, the nonce binding of window mode. Kept in this one function so it can be
 * dropped on its own (the window would then be bounded by UNTIL alone). A
 * repeated header (an array, or Node's ", "-joined value) is a mismatch; the
 * compare is timingSafeEqual over equal-length bytes, never ===.
 */
function windowNonceProblem(header: string | string[] | undefined, nonce: string): 'window_nonce_missing' | 'window_nonce_mismatch' | null {
  if (header === undefined || header === '') return 'window_nonce_missing'
  if (typeof header !== 'string') return 'window_nonce_mismatch'
  const presented = Buffer.from(header, 'utf8')
  const expected = Buffer.from(nonce, 'utf8')
  if (presented.length !== expected.length) return 'window_nonce_mismatch'
  return timingSafeEqual(presented, expected) ? null : 'window_nonce_mismatch'
}

/** The switch decision over already-read .env values; pure, nowS in epoch seconds. */
export function decideBearerCredentialSwitch(
  env: Readonly<Record<string, string>>,
  header: string | string[] | undefined,
  nowS: number,
): SwitchDecision {
  if (env[ENABLED] !== '1') return { open: false, reason: 'switch_off' }
  const hasUntil = has(env, UNTIL)
  const hasNonce = has(env, NONCE)
  if (!hasUntil && !hasNonce) return { open: true, mode: 'manual' }
  if (!hasUntil || !hasNonce) return { open: false, reason: 'window_malformed' }
  const untilRaw = env[UNTIL]!
  const nonce = env[NONCE]!
  if (!UNTIL_RE.test(untilRaw) || !NONCE_RE.test(nonce)) return { open: false, reason: 'window_malformed' }
  const until = Number(untilRaw)
  // Written so a NaN nowS fails closed.
  if (!(until > nowS)) return { open: false, reason: 'window_expired' }
  if (!(until <= nowS + CREDENTIAL_WINDOW_MAX_SECONDS)) return { open: false, reason: 'window_too_long' }
  const problem = windowNonceProblem(header, nonce)
  if (problem) return { open: false, reason: problem }
  return { open: true, mode: 'window' }
}

/** The switch for this request: ONE .env read of ENABLED, UNTIL and NONCE. nowS is injectable for tests. */
export function bearerCredentialSwitch(req: http.IncomingMessage, nowS: number = Math.floor(Date.now() / 1000)): SwitchDecision {
  const env = readEnvFile([ENABLED, UNTIL, NONCE])
  return decideBearerCredentialSwitch(env, req.headers[CREDENTIAL_WINDOW_HEADER], nowS)
}

export interface CredentialAdminAdmission {
  mode: CredentialAdminMode
}

/**
 * Call ONLY for a 'token' caller, BEFORE the request body is read.
 * null -> the 403 is written and exactly one WARN {caller, at, action, reason}
 *         is logged; the handler returns.
 * else -> the switch is open; one WARN {caller, at, action, via, mode} is
 *         logged and the handler continues.
 */
export function admitBearerCredentialAdmin(ctx: RouteContext, action: CredentialAdminAction): CredentialAdminAdmission | null {
  const decision = bearerCredentialSwitch(ctx.req)
  const caller = callerLabel(ctx.req)
  const at = new Date().toISOString()
  if (!decision.open) {
    logger.warn(
      { caller, at, action, reason: decision.reason },
      `Credential admin refused for the shared token (${ENABLED} off)`,
    )
    json(ctx.res, REFUSAL_BODY, 403)
    return null
  }
  logger.warn(
    { caller, at, action, via: 'switch', mode: decision.mode },
    `Credential admin by the shared token (${ENABLED}=1)`,
  )
  return { mode: decision.mode }
}

const MODE_TEXT: Record<CredentialAdminMode, string> = {
  manual: 'kézi mód',
  window: 'hitelesítő-ablak',
}

/**
 * After a SUCCESSFUL token mint of a user or a device key: one durable audit
 * row (actor 'token') and one owner notification. The subject is metadata
 * only (a username, or a key's name, id, scope and expiry), never the
 * password or the raw key. The password reset and the Bridge pairing keep
 * their own, existing audit and notification instead.
 */
export function recordBearerCredentialMint(
  action: 'auth.users.create' | 'auth.device_keys.create',
  admission: CredentialAdminAdmission,
  subject: string,
): void {
  logConfigChange('security.bearer_credential_admin', null, `${action} ${subject} mode=${admission.mode}`, 'token')
  const what = action === 'auth.users.create' ? 'Dashboard-felhasználó' : 'Eszközkulcs'
  // The text goes through formatForTelegram (Markdown-ish -> Telegram HTML):
  // bare underscores (expires_at, BEARER_CREDENTIAL_ADMIN_ENABLED, a key name)
  // would turn into <i> tags. Inline code spans are exempt from that and HTML-
  // escaped, so the technical parts go into one. A backtick or newline in the
  // (attacker-influenced) subject must not close the span early.
  const code = (t: string) => `\`${t.replace(/[`\r\n]+/g, ' ')}\``
  void notifySecurityEvent(
    `🔑 ${what} a közös tokennel: ${code(subject)} (${code(ENABLED)}, ${MODE_TEXT[admission.mode]}). ` +
      'Ha nem te voltál: zárd a kapcsolót, és töröld a felhasználót vagy vond vissza a kulcsot a Biztonság fülön.',
  )
}
