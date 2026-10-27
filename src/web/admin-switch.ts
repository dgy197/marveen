import type http from 'node:http'
import { readEnvFile } from '../env.js'

// Card 053f4e66: install-level switches for the operations the one shared
// dashboard Bearer must not reach by default. Each is OFF unless the install's
// .env holds exactly "1" for it (after the usual .env parsing: trim, one pair
// of quotes); "true", "yes", "", " 1" and a missing key all mean off. Read per
// request from the .env ONLY: launchd does not pass the .env in, and neither a
// process-environment value nor store/config-overrides.json (the dashboard
// Settings page writes that one) may be a second way in.
export const FLEET_IMPORT_APPLY_ENV = 'FLEET_IMPORT_APPLY_ENABLED'
export const MAIN_CHANNEL_ADMIN_ENV = 'MAIN_CHANNEL_ADMIN_ENABLED'

/** The migrate scan allowlist (routes/migrate.ts): PATH-style, ':'-separated absolute folders. */
export const MIGRATE_ROOTS_ENV = 'MIGRATE_ROOTS'

// Card 053f4e66 B: may the shared Bearer issue a credential (dashboard user,
// device key, token password reset, Bridge pairing)? Same "exactly 1 in the
// .env" rule as above. UNTIL and NONCE turn it into a short window (at most
// 900 s, one nonce): the decision lives in credential-admin.ts, which reads
// all three in ONE .env read. In v4 nothing in the code writes UNTIL or NONCE
// (no window CLI ships): window mode exists only if the owner adds both lines
// by hand, and it can only narrow what ENABLED=1 alone already opens.
export const BEARER_CREDENTIAL_ADMIN_ENV = 'BEARER_CREDENTIAL_ADMIN_ENABLED'
export const BEARER_CREDENTIAL_ADMIN_UNTIL_ENV = 'BEARER_CREDENTIAL_ADMIN_UNTIL'
export const BEARER_CREDENTIAL_ADMIN_NONCE_ENV = 'BEARER_CREDENTIAL_ADMIN_NONCE'

/** Every protected install key. An import or any other Bearer-reachable writer must never set these. */
export const ADMIN_SWITCH_KEYS: ReadonlySet<string> = new Set([
  FLEET_IMPORT_APPLY_ENV, MAIN_CHANNEL_ADMIN_ENV, MIGRATE_ROOTS_ENV,
  BEARER_CREDENTIAL_ADMIN_ENV, BEARER_CREDENTIAL_ADMIN_UNTIL_ENV, BEARER_CREDENTIAL_ADMIN_NONCE_ENV,
])

export function isAdminSwitchOn(key: string): boolean {
  return readEnvFile([key])[key] === '1'
}

/** Is this key one of the protected install keys? Trimmed and upper-cased, so "x " or "x" in lower case cannot slip by. */
export function isAdminSwitchKey(key: string): boolean {
  return ADMIN_SWITCH_KEYS.has(String(key).trim().toUpperCase())
}

const CALLER_MAX = 64

/**
 * The self-asserted X-Agent-Id, for refusal logs only (never an authorization
 * input). Capped and reduced to a safe charset so a crafted header cannot
 * forge or bloat log lines; "unknown" when absent.
 */
export function callerLabel(req: http.IncomingMessage): string {
  const raw = req.headers['x-agent-id']
  const value = (Array.isArray(raw) ? raw[0] : raw)?.trim() ?? ''
  const safe = value.slice(0, CALLER_MAX).replace(/[^A-Za-z0-9_.@-]/g, '_')
  return safe || 'unknown'
}
