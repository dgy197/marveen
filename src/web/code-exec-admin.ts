import type http from 'node:http'
import { logger } from '../logger.js'
import { logConfigChange } from '../db.js'
import { notifySecurityEvent } from '../notify.js'
import { json } from './http-helpers.js'
import { BEARER_CODE_EXEC_ADMIN_ENV, callerLabel, isAdminSwitchOn } from './admin-switch.js'
import { bareTokenNeedsSwitch } from './routes/auth.js'
import type { RouteContext } from './routes/types.js'

// Card 89df7a00: the one shared dashboard Bearer (auth kind 'token', held by
// every agent of the fleet) must not create state that RUNS CODE LATER and
// outlives a token rotation: an MCP server entry (POST /api/connectors, the
// catalog install), a cloned repo with npm lifecycle scripts (github-repos), a
// scheduled task's command/preCheck, or an agent's raw .mcp.json. If the token
// leaks, or an agent is prompt-injected, rotating it is not enough when it could
// meanwhile plant a command the machine runs next week. So these paths refuse a
// gated caller with 403 unless the install's .env opens the switch.
//
// Who is gated (execGateApplies, defined once, here): a bare shared token (no
// live dashboard session cookie next to it, same rule as the credential gate)
// and a FULL device key (a rotation-independent credential too, Brainy K2). The
// logged-in owner ('session') and a token request that also carries the owner's
// session cookie are never gated. An operator-scoped key never gets this far
// (the operator gate in web.ts refuses it before any handler).
//
// The handlers call admitCodeExecAdmin ONLY when execGateApplies is true, and
// BEFORE the body is read (or, for the schedule and agent PUTs, after the body
// is parsed but before any write): a refused request writes nothing.
//
// The switch is read per request from the .env only (admin-switch.ts rule; the
// process environment and store/config-overrides.json do not count): open only
// on exactly "1". There is no window mode. Every refusal answers the same 403
// body; the reason is only in the WARN line. The credential switch
// (credential-admin.ts) is a separate key and does not open this one.
const ENABLED = BEARER_CODE_EXEC_ADMIN_ENV

export type CodeExecAction =
  | 'connectors.add'
  | 'mcp_catalog.install'
  | 'connectors.github_repo.add'
  | 'connectors.github_repo.update'
  | 'schedules.exec_fields'
  | 'agents.mcp_json'

export const BEARER_CODE_EXEC_ADMIN_OFF = 'bearer_code_exec_admin_off'

const REFUSAL_BODY = {
  error: `Forbidden for this credential (${ENABLED} is off)`,
  code: BEARER_CODE_EXEC_ADMIN_OFF,
} as const

/**
 * Does the code-exec gate stand in front of this caller? True for a bare shared
 * token and for a full device key; false for a session, a token that also
 * carries a live session cookie, an operator-scoped key, federation and none.
 */
export function execGateApplies(auth: RouteContext['auth'], req?: http.IncomingMessage): boolean {
  if (bareTokenNeedsSwitch(auth, req)) return true
  return auth?.kind === 'device' && auth.scope !== 'operator'
}

/**
 * Call ONLY when execGateApplies is true.
 * false -> the 403 is written and exactly one WARN {caller, at, action, kind,
 *          reason} is logged; the handler returns.
 * true  -> the switch is open; one WARN {caller, at, action, kind, via} is
 *          logged and the handler continues.
 * The WARN never carries a body, a command, a URL or an env value.
 */
export function admitCodeExecAdmin(ctx: RouteContext, action: CodeExecAction): boolean {
  const caller = callerLabel(ctx.req)
  const at = new Date().toISOString()
  const kind = ctx.auth?.kind ?? 'none'
  if (!isAdminSwitchOn(ENABLED)) {
    logger.warn(
      { caller, at, action, kind, reason: 'switch_off' },
      `Code-exec admin refused (${ENABLED} off)`,
    )
    json(ctx.res, REFUSAL_BODY, 403)
    return false
  }
  logger.warn(
    { caller, at, action, kind, via: 'switch' },
    `Code-exec admin by a gated credential (${ENABLED}=1)`,
  )
  return true
}

/**
 * After a SUCCESSFUL gated create/update: one durable audit row (actor 'token',
 * or 'device' for a full device key) and one owner notification. The subject is
 * metadata only (a connector name, a URL host, a task or agent name), never a
 * command, its arguments, an env value or a full URL.
 */
export function recordCodeExecAdmin(action: CodeExecAction, subject: string, auth?: RouteContext['auth']): void {
  logConfigChange('security.bearer_code_exec_admin', null, `${action} ${subject}`, auth?.kind === 'device' ? 'device' : 'token')
  // The text goes through formatForTelegram (Markdown-ish -> Telegram HTML):
  // bare underscores (the action, BEARER_CODE_EXEC_ADMIN_ENABLED, a name) would
  // turn into <i> tags. Inline code spans are exempt from that and HTML-escaped,
  // so the technical parts go into one. A backtick or newline in the
  // (attacker-influenced) subject must not close the span early.
  const code = (t: string) => `\`${t.replace(/[`\r\n]+/g, ' ')}\``
  void notifySecurityEvent(
    `⚙️ Kódfuttatásra képes beállítás a közös tokennel vagy eszközkulccsal: ${code(action)} ${code(subject)} (${code(ENABLED)}). ` +
      'Ha nem te voltál: zárd a kapcsolót, és vedd vissza a változást (MCP-bejegyzés, ütemezés, repó, .mcp.json).',
  )
}
