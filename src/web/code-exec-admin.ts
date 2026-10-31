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
  | 'agents.import'

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
 * The START of a gated create/update, recorded BEFORE its first write (card
 * 89df7a00 N6, BE B2 / E3): one durable audit row (actor 'token', or 'device' for
 * a full device key) and one owner notification. An operation that writes a
 * file and then throws would otherwise leave no trace at all. The subject is
 * metadata only (a connector name, a URL host, a task or agent name), never a
 * command, its arguments, an env value or a full URL. The row and the
 * notification are independent: a failing audit row no longer suppresses the
 * notification (card 80e8eca4).
 */
export function recordCodeExecAdmin(action: CodeExecAction, subject: string, auth?: RouteContext['auth']): void {
  try {
    logConfigChange('security.bearer_code_exec_admin', null, `${action} ${subject}`, auth?.kind === 'device' ? 'device' : 'token')
  } catch (err) {
    logger.error({ err, action }, 'Failed to write the code-exec admin audit row')
  }
  // The text goes through formatForTelegram (Markdown-ish -> Telegram HTML):
  // bare underscores (the action, BEARER_CODE_EXEC_ADMIN_ENABLED, a name) would
  // turn into <i> tags. Inline code spans are exempt from that and HTML-escaped,
  // so the technical parts go into one. A backtick or newline in the
  // (attacker-influenced) subject must not close the span early.
  const code = (t: string) => `\`${t.replace(/[`\r\n]+/g, ' ')}\``
  void notifySecurityEvent(
    `⚙️ Kódfuttatásra képes beállítás a közös tokennel vagy eszközkulccsal: ${code(action)} ${code(subject)} (${code(ENABLED)}). ` +
      'Ha nem te voltál: zárd a kapcsolót, és vedd vissza a változást (MCP-bejegyzés, ütemezés, repó, .mcp.json).',
  ).catch(() => {})
}

export type CodeExecOutcome = 'ok' | 'failed'

// Only the class name of a thrown error may leave this module (never its
// message, which can carry a path, a command or a URL). Anything that is not a
// plain identifier collapses to the fixed word 'Error'.
function errorClassOf(err: unknown): string {
  const name = err instanceof Error ? err.name : ''
  return /^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(name) ? name : 'Error'
}

/**
 * The END of a gated create/update whose start recordCodeExecAdmin already
 * recorded: one audit row with the outcome. 'ok' adds no notification (the start
 * already sent one). 'failed' adds one: the operation may have left a partial
 * state behind, so the owner should look and roll it back. The subject is the
 * same metadata as at the start; a failed outcome adds at most the error CLASS.
 * A failing audit row does not suppress the 'failed' notification (card 80e8eca4).
 */
export function recordCodeExecOutcome(
  action: CodeExecAction,
  subject: string,
  outcome: CodeExecOutcome,
  auth?: RouteContext['auth'],
  err?: unknown,
): void {
  const errClass = outcome === 'failed' ? errorClassOf(err) : ''
  try {
    logConfigChange(
      'security.bearer_code_exec_admin',
      null,
      `${action} ${subject} -> ${outcome}${errClass ? ` (${errClass})` : ''}`,
      auth?.kind === 'device' ? 'device' : 'token',
    )
  } catch (e) {
    logger.error({ err: e, action }, 'Failed to write the code-exec admin outcome row')
  }
  if (outcome !== 'failed') return
  const code = (t: string) => `\`${t.replace(/[`\r\n]+/g, ' ')}\``
  void notifySecurityEvent(
    `⚠️ A kódfuttatásra képes beállítás félúton elhasalt: ${code(action)} ${code(subject)} (${code(errClass)}). ` +
      'Részleges állapot maradhatott: nézd meg, és vedd vissza (MCP-bejegyzés, ügynök-mappa, repó).',
  ).catch(() => {})
}

export interface CodeExecAuditTrail {
  /** Before the first write: the start row + notification. Once per trail; a no-op for an ungated caller. */
  start(subject: string): void
  /** Success: the outcome row. A no-op unless started, and only the first close counts. */
  ok(subject?: string): void
  /** Failure (or an abandoned operation): the outcome row + notification. Same guards as ok. */
  failed(err?: unknown): void
}

/**
 * One request's start/outcome pair for a gated operation (card 89df7a00 N6). A
 * recording failure is logged and never changes the response. Nothing is
 * recorded for an ungated caller, nor for an operation that never started (e.g.
 * refused by a later gate before it wrote anything).
 */
export function codeExecAuditTrail(gated: boolean, action: CodeExecAction, auth: RouteContext['auth']): CodeExecAuditTrail {
  let started = false
  let closed = false
  let startSubject = ''
  const guard = (what: string, fn: () => void): void => {
    try { fn() } catch (err) { logger.error({ err, action }, `Failed to record a code-exec admin ${what}`) }
  }
  return {
    start(subject) {
      if (!gated || started) return
      started = true
      startSubject = subject
      guard('start', () => recordCodeExecAdmin(action, subject, auth))
    },
    ok(subject) {
      if (!started || closed) return
      closed = true
      guard('outcome', () => recordCodeExecOutcome(action, subject ?? startSubject, 'ok', auth))
    },
    failed(err) {
      if (!started || closed) return
      closed = true
      guard('outcome', () => recordCodeExecOutcome(action, startSubject, 'failed', auth, err))
    },
  }
}
