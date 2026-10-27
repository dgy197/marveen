// Interactive Anthropic-key guard: INTERACTIVE_ANTHROPIC_KEY_POLICY (fec6335f, PR-A).
//
// An interactive Claude Code session (every tmux agent, the worker, the main
// agent) is not covered by an organisation's API credit: run on an API key it
// bills the key's own prepaid balance. `forbid` makes that impossible for a
// first-party Claude agent on every launch path this install owns:
//   - a config that would launch it on a key (authMode 'api', a custom provider
//     that is Anthropic itself, an auth key in the settings it loads) refuses
//     the start and leaves a guard event behind;
//   - every launch it does allow strips the inherited key names first
//     (INTERACTIVE_UNSET), and the finished command is checked once more right
//     before the sink (assertLaunchCmdClean).
//
// `allow` (also: absent or empty) is today's behaviour, byte for byte: every
// function here returns the no-op answer and nothing is written. Any other
// value is `forbid` -- a typo must not silently switch the guard off.
//
// The policy is read from .env only, never from the settings registry, so a
// Bearer-authenticated API call cannot flip it. It is read once per dashboard
// process (the first launch decision) and kept: an edit takes effect on the
// next dashboard restart, the same as the shell launchers that read it per run.
//
// NAMES ONLY. Nothing in this module reads, returns, logs or writes the value
// of a key: settings are scanned for property names, events carry names.

import { closeSync, constants as fsConstants, fchmodSync, mkdirSync, openSync, readFileSync, writeSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { STORE_DIR } from '../config.js'
import { envFilePath } from '../env.js'
import { logger } from '../logger.js'
import type { AuthMode } from './agent-config.js'
import type { CustomProviderDef } from './custom-providers.js'

export type InteractiveKeyPolicy = 'allow' | 'forbid'

export const INTERACTIVE_KEY_POLICY_KEY = 'INTERACTIVE_ANTHROPIC_KEY_POLICY'

// The shared Team key (spec D-1). A custom provider that reads it is first-party
// whatever URL it points at: the key only works against Anthropic.
export const SHARED_TEAM_KEY_ID = 'ANTHROPIC_API_KEY_BATCH'

// The env names that put Claude Code on an API key, and the settings key that
// computes one. CLAUDE_CODE_OAUTH_TOKEN is deliberately absent: it is the
// subscription path this guard exists to keep agents on.
export const INTERACTIVE_KEY_ENV_NAMES: readonly string[] = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN']
export const API_KEY_HELPER = 'apiKeyHelper'

// Prepended to a first-party launch in forbid mode. A tmux pane inherits the
// SERVER's environment, so a key exported anywhere into that server reaches
// every later pane unless the pane command itself removes it.
export const INTERACTIVE_UNSET = 'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && '

// The same for a `;`-separated chain (the worker's `bash -lc`), where a failed
// `&&` would only skip the next statement: a key that cannot be unset (a
// readonly variable from a login rc file) ends the shell instead of reaching claude.
export const INTERACTIVE_UNSET_OR_EXIT = 'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN || exit 1; '

// The part every unset form shares (`... && ` here, `...; ` in a bash -lc
// chain); assertLaunchCmdClean requires it in a guarded first-party command.
const UNSET_CORE = 'unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN'

// Marker name for a settings file that exists but could not be read.
export const UNREADABLE_SETTINGS = '<unreadable>'

// ---- policy -----------------------------------------------------------------

/** Value -> policy. Empty or absent and `allow` are allow; everything else forbids (fail-closed). */
export function policyFromValue(raw: string | undefined): InteractiveKeyPolicy {
  const v = (raw ?? '').trim()
  return v === '' || v === 'allow' ? 'allow' : 'forbid'
}

// ASCII whitespace only -- exactly what sed's [[:space:]] is in the C locale,
// the shell readers' side (channels.sh, watchdog.sh, morning-briefing.sh).
// String.trim() also strips NBSP, U+2028, a BOM..., which the shell does not:
// that split was a fail-open policy mismatch (BE-1).
const ASCII_WS_TRIM = /^[ \t\v\f\r]+|[ \t\v\f\r]+$/g
const KEY_LINE = new RegExp(`^[ \\t\\v\\f\\r]*${INTERACTIVE_KEY_POLICY_KEY}[ \\t\\v\\f\\r]*=([\\s\\S]*)$`)
const COMMENT_LINE = /^[ \t\v\f\r]*#/

/**
 * The policy from the text of a .env, the same rule as the shell readers: a
 * BOM in front is dropped; the last `KEY=value` line wins (value trimmed of
 * ASCII whitespace, one pair of matching quotes stripped, trimmed again); a
 * non-comment line that names the key in any other shape is forbid.
 */
export function policyFromEnvText(text: string): InteractiveKeyPolicy {
  const body = text.startsWith('\ufeff') ? text.slice(1) : text
  let value: string | undefined
  for (const line of body.split('\n')) {
    if (!line.includes(INTERACTIVE_KEY_POLICY_KEY) || COMMENT_LINE.test(line)) continue
    const m = KEY_LINE.exec(line)
    if (!m) return 'forbid'
    value = m[1]
  }
  let v = (value ?? '').replace(ASCII_WS_TRIM, '')
  if (v.length >= 1 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) v = v.slice(1, -1)
  v = v.replace(ASCII_WS_TRIM, '')
  return v === '' || v === 'allow' ? 'allow' : 'forbid'
}

/**
 * The policy, and whether it may be kept for the life of the process. A
 * missing .env is a definitive allow; one that exists but cannot be read is
 * forbid and NOT definitive -- read again on the next use (BE-1).
 */
export function readInteractiveKeyPolicyDetailed(path: string = envFilePath()): { policy: InteractiveKeyPolicy; definitive: boolean } {
  let text: string
  try {
    text = readFileSync(path, 'utf-8')
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code
    if (code === 'ENOENT') return { policy: 'allow', definitive: true }
    return { policy: 'forbid', definitive: false }
  }
  return { policy: policyFromEnvText(text), definitive: true }
}

/**
 * The policy from .env text (tests and the shell-parity checks pass the text),
 * or from the install's .env when no text is given.
 */
export function readInteractiveKeyPolicy(envFileText?: string): InteractiveKeyPolicy {
  return envFileText !== undefined ? policyFromEnvText(envFileText) : readInteractiveKeyPolicyDetailed().policy
}

let cachedPolicy: InteractiveKeyPolicy | null = null

/** The policy of this dashboard process: read on first use, then kept (an unreadable .env is not kept). */
export function interactiveKeyPolicy(): InteractiveKeyPolicy {
  if (cachedPolicy !== null) return cachedPolicy
  const r = readInteractiveKeyPolicyDetailed()
  if (r.definitive) {
    cachedPolicy = r.policy
    logger.info({ policy: r.policy }, 'interactive-key-guard: policy read from .env')
  } else {
    logger.warn('interactive-key-guard: .env exists but is unreadable -- forbid, read again on the next launch')
  }
  return r.policy
}

/** Test hook: pin the process policy (null = read .env again on next use). */
export function setInteractiveKeyPolicyForTest(policy: InteractiveKeyPolicy | null): void {
  cachedPolicy = policy
}

// ---- first-party ------------------------------------------------------------

/**
 * Does this base URL point at Anthropic? Only an http(s) URL with a host is
 * judged by its host (anthropic.com or a subdomain); anything the URL parser
 * cannot read that way counts as Anthropic (fail-closed), since the guard
 * cannot tell where the CLI would send the key.
 */
export function isAnthropicBaseUrl(baseUrl: string): boolean {
  let u: URL
  try {
    u = new URL(String(baseUrl).trim())
  } catch {
    return true
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return true
  const host = u.hostname.toLowerCase().replace(/\.+$/, '')
  if (!host) return true
  return host === 'anthropic.com' || host.endsWith('.anthropic.com')
}

export interface FirstPartyInput {
  isCustom: boolean
  customProviderDef: Pick<CustomProviderDef, 'baseUrl' | 'vaultKey'> | null
  model: string
  /**
   * The launcher exports no provider URL (the worker, the remote ssh launch):
   * without a customProvider the session reaches Anthropic's endpoint whatever
   * the model NAME is -- an alias like `opus` included (BE-1).
   */
  directAnthropic?: boolean
}

/**
 * Is this agent's traffic Anthropic's own? The launcher's discriminators: a
 * set customProvider wins over the model pattern; without one, a `claude-`
 * model is first-party (the same test as the launcher's isClaude). A custom
 * provider is first-party if it targets *.anthropic.com or reads the shared
 * Team key; one whose definition is missing counts as first-party
 * (the launcher refuses it anyway, and the guard must not be the weaker check).
 */
export function isAnthropicFirstParty(i: FirstPartyInput): boolean {
  if (!i.isCustom) return i.directAnthropic === true || i.model.startsWith('claude-')
  const def = i.customProviderDef
  if (!def) return true
  if ((def.vaultKey ?? '').trim() === SHARED_TEAM_KEY_ID) return true
  return isAnthropicBaseUrl(def.baseUrl)
}

// ---- settings scan (names only) ---------------------------------------------

function ownKey(o: unknown, k: string): boolean {
  return typeof o === 'object' && o !== null && !Array.isArray(o) && Object.prototype.hasOwnProperty.call(o, k)
}

/**
 * The auth names a settings.json text carries: `env` entries from
 * INTERACTIVE_KEY_ENV_NAMES and a top-level `apiKeyHelper`. A text that does
 * not parse is scanned for the quoted names instead, so a broken file can only
 * produce a finding, never hide one. Values are never looked at.
 */
export function interactiveKeyNamesInSettingsText(text: string): string[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(text)
  } catch {
    const raw = [...INTERACTIVE_KEY_ENV_NAMES, API_KEY_HELPER].filter((n) => new RegExp(`"${n}"\\s*:`).test(text))
    return raw
  }
  const env = ownKey(parsed, 'env') ? (parsed as { env: unknown }).env : undefined
  const names = INTERACTIVE_KEY_ENV_NAMES.filter((n) => ownKey(env, n))
  if (ownKey(parsed, API_KEY_HELPER)) names.push(API_KEY_HELPER)
  return names
}

export interface SettingsFinding {
  path: string
  names: string[]
}

/**
 * Scan settings files for auth names. An absent file is no finding; a file that
 * exists but cannot be read is a finding (UNREADABLE_SETTINGS), because the CLI
 * running as the same user would have read it.
 */
export function scanSettingsForInteractiveKeys(
  paths: readonly string[],
  read: (p: string) => string = (p) => readFileSync(p, 'utf-8'),
): SettingsFinding[] {
  const out: SettingsFinding[] = []
  for (const path of paths) {
    let text: string
    try {
      text = read(path)
    } catch (err) {
      const code = (err as NodeJS.ErrnoException)?.code
      if (code === 'ENOENT' || code === 'ENOTDIR') continue
      out.push({ path, names: [UNREADABLE_SETTINGS] })
      continue
    }
    const names = interactiveKeyNamesInSettingsText(text)
    if (names.length) out.push({ path, names })
  }
  return out
}

// ---- launch decision ----------------------------------------------------------

export type InteractiveRefusal = 'first-party-custom-provider' | 'auth-mode-api' | 'settings-auth-key'

export interface InteractiveLaunchCtx extends FirstPartyInput {
  policy: InteractiveKeyPolicy
  authMode: AuthMode
  settingsFindings?: readonly SettingsFinding[]
}

export type InteractiveLaunchDecision =
  | { ok: true; unsetPrefix: string }
  | { ok: false; reason: InteractiveRefusal }

/**
 * May this interactive session start, and with what prefix? `allow`, and every
 * agent that is not first-party, get `{ok:true, unsetPrefix:''}` -- the launch
 * command stays exactly what it was. A first-party agent under `forbid`
 * refuses on any route to a key (I-03), else starts with INTERACTIVE_UNSET.
 */
export function decideInteractiveLaunch(ctx: InteractiveLaunchCtx): InteractiveLaunchDecision {
  if (ctx.policy !== 'forbid') return { ok: true, unsetPrefix: '' }
  if (!isAnthropicFirstParty(ctx)) return { ok: true, unsetPrefix: '' }
  // A first-party custom provider always launches on its own key.
  if (ctx.isCustom) return { ok: false, reason: 'first-party-custom-provider' }
  if (ctx.authMode === 'api') return { ok: false, reason: 'auth-mode-api' }
  if (ctx.settingsFindings && ctx.settingsFindings.length > 0) return { ok: false, reason: 'settings-auth-key' }
  return { ok: true, unsetPrefix: INTERACTIVE_UNSET }
}

/** The names a refusal is about, for the guard event. */
export function refusalNames(reason: InteractiveRefusal, findings: readonly SettingsFinding[] = []): string[] {
  if (reason === 'auth-mode-api') return ['ANTHROPIC_API_KEY']
  if (reason === 'first-party-custom-provider') return [...INTERACTIVE_KEY_ENV_NAMES]
  return [...new Set(findings.flatMap((f) => f.names))]
}

export class InteractiveKeyGuardError extends Error {
  constructor(public readonly names: string[]) {
    super(`interactive-key-guard: launch command carries ${names.join(', ')} for a first-party agent (forbid)`)
    this.name = 'InteractiveKeyGuardError'
  }
}

/**
 * Last check before a sink (S15): a first-party launch under `forbid` must
 * strip the key names and must not set either of them or an apiKeyHelper.
 * Throws InteractiveKeyGuardError; a no-op for `allow` and for every agent
 * that is not first-party.
 */
export function assertLaunchCmdClean(cmd: string, ctx: { policy: InteractiveKeyPolicy; firstParty: boolean }): void {
  if (ctx.policy !== 'forbid' || !ctx.firstParty) return
  const bad = INTERACTIVE_KEY_ENV_NAMES.filter((n) => new RegExp(`\\b${n}\\s*=`).test(cmd))
  if (cmd.includes(API_KEY_HELPER)) bad.push(API_KEY_HELPER)
  if (!cmd.includes(UNSET_CORE)) bad.push('missing-unset')
  if (bad.length) throw new InteractiveKeyGuardError(bad)
}

// ---- guard events -------------------------------------------------------------

export interface GuardEvent {
  source: string
  where: string
  names: readonly string[]
  agent?: string
}

let eventsPathOverride: string | null = null

/** store/interactive-key-guard-events.jsonl, the file the credit gate (PR-B) reads. */
export function guardEventsPath(): string {
  return eventsPathOverride ?? join(STORE_DIR, 'interactive-key-guard-events.jsonl')
}

/** Test hook: redirect the event file (null = the store default). */
export function setGuardEventsPathForTest(path: string | null): void {
  eventsPathOverride = path
}

// An event name is an identifier or the unreadable marker -- never free text,
// so a value can not ride along in the names array.
const NAME_RX = /^[A-Za-z_][A-Za-z0-9_]*$/

/**
 * Append to a 0600 file without following a symlink at its path (O_NOFOLLOW:
 * ELOOP instead of writing through a link a same-uid process planted). Throws.
 */
export function appendNoFollow(path: string, text: string): void {
  mkdirSync(dirname(path), { recursive: true })
  const fd = openSync(path, fsConstants.O_WRONLY | fsConstants.O_APPEND | fsConstants.O_CREAT | fsConstants.O_NOFOLLOW, 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeSync(fd, text)
  } finally {
    closeSync(fd)
  }
}

/**
 * Append one guard event ({ts, source, where, names[], agent?}) and log it.
 * Never throws: a refusal must reach its caller even if the store is not
 * writable (the logger line is then the only record, and says so).
 */
export function recordGuardEvent(ev: GuardEvent): void {
  const names = ev.names.filter((n) => NAME_RX.test(n) || n === UNREADABLE_SETTINGS)
  const line: Record<string, unknown> = { ts: new Date().toISOString(), source: ev.source, where: ev.where, names }
  if (ev.agent) line.agent = ev.agent
  logger.error(line, 'interactive-key-guard: key route blocked')
  const path = guardEventsPath()
  try {
    appendNoFollow(path, JSON.stringify(line) + '\n')
  } catch (err) {
    logger.error({ err, path }, 'interactive-key-guard: could not append the guard event file')
  }
}
