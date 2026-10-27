// fec6335f N3b: the MAIN agent's settings under INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid.
//
// Every main-session launch strips the key names from its environment (the
// INTERACTIVE_UNSET prefix in buildMainSessionRespawnCmd and channels.sh). An
// `env` key or an apiKeyHelper in a settings file that session loads is out of
// that unset's reach. For a sub-agent that refuses the start (startAgentProcess);
// for the main agent it does NOT (blueprint 12.8): the channel staying reachable
// comes first and the loss is bounded, so the session starts and the finding is
// made loud instead -- a guard event per file (the credit gate turns it into an
// INCIDENT) and a direct alert to the owner (notifyChannel).
//
// Called from resolveMainConfigDecision(), the one production source of the
// decision every in-process respawn needs, so a respawn path cannot skip it.
// channels.sh does the same scan for the launchd/systemd boot path.
//
// NAMES ONLY: the scan reads property names, the event and the alert carry names
// and paths, never a value.

import { createHash } from 'node:crypto'
import { lstatSync, mkdirSync, readFileSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join } from 'node:path'
import { MAIN_AGENT_ID, PROJECT_ROOT, STORE_DIR } from '../config.js'
import { logger } from '../logger.js'
import { notifyChannel } from '../notify.js'
import { atomicWriteFileSync } from './atomic-write.js'
import {
  interactiveKeyPolicy,
  recordGuardEvent,
  scanSettingsForInteractiveKeys,
  type InteractiveKeyPolicy,
  type SettingsFinding,
} from './interactive-key-guard.js'

/**
 * The settings files the main session loads: its user config dir (the isolated,
 * explicit or plan dir when the decision has one, else the shared ~/.claude) and
 * the install's project scope (the session's cwd).
 */
export function mainAgentSettingsPaths(
  configDir: string | null,
  projectRoot: string = PROJECT_ROOT,
  home: string = homedir(),
): string[] {
  return [
    join(configDir ?? join(home, '.claude'), 'settings.json'),
    join(projectRoot, '.claude', 'settings.json'),
    join(projectRoot, '.claude', 'settings.local.json'),
  ]
}

// Same rule as the runtime guard (N3c): one alert per fingerprint a day, a
// changed finding at once. The guard event is written on every launch.
//
// The fingerprint is per finding (path + names), and the ledger is shared with
// the runtime guard (interactive-key-guard-runner.ts), which turns the guard
// events channels.sh and the custom-provider helper write -- the shell launch
// paths, which cannot reach Telegram themselves -- into the same owner alert.
// One ledger, so a launch this process already alerted on is not alerted a
// second time when the runner reads its event back from the file.
//
// The ledger is a file under the store (store/interactive-key-guard-owner-alerts.json,
// 0600, written atomically), so "once a day" survives a dashboard restart: kept
// in memory only, every restart alerted the owner again. The in-memory map stays
// as the floor -- a store that cannot be read or written degrades to the
// per-process dedupe, never to an alert on every launch. Names and paths only.
const ALERT_REPEAT_MS = 24 * 60 * 60 * 1000
const lastAlertAt = new Map<string, number>()
let ledgerPathOverride: string | null = null

/** store/interactive-key-guard-owner-alerts.json: the owner-alert ledger. */
export function ownerAlertLedgerPath(): string {
  return ledgerPathOverride ?? join(STORE_DIR, 'interactive-key-guard-owner-alerts.json')
}

/** Test hook: redirect the ledger file (null = the store default). */
export function setOwnerAlertLedgerPathForTest(path: string | null): void {
  ledgerPathOverride = path
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException)?.code ?? 'unknown'
}

function loadOwnerAlertLedger(path: string): Record<string, number> {
  const alerts: Record<string, number> = {}
  try {
    const s = JSON.parse(readFileSync(path, 'utf-8')) as { alerts?: unknown }
    if (s.alerts && typeof s.alerts === 'object') {
      for (const [k, v] of Object.entries(s.alerts)) if (typeof v === 'number' && Number.isFinite(v)) alerts[k] = v
    }
  } catch (err) {
    if (errCode(err) !== 'ENOENT') logger.warn({ path, code: errCode(err) }, 'main-agent-key-guard: owner-alert ledger unreadable (per-process dedupe only)')
  }
  return alerts
}

function saveOwnerAlertLedger(path: string, alerts: Record<string, number>, now: number): void {
  const kept: Record<string, number> = {}
  for (const [k, v] of Object.entries(alerts)) if (now - v < ALERT_REPEAT_MS) kept[k] = v
  try {
    mkdirSync(dirname(path), { recursive: true })
    atomicWriteFileSync(path, JSON.stringify({ v: 1, alerts: kept }), { mode: 0o600 })
  } catch (err) {
    logger.warn({ path, code: errCode(err) }, 'main-agent-key-guard: owner-alert ledger not saved (a dashboard restart may repeat the alert)')
  }
}

/**
 * What an owner alert is about. The dedupe key is (source, agent, names) -- not
 * a path or any other free text a writer of the event file controls (BE-1): a
 * varied `where` used to open a new key, and a new Telegram message, every time.
 */
export interface OwnerAlertFinding {
  source: string
  agent: string
  names: readonly string[]
}

// At most one owner alert an hour, whatever the keys: a writer that varies the
// names still cannot turn the guard into a Telegram flood. A capped finding is
// not marked, so it is alerted once the hour has passed.
const OWNER_ALERT_MIN_GAP_MS = 60 * 60 * 1000
const ANY_ALERT_KEY = '__any__'

function ownerAlertKey(f: OwnerAlertFinding): string {
  return JSON.stringify([f.source, f.agent, [...f.names].sort()])
}

/**
 * Claim the owner alert for these findings: true (and every one of them marked
 * as alerted at `now`) when at least one was not alerted in the last 24 hours
 * and no owner alert went out in the last hour; false otherwise.
 */
export function claimMainOwnerAlert(findings: readonly OwnerAlertFinding[], now: number): boolean {
  const path = ownerAlertLedgerPath()
  const ledger = loadOwnerAlertLedger(path)
  const last = (k: string) => Math.max(lastAlertAt.get(k) ?? -Infinity, ledger[k] ?? -Infinity)
  const keys = findings.map(ownerAlertKey)
  const due = keys.some((k) => now - last(k) >= ALERT_REPEAT_MS)
  if (!due || now - last(ANY_ALERT_KEY) < OWNER_ALERT_MIN_GAP_MS) return false
  for (const k of [...keys, ANY_ALERT_KEY]) {
    lastAlertAt.set(k, now)
    ledger[k] = now
  }
  saveOwnerAlertLedger(path, ledger, now)
  return true
}

export interface MainSettingsKeyDeps {
  policy?: InteractiveKeyPolicy
  scan?: (paths: readonly string[]) => SettingsFinding[]
  notify?: (text: string) => Promise<void>
  now?: () => number
  home?: string
  projectRoot?: string
}

export function mainSettingsKeyAlertText(findings: readonly SettingsFinding[]): string {
  const where = findings.map((f) => `${f.path} (${f.names.join(', ')})`).join('; ')
  return (
    `🔑 [interactive-key-guard] A fo agens (${MAIN_AGENT_ID}) settings-fajlja API-kulcs utat hordoz ` +
    `INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid mellett: ${where}. ` +
    'A fo agens ennek ellenere elindult (a csatorna elerhetosege az elso), de ez a kulcs a vasarolt kreditet fogyaszthatja. ' +
    'Teendo: a kulcsnev eltavolitasa a fenti settings-fajlbol, majd a fo session ujrainditasa.'
  )
}

/**
 * Under forbid, scan the main session's settings for an API-key route; for each
 * finding write a guard event, and alert the owner (deduplicated). Returns the
 * findings ([] under allow, where nothing is read). Never throws: a guard must
 * not be the reason a respawn fails.
 */
export function reportMainAgentSettingsKeys(configDir: string | null, deps: MainSettingsKeyDeps = {}): SettingsFinding[] {
  try {
    const policy = deps.policy ?? interactiveKeyPolicy()
    if (policy !== 'forbid') return []
    const scan = deps.scan ?? ((p: readonly string[]) => scanSettingsForInteractiveKeys(p))
    const findings = scan(mainAgentSettingsPaths(configDir, deps.projectRoot, deps.home))
    if (findings.length === 0) return []
    for (const f of findings) {
      recordGuardEvent({ source: 'main-launch-guard', where: f.path, names: f.names, agent: MAIN_AGENT_ID })
    }
    const now = (deps.now ?? Date.now)()
    if (claimMainOwnerAlert(findings.map((f) => ({ source: 'main-launch-guard', agent: MAIN_AGENT_ID, names: f.names })), now)) {
      const notify = deps.notify ?? notifyChannel
      notify(mainSettingsKeyAlertText(findings)).catch((err) => {
        logger.warn({ err }, 'main-agent-key-guard: owner alert not delivered')
      })
    }
    return findings
  } catch (err) {
    logger.warn({ err }, 'main-agent-key-guard: settings scan failed (continuing the launch)')
    return []
  }
}

// ---- the channels.sh refusal marker -------------------------------------------------
//
// When channels.sh refuses the main agent (forbid + an Anthropic customProvider,
// the custom-provider helper's exit 3) it writes store/.channels-key-guard-refused:
// "<epoch seconds> <sha256 of the decision's inputs>", and holds the refusal for
// KEY_GUARD_REFUSAL_HOLD_S (it re-runs the decision on every start, only the
// repeat event is left out). The dashboard reads the same marker for ONE thing:
// a main session that is absent because of a standing refusal is not reported
// as "session gone, restarting" every few minutes -- the owner hears about it
// once a day instead. createMainChannelsSession still starts channels.sh, so
// the decision is never skipped here either.
//
// Any process of this uid can write the store, so the marker only counts (BE-1):
// under forbid; as a regular file (lstat, not a symlink) owned by this uid; with
// an mtime and a time that are not in the future; and while the inputs hash the
// same BY CONTENT (an mtime can be set to anything). Same rules as channels.sh,
// same input list and hash.
export const KEY_GUARD_REFUSAL_HOLD_S = 300

export interface KeyGuardRefusalPaths {
  marker: string
  inputs: string[]
}

let refusalPathsOverride: KeyGuardRefusalPaths | null = null

export function keyGuardRefusalPaths(): KeyGuardRefusalPaths {
  return refusalPathsOverride ?? {
    marker: join(STORE_DIR, '.channels-key-guard-refused'),
    inputs: [
      join(PROJECT_ROOT, '.env'),
      join(PROJECT_ROOT, 'agents', MAIN_AGENT_ID, 'agent-config.json'),
      join(STORE_DIR, 'custom-providers.json'),
      join(PROJECT_ROOT, 'dist', 'web', 'interactive-key-guard.js'),
    ],
  }
}

/** Test hook: redirect the marker and the input list (null = the install's). */
export function setKeyGuardRefusalPathsForTest(paths: KeyGuardRefusalPaths | null): void {
  refusalPathsOverride = paths
}

/**
 * sha256 over one line per input -- the sha256 hex of its content, or `absent`
 * -- exactly what channels.sh's _kg_inputs_hash prints. null when an input
 * exists but cannot be read.
 */
export function keyGuardInputsHash(inputs: readonly string[]): string | null {
  let lines = ''
  for (const p of inputs) {
    let st
    try {
      st = statSync(p)
    } catch {
      lines += 'absent\n'
      continue
    }
    if (!st.isFile()) {
      lines += 'absent\n'
      continue
    }
    try {
      lines += createHash('sha256').update(readFileSync(p)).digest('hex') + '\n'
    } catch {
      return null
    }
  }
  return createHash('sha256').update(lines).digest('hex')
}

export interface KeyGuardRefusalDeps {
  policy?: InteractiveKeyPolicy
  paths?: KeyGuardRefusalPaths
  uid?: number
}

/**
 * The standing channels.sh refusal ({ageS, held}), or null when there is none
 * or the marker does not pass the checks above.
 */
export function mainKeyGuardRefusal(nowMs: number, deps: KeyGuardRefusalDeps = {}): { ageS: number; held: boolean } | null {
  try {
    if ((deps.policy ?? interactiveKeyPolicy()) !== 'forbid') return null
    const paths = deps.paths ?? keyGuardRefusalPaths()
    const st = lstatSync(paths.marker)
    const uid = deps.uid ?? process.getuid?.()
    if (!st.isFile() || (uid !== undefined && st.uid !== uid)) return null
    const nowS = Math.floor(nowMs / 1000)
    if (Math.floor(st.mtimeMs / 1000) > nowS) return null
    const m = /^(\d{1,12}) ([0-9a-f]{64})\s*$/.exec(readFileSync(paths.marker, 'utf-8').split('\n')[0] ?? '')
    if (!m) return null
    const at = Number(m[1])
    if (at > nowS) return null
    if (keyGuardInputsHash(paths.inputs) !== m[2]) return null
    const ageS = nowS - at
    return { ageS, held: ageS < KEY_GUARD_REFUSAL_HOLD_S }
  } catch {
    return null
  }
}

/**
 * Whether a refusal from mainKeyGuardRefusal() still STANDS, or is a stale
 * marker that must not keep eating the "session gone" alert. channels.sh only
 * deletes the marker when it reaches the helper and the helper passes; one that
 * exits before it (no node, an early error) leaves the marker behind, and its
 * input hash keeps matching.
 *
 * The rule: the marker counts while `held` (younger than the hold), or while it
 * is no older than the hold measured back from the dashboard's PREVIOUS start
 * of channels.sh (`prevStartMs`; 0 = none in this process). A channels.sh that
 * was started and still refused either sat inside the hold (marker time later
 * than that start minus the hold) or rewrote the marker after that start --
 * so an older marker means the previous start did NOT refuse, and the session
 * really is gone. `held` alone would not do: without launchd only the
 * dashboard restarts channels.sh, once per grace window (> the hold), so a
 * standing refusal is always seen just past its hold, a moment before the
 * channels.sh just started rewrites it. A stale marker suppresses at most two
 * grace windows; a backwards clock counts as no time passed.
 */
export function keyGuardRefusalStands(refusal: { ageS: number; held: boolean }, nowMs: number, prevStartMs: number): boolean {
  if (refusal.held) return true
  if (!prevStartMs) return false
  const sinceStartS = Math.max(0, Math.floor((nowMs - prevStartMs) / 1000))
  return refusal.ageS < KEY_GUARD_REFUSAL_HOLD_S + sinceStartS
}

/**
 * The once-a-day owner alert for a main session that is absent because of a
 * standing refusal. It says that it rests on the marker, and where the marker
 * is: a same-uid process can write a marker that passes every check above
 * (it can compute the input hash too), and then this text stands in for the
 * "session gone, restarting" alert. channels.sh is still started either way;
 * a real refusal leaves its line in store/channels-failures.log.
 */
export function mainSessionHeldAlertText(markerPath: string = keyGuardRefusalPaths().marker): string {
  return (
    `🔑 [interactive-key-guard] A fo agens (${MAIN_AGENT_ID}) nem indul -- a channels.sh elutasito jelolo alapjan (${markerPath}): ` +
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid mellett a fo agens customProvider-e maga az Anthropic (API-kulcsos inditas lenne). ' +
    'A channels.sh ezt 5 percenkent ujraellenorzi, a csatorna addig nem valaszol. ' +
    'Teendo: a fo agens customProvider-enek modositasa vagy torlese (vagy a policy), majd a channels session ujrainditasa. ' +
    'Ha a store/channels-failures.log-ban nincs friss "main-agent-custom-provider refused" sor, a jelolot nem a channels.sh irta: ' +
    'akkor a session valojaban eltunt, es a jelolo torlese utan a szokasos "session eltunt" riasztas jon.'
  )
}

/** Test hook: forget the in-memory alert dedupe (the ledger file is the test's own, see setOwnerAlertLedgerPathForTest). */
export function resetMainSettingsKeyAlertsForTest(): void {
  lastAlertAt.clear()
}
