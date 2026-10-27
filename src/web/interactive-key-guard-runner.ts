// fec6335f N3c: the runtime interactive-key guard (spec I-04).
//
// The launch guards (N3a, N3b) keep an API key out of every session they
// start. This runner looks at what is already THERE: at dashboard start and
// every 10 minutes it checks, by NAME only, the places an ANTHROPIC_API_KEY,
// an ANTHROPIC_AUTH_TOKEN or an apiKeyHelper can sit and reach an interactive
// Claude Code session:
//   - the tmux server's global environment and the environment of every
//     Marveen session (`show-environment`; a `-NAME` line means "removed");
//   - the shared ~/.claude/settings.json and the settings every agent loads
//     (its user config dir and its project scope);
//   - the install's .env, the dashboard's own process.env, the login-shell rc
//     files, and the EnvironmentVariables of this install's launchd plists;
//   - best effort, the env of the running interactive `claude` processes.
// Every minute it also reads the guard events the launch paths appended to
// store/interactive-key-guard-events.jsonl since the last read. The shell
// paths (channels.sh, the custom-provider helper) can only write that file
// and a log line; this is where they reach a person.
//
// Alert: a finding in a global source, or in a first-party agent's own source,
// goes to the main agent as an inter-agent message (spec I-04, L-01). A
// guard event about the MAIN agent also goes to the owner on Telegram -- the
// main agent may be the one that did not start -- deduplicated in the same
// ledger as main-agent-key-guard.ts, so a launch the dashboard already alerted
// on is not alerted twice. Same fingerprint: once in 24 hours; a changed one
// at once. A custom-provider agent's own ANTHROPIC_AUTH_TOKEN is not an alert.
// A source that cannot be read is reported as "not measurable": never a
// finding, never silence. Nothing is repaired automatically.
//
// Policy: the runner runs under `allow` too, but there it only writes its
// findings to the audit log (store/interactive-key-guard-audit.jsonl, once a
// day per fingerprint) and sends no message (Brainy, 1798). Only under
// `forbid` does it write guard events for its own findings and alert the main
// agent -- the event file is what moves the credit gate (PR-B) into INCIDENT,
// and under `allow` it must not.
//
// NAMES ONLY. A source that hands over values with the names (`ps -wwE`,
// `tmux show-environment`, .env, rc files) is reduced to the matching names
// inside the parser that receives it, and the text is dropped there. Nothing
// here logs, stores, returns or sends a value; a failed command is reported by
// its exit code, never by its output.

import { execFile } from 'node:child_process'
import { closeSync, fstatSync, mkdirSync, openSync, readFileSync, readSync, readdirSync } from 'node:fs'
import { homedir } from 'node:os'
import { basename, dirname, join } from 'node:path'
import { LEGACY_SERVICE_ID, MAIN_AGENT_ID, PROJECT_ROOT, SERVICE_ID, STORE_DIR } from '../config.js'
import { createAgentMessage } from '../db.js'
import { logger } from '../logger.js'
import { notifyChannel } from '../notify.js'
import { tryResolveFromPath } from '../platform.js'
import { exactTmuxTarget } from '../tmux-target.js'
import { agentDir, listAgentNames, readAgentCustomProvider, readAgentModel } from './agent-config.js'
import {
  agentSessionName,
  mainAgentConfigDirIfSeparate,
  resolveMainAgentConfigDir,
  resolveMainAgentRotatedConfigDir,
  subAgentIsFirstPartyForKeyGuard,
} from './agent-process.js'
import { workerContexts } from './agent-worker.js'
import { resolveAgentConfigDir } from './claude-plans.js'
import { loadCustomProvider } from './custom-providers.js'
import { MAIN_CHANNELS_SESSION } from './main-agent.js'
import { claimMainOwnerAlert, type OwnerAlertFinding } from './main-agent-key-guard.js'
import { atomicWriteFileSync } from './atomic-write.js'
import {
  API_KEY_HELPER,
  appendNoFollow,
  INTERACTIVE_KEY_ENV_NAMES,
  UNREADABLE_SETTINGS,
  guardEventsPath,
  interactiveKeyNamesInSettingsText,
  interactiveKeyPolicy,
  isAnthropicFirstParty,
  recordGuardEvent,
  type GuardEvent,
  type InteractiveKeyPolicy,
} from './interactive-key-guard.js'

export const RUNTIME_GUARD_EVENT_SOURCE = 'runtime-guard'
export const ALERT_REPEAT_MS = 24 * 60 * 60 * 1000
const INITIAL_DELAY_MS = 45_000
const TICK_MS = 60_000
export const FULL_SCAN_MS = 10 * 60_000
// A first read of a long event history only looks at its tail.
const MAX_EVENT_BYTES = 1024 * 1024
const MAX_LISTED_ROWS = 25

// The login-shell files a tmux pane (zsh -c, bash -lc) or a launch script reads.
export const SHELL_RC_FILES: readonly string[] = ['.zshenv', '.zprofile', '.zshrc', '.zlogin', '.profile', '.bash_profile', '.bash_login', '.bashrc']

// ---- parsers: text in, matching names out -------------------------------------

const NAME_RX = /^[A-Za-z_][A-Za-z0-9_]*$/

function inOrder(found: Set<string>): string[] {
  return INTERACTIVE_KEY_ENV_NAMES.filter((n) => found.has(n))
}

/** `tmux show-environment` output: NAME=value lines count, `-NAME` (removed) does not. */
export function keyNamesFromTmuxEnvironment(stdout: string): string[] {
  const found = new Set<string>()
  for (const line of stdout.split('\n')) {
    if (line.startsWith('-')) continue
    const eq = line.indexOf('=')
    if (eq > 0) found.add(line.slice(0, eq))
  }
  return inOrder(found)
}

/** .env text: an assignment (`NAME=`, `export NAME=`) names the key, empty or not. Comments do not. */
export function keyNamesFromDotenv(text: string): string[] {
  const found = new Set<string>()
  for (const line of text.split('\n')) {
    const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=/.exec(line)
    if (m) found.add(m[1])
  }
  return inOrder(found)
}

/**
 * A shell rc file: an assignment anywhere on an active line (`export NAME=`,
 * `NAME=`, the rc-secrets reader line), a `setenv NAME`, or the
 * `# marveen: NAME` marker scripts/lib/rc-secrets.sh writes above its reader.
 * A commented-out assignment and an `unset NAME` are not findings.
 */
export function keyNamesFromShellRc(text: string): string[] {
  const found = new Set<string>()
  for (const raw of text.split('\n')) {
    const line = raw.trim()
    for (const n of INTERACTIVE_KEY_ENV_NAMES) {
      if (line.startsWith('#')) {
        if (new RegExp(`^#\\s*marveen:\\s*${n}\\b`).test(line)) found.add(n)
        continue
      }
      if (new RegExp(`(?:^|[^A-Za-z0-9_$])${n}=`).test(line) || new RegExp(`\\bsetenv\\s+${n}\\b`).test(line)) found.add(n)
    }
  }
  return inOrder(found)
}

/**
 * The key names of a launchd plist's EnvironmentVariables dict (XML form).
 * null = not an XML plist this parser can read (a binary plist): not measurable.
 */
export function keyNamesFromPlist(text: string): string[] | null {
  if (text.startsWith('bplist')) return null
  if (!/<plist[\s>]/.test(text)) return null
  const found = new Set<string>()
  const dictRx = /<key>\s*EnvironmentVariables\s*<\/key>\s*<dict>([\s\S]*?)<\/dict>/g
  for (const d of text.matchAll(dictRx)) {
    for (const k of d[1].matchAll(/<key>\s*([^<]*?)\s*<\/key>/g)) found.add(k[1])
  }
  return inOrder(found)
}

/** `ps -wwE -o command=` output (macOS): the env follows the argv as NAME=value words. */
export function keyNamesFromPsEnv(text: string): string[] {
  const found = new Set<string>()
  for (const n of INTERACTIVE_KEY_ENV_NAMES) {
    if (new RegExp(`(?:^|\\s)${n}=`).test(text)) found.add(n)
  }
  return inOrder(found)
}

/** /proc/<pid>/environ (Linux): NUL-separated NAME=value entries. */
export function keyNamesFromProcEnviron(text: string): string[] {
  const found = new Set<string>()
  for (const entry of text.split('\0')) {
    const eq = entry.indexOf('=')
    if (eq > 0) found.add(entry.slice(0, eq))
  }
  return inOrder(found)
}

/** An env object: own property names only. */
export function keyNamesInEnvObject(env: NodeJS.ProcessEnv): string[] {
  return INTERACTIVE_KEY_ENV_NAMES.filter((n) => Object.prototype.hasOwnProperty.call(env, n))
}

// ---- rows ---------------------------------------------------------------------

export type RuntimeSourceKind =
  | 'dashboard-env'
  | 'dotenv'
  | 'shell-rc'
  | 'launchd-plist'
  | 'settings'
  | 'tmux-global'
  | 'tmux-session'
  | 'claude-process'
  | 'guard-event'
  | 'targets'

export interface RuntimeGuardRow {
  kind: RuntimeSourceKind
  /** A path, a session name, `pid N (session)`, or a launch path label. */
  where: string
  status: 'hit' | 'unmeasurable'
  /** hit: the key names found; unmeasurable: []. */
  names: string[]
  /** global = reaches every interactive session; agent = one agent's own source. */
  scope: 'global' | 'agent'
  agent?: string
  firstParty?: boolean
  /** unmeasurable: a short fixed reason or an errno/exit code, never output text. */
  reason?: string
  /** guard-event rows: the source the launch path wrote (launch-guard, main-launch-guard, ...). */
  eventSource?: string
}

// ---- dependencies (all injectable; the tests never touch tmux, ps or ~/Library) --

export type GuardExecResult = { ok: true; stdout: string } | { ok: false; code: string; stderr: string }
export type GuardExec = (file: string, args: readonly string[]) => Promise<GuardExecResult>

export interface RuntimeAgentTarget {
  agent: string
  firstParty: boolean
  sessions: readonly string[]
  settingsPaths: readonly string[]
}

export interface RuntimeSessionPrefix {
  prefix: string
  agent: string
  firstParty: boolean
}

export interface RuntimeGuardTargets {
  agents: RuntimeAgentTarget[]
  sessionPrefixes: RuntimeSessionPrefix[]
}

export interface RuntimeGuardDeps {
  policy: () => InteractiveKeyPolicy
  now: () => number
  platform: NodeJS.Platform
  home: string
  envFilePath: string
  processEnv: () => NodeJS.ProcessEnv
  launchAgentsDir: string
  launchdPrefixes: readonly string[]
  targets: () => RuntimeGuardTargets
  exec: GuardExec
  tmuxBin: string | null
  psBin: string
  readText: (path: string) => string
  listDir: (path: string) => string[]
  eventsPath: string
  statePath: string
  /** allow mode: where the findings are written instead of a message (names only). */
  auditPath: string
  sendToMain: (text: string) => void
  notifyOwner: (text: string) => Promise<void>
  claimOwnerAlert: (findings: readonly OwnerAlertFinding[], now: number) => boolean
  recordEvent: (ev: GuardEvent) => void
}

/** execFile with a timeout. A failure carries its code and (capped) stderr, never stdout. */
export const defaultGuardExec: GuardExec = (file, args) =>
  new Promise((resolve) => {
    execFile(file, [...args], { encoding: 'utf-8', timeout: 5000, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (!err) {
        resolve({ ok: true, stdout: String(stdout ?? '') })
        return
      }
      const e = err as NodeJS.ErrnoException & { code?: unknown; killed?: boolean }
      const code = typeof e.code === 'string' ? e.code : typeof e.code === 'number' ? `exit ${e.code}` : e.killed ? 'timeout' : 'failed'
      resolve({ ok: false, code, stderr: String(stderr ?? '').slice(0, 300) })
    })
  })

function errCode(err: unknown): string {
  const c = (err as NodeJS.ErrnoException | null)?.code
  return typeof c === 'string' ? c : 'read-failed'
}

function isAbsent(err: unknown): boolean {
  const c = (err as NodeJS.ErrnoException | null)?.code
  return c === 'ENOENT' || c === 'ENOTDIR'
}

const NO_TMUX_SERVER_RX = /no server running|error connecting to|server exited unexpectedly/i
const NO_TMUX_SESSION_RX = /can't find session|session not found|no such session/i

/** Is the main agent first-party? Without a customProvider it always is (the CLI talks to Anthropic). */
function mainAgentFirstParty(): boolean {
  try {
    const id = readAgentCustomProvider(MAIN_AGENT_ID)
    if (!id) return true
    return isAnthropicFirstParty({ isCustom: true, customProviderDef: loadCustomProvider(id), model: readAgentModel(MAIN_AGENT_ID) })
  } catch {
    return true
  }
}

function settingsIn(dir: string): string {
  return join(dir, 'settings.json')
}

/**
 * The production targets: the main agent, the two worker sessions, every
 * sub-agent, and the background-task sessions. An agent whose first-party
 * status cannot be read counts as first-party (the alerting side).
 */
export function defaultRuntimeGuardTargets(): RuntimeGuardTargets {
  const mainFirst = mainAgentFirstParty()
  const mainDirs = [resolveMainAgentConfigDir(), resolveMainAgentRotatedConfigDir(), mainAgentConfigDirIfSeparate()]
    .filter((d): d is string => typeof d === 'string' && d.length > 0)
  const agents: RuntimeAgentTarget[] = [
    {
      agent: MAIN_AGENT_ID,
      firstParty: mainFirst,
      sessions: [MAIN_CHANNELS_SESSION],
      settingsPaths: [
        ...mainDirs.map(settingsIn),
        join(PROJECT_ROOT, '.claude', 'settings.json'),
        join(PROJECT_ROOT, '.claude', 'settings.local.json'),
      ],
    },
  ]
  for (const ctx of workerContexts()) {
    agents.push({
      agent: ctx.session,
      firstParty: mainFirst,
      sessions: [ctx.session],
      settingsPaths: [settingsIn(ctx.configDir), join(ctx.home, '.claude', 'settings.json'), join(ctx.home, '.claude', 'settings.local.json')],
    })
  }
  for (const name of listAgentNames()) {
    if (name === MAIN_AGENT_ID) continue
    let firstParty = true
    try { firstParty = subAgentIsFirstPartyForKeyGuard(name) } catch { firstParty = true }
    let configured: string | null = null
    try { configured = resolveAgentConfigDir(name).configDir } catch { configured = null }
    const dir = agentDir(name)
    agents.push({
      agent: name,
      firstParty,
      sessions: [agentSessionName(name)],
      settingsPaths: [
        ...(configured ? [settingsIn(configured)] : []),
        settingsIn(join(dir, '.claude-config')),
        join(dir, '.claude', 'settings.json'),
        join(dir, '.claude', 'settings.local.json'),
      ],
    })
  }
  return { agents, sessionPrefixes: [{ prefix: 'bg-', agent: 'background-task', firstParty: true }] }
}

export function defaultRuntimeGuardDeps(): RuntimeGuardDeps {
  const home = homedir()
  return {
    policy: interactiveKeyPolicy,
    now: Date.now,
    platform: process.platform,
    home,
    envFilePath: join(PROJECT_ROOT, '.env'),
    processEnv: () => process.env,
    launchAgentsDir: join(home, 'Library', 'LaunchAgents'),
    // The helper and service labels are com.<SERVICE_ID>.* (scripts/launchd-label.sh);
    // the older fixed and legacy names are checked as well.
    launchdPrefixes: [...new Set([`com.${SERVICE_ID}.`, `com.${MAIN_AGENT_ID}.`, 'com.marveen.', `com.${LEGACY_SERVICE_ID}.`, 'com.jarvis.'])],
    targets: defaultRuntimeGuardTargets,
    exec: defaultGuardExec,
    tmuxBin: tryResolveFromPath('tmux'),
    psBin: tryResolveFromPath('ps') ?? '/bin/ps',
    readText: (p) => readFileSync(p, 'utf-8'),
    listDir: (p) => readdirSync(p),
    eventsPath: guardEventsPath(),
    statePath: join(STORE_DIR, 'interactive-key-guard-runner.json'),
    auditPath: join(STORE_DIR, 'interactive-key-guard-audit.jsonl'),
    sendToMain: (text) => { createAgentMessage('system', MAIN_AGENT_ID, text) },
    notifyOwner: notifyChannel,
    claimOwnerAlert: claimMainOwnerAlert,
    recordEvent: recordGuardEvent,
  }
}

// ---- the scan -------------------------------------------------------------------

type ReadOutcome = { state: 'ok'; text: string } | { state: 'absent' } | { state: 'unreadable'; code: string }

function readSource(deps: RuntimeGuardDeps, path: string): ReadOutcome {
  try {
    return { state: 'ok', text: deps.readText(path) }
  } catch (err) {
    return isAbsent(err) ? { state: 'absent' } : { state: 'unreadable', code: errCode(err) }
  }
}

function classifySession(name: string, targets: RuntimeGuardTargets | null): { agent: string; firstParty: boolean } | null {
  if (!targets) return null
  for (const a of targets.agents) if (a.sessions.includes(name)) return { agent: a.agent, firstParty: a.firstParty }
  for (const p of targets.sessionPrefixes) if (name.startsWith(p.prefix)) return { agent: p.agent, firstParty: p.firstParty }
  return null
}

/** Every source once; one row per finding and per source that could not be measured. */
export async function scanRuntimeSources(deps: RuntimeGuardDeps): Promise<RuntimeGuardRow[]> {
  const rows: RuntimeGuardRow[] = []
  const hit = (r: Omit<RuntimeGuardRow, 'status'>): void => {
    if (r.names.length) rows.push({ ...r, status: 'hit' })
  }
  const blind = (r: Omit<RuntimeGuardRow, 'status' | 'names'> & { reason: string }): void => {
    rows.push({ ...r, status: 'unmeasurable', names: [] })
  }

  // The dashboard's own environment: every launch it makes inherits it.
  hit({ kind: 'dashboard-env', where: 'process.env', names: keyNamesInEnvObject(deps.processEnv()), scope: 'global' })

  // .env
  const env = readSource(deps, deps.envFilePath)
  if (env.state === 'ok') hit({ kind: 'dotenv', where: deps.envFilePath, names: keyNamesFromDotenv(env.text), scope: 'global' })
  else if (env.state === 'unreadable') blind({ kind: 'dotenv', where: deps.envFilePath, scope: 'global', reason: env.code })

  // shell rc files
  for (const f of SHELL_RC_FILES) {
    const p = join(deps.home, f)
    const r = readSource(deps, p)
    if (r.state === 'ok') hit({ kind: 'shell-rc', where: p, names: keyNamesFromShellRc(r.text), scope: 'global' })
    else if (r.state === 'unreadable') blind({ kind: 'shell-rc', where: p, scope: 'global', reason: r.code })
  }

  // launchd plists of this install (macOS)
  if (deps.platform === 'darwin') {
    let entries: string[] | null = null
    try {
      entries = deps.listDir(deps.launchAgentsDir)
    } catch (err) {
      if (!isAbsent(err)) blind({ kind: 'launchd-plist', where: deps.launchAgentsDir, scope: 'global', reason: errCode(err) })
    }
    for (const f of (entries ?? []).filter((n) => n.endsWith('.plist') && deps.launchdPrefixes.some((pre) => n.startsWith(pre))).sort()) {
      const p = join(deps.launchAgentsDir, f)
      const r = readSource(deps, p)
      if (r.state === 'unreadable') blind({ kind: 'launchd-plist', where: p, scope: 'global', reason: r.code })
      if (r.state !== 'ok') continue
      const names = keyNamesFromPlist(r.text)
      if (names === null) blind({ kind: 'launchd-plist', where: p, scope: 'global', reason: 'not-an-xml-plist' })
      else hit({ kind: 'launchd-plist', where: p, names, scope: 'global' })
    }
  }

  // targets (agents, sessions)
  let targets: RuntimeGuardTargets | null = null
  try {
    targets = deps.targets()
  } catch (err) {
    blind({ kind: 'targets', where: 'agent list', scope: 'global', reason: errCode(err) })
  }

  // settings: the shared file (global), then each agent's own, each path once
  const shared = join(deps.home, '.claude', 'settings.json')
  const owners = new Map<string, { agents: string[]; firstParty: boolean }>()
  for (const a of targets?.agents ?? []) {
    for (const p of a.settingsPaths) {
      if (p === shared) continue
      const o = owners.get(p) ?? { agents: [], firstParty: false }
      if (!o.agents.includes(a.agent)) o.agents.push(a.agent)
      o.firstParty = o.firstParty || a.firstParty
      owners.set(p, o)
    }
  }
  const settingsRow = (p: string, scope: 'global' | 'agent', agent?: string, firstParty?: boolean): void => {
    const r = readSource(deps, p)
    const base = { kind: 'settings' as const, where: p, scope, ...(agent ? { agent } : {}), ...(firstParty !== undefined ? { firstParty } : {}) }
    if (r.state === 'unreadable') blind({ ...base, reason: r.code })
    if (r.state !== 'ok') return
    hit({ ...base, names: interactiveKeyNamesInSettingsText(r.text) })
  }
  settingsRow(shared, 'global')
  for (const [p, o] of owners) settingsRow(p, 'agent', o.agents.join(','), o.firstParty)

  // tmux: the server's global env, each Marveen session's env, and the claude in each pane
  if (!deps.tmuxBin) {
    blind({ kind: 'tmux-global', where: 'tmux', scope: 'global', reason: 'tmux-not-found' })
    return rows
  }
  const ls = await deps.exec(deps.tmuxBin, ['list-sessions', '-F', '#{session_name}'])
  if (!ls.ok) {
    // No server = no session can inherit anything: nothing to measure, and nothing wrong.
    if (!NO_TMUX_SERVER_RX.test(ls.stderr)) blind({ kind: 'tmux-global', where: 'tmux list-sessions', scope: 'global', reason: ls.code })
    return rows
  }
  const g = await deps.exec(deps.tmuxBin, ['show-environment', '-g'])
  if (g.ok) hit({ kind: 'tmux-global', where: 'tmux show-environment -g', names: keyNamesFromTmuxEnvironment(g.stdout), scope: 'global' })
  else blind({ kind: 'tmux-global', where: 'tmux show-environment -g', scope: 'global', reason: g.code })

  const sessions = ls.stdout.split('\n').map((s) => s.trim()).filter(Boolean)
  const owned = new Map<string, { agent: string; firstParty: boolean }>()
  for (const s of sessions) {
    const c = classifySession(s, targets)
    if (c) owned.set(s, c)
  }
  for (const [s, c] of owned) {
    const r = await deps.exec(deps.tmuxBin, ['show-environment', '-t', exactTmuxTarget(s)])
    if (r.ok) hit({ kind: 'tmux-session', where: s, names: keyNamesFromTmuxEnvironment(r.stdout), scope: 'agent', agent: c.agent, firstParty: c.firstParty })
    else if (!NO_TMUX_SESSION_RX.test(r.stderr)) blind({ kind: 'tmux-session', where: s, scope: 'agent', agent: c.agent, firstParty: c.firstParty, reason: r.code })
  }

  // Best effort: the env the running claude processes actually got.
  if (owned.size === 0) return rows
  if (deps.platform !== 'darwin' && deps.platform !== 'linux') {
    blind({ kind: 'claude-process', where: 'ps', scope: 'global', reason: `unsupported-platform:${deps.platform}` })
    return rows
  }
  const panes = await deps.exec(deps.tmuxBin, ['list-panes', '-a', '-F', '#{session_name}\t#{pane_pid}'])
  if (!panes.ok) {
    blind({ kind: 'claude-process', where: 'tmux list-panes', scope: 'global', reason: panes.code })
    return rows
  }
  const table = await deps.exec(deps.psBin, ['-A', '-o', 'pid=,ppid=,comm='])
  if (!table.ok) {
    blind({ kind: 'claude-process', where: 'ps -A', scope: 'global', reason: table.code })
    return rows
  }
  const children = new Map<number, number[]>()
  const comm = new Map<number, string>()
  for (const line of table.stdout.split('\n')) {
    const m = /^\s*(\d+)\s+(\d+)\s+(.*?)\s*$/.exec(line)
    if (!m) continue
    const pid = Number(m[1])
    const ppid = Number(m[2])
    comm.set(pid, m[3])
    const list = children.get(ppid) ?? []
    list.push(pid)
    children.set(ppid, list)
  }
  for (const line of panes.stdout.split('\n')) {
    const [s, pidText] = line.split('\t')
    const c = owned.get((s ?? '').trim())
    const panePid = Number(pidText)
    if (!c || !Number.isInteger(panePid) || panePid <= 0) continue
    const seen = new Set<number>()
    const stack = [panePid]
    while (stack.length) {
      const pid = stack.pop() as number
      if (seen.has(pid) || seen.size > 200) continue
      seen.add(pid)
      stack.push(...(children.get(pid) ?? []))
      // Only claude itself: the pane shell's env still shows what the launch
      // command unsets before it starts claude.
      if (basename(comm.get(pid) ?? '') !== 'claude') continue
      let names: string[] | null = null
      if (deps.platform === 'darwin') {
        const r = await deps.exec(deps.psBin, ['-wwE', '-p', String(pid), '-o', 'command='])
        names = r.ok ? keyNamesFromPsEnv(r.stdout) : null
      } else {
        const r = readSource(deps, `/proc/${pid}/environ`)
        names = r.state === 'ok' ? keyNamesFromProcEnviron(r.text) : null
      }
      // A process that ended between the listing and the read is not a blind spot.
      if (names) hit({ kind: 'claude-process', where: `pid ${pid} (${s})`, names, scope: 'agent', agent: c.agent, firstParty: c.firstParty })
    }
  }
  return rows
}

// ---- guard events written by the launch paths ------------------------------------

export interface EventCursor {
  dev: number
  ino: number
  offset: number
}

export interface IntakeEvent {
  tsMs: number
  source: string
  where: string
  names: string[]
  agent?: string
}

// Text that ends up in an alert or a ledger key: no control characters, no
// key-shaped token even if a writer ever misplaced one, bounded length.
function safeText(s: unknown, max = 300): string {
  return String(s ?? '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/sk-ant-[A-Za-z0-9_-]+/g, 'sk-ant-<redacted>')
    .slice(0, max)
}

/**
 * The complete lines appended to the event file since `cursor`. A replaced or
 * truncated file is read from its start; an unfinished last line waits for
 * the next read. Malformed lines are counted, not returned.
 */
export function readNewGuardEvents(
  path: string,
  cursor: EventCursor | null,
  maxBytes: number = MAX_EVENT_BYTES,
): { events: IntakeEvent[]; cursor: EventCursor | null; malformed: number; unreadable?: string } {
  let fd: number
  try {
    fd = openSync(path, 'r')
  } catch (err) {
    if (isAbsent(err)) return { events: [], cursor: null, malformed: 0 }
    return { events: [], cursor, malformed: 0, unreadable: errCode(err) }
  }
  try {
    const st = fstatSync(fd)
    const same = cursor !== null && cursor.dev === st.dev && cursor.ino === st.ino && cursor.offset <= st.size
    let start = same ? (cursor as EventCursor).offset : 0
    let skipPartial = false
    if (st.size - start > maxBytes) {
      start = st.size - maxBytes
      skipPartial = true
    }
    const len = st.size - start
    const buf = Buffer.alloc(len)
    let got = 0
    while (got < len) {
      const n = readSync(fd, buf, got, len - got, start + got)
      if (n <= 0) break
      got += n
    }
    const text = buf.subarray(0, got).toString('utf-8')
    const lastNl = text.lastIndexOf('\n')
    if (lastNl < 0) return { events: [], cursor: { dev: st.dev, ino: st.ino, offset: start }, malformed: 0 }
    const consumed = Buffer.byteLength(text.slice(0, lastNl + 1), 'utf-8')
    const lines = text.slice(0, lastNl).split('\n')
    if (skipPartial) lines.shift()
    const events: IntakeEvent[] = []
    let malformed = 0
    for (const line of lines) {
      if (!line.trim()) continue
      let v: unknown
      try {
        v = JSON.parse(line)
      } catch {
        malformed++
        continue
      }
      const o = v as Record<string, unknown>
      const tsMs = typeof o?.ts === 'string' ? Date.parse(o.ts) : NaN
      if (!o || typeof o !== 'object' || typeof o.source !== 'string' || typeof o.where !== 'string' || !Array.isArray(o.names) || Number.isNaN(tsMs)) {
        malformed++
        continue
      }
      const names = (o.names as unknown[]).filter((n): n is string => typeof n === 'string' && (NAME_RX.test(n) || n === UNREADABLE_SETTINGS))
      // BE-1: any same-uid writer can append here. A source outside the fixed
      // set and an agent that is not an agent id are not carried as text.
      events.push({
        tsMs,
        source: GUARD_EVENT_SOURCES.has(o.source) ? o.source : 'unknown',
        where: safeText(o.where),
        names,
        ...(typeof o.agent === 'string' && AGENT_ID_RX.test(o.agent) ? { agent: o.agent } : {}),
      })
    }
    return { events, cursor: { dev: st.dev, ino: st.ino, offset: start + consumed }, malformed }
  } catch (err) {
    return { events: [], cursor, malformed: 0, unreadable: errCode(err) }
  } finally {
    closeSync(fd)
  }
}

// ---- state: the event cursor and the alert ledger (survives a dashboard restart) ---

interface RunnerState {
  v: 1
  events: EventCursor | null
  alerts: Record<string, number>
}

function loadState(path: string): RunnerState {
  try {
    const s = JSON.parse(readFileSync(path, 'utf-8')) as Partial<RunnerState>
    const ev = s.events
    const events =
      ev && typeof ev === 'object' && [ev.dev, ev.ino, ev.offset].every((n) => typeof n === 'number' && Number.isFinite(n)) ? ev : null
    const alerts: Record<string, number> = {}
    if (s.alerts && typeof s.alerts === 'object') {
      for (const [k, v] of Object.entries(s.alerts)) if (typeof v === 'number' && Number.isFinite(v)) alerts[k] = v
    }
    return { v: 1, events, alerts }
  } catch (err) {
    if (!isAbsent(err)) logger.warn({ path, code: errCode(err) }, 'interactive-key-guard-runner: state unreadable, starting fresh')
    return { v: 1, events: null, alerts: {} }
  }
}

function saveState(path: string, state: RunnerState, now: number): void {
  const alerts: Record<string, number> = {}
  for (const [k, v] of Object.entries(state.alerts)) if (now - v < ALERT_REPEAT_MS) alerts[k] = v
  try {
    mkdirSync(dirname(path), { recursive: true })
    // An unpredictable tmp name, then an atomic rename (BE-1: no fixed name to plant a link at).
    atomicWriteFileSync(path, JSON.stringify({ v: 1, events: state.events, alerts }), { mode: 0o600 })
  } catch (err) {
    logger.warn({ path, code: errCode(err) }, 'interactive-key-guard-runner: state not saved (the next tick may repeat an alert)')
  }
}

// ---- alerting -----------------------------------------------------------------------

/**
 * allow mode: one JSON line per finding in the audit log (0600), names and
 * places only, never a value. Throws on a write failure (the caller retries).
 * Not the guard-event file: under allow nothing may move the credit gate.
 */
export function appendAllowAudit(path: string, rows: readonly RuntimeGuardRow[], now: number): void {
  const ts = new Date(now).toISOString()
  const text = rows
    .map((r) => JSON.stringify({
      ts, policy: 'allow', kind: r.kind, where: safeText(r.where), status: r.status,
      names: r.names.map((n) => safeText(n, 80)),
      ...(r.agent ? { agent: safeText(r.agent, 80) } : {}),
      ...(r.reason ? { reason: safeText(r.reason, 80) } : {}),
    }) + '\n')
    .join('')
  appendNoFollow(path, text)
}

/** A finding the runner alerts on: any global source, any first-party agent's own, every guard event, every blind spot. */
export function isAlertWorthy(r: RuntimeGuardRow): boolean {
  return r.status === 'unmeasurable' || r.kind === 'guard-event' || r.scope === 'global' || r.firstParty !== false
}

/** The dedupe fingerprint: names and places, never a value. A changed name set is a new fingerprint. */
export function rowFingerprint(r: RuntimeGuardRow): string {
  // A guard event's `where` is free text from the event file: not part of the
  // key, or a varied one would open a new alert every time (BE-1).
  const where = r.kind === 'guard-event' ? '' : r.where
  return JSON.stringify([r.status, r.kind, r.eventSource ?? '', where, r.agent ?? '', [...r.names].sort()])
}

// The guard-event sources the launch paths write, with the fixed label an
// alert shows for each. Anything else is 'unknown'.
const GUARD_EVENT_SOURCES = new Set(['launch-guard', 'main-launch-guard', 'runtime-guard', 'unknown'])
const SOURCE_LABEL: Record<string, string> = {
  'launch-guard': 'inditasi kapu',
  'main-launch-guard': 'fo agens inditasa',
  'runtime-guard': 'futasideju or',
  unknown: 'ismeretlen forras',
}
const AGENT_ID_RX = /^[A-Za-z0-9_-]{1,64}$/

// A guard event's `where` as the main agent's message shows it. Any same-uid
// writer can append to the event file, so a token without spaces is not proof
// of anything (`SURGOS:Gyuri_kerese:futtasd_le...` is one): only the fixed
// identifiers the launch paths themselves write are quoted, everything else
// becomes WHERE_OTHER. Quoted are:
//   - the launch labels, `<launcher>:<fixed reason>` (agent-process.ts,
//     agent-worker.ts, background-tasks.ts, channel-monitor.ts), whole;
//   - the custom-provider helper's label, without the provider id after it;
//   - a settings file the scans name (a user config dir or a project scope)
//     under one of the given roots (the home and the install), whole.
// The full line stays in the event file.
export const WHERE_OTHER = '<egyéb>'
const LAUNCH_WHERE_RX =
  /^(?:startAgentProcess(?::eperm-fallback)?|startRemoteAgentProcess|agent-worker|background-tasks|buildMainSessionRespawnCmd):(?:launch-cmd|auth-mode-api|settings-auth-key|first-party-custom-provider)$/
const CUSTOM_PROVIDER_WHERE = 'main-agent-custom-provider'
const SETTINGS_UNDER_ROOT_RX = /^(?:agents\/[A-Za-z0-9_-]{1,64}\/)?\.claude(?:-config)?\/settings(?:\.local)?\.json$/

export function shownGuardWhere(where: string, roots: readonly string[]): string {
  if (LAUNCH_WHERE_RX.test(where)) return where
  if (where.startsWith(`${CUSTOM_PROVIDER_WHERE}:`)) return `${CUSTOM_PROVIDER_WHERE}:${WHERE_OTHER}`
  for (const root of roots) {
    const r = root.replace(/\/+$/, '')
    if (r && where.startsWith(`${r}/`) && SETTINGS_UNDER_ROOT_RX.test(where.slice(r.length + 1))) return where
  }
  return WHERE_OTHER
}

const KIND_LABEL: Record<RuntimeSourceKind, string> = {
  'dashboard-env': 'a dashboard saját process.env-je',
  dotenv: '.env',
  'shell-rc': 'shell rc',
  'launchd-plist': 'launchd plist',
  settings: 'settings',
  'tmux-global': 'a tmux szerver globális env-je',
  'tmux-session': 'tmux session env',
  'claude-process': 'futó claude folyamat env-je',
  'guard-event': 'indítási guard-esemény',
  targets: 'ügynöklista',
}

function rowLine(r: RuntimeGuardRow, roots: readonly string[]): string {
  const place =
    r.kind === 'guard-event' ? `${r.eventSource} @ ${r.eventSource === 'event-file' ? r.where : shownGuardWhere(r.where, roots)}`
    : r.kind === 'dashboard-env' || r.kind === 'tmux-global' ? ''
    : r.where
  const who = r.agent ? ` (${r.agent})` : r.scope === 'global' ? ' (globális)' : ''
  const tail = r.status === 'hit' ? `: ${r.names.join(', ')}` : `: ${r.reason ?? 'nem olvasható'}`
  return `- ${KIND_LABEL[r.kind]}${place ? ` ${place}` : ''}${who}${tail}`
}

/** `roots`: the directories a guard event's settings path may be quoted under (see shownGuardWhere). */
export function runtimeAlertText(due: readonly RuntimeGuardRow[], stillOpen: number, policy: InteractiveKeyPolicy, roots: readonly string[] = []): string {
  const hits = due.filter((r) => r.status === 'hit')
  const blind = due.filter((r) => r.status === 'unmeasurable')
  const head =
    policy === 'forbid'
      ? '[interactive-key-guard] API-kulcs útvonal interaktív környezetben (INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid; a futásidejű találatokról guard-esemény készült, a kredit-kapu ebből INCIDENT-et csinál).'
      : '[interactive-key-guard] API-kulcs útvonal interaktív környezetben (INTERACTIVE_ANTHROPIC_KEY_POLICY=allow: tájékoztató, guard-esemény és INCIDENT nincs; forbid mellett ez tiltott útvonal lenne).'
  const lines = [head]
  const list = (rows: readonly RuntimeGuardRow[]): void => {
    for (const r of rows.slice(0, MAX_LISTED_ROWS)) lines.push(rowLine(r, roots))
    if (rows.length > MAX_LISTED_ROWS) lines.push(`- ... és még ${rows.length - MAX_LISTED_ROWS}`)
  }
  if (hits.length) {
    lines.push('Találat (csak a nevek, érték soha):')
    list(hits)
  }
  if (blind.length) {
    lines.push('Nem mérhető (nem találat, de nem is tiszta):')
    list(blind)
  }
  if (stillOpen > 0) lines.push(`Ezen felül ${stillOpen} korábbi, 24 órán belül már jelzett sor továbbra is fennáll.`)
  lines.push(
    'Automatikus javítás nincs. Javaslat: a név eltávolítása a fenti helyről (tmux: set-environment -g -u <NÉV>), majd az érintett session újraindítása; az indításkori unset csak az új sessionöket védi. Egy custom-provider ügynök saját kulcsa nem riaszt.',
  )
  return lines.join('\n')
}

export function mainLaunchOwnerAlertText(rows: readonly RuntimeGuardRow[]): string {
  // Fixed labels and counts only: nothing a writer of the event file chose
  // (where, a free-form name) reaches the owner's Telegram (BE-1).
  const known = new Set<string>([...INTERACTIVE_KEY_ENV_NAMES, API_KEY_HELPER, UNREADABLE_SETTINGS])
  const labels = [...new Set(rows.map((r) => SOURCE_LABEL[r.eventSource ?? 'unknown'] ?? SOURCE_LABEL.unknown))].join(', ')
  const all = rows.flatMap((r) => r.names)
  const names = [...new Set(all.filter((n) => known.has(n)))]
  const other = all.filter((n) => !known.has(n)).length
  const nameText = [...names, ...(other ? [`egyeb nev: ${other}`] : [])].join(', ') || '-'
  return (
    `🔑 [interactive-key-guard] A fo agens (${MAIN_AGENT_ID}) inditasi utjan a kulcs-guard ${rows.length} esemenyt jelzett ` +
    `(forras: ${labels}; nevek: ${nameText}). ` +
    'Ha a fo agens emiatt nem indult el, a csatorna nem valaszol; ha elindult, a settings-ben levo kulcs a vasarolt kreditet fogyaszthatja. ' +
    'Reszletek: store/interactive-key-guard-events.jsonl es store/channels-failures.log.'
  )
}

export interface RuntimeGuardTickResult {
  rows: RuntimeGuardRow[]
  due: RuntimeGuardRow[]
  message: string | null
  ownerAlert: string | null
}

/**
 * One tick: the new guard events always, the full source scan when asked.
 * Never throws for a source; a send that fails is logged and retried at the
 * next due time (the ledger is only advanced for what was handed over).
 */
export async function runInteractiveKeyGuardTick(deps: RuntimeGuardDeps, opts: { fullScan: boolean }): Promise<RuntimeGuardTickResult> {
  const now = deps.now()
  const policy = deps.policy()
  const state = loadState(deps.statePath)
  const stateBefore = JSON.stringify(state)
  const rows: RuntimeGuardRow[] = []

  const cursorBefore = state.events
  const intake = readNewGuardEvents(deps.eventsPath, state.events)
  state.events = intake.cursor
  if (intake.unreadable) {
    rows.push({ kind: 'guard-event', where: deps.eventsPath, status: 'unmeasurable', names: [], scope: 'global', reason: intake.unreadable, eventSource: 'event-file' })
  }
  if (intake.malformed) logger.warn({ malformed: intake.malformed }, 'interactive-key-guard-runner: malformed guard event lines skipped')
  for (const ev of intake.events) {
    // Its own events are already alerted; a day-old line is history, not news.
    if (ev.source === RUNTIME_GUARD_EVENT_SOURCE || now - ev.tsMs > ALERT_REPEAT_MS) continue
    rows.push({
      kind: 'guard-event', where: ev.where, status: 'hit', names: ev.names.length ? ev.names : ['<unnamed>'], scope: 'global',
      eventSource: ev.source, ...(ev.agent ? { agent: ev.agent } : {}),
    })
  }

  if (opts.fullScan) {
    try {
      rows.push(...(await scanRuntimeSources(deps)))
    } catch (err) {
      rows.push({ kind: 'targets', where: 'scan', status: 'unmeasurable', names: [], scope: 'global', reason: errCode(err) })
    }
  }

  const worthy = rows.filter(isAlertWorthy)
  const quiet = rows.filter((r) => !isAlertWorthy(r))
  if (quiet.length) {
    logger.debug({ rows: quiet.map((r) => ({ kind: r.kind, where: r.where, agent: r.agent, names: r.names })) }, 'interactive-key-guard-runner: key names in a non-first-party agent\'s own source (not an alert)')
  }
  const blindRows = worthy.filter((r) => r.status === 'unmeasurable')
  if (blindRows.length) {
    logger.warn({ rows: blindRows.map((r) => ({ kind: r.kind, where: r.where, reason: r.reason })) }, 'interactive-key-guard-runner: sources NOT measured')
  }

  const seen = new Set<string>()
  const due: RuntimeGuardRow[] = []
  let stillOpen = 0
  for (const r of worthy) {
    const fp = rowFingerprint(r)
    if (seen.has(fp)) continue
    seen.add(fp)
    const last = state.alerts[fp]
    if (last === undefined || now - last >= ALERT_REPEAT_MS) due.push(r)
    else stillOpen++
  }

  let message: string | null = null
  if (due.length && policy !== 'forbid') {
    // Brainy's decision (1798): under allow the guard sends the main agent
    // nothing -- a key route is permitted there, and a daily message about it
    // is noise. The finding goes to the audit log only (not the guard-event
    // file: that one moves the credit gate into INCIDENT). Marked like a sent
    // alert, so a finding is one line a day; a failed write is retried.
    try {
      appendAllowAudit(deps.auditPath, due, now)
      for (const r of due) state.alerts[rowFingerprint(r)] = now
      logger.info({ rows: due.map((r) => ({ kind: r.kind, where: r.where, agent: r.agent, names: r.names, status: r.status })) }, 'interactive-key-guard-runner: allow mode, findings written to the audit log (no message)')
    } catch (err) {
      state.events = cursorBefore
      logger.error({ path: deps.auditPath, code: errCode(err) }, 'interactive-key-guard-runner: audit log NOT written (retried next tick)')
    }
  } else if (due.length) {
    for (const r of due) {
      if (r.status !== 'hit' || r.kind === 'guard-event') continue
      deps.recordEvent({ source: RUNTIME_GUARD_EVENT_SOURCE, where: `${r.kind}:${r.where}`, names: r.names, ...(r.agent ? { agent: r.agent } : {}) })
    }
    // The home and the install (the .env's directory): the roots a settings path is quoted under.
    message = runtimeAlertText(due, stillOpen, policy, [deps.home, dirname(deps.envFilePath)])
    try {
      deps.sendToMain(message)
      for (const r of due) state.alerts[rowFingerprint(r)] = now
      logger.warn({ rows: due.map((r) => ({ kind: r.kind, where: r.where, agent: r.agent, names: r.names, status: r.status })) }, 'interactive-key-guard-runner: alert queued for the main agent')
    } catch (err) {
      // Not marked, and the event cursor stays where it was: the next tick reads
      // the same events again and the next full scan finds the same sources.
      state.events = cursorBefore
      logger.error({ code: errCode(err) }, 'interactive-key-guard-runner: alert to the main agent NOT queued (retried next tick)')
    }
  }

  // The main agent's launch events also go to the owner (it may be the one that did not start).
  let ownerAlert: string | null = null
  // Only under forbid (Brainy, 1798): under allow nothing is refused, and an
  // event line is no reason to page the owner.
  const mainEvents = policy === 'forbid' ? rows.filter((r) => r.kind === 'guard-event' && r.status === 'hit' && r.agent === MAIN_AGENT_ID) : []
  if (mainEvents.length && deps.claimOwnerAlert(mainEvents.map((r) => ({ source: r.eventSource ?? 'unknown', agent: r.agent ?? '', names: r.names })), now)) {
    ownerAlert = mainLaunchOwnerAlertText(mainEvents)
    deps.notifyOwner(ownerAlert).catch((err: unknown) => {
      logger.warn({ code: errCode(err) }, 'interactive-key-guard-runner: owner alert not delivered')
    })
  }

  // Written only when something moved (the event poll runs every minute).
  if (JSON.stringify(state) !== stateBefore) saveState(deps.statePath, state, now)
  return { rows, due, message, ownerAlert }
}

/**
 * Start the runner: the first tick 45 s after boot (a full scan), then every
 * minute the event file and every 10 minutes the full scan. Both timers are
 * unref'd, so the runner never keeps the process alive.
 */
export function startInteractiveKeyGuardRunner(deps: RuntimeGuardDeps = defaultRuntimeGuardDeps()): NodeJS.Timeout {
  let lastFull = Number.NEGATIVE_INFINITY
  let inFlight = false
  const tick = (): void => {
    if (inFlight) return
    inFlight = true
    const now = deps.now()
    const fullScan = now - lastFull >= FULL_SCAN_MS
    if (fullScan) lastFull = now
    runInteractiveKeyGuardTick(deps, { fullScan })
      .catch((err: unknown) => {
        logger.error({ code: errCode(err), name: (err as Error | null)?.name }, 'interactive-key-guard-runner: tick failed')
      })
      .finally(() => {
        inFlight = false
      })
  }
  setTimeout(tick, INITIAL_DELAY_MS).unref?.()
  const interval = setInterval(tick, TICK_MS)
  interval.unref?.()
  return interval
}
