import { randomBytes } from 'node:crypto'
import { execSync, execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { homedir } from 'node:os'
import {
  createBackgroundTaskAtomic, finishBackgroundTask, getBackgroundTasks,
  getBackgroundTask, getRunningBackgroundTasks, markOrphanedTasksFailed,
  type BackgroundTask,
} from '../../db.js'
import { resolveFromPath } from '../../platform.js'
import { APP_TZ } from '../../config.js'
import { logger } from '../../logger.js'
import { fleetVenvPathPrefix } from '../agent-process.js'
import { readBody, json } from '../http-helpers.js'
import type { RouteContext } from './types.js'
import { exactTmuxTarget } from '../../tmux-target.js'
import {
  interactiveKeyPolicy,
  decideInteractiveLaunch,
  scanSettingsForInteractiveKeys,
  assertLaunchCmdClean,
  recordGuardEvent,
  InteractiveKeyGuardError,
  INTERACTIVE_UNSET,
  INTERACTIVE_KEY_ENV_NAMES,
  type InteractiveKeyPolicy,
} from '../interactive-key-guard.js'

const TMUX = resolveFromPath('tmux')
const CLAUDE = resolveFromPath('claude')
const MAX_CONCURRENT = 3
const TIMEOUT_MS = 30 * 60 * 1000

const TZ = APP_TZ  // install zone (config.APP_TZ); was hardcoded Europe/Budapest

function bgSessionName(id: string): string {
  return `bg-${id}`
}

function isBgSessionAlive(session: string): boolean {
  try {
    const out = execFileSync(TMUX, ['list-sessions', '-F', '#{session_name}'], { timeout: 3000, encoding: 'utf-8' })
    return out.split('\n').some(l => l.trim() === session)
  } catch {
    return false
  }
}

function captureSession(session: string): string | null {
  try {
    return execFileSync(TMUX, ['capture-pane', '-t', exactTmuxTarget(session), '-p', '-S', '-500'], { timeout: 5000, encoding: 'utf-8' })
  } catch {
    return null
  }
}

function killSession(session: string): void {
  try {
    execFileSync(TMUX, ['kill-session', '-t', exactTmuxTarget(session)], { timeout: 3000 })
  } catch { /* already dead */ }
}

/**
 * The env handed to the tmux client that spawns a background task. Under
 * forbid the key names are dropped (fec6335f); under allow it is exactly the
 * parent env plus BG_PROMPT, as before.
 */
export function backgroundTaskEnv(parent: NodeJS.ProcessEnv, prompt: string, policy: InteractiveKeyPolicy): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...parent, BG_PROMPT: prompt }
  if (policy === 'forbid') {
    for (const k of INTERACTIVE_KEY_ENV_NAMES) delete env[k]
  }
  return env
}

/**
 * The settings a background `claude -p` loads: the user config dir (the shared
 * ~/.claude, and CLAUDE_CONFIG_DIR when the dashboard env sets one) and the
 * project scope of the pane's cwd, which is the dashboard's own (new-session
 * gets no -c). An `env` key or apiKeyHelper there wins over the unset below.
 */
export function backgroundTaskSettingsPaths(env: NodeJS.ProcessEnv = process.env, cwd: string = process.cwd(), home: string = homedir()): string[] {
  const own = env.CLAUDE_CONFIG_DIR?.trim()
  return [...new Set([
    join(home, '.claude', 'settings.json'),
    ...(own ? [join(own, 'settings.json')] : []),
    join(cwd, '.claude', 'settings.json'),
    join(cwd, '.claude', 'settings.local.json'),
  ])]
}

export function spawnBackgroundTask(agentId: string, prompt: string): BackgroundTask | { error: string } {
  const id = randomBytes(4).toString('hex').toUpperCase()
  const session = bgSessionName(id)

  // fec6335f: a background task is a claude on the CLI's default model, i.e.
  // first-party. Under INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid an auth key name
  // in the settings it would load refuses it -- the same decision as the
  // worker's -- BEFORE a task row or a session exists. Under allow nothing is read.
  const keyPolicy = interactiveKeyPolicy()
  if (keyPolicy === 'forbid') {
    const settingsFindings = scanSettingsForInteractiveKeys(backgroundTaskSettingsPaths())
    const decision = decideInteractiveLaunch({
      policy: keyPolicy, isCustom: false, customProviderDef: null, model: 'claude-(cli-default)', authMode: 'shared', settingsFindings,
    })
    if (!decision.ok) {
      for (const f of settingsFindings) recordGuardEvent({ source: 'launch-guard', where: f.path, names: f.names, agent: agentId })
      return { error: `interactive-key-guard: ${decision.reason} (INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid)` }
    }
  }

  const task = createBackgroundTaskAtomic(id, agentId, prompt, session, MAX_CONCURRENT)
  if (!task) {
    return { error: `Maximum ${MAX_CONCURRENT} egyidejű háttérfeladat ágensenként.` }
  }

  // fec6335f: under forbid it also starts with the key names unset (the pane
  // inherits the tmux SERVER env) and without them in the env handed to the
  // tmux client (which seeds a server this call starts). Under allow both are
  // exactly as before.
  const shellCmd = (keyPolicy === 'forbid' ? INTERACTIVE_UNSET : '') + [
    // FLEETVENV923: the fleet venv's bin/ first, as in every agent launch.
    `export PATH="${fleetVenvPathPrefix()}/opt/homebrew/bin:$HOME/.bun/bin:/usr/local/bin:/usr/bin:/bin:$PATH"`,
    `${CLAUDE} -p "$BG_PROMPT" --output-format text 2>&1`,
  ].join(' && ')

  try {
    assertLaunchCmdClean(shellCmd, { policy: keyPolicy, firstParty: true })
    execFileSync(TMUX, [
      'new-session', '-d', '-s', session, '-x', '200', '-y', '50',
      `${shellCmd}; echo '___BG_DONE___'; sleep 5`,
    ], {
      timeout: 5000,
      env: backgroundTaskEnv(process.env, prompt, keyPolicy),
    })
  } catch (err) {
    if (err instanceof InteractiveKeyGuardError) {
      recordGuardEvent({ source: 'launch-guard', where: 'background-tasks:launch-cmd', names: err.names, agent: agentId })
    }
    logger.error({ err, id, session }, 'Failed to spawn background task tmux session')
    finishBackgroundTask(id, 'failed', '(spawn failed)')
    return { error: 'Nem sikerült elindítani a háttérfeladatot' }
  }

  logger.info({ id, agentId, session, prompt: prompt.slice(0, 100) }, 'Background task started')

  setTimeout(() => checkAndFinalize(id), TIMEOUT_MS)
  pollUntilDone(id)

  return task
}

function pollUntilDone(id: string): void {
  const interval = setInterval(() => {
    const task = getBackgroundTask(id)
    if (!task || task.status !== 'running') {
      clearInterval(interval)
      return
    }

    const session = task.tmux_session
    if (!session) { clearInterval(interval); return }

    if (!isBgSessionAlive(session)) {
      const output = '(session ended)'
      finishBackgroundTask(id, 'done', output)
      logger.info({ id }, 'Background task session ended')
      clearInterval(interval)
      return
    }

    const pane = captureSession(session)
    if (pane && pane.includes('___BG_DONE___')) {
      const output = pane.replace(/___BG_DONE___[\s\S]*$/, '').trim()
      finishBackgroundTask(id, 'done', output)
      killSession(session)
      logger.info({ id }, 'Background task completed')
      clearInterval(interval)
    }
  }, 10_000)
}

function checkAndFinalize(id: string): void {
  const task = getBackgroundTask(id)
  if (!task || task.status !== 'running') return

  const session = task.tmux_session
  const output = session ? captureSession(session) : null
  finishBackgroundTask(id, 'timeout', output?.trim() || '(timeout)')
  if (session) killSession(session)
  logger.warn({ id }, 'Background task timed out after 30 minutes')
}

export function sweepOrphanedBackgroundTasks(): void {
  const running = getRunningBackgroundTasks()
  let orphaned = 0
  for (const task of running) {
    if (!task.tmux_session || !isBgSessionAlive(task.tmux_session)) {
      const output = task.tmux_session ? captureSession(task.tmux_session) : null
      finishBackgroundTask(task.id, 'failed', output?.trim() || '(orphaned on restart)')
      orphaned++
    } else {
      setTimeout(() => checkAndFinalize(task.id), TIMEOUT_MS)
      pollUntilDone(task.id)
    }
  }
  if (orphaned) logger.info({ orphaned }, 'Swept orphaned background tasks on startup')
}

const TASK_ID_RE = /^\/api\/background-tasks\/([A-F0-9]{8})$/

export async function tryHandleBackgroundTasks(ctx: RouteContext): Promise<boolean> {
  const { req, res, path, method, url } = ctx

  if (path === '/api/background-tasks' && method === 'POST') {
    const body = await readBody(req)
    const data = JSON.parse(body.toString()) as { agent_id: string; prompt: string }
    if (!data.prompt?.trim()) {
      json(res, { error: 'Prompt megadása kötelező' }, 400)
      return true
    }
    if (!data.agent_id?.trim()) {
      json(res, { error: 'Agent ID megadása kötelező' }, 400)
      return true
    }

    const result = spawnBackgroundTask(data.agent_id.trim(), data.prompt.trim())
    if ('error' in result) {
      json(res, { error: result.error }, 429)
      return true
    }
    json(res, result, 201)
    return true
  }

  if (path === '/api/background-tasks' && method === 'GET') {
    const agentId = url.searchParams.get('agent') || undefined
    const all = url.searchParams.get('all') === 'true'
    const tasks = getBackgroundTasks(agentId, all)
    const formatted = tasks.map(t => ({
      ...t,
      started_label: new Date(t.started_at * 1000).toLocaleString('hu-HU', { timeZone: TZ }),
      finished_label: t.finished_at ? new Date(t.finished_at * 1000).toLocaleString('hu-HU', { timeZone: TZ }) : null,
    }))
    json(res, formatted)
    return true
  }

  const taskMatch = path.match(TASK_ID_RE)
  if (taskMatch && method === 'GET') {
    const task = getBackgroundTask(taskMatch[1])
    if (!task) { json(res, { error: 'Háttérfeladat nem található' }, 404); return true }

    let liveOutput: string | null = null
    if (task.status === 'running' && task.tmux_session) {
      liveOutput = captureSession(task.tmux_session)
    }

    json(res, {
      ...task,
      liveOutput,
      started_label: new Date(task.started_at * 1000).toLocaleString('hu-HU', { timeZone: TZ }),
      finished_label: task.finished_at ? new Date(task.finished_at * 1000).toLocaleString('hu-HU', { timeZone: TZ }) : null,
    })
    return true
  }

  if (taskMatch && method === 'DELETE') {
    const task = getBackgroundTask(taskMatch[1])
    if (!task) { json(res, { error: 'Háttérfeladat nem található' }, 404); return true }
    const output = task.tmux_session ? captureSession(task.tmux_session) : null
    if (task.status === 'running' && task.tmux_session) {
      killSession(task.tmux_session)
    }
    finishBackgroundTask(task.id, 'failed', output?.trim() || '(cancelled)')
    json(res, { ok: true })
    return true
  }

  return false
}
