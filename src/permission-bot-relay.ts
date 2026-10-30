// marveen-permission-bot-relay: the ONLY poller of the permission bot (card d7f586bf, N3).
//
// A standalone process (launchd: com.<SERVICE_ID>.permission-bot-relay) that
// long-polls getUpdates for callback_query updates of the permission bot,
// pre-filters the apv: button presses and forwards them to the dashboard route
// POST /api/approvals/:id/permission-bot over loopback. It decides NOTHING: the
// route (card 9a77b3e5) is the single decision point. This file only wires the
// parts together; the logic lives in src/permission-bot-relay/*.
//
// Wiring order (every step fail-closed):
//   1. exclusive lock (store/permission-bot-relay.lock)       else exit 3, status untouched
//   2. start-up gates (switch, pin, owner, Vault token, main-bot exclusion, getMe)
//   3. disabled: idle (no poll, no busy KeepAlive loop); refused: exit 2
//   4. poll loop (webhook check, backlog drop, apv: dispatcher, offset, shutdown)
//
// Sources: the switch (PERMISSION_BOT_RELAY_ENABLED) and the dashboard port come
// from the install .env (config.ts), the pinned bot id from config.ts
// (PERMISSION_BOT_ID), the token ONLY from the Vault (startup.ts). The main bot's
// id (exclusion list) is the id part of TELEGRAM_BOT_TOKEN in the install .env
// and in the main channel's state-dir .env (TELEGRAM_STATE_DIR, else the
// install-scoped .claude/channels/telegram); only the digits before the colon
// ever leave those files, and no id is logged.
//
// `node dist/permission-bot-relay.js --status` prints the status file; it opens
// no socket and touches neither the Vault nor the lock.

import { join } from 'node:path'
import { pathToFileURL } from 'node:url'
import { logger } from './logger.js'
import { readEnvFile } from './env.js'
import { STORE_DIR, WEB_PORT, PERMISSION_BOT_ID, TELEGRAM_BOT_TOKEN } from './config.js'
import { channelStateDir, readChannelToken } from './channel-provider.js'
import { createApvHandler, dashboardTokenFileReader } from './permission-bot-relay/apv-handler.js'
import { createDispatcher } from './permission-bot-relay/dispatch.js'
import { acquireRelayLock, type RelayLock } from './permission-bot-relay/lock.js'
import { OffsetStore, StatusFile, readStatusFile, relayPaths, type RelayStatus } from './permission-bot-relay/offset-store.js'
import { isPidAlive } from './permission-bot-relay/process-identity.js'
import { PollLoop, attachShutdownSignals, type RelayLog } from './permission-bot-relay/poll-loop.js'
import { REFUSED_EXIT_CODE, runStartupGates, tokenBotId } from './permission-bot-relay/startup.js'

export const EXIT_FATAL = 1
export const EXIT_LOCK_REFUSED = 3
export const EXIT_NO_STATUS = 1

const ENABLED_ENV_KEY = 'PERMISSION_BOT_RELAY_ENABLED'

/**
 * Main-bot ids (digits only) from the tokens the install knows. A token that is
 * missing or malformed is skipped; duplicates collapse. Two different valid ids
 * are both kept: the exclusion list may only grow, never shrink.
 */
export function mainBotIdsFromTokens(tokens: ReadonlyArray<string | null | undefined>): string[] {
  const ids = new Set<string>()
  for (const t of tokens) {
    const id = tokenBotId(t)
    if (id !== null) ids.add(id)
  }
  return [...ids]
}

function mainChannelToken(): string | null {
  try {
    return readChannelToken('telegram', join(channelStateDir('telegram'), '.env'))
  } catch {
    return null
  }
}

/** The production source of the main bot's id list (install .env + channel state dir). */
export function installMainBotIds(): string[] {
  return mainBotIdsFromTokens([TELEGRAM_BOT_TOKEN, mainChannelToken()])
}

export type RelayCli = { kind: 'run' } | { kind: 'status' } | { kind: 'bad'; arg: string }

export function parseRelayArgs(argv: readonly string[]): RelayCli {
  if (argv.length === 0) return { kind: 'run' }
  if (argv.length === 1 && argv[0] === '--status') return { kind: 'status' }
  return { kind: 'bad', arg: argv[0] ?? '' }
}

const LIVE_STATES: ReadonlySet<string> = new Set(['starting', 'polling', 'degraded', 'conflict', 'stopping'])

/** Human-readable status lines (F5.2 fields only; nothing but codes and counters). */
export function formatStatus(s: RelayStatus, pidAlive: boolean): string[] {
  const lines = [
    `state: ${s.state}${s.reason ? ` (${s.reason})` : ''}`,
    `last_poll_ok_at: ${s.last_poll_ok_at ?? 'never'}`,
    `updated_at: ${s.updated_at}`,
    `pid: ${s.pid} (${pidAlive ? 'running' : 'not running'})`,
    `counters: processed=${s.counters.processed} rejected=${s.counters.rejected} ignored=${s.counters.ignored} dropped=${s.counters.dropped} errors=${s.counters.errors}`,
  ]
  if (LIVE_STATES.has(s.state) && !pidAlive) lines.push('WARNING: the status file says the relay is live, but its process is gone (stale status).')
  return lines
}

/** `--status`: reads the status file only. Returns the exit code. */
export function runStatusCommand(
  statusPath: string,
  out: (line: string) => void,
  isAlive: (pid: number) => boolean = isPidAlive,
): number {
  const s = readStatusFile(statusPath)
  if (!s) {
    out('state: unknown (no readable status file; the relay never ran here or is not installed)')
    return EXIT_NO_STATUS
  }
  for (const line of formatStatus(s, isAlive(s.pid))) out(line)
  return 0
}

async function runRelay(): Promise<void> {
  const log: RelayLog = logger
  const paths = relayPaths(STORE_DIR)

  // 1. Lock first, so a second instance never touches the live one's status file.
  const got = acquireRelayLock(paths.lock)
  if (!got.ok) {
    log.error({ alert: 'permission_bot_relay_refused', reason: got.reason }, 'permission-bot-relay: lock not acquired, not polling')
    process.exit(EXIT_LOCK_REFUSED)
  }
  const lock: RelayLock = got.lock
  const status = new StatusFile(paths.status, Date.now, logger)

  // A signal during start-up (getMe is a network call) must still free the lock.
  const early = (): void => { lock.release(); process.exit(0) }
  process.on('SIGTERM', early)
  process.on('SIGINT', early)

  // 2. Gates. Every input is resolved here; the token is read by startup.ts from the Vault only.
  const gates = await runStartupGates({
    enabled: readEnvFile([ENABLED_ENV_KEY])[ENABLED_ENV_KEY],
    pinnedBotId: PERMISSION_BOT_ID,
    mainBotIds: installMainBotIds,
    status,
    log,
  })

  if (gates.kind === 'refused') {
    lock.release()
    process.exit(gates.exitCode ?? REFUSED_EXIT_CODE)
  }
  if (gates.kind === 'disabled') {
    // Stay up and idle: exiting would make KeepAlive respawn the switch check in a loop.
    setInterval(() => { /* keep-alive tick */ }, 3_600_000)
    return
  }

  // 3. Poll loop with the apv: handler behind the prefix dispatcher.
  const handler = createDispatcher(
    {
      'apv:': createApvHandler({
        pinnedBotId: gates.botId,
        dashboardPort: WEB_PORT,
        readBearer: dashboardTokenFileReader(join(STORE_DIR, '.dashboard-token')),
        log,
      }),
    },
    { log },
  )
  const loop = new PollLoop({ api: gates.api, offsets: new OffsetStore(paths.offset), status, handler, log })
  process.off('SIGTERM', early)
  process.off('SIGINT', early)
  attachShutdownSignals(loop, { log, lock })

  const exit = await loop.run()
  lock.release()
  if (exit.kind === 'refused') process.exit(REFUSED_EXIT_CODE)
  if (exit.kind === 'fatal') process.exit(EXIT_FATAL)
  // 'stopped': the shutdown handler exits with the drain result.
}

// Entry-point guard: only run when executed directly (launchd / `node dist/permission-bot-relay.js`),
// not when imported by tests.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const cli = parseRelayArgs(process.argv.slice(2))
  if (cli.kind === 'status') {
    process.exit(runStatusCommand(relayPaths(STORE_DIR).status, (l) => console.log(l)))
  } else if (cli.kind === 'bad') {
    console.error('usage: permission-bot-relay [--status]')
    process.exit(64)
  } else {
    runRelay().catch((err: unknown) => {
      // Name only: never a message (it could carry a path or a masked URL).
      logger.error({ err_name: err instanceof Error ? err.name : typeof err }, 'permission-bot-relay: crashed')
      process.exit(EXIT_FATAL)
    })
  }
}
