// Worker self-restart on a fleet-token swap (card acdb8045 K4).
//
// Why: a worker session exports CLAUDE_CODE_OAUTH_TOKEN once, at launch. After
// store/.claude-oauth-token is swapped it keeps the old identity. The worker is
// ours and holds no conversation worth keeping (every request starts with /clear),
// so inside its own request lock -- never under a running request -- it restarts
// itself ONCE per fingerprint change.
//
// Loop guard (a restart that fails, or a token that flaps, must not restart on
// every request):
//  - one attempt per (session, current fingerprint): `attempted` is remembered
//    until the session reads `current` again;
//  - at most MAX_PER_WINDOW attempts per session per hour, successful or not;
//  - a dead session is never restarted here (the lazy start stamps the new token);
//  - WEB_ONLY staging never restarts (`allowed`).
//
// Reporting (Brainy 6344, Q6): a successful self-restart is ONE line in the next
// heartbeat digest (session, time, reason: token swap), no immediate Telegram.
// The same session restarted NOTIFY_AT times within an hour -> one inter-agent
// message to hazmester (at most once per window).
//
// Hygiene: the fingerprints are compared in memory only. Neither the token nor
// any fingerprint reaches a log line, a digest line or a message; every field
// below is a session name, a count or a fixed string. Never touches the main agent
// (a worker session is not the main agent's session).
//
// IO is injected (WorkerTokenRestartDeps), so the decision logic is unit-tested
// without tmux, the store or the DB.

export const WORKER_TOKEN_RESTART_WINDOW_MS = 60 * 60 * 1000
export const WORKER_TOKEN_RESTART_NOTIFY_AT = 2
export const WORKER_TOKEN_RESTART_MAX_PER_WINDOW = 3
export const WORKER_TOKEN_RESTART_HAZMESTER = 'hazmester'
export const WORKER_TOKEN_RESTART_REASON = 'token swap'

export interface WorkerTokenRestartDeps {
  /** Fingerprint of the fleet token file now (null: missing / empty / unreadable). */
  currentFingerprint: () => string | null
  /** The stamped launch fingerprint of `worker:<session>` (null: no stamp). */
  launchFingerprint: (session: string) => string | null
  /** Kill + relaunch the worker session. Must re-stamp on a successful launch. */
  restart: (session: string) => void
  /** Is the tmux session up now? */
  sessionAlive: (session: string) => boolean
  /** False in WEB_ONLY staging: no restart may happen. */
  allowed: () => boolean
  now: () => number
  /** Human time label for the digest line. */
  timeLabel: (ms: number) => string
  /** Queue one digest line (drained by the next heartbeat block). */
  addDigestNote: (line: string) => void
  /** Inter-agent message to hazmester. */
  notifyHazmester: (text: string) => void
  info: (obj: Record<string, unknown>, msg: string) => void
  warn: (obj: Record<string, unknown>, msg: string) => void
}

interface SessionState {
  /** The fingerprint we already tried for; cleared when the session reads current again. */
  attempted: string | null
  /** Attempts inside the window: { at, ok }. */
  history: Array<{ at: number; ok: boolean }>
  lastNotifyAt: number
  capLoggedAt: number
}

export type TokenSwapOutcome =
  | 'none'          // nothing to do (current / unknown / no change)
  | 'skipped'       // stale, but not allowed to restart (dead session, WEB_ONLY, already attempted, capped)
  | 'restarted'     // restart done, stamp now matches the token
  | 'failed'        // restart attempted, stamp still differs

export interface WorkerTokenRestarter {
  /** Call INSIDE the worker's request lock, before the request runs. Never throws. */
  check(session: string): TokenSwapOutcome
}

export function createWorkerTokenRestarter(deps: WorkerTokenRestartDeps): WorkerTokenRestarter {
  const states = new Map<string, SessionState>()
  const stateOf = (session: string): SessionState => {
    let s = states.get(session)
    if (!s) {
      s = { attempted: null, history: [], lastNotifyAt: -Infinity, capLoggedAt: -Infinity }
      states.set(session, s)
    }
    return s
  }

  return {
    check(session: string): TokenSwapOutcome {
      try {
        const s = stateOf(session)
        const current = deps.currentFingerprint()
        const launched = deps.launchFingerprint(session)
        // Both fingerprints must exist: no stamp (old session) and an unreadable /
        // empty token file are `unknown`, and unknown restarts nothing.
        // `attempted` survives an unknown read (a half-written file must not reset the guard).
        if (!current || !launched) return 'none'
        if (current === launched) { s.attempted = null; return 'none' }

        // stale from here on
        if (s.attempted === current) return 'skipped'
        if (!deps.allowed()) return 'skipped'
        // A dead session is brought up by the lazy start, which stamps the new token.
        if (!deps.sessionAlive(session)) return 'skipped'

        const now = deps.now()
        s.history = s.history.filter(h => now - h.at < WORKER_TOKEN_RESTART_WINDOW_MS)
        if (s.history.length >= WORKER_TOKEN_RESTART_MAX_PER_WINDOW) {
          if (now - s.capLoggedAt >= WORKER_TOKEN_RESTART_WINDOW_MS) {
            s.capLoggedAt = now
            deps.warn({ session, attempts: s.history.length }, 'worker: token-swap restart cap reached for this hour -- not restarting again until the window passes')
          }
          return 'skipped'
        }

        // Mark BEFORE the restart: a throw or a failed launch still counts as the
        // one attempt for this fingerprint.
        s.attempted = current
        deps.restart(session)
        const stampAfter = deps.launchFingerprint(session)
        // The stamp is written BEFORE new-session, so a failed launch can still show
        // the new fingerprint: success also needs the session to be up afterwards.
        const ok = stampAfter === current && deps.sessionAlive(session)
        s.history.push({ at: now, ok })

        if (!ok) {
          deps.warn({ session, reason: 'fleet-token-changed' }, 'worker: token-swap restart did not complete (no live session with the new stamp); will not retry for this token')
          return 'failed'
        }

        deps.info({ session, reason: 'fleet-token-changed' }, 'worker: restarted after a fleet token swap')
        deps.addDigestNote(`- ${session} (worker): ujrainditva ${deps.timeLabel(now)}, ok: ${WORKER_TOKEN_RESTART_REASON}`)

        const okCount = s.history.filter(h => h.ok).length
        if (okCount >= WORKER_TOKEN_RESTART_NOTIFY_AT && now - s.lastNotifyAt >= WORKER_TOKEN_RESTART_WINDOW_MS) {
          s.lastNotifyAt = now
          deps.notifyHazmester(
            `[FLOTTA-TOKEN] A(z) ${session} worker ${okCount}x ujrainditotta magat az elmult oraban (ok: ${WORKER_TOKEN_RESTART_REASON}). ` +
            'Tajekoztatas: ellenorizd, hogy a flotta-token fajl nem csereledik-e ismetlodoen.',
          )
        }
        return 'restarted'
      } catch (err) {
        // Fixed string + error class only: nothing from an exception message.
        deps.warn({ session, err: err instanceof Error ? err.name : 'error' }, 'worker: token-swap check failed (request continues)')
        return 'none'
      }
    },
  }
}

// --- digest notes ---------------------------------------------------------------

const pendingDigestNotes: string[] = []
const MAX_PENDING_NOTES = 20

/** Queue one digest line (bounded, oldest dropped). */
export function queueWorkerRestartDigestNote(line: string): void {
  pendingDigestNotes.push(line)
  while (pendingDigestNotes.length > MAX_PENDING_NOTES) pendingDigestNotes.shift()
}

/** Take (and clear) the queued lines; the heartbeat block renders them once. */
export function drainWorkerRestartDigestNotes(): string[] {
  return pendingDigestNotes.splice(0, pendingDigestNotes.length)
}

/** Test helper: peek without clearing. */
export function peekWorkerRestartDigestNotes(): readonly string[] {
  return pendingDigestNotes
}
