// Process identity probe for the relay's single-instance lock (card d7f586bf).
//
// A pid alone does not identify a process: macOS recycles pids, and the
// channel-reap incident (#2000) showed a recycled pid passing a bare
// kill(pid, 0) check. The lock therefore records pid + start time + a command
// fingerprint, and a holder only counts as "the same process" when all three
// match.
//
// Node has no API for another process's start time on macOS (no /proc), so the
// default probe asks /bin/ps. This is the ONLY child process anywhere in the
// relay, and it is spawned with a fixed argv and a minimal, explicit
// environment (PATH and LC_ALL only): the bot token is never in the process environment and
// never in argv, and this child gets neither. When ps is unavailable (e.g. under
// sandbox-exec it fails with EPERM), the probe returns null and the lock fails
// CLOSED: it refuses to start rather than guess (see lock.ts).

import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'

export interface ProcessIdentity {
  // Opaque start-time string; only compared for equality.
  start: string
  // sha256 hex of the full command line; the command itself is never stored.
  cmdSha256: string
}

// alive: kill(pid, 0) semantics (EPERM counts as alive). identity: best effort.
export interface ProcessProbe {
  isAlive(pid: number): boolean
  identity(pid: number): ProcessIdentity | null
}

export function isPidAlive(pid: number): boolean {
  if (!Number.isSafeInteger(pid) || pid <= 0) return false
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM'
  }
}

export function fingerprintCommand(command: string): string {
  return createHash('sha256').update(command).digest('hex')
}

// `ps -o lstart= -o command=` prints a fixed-width 24-char lstart under LC_ALL=C
// ("Thu Oct 29 11:03:12 2026"), then the command line.
const LSTART_WIDTH = 24

export function parsePsLine(out: string): ProcessIdentity | null {
  const line = out.split('\n').find((l) => l.trim().length > 0)
  if (!line || line.length <= LSTART_WIDTH) return null
  const start = line.slice(0, LSTART_WIDTH).trim()
  const command = line.slice(LSTART_WIDTH).trim()
  if (!start || !command) return null
  return { start, cmdSha256: fingerprintCommand(command) }
}

function psIdentity(pid: number): ProcessIdentity | null {
  if (!Number.isSafeInteger(pid) || pid <= 0) return null
  try {
    const out = execFileSync('/bin/ps', ['-o', 'lstart=', '-o', 'command=', '-p', String(pid)], {
      encoding: 'utf8',
      env: { PATH: '/bin:/usr/bin', LC_ALL: 'C' },
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    })
    return parsePsLine(out)
  } catch {
    return null
  }
}

export const defaultProcessProbe: ProcessProbe = {
  isAlive: isPidAlive,
  identity: psIdentity,
}
