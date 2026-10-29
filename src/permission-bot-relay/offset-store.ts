// Offset and status files for the permission-bot relay (card d7f586bf).
//
// Both files are 0600 and replaced atomically (temp file in the same directory,
// fsync, rename), so a crash leaves either the old or the new content, never a
// torn one.
//
// Offset file (`store/permission-bot-relay.offset`, JSON):
//   { "v": 1, "offset": <next getUpdates offset> | null, "inflight": <update_id> | null }
// `inflight` is written BEFORE the handler runs and cleared together with the
// offset advance AFTER it returns. On restart the backlog is dropped (K3)
// EXCEPT the in-flight update, which is handed to the handler again (F4.2: the
// server decides once, so a replay yields at most already_resolved).
//
// Status file (`store/permission-bot-relay.status.json`, F5.2): state, reason
// code, last successful poll time, counters, pid, updated_at. The writer only
// accepts these typed fields, so no nonce, approval id or user id can end up in
// it by accident.

import { closeSync, fchmodSync, fsyncSync, mkdirSync, openSync, readFileSync, renameSync, unlinkSync, writeSync } from 'node:fs'
import { dirname, join, basename } from 'node:path'
import { randomBytes } from 'node:crypto'

export const LOCK_FILE_NAME = 'permission-bot-relay.lock'
export const OFFSET_FILE_NAME = 'permission-bot-relay.offset'
export const STATUS_FILE_NAME = 'permission-bot-relay.status.json'

export interface RelayPaths {
  lock: string
  offset: string
  status: string
}

// N3 passes join(PROJECT_ROOT, 'store'); tests pass a temp dir.
export function relayPaths(storeDir: string): RelayPaths {
  return {
    lock: join(storeDir, LOCK_FILE_NAME),
    offset: join(storeDir, OFFSET_FILE_NAME),
    status: join(storeDir, STATUS_FILE_NAME),
  }
}

export function writeFileAtomic0600(path: string, content: string): void {
  const dir = dirname(path)
  mkdirSync(dir, { recursive: true, mode: 0o700 })
  const tmp = join(dir, `.${basename(path)}.tmp-${process.pid}-${randomBytes(6).toString('hex')}`)
  const fd = openSync(tmp, 'wx', 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeSync(fd, content)
    fsyncSync(fd)
  } catch (err) {
    closeSync(fd)
    try { unlinkSync(tmp) } catch { /* best effort */ }
    throw err
  }
  closeSync(fd)
  try {
    renameSync(tmp, path)
  } catch (err) {
    try { unlinkSync(tmp) } catch { /* best effort */ }
    throw err
  }
}

// ---- offset ----------------------------------------------------------------

export interface OffsetRecord {
  offset: number | null
  inflight: number | null
}

export type OffsetReadResult = OffsetRecord & { corrupt: boolean }

function asUpdateId(v: unknown): number | null {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 ? v : null
}

export class OffsetStore {
  constructor(public readonly path: string) {}

  // Missing file -> nulls. Corrupt file -> nulls + corrupt:true (the caller
  // logs it; with the K3 backlog drop nothing gets decided from it).
  read(): OffsetReadResult {
    let raw: string
    try {
      raw = readFileSync(this.path, 'utf8')
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'ENOENT') return { offset: null, inflight: null, corrupt: false }
      throw err
    }
    try {
      const j = JSON.parse(raw) as { v?: unknown; offset?: unknown; inflight?: unknown }
      if (j === null || typeof j !== 'object' || j.v !== 1) return { offset: null, inflight: null, corrupt: true }
      return { offset: asUpdateId(j.offset), inflight: asUpdateId(j.inflight), corrupt: false }
    } catch {
      return { offset: null, inflight: null, corrupt: true }
    }
  }

  write(rec: OffsetRecord): void {
    writeFileAtomic0600(this.path, JSON.stringify({ v: 1, offset: asUpdateId(rec.offset), inflight: asUpdateId(rec.inflight) }) + '\n')
  }
}

// ---- status ----------------------------------------------------------------

export type RelayState =
  | 'starting'
  | 'disabled'
  | 'refused'
  | 'polling'
  | 'degraded'
  | 'conflict'
  | 'stopping'
  | 'stopped'

// Reason codes are fixed identifiers (F1.2: by name, never with a value).
export const REASON_CODE_RE = /^[a-z][a-z0-9_]{0,63}$/

export interface RelayCounters {
  processed: number
  rejected: number
  ignored: number
  dropped: number
  errors: number
}

export interface RelayStatus {
  v: 1
  state: RelayState
  reason: string | null
  last_poll_ok_at: string | null
  counters: RelayCounters
  pid: number
  updated_at: string
}

export interface StatusLog {
  warn(obj: Record<string, unknown>, msg: string): void
}

export class StatusFile {
  private status: RelayStatus

  constructor(
    public readonly path: string,
    private readonly now: () => number = Date.now,
    private readonly log?: StatusLog,
  ) {
    this.status = {
      v: 1,
      state: 'starting',
      reason: null,
      last_poll_ok_at: null,
      counters: { processed: 0, rejected: 0, ignored: 0, dropped: 0, errors: 0 },
      pid: process.pid,
      updated_at: new Date(this.now()).toISOString(),
    }
  }

  get snapshot(): RelayStatus {
    return { ...this.status, counters: { ...this.status.counters } }
  }

  setState(state: RelayState, reason: string | null = null): void {
    // An unexpected reason string is replaced, never written verbatim.
    const safeReason = reason === null ? null : REASON_CODE_RE.test(reason) ? reason : 'invalid_reason_code'
    this.status.state = state
    this.status.reason = safeReason
    this.flush()
  }

  bump(counter: keyof RelayCounters, by = 1): void {
    this.status.counters[counter] += by
    this.flush()
  }

  pollOk(): void {
    this.status.last_poll_ok_at = new Date(this.now()).toISOString()
    this.flush()
  }

  // A status-file failure must not stop the relay; it is logged (path only).
  flush(): void {
    this.status.updated_at = new Date(this.now()).toISOString()
    try {
      writeFileAtomic0600(this.path, JSON.stringify(this.status, null, 2) + '\n')
    } catch (err) {
      this.log?.warn({ code: (err as NodeJS.ErrnoException).code ?? 'unknown' }, 'permission-bot-relay: status file write failed')
    }
  }
}

export function readStatusFile(path: string): RelayStatus | null {
  try {
    const j = JSON.parse(readFileSync(path, 'utf8')) as RelayStatus
    return j && j.v === 1 ? j : null
  } catch {
    return null
  }
}
