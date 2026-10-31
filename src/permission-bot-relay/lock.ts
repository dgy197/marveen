// Single-instance lock for the permission-bot relay (card d7f586bf, spec F2.1-F2.2).
//
// Two pollers on one token means 409s and, worse, presses landing in whichever
// process happened to win the long-poll. So the relay polls only while it holds
// `store/permission-bot-relay.lock` (0600).
//
// Record: { v, pid, start, cmd_sha256, nonce, created_at }. A holder counts as
// live only when the pid is alive AND its start time AND command fingerprint
// equal the record (a recycled pid has a different start time; see
// process-identity.ts). The nonce identifies this acquisition, so release()
// never deletes a lock that some later instance took over.
//
// Exclusive create: the record is written to a private temp file first and then
// published with link(2), which fails with EEXIST exactly like O_EXCL but makes
// the full content appear at once, so no reader ever sees a half-written lock.
//
// Stale takeover runs under a second, O_EXCL mutex (`<lock>.takeover`): only the
// mutex holder may re-read, judge and replace the lock, so two starts that both
// see the same stale record cannot both win. The loser gets `lock_busy` (launchd
// retries). The mutex holder re-reads the lock, checks it is still byte-for-byte
// the record it judged, and replaces it with ONE atomic rename(2) of a fresh temp
// file (the lock path never disappears, so nobody can slip a new lock in between).
// It then re-reads the lock and proceeds only if it carries OUR nonce; a loser
// (another takeover replaced it again) refuses with lock_busy and touches nothing.
//
// An unparseable or other-version lock file is NOT taken over: spec F2 allows a
// takeover only for a dead or recycled pid, and a file we cannot read tells us
// neither. It is refused as `lock_unrecognized`; the owner removes the file by hand.
//
// Fail-closed: if the holder is alive but its identity cannot be read (ps not
// available), the result is `lock_unverifiable`, never a takeover. If our OWN
// identity cannot be read, we refuse (`lock_identity_unavailable`): a record
// without identity could never be verified by the next instance.
//
// Known limit: a crashed takeover mutex older than mutexStaleMs is removed by
// the next start, which then reports lock_busy for that attempt. Removing it is
// a path unlink, so in the (three concurrent starts + crashed mutex) case two
// processes could hold the mutex at once; the lock itself is still created with
// link(2), so at most one of them can create it.

import { closeSync, fchmodSync, fsyncSync, linkSync, mkdirSync, openSync, readFileSync, renameSync, statSync, unlinkSync, writeSync } from 'node:fs'
import { basename, dirname, join } from 'node:path'
import { randomBytes } from 'node:crypto'
import { defaultProcessProbe, type ProcessIdentity, type ProcessProbe } from './process-identity.js'

export type LockRefusal =
  | 'already_running'
  | 'lock_busy'
  | 'lock_unverifiable'
  | 'lock_unrecognized'
  | 'lock_identity_unavailable'
  | 'lock_io_error'

export interface RelayLock {
  readonly path: string
  readonly nonce: string
  // Removes the lock file only if it still carries our nonce. Idempotent.
  release(): boolean
}

export type LockResult = { ok: true; lock: RelayLock; tookOver: boolean } | { ok: false; reason: LockRefusal }

export interface LockOptions {
  probe?: ProcessProbe
  now?: () => number
  // Age after which a leftover takeover mutex is considered crashed.
  mutexStaleMs?: number
}

interface LockRecord {
  v: 1
  pid: number
  start: string
  cmd_sha256: string
  nonce: string
  created_at: string
}

const DEFAULT_MUTEX_STALE_MS = 30_000

function parseRecord(raw: string): LockRecord | null {
  try {
    const j = JSON.parse(raw) as Partial<LockRecord>
    if (!j || j.v !== 1) return null
    if (typeof j.pid !== 'number' || !Number.isSafeInteger(j.pid) || j.pid <= 0) return null
    if (typeof j.start !== 'string' || typeof j.cmd_sha256 !== 'string' || typeof j.nonce !== 'string') return null
    return j as LockRecord
  } catch {
    return null
  }
}

function readIfExists(path: string): string | null {
  try {
    return readFileSync(path, 'utf8')
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === 'ENOENT') return null
    throw err
  }
}

// Private temp file next to the target (O_EXCL, 0600), fully written.
function writeTemp(path: string, content: string): string {
  const dir = dirname(path)
  const tmp = join(dir, `.${basename(path)}.new-${process.pid}-${randomBytes(6).toString('hex')}`)
  const fd = openSync(tmp, 'wx', 0o600)
  try {
    fchmodSync(fd, 0o600)
    writeSync(fd, content)
    fsyncSync(fd)
  } catch (err) {
    try { unlinkSync(tmp) } catch { /* best effort */ }
    throw err
  } finally {
    closeSync(fd)
  }
  return tmp
}

// Atomic replace of an existing target: the path is never absent.
function replaceAtomic(path: string, content: string): void {
  const tmp = writeTemp(path, content)
  try {
    renameSync(tmp, path)
  } catch (err) {
    try { unlinkSync(tmp) } catch { /* best effort */ }
    throw err
  }
}

// Exclusive, atomic publish: temp file (O_EXCL, 0600) + link(2). Throws EEXIST
// when the target exists.
function publishExclusive(path: string, content: string): void {
  const tmp = writeTemp(path, content)
  try {
    linkSync(tmp, path)
  } finally {
    try { unlinkSync(tmp) } catch { /* best effort */ }
  }
}

type Verdict = 'live' | 'stale' | 'unverifiable' | 'unrecognized'

function judge(raw: string, probe: ProcessProbe): Verdict {
  const rec = parseRecord(raw)
  // Neither readable nor taken over (F2): not a record of this version.
  if (!rec) return 'unrecognized'
  if (!probe.isAlive(rec.pid)) return 'stale'
  const id = probe.identity(rec.pid)
  if (!id) return 'unverifiable'
  if (id.start !== rec.start || id.cmdSha256 !== rec.cmd_sha256) return 'stale'
  return 'live'
}

function errCode(err: unknown): string | undefined {
  return (err as NodeJS.ErrnoException | null)?.code
}

// Removes a takeover mutex left by a crashed holder. The old mutex is moved aside
// with one rename(2) and only deleted if it is the very file (inode, mtime) that
// was judged stale; a fresh mutex of another start is linked back (no clobber).
function breakStaleMutex(mutexPath: string, nowMs: number, staleMs: number): void {
  try {
    const before = statSync(mutexPath)
    if (nowMs - before.mtimeMs <= staleMs) return
    const aside = `${mutexPath}.stale-${process.pid}-${randomBytes(6).toString('hex')}`
    renameSync(mutexPath, aside)
    try {
      const moved = statSync(aside)
      if (moved.ino !== before.ino || moved.dev !== before.dev || moved.mtimeMs !== before.mtimeMs) {
        try { linkSync(aside, mutexPath) } catch { /* someone created a new one */ }
      }
    } finally {
      try { unlinkSync(aside) } catch { /* best effort */ }
    }
  } catch { /* gone already */ }
}

export function acquireRelayLock(path: string, opts: LockOptions = {}): LockResult {
  const probe = opts.probe ?? defaultProcessProbe
  const now = opts.now ?? Date.now
  const mutexStaleMs = opts.mutexStaleMs ?? DEFAULT_MUTEX_STALE_MS

  const own: ProcessIdentity | null = probe.identity(process.pid)
  if (!own) return { ok: false, reason: 'lock_identity_unavailable' }

  const nonce = randomBytes(16).toString('hex')
  const record: LockRecord = {
    v: 1,
    pid: process.pid,
    start: own.start,
    cmd_sha256: own.cmdSha256,
    nonce,
    created_at: new Date(now()).toISOString(),
  }
  const content = JSON.stringify(record) + '\n'
  const makeLock = (): RelayLock => ({
    path,
    nonce,
    release(): boolean {
      try {
        const cur = readIfExists(path)
        if (cur === null) return false
        if (parseRecord(cur)?.nonce !== nonce) return false
        unlinkSync(path)
        return true
      } catch {
        return false
      }
    },
  })

  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    publishExclusive(path, content)
    return { ok: true, lock: makeLock(), tookOver: false }
  } catch (err) {
    if (errCode(err) !== 'EEXIST') return { ok: false, reason: 'lock_io_error' }
  }

  // The lock exists: only the takeover-mutex holder may judge and replace it.
  const mutexPath = `${path}.takeover`
  const mutexToken = `${process.pid}:${randomBytes(8).toString('hex')}\n`
  try {
    const fd = openSync(mutexPath, 'wx', 0o600)
    try { writeSync(fd, mutexToken) } finally { closeSync(fd) }
  } catch (err) {
    if (errCode(err) !== 'EEXIST') return { ok: false, reason: 'lock_io_error' }
    breakStaleMutex(mutexPath, now() , mutexStaleMs)
    return { ok: false, reason: 'lock_busy' }
  }

  try {
    const raw = readIfExists(path)
    if (raw === null) {
      // The holder released between our attempt and the mutex: try once more.
      try {
        publishExclusive(path, content)
        return { ok: true, lock: makeLock(), tookOver: false }
      } catch (err) {
        return { ok: false, reason: errCode(err) === 'EEXIST' ? 'lock_busy' : 'lock_io_error' }
      }
    }
    const verdict = judge(raw, probe)
    if (verdict === 'live') return { ok: false, reason: 'already_running' }
    if (verdict === 'unverifiable') return { ok: false, reason: 'lock_unverifiable' }
    if (verdict === 'unrecognized') return { ok: false, reason: 'lock_unrecognized' }

    // Still exactly the record we judged? (a crashed-mutex break can let a second
    // takeover run in between; then we are the loser.)
    if (readIfExists(path) !== raw) return { ok: false, reason: 'lock_busy' }
    try {
      replaceAtomic(path, content)
    } catch {
      return { ok: false, reason: 'lock_io_error' }
    }
    // Proceed only if the lock still carries OUR nonce.
    if (readIfExists(path) !== content) return { ok: false, reason: 'lock_busy' }
    return { ok: true, lock: makeLock(), tookOver: true }
  } catch {
    return { ok: false, reason: 'lock_io_error' }
  } finally {
    try {
      if (readIfExists(mutexPath) === mutexToken) unlinkSync(mutexPath)
    } catch { /* best effort */ }
  }
}
