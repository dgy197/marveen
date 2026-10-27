// The batch path's STOP file, the gate's way of stopping it (card fec6335f,
// spec A-03, A-05, A-06, blueprint 3.6, node N2a).
//
// The STOP file is shared with people: anyone may put one down by hand, and
// the gate must never touch theirs (A-06, blueprint 14). So the gate:
//  - WRITES only through link(): a fresh tmp file (O_EXCL, 0600, content
//    `credit-gate v1 <nonce>`) is hard-linked to the STOP name. link() never
//    replaces an existing name, so EEXIST means a STOP is already there and
//    the gate does not own it.
//  - OWNS a STOP only while it is exactly the one it wrote: a regular file
//    (not a symlink, not a directory) with the recorded dev, inode, size,
//    mtime (nanoseconds) and content. Anything else -- including a `touch` on
//    the gate's own STOP -- is a human STOP.
//  - REMOVES only its own: check, rename(STOP -> STOP.credit-gate-release.
//    <nonce>), check the renamed file AGAIN on its open descriptor, and only
//    then unlink it. If the renamed file is not the gate's (someone swapped
//    the STOP between the check and the rename), it is put back -- with
//    link() for a regular file, so a newer STOP is never overwritten -- and
//    the caller goes to HOLD. If a newer STOP appeared meanwhile, both stay.
// All file access goes through StopFs, so a test can inject the races.

import {
  closeSync,
  constants,
  fstatSync,
  fsyncSync,
  linkSync,
  lstatSync,
  openSync,
  readSync,
  renameSync,
  unlinkSync,
  writeSync,
} from 'node:fs'

export const STOP_CONTENT_PREFIX = 'credit-gate v1 '
const NONCE_RE = /^[0-9a-f]{32}$/
const DIGITS_RE = /^[0-9]{1,40}$/

export interface StopStat {
  isFile(): boolean
  isDirectory(): boolean
  isSymbolicLink(): boolean
  readonly dev: bigint
  readonly ino: bigint
  readonly size: bigint
  readonly mtimeNs: bigint
}

/** The file operations the STOP protocol needs; nodeStopFs is the real one. */
export interface StopFs {
  lstat(path: string): StopStat
  /** O_RDONLY | O_NOFOLLOW. */
  openRead(path: string): number
  /** O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode 0600. */
  openExclusive(path: string): number
  fstat(fd: number): StopStat
  read(fd: number, buf: Buffer, position: number): number
  write(fd: number, data: Buffer): void
  fsync(fd: number): void
  close(fd: number): void
  link(existingPath: string, newPath: string): void
  unlink(path: string): void
  rename(from: string, to: string): void
}

export const nodeStopFs: StopFs = {
  lstat: (p) => lstatSync(p, { bigint: true }),
  openRead: (p) => openSync(p, constants.O_RDONLY | constants.O_NOFOLLOW),
  openExclusive: (p) => openSync(p, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600),
  fstat: (fd) => fstatSync(fd, { bigint: true }),
  read: (fd, buf, position) => readSync(fd, buf, 0, buf.length, position),
  write: (fd, data) => {
    let done = 0
    while (done < data.length) done += writeSync(fd, data, done, data.length - done)
  },
  fsync: (fd) => fsyncSync(fd),
  close: (fd) => closeSync(fd),
  link: (a, b) => linkSync(a, b),
  unlink: (p) => unlinkSync(p),
  rename: (a, b) => renameSync(a, b),
}

/** What the gate remembers about the STOP it wrote (credit_gate_state.stop_owner_json). */
export interface StopOwnerRecord {
  readonly v: 1
  readonly nonce: string
  readonly dev: string
  readonly ino: string
  readonly size: string
  readonly mtimeNs: string
  readonly placed_at: number
}

export type HumanStopWhy = 'no_record' | 'symlink' | 'directory' | 'not_regular' | 'inode' | 'size' | 'mtime' | 'content'

export type StopInspection =
  | { readonly kind: 'absent' }
  | { readonly kind: 'gate' }
  | { readonly kind: 'human'; readonly why: HumanStopWhy }
  | { readonly kind: 'error'; readonly why: string }

export type PlaceResult =
  | { readonly placed: true; readonly rec: StopOwnerRecord }
  | { readonly placed: false; readonly why: 'exists' | 'raced' | 'error'; readonly detail?: string }

export type ReleaseResult =
  | { readonly released: true; readonly how: 'unlinked' | 'vanished' }
  | { readonly released: false; readonly why: 'not_owner'; readonly inspection: StopInspection }
  | { readonly released: false; readonly why: 'error'; readonly detail: string }
  | {
      readonly released: false
      readonly why: 'raced'
      /** The swapped-in file is back under the STOP name. */
      readonly restored: boolean
      /** A newer STOP took the name meanwhile: both files are kept. */
      readonly bothPresent: boolean
      readonly releasePath: string
    }

export function stopContent(nonce: string): string {
  return `${STOP_CONTENT_PREFIX}${nonce}`
}

/** The stored owner record, or null when absent or not well-formed. */
export function parseStopOwner(json: string | null | undefined): StopOwnerRecord | null {
  if (typeof json !== 'string') return null
  let o: unknown
  try {
    o = JSON.parse(json)
  } catch {
    return null
  }
  if (typeof o !== 'object' || o === null || Array.isArray(o)) return null
  const r = o as Record<string, unknown>
  if (r.v !== 1 || typeof r.nonce !== 'string' || !NONCE_RE.test(r.nonce)) return null
  for (const k of ['dev', 'ino', 'size', 'mtimeNs'] as const) {
    if (typeof r[k] !== 'string' || !DIGITS_RE.test(r[k] as string)) return null
  }
  if (typeof r.placed_at !== 'number' || !Number.isSafeInteger(r.placed_at)) return null
  return {
    v: 1,
    nonce: r.nonce,
    dev: r.dev as string,
    ino: r.ino as string,
    size: r.size as string,
    mtimeNs: r.mtimeNs as string,
    placed_at: r.placed_at,
  }
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException)?.code ?? 'error'
}

/** Read at most `max` bytes of an open file from offset 0. */
function readHead(fs: StopFs, fd: number, max: number): Buffer {
  const buf = Buffer.alloc(max)
  let done = 0
  while (done < max) {
    const n = fs.read(fd, buf.subarray(done), done)
    if (n === 0) break
    done += n
  }
  return buf.subarray(0, done)
}

/**
 * The check behind inspectStop and the re-check of the release: the name's
 * own type (lstat, no following), then the open descriptor (O_NOFOLLOW) for
 * dev, inode, size, mtime and content, so a swap between the two shows as a
 * mismatch rather than slipping through.
 */
function inspectAt(fs: StopFs, path: string, rec: StopOwnerRecord | null): StopInspection {
  let st: StopStat
  try {
    st = fs.lstat(path)
  } catch (err) {
    const code = errCode(err)
    if (code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'error', why: `lstat:${code}` }
  }
  if (st.isSymbolicLink()) return { kind: 'human', why: 'symlink' }
  if (st.isDirectory()) return { kind: 'human', why: 'directory' }
  if (!st.isFile()) return { kind: 'human', why: 'not_regular' }
  if (rec === null) return { kind: 'human', why: 'no_record' }

  let fd: number
  try {
    fd = fs.openRead(path)
  } catch (err) {
    const code = errCode(err)
    // Swapped for a symlink after the lstat: someone else's.
    if (code === 'ELOOP') return { kind: 'human', why: 'symlink' }
    if (code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'error', why: `open:${code}` }
  }
  try {
    const f = fs.fstat(fd)
    if (!f.isFile()) return { kind: 'human', why: 'not_regular' }
    if (f.dev.toString() !== rec.dev || f.ino.toString() !== rec.ino) return { kind: 'human', why: 'inode' }
    if (f.size.toString() !== rec.size) return { kind: 'human', why: 'size' }
    if (f.mtimeNs.toString() !== rec.mtimeNs) return { kind: 'human', why: 'mtime' }
    const expected = Buffer.from(stopContent(rec.nonce), 'utf8')
    const head = readHead(fs, fd, expected.length + 1)
    if (!head.equals(expected)) return { kind: 'human', why: 'content' }
    return { kind: 'gate' }
  } catch (err) {
    return { kind: 'error', why: `read:${errCode(err)}` }
  } finally {
    try { fs.close(fd) } catch { /* nothing to do */ }
  }
}

/** Is the file at `path` the gate's STOP, a human one, or none? Never modifies anything. */
export function inspectStop(fs: StopFs, path: string, rec: StopOwnerRecord | null): StopInspection {
  return inspectAt(fs, path, rec)
}

/**
 * Without the gate's record (off mode in production has no database handle):
 * is the STOP the gate's by its own content? A regular file whose content is
 * exactly `credit-gate v1 <32 hex>` is labelled the gate's; anything else is
 * human. Only for the status: it does not prove ownership, and nothing is
 * ever removed on this basis.
 */
export function inspectStopContent(fs: StopFs, path: string): StopInspection {
  let st: StopStat
  try {
    st = fs.lstat(path)
  } catch (err) {
    const code = errCode(err)
    if (code === 'ENOENT') return { kind: 'absent' }
    return { kind: 'error', why: `lstat:${code}` }
  }
  if (st.isSymbolicLink()) return { kind: 'human', why: 'symlink' }
  if (st.isDirectory()) return { kind: 'human', why: 'directory' }
  if (!st.isFile()) return { kind: 'human', why: 'not_regular' }
  let fd: number
  try {
    fd = fs.openRead(path)
  } catch (err) {
    const code = errCode(err)
    if (code === 'ELOOP') return { kind: 'human', why: 'symlink' }
    return { kind: 'error', why: `open:${code}` }
  }
  try {
    const head = readHead(fs, fd, STOP_CONTENT_PREFIX.length + 33).toString('utf8')
    const nonce = head.startsWith(STOP_CONTENT_PREFIX) ? head.slice(STOP_CONTENT_PREFIX.length) : ''
    return NONCE_RE.test(nonce) ? { kind: 'gate' } : { kind: 'human', why: 'content' }
  } catch (err) {
    return { kind: 'error', why: `read:${errCode(err)}` }
  } finally {
    try { fs.close(fd) } catch { /* nothing to do */ }
  }
}

/** Put the gate's STOP down; never replaces an existing one. */
export function placeStop(fs: StopFs, path: string, nonce: string, nowMs: number): PlaceResult {
  if (!NONCE_RE.test(nonce)) throw new Error('placeStop: the nonce must be 32 hex digits')
  const tmp = `${path}.credit-gate-tmp.${nonce}`
  let fd: number
  try {
    fd = fs.openExclusive(tmp)
  } catch (err) {
    return { placed: false, why: 'error', detail: `create:${errCode(err)}` }
  }
  let ino: string
  try {
    fs.write(fd, Buffer.from(stopContent(nonce), 'utf8'))
    fs.fsync(fd)
    ino = fs.fstat(fd).ino.toString()
  } catch (err) {
    try { fs.close(fd) } catch { /* nothing to do */ }
    try { fs.unlink(tmp) } catch { /* nothing to do */ }
    return { placed: false, why: 'error', detail: `write:${errCode(err)}` }
  }
  fs.close(fd)
  try {
    // link() never replaces: an existing STOP, of any kind, stays as it is.
    fs.link(tmp, path)
  } catch (err) {
    try { fs.unlink(tmp) } catch { /* nothing to do */ }
    const code = errCode(err)
    if (code === 'EEXIST') return { placed: false, why: 'exists' }
    return { placed: false, why: 'error', detail: `link:${code}` }
  }
  try {
    fs.unlink(tmp)
  } catch {
    // A leftover tmp name is harmless: the nonce makes it unique.
  }
  // Record what is under the name NOW; if it is not our inode, someone was
  // faster between the link and here, and the gate owns nothing.
  let st: StopStat
  try {
    st = fs.lstat(path)
  } catch (err) {
    return { placed: false, why: 'raced', detail: `lstat:${errCode(err)}` }
  }
  if (!st.isFile() || st.ino.toString() !== ino) return { placed: false, why: 'raced' }
  return {
    placed: true,
    rec: {
      v: 1,
      nonce,
      dev: st.dev.toString(),
      ino,
      size: st.size.toString(),
      mtimeNs: st.mtimeNs.toString(),
      placed_at: nowMs,
    },
  }
}

/**
 * Put a file that was renamed away by mistake back under the STOP name,
 * without ever replacing a STOP that appeared meanwhile.
 */
function restore(fs: StopFs, releasePath: string, path: string): { restored: boolean; bothPresent: boolean } {
  let st: StopStat
  try {
    st = fs.lstat(releasePath)
  } catch {
    return { restored: false, bothPresent: false }
  }
  if (st.isFile()) {
    // link() fails with EEXIST rather than replacing a newer STOP.
    try {
      fs.link(releasePath, path)
    } catch (err) {
      return { restored: false, bothPresent: errCode(err) === 'EEXIST' }
    }
    try { fs.unlink(releasePath) } catch { /* the hard link under STOP is what counts */ }
    return { restored: true, bothPresent: false }
  }
  // A symlink or a directory cannot be hard-linked as itself (link() follows
  // symlinks on macOS): rename it back, but only onto a free name.
  try {
    fs.lstat(path)
    return { restored: false, bothPresent: true }
  } catch (err) {
    if (errCode(err) !== 'ENOENT') return { restored: false, bothPresent: false }
  }
  try {
    fs.rename(releasePath, path)
    return { restored: true, bothPresent: false }
  } catch {
    return { restored: false, bothPresent: false }
  }
}

/** Remove the gate's own STOP (rename, re-check, unlink); a human STOP is never removed. */
export function releaseStop(fs: StopFs, path: string, rec: StopOwnerRecord): ReleaseResult {
  const first = inspectAt(fs, path, rec)
  if (first.kind === 'error') return { released: false, why: 'error', detail: first.why }
  if (first.kind !== 'gate') return { released: false, why: 'not_owner', inspection: first }

  const releasePath = `${path}.credit-gate-release.${rec.nonce}`
  try {
    fs.rename(path, releasePath)
  } catch (err) {
    const code = errCode(err)
    // Gone between the check and the rename: the name is free, nothing was moved.
    if (code === 'ENOENT') return { released: true, how: 'vanished' }
    return { released: false, why: 'error', detail: `rename:${code}` }
  }
  const again = inspectAt(fs, releasePath, rec)
  if (again.kind === 'gate') {
    try {
      fs.unlink(releasePath)
    } catch (err) {
      return { released: false, why: 'error', detail: `unlink:${errCode(err)}` }
    }
    return { released: true, how: 'unlinked' }
  }
  // What was renamed is not the gate's file: give it back, delete nothing.
  const r = restore(fs, releasePath, path)
  return { released: false, why: 'raced', restored: r.restored, bothPresent: r.bothPresent, releasePath }
}
