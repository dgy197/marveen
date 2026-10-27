// The CLI side of `forward --comment-file <root>/<name> --comment-sha256 <hex>`
// (card graph-forward, Brainy 3011, spec-delta KB and KF).
//
// The comment of an urgent forward is several paragraphs long, so it comes
// from a file, and the command pins the file's sha256. The approval gate reads
// and checks the same file with its Python twin
// (scripts/hooks/email_extract.py, read_forward_comment_file); both are bound
// to the shared vectors in scripts/hooks/graph-forward-cases.json. The binding
// between what the gate audited and anchored and what goes out is the hash in
// the argv, not the path: the CLI reads the file EXACTLY ONCE, checks the hash
// on the bytes it read, and sends the text decoded from those very bytes.
//
// Node has no openat(), so the path checks are: the root itself (lstat, owner,
// mode, realpath), the file opened with O_NOFOLLOW | O_NONBLOCK (a symlink
// fails with ELOOP, a FIFO cannot block), and after the open the realpath of
// the directory and the (dev, ino) of the path compared with the open
// descriptor. The Python side has dir_fd instead; the asymmetry is known, and
// the hash binds the content on both sides.

import { createHash } from 'node:crypto'
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync, realpathSync } from 'node:fs'
import type { Stats } from 'node:fs'
import { dirname, join } from 'node:path'
import { isOutboxCommentPath, isOutboxRoot, isSha256Hex } from './graph-forward-validate.js'

/** Spec-delta KB3/KB4: the largest comment file, in bytes. */
export const FORWARD_COMMENT_MAX_BYTES = 16384

/**
 * Spec-delta KB7: code points a forward comment must not contain. A closed
 * list of ranges, inclusive, NOT a Unicode category, so the gate's Python and
 * this Node cannot disagree through different Unicode versions. TAB (U+0009)
 * and LF (U+000A) are allowed; CR is not.
 */
export const FORWARD_COMMENT_FORBIDDEN_RANGES: ReadonlyArray<readonly [number, number]> = [
  [0x0000, 0x0008],
  [0x000b, 0x001f],
  [0x007f, 0x009f],
  [0x200b, 0x200f],
  [0x2028, 0x202e],
  [0x2060, 0x2064],
  [0x2066, 0x2069],
  [0xfeff, 0xfeff],
]

/** Spec-delta KF1: the env override of the outbox root, the same name on the gate side. Tests only; empty in production. */
export const OUTBOX_ENV = 'GRAPH_MAIL_OUTBOX_DIR'

/**
 * Spec-delta KF1: the outbox root is `<repo>/store/mail-outbox`, `<repo>` being
 * where the calling file lives (the CLI passes its REPO_ROOT). The env
 * override is taken verbatim when it is set at all, even when empty: an odd
 * value then fails isOutboxRoot instead of quietly meaning the default.
 */
export function resolveOutboxRoot(repoRoot: string, env: NodeJS.ProcessEnv = process.env): string {
  const override = env[OUTBOX_ENV]
  return override !== undefined ? override : join(repoRoot, 'store', 'mail-outbox')
}

/** A refused comment file. The message names the failed check; it never carries file content. */
export class ForwardCommentFileError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ForwardCommentFileError'
  }
}

export interface ForwardCommentFile {
  /** The comment, decoded from exactly the bytes that were hashed. */
  text: string
  /** sha256 hex of those bytes (equal to the expected value). */
  sha256: string
  /** Size in bytes. */
  bytes: number
}

/** Test seam only: called right after the open, before the post-open checks (the TOCTOU tests swap the file here). */
export interface ReadForwardCommentFileHooks {
  afterOpen?: () => void
}

function forbiddenCodePoint(cp: number): boolean {
  return FORWARD_COMMENT_FORBIDDEN_RANGES.some(([lo, hi]) => cp >= lo && cp <= hi)
}

function fileKind(st: Stats): string {
  if (st.isDirectory()) return 'a directory'
  if (st.isFIFO()) return 'a FIFO'
  if (st.isSocket()) return 'a socket'
  if (st.isSymbolicLink()) return 'a symlink'
  if (st.isCharacterDevice() || st.isBlockDevice()) return 'a device'
  return 'not a regular file'
}

const hex16 = (hex: string): string => `${hex.slice(0, 16)}...`
const errCode = (err: unknown): string => {
  const code = (err as { code?: unknown } | null)?.code
  return typeof code === 'string' && /^[A-Z0-9_]{1,32}$/.test(code) ? code : 'unknown error'
}

/** Spec-delta KB1 on the root: exists, a real directory (no symlink), ours, not group/world-writable, canonical. */
function checkOutboxRoot(root: string): Stats {
  let st: Stats
  try {
    st = lstatSync(root)
  } catch (err) {
    if (errCode(err) === 'ENOENT') {
      throw new ForwardCommentFileError(
        `a kimenő-mappa hiányzik (${root}); egyszer létre kell hozni 0700-as joggal`,
      )
    }
    throw new ForwardCommentFileError(`the outbox root ${root} cannot be inspected (${errCode(err)})`)
  }
  if (st.isSymbolicLink()) throw new ForwardCommentFileError(`the outbox root ${root} is a symlink`)
  if (!st.isDirectory()) throw new ForwardCommentFileError(`the outbox root ${root} is not a directory`)
  const euid = typeof process.geteuid === 'function' ? process.geteuid() : undefined
  if (euid === undefined || st.uid !== euid) {
    throw new ForwardCommentFileError(`the outbox root ${root} is not owned by the current user`)
  }
  if ((st.mode & 0o022) !== 0) {
    throw new ForwardCommentFileError(
      `the outbox root ${root} is group- or world-writable (mode ${(st.mode & 0o777).toString(8)}); it must be 0700`,
    )
  }
  let real: string
  try {
    real = realpathSync(root)
  } catch (err) {
    throw new ForwardCommentFileError(`the outbox root ${root} cannot be resolved (${errCode(err)})`)
  }
  if (real !== root) {
    throw new ForwardCommentFileError(`the outbox root ${root} is not a canonical path (a parent is a symlink)`)
  }
  return st
}

/**
 * Read and check one forward comment file (spec-delta KB1-KB10), or throw
 * ForwardCommentFileError. In order:
 *   KF1/KA4  the root and the path have the required shape;
 *   KB1      the root exists, is a directory and no symlink, is owned by the
 *            euid, has no group/world write bit, and realpath(root) === root;
 *   KB2      open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK) (no O_NOFOLLOW in
 *            this Node: refused), then realpath(dirname(path)) === root, the
 *            root is still the same directory, and lstat(path) has the
 *            (dev, ino) of the open descriptor;
 *   KB3      fstat: a regular file, owned by the euid, exactly one link, at
 *            most FORWARD_COMMENT_MAX_BYTES (a FIFO, socket, directory or
 *            device is refused before any read);
 *   KB4      one read loop from that descriptor, at most MAX + 1 bytes; more
 *            than MAX is refused (the file grew after the fstat);
 *   KB5      sha256 of those bytes === sha256Hex;
 *   KB6      strict UTF-8 (fatal, BOM kept, so a BOM is seen and refused);
 *   KB7      no code point from FORWARD_COMMENT_FORBIDDEN_RANGES;
 *   KB8      not blank after trim().
 * KB9: nothing is normalised (no trim, no CRLF change, no NFC); a trailing LF
 * stays part of the comment. Error messages carry the path, the check and at
 * most the first 16 hex digits of a hash, never the content (KE4).
 */
function readOutboxTextFile(
  path: string,
  sha256Hex: string,
  root: string,
  hooks: ReadForwardCommentFileHooks,
  noun: string,
  hashFlag: string,
): ForwardCommentFile {
  if (!isOutboxRoot(root)) throw new ForwardCommentFileError('the outbox root is not a plain absolute path')
  if (!isOutboxCommentPath(path, root)) {
    throw new ForwardCommentFileError(`the ${noun} file must be ${root}/<name>`)
  }
  if (!isSha256Hex(sha256Hex)) throw new ForwardCommentFileError('the expected sha256 is not 64 lower-case hex digits')

  const rootStat = checkOutboxRoot(root)

  const { O_RDONLY, O_NOFOLLOW, O_NONBLOCK } = constants
  if (typeof O_NOFOLLOW !== 'number' || typeof O_NONBLOCK !== 'number') {
    throw new ForwardCommentFileError(`this platform has no O_NOFOLLOW / O_NONBLOCK; the ${noun} file cannot be opened safely`)
  }
  let fd: number
  try {
    fd = openSync(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
  } catch (err) {
    const code = errCode(err)
    if (code === 'ELOOP') throw new ForwardCommentFileError(`the ${noun} file ${path} is a symlink`)
    if (code === 'ENOENT') throw new ForwardCommentFileError(`the ${noun} file ${path} does not exist`)
    throw new ForwardCommentFileError(`the ${noun} file ${path} cannot be opened (${code})`)
  }
  try {
    hooks.afterOpen?.()

    // KB2, after the open: the directory is still the canonical root, and the
    // name still points at the very file the descriptor has.
    let realDir: string
    let rootNow: Stats
    let atPath: Stats
    try {
      realDir = realpathSync(dirname(path))
      rootNow = lstatSync(root)
      atPath = lstatSync(path)
    } catch (err) {
      throw new ForwardCommentFileError(`the ${noun} file ${path} changed while it was opened (${errCode(err)})`)
    }
    if (realDir !== root || !rootNow.isDirectory() || rootNow.dev !== rootStat.dev || rootNow.ino !== rootStat.ino) {
      throw new ForwardCommentFileError(`the outbox root ${root} changed while the ${noun} file was opened`)
    }
    const st = fstatSync(fd)
    if (atPath.dev !== st.dev || atPath.ino !== st.ino) {
      throw new ForwardCommentFileError(`the ${noun} file ${path} was replaced while it was opened`)
    }

    // KB3: decided on the descriptor, before any byte is read.
    if (!st.isFile()) throw new ForwardCommentFileError(`the ${noun} file ${path} is ${fileKind(st)}`)
    if (st.uid !== process.geteuid?.()) {
      throw new ForwardCommentFileError(`the ${noun} file ${path} is not owned by the current user`)
    }
    if (st.nlink !== 1) {
      throw new ForwardCommentFileError(`the ${noun} file ${path} has ${st.nlink} hard links; it must have exactly 1`)
    }
    if (st.size > FORWARD_COMMENT_MAX_BYTES) {
      throw new ForwardCommentFileError(
        `the ${noun} file ${path} is larger than ${FORWARD_COMMENT_MAX_BYTES} bytes (${st.size})`,
      )
    }

    // KB4: one descriptor, at most MAX + 1 bytes, no second read anywhere.
    const buf = Buffer.alloc(FORWARD_COMMENT_MAX_BYTES + 1)
    let n = 0
    while (n < buf.length) {
      const got = readSync(fd, buf, n, buf.length - n, null)
      if (got === 0) break
      n += got
    }
    if (n > FORWARD_COMMENT_MAX_BYTES) {
      throw new ForwardCommentFileError(
        `the ${noun} file ${path} grew past ${FORWARD_COMMENT_MAX_BYTES} bytes while it was read`,
      )
    }
    const bytes = buf.subarray(0, n)

    // KB5: the hash of exactly these bytes.
    const sha256 = createHash('sha256').update(bytes).digest('hex')
    if (sha256 !== sha256Hex) {
      throw new ForwardCommentFileError(
        `${hashFlag} does not match the ${noun} file: expected ${hex16(sha256Hex)}, the file has ${hex16(sha256)}`,
      )
    }

    // KB6: strict UTF-8. ignoreBOM keeps a leading BOM in the text (the
    // default would swallow it, Python would not), so KB7 refuses it.
    let text: string
    try {
      text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes)
    } catch {
      throw new ForwardCommentFileError(`the ${noun} file ${path} is not valid UTF-8`)
    }

    // KB7: position in code points, from 0 (the same index Python's str gives).
    let pos = 0
    for (const ch of text) {
      const cp = ch.codePointAt(0) as number
      if (forbiddenCodePoint(cp)) {
        const name = `U+${cp.toString(16).toUpperCase().padStart(4, '0')}`
        throw new ForwardCommentFileError(
          `the ${noun} file ${path} contains the forbidden character ${name} at position ${pos}`,
        )
      }
      pos++
    }

    // KB8
    if (text.trim() === '') throw new ForwardCommentFileError(`the ${noun} file ${path} is blank`)

    return { text, sha256, bytes: n }
  } finally {
    closeSync(fd)
  }
}

/** The `forward --comment-file` reader (spec-delta KB1-KB10); see readOutboxTextFile for the checks. */
export function readForwardCommentFile(
  path: string,
  sha256Hex: string,
  root: string,
  hooks: ReadForwardCommentFileHooks = {},
): ForwardCommentFile {
  return readOutboxTextFile(path, sha256Hex, root, hooks, 'comment', '--comment-sha256')
}

/**
 * The `send --body-file` reader (card graph-forward r3, node W2): the SAME
 * reader, root, name, size, UTF-8 and code point rules as the comment file,
 * only the messages say "body file" and "--body-sha256". The result's `text`
 * is the mail body, decoded from exactly the hashed bytes.
 */
export function readSendBodyFile(
  path: string,
  sha256Hex: string,
  root: string,
  hooks: ReadForwardCommentFileHooks = {},
): ForwardCommentFile {
  return readOutboxTextFile(path, sha256Hex, root, hooks, 'body', '--body-sha256')
}
