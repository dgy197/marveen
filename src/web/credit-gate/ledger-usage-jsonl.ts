// usage.jsonl, format `usage-jsonl-v1` (card fec6335f, blueprint 3.2 and N1b):
// the line parser and the incremental, cursor-based file scanner.
//
// The format is what the two real writers produce, both through
// usage_log.append_usage (json.dumps(record, ensure_ascii=True) + "\n", under
// flock, O_NOFOLLOW, never more than 64 MiB):
//  - a synchronous Messages call (batch_client.py):
//      {ts, month, caller, model, in, out}
//  - a Message Batches result (message_batches.py): the same plus
//      cache_creation_input_tokens, cache_read_input_tokens, batch_id,
//      custom_id, api
// The canary's two callers ("ezermester-kanari-messages" and
// "ezermester-kanari-headless") write through the same function and must stay
// inside this key set: a synchronous row may carry the two cache counts, a
// batch row is exactly the one with batch_id + custom_id. The one key added
// for them: cost_usd_reported, the CLI's own total_cost_usd of a `claude -p`
// run as a strict decimal string (seen in the two real canary rows,
// 2026-10-16). It becomes the row's cli cost, and L takes max(est, cli).
//
// Strict on purpose. A line that does not fit -- not JSON, a duplicated key
// (compared decoded, so "\u0069n" is "in"), an UNKNOWN key (it could carry
// tokens we would silently drop), a negative, fractional or absurd count (one
// request field at or above 10^9 tokens), a missing model -- is a broken
// source (HOLD), never a skipped line: a skipped line is a request the ledger
// does not count (B-01). The per-field cap also keeps every sum the ledger
// builds far inside the safe-integer range.
//
// The scanner reads only COMPLETE lines (terminated by "\n"); the bytes after
// the last newline are a line still being written and stay unread, the cursor
// does not move past them. Before reading on, it proves the file is still the
// one it read before: same dev + inode, not shorter than the cursor, and the
// last TAIL_BYTES before the cursor hash to what they hashed to then. It opens
// with O_NONBLOCK, so a FIFO planted at the path cannot hang the dashboard in
// open(); the fstat that follows turns it into `not_regular`.

import { createHash } from 'node:crypto'
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs'
import { findDuplicateJsonKeys } from '../json-dup-keys.js'
import { ceilDiv, MAX_USD_AMOUNT_MICRO, microFromBigInt } from './money.js'
import type { Micro } from './types.js'

export const USAGE_JSONL_V1 = 'usage-jsonl-v1'
/** How much of the already-read file the tail hash covers. */
export const TAIL_BYTES = 4096
/** One token field of one request must stay BELOW this (exclusive). The
 *  batch writer itself refuses 10^8; 10^9 leaves room and still keeps
 *  every ledger sum exact. */
export const MAX_TOKENS_PER_FIELD = 1_000_000_000

/** One usage.jsonl line, in the ledger's own field names. */
export interface UsageRow {
  /** Epoch seconds, as the writer stamped it (int(time.time())). */
  readonly ts: number
  readonly caller: string
  readonly model: string
  readonly input_tokens: number
  readonly output_tokens: number
  readonly cache_write_tokens: number
  readonly cache_read_tokens: number
  readonly batch_id: string | null
  readonly custom_id: string | null
  /** cost_usd_reported (the CLI's own cost), rounded UP; null when absent. */
  readonly cli_micro: Micro | null
}

export type UsageLineReject =
  | 'invalid_json'
  | 'duplicate_key'
  | 'not_object'
  | 'unknown_key'
  | 'bad_ts'
  | 'bad_month'
  | 'bad_caller'
  | 'bad_model'
  | 'bad_tokens'
  | 'bad_batch'
  | 'bad_api'
  | 'bad_cost'

export type UsageLineResult =
  | { readonly ok: true; readonly row: UsageRow }
  | { readonly ok: false; readonly reason: UsageLineReject }

const KEYS: ReadonlySet<string> = new Set([
  'ts', 'month', 'caller', 'model', 'in', 'out',
  'cache_creation_input_tokens', 'cache_read_input_tokens', 'batch_id', 'custom_id', 'api',
  'cost_usd_reported',
])
// The writers' own checks (message_batches.py): model, batch_id, custom_id.
// Anchored; without the m flag `$` matches only at the very end.
const MODEL_RE = /^[A-Za-z0-9_.-]{1,128}$/
const BATCH_ID_RE = /^msgbatch_[A-Za-z0-9_-]{1,160}$/
const CUSTOM_ID_RE = /^[A-Za-z0-9_-]{1,64}$/
const MONTH_RE = /^[0-9]{4}-(0[1-9]|1[0-2])$/
// A plain decimal: no sign, exponent, whitespace or leading zero, up to 15
// decimals (a float's shortest form), at most 100 000 USD (checked below).
const COST_RE = /^(0|[1-9][0-9]{0,5})(?:\.([0-9]{1,15}))?$/

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

/** A token count: an integer 0 <= n < 10^9 (a bool or a float is not). */
function count(v: unknown): number | null {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < MAX_TOKENS_PER_FIELD ? v : null
}

/** A reported cost ("0.0749821") as micro-USD rounded UP, or null. */
export function parseReportedUsd(v: unknown): Micro | null {
  if (typeof v !== 'string') return null
  const m = COST_RE.exec(v)
  if (!m) return null
  const frac = m[2] ?? ''
  const scaled = BigInt(m[1] + frac) // the cost x 10^frac.length
  const micro = frac.length <= 6
    ? scaled * 10n ** BigInt(6 - frac.length)
    : ceilDiv(scaled, 10n ** BigInt(frac.length - 6))
  return micro <= BigInt(MAX_USD_AMOUNT_MICRO) ? microFromBigInt(micro) : null
}

/** Parse one line (without its "\n"). Any doubt is a rejection with a reason. */
export function parseUsageLine(text: string): UsageLineResult {
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    return { ok: false, reason: 'invalid_json' }
  }
  // JSON.parse keeps the LAST of two equal keys; "in" twice would be a
  // silently halved count.
  if (findDuplicateJsonKeys(text).length > 0) return { ok: false, reason: 'duplicate_key' }
  if (!isPlainObject(doc)) return { ok: false, reason: 'not_object' }
  for (const k of Object.keys(doc)) {
    if (!KEYS.has(k)) return { ok: false, reason: 'unknown_key' }
  }

  const ts = doc.ts
  if (typeof ts !== 'number' || !Number.isSafeInteger(ts) || ts <= 0) return { ok: false, reason: 'bad_ts' }
  if (typeof doc.month !== 'string' || !MONTH_RE.test(doc.month)) return { ok: false, reason: 'bad_month' }
  const caller = doc.caller
  if (typeof caller !== 'string' || caller.length === 0 || caller.length > 256) return { ok: false, reason: 'bad_caller' }
  const model = doc.model
  if (typeof model !== 'string' || !MODEL_RE.test(model)) return { ok: false, reason: 'bad_model' }

  const input = count(doc.in)
  const output = count(doc.out)
  const cacheWrite = Object.hasOwn(doc, 'cache_creation_input_tokens') ? count(doc.cache_creation_input_tokens) : 0
  const cacheRead = Object.hasOwn(doc, 'cache_read_input_tokens') ? count(doc.cache_read_input_tokens) : 0
  if (input === null || output === null || cacheWrite === null || cacheRead === null) {
    return { ok: false, reason: 'bad_tokens' }
  }

  // A batch row is exactly the one with both ids; one without the other, or a
  // present-but-null id, is neither a batch row nor a synchronous one.
  const hasBatch = Object.hasOwn(doc, 'batch_id')
  const hasCustom = Object.hasOwn(doc, 'custom_id')
  let batchId: string | null = null
  let customId: string | null = null
  if (hasBatch || hasCustom) {
    const b = doc.batch_id
    const c = doc.custom_id
    if (typeof b !== 'string' || !BATCH_ID_RE.test(b) || typeof c !== 'string' || !CUSTOM_ID_RE.test(c)) {
      return { ok: false, reason: 'bad_batch' }
    }
    batchId = b
    customId = c
  }
  if (Object.hasOwn(doc, 'api')) {
    const api = doc.api
    if (typeof api !== 'string' || api.length === 0 || api.length > 64) return { ok: false, reason: 'bad_api' }
  }
  // The CLI's cost belongs to a `claude -p` row; the batch writer never sets
  // it, and a batch row carrying one is not a row we know.
  let cli: Micro | null = null
  if (Object.hasOwn(doc, 'cost_usd_reported')) {
    cli = batchId === null ? parseReportedUsd(doc.cost_usd_reported) : null
    if (cli === null) return { ok: false, reason: 'bad_cost' }
  }

  return {
    ok: true,
    row: {
      ts,
      caller,
      model,
      input_tokens: input,
      output_tokens: output,
      cache_write_tokens: cacheWrite,
      cache_read_tokens: cacheRead,
      batch_id: batchId,
      custom_id: customId,
      cli_micro: cli,
    },
  }
}

/**
 * The dedupe key of a usage line: source + dev + inode + byte offset + sha256
 * of the line. Two byte-identical lines at different offsets are two requests;
 * the same bytes read again after a cursor reset are the same request.
 */
export function usageDedupeKey(k: {
  readonly source: string
  readonly dev: string
  readonly ino: string
  readonly offset: number
  readonly lineSha256: string
}): string {
  return `usage:${k.source}:${k.dev}:${k.ino}:${k.offset}:${k.lineSha256}`
}

/** Where the ledger stopped reading a file last time. */
export interface FileCursor {
  readonly dev: string
  readonly ino: string
  readonly offset: number
  readonly tail_sha256: string | null
}

export interface ScannedLine {
  /** Byte offset of the line's first byte. */
  readonly offset: number
  /** Byte offset just after its "\n" (= the next line's offset). */
  readonly end: number
  readonly sha256: string
  /** The line without its "\n"; null when the bytes are not valid UTF-8. */
  readonly text: string | null
}

export type ScanBroken =
  | 'missing'
  | 'symlink'
  | 'not_regular'
  | 'unreadable'
  | 'replaced'
  | 'truncated'
  | 'too_large'
  | 'rewritten'

export type ScanResult =
  | {
      readonly ok: true
      readonly dev: string
      readonly ino: string
      readonly size: number
      /** Every complete line after the cursor, in file order. */
      readonly lines: readonly ScannedLine[]
      /** Bytes after the last "\n": a line still being written. */
      readonly partialBytes: number
      /** The tail hash a cursor at `offset` (>= the old cursor) must store. */
      readonly tailShaAt: (offset: number) => string
    }
  | { readonly ok: false; readonly reason: ScanBroken }

function sha256(b: Uint8Array): string {
  return createHash('sha256').update(b).digest('hex')
}

const UTF8 = new TextDecoder('utf-8', { fatal: true })

function decode(b: Uint8Array): string | null {
  try {
    return UTF8.decode(b)
  } catch {
    return null
  }
}

/** Read exactly `length` bytes from `position`, or fewer if the file ends. */
function readAt(fd: number, position: number, length: number): Buffer {
  const buf = Buffer.alloc(length)
  let done = 0
  while (done < length) {
    const n = readSync(fd, buf, done, length - done, position + done)
    if (n === 0) break
    done += n
  }
  return done === length ? buf : buf.subarray(0, done)
}

/**
 * Read the complete lines after `cursor` (null = from the start). Opens with
 * O_NOFOLLOW (like the writer) and checks everything on the open descriptor,
 * so the file cannot be swapped between the check and the read.
 */
export function scanUsageFile(path: string, cursor: FileCursor | null, maxFileBytes: number): ScanResult {
  let fd: number
  try {
    // O_NONBLOCK: open() of a FIFO without a writer would block forever.
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR') return { ok: false, reason: 'missing' }
    if (code === 'ELOOP') return { ok: false, reason: 'symlink' }
    return { ok: false, reason: 'unreadable' }
  }
  try {
    const st = fstatSync(fd, { bigint: true })
    if (!st.isFile()) return { ok: false, reason: 'not_regular' }
    const dev = st.dev.toString()
    const ino = st.ino.toString()
    if (cursor && (cursor.dev !== dev || cursor.ino !== ino)) return { ok: false, reason: 'replaced' }
    if (st.size > BigInt(maxFileBytes)) return { ok: false, reason: 'too_large' }
    const size = Number(st.size)
    const start = cursor?.offset ?? 0
    if (size < start) return { ok: false, reason: 'truncated' }

    // One read: the tail window before the cursor plus everything after it.
    const base = Math.max(0, start - TAIL_BYTES)
    const buf = readAt(fd, base, size - base)
    // Shorter than fstat said: the file shrank while we read it.
    if (buf.length < start - base) return { ok: false, reason: 'truncated' }
    if (cursor && start > 0 && sha256(buf.subarray(0, start - base)) !== cursor.tail_sha256) {
      return { ok: false, reason: 'rewritten' }
    }

    const lines: ScannedLine[] = []
    let pos = start
    for (;;) {
      const nl = buf.indexOf(0x0a, pos - base)
      if (nl === -1) break
      const bytes = buf.subarray(pos - base, nl)
      const end = base + nl + 1
      lines.push({ offset: pos, end, sha256: sha256(bytes), text: decode(bytes) })
      pos = end
    }
    const readEnd = base + buf.length
    return {
      ok: true,
      dev,
      ino,
      size: readEnd,
      lines,
      partialBytes: readEnd - pos,
      tailShaAt: (offset: number) => {
        if (!Number.isSafeInteger(offset) || offset < start || offset > readEnd) {
          throw new RangeError(`tail offset ${offset} outside the scanned range`)
        }
        return sha256(buf.subarray(Math.max(0, offset - TAIL_BYTES) - base, offset - base))
      },
    }
  } finally {
    closeSync(fd)
  }
}
