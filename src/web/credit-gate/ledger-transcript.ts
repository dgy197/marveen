// The transcript fallback of a headless run (card fec6335f, spec B-04, N1b):
// when the CLI's JSON result is missing (the run was killed, crashed, timed
// out), the run's own transcripts -- <run>/config/projects/**.jsonl, written
// by Claude Code under the run's private CLAUDE_CONFIG_DIR -- give the token
// counts of every API response the run received.
//
// Same rule as token-usage.ts (collapseByMessageId): one tool-calling turn is
// written as SEVERAL `assistant` lines that share the message id and carry the
// same usage, so lines are collapsed per message id, field by field, by the
// maximum. A line without an id cannot be collapsed and counts on its own (an
// overcount, the safe direction). A message whose four counts are all zero
// costs nothing and is dropped (Claude Code's "<synthetic>" error turns).
//
// Not reused from token-usage.ts on purpose: that parser skips a line it
// cannot read and reads a missing count as 0, which is right for a dashboard
// chart and wrong for money. Here any doubt makes the transcript unusable,
// and the caller then books the run's FULL reservation (B-04): a damaged or
// half-written file, a symlink or a non-regular *.jsonl (a FIFO) anywhere in
// the tree, a duplicated key in any line (compared decoded; a second "type"
// could hide an assistant line, a second "output_tokens" could shrink it), a
// usage line without a model, a count that is not an integer 0 <= n < 10^9,
// or a tree above the size limits. Files are opened with O_NONBLOCK, so a
// FIFO swapped in after the directory listing cannot block either.

import { closeSync, constants, fstatSync, lstatSync, openSync, readdirSync, readSync } from 'node:fs'
import { join } from 'node:path'
import { findDuplicateJsonKeys } from '../json-dup-keys.js'
import { MAX_TOKENS_PER_FIELD } from './ledger-usage-jsonl.js'

/** The token counts of ONE API response, ready for pricing. */
export interface TranscriptMessage {
  readonly model: string
  readonly input_tokens: number
  readonly output_tokens: number
  readonly cache_write_tokens: number
  readonly cache_read_tokens: number
}

export type TranscriptReject =
  | 'missing'
  | 'not_directory'
  | 'not_regular'
  | 'duplicate_key'
  | 'symlink'
  | 'unreadable'
  | 'too_large'
  | 'too_deep'
  | 'too_many_files'
  | 'invalid_utf8'
  | 'partial_line'
  | 'invalid_json'
  | 'bad_tokens'
  | 'bad_model'

export type TranscriptResult =
  | { readonly ok: true; readonly messages: readonly TranscriptMessage[] }
  | { readonly ok: false; readonly reason: TranscriptReject }

export interface TranscriptLimits {
  readonly maxBytes?: number
  readonly maxFiles?: number
  readonly maxDepth?: number
}

const DEFAULT_MAX_BYTES = 64 * 1024 * 1024
const DEFAULT_MAX_FILES = 1000
const DEFAULT_MAX_DEPTH = 8
const MODEL_RE = /^[A-Za-z0-9_.-]{1,128}$/

class Unusable extends Error {
  constructor(readonly reason: TranscriptReject) {
    super(reason)
  }
}

interface Acc {
  model: string | null
  input_tokens: number
  output_tokens: number
  cache_write_tokens: number
  cache_read_tokens: number
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function count(v: unknown, required: boolean): number {
  if (v === undefined && !required) return 0
  if (typeof v === 'number' && Number.isSafeInteger(v) && v >= 0 && v < MAX_TOKENS_PER_FIELD) return v
  throw new Unusable('bad_tokens')
}

/** Every *.jsonl file under `dir`, depth-first in name order; no symlinks. */
function listFiles(dir: string, limits: Required<TranscriptLimits>): string[] {
  let st
  try {
    st = lstatSync(dir)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    throw new Unusable(code === 'ENOENT' || code === 'ENOTDIR' ? 'missing' : 'unreadable')
  }
  if (st.isSymbolicLink()) throw new Unusable('symlink')
  if (!st.isDirectory()) throw new Unusable('not_directory')

  const files: string[] = []
  const walk = (d: string, depth: number): void => {
    if (depth > limits.maxDepth) throw new Unusable('too_deep')
    let entries
    try {
      entries = readdirSync(d, { withFileTypes: true })
    } catch {
      throw new Unusable('unreadable')
    }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const e of entries) {
      const full = join(d, e.name)
      if (e.isSymbolicLink()) throw new Unusable('symlink')
      if (e.isDirectory()) {
        walk(full, depth + 1)
      } else if (e.name.endsWith('.jsonl')) {
        // Not filtered by type here: readFile opens it non-blocking and
        // refuses anything that is not a regular file (a FIFO, a socket).
        files.push(full)
        if (files.length > limits.maxFiles) throw new Unusable('too_many_files')
      }
    }
  }
  walk(dir, 0)
  return files
}

function readFile(path: string, budget: number): Buffer {
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK)
  } catch (err) {
    throw new Unusable((err as NodeJS.ErrnoException).code === 'ELOOP' ? 'symlink' : 'unreadable')
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) throw new Unusable('not_regular')
    if (st.size > budget) throw new Unusable('too_large')
    const buf = Buffer.alloc(st.size)
    let done = 0
    while (done < st.size) {
      const n = readSync(fd, buf, done, st.size - done, done)
      if (n === 0) break
      done += n
    }
    return buf.subarray(0, done)
  } finally {
    closeSync(fd)
  }
}

const UTF8 = new TextDecoder('utf-8', { fatal: true })

function addLine(line: string, byId: Map<string, Acc>, out: Acc[]): void {
  let obj: unknown
  try {
    obj = JSON.parse(line)
  } catch {
    throw new Unusable('invalid_json')
  }
  if (!isPlainObject(obj)) throw new Unusable('invalid_json')
  if (findDuplicateJsonKeys(line).length > 0) throw new Unusable('duplicate_key')
  if (obj.type !== 'assistant' || !isPlainObject(obj.message)) return
  const msg = obj.message
  if (msg.usage === undefined || msg.usage === null) return
  if (!isPlainObject(msg.usage)) throw new Unusable('bad_tokens')
  const u = msg.usage
  const cur: Acc = {
    model: typeof msg.model === 'string' && MODEL_RE.test(msg.model) ? msg.model : null,
    input_tokens: count(u.input_tokens, true),
    output_tokens: count(u.output_tokens, true),
    cache_write_tokens: count(u.cache_creation_input_tokens, false),
    cache_read_tokens: count(u.cache_read_input_tokens, false),
  }
  const id = typeof msg.id === 'string' && msg.id.length > 0 ? msg.id : null
  if (id === null) {
    out.push(cur)
    return
  }
  const prev = byId.get(id)
  if (!prev) {
    byId.set(id, cur)
    out.push(cur)
    return
  }
  prev.input_tokens = Math.max(prev.input_tokens, cur.input_tokens)
  prev.output_tokens = Math.max(prev.output_tokens, cur.output_tokens)
  prev.cache_write_tokens = Math.max(prev.cache_write_tokens, cur.cache_write_tokens)
  prev.cache_read_tokens = Math.max(prev.cache_read_tokens, cur.cache_read_tokens)
  if (prev.model === null) prev.model = cur.model
}

/**
 * The API responses recorded under `dir` (the run's `config/projects`), one
 * entry per message id. `ok:true` with an empty list means the run left a
 * transcript but no response with a cost in it.
 */
export function readTranscriptUsage(dir: string, limits: TranscriptLimits = {}): TranscriptResult {
  const lim: Required<TranscriptLimits> = {
    maxBytes: limits.maxBytes ?? DEFAULT_MAX_BYTES,
    maxFiles: limits.maxFiles ?? DEFAULT_MAX_FILES,
    maxDepth: limits.maxDepth ?? DEFAULT_MAX_DEPTH,
  }
  try {
    const byId = new Map<string, Acc>()
    const all: Acc[] = []
    let budget = lim.maxBytes
    for (const file of listFiles(dir, lim)) {
      const buf = readFile(file, budget)
      budget -= buf.length
      let text: string
      try {
        text = UTF8.decode(buf)
      } catch {
        throw new Unusable('invalid_utf8')
      }
      const lines = text.split('\n')
      // A file that does not end in "\n" was cut off mid-line: the response
      // in that line is not countable, so the whole transcript is not either.
      if (lines.pop() !== '') throw new Unusable('partial_line')
      for (const line of lines) {
        if (line.trim() === '') continue
        addLine(line, byId, all)
      }
    }
    const messages: TranscriptMessage[] = []
    for (const m of all) {
      if (m.input_tokens + m.output_tokens + m.cache_write_tokens + m.cache_read_tokens === 0) continue
      if (m.model === null) throw new Unusable('bad_model')
      messages.push({
        model: m.model,
        input_tokens: m.input_tokens,
        output_tokens: m.output_tokens,
        cache_write_tokens: m.cache_write_tokens,
        cache_read_tokens: m.cache_read_tokens,
      })
    }
    return { ok: true, messages }
  } catch (err) {
    if (err instanceof Unusable) return { ok: false, reason: err.reason }
    throw err
  }
}
