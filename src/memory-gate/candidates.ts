// Memory write gate: candidate finder, narrowed to ONE owner (card 3e9f6c28, node G2d;
// spec-delta SD-12, SD-13, SD-14).
//
// This decides which stored rows may end up in a prompt that leaves the machine, so it is
// deliberately NOT hybridSearchWith(): that query is `agent_id = ? OR category = 'shared'`
// and would hand other agents' shared rows to the classifier. Here BOTH branches filter in
// the SQL itself, never afterwards:
//   agent_id = <source owner>  AND  category IN ('warm','cold')  AND  id < <source id>
//   AND (when the table exists) the row is not a daily-log mirror row.
// No "superseded" exclusion in b1: there is no memory_gate_state table yet (b2).
//
// Branches
//   keyword  FTS5 MATCH built from the source keywords + first 400 characters of content:
//            at most 24 terms, each ONLY letters/digits (so no FTS5 syntax can be injected),
//            each double-quoted, joined with OR.
//   vector   the source's STORED vector against the stored vectors of the same filtered rows
//            (own cosine; none stored yet = this branch is skipped, the caller waits).
// Fusion is the pure db.fuseRanked(). After fusion every candidate is re-read from the DB
// and re-checked against the same rules (defence in depth); a failure drops the candidate and
// is counted (`rejected`, expected 0 in production).
//
// Event loop (B10): the finder is a generator that yields at every slice boundary (after the
// keyword branch, after each page of VECTOR_PAGE stored vectors, before the deep re-check).
// findGateCandidates() drives it to the end synchronously (tests, scripts);
// findGateCandidatesAsync() awaits setImmediate between slices, so a tick never holds the
// dashboard's event loop for long. Vectors are read page by page (keyset on id), so no single
// query pulls thousands of stored vectors at once. db.ts has no reusable vector cache
// (checked), so the row cap is MAX_VECTOR_ROWS = 1500.
//
// Read-only: nothing here writes, and in particular no access time is ever touched.
import type Database from 'better-sqlite3'
import { fuseRanked, type HybridHit, type Memory, type VectorHit } from '../db.js'
import { FORBIDDEN_OWNERS } from './gate-env.js'

export const MAX_FTS_TERMS = 24
const MAX_TERM_CHARS = 64
const SOURCE_TEXT_CHARS = 400
const BRANCH_LIMIT = 20
const MAX_VECTOR_ROWS = 1500
/** Stored vectors parsed and scored per synchronous slice. */
export const VECTOR_PAGE = 100

export interface GateSourceRow {
  id: number
  agent_id: string
  content: string
  keywords?: string | null
  /** Stored vector as JSON text, or null when the embedder has not run yet. */
  embedding?: string | null
}

export interface CandidateOptions {
  /** 1..5, default 5 (MEMORY_GATE_CANDIDATES). */
  limit?: number
  maxVectorRows?: number
}

export interface CandidateResult {
  hits: HybridHit[]
  /** Candidates dropped by the deep re-check. Expected 0. */
  rejected: number
  ftsTerms: number
  vectorUsed: boolean
  /** Set when the finder refused to run at all ('forbidden_owner' | 'bad_source'). */
  refused?: string
}

// The access time is deliberately not read: the gate neither reads nor writes it, and the
// Memory shape gets a constant instead (nothing downstream looks at it).
const COLUMNS = 'm.id, m.chat_id, m.topic_key, m.content, m.sector, m.salience, m.created_at, m.agent_id, m.category, m.auto_generated, m.keywords'

type Row = Omit<Memory, 'accessed_at' | 'embedding'> & { embedding?: string | null }
function toMemory(r: Row, embedding: string | null): Memory {
  return { ...r, accessed_at: 0, embedding }
}

/** Letters/digits terms, keywords first, deduplicated case-insensitively, at most MAX_FTS_TERMS. */
export function gateFtsTerms(keywords: string | null | undefined, content: string): string[] {
  const text = `${keywords ?? ''} ${content.slice(0, SOURCE_TEXT_CHARS)}`
  const seen = new Set<string>()
  const out: string[] = []
  for (const m of text.normalize('NFKC').matchAll(/[\p{L}\p{N}]{3,}/gu)) {
    const term = m[0].slice(0, MAX_TERM_CHARS)
    const key = term.toLowerCase()
    if (seen.has(key)) continue
    seen.add(key)
    out.push(term)
    if (out.length >= MAX_FTS_TERMS) break
  }
  return out
}

/** `"a" OR "b"`; every term is plain letters/digits, so the quotes can never be closed from inside. */
export function gateFtsExpression(terms: string[]): string {
  return terms.map(t => `"${t}"`).join(' OR ')
}

function cosine(a: number[], b: number[]): number {
  let dot = 0, na = 0, nb = 0
  for (let i = 0; i < a.length; i++) { dot += a[i] * b[i]; na += a[i] * a[i]; nb += b[i] * b[i] }
  return dot / (Math.sqrt(na) * Math.sqrt(nb))
}

function parseVector(raw: string | null | undefined): number[] | null {
  if (!raw) return null
  try {
    const v = JSON.parse(raw) as unknown
    if (!Array.isArray(v) || v.length === 0) return null
    for (const x of v) if (typeof x !== 'number' || !Number.isFinite(x)) return null
    let norm = 0
    for (const x of v as number[]) norm += x * x
    return norm > 0 && Number.isFinite(norm) ? (v as number[]) : null
  } catch {
    return null
  }
}

function hasMirrorTable(handle: Database.Database): boolean {
  return handle.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'daily_log_memory'").get() !== undefined
}

/**
 * Candidates for ONE source row, as a generator: every `yield` is a slice boundary where the
 * async driver gives the event loop back. Never throws on an absent vector, an odd source, or a
 * missing mirror table; a real DB error propagates to the worker (which records an error class).
 */
function* candidateSteps(handle: Database.Database, source: GateSourceRow, opts: CandidateOptions): Generator<void, CandidateResult, void> {
  const empty = (refused?: string): CandidateResult => ({ hits: [], rejected: 0, ftsTerms: 0, vectorUsed: false, ...(refused ? { refused } : {}) })
  if (!source || !Number.isInteger(source.id) || source.id <= 0 || typeof source.agent_id !== 'string' || source.agent_id === '' || typeof source.content !== 'string') {
    return empty('bad_source')
  }
  // Defence in depth: the worker already screens owners, the finder refuses the forbidden ones too.
  if (FORBIDDEN_OWNERS.includes(source.agent_id)) return empty('forbidden_owner')

  const limit = Math.min(Math.max(Math.floor(opts.limit ?? 5), 1), 5)
  const maxVec = Math.min(Math.max(Math.floor(opts.maxVectorRows ?? MAX_VECTOR_ROWS), 1), 50000)
  const mirror = hasMirrorTable(handle)
  const notMirror = mirror ? ' AND NOT EXISTS (SELECT 1 FROM daily_log_memory dlm WHERE dlm.memory_id = m.id)' : ''
  // Owner, category and id bound live IN the WHERE clause of both branches.
  const scope = `m.agent_id = ? AND m.category IN ('warm','cold') AND m.id < ?${notMirror}`

  // --- keyword branch
  const terms = gateFtsTerms(source.keywords, source.content)
  let fts: Memory[] = []
  if (terms.length > 0) {
    const rows = handle.prepare(
      `SELECT ${COLUMNS} FROM memories m
       JOIN memories_fts f ON m.id = f.rowid
       WHERE f.memories_fts MATCH ? AND ${scope}
       ORDER BY f.rank
       LIMIT ?`,
    ).all(gateFtsExpression(terms), source.agent_id, source.id, BRANCH_LIMIT) as Row[]
    fts = rows.map(r => toMemory(r, null))
  }
  yield

  // --- vector branch
  let vec: VectorHit[] = []
  const queryVec = parseVector(source.embedding)
  if (queryVec) {
    const page = handle.prepare(
      `SELECT ${COLUMNS}, m.embedding FROM memories m
       WHERE m.embedding IS NOT NULL AND ${scope} AND m.id < ?
       ORDER BY m.id DESC
       LIMIT ?`,
    )
    const scored: VectorHit[] = []
    let before = source.id
    let seen = 0
    while (seen < maxVec) {
      const want = Math.min(VECTOR_PAGE, maxVec - seen)
      const rows = page.all(source.agent_id, source.id, before, want) as Row[]
      for (const row of rows) {
        // A stored vector with no usable direction (malformed, other length, zero norm) has no
        // similarity to offer: skip it instead of letting a fake score of 0 into the candidate list.
        let score: number
        try {
          const emb = JSON.parse(row.embedding as string) as unknown
          if (!Array.isArray(emb) || emb.length !== queryVec.length || !emb.every(x => typeof x === 'number')) continue
          let norm = 0
          for (const x of emb as number[]) norm += x * x
          if (!Number.isFinite(norm) || norm === 0) continue
          const c = cosine(queryVec, emb as number[])
          if (!Number.isFinite(c)) continue
          score = c
        } catch {
          continue
        }
        scored.push({ memory: toMemory(row, null), score })
      }
      seen += rows.length
      if (rows.length < want) break
      before = rows[rows.length - 1].id
      yield
    }
    scored.sort((a, b) => b.score - a.score)
    vec = scored.slice(0, BRANCH_LIMIT)
  }
  yield

  const fused = fuseRanked(fts, vec, limit)

  // --- deep re-check: re-read each candidate and test the rules again, independent of the branch SQL
  const check = handle.prepare('SELECT id, agent_id, category FROM memories WHERE id = ?')
  const isMirror = mirror ? handle.prepare('SELECT 1 FROM daily_log_memory WHERE memory_id = ?') : null
  const hits: HybridHit[] = []
  let rejected = 0
  for (const hit of fused) {
    const row = check.get(hit.memory.id) as { id: number; agent_id: string; category: string } | undefined
    const good = row !== undefined
      && row.agent_id === source.agent_id
      && (row.category === 'warm' || row.category === 'cold')
      && row.id < source.id
      && !(isMirror && isMirror.get(row.id) !== undefined)
      // what we hold must also agree with the fresh read (a branch that returned a stale or foreign row)
      && hit.memory.agent_id === source.agent_id
      && (hit.memory.category === 'warm' || hit.memory.category === 'cold')
    if (good) hits.push({ ...hit, memory: { ...hit.memory, embedding: null } })
    else rejected++
  }
  return { hits, rejected, ftsTerms: terms.length, vectorUsed: queryVec !== null }
}

function yieldToLoop(): Promise<void> {
  return new Promise<void>(resolve => setImmediate(resolve))
}

/** Synchronous driver: runs every slice back to back. */
export function findGateCandidates(handle: Database.Database, source: GateSourceRow, opts: CandidateOptions = {}): CandidateResult {
  const it = candidateSteps(handle, source, opts)
  for (;;) {
    const n = it.next()
    if (n.done) return n.value
  }
}

/** Event-loop-friendly driver: the same slices, with a setImmediate between them. */
export async function findGateCandidatesAsync(handle: Database.Database, source: GateSourceRow, opts: CandidateOptions = {}): Promise<CandidateResult> {
  const it = candidateSteps(handle, source, opts)
  for (;;) {
    const n = it.next()
    if (n.done) return n.value
    await yieldToLoop()
  }
}
