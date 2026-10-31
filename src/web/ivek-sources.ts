import * as nodeFs from 'node:fs'
import { isAbsolute, join, sep } from 'node:path'

// "Ivek" view (card 46e935d6): the file side. This is the first dashboard code
// that reads the 8T _ezermester / _brainy-deploy folders, so every read is
// fenced:
//  - the card id is validated as hex8 BEFORE it becomes a path component;
//  - roots come from the caller (the service takes them from config, never from
//    a request); the root realpath is resolved once per call and every
//    candidate must stay under it;
//  - no symlink is followed: lstat on every directory and file, then the file
//    is opened with O_NOFOLLOW and the fd's fstat must be the same regular file
//    (dev + ino) as the lstat (closes the swap window);
//  - size is checked from stat before the read, and the read itself is bounded;
//  - ONLY allowlisted, normalised fields leave: findings-log id/round/reviewer/
//    severity/event/ts aggregated (never summary/reason/location), brief file
//    name + mtime (the file is never opened), deploy base/tip/files + a status
//    enum (never the file list or the status line text);
//  - failures are reported as a reason code, never as an error message or path.

export const HEX8_RE = /^[0-9a-f]{8}$/

export const FINDINGS_MAX_BYTES = 1024 * 1024
export const DEPLOY_LOG_MAX_BYTES = 64 * 1024
export const MAX_FINDINGS_LINES = 10_000
export const MAX_BRIEFS = 200
export const MAX_DEPLOY_LOGS = 200
export const MAX_DEPLOY_ROOT_ENTRIES = 1000
const MAX_ROUND_GROUPS = 500
const MAX_ROUND = 99
const MAX_REVIEWER_LEN = 64
const MAX_NAME_LEN = 128

export type MissingReason =
  | 'missing' | 'not_regular' | 'symlink' | 'outside_root' | 'too_large' | 'unreadable' | 'bad_id'
export type Missing = { ok: false; reason: MissingReason }

export type Severity = 'HIGH' | 'MED' | 'LOW' | 'OTHER'

export interface RoundSummary {
  round: number | null
  reviewer: string
  bySeverity: Record<Severity, number>
  add: number
  close: number
  reject: number
}

export interface FindingsSummary {
  ok: true
  rounds: RoundSummary[]
  events: { add: number; close: number; reject: number }
  lastTs: string | null
}

export interface BriefList { ok: true; files: { name: string; mtime: number }[] }

export type DeployMode = 'check' | 'apply' | 'rollback'
export type DeployResult = 'ok' | 'refused' | 'fail' | 'unknown'
export interface DeployRun {
  mode: DeployMode
  at: string
  base: string | null
  tip: string | null
  files: number | null
  result: DeployResult
}
export interface DeployRunList { ok: true; runs: DeployRun[] }

/** The fs surface the reader uses; a test passes a counting / swapping wrapper. */
export type IvekFs = Pick<
  typeof nodeFs,
  'lstatSync' | 'realpathSync' | 'readdirSync' | 'openSync' | 'fstatSync' | 'readSync' | 'closeSync'
>

const defaultFs: IvekFs = nodeFs

function fail(reason: MissingReason): Missing {
  return { ok: false, reason }
}

function errReason(e: unknown): MissingReason {
  const code = (e as NodeJS.ErrnoException | null)?.code
  return code === 'ENOENT' || code === 'ENOTDIR' ? 'missing' : 'unreadable'
}

function validId(cardId: unknown): cardId is string {
  return typeof cardId === 'string' && HEX8_RE.test(cardId)
}

function under(parent: string, child: string): boolean {
  return child.startsWith(parent.endsWith(sep) ? parent : parent + sep)
}

/** Resolve the root once. A root that is itself a symlink (8T mount) is fine: its realpath counts. */
function resolveRoot(root: string, fsi: IvekFs): { ok: true; real: string } | Missing {
  if (typeof root !== 'string' || !isAbsolute(root)) return fail('unreadable')
  try {
    const real = fsi.realpathSync(root)
    if (!fsi.lstatSync(real).isDirectory()) return fail('not_regular')
    return { ok: true, real }
  } catch (e) {
    return fail(errReason(e))
  }
}

/**
 * A real (non-symlink) directory directly under `parentReal`, contained under `rootReal`.
 * `name` must already be a validated plain name (no separators).
 */
function openDir(rootReal: string, parentReal: string, name: string, fsi: IvekFs): { ok: true; real: string } | Missing {
  const p = join(parentReal, name)
  try {
    const st = fsi.lstatSync(p)
    if (st.isSymbolicLink()) return fail('symlink')
    if (!st.isDirectory()) return fail('not_regular')
    const real = fsi.realpathSync(p)
    if (!under(rootReal, real)) return fail('outside_root')
    return { ok: true, real }
  } catch (e) {
    return fail(errReason(e))
  }
}

/** Read one regular, non-symlink file under dirReal, bounded by maxBytes. */
function readBounded(
  rootReal: string, dirReal: string, name: string, maxBytes: number, fsi: IvekFs,
): { ok: true; text: string } | Missing {
  const p = join(dirReal, name)
  let fd: number | null = null
  try {
    const st = fsi.lstatSync(p)
    if (st.isSymbolicLink()) return fail('symlink')
    if (!st.isFile()) return fail('not_regular')
    if (st.size > maxBytes) return fail('too_large')
    const real = fsi.realpathSync(p)
    if (!under(rootReal, real)) return fail('outside_root')
    const flags = nodeFs.constants.O_RDONLY | (nodeFs.constants.O_NOFOLLOW ?? 0) | (nodeFs.constants.O_NONBLOCK ?? 0)
    fd = fsi.openSync(p, flags)
    const fst = fsi.fstatSync(fd)
    if (!fst.isFile() || fst.ino !== st.ino || fst.dev !== st.dev) return fail('unreadable')
    if (fst.size > maxBytes) return fail('too_large')
    const buf = Buffer.alloc(maxBytes + 1)
    let total = 0
    while (total <= maxBytes) {
      const n = fsi.readSync(fd, buf, total, maxBytes + 1 - total, null)
      if (n <= 0) break
      total += n
    }
    if (total > maxBytes) return fail('too_large')
    return { ok: true, text: buf.toString('utf8', 0, total) }
  } catch (e) {
    return fail(errReason(e))
  } finally {
    if (fd !== null) {
      try { fsi.closeSync(fd) } catch { /* nothing to report */ }
    }
  }
}

// ---------------------------------------------------------------- findings-log

const REVIEWER_RE = /^[A-Za-z0-9._-]+$/
const ID_RE = /^[A-Za-z0-9._-]{1,64}$/

function normSeverity(v: unknown): Severity {
  if (typeof v !== 'string') return 'OTHER'
  const u = v.trim().toUpperCase()
  if (u === 'HIGH') return 'HIGH'
  if (u === 'MED' || u === 'MEDIUM') return 'MED'
  if (u === 'LOW') return 'LOW'
  return 'OTHER'
}

function normRound(v: unknown): number | null {
  return typeof v === 'number' && Number.isInteger(v) && v >= 0 && v <= MAX_ROUND ? v : null
}

function normReviewer(v: unknown): string | null {
  return typeof v === 'string' && v.length > 0 && v.length <= MAX_REVIEWER_LEN && REVIEWER_RE.test(v) ? v : null
}

function normTs(v: unknown): number | null {
  if (typeof v !== 'string' || v.length > 64) return null
  const ms = Date.parse(v)
  return Number.isNaN(ms) ? null : ms
}

interface Row {
  event: 'add' | 'close' | 'reject'
  id: string | null
  round: number | null
  reviewer: string | null
  severity: Severity
}

export function readFindingsSummary(root: string, cardId: string, fsi: IvekFs = defaultFs): FindingsSummary | Missing {
  if (!validId(cardId)) return fail('bad_id')
  const r = resolveRoot(root, fsi)
  if (!r.ok) return r
  const d = openDir(r.real, r.real, cardId, fsi)
  if (!d.ok) return d
  const f = readBounded(r.real, d.real, 'findings-log.jsonl', FINDINGS_MAX_BYTES, fsi)
  if (!f.ok) return f

  const rows: Row[] = []
  let lastMs: number | null = null
  const lines = f.text.split('\n')
  for (let i = 0; i < lines.length && i < MAX_FINDINGS_LINES; i++) {
    const line = lines[i].trim()
    if (!line) continue
    let o: unknown
    try { o = JSON.parse(line) } catch { continue }
    if (typeof o !== 'object' || o === null || Array.isArray(o)) continue
    const rec = o as Record<string, unknown>
    const ev = rec.event
    if (ev !== 'add' && ev !== 'close' && ev !== 'reject') continue
    rows.push({
      event: ev,
      id: typeof rec.id === 'string' && ID_RE.test(rec.id) ? rec.id : null,
      round: normRound(rec.round),
      reviewer: normReviewer(rec.reviewer),
      severity: normSeverity(rec.severity),
    })
    const ms = normTs(rec.ts)
    if (ms !== null && (lastMs === null || ms > lastMs)) lastMs = ms
  }

  // close / reject rows carry no round: take it (and the reviewer) from the add row with the same id.
  const addById = new Map<string, Row>()
  for (const row of rows) {
    if (row.event === 'add' && row.id !== null && !addById.has(row.id)) addById.set(row.id, row)
  }
  const groups = new Map<string, RoundSummary>()
  const events = { add: 0, close: 0, reject: 0 }
  for (const row of rows) {
    events[row.event]++
    const src = row.event === 'add' ? row : (row.id !== null ? addById.get(row.id) : undefined)
    const round = row.round ?? src?.round ?? null
    const reviewer = row.reviewer ?? src?.reviewer ?? 'unknown'
    const key = `${round ?? 'n'}|${reviewer}`
    let g = groups.get(key)
    if (!g) {
      if (groups.size >= MAX_ROUND_GROUPS) continue
      g = { round, reviewer, bySeverity: { HIGH: 0, MED: 0, LOW: 0, OTHER: 0 }, add: 0, close: 0, reject: 0 }
      groups.set(key, g)
    }
    g[row.event]++
    if (row.event === 'add') g.bySeverity[row.severity]++
  }
  const rounds = [...groups.values()].sort((a, b) => {
    if (a.round === null && b.round !== null) return 1
    if (a.round !== null && b.round === null) return -1
    if (a.round !== b.round) return (a.round as number) - (b.round as number)
    return a.reviewer < b.reviewer ? -1 : a.reviewer > b.reviewer ? 1 : 0
  })
  return { ok: true, rounds, events, lastTs: lastMs === null ? null : new Date(lastMs).toISOString() }
}

// ---------------------------------------------------------------------- briefs

const BRIEF_NAME_RE = /^[A-Za-z0-9._-]*brief[A-Za-z0-9._-]*\.md$/

/** File name + mtime only. A brief is never opened. */
export function listBriefs(root: string, cardId: string, fsi: IvekFs = defaultFs): BriefList | Missing {
  if (!validId(cardId)) return fail('bad_id')
  const r = resolveRoot(root, fsi)
  if (!r.ok) return r
  const d = openDir(r.real, r.real, cardId, fsi)
  if (!d.ok) return d
  let names: string[]
  try {
    names = (fsi.readdirSync(d.real) as string[]).map(String)
  } catch (e) {
    return fail(errReason(e))
  }
  names = names.filter((n) => n.length <= MAX_NAME_LEN && BRIEF_NAME_RE.test(n)).sort()
  const files: { name: string; mtime: number }[] = []
  for (const name of names) {
    if (files.length >= MAX_BRIEFS) break
    try {
      const st = fsi.lstatSync(join(d.real, name))
      if (st.isSymbolicLink() || !st.isFile()) continue
      files.push({ name, mtime: Math.floor(st.mtimeMs) })
    } catch { continue }
  }
  return { ok: true, files }
}

// --------------------------------------------------------------------- deploy

const DEPLOY_FILE_RE = /^deploy-(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})(\d{2})-(check|apply|rollback)\.log$/
const DEPLOY_DIR_RE = /^[A-Za-z0-9._-]+$/
const FIRST_LINE_RE = /^base=([0-9a-f]{7,40}) tip=([0-9a-f]{7,40}) files=(\d{1,6})(?:\s|$)/
const SHORT_HASH_LEN = 8

function deployAt(m: RegExpMatchArray): string | null {
  const [y, mo, d, h, mi, s] = m.slice(1, 7).map(Number)
  if (mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59) return null
  const p = (n: number, w = 2): string => String(n).padStart(w, '0')
  return `${p(y, 4)}-${p(mo)}-${p(d)}T${p(h)}:${p(mi)}:${p(s)}`
}

/** Only the enum survives; the status line text itself is dropped. */
function deployResult(text: string): DeployResult {
  let result: DeployResult = 'unknown'
  for (const line of text.split('\n')) {
    if (/^(CHECK OK|APPLY OK|ROLLBACK OK)\b/.test(line)) result = 'ok'
    else if (/^REFUSED\b/.test(line)) result = 'refused'
    else if (/^FAIL\b/.test(line)) result = 'fail'
  }
  return result
}

/** A deploy folder name matches when one of its '-'-separated tokens is exactly the card id. */
function folderMatches(name: string, cardId: string): boolean {
  return name.length <= MAX_NAME_LEN && DEPLOY_DIR_RE.test(name) && name.split('-').includes(cardId)
}

export function listDeployRuns(root: string, cardId: string, fsi: IvekFs = defaultFs): DeployRunList | Missing {
  if (!validId(cardId)) return fail('bad_id')
  const r = resolveRoot(root, fsi)
  if (!r.ok) return r
  let entries: string[]
  try {
    entries = (fsi.readdirSync(r.real) as string[]).map(String).sort().slice(0, MAX_DEPLOY_ROOT_ENTRIES)
  } catch (e) {
    return fail(errReason(e))
  }
  const runs: DeployRun[] = []
  let matched = 0
  let sawSymlink = false
  for (const name of entries) {
    if (!folderMatches(name, cardId)) continue
    const d = openDir(r.real, r.real, name, fsi)
    if (!d.ok) {
      if (d.reason === 'symlink') sawSymlink = true
      continue
    }
    matched++
    let files: string[]
    try {
      files = (fsi.readdirSync(d.real) as string[]).map(String).sort()
    } catch { continue }
    for (const fname of files) {
      if (runs.length >= MAX_DEPLOY_LOGS) break
      const m = fname.match(DEPLOY_FILE_RE)
      if (!m) continue
      const at = deployAt(m)
      if (at === null) continue
      const f = readBounded(r.real, d.real, fname, DEPLOY_LOG_MAX_BYTES, fsi)
      if (!f.ok) continue
      const first = f.text.split('\n', 1)[0]
      const fm = first.match(FIRST_LINE_RE)
      runs.push({
        mode: m[7] as DeployMode,
        at,
        base: fm ? fm[1].slice(0, SHORT_HASH_LEN) : null,
        tip: fm ? fm[2].slice(0, SHORT_HASH_LEN) : null,
        files: fm ? Number(fm[3]) : null,
        result: deployResult(f.text),
      })
    }
  }
  if (matched === 0) return fail(sawSymlink ? 'symlink' : 'missing')
  runs.sort((a, b) => (a.at < b.at ? -1 : a.at > b.at ? 1 : 0))
  return { ok: true, runs }
}
