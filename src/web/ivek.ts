import { realpathSync } from 'node:fs'
import { IVEK_DEPLOY_ROOT, IVEK_EZERMESTER_ROOT, PROJECT_ROOT } from '../config.js'
import { getKanbanCard, getKanbanCardEvents, listKanbanCards, type KanbanCard, type KanbanCardEvent } from '../db.js'
import { cardRefsIn, createGitLogReader, type GitLogReader } from './funkciok-git.js'
import {
  HEX8_RE,
  listBriefs,
  listDeployRuns,
  readFindingsSummary,
  type BriefList,
  type DeployRun,
  type DeployRunList,
  type FindingsSummary,
  type Missing,
} from './ivek-sources.js'

// "Ivek" view (card 46e935d6): the service behind GET /api/ivek[/:id].
//
// Joins four sources per card: kanban (db.ts), git (the Funkciok git reader,
// one cached `git log` for the whole view), and the two 8T folders through the
// fenced readers in ivek-sources.ts. Every block is independent: a source that
// fails becomes `{ ok: false, reason }` and the rest of the answer stays. What
// leaves is allowlisted and normalised; there are no absolute paths and no
// free text from findings, briefs or deploy logs (commit subjects and kanban
// titles are the two free-text fields, both by spec).

/** Assignees whose cards form the list (spec 2). */
export const IVEK_ASSIGNEES: ReadonlySet<string> = new Set(['ezermester', 'fejleszto', 'lapszabasz'])
/** A done card stays in the list for this long after its last update (K3: updated_at). */
export const IVEK_DONE_WINDOW_SECONDS = 14 * 24 * 3600
export const MAX_COMMITS = 200
export const MAX_EVENTS = 500
export const MAX_CHILDREN = 500
const MAX_SUBJECT = 200

export type PhaseKey = 'brief' | 'vegrehajtas' | 'review' | 'deploy_jelolt' | 'elesitve' | 'nincs_jel'

export interface Phase {
  phase: PhaseKey
  /** Review round, only for phase 'review' (null when the log has no numbered round). */
  round: number | null
  /** Unix seconds of the newest signal of that phase, null for 'nincs_jel'. */
  since: number | null
}

export interface PhaseSignals {
  /** Unix seconds of the newest brief file, null = none. */
  briefAt: number | null
  /** Unix seconds of the newest commit that references the card. */
  commitAt: number | null
  /** Highest numbered findings round, null = no numbered round. */
  reviewRound: number | null
  reviewAt: number | null
  checkAt: number | null
  applyAt: number | null
}

export const NO_SIGNALS: PhaseSignals = { briefAt: null, commitAt: null, reviewRound: null, reviewAt: null, checkAt: null, applyAt: null }

/**
 * The furthest phase reached wins (brief < vegrehajtas < review < deploy_jelolt
 * < elesitve); `since` is the timestamp of its newest trigger. No machine
 * signal at all is 'nincs_jel' ("GO-ra vár" cannot be derived).
 */
export function derivePhase(s: PhaseSignals): Phase {
  if (s.applyAt !== null) return { phase: 'elesitve', round: null, since: s.applyAt }
  if (s.checkAt !== null) return { phase: 'deploy_jelolt', round: null, since: s.checkAt }
  if (s.reviewRound !== null) return { phase: 'review', round: s.reviewRound, since: s.reviewAt }
  if (s.commitAt !== null) return { phase: 'vegrehajtas', round: null, since: s.commitAt }
  if (s.briefAt !== null) return { phase: 'brief', round: null, since: s.briefAt }
  return { phase: 'nincs_jel', round: null, since: null }
}

export type Block<T> = ({ ok: true } & T) | { ok: false; reason: string }

export interface IvekListItem {
  id: string
  title: string
  status: string
  assignee: string | null
  phase: Phase
}

export interface IvekEvent {
  created_at: number
  from_status: string | null
  to_status: string | null
  actor: string | null
}

export interface IvekCommit { hash: string; date: number; subject: string }
export interface IvekChild { id: string; title: string; status: string }

export interface IvekDetail {
  id: string
  title: string
  status: string
  assignee: string | null
  phase: Phase
  events: IvekEvent[] | { ok: false; reason: string }
  briefs: Block<{ files: { name: string; mtime: number }[] }>
  reviews: Block<{ rounds: FindingsSummary['rounds']; events: FindingsSummary['events']; lastTs: string | null }>
  commits: Block<{ commits: IvekCommit[] }>
  deploys: Block<{ runs: DeployRun[] }>
  children: IvekChild[] | { ok: false; reason: string }
}

export interface IvekService {
  list(): Promise<IvekListItem[]>
  /** null = no such kanban card. */
  detail(id: string): Promise<IvekDetail | null>
}

/** The kanban fields the service reads. */
export type CardRow = Pick<KanbanCard, 'id' | 'title' | 'status' | 'assignee' | 'parent_id' | 'updated_at'>

export interface IvekSources {
  findings(root: string, id: string): FindingsSummary | Missing
  briefs(root: string, id: string): BriefList | Missing
  deploys(root: string, id: string): DeployRunList | Missing
}

export interface IvekDeps {
  /** Non-archived cards. */
  cards(): CardRow[]
  /** Every card, archived included (children). */
  allCards(): CardRow[]
  card(id: string): CardRow | undefined
  events(id: string): KanbanCardEvent[]
  git: GitLogReader
  /** realpath of the repo to read, null when it cannot be resolved. */
  repo(): string | null
  ezermesterRoot: string
  deployRoot: string
  /** ms. */
  now(): number
  sources: IvekSources
}

const defaultSources: IvekSources = { findings: readFindingsSummary, briefs: listBriefs, deploys: listDeployRuns }

function defaultRepo(): string | null {
  try { return realpathSync(PROJECT_ROOT) } catch { return null }
}

export function defaultIvekDeps(): IvekDeps {
  return {
    cards: () => listKanbanCards(),
    allCards: () => listKanbanCards({ includeArchived: true }),
    card: (id) => getKanbanCard(id),
    events: (id) => getKanbanCardEvents(id),
    git: createGitLogReader(),
    repo: defaultRepo,
    ezermesterRoot: IVEK_EZERMESTER_ROOT,
    deployRoot: IVEK_DEPLOY_ROOT,
    now: () => Date.now(),
    sources: defaultSources,
  }
}

// ------------------------------------------------------------------ helpers

const REASON_RE = /^[a-z_]{1,24}$/
const TOKEN_RE = /^[A-Za-z0-9._:@-]{1,64}$/
const STATUS_RE = /^[a-z_]{1,32}$/

function gap(reason: string): { ok: false; reason: string } {
  return { ok: false, reason: REASON_RE.test(reason) ? reason : 'unreadable' }
}

/** Run a source; a throw (a bug or a hostile fs) is a gap, never an error response. */
function guarded<T>(fn: () => T): T | { ok: false; reason: string } {
  try { return fn() } catch { return gap('unreadable') }
}

function cleanText(s: unknown, max: number): string {
  return String(s ?? '').replace(/[\x00-\x1f\x7f]/g, ' ').trim().slice(0, max)
}

function tokenOrNull(s: string | null | undefined): string | null {
  return typeof s === 'string' && TOKEN_RE.test(s) ? s : null
}

function statusOrNull(s: string | null | undefined): string | null {
  return typeof s === 'string' && STATUS_RE.test(s) ? s : null
}

function cardHead(c: CardRow): { id: string; title: string; status: string; assignee: string | null } {
  return {
    id: cleanText(c.id, 64),
    title: cleanText(c.title, 300),
    status: statusOrNull(c.status) ?? 'unknown',
    assignee: tokenOrNull(c.assignee),
  }
}

function toSeconds(ms: number): number {
  return Math.floor(ms / 1000)
}

/** Deploy `at` is a naive local "YYYY-MM-DDTHH:MM:SS" (from the file name). */
function atSeconds(at: string): number | null {
  const ms = Date.parse(at)
  return Number.isFinite(ms) ? toSeconds(ms) : null
}

function maxOf(values: Array<number | null>): number | null {
  let m: number | null = null
  for (const v of values) if (v !== null && (m === null || v > m)) m = v
  return m
}

interface CommitIndex { ok: true; byCard: Map<string, IvekCommit[]> }

function indexCommits(commits: readonly { short: string; date: number; subject: string; body: string }[]): CommitIndex {
  const byCard = new Map<string, IvekCommit[]>()
  for (const c of commits) {
    const refs = new Set(cardRefsIn(`${c.subject}\n${c.body}`))
    for (const ref of refs) {
      const row: IvekCommit = { hash: c.short.slice(0, 12), date: c.date, subject: cleanText(c.subject, MAX_SUBJECT) }
      const list = byCard.get(ref)
      if (list) list.push(row)
      else byCard.set(ref, [row])
    }
  }
  return { ok: true, byCard }
}

// ------------------------------------------------------------------- service

export function createIvekService(deps: IvekDeps = defaultIvekDeps()): IvekService {
  async function commitIndex(): Promise<CommitIndex | { ok: false; reason: string }> {
    const repo = deps.repo()
    if (!repo) return gap('repo_missing')
    try {
      const r = await deps.git.read(repo)
      if (!r.ok) return gap(r.error)
      return indexCommits(r.commits)
    } catch {
      return gap('git_failed')
    }
  }

  function signalsOf(
    id: string,
    commits: CommitIndex | { ok: false; reason: string },
    fileBlocks: { findings: FindingsSummary | Missing | { ok: false; reason: string }; briefs: BriefList | Missing | { ok: false; reason: string }; deploys: DeployRunList | Missing | { ok: false; reason: string } },
  ): PhaseSignals {
    const sig: PhaseSignals = { ...NO_SIGNALS }
    if (commits.ok) {
      const rows = commits.byCard.get(id)
      if (rows && rows.length > 0) sig.commitAt = maxOf(rows.map((r) => r.date))
    }
    const b = fileBlocks.briefs
    if (b.ok && 'files' in b && b.files.length > 0) sig.briefAt = maxOf(b.files.map((f) => toSeconds(f.mtime)))
    const f = fileBlocks.findings
    if (f.ok && 'rounds' in f) {
      const rounds = f.rounds.map((r) => r.round).filter((n): n is number => n !== null)
      if (rounds.length > 0) {
        sig.reviewRound = Math.max(...rounds)
        if (f.lastTs) {
          const ms = Date.parse(f.lastTs)
          if (Number.isFinite(ms)) sig.reviewAt = toSeconds(ms)
        }
      }
    }
    const d = fileBlocks.deploys
    if (d.ok && 'runs' in d) {
      const at = (mode: string, okOnly: boolean): number | null =>
        maxOf(d.runs.filter((r) => r.mode === mode && (!okOnly || r.result === 'ok')).map((r) => atSeconds(r.at)))
      sig.checkAt = at('check', true)
      const apply = at('apply', true)
      const rollback = at('rollback', true)
      // A successful rollback after the apply takes the card back out of "elesitve".
      sig.applyAt = apply !== null && (rollback === null || rollback < apply) ? apply : null
    }
    return sig
  }

  function readFiles(id: string) {
    // K4: only a lower-case hex8 id reaches the file readers; anything else is "nincs adat".
    if (!HEX8_RE.test(id)) {
      const g = gap('bad_id')
      return { findings: g, briefs: g, deploys: g }
    }
    return {
      findings: guarded(() => deps.sources.findings(deps.ezermesterRoot, id)),
      briefs: guarded(() => deps.sources.briefs(deps.ezermesterRoot, id)),
      deploys: guarded(() => deps.sources.deploys(deps.deployRoot, id)),
    }
  }

  return {
    async list() {
      const nowS = toSeconds(deps.now())
      let cards: CardRow[]
      try { cards = deps.cards() } catch { return [] }
      const wanted = cards.filter((c) => {
        if (!c.assignee || !IVEK_ASSIGNEES.has(c.assignee.toLowerCase())) return false
        if (c.status === 'done') return c.updated_at >= nowS - IVEK_DONE_WINDOW_SECONDS
        return true
      })
      // One git read for the whole list (the reader caches it as well).
      const commits = wanted.length > 0 ? await commitIndex() : gap('git_failed')
      return wanted.map((c) => {
        const head = cardHead(c)
        const hex = HEX8_RE.test(c.id)
        const files = readFiles(c.id)
        const sig = signalsOf(c.id, hex ? commits : gap('bad_id'), files)
        return { ...head, phase: derivePhase(sig) }
      })
    },

    async detail(id) {
      if (!HEX8_RE.test(id)) return null
      const card = deps.card(id)
      if (!card) return null
      const head = cardHead(card)

      const files = readFiles(id)
      const commits = await commitIndex()

      let events: IvekDetail['events']
      try {
        events = deps.events(id).slice(-MAX_EVENTS).map((e) => ({
          created_at: Number.isFinite(e.created_at) ? e.created_at : 0,
          from_status: statusOrNull(e.from_status),
          to_status: statusOrNull(e.to_status),
          actor: tokenOrNull(e.actor),
        }))
      } catch { events = gap('unreadable') }

      let children: IvekDetail['children']
      try {
        children = deps.allCards()
          .filter((c) => c.parent_id === id)
          .slice(0, MAX_CHILDREN)
          .map((c) => ({ id: cleanText(c.id, 64), title: cleanText(c.title, 300), status: statusOrNull(c.status) ?? 'unknown' }))
      } catch { children = gap('unreadable') }

      const briefs: IvekDetail['briefs'] = files.briefs.ok && 'files' in files.briefs
        ? { ok: true, files: files.briefs.files.map((f) => ({ name: f.name, mtime: f.mtime })) }
        : gap((files.briefs as { reason: string }).reason)
      const reviews: IvekDetail['reviews'] = files.findings.ok && 'rounds' in files.findings
        ? { ok: true, rounds: files.findings.rounds, events: files.findings.events, lastTs: files.findings.lastTs }
        : gap((files.findings as { reason: string }).reason)
      const deploys: IvekDetail['deploys'] = files.deploys.ok && 'runs' in files.deploys
        ? { ok: true, runs: files.deploys.runs.map((r) => ({ ...r })) }
        : gap((files.deploys as { reason: string }).reason)
      let commitBlock: IvekDetail['commits']
      if (commits.ok) {
        const rows = (commits.byCard.get(id) ?? []).slice().sort((a, b) => a.date - b.date)
        commitBlock = { ok: true, commits: rows.slice(-MAX_COMMITS) }
      } else commitBlock = gap(commits.reason)

      return {
        ...head,
        phase: derivePhase(signalsOf(id, commits, files)),
        events,
        briefs,
        reviews,
        commits: commitBlock,
        deploys,
        children,
      }
    },
  }
}
