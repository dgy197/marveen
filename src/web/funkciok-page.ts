import { getDb } from '../db.js'
import { maskSecrets } from './agent-transcript.js'
import {
  checkRepoPath, getRegistryEntry, listRegistry,
  type Funkcio, type RegistryEntry,
} from './funkciok-registry.js'
import {
  containsToken, matchCommits, matchesAnyGlob, prNumberOf,
  type GitLogReader, type MatchedCommit, type MatchReason,
} from './funkciok-git.js'

// Function page (S1): assembles the function page from the registry, the kanban
// tables, the inter-agent bus and git. READ ONLY.
//
// Spec 5.4: every response is built by one of the explicit serializers below.
// A field that is not named in a serializer cannot leave the server, whatever
// the source row happens to carry (no SELECT * passthrough, no "strip the bad
// ones"). The *_KEYS constants are the allowlists the snapshot tests pin.

export const MESSAGE_PREVIEW_CHARS = 200
export const MESSAGE_MAX_ROWS = 200
export const COMMIT_MAX_ROWS = 500
export const TEST_MAX_ROWS = 200
const MESSAGE_CANDIDATE_LIMIT = 5000
const MESSAGE_FULL_MAX_CHARS = 200_000
const SUBJECT_MAX_CHARS = 300

export const LIST_ITEM_KEYS = ['slug', 'nev', 'last_change', 'open_cards', 'error'] as const
export const PAGE_KEYS = [
  'slug', 'nev', 'leiras', 'last_change', 'open_cards', 'commits_without_card', 'commits_total',
  'cards', 'cards_missing', 'messages', 'commits', 'tests', 'repos', 'tiltasok', 'specUtak',
] as const
export const CARD_KEYS = ['seq', 'id', 'title', 'status', 'assignee', 'parent_id', 'created_at', 'last_status_at', 'archived', 'events'] as const
export const CARD_EVENT_KEYS = ['from_status', 'to_status', 'actor', 'created_at'] as const
export const MESSAGE_ROW_KEYS = ['id', 'from_agent', 'to_agent', 'status', 'created_at', 'completed_at', 'reason', 'content_excerpt', 'result_excerpt'] as const
export const MESSAGE_FULL_KEYS = ['id', 'from_agent', 'to_agent', 'status', 'created_at', 'completed_at', 'content', 'result'] as const
export const COMMIT_KEYS = ['repo', 'hash', 'date', 'author', 'subject', 'pr', 'reason'] as const
export const TEST_KEYS = ['repo', 'path', 'last_commit', 'last_date'] as const
export const REPO_KEYS = ['nev', 'error', 'commits'] as const

export interface FunkcioListItem {
  slug: string
  nev: string | null
  last_change: number | null
  open_cards: number | null
  error?: string
}

export interface CardEventOut { from_status: string | null; to_status: string; actor: string | null; created_at: number }
export interface CardOut {
  seq: number
  id: string
  title: string
  status: string
  assignee: string | null
  parent_id: string | null
  created_at: number
  last_status_at: number
  archived: boolean
  events: CardEventOut[]
}
export interface MessageRowOut {
  id: number
  from_agent: string
  to_agent: string
  status: string
  created_at: number
  completed_at: number | null
  reason: 'card' | 'hex' | 'tag'
  content_excerpt: string
  result_excerpt: string | null
}
export interface MessageFullOut {
  id: number
  from_agent: string
  to_agent: string
  status: string
  created_at: number
  completed_at: number | null
  content: string
  result: string | null
}
export interface CommitOut { repo: string; hash: string; date: number; author: string; subject: string; pr: number | null; reason: MatchReason }
export interface TestOut { repo: string; path: string; last_commit: string; last_date: number }
export interface RepoOut { nev: string; error: string | null; commits: number }
export interface FunkcioPage {
  slug: string
  nev: string
  leiras: string
  last_change: number | null
  open_cards: number
  commits_without_card: number
  commits_total: number
  cards: CardOut[]
  cards_missing: string[]
  messages: MessageRowOut[]
  commits: CommitOut[]
  tests: TestOut[]
  repos: RepoOut[]
  tiltasok: string[]
  specUtak: string[]
}

export interface FunkciokDeps {
  registryDir: string
  getAllowedRepos: () => Set<string>
  git: GitLogReader
}

// ---------------------------------------------------------------------------
// Text helpers
// ---------------------------------------------------------------------------

function clip(s: string, max: number): string {
  const chars = Array.from(s)
  return chars.length <= max ? s : chars.slice(0, max).join('')
}

// B3 (S1 security r1): above this size the text is not masked at all and a fixed
// marker is returned instead (fail closed). A partial cut BEFORE masking could
// leave half of a multi-part secret unmatched, so there is no "mask a prefix".
export const MASK_INPUT_MAX_CHARS = 1_000_000
export const TOO_LONG_MARKER = '[too long]'

/** Mask the WHOLE text first, then cut: a secret cut in half would dodge the patterns. */
function maskedPreview(raw: string | null, max: number): string | null {
  if (raw === null || raw === undefined) return null
  if (raw.length > MASK_INPUT_MAX_CHARS) return TOO_LONG_MARKER
  return clip(maskSecrets(raw), max)
}

// ---------------------------------------------------------------------------
// Cards
// ---------------------------------------------------------------------------

interface CardRow {
  seq: number
  id: string
  title: string
  status: string
  assignee: string | null
  parent_id: string | null
  created_at: number
  updated_at: number
  archived_at: number | null
}

interface EventRow { from_status: string | null; to_status: string; actor: string | null; created_at: number }

const CARD_SELECT = 'SELECT rowid AS seq, id, title, status, assignee, parent_id, created_at, updated_at, archived_at FROM kanban_cards'

interface LoadedCards { cards: CardOut[]; missing: string[]; seqs: Set<number>; ids: string[] }

/**
 * Registry cards plus their subcards. `seqs` and `ids` cover BOTH: a message or
 * commit that names a subcard belongs to the function (spec 6/S1 steps 2-3).
 */
function loadCards(kartyak: readonly string[]): LoadedCards {
  const db = getDb()
  const byId = db.prepare(`${CARD_SELECT} WHERE id = ? COLLATE NOCASE`)
  const children = db.prepare(`${CARD_SELECT} WHERE parent_id = ? COLLATE NOCASE ORDER BY created_at ASC, rowid ASC`)
  const events = db.prepare('SELECT from_status, to_status, actor, created_at FROM kanban_card_events WHERE card_id = ? ORDER BY created_at ASC, id ASC')

  const seen = new Set<string>()
  const rows: CardRow[] = []
  const missing: string[] = []
  const seqs = new Set<number>()
  for (const hex of kartyak) {
    const row = byId.get(hex) as CardRow | undefined
    if (!row) { missing.push(hex); continue }
    seqs.add(row.seq)
    if (!seen.has(row.id)) { seen.add(row.id); rows.push(row) }
    for (const child of children.all(row.id) as CardRow[]) {
      seqs.add(child.seq)
      if (!seen.has(child.id)) { seen.add(child.id); rows.push(child) }
    }
  }

  const cards = rows.map((r): CardOut => serializeCard(r, events.all(r.id) as EventRow[]))
  return { cards, missing, seqs, ids: rows.map((r) => r.id.toLowerCase()) }
}

function serializeCard(r: CardRow, ev: EventRow[]): CardOut {
  const lastEvent = ev.length > 0 ? ev[ev.length - 1].created_at : null
  return {
    seq: r.seq,
    id: r.id,
    title: maskedPreview(r.title, 300) ?? '',
    status: r.status,
    assignee: r.assignee,
    parent_id: r.parent_id,
    created_at: r.created_at,
    last_status_at: lastEvent ?? r.created_at,
    archived: r.archived_at !== null && r.archived_at !== undefined,
    events: ev.map((e): CardEventOut => ({
      from_status: e.from_status,
      to_status: e.to_status,
      actor: e.actor,
      created_at: e.created_at,
    })),
  }
}

function countOpen(cards: readonly CardOut[]): number {
  return cards.filter((c) => c.status !== 'done' && !c.archived).length
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

interface MsgRow {
  id: number
  from_agent: string
  to_agent: string
  status: string
  content: string
  result: string | null
  created_at: number
  completed_at: number | null
}

export interface MessageMatchCtx {
  seqs: ReadonlySet<number>
  /** Registry card ids, lowercase hex8: the pre-normalisation form of a reference. */
  hex: readonly string[]
  tags: readonly string[]
}

const SEQ_REF_RE = /#(\d+)\b/g
/**
 * Why (if at all) a message belongs to the function: `#<seq>` of a registry
 * card with a word boundary, the bare hex8 (rows written before the server
 * rewrote references), or a registry tag. `#1234` matches only when 1234 IS a
 * registry card's seq.
 */
export function messageReason(content: string, ctx: MessageMatchCtx): 'card' | 'hex' | 'tag' | null {
  if (ctx.seqs.size > 0 && content.includes('#')) {
    for (const m of content.matchAll(SEQ_REF_RE)) {
      if (ctx.seqs.has(Number(m[1]))) return 'card'
    }
  }
  for (const h of ctx.hex) if (containsToken(content, h)) return 'hex'
  for (const t of ctx.tags) if (containsToken(content, t)) return 'tag'
  return null
}

const MSG_COLS = 'id, from_agent, to_agent, status, content, result, created_at, completed_at'

function matchContext(fn: Funkcio, loaded: Pick<LoadedCards, 'seqs' | 'ids'>): MessageMatchCtx {
  return { seqs: loaded.seqs, hex: [...new Set([...fn.kartyak, ...loaded.ids])], tags: fn.tagek }
}

function loadMessages(ctx: MessageMatchCtx): MessageRowOut[] {
  const terms: string[] = [...[...ctx.seqs].map((s) => `#${s}`), ...ctx.hex, ...ctx.tags]
  if (terms.length === 0) return []
  // instr(), not LIKE: a tag with % or _ is a literal here. The SQL narrows the
  // table; messageReason() makes the real (word-boundary) decision.
  const where = terms.map(() => 'instr(content, ?) > 0').join(' OR ')
  const rows = getDb()
    .prepare(`SELECT ${MSG_COLS} FROM agent_messages WHERE ${where} ORDER BY id DESC LIMIT ${MESSAGE_CANDIDATE_LIMIT}`)
    .all(...terms) as MsgRow[]
  const out: MessageRowOut[] = []
  for (const r of rows) {
    const reason = messageReason(r.content, ctx)
    if (!reason) continue
    out.push({
      id: r.id,
      from_agent: r.from_agent,
      to_agent: r.to_agent,
      status: r.status,
      created_at: r.created_at,
      completed_at: r.completed_at,
      reason,
      content_excerpt: maskedPreview(r.content, MESSAGE_PREVIEW_CHARS) ?? '',
      result_excerpt: maskedPreview(r.result, MESSAGE_PREVIEW_CHARS),
    })
    if (out.length >= MESSAGE_MAX_ROWS) break
  }
  return out
}

// ---------------------------------------------------------------------------
// Git blocks
// ---------------------------------------------------------------------------

interface GitBlocks {
  repos: RepoOut[]
  commits: CommitOut[]
  commitsTotal: number
  commitsWithoutCard: number
  tests: TestOut[]
}

async function gatherGit(deps: FunkciokDeps, fn: Funkcio, cardIds: readonly string[]): Promise<GitBlocks> {
  const allowed = deps.getAllowedRepos()
  const cards = new Set([...fn.kartyak, ...cardIds])
  const repos: RepoOut[] = []
  const commits: CommitOut[] = []
  const tests: TestOut[] = []
  let withoutCard = 0

  for (const repo of fn.repok) {
    // The allowlist decision comes BEFORE any process exists.
    const check = checkRepoPath(repo.ut, allowed)
    if (!check.ok) { repos.push({ nev: repo.nev, error: check.error, commits: 0 }); continue }
    const log = await deps.git.read(check.realPath)
    if (!log.ok) { repos.push({ nev: repo.nev, error: log.error, commits: 0 }); continue }

    const matched: MatchedCommit[] = matchCommits(log.commits, { cards, tags: fn.tagek, pathGlobs: repo.pathGlobok })
    // B2: records the strict parser refused (forged or misaligned) are counted,
    // never silent: the repo shows an error next to the commits that did parse.
    repos.push({ nev: repo.nev, error: log.dropped > 0 ? 'git_records_dropped' : null, commits: matched.length })

    const seenTests = new Set<string>()
    for (const m of matched) {
      if (!m.hasCardRef) withoutCard++
      commits.push({
        repo: repo.nev,
        hash: m.commit.short,
        date: m.commit.date,
        author: clip(m.commit.author, 100),
        subject: maskedPreview(m.commit.subject, SUBJECT_MAX_CHARS) ?? '',
        pr: prNumberOf(m.commit.subject),
        reason: m.reason,
      })
      // Newest first: the first commit that touched a test file is its last one.
      if (repo.tesztGlobok.length > 0) {
        for (const file of m.commit.files) {
          if (seenTests.has(file) || !matchesAnyGlob(file, repo.tesztGlobok)) continue
          seenTests.add(file)
          tests.push({ repo: repo.nev, path: file, last_commit: m.commit.short, last_date: m.commit.date })
        }
      }
    }
  }

  commits.sort((a, b) => b.date - a.date)
  tests.sort((a, b) => (a.repo === b.repo ? a.path.localeCompare(b.path) : a.repo.localeCompare(b.repo)))
  return {
    repos,
    commits: commits.slice(0, COMMIT_MAX_ROWS),
    commitsTotal: commits.length,
    commitsWithoutCard: withoutCard,
    tests: tests.slice(0, TEST_MAX_ROWS),
  }
}

function lastChangeOf(cards: readonly CardOut[], commits: readonly CommitOut[]): number | null {
  let max: number | null = null
  for (const c of cards) if (max === null || c.last_status_at > max) max = c.last_status_at
  for (const c of commits) if (max === null || c.date > max) max = c.date
  return max
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export type PageResult =
  | { kind: 'ok'; page: FunkcioPage }
  | { kind: 'not_found' }
  | { kind: 'invalid'; slug: string; error: string }

export type MessageResult =
  | { kind: 'ok'; message: MessageFullOut }
  | { kind: 'not_found' }
  | { kind: 'invalid'; slug: string; error: string }

export interface FunkciokService {
  list(): Promise<FunkcioListItem[]>
  page(slug: string): Promise<PageResult>
  message(slug: string, id: number): Promise<MessageResult>
}

export function createFunkciokService(deps: FunkciokDeps): FunkciokService {
  async function listItem(e: RegistryEntry): Promise<FunkcioListItem> {
    if (!e.ok) return { slug: e.slug, nev: null, last_change: null, open_cards: null, error: e.error }
    const { cards, ids } = loadCards(e.funkcio.kartyak)
    const g = await gatherGit(deps, e.funkcio, ids)
    return { slug: e.slug, nev: e.funkcio.nev, last_change: lastChangeOf(cards, g.commits), open_cards: countOpen(cards) }
  }

  return {
    async list() {
      // Sequential: one git run at a time keeps a cold load from spawning a herd.
      const out: FunkcioListItem[] = []
      for (const e of listRegistry(deps.registryDir)) out.push(await listItem(e))
      return out
    },

    async page(slug) {
      const e = getRegistryEntry(deps.registryDir, slug)
      if (!e) return { kind: 'not_found' }
      if (!e.ok) return { kind: 'invalid', slug: e.slug, error: e.error }
      const fn = e.funkcio
      const loaded = loadCards(fn.kartyak)
      const { cards, missing } = loaded
      const g = await gatherGit(deps, fn, loaded.ids)
      return {
        kind: 'ok',
        page: {
          slug: fn.slug,
          nev: fn.nev,
          leiras: fn.leiras,
          last_change: lastChangeOf(cards, g.commits),
          open_cards: countOpen(cards),
          commits_without_card: g.commitsWithoutCard,
          commits_total: g.commitsTotal,
          cards,
          cards_missing: missing,
          messages: loadMessages(matchContext(fn, loaded)),
          commits: g.commits,
          tests: g.tests,
          repos: g.repos,
          tiltasok: fn.tiltasok,
          specUtak: fn.specUtak,
        },
      }
    },

    async message(slug, id) {
      const e = getRegistryEntry(deps.registryDir, slug)
      if (!e) return { kind: 'not_found' }
      if (!e.ok) return { kind: 'invalid', slug: e.slug, error: e.error }
      const fn = e.funkcio
      const row = getDb().prepare(`SELECT ${MSG_COLS} FROM agent_messages WHERE id = ?`).get(id) as MsgRow | undefined
      if (!row) return { kind: 'not_found' }
      // A message that is not a ROW of THIS function's page (same selection:
      // newest MESSAGE_MAX_ROWS matches) is a 404, the same as a missing one:
      // the endpoint is not a general message reader.
      const onPage = loadMessages(matchContext(fn, loadCards(fn.kartyak)))
      if (!onPage.some((m) => m.id === id)) return { kind: 'not_found' }
      return {
        kind: 'ok',
        message: {
          id: row.id,
          from_agent: row.from_agent,
          to_agent: row.to_agent,
          status: row.status,
          created_at: row.created_at,
          completed_at: row.completed_at,
          content: clip(maskSecrets(row.content), MESSAGE_FULL_MAX_CHARS),
          result: row.result === null ? null : clip(maskSecrets(row.result), MESSAGE_FULL_MAX_CHARS),
        },
      }
    },
  }
}
