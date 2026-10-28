import { join } from 'node:path'
import { STORE_DIR } from '../config.js'
import { getDb } from '../db.js'
import { isAgentRunning } from './agent-process.js'
import { listRegistry } from './funkciok-registry.js'
import { listQuestionsPage, type QuestionOut } from './open-questions.js'

// Open questions S3-N3: the data behind the "Fejlesztes > Kerdesek" overview.
//
//   - open (not expired) questions grouped per agent, each with agent_running,
//     and per card row its card_seq (#<seq>) and funkcio_slug (spec D13);
//   - the pending approvals, SHOWN only (spec 5.3): the five allowlisted
//     columns below plus a link to the existing approvals page. No decision
//     path, and never action_description / action_payload / content_hash /
//     consumed_at: those can carry the very text the approval protects.
//
// This module only READS. Nothing in an approval gate reads open_questions
// (open-questions-gate-independence.test.ts pins that), and an answer to a
// question never touches the approvals table.

export const APPROVAL_LINK = '#approvals'
export const OVERVIEW_APPROVALS_MAX_ROWS = 50

/** The only approval columns that leave the server through the overview. */
export const APPROVAL_KEYS = ['id', 'agent_id', 'category', 'status', 'requested_at', 'link'] as const

export interface OverviewQuestion extends QuestionOut {
  card_seq: number | null
  funkcio_slug: string | null
}

export interface OverviewAgent {
  agent_id: string
  agent_running: boolean
  questions: OverviewQuestion[]
}

export interface OverviewApproval {
  id: string
  agent_id: string
  category: string
  status: 'pending'
  requested_at: number
  link: string
}

export interface Overview {
  agents: OverviewAgent[]
  pending_approvals: OverviewApproval[]
  /** The open-question list hit its cap (some questions are not shown). */
  questions_truncated: boolean
  /** More pending approvals exist than OVERVIEW_APPROVALS_MAX_ROWS. */
  approvals_truncated: boolean
}

export interface OverviewDeps {
  /** Directory of the function registry (one <slug>.json per function). */
  registryDir: string
  isRunning: (agent: string) => boolean
}

let depsOverride: OverviewDeps | null = null

/** Test seam: a temp registry dir and a fake run-state. null restores the defaults. */
export function setOverviewDepsForTest(d: OverviewDeps | null): void {
  depsOverride = d
}

export function defaultOverviewDeps(): OverviewDeps {
  return depsOverride ?? { registryDir: join(STORE_DIR, 'funkciok'), isRunning: isAgentRunning }
}

/** card id (8 hex) -> slug of the first (by slug) valid function that lists the card. */
function cardToSlug(registryDir: string): Map<string, string> {
  const map = new Map<string, string>()
  for (const entry of listRegistry(registryDir)) {
    if (!entry.ok) continue
    for (const card of entry.funkcio.kartyak) {
      if (!map.has(card)) map.set(card, entry.slug)
    }
  }
  return map
}

interface CardRef { seq: number | null; parent: string | null }

function cardRef(cardId: string): CardRef {
  const row = getDb().prepare('SELECT rowid AS seq, parent_id FROM kanban_cards WHERE id = ?').get(cardId) as { seq: number; parent_id: string | null } | undefined
  return row ? { seq: row.seq, parent: row.parent_id } : { seq: null, parent: null }
}

interface ApprovalRow {
  id: string
  agent_id: string
  category: string
  requested_at: number
}

// Named columns, never `*`: the allowlist is the SELECT list.
function listPendingApprovals(): { list: OverviewApproval[]; truncated: boolean } {
  const rows = getDb()
    .prepare(`SELECT id, agent_id, category, requested_at FROM approvals
              WHERE status = 'pending' ORDER BY requested_at DESC, id LIMIT ${OVERVIEW_APPROVALS_MAX_ROWS + 1}`)
    .all() as ApprovalRow[]
  const list = rows.slice(0, OVERVIEW_APPROVALS_MAX_ROWS).map((r): OverviewApproval => ({
    id: r.id,
    agent_id: r.agent_id,
    category: r.category,
    status: 'pending',
    requested_at: r.requested_at,
    link: APPROVAL_LINK,
  }))
  return { list, truncated: rows.length > OVERVIEW_APPROVALS_MAX_ROWS }
}

export function buildOverview(nowSec: number, deps: OverviewDeps = defaultOverviewDeps()): Overview {
  const slugs = cardToSlug(deps.registryDir)
  const byAgent = new Map<string, OverviewQuestion[]>()
  const page = listQuestionsPage('open', nowSec)
  for (const q of page.questions) {
    // A subcard (parent_id is a registry card) belongs to its parent's function, like the S1 page lists it.
    const ref = q.card_id === null ? null : cardRef(q.card_id)
    const row: OverviewQuestion = {
      ...q,
      card_seq: ref ? ref.seq : null,
      funkcio_slug: q.card_id === null || ref === null ? null : (slugs.get(q.card_id) ?? (ref.parent ? slugs.get(ref.parent.toLowerCase()) : undefined) ?? null),
    }
    const list = byAgent.get(q.agent_id)
    if (list) list.push(row)
    else byAgent.set(q.agent_id, [row])
  }
  const agents = [...byAgent.keys()].sort().map((agent_id): OverviewAgent => {
    let running = false
    try { running = deps.isRunning(agent_id) } catch { /* unknown state shows as not running */ }
    return { agent_id, agent_running: running, questions: byAgent.get(agent_id) ?? [] }
  })
  const approvals = listPendingApprovals()
  return { agents, pending_approvals: approvals.list, questions_truncated: page.truncated, approvals_truncated: approvals.truncated }
}
