import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import {
  CARD_EVENT_KEYS, CARD_KEYS, COMMIT_KEYS, LIST_ITEM_KEYS, MESSAGE_FULL_KEYS, MESSAGE_MAX_ROWS,
  MESSAGE_PREVIEW_CHARS, MESSAGE_ROW_KEYS, PAGE_KEYS, REPO_KEYS, TEST_KEYS, createFunkciokService,
  messageReason, type FunkciokService,
} from '../web/funkciok-page.js'
import { createGitLogReader, type ExecFileFn } from '../web/funkciok-git.js'

// Card d7b2d5c8 (S1): the assembled page against an in-memory sqlite, a temp
// registry directory and a real temp git repository. Acceptance S1-1 .. S1-5.

const MARKER = 'TITOK-MARKER'
const T0 = 1_760_000_000

const GIT_ENV = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Teszt Elek',
  GIT_AUTHOR_EMAIL: 'teszt@example.invalid',
  GIT_COMMITTER_NAME: 'Teszt Elek',
  GIT_COMMITTER_EMAIL: 'teszt@example.invalid',
}

function git(repo: string, args: string[], extraEnv: Record<string, string> = {}): void {
  execFileSync('git', ['-C', repo, '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], {
    env: { ...GIT_ENV, ...extraEnv },
    stdio: 'ignore',
  })
}

function makeRepo(commits: { msg: string; files: Record<string, string>; at: number }[]): string {
  const repo = mkdtempSync(join(tmpdir(), 'funkciok-page-repo-'))
  git(repo, ['init', '-q'])
  for (const c of commits) {
    for (const [rel, content] of Object.entries(c.files)) {
      const abs = join(repo, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content)
    }
    git(repo, ['add', '-A'])
    git(repo, ['commit', '-q', '-m', c.msg], { GIT_AUTHOR_DATE: `${c.at} +0000`, GIT_COMMITTER_DATE: `${c.at} +0000` })
  }
  return repo
}

// Secret-shaped strings are built at run time so no literal credential shape sits in this file.
const FAKE_SECRET = `token=${'Q'.repeat(30)}`

let registryDir: string
let repo: string
let svc: FunkciokService
let allowed: Set<string>
let seq: Record<string, number>

function insertCard(id: string, title: string, status: string, parent: string | null = null): number {
  const db = getDb()
  db.prepare(`INSERT INTO kanban_cards (id, title, description, test_steps, status, parent_id, assignee, sort_order, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?, 'ezermester', 0, ?, ?)`).run(id, title, `${MARKER} description`, `${MARKER} steps`, status, parent, T0, T0)
  return (db.prepare('SELECT rowid AS seq FROM kanban_cards WHERE id = ?').get(id) as { seq: number }).seq
}

function insertMessage(content: string, result: string | null = null, extra: { from?: string; to?: string } = {}): number {
  const info = getDb().prepare(`INSERT INTO agent_messages (from_agent, to_agent, content, status, result, created_at, completed_at)
                                VALUES (?, ?, ?, 'done', ?, ?, ?)`).run(extra.from ?? 'brainy', extra.to ?? 'ezermester', content, result, T0 + 5, T0 + 9)
  return Number(info.lastInsertRowid)
}

/** A marker row in every source table the page must NEVER read from. */
function seedMarkerRows(): void {
  const db = getDb()
  const cols = (t: string) => (db.prepare(`PRAGMA table_info(${t})`).all() as { name: string }[]).map((c) => c.name)
  db.prepare('INSERT INTO kanban_comments (card_id, author, content, created_at) VALUES (?, ?, ?, ?)').run('4fbbb27c', 'someone', `${MARKER} comment with a quoted mail`, T0)
  db.prepare('INSERT INTO kanban_card_field_events (card_id, field, old_value, new_value, actor, created_at) VALUES (?, ?, ?, ?, ?, ?)').run('4fbbb27c', 'title', `${MARKER} old`, `${MARKER} new`, 'x', T0)
  db.prepare('INSERT INTO memories (chat_id, content, sector, created_at, accessed_at) VALUES (?, ?, ?, ?, ?)').run('c', `${MARKER} memory`, 'semantic', T0, T0)
  db.prepare('INSERT INTO approvals (id, agent_id, category, action_description, action_payload) VALUES (?, ?, ?, ?, ?)').run('ap1', 'brainy', 'email_send', `${MARKER} action`, `${MARKER} payload`)
  db.prepare('INSERT INTO token_usage (agent, session_id, timestamp, content_preview, task_title) VALUES (?, ?, ?, ?, ?)').run('ezermester', 's', T0, `${MARKER} preview`, `${MARKER} title`)
  db.prepare('INSERT INTO tool_call_log (session_id, tool_name, input_summary, created_at) VALUES (?, ?, ?, ?)').run('s', 'Bash', `${MARKER} input`, T0)
  db.prepare("INSERT INTO conversation_log (agent_id, chat_id, direction, message_id, text, created_at) VALUES (?, ?, 'in', ?, ?, ?)").run('brainy', '1', '1', `${MARKER} gyuri says`, T0)
  db.prepare('INSERT INTO daily_logs (agent_id, date, content, created_at) VALUES (?, ?, ?, ?)').run('brainy', '2026-10-27', `${MARKER} diary`, T0)
  // The bus carries free text in more columns than the page reads.
  const msgCols = cols('agent_messages')
  const id = insertMessage('about #' + seq.A + ' and nothing else')
  if (msgCols.includes('origin_note')) db.prepare('UPDATE agent_messages SET origin_note = ? WHERE id = ?').run(`${MARKER} origin`, id)
  // A message that does NOT belong to any function: its text must never surface.
  insertMessage(`${MARKER} unrelated chatter`, `${MARKER} unrelated result`)
}

function writeRegistry(slug: string, over: Record<string, unknown> = {}): void {
  writeFileSync(join(registryDir, `${slug}.json`), JSON.stringify({
    slug,
    nev: `Funkcio ${slug}`,
    leiras: 'Leiras.',
    kartyak: ['4fbbb27c', '6a52389f'],
    tagek: ['FUNKTAG1'],
    repok: [{ nev: 'fixture', ut: repo, pathGlobok: ['src/gate/*.ts'], tesztGlobok: ['src/**/*.test.ts'] }],
    tiltasok: ['Ne kuldj levelet jovahagyas nelkul.'],
    specUtak: ['/tmp/some/spec.md'],
    ...over,
  }))
}

beforeEach(() => {
  initDatabase(':memory:')
  registryDir = mkdtempSync(join(tmpdir(), 'funkciok-page-reg-'))
  repo = makeRepo([
    { at: T0 + 10, msg: 'feat: one (card 4fbbb27c, N1)', files: { 'src/a.ts': '1', 'src/__tests__/a.test.ts': '1' } },
    { at: T0 + 20, msg: 'feat: two (card 6a52389f, N2)', files: { 'src/b.ts': '1' } },
    { at: T0 + 30, msg: 'chore: tagged FUNKTAG1 work', files: { 'docs/x.md': '1' } },
    { at: T0 + 40, msg: 'fix: gate file touched (#2315)', files: { 'src/gate/check.ts': '1', 'src/gate/check.test.ts': '1' } },
    { at: T0 + 50, msg: 'docs: unrelated', files: { 'LICENSE': 'x' } },
    { at: T0 + 60, msg: 'feat: three (card 4fbbb27c)', files: { 'src/__tests__/a.test.ts': '2' } },
  ])
  allowed = new Set([realpathSync(repo)])
  svc = createFunkciokService({ registryDir, getAllowedRepos: () => allowed, git: createGitLogReader() })

  seq = {}
  seq.A = insertCard('4fbbb27c', 'Levelkapu fo kartya', 'in_progress')
  seq.B = insertCard('6a52389f', 'Masodik kartya', 'done')
  seq.child = insertCard('c1c1c1c1', 'Alkartya', 'planned', '4fbbb27c')
  seq.other = insertCard('d0d0d0d0', 'Idegen kartya', 'planned')
  const ev = getDb().prepare("INSERT INTO kanban_card_events (card_id, from_status, to_status, actor, created_at) VALUES (?, ?, ?, ?, ?)")
  ev.run('4fbbb27c', 'planned', 'in_progress', 'ezermester', T0 + 100)
  ev.run('6a52389f', 'in_progress', 'done', 'brainy', T0 + 200)
})

afterEach(() => {
  rmSync(registryDir, { recursive: true, force: true })
  rmSync(repo, { recursive: true, force: true })
})

const keysOf = (o: object) => Object.keys(o).sort()
const sorted = (a: readonly string[]) => [...a].sort()

describe('S1-1: the list', () => {
  it('four valid functions give four items, sorted by slug, with exactly the allowlisted keys', async () => {
    for (const s of ['levelkapu', 'szamlamento-olvasottra-jeloles', 'ajanlat-kor', 'context-guard']) writeRegistry(s)
    const list = await svc.list()
    expect(list.map((i) => i.slug)).toEqual(['ajanlat-kor', 'context-guard', 'levelkapu', 'szamlamento-olvasottra-jeloles'])
    for (const i of list) expect(keysOf(i)).toEqual(sorted(LIST_ITEM_KEYS.filter((k) => k !== 'error')))
    expect(list[0].open_cards).toBe(2) // 4fbbb27c in_progress + its planned child; 6a52389f is done
    expect(list[0].last_change).toBe(T0 + 200) // newest of: matched commits (T0+60), card status events (T0+200)
  })

  it('a broken file is flagged and the other functions still load', async () => {
    writeRegistry('good-one')
    writeFileSync(join(registryDir, 'bad-one.json'), '{ nope')
    const list = await svc.list()
    expect(list.map((i) => i.slug)).toEqual(['bad-one', 'good-one'])
    expect(list[0]).toEqual({ slug: 'bad-one', nev: null, last_change: null, open_cards: null, error: 'invalid JSON' })
    expect(list[1].error).toBeUndefined()
    expect(list[1].nev).toBe('Funkcio good-one')
  })
})

describe('cards block', () => {
  it('registry cards plus their children, with the status events as a timeline', async () => {
    writeRegistry('f')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.cards.map((c) => c.id)).toEqual(['4fbbb27c', 'c1c1c1c1', '6a52389f'])
    const a = r.page.cards[0]
    expect(a.seq).toBe(seq.A)
    expect(a.status).toBe('in_progress')
    expect(a.events).toEqual([{ from_status: 'planned', to_status: 'in_progress', actor: 'ezermester', created_at: T0 + 100 }])
    expect(a.last_status_at).toBe(T0 + 100)
    expect(r.page.cards[1].parent_id).toBe('4fbbb27c')
    expect(r.page.cards[1].last_status_at).toBe(T0) // never moved: falls back to created_at
    expect(r.page.open_cards).toBe(2)
  })

  it('a registry card that does not exist is reported, not invented', async () => {
    writeRegistry('f', { kartyak: ['4fbbb27c', 'deadbeef'] })
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.cards_missing).toEqual(['deadbeef'])
  })
})

describe('S1-2: the commit block', () => {
  it('every commit naming a registry card is there with reason "card"; tag and path commits keep their own reason', async () => {
    writeRegistry('f')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    const bySubject = Object.fromEntries(r.page.commits.map((c) => [c.subject, c]))
    expect(bySubject['feat: one (card 4fbbb27c, N1)'].reason).toBe('card')
    expect(bySubject['feat: two (card 6a52389f, N2)'].reason).toBe('card')
    expect(bySubject['feat: three (card 4fbbb27c)'].reason).toBe('card')
    expect(bySubject['chore: tagged FUNKTAG1 work'].reason).toBe('tag')
    expect(bySubject['fix: gate file touched (#2315)'].reason).toBe('path')
    expect(bySubject['fix: gate file touched (#2315)'].pr).toBe(2315)
    expect(bySubject['docs: unrelated']).toBeUndefined()
    expect(r.page.commits_total).toBe(5)
    // newest first
    expect(r.page.commits[0].subject).toBe('feat: three (card 4fbbb27c)')
    // the tag commit and the path commit carry no "card <hex8>" at all
    expect(r.page.commits_without_card).toBe(2)
    expect(r.page.repos).toEqual([{ nev: 'fixture', error: null, commits: 5 }])
  })

  it('the tests block lists test files of the matched commits, with the last commit that touched them', async () => {
    writeRegistry('f')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    const byPath = Object.fromEntries(r.page.tests.map((t) => [t.path, t]))
    expect(Object.keys(byPath).sort()).toEqual(['src/__tests__/a.test.ts', 'src/gate/check.test.ts'])
    expect(byPath['src/__tests__/a.test.ts'].last_date).toBe(T0 + 60)
    expect(byPath['src/gate/check.test.ts'].last_date).toBe(T0 + 40)
  })
})

describe('S1-3: the inter-agent message block', () => {
  it('matches #<seq> of a registry card (word boundary), the bare hex8 and a registry tag; nothing else', async () => {
    writeRegistry('f')
    const hit1 = insertMessage(`Feladat #${seq.A}: kesz`, 'Kesz.')
    const hit2 = insertMessage(`Masodik: #${seq.B} kesz`)
    const hitHex = insertMessage('regi sor 4fbbb27c hivatkozas')
    const hitTag = insertMessage('FUNKTAG1 modositas')
    const missOther = insertMessage(`masik kartya #${seq.other}`)
    const missPr = insertMessage('PR #1234 merged') // 1234 is not a registry seq
    const missPrefix = insertMessage(`#${seq.A}0 only`) // "#<seq>0" is a different number
    const missGlued = insertMessage('x4fbbb27cx glued hex')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    const ids = r.page.messages.map((m) => m.id)
    expect(ids).toEqual([hitTag, hitHex, hit2, hit1]) // newest first
    for (const miss of [missOther, missPr, missPrefix, missGlued]) expect(ids).not.toContain(miss)
    expect(r.page.messages.find((m) => m.id === hit1)!.reason).toBe('card')
    expect(r.page.messages.find((m) => m.id === hitHex)!.reason).toBe('hex')
    expect(r.page.messages.find((m) => m.id === hitTag)!.reason).toBe('tag')
  })

  it('"#1234" matches when (and only when) 1234 IS a registry card seq', () => {
    expect(messageReason('PR #1234 merged', { seqs: new Set([7]), hex: [], tags: [] })).toBeNull()
    expect(messageReason('PR #1234 merged', { seqs: new Set([1234]), hex: [], tags: [] })).toBe('card')
    expect(messageReason('PR #12345', { seqs: new Set([1234]), hex: [], tags: [] })).toBeNull()
    expect(messageReason('PR #1234abc', { seqs: new Set([1234]), hex: [], tags: [] })).toBeNull()
  })

  it('a tag starting with "-" is a plain string in the match (never an option anywhere)', () => {
    expect(messageReason('use --force carefully', { seqs: new Set(), hex: [], tags: ['--force'] })).toBe('tag')
    expect(messageReason('use force carefully', { seqs: new Set(), hex: [], tags: ['--force'] })).toBeNull()
  })

  it('a tag with SQL wildcards is literal (instr, not LIKE)', async () => {
    writeRegistry('f', { tagek: ['A%B'] })
    const noise = insertMessage('AxxB should not match a percent tag')
    const hit = insertMessage('real A%B tag here')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.messages.map((m) => m.id)).toEqual([hit])
    expect(r.page.messages.map((m) => m.id)).not.toContain(noise)
  })

  it('excerpts are cut to 200 characters AFTER masking; secrets are redacted in content and result', async () => {
    writeRegistry('f')
    const id = insertMessage(`#${seq.A} ${FAKE_SECRET} ${'x'.repeat(500)}`, `result ${FAKE_SECRET} ${'y'.repeat(500)}`)
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    const m = r.page.messages.find((x) => x.id === id)!
    expect(Array.from(m.content_excerpt).length).toBeLessThanOrEqual(MESSAGE_PREVIEW_CHARS)
    expect(Array.from(m.result_excerpt!).length).toBeLessThanOrEqual(MESSAGE_PREVIEW_CHARS)
    expect(m.content_excerpt).toContain('<REDACTED>')
    expect(m.result_excerpt).toContain('<REDACTED>')
    expect(JSON.stringify(r.page)).not.toContain('Q'.repeat(30))
  })

  it('at most 200 rows, newest first', async () => {
    writeRegistry('f')
    const last: number[] = []
    for (let i = 0; i < MESSAGE_MAX_ROWS + 50; i++) last.push(insertMessage(`bulk #${seq.A} n${i}`))
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.messages).toHaveLength(MESSAGE_MAX_ROWS)
    expect(r.page.messages[0].id).toBe(last[last.length - 1])
  })
})

describe('R1-1: subcards count as the function\'s cards', () => {
  it('a message naming a subcard by #seq or hex8, and a commit naming it, are on the page; an unknown #seq is not', async () => {
    const subRepo = makeRepo([
      { at: T0 + 10, msg: 'feat: sub work (card c1c1c1c1, S1)', files: { 'src/s.ts': '1' } },
      { at: T0 + 20, msg: 'feat: foreign (card d0d0d0d0)', files: { 'src/t.ts': '1' } },
    ])
    try {
      allowed.add(realpathSync(subRepo))
      writeRegistry('f', { repok: [{ nev: 'sub', ut: subRepo, pathGlobok: [], tesztGlobok: [] }] })
      const bySeq = insertMessage(`sub done #${seq.child}`)
      const byHex = insertMessage('legacy line c1c1c1c1 done')
      const miss = insertMessage('PR #987654 merged')
      const r = await svc.page('f')
      if (r.kind !== 'ok') throw new Error('expected ok')
      const ids = r.page.messages.map((m) => m.id)
      expect(ids).toContain(bySeq)
      expect(ids).toContain(byHex)
      expect(ids).not.toContain(miss)
      expect(r.page.messages.find((m) => m.id === bySeq)!.reason).toBe('card')
      expect(r.page.commits.map((c) => c.reason)).toEqual(['card'])
      expect(r.page.commits).toHaveLength(1)
      expect((await svc.message('f', bySeq)).kind).toBe('ok')
    } finally {
      rmSync(subRepo, { recursive: true, force: true })
    }
  })
})

describe('R1-4: the D3 endpoint serves only rows of the page', () => {
  it('201 matching messages: the oldest is on no page row, so 404; a listed one is 200', async () => {
    writeRegistry('f')
    const ids: number[] = []
    for (let i = 0; i < MESSAGE_MAX_ROWS + 1; i++) ids.push(insertMessage(`bulk #${seq.A} n${i}`))
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.messages).toHaveLength(MESSAGE_MAX_ROWS)
    expect(r.page.messages.map((m) => m.id)).not.toContain(ids[0])
    expect((await svc.message('f', ids[0])).kind).toBe('not_found')
    expect((await svc.message('f', ids[ids.length - 1])).kind).toBe('ok')
    expect((await svc.message('f', ids[1])).kind).toBe('ok')
  })
})

describe('S1-4: allowlisted keys and the marker in every source table', () => {
  it('response keys are EXACTLY the allowlists, at every level', async () => {
    writeRegistry('f')
    insertMessage(`#${seq.A} hello`, 'ok')
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(keysOf(r.page)).toEqual(sorted(PAGE_KEYS))
    expect(r.page.cards.length).toBeGreaterThan(0)
    for (const c of r.page.cards) {
      expect(keysOf(c)).toEqual(sorted(CARD_KEYS))
      for (const e of c.events) expect(keysOf(e)).toEqual(sorted(CARD_EVENT_KEYS))
    }
    expect(r.page.messages.length).toBeGreaterThan(0)
    for (const m of r.page.messages) expect(keysOf(m)).toEqual(sorted(MESSAGE_ROW_KEYS))
    for (const c of r.page.commits) expect(keysOf(c)).toEqual(sorted(COMMIT_KEYS))
    for (const t of r.page.tests) expect(keysOf(t)).toEqual(sorted(TEST_KEYS))
    for (const p of r.page.repos) expect(keysOf(p)).toEqual(sorted(REPO_KEYS))
  })

  it('a marker row in every source table never shows up in the list, the page or the D3 text', async () => {
    writeRegistry('f')
    seedMarkerRows()
    const list = await svc.list()
    const page = await svc.page('f')
    if (page.kind !== 'ok') throw new Error('expected ok')
    const msgId = insertMessage(`#${seq.A} legit text`, 'legit result')
    const full = await svc.message('f', msgId)
    const dump = JSON.stringify({ list, page, full })
    expect(dump).not.toContain(MARKER)
    // and the forbidden FIELD names do not exist in the response shape
    for (const bad of ['content_preview', 'input_summary', 'action_description', 'action_payload', 'description', 'test_steps', 'comments', 'origin_note']) {
      expect(dump).not.toContain(`"${bad}"`)
    }
  })

  it('card comments are not part of the page: only the card row and its status events are read', async () => {
    writeRegistry('f')
    seedMarkerRows()
    const page = await svc.page('f')
    if (page.kind !== 'ok') throw new Error('expected ok')
    expect(JSON.stringify(page.page.cards)).not.toContain('comment')
  })
})

describe('D3: the full text of one message, only if it is on that function page', () => {
  it('returns the masked full content and result of a message on the page', async () => {
    writeRegistry('f')
    const id = insertMessage(`#${seq.A} ${'z'.repeat(400)} ${FAKE_SECRET}`, `done ${FAKE_SECRET} ${'w'.repeat(300)}`)
    const r = await svc.message('f', id)
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(keysOf(r.message)).toEqual(sorted(MESSAGE_FULL_KEYS))
    expect(r.message.content.length).toBeGreaterThan(MESSAGE_PREVIEW_CHARS) // not cut to the excerpt
    expect(r.message.content).toContain('<REDACTED>')
    expect(r.message.result).toContain('<REDACTED>')
    expect(JSON.stringify(r.message)).not.toContain('Q'.repeat(30))
  })

  it('404 for a message that is not on this function page, a missing id, and another function\'s message', async () => {
    writeRegistry('f')
    writeRegistry('g', { kartyak: ['d0d0d0d0'], tagek: [], repok: [] })
    const foreign = insertMessage(`${MARKER} nothing to do with any card`)
    const ofOther = insertMessage(`about #${seq.other}`)
    const mine = insertMessage(`about #${seq.A}`)
    expect((await svc.message('f', foreign)).kind).toBe('not_found')
    expect((await svc.message('f', ofOther)).kind).toBe('not_found')
    expect((await svc.message('f', 9_999_999)).kind).toBe('not_found')
    expect((await svc.message('g', mine)).kind).toBe('not_found') // belongs to f, not to g
    expect((await svc.message('g', ofOther)).kind).toBe('ok')
    expect((await svc.message('nope', mine)).kind).toBe('not_found')
    expect(JSON.stringify(await svc.message('f', foreign))).not.toContain(MARKER)
  })

  it('an invalid registry file answers "invalid", not a message', async () => {
    writeFileSync(join(registryDir, 'broken.json'), '{ nope')
    const m = insertMessage('whatever')
    expect(await svc.message('broken', m)).toMatchObject({ kind: 'invalid', slug: 'broken' })
  })
})

describe('S1-5: a repo that is not on the allowlist gets no git process', () => {
  function spyService(allow: Set<string>): { s: FunkciokService; exec: ReturnType<typeof vi.fn> } {
    const exec = vi.fn(async () => ({ stdout: '' }))
    const s = createFunkciokService({
      registryDir,
      getAllowedRepos: () => allow,
      git: createGitLogReader({ exec: exec as unknown as ExecFileFn }),
    })
    return { s, exec }
  }

  it('page and list: no execFile call, the repo block carries the error, the rest of the page still works', async () => {
    writeRegistry('f')
    const { s, exec } = spyService(new Set(['/some/other/repo']))
    const r = await s.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(exec).not.toHaveBeenCalled()
    expect(r.page.repos).toEqual([{ nev: 'fixture', error: 'repo_not_allowed', commits: 0 }])
    expect(r.page.commits).toEqual([])
    expect(r.page.tests).toEqual([])
    expect(r.page.cards.length).toBeGreaterThan(0) // the kanban side is unaffected
    await s.list()
    expect(exec).not.toHaveBeenCalled()
  })

  it('a repo path that does not exist is "repo_missing", also without a process', async () => {
    writeRegistry('f', { repok: [{ nev: 'ghost', ut: join(registryDir, 'no-such-repo'), pathGlobok: [], tesztGlobok: [] }] })
    const { s, exec } = spyService(allowed)
    const r = await s.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(exec).not.toHaveBeenCalled()
    expect(r.page.repos[0].error).toBe('repo_missing')
  })

  it('an allowlisted repo does run git exactly once per page, and a git failure is reported, not thrown', async () => {
    writeRegistry('f')
    const { s, exec } = spyService(allowed)
    const ok = await s.page('f')
    if (ok.kind !== 'ok') throw new Error('expected ok')
    expect(exec).toHaveBeenCalledTimes(1)
    expect(ok.page.repos[0].error).toBeNull()

    const failing = createFunkciokService({
      registryDir,
      getAllowedRepos: () => allowed,
      git: createGitLogReader({ exec: (async () => { throw new Error('boom') }) as unknown as ExecFileFn }),
    })
    const bad = await failing.page('f')
    if (bad.kind !== 'ok') throw new Error('expected ok')
    expect(bad.page.repos[0]).toEqual({ nev: 'fixture', error: 'git_failed', commits: 0 })
  })
})

describe('page edge cases', () => {
  it('an unknown slug is not_found, a traversal slug is not_found, an invalid file is "invalid"', async () => {
    writeRegistry('f')
    expect((await svc.page('nope')).kind).toBe('not_found')
    for (const s of ['../f', '..', '%2e%2e', 'F', '']) expect((await svc.page(s)).kind).toBe('not_found')
    writeFileSync(join(registryDir, 'broken.json'), '{ nope')
    expect(await svc.page('broken')).toMatchObject({ kind: 'invalid', slug: 'broken', error: 'invalid JSON' })
  })

  it('tiltasok and specUtak come from the registry as plain strings (paths only, no file content)', async () => {
    writeRegistry('f', { specUtak: [join(registryDir, 'spec-with-marker.md')] })
    writeFileSync(join(registryDir, 'spec-with-marker.md'), `${MARKER} spec body`)
    const r = await svc.page('f')
    if (r.kind !== 'ok') throw new Error('expected ok')
    expect(r.page.tiltasok).toEqual(['Ne kuldj levelet jovahagyas nelkul.'])
    expect(r.page.specUtak).toEqual([join(registryDir, 'spec-with-marker.md')])
    expect(JSON.stringify(r.page)).not.toContain(MARKER)
  })
})
