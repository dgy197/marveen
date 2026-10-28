import { describe, it, expect, beforeEach } from 'vitest'
import { initDatabase, getDb } from '../db.js'
import { maskSecrets } from '../web/agent-transcript.js'
import {
  QUESTION_KEYS, QUESTION_DEFAULT_EXPIRY_S, QUESTION_MAX_CODEPOINTS, QUESTION_MAX_EXPIRY_S, QUESTION_MIN_EXPIRY_S,
  QUESTION_OPEN_PER_AGENT_MAX, createQuestion, listQuestions, validateQuestionInput, type QuestionInput,
} from '../web/open-questions.js'

// Open questions S3-N1 at store level, against an in-memory sqlite: the schema
// and its triggers, the input validation, the per-agent cap, the lazy expiry
// in the view, and the response allowlist (spec 5.4, S3-6).

const MARKER = 'TITOK-MARKER'
const T0 = 1_760_000_000
const keysOf = (o: object) => Object.keys(o).sort()
const sorted = (a: readonly string[]) => [...a].sort()
const ESC = String.fromCodePoint(0x1b)
const RLO = String.fromCodePoint(0x202e)
const BOM = String.fromCodePoint(0xfeff)
const ZWSP = String.fromCodePoint(0x200b)
const NUL = String.fromCodePoint(0)
const DEL = String.fromCodePoint(0x7f)
const LS = String.fromCodePoint(0x2028)
const E_ACUTE = String.fromCodePoint(0xe9)
const EMOJI = String.fromCodePoint(0x1f600)

const base = { agent_id: 'alfa', kind: 'yesno', question_short: 'Mehet a teszt-kiadas?' }

function input(over: Partial<QuestionInput> = {}): QuestionInput {
  return { agent_id: 'alfa', kind: 'yesno', question_short: 'Mehet?', card_id: null, msg_id: null, expires_in_s: QUESTION_DEFAULT_EXPIRY_S, ...over }
}

function insertRaw(over: Record<string, unknown> = {}): number {
  const row = {
    agent_id: 'alfa', card_id: null, msg_id: null, kind: 'yesno', question_short: 'Mehet?', status: 'open',
    answer_short: null, answered_via: null, answered_at: null, answered_by: null, answered_principal: null,
    created_at: T0, expires_at: T0 + 1000, source: 'agent', ...over,
  }
  const cols = Object.keys(row)
  const info = getDb().prepare(`INSERT INTO open_questions (${cols.join(',')}) VALUES (${cols.map(() => '?').join(',')})`).run(...Object.values(row) as never[])
  return Number(info.lastInsertRowid)
}

function insertCard(id: string): void {
  getDb().prepare(`INSERT INTO kanban_cards (id, title, description, test_steps, status, assignee, sort_order, created_at, updated_at)
                   VALUES (?, ?, ?, ?, 'in_progress', 'alfa', 0, ?, ?)`).run(id, `${MARKER} cim`, `${MARKER} leiras`, `${MARKER} lepesek`, T0, T0)
}

function insertMessage(): number {
  return Number(getDb().prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at) VALUES ('alfa', 'beta', ?, 'done', ?)")
    .run(`${MARKER} uzenet`, T0).lastInsertRowid)
}

const count = () => (getDb().prepare('SELECT COUNT(*) AS n FROM open_questions').get() as { n: number }).n

beforeEach(() => { initDatabase(':memory:') })

describe('schema and triggers (blueprint N1)', () => {
  it('the table has exactly the specified columns, and no hash / nonce / payload column (spec 4.1, 5.3)', () => {
    const cols = (getDb().prepare('PRAGMA table_info(open_questions)').all() as { name: string }[]).map((c) => c.name)
    expect(sorted(cols)).toEqual(sorted([
      'id', 'agent_id', 'card_id', 'msg_id', 'kind', 'question_short', 'status', 'answer_short', 'answered_via',
      'answered_at', 'answered_by', 'answered_principal', 'created_at', 'expires_at', 'source',
    ]))
    expect(cols.filter((c) => /hash|nonce|payload/.test(c))).toEqual([])
  })

  it('the index and both triggers exist', () => {
    const names = (getDb().prepare("SELECT name FROM sqlite_master WHERE tbl_name = 'open_questions'").all() as { name: string }[]).map((r) => r.name)
    expect(names).toContain('idx_open_questions_status_agent')
    expect(names).toContain('open_questions_guard_update')
    expect(names).toContain('open_questions_no_delete')
  })

  it.each([
    ['kind', { kind: 'maybe' }],
    ['status', { status: 'closed' }],
    ['source', { source: 'human' }],
    ['question_short empty', { question_short: '' }],
    ['question_short 401 characters', { question_short: 'x'.repeat(401) }],
    ['answer_short 1001 characters', { status: 'answered', answered_via: 'ui', answered_at: T0, answer_short: 'x'.repeat(1001) }],
    ['answered_via', { status: 'yes', answered_via: 'sms', answered_at: T0 }],
    ['answered_principal', { status: 'yes', answered_via: 'ui', answered_at: T0, answered_principal: 'token' }],
    ['expires_at not after created_at', { expires_at: T0 }],
    ['an open row that already has an answer', { answer_short: 'igen' }],
    ['an answered row without answered_at', { status: 'yes', answered_via: 'ui' }],
    ['an answered row without answered_via', { status: 'yes', answered_at: T0 }],
  ])('CHECK refuses: %s', (_name, over) => {
    expect(() => insertRaw(over)).toThrow()
    expect(count()).toBe(0)
  })

  it('CHECK accepts the boundaries: 400 characters, answer 1000 characters', () => {
    expect(() => insertRaw({ question_short: 'x'.repeat(400) })).not.toThrow()
    expect(() => insertRaw({ status: 'answered', answered_via: 'ui', answered_at: T0, answer_short: 'y'.repeat(1000), answered_principal: 'session' })).not.toThrow()
  })

  it('an open row can be answered once; the answer columns are the only ones that change', () => {
    const id = insertRaw()
    getDb().prepare("UPDATE open_questions SET status = 'yes', answered_via = 'ui', answered_at = ?, answered_by = 'session:tulaj-teszt', answered_principal = 'session' WHERE id = ?").run(T0 + 5, id)
    const row = getDb().prepare('SELECT status, answered_by, answered_principal FROM open_questions WHERE id = ?').get(id)
    expect(row).toEqual({ status: 'yes', answered_by: 'session:tulaj-teszt', answered_principal: 'session' })
  })

  it('an answered row cannot change again (any column)', () => {
    const id = insertRaw({ status: 'yes', answered_via: 'ui', answered_at: T0 + 5 })
    expect(() => getDb().prepare("UPDATE open_questions SET status = 'no' WHERE id = ?").run(id)).toThrow(/only an open question/)
    expect(() => getDb().prepare("UPDATE open_questions SET answer_short = 'x' WHERE id = ?").run(id)).toThrow(/only an open question/)
    expect((getDb().prepare('SELECT status FROM open_questions WHERE id = ?').get(id) as { status: string }).status).toBe('yes')
  })

  it.each([
    ['question_short', "question_short = 'masik'"],
    ['agent_id', "agent_id = 'beta'"],
    ['kind', "kind = 'free'"],
    ['card_id', "card_id = '0a0b0c0d'"],
    ['msg_id', 'msg_id = 5'],
    ['created_at', 'created_at = 1'],
    ['expires_at', 'expires_at = expires_at + 100000'],
    ['source', "source = 'extractor'"],
    ['id', 'id = id + 100'],
  ])('an open row\'s %s is immutable (trigger ABORT)', (_name, set) => {
    const id = insertRaw()
    expect(() => getDb().prepare(`UPDATE open_questions SET ${set} WHERE id = ?`).run(id)).toThrow(/only an open question/)
    const row = getDb().prepare('SELECT question_short, agent_id, kind, source FROM open_questions WHERE id = ?').get(id)
    expect(row).toEqual({ question_short: 'Mehet?', agent_id: 'alfa', kind: 'yesno', source: 'agent' })
  })

  it('DELETE aborts, open or answered', () => {
    const a = insertRaw()
    const b = insertRaw({ status: 'no', answered_via: 'ui', answered_at: T0 })
    expect(() => getDb().prepare('DELETE FROM open_questions WHERE id = ?').run(a)).toThrow(/never deleted/)
    expect(() => getDb().prepare('DELETE FROM open_questions WHERE id = ?').run(b)).toThrow(/never deleted/)
    expect(() => getDb().prepare('DELETE FROM open_questions').run()).toThrow(/never deleted/)
    expect(count()).toBe(2)
  })
})

describe('validateQuestionInput (every field)', () => {
  const ok = (o: unknown) => validateQuestionInput(o)
  const err = (o: unknown) => { const r = validateQuestionInput(o); return r.ok ? null : r.error }

  it('a minimal body is valid and gets the 7-day default expiry', () => {
    const r = ok(base)
    expect(r.ok && r.value).toEqual({ agent_id: 'alfa', kind: 'yesno', question_short: 'Mehet a teszt-kiadas?', card_id: null, msg_id: null, expires_in_s: 7 * 24 * 3600 })
  })

  it('the body must be a JSON object', () => {
    for (const raw of [null, 'x', 5, [], [base]]) expect(err(raw)).toMatch(/JSON object/)
  })

  it('unknown fields are refused, so source / status / answer_short / id cannot be set from the body', () => {
    for (const k of ['source', 'status', 'answer_short', 'answered_by', 'id', 'created_at', 'expires_at', 'answered_via']) {
      expect(err({ ...base, [k]: 'extractor' })).toMatch(/Unknown field/)
    }
  })

  it('agent_id: required, a string of the fleet-id shape', () => {
    expect(err({ kind: 'info', question_short: 'x' })).toMatch(/agent_id/)
    for (const v of [5, null, '', 'Alfa', '../x', 'a b', 'x'.repeat(65), '-a']) expect(err({ ...base, agent_id: v })).toMatch(/agent_id/)
  })

  it('kind: info, yesno, free only', () => {
    for (const k of ['info', 'yesno', 'free']) expect(ok({ ...base, kind: k }).ok).toBe(true)
    for (const v of [undefined, 'maybe', 'INFO', 3, null]) expect(err({ ...base, kind: v })).toMatch(/kind/)
  })

  it('question_short: required string, trimmed, 1..400 code points (astral characters count once)', () => {
    expect(err({ ...base, question_short: undefined })).toMatch(/required/)
    expect(err({ ...base, question_short: 7 })).toMatch(/required/)
    expect(err({ ...base, question_short: '' })).toMatch(/empty/)
    expect(err({ ...base, question_short: '  \n ' })).toMatch(/empty/)
    expect(ok({ ...base, question_short: 'x'.repeat(QUESTION_MAX_CODEPOINTS) }).ok).toBe(true)
    expect(err({ ...base, question_short: 'x'.repeat(QUESTION_MAX_CODEPOINTS + 1) })).toMatch(/longer than 400/)
    expect(ok({ ...base, question_short: EMOJI.repeat(400) }).ok).toBe(true)
    expect(err({ ...base, question_short: EMOJI.repeat(401) })).toMatch(/longer than 400/)
    const r = ok({ ...base, question_short: `  K${E_ACUTE}rd${E_ACUTE}s \r\n masodik sor  ` })
    expect(r.ok && r.value.question_short).toBe(`K${E_ACUTE}rd${E_ACUTE}s \n masodik sor`)
  })

  it('question_short: control, invisible and direction-override characters are refused (the S2 shared check)', () => {
    for (const ch of [NUL, ESC, DEL, RLO, BOM, ZWSP, LS, String.fromCodePoint(0x0d + 0x80)]) {
      expect(err({ ...base, question_short: `elo${ch}utan` })).toMatch(/control, invisible/)
    }
    // a newline is allowed
    expect(ok({ ...base, question_short: 'egy\nketto' }).ok).toBe(true)
  })

  it('question_short: a secret-shaped string is refused', () => {
    const secret = `token=${'Q'.repeat(30)}`
    expect(maskSecrets(secret)).not.toBe(secret) // precondition: the masker treats this shape as a secret
    expect(err({ ...base, question_short: `${MARKER} ${secret}` })).toMatch(/secret-shaped/)
  })

  it('card_id: 8 lowercase hex characters or absent', () => {
    expect(ok({ ...base, card_id: '0a0b0c0d' }).ok).toBe(true)
    expect(ok({ ...base, card_id: null }).ok).toBe(true)
    for (const v of ['0A0B0C0D', '0a0b0c0', '0a0b0c0d1', 'zzzzzzzz', 12345678, '']) expect(err({ ...base, card_id: v })).toMatch(/card_id/)
  })

  it('msg_id: a positive safe integer or absent', () => {
    expect(ok({ ...base, msg_id: 1 }).ok).toBe(true)
    for (const v of [0, -1, 1.5, '3', Number.MAX_SAFE_INTEGER + 2]) expect(err({ ...base, msg_id: v })).toMatch(/msg_id/)
  })

  it('expires_in_s: integer, 300..30 days; 299 and 30 days + 1 s are refused', () => {
    const exp = (v: unknown) => { const r = ok({ ...base, expires_in_s: v }); return r.ok ? r.value.expires_in_s : r.error }
    expect(exp(QUESTION_MIN_EXPIRY_S)).toBe(300)
    expect(exp(QUESTION_MAX_EXPIRY_S)).toBe(30 * 24 * 3600)
    expect(exp(QUESTION_MIN_EXPIRY_S - 1)).toMatch(/between 300 and/)
    expect(exp(QUESTION_MAX_EXPIRY_S + 1)).toMatch(/between 300 and/)
    for (const v of [1.5, '600', NaN, Infinity, 0, -5]) expect(String(exp(v))).toMatch(/expires_in_s/)
  })
})

describe('createQuestion and listQuestions', () => {
  it('a created question has source agent, status open, expiry = now + expires_in_s, and exactly the allowlisted keys (S3-6, 5.4)', () => {
    const r = createQuestion(input({ expires_in_s: 600 }), T0)
    if (r.kind !== 'ok') throw new Error(JSON.stringify(r))
    expect(keysOf(r.question)).toEqual(sorted(QUESTION_KEYS))
    expect(r.question).toMatchObject({
      agent_id: 'alfa', kind: 'yesno', question_short: 'Mehet?', status: 'open', source: 'agent',
      answer_short: null, answered_via: null, answered_at: null, created_at: T0, expires_at: T0 + 600,
    })
    const listed = listQuestions('open', T0 + 1)
    expect(listed).toHaveLength(1)
    expect(keysOf(listed[0])).toEqual(sorted(QUESTION_KEYS))
  })

  it('an answered row is serialized with the answer, still only the allowlisted keys; answered_by / answered_principal never leave', () => {
    insertRaw({ status: 'answered', kind: 'free', answer_short: 'igen, de holnap', answered_via: 'ui', answered_at: T0 + 9, answered_by: `session:${MARKER}`, answered_principal: 'session' })
    const [q] = listQuestions('all', T0 + 10)
    expect(q.answer_short).toBe('igen, de holnap')
    expect(keysOf(q)).toEqual(sorted(QUESTION_KEYS))
    expect(JSON.stringify(q)).not.toContain(MARKER)
  })

  it('card_id and msg_id must exist, else unprocessable; nothing is written', () => {
    expect(createQuestion(input({ card_id: '0a0b0c0d' }), T0)).toMatchObject({ kind: 'unprocessable', error: expect.stringMatching(/card_id/) })
    expect(createQuestion(input({ msg_id: 99 }), T0)).toMatchObject({ kind: 'unprocessable', error: expect.stringMatching(/msg_id/) })
    expect(count()).toBe(0)
    insertCard('0a0b0c0d')
    const m = insertMessage()
    const r = createQuestion(input({ card_id: '0a0b0c0d', msg_id: m }), T0)
    expect(r.kind).toBe('ok')
    expect(JSON.stringify(r)).not.toContain(MARKER) // the card title / description and the message text never come along
  })

  it('20 open questions per agent are fine, the 21st is too_many; another agent is unaffected', () => {
    for (let i = 0; i < QUESTION_OPEN_PER_AGENT_MAX; i++) expect(createQuestion(input({ question_short: `k${i}` }), T0).kind).toBe('ok')
    const r = createQuestion(input({ question_short: 'huszonegyedik' }), T0)
    expect(r.kind).toBe('too_many')
    expect(count()).toBe(20)
    expect(createQuestion(input({ agent_id: 'beta' }), T0).kind).toBe('ok')
  })

  it('answered and expired questions do not count against the cap', () => {
    for (let i = 0; i < 19; i++) createQuestion(input({ question_short: `k${i}` }), T0)
    insertRaw({ status: 'yes', answered_via: 'ui', answered_at: T0, created_at: T0, expires_at: T0 + 99999 })
    expect(createQuestion(input(), T0).kind).toBe('ok') // 20th open
    expect(createQuestion(input(), T0).kind).toBe('too_many')
    // a week later all of them are expired: the agent may ask again
    expect(createQuestion(input(), T0 + QUESTION_DEFAULT_EXPIRY_S + 1).kind).toBe('ok')
  })

  it('filters: open (default), answered, expired, all; newest first; lazy expiry shows as expired while the stored status stays open', () => {
    const live = insertRaw({ question_short: 'elo', created_at: T0, expires_at: T0 + 1000 })
    const old = insertRaw({ question_short: 'lejart', created_at: T0 - 50, expires_at: T0 + 10 })
    const done = insertRaw({ question_short: 'valaszolt', status: 'no', answered_via: 'ui', answered_at: T0 + 2, created_at: T0 + 1, expires_at: T0 + 1000 })
    const now = T0 + 100

    expect(listQuestions('open', now).map((q) => q.id)).toEqual([live])
    expect(listQuestions('answered', now).map((q) => q.id)).toEqual([done])
    const expired = listQuestions('expired', now)
    expect(expired.map((q) => q.id)).toEqual([old])
    expect(expired[0].status).toBe('expired')
    const all = listQuestions('all', now)
    expect(all.map((q) => q.id)).toEqual([done, live, old])
    expect(all.map((q) => q.status)).toEqual(['no', 'open', 'expired'])

    // lazy: nothing was written
    expect((getDb().prepare('SELECT status FROM open_questions WHERE id = ?').get(old) as { status: string }).status).toBe('open')
    // the boundary: expires_at <= now is expired
    expect(listQuestions('open', T0 + 1000).map((q) => q.id)).toEqual([])
    expect(listQuestions('open', T0 + 999).map((q) => q.id)).toEqual([live])
  })

  it('the list is capped at 200 rows', () => {
    const db = getDb()
    const ins = db.prepare("INSERT INTO open_questions (agent_id, kind, question_short, created_at, expires_at, source) VALUES ('alfa', 'info', 'x', ?, ?, 'agent')")
    db.transaction(() => { for (let i = 0; i < 230; i++) ins.run(T0 + i, T0 + 5000) })()
    const rows = listQuestions('all', T0 + 1)
    expect(rows).toHaveLength(200)
    expect(rows[0].created_at).toBeGreaterThan(rows[199].created_at)
  })

  it('question_short is masked on the way out even if a secret-shaped text is already in the table (S3-6)', () => {
    const secret = `token=${'Q'.repeat(30)}`
    insertRaw({ question_short: `${MARKER} szia ${secret}`, expires_at: T0 + 5000 })
    const [q] = listQuestions('open', T0 + 1)
    expect(q.question_short).not.toContain('Q'.repeat(30))
    expect(q.question_short).toContain('<REDACTED>')
  })
})
