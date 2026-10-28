import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Readable } from 'node:stream'
import { initDatabase, getDb } from '../db.js'
import { maskSecrets } from '../web/agent-transcript.js'
import {
  DECISION_KEYS, QUOTE_MAX_CODEPOINTS, decisionActor, validateDecisionInput, type DecisionActor,
} from '../web/funkciok-decisions.js'
import { PAGE_KEYS, createFunkciokService, type FunkciokService } from '../web/funkciok-page.js'
import { createGitLogReader } from '../web/funkciok-git.js'
import { setFunkciokServiceForTest, tryHandleFunkciok } from '../web/routes/funkciok.js'
import type { RouteContext } from '../web/routes/types.js'

// Function page S2-A: the append-only decision log against an in-memory sqlite
// and a temp registry. Acceptance S2-1 (no source -> 400), S2-2 (source check),
// S2-3 (append-only, correction by a new row), spec 5.1 (write rights),
// 5.4 (allowlisted keys, marker).

const MARKER = 'TITOK-MARKER'
const T0 = 1_760_000_000
const NOW = T0 + 1000
const OWNER = '555'

const TOKEN: DecisionActor = { via: 'token', by: 'agent-b' }
const keysOf = (o: object) => Object.keys(o).sort()
const sorted = (a: readonly string[]) => [...a].sort()
const E_ACUTE = String.fromCharCode(0xe9)
const EMOJI = String.fromCodePoint(0x1f600)

let registryDir: string
let svc: FunkciokService

function writeRegistry(slug: string): void {
  writeFileSync(join(registryDir, `${slug}.json`), JSON.stringify({
    slug, nev: `Funkcio ${slug}`, leiras: 'Leiras.', kartyak: ['3333aaaa'], tagek: ['FUNKTAG1'], repok: [], tiltasok: [], specUtak: [],
  }))
}

function inbound(chat: string, messageId: string, text = 'mallory szavai', direction: 'in' | 'out' = 'in'): void {
  getDb().prepare('INSERT INTO conversation_log (agent_id, chat_id, direction, message_id, text, created_at) VALUES (?, ?, ?, ?, ?, ?)')
    .run('agent-a', chat, direction, messageId, text, T0)
}

function busMessage(): number {
  return Number(getDb().prepare("INSERT INTO agent_messages (from_agent, to_agent, content, status, created_at) VALUES ('agent-a', 'agent-b', 'x', 'done', ?)").run(T0).lastInsertRowid)
}

const rec = (body: unknown, actor: DecisionActor = TOKEN, slug = 'f') =>
  svc.recordDecision(slug, typeof body === 'string' ? body : JSON.stringify(body), actor)

async function recOk(body: Record<string, unknown>, actor: DecisionActor = TOKEN, slug = 'f') {
  const r = await rec(body, actor, slug)
  if (r.kind !== 'ok') throw new Error(`expected ok, got ${JSON.stringify(r)}`)
  return r.decision
}

const count = () => (getDb().prepare('SELECT COUNT(*) AS n FROM function_decisions').get() as { n: number }).n

beforeEach(() => {
  initDatabase(':memory:')
  registryDir = mkdtempSync(join(tmpdir(), 'funkciok-dec-reg-'))
  writeRegistry('f')
  writeRegistry('g')
  svc = createFunkciokService({
    registryDir, getAllowedRepos: () => new Set(), git: createGitLogReader(),
    ownerChat: () => OWNER, now: () => NOW * 1000,
  })
})
afterEach(() => {
  setFunkciokServiceForTest(null)
  rmSync(registryDir, { recursive: true, force: true })
})

describe('S2-1: input validation', () => {
  it('no source (neither tg_msg_id nor msg_id) is a 400-class refusal and writes nothing', async () => {
    const r = await rec({ quote_short: 'igen' })
    expect(r.kind).toBe('bad_request')
    expect(count()).toBe(0)
  })

  it('quote_short: 280 code points are accepted (accented and emoji), 281 are refused and never truncated', async () => {
    expect((await recOk({ quote_short: E_ACUTE.repeat(QUOTE_MAX_CODEPOINTS), tg_msg_id: '1' })).quote_short).toHaveLength(QUOTE_MAX_CODEPOINTS)
    const emoji = await recOk({ quote_short: EMOJI.repeat(QUOTE_MAX_CODEPOINTS), tg_msg_id: '2' })
    expect(Array.from(emoji.quote_short)).toHaveLength(QUOTE_MAX_CODEPOINTS)
    expect(count()).toBe(2)
    for (const q of [E_ACUTE.repeat(QUOTE_MAX_CODEPOINTS + 1), EMOJI.repeat(QUOTE_MAX_CODEPOINTS + 1)]) {
      expect((await rec({ quote_short: q, tg_msg_id: '3' })).kind).toBe('bad_request')
    }
    expect(count()).toBe(2) // nothing was stored cut short
  })

  it('quote_short: empty, blank, non-string, control characters, direction overrides and secrets are refused; a newline is fine', async () => {
    const base = { tg_msg_id: '1' }
    const withChar = (cp: number) => `a${String.fromCodePoint(cp)}b`
    for (const q of ['', '   ', 5, null, ...[0x00, 0x1b, 0x85, 0x202e, 0x2028, 0xfeff].map(withChar)]) {
      expect((await rec({ ...base, quote_short: q })).kind, JSON.stringify(q)).toBe('bad_request')
    }
    const secret = `token=${'Q'.repeat(30)}`
    expect(maskSecrets(secret)).not.toBe(secret) // precondition: this shape IS a secret to the masker
    expect((await rec({ ...base, quote_short: `szia ${secret}` })).kind).toBe('bad_request')
    expect((await recOk({ ...base, quote_short: 'elso sor\nmasodik sor' })).quote_short).toBe('elso sor\nmasodik sor')
    expect(count()).toBe(1)
  })

  it('S2-M2: Unicode tag characters and invisible format characters are refused', async () => {
    const withChar = (cp: number) => `a${String.fromCodePoint(cp)}b`
    const cps = [0xe0000, 0xe0041, 0xe007f, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x061c, 0x2060, 0x2064]
    for (const cp of cps) {
      expect((await rec({ tg_msg_id: '1', quote_short: withChar(cp) })).kind, cp.toString(16)).toBe('bad_request')
    }
    expect(count()).toBe(0)
  })

  it('S2-B1: variation selectors, soft hyphen and the other default-ignorable code points are refused; Hungarian text passes', async () => {
    const withChar = (cp: number) => `a${String.fromCodePoint(cp)}b`
    const cps = [
      0x00ad, 0x034f, 0x115f, 0x180e, 0x2065, 0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f, 0x3164, 0xfff9, 0xfffa, 0xfffb, 0x1d173,
      0xfe00, 0xfe08, 0xfe0f, 0xe0100, 0xe01ef,
    ]
    for (const cp of cps) {
      expect((await rec({ tg_msg_id: '1', quote_short: withChar(cp) })).kind, cp.toString(16)).toBe('bad_request')
    }
    // "merge main" hidden behind a visible "Rendben" as variation selectors (U+E0100 + byte value)
    const hidden = Array.from('merge main').map((ch) => String.fromCodePoint(0xe0100 + ((ch.codePointAt(0) as number) - 0x20))).join('')
    expect((await rec({ tg_msg_id: '1', quote_short: `Rendben${hidden}` })).kind).toBe('bad_request')
    const hiddenBmp = Array.from('merge main').map((ch) => String.fromCodePoint(0xfe00 + ((ch.codePointAt(0) as number) % 16))).join('')
    expect((await rec({ tg_msg_id: '1', quote_short: `Rendben${hiddenBmp}` })).kind).toBe('bad_request')
    expect(count()).toBe(0)
    const hu = 'Árvíztűrő tükörfúrógép: áéíóöőúüű, "igen" (rendben) - 5/6; ok?'
    expect((await recOk({ tg_msg_id: '1', quote_short: hu })).quote_short).toBe(hu)
  })

  it('an unknown or forged key is refused (recorded_by / recorded_via / created_at / id cannot be sent)', async () => {
    for (const extra of [{ recorded_by: 'mallory' }, { recorded_via: 'session' }, { created_at: 1 }, { id: 9 }, { source_found: 1 }, { __proto__x: 1 }]) {
      const r = await rec(JSON.stringify({ quote_short: 'igen', tg_msg_id: '1', ...extra }))
      expect(r.kind, JSON.stringify(extra)).toBe('bad_request')
    }
    expect(count()).toBe(0)
  })

  it('body shape: invalid JSON, array, scalar, null and an oversize body are refused', async () => {
    for (const b of ['{nope', '[]', '5', 'null', '"x"', '']) expect((await rec(b)).kind, b).toBe('bad_request')
    const big = JSON.stringify({ quote_short: 'igen', tg_msg_id: '1', card_id: 'a'.repeat(20_000) })
    expect((await rec(big)).kind).toBe('bad_request')
    expect(count()).toBe(0)
  })

  it('ids: tg_msg_id digits only (a JSON number is accepted as its string), tg_chat integer, card_id hex8, msg_id positive int', async () => {
    expect((await recOk({ quote_short: 'igen', tg_msg_id: 3725 })).tg_msg_id).toBe('3725')
    for (const bad of [{ tg_msg_id: 'abc' }, { tg_msg_id: '1 OR 1=1' }, { tg_msg_id: '1'.repeat(21) }, { tg_msg_id: -4 }, { tg_msg_id: 1.5 }]) {
      expect((await rec({ quote_short: 'igen', ...bad })).kind, JSON.stringify(bad)).toBe('bad_request')
    }
    expect((await rec({ quote_short: 'igen', tg_msg_id: '1', tg_chat: 'x' })).kind).toBe('bad_request')
    expect((await rec({ quote_short: 'igen', tg_chat: '555', msg_id: 1 })).kind).toBe('bad_request') // chat without a tg message
    expect((await rec({ quote_short: 'igen', tg_msg_id: '1', card_id: 'XYZ' })).kind).toBe('bad_request')
    expect((await rec({ quote_short: 'igen', tg_msg_id: '1', card_id: '3333AAAA' })).kind).toBe('bad_request')
    for (const m of [0, -1, 1.5, '3', true]) expect((await rec({ quote_short: 'igen', msg_id: m })).kind, String(m)).toBe('bad_request')
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '9', tg_chat: '-100123', card_id: '3333aaaa' })).card_id).toBe('3333aaaa')
  })

  it('decided_at: unix seconds, not before 2020, not in the future; the default is the server clock', async () => {
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '1' })).decided_at).toBe(NOW)
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '2', decided_at: T0 })).decided_at).toBe(T0)
    for (const d of [NOW + 3600, 1_000_000, 'x', 1.5, NOW * 1000]) {
      expect((await rec({ quote_short: 'igen', tg_msg_id: '3', decided_at: d })).kind, String(d)).toBe('bad_request')
    }
  })

  it('msg_id must exist on the bus: a missing one is 422-class, an existing one is stored', async () => {
    const r = await rec({ quote_short: 'igen', msg_id: 424242 })
    expect(r.kind).toBe('unprocessable')
    expect(count()).toBe(0)
    const id = busMessage()
    const d = await recOk({ quote_short: 'igen', msg_id: id })
    expect(d.msg_id).toBe(id)
    expect(d.source_status).toBe('none') // a bus message has no Telegram source to check
  })

  it('an unknown slug is not_found before the body is even parsed', async () => {
    expect((await svc.recordDecision('nincs-ilyen', '{garbage', TOKEN)).kind).toBe('not_found')
    expect((await svc.decisions('nincs-ilyen')).kind).toBe('not_found')
    expect(count()).toBe(0)
  })

  it('validateDecisionInput is pure and exported for the backfill file check', () => {
    const ok = validateDecisionInput({ quote_short: ' igen ', tg_msg_id: '5' }, NOW)
    expect(ok).toEqual({ ok: true, value: { quote_short: 'igen', tg_chat: null, tg_msg_id: '5', msg_id: null, card_id: null, decided_at: null, supersedes: null } })
  })
})

describe('S2-2: the source check (found / not found, never the text)', () => {
  it('an inbound row of the owner chat is verified; none is not_found; an outbound row is not_found', async () => {
    inbound(OWNER, '100')
    inbound(OWNER, '200', 'out text', 'out')
    const a = await recOk({ quote_short: 'igen', tg_msg_id: '100' })
    expect(a.source_status).toBe('verified')
    expect(a.tg_chat).toBe(OWNER) // defaulted to the owner chat
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '101' })).source_status).toBe('not_found')
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '200' })).source_status).toBe('not_found')
    const list = await svc.decisions('f')
    if (list.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions.map((d) => d.source_status).sort()).toEqual(['not_found', 'not_found', 'verified'])
  })

  it('only the owner chat is looked up: the same message id in another chat is not_found', async () => {
    inbound('999', '300')
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '300', tg_chat: '999' })).source_status).toBe('not_found')
    expect((await recOk({ quote_short: 'igen', tg_msg_id: '300' })).source_status).toBe('not_found') // owner chat has no 300
  })

  it('without an owner chat and without tg_chat the write is refused; with tg_chat it is stored as not_found', async () => {
    const noOwner = createFunkciokService({ registryDir, getAllowedRepos: () => new Set(), git: createGitLogReader(), ownerChat: () => null, now: () => NOW * 1000 })
    expect((await noOwner.recordDecision('f', JSON.stringify({ quote_short: 'igen', tg_msg_id: '1' }), TOKEN)).kind).toBe('bad_request')
    const r = await noOwner.recordDecision('f', JSON.stringify({ quote_short: 'igen', tg_msg_id: '1', tg_chat: '555' }), TOKEN)
    expect(r.kind === 'ok' && r.decision.source_status).toBe('not_found')
  })

  it('B2: the result at write time is kept, so a later retention purge reads verified_at_record, not not_found', async () => {
    inbound(OWNER, '100')
    const d = await recOk({ quote_short: 'igen', tg_msg_id: '100' })
    expect(d.source_status).toBe('verified')
    getDb().prepare('DELETE FROM conversation_log').run() // the conversation_log retention purge
    const list = await svc.decisions('f')
    if (list.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions[0].source_status).toBe('verified_at_record')
    const row = getDb().prepare('SELECT source_found, source_checked_at FROM function_decisions WHERE id = ?').get(d.id) as { source_found: number; source_checked_at: number }
    expect(row).toEqual({ source_found: 1, source_checked_at: NOW })
  })

  it('a source that was missing at write time turns verified once the message shows up', async () => {
    const d = await recOk({ quote_short: 'igen', tg_msg_id: '700' })
    expect(d.source_status).toBe('not_found')
    inbound(OWNER, '700')
    const list = await svc.decisions('f')
    if (list.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions[0].source_status).toBe('verified')
  })

  it('the conversation_log text never leaves: marker in the text, absent from the write answer, the list and the page', async () => {
    inbound(OWNER, '100', `${MARKER} mallory titkos uzenete`)
    inbound(OWNER, '101', `${MARKER} masik`)
    const written = await rec({ quote_short: 'igen', tg_msg_id: '100' })
    await recOk({ quote_short: 'nem', tg_msg_id: '101' })
    const list = await svc.decisions('f')
    const page = await svc.page('f')
    for (const out of [written, list, page]) expect(JSON.stringify(out)).not.toContain(MARKER)
  })
})

describe('S2-3: append-only, a correction is a new row', () => {
  it('UPDATE and DELETE abort at the database level and leave the row intact', async () => {
    const d = await recOk({ quote_short: 'igen', tg_msg_id: '1' })
    const db = getDb()
    expect(() => db.prepare("UPDATE function_decisions SET quote_short = 'mas' WHERE id = ?").run(d.id)).toThrow(/append-only/)
    expect(() => db.prepare('DELETE FROM function_decisions WHERE id = ?').run(d.id)).toThrow(/append-only/)
    expect((db.prepare('SELECT quote_short FROM function_decisions WHERE id = ?').get(d.id) as { quote_short: string }).quote_short).toBe('igen')
  })

  it('the table itself refuses what the writer would: 281 characters, no source, a foreign recorded_via, a second correction of one row', async () => {
    const d = await recOk({ quote_short: 'igen', tg_msg_id: '1' })
    const ins = (over: Record<string, unknown>) => {
      const v = { quote_short: 'x', tg_msg_id: '1', msg_id: null, recorded_via: 'token', supersedes: null, ...over }
      getDb().prepare(`INSERT INTO function_decisions (slug, quote_short, tg_msg_id, msg_id, decided_at, recorded_by, recorded_via, supersedes, created_at)
        VALUES ('f', ?, ?, ?, ?, 'x', ?, ?, ?)`).run(v.quote_short, v.tg_msg_id, v.msg_id, T0, v.recorded_via, v.supersedes, T0)
    }
    expect(() => ins({ quote_short: 'x'.repeat(281) })).toThrow()
    expect(() => ins({ tg_msg_id: null, msg_id: null })).toThrow()
    expect(() => ins({ recorded_via: 'agent' })).toThrow()
    ins({ supersedes: d.id })
    expect(() => ins({ supersedes: d.id })).toThrow(/UNIQUE/)
  })

  it('a correction: the list shows both with superseded_by set, the page shows only the newer row', async () => {
    const old = await recOk({ quote_short: 'regi dontes', tg_msg_id: '1' })
    const fix = await recOk({ quote_short: 'javitott dontes', tg_msg_id: '2', supersedes: old.id })
    expect(fix.supersedes).toBe(old.id)
    expect(fix.superseded_by).toBeNull()
    const list = await svc.decisions('f')
    if (list.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions.map((d) => d.id)).toEqual([fix.id, old.id]) // newest first
    expect(list.decisions.find((d) => d.id === old.id)?.superseded_by).toBe(fix.id)
    const page = await svc.page('f')
    if (page.kind !== 'ok') throw new Error('expected ok')
    expect(page.page.decisions.map((d) => d.id)).toEqual([fix.id])
  })

  it('a correction must point at an existing, uncorrected row of the SAME slug (409-class otherwise)', async () => {
    const old = await recOk({ quote_short: 'regi', tg_msg_id: '1' })
    await recOk({ quote_short: 'javitas', tg_msg_id: '2', supersedes: old.id })
    expect((await rec({ quote_short: 'masodik javitas', tg_msg_id: '3', supersedes: old.id })).kind).toBe('conflict') // already corrected
    expect((await rec({ quote_short: 'mas funkcio', tg_msg_id: '4', supersedes: old.id }, TOKEN, 'g')).kind).toBe('conflict') // other slug
    expect((await rec({ quote_short: 'nincs ilyen', tg_msg_id: '5', supersedes: 99999 })).kind).toBe('conflict') // missing row
    expect(count()).toBe(2)
  })

  it('the list is capped at 500 rows and the page at 50, newest first', async () => {
    const ins = getDb().prepare(`INSERT INTO function_decisions (slug, quote_short, tg_msg_id, decided_at, recorded_by, recorded_via, created_at)
      VALUES ('f', ?, ?, ?, 'x', 'token', ?)`)
    getDb().transaction(() => { for (let i = 1; i <= 520; i++) ins.run(`d${i}`, String(i), T0 + i, T0 + i) })()
    const list = await svc.decisions('f')
    const page = await svc.page('f')
    if (list.kind !== 'ok' || page.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions).toHaveLength(500)
    expect(list.decisions[0].quote_short).toBe('d520')
    expect(page.page.decisions).toHaveLength(50)
    expect(page.page.decisions[0].quote_short).toBe('d520')
  })

  it('the decisions of one function never show up on another', async () => {
    await recOk({ quote_short: 'f-es', tg_msg_id: '1' })
    const g = await svc.decisions('g')
    expect(g.kind === 'ok' && g.decisions).toEqual([])
  })
})

describe('S2-N1/N2: source-check index and the unique-violation catch', () => {
  it('S2-N1: the source-check lookup on conversation_log uses an index, not a table scan', () => {
    const plan = getDb()
      .prepare("EXPLAIN QUERY PLAN SELECT DISTINCT message_id FROM conversation_log WHERE direction = 'in' AND chat_id = ? AND message_id IN (?, ?)")
      .all('555', '1', '2') as { detail: string }[]
    const text = plan.map((r) => r.detail).join('\n')
    expect(text).toContain('USING')
    expect(text).toContain('idx_convlog_source_check')
    expect(text).not.toMatch(/SCAN conversation_log(?! USING)/)
  })

  // Wraps the db so the INSERT into function_decisions throws a chosen error after the pre-checks passed.
  function failInsertWith(err: Error & { code?: string }): void {
    const db = getDb()
    const realPrepare = db.prepare.bind(db)
    ;(db as unknown as { prepare: unknown }).prepare = (sql: string) => {
      if (/INSERT INTO function_decisions/.test(sql)) {
        return { run: () => { throw err } }
      }
      return realPrepare(sql)
    }
  }

  it('S2-N2: a UNIQUE(supersedes) error after the pre-check is a 409-class conflict', async () => {
    const old = await recOk({ quote_short: 'regi', tg_msg_id: '1' })
    failInsertWith(Object.assign(new Error('UNIQUE constraint failed: function_decisions.supersedes'), { code: 'SQLITE_CONSTRAINT_UNIQUE' }))
    expect((await rec({ quote_short: 'javitas', tg_msg_id: '2', supersedes: old.id })).kind).toBe('conflict')
  })

  it('S2-N2: another constraint error is not a conflict (it surfaces)', async () => {
    failInsertWith(Object.assign(new Error('CHECK constraint failed: quote_short'), { code: 'SQLITE_CONSTRAINT_CHECK' }))
    await expect(rec({ quote_short: 'x', tg_msg_id: '1' })).rejects.toThrow('CHECK constraint failed')
    failInsertWith(Object.assign(new Error('UNIQUE constraint failed: something_else.col'), { code: 'SQLITE_CONSTRAINT_UNIQUE' }))
    await expect(rec({ quote_short: 'x', tg_msg_id: '1' })).rejects.toThrow('something_else')
  })
})

describe('spec 5.4: allowlisted keys', () => {
  it('the write answer, every list row and every page row carry EXACTLY the DECISION_KEYS', async () => {
    inbound(OWNER, '100')
    const w = await recOk({ quote_short: 'igen', tg_msg_id: '100', msg_id: busMessage(), card_id: '3333aaaa' })
    await recOk({ quote_short: 'masik', tg_msg_id: '101', supersedes: w.id })
    expect(keysOf(w)).toEqual(sorted(DECISION_KEYS))
    const list = await svc.decisions('f')
    const page = await svc.page('f')
    if (list.kind !== 'ok' || page.kind !== 'ok') throw new Error('expected ok')
    expect(list.decisions).toHaveLength(2)
    for (const d of list.decisions) expect(keysOf(d)).toEqual(sorted(DECISION_KEYS))
    expect(page.page.decisions).toHaveLength(1)
    for (const d of page.page.decisions) expect(keysOf(d)).toEqual(sorted(DECISION_KEYS))
    expect(keysOf(page.page)).toEqual(sorted(PAGE_KEYS))
    expect(PAGE_KEYS).toContain('decisions')
  })

  it('quote_short is masked on the way out even if a secret-shaped text is already in the table', async () => {
    const secret = `token=${'Q'.repeat(30)}`
    getDb().prepare(`INSERT INTO function_decisions (slug, quote_short, tg_msg_id, decided_at, recorded_by, recorded_via, created_at)
      VALUES ('f', ?, '1', ?, 'x', 'token', ?)`).run(`szia ${secret}`, T0, T0)
    const list = await svc.decisions('f')
    expect(JSON.stringify(list)).not.toContain('Q'.repeat(30))
  })

  it('the table columns recorded_via and source_checked_at stay out of every response', async () => {
    const w = await recOk({ quote_short: 'igen', tg_msg_id: '1' })
    expect(JSON.stringify(w)).not.toContain('recorded_via')
    expect(JSON.stringify(w)).not.toContain('source_checked_at')
    expect(JSON.stringify(w)).not.toContain('source_found')
  })
})

describe('spec 5.1: who writes (decisionActor) and how it is recorded', () => {
  it('maps every credential kind', () => {
    expect(decisionActor({ kind: 'token', agent: 'agent-b' })).toEqual({ via: 'token', by: 'agent-b' })
    expect(decisionActor({ kind: 'token' })).toEqual({ via: 'token', by: 'token' })
    expect(decisionActor({ kind: 'device', device: 'phone', scope: 'full' })).toEqual({ via: 'device', by: 'device:phone' })
    expect(decisionActor({ kind: 'session', user: 'owner' })).toEqual({ via: 'session', by: 'session:owner' })
    expect(decisionActor({ kind: 'device', device: 'op', scope: 'operator' })).toBeNull()
    expect(decisionActor({ kind: 'federation' })).toBeNull()
    expect(decisionActor(undefined)).toBeNull()
    expect(decisionActor(null)).toBeNull()
  })

  it('stores recorded_by and recorded_via from the principal, never from the body', async () => {
    const t = await recOk({ quote_short: 'a', tg_msg_id: '1' }, { via: 'token', by: 'agent-b' })
    const n = await recOk({ quote_short: 'b', tg_msg_id: '2' }, { via: 'token', by: 'token' })
    const d = await recOk({ quote_short: 'c', tg_msg_id: '3' }, { via: 'device', by: 'device:phone' })
    const s = await recOk({ quote_short: 'd', tg_msg_id: '4' }, { via: 'session', by: 'session:owner' })
    expect([t, n, d, s].map((x) => x.recorded_by)).toEqual(['agent-b', 'token', 'device:phone', 'session:owner'])
    const via = getDb().prepare('SELECT recorded_via FROM function_decisions ORDER BY id').all() as { recorded_via: string }[]
    expect(via.map((v) => v.recorded_via)).toEqual(['token', 'token', 'device', 'session'])
  })
})

// ---- through the route handler with the real service ----------------------------------

type Auth = RouteContext['auth']

function post(path: string, body: string, auth: Auth | null, method = 'POST'): { ctx: RouteContext; out: { status: number; body: any } } {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const req: any = Object.assign(Readable.from([Buffer.from(body, 'utf8')]), { headers: { 'content-length': String(Buffer.byteLength(body)) } })
  const url = new URL(`http://localhost:3420${path}`)
  return { ctx: { req, res, path: url.pathname, method, url, auth: auth ?? undefined } as RouteContext, out }
}

describe('end to end through the route', () => {
  beforeEach(() => setFunkciokServiceForTest(svc))
  const P = '/api/funkciok/f/decisions'
  const body = JSON.stringify({ quote_short: 'igen, mehet', tg_msg_id: '100' })

  it('token with X-Agent-Id: 201, recorded_by is the agent, recorded_via token; the GET lists it', async () => {
    inbound(OWNER, '100', `${MARKER} szoveg`)
    const r = post(P, body, { kind: 'token', agent: 'agent-b' })
    expect(await tryHandleFunkciok(r.ctx)).toBe(true)
    expect(r.out.status).toBe(201)
    expect(r.out.body.recorded_by).toBe('agent-b')
    expect(r.out.body.source_status).toBe('verified')
    expect(JSON.stringify(r.out.body)).not.toContain(MARKER)
    expect((getDb().prepare('SELECT recorded_via FROM function_decisions').get() as { recorded_via: string }).recorded_via).toBe('token')
    const g = post(P, '', { kind: 'token' }, 'GET')
    await tryHandleFunkciok(g.ctx)
    expect(g.out.status).toBe(200)
    expect(g.out.body.decisions).toHaveLength(1)
    expect(keysOf(g.out.body.decisions[0])).toEqual(sorted(DECISION_KEYS))
  })

  it('token without a claim -> "token"; session -> session:<user>; device full -> device:<name>', async () => {
    for (const [auth, by, via] of [
      [{ kind: 'token' }, 'token', 'token'],
      [{ kind: 'session', user: 'owner' }, 'session:owner', 'session'],
      [{ kind: 'device', device: 'phone', deviceId: 2, scope: 'full' }, 'device:phone', 'device'],
    ] as [Auth, string, string][]) {
      const r = post(P, JSON.stringify({ quote_short: `via ${via}`, tg_msg_id: '5' }), auth)
      await tryHandleFunkciok(r.ctx)
      expect(r.out.status).toBe(201)
      expect(r.out.body.recorded_by).toBe(by)
    }
  })

  it('operator scope and federation are 403, no principal is 401, and nothing is written', async () => {
    for (const [auth, status] of [
      [{ kind: 'device', device: 'op', deviceId: 1, scope: 'operator' }, 403],
      [{ kind: 'federation', peer: 'p' }, 403],
      [null, 401],
    ] as [Auth | null, number][]) {
      const r = post(P, body, auth)
      await tryHandleFunkciok(r.ctx)
      expect(r.out.status).toBe(status)
    }
    expect(count()).toBe(0)
  })

  it('a refused write maps to the status: 400 no source, 404 unknown slug, 422 missing msg_id, 409 double correction', async () => {
    let r = post(P, JSON.stringify({ quote_short: 'igen' }), { kind: 'token' })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(400)
    r = post('/api/funkciok/nincs-ilyen/decisions', body, { kind: 'token' })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(404)
    r = post(P, JSON.stringify({ quote_short: 'igen', msg_id: 31337 }), { kind: 'token' })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(422)
    const first = await recOk({ quote_short: 'a', tg_msg_id: '1' })
    await recOk({ quote_short: 'b', tg_msg_id: '2', supersedes: first.id })
    r = post(P, JSON.stringify({ quote_short: 'c', tg_msg_id: '3', supersedes: first.id }), { kind: 'token' })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(409)
  })

  it('the request body limit: 16 KB is refused with 413 and nothing is written', async () => {
    const big = JSON.stringify({ quote_short: 'igen', tg_msg_id: '1', card_id: 'a'.repeat(20_000) })
    const r = post(P, big, { kind: 'token' })
    await tryHandleFunkciok(r.ctx)
    expect(r.out.status).toBe(413)
    // a chunked body without a declared length hits the read limit instead
    const chunked = post(P, big, { kind: 'token' })
    delete (chunked.ctx.req as any).headers['content-length']
    await tryHandleFunkciok(chunked.ctx)
    expect(chunked.out.status).toBe(413)
    expect(count()).toBe(0)
  })

  it('there is no PUT, PATCH or DELETE on the decisions path: 405 and nothing changes', async () => {
    const d = await recOk({ quote_short: 'igen', tg_msg_id: '1' })
    for (const method of ['PUT', 'PATCH', 'DELETE']) {
      for (const p of [P, `${P}/${d.id}`]) {
        const r = post(p, JSON.stringify({ quote_short: 'felulir' }), { kind: 'token' }, method)
        const handled = await tryHandleFunkciok(r.ctx)
        // `${P}/<id>` is not a route of this module at all: it falls through to the 404 of the dispatcher
        if (p === P) { expect(handled).toBe(true); expect(r.out.status).toBe(405) } else expect(handled).toBe(false)
      }
    }
    expect((getDb().prepare('SELECT quote_short FROM function_decisions WHERE id = ?').get(d.id) as { quote_short: string }).quote_short).toBe('igen')
  })
})
