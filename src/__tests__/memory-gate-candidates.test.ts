/**
 * Memory write gate (card 3e9f6c28, node G2d): the owner-narrowed candidate finder.
 *
 * Every fixture row carries a unique marker word, so "which rows could reach a prompt" is a
 * plain set comparison. The transport-spy part of the data-scope proof (what actually goes
 * to the classifier across whole rounds) belongs to G2c; this file proves the finder.
 */
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import type Database from 'better-sqlite3'
import { initDatabase, getDb, appendDailyLog } from '../db.js'
import { findGateCandidates, findGateCandidatesAsync, VECTOR_PAGE, gateFtsTerms, gateFtsExpression, MAX_FTS_TERMS } from '../memory-gate/candidates.js'

vi.mock('../logger.js', () => ({
  logger: { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() },
}))
vi.mock('../config.js', async () => {
  const actual = await vi.importActual<typeof import('../config.js')>('../config.js')
  return { ...actual, MAIN_AGENT_ID: 'brainy', OLLAMA_URL: '' }
})

const W = {
  warm: 'zorvalux', cold: 'quimbleton', hot: 'frestagon', sharedOwn: 'dolmerix',
  otherWarm: 'velkandra', otherShared: 'tarnopell', feszek: 'ombrelix', main: 'kastrovian',
  mirror: 'plenthorix', later: 'wyndraxis', source: 'brimoleon',
}
const ALL_MARKERS = Object.values(W).join(' ')

let ids: Record<string, number> = {}

function put(agent: string, category: string, text: string, embedding: string | null = null, keywords: string | null = null): number {
  const now = Math.floor(Date.now() / 1000)
  return Number(getDb().prepare(
    `INSERT INTO memories (chat_id, topic_key, content, sector, salience, created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
     VALUES ('0', NULL, ?, 'semantic', 1.0, ?, ?, ?, ?, 0, ?, ?)`,
  ).run(text, now, now, agent, category, keywords, embedding).lastInsertRowid)
}

function seed(): void {
  const v = (x: number[]) => JSON.stringify(x)
  ids = {}
  ids.warm = put('iroda', 'warm', `${W.warm} a szerzodes rendben van`, v([0.9, 0.1, 0]))
  ids.cold = put('iroda', 'cold', `${W.cold} regi megjegyzes`, v([0.5, 0.5, 0]))
  ids.hot = put('iroda', 'hot', `${W.hot} aktualis feladat`, v([1, 0, 0]))
  ids.sharedOwn = put('iroda', 'shared', `${W.sharedOwn} kozos tudas`, v([1, 0, 0]))
  ids.otherWarm = put('lapszabasz', 'warm', `${W.otherWarm} masik ugynok`, v([1, 0, 0]))
  ids.otherShared = put('lapszabasz', 'shared', `${W.otherShared} masik ugynok kozos`, v([1, 0, 0]))
  ids.feszek = put('feszek', 'warm', `${W.feszek} csaladi`, v([1, 0, 0]))
  ids.main = put('brainy', 'warm', `${W.main} fougynok`, v([1, 0, 0]))
  // a daily-log mirror row of the same owner (category cold)
  const log = appendDailyLog('iroda', `${W.mirror} napi bejegyzes elegendoen hosszu szoveg`, { mirror: true })
  ids.mirror = log.memoryId as number
  getDb().prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(v([1, 0, 0]), ids.mirror)
  // bad vectors of the right owner and category
  ids.dimMismatch = put('iroda', 'warm', 'dimmismatchrow alfa', v([1, 0]))
  ids.malformed = put('iroda', 'warm', 'malformedrow alfa', 'not json')
  ids.zeroNorm = put('iroda', 'warm', 'zeronormrow alfa', v([0, 0, 0]))
  ids.source = put('iroda', 'warm', `${ALL_MARKERS} ez az uj emlek`, v([1, 0, 0]), 'szerzodes, brimoleon')
  ids.later = put('iroda', 'warm', `${W.later} kesobbi sor`, v([1, 0, 0]))
}

function source(over: Partial<{ content: string; keywords: string | null; embedding: string | null; agent_id: string }> = {}) {
  const row = getDb().prepare('SELECT id, agent_id, content, keywords, embedding FROM memories WHERE id = ?').get(ids.source) as
    { id: number; agent_id: string; content: string; keywords: string | null; embedding: string | null }
  return { ...row, ...over }
}

const idsOf = (r: { hits: Array<{ memory: { id: number } }> }) => r.hits.map(h => h.memory.id).sort((a, b) => a - b)

beforeEach(() => {
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('network disabled in test') }))
  initDatabase(':memory:')
  seed()
})
afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals() })

describe('scope: only the owner\'s warm/cold rows below the source id, never a mirror row', () => {
  it('keyword branch alone: warm and cold of the same owner come in, everything else stays out', () => {
    const r = findGateCandidates(getDb(), source({ embedding: null }))
    expect(idsOf(r)).toEqual([ids.warm, ids.cold].sort((a, b) => a - b))
    expect(r.rejected).toBe(0)
    expect(r.vectorUsed).toBe(false)
    expect(r.ftsTerms).toBeGreaterThan(0)
    for (const bad of ['hot', 'sharedOwn', 'otherWarm', 'otherShared', 'feszek', 'main', 'mirror', 'later', 'source', 'dimMismatch', 'malformed', 'zeroNorm']) {
      expect(idsOf(r), bad).not.toContain(ids[bad])
    }
  })

  it('vector branch alone: same set, bad vectors skipped, nothing foreign', () => {
    const r = findGateCandidates(getDb(), source({ content: 'xyzzy plugh nothing in common', keywords: null }))
    expect(r.vectorUsed).toBe(true)
    expect(idsOf(r)).toEqual([ids.warm, ids.cold].sort((a, b) => a - b))
    expect(r.hits.every(h => h.vecRank !== null && h.cosine !== null)).toBe(true)
    // closest first: [0.9,0.1,0] is nearer to [1,0,0] than [0.5,0.5,0]
    expect(r.hits[0].memory.id).toBe(ids.warm)
    for (const bad of ['dimMismatch', 'malformed', 'zeroNorm', 'hot', 'sharedOwn', 'otherWarm', 'feszek', 'main', 'mirror', 'later']) {
      expect(idsOf(r), bad).not.toContain(ids[bad])
    }
  })

  it('both branches: a row found by both carries both ranks', () => {
    const r = findGateCandidates(getDb(), source())
    expect(r.hits.length).toBe(2)
    for (const h of r.hits) {
      expect(h.ftsRank).not.toBeNull()
      expect(h.vecRank).not.toBeNull()
    }
  })

  it('a row with a bigger id than the source is never a candidate, in either branch', () => {
    expect(idsOf(findGateCandidates(getDb(), source()))).not.toContain(ids.later)
    expect(idsOf(findGateCandidates(getDb(), source({ content: 'wyndraxis only', keywords: null })))).not.toContain(ids.later)
  })

  it('works for any owner: the owner is the source\'s own, not a constant', () => {
    const mine = put('hazmester', 'cold', 'mine only hazmesterrow', JSON.stringify([1, 0, 0]))
    const src = put('hazmester', 'warm', 'hazmesterrow follow up', JSON.stringify([1, 0, 0]))
    const r = findGateCandidates(getDb(), { id: src, agent_id: 'hazmester', content: 'hazmesterrow follow up', keywords: null, embedding: JSON.stringify([1, 0, 0]) })
    expect(idsOf(r)).toEqual([mine])
  })

  it('the limit is clamped to 1..5', () => {
    for (let i = 0; i < 8; i++) put('iroda', 'warm', `${W.warm} extra ${i}`, JSON.stringify([1, 0, 0]))
    ids.source = put('iroda', 'warm', `${ALL_MARKERS} ez az uj emlek ketto`, JSON.stringify([1, 0, 0]))
    expect(findGateCandidates(getDb(), source()).hits.length).toBe(5)
    expect(findGateCandidates(getDb(), source(), { limit: 2 }).hits.length).toBe(2)
    expect(findGateCandidates(getDb(), source(), { limit: 99 }).hits.length).toBe(5)
    expect(findGateCandidates(getDb(), source(), { limit: 0 }).hits.length).toBe(1)
  })

  it('returned memories carry no stored vector', () => {
    const r = findGateCandidates(getDb(), source())
    expect(r.hits.length).toBeGreaterThan(0)
    for (const h of r.hits) expect(h.memory.embedding).toBeNull()
  })
})

describe('refusals', () => {
  it('feszek is refused before any query runs', () => {
    const calls: string[] = []
    const spyDb = new Proxy(getDb(), {
      get(t, p) {
        if (p === 'prepare') return (sql: string) => { calls.push(sql); return t.prepare(sql) }
        const v = (t as any)[p]
        return typeof v === 'function' ? v.bind(t) : v
      },
    }) as Database.Database
    const r = findGateCandidates(spyDb, source({ agent_id: 'feszek' }))
    expect(r).toMatchObject({ hits: [], refused: 'forbidden_owner' })
    expect(calls).toEqual([])
  })

  it('a malformed source is refused, not thrown', () => {
    for (const bad of [
      { id: 0, agent_id: 'iroda', content: 'x' },
      { id: -5, agent_id: 'iroda', content: 'x' },
      { id: 1.5, agent_id: 'iroda', content: 'x' },
      { id: 5, agent_id: '', content: 'x' },
      { id: 5, agent_id: 'iroda', content: undefined as unknown as string },
    ]) {
      expect(findGateCandidates(getDb(), bad)).toMatchObject({ hits: [], refused: 'bad_source' })
    }
  })
})

describe('FTS terms and expression (syntax-injection proof)', () => {
  it('keeps only letters/digits terms of 3+ characters, keywords first, deduplicated, at most 24', () => {
    expect(gateFtsTerms('alma, k\u00F6rte', 'AB 12 abc Alma x1 \u00E9v2026')).toEqual(['alma', 'k\u00F6rte', 'abc', '\u00E9v2026'])
    const many = Array.from({ length: 60 }, (_, i) => `term${i}`).join(' ')
    expect(gateFtsTerms(null, many.slice(0, 400)).length).toBeLessThanOrEqual(MAX_FTS_TERMS)
    expect(gateFtsTerms(many, '').length).toBe(MAX_FTS_TERMS)
  })

  it('only the first 400 characters of the content are used', () => {
    const content = 'a'.repeat(399) + ' lateword'
    expect(gateFtsTerms(null, content + ' beyondword').join(' ')).not.toContain('beyondword')
  })

  it('every term is double-quoted and OR-joined', () => {
    expect(gateFtsExpression(['alma', 'korte'])).toBe('"alma" OR "korte"')
    expect(gateFtsExpression([])).toBe('')
  })

  const hostile = [
    '"', '""', '" OR 1=1 --', 'foo" OR agent_id:feszek OR "bar', 'NEAR(a b, 3)', 'a AND NOT b', '*', 'a*', '^start', '-neg', 'col:val',
    '(((', ')))', '{x}', "O'Brien", 'back\\slash', String.fromCharCode(0) + 'nul', 'x'.repeat(10000), 'OR', 'AND', 'NOT', 'NEAR',
  ]
  for (const h of hostile) {
    it(`does not throw or widen on hostile source text ${JSON.stringify(h.slice(0, 24))}`, () => {
      const terms = gateFtsTerms(h, h)
      expect(terms.every(t => /^[\p{L}\p{N}]{3,64}$/u.test(t))).toBe(true)
      const expr = gateFtsExpression(terms)
      expect(expr).toMatch(/^("[\p{L}\p{N}]+"( OR "[\p{L}\p{N}]+")*)?$/u)
      const r = findGateCandidates(getDb(), source({ content: h, keywords: h, embedding: null }))
      // a hostile query can only ever return rows that satisfy the scope; never another owner's
      for (const hit of r.hits) {
        expect(hit.memory.agent_id).toBe('iroda')
        expect(['warm', 'cold']).toContain(hit.memory.category)
      }
      expect(r.rejected).toBe(0)
    })
  }

  it('a quoted operator word is a plain phrase, not an operator', () => {
    put('iroda', 'warm', 'operator word near alpha beta', JSON.stringify([1, 0, 0]))
    const src = put('iroda', 'warm', 'NEAR something else', JSON.stringify([0, 1, 0]))
    expect(() => findGateCandidates(getDb(), { id: src, agent_id: 'iroda', content: 'NEAR something else', keywords: null, embedding: null })).not.toThrow()
  })
})

describe('robustness', () => {
  it('no stored vector on the source: keyword branch only, vectorUsed=false', () => {
    for (const e of [null, undefined, '', 'not json', '[]', '[0,0,0]', '["a"]', '{"a":1}']) {
      const r = findGateCandidates(getDb(), source({ embedding: e as string | null }))
      expect(r.vectorUsed, JSON.stringify(e)).toBe(false)
      expect(idsOf(r)).toEqual([ids.warm, ids.cold].sort((a, b) => a - b))
    }
  })

  it('a database without the daily_log_memory table does not throw', () => {
    getDb().exec('DROP TABLE daily_log_memory')
    expect(() => findGateCandidates(getDb(), source())).not.toThrow()
    const r = findGateCandidates(getDb(), source())
    expect(idsOf(r)).toContain(ids.warm)
  })

  it('reads only: accessed_at and every other column are unchanged afterwards', () => {
    const snap = () => getDb().prepare('SELECT id, accessed_at, content, keywords, category, agent_id, embedding, updated_at FROM memories ORDER BY id').all()
    const before = snap()
    const memoriesChanges = getDb().prepare('SELECT total_changes() AS n').get() as { n: number }
    findGateCandidates(getDb(), source())
    findGateCandidates(getDb(), source({ embedding: null }))
    expect(snap()).toEqual(before)
    expect((getDb().prepare('SELECT total_changes() AS n').get() as { n: number }).n).toBe(memoriesChanges.n)
  })
})

describe('deep re-check catches a faulty branch', () => {
  // A handle whose branch queries have lost their owner/category scope (a deliberately wrong SQL).
  function faultyHandle(): Database.Database {
    const db = getDb()
    return new Proxy(db, {
      get(t, p) {
        if (p === 'prepare') {
          return (sql: string) => t.prepare(sql.replace("m.agent_id = ? AND m.category IN ('warm','cold') AND", '? IS NOT NULL AND'))
        }
        const v = (t as any)[p]
        return typeof v === 'function' ? v.bind(t) : v
      },
    }) as Database.Database
  }

  it('the re-check drops foreign rows, counts them, and returns only legitimate candidates', () => {
    const r = findGateCandidates(faultyHandle(), source())
    expect(r.rejected).toBeGreaterThan(0)
    for (const h of r.hits) {
      expect(h.memory.agent_id).toBe('iroda')
      expect(['warm', 'cold']).toContain(h.memory.category)
    }
    for (const bad of ['otherWarm', 'otherShared', 'feszek', 'main', 'hot', 'sharedOwn']) {
      expect(idsOf(r), bad).not.toContain(ids[bad])
    }
  })

  it('a row deleted between the branch and the re-check is dropped and counted', () => {
    const db = getDb()
    let armed = true
    const racing = new Proxy(db, {
      get(t, p) {
        if (p === 'prepare') {
          return (sql: string) => {
            if (armed && sql.startsWith('SELECT id, agent_id, category FROM memories WHERE id = ?')) {
              armed = false
              t.prepare('DELETE FROM memories WHERE id = ?').run(ids.warm)
            }
            return t.prepare(sql)
          }
        }
        const v = (t as any)[p]
        return typeof v === 'function' ? v.bind(t) : v
      },
    }) as Database.Database
    const r = findGateCandidates(racing, source())
    expect(r.rejected).toBe(1)
    expect(idsOf(r)).toEqual([ids.cold])
  })
})

describe('B10: event loop friendliness', () => {
  // Extra rows of the same owner with a usable vector; the source is re-created last so that
  // every bulk row lies below its id.
  function bulk(n: number): void {
    const stmt = getDb().prepare(
      `INSERT INTO memories (chat_id, topic_key, content, sector, salience, created_at, accessed_at, agent_id, category, auto_generated, keywords, embedding)
       VALUES ('0', NULL, ?, 'semantic', 1.0, ?, ?, 'iroda', 'warm', 0, NULL, ?)`,
    )
    const now = Math.floor(Date.now() / 1000)
    for (let i = 0; i < n; i++) stmt.run(`bulkrow${i} filler`, now, now, JSON.stringify([1 - i / (n * 2), i / (n * 2), 0]))
    ids.source = put('iroda', 'warm', `${ALL_MARKERS} bulk source`, JSON.stringify([1, 0, 0]), 'szerzodes, brimoleon')
  }

  /** A handle whose vector-page query reports each call (the number of rows it returned). */
  function pageSpy(onPage: (rows: number) => void): Database.Database {
    return new Proxy(getDb(), {
      get(target, p) {
        if (p === 'prepare') {
          return (sql: string) => {
            const stmt = target.prepare(sql)
            if (!sql.includes('m.embedding IS NOT NULL')) return stmt
            return new Proxy(stmt, {
              get(s, q) {
                if (q === 'all') return (...a: unknown[]) => { const rows = (s as any).all(...a) as unknown[]; onPage(rows.length); return rows }
                const v = (s as any)[q]
                return typeof v === 'function' ? v.bind(s) : v
              },
            })
          }
        }
        const v = (target as any)[p]
        return typeof v === 'function' ? v.bind(target) : v
      },
    }) as Database.Database
  }

  it('the async driver lets a pending timer run in the middle of a long vector scan', async () => {
    bulk(VECTOR_PAGE * 3 + 7)
    let pages = 0
    let timerRanAfterPage = -1
    const t = setTimeout(() => { timerRanAfterPage = pages }, 0)
    const r = await findGateCandidatesAsync(pageSpy(() => { pages++ }), source())
    clearTimeout(t)
    expect(pages).toBe(4) // 3 full pages + the short last one
    expect(timerRanAfterPage).toBeGreaterThanOrEqual(1)
    expect(timerRanAfterPage).toBeLessThan(pages) // it ran before the scan finished
    expect(r.vectorUsed).toBe(true)
  })

  it('the sync driver never yields (same result, no timer in between)', () => {
    bulk(VECTOR_PAGE * 2 + 1)
    let timerRan = false
    const t = setTimeout(() => { timerRan = true }, 0)
    findGateCandidates(getDb(), source())
    clearTimeout(t)
    expect(timerRan).toBe(false)
  })

  it('the sync and the async driver return the same candidates; paging does not skip or repeat a row', async () => {
    bulk(VECTOR_PAGE * 2 + 1)
    const a = findGateCandidates(getDb(), source())
    const b = await findGateCandidatesAsync(getDb(), source())
    expect(b).toEqual(a)
    expect(a.rejected).toBe(0)
  })

  it('the vector scan stops at maxVectorRows even when more rows exist', async () => {
    bulk(VECTOR_PAGE * 3)
    const seen: number[] = []
    await findGateCandidatesAsync(pageSpy(n => { seen.push(n) }), source(), { maxVectorRows: 150 })
    expect(seen).toEqual([VECTOR_PAGE, 50])
  })
})
