// Card 0bb35172, node N0 (RED tests): the self-pace gate's strippers and its segmentation must use the same
// lexer model as joinShellLines (findings 3660cf43 B3 HIGH: a heredoc / payload that only LOOKS like one, in a
// comment or in a quote, erases real command lines; B4 MED: a newline or separator inside quotes cuts the
// dangerous pair into two segments). Spec: /Volumes/8T/10_LOCAL/Brainy/_ezermester/0bb35172/spec.md, section 5.
//
// Every test hands STRINGS to the exported decision functions (gateDecision, the four strippers, maskedSegments,
// shellContext). Nothing in this file, or in the corpus it imports, executes a command or starts a process.
//
// RED on 78b178b2:
//   - ATTACK H1 H2 H3 H4 D1 D2 t1 t2 t3 (9 gaps; K1 and K6 are green guards),
//   - OPLINE OP1 OP2 (the stripper erases the rest of the operator line),
//   - INTERP gd47 gd48 gd49 (spec E4),
//   - STRIPPER-unchanged: stripHeredocBodies H1-H4, stripDataPayloads D1, stripProseArguments D2,
//   - the missing exports maskedSegments (and shellContext, see shell-line-join.test.ts) and their behaviour rows,
//   - the structural checks (no `<<` regex in the strippers / maskInertLiterals, shellContext calls).
// Green guards: FLEET rows (27, Q17 stays DENY), STRIP_CONTRACT rows (5), ATTACK K1 K6.
//
// Card 6f27c86a, node N0 (blocks (f)-(n) at the end of this file): a heredoc body is DATA only when its owner provably
// does not execute it (spec: /Volumes/8T/10_LOCAL/Brainy/_ezermester/6f27c86a/spec.md, blueprint N0, variant V2), plus
// the test gaps of the 0bb35172 review (E2). Same rule: strings only, through exported functions; no shell, no process,
// the shell oracle is never enabled.
// RED on fbbf7016: the 18 OPEN rows (gate, stripper, keepRunBodies mask), the missing export heredocBodyIsData and its
// unit table, ctx.substs of shellContext, F11 (accepted over-block of V2), the structural checks.
// Green guards: FH rows except F11, GOV 22, O14 / O20, the E2 comment and exact=false rows, the mask default path.
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
// @ts-expect-error -- plain .mjs hook script, no types
import * as gate from '../../scripts/self-pace-gate.mjs'
// @ts-expect-error -- plain .mjs hook script, no types
import * as lexer from '../../scripts/shell-line-join.mjs'
// @ts-expect-error -- plain .mjs fixture module, no types
import { NL, Q, ATTACK_CASES, STRIPPER_UNCHANGED_IDS, INTERP_CASES, OPLINE_CASES, FLEET_CASES, STRIP_CONTRACT_CASES, HEREDOC_OWNER_CASES, HEREDOC_LIMIT_CASES, HEREDOC_DATA_CASES, HEREDOC_GOV_CASES, HEREDOC_LIST_CASES, HEREDOC_KEEP_CASES, SUBST_CASES, COMMIT_COMMENT_CASES, INEXACT_CASES } from './fixtures/self-pace-context/cases.mjs'

type Row = { id: string; command: string; expect: 'DENY' | 'ALLOW'; note?: string; keep?: string; fn?: string; out?: string; why?: string; data?: boolean; marker?: string }
type StripFn = 'stripHeredocBodies' | 'stripDataPayloads' | 'stripGitCommitMessages' | 'stripProseArguments'

const attackRows = ATTACK_CASES as Row[]
const interpRows = INTERP_CASES as Row[]
const oplineRows = OPLINE_CASES as Row[]
const fleetRows = FLEET_CASES as Row[]
const contractRows = STRIP_CONTRACT_CASES as Row[]
const STRIPPERS: StripFn[] = ['stripHeredocBodies', 'stripDataPayloads', 'stripGitCommitMessages', 'stripProseArguments']

function verdict(command: string): { deny: boolean; reason?: string } {
  const v = gate.gateDecision('Bash', { command })
  return { deny: v.deny === true, reason: v.reason }
}

// ---------------------------------------------------------------------------------------------------------
// (a) ATTACK: the shell runs the dangerous line; a look-alike heredoc / payload / quote must not hide it
// ---------------------------------------------------------------------------------------------------------
describe('(a) ATTACK rows: the gate decides what the shell would do', () => {
  it('the corpus has the 11 reviewer rows (9 gaps + the K1 and K6 guards)', () => {
    expect(attackRows.map((r) => r.id)).toEqual(['H1', 'H2', 'H3', 'H4', 'D1', 'D2', 't1', 't2', 't3', 'K1', 'K6'])
  })
  for (const row of attackRows) {
    it(`${row.id}: DENY${row.note ? ` (${row.note})` : ''}`, () => {
      const v = verdict(row.command)
      expect(v.deny ? 'DENY' : 'ALLOW', JSON.stringify(row.command)).toBe('DENY')
    })
  }
})

describe('(a) OPLINE rows: the rest of a heredoc operator line is code, not heredoc body', () => {
  for (const row of oplineRows) {
    it(`${row.id}: the gate says DENY`, () => {
      expect(verdict(row.command).deny ? 'DENY' : 'ALLOW', JSON.stringify(row.command)).toBe('DENY')
    })
    it(`${row.id}: stripHeredocBodies keeps the operator-line remainder`, () => {
      const out = gate.stripHeredocBodies(row.command) as string
      expect(out, JSON.stringify(out)).toContain(row.keep as string)
    })
  }
})

// Brainy decision Q1 (spec E4): kept in its own describe so it can be lifted out if the scope changes.
describe('(a) INTERP rows (E4): a heredoc owned by bash / python3 - / ssh is code, the scheduler check sees it', () => {
  for (const row of interpRows) {
    it(`${row.id}: DENY`, () => {
      expect(verdict(row.command).deny ? 'DENY' : 'ALLOW', JSON.stringify(row.command)).toBe('DENY')
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (b) FLEET: real multi-line fleet shapes keep their verdict (no new false deny)
// ---------------------------------------------------------------------------------------------------------
describe('(b) FLEET rows: real multi-line shapes keep their verdict (E5)', () => {
  it('the corpus has the 7 p6 rows and the 20 Q rows', () => {
    expect(fleetRows.length).toBe(27)
  })
  for (const row of fleetRows) {
    it(`${row.id}: ${row.expect}${row.note ? ` (${row.note})` : ''}`, () => {
      const v = verdict(row.command)
      expect(v.deny ? 'DENY' : 'ALLOW', `${JSON.stringify(row.command)} -> ${v.reason ?? 'no reason'}`).toBe(row.expect)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (c) STRIPPERS (E2, E8)
// ---------------------------------------------------------------------------------------------------------
describe('(c) E2: a heredoc opener, a -d flag or a -m flag in a comment or a quote deletes nothing', () => {
  const rows = attackRows.filter((r) => (STRIPPER_UNCHANGED_IDS as string[]).includes(r.id))
  it('the six rows have no backslash-newline, so the joined text equals the input', () => {
    expect(rows.map((r) => r.id)).toEqual(STRIPPER_UNCHANGED_IDS)
  })
  for (const row of rows) {
    for (const fn of STRIPPERS) {
      it(`${fn}(${row.id}) returns the input byte for byte`, () => {
        expect(gate[fn](row.command)).toBe(row.command)
      })
    }
  }
})

describe('(c) E8: the strippers still strip real code-position input (guard against over-fixing)', () => {
  for (const row of contractRows) {
    it(`${row.id}: ${row.fn}`, () => {
      expect(gate[row.fn as StripFn](row.command)).toBe(row.out)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (d) maskedSegments (E3): the pass that does not cut inside quotes
// ---------------------------------------------------------------------------------------------------------
describe('(d) maskedSegments: literal classes become spaces, only code positions cut', () => {
  const segs = (cmd: string): string[] => {
    expect(typeof gate.maskedSegments, 'maskedSegments is exported by self-pace-gate.mjs').toBe('function')
    const out = gate.maskedSegments(cmd) as unknown
    expect(Array.isArray(out)).toBe(true)
    return (out as string[]).map((s) => String(s).trim()).filter(Boolean)
  }
  const T = 'tm' + 'ux'
  const S = 'send' + '-keys'
  const C = 'cron' + 'tab'

  it('a quoted newline does not cut: t2 stays ONE segment that holds both trigger words', () => {
    const t2 = attackRows.find((r) => r.id === 't2') as Row
    expect(segs(t2.command).some((s) => new RegExp(`\\b${T}\\s+${S}\\b`).test(s))).toBe(true)
  })

  it('a quoted ; and a quoted newline inside one message stay in ONE segment (no words of the literal survive)', () => {
    const out = segs(`echo "x; y${NL}z"`)
    expect(out.length).toBe(1)
    expect(out[0]).not.toMatch(/[xyz]/)
  })

  it('the literal text is gone: a trigger word that only sits inside quotes is not in any segment', () => {
    const out = segs(`echo ${Q}${T} ${S}${Q}`)
    expect(out.some((s) => s.includes(T))).toBe(false)
  })

  it('a real separator in code position still cuts', () => {
    const out = segs(`ls; ${C} -r`)
    expect(out.some((s) => s.startsWith(C))).toBe(true)
  })

  it('a newline in code position still cuts (the dangerous line after a look-alike heredoc is its own segment)', () => {
    const h1 = attackRows.find((r) => r.id === 'H1') as Row
    expect(segs(h1.command).some((s) => s.startsWith(C))).toBe(true)
  })
})

// ---------------------------------------------------------------------------------------------------------
// (e) structural: one lexer model, no private heredoc / quote regexes in the strippers and the mask
// ---------------------------------------------------------------------------------------------------------
describe('(e) structural: strippers and maskInertLiterals ask shellContext, they do not search for <<TAG', () => {
  const read = (rel: string) => readFileSync(new URL(`../../scripts/${rel}`, import.meta.url), 'utf8')
  const src = read('self-pace-gate.mjs')

  // The text of `export function NAME(` up to the closing brace in column 0, without comment text.
  function functionCode(source: string, name: string): string {
    const start = source.indexOf(`export function ${name}(`)
    if (start === -1) return ''
    const end = source.indexOf('\n}\n', start)
    const body = source.slice(start, end === -1 ? source.length : end)
    return body
      .split('\n')
      .filter((line) => !/^\s*\/\//.test(line))
      .map((line) => line.replace(/\s\/\/\s.*$/, ''))
      .join('\n')
  }

  it('the extractor finds the five functions and drops comment text (self-test, so the checks below cannot pass vacuously)', () => {
    for (const name of [...STRIPPERS, 'maskInertLiterals']) expect(functionCode(src, name).length, name).toBeGreaterThan(80)
    expect(functionCode('export function f(x) {\n  // a <<TAG in a comment\n  return 1 // <<X trailing\n}\n', 'f')).not.toContain('<<')
    expect(functionCode('export function f(x) {\n  return /<<-?x/.test(x)\n}\n', 'f')).toContain('<<')
  })

  for (const name of [...STRIPPERS, 'maskInertLiterals']) {
    it(`${name} holds no \`<<\` pattern`, () => {
      expect(functionCode(src, name), `${name} still recognises a heredoc with its own pattern`).not.toContain('<<')
    })
    it(`${name} calls shellContext(`, () => {
      expect(functionCode(src, name)).toMatch(/\bshellContext\(/)
    })
  }

  it('self-pace-gate.mjs imports shellContext from the shared module', () => {
    expect(src).toMatch(/import\s*\{[^}]*\bshellContext\b[^}]*\}\s*from\s*['"]\.\/shell-line-join\.mjs['"]/)
  })

  it('self-pace-gate.mjs exports maskedSegments and the decision runs it next to the naive segments', () => {
    expect(src).toMatch(/export function maskedSegments\(/)
    expect((src.match(/\bmaskedSegments\(/g) ?? []).length).toBeGreaterThanOrEqual(2)
  })

  it('kanban-write-gate.mjs runs the masked pass too', () => {
    expect(read('kanban-write-gate.mjs')).toMatch(/\bmaskedSegments\b/)
  })
})

// =============================================================================================================
// Card 6f27c86a, node N0: the heredoc owner rule is inverted (blocks (f)-(n)).
// =============================================================================================================
type Subst = { start: number; end: number; kind: string }
type Heredoc = { opStart: number; tagEnd: number; bodyStart: number; bodyEnd: number; termEnd: number }
type Ctx = { text: string; cls: Uint8Array; heredocs: Heredoc[]; substs?: Subst[]; exact: boolean }

const ownerRows = HEREDOC_OWNER_CASES as Row[]
const limitRows = HEREDOC_LIMIT_CASES as Row[]
const dataRows = HEREDOC_DATA_CASES as Row[]
const govRows = HEREDOC_GOV_CASES as Row[]
const listRows = HEREDOC_LIST_CASES as Row[]
const keepRows = HEREDOC_KEEP_CASES as Row[]
const substRows = SUBST_CASES as Array<{ id: string; command: string; substs: Array<{ kind: string; open: string; close: string }> }>
const commentRows = COMMIT_COMMENT_CASES as Row[]
const inexactRows = INEXACT_CASES as Row[]

const ctxOf = (command: string): Ctx => lexer.shellContext(command) as Ctx
const verdictOf = (command: string): 'DENY' | 'ALLOW' => (verdict(command).deny ? 'DENY' : 'ALLOW')
const maskOf = (command: string, options?: { keepRunBodies?: boolean }) => {
  const heredocs: Array<{ runsBody: boolean }> = []
  const masked = gate.maskInertLiterals(command, heredocs, false, {}, options) as string | null
  return { masked, heredocs }
}

// ---------------------------------------------------------------------------------------------------------
// (f) OPEN rows (E1): a body the shell runs is seen by the self-pace checks
// ---------------------------------------------------------------------------------------------------------
describe('(f) OPEN rows (E1): a heredoc body that the shell runs stays visible', () => {
  it('the corpus has the 18 reviewer rows O1-O13 and O15-O19', () => {
    expect(ownerRows.slice(0, 18).map((r) => r.id.split('-')[0])).toEqual(['O1', 'O2', 'O3', 'O4', 'O5', 'O6', 'O7', 'O8', 'O9', 'O10', 'O11', 'O12', 'O13', 'O15', 'O16', 'O17', 'O18', 'O19'])
  })
  it('the corpus has the 24 round-1 review rows O21-O44 (B1: 8, B2: 4, B3: 8, B4: 4)', () => {
    expect(ownerRows.slice(18).map((r) => r.id.split('-')[0])).toEqual(Array.from({ length: 24 }, (_, i) => `O${21 + i}`))
  })
  for (const row of ownerRows) {
    it(`${row.id} [${row.why}]: gateDecision says DENY${row.note ? ` (${row.note})` : ''}`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe('DENY')
    })
    it(`${row.id}: stripHeredocBodies keeps the body (${JSON.stringify(row.keep)})`, () => {
      expect(gate.stripHeredocBodies(row.command) as string, JSON.stringify(row.command)).toContain(row.keep as string)
    })
  }
})

describe('(f) O14 and O20: the limit of this card and a green guard', () => {
  for (const row of limitRows) {
    it(`${row.id}: ${row.expect} (${row.note})`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe(row.expect)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (g) heredocBodyIsData(ctx, heredoc): one decision function, per heredoc, with a reason label
// ---------------------------------------------------------------------------------------------------------
describe('(g) heredocBodyIsData(ctx, heredoc): the decision per heredoc', () => {
  it('self-pace-gate.mjs exports heredocBodyIsData', () => {
    expect(typeof gate.heredocBodyIsData, 'heredocBodyIsData is exported by self-pace-gate.mjs').toBe('function')
  })
  // reason labels: owner (the redirect owner is no provable data consumer), pipe (a pipe stage on the operator line),
  // subst (an enclosing $( ) whose command is no data consumer), procsubst (<( ) / >( )), data (the body is data)
  for (const row of [...ownerRows, ...dataRows, ...listRows, ...keepRows]) {
    const want = row.data === true
    it(`${row.id} [${row.why}]: data=${want}`, () => {
      expect(typeof gate.heredocBodyIsData, 'heredocBodyIsData is exported').toBe('function')
      const ctx = ctxOf(row.command)
      expect(ctx.heredocs.length, 'the row opens exactly one heredoc').toBe(1)
      expect(gate.heredocBodyIsData(ctx, ctx.heredocs[0]), JSON.stringify(row.command)).toBe(want)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (h) ctx.substs: the substitution frames come from the one lexer pass
// ---------------------------------------------------------------------------------------------------------
describe('(h) shellContext(x).substs: the frames the decision is made from (N1)', () => {
  for (const row of substRows) {
    it(`${row.id}: ${row.substs.length ? row.substs.map((s) => s.kind).join(',') : 'no frame'}`, () => {
      const ctx = ctxOf(row.command)
      expect(Array.isArray(ctx.substs), 'shellContext returns substs').toBe(true)
      const got = ctx.substs as Subst[]
      expect(got.map((s) => s.kind)).toEqual(row.substs.map((s) => s.kind))
      got.forEach((s, i) => {
        const want = row.substs[i]
        expect(ctx.text.slice(s.start, s.start + want.open.length), 'start is the first character of the opener').toBe(want.open)
        expect(s.end, 'a closed frame has end after its opener').toBeGreaterThan(s.start + want.open.length)
        expect(ctx.text[s.end - 1], 'end is the index after the closing character').toBe(want.close)
        for (const h of ctx.heredocs) {
          expect(h.opStart >= s.start && h.termEnd <= s.end, 'the heredoc lies inside its frame').toBe(true)
        }
      })
    })
  }
  const all = [...ownerRows, ...limitRows, ...dataRows, ...govRows, ...listRows]
  it('E6 on the new corpus: text equals joinShellLines, exact is unchanged, the frames are valid, ordered and nested or disjoint', () => {
    expect(all.length).toBe(42 + 2 + 13 + 22 + 24)
    for (const row of all) {
      const info: { exact?: boolean } = {}
      const joined = lexer.joinShellLines(row.command, info) as string
      const ctx = ctxOf(row.command)
      expect(ctx.text, row.id).toBe(joined)
      expect(ctx.exact, row.id).toBe(info.exact)
      expect(Array.isArray(ctx.substs), `${row.id}: substs`).toBe(true)
      const frames = ctx.substs as Subst[]
      for (let i = 0; i < frames.length; i++) {
        const f = frames[i]
        expect(f.start, row.id).toBeGreaterThanOrEqual(0)
        expect(['cmd', 'proc-in', 'proc-out', 'bq'], row.id).toContain(f.kind)
        if (f.end !== -1) {
          expect(f.end, row.id).toBeGreaterThan(f.start)
          expect(f.end, row.id).toBeLessThanOrEqual(ctx.text.length)
        }
        if (i > 0) expect(f.start, `${row.id}: ordered by start`).toBeGreaterThanOrEqual(frames[i - 1].start)
        for (let j = 0; j < i; j++) {
          const p = frames[j]
          const disjoint = p.end !== -1 && p.end <= f.start
          const nested = p.end === -1 || (f.end !== -1 && f.end <= p.end)
          expect(disjoint || nested, `${row.id}: frames ${j} and ${i} overlap`).toBe(true)
        }
      }
    }
  })
})

// ---------------------------------------------------------------------------------------------------------
// (i) the E2 test gaps of card 0bb35172: a commit flag in a comment, and exact=false readings
// ---------------------------------------------------------------------------------------------------------
describe('(i) E2: a `git commit -m` in a comment deletes nothing, the real line after it runs', () => {
  for (const row of commentRows) {
    it(`${row.id}: the gate says DENY`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe('DENY')
    })
    for (const fn of STRIPPERS) {
      it(`${row.id}: ${fn} returns the input byte for byte`, () => {
        expect(gate[fn](row.command)).toBe(row.command)
      })
    }
  }
})

describe('(i) E2: a reading the lexer is not sure of (exact=false) strips nothing', () => {
  for (const row of inexactRows) {
    it(`${row.id}: the lexer reading is not exact (the row tests what it claims)`, () => {
      expect(ctxOf(row.command).exact).toBe(false)
    })
    for (const fn of STRIPPERS) {
      it(`${row.id}: ${fn} returns the input byte for byte`, () => {
        expect(gate[fn](row.command)).toBe(row.command)
      })
    }
  }
})

// ---------------------------------------------------------------------------------------------------------
// (j) maskInertLiterals: keepRunBodies true leaves a non-data body visible and says so (runsBody); the default
// path (the egress parser) masks every body and reports runsBody false
// ---------------------------------------------------------------------------------------------------------
describe('(j) maskInertLiterals keepRunBodies: runsBody and the visible or masked body', () => {
  const dataRow = (id: string) => dataRows.find((r) => r.id === id) as Row
  const maskRows: Array<{ id: string; command: string; runs: boolean; marker: string }> = [
    // every OPEN row whose mask is not refused by a double-quoted substitution (O8 and O9 are)
    ...ownerRows.filter((r) => !/^O(8|9)-/.test(r.id)).map((r) => ({ id: r.id, command: r.command, runs: true, marker: r.keep as string })),
    { id: 'gd47', command: (INTERP_CASES as Row[]).find((r) => r.id === 'gd47')!.command, runs: true, marker: 'cron' + 'tab -r' },
    ...['F5-cat-pipe-grep', 'F6-git-F', 'F8-assign-subst', 'F9-agentmsg-direct-owner', 'F10-cat-pipe-agentmsg-plain', 'F12-cat-to-file'].map((id) => ({ id, command: dataRow(id).command, runs: dataRow(id).data !== true, marker: dataRow(id).marker as string })),
    { id: 'S1-heredoc', command: (STRIP_CONTRACT_CASES as Row[]).find((r) => r.id === 'S1-heredoc')!.command, runs: false, marker: 'at the same time' },
  ]
  it('the table has the 40 OPEN rows (all but O8 and O9), gd47, six FH rows and S1', () => {
    expect(maskRows.length).toBe(40 + 1 + 6 + 1)
  })
  for (const row of maskRows) {
    it(`${row.id}: keepRunBodies:true -> runsBody=${row.runs}, the body is ${row.runs ? 'visible' : 'masked'}`, () => {
      const { masked, heredocs } = maskOf(row.command, { keepRunBodies: true })
      expect(masked, 'the mask is not refused').not.toBeNull()
      expect(heredocs.length).toBe(1)
      expect(heredocs[0].runsBody).toBe(row.runs)
      expect((masked as string).includes(row.marker), JSON.stringify(masked)).toBe(row.runs)
    })
    it(`${row.id}: default options and keepRunBodies:false -> runsBody=false, the body is masked, both the same`, () => {
      const a = maskOf(row.command)
      const b = maskOf(row.command, { keepRunBodies: false })
      expect(a.masked).not.toBeNull()
      expect(a.heredocs[0].runsBody).toBe(false)
      expect(b.heredocs[0].runsBody).toBe(false)
      expect((a.masked as string).includes(row.marker)).toBe(false)
      expect(b.masked).toBe(a.masked)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (k) FH rows (E4, E5/V2): data heredocs of the fleet that mention trigger words; GOV rows (E2)
// ---------------------------------------------------------------------------------------------------------
describe('(k) FH rows: a data heredoc keeps its verdict, a visible one is DENY', () => {
  it('the corpus has the 13 FH rows', () => {
    expect(dataRows.length).toBe(13)
  })
  for (const row of dataRows) {
    it(`${row.id}: ${row.expect}${row.note ? ` (${row.note})` : ''}`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe(row.expect)
    })
    it(`${row.id}: stripHeredocBodies ${row.data ? 'removes' : 'keeps'} the body (${JSON.stringify(row.marker)})`, () => {
      const out = gate.stripHeredocBodies(row.command) as string
      expect(out.includes(row.marker as string), JSON.stringify(out)).toBe(row.data !== true)
    })
  }
})

describe('(k) KEEP rows (review r1): the stronger proof conditions leave a plain data heredoc alone', () => {
  it('the corpus has the 4 KEEP rows', () => {
    expect(keepRows.length).toBe(4)
  })
  for (const row of keepRows) {
    it(`${row.id}: ${row.expect} and the body is stripped`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe(row.expect)
      expect((gate.stripHeredocBodies(row.command) as string).includes(row.marker as string), JSON.stringify(row.command)).toBe(false)
    })
  }
})

describe('(k) GOV rows (E2): the heredoc shapes of governance-gates keep their verdict', () => {
  it('the corpus has the 22 GOV rows', () => {
    expect(govRows.length).toBe(22)
  })
  for (const row of govRows) {
    it(`${row.id}: ${row.expect}`, () => {
      expect(verdictOf(row.command), JSON.stringify(row.command)).toBe(row.expect)
    })
  }
})

// ---------------------------------------------------------------------------------------------------------
// (n) structural: ONE decision function, no private heredoc pattern, no private bracket counting
// ---------------------------------------------------------------------------------------------------------
describe('(n) structural: heredocBodyIsData is the one rule, built on ctx.substs', () => {
  const src = readFileSync(new URL('../../scripts/self-pace-gate.mjs', import.meta.url), 'utf8')
  const withoutComments = (text: string): string =>
    text
      .split('\n')
      .filter((line) => !/^\s*\/\//.test(line))
      .map((line) => line.replace(/\s\/\/\s.*$/, ''))
      .join('\n')

  // The code of `function NAME(` / `export function NAME(` up to the closing brace in column 0, without comment text.
  function fnCode(name: string): string {
    const m = new RegExp(String.raw`(?:^|\n)(?:export )?function ${name}\(`).exec(src)
    if (!m) return ''
    const end = src.indexOf('\n}\n', m.index + 1)
    return withoutComments(src.slice(m.index, end === -1 ? src.length : end))
  }

  it('the extractor finds the functions (self-test, so the checks below cannot pass vacuously)', () => {
    for (const name of ['stripFlagArguments', 'stripHeredocBodies', 'maskInertLiterals']) expect(fnCode(name).length, name).toBeGreaterThan(80)
    expect(fnCode('heredocBodyIsData').length, 'heredocBodyIsData exists in self-pace-gate.mjs').toBeGreaterThan(80)
    expect(src).toMatch(/export function heredocBodyIsData\(/)
  })

  for (const name of ['stripFlagArguments', 'stripHeredocBodies', 'heredocBodyIsData']) {
    it(`${name} holds no \`<<\` pattern`, () => {
      expect(fnCode(name).length, `${name} exists`).toBeGreaterThan(80)
      expect(fnCode(name), `${name} recognises a heredoc with its own pattern`).not.toContain('<<')
    })
  }

  it('heredocBodyIsData counts no brackets of its own: it reads ctx.substs', () => {
    const code = fnCode('heredocBodyIsData')
    expect(code.length, 'heredocBodyIsData exists').toBeGreaterThan(80)
    expect(code, 'a quoted parenthesis character').not.toMatch(/['"`][()]['"`]/)
    expect(code, 'a character code compare or a depth counter').not.toMatch(/charCodeAt|\b(?:depth|level|nest\w*)\s*(?:\+\+|--|\+=|-=)/)
    expect(code).toMatch(/\bsubsts\b/)
  })

  it('both call sites ask heredocBodyIsData(', () => {
    expect(fnCode('stripHeredocBodies')).toMatch(/\bheredocBodyIsData\(/)
    expect(fnCode('maskInertLiterals')).toMatch(/\bheredocBodyIsData\(/)
  })

  it('the old rule is gone: no heredocOwnerRunsBody in any code line', () => {
    expect(withoutComments(src)).not.toContain('heredocOwnerRunsBody')
  })
})
