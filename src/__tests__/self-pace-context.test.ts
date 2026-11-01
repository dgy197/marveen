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
import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
// @ts-expect-error -- plain .mjs hook script, no types
import * as gate from '../../scripts/self-pace-gate.mjs'
// @ts-expect-error -- plain .mjs fixture module, no types
import { NL, Q, ATTACK_CASES, STRIPPER_UNCHANGED_IDS, INTERP_CASES, OPLINE_CASES, FLEET_CASES, STRIP_CONTRACT_CASES } from './fixtures/self-pace-context/cases.mjs'

type Row = { id: string; command: string; expect: 'DENY' | 'ALLOW'; note?: string; keep?: string; fn?: string; out?: string }
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
