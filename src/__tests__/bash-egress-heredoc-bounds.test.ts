// Card 0983a3fc: the egress parser finds heredoc bounds and joins backslash-newline lines with the shared
// lexer (scripts/shell-line-join.mjs), not with its own regexes.
//
// Finding B6 (44167c0b be-review-r2.md:7): a backslash at the end of a QUOTED heredoc body line is no
// continuation, so the terminator line is a real terminator and the line behind it runs. The old
// whole-text join swallowed that terminator and read the next line as body. The same family: tags the old
// regex read wrong (`<<E"F"`, `<<E.X`, `<<E\F`), a command word cut by a backslash-newline, and a host cut
// by a backslash-newline inside interpreter code.
//
// Rows live in fixtures/egress-corpus/heredoc-bounds.mjs. Strings only: nothing is executed.
import { describe, it, expect } from 'vitest'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify, liftSubstitutions } from '../../scripts/hooks/bash-egress-parser.mjs'
// @ts-expect-error -- plain .mjs hook script, no types
import { joinShellLines } from '../../scripts/shell-line-join.mjs'
import {
  DENY_ROWS,
  ALLOW_ROWS,
  LOOSENED_ROWS,
  FAILCLOSED_IDS,
  FAILCLOSED_REASON,
  EXTERNAL_HOST,
  // @ts-expect-error -- plain .mjs fixture module, no types
} from './fixtures/egress-corpus/heredoc-bounds.mjs'

type Row = [string, string, string]
type Decision = { deny: boolean; reason?: string; hosts: string[] }
const VENDOR = new Set(['api.github.com'])
const NO_DOMAINS = new Set<string>()
const run = (cmd: string): Decision => classify(cmd, 0, VENDOR, NO_DOMAINS)

describe('fixture sanity', () => {
  const all = [...(DENY_ROWS as Row[]), ...(ALLOW_ROWS as Row[]), ...(LOOSENED_ROWS as Row[])]
  it('row ids are unique', () => {
    expect(new Set(all.map((r) => r[0])).size).toBe(all.length)
  })
  it('every fail-closed id is a DENY row', () => {
    const ids = (DENY_ROWS as Row[]).map((r) => r[0])
    for (const id of FAILCLOSED_IDS as string[]) expect(ids).toContain(id)
  })
})

describe('DENY: the line behind a real terminator runs and the external host is reported (E1, E2, E3)', () => {
  for (const [id, description, cmd] of DENY_ROWS as Row[]) {
    if ((FAILCLOSED_IDS as string[]).includes(id)) continue
    it(`${id} denies and reports the host: ${description}`, () => {
      const r = run(cmd)
      expect({ id, deny: r.deny }).toEqual({ id, deny: true })
      // The interpreter rows (I*) report the host behind the open local prefix, so match by substring.
      const exact = !id.startsWith('I')
      const named = exact ? r.hosts.includes(EXTERNAL_HOST) : r.hosts.some((h: string) => h.includes(EXTERNAL_HOST))
      expect({ id, hosts: r.hosts, named }).toMatchObject({ id, named: true })
      // The reason must come from reading the command, not from a parse failure or a launched-shell marker.
      expect({ id, unparseable: r.reason === 'unparseable' }).toEqual({ id, unparseable: false })
      expect({ id, launched: r.reason === 'launched' }).toEqual({ id, launched: false })
    })
  }
})

describe('DENY, fail-closed: a body line that differs from the tag only in blanks (spec 0.5 c)', () => {
  for (const id of FAILCLOSED_IDS as string[]) {
    const row = (DENY_ROWS as Row[]).find((r) => r[0] === id)!
    it(`${id} denies as ${FAILCLOSED_REASON}`, () => {
      const r = run(row[2])
      expect({ id, deny: r.deny, reason: r.reason }).toEqual({ id, deny: true, reason: FAILCLOSED_REASON })
    })
  }
})

describe('ALLOW: controls that must stay allowed (E5)', () => {
  for (const [id, description, cmd] of ALLOW_ROWS as Row[]) {
    it(`${id} is allowed: ${description}`, () => {
      expect({ id, r: run(cmd) }).toMatchObject({ id, r: { deny: false, hosts: [] } })
    })
  }
})

// N2: liftSubstitutions takes the heredoc bounds from the lexer, in the lexer's coordinates (blueprint risk
// "rossz koordináta"). Its output is length-preserving, so every offset of the caller still points into norm.
describe('liftSubstitutions: lexer coordinates, length-preserving (N2)', () => {
  type Lifted = { stripped: string; bodies: [number, number][]; heredocs: { opStart: number; bodyStart: number; bodyEnd: number; quoted: boolean }[] }
  const lift = (cmd: string): Lifted => liftSubstitutions(joinShellLines(cmd))
  const all = [...(DENY_ROWS as Row[]), ...(ALLOW_ROWS as Row[]), ...(LOOSENED_ROWS as Row[])]
  it('stripped.length === norm.length on every row that lifts', () => {
    for (const [id, , cmd] of all) {
      if ((FAILCLOSED_IDS as string[]).includes(id)) continue
      const norm: string = joinShellLines(cmd)
      expect({ id, len: lift(cmd).stripped.length }).toEqual({ id, len: norm.length })
    }
  })
  it('two heredocs on one line: both walked, bodies back to back, in operator order', () => {
    const cmd = (DENY_ROWS as Row[]).find((r) => r[0] === 'B6-two-first')![2]
    const norm: string = joinShellLines(cmd)
    const { heredocs, bodies } = lift(cmd)
    expect(heredocs.length).toBe(2)
    expect(heredocs.map((h) => norm.slice(h.opStart, h.opStart + 2))).toEqual(['<<', '<<'])
    expect(bodies).toEqual(heredocs.map((h) => [h.bodyStart, h.bodyEnd]))
    expect(heredocs.map((h) => norm.slice(h.bodyStart, h.bodyEnd))).toEqual(['x\\\n', 'y\n'])
  })
  it('an operator inside a lifted $(...) is not a walked heredoc of the outer text', () => {
    const cmd = (DENY_ROWS as Row[]).find((r) => r[0] === 'B6-in-subst')![2]
    expect(lift(cmd).heredocs).toEqual([])
  })
  it('the tag the lexer reads, not a regex: <<E"F" ends at EF', () => {
    const cmd = (DENY_ROWS as Row[]).find((r) => r[0] === 'B6-part-tag-nobs')![2]
    const norm: string = joinShellLines(cmd)
    const [h] = lift(cmd).heredocs
    expect({ body: norm.slice(h.bodyStart, h.bodyEnd), quoted: h.quoted }).toEqual({ body: 'x\n', quoted: true })
  })
  it('text that is not joined yet is refused, not read with shifted coordinates', () => {
    expect(() => liftSubstitutions('cat <<E\na\\\nb\nE')).toThrow('heredoc-bounds')
  })
  it('a quote in a comment does not hide the heredoc operator behind it', () => {
    const cmd = "# don't touch\ncat > /tmp/0983-x.txt <<'EOF'\nx\nEOF\necho ok"
    expect(lift(cmd).heredocs.length).toBe(1)
    expect(run(cmd)).toMatchObject({ deny: false })
  })
})

describe('LOOSENED: allowed on purpose, denied at a6ed3744 (E6, spec 0.5 a and b)', () => {
  for (const [id, description, cmd] of LOOSENED_ROWS as Row[]) {
    it(`${id} is allowed: ${description}`, () => {
      expect({ id, r: run(cmd) }).toMatchObject({ id, r: { deny: false, hosts: [] } })
    })
  }
  it('the escaped-tag body fed to bash still denies with the host', () => {
    const r = run((DENY_ROWS as Row[]).find((x) => x[0] === 'F-bash-esc-tag')![2])
    expect(r.deny).toBe(true)
    expect(r.hosts).toContain(EXTERNAL_HOST)
  })
})
