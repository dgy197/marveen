// Card 3660cf43 (planned under the duplicate id 3e13973c), node N0 (RED tests): the self-pace gate must read a
// backslash-newline exactly like the shell does. A dangerous command on the line after a continuation that the
// shell does NOT join must be denied; one the shell DOES join into a single word must be read as that word.
//
// (a) corpus verdicts, (b) differential oracle against the real /bin/bash and /bin/zsh (marker-rewritten text only,
// behind a guard: see fixtures/self-pace-continuation/oracle.mjs), (c) structural: no private `\<newline>` replace
// left in the gates, (d) timing.
//
// RED on the unfixed gate: the 13 GAP rows (R1 R2 R3 V1 V3 V4 V5 V13 V17 V18 V19 V20 V21), the extra rows X5 X7 X8
// X12 X13 X14, V22, 62 matrix rows, the structural import check, and the oracle tests that report them.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { readFileSync } from 'node:fs'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision } from '../../scripts/self-pace-gate.mjs'
// @ts-expect-error -- plain .mjs fixture module, no types
import { SPEC_CASES, EXTRA_CASES, BENIGN_CASES, buildMatrix, bigShapes } from './fixtures/self-pace-continuation/cases.mjs'
import {
  rewriteForOracle, runOracle, guardOracleScript, guardSelfTest, freshOracleDir, cleanupOracleDirs,
  shellAvailable, ORACLE_DEFS, OracleRefused, GUARD_SELF_TEST_TEXTS,
// @ts-expect-error -- plain .mjs fixture module, no types
} from './fixtures/self-pace-continuation/oracle.mjs'

type Row = {
  id: string
  command: string
  oracle?: string
  runs?: boolean | null
  expect?: 'DENY' | 'ALLOW'
  reason?: string
  readOnly?: boolean
  noOracle?: string
}
type MatrixRow = Row & { ctx: string; n: number; eol: string; second: string; dangerous: boolean; mustAllow: boolean }

const specRows = SPEC_CASES as Row[]
const extraRows = EXTRA_CASES as Row[]
const benignRows = BENIGN_CASES as Row[]
const matrixRows = buildMatrix() as MatrixRow[]

function verdict(command: string): { deny: boolean; reason?: string } {
  const v = gateDecision('Bash', { command })
  return { deny: v.deny === true, reason: v.reason }
}

// ---------------------------------------------------------------------------------------------------------
// (a) corpus verdicts
// ---------------------------------------------------------------------------------------------------------
describe('(a) the 35 measured shapes: the gate decides what the shell would do', () => {
  for (const row of specRows) {
    it(`${row.id}: ${row.expect}${row.runs ? ' (the shell reaches the dangerous command)' : ''}`, () => {
      const v = verdict(row.command)
      expect(v.deny ? 'DENY' : 'ALLOW', JSON.stringify(row.command)).toBe(row.expect)
      if (row.reason) expect(v.reason).toBe(row.reason)
    })
  }
})

describe('(a) extra edges of the same rule', () => {
  for (const row of extraRows) {
    it(`${row.id}: ${row.expect}${row.reason ? ` (${row.reason})` : ''}`, () => {
      const v = verdict(row.command)
      expect(v.deny ? 'DENY' : 'ALLOW', JSON.stringify(row.command)).toBe(row.expect)
      if (row.reason) expect(v.reason).toBe(row.reason)
    })
  }
})

describe('(a) real multi-line fleet shapes stay ALLOW (no new false deny)', () => {
  it('the corpus has at least 20 of them', () => {
    expect(benignRows.length).toBeGreaterThanOrEqual(20)
  })
  for (const row of benignRows) {
    it(`${row.id}: ALLOW`, () => {
      const v = verdict(row.command)
      expect(v.deny, `${JSON.stringify(row.command)} -> ${v.reason ?? 'no reason'}`).toBe(false)
    })
  }
})

describe('(a) matrix: harmless second line', () => {
  it('every harmless row that the shell closes cleanly stays ALLOW', () => {
    const rows = matrixRows.filter((r) => r.mustAllow)
    const falseDenies = rows.filter((r) => verdict(r.command).deny).map((r) => r.id)
    expect(rows.length).toBeGreaterThan(60)
    expect(falseDenies).toEqual([])
  })
})

// ---------------------------------------------------------------------------------------------------------
// (b) differential oracle
// ---------------------------------------------------------------------------------------------------------
describe('(b) oracle guard', () => {
  it('self-test: a deliberately dangerous text is refused BEFORE any spawn (spy never called)', () => {
    const r = guardSelfTest()
    expect(r.total).toBe(GUARD_SELF_TEST_TEXTS.length * 2)
    expect(r.notRefused).toEqual([])
    expect(r.refused).toBe(r.total)
    expect(r.spawned).toBe(0)
  })

  it('a refusal is an OracleRefused thrown by runOracle itself, with a reason', () => {
    let spawned = 0
    const spy = () => { spawned++; return { stdout: '', status: 0 } }
    for (const text of ['crontab -r', 'echo ok; at now', 'tmux send-keys -t x Enter', "bash -c 'echo x'", 'eval "echo"', 'echo hi > /etc/x']) {
      for (const shell of ['bash', 'zsh']) {
        let caught: unknown
        try { runOracle(text, shell, { spawn: spy, cwd: '/var/empty' }) } catch (e) { caught = e }
        expect(caught, text).toBeInstanceOf(OracleRefused)
        expect(String((caught as { reason?: string }).reason).length).toBeGreaterThan(0)
      }
    }
    expect(spawned).toBe(0)
  })

  it('a rewritten marker text passes the guard and reaches the spawn exactly once (positive control, spy only)', () => {
    let spawned = 0
    const spy = () => { spawned++; return { stdout: '@@M1@@\n', status: 0 } }
    const r = runOracle(rewriteForOracle('crontab -r'), 'bash', { spawn: spy, cwd: '/var/empty' })
    expect(spawned).toBe(1)
    expect(r.danger).toBe(true)
  })

  it('every corpus row is rewritten into marker-only text that the guard accepts; skips are declared and counted', () => {
    const rows = [...specRows, ...extraRows, ...matrixRows]
    const skipped = rows.filter((r) => r.noOracle)
    const refused: string[] = []
    for (const r of rows) {
      if (r.noOracle) continue
      const body = r.oracle ?? rewriteForOracle(r.command)
      const g = guardOracleScript(ORACLE_DEFS + body)
      if (!g.ok) refused.push(`${r.id}: ${g.reason}`)
    }
    expect(refused).toEqual([])
    // a row dropping out of the oracle must be a visible decision, not a silent skip
    // B5, X6: the positive allowlist cannot prove them harmless; X14: backtick; X15-X19: the reviewer's K shapes
    // wrapped in "..." (the guard cannot prove the # inside $( ) inside quotes is a comment). All carry a reason.
    expect(skipped.map((r) => r.id)).toEqual(['B5', 'X6', 'X14', 'X15', 'X16', 'X17', 'X18', 'X19'])
    expect(skipped.filter((r) => !r.noOracle || r.noOracle.length < 10)).toEqual([])
    // most of the corpus still reaches the shell: the allowlist must not hollow the differential test out
    expect(rows.length - skipped.length).toBeGreaterThan(420)
  })

  it('the guard is a positive allowlist: quote-split words, module loading and unknown command words are refused', () => {
    const refusedTexts = [
      'zmodload z""s""h/files', 'zmodload zsh/files; zf_rm x', 'c""rontab -r', 'cr\\ontab -r', "$'cron'tab -r",
      'echo ok; c""rontab -r', 'x=rm; $x -rf y', 'echo $(c""rontab -r)', 'echo ok\nrm x', 'for f in a; do rm x; done',
      'cat <<EOF\n$(rm -rf x)\nEOF', "echo '<<EOF'\nrm -rf x\nEOF", 'echo "a" # c \\\nrm -rf x', 'echo hi > ../x',
    ]
    for (const t of refusedTexts) expect(guardOracleScript(ORACLE_DEFS + t).ok, JSON.stringify(t)).toBe(false)
    const acceptedTexts = ['__m1 -r', 'echo ok; __m2 now', '__m7 <<EOF\nx\nEOF\n__m1', 'case a in a) __m1 ;; esac', 'echo $(__m6)']
    for (const t of acceptedTexts) expect(guardOracleScript(ORACLE_DEFS + t).ok, JSON.stringify(t)).toBe(true)
  })

  it('the rewrite leaves no real scheduler / network word in the executed text', () => {
    for (const r of [...specRows, ...extraRows, ...matrixRows]) {
      if (r.noOracle) continue
      const body = ORACLE_DEFS + (r.oracle ?? rewriteForOracle(r.command))
      expect(body, r.id).not.toMatch(/\b(crontab|at|batch|tmux|launchctl|kill|rm|shutdown|reboot|osascript|curl|wget|nc|ssh|sudo)\b/)
    }
  })
})

for (const shell of ['bash', 'zsh']) {
  describe.skipIf(!shellAvailable(shell))(`(b) differential oracle on /bin/${shell}`, () => {
    const truth = new Map<string, boolean>()
    beforeAll(() => {
      const cwd = freshOracleDir()
      for (const r of [...specRows, ...extraRows, ...matrixRows.filter((m) => m.dangerous)]) {
        if (r.noOracle) continue
        const body = r.oracle ?? rewriteForOracle(r.command)
        const out = runOracle(body, shell, { cwd })
        expect(out.timedOut, `${r.id} timed out`).toBe(false)
        truth.set(r.id, out.danger)
      }
    }, 120_000)
    afterAll(() => cleanupOracleDirs())

    it('the corpus claims about the shell are true (V2 does not run, R1 does, ...)', () => {
      const wrong = [...specRows, ...extraRows]
        .filter((r) => !r.noOracle && r.runs !== null && r.runs !== undefined && truth.get(r.id) !== r.runs)
        .map((r) => `${r.id}: claimed ${r.runs}, ${shell} says ${truth.get(r.id)}`)
      expect(wrong).toEqual([])
    })

    it('whenever the shell reaches the dangerous command, the gate denies (35 shapes + extras)', () => {
      const leaks = [...specRows, ...extraRows]
        .filter((r) => !r.noOracle && !r.readOnly && truth.get(r.id) === true && !verdict(r.command).deny)
        .map((r) => r.id)
      expect(leaks).toEqual([])
    })

    it('whenever the shell reaches the dangerous command, the gate denies (matrix of 288 dangerous rows)', () => {
      const dangerous = matrixRows.filter((m) => m.dangerous)
      const leaks = dangerous.filter((r) => truth.get(r.id) === true && !verdict(r.command).deny).map((r) => r.id)
      // sanity: the oracle must actually see the shell run most rows, or this test proves nothing
      const runs = dangerous.filter((r) => truth.get(r.id) === true).length
      expect(runs).toBeGreaterThan(200)
      expect(leaks).toEqual([])
    })
  })
}

// ---------------------------------------------------------------------------------------------------------
// (c) structural: the gates keep no private backslash-newline replace
// ---------------------------------------------------------------------------------------------------------
describe('(c) structural: one invariant, no private continuation replace', () => {
  const read = (rel: string) => readFileSync(new URL(`../../scripts/${rel}`, import.meta.url), 'utf8')
  const OLD_JOIN = String.raw`replace(/\\\r?\n/`
  const OLD_RUN_JOIN = String.raw`replace(/(\\+)(\r?\n)/`

  for (const rel of ['self-pace-gate.mjs', 'kanban-write-gate.mjs']) {
    it(`${rel} keeps neither the naive nor the run-counting backslash-newline replace`, () => {
      const src = read(rel)
      expect(src.includes(OLD_JOIN), 'old naive join pattern still present').toBe(false)
      expect(src.includes(OLD_RUN_JOIN), 'old run-counting join pattern still present').toBe(false)
    })
  }

  it('self-pace-gate.mjs imports the shared module and calls joinShellLines', () => {
    const src = read('self-pace-gate.mjs')
    expect(src).toMatch(/from\s+['"]\.\/shell-line-join\.mjs['"]/)
    expect(src).toMatch(/\bjoinShellLines\(/)
  })

  it('the shared module has no import and no file or process access (dependency-free, pure)', () => {
    const src = read('shell-line-join.mjs')
    expect(src).not.toMatch(/^\s*import\s/m)
    expect(src).not.toMatch(/\brequire\(|child_process|node:fs|\bprocess\.(argv|env|exit|stdin|stdout|stderr)\b/)
  })
})

// ---------------------------------------------------------------------------------------------------------
// (d) timing: spec E9, 100 ms ceiling per decision on the four large shapes
// ---------------------------------------------------------------------------------------------------------
describe('(d) timing: large continuation shapes decide in under 100 ms', () => {
  const shapes = bigShapes() as Record<string, string>
  for (const [name, command] of Object.entries(shapes)) {
    it(`${name}: ALLOW, best of 5 under 100 ms`, () => {
      expect(verdict(command).deny).toBe(false) // warm-up and verdict
      let best = Infinity
      for (let i = 0; i < 5; i++) {
        const t0 = process.hrtime.bigint()
        gateDecision('Bash', { command })
        best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6)
      }
      expect(best, `${name}: ${best.toFixed(1)} ms`).toBeLessThan(100)
    })
  }
})
