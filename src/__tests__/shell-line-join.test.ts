// Card 3660cf43 (planned under the duplicate id 3e13973c), node N0 (RED tests): unit tests of the one shared
// backslash-newline joiner, scripts/shell-line-join.mjs (joinShellLines), written against spec.md section 3
// (rules 1-7). The module does not exist yet, so this whole file is RED until node N1 adds it; the expected
// strings below are what the shell itself produces (measured on /bin/bash 3.2.57 and /bin/zsh 5.9, spec section 2).
//
// Notation: BS = one backslash, NL = LF, CRLF = CR LF.
import { describe, it, expect } from 'vitest'
// @ts-expect-error -- plain .mjs hook script, no types (new module, written in node N1)
import * as joinModule from '../../scripts/shell-line-join.mjs'
// @ts-expect-error -- plain .mjs hook script, no types
import * as gate from '../../scripts/self-pace-gate.mjs'
// @ts-expect-error -- plain .mjs fixture module, no types
import { BS, NL, CRLF, SPEC_CASES, EXTRA_CASES, BENIGN_CASES, allCommands, bigShapes } from './fixtures/self-pace-continuation/cases.mjs'

type Info = { exact?: boolean; reason?: string | null }
function join(src: string): { out: string; info: Info } {
  const info: Info = {}
  const out = joinModule.joinShellLines(src, info) as string
  return { out, info }
}
const J = (src: string): string => join(src).out
const same = (src: string): void => {
  expect(J(src)).toBe(src)
}

describe('module contract', () => {
  it('exports joinShellLines; info defaults to a fresh object; clean input is exact with reason null', () => {
    expect(typeof joinModule.joinShellLines).toBe('function')
    expect(joinModule.joinShellLines('ls -la')).toBe('ls -la')
    const { out, info } = join('ls -la')
    expect(out).toBe('ls -la')
    expect(info.exact).toBe(true)
    expect(info.reason ?? null).toBeNull()
  })

  it('an info object that is reused is reset on every call', () => {
    const info: Info = { exact: false, reason: 'stale' }
    joinModule.joinShellLines('ls', info)
    expect(info.exact).toBe(true)
    expect(info.reason ?? null).toBeNull()
  })

  it('the empty string and a lone newline are fixed points', () => {
    same('')
    same(NL)
    same(CRLF)
  })
})

describe('rule 1: only backslash + LF continues; the pair vanishes, nothing takes its place', () => {
  it('a lone continuation joins the two halves of a word (cron\\<NL>tab = crontab)', () => {
    expect(J(`cron${BS}${NL}tab -r`)).toBe('crontab -r')
    expect(J(`tm${BS}${NL}ux send-keys -t x Enter`)).toBe('tmux send-keys -t x Enter')
    expect(J(`echo ok; c${BS}${NL}rontab -r`)).toBe('echo ok; crontab -r')
    expect(J(`echo a${BS}${NL}  b`)).toBe('echo a  b')
  })

  it('an EVEN run is escaped backslashes: nothing joins and the newline stays a newline', () => {
    for (const n of [2, 4, 6]) same(`echo a${BS.repeat(n)}${NL}crontab -r`)
  })

  it('an ODD run: the last backslash and the newline vanish, the escaped pairs stay', () => {
    expect(J(`echo a${BS}${NL}crontab -r`)).toBe('echo acrontab -r')
    expect(J(`echo a${BS.repeat(3)}${NL}crontab -r`)).toBe(`echo a${BS.repeat(2)}crontab -r`)
    expect(J(`echo a${BS.repeat(5)}${NL}crontab -r`)).toBe(`echo a${BS.repeat(4)}crontab -r`)
  })

  it('inside "..." and $(...) a continuation joins; an even run does not', () => {
    expect(J(`echo "a${BS}${NL}b"`)).toBe('echo "ab"')
    same(`echo "a${BS}${BS}${NL}b"`)
    expect(J(`echo $(echo a${BS}${NL}b)`)).toBe('echo $(echo ab)')
    expect(J(`echo "$(echo a${BS}${NL}b)"`)).toBe('echo "$(echo ab)"')
    same(`echo $(echo a${BS}${BS}${NL}crontab -r)`)
  })

  it('backslash + CR is an ordinary escape, not a continuation: the CR LF line break survives', () => {
    for (const n of [1, 2, 3, 4]) same(`echo a${BS.repeat(n)}${CRLF}crontab -r`)
    same(`printf x a b ${BS}${CRLF}  c`)
  })

  it('a continuation at the very start or end of the text, and two in a row', () => {
    expect(J(`${BS}${NL}crontab -r`)).toBe('crontab -r')
    expect(J(`crontab -r ${BS}${NL}`)).toBe('crontab -r ')
    expect(J(`echo a ${BS}${NL}${BS}${NL}crontab -r`)).toBe('echo a crontab -r')
    expect(J(`echo a${BS}${BS}${NL}${BS}${NL}crontab -r`)).toBe(`echo a${BS}${BS}${NL}crontab -r`)
  })
})

describe('rule 2: no joining inside single quotes, $\'...\', quoted heredoc bodies and comments', () => {
  it("'...' and $'...' keep the backslash and the newline", () => {
    same(`echo 'a${BS}${NL}b'`)
    same(`echo $'a${BS}${NL}b'`)
    same(`echo 'a${BS}${NL}crontab -r'`)
  })

  it('a quoted heredoc body is data, whatever the form of the quoted tag', () => {
    for (const op of [`<<'EOF'`, `<<"EOF"`, `<<${BS}EOF`, `<<E"OF"`, `<<E'O'F`, `<<-'EOF'`]) {
      const src = `cat ${op}${NL}x${BS}${NL}EOF${NL}crontab -r`
      const r = join(src)
      expect(r.out, op).toBe(src)
      expect(r.info.exact, op).toBe(true)
    }
  })

  it('a comment keeps its trailing backslash: the next line is a new command', () => {
    same(`# note ${BS}${NL}crontab -r`)
    same(`ls -la # tail ${BS}${NL}crontab -r`)
    same(`printf x # c ${BS}${BS}${BS}${NL}at now`)
  })
})

describe('rule 3: a comment starts at a word-initial #', () => {
  it('# in the middle of a word, after $ or after an escape is not a comment', () => {
    expect(J(`echo a#b${BS}${NL}c`)).toBe('echo a#bc')
    expect(J(`echo $# ${BS}${NL}ls`)).toBe('echo $# ls')
    expect(J(`echo ${BS}# x ${BS}${NL}ls`)).toBe(`echo ${BS}# x ls`)
    expect(J(`echo "a #c ${BS}${NL}b"`)).toBe('echo "a #c b"')
    expect(J(`echo "# x" ${BS}${NL}crontab -r`)).toBe('echo "# x" crontab -r')
  })

  it('after whitespace or one of ; & | ( ) < > the # opens a comment that a trailing backslash does not extend', () => {
    for (const lead of [' ', ';', '&', '|', '(', ')', '<', '>']) same(`echo a${lead}# c ${BS}${NL}ls`)
  })

  it('the comment ends at the LF and joining resumes on the next line', () => {
    expect(J(`echo a # c${NL}b ${BS}${NL}c`)).toBe(`echo a # c${NL}b c`)
  })

  it('a comment inside $(...) also ends at the newline (the conservative reading, zsh)', () => {
    same(`echo $(echo a # c ${BS}${NL}crontab -r)`)
  })
})

describe('rule 4: the context is decided on the JOINED stream', () => {
  it('<\\<NL><\'EOF\' is a quoted heredoc operator, so the body is not joined', () => {
    expect(J(`cat <${BS}${NL}<'EOF'${NL}x${BS}${NL}EOF${NL}crontab -r`)).toBe(`cat <<'EOF'${NL}x${BS}${NL}EOF${NL}crontab -r`)
    expect(J(`cat <<${BS}${NL}'EOF'${NL}x${BS}${NL}EOF${NL}ls`)).toBe(`cat <<'EOF'${NL}x${BS}${NL}EOF${NL}ls`)
  })

  it('a continuation before the # makes it word-initial: " \\<NL>#c" is a comment, "a\\<NL>#b" is one word', () => {
    expect(J(`echo x ${BS}${NL}#c ${BS}${NL}crontab -r`)).toBe(`echo x #c ${BS}${NL}crontab -r`)
    expect(J(`echo a${BS}${NL}#b ${BS}${NL}crontab -r`)).toBe('echo a#b crontab -r')
  })

  it('$\\<NL>( opens a substitution and $\\<NL>\' opens an ANSI-C quote', () => {
    expect(J(`echo $${BS}${NL}(echo a${BS}${NL}b)`)).toBe('echo $(echo ab)')
    expect(J(`echo $${BS}${NL}'a${BS}${NL}b'`)).toBe(`echo $'a${BS}${NL}b'`)
  })
})

describe('rule 5: heredocs', () => {
  it('an unquoted body is joined, and the terminator is looked for on the JOINED line (V12)', () => {
    expect(J(`cat <<EOF${NL}line a ${BS}${NL}line b${NL}EOF${NL}ls`)).toBe(`cat <<EOF${NL}line a line b${NL}EOF${NL}ls`)
    const r = join(`cat <<EOF${NL}x${BS}${NL}EOF${NL}crontab -r`)
    expect(r.out).toBe(`cat <<EOF${NL}xEOF${NL}crontab -r`)
    expect(r.info.exact).toBe(false)
  })

  it('<<- strips leading TABs before the terminator match, quoted or not', () => {
    same(`cat <<-'EOF'${NL}\tx${BS}${NL}\tEOF${NL}crontab -r`)
    expect(J(`cat <<-EOF${NL}\tx${BS}${NL}\ty${NL}\tEOF${NL}ls`)).toBe(`cat <<-EOF${NL}\tx\ty${NL}\tEOF${NL}ls`)
    expect(join(`cat <<-'EOF'${NL}\tx${BS}${NL}\tEOF${NL}crontab -r`).info.exact).toBe(true)
  })

  it('two heredocs on one line: the bodies follow in order, each with its own quoting', () => {
    const r = join(`cat <<'A'; cat <<B${NL}x${BS}${NL}A${NL}y${BS}${NL}z${NL}B${NL}ls`)
    expect(r.out).toBe(`cat <<'A'; cat <<B${NL}x${BS}${NL}A${NL}yz${NL}B${NL}ls`)
    expect(r.info.exact).toBe(true)
  })

  it('the operator line itself continues; the body starts after the logical line', () => {
    expect(J(`cat <<'EOF' ${BS}${NL}  | wc -l${NL}x${BS}${NL}EOF${NL}ls`)).toBe(`cat <<'EOF'   | wc -l${NL}x${BS}${NL}EOF${NL}ls`)
  })

  it('<<< is a here-string, not a heredoc: the following lines are commands', () => {
    same(`cat <<< a${BS}${BS}${NL}crontab -r`)
    expect(J(`cat <<< a${BS}${NL}crontab -r`)).toBe('cat <<< acrontab -r')
    expect(J(`cat <<< x${NL}y${BS}${NL}z`)).toBe(`cat <<< x${NL}yz`)
    same(`cat <<< 'a${BS}'${NL}crontab -r`)
  })

  it('a << inside quotes is text, not a heredoc operator', () => {
    expect(J(`echo "<<EOF"${NL}x${BS}${NL}y`)).toBe(`echo "<<EOF"${NL}xy`)
    expect(J(`echo '<<EOF' ${BS}${NL}ls`)).toBe("echo '<<EOF' ls")
  })
})

describe('rule 6: exact=false when no sure reading exists (the text is still the rules\' reading)', () => {
  it('unterminated single quote: no joining, inexact', () => {
    const r = join(`echo 'abc${BS}${NL}def`)
    expect(r.out).toBe(`echo 'abc${BS}${NL}def`)
    expect(r.info.exact).toBe(false)
    expect(String(r.info.reason ?? '').length).toBeGreaterThan(0)
  })

  it('unterminated double quote: joined as inside "...", inexact', () => {
    const r = join(`echo "abc${BS}${NL}def`)
    expect(r.out).toBe('echo "abcdef')
    expect(r.info.exact).toBe(false)
  })

  it('unterminated heredoc: body untouched (quoted) and inexact', () => {
    const r = join(`cat <<'EOF'${NL}x${BS}${NL}`)
    expect(r.out).toBe(`cat <<'EOF'${NL}x${BS}${NL}`)
    expect(r.info.exact).toBe(false)
  })

  it('a backslash + LF inside backticks is inexact (the backtick halves the run, V22); a plain backtick is exact', () => {
    expect(join(`echo \`echo a${BS}${BS}${NL}crontab -r\``).info.exact).toBe(false)
    expect(join(`echo \`echo a${BS}${NL}b\``).info.exact).toBe(false)
    expect(join('echo `date`').info.exact).toBe(true)
    const r = join(`echo \`date\` ${BS}${NL}ls`)
    expect(r.out).toBe('echo `date` ls')
    expect(r.info.exact).toBe(true)
  })

  // Fix round 1, B1: the `case` keyword was read on the RAW stream, so a continuation inside it hid it, the
  // pattern `)` closed the substitution and a "comment" of the dq context swallowed the next command.
  it('a case keyword inside $(...) is inexact, also when a continuation splits it (ca\\<NL>se, case\\<NL> a)', () => {
    const rows: Array<[string, string]> = [
      ['K1 ca\\<NL>se', `echo "$(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)"`],
      ['K2 case\\<NL> blank', `echo "$(case${BS}${NL} a in a) # c ${BS}${NL}crontab -r ;; esac)"`],
      ['K3 unsplit', `echo "$(case a in a) # c ${BS}${NL}crontab -r ;; esac)"`],
      ['K5 at now', `echo "$(ca${BS}${NL}se a in a) # c ${BS}${NL}at now ;; esac)"`],
      ['K6 unwrapped', `echo $(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)`],
      ['inside ${x:-...}', `echo "\${x:-$(ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)}"`],
      ['two splits', `echo $(c${BS}${NL}a${BS}${NL}s${BS}${NL}e a in a) # c ${BS}${NL}crontab -r ;; esac)`],
      ['continuation before and inside', `echo $( ${BS}${NL}ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)`],
      ['after a separator', `echo $(true; ca${BS}${NL}se a in a) # c ${BS}${NL}crontab -r ;; esac)`],
    ]
    for (const [name, src] of rows) {
      const r = join(src)
      expect(r.info.exact, name).toBe(false)
      expect(r.info.reason, name).toMatch(/case inside|unmatched \)/)
    }
  })

  it('the keyword rule has no false hit on words that merely contain or continue "case"', () => {
    for (const src of [
      `echo $(echo showcase${BS}${NL}x)`,
      `echo $(echo case_x ${BS}${NL}y)`,
      `echo $(ca${BS}${NL}sex a ${BS}${NL}b)`,
      `echo $(echo a ${BS}${NL}b) case`,
    ]) {
      const r = join(src)
      expect(r.info.exact, src).toBe(true)
    }
  })

  it('a `)` that closes $(...) after an `in` word is inexact too (a case pattern close looks the same)', () => {
    const r = join(`echo $(for x in a b; do echo ${BS}${NL}$x; done)`)
    expect(r.info.exact).toBe(false)
    expect(r.info.reason).toMatch(/unmatched \)/)
    // no `in` word, no hit
    expect(join(`echo $(echo a ${BS}${NL}b)`).info.exact).toBe(true)
    expect(join(`echo $(echo inside ${BS}${NL}b)`).info.exact).toBe(true)
  })

  it('exact stays true on the clean shapes of the card', () => {
    const exactRows = ['R1', 'R2', 'R3', 'V1', 'V3', 'V4', 'V5', 'V8', 'V9', 'V10', 'V11', 'V13', 'V14', 'V15', 'V18', 'V21', 'B7', 'B9']
    for (const id of exactRows) {
      const row = (SPEC_CASES as Array<{ id: string; command: string }>).find((r) => r.id === id)!
      expect(join(row.command).info.exact, id).toBe(true)
    }
  })
})

describe('rule 7: idempotence, shape invariants, no throw', () => {
  const rows = [...SPEC_CASES, ...EXTRA_CASES, ...BENIGN_CASES] as Array<{ id: string; command: string }>

  it('joinShellLines(joinShellLines(x)) === joinShellLines(x) on every row of the corpus and the matrix', () => {
    const bad: string[] = []
    for (const command of allCommands() as string[]) {
      const once = J(command)
      if (J(once) !== once) bad.push(JSON.stringify(command).slice(0, 60))
    }
    expect(bad).toEqual([])
  })

  it('a text without backslash-newline comes back unchanged (benign multi-line shapes without it)', () => {
    for (const command of ['ls -la', `echo a${NL}echo b`, `echo a${CRLF}echo b`, `cat <<'EOF'${NL}x${NL}EOF`]) same(command)
  })

  it('the joined text never contains an odd-run backslash + LF outside a comment, quote or quoted heredoc', () => {
    // the plain shapes: after joining, no continuation is left to join
    for (const command of [`echo a${BS}${NL}b`, `echo a${BS.repeat(3)}${NL}b`, `a${BS}${NL}b${BS}${NL}c`, `echo "x${BS}${NL}y"`]) {
      expect(J(command)).not.toMatch(/(?<!\\)(\\\\)*\\\n/)
    }
  })

  it('B-rows of the card keep their reading: B1 joins to one curl line, B5 keeps the CR LF break', () => {
    const b1 = rows.find((r) => r.id === 'B1')!.command
    expect(J(b1)).toBe('curl -s   -H "Accept: application/json"   http://localhost:3420/api/kanban')
    const b5 = rows.find((r) => r.id === 'B5')!.command
    expect(J(b5)).toBe(`printf '%s\\n' a   b ${BS}${CRLF}  c`)
  })

  it('fuzz: 1000 random byte strings never throw, return a string, a boolean exact, shrink or keep length, and are idempotent', () => {
    // mulberry32, fixed seed: the same 1000 strings on every run
    let seed = 0x3660cf43
    const rnd = () => {
      seed = (seed + 0x6d2b79f5) >>> 0
      let t = seed
      t = Math.imul(t ^ (t >>> 15), t | 1)
      t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296
    }
    const alphabet = [BS, BS, BS, NL, NL, '\r', "'", '"', '`', '$', '(', ')', '#', '<', '<', '>', ' ', ' ', 'a', 'b', 'E', 'O', 'F', '-', '\t', ';', '&', '|', '{', '}']
    const failures: string[] = []
    for (let k = 0; k < 1000; k++) {
      const len = Math.floor(rnd() * 60)
      let s = ''
      for (let i = 0; i < len; i++) s += rnd() < 0.08 ? String.fromCharCode(Math.floor(rnd() * 256)) : alphabet[Math.floor(rnd() * alphabet.length)]
      try {
        const r = join(s)
        if (typeof r.out !== 'string') failures.push(`not a string: ${JSON.stringify(s)}`)
        else if (typeof r.info.exact !== 'boolean') failures.push(`exact not boolean: ${JSON.stringify(s)}`)
        else if (r.out.length > s.length) failures.push(`grew: ${JSON.stringify(s)}`)
        else if (!s.includes(`${BS}${NL}`) && r.out !== s) failures.push(`changed without a continuation: ${JSON.stringify(s)}`)
        else if (J(r.out) !== r.out) failures.push(`not idempotent: ${JSON.stringify(s)}`)
      } catch (e) {
        failures.push(`threw ${String(e)}: ${JSON.stringify(s)}`)
      }
      if (failures.length >= 5) break
    }
    expect(failures).toEqual([])
  })

  it('runs in linear time on the four large shapes (50 ms ceiling, best of 3)', () => {
    for (const [name, command] of Object.entries(bigShapes() as Record<string, string>)) {
      J(command) // warm-up
      let best = Infinity
      for (let i = 0; i < 3; i++) {
        const t0 = process.hrtime.bigint()
        J(command)
        best = Math.min(best, Number(process.hrtime.bigint() - t0) / 1e6)
      }
      expect(best, `${name}: ${best.toFixed(1)} ms`).toBeLessThan(50)
    }
  })
})

// Spec section 3 rule 7, last sentence: the gate's exported helpers join on their own entrance, so a caller that
// passes raw text (kanban-write-gate, the egress parser) gets the same answer as one that passes joined text.
describe('the gate helpers join on their own entrance (raw text equals pre-joined text)', () => {
  const commands = allCommands() as string[]
  const pairs = commands.map((c) => [c, J(c)] as const)

  it('splitSegments', () => {
    const bad = pairs.filter(([raw, joined]) => JSON.stringify(gate.splitSegments(raw)) !== JSON.stringify(gate.splitSegments(joined)))
    expect(bad.map(([raw]) => JSON.stringify(raw).slice(0, 60))).toEqual([])
  })

  it('maskInertLiterals', () => {
    const bad = pairs.filter(([raw, joined]) => JSON.stringify(gate.maskInertLiterals(raw, [], true)) !== JSON.stringify(gate.maskInertLiterals(joined, [], true)))
    expect(bad.map(([raw]) => JSON.stringify(raw).slice(0, 60))).toEqual([])
  })

  it('quotedWords', () => {
    const bad = pairs.filter(([raw, joined]) => JSON.stringify(gate.quotedWords(raw)) !== JSON.stringify(gate.quotedWords(joined)))
    expect(bad.map(([raw]) => JSON.stringify(raw).slice(0, 60))).toEqual([])
  })

  it('shellSegments', () => {
    const bad = pairs.filter(([raw, joined]) => JSON.stringify(gate.shellSegments(raw)) !== JSON.stringify(gate.shellSegments(joined)))
    expect(bad.map(([raw]) => JSON.stringify(raw).slice(0, 60))).toEqual([])
  })

  it('scheduleSurfaceVariants offers the canonical join and keeps the old naive join as an extra variant', () => {
    const missing: string[] = []
    for (const [raw, joined] of pairs) {
      const variants = gate.scheduleSurfaceVariants(raw) as string[]
      const naive = raw.replace(/\\\r?\n/g, '')
      if (!variants.includes(joined) || !variants.includes(naive)) missing.push(JSON.stringify(raw).slice(0, 60))
    }
    expect(missing).toEqual([])
  })
})
