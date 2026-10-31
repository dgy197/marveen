// Static pins of the permission-bot relay (card d7f586bf N4, spec F1.3 / F2 / F5).
// Text-level only: nothing is executed, nothing touches the network.
//
//  a. Single poller: outside the relay (src/permission-bot-relay/** and
//     src/permission-bot-relay.ts) no src file calls getUpdates with the
//     permission bot's Vault token, and the relay itself never calls
//     deleteWebhook.
//  b. child_process, TRANSITIVE (owner decision, Brainy 5834): every file
//     reachable from src/permission-bot-relay.ts through relative imports is
//     scanned; any child_process import (static, dynamic, require) is a failure
//     EXCEPT in exactly two files pinned by path: permission-bot-relay/
//     process-identity.ts and web/keychain.ts.
//  c. Those two files call only execFileSync, with a literal binary.
//  d. The walker is proven not to pass vacuously: it must reach both files over
//     the real import chain, and an in-memory fixture with an extra
//     child_process import must turn it red.
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { posix, join, relative, sep } from 'node:path'

const SRC = join(import.meta.dirname, '..')

// ---- source helpers -----------------------------------------------------------

/** Whole-line and trailing "//" comments and "*" block-comment lines dropped. Used where a comment may legitimately name a forbidden word. */
function codeOnly(src: string): string {
  return src
    .split('\n')
    .filter((l) => {
      const t = l.trim()
      return !(t.startsWith('//') || t.startsWith('/*') || t.startsWith('*'))
    })
    .map((l) => l.replace(/\s\/\/.*$/, ''))
    .join('\n')
}

/** Fail-closed variant for the import scan: only lines that are unmistakably comments are skipped. */
function importScanText(src: string): string {
  // A block comment is dropped only where it starts at a token boundary (so a
  // glob inside a string such as 'a/**/*.ts' never swallows code); code that
  // follows a closed block comment on the same line stays in the scan.
  const noBlocks = src.replace(/(^|[\s;{}()])\/\*[\s\S]*?\*\//g, '$1 ')
  return noBlocks
    .split('\n')
    .filter((l) => !l.trim().startsWith('//'))
    .join('\n')
}

function listTs(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name)
    if (e.isDirectory()) {
      if (e.name === 'node_modules' || e.name === '__tests__') continue
      listTs(p, out)
    } else if (e.isFile() && e.name.endsWith('.ts')) {
      out.push(p)
    }
  }
  return out
}

const relSrc = (abs: string): string => relative(SRC, abs).split(sep).join('/')
const read = (rel: string): string => readFileSync(join(SRC, rel), 'utf8')

const isRelayPath = (rel: string): boolean => rel === 'permission-bot-relay.ts' || rel.startsWith('permission-bot-relay/')

// ---- import walker -------------------------------------------------------------

const STATIC_RE = /\b(?:import|export)\s*(?:type\s+)?(?:[^'";]*?\bfrom\s*)?['"]([^'"]+)['"]/g
const DYNAMIC_RE = /\bimport\s*\(\s*['"]([^'"]+)['"]\s*\)/g
const REQUIRE_RE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g
// Any load whose specifier is not a plain string literal cannot be pinned (E3).
const ANY_DYNAMIC_RE = /\bimport\s*\(/g
const ANY_REQUIRE_RE = /\brequire\s*\(/g
const CREATE_REQUIRE_RE = /\bcreateRequire\b/
const CHILD_PROCESS_SPECS = new Set(['node:child_process', 'child_process'])
const IGNORED_ASSET_RE = /\.(json|css|html|txt|md)$/

function specifiersOf(source: string): string[] {
  const text = importScanText(source)
  const out: string[] = []
  for (const re of [STATIC_RE, DYNAMIC_RE, REQUIRE_RE]) {
    re.lastIndex = 0
    for (let m = re.exec(text); m; m = re.exec(text)) out.push(m[1]!)
  }
  return out
}

/** True when the source loads a module in a way the literal-specifier scan cannot see. */
function hasNonLiteralLoad(source: string): boolean {
  const text = importScanText(source)
  const count = (re: RegExp): number => (text.match(re) ?? []).length
  if (count(ANY_DYNAMIC_RE) !== count(DYNAMIC_RE)) return true
  if (count(ANY_REQUIRE_RE) !== count(REQUIRE_RE)) return true
  return CREATE_REQUIRE_RE.test(text)
}

/** Files are keyed by a posix path relative to the source root ('web/vault.ts'). null = no such file. */
type Reader = (rel: string) => string | null

function resolveRelative(from: string, spec: string, read: Reader): string | null {
  const base = posix.normalize(posix.join(posix.dirname(from), spec))
  const stem = base.replace(/\.(?:js|mjs|ts)$/, '')
  for (const c of [`${stem}.ts`, `${base}.ts`, `${base}/index.ts`, `${stem}/index.ts`]) {
    if (read(c) !== null) return c
  }
  return null
}

interface Walk {
  files: Set<string>
  edges: Map<string, Set<string>>
  childProcessImporters: Set<string>
  nonLiteralLoaders: Set<string>
  unresolved: string[]
}

/** `entry` may be several roots: the walk covers everything reachable from any of them. */
function walkImports(entry: string | string[], read: Reader): Walk {
  const w: Walk = { files: new Set(), edges: new Map(), childProcessImporters: new Set(), nonLiteralLoaders: new Set(), unresolved: [] }
  const queue = Array.isArray(entry) ? [...entry] : [entry]
  while (queue.length > 0) {
    const file = queue.pop()!
    if (w.files.has(file)) continue
    const source = read(file)
    if (source === null) { w.unresolved.push(file); continue }
    w.files.add(file)
    if (hasNonLiteralLoad(source)) w.nonLiteralLoaders.add(file)
    const children = new Set<string>()
    w.edges.set(file, children)
    for (const spec of specifiersOf(source)) {
      if (CHILD_PROCESS_SPECS.has(spec)) { w.childProcessImporters.add(file); continue }
      if (!spec.startsWith('.')) continue // node: builtins and packages
      if (IGNORED_ASSET_RE.test(spec)) continue
      const target = resolveRelative(file, spec, read)
      if (target === null) { w.unresolved.push(`${file} -> ${spec}`); continue }
      children.add(target)
      queue.push(target)
    }
  }
  return w
}

const ENTRY = 'permission-bot-relay.ts'
const PROCESS_IDENTITY = 'permission-bot-relay/process-identity.ts'
const KEYCHAIN = 'web/keychain.ts'
const ALLOWED_CHILD_PROCESS = new Set([PROCESS_IDENTITY, KEYCHAIN])

// The two pinned files may import child_process (exceptions kept as they are);
// NO file may load a module non-literally (import(variable), template import(),
// createRequire, require(variable)).
function offendersOf(w: Walk): string[] {
  const cp = [...w.childProcessImporters].filter((f) => !ALLOWED_CHILD_PROCESS.has(f))
  return [...new Set([...cp, ...w.nonLiteralLoaders])].sort()
}

/** Every relay file is a root of the walk, not just the entry. */
function relayRoots(): string[] {
  return listTs(SRC).map(relSrc).filter(isRelayPath).sort()
}

function realReader(rel: string): string | null {
  if (!rel.endsWith('.ts')) return null
  try {
    const abs = join(SRC, rel)
    return statSync(abs).isFile() ? readFileSync(abs, 'utf8') : null
  } catch {
    return null
  }
}

function memoryReader(files: Record<string, string>): Reader {
  return (rel) => (Object.prototype.hasOwnProperty.call(files, rel) ? files[rel]! : null)
}

// ---- a. single poller ------------------------------------------------------------

describe('a. single poller: nothing outside the relay polls with the permission bot\'s token', () => {
  const outside = listTs(SRC).map(relSrc).filter((r) => !isRelayPath(r))
  // Any of these in a file means it can obtain the permission bot's token.
  const TOKEN_REFS = [
    'PERMISSION_BOT_VAULT_ID',
    'telegram-engedely-bot-token',
    'permission-bot-vault',
    'resolvePermissionBot',
    'setPermissionBotTokenReader',
    'vaultPermissionBotToken',
  ]

  it('the scan is not vacuous: it sees the other pollers and the token readers', () => {
    expect(outside.length).toBeGreaterThan(50)
    const pollers = outside.filter((r) => /\bgetUpdates\b/.test(codeOnly(read(r))))
    expect(pollers).toContain('channel-coordinator/telegram-client.ts')
    const readers = outside.filter((r) => TOKEN_REFS.some((t) => codeOnly(read(r)).includes(t)))
    expect(readers).toContain('web/routes/approvals.ts')
    expect(readers).toContain('web/vault.ts')
  })

  it('no file outside the relay combines getUpdates with a way to the permission bot\'s token (src/web/** included)', () => {
    const bad: string[] = []
    for (const r of outside) {
      const code = codeOnly(read(r))
      if (!/\bgetUpdates\b/.test(code)) continue
      const hit = TOKEN_REFS.find((t) => code.includes(t))
      if (hit) bad.push(`${r} (${hit})`)
    }
    expect(bad).toEqual([])
  })

  it('the web layer (the files that DO read the token) never calls getUpdates at all', () => {
    const bad = outside
      .filter((r) => r.startsWith('web/'))
      .filter((r) => TOKEN_REFS.some((t) => codeOnly(read(r)).includes(t)))
      .filter((r) => /\bgetUpdates\b/.test(codeOnly(read(r))))
    expect(bad).toEqual([])
  })

  it('the relay never calls deleteWebhook (F1.3), in any of its files', () => {
    const relayFiles = listTs(SRC).map(relSrc).filter(isRelayPath)
    expect(relayFiles).toContain(ENTRY)
    expect(relayFiles).toContain('permission-bot-relay/poll-loop.ts')
    const bad = relayFiles.filter((r) => /deleteWebhook|delete_webhook|setWebhook/i.test(codeOnly(read(r))))
    expect(bad).toEqual([])
  })
})

// ---- b. child_process, transitive ---------------------------------------------------

describe('b. child_process: the relay\'s import tree reaches it only through the two pinned files', () => {
  const walk = walkImports(relayRoots(), realReader)

  it('every relay file is a root of the walk', () => {
    expect(relayRoots()).toContain(ENTRY)
    expect(relayRoots()).toContain('permission-bot-relay/apv-handler.ts')
    for (const r of relayRoots()) expect(walk.files.has(r)).toBe(true)
  })

  it('every relative import of the tree resolves to a file', () => {
    expect(walk.unresolved).toEqual([])
  })

  it('no file of the tree loads a module non-literally (import(variable), template import(), createRequire, require(variable))', () => {
    expect([...walk.nonLiteralLoaders].sort()).toEqual([])
  })

  it('no file of the tree other than the two pinned ones imports child_process', () => {
    expect(offendersOf(walk)).toEqual([])
  })

  it('both pinned files really do import it (the allow-list is not stale)', () => {
    expect([...walk.childProcessImporters].sort()).toEqual([KEYCHAIN, PROCESS_IDENTITY].sort())
  })
})

// ---- c. the two exceptions ----------------------------------------------------------

const FORBIDDEN_CALLS_RE = /\b(?:exec|execSync|execFile|spawn|spawnSync|fork)\s*\(/
const SHELL_TRUE_RE = /\bshell\s*:\s*true\b/
const CHILD_PROCESS_IMPORT_RE = /import\s*(?:type\s+)?([^'";]*?)\s*\bfrom\s*['"](?:node:)?child_process['"]/g

function childProcessImportClauses(code: string): string[] {
  CHILD_PROCESS_IMPORT_RE.lastIndex = 0
  const out: string[] = []
  for (let m = CHILD_PROCESS_IMPORT_RE.exec(code); m; m = CHILD_PROCESS_IMPORT_RE.exec(code)) out.push(m[1]!.replace(/\s+/g, ' ').trim())
  return out
}

describe('c. the two child_process users are narrow', () => {
  it('process-identity.ts: execFileSync only, only with the literal /bin/ps', () => {
    const code = codeOnly(read(PROCESS_IDENTITY))
    expect(childProcessImportClauses(code)).toEqual(['{ execFileSync }'])
    const calls = code.match(/\bexecFileSync\s*\(/g) ?? []
    expect(calls.length).toBeGreaterThan(0)
    const literal = code.match(/\bexecFileSync\s*\(\s*'\/bin\/ps'\s*,/g) ?? []
    expect(literal.length).toBe(calls.length)
    expect(FORBIDDEN_CALLS_RE.test(code)).toBe(false)
    expect(SHELL_TRUE_RE.test(code)).toBe(false)
    // no dynamic import / require of child_process next to the static one
    expect(/\bimport\s*\(|\brequire\s*\(/.test(code)).toBe(false)
  })

  it('web/keychain.ts: execFileSync only, only with the SECURITY constant == /usr/bin/security', () => {
    const code = codeOnly(read(KEYCHAIN))
    expect(childProcessImportClauses(code)).toEqual(['{ execFileSync }'])
    // exactly one binding of SECURITY, a const holding the literal
    expect(code.match(/\bSECURITY\s*=/g) ?? []).toHaveLength(1)
    expect(code).toMatch(/^const SECURITY = '\/usr\/bin\/security'$/m)
    const calls = code.match(/\bexecFileSync\s*\(/g) ?? []
    expect(calls.length).toBeGreaterThan(0)
    const viaConst = code.match(/\bexecFileSync\s*\(\s*SECURITY\s*,/g) ?? []
    expect(viaConst.length).toBe(calls.length)
    expect(FORBIDDEN_CALLS_RE.test(code)).toBe(false)
    expect(SHELL_TRUE_RE.test(code)).toBe(false)
    expect(/\bimport\s*\(|\brequire\s*\(/.test(code)).toBe(false)
  })

  it('the pin text checks themselves catch a widened call (negative fixtures)', () => {
    const widened = [
      "import { execFileSync, exec } from 'node:child_process'\nexecFileSync('/bin/ps', [])",
      "import { execFileSync } from 'node:child_process'\nexecFileSync(binary, [])",
      "import { execFileSync } from 'node:child_process'\nexecFileSync('/bin/ps', [], { shell: true })",
      "import { execFileSync } from 'node:child_process'\nspawnSync('/bin/ps')",
    ]
    for (const src of widened) {
      const code = codeOnly(src)
      const calls = code.match(/\bexecFileSync\s*\(/g) ?? []
      const literal = code.match(/\bexecFileSync\s*\(\s*'\/bin\/ps'\s*,/g) ?? []
      const red =
        childProcessImportClauses(code).join() !== '{ execFileSync }' ||
        literal.length !== calls.length ||
        FORBIDDEN_CALLS_RE.test(code) ||
        SHELL_TRUE_RE.test(code)
      expect(red, src).toBe(true)
    }
  })
})

// ---- d. the walker is not vacuous ---------------------------------------------------

describe('d. the walker really reaches the pinned files, and an extra import turns it red', () => {
  it('reaches web/keychain.ts via startup.ts -> web/vault.ts, and process-identity.ts via lock.ts', () => {
    const w = walkImports(ENTRY, realReader)
    expect(w.files.has('permission-bot-relay/startup.ts')).toBe(true)
    expect(w.files.has('web/vault.ts')).toBe(true)
    expect(w.files.has(KEYCHAIN)).toBe(true)
    expect(w.files.has('permission-bot-relay/lock.ts')).toBe(true)
    expect(w.files.has(PROCESS_IDENTITY)).toBe(true)
    expect(w.edges.get(ENTRY)!.has('permission-bot-relay/startup.ts')).toBe(true)
    expect(w.edges.get('permission-bot-relay/startup.ts')!.has('web/vault.ts')).toBe(true)
    expect(w.edges.get('web/vault.ts')!.has(KEYCHAIN)).toBe(true)
    expect(w.edges.get(ENTRY)!.has('permission-bot-relay/lock.ts')).toBe(true)
    expect(w.edges.get('permission-bot-relay/lock.ts')!.has(PROCESS_IDENTITY)).toBe(true)
    // a real tree, not a stub
    expect(w.files.size).toBeGreaterThan(12)
  })

  const clean = {
    'permission-bot-relay.ts': "import { a } from './permission-bot-relay/a.js'\nexport const x = a",
    'permission-bot-relay/a.ts': "import { b } from '../lib/b.js'\nexport const a = b",
    'lib/b.ts': "import { c } from './deep/index.js'\nexport const b = c",
    'lib/deep/index.ts': "import fs from 'node:fs'\nexport const c = fs",
    [PROCESS_IDENTITY]: "import { execFileSync } from 'node:child_process'\nexport const p = execFileSync('/bin/ps', [])",
  }

  it('fixture: the clean set is green, and the pinned path itself is allowed', () => {
    const w = walkImports(ENTRY, memoryReader({
      ...clean,
      'permission-bot-relay/a.ts': "import { b } from '../lib/b.js'\nimport { p } from './process-identity.js'\nexport const a = b + p",
    }))
    expect(w.unresolved).toEqual([])
    expect(w.files.has('lib/deep/index.ts')).toBe(true) // index resolution works
    expect(w.childProcessImporters.has(PROCESS_IDENTITY)).toBe(true)
    expect(offendersOf(w)).toEqual([])
  })

  const variants: Array<[string, string]> = [
    ['static named import', "import { exec } from 'child_process'"],
    ['static node: import', "import cp from 'node:child_process'"],
    ['multi-line named import', "import {\n  spawn,\n  fork,\n} from 'node:child_process'"],
    ['namespace import', "import * as cp from 'node:child_process'"],
    ['type-less side-effect import', "import 'node:child_process'"],
    ['re-export', "export { execSync } from 'node:child_process'"],
    ['dynamic import', "export const f = async () => (await import('node:child_process')).exec"],
    ['require', "const cp = require('child_process')\nexport { cp }"],
    ['import without whitespace around from', "import{exec}from'child_process'"],
    ['quote right after from', "import cp from'node:child_process'"],
    ['import after a closed block comment on the same line', "/* harmless */ import { exec } from 'child_process'"],
    ['import after a block comment that closes mid-line', "/* a\n b */ import cp from 'child_process'"],
  ]
  for (const [name, line] of variants) {
    it(`fixture: an extra child_process ${name} in a transitive file turns the pin red`, () => {
      const w = walkImports(ENTRY, memoryReader({ ...clean, 'lib/deep/index.ts': `${line}\nexport const c = 1` }))
      expect(w.files.has('lib/deep/index.ts')).toBe(true)
      expect(offendersOf(w)).toEqual(['lib/deep/index.ts'])
    })
  }

  const nonLiteral: Array<[string, string]> = [
    ['import(variable)', "export const f = async (m: string) => import(m)"],
    ['template-literal import()', "export const f = async () => import(`node:child_${'process'}`)"],
    ['import() of a concatenated specifier', "export const f = async () => import('node:child_' + 'process')"],
    ['createRequire', "import { createRequire } from 'node:module'\nexport const r = createRequire(import.meta.url)"],
    ['require(variable)', "declare const require: (m: string) => unknown\nexport const f = (m: string) => require(m)"],
  ]
  for (const [name, line] of nonLiteral) {
    it(`fixture: a ${name} in a transitive file turns the pin red`, () => {
      const w = walkImports(ENTRY, memoryReader({ ...clean, 'lib/deep/index.ts': `${line}\nexport const c = 1` }))
      expect(offendersOf(w)).toEqual(['lib/deep/index.ts'])
    })
  }

  it('fixture: a relay file that the entry does not import is still walked as a root', () => {
    const files = { ...clean, 'permission-bot-relay/orphan.ts': "import { exec } from 'child_process'\nexport const o = exec" }
    expect(offendersOf(walkImports(ENTRY, memoryReader(files)))).toEqual([])
    expect(offendersOf(walkImports([ENTRY, 'permission-bot-relay/orphan.ts'], memoryReader(files)))).toEqual(['permission-bot-relay/orphan.ts'])
  })

  it('fixture: literal loads and comments that merely mention the words stay green', () => {
    const w = walkImports(ENTRY, memoryReader({
      ...clean,
      'lib/deep/index.ts': "// import(x) and createRequire in a comment\n/* require(y) */ import fs from 'node:fs'\nconst g = 'a/**/*.ts'\nexport const c = [fs, g, import('node:fs')]",
    }))
    expect(offendersOf(w)).toEqual([])
  })

  it('fixture: the same import in a file with a different path than the two pinned ones is red even if it is named alike', () => {
    const w = walkImports(ENTRY, memoryReader({
      ...clean,
      'permission-bot-relay/a.ts': "import { x } from '../lib/process-identity.js'\nexport const a = x",
      'lib/process-identity.ts': "import { execFileSync } from 'node:child_process'\nexport const x = execFileSync('/bin/ps', [])",
    }))
    expect(offendersOf(w)).toEqual(['lib/process-identity.ts'])
  })

  it('fixture: a commented-out child_process import is not an import, an unreachable file is not scanned', () => {
    const w = walkImports(ENTRY, memoryReader({
      ...clean,
      'lib/deep/index.ts': "// import { exec } from 'child_process'\n/*\n * import cp from 'node:child_process'\n */\nexport const c = 1",
      'unrelated/tool.ts': "import { exec } from 'node:child_process'",
    }))
    expect(offendersOf(w)).toEqual([])
    expect(w.files.has('unrelated/tool.ts')).toBe(false)
  })

  it('fixture: an unresolvable relative import is reported, not silently skipped', () => {
    const w = walkImports(ENTRY, memoryReader({ ...clean, 'lib/deep/index.ts': "import { z } from './missing.js'\nexport const c = z" }))
    expect(w.unresolved).toEqual(['lib/deep/index.ts -> ./missing.js'])
  })
})
