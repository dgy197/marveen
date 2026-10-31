// Card 8e9f4670 (N2, r3): the permission bot's token has exactly one reader,
// readPermissionBotToken() in the vault module. getSecret refuses that id for
// everybody else, so a new in-process caller of the reader would be a new way
// to the token. This pin fails CI when one appears: the only non-test files that
// may mention the reader are the vault module itself and the two legitimate
// callers (the relay startup and the approvals route).
import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const REPO = process.cwd()
const NAME = 'readPermissionBotToken'

const ALLOWED_NON_TEST = new Set([
  'src/web/vault.ts',
  'src/permission-bot-relay/startup.ts',
  'src/web/routes/approvals.ts',
])

const SCANNED_EXT = /\.(ts|tsx|js|mjs|cjs|sh)$/

function walk(dir: string, out: string[]): void {
  for (const name of readdirSync(dir)) {
    if (name === 'node_modules' || name === 'dist' || name === '.git') continue
    const p = join(dir, name)
    const st = statSync(p)
    if (st.isDirectory()) walk(p, out)
    else if (SCANNED_EXT.test(name)) out.push(p)
  }
}

const isTest = (rel: string): boolean => rel.split('/').includes('__tests__') || /\.test\.[a-z]+$/.test(rel)

function referencing(): string[] {
  const files: string[] = []
  walk(join(REPO, 'src'), files)
  walk(join(REPO, 'scripts'), files)
  return files
    .map(f => relative(REPO, f))
    .filter(rel => readFileSync(join(REPO, rel), 'utf-8').includes(NAME))
    .sort()
}

describe('readPermissionBotToken has a closed set of callers', () => {
  const nonTest = referencing().filter(rel => !isTest(rel))

  it('the scan sees the vault module (positive control: the scan really reads src/)', () => {
    expect(nonTest).toContain('src/web/vault.ts')
  })

  it('every allowed caller really uses it (the allowlist holds no dead entries)', () => {
    for (const rel of ALLOWED_NON_TEST) expect(nonTest, rel).toContain(rel)
  })

  it('no other non-test file in src/ or scripts/ references it', () => {
    expect(nonTest.filter(rel => !ALLOWED_NON_TEST.has(rel))).toEqual([])
  })

  it('no shell or .mjs script reads it (scripts/ is out of the allowed set entirely)', () => {
    expect(nonTest.filter(rel => rel.startsWith('scripts/'))).toEqual([])
  })
})

// Card 8e9f4670 (N2-B3): the Vault-reading wrappers must not leave their modules. The relay's
// vaultPermissionBotToken() is module-private, and the approvals route's test seam hands the previous
// reader back only under a test runner (outside one it returns null).
describe('the Vault-reading wrappers stay module-private', () => {
  const read = (rel: string): string => readFileSync(join(REPO, rel), 'utf-8')
  const nonTestFiles = (): string[] => {
    const files: string[] = []
    walk(join(REPO, 'src'), files)
    walk(join(REPO, 'scripts'), files)
    return files.map(f => relative(REPO, f)).filter(rel => !isTest(rel))
  }

  it('no non-test file exports vaultPermissionBotToken', () => {
    const exporting = nonTestFiles().filter(rel => {
      const src = read(rel)
      return /export\s+(async\s+)?(function|const|let|var)\s+vaultPermissionBotToken\b/.test(src)
        || /export\s*\{[^}]*\bvaultPermissionBotToken\b[^}]*\}/.test(src)
    })
    expect(exporting).toEqual([])
  })

  it('positive control: the relay startup still defines vaultPermissionBotToken (as a private function)', () => {
    expect(read('src/permission-bot-relay/startup.ts')).toMatch(/^function vaultPermissionBotToken\(/m)
  })

  it('setPermissionBotTokenReader returns the previous reader only under a test runner', () => {
    const src = read('src/web/routes/approvals.ts')
    const start = src.indexOf('export function setPermissionBotTokenReader(')
    expect(start).toBeGreaterThan(-1)
    const body = src.slice(start, src.indexOf('\n}\n', start))
    const returns = body.match(/\breturn\b[^\n]*/g) ?? []
    expect(returns).toEqual(['return isTestRun() ? prev : null'])
  })
})
