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
