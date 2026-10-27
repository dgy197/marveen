// fec6335f, BE-1 review point 5: a .env that exists but cannot be read must not
// read as `allow`, and that answer must not be kept for the life of the dashboard
// process. Before the fix readEnvFile() swallowed every read error into {} ->
// allow, and interactiveKeyPolicy() cached it.
//
// The .env is a throwaway one: CLAUDECLAW_ENV_DIR is set before env.ts is
// imported (it is read at import time), so the checkout's own .env is never read.
import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

const dir = mkdtempSync(join(tmpdir(), 'ikg-policy-read-'))
process.env.CLAUDECLAW_ENV_DIR = dir
const envPath = join(dir, '.env')

const G = await import('../web/interactive-key-guard.js')

beforeAll(() => { G.setInteractiveKeyPolicyForTest(null) })
afterAll(() => {
  G.setInteractiveKeyPolicyForTest(null)
  try { chmodSync(envPath, 0o600) } catch { /* may be a dir */ }
  rmSync(dir, { recursive: true, force: true })
  delete process.env.CLAUDECLAW_ENV_DIR
})

describe('readInteractiveKeyPolicyDetailed: an unreadable .env is forbid, and not definitive', () => {
  it('no .env: allow, definitive (the upstream default)', () => {
    expect(G.readInteractiveKeyPolicyDetailed(join(dir, 'absent.env'))).toEqual({ policy: 'allow', definitive: true })
  })
  it('a .env that is a directory (EISDIR): forbid, not definitive', () => {
    const d = join(dir, 'isdir.env')
    mkdirSync(d)
    expect(G.readInteractiveKeyPolicyDetailed(d)).toEqual({ policy: 'forbid', definitive: false })
  })
  it.skipIf(process.getuid?.() === 0)('a .env without read permission (EACCES): forbid, not definitive', () => {
    const p = join(dir, 'noread.env')
    writeFileSync(p, 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\n')
    chmodSync(p, 0o000)
    expect(G.readInteractiveKeyPolicyDetailed(p)).toEqual({ policy: 'forbid', definitive: false })
    chmodSync(p, 0o600)
  })
})

describe.skipIf(process.getuid?.() === 0)('interactiveKeyPolicy(): the process cache does not keep a forced forbid', () => {
  it('unreadable -> forbid (not cached); readable allow -> allow (cached from then on)', () => {
    writeFileSync(envPath, 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\n')
    chmodSync(envPath, 0o000)
    expect(G.interactiveKeyPolicy()).toBe('forbid')
    chmodSync(envPath, 0o600)
    expect(G.interactiveKeyPolicy()).toBe('allow')
    writeFileSync(envPath, 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')
    expect(G.interactiveKeyPolicy()).toBe('allow') // a definitive read is kept, as documented
  })
})
