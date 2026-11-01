import { describe, it, expect } from 'vitest'
import { homedir } from 'node:os'
import { join } from 'node:path'
import { sandboxGateVerdict, assertInSafeVitestSandbox } from './setup/safe-vitest-sandbox-gate.js'

// Card 9b4d8a33: the suite itself refuses to run outside the scripts/safe-vitest.sh sandbox, so a vitest
// started any other way (npx vitest, npm test, a wrapper script the command gate cannot read) stops before
// any test runs. The decision is a pure function; the probe write is injected.

const ROOT = '/Users/someone/marveen-wt/card'
const RUN_TMP = '/private/var/folders/ab/cdef123/T/safe-vitest.Ab12Cd34'
const eperm = () => Object.assign(new Error('EPERM: operation not permitted'), { code: 'EPERM' })

function verdict(over: Partial<Parameters<typeof sandboxGateVerdict>[0]> = {}) {
  return sandboxGateVerdict({
    platform: 'darwin',
    checkoutRoot: ROOT,
    tmpdir: RUN_TMP,
    probeDir: homedir(),
    tryWrite: () => { throw eperm() },
    ...over,
  })
}

describe('9b4d8a33: vitest runs only inside the safe-vitest sandbox', () => {
  it('allows the run inside the sandbox (run-dir TMPDIR and a $HOME write refused with EPERM)', () => {
    expect(verdict()).toEqual({ ok: true })
  })

  it('refuses when a write to $HOME succeeds (no sandbox), and cleans the probe up', () => {
    const removed: string[] = []
    const v = verdict({ tryWrite: () => 'written', removeProbe: (p: string) => { removed.push(p) } })
    expect(v.ok).toBe(false)
    expect(removed).toHaveLength(1)
    expect(removed[0].startsWith(join(homedir(), '.safe-vitest-probe-'))).toBe(true)
  })

  it('refuses when TMPDIR is not a safe-vitest run dir, even if the write is refused', () => {
    expect(verdict({ tmpdir: '/var/folders/ab/cdef123/T/' }).ok).toBe(false)
    expect(verdict({ tmpdir: '/tmp' }).ok).toBe(false)
    expect(verdict({ tmpdir: undefined }).ok).toBe(false)
    expect(verdict({ tmpdir: '/private/var/folders/ab/cdef123/T/safe-vitest.Ab12Cd34/../x' }).ok).toBe(false)
  })

  it('refuses when the probe fails for another reason than a denied write (cannot verify)', () => {
    const enoent = () => { throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' }) }
    expect(verdict({ tryWrite: enoent }).ok).toBe(false)
  })

  it('accepts EACCES as a refused write too', () => {
    const eacces = () => { throw Object.assign(new Error('EACCES'), { code: 'EACCES' }) }
    expect(verdict({ tryWrite: eacces })).toEqual({ ok: true })
  })

  it('refuses when the probe dir lies inside the checkout or the run dir (the sandbox allows those writes)', () => {
    expect(verdict({ probeDir: ROOT }).ok).toBe(false)
    expect(verdict({ probeDir: join(ROOT, 'sub') }).ok).toBe(false)
    expect(verdict({ probeDir: RUN_TMP }).ok).toBe(false)
  })

  it('the refusal names safe-vitest.sh with its path and the worktree root', () => {
    const v = verdict({ tryWrite: () => 'written', removeProbe: () => {} })
    expect(v.ok).toBe(false)
    if (v.ok) return
    expect(v.reason).toContain(join(ROOT, 'scripts', 'safe-vitest.sh'))
    expect(v.reason).toContain(ROOT)
  })

  it('named exception: no macOS sandbox-exec off darwin (CI on ubuntu, a Linux install)', () => {
    expect(verdict({ platform: 'linux', tmpdir: '/tmp', tryWrite: () => 'written' })).toEqual({ ok: true, exempt: 'non-darwin' })
  })

  it('there is no environment override on darwin', () => {
    // The verdict takes no env input at all: CI=true / GITHUB_ACTIONS=true on the Mac change nothing.
    expect(sandboxGateVerdict.length).toBe(1)
    expect(verdict({ tryWrite: () => 'written', removeProbe: () => {} }).ok).toBe(false)
  })

  it('assertInSafeVitestSandbox throws the refusal and passes inside the sandbox', () => {
    expect(() => assertInSafeVitestSandbox({ ...baseInput(), tryWrite: () => 'written', removeProbe: () => {} })).toThrow(/safe-vitest\.sh/)
    expect(() => assertInSafeVitestSandbox(baseInput())).not.toThrow()
  })

  it('this very run is inside the sandbox (the suite is started by safe-vitest.sh)', () => {
    // The real probe, no seams: if this test runs at all, globalSetup already passed; this checks it again.
    expect(() => assertInSafeVitestSandbox()).not.toThrow()
  })
})

function baseInput() {
  return { platform: 'darwin' as const, checkoutRoot: ROOT, tmpdir: RUN_TMP, probeDir: homedir(), tryWrite: () => { throw eperm() } }
}
