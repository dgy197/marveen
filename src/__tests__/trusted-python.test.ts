import { describe, it, expect } from 'vitest'
import { existsSync, mkdtempSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  NO_TRUSTED_PYTHON_MESSAGE,
  TRUSTED_ENV_ALLOWLIST,
  TRUSTED_PATH,
  TRUSTED_PYTHON_CANDIDATES,
  resolveTrustedPython,
  trustedPythonEnv,
  type StatLike,
  type TrustedPythonDeps,
} from '../trusted-python.js'
import { authorizeSend, buildSendEnvelope } from '../graph-send-authorize.js'
import { makeCliRoot, makeShimTrap, setStubEnv, stubRequests } from './graph-cli-root.js'

// Card c3c32903, BE2-1: the mail approval step runs a root-owned, non-shim python3 with an
// environment built from an allowlist. A `DEVELOPER_DIR=<own tree>` prefix (the macOS
// /usr/bin/python3 is an xcrun shim that follows it), a python3 shim on PATH, PYTHONPATH,
// PYTHONHOME or DYLD_INSERT_LIBRARIES must never reach the interpreter or the helper.
//
// HOW TO RUN: under the deny-net sandbox, from the repo root:
//   /Users/gyorgydecsi/marveen/agents/ezermester/.claude/sandbox/run-sandboxed.sh \
//     npx vitest run src/__tests__/trusted-python.test.ts

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'trusted-py-')))

// --- the env builder ---------------------------------------------------------------------

describe('trustedPythonEnv: built from nothing', () => {
  const HOSTILE: NodeJS.ProcessEnv = {
    DEVELOPER_DIR: '/tmp/attacker',
    SDKROOT: '/tmp/attacker',
    TOOLCHAINS: 'com.attacker',
    TMPDIR: '/tmp/attacker',
    PYTHONPATH: '/tmp/attacker',
    PYTHONHOME: '/tmp/attacker',
    PYTHONSTARTUP: '/tmp/attacker/x.py',
    PYTHONUSERBASE: '/tmp/attacker',
    DYLD_INSERT_LIBRARIES: '/tmp/attacker/evil.dylib',
    DYLD_LIBRARY_PATH: '/tmp/attacker',
    LD_PRELOAD: '/tmp/attacker/evil.so',
    LD_LIBRARY_PATH: '/tmp/attacker',
    PATH: '/tmp/attacker/bin:/usr/bin',
    EMAIL_APPROVAL_GATE_STORE: '/tmp/attacker/store',
    OUTGOING_COPY_GATE_RULES: '/tmp/attacker/rules.json',
    HARDER_MAIL_PYTHON: '/tmp/attacker/python',
    CLAUDE_CONFIG_DIR: '/tmp/attacker',
    SOMETHING_ELSE: 'x',
  }

  it('none of the dangerous variables is in the child env, and PATH is fixed', () => {
    const env = trustedPythonEnv(HOSTILE)
    for (const k of [
      'DEVELOPER_DIR', 'SDKROOT', 'TOOLCHAINS', 'TMPDIR', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONSTARTUP',
      'PYTHONUSERBASE', 'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
      'EMAIL_APPROVAL_GATE_STORE', 'OUTGOING_COPY_GATE_RULES', 'HARDER_MAIL_PYTHON', 'CLAUDE_CONFIG_DIR',
      'SOMETHING_ELSE',
    ]) {
      expect(Object.keys(env), k).not.toContain(k)
    }
    expect(env.PATH).toBe('/usr/bin:/bin')
    expect(TRUSTED_PATH).toBe('/usr/bin:/bin')
  })

  it('only allowlisted names (plus PATH) can ever appear, and the list holds no denied family', () => {
    const everything: NodeJS.ProcessEnv = {}
    for (const k of TRUSTED_ENV_ALLOWLIST) everything[k] = 'v'
    for (const k of Object.keys(HOSTILE)) everything[k] = 'v'
    const keys = Object.keys(trustedPythonEnv(everything)).sort()
    expect(keys).toEqual([...TRUSTED_ENV_ALLOWLIST, 'PATH'].sort())
    for (const k of TRUSTED_ENV_ALLOWLIST) {
      expect(k).not.toMatch(/^(DEVELOPER_DIR|SDKROOT|TOOLCHAINS|TMPDIR|PYTHON|DYLD_|LD_)/)
    }
  })

  it('the base set and the helper settings pass through; unset ones stay absent', () => {
    const env = trustedPythonEnv({ HOME: '/home/x', LANG: 'hu_HU.UTF-8', TZ: 'Europe/Budapest', USER: 'u', EMAIL_APPROVAL_WINDOW_S: '900' })
    expect(env).toEqual({ HOME: '/home/x', LANG: 'hu_HU.UTF-8', TZ: 'Europe/Budapest', USER: 'u', EMAIL_APPROVAL_WINDOW_S: '900', PATH: '/usr/bin:/bin' })
  })

  it('a caller-chosen extra value is added, but never a different PATH', () => {
    const env = trustedPythonEnv({}, { OUTGOING_COPY_GATE_RULES: '/dev/null/x', PATH: '/tmp/attacker' })
    expect(env.OUTGOING_COPY_GATE_RULES).toBe('/dev/null/x')
    expect(env.PATH).toBe('/usr/bin:/bin')
  })
})

// --- the interpreter choice, with an injected stat ----------------------------------------

type Node = { uid?: number; mode?: number; link?: string; kind?: 'file' | 'dir' | 'link' }
function fakeFs(nodes: Record<string, Node>) {
  const lstat = (p: string): StatLike => {
    const n = nodes[p]
    if (!n) throw Object.assign(new Error(`ENOENT ${p}`), { code: 'ENOENT' })
    const kind = n.kind ?? (n.link ? 'link' : 'dir')
    return { uid: n.uid ?? 0, mode: n.mode ?? (kind === 'file' ? 0o755 : 0o755), isSymbolicLink: () => kind === 'link', isFile: () => kind === 'file' }
  }
  const realpath = (p: string): string => {
    const n = nodes[p]
    if (!n) throw new Error(`ENOENT ${p}`)
    return n.link ?? p
  }
  return { lstat, realpath }
}

const CAND = '/Library/Developer/CommandLineTools/usr/bin/python3'
const REAL = '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin/python3.9'
const ALL_ROOT: Record<string, Node> = {
  '/': {},
  '/Library': {},
  '/Library/Developer': {},
  '/Library/Developer/CommandLineTools': {},
  '/Library/Developer/CommandLineTools/usr': {},
  '/Library/Developer/CommandLineTools/usr/bin': {},
  [CAND]: { link: REAL },
  '/Library/Developer/CommandLineTools/Library': {},
  '/Library/Developer/CommandLineTools/Library/Frameworks': {},
  '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework': {},
  '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions': {},
  '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9': {},
  '/Library/Developer/CommandLineTools/Library/Frameworks/Python3.framework/Versions/3.9/bin': {},
  [REAL]: { kind: 'file' },
}
const resolveWith = (nodes: Record<string, Node>, extra: Partial<TrustedPythonDeps> = {}) =>
  resolveTrustedPython({ platform: 'darwin', ...fakeFs(nodes), ...extra })

describe('resolveTrustedPython: root-owned along the whole path, real binary only', () => {
  it('a root-owned chain resolves to the REAL path of the framework binary, not the symlink', () => {
    expect(resolveWith(ALL_ROOT)).toBe(REAL)
  })

  it('a candidate that is not root-owned is rejected (the injected stat says uid 501)', () => {
    expect(resolveWith({ ...ALL_ROOT, [REAL]: { kind: 'file', uid: 501 } })).toBeNull()
  })

  it('a directory on the way that is not root-owned is rejected', () => {
    expect(resolveWith({ ...ALL_ROOT, '/Library/Developer': { uid: 501 } })).toBeNull()
  })

  it('a group-writable or world-writable component is rejected, in the written path and in the resolved one', () => {
    expect(resolveWith({ ...ALL_ROOT, '/Library/Developer/CommandLineTools/usr/bin': { mode: 0o775 } })).toBeNull()
    expect(resolveWith({ ...ALL_ROOT, '/Library/Developer/CommandLineTools/Library/Frameworks': { mode: 0o757 } })).toBeNull()
    expect(resolveWith({ ...ALL_ROOT, [REAL]: { kind: 'file', mode: 0o775 } })).toBeNull()
  })

  it('a symlink owned by someone else is rejected', () => {
    expect(resolveWith({ ...ALL_ROOT, [CAND]: { link: REAL, uid: 501 } })).toBeNull()
  })

  it('the target must be an executable regular file', () => {
    expect(resolveWith({ ...ALL_ROOT, [REAL]: { kind: 'file', mode: 0o644 } })).toBeNull()
    expect(resolveWith({ ...ALL_ROOT, [REAL]: { kind: 'dir' } })).toBeNull()
  })

  it('a missing candidate and an unsupported platform give null, not an exception', () => {
    expect(resolveWith({})).toBeNull()
    expect(resolveTrustedPython({ platform: 'win32', ...fakeFs(ALL_ROOT) })).toBeNull()
  })

  it('the next candidate is tried when the first fails', () => {
    const nodes = { ...ALL_ROOT, '/usr': {}, '/usr/bin': {}, '/usr/bin/python3x': { kind: 'file' } as Node, [REAL]: { kind: 'file', uid: 501 } as Node }
    expect(resolveWith(nodes, { candidates: [CAND, '/usr/bin/python3x'] })).toBe('/usr/bin/python3x')
  })

  it('Homebrew and /usr/local are not candidates on any platform', () => {
    for (const list of Object.values(TRUSTED_PYTHON_CANDIDATES)) {
      for (const c of list) expect(c).not.toMatch(/homebrew|\/usr\/local/)
    }
    expect(TRUSTED_PYTHON_CANDIDATES.darwin).toEqual([CAND])
    expect(TRUSTED_PYTHON_CANDIDATES.linux).toEqual(['/usr/bin/python3'])
  })

  it('on this machine the CLT python resolves to a root-owned, non-shim binary (darwin only)', () => {
    if (process.platform !== 'darwin' || !existsSync(CAND)) return
    const real = resolveTrustedPython()
    expect(real).not.toBeNull()
    expect(real).not.toBe('/usr/bin/python3')
    expect(real).toMatch(/^\/Library\/Developer\/CommandLineTools\//)
  })

  it('the refusal text is the Hungarian fail-closed line', () => {
    expect(NO_TRUSTED_PYTHON_MESSAGE).toBe('nincs megbízható python3 (root tulajdonú CLT út) a jóváhagyó lépéshez; a levél nem ment ki')
  })
})

// --- the trap: a fake DEVELOPER_DIR tree and a python3 shim on PATH ------------------------

const SUBJ = 'Teszt tárgy'
const BODY = 'Kedves Ügyfelünk! Törzs.'
const ENV = buildSendEnvelope({ argv: ['--subject', SUBJ, '--body', BODY], to: 'ugyfel@example.hu', subject: SUBJ, body: BODY }, 'ref-trap')

/** Runs fn with the trap's variables (and a shim python3 first on PATH) in process.env, then restores. */
function withTrapEnv<T>(trap: ReturnType<typeof makeShimTrap>, fn: () => T): T {
  const keys = { ...trap.env, PATH: `${trap.fakeBin}:${process.env.PATH ?? ''}`, PYTHONPATH: trap.developerDir, PYTHONHOME: trap.developerDir }
  const old: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(keys)) {
    old[k] = process.env[k]
    process.env[k] = v
  }
  try {
    return fn()
  } finally {
    for (const k of Object.keys(keys)) {
      if (old[k] === undefined) delete process.env[k]
      else process.env[k] = old[k]
    }
  }
}

describe('authorizeSend under a DEVELOPER_DIR / PATH / PYTHON* trap', () => {
  it('no shim is started; the decision comes from the helper run by the trusted python (a refusal stays a refusal)', () => {
    if (!resolveTrustedPython()) return // no root-owned python on this host: covered by the fail-closed test below
    const trap = makeShimTrap(BASE)
    const root = makeCliRoot(REPO, BASE)
    setStubEnv(root, { GS_MODE: 'refuse', GS_REASON: 'consumed' })
    const a = withTrapEnv(trap, () => authorizeSend(ENV, root))
    expect(existsSync(trap.marker)).toBe(false)
    expect(a).toMatchObject({ allowed: false, reason: 'consumed' })
    // the stub helper (not a shim) saw exactly one request: the trusted python ran it
    expect(stubRequests(root)).toHaveLength(1)
  })

  it('the same trap with an allowing helper: allowed only because the HELPER said so, still no shim', () => {
    if (!resolveTrustedPython()) return
    const trap = makeShimTrap(BASE)
    const root = makeCliRoot(REPO, BASE)
    setStubEnv(root, { GS_MODE: 'allow' })
    const a = withTrapEnv(trap, () => authorizeSend(ENV, root))
    expect(existsSync(trap.marker)).toBe(false)
    expect(a.allowed).toBe(true)
    if (a.allowed) expect(a.verdict.approval_id).toBe('ab12cd') // the stub's id, not the shim's "shim"
    expect(stubRequests(root)).toHaveLength(1)
  })

  it('a helper that crashes under the trap is a refusal, never an allow from a shim', () => {
    if (!resolveTrustedPython()) return
    const trap = makeShimTrap(BASE)
    const root = makeCliRoot(REPO, BASE)
    setStubEnv(root, { GS_MODE: 'crash' })
    const a = withTrapEnv(trap, () => authorizeSend(ENV, root))
    expect(existsSync(trap.marker)).toBe(false)
    expect(a).toMatchObject({ allowed: false, reason: 'authorizer_failed' })
  })
})
