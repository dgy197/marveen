import { lstatSync, realpathSync } from 'node:fs'

// The one place that decides WHICH python3 the mail approval step runs, and with
// WHAT environment (card c3c32903, BE2-1; BE-B1 before it).
//
// Why. The macOS `/usr/bin/python3` is an xcrun shim: it honours an inherited
// DEVELOPER_DIR (and SDKROOT / TOOLCHAINS), so `DEVELOPER_DIR=<own tree> <send>`
// makes the approval step run the attacker's python, which prints "allow". A
// denylist of such variables does not converge (the same bug class as a PATH
// shim), so there are two rules and no list of bad names:
//   1. the interpreter is a real, non-shim binary on a path where every component
//      is root-owned and not group/world-writable (the Command Line Tools python on
//      macOS, /usr/bin/python3 on Linux); Homebrew and /usr/local are NOT trusted,
//      they are user-writable;
//   2. the child's environment is built from nothing, from an allowlist, with a
//      fixed PATH.
// Nothing found: fail-closed, the letter does not go out.
//
// Used by src/graph-send-authorize.ts (the approval consumer) and by
// scripts/graph-mail.ts (the ledger check and the gate probe).

/** What the callers print when no trusted interpreter exists. */
export const NO_TRUSTED_PYTHON_MESSAGE =
  'nincs megbízható python3 (root tulajdonú CLT út) a jóváhagyó lépéshez; a levél nem ment ki'

/** In order; the first one that passes every check wins. */
export const TRUSTED_PYTHON_CANDIDATES: Readonly<Record<'darwin' | 'linux', readonly string[]>> = {
  darwin: ['/Library/Developer/CommandLineTools/usr/bin/python3'],
  linux: ['/usr/bin/python3'],
}

/** The only variables copied from the caller's environment into the child's. */
export const TRUSTED_ENV_ALLOWLIST = [
  'HOME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TZ',
  'USER',
  'LOGNAME',
  // what the helper scripts (email_send_authorize.py, email-approval-gate.py, email_extract.py) read:
  'EMAIL_APPROVAL_WINDOW_S', // the helper caps it at its 1800 s default: it cannot widen the window
  'GRAPH_MAIL_OUTBOX_DIR', // the outbox root; the CLI reads the same variable, the content is bound by sha256
  'WEB_PORT', // the standing trace's daily-log post (loopback), then the install .env, then 3420
  'MAIN_AGENT_ID', // the same post
] as const

export const TRUSTED_PATH = '/usr/bin:/bin'

/** The part of fs.Stats the checks read; tests inject their own. */
export interface StatLike {
  uid: number
  mode: number
  isSymbolicLink(): boolean
  isFile(): boolean
}

export interface TrustedPythonDeps {
  platform?: NodeJS.Platform
  lstat?: (path: string) => StatLike
  realpath?: (path: string) => string
  /** Overrides the platform's candidate list (tests). */
  candidates?: readonly string[]
}

/** "/", "/a", "/a/b", ... for an absolute path. */
function prefixes(path: string): string[] {
  const out = ['/']
  let cur = ''
  for (const part of path.split('/').filter(Boolean)) {
    cur = `${cur}/${part}`
    out.push(cur)
  }
  return out
}

/**
 * Every component of `path` (itself included) is owned by root, and none is group-
 * or world-writable. A symlink's own mode bits mean nothing (they are 0777 on
 * Linux), so only its owner counts there; where it points is checked on the
 * realpath.
 */
function chainIsRootOwned(path: string, lstat: (p: string) => StatLike): boolean {
  if (!path.startsWith('/')) return false
  for (const p of prefixes(path)) {
    let st: StatLike
    try {
      st = lstat(p)
    } catch {
      return false
    }
    if (st.uid !== 0) return false
    if (!st.isSymbolicLink() && (st.mode & 0o022) !== 0) return false
  }
  return true
}

/**
 * The trusted python3, as the REALPATH of the first candidate that exists, is a
 * regular executable file (not a symlink, not a shim) and whose path is root-owned
 * and not group/world-writable along the whole way, both as written and as
 * resolved. null when there is none.
 */
export function resolveTrustedPython(deps: TrustedPythonDeps = {}): string | null {
  const platform = deps.platform ?? process.platform
  const lstat = deps.lstat ?? ((p: string) => lstatSync(p))
  const realpath = deps.realpath ?? ((p: string) => realpathSync(p))
  const candidates = deps.candidates ?? (platform === 'darwin' ? TRUSTED_PYTHON_CANDIDATES.darwin : platform === 'linux' ? TRUSTED_PYTHON_CANDIDATES.linux : [])
  for (const candidate of candidates) {
    try {
      if (!chainIsRootOwned(candidate, lstat)) continue
      const real = realpath(candidate)
      if (!chainIsRootOwned(real, lstat)) continue
      const st = lstat(real)
      if (st.isSymbolicLink() || !st.isFile() || (st.mode & 0o111) === 0) continue
      return real
    } catch {
      /* not there or unreadable: try the next one */
    }
  }
  return null
}

/**
 * The environment of the trusted python child, built from nothing: the allowlisted
 * variables of `source` that are set, plus PATH=/usr/bin:/bin. `extra` is for fixed,
 * caller-chosen values (never for anything taken from the caller's environment).
 * DEVELOPER_DIR, SDKROOT, TOOLCHAINS, TMPDIR, PYTHON*, DYLD_*, LD_* and everything
 * else are absent by construction.
 */
export function trustedPythonEnv(
  source: NodeJS.ProcessEnv = process.env,
  extra: Readonly<Record<string, string>> = {},
): Record<string, string> {
  const env: Record<string, string> = {}
  for (const key of TRUSTED_ENV_ALLOWLIST) {
    const v = source[key]
    if (typeof v === 'string') env[key] = v
  }
  return { ...env, ...extra, PATH: TRUSTED_PATH }
}
