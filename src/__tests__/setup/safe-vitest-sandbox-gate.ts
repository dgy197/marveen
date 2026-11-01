// GLOBAL GATE (vitest `globalSetup`, card 9b4d8a33): refuse the WHOLE run outside the scripts/safe-vitest.sh
// sandbox.
//
// Why: on 2026-10-24 a full vitest run outside any sandbox executed a test cleanup that built a path from an
// empty variable and deleted the parent of the working directory. safe-vitest.sh runs vitest under a macOS
// sandbox-exec profile that refuses every file write outside the worktree, its own per-run temp dir and /dev.
// The command gate (scripts/hooks/test-run-gate.mjs) can only read the command text; this gate checks the
// process the suite actually runs in, so `npx vitest`, `npm test` or a wrapper script all stop here.
//
// Inside the sandbox both hold:
//   1. TMPDIR is the per-run dir safe-vitest.sh created: /private/var/folders/<a>/<b>/T/safe-vitest.XXXXXXXX,
//      and that directory exists, resolves to itself and belongs to this uid (a leftover exported TMPDIR fails)
//   2. a file write to $HOME is refused with EPERM. A write that succeeds means no sandbox; the probe file
//      is removed again at once.
// Named exception: off darwin there is no sandbox-exec and safe-vitest.sh cannot run (CI on ubuntu, a Linux
// install), so the gate does not apply there. There is deliberately no environment override on darwin.
//
// Test seams are function parameters (the input object), never environment variables.
import { writeFileSync, unlinkSync, realpathSync, statSync } from 'node:fs'
import { homedir } from 'node:os'
import { dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

const checkoutRootOfThisFile = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..')
const RUN_DIR = /^\/private\/var\/folders\/[^/]+\/[^/]+\/T\/safe-vitest\.[A-Za-z0-9]{8}\/?$/
// Only EPERM: the sandbox refuses with it (measured); EACCES also comes from plain unix permissions (review B1).
const DENIED = new Set(['EPERM'])

export interface SandboxGateInput {
  platform: string
  checkoutRoot: string
  tmpdir: string | undefined
  probeDir: string
  /** Create the probe file exclusively; return normally when it was written, throw the fs error otherwise. */
  tryWrite: (path: string) => unknown
  removeProbe?: (path: string) => void
  /** The uid of this process. */
  uid: number
  /** realpath and owner uid of a directory, or null when it does not exist / is not a directory. */
  inspectDir: (path: string) => { realpath: string; uid: number } | null
}

export type SandboxGateVerdict = { ok: true; exempt?: 'non-darwin' } | { ok: false; reason: string }

const within = (p: string, root: string) => {
  const a = resolve(p); const r = resolve(root)
  return a === r || a.startsWith(r.endsWith(sep) ? r : r + sep)
}

function refuse(root: string, detail: string): SandboxGateVerdict {
  return {
    ok: false,
    reason:
      `REFUSING TO RUN TESTS: vitest runs only inside the safe-vitest sandbox (${detail}).\n` +
      `Start it from the worktree root: cd ${root} && bash ${join(root, 'scripts', 'safe-vitest.sh')} [test files]\n` +
      '(card 9b4d8a33; the sandbox refuses writes outside the worktree, see scripts/safe-vitest.sh)',
  }
}

export function sandboxGateVerdict(input: SandboxGateInput): SandboxGateVerdict {
  const root = input.checkoutRoot
  if (input.platform !== 'darwin') return { ok: true, exempt: 'non-darwin' }
  const tmp = input.tmpdir
  if (!tmp || tmp.includes('/../') || tmp.endsWith('/..') || !RUN_DIR.test(tmp)) {
    return refuse(root, `TMPDIR is not a safe-vitest run dir: ${tmp ?? '(unset)'}`)
  }
  const dir = input.inspectDir(tmp)
  const want = tmp.replace(/\/$/, '')
  if (!dir || dir.realpath !== want || dir.uid !== input.uid) {
    return refuse(root, `TMPDIR ${tmp} is not a live safe-vitest run dir of this user (missing, a link elsewhere, or not ours)`)
  }
  if (within(input.probeDir, root) || within(input.probeDir, tmp)) {
    return refuse(root, `cannot verify: the probe dir ${input.probeDir} is one the sandbox allows writing`)
  }
  const probe = join(input.probeDir, `.safe-vitest-probe-${process.pid}-${randomBytes(4).toString('hex')}`)
  try {
    input.tryWrite(probe)
  } catch (e) {
    const code = (e as { code?: string })?.code
    if (code && DENIED.has(code)) return { ok: true }
    return refuse(root, `cannot verify: the probe write failed with ${code ?? String(e)}`)
  }
  ;(input.removeProbe ?? ((p) => { try { unlinkSync(p) } catch { /* best effort */ } }))(probe)
  return refuse(root, `a file write to ${input.probeDir} succeeded, so no write sandbox is active`)
}

function liveInput(): SandboxGateInput {
  return {
    platform: process.platform,
    checkoutRoot: checkoutRootOfThisFile,
    tmpdir: process.env.TMPDIR,
    probeDir: homedir(),
    tryWrite: (p) => writeFileSync(p, '', { flag: 'wx' }),
    uid: process.getuid?.() ?? -1,
    inspectDir: (p) => {
      try {
        const st = statSync(p)
        return st.isDirectory() ? { realpath: realpathSync.native(p), uid: st.uid } : null
      } catch { return null }
    },
  }
}

/** Throw the refusal unless the run is inside the sandbox. Without an argument it probes this process. */
export function assertInSafeVitestSandbox(input: SandboxGateInput = liveInput()): void {
  const v = sandboxGateVerdict(input)
  if (!v.ok) throw new Error(v.reason)
}

export default function setup(): void {
  assertInSafeVitestSandbox()
}
