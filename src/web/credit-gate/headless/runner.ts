// The headless `claude -p` runner (card fec6335f, spec E-01..E-05, I-05, B-04,
// C-02; blueprint 4.3, node N4a).
//
// One run, in order:
//  1. Refusals that cost nothing: the config's headless part, the caller, the
//     node id, the model (the config's list AND the ceiling: Opus 5.5 or
//     Sonnet 5.5, never Haiku, never a [1m] variant), the effort, the budget
//     (two decimals, at most the config's maximum, a canary below 1.00), the
//     prompt, the working directory (validateCwd), the config hash (a normal
//     run only under the approved hash, a canary only under its approval's),
//     the pinned binary's shape, the runs directory and the key (E-05).
//  2. The gate's reservation (budget x factor, C-02) -- shadow or closed: no run.
//  3. The run directory (0700) with prompt.txt, settings.json and, in helper
//     mode, the key file (0600); config/ must be empty (no .credentials.json).
//  4. Right before the spawn: the binary's sha256 against the pin, the argv
//     against the template (-p first), the env against the allowlist, and the
//     hash of exactly this argv/env/settings against the approved one.
//     spawn(file, args, {shell:false, detached:true}) -- its own process group.
//  5. The wall clock: SIGTERM to the group, SIGKILL after a grace period.
//  6. The end, every way it can end (exit, timeout, cancel, the dashboard's
//     own SIGTERM/SIGINT/SIGHUP/exit, a thrown exception): the key file is
//     deleted FIRST; leftover group members are killed; the JSON result is
//     read (usage and cost only); the run dir is scanned for the key, its last
//     20 characters and "sk-ant-" (only file NAMES are ever logged); a
//     credit-too-low or 401 answer becomes a gate signal; the gate books the
//     run in the ledger (recordHeadless: JSON, else the transcript, else the
//     whole reservation, B-04) and settles the reservation; config/, home/,
//     tmp/ and empty-state/ are deleted. The run never writes usage.jsonl:
//     the ledger has it from the gate only (no double count).
//  7. A dashboard restart: reconcile.ts re-attaches a run whose pid is alive
//     with the same start time (it is polled, and still stopped at its wall
//     clock), and closes the others by B-04.
//
// Nothing here ever logs, stores or returns the key or the prompt. The model's
// answer leaves the disk at the end of the run: stdout.json and stderr.txt are
// deleted, and the run row keeps the usage, the cost and the answer text with
// every key-shaped string replaced (filterAnswer).
//
// A row read back from the database is not trusted (BE-4): reconcile checks
// the id, that run_dir is exactly <runsDir>/<id>, that pgid is the pid, and
// that the reservation is this run's own, before it touches a file or a
// process. A process is this run's only when it is the pinned CLI with the
// run's settings file in the template's place, or a member of that CLI's own
// process group whose env names the run dir (runProcesses); a mention in an
// argv or an env (grep, pgrep, a stray variable) is not enough. A row that
// fails is closed without touching anything.

import { execFileSync, spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import {
  closeSync,
  constants as fsc,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readdirSync,
  readFileSync,
  readlinkSync,
  readSync,
  realpathSync,
  rmdirSync,
  rmSync,
  unlinkSync,
  writeSync,
} from 'node:fs'
import { basename, dirname, isAbsolute, join, normalize, relative, resolve } from 'node:path'
import type Database from 'better-sqlite3'
import { logger } from '../../../logger.js'
import type { ConfigLoadResult, HeadlessConfig } from '../config.js'
import type { HeadlessReserveRequest, OpResult, ReserveResult, SignalKind } from '../gate.js'
import { HEADLESS_SOURCE, type HeadlessModelUsage, type HeadlessRun, type LedgerBasis } from '../ledger.js'
import { parseUsd } from '../money.js'
import type { Micro } from '../types.js'
import { assertRunArgs, buildRunArgs, EFFORTS, SETTINGS_ARG_INDEX, type Effort, type ToolProfile } from './args.js'
import { computeRunnerConfigHash, configHashOf } from './config-hash.js'
import { buildRunEnv, buildRunSettings, isSafeRunPath, runPaths, WIPED_SUBDIRS, type KeyMode, type RunPaths } from './env.js'
import { applyHeadlessRunsSchema, OPEN_RUN_STATUSES, type RunStatus } from './schema-runs.js'

/** The models a headless run may use, whatever the config lists (spec D-5; Haiku never codes). */
export const HEADLESS_MODEL_CEILING: readonly string[] = Object.freeze(['claude-opus-5-5', 'claude-sonnet-5-5'])
/** A canary's budget must stay below 1.00 USD (spec K-01). */
export const CANARY_BUDGET_LIMIT_MICRO = 1_000_000
export const MAX_PROMPT_BYTES = 256 * 1024
export const MAX_STDOUT_BYTES = 16 * 1024 * 1024
const STDERR_TAIL_BYTES = 64 * 1024
const MAX_SCAN_FILE_BYTES = 64 * 1024 * 1024
export const DEFAULT_KILL_GRACE_MS = 10_000
export const DEFAULT_POLL_MS = 2_000
/** On the dashboard's own SIGTERM/exit: how long the group gets after SIGTERM. */
const SHUTDOWN_GRACE_MS = 500
export const KEY_TAIL_CHARS = 20
export const KEY_MARKER = 'sk-ant-'
const SIGNAL_SOURCE = 'headless-runner'
/** The answer text kept in result_json, at most (then "[truncated]"). */
export const RESULT_TEXT_MAX = 64 * 1024
/** Ticks a row may wait for a usable ps before it is closed unverified (BE-4 3). */
export const DEFAULT_PS_RETRY_LIMIT = 30
/** BE-4b P5: ticks a failed settle is retried before the gate is told (about 5 min at the default poll). */
export const DEFAULT_SETTLE_RETRY_LIMIT = 150
/** The worktree walk before a spawn (BE-4 2): above either limit, no run. */
export const DEFAULT_CWD_TREE_LIMITS: CwdTreeLimits = Object.freeze({ maxDepth: 32, maxEntries: 50_000 })

const NODE_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/
const CALLER_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/
const SHA256_RE = /^[0-9a-f]{64}$/
const RUN_ID_RE = /^[A-Za-z0-9_-]{1,64}$/
/** allocateRunId(): at most this many ids wait for their start. */
const MAX_ALLOCATED_RUN_IDS = 64
/** The run dirs the startup sweep enters: the generated hr-<uuid> names only. */
const RUN_DIR_NAME_RE = /^hr-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const APPROVAL_ID_RE = /^[A-Za-z0-9_-]{1,64}$/
const SAFE_NAME_RE = /^[A-Za-z0-9_.:[\]-]{1,128}$/
const CREDIT_TOO_LOW_RE = /credit balance (is )?too low/i
const AUTH_ERROR_RE = /authentication_error|invalid x-api-key|invalid api key/i

/** What the caller asks for. Who asks is not in it: see StartContext. */
export interface HeadlessRunRequest {
  readonly node_id: string
  readonly model: string
  readonly effort: string
  /** The --max-budget-usd cap, a two-decimal USD string. */
  readonly budget_usd: string
  /** The node's worktree: absolute, canonical, under a configured root. */
  readonly cwd: string
  readonly prompt: string
  readonly mode: 'normal' | 'canary'
}

/**
 * Who starts the run -- never taken from the request body (BE-4 7). The
 * route (N4b) fills `caller` from the dashboard's own context: the
 * X-Agent-Id claim, which is self-reported (blueprint 11.6), so
 * allowedCallers only stops accidental use. A canary names the
 * credit_gate_canary approval the route has just consumed (owner-verified,
 * single use) for the run id it took from allocateRunId(); the runner asks
 * deps.canaryApprovedHash for the hash that approval's row binds to exactly
 * that run (N2c takeCanaryHash: once).
 */
export interface StartContext {
  readonly caller: string
  readonly canaryApprovalId?: string
  /** A run id from this runner's allocateRunId(), used once; omitted = a fresh one. */
  readonly runId?: string
}

/** What the runner needs of the gate (CreditGate has it). */
export interface HeadlessGatePort {
  reserve(req: HeadlessReserveRequest): ReserveResult
  settleHeadless(id: string, run?: HeadlessRun | null, nowMs?: number): OpResult
  signal(kind: SignalKind, source: string, detail: string | null, nowMs?: number): unknown
}

export type Spawner = (file: string, args: readonly string[], options: SpawnOptions) => ChildProcess

export interface ProcInfo {
  readonly pid: number
  readonly pgid: number
  readonly start: string
  /** argv, then (ps -E) the environment -- hidden by macOS for platform binaries. */
  readonly command: string
}

export interface HeadlessRunnerDeps {
  readonly db: Database.Database
  /** null: the gate is off (or not running) -- nothing starts. */
  readonly gate: HeadlessGatePort | null
  readonly loadConfig: () => ConfigLoadResult
  /** The shared key from the Vault (config.vaultKeyId); null = missing. */
  readonly getKey: () => string | null
  /** The config hash a successful canary approved (N2c); null = none. */
  readonly approvedHash: () => string | null
  /** The config hash a consumed credit_gate_canary approval binds to this run id, handed out once (N2c takeCanaryHash); null = none. */
  readonly canaryApprovedHash?: (approvalId: string, runId: string) => string | null
  /** Never a working directory, nor a parent of one: the install root, the store. */
  readonly forbiddenRoots: readonly string[]
  readonly spawner?: Spawner
  readonly now?: () => number
  readonly newRunId?: () => string
  readonly procStart?: (pid: number) => string | null
  readonly listProcesses?: () => readonly ProcInfo[]
  readonly kill?: (pid: number, signal: NodeJS.Signals | 0) => void
  /** Overrides headless.wallClockMin (tests). */
  readonly wallClockMs?: number
  readonly killGraceMs?: number
  readonly pollMs?: number
  /** Ticks a row may wait for a usable ps (default DEFAULT_PS_RETRY_LIMIT). */
  readonly psRetryLimit?: number
  /** Ticks a failed settle is retried (default DEFAULT_SETTLE_RETRY_LIMIT). */
  readonly settleRetryLimit?: number
  readonly cwdTreeLimits?: CwdTreeLimits
  /** Kill the runs' groups on this process's SIGTERM/SIGINT/SIGHUP/exit. Default true. */
  readonly installSignalHandlers?: boolean
  /**
   * Test seams. afterPrepare: the run dir is ready (inside the prepare step).
   * beforeSpawn / afterSpawn: outside every inner try -- a throw there is the
   * launch catch-all's (reviewer 9).
   */
  readonly hooks?: {
    readonly afterPrepare?: (runDir: string) => void
    readonly beforeSpawn?: (runDir: string) => void
    readonly afterSpawn?: () => void
  }
}

export type StartResult =
  | {
      readonly ok: true
      readonly run_id: string
      readonly reservation_id: string
      readonly config_hash: string
      readonly done: Promise<RunOutcome>
    }
  | { readonly ok: false; readonly reason: string; readonly detail?: string }

export type StartRefusal = Extract<StartResult, { readonly ok: false }>

/** A run as the route shows it (N4b): the row's own columns and its stored result; never the prompt or the key. */
export interface RunRecord {
  readonly id: string
  readonly node_id: string
  readonly caller: string
  readonly model: string
  readonly effort: string
  readonly mode: 'normal' | 'canary'
  readonly status: RunStatus
  readonly started_at: number
  readonly ended_at: number | null
  readonly exit_code: number | null
  readonly signal: string | null
  readonly reason: string | null
  readonly budget_micro: number
  readonly est_micro: number | null
  readonly cli_micro: number | null
  readonly basis: string | null
  /** result_json: the CLI's usage and cost fields and the filtered answer; null = none or unreadable. */
  readonly result: Record<string, unknown> | null
}

/** BE-4b P5: a run's settle that failed, retried by the tick. */
interface PendingSettle {
  readonly runId: string
  readonly reservationId: string
  readonly booking: HeadlessRun | null
  attempts: number
}

interface Admitted {
  readonly ok: true
  readonly hc: HeadlessConfig
  readonly gate: HeadlessGatePort
  readonly caller: string
  readonly effort: Effort
  readonly budget: Micro
  readonly cwdCheck: Extract<CwdCheck, { readonly ok: true }>
  readonly cwdRules: CwdRules
}

export interface RunOutcome {
  readonly run_id: string
  readonly status: RunStatus
  readonly exit_code: number | null
  readonly signal: string | null
  readonly basis: LedgerBasis | null
  readonly est_micro: number | null
  readonly cli_micro: number | null
  /** Run-dir files (relative names) that carried key material or the key marker. */
  readonly residue: readonly string[]
  readonly reason: string | null
  readonly credit_too_low: boolean
  readonly auth_error: boolean
  /** Cleanup steps that failed, by name (each was logged). */
  readonly errors: readonly string[]
}

/** A credit_headless_runs row (the columns the runner reads back). */
export interface RunRow {
  id: string
  node_id: string
  model: string
  reservation_id: string
  key_mode: KeyMode
  pid: number | null
  pid_start: string | null
  pgid: number | null
  status: RunStatus
  deadline_at: number | null
  run_dir: string
}

interface ActiveRun {
  readonly id: string
  readonly nodeId: string
  readonly reservationId: string
  readonly reservationMicro: number
  readonly model: string
  readonly paths: RunPaths
  /** The key, for the residue scan (and the env in env mode); null after a restart. */
  readonly key: string | null
  child: ChildProcess | null
  pid: number | null
  pidStart: string | null
  /** Failed attempts to read the start time (ps unusable); retried on each tick. */
  startRetries: number
  /** Why this runner stopped the run itself (a check after the spawn failed). */
  stopReason: string | null
  deadlineAt: number | null
  reattached: boolean
  terminating: 'timeout' | 'cancelled' | 'killed' | null
  finished: boolean
  wallTimer: NodeJS.Timeout | null
  killTimer: NodeJS.Timeout | null
  resolve: (o: RunOutcome) => void
  readonly done: Promise<RunOutcome>
}

interface EndHow {
  readonly exitCode: number | null
  readonly signal: string | null
  /** A status decided by the caller (refused, spawn_failed, killed, lost). */
  readonly status?: RunStatus
  readonly reason?: string
  /** Provably no process ran: the reservation is settled at zero. */
  readonly nothingRan?: boolean
}

interface ParsedResult {
  readonly summary: Record<string, unknown>
  /** The model's answer (`result`), raw: filterAnswer() before it is stored. */
  readonly answer: string | null
  readonly isError: boolean | null
  readonly ledger: HeadlessRun['result']
  readonly creditTooLow: boolean
  readonly authError: boolean
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function isTokenCount(v: unknown): v is number {
  return typeof v === 'number' && Number.isSafeInteger(v) && v >= 0
}

function finiteNumber(v: unknown): number | null {
  return typeof v === 'number' && Number.isFinite(v) ? v : null
}

function errCode(err: unknown): string {
  return (err as NodeJS.ErrnoException)?.code ?? (err instanceof Error ? err.name : 'error')
}

function within(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent.endsWith('/') ? parent : parent + '/')
}

function realOrSelf(p: string): string {
  try {
    return realpathSync(p)
  } catch {
    return p
  }
}

/** Blocks the thread for `ms` (a synchronous wait: signal and exit handlers cannot await). */
function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

// ------------------------------------------------------------------ checks

export interface CwdTreeLimits {
  readonly maxDepth: number
  readonly maxEntries: number
}

export interface CwdRules {
  readonly roots: readonly string[]
  readonly forbidden: readonly string[]
  readonly runsDir: string
  readonly treeLimits?: CwdTreeLimits
}

export type CwdCheck =
  | { readonly ok: true; readonly cwd: string; /** dev:ino of the directory, for the check after the spawn */ readonly identity: string }
  | { readonly ok: false; readonly reason: string }

/**
 * The node's working directory: an absolute, canonical path (no `..`, no
 * symlink anywhere in it -- realpath must be the path itself), a directory we
 * own, strictly under one of the canonical roots, neither inside nor a parent
 * of a forbidden path (the install root, the store, the runs dir: the key file
 * must stay outside what the confined file tools can reach), a LINKED git
 * worktree (`.git` is a file with `gitdir:`; a clone's `.git` directory is
 * refused: ~/Brainy/main and the live checkouts are clones), and no symlink in
 * its tree may resolve outside it (checkCwdTree).
 */
export function validateCwd(cwd: unknown, rules: CwdRules): CwdCheck {
  if (typeof cwd !== 'string' || cwd.length === 0 || cwd.length > 1024 || cwd.includes('\0') || !isAbsolute(cwd)) {
    return { ok: false, reason: 'cwd_invalid' }
  }
  if (normalize(cwd) !== cwd || (cwd.length > 1 && cwd.endsWith('/'))) return { ok: false, reason: 'cwd_not_canonical' }
  let real: string
  try {
    real = realpathSync(cwd)
  } catch {
    return { ok: false, reason: 'cwd_invalid' }
  }
  if (real !== cwd) return { ok: false, reason: 'cwd_not_canonical' }
  let st
  try {
    st = lstatSync(cwd)
  } catch {
    return { ok: false, reason: 'cwd_invalid' }
  }
  if (!st.isDirectory()) return { ok: false, reason: 'cwd_invalid' }
  for (const f of [...rules.forbidden, rules.runsDir]) {
    for (const p of new Set([f, realOrSelf(f)])) {
      if (within(cwd, p) || within(p, cwd)) return { ok: false, reason: 'cwd_forbidden' }
    }
  }
  const inRoot = rules.roots.some((r) => realOrSelf(r) === r && r !== '/' && cwd.startsWith(r + '/'))
  if (!inRoot) return { ok: false, reason: 'cwd_outside_roots' }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null
  if (uid !== null && st.uid !== uid) return { ok: false, reason: 'cwd_not_owned' }
  let g
  try {
    g = lstatSync(join(cwd, '.git'))
  } catch {
    return { ok: false, reason: 'cwd_not_worktree' }
  }
  if (g.isDirectory()) return { ok: false, reason: 'cwd_not_linked_worktree' }
  if (!g.isFile() || g.size > 4096 || !readFileSync(join(cwd, '.git'), 'utf8').startsWith('gitdir: ')) return { ok: false, reason: 'cwd_not_worktree' }
  const tree = checkCwdTree(cwd, rules.treeLimits ?? DEFAULT_CWD_TREE_LIMITS)
  return tree === null ? { ok: true, cwd, identity: `${st.dev}:${st.ino}` } : { ok: false, reason: tree }
}

/** dev:ino of a path itself (a symlink is its own inode); null when it is gone. */
function pathIdentity(p: string): string | null {
  try {
    const st = lstatSync(p)
    return `${st.dev}:${st.ino}`
  } catch {
    return null
  }
}

/**
 * Every symlink in the tree must resolve inside `root` (a dangling one by its
 * text). Links are not followed while walking. Above maxDepth or maxEntries,
 * or an unreadable directory: refused -- an unchecked tree is not a checked one.
 */
export function checkCwdTree(root: string, limits: CwdTreeLimits): string | null {
  let entries = 0
  const walk = (dir: string, depth: number): string | null => {
    if (depth > limits.maxDepth) return 'cwd_tree_too_large'
    let list
    try {
      list = readdirSync(dir, { withFileTypes: true })
    } catch {
      return 'cwd_tree_unreadable'
    }
    for (const e of list) {
      if (++entries > limits.maxEntries) return 'cwd_tree_too_large'
      const full = join(dir, e.name)
      if (e.isSymbolicLink()) {
        let target: string
        try {
          target = realpathSync(full)
        } catch {
          try {
            target = resolve(dirname(full), readlinkSync(full))
          } catch {
            return 'cwd_tree_unreadable'
          }
        }
        if (!within(target, root)) return 'cwd_symlink_escape'
      } else if (e.isDirectory()) {
        const r = walk(full, depth + 1)
        if (r !== null) return r
      }
    }
    return null
  }
  return walk(root, 0)
}

export type BinaryCheck = { readonly ok: true; readonly identity: string } | { readonly ok: false; readonly reason: string }

/** The pinned binary's shape: a regular, executable file at its own real path, not writable by others. */
export function checkBinaryShape(path: string): BinaryCheck {
  let st
  try {
    st = lstatSync(path)
  } catch {
    return { ok: false, reason: 'binary_missing' }
  }
  if (!st.isFile() || realOrSelf(path) !== path) return { ok: false, reason: 'binary_not_regular' }
  if ((st.mode & 0o111) === 0) return { ok: false, reason: 'binary_not_executable' }
  if ((st.mode & 0o022) !== 0) return { ok: false, reason: 'binary_writable_by_others' }
  return { ok: true, identity: `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs}:${st.ctimeMs}` }
}

/** The shape, then the sha256 of the bytes against the pin (the last check before the spawn). */
export function verifyBinary(path: string, sha256: string | null): BinaryCheck {
  if (sha256 === null || !SHA256_RE.test(sha256)) return { ok: false, reason: 'binary_unpinned' }
  const shape = checkBinaryShape(path)
  if (!shape.ok) return shape
  let fd: number
  try {
    fd = openSync(path, fsc.O_RDONLY | fsc.O_NOFOLLOW)
  } catch {
    return { ok: false, reason: 'binary_missing' }
  }
  try {
    const h = createHash('sha256')
    const buf = Buffer.alloc(1 << 20)
    for (;;) {
      const n = readSync(fd, buf, 0, buf.length, null)
      if (n === 0) break
      h.update(buf.subarray(0, n))
    }
    if (h.digest('hex') !== sha256) return { ok: false, reason: 'binary_sha256_mismatch' }
  } finally {
    closeSync(fd)
  }
  const after = checkBinaryShape(path)
  if (!after.ok || after.identity !== shape.identity) return { ok: false, reason: 'binary_changed' }
  return shape
}

/**
 * The CLI version, for the log and the run row (never run to find out): the
 * native install keeps it as the file name (versions/2.1.299), an npm install
 * in the package.json next to it.
 */
export function cliVersionOf(binPath: string): string {
  const base = basename(binPath)
  if (/^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$/.test(base)) return base
  try {
    const pkg = JSON.parse(readFileSync(join(dirname(binPath), 'package.json'), 'utf8')) as Record<string, unknown>
    if (pkg.name === '@anthropic-ai/claude-code' && typeof pkg.version === 'string' && /^[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,6}$/.test(pkg.version)) {
      return pkg.version
    }
  } catch {
    // not an npm install
  }
  return 'unknown'
}

/**
 * The start time of a process (`ps -o lstart=`, C locale); null when there is
 * no such process (ps ran and exited 1). THROWS when ps itself cannot run --
 * "cannot check" is not "gone" (measured 2026-10-16: under sandbox-exec the
 * exec of the setuid /bin/ps is denied, EPERM).
 */
export function procStartOf(pid: number): string | null {
  if (!Number.isSafeInteger(pid) || pid <= 1) return null
  try {
    const out = execFileSync('/bin/ps', ['-o', 'lstart=', '-p', String(pid)], {
      encoding: 'utf8', env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'ignore'], timeout: 5_000,
    }).trim()
    return out === '' ? null : out
  } catch (err) {
    if ((err as { status?: unknown }).status === 1) return null
    throw new Error(`ps is not usable: ${errCode(err)}`)
  }
}

/**
 * Every process: pid, process group, start time, and argv + environment
 * (`ps -A -wwE`, C locale). Measured 2026-10-16: the environment is shown for
 * a node process of ours, not for an Apple platform binary (/bin/sleep).
 * Throws when ps cannot run.
 */
export function listProcessesPs(): ProcInfo[] {
  const out = execFileSync('/bin/ps', ['-A', '-wwE', '-o', 'pid=,pgid=,lstart=,command='], {
    encoding: 'utf8', env: { PATH: '/usr/bin:/bin', LC_ALL: 'C' }, stdio: ['ignore', 'pipe', 'ignore'], timeout: 10_000, maxBuffer: 64 * 1024 * 1024,
  })
  const procs: ProcInfo[] = []
  for (const line of out.split('\n')) {
    const m = /^\s*([0-9]+)\s+([0-9]+)\s+([A-Za-z]{3} [A-Za-z]{3} +[0-9]{1,2} [0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4})\s+(.*)$/.exec(line)
    if (m) procs.push({ pid: Number(m[1]), pgid: Number(m[2]), start: m[3], command: m[4] })
  }
  return procs
}

/**
 * The run's CLI: argv[0] -- or argv[1], after an interpreter running a #!
 * script -- is the pinned binary, `-p` follows it, and the run's settings
 * file stands exactly where the template puts it. ps joins the argv with
 * spaces; no token of the template contains one.
 */
export function runLeaderOf(command: string, runDir: string, claudeBin: string): boolean {
  const t = command.split(' ')
  const bin = claudeBin.split(' ')
  for (const at of [0, 1]) {
    if (!bin.every((b, k) => t[at + k] === b)) continue
    const p = at + bin.length
    if (t[p] === '-p' && t[p + SETTINGS_ARG_INDEX] === '--settings' && t[p + SETTINGS_ARG_INDEX + 1] === `${runDir}/settings.json`) return true
  }
  return false
}

/** The env part of a ps line names the run's config dir (a whole word). */
function envNamesRun(command: string, runDir: string): boolean {
  const needle = `CLAUDE_CONFIG_DIR=${runDir}/config`
  for (let i = command.indexOf(needle); i >= 0; i = command.indexOf(needle, i + 1)) {
    const end = i + needle.length
    if (i > 0 && command[i - 1] === ' ' && (end === command.length || command[end] === ' ')) return true
  }
  return false
}

/**
 * The processes of one run: its CLI (runLeaderOf), and the members of the
 * CLI's own process group -- or of `pgid`, a group the caller has verified
 * (a trusted row) -- whose env names the run dir. Never this process.
 */
export function runProcesses(procs: readonly ProcInfo[], runDir: string, claudeBin: string, pgid: number | null): ProcInfo[] {
  const leaders = procs.filter((p) => runLeaderOf(p.command, runDir, claudeBin))
  const groups = new Set<number>(leaders.filter((p) => p.pgid === p.pid).map((p) => p.pid))
  if (pgid !== null && pgid > 1) groups.add(pgid)
  return procs.filter((p) => p.pid !== process.pid && p.pid > 1
    && (leaders.includes(p) || (groups.has(p.pgid) && envNamesRun(p.command, runDir))))
}

export function defaultKill(pid: number, signal: NodeJS.Signals | 0): void {
  process.kill(pid, signal)
}

export interface SweepOptions {
  /** Run ids whose key file and processes are left alone (re-attached runs). */
  readonly keep: ReadonlySet<string>
  /** The pinned CLI (headless.claudeBin): how a run's process is recognised. */
  readonly claudeBin: string
  readonly listProcesses: () => readonly ProcInfo[]
  readonly kill: (pid: number, signal: NodeJS.Signals | 0) => void
}

export interface SweepReport {
  readonly keysRemoved: number
  readonly stopped: readonly number[]
  readonly psUsable: boolean
}

/**
 * The startup cleanup (BE-4 6, the rollback path; it runs in every mode):
 * every `key` file under the runs dir is deleted, and every process of a run
 * (runProcesses) gets SIGTERM, a short wait, SIGKILL -- except the kept runs.
 * The runs dir must pass ensureRunsDir's checks (a real directory at its own
 * real path, ours, 0700); only hr-<uuid> directories in it are entered.
 */
export function sweepRunsDir(runsDir: string, o: SweepOptions): SweepReport {
  let dirs: string[] = []
  try {
    const st = lstatSync(runsDir)
    const uid = typeof process.getuid === 'function' ? process.getuid() : null
    if (!st.isDirectory() || realpathSync(runsDir) !== runsDir || (st.mode & 0o077) !== 0 || (uid !== null && st.uid !== uid)) {
      logger.warn({ runs_dir: runsDir }, 'credit gate: the headless runs dir is not 0700, ours and real; not swept')
      return { keysRemoved: 0, stopped: [], psUsable: true }
    }
    dirs = readdirSync(runsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && RUN_DIR_NAME_RE.test(e.name) && !o.keep.has(e.name))
      .map((e) => join(runsDir, e.name))
  } catch {
    return { keysRemoved: 0, stopped: [], psUsable: true }
  }
  let keysRemoved = 0
  for (const d of dirs) {
    try {
      unlinkSync(join(d, 'key'))
      keysRemoved++
    } catch (err) {
      if (errCode(err) !== 'ENOENT') logger.error({ err: errCode(err), dir: basename(d) }, 'credit gate: a headless key file could not be removed')
    }
  }
  let procs: readonly ProcInfo[]
  try {
    procs = o.listProcesses()
  } catch (err) {
    logger.error({ err: errCode(err) }, 'credit gate: the process list is not readable; headless processes not checked')
    return { keysRemoved, stopped: [], psUsable: false }
  }
  const targets = [...new Set(dirs.flatMap((d) => runProcesses(procs, d, o.claudeBin, null).map((p) => p.pid)))]
  const aliveNow = (pid: number): boolean => {
    try {
      o.kill(pid, 0)
      return true
    } catch (err) {
      return errCode(err) === 'EPERM'
    }
  }
  for (const pid of targets) {
    try {
      o.kill(pid, 'SIGTERM')
    } catch {
      // already gone
    }
  }
  const end = Date.now() + SHUTDOWN_GRACE_MS
  while (Date.now() < end && targets.some(aliveNow)) sleepSync(20)
  for (const pid of targets.filter(aliveNow)) {
    try {
      o.kill(pid, 'SIGKILL')
    } catch {
      // already gone
    }
  }
  if (targets.length > 0) logger.warn({ pids: targets }, 'credit gate: stopped headless processes nobody supervises')
  return { keysRemoved, stopped: targets, psUsable: true }
}

/** The model's answer, fit to store: no key, no key tail, no sk-ant- string, no 64-hex token; capped. */
export function filterAnswer(text: string, key: string | null): string {
  let t = text
  if (key !== null && key.length >= KEY_TAIL_CHARS) {
    t = t.split(key).join('[REDACTED]')
    t = t.split(key.slice(-KEY_TAIL_CHARS)).join('[REDACTED]')
  }
  t = t.replace(/sk-ant-[A-Za-z0-9_-]*/g, '[REDACTED]')
  // The dashboard token's shape: randomBytes(32).toString('hex') (dashboard-auth.ts).
  t = t.replace(/[0-9a-fA-F]{64}/g, '[REDACTED]')
  return t.length > RESULT_TEXT_MAX ? t.slice(0, RESULT_TEXT_MAX) + '[truncated]' : t
}

/** The last checks and the spawn: absolute file, argv per template, no shell, own process group. */
export function spawnHeadless(
  spawner: Spawner,
  file: string,
  args: readonly string[],
  toolProfile: ToolProfile,
  options: { readonly cwd: string; readonly env: Record<string, string>; readonly detached: boolean; readonly shell: false; readonly stdio: SpawnOptions['stdio'] },
): ChildProcess {
  if (typeof file !== 'string' || !isAbsolute(file)) throw new Error('headless run refused: the binary must be an absolute path')
  assertRunArgs(args, toolProfile)
  if (options.shell !== false) throw new Error('headless run refused: shell must be false')
  if (options.detached !== true) throw new Error('headless run refused: the child must be detached (its own process group)')
  return spawner(file, args, { cwd: options.cwd, env: options.env, detached: true, shell: false, stdio: options.stdio, windowsHide: true })
}

const defaultSpawner: Spawner = (file, args, options) => nodeSpawn(file, [...args], options)

// ------------------------------------------------------------------ run-dir files

function writePrivate(path: string, text: string): void {
  const fd = openSync(path, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600)
  try {
    const buf = Buffer.from(text, 'utf8')
    let done = 0
    while (done < buf.length) done += writeSync(fd, buf, done, buf.length - done)
  } finally {
    closeSync(fd)
  }
}

function removeFile(path: string): void {
  try {
    unlinkSync(path)
  } catch (err) {
    if (errCode(err) !== 'ENOENT') throw err
  }
}

/** Up to `max` bytes of a regular file (not a symlink); null when it is not there or larger. */
function readBounded(path: string, max: number, tail = false): Buffer | null {
  let fd: number
  try {
    fd = openSync(path, fsc.O_RDONLY | fsc.O_NOFOLLOW | fsc.O_NONBLOCK)
  } catch {
    return null
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) return null
    if (st.size > max && !tail) return null
    const len = Math.min(st.size, max)
    const buf = Buffer.alloc(len)
    let done = 0
    const from = st.size - len
    while (done < len) {
      const n = readSync(fd, buf, done, len - done, from + done)
      if (n === 0) break
      done += n
    }
    return buf.subarray(0, done)
  } finally {
    closeSync(fd)
  }
}

interface ResidueHit {
  readonly name: string
  /** The key or its tail (or an unverifiable file): not only the marker. */
  readonly secret: boolean
}

function scanDetailed(root: string, secret: readonly Buffer[], marker: readonly Buffer[]): ResidueHit[] {
  const hits: ResidueHit[] = []
  try {
    lstatSync(root)
  } catch (err) {
    if (errCode(err) === 'ENOENT') return hits // no run dir: nothing was ever written
  }
  const walk = (dir: string): void => {
    let entries
    try {
      entries = readdirSync(dir, { withFileTypes: true })
    } catch {
      hits.push({ name: relative(root, dir) || '.', secret: true })
      return
    }
    for (const e of entries) {
      const full = join(dir, e.name)
      const name = relative(root, full)
      if (e.isSymbolicLink()) {
        hits.push({ name, secret: true })
      } else if (e.isDirectory()) {
        walk(full)
      } else {
        const buf = e.isFile() ? readBounded(full, MAX_SCAN_FILE_BYTES) : null
        if (buf === null) {
          hits.push({ name, secret: true }) // not a regular file, unreadable or too large: unverifiable
        } else if (secret.some((n) => buf.includes(n))) {
          hits.push({ name, secret: true })
        } else if (marker.some((n) => buf.includes(n))) {
          hits.push({ name, secret: false })
        }
      }
    }
  }
  walk(root)
  return hits.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
}

/** Run-dir files (relative names, sorted) that contain any of the needles; never their content. */
export function scanResidue(root: string, needles: readonly string[]): string[] {
  return scanDetailed(root, needles.filter((n) => n.length > 0).map((n) => Buffer.from(n, 'utf8')), []).map((h) => h.name)
}

function keyNeedles(key: string | null): Buffer[] {
  if (key === null || key.length < KEY_TAIL_CHARS) return []
  return [Buffer.from(key, 'utf8'), Buffer.from(key.slice(-KEY_TAIL_CHARS), 'utf8')]
}

function validKey(key: unknown): key is string {
  if (typeof key !== 'string' || key.length < 20 || key.length > 8192) return false
  for (let i = 0; i < key.length; i++) {
    const c = key.charCodeAt(i)
    if (c <= 32 || c >= 127) return false
  }
  return true
}

/** The CLI's JSON result, reduced to usage and cost; null when there is none. */
export function parseHeadlessResult(stdout: Buffer | null, stderrTail: string, runModel: string): ParsedResult | null {
  const stderrCredit = CREDIT_TOO_LOW_RE.test(stderrTail)
  const stderrAuth = AUTH_ERROR_RE.test(stderrTail)
  let doc: unknown = null
  if (stdout !== null && stdout.length > 0) {
    const text = stdout.toString('utf8').trim()
    try {
      doc = JSON.parse(text)
    } catch {
      const lines = text.split('\n').filter((l) => l.trim() !== '')
      try {
        doc = lines.length > 0 ? JSON.parse(lines[lines.length - 1]) : null
      } catch {
        doc = null
      }
    }
  }
  if (!isPlainObject(doc)) {
    if (!stderrCredit && !stderrAuth) return null
    return { summary: {}, answer: null, isError: null, ledger: null, creditTooLow: stderrCredit, authError: stderrAuth }
  }
  const isError = typeof doc.is_error === 'boolean' ? doc.is_error : null
  const resultText = typeof doc.result === 'string' ? doc.result : ''
  const summary: Record<string, unknown> = {}
  for (const k of ['type', 'subtype'] as const) {
    if (typeof doc[k] === 'string' && SAFE_NAME_RE.test(doc[k] as string)) summary[k] = doc[k]
  }
  if (isError !== null) summary.is_error = isError
  for (const k of ['num_turns', 'duration_ms', 'total_cost_usd'] as const) {
    const n = finiteNumber(doc[k])
    if (n !== null) summary[k] = n
  }
  if (isPlainObject(doc.usage)) {
    const u: Record<string, number> = {}
    for (const k of ['input_tokens', 'output_tokens', 'cache_creation_input_tokens', 'cache_read_input_tokens']) {
      const n = finiteNumber(doc.usage[k])
      if (n !== null) u[k] = n
    }
    summary.usage = u
  }
  const mu = isPlainObject(doc.modelUsage) ? doc.modelUsage : null
  if (mu !== null) {
    const out: Record<string, Record<string, number>> = {}
    for (const [model, row] of Object.entries(mu)) {
      if (!SAFE_NAME_RE.test(model) || !isPlainObject(row)) continue
      const r: Record<string, number> = {}
      for (const k of ['inputTokens', 'outputTokens', 'cacheReadInputTokens', 'cacheCreationInputTokens', 'costUSD', 'thinkingTokens', 'webSearchRequests']) {
        const n = finiteNumber(row[k])
        if (n !== null) r[k] = n
      }
      out[model] = r
    }
    summary.modelUsage = out
  }
  if (Array.isArray(doc.permission_denials)) summary.permission_denials = doc.permission_denials.length

  // The ledger's input: per model from modelUsage, else the totals of `usage`
  // on the run's model. Any missing or odd count makes the JSON unusable (the
  // ledger then falls back to the transcript, then to the reservation).
  let usage: HeadlessModelUsage[] | null = null
  if (mu !== null && Object.keys(mu).length > 0) {
    usage = []
    for (const [model, row] of Object.entries(mu)) {
      if (!/^[A-Za-z0-9_.-]{1,128}$/.test(model) || !isPlainObject(row)) {
        usage = null
        break
      }
      const f = [row.inputTokens, row.outputTokens, row.cacheCreationInputTokens, row.cacheReadInputTokens]
      if (!f.every(isTokenCount)) {
        usage = null
        break
      }
      usage.push({ model, input_tokens: f[0] as number, output_tokens: f[1] as number, cache_write_tokens: f[2] as number, cache_read_tokens: f[3] as number })
    }
  } else if (isPlainObject(doc.usage)) {
    const u = doc.usage
    const f = [u.input_tokens, u.output_tokens, u.cache_creation_input_tokens, u.cache_read_input_tokens]
    if (f.every(isTokenCount)) {
      usage = [{ model: runModel, input_tokens: f[0] as number, output_tokens: f[1] as number, cache_write_tokens: f[2] as number, cache_read_tokens: f[3] as number }]
    }
  }
  const ledger = usage === null ? null : { total_cost_usd: finiteNumber(doc.total_cost_usd), usage }
  return {
    summary,
    answer: typeof doc.result === 'string' ? doc.result : null,
    isError,
    ledger,
    creditTooLow: (isError === true && CREDIT_TOO_LOW_RE.test(resultText)) || stderrCredit,
    authError: (isError === true && AUTH_ERROR_RE.test(resultText)) || stderrAuth,
  }
}

// ------------------------------------------------------------------ process-wide signal guard

const liveRunners = new Set<HeadlessRunner>()
const GUARDED_SIGNALS = ['SIGTERM', 'SIGINT', 'SIGHUP'] as const
type GuardedSignal = typeof GUARDED_SIGNALS[number]
const signalListeners = new Map<GuardedSignal, () => void>()
let exitListener: (() => void) | null = null

function killEveryRunSync(): void {
  for (const r of liveRunners) {
    try {
      r.killAllSync()
    } catch (err) {
      logger.error({ err: errCode(err) }, 'credit gate: headless runs could not be stopped')
    }
  }
}

function installGuards(): void {
  if (exitListener !== null) return
  for (const sig of GUARDED_SIGNALS) {
    const fn = (): void => {
      killEveryRunSync()
      // Our listener took the default action away; with nobody else
      // listening, give it back: the process ends by this signal.
      if (process.listenerCount(sig) <= 1) {
        uninstallGuards()
        process.kill(process.pid, sig)
      }
    }
    signalListeners.set(sig, fn)
    process.on(sig, fn)
  }
  exitListener = killEveryRunSync
  process.on('exit', exitListener)
}

function uninstallGuards(): void {
  for (const [sig, fn] of signalListeners) process.removeListener(sig, fn)
  signalListeners.clear()
  if (exitListener !== null) process.removeListener('exit', exitListener)
  exitListener = null
}

// ------------------------------------------------------------------ the runner

export class HeadlessRunner {
  private readonly db: Database.Database
  private readonly spawner: Spawner
  private readonly now: () => number
  private readonly newRunId: () => string
  private readonly procStart: (pid: number) => string | null
  private readonly listProcesses: () => readonly ProcInfo[]
  private readonly kill: (pid: number, signal: NodeJS.Signals | 0) => void
  private readonly killGraceMs: number
  private readonly pollMs: number
  private readonly psRetryLimit: number
  private readonly settleRetryLimit: number
  private readonly active = new Map<string, ActiveRun>()
  /** BE-4b P5: settles that failed at the end of a run (a canary's would hold the batch path). */
  private readonly settleRetries = new Map<string, PendingSettle>()
  /** Rows whose processes could not be identified (ps unusable): id -> failed ticks. */
  private readonly pending = new Map<string, number>()
  private poll: NodeJS.Timeout | null = null
  private stopped = false
  /** Run ids handed out by allocateRunId() and not yet used by a start (oldest first). */
  private readonly allocated = new Set<string>()

  constructor(private readonly deps: HeadlessRunnerDeps) {
    this.db = deps.db
    this.spawner = deps.spawner ?? defaultSpawner
    this.now = deps.now ?? Date.now
    this.newRunId = deps.newRunId ?? (() => `hr-${randomUUID()}`)
    this.procStart = deps.procStart ?? procStartOf
    this.listProcesses = deps.listProcesses ?? listProcessesPs
    this.kill = deps.kill ?? defaultKill
    this.killGraceMs = deps.killGraceMs ?? DEFAULT_KILL_GRACE_MS
    this.pollMs = deps.pollMs ?? DEFAULT_POLL_MS
    this.psRetryLimit = deps.psRetryLimit ?? DEFAULT_PS_RETRY_LIMIT
    this.settleRetryLimit = deps.settleRetryLimit ?? DEFAULT_SETTLE_RETRY_LIMIT
    applyHeadlessRunsSchema(this.db)
    liveRunners.add(this)
    if (deps.installSignalHandlers ?? true) installGuards()
  }

  private headless(): { ok: true; hc: HeadlessConfig } | { ok: false; reason: string; detail?: string } {
    const cfgR = this.deps.loadConfig()
    if (!cfgR.ok) return { ok: false, reason: 'config_invalid', detail: cfgR.reason }
    if (cfgR.config.headless === null) return { ok: false, reason: 'headless_disabled' }
    return { ok: true, hc: cfgR.config.headless }
  }

  /** The hash of the configured launch template (key mode + tool profile); null without a headless config. */
  configHash(): string | null {
    const h = this.headless()
    return h.ok ? computeRunnerConfigHash({ keyMode: h.hc.keyMode, toolProfile: h.hc.toolProfile }) : null
  }

  activeCount(): number {
    return this.active.size
  }

  /** The runs this runner watches right now (own and re-attached). */
  activeIds(): string[] {
    return [...this.active.keys()]
  }

  whenDone(runId: string): Promise<RunOutcome> {
    const run = this.active.get(runId)
    return run ? run.done : Promise.reject(new Error('not an active run'))
  }

  /** N4b: one run's row for GET /runs/:id; null = no such run. */
  runRecord(runId: string): RunRecord | null {
    if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) return null
    const r = this.db.prepare(`SELECT id, node_id, caller, model, effort, mode, status, started_at, ended_at, exit_code, signal, reason,
        budget_micro, est_micro, cli_micro, basis, result_json FROM credit_headless_runs WHERE id = ?`).get(runId) as
      (Omit<RunRecord, 'result'> & { result_json: string | null }) | undefined
    if (!r) return null
    const { result_json, ...row } = r
    let result: Record<string, unknown> | null = null
    if (result_json !== null) {
      try {
        const doc = JSON.parse(result_json) as unknown
        result = isPlainObject(doc) ? doc : null
      } catch {
        result = null
      }
    }
    return { ...row, result }
  }

  private refuse(reason: string, detail?: string): StartResult {
    logger.warn({ reason, detail }, 'credit gate: headless run refused')
    return detail === undefined ? { ok: false, reason } : { ok: false, reason, detail }
  }

  /** A closing signal to the gate (disarm); only ever closes. */
  private signalGate(detail: string): void {
    try {
      this.deps.gate?.signal('disarm', SIGNAL_SOURCE, detail, this.now())
    } catch (err) {
      logger.error({ err: errCode(err), detail }, 'credit gate: the headless runner could not signal the gate')
    }
  }

  /**
   * N4b: a run id for a start that is named before it begins -- a canary,
   * whose approval is consumed for this id first. start() accepts it once.
   */
  allocateRunId(): string {
    const id = this.newRunId()
    if (typeof id !== 'string' || !RUN_ID_RE.test(id)) throw new Error('HeadlessRunner: the run id generator returned an unusable id')
    this.allocated.add(id)
    // Ids of starts that never came (a refused consume) do not pile up.
    while (this.allocated.size > MAX_ALLOCATED_RUN_IDS) this.allocated.delete(this.allocated.values().next().value as string)
    return id
  }

  /** N4b: null when `caller` may start runs, else why not (the route asks first). */
  checkCaller(caller: unknown): string | null {
    const h = this.headless()
    if (!h.ok) return h.reason
    return typeof caller === 'string' && CALLER_RE.test(caller) && h.hc.allowedCallers.includes(caller) ? null : 'caller_not_allowed'
  }

  /**
   * Step 1 of a start: everything that costs nothing. The caller comes from
   * the context only.
   */
  private admit(req: HeadlessRunRequest, ctx: StartContext): Admitted | StartRefusal {
    const no = (reason: string, detail?: string): StartRefusal => (detail === undefined ? { ok: false, reason } : { ok: false, reason, detail })
    if (this.stopped) return no('runner_stopped')
    const h = this.headless()
    if (!h.ok) return no(h.reason, h.detail)
    const hc = h.hc
    if (this.deps.gate === null) return no('gate_off')
    const gate = this.deps.gate
    if (typeof req !== 'object' || req === null || typeof ctx !== 'object' || ctx === null) return no('request_invalid')
    const caller = ctx.caller
    if (typeof caller !== 'string' || !CALLER_RE.test(caller) || !hc.allowedCallers.includes(caller)) return no('caller_not_allowed')
    if (typeof req.node_id !== 'string' || !NODE_ID_RE.test(req.node_id)) return no('node_id_invalid')
    if (typeof req.model !== 'string' || !HEADLESS_MODEL_CEILING.includes(req.model) || !hc.models.includes(req.model)) return no('model_not_allowed')
    if (typeof req.effort !== 'string' || !EFFORTS.includes(req.effort as Effort)) return no('effort_not_allowed')
    const effort = req.effort as Effort
    if (req.mode !== 'normal' && req.mode !== 'canary') return no('mode_invalid')
    const budget = parseUsd(req.budget_usd)
    if (budget === null || budget <= 0) return no('budget_invalid')
    if (budget > hc.maxBudget) return no('budget_over_max')
    if (req.mode === 'canary' && budget >= CANARY_BUDGET_LIMIT_MICRO) return no('budget_over_canary')
    if (typeof req.prompt !== 'string' || req.prompt.length === 0 || req.prompt.includes('\0') || Buffer.byteLength(req.prompt, 'utf8') > MAX_PROMPT_BYTES) {
      return no('prompt_invalid')
    }
    const cwdRules: CwdRules = {
      roots: hc.cwdRoots, forbidden: [...hc.forbiddenCwds, ...this.deps.forbiddenRoots], runsDir: hc.runsDir, treeLimits: this.deps.cwdTreeLimits,
    }
    const cwdCheck = validateCwd(req.cwd, cwdRules)
    if (!cwdCheck.ok) return no(cwdCheck.reason)
    // The config admits `read` only; refuse anything else here as well.
    if (hc.toolProfile !== 'read') return no('tool_profile_not_enabled')
    return { ok: true, hc, gate, caller, effort, budget, cwdCheck, cwdRules }
  }

  /** The pinned binary's pin and shape, and the runs directory; null = usable. */
  private admitLate(hc: HeadlessConfig): string | null {
    if (!SHA256_RE.test(hc.claudeBinSha256)) return 'binary_unpinned'
    const shape = checkBinaryShape(hc.claudeBin)
    if (!shape.ok) return shape.reason
    return this.ensureRunsDir(hc.runsDir)
  }

  /** E-05: the key when it is there and well formed; null otherwise (precheck drops the value at once). */
  private keyPresent(): string | null {
    let key: string | null
    try {
      key = this.deps.getKey()
    } catch {
      key = null
    }
    return validKey(key) ? key : null
  }

  /**
   * N4b: every check of start() except the config hash and the reservation --
   * nothing is reserved or spawned (the runs dir is created if missing). The
   * route runs it before it consumes a canary approval, so a request start()
   * would refuse anyway does not spend the owner's approval. start() checks
   * all of it again.
   */
  precheck(req: HeadlessRunRequest, ctx: StartContext): { readonly ok: true } | StartRefusal {
    const a = this.admit(req, ctx)
    if (!a.ok) return this.refuse(a.reason, a.detail) as StartRefusal
    const late = this.admitLate(a.hc)
    if (late !== null) return this.refuse(late) as StartRefusal
    if (this.keyPresent() === null) return this.refuse('key_missing') as StartRefusal
    return { ok: true }
  }

  start(req: HeadlessRunRequest, ctx: StartContext): StartResult {
    // 1. Everything that costs nothing.
    const a = this.admit(req, ctx)
    if (!a.ok) return this.refuse(a.reason, a.detail)
    const { hc, gate, caller, effort, budget, cwdCheck, cwdRules } = a

    // The run's id: one this runner allocated (once), or a fresh one.
    let runId: string
    if (ctx.runId !== undefined) {
      if (typeof ctx.runId !== 'string' || !this.allocated.delete(ctx.runId)) return this.refuse('run_id_unknown')
      runId = ctx.runId
    } else {
      runId = this.newRunId()
      if (typeof runId !== 'string' || !RUN_ID_RE.test(runId)) throw new Error('HeadlessRunner: the run id generator returned an unusable id')
    }

    // E-04: the template must be the approved one. A canary's hash comes from
    // its consumed approval's row, bound to this run id (canaryApprovedHash),
    // never from the request.
    const hash = computeRunnerConfigHash({ keyMode: hc.keyMode, toolProfile: hc.toolProfile })
    let approved: string | null = null
    try {
      if (req.mode === 'canary') {
        const id = ctx.canaryApprovalId
        approved = typeof id === 'string' && APPROVAL_ID_RE.test(id) && this.deps.canaryApprovedHash ? this.deps.canaryApprovedHash(id, runId) : null
      } else {
        approved = this.deps.approvedHash()
      }
    } catch {
      approved = null
    }
    if (typeof approved !== 'string' || approved !== hash) return this.refuse('hash_not_approved')

    const late = this.admitLate(hc)
    if (late !== null) return this.refuse(late)

    // E-05: no key, no run (and no reservation).
    const key = this.keyPresent()
    if (key === null) return this.refuse('key_missing')

    const paths = runPaths(join(hc.runsDir, runId))
    if (!isSafeRunPath(paths.root)) return this.refuse('runs_dir_unsafe')

    // 2. The reservation (C-02): the gate decides.
    const res = gate.reserve({ kind: req.mode === 'canary' ? 'canary' : 'headless', budget_micro: budget, model: req.model, ref: runId, caller })
    if (!res.enforced) return this.refuse('gate_shadow')
    if (!res.ok) return this.refuse(res.reason, res.detail)

    const startedAt = this.now()
    const wallMs = this.deps.wallClockMs ?? hc.wallClockMin * 60_000
    try {
      this.db.prepare(`INSERT INTO credit_headless_runs
          (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd, config_hash, key_mode, status, started_at, deadline_at, run_dir, cli_version)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'starting', ?, ?, ?, ?)`).run(
        runId, req.node_id, caller, req.model, effort, budget, res.reservation_id, req.mode, cwdCheck.cwd, hash, hc.keyMode,
        startedAt, startedAt + wallMs, paths.root, cliVersionOf(hc.claudeBin),
      )
    } catch (err) {
      logger.error({ err: errCode(err), run_id: runId }, 'credit gate: headless run row could not be written')
      this.safeSettle(res.reservation_id, null)
      return this.refuse('db_error')
    }

    let resolve!: (o: RunOutcome) => void
    const done = new Promise<RunOutcome>((r) => { resolve = r })
    const run: ActiveRun = {
      id: runId, nodeId: req.node_id, reservationId: res.reservation_id, reservationMicro: res.amount_micro, model: req.model, paths, key,
      child: null, pid: null, pidStart: null, startRetries: 0, stopReason: null, deadlineAt: startedAt + wallMs, reattached: false, terminating: null,
      finished: false, wallTimer: null, killTimer: null, resolve, done,
    }
    this.active.set(runId, run)
    try {
      this.launch(run, hc, { prompt: req.prompt, model: req.model, effort, budget, cwd: cwdCheck.cwd, cwdRules, hash, wallMs, keyMode: hc.keyMode })
    } catch (err) {
      this.launchThrew(run, err)
    }
    return { ok: true, run_id: runId, reservation_id: res.reservation_id, config_hash: hash, done }
  }

  /**
   * Reviewer 9: whatever threw inside the launch, the run is closed: the key
   * file goes, a started process group is killed (and the run booked by
   * B-04), an unstarted one is settled at zero, and the gate is told.
   */
  private launchThrew(run: ActiveRun, err: unknown): void {
    logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: the headless launch threw; the run is closed')
    this.signalGate('launch_threw')
    if (run.finished) return
    const ran = run.child !== null && run.pid !== null
    if (ran) {
      run.terminating = 'killed'
      try {
        this.kill(-(run.pid as number), 'SIGKILL')
      } catch {
        // already gone
      }
    }
    this.finish(run, { exitCode: null, signal: null, status: ran ? 'killed' : 'refused', reason: 'launch_threw', nothingRan: !ran })
  }

  /** null when the runs directory is usable (created 0700 if missing), else a reason. */
  private ensureRunsDir(dir: string): string | null {
    if (!isSafeRunPath(dir)) return 'runs_dir_unsafe'
    try {
      mkdirSync(dir, { recursive: true, mode: 0o700 })
      const st = lstatSync(dir)
      const uid = typeof process.getuid === 'function' ? process.getuid() : null
      if (!st.isDirectory() || realpathSync(dir) !== dir) return 'runs_dir_unsafe'
      if ((st.mode & 0o077) !== 0 || (uid !== null && st.uid !== uid)) return 'runs_dir_unsafe'
    } catch {
      return 'runs_dir_unsafe'
    }
    return null
  }

  private launch(
    run: ActiveRun,
    hc: HeadlessConfig,
    o: { prompt: string; model: string; effort: Effort; budget: Micro; cwd: string; cwdRules: CwdRules; hash: string; wallMs: number; keyMode: KeyMode },
  ): void {
    const p = run.paths
    const toolProfile: ToolProfile = hc.toolProfile
    // 3. The run directory.
    try {
      mkdirSync(p.root, { mode: 0o700 })
      for (const sub of WIPED_SUBDIRS) mkdirSync(join(p.root, sub), { mode: 0o700 })
      writePrivate(p.prompt, o.prompt)
      writePrivate(p.settings, JSON.stringify(buildRunSettings(p, o.keyMode)))
      if (o.keyMode === 'helper') writePrivate(p.key, run.key as string)
      this.deps.hooks?.afterPrepare?.(p.root)
    } catch (err) {
      logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: headless run dir could not be prepared')
      this.finish(run, { exitCode: null, signal: null, status: 'refused', reason: 'prepare_failed', nothingRan: true })
      return
    }
    let configEntries: string[]
    try {
      configEntries = readdirSync(p.config)
    } catch {
      configEntries = ['?']
    }
    if (configEntries.length > 0) {
      const reason = configEntries.includes('.credentials.json') ? 'credentials_present' : 'config_not_empty'
      this.finish(run, { exitCode: null, signal: null, status: 'refused', reason, nothingRan: true })
      return
    }

    // 4. The last checks, right before the spawn: the binary's sha256 (the
    // slow one) first, then the WHOLE cwd check again, so the window between
    // the cwd check and the spawn is as short as it can be.
    this.deps.hooks?.beforeSpawn?.(p.root)
    const bin = verifyBinary(hc.claudeBin, hc.claudeBinSha256)
    if (!bin.ok) {
      this.finish(run, { exitCode: null, signal: null, status: 'refused', reason: bin.reason, nothingRan: true })
      return
    }
    const cwdNow = validateCwd(o.cwd, o.cwdRules)
    if (!cwdNow.ok) {
      this.finish(run, { exitCode: null, signal: null, status: 'refused', reason: cwdNow.reason, nothingRan: true })
      return
    }
    let args: string[]
    let env: Record<string, string>
    try {
      args = buildRunArgs({ model: o.model, effort: o.effort, budgetMicro: o.budget, settingsPath: p.settings, toolProfile })
      env = buildRunEnv(p, o.keyMode, o.keyMode === 'env' ? run.key : null)
      const concrete = configHashOf({ args, env, settings: buildRunSettings(p, o.keyMode), keyMode: o.keyMode, runDir: p.root })
      if (concrete !== o.hash) throw new Error('the launch differs from the approved template')
    } catch (err) {
      logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: headless launch does not match its template')
      this.finish(run, { exitCode: null, signal: null, status: 'refused', reason: 'config_hash_drift', nothingRan: true })
      return
    }

    const fds: number[] = []
    let child: ChildProcess
    try {
      fds.push(openSync(p.prompt, fsc.O_RDONLY | fsc.O_NOFOLLOW))
      fds.push(openSync(p.stdout, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600))
      fds.push(openSync(p.stderr, fsc.O_WRONLY | fsc.O_CREAT | fsc.O_EXCL | fsc.O_NOFOLLOW, 0o600))
      this.db.prepare(`UPDATE credit_headless_runs SET status = 'spawning' WHERE id = ?`).run(run.id)
      child = spawnHeadless(this.spawner, hc.claudeBin, args, toolProfile, {
        cwd: o.cwd, env, detached: true, shell: false, stdio: [fds[0], fds[1], fds[2]],
      })
    } catch (err) {
      for (const fd of fds) closeSync(fd)
      logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: headless run could not be spawned')
      this.finish(run, { exitCode: null, signal: null, status: 'spawn_failed', reason: 'spawn_threw', nothingRan: true })
      return
    }
    run.child = child
    for (const fd of fds) closeSync(fd)
    if (child.pid === undefined) {
      // The spawn failed asynchronously (ENOENT, EACCES): no process ran.
      child.once('error', (err) => {
        logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: headless run could not be spawned')
        this.finish(run, { exitCode: null, signal: null, status: 'spawn_failed', reason: 'spawn_error', nothingRan: true })
      })
      return
    }
    run.pid = child.pid
    child.on('error', (err) => logger.warn({ err: errCode(err), run_id: run.id }, 'credit gate: headless child error'))
    child.once('exit', (code, signal) => this.finish(run, { exitCode: code, signal }))
    // BE-4 3: the pid is in the row BEFORE ps runs; a dashboard that dies
    // right here still leaves the pid for the next start.
    try {
      this.db.prepare(`UPDATE credit_headless_runs SET status = 'running', pid = ?, pgid = ? WHERE id = ?`).run(child.pid, child.pid, run.id)
    } catch (err) {
      logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: headless run row could not be updated')
    }
    this.recordStart(run)
    logger.info({
      run_id: run.id, node_id: run.nodeId, model: o.model, effort: o.effort, budget_micro: o.budget, child_pid: child.pid,
      cli_version: cliVersionOf(hc.claudeBin), config_hash: o.hash, key_mode: o.keyMode,
    }, 'credit gate: headless run started')
    this.deps.hooks?.afterSpawn?.()
    // Neither the binary nor the working directory may have changed while
    // the child was being started (a cwd swapped for a symlink is another inode).
    const after = checkBinaryShape(hc.claudeBin)
    const changed = !after.ok || after.identity !== bin.identity ? 'binary_changed_during_spawn'
      : pathIdentity(o.cwd) !== cwdNow.identity || realOrSelf(o.cwd) !== o.cwd ? 'cwd_changed_during_spawn' : null
    if (changed !== null) {
      logger.error({ run_id: run.id, why: changed }, 'credit gate: a check after the spawn failed; the run is stopped')
      run.terminating = 'killed'
      run.stopReason = changed
      this.signalGroup(run, 'SIGKILL')
      return
    }
    // 5. The wall clock.
    run.wallTimer = setTimeout(() => this.terminate(run, 'timeout'), o.wallMs)
    run.wallTimer.unref?.()
  }

  /**
   * The child's start time into its row. When ps cannot run, the gate is told
   * once and the next ticks try again (up to psRetryLimit); the run itself goes
   * on -- this process holds its child and needs no start time to stop it.
   */
  private recordStart(run: ActiveRun): void {
    if (run.pid === null) return
    try {
      run.pidStart = this.procStart(run.pid)
      this.db.prepare('UPDATE credit_headless_runs SET pid_start = ? WHERE id = ?').run(run.pidStart, run.id)
    } catch (err) {
      if (run.startRetries === 0) {
        logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: the headless child\'s start time is unknown (ps); retrying')
        this.signalGate('ps_unusable')
      }
      run.startRetries++
      this.ensurePoll()
    }
  }

  /** SIGTERM to the run's group now, SIGKILL after the grace period. */
  private terminate(run: ActiveRun, why: 'timeout' | 'cancelled' | 'killed'): void {
    if (run.finished || run.terminating !== null) return
    run.terminating = why
    logger.warn({ run_id: run.id, why }, 'credit gate: stopping a headless run')
    this.signalGroup(run, 'SIGTERM')
    run.killTimer = setTimeout(() => this.signalGroup(run, 'SIGKILL'), this.killGraceMs)
    run.killTimer.unref?.()
  }

  /** Signal the run's process group; a re-attached run only while its pid is provably still that process. */
  private signalGroup(run: ActiveRun, sig: NodeJS.Signals): void {
    if (run.pid === null || run.finished) return
    if (run.reattached && this.liveness(run.pid, run.pidStart) !== 'alive') return
    try {
      this.kill(-run.pid, sig)
    } catch (err) {
      if (errCode(err) !== 'ESRCH') logger.warn({ err: errCode(err), run_id: run.id }, 'credit gate: signalling a headless run failed')
    }
  }

  /**
   * `alive`: pid exists and started at `start`; `gone`: no such pid, or it
   * started at another time (a reused pid); `unknown`: no start time to
   * compare, or ps cannot run. Only `alive` is ever signalled.
   */
  private liveness(pid: number, start: string | null): 'alive' | 'gone' | 'unknown' {
    try {
      this.kill(pid, 0)
    } catch (err) {
      if (errCode(err) !== 'EPERM') return 'gone'
    }
    if (start === null) return 'unknown'
    try {
      const now = this.procStart(pid)
      return now === null ? 'gone' : now === start ? 'alive' : 'gone'
    } catch {
      return 'unknown'
    }
  }

  /** True only while `pid` is provably the process that started at `start`. */
  processMatches(pid: number, start: string | null): boolean {
    return this.liveness(pid, start) === 'alive'
  }

  /** N4b: stop a run (SIGTERM, then SIGKILL); false when it is not running here. */
  cancel(runId: string): boolean {
    const run = this.active.get(runId)
    if (!run || run.finished) return false
    this.terminate(run, 'cancelled')
    return true
  }

  /**
   * The dashboard is going away (a signal, exit, stop()): every run's group
   * gets SIGTERM, a short wait, SIGKILL; then each run is closed right here,
   * synchronously (the key file goes, the reservation is settled).
   */
  killAllSync(): void {
    const runs = [...this.active.values()].filter((r) => !r.finished)
    for (const run of runs) {
      run.terminating ??= 'killed'
      this.signalGroup(run, 'SIGTERM')
    }
    const end = Date.now() + SHUTDOWN_GRACE_MS
    while (Date.now() < end && runs.some((r) => r.pid !== null && this.groupExists(r.pid))) sleepSync(20)
    for (const run of runs) {
      this.signalGroup(run, 'SIGKILL')
      this.finish(run, { exitCode: null, signal: null, status: 'killed', reason: 'dashboard_shutdown' })
    }
  }

  private groupExists(pgid: number): boolean {
    try {
      this.kill(-pgid, 0)
      return true
    } catch (err) {
      return errCode(err) === 'EPERM'
    }
  }

  /** Stop polling, stop every run of this runner, and leave the process-wide guard. */
  stop(): void {
    this.stopped = true
    this.killAllSync()
    if (this.poll !== null) clearInterval(this.poll)
    this.poll = null
    this.pending.clear()
    if (this.settleRetries.size > 0) {
      logger.error({ run_ids: [...this.settleRetries.keys()] }, 'credit gate: unsettled headless reservations at stop; they stay counted until stale')
    }
    this.settleRetries.clear()
    liveRunners.delete(this)
    if (liveRunners.size === 0) uninstallGuards()
  }

  private ensurePoll(): void {
    if (this.poll !== null || this.stopped) return
    this.poll = setInterval(() => this.tick(), this.pollMs)
    this.poll.unref?.()
  }

  /** One poll: start times still missing, re-attached runs, rows waiting for ps. */
  private tick(): void {
    for (const run of [...this.active.values()]) {
      if (run.finished || run.pid === null) continue
      try {
        if (!run.reattached) {
          if (run.pidStart === null && run.startRetries > 0 && run.startRetries < this.psRetryLimit) this.recordStart(run)
          continue
        }
        const l = this.liveness(run.pid, run.pidStart)
        if (l === 'gone') {
          this.killRunProcesses(run.id, run.paths.root, run.pid)
          this.finish(run, { exitCode: null, signal: null })
        } else if (l === 'alive' && run.deadlineAt !== null && this.now() >= run.deadlineAt) {
          this.terminate(run, 'timeout')
        }
      } catch (err) {
        logger.error({ err: errCode(err), run_id: run.id }, 'credit gate: watching a headless run failed')
      }
    }
    for (const [id, n] of [...this.pending]) {
      try {
        const row = this.openRows(true).find((r) => r.id === id)
        if (!row) {
          this.pending.delete(id)
          continue
        }
        if (this.reconcileRow(row) !== 'pending') {
          this.pending.delete(id)
        } else if (n + 1 >= this.psRetryLimit) {
          this.pending.delete(id)
          this.closeWithoutTouching(row, 'unverifiable', { book: true, removeKey: true })
        } else {
          this.pending.set(id, n + 1)
        }
      } catch (err) {
        logger.error({ err: errCode(err), run_id: id }, 'credit gate: retrying a headless run row failed')
      }
    }
    for (const ps of [...this.settleRetries.values()]) {
      ps.attempts++
      try {
        this.settleOrThrow(ps.reservationId, ps.booking)
        this.settleRetries.delete(ps.runId)
        this.copyBooking(ps.runId)
        logger.warn({ run_id: ps.runId, attempts: ps.attempts }, 'credit gate: a headless reservation settled on a retry')
      } catch (err) {
        if (ps.attempts >= this.settleRetryLimit) {
          this.settleRetries.delete(ps.runId)
          logger.error({ err: errCode(err), run_id: ps.runId, attempts: ps.attempts }, 'credit gate: a headless reservation could not be settled; it stays counted')
          this.signalGate('settle_failed')
        }
      }
    }
    const busy = this.pending.size > 0 || this.settleRetries.size > 0
      || [...this.active.values()].some((r) => !r.finished && (r.reattached || (r.pidStart === null && r.startRetries > 0 && r.startRetries < this.psRetryLimit)))
    if (!busy && this.poll !== null) {
      clearInterval(this.poll)
      this.poll = null
    }
  }

  // ---------------------------------------------------------------- restart (reconcile.ts)

  /** Rows of unfinished runs that no runner of this process is holding (pending ones too, with `all`). */
  openRows(all = false): RunRow[] {
    const marks = OPEN_RUN_STATUSES.map(() => '?').join(', ')
    const rows = this.db.prepare(`SELECT id, node_id, model, reservation_id, key_mode, pid, pid_start, pgid, status, deadline_at, run_dir
      FROM credit_headless_runs WHERE status IN (${marks}) ORDER BY started_at, id`).all(...OPEN_RUN_STATUSES) as RunRow[]
    return rows.filter((r) => !this.active.has(r.id) && (all || !this.pending.has(r.id)))
  }

  /**
   * BE-4 1: null when the row may be acted on, else why not. The id must be a
   * run id, run_dir exactly <runsDir>/<id> (not a symlink, the runs dir
   * canonical), a pid's group the pid itself, and the reservation this run's.
   */
  private untrustedWhy(row: RunRow, hc: HeadlessConfig): string | null {
    if (typeof row.id !== 'string' || !RUN_ID_RE.test(row.id)) return 'id'
    const expected = join(hc.runsDir, row.id)
    if (row.run_dir !== expected) return 'run_dir'
    try {
      if (realpathSync(hc.runsDir) !== hc.runsDir) return 'run_dir'
      const st = lstatSync(row.run_dir)
      if (!st.isDirectory() || realpathSync(row.run_dir) !== realpathSync(expected)) return 'run_dir'
    } catch (err) {
      if (errCode(err) !== 'ENOENT') return 'run_dir'
    }
    if (row.pid !== null && (!Number.isSafeInteger(row.pid) || row.pid <= 1 || row.pgid !== row.pid)) return 'pgid'
    if (!this.ownsReservation(row)) return 'reservation'
    return null
  }

  /** The row's reservation exists, is a headless/canary one, and was taken for this run id. */
  private ownsReservation(row: RunRow): boolean {
    const res = this.db.prepare('SELECT kind, ref FROM credit_reservations WHERE id = ?').get(row.reservation_id) as { kind: string; ref: string | null } | undefined
    return res !== undefined && res.ref === row.id && (res.kind === 'headless' || res.kind === 'canary')
  }

  /**
   * Decide one unfinished row of a previous dashboard: `reattached` (alive and
   * provably ours), `closed` (B-04, or untrusted), or `pending` (ps cannot
   * run now: the row stays open, the gate is told once, a later tick retries).
   */
  reconcileRow(row: RunRow): 'reattached' | 'closed' | 'pending' {
    const h = this.headless()
    // Without a valid config the row cannot be checked: wait, do not judge it.
    if (!h.ok) return this.pend(row, 'config_invalid', null)
    const why = this.untrustedWhy(row, h.hc)
    if (why !== null) {
      // Book only a reservation that is provably this row's (round 2): a
      // forged row must not settle another run's reservation.
      const book = (why === 'run_dir' || why === 'pgid') && this.ownsReservation(row)
      this.closeWithoutTouching(row, `untrusted_row:${why}`, { book, removeKey: false })
      return 'closed'
    }
    if (row.status === 'starting') {
      this.closeRow(row, { status: 'refused', reason: 'interrupted_before_spawn' })
      return 'closed'
    }
    let members: ProcInfo[]
    let start: string | null = null
    try {
      members = runProcesses(this.listProcesses(), row.run_dir, h.hc.claudeBin, row.pid)
      if (row.pid !== null) start = this.procStart(row.pid)
    } catch (err) {
      return this.pend(row, 'ps_unusable', err)
    }
    if (row.pid !== null && start !== null) {
      const leader = members.find((p) => p.pid === row.pid && runLeaderOf(p.command, row.run_dir, h.hc.claudeBin))
      // Alive, its argv names this run, and the start time is the recorded one
      // (or none was recorded: then the argv decides, and the start is kept).
      if (leader && leader.start === start && (row.pid_start === null || row.pid_start === start)) {
        if (row.pid_start === null) this.db.prepare('UPDATE credit_headless_runs SET pid_start = ? WHERE id = ?').run(start, row.id)
        this.reattach({ ...row, pid_start: start })
        return 'reattached'
      }
    }
    this.killMembers(row.id, members)
    this.closeRow(row, { status: 'lost', reason: row.pid === null ? 'interrupted_at_spawn' : 'process_gone' })
    return 'closed'
  }

  /** The row stays open; the gate is told once; the tick retries (psRetryLimit). */
  private pend(row: RunRow, why: string, err: unknown): 'pending' {
    if (!this.pending.has(row.id)) {
      logger.error({ err: err === null ? undefined : errCode(err), run_id: row.id, why }, 'credit gate: a headless run row cannot be checked now; it stays open')
      this.signalGate(why)
      this.pending.set(row.id, 0)
      this.ensurePoll()
    }
    return 'pending'
  }

  private runFromRow(row: RunRow): ActiveRun {
    const amount = this.db.prepare('SELECT amount_micro FROM credit_reservations WHERE id = ?').get(row.reservation_id) as { amount_micro: number } | undefined
    let resolve!: (o: RunOutcome) => void
    const done = new Promise<RunOutcome>((r) => { resolve = r })
    return {
      id: row.id, nodeId: row.node_id, reservationId: row.reservation_id, reservationMicro: amount?.amount_micro ?? 0, model: row.model,
      paths: runPaths(row.run_dir), key: null, child: null, pid: row.pid, pidStart: row.pid_start, startRetries: 0, stopReason: null, deadlineAt: row.deadline_at,
      reattached: true, terminating: null, finished: false, wallTimer: null, killTimer: null, resolve, done,
    }
  }

  /** A live run of a previous dashboard: watch it until it ends (and stop it at its wall clock). */
  reattach(row: RunRow): void {
    if (row.pid === null) throw new Error('reattach: no pid')
    const run = this.runFromRow(row)
    this.active.set(run.id, run)
    logger.info({ run_id: run.id, child_pid: run.pid }, 'credit gate: headless run re-attached after a restart')
    this.ensurePoll()
  }

  /**
   * A trusted run whose process is gone (or never started): close it now.
   * `lost` books by B-04; `refused` (it never reached the spawn) settles at zero.
   */
  closeRow(row: RunRow, how: { status: 'lost' | 'refused'; reason: string }): RunOutcome {
    const run = this.runFromRow(row)
    this.active.set(run.id, run)
    this.finish(run, { exitCode: null, signal: null, status: how.status, reason: how.reason, nothingRan: how.status === 'refused' })
    return this.outcomeOf(run.id)
  }

  /**
   * A row that must not steer any file or process action: `lost`, nothing
   * wiped, scanned or signalled, and the gate told. With `book` the whole
   * reservation is booked (only when the reservation is provably this row's);
   * otherwise it stays open and counts in full until the gate's own expiry.
   * `removeKey` only for a row whose run dir passed the checks.
   */
  private closeWithoutTouching(row: RunRow, reason: string, o: { book: boolean; removeKey: boolean }): void {
    logger.error({ run_id: RUN_ID_RE.test(String(row.id)) ? row.id : '?', reason }, 'credit gate: a headless run row is closed without touching files or processes')
    this.signalGate(reason.startsWith('untrusted_row') ? 'untrusted_row' : reason)
    const errors: string[] = []
    if (o.removeKey) {
      try {
        removeFile(join(row.run_dir, 'key'))
      } catch {
        errors.push('key')
      }
    }
    let booked: { basis: string; est_micro: number | null; cli_micro: number | null } | undefined
    if (o.book) {
      try {
        const r = this.deps.gate?.settleHeadless(row.reservation_id, {
          run_id: row.id, ended_at_s: Math.max(1, Math.floor(this.now() / 1000)), model: row.model, reservation_micro: 0 as Micro, result: null, transcript_dir: null,
        }, this.now())
        if (!r || !r.ok) errors.push('settle')
        booked = this.db.prepare('SELECT basis, est_micro, cli_micro FROM credit_ledger_entries WHERE dedupe_key = ?')
          .get(`${HEADLESS_SOURCE}:${row.id}`) as typeof booked
      } catch (err) {
        errors.push('settle')
        logger.error({ err: errCode(err) }, 'credit gate: booking an untrusted headless run failed')
      }
    }
    try {
      this.db.prepare(`UPDATE credit_headless_runs SET status = 'lost', ended_at = ?, reason = ?, basis = ?, est_micro = ?, cli_micro = ?, errors_json = ?
        WHERE id = ?`).run(this.now(), reason, booked?.basis ?? null, booked?.est_micro ?? null, booked?.cli_micro ?? null,
        errors.length > 0 ? JSON.stringify(errors) : null, row.id)
    } catch (err) {
      logger.error({ err: errCode(err) }, 'credit gate: closing an untrusted headless run row failed')
    }
  }

  /**
   * BE-4b N1: the settle retry lives in memory, so a restart forgets it. At
   * startup (reconcile.ts, after the open rows are decided) a CLOSED run row
   * whose own reservation (ref = the row id, a headless or canary one) is
   * still open or unknown is settled here: a refused or spawn_failed run at
   * zero, as its own end does; any other by B-04, the whole reservation (its
   * run dir and its JSON answer are gone; the overstatement only closes the
   * gate sooner). No file or process is touched. A settle that fails goes to
   * the tick's retry. Unfinished rows (re-attached, pending) are never
   * touched: only closed statuses, and never a run this runner holds.
   * Idempotent: a settled reservation is not selected again, and the ledger
   * books a run once.
   */
  settleClosedRows(): { settled: string[]; retrying: string[] } {
    const out = { settled: [] as string[], retrying: [] as string[] }
    if (this.stopped || this.deps.gate === null) return out
    const marks = OPEN_RUN_STATUSES.map(() => '?').join(', ')
    const rows = this.db.prepare(`SELECT h.id, h.model, h.status, h.reservation_id FROM credit_headless_runs h
      JOIN credit_reservations r ON r.id = h.reservation_id
      WHERE h.status NOT IN (${marks}) AND r.status IN ('open', 'unknown') AND r.ref = h.id AND r.kind IN ('headless', 'canary')
      ORDER BY h.started_at, h.id`).all(...OPEN_RUN_STATUSES) as Array<{ id: string; model: string; status: RunStatus; reservation_id: string }>
    for (const row of rows) {
      if (!RUN_ID_RE.test(row.id) || this.active.has(row.id) || this.pending.has(row.id) || this.settleRetries.has(row.id)) continue
      const nothingRan = row.status === 'refused' || row.status === 'spawn_failed'
      const booking: HeadlessRun | null = nothingRan ? null : {
        run_id: row.id, ended_at_s: Math.max(1, Math.floor(this.now() / 1000)), model: row.model, reservation_micro: 0 as Micro, result: null, transcript_dir: null,
      }
      try {
        this.settleOrThrow(row.reservation_id, booking)
        this.copyBooking(row.id)
        out.settled.push(row.id)
        logger.warn({ run_id: row.id, status: row.status, at_zero: nothingRan }, 'credit gate: a closed headless run\'s open reservation settled at startup')
      } catch (err) {
        this.settleRetries.set(row.id, { runId: row.id, reservationId: row.reservation_id, booking, attempts: 0 })
        this.ensurePoll()
        out.retrying.push(row.id)
        logger.error({ err: errCode(err), run_id: row.id }, 'credit gate: a closed headless run\'s open reservation could not be settled at startup; the tick retries')
      }
    }
    return out
  }

  /** SIGKILL to processes already proven to be this run's (runProcesses). */
  private killMembers(runId: string, members: readonly ProcInfo[]): void {
    for (const p of members) {
      if (p.pid === process.pid || p.pid <= 1) continue
      try {
        this.kill(p.pid, 'SIGKILL')
        logger.warn({ run_id: runId, orphan_pid: p.pid }, 'credit gate: killed a process of a headless run that nobody watches')
      } catch {
        // already gone
      }
    }
  }

  /** The processes of a run that ended while nobody held it (runProcesses, never by a bare group id). */
  private killRunProcesses(runId: string, runDir: string, pgid: number | null): void {
    const h = this.headless()
    if (!h.ok) {
      logger.warn({ run_id: runId }, 'credit gate: no valid config; leftovers of a headless run not checked')
      return
    }
    let procs: readonly ProcInfo[]
    try {
      procs = this.listProcesses()
    } catch (err) {
      logger.warn({ err: errCode(err), run_id: runId }, 'credit gate: the process list is not readable; leftovers not checked')
      return
    }
    this.killMembers(runId, runProcesses(procs, runDir, h.hc.claudeBin, pgid))
  }

  private outcomeOf(id: string): RunOutcome {
    const r = this.db.prepare('SELECT * FROM credit_headless_runs WHERE id = ?').get(id) as Record<string, unknown>
    return {
      run_id: id, status: r.status as RunStatus, exit_code: r.exit_code as number | null, signal: r.signal as string | null,
      basis: r.basis as LedgerBasis | null, est_micro: r.est_micro as number | null, cli_micro: r.cli_micro as number | null,
      residue: r.residue_json ? JSON.parse(r.residue_json as string) as string[] : [], reason: r.reason as string | null,
      credit_too_low: false, auth_error: false, errors: r.errors_json ? JSON.parse(r.errors_json as string) as string[] : [],
    }
  }

  /** Book and settle a run's reservation; throws when the gate refuses or fails. */
  private settleOrThrow(reservationId: string, booking: HeadlessRun | null): void {
    const gate = this.deps.gate
    if (gate === null) throw new Error('no gate')
    const r = gate.settleHeadless(reservationId, booking, this.now())
    if (!r.ok) throw new Error(`settle refused: ${r.reason}`)
  }

  /** After a retried settle: the run row gets what the ledger booked. */
  private copyBooking(runId: string): void {
    try {
      const b = this.db.prepare('SELECT basis, est_micro, cli_micro FROM credit_ledger_entries WHERE dedupe_key = ?')
        .get(`${HEADLESS_SOURCE}:${runId}`) as { basis: string; est_micro: number | null; cli_micro: number | null } | undefined
      if (b) this.db.prepare('UPDATE credit_headless_runs SET basis = ?, est_micro = ?, cli_micro = ? WHERE id = ?').run(b.basis, b.est_micro, b.cli_micro, runId)
    } catch (err) {
      logger.error({ err: errCode(err), run_id: runId }, 'credit gate: the run row could not take its booking')
    }
  }

  private safeSettle(reservationId: string, run: HeadlessRun | null): OpResult | null {
    try {
      return this.deps.gate?.settleHeadless(reservationId, run, this.now()) ?? null
    } catch (err) {
      logger.error({ err: errCode(err) }, 'credit gate: settling a headless reservation threw')
      return null
    }
  }

  // ---------------------------------------------------------------- the end of a run

  private finish(run: ActiveRun, how: EndHow): void {
    if (run.finished) return
    run.finished = true
    if (run.wallTimer) clearTimeout(run.wallTimer)
    if (run.killTimer) clearTimeout(run.killTimer)
    const p = run.paths
    const errors: string[] = []
    const step = (name: string, fn: () => void): void => {
      try {
        fn()
      } catch (err) {
        errors.push(name)
        logger.error({ err: errCode(err), run_id: run.id, step: name }, 'credit gate: headless run cleanup step failed')
      }
    }

    // The key file first, whatever else happens.
    step('key', () => removeFile(p.key))
    // Whatever is left of the group (an own child just exited; its pgid is
    // still ours while any member lives).
    if (run.child !== null && run.pid !== null && !how.nothingRan) {
      step('group', () => {
        try {
          this.kill(-run.pid!, 'SIGKILL')
        } catch (err) {
          if (errCode(err) !== 'ESRCH') throw err
        }
      })
    }

    let parsed: ParsedResult | null = null
    if (!how.nothingRan) {
      step('read', () => {
        const tail = readBounded(p.stderr, STDERR_TAIL_BYTES, true)
        parsed = parseHeadlessResult(readBounded(p.stdout, MAX_STDOUT_BYTES), tail ? tail.toString('utf8') : '', run.model)
      })
    }
    const result = parsed as ParsedResult | null

    let key = run.key
    if (key === null) {
      try {
        key = this.deps.getKey()
      } catch {
        key = null
      }
      if (!validKey(key)) key = null
    }
    let hits: ResidueHit[] = []
    step('scan', () => {
      hits = scanDetailed(p.root, keyNeedles(key), [Buffer.from(KEY_MARKER, 'utf8')])
      if (key === null) errors.push('scan_without_key')
    })

    if (result?.creditTooLow) step('signal', () => { this.deps.gate?.signal('credit_balance_too_low', SIGNAL_SOURCE, run.id, this.now()) })
    if (result?.authError) step('signal', () => { this.deps.gate?.signal('auth_401', SIGNAL_SOURCE, run.id, this.now()) })

    // The booking, before the wipe: the transcript fallback reads config/.
    const booking: HeadlessRun | null = how.nothingRan ? null : {
      run_id: run.id,
      ended_at_s: Math.max(1, Math.floor(this.now() / 1000)),
      model: run.model,
      reservation_micro: run.reservationMicro as Micro,
      result: result?.ledger ?? null,
      transcript_dir: join(p.config, 'projects'),
    }
    step('settle', () => {
      try {
        this.settleOrThrow(run.reservationId, booking)
      } catch (err) {
        // BE-4b P5: retried by the tick (the run dir is gone by then: the JSON, else the whole reservation).
        this.settleRetries.set(run.id, { runId: run.id, reservationId: run.reservationId, booking, attempts: 0 })
        this.ensurePoll()
        throw err
      }
    })

    // Nothing of the run stays on disk: the child's dirs, the prompt, the
    // settings, the answer (stdout.json -- kept, filtered, in the row) and
    // stderr, and any other file that carried key material.
    step('wipe', () => {
      for (const sub of WIPED_SUBDIRS) rmSync(join(p.root, sub), { recursive: true, force: true })
      for (const f of [p.prompt, p.settings, p.stdout, p.stderr]) removeFile(f)
      for (const h of hits) {
        const top = h.name.split('/')[0]
        if ((WIPED_SUBDIRS as readonly string[]).includes(top)) continue
        const full = join(p.root, h.name)
        // Never followed a link while scanning: the parent is inside the run dir.
        if (within(realOrSelf(dirname(full)), realOrSelf(p.root))) removeFile(full)
      }
      try {
        rmdirSync(p.root)
      } catch (err) {
        if (errCode(err) !== 'ENOENT' && errCode(err) !== 'ENOTEMPTY') throw err
      }
    })

    type Booked = { basis: LedgerBasis; est_micro: number | null; cli_micro: number | null }
    let bookedRow: Booked | undefined
    step('ledger', () => {
      bookedRow = this.db.prepare('SELECT basis, est_micro, cli_micro FROM credit_ledger_entries WHERE dedupe_key = ?')
        .get(`${HEADLESS_SOURCE}:${run.id}`) as Booked | undefined
    })
    const booked = bookedRow as Booked | undefined

    const secretHit = hits.some((h) => h.secret)
    let status: RunStatus
    if (how.status === 'refused' || how.status === 'spawn_failed') status = how.status
    else if (run.terminating === 'timeout') status = 'timeout'
    else if (run.terminating === 'cancelled') status = 'cancelled'
    else if (how.status !== undefined) status = how.status
    else if (run.terminating === 'killed') status = 'killed'
    else if (result?.isError === false && (how.exitCode === 0 || (run.reattached && how.exitCode === null))) status = 'succeeded'
    else status = run.reattached ? 'lost' : 'failed'
    if (secretHit && status !== 'refused' && status !== 'spawn_failed') status = 'secret_residue'

    const residue = hits.map((h) => h.name)
    if (hits.length > 0) {
      const log = secretHit ? logger.error.bind(logger) : logger.warn.bind(logger)
      log({ run_id: run.id, files: residue, key_material: secretHit }, 'credit gate: headless run dir carried key material; files removed')
    }
    const outcome: RunOutcome = {
      run_id: run.id,
      status,
      exit_code: how.exitCode,
      signal: how.signal,
      basis: booked?.basis ?? null,
      est_micro: booked?.est_micro ?? null,
      cli_micro: booked?.cli_micro ?? null,
      residue,
      reason: how.reason ?? run.stopReason,
      credit_too_low: result?.creditTooLow ?? false,
      auth_error: result?.authError ?? false,
      errors,
    }
    let resultJson: string | null = null
    if (result) {
      const doc: Record<string, unknown> = { ...result.summary }
      if (result.answer !== null) doc.result = filterAnswer(result.answer, key)
      resultJson = JSON.stringify(doc)
    }
    step('row', () => {
      this.db.prepare(`UPDATE credit_headless_runs SET status = ?, ended_at = ?, exit_code = ?, signal = ?, result_json = ?,
          est_micro = ?, cli_micro = ?, basis = ?, reason = ?, residue_json = ?, errors_json = ? WHERE id = ?`).run(
        status, this.now(), how.exitCode, how.signal, resultJson,
        outcome.est_micro, outcome.cli_micro, outcome.basis, outcome.reason, residue.length > 0 ? JSON.stringify(residue) : null,
        errors.length > 0 ? JSON.stringify(errors) : null, run.id,
      )
    })
    const log = status === 'succeeded' ? logger.info.bind(logger) : logger.warn.bind(logger)
    log({
      run_id: run.id, status, exit_code: how.exitCode, signal: how.signal, basis: outcome.basis, est_micro: outcome.est_micro,
      cli_micro: outcome.cli_micro, reason: outcome.reason, errors,
    }, 'credit gate: headless run ended')
    this.active.delete(run.id)
    run.resolve(outcome)
  }
}
