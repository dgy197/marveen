// Memory write gate, b1: transport to the Python adapter (card 3e9f6c28, node G2b).
//
// One child per round: /usr/bin/python3 -I scripts/memory-gate/gate_adapter.py,
// shell:false, an EXACT four-key environment (nothing of the dashboard's env
// leaks through: no proxy, no SSLKEYLOGFILE, no PYTHONPATH), cwd under
// store/iras-kapu/run. Protocol: blueprint r5 4.3.
//
// The dashboard process never holds the API key or the tokens: the key is read
// by the shared client (Vault), the tokens by the adapter, inside the child.
// stderr is discarded (only its length reaches the log), stdout is capped at
// 256 KB, and the whole round has a hard deadline (30 s per call + 10 s); on
// the deadline the child is SIGKILLed and every unanswered call is
// `maybe_billed` (it may have reached the API).
//
// Test guard: under vitest the batch and store directories must resolve under
// os.tmpdir(), so no test can ever drive the real client (and api.anthropic.com).
import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process'
import { mkdirSync, realpathSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, isAbsolute, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { logger } from '../logger.js'

export const GATE_CALLER = 'memoria-iras-kapu'
export const GATE_PYTHON = '/usr/bin/python3'
export const MAX_CALLS_PER_SPAWN = 5
export const MAX_STDOUT_BYTES = 256 * 1024
export const MAX_TEXT_BYTES = 4096

/** Every error class the adapter may report; anything else is read as `error`. */
export const GATE_ERROR_CLASSES = [
  'stopped', 'transient', 'maybe_billed', 'credit', 'auth', 'bad_request', 'usage_log_failed',
  'secret_residue', 'residue_check_unavailable', 'error', 'untrusted_batch_dir', 'contract_mismatch',
] as const
export type GateErrorClass = typeof GATE_ERROR_CLASSES[number]

export interface GateCall {
  /** Decision id as a decimal string. */
  k: string
  model: string
  max_tokens: number
  system: string
  prompt: string
}

export type GateCallResult =
  | { k: string; ok: true; text: string }
  | { k: string; ok: false; error: GateErrorClass }

export type SpawnFn = (cmd: string, args: readonly string[], opts: SpawnOptions) => ChildProcess

export interface TransportOptions {
  batchDir: string
  storeDir: string
  /** Per-call budget handed to ask(); also sizes the hard deadline. Default 30. */
  callTimeoutS?: number
  /** Extra seconds on top of callTimeoutS x calls before SIGKILL. Default 10. */
  graceS?: number
  spawn?: SpawnFn
  adapterPath?: string
  /** Defaults to process.env.VITEST being set. */
  underTest?: boolean
}

const HERE = dirname(fileURLToPath(import.meta.url))
// src/memory-gate -> repo root; dist/memory-gate -> repo root as well.
export const DEFAULT_ADAPTER = resolve(HERE, '..', '..', 'scripts', 'memory-gate', 'gate_adapter.py')

function allErr(calls: GateCall[], error: GateErrorClass): GateCallResult[] {
  return calls.map(c => ({ k: c.k, ok: false as const, error }))
}

function isUnder(path: string, root: string): boolean {
  try {
    const real = realpathSync(path)
    const r = realpathSync(root)
    return real === r || real.startsWith(r.endsWith(sep) ? r : r + sep)
  } catch {
    return false
  }
}

/** The exact child environment (4.3): nothing else crosses. */
export function gateChildEnv(): Record<string, string> {
  return {
    PATH: '/usr/bin:/bin',
    HOME: homedir(),
    LANG: 'en_US.UTF-8',
    PYTHONDONTWRITEBYTECODE: '1',
  }
}

/** Parse the adapter's stdout against the calls we sent; missing answers are maybe_billed. */
export function parseAdapterOutput(raw: string, calls: GateCall[]): GateCallResult[] {
  let parsed: unknown
  try { parsed = JSON.parse(raw) } catch { return allErr(calls, 'maybe_billed') }
  const p = parsed as { v?: unknown; results?: unknown }
  if (!p || typeof p !== 'object' || p.v !== 1 || !Array.isArray(p.results)) return allErr(calls, 'maybe_billed')
  const wanted = new Set(calls.map(c => c.k))
  const got = new Map<string, GateCallResult>()
  for (const r of p.results as unknown[]) {
    const o = r as { k?: unknown; ok?: unknown; text?: unknown; error?: unknown }
    if (!o || typeof o !== 'object' || typeof o.k !== 'string' || !wanted.has(o.k) || got.has(o.k)) continue
    if (o.ok === true && typeof o.text === 'string' && Buffer.byteLength(o.text, 'utf8') <= MAX_TEXT_BYTES) {
      got.set(o.k, { k: o.k, ok: true, text: o.text })
    } else if (o.ok === false && typeof o.error === 'string' && (GATE_ERROR_CLASSES as readonly string[]).includes(o.error)) {
      got.set(o.k, { k: o.k, ok: false, error: o.error as GateErrorClass })
    } else {
      got.set(o.k, { k: o.k, ok: false, error: 'error' })
    }
  }
  // No answer for a call = we cannot know whether it reached the API.
  return calls.map(c => got.get(c.k) ?? { k: c.k, ok: false as const, error: 'maybe_billed' as const })
}

/**
 * Run up to five calls through one adapter child. Never throws; every call
 * gets exactly one result, in the order given.
 */
export async function runGateCalls(calls: GateCall[], opts: TransportOptions): Promise<GateCallResult[]> {
  if (calls.length === 0) return []
  if (calls.length > MAX_CALLS_PER_SPAWN) return allErr(calls, 'error')
  for (const c of calls) {
    if (!/^[0-9]{1,18}$/.test(c.k)) return allErr(calls, 'error')
  }
  if (!isAbsolute(opts.batchDir) || !isAbsolute(opts.storeDir)) return allErr(calls, 'untrusted_batch_dir')
  const underTest = opts.underTest ?? Boolean(process.env.VITEST)
  if (underTest && !(isUnder(opts.batchDir, tmpdir()) && isUnder(opts.storeDir, tmpdir()))) {
    // A test must never drive the real client: refuse before any spawn.
    return allErr(calls, 'untrusted_batch_dir')
  }
  const callTimeoutS = Math.max(1, Math.min(30, Math.floor(opts.callTimeoutS ?? 30)))
  const graceS = Math.max(0, opts.graceS ?? 10)
  const runDir = join(opts.storeDir, 'iras-kapu', 'run')
  try { mkdirSync(runDir, { recursive: true, mode: 0o700 }) } catch { return allErr(calls, 'error') }

  const request = JSON.stringify({ v: 1, caller: GATE_CALLER, timeout_s: callTimeoutS, calls })
  const spawnFn: SpawnFn = opts.spawn ?? (nodeSpawn as unknown as SpawnFn)
  const args = ['-I', opts.adapterPath ?? DEFAULT_ADAPTER, '--batch-dir', opts.batchDir, '--store-dir', opts.storeDir]

  return await new Promise<GateCallResult[]>((resolvePromise) => {
    let child: ChildProcess
    try {
      child = spawnFn(GATE_PYTHON, args, { cwd: runDir, env: gateChildEnv(), shell: false, stdio: ['pipe', 'pipe', 'pipe'] })
    } catch {
      resolvePromise(allErr(calls, 'error'))
      return
    }
    const chunks: Buffer[] = []
    let stdoutBytes = 0
    let stderrBytes = 0
    let overflow = false
    let killedByDeadline = false
    let settled = false
    const finish = (results: GateCallResult[]) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      resolvePromise(results)
    }
    const timer = setTimeout(() => {
      killedByDeadline = true
      try { child.kill('SIGKILL') } catch { /* already gone */ }
    }, (callTimeoutS * calls.length + graceS) * 1000)

    child.stdout?.on('data', (d: Buffer) => {
      if (overflow) return
      stdoutBytes += d.length
      if (stdoutBytes > MAX_STDOUT_BYTES) {
        overflow = true
        try { child.kill('SIGKILL') } catch { /* already gone */ }
        return
      }
      chunks.push(d)
    })
    // stderr content is never kept or logged: it could carry anything.
    child.stderr?.on('data', (d: Buffer) => { stderrBytes += d.length })
    child.on('error', () => {
      try { logger.warn({ stderrBytes }, 'memory-gate: adapter spawn failed') } catch { /* ignore */ }
      finish(allErr(calls, 'error'))
    })
    child.on('close', (code, signal) => {
      try { logger.debug({ code, signal, stderrBytes, stdoutBytes }, 'memory-gate: adapter exited') } catch { /* ignore */ }
      if (overflow) { finish(allErr(calls, 'error')); return }
      if (killedByDeadline) { finish(allErr(calls, 'maybe_billed')); return }
      finish(parseAdapterOutput(Buffer.concat(chunks).toString('utf8'), calls))
    })
    try {
      child.stdin?.on('error', () => { /* child died early; close decides */ })
      child.stdin?.end(request)
    } catch { /* close decides */ }
  })
}
