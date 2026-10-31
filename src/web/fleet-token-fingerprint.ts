// Fleet-token fingerprint + launch registry (card acdb8045 K2).
//
// Why: Claude Code reads CLAUDE_CODE_OAUTH_TOKEN once, from the launch env. When
// store/.claude-oauth-token is swapped, sessions started before the swap keep the
// old identity. To SEE that, each launcher records a fingerprint of the token it
// exported (stamp, written BEFORE `tmux new-session`), and the detector compares
// the stamp with the file as it is now.
//
// Hygiene (the whole point of this module):
//  - The fingerprint is the first 16 hex chars of sha256(trimmed token). It is a
//    local comparison key: it is compared in memory and persisted ONLY in the
//    0600 launch registry (store/fleet-token-launch.json). It is never returned
//    by an API, written to a log, put in an error string or passed in argv.
//  - This module imports no logger and never builds an error string from an
//    exception: every failure is a fixed string, so a path/fs message that could
//    carry content cannot leak.
//  - The token value itself never leaves fingerprintOfToken's argument scope.
//
// Everything is IO-injected (FleetTokenIO) so the decision logic is unit-tested
// without tmux or the real store. Production paths come from STORE_DIR.
import { createHash } from 'node:crypto'
import { readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { STORE_DIR } from '../config.js'
import { atomicWriteFileSync } from './atomic-write.js'

/** The shared fleet token file (same path as agent-process FLEET_OAUTH_TOKEN_PATH). */
export function fleetTokenFilePath(): string {
  return join(STORE_DIR, '.claude-oauth-token')
}

/** The launch registry side-car: { v, entries: { '<agent|worker>:<name>': { fp, at } } }. */
export function launchRegistryPath(): string {
  return join(STORE_DIR, 'fleet-token-launch.json')
}

export const LAUNCH_REGISTRY_MODE = 0o600
const FP_RE = /^[0-9a-f]{16}$/
const KEY_RE = /^(agent|worker):[A-Za-z0-9._-]{1,128}$/

export interface FleetTokenIO {
  readFile(path: string): string
  /** Atomic replace (tmp + rename), mode applied from the first byte. */
  writeAtomic(path: string, data: string, mode: number): void
  /** mtime in ms, or null when the path does not exist / cannot be stat-ed. */
  mtimeMs(path: string): number | null
}

export const realFleetTokenIO: FleetTokenIO = {
  readFile: (p) => readFileSync(p, 'utf-8'),
  writeAtomic: (p, data, mode) => atomicWriteFileSync(p, data, { mode }),
  mtimeMs: (p) => {
    try { return statSync(p).mtimeMs } catch { return null }
  },
}

export interface LaunchEntry {
  /** 16 hex chars of sha256(trimmed token) as it was at launch time. */
  fp: string
  /** Epoch ms of the stamp. */
  at: number
}
export type LaunchRegistry = Record<string, LaunchEntry>

export type FleetTokenState = 'current' | 'stale' | 'unknown'

/**
 * Fingerprint of a token value: first 16 hex of sha256 over the TRIMMED content
 * (the file is written without a trailing newline, the launcher's `$(cat)`
 * strips trailing newlines, and hasFleetOauthToken trims too). null for an
 * empty / whitespace-only value.
 */
export function fingerprintOfToken(token: string): string | null {
  const t = token.trim()
  if (!t) return null
  return createHash('sha256').update(t, 'utf8').digest('hex').slice(0, 16)
}

/** Fingerprint of the fleet token file now. null when missing, empty or unreadable. */
export function fingerprintFleetToken(path: string = fleetTokenFilePath(), io: FleetTokenIO = realFleetTokenIO): string | null {
  try {
    return fingerprintOfToken(io.readFile(path))
  } catch {
    return null
  }
}

/** True for a key shape the registry accepts: `agent:<name>` or `worker:<session>`. */
export function isLaunchKey(key: string): boolean {
  return KEY_RE.test(key)
}

/**
 * Read the registry. Tolerant: missing, unparsable or wrong-shaped file gives an
 * empty registry, and any entry with a bad key or a non-16-hex fingerprint is
 * dropped. Never throws.
 */
export function readLaunchRegistry(path: string = launchRegistryPath(), io: FleetTokenIO = realFleetTokenIO): LaunchRegistry {
  const out: LaunchRegistry = Object.create(null)
  let parsed: unknown
  try {
    parsed = JSON.parse(io.readFile(path))
  } catch {
    return out
  }
  if (!parsed || typeof parsed !== 'object') return out
  const entries = (parsed as { entries?: unknown }).entries
  if (!entries || typeof entries !== 'object' || Array.isArray(entries)) return out
  for (const [key, raw] of Object.entries(entries as Record<string, unknown>)) {
    if (!KEY_RE.test(key) || !raw || typeof raw !== 'object') continue
    const { fp, at } = raw as { fp?: unknown; at?: unknown }
    if (typeof fp !== 'string' || !FP_RE.test(fp)) continue
    if (typeof at !== 'number' || !Number.isFinite(at)) continue
    out[key] = { fp, at }
  }
  return out
}

export type RegistryWriteResult = { ok: true } | { ok: false; error: string }

function writeRegistry(path: string, reg: LaunchRegistry, io: FleetTokenIO): RegistryWriteResult {
  try {
    io.writeAtomic(path, JSON.stringify({ v: 1, entries: reg }), LAUNCH_REGISTRY_MODE)
    return { ok: true }
  } catch {
    return { ok: false, error: 'fleet token launch registry write failed' }
  }
}

/**
 * Stamp one launch: `key` ran with the token whose fingerprint is `fp`. Must be
 * called BEFORE `tmux new-session` so a token swap between the stamp and the
 * pane's `$(cat)` can only produce a false `stale` (one needless restart), never
 * a stale session shown as current. Read-modify-write is synchronous, so two
 * stamps in this process cannot interleave. Never throws; the failure is a fixed
 * string.
 */
export function recordLaunch(
  key: string,
  fp: string,
  nowMs: number,
  path: string = launchRegistryPath(),
  io: FleetTokenIO = realFleetTokenIO,
): RegistryWriteResult {
  if (!KEY_RE.test(key)) return { ok: false, error: 'fleet token launch key invalid' }
  if (!FP_RE.test(fp)) return { ok: false, error: 'fleet token fingerprint invalid' }
  const reg = readLaunchRegistry(path, io)
  reg[key] = { fp, at: nowMs }
  return writeRegistry(path, reg, io)
}

/**
 * Drop `key`'s stamp (the session now runs without the fleet token: own token,
 * own config, main agent...). No-op, and no write, when there is none.
 */
export function clearLaunch(key: string, path: string = launchRegistryPath(), io: FleetTokenIO = realFleetTokenIO): RegistryWriteResult {
  if (!KEY_RE.test(key)) return { ok: false, error: 'fleet token launch key invalid' }
  const reg = readLaunchRegistry(path, io)
  if (!(key in reg)) return { ok: true }
  delete reg[key]
  return writeRegistry(path, reg, io)
}

/** The stamped fingerprint of `key`, or null when there is none. In-memory use only. */
export function launchFingerprint(key: string, path: string = launchRegistryPath(), io: FleetTokenIO = realFleetTokenIO): string | null {
  return readLaunchRegistry(path, io)[key]?.fp ?? null
}

/**
 * Pure state: `stale` only when BOTH fingerprints exist and differ.
 * - no stamp (session started before the stamping deploy): `unknown`, never `stale`
 * - the current token cannot be fingerprinted (missing / empty / unreadable file):
 *   `unknown` -- an empty or half-written file must not restart anything.
 */
export function fleetTokenState(launchFp: string | null | undefined, currentFp: string | null): FleetTokenState {
  if (!currentFp || !launchFp) return 'unknown'
  return launchFp === currentFp ? 'current' : 'stale'
}

/**
 * Label-only estimate for a session with no stamp: it was created after the token
 * file's last change, so it must have exported the current token. Never decides a
 * restart (the caller keeps the state `unknown`).
 */
export function createdAfterTokenChange(sessionCreatedMs: number | null, tokenMtimeMs: number | null): boolean {
  if (sessionCreatedMs === null || tokenMtimeMs === null) return false
  return sessionCreatedMs > tokenMtimeMs
}

/** Convenience: state of `key` against the real files now. */
export function fleetTokenStateFor(
  key: string,
  tokenPath: string = fleetTokenFilePath(),
  registryPath: string = launchRegistryPath(),
  io: FleetTokenIO = realFleetTokenIO,
): FleetTokenState {
  return fleetTokenState(launchFingerprint(key, registryPath, io), fingerprintFleetToken(tokenPath, io))
}
