// The credit gate's mode flag and its config file (card fec6335f, blueprint
// 3.1, 3.2, node N2a).
//
// CREDIT_GATE_MODE comes from .env ONLY, never from the Settings registry, so
// a Bearer call cannot switch the gate off (blueprint 14). Missing or empty:
// `off`, today's behaviour. Unknown: `enforce` (fail-closed), and the gate
// then never opens -- a typo must not be read as a decision to spend.
//
// store/credit-gate/config.json (`credit-gate-config/v1`) is data, loaded from
// the file only; there is no endpoint that writes it. The loader is
// fail-closed like the price table's: an unknown key, a missing field, a
// duplicated key, a value outside its bounds, a symlink, or a file or folder
// readable by group or others rejects the whole config, and the gate stays
// closed with the reason.

import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs'
import { dirname, isAbsolute, normalize } from 'node:path'
import { findDuplicateJsonKeys } from '../json-dup-keys.js'
import { HEADLESS_SOURCE, type LedgerSource } from './ledger.js'
import { USAGE_JSONL_V1 } from './ledger-usage-jsonl.js'
import { parseFactor, parseUsd } from './money.js'
import type { Factor, Micro } from './types.js'

export const CONFIG_SCHEMA = 'credit-gate-config/v1'
/** Files of store/credit-gate/ and the guard-event file of PR-A, by name. */
export const CREDIT_GATE_DIR = 'credit-gate'
export const CONFIG_FILE = 'config.json'
export const PRICING_FILE = 'pricing.json'
export const GUARD_EVENTS_FILE = 'interactive-key-guard-events.jsonl'
/** Spec C-04: the closing threshold is never below 20 USD. */
export const MIN_T_CLOSE_MICRO = 20_000_000
/** Spec C-02: a headless reservation is at least the budget x 1.5. */
const MIN_RESERVATION_FACTOR_NUM = 1_500_000n
/**
 * K-01 (N7B1): after a canary's run is settled, its after-reading must be
 * recorded within canaryCloseMaxH hours, else the gate goes on HOLD
 * (`canary_close_timeout`). Never more than this, whatever the config says.
 */
export const MAX_CANARY_CLOSE_H = 24
export const DEFAULT_CANARY_CLOSE_H = 6
/** No config or price file is anywhere near this; a bigger one is not ours. */
const MAX_PROTECTED_FILE_BYTES = 256 * 1024

export type GateMode = 'off' | 'shadow' | 'enforce'

export interface ModeReading {
  /** The effective mode: an unknown value is `enforce`. */
  readonly mode: GateMode
  /** The trimmed value as written, null when missing or empty. */
  readonly raw: string | null
  /** True when the value was not one of the three: the gate never opens. */
  readonly unknown: boolean
}

/** CREDIT_GATE_MODE as read from .env (blueprint 3.1). */
export function readCreditGateMode(value: string | null | undefined): ModeReading {
  const raw = typeof value === 'string' ? value.trim() : ''
  if (raw === '') return { mode: 'off', raw: null, unknown: false }
  if (raw === 'off' || raw === 'shadow' || raw === 'enforce') return { mode: raw, raw, unknown: false }
  return { mode: 'enforce', raw, unknown: true }
}

export interface GateThresholds {
  readonly tClose: Micro
  readonly tLowcal: Micro
  readonly tReopen: Micro
  readonly tCloseLowcalFallback: Micro
  readonly lowcalWaitH: number
}

/** The headless runner's part (N4a/N4b use it; validated here, not acted on). */
export interface HeadlessConfig {
  readonly allowedCallers: readonly string[]
  readonly cwdRoots: readonly string[]
  readonly forbiddenCwds: readonly string[]
  readonly runsDir: string
  readonly claudeBin: string
  /** sha256 (64 lowercase hex) of claudeBin's bytes; checked right before every spawn. */
  readonly claudeBinSha256: string
  /** How the key reaches the CLI (headless/env.ts); default `helper`. Part of the config hash. */
  readonly keyMode: 'helper' | 'env'
  /** Only `read` (the canary's): `edit` stays off until a canary measures it. Part of the config hash. */
  readonly toolProfile: 'read'
  readonly models: readonly string[]
  readonly maxBudget: Micro
  readonly wallClockMin: number
  /**
   * BE-4b: at most this many headless (and canary) reservations open at once,
   * checked in the reserve transaction. `maxConcurrent`, 1..16, default 1.
   */
  readonly maxConcurrent: number
  /**
   * BE-4b: the most the headless reservations of the last 24 hours may add up
   * to (the reserved amounts, budget x factor, released ones aside), checked
   * in the reserve transaction. `dailyCapUsd`, a two-decimal string above
   * 0.00. Default: none -- OFF (Gyuri, D-10: no daily cap in the first cycle).
   */
  readonly dailyCap: Micro | null
}

export interface CreditGateConfig {
  readonly schema: typeof CONFIG_SCHEMA
  readonly ledgerSources: readonly LedgerSource[]
  /** Absolute path of the batch path's STOP file. */
  readonly stopFile: string
  readonly thresholds: GateThresholds
  readonly expiryMarginH: number
  /**
   * A batch is admitted only against grants that are still alive this many
   * hours from now, and not later than the last expiry minus this (BE-3: a
   * batch may take up to 24 h; a grant must not expire under it).
   */
  readonly batchHorizonH: number
  readonly refreshS: number
  readonly maxLedgerAgeS: number
  readonly reservationFactor: Factor
  /** D-01: the protected stores' baseline (R = old promo, V = purchased). */
  readonly protected: { readonly R: Micro; readonly V: Micro }
  readonly calibrationMaxAgeH: number
  /**
   * K-01 (N7B1): hours from the canary's settle to the recording of its
   * after-reading (the close of the canary window); past it the gate holds
   * (`canary_close_timeout`) and the STOP stays down. Optional, 1..24
   * (MAX_CANARY_CLOSE_H), default DEFAULT_CANARY_CLOSE_H.
   */
  readonly canaryCloseMaxH: number
  readonly vaultKeyId: string
  /** null: the config has no headless part, the headless path stays off. */
  readonly headless: HeadlessConfig | null
}

export type ConfigRejectReason =
  | 'missing'
  | 'unreadable'
  | 'permissions'
  | 'invalid_json'
  | 'duplicate_key'
  | 'schema'
  | 'invalid'

export type ConfigLoadResult =
  | { readonly ok: true; readonly config: CreditGateConfig }
  | { readonly ok: false; readonly reason: ConfigRejectReason; readonly detail: string }

export type ProtectedReadResult =
  | { readonly ok: true; readonly text: string }
  | { readonly ok: false; readonly reason: 'missing' | 'unreadable' | 'permissions'; readonly detail: string }

/**
 * Read a gate data file: a regular file, not a symlink (O_NOFOLLOW, checked on
 * the open descriptor), owned by us, with no group or other permission bits on
 * the file or its folder (blueprint 3.2: the folder 0700, the files 0600).
 */
export function readProtectedFile(path: string): ProtectedReadResult {
  if (!isAbsolute(path)) return { ok: false, reason: 'unreadable', detail: 'path must be absolute' }
  const uid = typeof process.getuid === 'function' ? process.getuid() : null
  try {
    const dir = lstatSync(dirname(path))
    if (!dir.isDirectory()) return { ok: false, reason: 'permissions', detail: 'the folder is not a directory' }
    if ((dir.mode & 0o077) !== 0) return { ok: false, reason: 'permissions', detail: 'the folder is open to group or others' }
    if (uid !== null && dir.uid !== uid) return { ok: false, reason: 'permissions', detail: 'the folder belongs to another user' }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT' || code === 'ENOTDIR') return { ok: false, reason: 'missing', detail: 'no such folder' }
    return { ok: false, reason: 'unreadable', detail: `folder: ${code ?? 'error'}` }
  }
  let fd: number
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW)
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code
    if (code === 'ENOENT') return { ok: false, reason: 'missing', detail: 'no such file' }
    if (code === 'ELOOP') return { ok: false, reason: 'permissions', detail: 'the file is a symlink' }
    return { ok: false, reason: 'unreadable', detail: code ?? 'error' }
  }
  try {
    const st = fstatSync(fd)
    if (!st.isFile()) return { ok: false, reason: 'permissions', detail: 'not a regular file' }
    if ((st.mode & 0o077) !== 0) return { ok: false, reason: 'permissions', detail: 'the file is open to group or others' }
    if (uid !== null && st.uid !== uid) return { ok: false, reason: 'permissions', detail: 'the file belongs to another user' }
    if (st.size > MAX_PROTECTED_FILE_BYTES) return { ok: false, reason: 'unreadable', detail: 'the file is too large' }
    const buf = Buffer.alloc(st.size)
    let done = 0
    while (done < buf.length) {
      const n = readSync(fd, buf, done, buf.length - done, done)
      if (n === 0) break
      done += n
    }
    return { ok: true, text: buf.subarray(0, done).toString('utf8') }
  } catch (err) {
    return { ok: false, reason: 'unreadable', detail: (err as NodeJS.ErrnoException).code ?? 'error' }
  } finally {
    closeSync(fd)
  }
}

class ConfigInvalid extends Error {}

function fail(detail: string): never {
  throw new ConfigInvalid(detail)
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function checkKeys(o: Record<string, unknown>, path: string, required: readonly string[], optional: readonly string[] = []): void {
  for (const k of Object.keys(o)) {
    if (!required.includes(k) && !optional.includes(k)) fail(`${path}: unknown key ${JSON.stringify(k)}`)
  }
  for (const k of required) {
    if (!Object.hasOwn(o, k)) fail(`${path}.${k}: missing`)
  }
}

function int(v: unknown, path: string, min: number, max: number): number {
  if (typeof v !== 'number' || !Number.isSafeInteger(v) || v < min || v > max) fail(`${path}: must be an integer ${min}..${max}`)
  return v
}

function usd(v: unknown, path: string): Micro {
  const m = parseUsd(v)
  if (m === null) fail(`${path}: must be a USD amount with exactly two decimals`)
  return m
}

/** An absolute, already-normalised path without a NUL or a trailing slash. */
function absPath(v: unknown, path: string): string {
  if (typeof v !== 'string' || v.length === 0 || v.length > 1024 || v.includes('\0') || !isAbsolute(v)) {
    fail(`${path}: must be an absolute path`)
  }
  if (normalize(v) !== v || (v.length > 1 && v.endsWith('/'))) fail(`${path}: must be a normalised path`)
  return v
}

function stringList(v: unknown, path: string, re: RegExp, max: number): string[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > max) fail(`${path}: must be a list of 1..${max} entries`)
  const out: string[] = []
  for (const [i, s] of v.entries()) {
    if (typeof s !== 'string' || !re.test(s)) fail(`${path}[${i}]: not allowed`)
    if (out.includes(s)) fail(`${path}[${i}]: duplicated`)
    out.push(s)
  }
  return out
}

const SOURCE_ID_RE = /^[a-z0-9][a-z0-9_.-]{0,63}$/
const AGENT_ID_RE = /^[a-z0-9][a-z0-9_-]{0,63}$/
const MODEL_ID_RE = /^[a-z0-9][a-z0-9._-]{0,127}$/
const VAULT_KEY_RE = /^[A-Z][A-Z0-9_]{0,63}$/

const TOP_KEYS = [
  'schema', 'ledgerSources', 'stopFile', 'thresholds', 'expiryMarginH', 'batchHorizonH', 'refreshS', 'maxLedgerAgeS',
  'reservationFactor', 'protected', 'calibrationMaxAgeH', 'vaultKeyId',
] as const
const THRESHOLD_KEYS = ['tClose', 'tLowcal', 'tReopen', 'tCloseLowcalFallback', 'lowcalWaitH'] as const
const HEADLESS_KEYS = [
  'allowedCallers', 'cwdRoots', 'forbiddenCwds', 'runsDir', 'claudeBin', 'claudeBinSha256', 'models', 'maxBudgetUsd', 'wallClockMin',
] as const
const HEADLESS_OPTIONAL_KEYS = ['keyMode', 'toolProfile', 'maxConcurrent', 'dailyCapUsd'] as const

function readSources(v: unknown): LedgerSource[] {
  if (!Array.isArray(v) || v.length === 0 || v.length > 8) fail('ledgerSources: must be a list of 1..8 sources')
  const out: LedgerSource[] = []
  for (const [i, s] of v.entries()) {
    const p = `ledgerSources[${i}]`
    if (!isPlainObject(s)) fail(`${p}: must be an object`)
    checkKeys(s, p, ['id', 'path', 'format'])
    if (typeof s.id !== 'string' || !SOURCE_ID_RE.test(s.id) || s.id === HEADLESS_SOURCE) fail(`${p}.id: not allowed`)
    if (out.some((o) => o.id === s.id)) fail(`${p}.id: duplicated`)
    if (s.format !== USAGE_JSONL_V1) fail(`${p}.format: must be ${USAGE_JSONL_V1}`)
    out.push(Object.freeze({ id: s.id, path: absPath(s.path, `${p}.path`), format: USAGE_JSONL_V1 }))
  }
  return out
}

function readThresholds(v: unknown): GateThresholds {
  if (!isPlainObject(v)) fail('thresholds: must be an object')
  checkKeys(v, 'thresholds', THRESHOLD_KEYS)
  const t = {
    tClose: usd(v.tClose, 'thresholds.tClose'),
    tLowcal: usd(v.tLowcal, 'thresholds.tLowcal'),
    tReopen: usd(v.tReopen, 'thresholds.tReopen'),
    tCloseLowcalFallback: usd(v.tCloseLowcalFallback, 'thresholds.tCloseLowcalFallback'),
    lowcalWaitH: int(v.lowcalWaitH, 'thresholds.lowcalWaitH', 1, 168),
  }
  if (t.tClose < MIN_T_CLOSE_MICRO) fail('thresholds.tClose: the minimum is 20.00')
  // The hysteresis only works in this order: close <= lowcal close < reopen <= lowcal ask.
  if (t.tCloseLowcalFallback < t.tClose) fail('thresholds.tCloseLowcalFallback: must not be below tClose')
  if (t.tReopen <= t.tCloseLowcalFallback) fail('thresholds.tReopen: must be above tCloseLowcalFallback')
  if (t.tLowcal < t.tReopen) fail('thresholds.tLowcal: must not be below tReopen')
  return Object.freeze(t)
}

function readHeadless(v: unknown): HeadlessConfig {
  if (!isPlainObject(v)) fail('headless: must be an object')
  checkKeys(v, 'headless', HEADLESS_KEYS, HEADLESS_OPTIONAL_KEYS)
  const absList = (x: unknown, p: string): string[] => {
    if (!Array.isArray(x) || x.length > 16) fail(`${p}: must be a list of at most 16 paths`)
    return x.map((e, i) => absPath(e, `${p}[${i}]`))
  }
  const cwdRoots = absList(v.cwdRoots, 'headless.cwdRoots')
  if (cwdRoots.length === 0) fail('headless.cwdRoots: must not be empty')
  const maxBudget = usd(v.maxBudgetUsd, 'headless.maxBudgetUsd')
  if (maxBudget <= 0) fail('headless.maxBudgetUsd: must be above 0.00')
  if (typeof v.claudeBinSha256 !== 'string' || !/^[0-9a-f]{64}$/.test(v.claudeBinSha256)) {
    fail('headless.claudeBinSha256: must be the 64-hex sha256 of claudeBin')
  }
  const keyMode = v.keyMode ?? 'helper'
  if (keyMode !== 'helper' && keyMode !== 'env') fail('headless.keyMode: must be helper or env')
  const toolProfile = v.toolProfile ?? 'read'
  // `edit` (Read, Edit, Write) has not been measured by a canary: it stays off.
  if (toolProfile !== 'read') fail('headless.toolProfile: only read is enabled')
  const dailyCap = v.dailyCapUsd === undefined || v.dailyCapUsd === null ? null : usd(v.dailyCapUsd, 'headless.dailyCapUsd')
  if (dailyCap !== null && dailyCap <= 0) fail('headless.dailyCapUsd: must be above 0.00 (omit it for no cap)')
  return Object.freeze({
    allowedCallers: Object.freeze(stringList(v.allowedCallers, 'headless.allowedCallers', AGENT_ID_RE, 16)),
    cwdRoots: Object.freeze(cwdRoots),
    forbiddenCwds: Object.freeze(absList(v.forbiddenCwds, 'headless.forbiddenCwds')),
    runsDir: absPath(v.runsDir, 'headless.runsDir'),
    claudeBin: absPath(v.claudeBin, 'headless.claudeBin'),
    claudeBinSha256: v.claudeBinSha256,
    keyMode,
    toolProfile,
    models: Object.freeze(stringList(v.models, 'headless.models', MODEL_ID_RE, 8)),
    maxBudget,
    wallClockMin: int(v.wallClockMin, 'headless.wallClockMin', 1, 600),
    maxConcurrent: v.maxConcurrent === undefined ? 1 : int(v.maxConcurrent, 'headless.maxConcurrent', 1, 16),
    dailyCap,
  })
}

/** Parse and validate a `credit-gate-config/v1` text. Any doubt is a rejection. */
export function parseCreditGateConfig(text: string): ConfigLoadResult {
  let doc: unknown
  try {
    doc = JSON.parse(text)
  } catch {
    return { ok: false, reason: 'invalid_json', detail: 'not valid JSON' }
  }
  const dups = findDuplicateJsonKeys(text)
  if (dups.length > 0) return { ok: false, reason: 'duplicate_key', detail: `duplicated key: ${dups.join(', ')}` }
  if (!isPlainObject(doc)) return { ok: false, reason: 'invalid', detail: 'top level: must be an object' }
  if (doc.schema !== CONFIG_SCHEMA) return { ok: false, reason: 'schema', detail: `schema: expected ${CONFIG_SCHEMA}` }
  try {
    checkKeys(doc, 'top level', TOP_KEYS, ['headless', 'canaryCloseMaxH'])
    const factor = parseFactor(doc.reservationFactor)
    if (factor === null || factor.num * 1_000_000n < MIN_RESERVATION_FACTOR_NUM * factor.den) {
      fail('reservationFactor: must be a factor of at least 1.5')
    }
    if (!isPlainObject(doc.protected)) fail('protected: must be an object')
    checkKeys(doc.protected, 'protected', ['R', 'V'])
    const refreshS = int(doc.refreshS, 'refreshS', 5, 60)
    const maxLedgerAgeS = int(doc.maxLedgerAgeS, 'maxLedgerAgeS', 30, 120)
    if (refreshS * 2 > maxLedgerAgeS) fail('refreshS: must fit twice into maxLedgerAgeS')
    if (typeof doc.vaultKeyId !== 'string' || !VAULT_KEY_RE.test(doc.vaultKeyId)) fail('vaultKeyId: not a vault key id')
    const config: CreditGateConfig = Object.freeze({
      schema: CONFIG_SCHEMA,
      ledgerSources: Object.freeze(readSources(doc.ledgerSources)),
      stopFile: absPath(doc.stopFile, 'stopFile'),
      thresholds: readThresholds(doc.thresholds),
      // C-06: the gate closes at least 2 hours before the last grant expires.
      expiryMarginH: int(doc.expiryMarginH, 'expiryMarginH', 2, 168),
      // Spec C-06b: a batch may run up to 24 h, so the horizon is never shorter.
      batchHorizonH: int(doc.batchHorizonH, 'batchHorizonH', 24, 168),
      refreshS,
      maxLedgerAgeS,
      reservationFactor: factor,
      protected: Object.freeze({ R: usd(doc.protected.R, 'protected.R'), V: usd(doc.protected.V, 'protected.V') }),
      calibrationMaxAgeH: int(doc.calibrationMaxAgeH, 'calibrationMaxAgeH', 1, 168),
      canaryCloseMaxH: doc.canaryCloseMaxH === undefined
        ? DEFAULT_CANARY_CLOSE_H
        : int(doc.canaryCloseMaxH, 'canaryCloseMaxH', 1, MAX_CANARY_CLOSE_H),
      vaultKeyId: doc.vaultKeyId,
      headless: Object.hasOwn(doc, 'headless') ? readHeadless(doc.headless) : null,
    })
    return { ok: true, config }
  } catch (err) {
    if (err instanceof ConfigInvalid) return { ok: false, reason: 'invalid', detail: err.message }
    throw err
  }
}

/** Read and validate the config file (readProtectedFile + parseCreditGateConfig). */
export function loadCreditGateConfigFile(path: string): ConfigLoadResult {
  const r = readProtectedFile(path)
  if (!r.ok) return r
  return parseCreditGateConfig(r.text)
}

const DATE_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})$/
const STAMP_RE = /^([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})Z$/

function utcDay(y: number, mo: number, d: number): number | null {
  const ms = Date.UTC(y, mo - 1, d)
  const dt = new Date(ms)
  return dt.getUTCFullYear() === y && dt.getUTCMonth() === mo - 1 && dt.getUTCDate() === d ? ms : null
}

/**
 * "YYYY-MM-DD" or "YYYY-MM-DDTHH:MM:SSZ" as epoch ms, else null. A date-only
 * value is that day's 00:00:00Z (spec C-06: an expiry known only to the day
 * counts from the start of the day).
 */
export function parseUtcInstant(s: unknown): number | null {
  if (typeof s !== 'string') return null
  const d = DATE_RE.exec(s)
  if (d) return utcDay(Number(d[1]), Number(d[2]), Number(d[3]))
  const t = STAMP_RE.exec(s)
  if (!t) return null
  const day = utcDay(Number(t[1]), Number(t[2]), Number(t[3]))
  const [h, mi, se] = [Number(t[4]), Number(t[5]), Number(t[6])]
  if (day === null || h > 23 || mi > 59 || se > 59) return null
  return day + ((h * 60 + mi) * 60 + se) * 1000
}
