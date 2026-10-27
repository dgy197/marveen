// Memory write gate, b1: the full .env-only configuration, the kill-switch file,
// the credit-gate pause decision and the Budapest-day arithmetic (card 3e9f6c28,
// node G2c; blueprint r5 4.1, r6 2. and 6.).
//
// Every MEMORY_GATE_* key comes from the .env file ONLY, through readEnvFile()
// (GN1): never cfg(), never config-overrides.json, never the config registry, so
// nothing in the dashboard UI can widen the gate's data scope or its budget. A
// change needs a dashboard restart; the DISABLE file is the restart-free switch.
//
// Mode and owner resolution are gate-env.ts's (one implementation): feszek is a
// config error whatever .env says, the main agent counts only with
// MEMORY_GATE_MAIN_AGENT_OK=tg-<digits>.
import { lstatSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'
import { readEnvFile } from '../env.js'
import { APP_TZ, MAIN_AGENT_ID } from '../config.js'
import { gateEnvFromValues, type GateEnv } from './gate-env.js'

export const MEMORY_GATE_KEYS = [
  'MEMORY_GATE_MODE', 'MEMORY_GATE_OWNERS', 'MEMORY_GATE_MAIN_AGENT_OK', 'MEMORY_GATE_BATCH_DIR',
  'MEMORY_GATE_MODEL', 'MEMORY_GATE_MAX_CALLS_PER_DAY', 'MEMORY_GATE_DAILY_USD', 'MEMORY_GATE_MAX_PROMPT_BYTES',
  'MEMORY_GATE_MAX_TOKENS', 'MEMORY_GATE_CANDIDATES', 'MEMORY_GATE_SUPERSEDE_MIN_CONF', 'MEMORY_GATE_OTHER_MIN_CONF',
  'MEMORY_GATE_MAX_SUPERSEDE_PER_DAY', 'MEMORY_GATE_MAX_CONTRADICT_PER_DAY',
] as const

/** Hard ceiling of the daily spend, in code: .env may lower it, never raise it (Brainy 4217, r6 6.). */
export const DAILY_USD_CEILING_MICRO = 500_000
export const DEFAULT_MODEL = 'claude-haiku-5-5'
export const DISABLE_CACHE_MS = 5_000

export interface GateConfig {
  env: GateEnv
  /** Non-null = the gate does nothing ('bad_owner', 'forbidden_owner', 'bad_<key>', 'batch_dir'). */
  configError: string | null
  batchDir: string
  model: string
  maxCallsPerDay: number
  dailyUsdMicro: number
  maxPromptBytes: number
  maxTokens: number
  candidates: number
  supersedeMinConf: number
  otherMinConf: number
  maxSupersedePerDay: number
  maxContradictPerDay: number
}

function intIn(raw: string | undefined, def: number, lo: number, hi: number): number | null {
  const v = (raw ?? '').trim()
  if (v === '') return def
  if (!/^[0-9]{1,7}$/.test(v)) return null
  const n = parseInt(v, 10)
  return n >= lo && n <= hi ? n : null
}

function confIn(raw: string | undefined, def: number, lo: number): number | null {
  const v = (raw ?? '').trim()
  if (v === '') return def
  if (!/^(0(\.[0-9]{1,3})?|1(\.0{1,3})?)$/.test(v)) return null
  const n = Number(v)
  return n >= lo && n <= 1 ? n : null
}

/** "0.50" -> 500000 micro-USD; at most two decimals, 0.01 .. the code ceiling. */
function usdMicro(raw: string | undefined): number | null {
  const v = (raw ?? '').trim()
  if (v === '') return DAILY_USD_CEILING_MICRO
  const m = /^([0-9])(?:\.([0-9]{1,2}))?$/.exec(v)
  if (!m) return null
  const micro = parseInt(m[1], 10) * 1_000_000 + parseInt((m[2] ?? '0').padEnd(2, '0'), 10) * 10_000
  return micro >= 10_000 && micro <= DAILY_USD_CEILING_MICRO ? micro : null
}

/** Pure resolution over raw .env values (tests feed values directly). */
export function resolveGateConfig(e: Record<string, string | undefined>, mainAgentId: string = MAIN_AGENT_ID): GateConfig {
  const env = gateEnvFromValues(e, mainAgentId)
  let configError: string | null = env.owners.configError
  const bad = (key: string) => { if (configError === null) configError = `bad_${key}` }
  const num = <T>(v: T | null, key: string, fallback: T): T => { if (v === null) { bad(key); return fallback } return v }

  const model = (e.MEMORY_GATE_MODEL ?? '').trim() || DEFAULT_MODEL
  if (!/^[a-z0-9][a-z0-9.-]{2,63}$/.test(model)) bad('model')
  const cfg: GateConfig = {
    env,
    configError: null,
    batchDir: (e.MEMORY_GATE_BATCH_DIR ?? '').trim(),
    model,
    maxCallsPerDay: num(intIn(e.MEMORY_GATE_MAX_CALLS_PER_DAY, 300, 1, 2000), 'max_calls_per_day', 300),
    dailyUsdMicro: num(usdMicro(e.MEMORY_GATE_DAILY_USD), 'daily_usd', DAILY_USD_CEILING_MICRO),
    maxPromptBytes: num(intIn(e.MEMORY_GATE_MAX_PROMPT_BYTES, 12000, 2000, 48000), 'max_prompt_bytes', 12000),
    maxTokens: num(intIn(e.MEMORY_GATE_MAX_TOKENS, 300, 64, 1000), 'max_tokens', 300),
    candidates: num(intIn(e.MEMORY_GATE_CANDIDATES, 5, 1, 5), 'candidates', 5),
    supersedeMinConf: num(confIn(e.MEMORY_GATE_SUPERSEDE_MIN_CONF, 0.85, 0.5), 'supersede_min_conf', 0.85),
    otherMinConf: num(confIn(e.MEMORY_GATE_OTHER_MIN_CONF, 0.70, 0.5), 'other_min_conf', 0.70),
    maxSupersedePerDay: num(intIn(e.MEMORY_GATE_MAX_SUPERSEDE_PER_DAY, 20, 0, 1000), 'max_supersede_per_day', 20),
    maxContradictPerDay: num(intIn(e.MEMORY_GATE_MAX_CONTRADICT_PER_DAY, 20, 0, 1000), 'max_contradict_per_day', 20),
  }
  // The batch dir matters only once the gate would call at all.
  if (env.effectiveMode !== 'off' && env.owners.owners.length > 0 && !isAbsolute(cfg.batchDir)) bad('batch_dir')
  cfg.configError = configError
  return cfg
}

/** One read of every gate key from .env. */
export function readGateConfig(mainAgentId: string = MAIN_AGENT_ID): GateConfig {
  return resolveGateConfig(readEnvFile([...MEMORY_GATE_KEYS]), mainAgentId)
}

/** The gate may do anything at all (enqueue, call) only with this true. */
export function gateRuns(cfg: GateConfig): boolean {
  return cfg.configError === null && cfg.env.effectiveMode !== 'off' && cfg.env.owners.owners.length > 0
}

// ---------------------------------------------------------------- kill switch

export function disablePath(storeDir: string): string {
  return join(storeDir, 'iras-kapu', 'DISABLE')
}

/**
 * store/iras-kapu/DISABLE via lstat (a symlink counts, even a dangling one),
 * cached for at most DISABLE_CACHE_MS. Any lstat error other than ENOENT counts
 * as present (fail closed).
 */
export function makeDisableCheck(storeDir: string, nowMs: () => number = Date.now, lstat: (p: string) => unknown = lstatSync): () => boolean {
  let cached: { at: number; value: boolean } | null = null
  return () => {
    const now = nowMs()
    if (cached && now - cached.at < DISABLE_CACHE_MS && now >= cached.at) return cached.value
    let value: boolean
    try { lstat(disablePath(storeDir)); value = true } catch (err) {
      value = (err as { code?: string } | null)?.code !== 'ENOENT'
    }
    cached = { at: now, value }
    return value
  }
}

// ---------------------------------------------------------------- credit gate

export interface CreditView {
  /** The credit gate's effective mode ('enforce' for an unknown value). */
  mode: 'off' | 'shadow' | 'enforce'
  /** CREDIT_GATE_MODE held a value that is not one of the three. */
  unknown: boolean
  startError: string | null
  /** null = no gate object (off mode, failed start, web-only). */
  gate: { state: string } | null
}

/**
 * SR-6a-r6 B2: in enforce mode ONLY a running gate in state OPEN lets a round
 * call. Everything else (no gate, a start error, a non-OPEN state, an unknown
 * mode that falls back to enforce) pauses. off / shadow credit gate: the round runs.
 * Returns null (go) or the pause class.
 */
export function creditPause(v: CreditView): 'credit_paused' | 'credit_unknown' | null {
  if (v.unknown) return 'credit_unknown'
  if (v.mode === 'off' || v.mode === 'shadow') return null
  if (v.startError !== null || v.gate === null) return 'credit_unknown'
  return v.gate.state === 'OPEN' ? null : 'credit_paused'
}

// ---------------------------------------------------------------- Budapest day

export function dayKey(ms: number, tz: string = APP_TZ): string {
  return new Intl.DateTimeFormat('sv-SE', { timeZone: tz, year: 'numeric', month: '2-digit', day: '2-digit' }).format(new Date(ms))
}

/** First instant (ms, 1 s resolution) of the day after the one `ms` falls in; DST-safe (23 h / 25 h days). */
export function nextDayStart(ms: number, tz: string = APP_TZ): number {
  const today = dayKey(ms, tz)
  let lo = ms
  let hi = ms + 3_600_000
  while (dayKey(hi, tz) === today) { lo = hi; hi += 3_600_000 }
  while (hi - lo > 1000) {
    const mid = lo + Math.floor((hi - lo) / 2000) * 1000
    if (dayKey(mid, tz) === today) lo = mid; else hi = mid
  }
  return Math.ceil(hi / 1000) * 1000
}

/** First instant of the day `ms` falls in. */
export function dayStart(ms: number, tz: string = APP_TZ): number {
  // A day is at most 25 h long, so the start of today lies within the 26 h before `ms`.
  let s = nextDayStart(ms - 26 * 3_600_000, tz)
  while (nextDayStart(s, tz) <= ms) s = nextDayStart(s, tz)
  return s
}
