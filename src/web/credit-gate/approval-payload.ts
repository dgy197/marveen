// The owner-approved credit-gate requests (card fec6335f, blueprint 3.7, node
// N2b): their categories, their bound payloads, and the binding of a payload
// to the approval's content_hash.
//
// Three categories travel the strict Telegram button path of card 345f34e2
// (owner:telegram:<id>, a nonce per button, one conditional UPDATE):
//   credit_gate_calibration    a Console reading, grant by grant (G-02, D-01)
//   credit_gate_canary         the one canary run (K-01)
//   credit_gate_incident_clear the owner lifts one INCIDENT (3.5)
// The gate itself (consume, calibration, the INCIDENT lift) is node N2c; this
// module only decides what such an approval may carry and whether its payload
// is the one its content_hash approves.
//
// A payload is accepted only in its CANONICAL form: exactly the text
// canonicalJson() produces (Python's json.dumps(v, ensure_ascii=False,
// sort_keys=True, separators=(",", ":")), UTF-8). The content_hash is the
// sha256 of that text. So one approval has one byte sequence: no whitespace,
// key order, duplicate key or escape spelling can make the owner see one
// thing and the gate read another (WYSIWYS). Every key is fixed, every number
// a strict decimal string (money.ts parseUsd: exactly two decimals), and
// nothing in a payload is free text: the only strings that are not a number, a
// date, a hash or an id are the screenshot path and the canary's cwd, and
// their alphabet is closed.
//
// BE-4b P6 (N4b): a canary approval names its run -- the node, the cwd and the
// sha256 of the prompt -- and the gate consumes it only for exactly that run,
// so nobody else holding the Bearer token can spend it on another prompt.
//
// Pure: no I/O, no clock. db.ts uses creditGateBinding() inside the decision
// transaction, the route uses parseCreditGatePayload() on create.

import { createHash } from 'node:crypto'
import { canonicalJson } from '../../approval-envelope.js'
import { parseUtcInstant } from './config.js'
import { MICRO_PER_USD, parseUsd } from './money.js'

export const CREDIT_GATE_APPROVAL_CATEGORIES = [
  'credit_gate_calibration',
  'credit_gate_canary',
  'credit_gate_incident_clear',
] as const

export type CreditGateApprovalCategory = (typeof CREDIT_GATE_APPROVAL_CATEGORIES)[number]

const CATEGORY_SET: ReadonlySet<string> = new Set(CREDIT_GATE_APPROVAL_CATEGORIES)

export function isCreditGateCategory(c: unknown): c is CreditGateApprovalCategory {
  return typeof c === 'string' && CATEGORY_SET.has(c)
}

const RESERVED_PREFIX = 'credit_gate_'

/**
 * True when the category claims the reserved credit_gate_ prefix (case and
 * whitespace do not matter). The route accepts such a category only when it is
 * exactly one of the three above.
 */
export function claimsCreditGatePrefix(c: unknown): boolean {
  return typeof c === 'string' && c.replace(/\s/g, '').toLowerCase().startsWith(RESERVED_PREFIX)
}

/**
 * The requester of a credit-gate approval: an agent id, nothing else. It is
 * shown on the owner's button message, so it must not be a sentence.
 */
export const CREDIT_GATE_REQUESTER_RE = /^[a-z0-9][a-z0-9_-]{0,49}$/

// Bounds. The grant limits are gate.ts's (validateCalibration): a reading the
// gate would refuse to use is not offered for approval either.
export const MAX_PAYLOAD_CHARS = 8192
export const MAX_GRANTS = 16
export const MAX_GRANT_USD_MICRO = 10_000 * MICRO_PER_USD
export const MAX_GRANTS_TOTAL_USD_MICRO = 20_000 * MICRO_PER_USD
// K-01: the canary's ceiling is below 1 USD, and it must cost at least 0.10 USD
// so the change shows at two decimals on the Console.
export const CANARY_BUDGET_LIMIT_MICRO = 1 * MICRO_PER_USD
export const CANARY_MIN_EXPECTED_MICRO = 100_000
export const MAX_SCREENSHOT_PATH_CHARS = 300
// The owner's message repeats a path with a non-ASCII letter with every such
// letter escaped (<U+XXXX>, 8 characters): this cap keeps the largest valid
// calibration inside one button message.
export const MAX_SCREENSHOT_NON_ASCII = 64

export interface CalibrationGrantReading {
  readonly granted: string
  readonly expires: string
  readonly original_usd: string
  readonly remaining_usd: string
}

export interface CalibrationPayload {
  readonly v: 1
  readonly kind: 'credit_gate_calibration'
  /** The earliest moment the screenshot may have been taken: YYYY-MM-DDTHH:MM:SSZ. */
  readonly captured_at_lb: string
  readonly grants: readonly CalibrationGrantReading[]
  readonly protected: {
    readonly R: { readonly remaining_usd: string; readonly expires: string }
    readonly V: { readonly remaining_usd: string }
  }
  /** Absolute path of the Console screenshot the numbers were read from. */
  readonly screenshot: string
}

export interface CanaryPayload {
  readonly v: 1
  readonly kind: 'credit_gate_canary'
  /** sha256 hex of the headless runner's launch configuration (E-04). */
  readonly config_hash: string
  readonly model: string
  readonly budget_usd: string
  readonly min_expected_usd: string
  /** The approval id (UUID) of the owner-approved calibration taken before the run. */
  readonly before_calibration_id: string
  /** BE-4b P6: the node id the run is for (the runs API's node_id). */
  readonly node: string
  /** BE-4b P6: the run's working directory, exactly as the runs API receives it. */
  readonly cwd: string
  /** BE-4b P6: sha256 hex of the prompt's UTF-8 bytes. */
  readonly prompt_sha256: string
}

export interface IncidentClearPayload {
  readonly v: 1
  readonly kind: 'credit_gate_incident_clear'
  /** credit_gate_events.id of the INCIDENT the owner lifts. */
  readonly incident_event_id: number
}

export type CreditGatePayload = CalibrationPayload | CanaryPayload | IncidentClearPayload

export type CreditGatePayloadResult =
  | { readonly ok: true; readonly payload: CreditGatePayload; readonly canonical: string; readonly contentHash: string }
  // The NAME (path) of the first bad field, never its value: safe to log and to answer with.
  | { readonly ok: false; readonly field: string }

const SHA256_HEX_RE = /^[0-9a-f]{64}$/
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/
const STAMP_Z_RE = /^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$/
const MODEL_RE = /^claude-[a-z0-9]+(?:[.-][a-z0-9]+)*$/
// BE-3b LOW-3: printable ASCII and the Hungarian accented letters, nothing
// else: no other script, no look-alike, no combining, invisible or full-width
// character, no no-break space. The same alphabet as the route's attribution
// text (ATTRIBUTION_TEXT_RE), written with escapes so the source carries no
// NFC-vs-NFD ambiguity. checkScreenshot also requires NFC and no trailing
// whitespace.
export const CREDIT_GATE_TEXT_CHARS = '\\x20-\\x7E\\u00E1\\u00E9\\u00ED\\u00F3\\u00F6\\u0151\\u00FA\\u00FC\\u0171\\u00C1\\u00C9\\u00CD\\u00D3\\u00D6\\u0150\\u00DA\\u00DC\\u0170'
const SCREENSHOT_CHARS_RE = new RegExp(`^[${CREDIT_GATE_TEXT_CHARS}]+$`)
const DOT_SEGMENT_RE = /(^|\/)\.{1,2}(\/|$)/
// The runs API's node id alphabet.
const NODE_ID_RE = /^[A-Za-z0-9_.:-]{1,64}$/

class Bad extends Error {
  constructor(readonly field: string) {
    super(field)
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

// Exactly these keys, each present (none optional in 3.7).
function exactKeys(v: unknown, keys: readonly string[], field: string): Record<string, unknown> {
  if (!isPlainObject(v)) throw new Bad(field)
  const got = Object.keys(v)
  if (got.length !== keys.length || !keys.every((k) => Object.prototype.hasOwnProperty.call(v, k))) {
    throw new Bad(field === '' ? 'keys' : `${field}.keys`)
  }
  return v
}

function usd(v: unknown, field: string): number {
  const m = parseUsd(v)
  if (m === null) throw new Bad(field)
  return m
}

// A grant date: YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ, a real calendar instant.
function instant(v: unknown, field: string): number {
  const ms = parseUtcInstant(v)
  if (ms === null) throw new Bad(field)
  return ms
}

// An absolute path in the closed alphabet (the screenshot, the canary's cwd).
function checkPath(v: unknown, field: string): string {
  if (typeof v !== 'string' || v.length < 2 || v.length > MAX_SCREENSHOT_PATH_CHARS) throw new Bad(field)
  if (!v.startsWith('/') || v.includes('//') || DOT_SEGMENT_RE.test(v)) throw new Bad(field)
  if (!SCREENSHOT_CHARS_RE.test(v) || v.normalize('NFC') !== v || /\s$/.test(v)) throw new Bad(field)
  if ((v.match(/[^\x20-\x7E]/g) ?? []).length > MAX_SCREENSHOT_NON_ASCII) throw new Bad(field)
  return v
}

function checkScreenshot(v: unknown): string {
  return checkPath(v, 'screenshot')
}

function checkCalibration(o: Record<string, unknown>): void {
  exactKeys(o, ['v', 'kind', 'captured_at_lb', 'grants', 'protected', 'screenshot'], '')
  const lb = o['captured_at_lb']
  if (typeof lb !== 'string' || !STAMP_Z_RE.test(lb)) throw new Bad('captured_at_lb')
  const lbMs = instant(lb, 'captured_at_lb')

  const grants = o['grants']
  if (!Array.isArray(grants) || grants.length === 0 || grants.length > MAX_GRANTS) throw new Bad('grants')
  let totalOriginal = 0
  let totalRemaining = 0
  grants.forEach((g, i) => {
    const p = `grants[${i}]`
    const grant = exactKeys(g, ['granted', 'expires', 'original_usd', 'remaining_usd'], p)
    const granted = instant(grant['granted'], `${p}.granted`)
    // A grant credited after the screenshot cannot be on it.
    if (granted > lbMs) throw new Bad(`${p}.granted`)
    if (instant(grant['expires'], `${p}.expires`) <= granted) throw new Bad(`${p}.expires`)
    const original = usd(grant['original_usd'], `${p}.original_usd`)
    if (original <= 0 || original > MAX_GRANT_USD_MICRO) throw new Bad(`${p}.original_usd`)
    const remaining = usd(grant['remaining_usd'], `${p}.remaining_usd`)
    if (remaining > original) throw new Bad(`${p}.remaining_usd`)
    totalOriginal += original
    totalRemaining += remaining
  })
  if (totalOriginal > MAX_GRANTS_TOTAL_USD_MICRO || totalRemaining > MAX_GRANTS_TOTAL_USD_MICRO) throw new Bad('grants')

  const prot = exactKeys(o['protected'], ['R', 'V'], 'protected')
  const r = exactKeys(prot['R'], ['remaining_usd', 'expires'], 'protected.R')
  usd(r['remaining_usd'], 'protected.R.remaining_usd')
  instant(r['expires'], 'protected.R.expires')
  const vv = exactKeys(prot['V'], ['remaining_usd'], 'protected.V')
  usd(vv['remaining_usd'], 'protected.V.remaining_usd')

  checkScreenshot(o['screenshot'])
}

function checkCanary(o: Record<string, unknown>): void {
  exactKeys(o, ['v', 'kind', 'config_hash', 'model', 'budget_usd', 'min_expected_usd', 'before_calibration_id', 'node', 'cwd', 'prompt_sha256'], '')
  const hash = o['config_hash']
  if (typeof hash !== 'string' || !SHA256_HEX_RE.test(hash)) throw new Bad('config_hash')
  const model = o['model']
  if (typeof model !== 'string' || model.length > 64 || !MODEL_RE.test(model)) throw new Bad('model')
  const budget = usd(o['budget_usd'], 'budget_usd')
  if (budget <= 0 || budget >= CANARY_BUDGET_LIMIT_MICRO) throw new Bad('budget_usd')
  const min = usd(o['min_expected_usd'], 'min_expected_usd')
  if (min < CANARY_MIN_EXPECTED_MICRO || min > budget) throw new Bad('min_expected_usd')
  const before = o['before_calibration_id']
  if (typeof before !== 'string' || !UUID_RE.test(before)) throw new Bad('before_calibration_id')
  const node = o['node']
  if (typeof node !== 'string' || !NODE_ID_RE.test(node)) throw new Bad('node')
  checkPath(o['cwd'], 'cwd')
  const promptHash = o['prompt_sha256']
  if (typeof promptHash !== 'string' || !SHA256_HEX_RE.test(promptHash)) throw new Bad('prompt_sha256')
}

function checkIncidentClear(o: Record<string, unknown>): void {
  exactKeys(o, ['v', 'kind', 'incident_event_id'], '')
  const id = o['incident_event_id']
  if (typeof id !== 'number' || !Number.isSafeInteger(id) || id <= 0) throw new Bad('incident_event_id')
}

/**
 * Strictly parse the action_payload of a credit-gate approval of `category`.
 * Accepted only when every field is valid AND the text is exactly the
 * canonical form of what it parses to; the result carries that text and its
 * sha256 (the content_hash the approval must have).
 */
export function parseCreditGatePayload(category: unknown, raw: unknown): CreditGatePayloadResult {
  if (!isCreditGateCategory(category)) return { ok: false, field: 'category' }
  if (typeof raw !== 'string' || raw === '') return { ok: false, field: 'action_payload' }
  if (raw.length > MAX_PAYLOAD_CHARS) return { ok: false, field: 'size' }
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch {
    return { ok: false, field: 'json' }
  }
  try {
    if (!isPlainObject(obj)) throw new Bad('json')
    if (obj['v'] !== 1) throw new Bad('v')
    if (obj['kind'] !== category) throw new Bad('kind')
    if (category === 'credit_gate_calibration') checkCalibration(obj)
    else if (category === 'credit_gate_canary') checkCanary(obj)
    else checkIncidentClear(obj)
  } catch (err) {
    if (err instanceof Bad) return { ok: false, field: err.field }
    throw err
  }
  const canonical = canonicalJson(obj)
  if (canonical === null || canonical !== raw) return { ok: false, field: 'canonical_form' }
  return { ok: true, payload: obj as unknown as CreditGatePayload, canonical, contentHash: creditGateContentHash(canonical) }
}

/** sha256 hex of the canonical payload text (UTF-8). */
export function creditGateContentHash(canonical: string): string {
  return createHash('sha256').update(canonical, 'utf8').digest('hex')
}

// Structural, so this module does not depend on db.ts; an Approval fits.
export interface CreditGateBindable {
  readonly category: string
  readonly content_hash: string | null
  readonly action_payload: string | null
}

// Safe to log: no hash, no payload content.
export type CreditGateUnboundReason = 'not_credit_gate' | 'no_content_hash' | 'no_payload' | 'bad_payload' | 'hash_mismatch'

export type CreditGateBinding =
  | { readonly bound: true; readonly payload: CreditGatePayload }
  | { readonly bound: false; readonly reason: CreditGateUnboundReason }

/** Whether the approval's payload is the very payload its content_hash approves. */
export function creditGateBinding(a: CreditGateBindable): CreditGateBinding {
  if (!isCreditGateCategory(a.category)) return { bound: false, reason: 'not_credit_gate' }
  if (typeof a.content_hash !== 'string' || !SHA256_HEX_RE.test(a.content_hash)) return { bound: false, reason: 'no_content_hash' }
  if (typeof a.action_payload !== 'string' || a.action_payload === '') return { bound: false, reason: 'no_payload' }
  const parsed = parseCreditGatePayload(a.category, a.action_payload)
  if (!parsed.ok) return { bound: false, reason: 'bad_payload' }
  if (parsed.contentHash !== a.content_hash) return { bound: false, reason: 'hash_mismatch' }
  return { bound: true, payload: parsed.payload }
}
