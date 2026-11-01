// Memory write gate: strict parser for the classifier's answer (card 3e9f6c28, node G2a;
// spec-delta SD-5, blueprint r5 4.5).
//
// The exact shape is ONE JSON object with exactly the keys op, target, confidence,
// reason. Anything else (extra or missing key, wrong type, unknown op, a label that was
// not offered, a number out of range, duplicate keys even when spelt through unicode
// escapes, prose around the object, more than one code fence) is invalid and the worker
// records a failed decision with op = UNKNOWN and error_class = bad_output (nothing is
// created from it). No retry, no repair.
//
// `UNKNOWN` is the gate's own marker for "no usable decision" and is NEVER accepted from
// the model.
//
// JSON.parse is not enough: it silently keeps the last of two equal keys, and it decodes
// "op" to "op" before anyone can compare names. So the object is read by a small
// RFC 8259 parser that compares keys AFTER decoding.
import { prepareForGate } from './mask.js'

export const MODEL_OPS = ['CREATE', 'SUPERSEDE', 'REINFORCE', 'CONTRADICT', 'EXPIRE', 'MERGE'] as const
export type ModelOp = (typeof MODEL_OPS)[number]

export const MAX_RAW_BYTES = 4096
export const MAX_REASON_CHARS = 200
const MAX_DEPTH = 6

export interface GateDecision {
  op: ModelOp
  /** null for CREATE, else one of the offered labels. */
  target: string | null
  confidence: number
  /** Sanitised: NFKC, no Cc/Cf, no nonce, re-masked, single line, <= 200 chars. */
  reason: string
  /** g2: set when a non-CREATE answer was turned into CREATE because its own reason says the entries do not overlap. */
  downgraded?: 'reason_says_new'
}
export type ParseResult = { ok: true; decision: GateDecision } | { ok: false; error: 'bad_output' }

const BAD: ParseResult = { ok: false, error: 'bad_output' }

// The model's own words that the new entry is NOT the earlier one (English and Hungarian), measured on the g1
// shadow week. Narrow on purpose: "same setting", "replaces the earlier" must not match.
const REASON_SAYS_NEW = /\bno (?:direct |clear )?overlap\b|\bnot (?:the same|a restatement)\b|\bdoes not (?:clearly )?(?:replace|restate|confirm)\b|\b(?:concern|cover|describe)s? different\b|\bunrelated\b|nincs (?:közvetlen |egyértelmű )?átfedés|\bnem ugyanaz|\bmás(?:ik)? (?:tény|projekt|ügy)ről\b/i

class Strict extends Error {}

type Json = null | boolean | number | string | Json[] | { [k: string]: Json }

function parseStrictJson(src: string): Json {
  let i = 0
  const fail = (): never => { throw new Strict() }
  const ws = () => { while (i < src.length && (src[i] === ' ' || src[i] === '\t' || src[i] === '\n' || src[i] === '\r')) i++ }

  function str(): string {
    if (src[i] !== '"') fail()
    i++
    let out = ''
    for (;;) {
      if (i >= src.length) fail()
      const c = src[i++]
      if (c === '"') return out
      if (c < ' ') fail() // raw control characters are not allowed in JSON strings
      if (c !== '\\') { out += c; continue }
      const e = src[i++]
      switch (e) {
        case '"': out += '"'; break
        case '\\': out += '\\'; break
        case '/': out += '/'; break
        case 'b': out += '\b'; break
        case 'f': out += '\f'; break
        case 'n': out += '\n'; break
        case 'r': out += '\r'; break
        case 't': out += '\t'; break
        case 'u': {
          const hex = src.slice(i, i + 4)
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail()
          out += String.fromCharCode(parseInt(hex, 16))
          i += 4
          break
        }
        default: fail()
      }
    }
  }

  function num(): number {
    const m = /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/.exec(src.slice(i, i + 64))
    if (!m) fail()
    i += m![0].length
    const n = Number(m![0])
    if (!Number.isFinite(n)) fail()
    return n
  }

  function value(depth: number): Json {
    if (depth > MAX_DEPTH) fail()
    ws()
    const c = src[i]
    if (c === '{') {
      i++
      const obj: { [k: string]: Json } = Object.create(null)
      ws()
      if (src[i] === '}') { i++; return obj }
      for (;;) {
        ws()
        const k = str()
        if (Object.prototype.hasOwnProperty.call(obj, k)) fail() // duplicate key, after escape decoding
        ws()
        if (src[i++] !== ':') fail()
        obj[k] = value(depth + 1)
        ws()
        const d = src[i++]
        if (d === '}') return obj
        if (d !== ',') fail()
      }
    }
    if (c === '[') {
      i++
      const arr: Json[] = []
      ws()
      if (src[i] === ']') { i++; return arr }
      for (;;) {
        arr.push(value(depth + 1))
        ws()
        const d = src[i++]
        if (d === ']') return arr
        if (d !== ',') fail()
      }
    }
    if (c === '"') return str()
    if (src.startsWith('true', i)) { i += 4; return true }
    if (src.startsWith('false', i)) { i += 5; return false }
    if (src.startsWith('null', i)) { i += 4; return null }
    return num()
  }

  const v = value(0)
  ws()
  if (i !== src.length) fail() // trailing text
  return v
}

/** Remove at most one ```json fence that wraps the WHOLE answer; anything else outside it is invalid. */
function unfence(raw: string): string | null {
  const t = raw.replace(/^[ \t\r\n]+|[ \t\r\n]+$/g, '')
  if (!t.includes('```')) return t
  const m = /^```(?:json)?[ \t]*\r?\n([\s\S]*?)\r?\n?```$/.exec(t)
  if (!m || m[1].includes('```')) return null
  return m[1]
}

function sanitiseReason(reason: string, nonce?: string): string {
  let r = prepareForGate(reason)
  if (nonce && /^[0-9a-f]{16}$/.test(nonce)) r = r.replace(new RegExp(`\\[\\[/?${nonce}`, 'gi'), '')
  r = r.replace(/\s+/g, ' ').trim()
  return Array.from(r).slice(0, MAX_REASON_CHARS).join('')
}

/**
 * @param raw     the model's text (the adapter already capped it at 4 KB)
 * @param offered the labels that were actually in the prompt (e.g. ['C1','C2'])
 * @param nonce   the call's nonce, removed from the reason if the model echoed a delimiter
 */
export function parseGateOutput(raw: unknown, offered: readonly string[], nonce?: string): ParseResult {
  if (typeof raw !== 'string' || raw.length === 0 || Buffer.byteLength(raw, 'utf8') > MAX_RAW_BYTES) return BAD
  const body = unfence(raw)
  if (body === null) return BAD
  let parsed: Json
  try { parsed = parseStrictJson(body) } catch { return BAD }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) return BAD
  const obj = parsed as { [k: string]: Json }
  const keys = Object.keys(obj).sort()
  if (keys.length !== 4 || keys[0] !== 'confidence' || keys[1] !== 'op' || keys[2] !== 'reason' || keys[3] !== 'target') return BAD

  const op = obj.op
  if (typeof op !== 'string' || !(MODEL_OPS as readonly string[]).includes(op)) return BAD

  const target = obj.target
  if (op === 'CREATE') {
    if (target !== null) return BAD
  } else if (typeof target !== 'string' || !offered.includes(target)) {
    return BAD
  }

  const confidence = obj.confidence
  if (typeof confidence !== 'number' || !Number.isFinite(confidence) || confidence < 0 || confidence > 1) return BAD

  const reason = obj.reason
  if (typeof reason !== 'string' || Array.from(reason).length > MAX_REASON_CHARS) return BAD

  const clean = sanitiseReason(reason, nonce)
  // g2 (card 3e9f6c28, b2): an answer whose own reason says the entries differ is a CREATE, whatever its op.
  if (op !== 'CREATE' && REASON_SAYS_NEW.test(clean)) {
    return { ok: true, decision: { op: 'CREATE', target: null, confidence, reason: clean, downgraded: 'reason_says_new' } }
  }
  return {
    ok: true,
    decision: { op: op as ModelOp, target: op === 'CREATE' ? null : (target as string), confidence, reason: clean },
  }
}
