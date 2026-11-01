// The SMS envelope an external_message approval carries in its action_payload
// (card e487f46c, security review B1), and its binding to the approval's content_hash.
//
// scripts/sms/seeme-send.py sends an SMS only when the approval's content_hash is the
// sha256 of the canonical {kind, number, text} envelope of THAT SMS. The hash alone is
// opaque to the owner, and the request's action_description is free text, so a requester
// could show one text and hash another. The requester therefore also sends the envelope
// as action_payload; the server checks on create that content_hash is the sha256 of it,
// and the owner's notification shows the payload's number and text (not the free text).
//
// A payload is accepted only in its CANONICAL form: exactly the text canonicalJson()
// produces (Python's json.dumps(ensure_ascii=False, sort_keys=True,
// separators=(",", ":")), UTF-8), which is the very text seeme-send.py hashes. One
// approval therefore has one byte sequence, and the hash is the sha256 of the payload.
//
// Pure: no I/O, no clock.

import { createHash } from 'node:crypto'
import { canonicalJson } from '../approval-envelope.js'

export const EXTERNAL_MESSAGE_CATEGORY = 'external_message'
export const SMS_ENVELOPE_KIND = 'sms'
// The SeeMe number form: international, no '+', Hungarian mobile (same as seeme-send.py HU_MOBILE).
const SMS_NUMBER_RE = /^36(20|30|31|50|70)\d{7}$/
// seeme-send.py refuses longer texts too.
export const SMS_MAX_TEXT_CHARS = 1600
const SHA256_HEX_RE = /^[0-9a-f]{64}$/
// B6: characters an SMS text may not carry, because they let it pass for something else in
// the owner's notification: any format character (\p{Cf}: bidi controls, zero-width, BOM,
// soft hyphen), any C0 control except \n (so \r, \t, ESC too), DEL and the C1 controls.
// scripts/sms/seeme-send.py applies the same rule (unicodedata category Cf, same ranges).
const SMS_FORBIDDEN_CHAR_RE = /[\p{Cf}\u0000-\u0009\u000b-\u001f\u007f-\u009f\u2028\u2029]/u

export function hasForbiddenSmsChar(text: string): boolean {
  return SMS_FORBIDDEN_CHAR_RE.test(text)
}

export interface SmsEnvelope {
  kind: 'sms'
  number: string
  text: string
}

export type SmsPayloadResult =
  | { ok: true; envelope: SmsEnvelope; contentHash: string }
  | { ok: false; field: string }

/**
 * Strictly parse an external_message action_payload. The payload must be the canonical
 * JSON of exactly {kind: "sms", number, text}: any other key, a non-canonical spelling
 * (whitespace, key order, escapes), a number that is not a normalised Hungarian mobile,
 * a blank or over-long text, a text with a format character (\p{Cf}) or a control
 * character other than \n (B6), or a lone surrogate gives { ok: false, field }.
 */
export function parseSmsPayload(raw: unknown): SmsPayloadResult {
  if (typeof raw !== 'string' || raw === '') return { ok: false, field: 'action_payload' }
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch {
    return { ok: false, field: 'action_payload' }
  }
  if (typeof obj !== 'object' || obj === null || Array.isArray(obj)) return { ok: false, field: 'action_payload' }
  const o = obj as Record<string, unknown>
  const keys = Object.keys(o)
  if (keys.length !== 3 || !['kind', 'number', 'text'].every(k => keys.includes(k))) {
    return { ok: false, field: 'action_payload' }
  }
  if (o['kind'] !== SMS_ENVELOPE_KIND) return { ok: false, field: 'kind' }
  const number = o['number']
  if (typeof number !== 'string' || !SMS_NUMBER_RE.test(number)) return { ok: false, field: 'number' }
  const text = o['text']
  if (typeof text !== 'string' || text.trim() === '' || text.length > SMS_MAX_TEXT_CHARS) return { ok: false, field: 'text' }
  if (hasForbiddenSmsChar(text)) return { ok: false, field: 'text' }
  const envelope: SmsEnvelope = { kind: SMS_ENVELOPE_KIND, number, text }
  const canon = canonicalJson(envelope)
  // null = lone surrogate (the sender could not hash it either); != raw = not canonical
  if (canon === null || canon !== raw) return { ok: false, field: 'action_payload' }
  return { ok: true, envelope, contentHash: createHash('sha256').update(canon, 'utf8').digest('hex') }
}

/**
 * B6: the owner-facing view of an SMS text (Telegram). Every line (empty ones too) carries
 * the prefix "│ ", and the header states the character and line count, so a text with
 * newlines cannot forge a separator or one of our own "Lejárat:" / "Döntés:" lines.
 * Characters are counted as code points (as seeme-send.py's len()).
 */
export const SMS_LINE_PREFIX = '│ '
export function smsTextBlock(text: string): string[] {
  const lines = text.split('\n')
  return [
    `SMS szövege (${Array.from(text).length} karakter, ${lines.length} sor):`,
    ...lines.map(l => SMS_LINE_PREFIX + l),
  ]
}

/** Whether the approval's payload is the very SMS its content_hash approves; null otherwise. */
export function boundSmsEnvelope(approval: {
  category: string
  content_hash: string | null
  action_payload: string | null
}): SmsEnvelope | null {
  if (approval.category !== EXTERNAL_MESSAGE_CATEGORY) return null
  if (typeof approval.content_hash !== 'string' || !SHA256_HEX_RE.test(approval.content_hash)) return null
  const parsed = parseSmsPayload(approval.action_payload)
  if (!parsed.ok || parsed.contentHash !== approval.content_hash) return null
  return parsed.envelope
}
