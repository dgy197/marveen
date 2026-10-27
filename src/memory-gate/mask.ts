// Memory write gate: normalisation, masking and residue check for every text that
// may leave the machine (card 3e9f6c28, node G2a; spec-delta SD-12, SD-16).
//
// Order for each text (tests pin it): NFKC -> delete Cc/Cf (keep \n and \t, \r -> \n)
// -> mask -> (caller) truncate. The mask runs BEFORE truncation on purpose: a
// truncated half-credential would slip under every length-based detector.
//
// Why this is wider than maskSecrets(): the reviewer's probe showed that
// maskSecrets() + SECRET_PATTERNS let through a 64-hex dashboard-token shape, a
// `kulcs <hex>` pair and `PIN: 4512`. This module adds, on top of maskSecrets():
//   hex      any run of >= 32 hex digits, always;
//   label    Hungarian/English secret label (inflected, with or without accents,
//            also as a compound suffix) followed by a value of >= 4 non-space chars;
//   pin      PIN/kod label STEM (pin, kod, kodja, riasztokod, PIN-kodja ...) followed by
//            a first word that holds >= 4 digits (the bare word "kod" stays readable);
//   entropy  >= 32 chars of [A-Za-z0-9+/_=-] with >= 3 character classes;
//   luhn     13-19 digit numbers (spaces/hyphens allowed) that pass the Luhn check.
// Over-masking is the safe direction: the classifier then sees "<REDACTED>".
//
// residueFindings() re-runs the whole detector set (this module's own detectors, the
// repo's SECRET_PATTERNS + TRANSCRIPT_PATTERNS, maskSecrets) on the FINISHED prompt.
// Any finding means the item is not sent (error class secret_residue). Findings are
// short codes, never the matched text.
import { maskSecrets } from '../web/agent-transcript.js'
import { SECRET_PATTERNS, TRANSCRIPT_PATTERNS } from '../security/secret-gate.js'

export const REDACTED = '<REDACTED>'

/** NFKC, delete Cc and Cf (except \n, \t), \r\n and lone \r become \n. */
export function normaliseForGate(text: unknown): string {
  if (typeof text !== 'string') return ''
  let out = text.normalize('NFKC')
  // NEL (Cc), LS and PS (Zl/Zp) are line breaks in disguise: keep them as breaks.
  out = out.replace(/\r\n|\r|\u0085|\u2028|\u2029/g, '\n')
  return out.replace(/[\p{Cc}\p{Cf}]/gu, ch => (ch === '\n' || ch === '\t' ? ch : ''))
}

// ---- detectors -----------------------------------------------------------

type Span = [number, number]

function applySpans(text: string, spans: Span[]): string {
  if (spans.length === 0) return text
  spans.sort((a, b) => a[0] - b[0] || a[1] - b[1])
  const merged: Span[] = []
  for (const s of spans) {
    const last = merged[merged.length - 1]
    if (last && s[0] <= last[1]) last[1] = Math.max(last[1], s[1])
    else merged.push([s[0], s[1]])
  }
  let out = ''
  let pos = 0
  for (const [a, b] of merged) { out += text.slice(pos, a) + REDACTED; pos = b }
  return out + text.slice(pos)
}

// Words that may sit between a label and its value ("jelszava legyen hunter2").
const BRIDGE = '(?:(?:a|az|is|van|volt|lett|legyen|ez|was|are|to|be|set)[ \\t]+)*'

// Secret labels. Hungarian stems take any letter ending (jelszavat, kulcsat, titkos ...)
// and may be the tail of a compound (wifijelszo, app-jelszo). The short English
// ones need word boundaries so that "pass" does not fire inside "passage".
const SECRET_LABEL =
  '(?:jelsz(?:[o\\u00f3]|av)\\p{L}*|kulcs\\p{L}*|tit(?:ok|k)\\p{L}*|token\\p{L}*|secret\\p{L}*|api[ _-]?key\\p{L}*' +
  '|(?<![\\p{L}\\p{N}])(?:passwords?|passwd|passphrase|pass|pwd|pw)(?![\\p{L}\\p{N}]))'
// label, then ":"/"=" or whitespace (or a digit glued on), then up to a few bridge words and an optional quote.
const LABEL_PREFIX = new RegExp(`${SECRET_LABEL}(?:\\s*[:=]\\s*|\\s+|(?=\\d))${BRIDGE}["'\u201C\u201D\u2018\u2019]?`, 'giu')
const LABEL_VALUE = /^[^\s"'\u201C\u201D\u2018\u2019<>`]{4,}/u

function maskLabelled(text: string): string {
  const spans: Span[] = []
  const re = new RegExp(LABEL_PREFIX.source, LABEL_PREFIX.flags)
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const valueStart = m.index + m[0].length
    const v = LABEL_VALUE.exec(text.slice(valueStart, valueStart + 400))
    // Continue right after the PREFIX, not after the value: the value may itself be (or hold) the next label.
    re.lastIndex = m.index + Math.max(1, m[0].length)
    if (v) spans.push([valueStart, valueStart + v[0].length])
  }
  return applySpans(text, spans)
}

// PIN/kod label stem: pin, kod, kodja, riasztokod, PIN-kodja ... (optionally accented).
const PIN_PREFIX = new RegExp(`(?:pin|k[o\\u00f3]d)\\p{L}*[ \\t]*[:=]?[ \\t]*${BRIDGE}`, 'giu')

function maskPin(text: string): string {
  const spans: Span[] = []
  const re = new RegExp(PIN_PREFIX.source, PIN_PREFIX.flags)
  let m: RegExpExecArray | null
  while ((m = re.exec(text)) !== null) {
    const valueStart = m.index + m[0].length
    const word = /^\S+/u.exec(text.slice(valueStart, valueStart + 200))
    // Retry from the next character: "PIN-kodja 4512" first matches "PIN", whose value
    // is "-kodja" (no digits); the real label starts inside it.
    re.lastIndex = m.index + 1
    if (word && (word[0].match(/[0-9]/g) ?? []).length >= 4) spans.push([valueStart, valueStart + word[0].length])
  }
  return applySpans(text, spans)
}

function maskHex(text: string): string {
  return text.replace(/[0-9a-fA-F]{32,}/g, REDACTED)
}

function maskEntropy(text: string): string {
  return text.replace(/[A-Za-z0-9+/_=-]{32,}/g, run => {
    let classes = 0
    if (/[a-z]/.test(run)) classes++
    if (/[A-Z]/.test(run)) classes++
    if (/[0-9]/.test(run)) classes++
    if (/[+/_=-]/.test(run)) classes++
    return classes >= 3 ? REDACTED : run
  })
}

function luhnValid(digits: string): boolean {
  let sum = 0
  let dbl = false
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48
    if (dbl) { d *= 2; if (d > 9) d -= 9 }
    sum += d
    dbl = !dbl
  }
  return sum % 10 === 0
}

function maskLuhn(text: string): string {
  return text.replace(/(?<![0-9])\d(?:[ -]?\d){12,18}(?![0-9])/g, run => {
    const digits = run.replace(/[ -]/g, '')
    return digits.length >= 13 && digits.length <= 19 && luhnValid(digits) ? REDACTED : run
  })
}

/** The module's own detectors, in application order. The codes are what residueFindings() reports. */
const DETECTORS: Array<{ code: string; mask: (t: string) => string }> = [
  { code: 'transcript_mask', mask: maskSecrets },
  { code: 'hex32', mask: maskHex },
  { code: 'label', mask: maskLabelled },
  { code: 'pin', mask: maskPin },
  { code: 'entropy', mask: maskEntropy },
  { code: 'luhn', mask: maskLuhn },
]

/** Normalise, then mask. The only way text should be prepared for the classifier. */
export function prepareForGate(text: unknown): string {
  let out = normaliseForGate(text)
  for (const d of DETECTORS) out = d.mask(out)
  return out
}

function slug(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '')
}

/**
 * Residue check on the finished prompt (system + user part). Returns short codes,
 * never matched text. Empty array = clean.
 */
export function residueFindings(prompt: string): string[] {
  const found: string[] = []
  for (const { name, pattern } of SECRET_PATTERNS) {
    if (new RegExp(pattern.source, pattern.flags.replace('g', '')).test(prompt)) found.push(`secret_gate:${slug(name)}`)
  }
  for (const { name, pattern } of TRANSCRIPT_PATTERNS) {
    if (new RegExp(pattern.source, pattern.flags.replace('g', '')).test(prompt)) found.push(`transcript_gate:${slug(name)}`)
  }
  for (const d of DETECTORS) {
    if (d.mask(prompt) !== prompt) found.push(`mask:${d.code}`)
  }
  return found
}
