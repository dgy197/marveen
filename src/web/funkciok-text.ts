// Function page S2: one shared definition of "characters that must never reach
// a stored decision quote or an agent prompt". The validator
// (funkciok-decisions.ts) rejects them, frameLine (funkciok-context.ts) strips
// them, so the two cannot drift apart.

// Unicode properties instead of a hand-kept list: every format character (Cf)
// and every Default_Ignorable_Code_Point (soft hyphen, combining grapheme
// joiner, Hangul fillers, Mongolian vowel separator, variation selectors,
// invisible operators, the unassigned 2065 slot, tag characters, ...).
const INVISIBLE = /[\p{Cf}\p{Default_Ignorable_Code_Point}]/u

/**
 * True for one character (a single code point) that is a control, a line or
 * paragraph separator, an invisible / format / default-ignorable character, or
 * a direction override or isolate. A newline is a control but is allowed on
 * request (the validator keeps it, frameLine flattens it itself).
 */
export function isHiddenChar(ch: string, allowNewline = false): boolean {
  const c = ch.codePointAt(0) as number
  if (c === 0x0a) return !allowNewline
  if (c <= 0x1f || (c >= 0x7f && c <= 0x9f)) return true
  if (c === 0x2028 || c === 0x2029) return true
  return INVISIBLE.test(ch)
}
