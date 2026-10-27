// Duplicate-key detector for raw JSON text.
//
// Why this exists: JSON.parse silently keeps only the LAST occurrence of a
// duplicated key. In a settings.json a duplicated hook-event key ("hooks"
// containing two "PreToolUse" arrays) therefore KILLS every hook in the
// earlier block -- no parse error, no warning, the guards just stop running.
// A parsed object cannot reveal this (the evidence is gone by then), so the
// check has to run on the raw text.
//
// The scanner is deliberately small: it tracks object/array nesting, string
// escapes, and key-vs-value position, and reports each duplicated key with
// its dotted path (arrays as [i]). It assumes syntactically valid JSON --
// callers parse the same text anyway, so malformed input surfaces there.
//
// Keys are compared DECODED, the way JSON.parse sees them: "\u0069n" and
// "in" are the same key, and so are "a\/b" and "a/b". Comparing the raw
// spelling let an escaped second key slip past this guard and still
// overwrite the first one (credit-gate review BE-2, 2026-10-16).

const SIMPLE_ESCAPES: Readonly<Record<string, string>> = { b: '\b', f: '\f', n: '\n', r: '\r', t: '\t' }
const HEX4 = /^[0-9a-fA-F]{4}$/

interface ObjFrame { type: 'obj'; keys: Set<string>; path: string; expectKey: boolean }
interface ArrFrame { type: 'arr'; index: number; path: string }
type Frame = ObjFrame | ArrFrame

function childPath(stack: Frame[], key?: string): string {
  const top = stack[stack.length - 1]
  if (!top) return key ?? ''
  if (top.type === 'arr') return `${top.path}[${top.index}]`
  return top.path ? `${top.path}.${key ?? ''}` : (key ?? '')
}

/**
 * Dotted paths of every key that appears more than once within the SAME
 * object, in source order (e.g. `hooks.PreToolUse`). Empty array = clean.
 */
export function findDuplicateJsonKeys(raw: string): string[] {
  const dups: string[] = []
  const stack: Frame[] = []
  let pendingKey: string | undefined
  let i = 0
  const n = raw.length

  const readString = (): string => {
    // raw[i] is the opening quote
    let s = ''
    i++
    while (i < n) {
      const ch = raw[i]
      if (ch === '\\') {
        const e = raw[i + 1] ?? ''
        const hex = raw.slice(i + 2, i + 6)
        if (e === 'u' && HEX4.test(hex)) {
          // One UTF-16 code unit; a surrogate pair is two escapes, which
          // concatenate to the same string JSON.parse builds.
          s += String.fromCharCode(parseInt(hex, 16))
          i += 6
          continue
        }
        // \" \\ \/ decode to themselves; a malformed escape fails JSON.parse.
        s += SIMPLE_ESCAPES[e] ?? e
        i += 2
        continue
      }
      if (ch === '"') { i++; return s }
      s += ch
      i++
    }
    return s
  }

  while (i < n) {
    const ch = raw[i]
    const top = stack[stack.length - 1]
    if (ch === '"') {
      if (top?.type === 'obj' && top.expectKey) {
        const key = readString()
        if (top.keys.has(key)) dups.push(top.path ? `${top.path}.${key}` : key)
        top.keys.add(key)
        top.expectKey = false
        pendingKey = key
      } else {
        readString() // a string VALUE; discard
        pendingKey = undefined
      }
      continue
    }
    if (ch === '{') {
      const path = childPath(stack, pendingKey)
      stack.push({ type: 'obj', keys: new Set(), path, expectKey: true })
      pendingKey = undefined
      i++
      continue
    }
    if (ch === '[') {
      const path = childPath(stack, pendingKey)
      stack.push({ type: 'arr', index: 0, path })
      pendingKey = undefined
      i++
      continue
    }
    if (ch === '}' || ch === ']') {
      stack.pop()
      i++
      continue
    }
    if (ch === ',') {
      if (top?.type === 'obj') top.expectKey = true
      if (top?.type === 'arr') top.index++
      i++
      continue
    }
    if (ch === ':') {
      i++
      continue
    }
    i++ // whitespace, literals, numbers
  }
  return dups
}
