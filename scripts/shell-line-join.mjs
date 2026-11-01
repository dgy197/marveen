// The ONE shared backslash-newline joiner of the gates (card 3660cf43, planned as 3e13973c; spec.md section 3).
//
// joinShellLines(src, info) returns the text the way the shell's lexer sees it after line continuation:
// every backslash + LF that the shell removes is removed, and nothing else changes. One left-to-right pass,
// a small state machine, no regex backtracking, no import, no I/O, never throws.
//
// Measured on /bin/bash 3.2.57 and /bin/zsh 5.9 (2026-11-01, card 3e13973c tmp/semantics*.txt, probe.mjs):
//   rule 1  only backslash + LF continues, and the pair vanishes (cron\<NL>tab = crontab). A run of
//           backslashes is read as escape pairs, so only an ODD run joins. backslash + CR is an ordinary escape.
//   rule 2  no joining in '...', $'...', a quoted heredoc body (<<'T', <<"T", <<\T, <<E"OF") or a comment.
//   rule 3  a comment starts at a word-initial # in a normal or $(...) context and ends at the LF; a trailing
//           backslash does not extend it. $# and a # inside a word are not comments.
//   rule 4  every context decision (word start, <<, $(, $', the heredoc tag) is made on the JOINED stream.
//   rule 5  the heredoc bodies follow the logical line that carries their operators, in order; an unquoted
//           body is joined and its terminator is matched on the joined line (V12); <<- strips leading TABs.
//   rule 6  info.exact = false when the reading is not sure: an unterminated quote, substitution or heredoc,
//           a backslash run + LF inside backticks (they halve the run, V22), a continuation inside arithmetic,
//           a `case` inside $(...) (the keyword is read on the joined stream), or a `)` that closes a $(...)
//           whose body holds the word `in` (a case pattern close looks the same; `for x in` trips it too).
//           The returned text is still the reading of these rules.
//   rule 7  idempotent: every decision depends only on the joined stream, and the output IS that stream.
//
// info: { exact: boolean, reason: string|null }, reset on every call; reason keeps the first cause.
//
// shellContext(src) (card 0bb35172, planned as spec section 4): the SAME pass, plus the context it decided on, so the
// gates never re-guess "is this << a heredoc, is this -d inside a quote" with a regex of their own. It returns
//   { text, cls, quotes, heredocs, exact, reason }
//   text      === joinShellLines(src); every coordinate below counts in `text`
//   cls       Uint8Array, one CTX_CLASS value per character of text:
//             CODE (including `$(`, `<<` and the heredoc tag), COMMENT (from the # to the LF), SQ ('...'),
//             ANSI ($'...'), DQ ("..." and $"...", the quotes themselves included; a ${...} inside "..." too),
//             BQ (a backtick run, both backticks included), HEREDOC_Q / HEREDOC_U (the body lines of a quoted /
//             unquoted delimiter, the terminator line included, every LF of those lines included)
//   quotes    [{ start, end, kind: 'sq'|'ansi'|'dq', subst }], in order of start, end exclusive; subst (dq only) is
//             true when a `$(` or a backtick opens inside, however deep. A "..." the text never closes is left out
//   heredocs  [{ opStart, tagEnd, bodyStart, bodyEnd, termEnd, quoted, strip, subst, tag }], in order of the
//             operators; opStart is the `<<`, tagEnd the end of the delimiter word, [bodyStart, bodyEnd) the body,
//             termEnd the end of the terminator line (with its LF); an unterminated body ends at the end of text.
//             subst (unquoted only) is true when a body line holds `$(` or a backtick. A `<<` the lexer did not
//             open as an operator (comment, quote, here-string) is not in the list.
//   exact/reason  what joinShellLines reports in info for the same call
// Without a map (every joinShellLines call) the scan allocates nothing for any of this.

// the values of cls (the numbers are part of the contract, tests and gates compare them)
export const CTX_CLASS = Object.freeze({ CODE: 0, COMMENT: 1, SQ: 2, ANSI: 3, DQ: 4, HEREDOC_Q: 5, HEREDOC_U: 6, BQ: 7 })
const K_CODE = 0
const K_COMMENT = 1
const K_SQ = 2
const K_ANSI = 3
const K_DQ = 4
const K_HQ = 5
const K_HU = 6
const K_BQ = 7

const BSL = 92
const LF = 10
const SQ = 39
const DQ = 34
const BQ = 96
const DOLLAR = 36
const HASH = 35
const LT = 60
const GT = 62
const LP = 40
const RP = 41
const LB = 123
const RB = 125
const SEMI = 59
const AMP = 38
const PIPE = 124
const SP = 32
const TAB = 9
const DASH = 45

// characters that end an unquoted word (shell metacharacters and blanks)
function isBreak(c) {
  return c === SP || c === TAB || c === LF || c === SEMI || c === AMP || c === PIPE || c === LP || c === RP || c === LT || c === GT
}

export function joinShellLines(src, info = {}) {
  return scan(src, info, null)
}

export function shellContext(src) {
  const info = {}
  const map = { cls: null, quotes: [], heredocs: [] }
  const text = scan(src, info, map)
  return { text, cls: map.cls.subarray(0, text.length), quotes: map.quotes, heredocs: map.heredocs, exact: info.exact, reason: info.reason }
}

// The one lexer pass. `map` is null (joinShellLines) or { cls, quotes, heredocs } to fill (shellContext).
function scan(src, info, map) {
  const s = typeof src === 'string' ? src : String(src ?? '')
  info.exact = true
  info.reason = null
  const n = s.length
  let i = 0
  let out = ''
  const rec = map !== null
  // the output is never longer than the input (it only drops backslash + LF pairs)
  const cls = rec ? new Uint8Array(n) : null
  if (rec) map.cls = cls
  // open "..." records, innermost last (a substitution marks every one of them)
  const dqOpen = []

  // append text of class k to the output (and to the class array when a map is wanted)
  const put = (text, k) => {
    if (rec) cls.fill(k, out.length, out.length + text.length)
    out += text
  }
  const markSubst = () => {
    if (rec) for (let q = 0; q < dqOpen.length; q++) dqOpen[q].subst = true
  }
  const openDq = (start) => {
    if (!rec) return
    const q = { start, end: -1, kind: 'dq', subst: false }
    map.quotes.push(q)
    dqOpen.push(q)
  }
  // atWord: the next joined character starts a word (decides whether # opens a comment, rule 3)
  let atWord = true
  // frames: top | subst $(...) | arith $((...)) / ((...)) | brace ${...} | dq "..." | bq `...`
  const frames = [{ t: 'top', depth: 0, inDq: false }]
  // heredocs whose operator has been read and whose body starts after the next LF of a normal context
  let pending = []

  const inexact = (reason) => {
    if (info.exact) {
      info.exact = false
      info.reason = reason
    }
  }

  // index of the next joined character: steps over every backslash + LF (lookahead across continuations, rule 4)
  const skip = (j) => {
    while (s.charCodeAt(j) === BSL && s.charCodeAt(j + 1) === LF) j += 2
    return j
  }

  // Does the joined stream hold `word` at i, as a whole word? Every character is read through skip(), so a
  // continuation inside the word (ca\<NL>se) or right after it (case\<NL> a) is stepped over (rule 4).
  // Returns true when the word is complete there: the next joined character is a word break or the end.
  const wordAt = (word, at) => {
    let j = at
    for (let k = 0; k < word.length; k++) {
      j = skip(j)
      if (s.charCodeAt(j) !== word.charCodeAt(k)) return false
      j++
    }
    j = skip(j)
    return j >= n || isBreak(s.charCodeAt(j))
  }

  // A backslash run at i, in a joining context. Escape pairs are copied; an odd run escapes the next
  // character, and when that is LF the last backslash and the LF vanish (rule 1). Returns the copied text.
  // `onLf` is called when the run is followed by LF (backtick halving, continuation in arithmetic).
  const backslashRun = (onLf) => {
    let j = i
    while (j < n && s.charCodeAt(j) === BSL) j++
    const k = j - i
    const nextIsLf = s.charCodeAt(j) === LF
    if (nextIsLf && onLf) onLf()
    let text
    if (k % 2 === 0) {
      text = s.slice(i, j)
      i = j
    } else if (j >= n) {
      // a lone trailing backslash stays as it is
      text = s.slice(i, j)
      i = j
    } else if (nextIsLf) {
      text = s.slice(i, j - 1)
      i = j + 1
    } else {
      text = s.slice(i, j + 1)
      i = j + 1
    }
    return text
  }

  const matchesTag = (line, h) => {
    let k = 0
    if (h.strip) while (line.charCodeAt(k) === TAB) k++
    return (k === 0 ? line : line.slice(k)) === h.tag
  }

  // the heredoc bodies, in order, right after the LF that ended their logical line (rule 5)
  const readBodies = () => {
    const list = pending
    pending = []
    for (const h of list) {
      let closed = false
      const bodyStart = out.length
      let bodyEnd = bodyStart
      let subst = false
      while (i < n && !closed) {
        const lineStart = out.length
        if (h.quoted) {
          // data: copied line by line, untouched (rule 2)
          const e = s.indexOf('\n', i)
          const end = e < 0 ? n : e
          const line = s.slice(i, end)
          put(e < 0 ? line : line + '\n', K_HQ)
          i = e < 0 ? n : e + 1
          closed = matchesTag(line, h)
          if (closed) bodyEnd = lineStart
        } else {
          // one logical line, joined; the terminator is looked for on the joined line (V12)
          let line = ''
          let ended = false
          while (i < n) {
            const c = s.charCodeAt(i)
            if (c === BSL) {
              line += backslashRun(null)
            } else if (c === LF) {
              i++
              ended = true
              break
            } else {
              let j = i + 1
              while (j < n && s.charCodeAt(j) !== BSL && s.charCodeAt(j) !== LF) j++
              line += s.slice(i, j)
              i = j
            }
          }
          put(ended ? line + '\n' : line, K_HU)
          closed = matchesTag(line, h)
          if (closed) bodyEnd = lineStart
          else if (rec && (line.includes('$(') || line.includes('`'))) subst = true
        }
      }
      if (!closed) {
        inexact('unterminated heredoc')
        bodyEnd = out.length
      }
      if (rec) {
        map.heredocs.push({ opStart: h.opStart, tagEnd: h.tagEnd, bodyStart, bodyEnd, termEnd: out.length, quoted: h.quoted, strip: h.strip, subst, tag: h.tag })
      }
    }
  }

  // the delimiter word after << or <<-, read on the joined stream; any quoting makes the body data (rule 5)
  const readTag = (strip, opStart) => {
    for (;;) {
      i = skip(i)
      const c = s.charCodeAt(i)
      if (c !== SP && c !== TAB) break
      put(s[i], K_CODE)
      i++
    }
    let tag = ''
    let quoted = false
    let any = false
    while (i < n) {
      i = skip(i)
      if (i >= n) break
      const c = s.charCodeAt(i)
      if (isBreak(c)) break
      any = true
      if (c === BSL) {
        // skip() already took a continuation, so this escapes a real character (or ends the text)
        if (i + 1 >= n) {
          put('\\', K_CODE)
          tag += '\\'
          i++
          break
        }
        quoted = true
        tag += s[i + 1]
        put(s.slice(i, i + 2), K_CODE)
        i += 2
      } else if (c === SQ) {
        quoted = true
        const e = s.indexOf("'", i + 1)
        if (e < 0) {
          inexact('unterminated quote in a heredoc delimiter')
          tag += s.slice(i + 1)
          put(s.slice(i), K_CODE)
          i = n
          break
        }
        tag += s.slice(i + 1, e)
        put(s.slice(i, e + 1), K_CODE)
        i = e + 1
      } else if (c === DQ) {
        quoted = true
        put('"', K_CODE)
        i++
        let closed = false
        while (i < n) {
          const d = s.charCodeAt(i)
          if (d === BSL) {
            if (s.charCodeAt(i + 1) === LF) {
              i += 2
              continue
            }
            if (i + 1 >= n) {
              put('\\', K_CODE)
              tag += '\\'
              i++
              continue
            }
            const e = s[i + 1]
            tag += '$`"\\'.includes(e) ? e : '\\' + e
            put(s.slice(i, i + 2), K_CODE)
            i += 2
          } else if (d === DQ) {
            put('"', K_CODE)
            i++
            closed = true
            break
          } else {
            put(s[i], K_CODE)
            tag += s[i]
            i++
          }
        }
        if (!closed) inexact('unterminated quote in a heredoc delimiter')
      } else {
        put(s[i], K_CODE)
        tag += s[i]
        i++
      }
    }
    if (!any) {
      // `<<` with no word: a syntax error, the shell runs nothing of it
      inexact('heredoc without a delimiter')
      return
    }
    pending.push({ tag, quoted, strip, opStart, tagEnd: out.length })
    atWord = false
  }

  // `$` at i in a normal, brace or double-quote frame: $( $(( ${ $' $" open a context (on the joined stream)
  const dollar = (allowAnsi) => {
    const j = skip(i + 1)
    const d = s.charCodeAt(j)
    if (d === LP) {
      const j2 = skip(j + 1)
      // the opener is code even inside "...": what follows runs
      markSubst()
      if (s.charCodeAt(j2) === LP) {
        put('$((', K_CODE)
        i = j2 + 1
        frames.push({ t: 'arith', depth: 1, inDq: false })
      } else {
        put('$(', K_CODE)
        i = j + 1
        frames.push({ t: 'subst', depth: 0, inDq: false })
      }
      atWord = true
      return
    }
    const top = frames[frames.length - 1]
    const inDq = top.t === 'dq' || top.inDq
    if (d === LB) {
      put('${', inDq ? K_DQ : K_CODE)
      i = j + 1
      frames.push({ t: 'brace', depth: 0, inDq })
      atWord = false
      return
    }
    if (allowAnsi && d === SQ) {
      // $'...': backslash escapes, no joining (rule 2)
      const qStart = out.length
      put("$'", K_ANSI)
      let k = j + 1
      while (k < n) {
        const c = s.charCodeAt(k)
        if (c === BSL) k += 2
        else if (c === SQ) break
        else k++
      }
      if (k >= n) {
        inexact("unterminated $'...'")
        put(s.slice(j + 1), K_ANSI)
        i = n
      } else {
        put(s.slice(j + 1, k + 1), K_ANSI)
        i = k + 1
      }
      if (rec) map.quotes.push({ start: qStart, end: out.length, kind: 'ansi', subst: false })
      atWord = false
      return
    }
    if (allowAnsi && d === DQ) {
      openDq(out.length)
      put('$"', K_DQ)
      i = j + 1
      frames.push({ t: 'dq', depth: 0, inDq: false })
      atWord = false
      return
    }
    put('$', inDq ? K_DQ : K_CODE)
    i++
    atWord = false
  }

  const stepNormal = (f) => {
    const t = f.t
    const c = s.charCodeAt(i)
    // a ${...} that sits inside "..." stays part of the string
    const kc = f.inDq ? K_DQ : K_CODE
    if (c === BSL) {
      const text = backslashRun(t === 'arith' ? () => inexact('continuation inside arithmetic') : null)
      if (text) {
        put(text, kc)
        atWord = false
      }
      return
    }
    if (c === LF) {
      put('\n', kc)
      i++
      atWord = true
      if (pending.length) readBodies()
      return
    }
    if (c === SQ && !f.inDq) {
      const qStart = out.length
      const e = s.indexOf("'", i + 1)
      if (e < 0) {
        inexact('unterminated single quote')
        put(s.slice(i), K_SQ)
        i = n
      } else {
        put(s.slice(i, e + 1), K_SQ)
        i = e + 1
      }
      if (rec) map.quotes.push({ start: qStart, end: out.length, kind: 'sq', subst: false })
      atWord = false
      return
    }
    if (c === DQ) {
      openDq(out.length)
      put('"', K_DQ)
      i++
      frames.push({ t: 'dq', depth: 0, inDq: false })
      atWord = false
      return
    }
    if (c === BQ) {
      markSubst()
      put('`', K_BQ)
      i++
      frames.push({ t: 'bq', depth: 0, inDq: false })
      atWord = false
      return
    }
    if (c === DOLLAR) {
      dollar(true)
      return
    }
    const words = t === 'top' || t === 'subst'
    if (c === HASH && atWord && words) {
      // a comment runs to the LF, untouched (rules 2 and 3); the LF itself is handled by the next step
      const e = s.indexOf('\n', i)
      const end = e < 0 ? n : e
      put(s.slice(i, end), K_COMMENT)
      i = end
      return
    }
    if (c === LT && words) {
      const j1 = skip(i + 1)
      if (s.charCodeAt(j1) !== LT) {
        put('<', K_CODE)
        i++
        atWord = true
        return
      }
      const j2 = skip(j1 + 1)
      const c2 = s.charCodeAt(j2)
      if (c2 === LT) {
        // <<< is a here-string, not a heredoc
        put('<<<', K_CODE)
        i = j2 + 1
        atWord = true
        return
      }
      const opStart = out.length
      if (c2 === DASH) {
        put('<<-', K_CODE)
        i = j2 + 1
        readTag(true, opStart)
      } else {
        put('<<', K_CODE)
        i = j2
        readTag(false, opStart)
      }
      return
    }
    if (t === 'brace') {
      if (c === LB) f.depth++
      else if (c === RB) {
        if (f.depth > 0) f.depth--
        else frames.pop()
      }
      put(s[i], kc)
      i++
      atWord = false
      return
    }
    if (c === LP) {
      if (atWord && t !== 'arith') {
        const j = skip(i + 1)
        if (s.charCodeAt(j) === LP) {
          // (( arithmetic command
          put('((', K_CODE)
          i = j + 1
          frames.push({ t: 'arith', depth: 1, inDq: false })
          atWord = true
          return
        }
      }
      if (t !== 'top') f.depth++
      put('(', K_CODE)
      i++
      atWord = true
      return
    }
    if (c === RP) {
      put(')', K_CODE)
      i++
      if (t === 'top') {
        atWord = true
      } else if (f.depth > 0) {
        f.depth--
        atWord = true
      } else {
        // a `)` with no matching `(` closes $(...); after an `in` word it may be a case pattern close instead
        if (t === 'subst' && f.sawIn) inexact('unmatched ) after in inside $(...)')
        frames.pop()
        atWord = false
      }
      return
    }
    if (isBreak(c)) {
      put(s[i], K_CODE)
      i++
      atWord = true
      return
    }
    // a run of ordinary word characters
    if (t === 'subst' && atWord) {
      // `case x in a)` would close $(...) early here: not modelled (spec section 5). Keywords are read on the
      // joined stream (rule 4): ca\<NL>se and case\<NL> a are the keyword too.
      if (wordAt('case', i)) inexact('case inside $(...)')
      else if (wordAt('in', i)) f.sawIn = true
    }
    let j = i + 1
    while (j < n) {
      const d = s.charCodeAt(j)
      if (d === BSL || d === SQ || d === DQ || d === BQ || d === DOLLAR || d === HASH || d === LB || d === RB || isBreak(d)) break
      j++
    }
    put(s.slice(i, j), kc)
    i = j
    atWord = false
  }

  const stepDq = () => {
    const c = s.charCodeAt(i)
    if (c === BSL) {
      put(backslashRun(null), K_DQ)
      return
    }
    if (c === DQ) {
      put('"', K_DQ)
      i++
      frames.pop()
      if (rec) dqOpen.pop().end = out.length
      atWord = false
      return
    }
    if (c === DOLLAR) {
      dollar(false)
      return
    }
    if (c === BQ) {
      markSubst()
      put('`', K_BQ)
      i++
      frames.push({ t: 'bq', depth: 0, inDq: false })
      return
    }
    let j = i + 1
    while (j < n) {
      const d = s.charCodeAt(j)
      if (d === BSL || d === DQ || d === DOLLAR || d === BQ) break
      j++
    }
    put(s.slice(i, j), K_DQ)
    i = j
  }

  // backticks: scanned to the next unescaped backtick; a backslash run + LF inside is not read exactly (V22)
  const stepBq = () => {
    const c = s.charCodeAt(i)
    if (c === BSL) {
      put(backslashRun(() => inexact('continuation inside backticks')), K_BQ)
      return
    }
    if (c === BQ) {
      put('`', K_BQ)
      i++
      frames.pop()
      atWord = false
      return
    }
    let j = i + 1
    while (j < n) {
      const d = s.charCodeAt(j)
      if (d === BSL || d === BQ) break
      j++
    }
    put(s.slice(i, j), K_BQ)
    i = j
  }

  while (i < n) {
    const f = frames[frames.length - 1]
    if (f.t === 'dq') stepDq()
    else if (f.t === 'bq') stepBq()
    else stepNormal(f)
  }

  if (frames.length > 1) {
    const t = frames[frames.length - 1].t
    inexact(t === 'dq' ? 'unterminated double quote' : t === 'bq' ? 'unterminated backtick' : `unterminated ${t}`)
  }
  if (pending.length) inexact('unterminated heredoc')
  // a "..." the text never closes is not a token (exact is false then, and the gates treat it as such)
  if (rec && dqOpen.length) map.quotes = map.quotes.filter((q) => q.end >= 0)
  return out
}
