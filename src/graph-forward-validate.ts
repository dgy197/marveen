// Pure validators for the graph-mail `forward` and `show` subcommands (card
// graph-forward, Brainy 2958). No I/O, no network: everything here runs BEFORE
// the CLI touches the credentials file or Graph.
//
// The approval gate carries a Python twin of the recipient rule
// (scripts/hooks/email_extract.py). Both are pinned to the same vectors in
// scripts/hooks/graph-forward-cases.json, so a drift between the two shows up
// as a red test, not as a letter one side lets through and the other did not
// expect.

/** The only domain a forward may go to (spec D1). Compared case-insensitively, ASCII only. */
export const FORWARD_DOMAIN = 'fireeng.hu'

const LOCAL_PART_RE = /^[A-Za-z0-9._+-]{1,64}$/
const ASCII_DOMAIN_RE = /^[A-Za-z.]+$/

/**
 * Spec D1: one plain address, `local@fireeng.hu`, nothing else. ASCII only,
 * no whitespace or control character, exactly one `@`, a local part of 1-64
 * characters from `[A-Za-z0-9._+-]` that neither starts nor ends with a dot
 * and has no `..`, and a domain that is exactly `fireeng.hu` up to ASCII case
 * (no subdomain, no trailing dot). Display names, quoted local parts, lists,
 * source routes and IP literals are all refused, because each of them is a
 * way for one string to mean a different mailbox to a different parser.
 */
export function isForwardRecipient(addr: unknown): boolean {
  if (typeof addr !== 'string') return false
  const at = addr.indexOf('@')
  if (at === -1 || at !== addr.lastIndexOf('@')) return false
  const local = addr.slice(0, at)
  const domain = addr.slice(at + 1)
  if (!LOCAL_PART_RE.test(local)) return false
  if (local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false
  // ASCII letters and dots FIRST, the case fold only after: toLowerCase() maps
  // some non-ASCII characters onto ASCII (the Kelvin sign becomes "k"), so a
  // fold on unchecked input could turn a lookalike into the real domain.
  if (!ASCII_DOMAIN_RE.test(domain)) return false
  return domain.toLowerCase() === FORWARD_DOMAIN
}

const BARE_LOCAL_RE = /^[A-Za-z0-9._+-]{1,64}$/
const BARE_DOMAIN_RE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/

/**
 * Card efa58ad2 (S2): one bare addr-spec, `local@domain`, ASCII only. The local
 * part is 1-64 of `[A-Za-z0-9._+-]` with no leading or trailing dot and no `..`;
 * the domain is dot-separated ASCII labels (at least two), none starting or
 * ending with a hyphen. No display name, quote, angle bracket, parenthesis,
 * semicolon or whitespace can match, so no parser can read it as another mailbox.
 */
export function isBareAddress(addr: unknown): boolean {
  if (typeof addr !== 'string' || addr.length > 254) return false
  const at = addr.indexOf('@')
  if (at === -1 || at !== addr.lastIndexOf('@')) return false
  const local = addr.slice(0, at)
  if (!BARE_LOCAL_RE.test(local) || local.startsWith('.') || local.endsWith('.') || local.includes('..')) return false
  return BARE_DOMAIN_RE.test(addr.slice(at + 1))
}

/**
 * Card efa58ad2 (S2): the value of `--to` / `--cc` / `--bcc` of a send: a
 * comma-separated list of bare addresses (`a@b.hu,c@d.hu`) and nothing else; an
 * empty element, a stray space or any non-bare element refuses the whole list.
 * The Python twin is email_extract.bare_address_list_ok, pinned to the same
 * vectors in scripts/hooks/graph-bare-recipient-cases.json.
 */
export function isBareAddressList(value: unknown): boolean {
  return typeof value === 'string' && value !== '' && value.split(',').every(isBareAddress)
}

const MESSAGE_ID_RE = /^[A-Za-z0-9_=+/-]{16,512}$/

/**
 * Spec E2: the shape of a Graph message id (base64url-ish, 16-512 chars).
 * The character set is a tip from the Graph docs, confirmed on a real id in
 * the N7 live step. The id still goes into the request path through
 * encodeURIComponent; this check only keeps `..`, `?`, `#`, `%` and friends
 * out of the argument before anything is sent anywhere.
 */
export function isGraphMessageId(id: unknown): id is string {
  return typeof id === 'string' && MESSAGE_ID_RE.test(id)
}

const SHA256_HEX_RE = /^[0-9a-f]{64}$/

/**
 * Spec-delta KA3: the `--comment-sha256` value, exactly 64 lower-case hex
 * digits (what `shasum -a 256` prints), so there is one canonical form.
 */
export function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && SHA256_HEX_RE.test(value)
}

const OUTBOX_ROOT_RE = /^\/[A-Za-z0-9._/-]+$/

/**
 * Spec-delta KF1: the outbox root must be a plain absolute path. On top of the
 * KF1 character set it must already be in normal form (no empty, `.` or `..`
 * segment, no trailing slash): a root that is not would fail the realpath
 * check of KB1 anyway, this only says so before any file system access.
 */
export function isOutboxRoot(root: unknown): root is string {
  if (typeof root !== 'string' || !OUTBOX_ROOT_RE.test(root)) return false
  return root
    .slice(1)
    .split('/')
    .every((seg) => seg !== '' && seg !== '.' && seg !== '..')
}

const OUTBOX_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/

/**
 * Spec-delta KA4: the `--comment-file` value must be exactly `<root>/<name>`,
 * with a name of 1-128 characters from `[A-Za-z0-9._-]`, starting with a
 * letter or digit, and without `..`. No relative path, no `~`, no `//` or
 * `/./`, no subdirectory, no trailing slash; so also no `$`, backtick, glob
 * character, space, quote or non-ASCII character, and bash hands the CLI the
 * same string the gate's shlex saw.
 */
export function isOutboxCommentPath(path: unknown, root: unknown): path is string {
  if (typeof path !== 'string' || !isOutboxRoot(root)) return false
  if (!path.startsWith(`${root}/`)) return false
  const name = path.slice(root.length + 1)
  return OUTBOX_NAME_RE.test(name) && !name.includes('..')
}

interface ForwardArgsCommon {
  id: string
  to: string
  origSubject: string
}

/** Comment source (a): `--comment <text>`. */
export interface ForwardInlineArgs extends ForwardArgsCommon {
  comment: string
}

/** Comment source (b): `--comment-file <root>/<name> --comment-sha256 <hex>` (spec-delta KA1). */
export interface ForwardFileArgs extends ForwardArgsCommon {
  commentFile: string
  commentSha256: string
}

export type ForwardArgs = ForwardInlineArgs | ForwardFileArgs

export type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string }

type ForwardField = 'id' | 'to' | 'comment' | 'origSubject' | 'commentFile' | 'commentSha256'

const FORWARD_FLAGS = new Map<string, ForwardField>([
  ['--id', 'id'],
  ['--to', 'to'],
  ['--comment', 'comment'],
  ['--orig-subject', 'origSubject'],
  ['--comment-file', 'commentFile'],
  ['--comment-sha256', 'commentSha256'],
])

/** The flags every forward needs, whichever comment source it uses. */
const REQUIRED_FLAGS: ReadonlyArray<readonly [string, ForwardField]> = [
  ['--id', 'id'],
  ['--to', 'to'],
  ['--orig-subject', 'origSubject'],
]

/** Short, display-safe rendering of an offending argv token for an error line. */
function tokenForError(token: string): string {
  return quoteForDisplay(token.length > 80 ? `${token.slice(0, 80)}...` : token)
}

export interface ParseForwardOptions {
  /**
   * The outbox root (spec-delta KF1) a `--comment-file` must sit directly in.
   * Without it the file form is refused; the inline form does not need it.
   */
  outboxRoot?: string
}

/**
 * Spec E1 (+ D1, E2, B5) and spec-delta KA1-KA4: the argv after the word `forward`.
 *
 * `--id`, `--to` and `--orig-subject`, plus EXACTLY ONE comment source:
 * (a) `--comment <text>`, or (b) `--comment-file <path>` together with
 * `--comment-sha256 <hex>`. Every flag at most once, each as its own token
 * followed by its value, in any order. Refused: a missing or repeated flag,
 * both sources or neither, half of the (b) pair, `--comment-sha256` next to
 * `--comment`, the `--flag=value` form, any other flag (`--cc`, `--bcc`,
 * `--attach`, `--html`, ...), a positional token, a flag with no value, and a
 * value that itself starts with `--` (a dropped value would otherwise silently
 * shift every pair after it). Then the values: the recipient must pass
 * isForwardRecipient, the id isGraphMessageId; an inline comment must not be
 * blank, a file comment needs a lower-case sha256 hex (KA3) and a path that is
 * exactly `<outboxRoot>/<name>` (KA4). The file itself is read later, by
 * readForwardCommentFile. The subject is not checked here: the CLI compares
 * it with the real message (E3).
 */
export function parseForwardArgv(
  argv: readonly string[],
  options: ParseForwardOptions = {},
): ParseResult<ForwardArgs> {
  const seen = new Map<ForwardField, string>()
  for (let i = 0; i < argv.length; i += 2) {
    const flag = argv[i]
    const key = FORWARD_FLAGS.get(flag)
    if (key === undefined) {
      return { ok: false, error: `unexpected argument ${tokenForError(flag)}` }
    }
    if (seen.has(key)) return { ok: false, error: `${flag} given more than once` }
    if (i + 1 >= argv.length) return { ok: false, error: `${flag} needs a value` }
    const value = argv[i + 1]
    if (value.startsWith('--')) {
      return { ok: false, error: `${flag} needs a value, got ${tokenForError(value)}` }
    }
    seen.set(key, value)
  }
  const missing = REQUIRED_FLAGS.filter(([, key]) => !seen.has(key)).map(([flag]) => flag)
  if (missing.length > 0) return { ok: false, error: `missing ${missing.join(', ')}` }

  // Spec-delta KA1: exactly one comment source.
  const inline = seen.has('comment')
  const file = seen.has('commentFile')
  const hash = seen.has('commentSha256')
  if (inline && (file || hash)) {
    return {
      ok: false,
      error: '--comment cannot be combined with --comment-file or --comment-sha256: give exactly one comment source',
    }
  }
  if (!inline && !file && !hash) {
    return { ok: false, error: 'missing the comment: --comment <text>, or --comment-file <path> --comment-sha256 <hex>' }
  }
  if (file !== hash) {
    return { ok: false, error: '--comment-file and --comment-sha256 go together: one is missing' }
  }

  const id = seen.get('id') as string
  const to = seen.get('to') as string
  const origSubject = seen.get('origSubject') as string
  if (!isGraphMessageId(id)) {
    return { ok: false, error: `--id is not a Graph message id: ${tokenForError(id)}` }
  }
  if (!isForwardRecipient(to)) {
    return {
      ok: false,
      error: `--to must be exactly one plain @${FORWARD_DOMAIN} address, got ${tokenForError(to)}`,
    }
  }
  if (inline) {
    const comment = seen.get('comment') as string
    if (comment.trim() === '') return { ok: false, error: '--comment must not be empty' }
    return { ok: true, value: { id, to, comment, origSubject } }
  }

  const commentFile = seen.get('commentFile') as string
  const commentSha256 = seen.get('commentSha256') as string
  if (!isSha256Hex(commentSha256)) {
    return {
      ok: false,
      error: `--comment-sha256 must be 64 lower-case hex digits (shasum -a 256), got ${tokenForError(commentSha256)}`,
    }
  }
  const root = options.outboxRoot
  if (!isOutboxRoot(root)) {
    return {
      ok: false,
      error: `the outbox root is not a plain absolute path: ${root === undefined ? 'none' : tokenForError(root)}`,
    }
  }
  if (!isOutboxCommentPath(commentFile, root)) {
    return {
      ok: false,
      error:
        `--comment-file must be ${root}/<name> (name: letters, digits, . _ -, at most 128, ` +
        `no leading dot, no ..), got ${tokenForError(commentFile)}`,
    }
  }
  return { ok: true, value: { id, to, origSubject, commentFile, commentSha256 } }
}

/** The argv after the word `show`: exactly `--id <id>`. */
export function parseShowArgv(argv: readonly string[]): ParseResult<{ id: string }> {
  if (argv.length !== 2 || argv[0] !== '--id') {
    return { ok: false, error: 'show takes exactly --id <message id>' }
  }
  if (!isGraphMessageId(argv[1])) {
    return { ok: false, error: `--id is not a Graph message id: ${tokenForError(argv[1])}` }
  }
  return { ok: true, value: { id: argv[1] } }
}

// Characters a terminal or a reader cannot see, or that reorder what is shown:
// controls (C0 is already escaped by JSON.stringify; DEL and C1 are not),
// format characters (bidi overrides, zero-width space and joiners, BOM, soft
// hyphen, tag characters) and the two Unicode line/paragraph separators.
const INVISIBLE_RE = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu

/**
 * JSON-quote a third-party string (a subject, a sender) for display, with every
 * invisible or reordering character written as a `\uXXXX` escape. The result
 * is still valid JSON, so JSON.parse gives back the exact original string; the
 * accented letters stay readable. A subject with a hidden character therefore
 * shows WHY a copied `--orig-subject` does not match, instead of looking equal.
 */
export function quoteForDisplay(value: string): string {
  return JSON.stringify(value).replace(INVISIBLE_RE, (ch) => {
    let out = ''
    for (let i = 0; i < ch.length; i++) out += '\\u' + ch.charCodeAt(i).toString(16).padStart(4, '0')
    return out
  })
}

// --- send -------------------------------------------------------------------

/** Body source (a): `--body <text>`. */
export interface SendInlineBody {
  body: string
}

/** Body source (b): `--body-file <root>/<name> --body-sha256 <hex>` (card graph-forward r3, node W2). */
export interface SendFileBody {
  bodyFile: string
  bodySha256: string
}

export type SendArgs = (SendInlineBody | SendFileBody) & {
  to: string
  subject: string
  cc?: string
  attach?: string
  html: boolean
}

type SendField = 'to' | 'subject' | 'body' | 'bodyFile' | 'bodySha256' | 'cc' | 'attach'

const SEND_VALUE_FLAGS = new Map<string, SendField>([
  ['--to', 'to'],
  ['--subject', 'subject'],
  ['--body', 'body'],
  ['--body-file', 'bodyFile'],
  ['--body-sha256', 'bodySha256'],
  ['--cc', 'cc'],
  ['--attach', 'attach'],
])

/**
 * The argv after the word `send` (card graph-forward r3, node W2): `--to` and
 * `--subject`, EXACTLY ONE body source, and optionally `--cc`, `--attach` and
 * `--html` (no value). The body source is either (a) `--body <text>` or (b)
 * `--body-file <path>` together with `--body-sha256 <hex>`. The shape rules are
 * those of parseForwardArgv: every flag at most once, each as its own token
 * followed by its value, in any order; refused are a missing or repeated flag,
 * both sources or neither, half of the (b) pair, `--body-sha256` next to
 * `--body`, the `--flag=value` form, any other flag (`--bcc` too: the CLI never
 * sent it, so the gate must not be able to see one), a positional token, a
 * flag with no value, and a value that itself starts with `--` (a dropped
 * value would otherwise shift every pair after it, and `--subject --body-file`
 * could not be told from a flag). The (b) values are checked like the forward
 * comment file: a lower-case sha256 hex (KA3) and a path that is exactly
 * `<outboxRoot>/<name>` (KA4). The file itself is read later, by
 * readSendBodyFile. `--to` and `--cc` must be bare address lists (S2,
 * isBareAddressList); the approval gate refuses anything else too.
 */
export function parseSendArgv(
  argv: readonly string[],
  options: ParseForwardOptions = {},
): ParseResult<SendArgs> {
  const seen = new Map<SendField, string>()
  let html = false
  for (let i = 0; i < argv.length; ) {
    const flag = argv[i]
    if (flag === '--html') {
      if (html) return { ok: false, error: '--html given more than once' }
      html = true
      i += 1
      continue
    }
    const key = SEND_VALUE_FLAGS.get(flag)
    if (key === undefined) return { ok: false, error: `unexpected argument ${tokenForError(flag)}` }
    if (seen.has(key)) return { ok: false, error: `${flag} given more than once` }
    if (i + 1 >= argv.length) return { ok: false, error: `${flag} needs a value` }
    const value = argv[i + 1]
    if (value.startsWith('--')) {
      return { ok: false, error: `${flag} needs a value, got ${tokenForError(value)}` }
    }
    seen.set(key, value)
    i += 2
  }
  const absent = (
    [
      ['--to', 'to'],
      ['--subject', 'subject'],
    ] as const
  )
    .filter(([, key]) => (seen.get(key) ?? '') === '')
    .map(([flag]) => flag)
  if (absent.length > 0) return { ok: false, error: `missing ${absent.join(', ')}` }

  for (const [flag, key] of [
    ['--to', 'to'],
    ['--cc', 'cc'],
  ] as const) {
    if (seen.has(key) && !isBareAddressList(seen.get(key))) {
      return {
        ok: false,
        error:
          `${flag} must be a comma-separated list of bare addresses (a@b.hu,c@d.hu): no display name, ` +
          `quote, angle bracket, comment, semicolon or space, got ${tokenForError(seen.get(key) as string)}`,
      }
    }
  }

  const inline = seen.has('body')
  const file = seen.has('bodyFile')
  const hash = seen.has('bodySha256')
  if (inline && (file || hash)) {
    return {
      ok: false,
      error: '--body cannot be combined with --body-file or --body-sha256: give exactly one body source',
    }
  }
  if (!inline && !file && !hash) {
    return { ok: false, error: 'missing the body: --body <text>, or --body-file <path> --body-sha256 <hex>' }
  }
  if (file !== hash) {
    return { ok: false, error: '--body-file and --body-sha256 go together: one is missing' }
  }

  const common = {
    to: seen.get('to') as string,
    subject: seen.get('subject') as string,
    html,
    ...(seen.has('cc') ? { cc: seen.get('cc') as string } : {}),
    ...(seen.has('attach') ? { attach: seen.get('attach') as string } : {}),
  }
  if (inline) return { ok: true, value: { ...common, body: seen.get('body') as string } }

  const bodyFile = seen.get('bodyFile') as string
  const bodySha256 = seen.get('bodySha256') as string
  if (!isSha256Hex(bodySha256)) {
    return {
      ok: false,
      error: `--body-sha256 must be 64 lower-case hex digits (shasum -a 256), got ${tokenForError(bodySha256)}`,
    }
  }
  const root = options.outboxRoot
  if (!isOutboxRoot(root)) {
    return {
      ok: false,
      error: `the outbox root is not a plain absolute path: ${root === undefined ? 'none' : tokenForError(root)}`,
    }
  }
  if (!isOutboxCommentPath(bodyFile, root)) {
    return {
      ok: false,
      error:
        `--body-file must be ${root}/<name> (name: letters, digits, . _ -, at most 128, ` +
        `no leading dot, no ..), got ${tokenForError(bodyFile)}`,
    }
  }
  return { ok: true, value: { ...common, bodyFile, bodySha256 } }
}
