import { spawnSync } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { realpathSync } from 'node:fs'
import { basename, join } from 'node:path'
import { NO_TRUSTED_PYTHON_MESSAGE, resolveTrustedPython, trustedPythonEnv } from './trusted-python.js'

// The CLI side of the send authorization (card efa58ad2, cli-send-enforce).
//
// scripts/graph-mail.ts `send` and `forward` decide for themselves whether a
// letter may go out, however the command was typed (glob, quotes, wrappers,
// `bash -c`...): right before the Graph POST they build the envelope from the
// bytes they are about to send and hand it to scripts/hooks/email_send_authorize.py,
// the SAME code the PreToolUse hook runs (level, standing recipients, content
// anchor, one-shot consumption). There is one implementation of the anchor, in
// Python; nothing here recomputes it.
//
// Fail-closed: the letter goes out ONLY if the helper exited 0 AND printed
// decision "allow". A helper that does not start, hangs past the timeout, exits
// with anything but 0/2, prints something that is not one JSON verdict, or
// contradicts its own exit code is a refusal ("authorizer_failed").
//
// Paths: the helper is found from the repo root the CLI itself was started from
// (realpath), never from an environment variable. The only way to point this
// module elsewhere is the `repoRoot` argument and the `options` object, which
// scripts/graph-mail.ts never passes (only the tests do).

const HELPER_REL = ['scripts', 'hooks', 'email_send_authorize.py'] as const
export const HELPER_TIMEOUT_MS = 10_000

/** One attachment as the hook's extractor yields it. */
export interface EnvelopeAttachment {
  name: string
  sha256: string
  size: number
}

/** The request the helper reads on stdin (see the helper's module docstring). */
export interface SendEnvelope {
  kind: 'send' | 'forward'
  /** Entries RAW, as the hook's extractor yields them: a `--to a@b.hu,c@d.hu` is ONE entry. */
  to: string[]
  cc: string[]
  bcc: string[]
  /** subject + body joined by LF in command-line flag order (send), or the comment (forward). */
  text: string
  attachments?: EnvelopeAttachment[]
  forward?: { message_id: string; subject: string }
  comment_source?: 'inline' | 'file'
  comment_sha256?: string
  comment_file?: string
  /** Idempotency key, stored in approvals.consumed_ref. */
  ref: string
}

export interface HelperVerdict {
  decision: 'allow' | 'refuse'
  reason: string
  approval_id: string | null
  anchor: string | null
  standing: string | null
  detail: string | null
  note: string | null
  level: number | null
}

export type Authorization =
  | { allowed: true; verdict: HelperVerdict }
  | { allowed: false; reason: string; detail: string | null; verdict: HelperVerdict | null }

/** Test-only knobs. scripts/graph-mail.ts never passes them. */
export interface AuthorizeTestOptions {
  timeoutMs?: number
}

const sha256Hex = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')

export function newRef(kind: 'send' | 'forward'): string {
  return `graph-mail:${kind}:${randomUUID()}`
}

// --- envelope building --------------------------------------------------------

const SEND_TEXT_FLAGS = ['--subject', '--body', '--body-file'] as const

/**
 * The text of a send, the way the hook's _graph_send_text builds it: the
 * subject and the body in the ORDER their flags stand in the command line,
 * joined by LF, no trim. `argv` is what parseSendArgv parsed (each flag at most
 * once, a value never starts with "--", so a flag name is never a value).
 */
export function sendText(argv: readonly string[], subject: string, body: string): string {
  const parts: Array<[number, string]> = []
  for (const flag of SEND_TEXT_FLAGS) {
    const at = argv.indexOf(flag)
    if (at === -1) continue
    parts.push([at, flag === '--subject' ? subject : body])
  }
  return parts
    .sort((a, b) => a[0] - b[0])
    .map((p) => p[1])
    .join('\n')
}

export interface SendEnvelopeInput {
  /** The argv after the word `send`. */
  argv: readonly string[]
  to: string
  cc?: string
  subject: string
  /** The body text that will be sent (decoded from the hash-checked bytes for a file body). */
  body: string
  /** Name, and the digest and size of the very bytes that will be attached. */
  attachments?: EnvelopeAttachment[]
}

export function buildSendEnvelope(input: SendEnvelopeInput, ref: string = newRef('send')): SendEnvelope {
  return {
    kind: 'send',
    to: [input.to],
    cc: input.cc ? [input.cc] : [],
    bcc: [],
    text: sendText(input.argv, input.subject, input.body),
    ...(input.attachments?.length ? { attachments: input.attachments } : {}),
    ref,
  }
}

export interface ForwardEnvelopeInput {
  id: string
  to: string
  /** The REAL subject, as Graph returned it (the CLI has already checked it equals --orig-subject). */
  subject: string
  /** The comment that will be sent (decoded from the hash-checked bytes for a file comment). */
  comment: string
  /** For a file comment: its path (<outbox>/<name>) and the sha256 of the bytes that were read. */
  file?: { path: string; sha256: string }
}

export function buildForwardEnvelope(input: ForwardEnvelopeInput, ref: string = newRef('forward')): SendEnvelope {
  return {
    kind: 'forward',
    to: [input.to],
    cc: [],
    bcc: [],
    text: input.comment,
    forward: { message_id: input.id, subject: input.subject },
    comment_source: input.file ? 'file' : 'inline',
    comment_sha256: input.file ? input.file.sha256 : sha256Hex(input.comment),
    ...(input.file ? { comment_file: basename(input.file.path) } : {}),
    ref,
  }
}

// --- the helper call ------------------------------------------------------------

/** stdin JSON, ASCII only: the helper's locale cannot garble a Hungarian letter. */
function asciiJson(value: unknown): string {
  return JSON.stringify(value).replace(/[\u007f-￿]/g, (c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

const REASON_RE = /^[a-z][a-z0-9_]{0,39}$/

const strOrNull = (v: unknown): string | null => (typeof v === 'string' ? v : null)

function parseVerdict(stdout: string): HelperVerdict | null {
  const lines = stdout.split('\n').filter((l) => l.trim() !== '')
  if (lines.length !== 1) return null
  let raw: unknown
  try {
    raw = JSON.parse(lines[0])
  } catch {
    return null
  }
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null
  const o = raw as Record<string, unknown>
  if (o.decision !== 'allow' && o.decision !== 'refuse') return null
  if (typeof o.reason !== 'string' || !REASON_RE.test(o.reason)) return null
  return {
    decision: o.decision,
    reason: o.reason,
    approval_id: strOrNull(o.approval_id),
    anchor: strOrNull(o.anchor),
    standing: strOrNull(o.standing),
    detail: strOrNull(o.detail),
    note: strOrNull(o.note),
    level: typeof o.level === 'number' ? o.level : null,
  }
}

function failed(detail: string): Authorization {
  return { allowed: false, reason: 'authorizer_failed', detail, verdict: null }
}

/**
 * Ask the helper of THIS checkout (`repoRoot`/scripts/hooks, realpath) in
 * consume mode. Returns allowed only on exit 0 + a well-formed allow verdict.
 */
export function authorizeSend(
  envelope: SendEnvelope,
  repoRoot: string,
  options: AuthorizeTestOptions = {},
): Authorization {
  let helper: string
  try {
    helper = realpathSync(join(repoRoot, ...HELPER_REL))
  } catch {
    return failed('the send authorizer (scripts/hooks/email_send_authorize.py) is missing')
  }
  const request = { mode: 'consume', tool: 'graph-mail', ...envelope }
  // BE-B1 / BE2-1 (c3c32903): a root-owned, non-shim interpreter by its real path, never
  // from PATH, and an environment built from an allowlist (src/trusted-python.ts): a python3
  // shim on PATH, or a DEVELOPER_DIR for the macOS xcrun shim, would otherwise answer "allow".
  // EMAIL_APPROVAL_GATE_STORE / OUTGOING_COPY_GATE_RULES are not on the list, so they never arrive.
  const python = resolveTrustedPython()
  if (!python) return failed(NO_TRUSTED_PYTHON_MESSAGE)
  const env = trustedPythonEnv()
  const run = spawnSync(python, ['-I', helper], {
    input: asciiJson(request),
    encoding: 'utf-8',
    timeout: options.timeoutMs ?? HELPER_TIMEOUT_MS,
    killSignal: 'SIGKILL',
    maxBuffer: 1024 * 1024,
    env,
  })
  if (run.error) {
    const code = (run.error as NodeJS.ErrnoException).code
    return failed(`the send authorizer did not finish (${code ?? run.error.name})`)
  }
  if (run.signal) return failed(`the send authorizer was killed (${run.signal})`)
  if (run.status !== 0 && run.status !== 2) return failed(`the send authorizer exited with ${run.status}`)
  const verdict = parseVerdict(run.stdout ?? '')
  if (!verdict) return failed('the send authorizer printed no single JSON verdict')
  if (run.status === 0 && verdict.decision === 'allow') return { allowed: true, verdict }
  if (run.status === 2 && verdict.decision === 'refuse') {
    return { allowed: false, reason: verdict.reason, detail: verdict.detail, verdict }
  }
  return failed('the send authorizer contradicted its exit code')
}

// --- messages --------------------------------------------------------------------

/** One printable line: control characters out, length capped. */
function oneLine(text: string, max = 300): string {
  const clean = text.replace(/[\u0000-\u001f\u007f-\u009f]+/g, ' ').trim()
  return clean.length > max ? `${clean.slice(0, max)}...` : clean
}

/**
 * The stderr text of a refusal. The FIRST line is machine readable:
 * `graph-mail: REFUSED <reason>`.
 */
export function refusalText(auth: Extract<Authorization, { allowed: false }>): string {
  const lines = [`graph-mail: REFUSED ${auth.reason}`]
  if (auth.reason === 'authorizer_failed') {
    lines.push(
      'Nothing was sent. The state of the approval is UNKNOWN (the authorizer may have stopped after spending it): ' +
        'check the approval before asking for a new one.',
    )
  } else {
    lines.push('Nothing was sent, and this run spent no approval.')
  }
  if (auth.detail) lines.push(`  detail: ${oneLine(auth.detail)}`)
  const v = auth.verdict
  if (v?.note) lines.push(`  note: ${oneLine(v.note)}`)
  if (v?.anchor) {
    lines.push(
      `  anchor (content_hash of the email_send approval this letter needs): ${v.anchor}`,
      'A levelet csak egy el nem használt, időablakon belül jóváhagyott email_send jóváhagyás engedi ki, ' +
        'amelynek content_hash-e a fenti horgony; a jóváhagyást a CLI a küldés pillanatában fogyasztja. ' +
        'Állandó címzettnek az élesített állandó címzett jog elég.',
    )
  }
  return lines.join('\n')
}

/**
 * The line a failed Graph call after an allow gets. An approval is strictly
 * single-use (Brainy 3132, Q1): after a failure a retry needs a NEW approval.
 */
export function consumedNote(verdict: HelperVerdict): string {
  if (verdict.reason === 'approval') {
    return (
      'graph-mail: the approval was CONSUMED by this attempt (single use, no refund); ' +
      'a new email_send approval is needed before the letter can be sent again.'
    )
  }
  if (verdict.reason === 'standing') {
    return 'graph-mail: this attempt was authorized by a standing recipient and its send trace is already written.'
  }
  return 'graph-mail: this attempt was authorized at autonomy level 3 (no approval was spent).'
}
