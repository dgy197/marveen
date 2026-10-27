#!/usr/bin/env tsx
// Thin CLI over src/graph-mail.ts, for operating the scoped M365 mailbox by
// hand (smoke test, quick read, one-off send or forward) without writing code.
//
//   tsx scripts/graph-mail.ts verify
//   tsx scripts/graph-mail.ts list [--unread] [--top N] [--folder inbox|sentitems]
//   tsx scripts/graph-mail.ts show --id <message id>
//   tsx scripts/graph-mail.ts send --to a@b.hu[,c@d.hu] --subject "..." --body "..." [--cc ...] [--html] [--attach FILE]
//   tsx scripts/graph-mail.ts send --to a@b.hu[,c@d.hu] --subject "..." --body-file <outbox>/<name> --body-sha256 <hex> [--cc ...] [--html] [--attach FILE]
//   tsx scripts/graph-mail.ts forward --id <message id> --to <one @fireeng.hu address> --comment "..." --orig-subject "..."
//   tsx scripts/graph-mail.ts forward --id <message id> --to <one @fireeng.hu address> --comment-file <outbox>/<name> --comment-sha256 <hex> --orig-subject "..."
//
// `list` prints every message's id as the last line of its block; `show`
// prints one message (exact subject JSON-quoted, sender, time, whether it has
// attachments) and only reads.
//
// `send` takes exactly ONE body source, each flag once, as separate tokens, in
// any order (anything else -- a second --to, --bcc, --flag=value, a positional,
// a value starting with "--" -- is refused with exit 2, nothing sent):
//   (a) --body "<text>" (one line; the approval gate refuses a multi-line command), or
//   (b) --body-file <outbox>/<name> --body-sha256 <hex> (card graph-forward r3,
//       node W2): a long, multi-paragraph body from a file. The outbox root, the
//       name rule, the hash, the size/UTF-8/code point limits and the read-once
//       rule are exactly those of forward's --comment-file (see below); the
//       body sent is the text decoded from the hashed bytes, unchanged (no
//       trim). Every refusal (hash, symlink, outside the outbox, too big, BOM,
//       CR, forbidden code point, blank) is exit 2 before any network call.
//
// `forward` (card graph-forward, Brainy 2958) forwards one message with Graph's
// own forward action: Graph quotes the original and carries its attachments.
// It takes --id, --to, --orig-subject and exactly ONE comment source, each flag
// once, as separate tokens, in any order; anything else (a second --to, --cc,
// --bcc, --attach, --html, --flag=value, a positional) is refused. The
// recipient must be one plain @fireeng.hu address. The comment source is either
//   (a) --comment "<text>", or
//   (b) --comment-file <outbox>/<name> --comment-sha256 <hex> (card graph-forward,
//       Brainy 3011): a long, multi-paragraph comment from a file. <outbox> is
//       <repo>/store/mail-outbox (GRAPH_MAIL_OUTBOX_DIR overrides it, for tests
//       only); it must exist as a 0700 directory of the current user, and the
//       code never creates it. <name> is 1-128 of [A-Za-z0-9._-], no leading
//       dot, no "..", no subdirectory. <hex> is the lower-case
//       `shasum -a 256 <file>` of the file. The file must be a regular file of
//       the current user with one link, at most 16384 bytes of strict UTF-8,
//       not blank, without CR, BOM, control, zero-width or bidi characters.
//       The CLI reads it exactly once, checks the hash on the bytes it read,
//       and sends the text decoded from those bytes, unchanged (no trim). The
//       approval gate reads the same file and pins the same hash, so do not
//       touch the file between `shasum` and the forward.
// --orig-subject must be the message's subject EXACTLY (copy it from `show`):
// the approval gate pins it into the anchor, and the CLI reads the real message
// first and refuses on any difference (no trim, no normalisation). Before any
// network call the CLI also checks that this checkout's gate knows `forward`
// (see gateKnowsForward), so a CLI that can forward never runs next to a gate
// that would wave the forward through as a non-send.
//
// Send authorization (card efa58ad2): `send` and `forward` decide for themselves
// whether the letter may go out, however the command was typed (glob, quotes,
// `bash -c`, wrappers): after the token is in hand and right before the Graph
// POST, the CLI builds the envelope from the exact bytes it will send (hash-checked
// body or comment, attachment bytes, the real forward subject) and asks
// scripts/hooks/email_send_authorize.py of THIS checkout (consume mode: the SAME
// code as the PreToolUse hook; the hook only peeks on graph-mail). The letter goes
// out only if the helper exits 0 AND says "allow": an unspent, in-window, approved
// email_send approval whose content_hash equals the envelope's anchor (spent HERE,
// strictly single use), an armed standing recipient, or autonomy level 3. Any
// other outcome (no approval, pending, spent, expired, level 1, a missing or
// unreadable DB or config, a helper that crashes, hangs for 10 s or prints
// garbage) is exit 2 with the stderr first line `graph-mail: REFUSED <reason>`
// and not one Graph POST. The helper path comes from this file's checkout; no
// environment variable moves it.
//   <reason> is one of: none pending consumed expired race (the approval),
//   level1 qa_failed config_invalid unreadable standing_not_live trace_unwritable
//   db_unavailable authorizer_failed bad_request internal_error. `consumed` after
//   a failed attempt means the earlier run spent the approval: a retry needs a NEW
//   approval (strictly single use, no refund). The PreToolUse hook only peeks on
//   graph-mail commands and never spends; this file is the only consumer, so it
//   enforces the same way for `bash -c`, `env -S`, a glob path or a quoted head.
//
// Recipients (S2): `send --to` / `--cc` take ONLY a comma-separated list of bare
// addresses (a@b.hu,c@d.hu). A display name, quote, angle bracket, comment,
// semicolon, space or empty element is refused (exit 2, before authorize and the
// network); the gate and the authorizer helper apply the same rule, so the CLI
// (split on ',') and the gate (getaddresses) can never read different mailboxes.
// Local preconditions (S1: the attachment read and its 3 MB base64 limit) also run
// BEFORE the authorizer, so such a refusal spends no approval.
//
// Exit codes of `send` and `forward`:
//   0  sent / forwarded (one line: forwarded <id>... "<subject>" -> <address>)
//   1  Graph refused or failed, or the token request failed. Before the
//      authorization nothing is spent; AFTER it a line says the approval was
//      CONSUMED (no refund) and a retry needs a NEW approval.
//   2  refused locally (arguments, gate capability, comment or body file, subject
//      mismatch, send authorization); nothing went out
//   3  the forward request got no answer: the outcome is UNKNOWN. Check Sent
//      Items; do not blindly run it again (the approval is consumed).
// Nothing is ever retried automatically.
//
// --attach does NOT take an arbitrary path. The file must sit inside the
// attachment drop directory (GRAPH_MAIL_ATTACH_DIR, default
// <repo>/store/mail-attachments); anything outside it is refused. Putting a
// file there is the deliberate act that authorises sending it.
//
// Credentials come from the gitignored marveen-mail-ugyfelkod file (override
// with MARVEEN_MAIL_CREDS). Send is intentionally CLI-explicit; the sub-agent
// email-send-gate hook still applies to any programmatic use elsewhere.
//
// Verified-recipient ledger (opt-in, MAIN_AGENT_RECIPIENT_LEDGER=1 in the install
// .env): before the token request and before the authorizer, `send` and `forward`
// run the ledger half of scripts/hooks/sender_check.py on the addresses they will
// deliver to, so a refusal spends no approval. A refusal is exit 2 with the reason
// on stderr. Off (the default): no check, as before. The level, the standing list,
// the copy audit and the approval itself are the authorizer's job (above), NOT
// sender_check.py's: that one would spend the approval a second time.

import {
  ForwardOutcomeUnknownError,
  GraphRequestError,
  assertAttachmentsWithinLimit,
  ensureToken,
  forwardMail,
  getMessage,
  listMessages,
  sendMail,
  verifyAccess,
} from '../src/graph-mail.js'
import { parseForwardArgv, parseSendArgv, parseShowArgv, quoteForDisplay } from '../src/graph-forward-validate.js'
import { readForwardCommentFile, readSendBodyFile, resolveOutboxRoot } from '../src/graph-forward-comment-file.js'
import {
  authorizeSend,
  buildForwardEnvelope,
  buildSendEnvelope,
  consumedNote,
  refusalText,
} from '../src/graph-send-authorize.js'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync, realpathSync, statSync } from 'node:fs'
import { basename, dirname, join, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))

const USAGE = [
  'usage: graph-mail.ts <verify|list|show|send|forward> [options] (see file header)',
  '  list    [--unread] [--top N] [--folder inbox|sentitems]',
  '  show    --id <message id>',
  '  send    --to a@b.hu[,c@d.hu] --subject "..." --body "..." [--cc ...] [--html] [--attach FILE]',
  '  send    --to a@b.hu[,c@d.hu] --subject "..." --body-file <outbox>/<name> --body-sha256 <hex> [--cc ...] [--html] [--attach FILE]',
  '          (<outbox> = <repo>/store/mail-outbox, <hex> = shasum -a 256; exactly one of --body / --body-file)',
  '  forward --id <message id> --to <one @fireeng.hu address> --comment "..." --orig-subject "<exact subject>"',
  '  forward --id <message id> --to <one @fireeng.hu address> --comment-file <outbox>/<name> --comment-sha256 <hex>',
  '          --orig-subject "<exact subject>"   (<outbox> = <repo>/store/mail-outbox, <hex> = shasum -a 256)',
].join('\n')

/**
 * Resolve --attach against the attachment drop directory and refuse anything
 * outside it. Symlinks are resolved first (realpath on both sides), so a link
 * planted inside the directory cannot reach out of it, and the separator on
 * the prefix check keeps a sibling like `<dir>-evil` from matching.
 */
function readAttachment(rawPath: string): { name: string; contentBytes: string; sha256: string; size: number } {
  const dir = realpathSync(
    resolve(process.env.GRAPH_MAIL_ATTACH_DIR ?? resolve(REPO_ROOT, 'store/mail-attachments')),
  )
  let file: string
  try {
    file = realpathSync(resolve(dir, rawPath))
  } catch {
    throw new Error(`graph-mail: attachment not found: ${rawPath}`)
  }
  if (file !== dir && !file.startsWith(dir + sep)) {
    throw new Error(
      `graph-mail: refusing to attach a file outside the drop directory.\n` +
        `  requested: ${file}\n  allowed:   ${dir}\n` +
        'Copy the file into the drop directory (or set GRAPH_MAIL_ATTACH_DIR) and retry.',
    )
  }
  if (!statSync(file).isFile()) {
    throw new Error(`graph-mail: attachment is not a regular file: ${file}`)
  }
  // One read: the digest, the size and the base64 all come from the same bytes.
  const bytes = readFileSync(file)
  return {
    name: basename(file),
    contentBytes: bytes.toString('base64'),
    sha256: createHash('sha256').update(bytes).digest('hex'),
    size: bytes.length,
  }
}

// The FIRST `--name value` or `--name=value`. The `=` form used to be ignored,
// while the main agent's hook reads it: `--cc=x@example.com` was anchored there and
// silently dropped here.
function flag(name: string): string | undefined {
  const args = process.argv.slice(2)
  for (let i = 0; i < args.length; i++) {
    if (args[i] === `--${name}`) return args[i + 1]
    if (args[i].startsWith(`--${name}=`)) return args[i].slice(name.length + 3)
  }
  return undefined
}
function has(name: string): boolean {
  return process.argv.includes(`--${name}`)
}

// The interpreters the ledger check may run under, by ABSOLUTE path (the
// Linux system python first, then the two macOS Homebrew prefixes), never
// resolved from PATH, and in isolated mode (-I) with every PYTHON* variable
// stripped: otherwise a `PATH=/x` or `PYTHONPATH=/x` prefix in front of the
// send could swap in a "check" that always passes.
const TRUSTED_PYTHONS = ['/usr/bin/python3', '/opt/homebrew/bin/python3', '/usr/local/bin/python3']
function trustedPython(): string | null {
  for (const p of TRUSTED_PYTHONS) {
    try {
      if (statSync(p).isFile()) return p
    } catch { /* not there, try the next one */ }
  }
  return null
}
function envWithoutPython(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {}
  for (const [k, v] of Object.entries(process.env)) {
    if (!k.toUpperCase().startsWith('PYTHON')) env[k] = v
  }
  return env
}

// The ledger half of scripts/hooks/sender_check.py, and nothing else: the level, the
// standing list, the copy audit and the one-shot approval belong to the authorizer
// (src/graph-send-authorize.ts), and sender_check.check() would spend the approval a
// second time. The program text is a fixed constant; the letter travels on stdin.
const LEDGER_PY = `
import importlib.util, json, os, sys
try:
    spec = importlib.util.spec_from_file_location("sender_check", os.path.join(sys.argv[1], "sender_check.py"))
    sc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sc)
    letter = json.loads(sys.stdin.read())
    gate = sc._gate()
    if gate.ledger_enabled():
        sc._ledger_check(gate, letter)
except SystemExit:
    raise
except BaseException as exc:
    msg = str(exc) if type(exc).__name__ == "Refused" else "a ledger-ellenorzes hibaval allt le (%r); fail-closed" % (exc,)
    print(msg, file=sys.stderr)
    sys.exit(3)
`

/** The verified-recipient ledger (opt-in) on the addresses about to be delivered; exit 2 on a refusal. */
function ledgerCheckOrExit(kind: string, letter: Record<string, unknown>): void {
  const python = trustedPython()
  if (!python) {
    console.error(`${kind}: REFUSED -- no trusted python3 for the recipient-ledger check ` +
      `(looked for: ${TRUSTED_PYTHONS.join(', ')}); PATH is not searched, fail-closed. Nothing was sent.`)
    process.exit(2)
  }
  // The authorizer (src/graph-send-authorize.ts) and the gate probe start a bare
  // `python3`, resolved through PATH: a `PATH=/x` prefix in front of the send must not
  // choose it. Pin PATH to the trusted interpreter's directory and the system ones.
  process.env.PATH = [dirname(python), '/usr/bin', '/bin'].join(':')
  const r = spawnSync(python, ['-I', '-c', LEDGER_PY, resolve(REPO_ROOT, 'scripts', 'hooks')],
    { input: JSON.stringify(letter), encoding: 'utf-8', timeout: 30_000, env: envWithoutPython() })
  if (r.status !== 0) {
    const said = (r.stderr || '').trim()
    console.error(`${kind}: REFUSED -- ${said || (r.error ? String(r.error) : `exit ${r.status}`)}. Nothing was sent.`)
    process.exit(2)
  }
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : String(err)
}

// --- Daily-log entry after a successful send or forward (card f90928e3, part B) --
// One line in agent brainy's daily log: who got a letter, about what, when.
// Never the body, the comment, the cc/bcc list, or an attachment (or its name):
// the approval payload is erased on purpose when it is consumed, and this entry
// must not bring that content back. It is strictly best-effort and runs only
// AFTER the POST returned and "sent to" / "forwarded" was printed: it sits
// behind authorizeSend and cannot call it, refuse, delay beyond its short
// timeout, or change the exit code or stdout of the send (AC16, AC18).
const DAILY_LOG_AGENT = 'brainy'
const DAILY_LOG_TIMEOUT_MS = 3000
const SUBJECT_MAX = 80

function truncateSubject(subject: string): string {
  const chars = Array.from(subject.replace(/\s+/g, ' ').trim())
  return chars.length <= SUBJECT_MAX ? chars.join('') : chars.slice(0, SUBJECT_MAX - 1).join('') + '…'
}

/** Install-zone time (SCHEDULER_TZ if pinned, else the host zone), "YYYY-MM-DD HH:MM". */
function budapestNow(now: Date = new Date()): string {
  const fmt = (timeZone?: string) => new Intl.DateTimeFormat('sv-SE', {
    timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hourCycle: 'h23',
  }).format(now).replace(',', '')
  try {
    return fmt(installSetting('SCHEDULER_TZ', '') || undefined)
  } catch { return fmt() } // an invalid pinned zone: the host zone
}

// Env first, then the install .env next to this script's checkout (the same
// order the hooks use), never an install-specific hardcode.
function installSetting(key: string, fallback: string): string {
  const fromEnv = process.env[key]?.trim()
  if (fromEnv) return fromEnv
  try {
    for (const line of readFileSync(resolve(REPO_ROOT, '.env'), 'utf-8').split('\n')) {
      if (line.startsWith(`${key}=`)) {
        const v = line.slice(key.length + 1).trim().replace(/^["']|["']$/g, '')
        if (v) return v
      }
    }
  } catch { /* no .env: the default stands */ }
  return fallback
}

function sentEntry(to: string[], subject: string): string {
  return `[Levél elküldve] ${to.join(', ')}, tárgy: ${truncateSubject(subject)}, ${budapestNow()}`
}

/** An error whose message WE wrote: the only exception text that may reach stderr. */
class DailyLogError extends Error {}

// The dashboard token is 64 hex chars when generated (src/web/dashboard-auth.ts);
// DASHBOARD_TOKEN may be any operator string, so allow the usual token alphabet
// and nothing that could break out of a header (CR, LF, NUL, spaces, non-ASCII).
const DASHBOARD_TOKEN_RE = /^[A-Za-z0-9._~+/=-]+$/
// The live CDP browser and its sibling: never a dashboard, never touched
// (same list as scripts/hooks/email-draft-log.py).
const FORBIDDEN_PORTS = new Set([18800, 18899])

/** The only text that may describe a failure: our own message, or the bare type name. */
function describeDailyLogFailure(err: unknown): string {
  if (err instanceof DailyLogError) return err.message
  const name = err instanceof Error ? (err.name || '') : ''
  if (name === 'TimeoutError' || name === 'AbortError') return 'timeout'
  const type = err instanceof Error ? (Object.getPrototypeOf(err)?.constructor?.name ?? '') : ''
  return /^[A-Za-z][A-Za-z0-9_]{0,39}$/.test(type) ? type : 'Error'
}

/** Never throws and never exits; any failure is one line on stderr that never
 * carries foreign exception text (a header-validation error can echo the token). */
async function postSentEntry(to: string[], subject: string): Promise<void> {
  try {
    let token: string
    try {
      token = readFileSync(resolve(REPO_ROOT, 'store', '.dashboard-token'), 'utf-8').trim()
    } catch {
      throw new DailyLogError('cannot read dashboard token file')
    }
    if (!token) throw new DailyLogError('empty dashboard token')
    if (!DASHBOARD_TOKEN_RE.test(token)) throw new DailyLogError('invalid dashboard token format')
    const port = Number(installSetting('WEB_PORT', '3420'))
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new DailyLogError('bad WEB_PORT')
    if (FORBIDDEN_PORTS.has(port)) throw new DailyLogError(`refused WEB_PORT ${port}`)
    const res = await fetch(`http://127.0.0.1:${port}/api/daily-log`, {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ agent_id: DAILY_LOG_AGENT, content: sentEntry(to, subject) }),
      signal: AbortSignal.timeout(DAILY_LOG_TIMEOUT_MS),
    })
    if (!res.ok) throw new DailyLogError(`HTTP ${res.status}`)
  } catch (err) {
    console.error(`graph-mail: a levél elment, de a napló-bejegyzés nem készült el (${describeDailyLogFailure(err)})`)
  }
}

// --- gate capability (spec E6) ------------------------------------------------
//
// Version-skew protection, not a defence against an adversary: if this CLI can
// forward but the checkout's gates predate the forward (a partial apply or
// revert, a hand `git checkout scripts/hooks`), the gates would classify the
// forward as a non-send and let it through unchecked. So before any network
// call the CLI asks the gates of ITS OWN checkout. Every path below comes from
// REPO_ROOT, i.e. from where this file lives; no environment variable can
// point the check at another tree. The interpreter is `python3 -I` (isolated:
// no PYTHONPATH, no user site, no cwd on sys.path), the same `python3` the
// hooks in .claude/settings.json are started with.

// A fixed, canonical forward command. The caller's own values never reach the
// probe: no third-party subject in a Python argv, no shell quoting to get wrong.
const PROBE_ID = 'AAMkAGdhdGVwcm9iZTAwMDE='
const PROBE_SUBJECT = 'Kapupróba'
const PROBE_COMMAND =
  `npx tsx scripts/graph-mail.ts forward --id ${PROBE_ID} --to kovacs@fireeng.hu ` +
  `--comment 'Szia! Kérlek, nézd meg.' --orig-subject '${PROBE_SUBJECT}'`

// Loads the two hook modules by file path and asks them about PROBE_COMMAND:
// the copy gate's classifier must call it a send, and the shared extractor
// must produce the `forward` field with the probe's id and subject. It also
// reports whether the extractor declares the --comment-file reader
// (spec-delta KE2: FORWARD_COMMENT_FILE, an int equal to 1; True is not).
const PROBE_PY = `
import importlib.util, json, os, sys
hooks, cmd, mid, subj = sys.argv[1:5]
def load(name, fname):
    spec = importlib.util.spec_from_file_location(name, os.path.join(hooks, fname))
    if spec is None or spec.loader is None:
        raise ImportError(fname)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod
out = {"is_send": False, "forward": False, "comment_file": False}
try:
    gate = load("graph_forward_probe_copy_gate", "outgoing-copy-gate.py")
    out["is_send"] = bool(gate.is_send_invocation(cmd))
    ext = load("graph_forward_probe_email_extract", "email_extract.py")
    env = ext.collect_email_envelope("Bash", {"command": cmd})
    fwd = env.get("forward") if isinstance(env, dict) else None
    out["forward"] = isinstance(fwd, dict) and fwd.get("message_id") == mid and fwd.get("subject") == subj
    flag = vars(ext).get("FORWARD_COMMENT_FILE")
    out["comment_file"] = type(flag) is int and flag == 1
except Exception as exc:
    out["error"] = type(exc).__name__
print(json.dumps(out))
`

/** Does a PreToolUse matcher select the Bash tool? Omitted, empty and `*` select every tool. */
function matcherSelectsBash(matcher: unknown): boolean {
  if (matcher === undefined || matcher === '' || matcher === '*') return true
  if (typeof matcher !== 'string') return false
  try {
    return new RegExp(`^(?:${matcher})$`).test('Bash')
  } catch {
    return false
  }
}

/** null when both gates are wired on Bash in the checkout's .claude/settings.json, else the reason. */
function settingsBindingProblem(settingsPath: string): string | null {
  let settings: unknown
  try {
    settings = JSON.parse(readFileSync(settingsPath, 'utf-8'))
  } catch {
    return '.claude/settings.json is missing or unreadable'
  }
  const pre = (settings as { hooks?: { PreToolUse?: unknown } } | null)?.hooks?.PreToolUse
  const bound = { approval: false, copy: false }
  for (const entry of Array.isArray(pre) ? pre : []) {
    if (!entry || typeof entry !== 'object' || !matcherSelectsBash((entry as { matcher?: unknown }).matcher)) continue
    const hooks = (entry as { hooks?: unknown }).hooks
    for (const hook of Array.isArray(hooks) ? hooks : []) {
      const command = (hook as { type?: unknown; command?: unknown } | null)?.command
      if ((hook as { type?: unknown }).type !== 'command' || typeof command !== 'string') continue
      if (command.includes('/scripts/hooks/email-approval-gate.py')) bound.approval = true
      if (command.includes('/scripts/hooks/outgoing-copy-gate.py')) bound.copy = true
    }
  }
  if (!bound.approval) return 'email-approval-gate.py is not wired on Bash in .claude/settings.json'
  if (!bound.copy) return 'outgoing-copy-gate.py is not wired on Bash in .claude/settings.json'
  return null
}

type GateCheck = { ok: true } | { ok: false; reason: string; commentFile?: true }

/**
 * Spec E6 (+ spec-delta KE2): does this checkout's gate know the forward, and,
 * when `commentFile` is asked for, the --comment-file form too? A gate that
 * knows the forward but not the file form would find no comment text in a
 * file-form command; that fails closed in the gate, but the CLI says so
 * itself, before any network call.
 */
function gateKnowsForward(repoRoot: string, opts: { commentFile: boolean }): GateCheck {
  const binding = settingsBindingProblem(join(repoRoot, '.claude', 'settings.json'))
  if (binding) return { ok: false, reason: binding }
  const run = spawnSync(
    'python3',
    ['-I', '-c', PROBE_PY, join(repoRoot, 'scripts', 'hooks'), PROBE_COMMAND, PROBE_ID, PROBE_SUBJECT],
    {
      encoding: 'utf-8',
      timeout: 15_000,
      // The copy gate loads its local name-rules file at import time and logs
      // when that file is absent. Not needed for classification, so point it
      // at a path that cannot exist: no read of the rules, no log line.
      env: { ...process.env, OUTGOING_COPY_GATE_RULES: '/dev/null/graph-mail-gate-probe' },
    },
  )
  if (run.error || run.status !== 0) return { ok: false, reason: 'the gate probe did not run (python3 -I)' }
  let out: { is_send?: unknown; forward?: unknown; comment_file?: unknown; error?: unknown }
  try {
    out = JSON.parse(run.stdout.trim().split('\n').pop() ?? '')
  } catch {
    return { ok: false, reason: 'the gate probe gave no verdict' }
  }
  if (typeof out.error === 'string') return { ok: false, reason: `the gate probe failed (${out.error})` }
  if (out.is_send !== true) return { ok: false, reason: 'outgoing-copy-gate.py does not classify forward as a send' }
  if (out.forward !== true) return { ok: false, reason: 'email_extract.py does not build the forward field' }
  if (opts.commentFile && out.comment_file !== true) {
    return { ok: false, commentFile: true, reason: 'email_extract.py does not export FORWARD_COMMENT_FILE = 1' }
  }
  return { ok: true }
}

// --- subcommands ----------------------------------------------------------------

async function show(argv: string[]): Promise<number> {
  const parsed = parseShowArgv(argv)
  if (!parsed.ok) {
    console.error(`show: ${parsed.error}\n${USAGE}`)
    return 2
  }
  const m = await getMessage(parsed.value.id, ['id', 'subject', 'from', 'receivedDateTime', 'hasAttachments'])
  const subject = typeof m.subject === 'string' ? quoteForDisplay(m.subject) : 'null'
  const name = m.from?.emailAddress?.name
  const address = m.from?.emailAddress?.address
  const from = [
    typeof name === 'string' ? quoteForDisplay(name) : '',
    typeof address === 'string' ? `<${quoteForDisplay(address)}>` : '<?>',
  ]
    .filter(Boolean)
    .join(' ')
  const attachments = m.hasAttachments === true ? 'yes' : m.hasAttachments === false ? 'no' : 'unknown'
  console.log(
    `id: ${parsed.value.id}\nsubject: ${subject}\nfrom: ${from}\n` +
      `received: ${m.receivedDateTime ?? '?'}\nattachments: ${attachments}`,
  )
  return 0
}

// Spec-delta KE1, the order of a forward: argv (KA) -> gate capability (E6,
// KE2 for the file form) -> the comment file, read once and checked (KB) ->
// GET and the subject check (E3) -> POST with the text held in memory. Every
// refusal before the GET is exit 2 without a single network call.
async function forward(argv: string[]): Promise<number> {
  const outboxRoot = resolveOutboxRoot(REPO_ROOT)
  const parsed = parseForwardArgv(argv, { outboxRoot })
  if (!parsed.ok) {
    console.error(`forward: ${parsed.error}. Nothing was sent.\n${USAGE}`)
    return 2
  }
  const args = parsed.value
  const fileForm = 'commentFile' in args
  const gate = gateKnowsForward(REPO_ROOT, { commentFile: fileForm })
  if (!gate.ok) {
    const what = gate.commentFile ? 'a --comment-file-t' : 'a forwardot'
    console.error(`forward: a kapu nem ismeri ${what} (${gate.reason}). Nothing was sent.`)
    return 2
  }
  let comment: string
  let commentFile: { path: string; sha256: string } | undefined
  if (fileForm) {
    // The one and only read of the file. From here on only `comment` (decoded
    // from the hashed bytes) is used; the path is never opened again.
    try {
      const read = readForwardCommentFile(args.commentFile, args.commentSha256, outboxRoot)
      comment = read.text
      commentFile = { path: args.commentFile, sha256: read.sha256 }
    } catch (err) {
      console.error(`forward: --comment-file refused: ${errorText(err)}. Nothing was sent.`)
      return 2
    }
  } else {
    comment = args.comment
  }
  const { id, to, origSubject } = args
  let actual: string | null
  try {
    const m = await getMessage(id)
    actual = typeof m.subject === 'string' ? m.subject : null
  } catch (err) {
    console.error(`forward: ${errorText(err)}. Nothing was sent.`)
    return 1
  }
  // Exact string equality, on purpose: the approval gate anchored the subject
  // as typed, so anything looser would forward a letter nobody approved.
  if (actual !== origSubject) {
    console.error(
      'forward: --orig-subject does not match the message subject. Nothing was sent.\n' +
        `  actual subject: ${actual === null ? 'null' : quoteForDisplay(actual)}`,
    )
    return 2
  }
  // Opt-in verified-recipient ledger, before anything is spent (see LEDGER_PY).
  ledgerCheckOrExit('forward', { to: [to], cc: [], raw_to: to, raw_cc: null })
  // The token comes BEFORE the authorizer: a credential or token failure must not
  // spend an approval. The envelope carries the real subject (== --orig-subject
  // here) and the comment exactly as it will be sent.
  try {
    await ensureToken()
  } catch (err) {
    console.error(`forward: ${errorText(err)}. Nothing was sent.`)
    return 1
  }
  const auth = authorizeSend(buildForwardEnvelope({ id, to, subject: actual, comment, file: commentFile }), REPO_ROOT)
  if (!auth.allowed) {
    console.error(refusalText(auth))
    return 2
  }
  try {
    await forwardMail({ id, to, comment })
  } catch (err) {
    if (err instanceof ForwardOutcomeUnknownError) {
      console.error(`forward: kimenet ismeretlen: nézd meg az Elküldött elemeket, ne küldd újra vakon (${err.message})`)
      console.error(consumedNote(auth.verdict))
      return 3
    }
    const unsure =
      err instanceof GraphRequestError && err.status >= 500
        ? ' Graph answered with a server error: check Sent Items before anything else, do not blindly run it again.'
        : ''
    console.error(`forward: ${errorText(err)}.${unsure}`)
    console.error(consumedNote(auth.verdict))
    return 1
  }
  console.log(`forwarded ${id.slice(0, 16)}... ${quoteForDisplay(origSubject)} -> ${to}`)
  await postSentEntry([to], origSubject) // best-effort, after the forward (card f90928e3)
  return 0
}

// Card graph-forward r3, node W2, the order of a send: argv (exactly one body
// source) -> the body file, read once and checked against --body-sha256 ->
// the attachment -> the envelope -> the token -> the send authorizer (card
// efa58ad2) -> POST. Every refusal before the POST is exit 2 without a
// single network call. A file body is sent as the text decoded from the very
// bytes that were hashed; the path is never opened again.
async function send(argv: string[]): Promise<number> {
  const outboxRoot = resolveOutboxRoot(REPO_ROOT)
  const parsed = parseSendArgv(argv, { outboxRoot })
  if (!parsed.ok) {
    console.error(`send: ${parsed.error}. Nothing was sent.\n${USAGE}`)
    return 2
  }
  const args = parsed.value
  let body: string
  if ('bodyFile' in args) {
    try {
      body = readSendBodyFile(args.bodyFile, args.bodySha256, outboxRoot).text
    } catch (err) {
      console.error(`send: --body-file refused: ${errorText(err)}. Nothing was sent.`)
      return 2
    }
  } else {
    body = args.body
  }
  // Card efa58ad2 (S1): every local, network-free precondition (the attachment
  // read, its size limit) runs BEFORE the authorizer, so a refusal here spends
  // no approval.
  let attachment: ReturnType<typeof readAttachment> | undefined
  if (args.attach) {
    try {
      attachment = readAttachment(args.attach)
      assertAttachmentsWithinLimit([attachment])
    } catch (err) {
      console.error(`send: --attach refused: ${errorText(err)}. Nothing was sent, and this run spent no approval.`)
      return 2
    }
  }
  const envelope = buildSendEnvelope({
    argv,
    to: args.to,
    cc: args.cc,
    subject: args.subject,
    body,
    attachments: attachment ? [{ name: attachment.name, sha256: attachment.sha256, size: attachment.size }] : undefined,
  })
  // Opt-in verified-recipient ledger, before anything is spent (see LEDGER_PY).
  ledgerCheckOrExit('send', {
    to: args.to.split(','),
    cc: args.cc ? args.cc.split(',') : [],
    raw_to: args.to,
    raw_cc: args.cc ?? null,
  })
  // Card efa58ad2: token first (a token failure spends nothing), then the
  // authorizer, then the POST.
  try {
    await ensureToken()
  } catch (err) {
    console.error(`send: ${errorText(err)}. Nothing was sent.`)
    return 1
  }
  const auth = authorizeSend(envelope, REPO_ROOT)
  if (!auth.allowed) {
    console.error(refusalText(auth))
    return 2
  }
  try {
    await sendMail({
      attachments: attachment ? [{ name: attachment.name, contentBytes: attachment.contentBytes }] : undefined,
      to: args.to.split(','),
      subject: args.subject,
      body,
      cc: args.cc?.split(','),
      contentType: args.html ? 'HTML' : 'Text',
    })
  } catch (err) {
    // An HTTP answer is a definite failure; anything else (no answer) may have gone out.
    const unsure = errorText(err).startsWith('graph-mail: sendMail failed (')
      ? ''
      : ' The request got no clear answer: check Sent Items before anything else.'
    console.error(`send: ${errorText(err)}.${unsure}`)
    console.error(consumedNote(auth.verdict))
    return 1
  }
  console.log(`sent to ${args.to}`)
  await postSentEntry(args.to.split(','), args.subject) // best-effort, after the send (card f90928e3)
  return 0
}

async function main(): Promise<number> {
  const cmd = process.argv[2]
  switch (cmd) {
    case 'verify': {
      const r = await verifyAccess()
      console.log(`OK -- reachable mailbox: ${r.mailbox}`)
      return 0
    }
    case 'list': {
      const msgs = await listMessages({
        top: flag('top') ? Number(flag('top')) : undefined,
        folder: flag('folder'),
        unreadOnly: has('unread'),
      })
      if (msgs.length === 0) {
        console.log('(no messages)')
        return 0
      }
      for (const m of msgs) {
        const from = m.from?.emailAddress?.address ?? '?'
        const when = m.receivedDateTime ?? ''
        const unread = m.isRead === false ? '● ' : '  '
        // The id is the NEW last line of the block; the lines above it keep
        // their place (the levelvalasz-vazlat skill reads them with grep -A).
        console.log(
          `${unread}${when}  ${from}\n    ${m.subject ?? '(no subject)'}\n    ${m.bodyPreview ?? ''}\n    id: ${m.id}\n`,
        )
      }
      return 0
    }
    case 'show':
      return show(process.argv.slice(3))
    case 'send':
      return send(process.argv.slice(3))
    case 'forward':
      return forward(process.argv.slice(3))
    default:
      console.error(USAGE)
      return 2
  }
}

// exitCode, not process.exit(): a clean return lets the logger flush its last
// line (the send and forward paths log after the request).
main().then(
  (code) => {
    process.exitCode = code
  },
  (err) => {
    console.error(errorText(err))
    process.exit(1)
  },
)
