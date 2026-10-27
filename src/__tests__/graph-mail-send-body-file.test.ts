import { describe, it, expect } from 'vitest'
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isOutboxCommentPath, parseSendArgv } from '../graph-forward-validate.js'
import { makeCliRoot } from './graph-cli-root.js'
import {
  ForwardCommentFileError,
  OUTBOX_ENV,
  readForwardCommentFile,
  readSendBodyFile,
} from '../graph-forward-comment-file.js'

// graph-mail `send --body-file <root>/<name> --body-sha256 <hex>` (card
// graph-forward r3, node W2). The reader is the one of forward's
// --comment-file, so the shared vectors in scripts/hooks/graph-forward-cases.json
// (comment_file_paths, comment_file_contents, comment_file_kinds) must give the
// same verdicts for a body file. Layers:
//   - in-process: parseSendArgv (exactly one body source) and readSendBodyFile;
//   - the real CLI as a subprocess (tsx) with a preloaded fetch stub, a fake
//     credentials file and a throwaway outbox root: every refusal is exit 2
//     with NOT A SINGLE fetch call (not even the token), a good run posts the
//     file text exactly.
// No real credentials file, no Vault, no network.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const CLI = join(REPO, 'scripts', 'graph-mail.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const GRAPH = 'https://graph.microsoft.com/v1.0'
const FIFO_TIMEOUT_MS = 5000

interface PathCase {
  name: string
  path: string
  expect: 'ok' | 'deny'
}
interface ContentCase {
  name: string
  expect: 'ok' | 'deny'
  rule: string
  text?: string
  bytes_hex?: string
  prefix_text?: string
  total_bytes?: number
  byte_len: number
  sha256: string
}
interface KindCase {
  name: string
  kind: string
  expect: 'ok' | 'deny'
}
interface Cases {
  comment_file_paths: PathCase[]
  comment_file_contents: ContentCase[]
  comment_file_kinds: KindCase[]
}
const CASES = JSON.parse(readFileSync(join(REPO, 'scripts', 'hooks', 'graph-forward-cases.json'), 'utf-8')) as Cases

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')
const sub = (s: string, root: string): string => s.split('{ROOT}').join(root)

function contentBytes(c: ContentCase): Buffer {
  if (c.text !== undefined) return Buffer.from(c.text, 'utf-8')
  if (c.bytes_hex !== undefined) return Buffer.from(c.bytes_hex, 'hex')
  if (c.prefix_text !== undefined && c.total_bytes !== undefined) {
    const prefix = Buffer.from(c.prefix_text, 'utf-8')
    return Buffer.concat([prefix, Buffer.alloc(c.total_bytes - prefix.length, 'a')])
  }
  throw new Error(`content vector ${c.name} has no content`)
}

const FAKE_SECRET = `FAKE-sb-client-secret-${'k3m7'.repeat(4)}`
const FAKE_TOKEN = `FAKE-sb-access-token-${'p5v9'.repeat(4)}`
const MAILBOX = 'sb-test-box@example.invalid'
const MAILBOX_ENC = encodeURIComponent(MAILBOX)

const TO = 'ugyfel@example.invalid'
const SUBJECT = 'Ajánlat: Minta utca 1.'
const BODY_TEXT = 'Tisztelt Ügyfelünk!\n\nCsatoltan küldjük az ajánlatot.\n\tÜdvözlettel,\n\tBrainy\n'
const BODY_SHA = sha(BODY_TEXT)
const SZIA = 'Szia!'
const SZIA_SHA = sha(SZIA)

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'sb-w2-test-')))
// card efa58ad2: the CLI runs from a throwaway root with an allow-stub send authorizer.
const ROOT = makeCliRoot(REPO, BASE)
const CREDS = join(BASE, 'fake-mail-creds')
writeFileSync(
  CREDS,
  [
    'TENANT_ID=00000000-0000-4000-8000-000000000001',
    'CLIENT_ID=00000000-0000-4000-8000-000000000002',
    `CLIENT_SECRET=${FAKE_SECRET}`,
    `MAILBOX=${MAILBOX}`,
  ].join('\n'),
  { mode: 0o600 },
)

/** A fresh outbox root: a real 0700 directory of ours, canonical path. */
function newRoot(): string {
  const root = realpathSync(mkdtempSync(join(BASE, 'ob-')))
  chmodSync(root, 0o700)
  return root
}
function put(root: string, name: string, content: Buffer | string): string {
  const p = join(root, name)
  writeFileSync(p, content, { mode: 0o600 })
  return p
}

function refusal(fn: () => unknown): string | null {
  try {
    fn()
    return null
  } catch (err) {
    expect(err).toBeInstanceOf(ForwardCommentFileError)
    return (err as Error).message
  }
}

const DENY_REASON: Record<string, RegExp> = {
  KB4: /is larger than 16384 bytes/,
  KB6: /is not valid UTF-8/,
  KB7: /contains the forbidden character U\+[0-9A-F]{4} at position \d+/,
  KB8: /is blank/,
}

function setupKind(kind: string): { root: string; path: string } {
  const root = newRoot()
  const path = join(root, 'a.txt')
  switch (kind) {
    case 'regular':
      put(root, 'a.txt', SZIA)
      return { root, path }
    case 'symlink_inside':
      put(root, 'real.txt', SZIA)
      symlinkSync(join(root, 'real.txt'), path)
      return { root, path }
    case 'symlink_outside': {
      const outside = put(newRoot(), 'outside.txt', SZIA)
      symlinkSync(outside, path)
      return { root, path }
    }
    case 'hardlink':
      put(root, 'a.txt', SZIA)
      linkSync(path, join(root, 'b.txt'))
      return { root, path }
    case 'directory':
      mkdirSync(path)
      return { root, path }
    case 'fifo': {
      const mk = spawnSync('mkfifo', [path], { encoding: 'utf-8', timeout: FIFO_TIMEOUT_MS })
      if (mk.status !== 0) throw new Error(`mkfifo failed: ${mk.stderr}`)
      return { root, path }
    }
    case 'root_symlink': {
      put(root, 'a.txt', SZIA)
      const link = join(BASE, `rootlink-${Math.random().toString(36).slice(2)}`)
      symlinkSync(root, link)
      return { root: link, path: join(link, 'a.txt') }
    }
    case 'root_mode_0775':
      put(root, 'a.txt', SZIA)
      chmodSync(root, 0o775)
      return { root, path }
    case 'root_missing': {
      const missing = join(root, 'not-there')
      return { root: missing, path: join(missing, 'a.txt') }
    }
    case 'root_under_symlink_parent': {
      const inner = join(root, 'outbox')
      mkdirSync(inner, { mode: 0o700 })
      put(inner, 'a.txt', SZIA)
      const parentLink = join(BASE, `parentlink-${Math.random().toString(36).slice(2)}`)
      symlinkSync(root, parentLink)
      const viaLink = join(parentLink, 'outbox')
      return { root: viaLink, path: join(viaLink, 'a.txt') }
    }
    default:
      throw new Error(`comment_file_kinds: unknown kind ${kind}; implement its setup in this test`)
  }
}

const KIND_REASON: Record<string, RegExp> = {
  symlink_inside: /the body file .*\/a\.txt is a symlink/,
  symlink_outside: /the body file .*\/a\.txt is a symlink/,
  hardlink: /has 2 hard links; it must have exactly 1/,
  directory: /is a directory/,
  fifo: /is a FIFO/,
  root_symlink: /the outbox root .* is a symlink/,
  root_mode_0775: /is group- or world-writable \(mode 775\); it must be 0700/,
  root_missing: /a kimenő-mappa hiányzik \(.*\); egyszer létre kell hozni 0700-as joggal/,
  root_under_symlink_parent: /is not a canonical path \(a parent is a symlink\)/,
}

// ---------------------------------------------------------------------------
// parseSendArgv: exactly one body source
// ---------------------------------------------------------------------------

describe('parseSendArgv (exactly one body source)', () => {
  const ROOT = '/private/tmp/sb-w2-pure/store/mail-outbox'
  const FILE = `${ROOT}/mail.txt`
  const base = ['--to', TO, '--subject', SUBJECT]
  const parse = (argv: string[], root: string | undefined = ROOT) => parseSendArgv(argv, { outboxRoot: root })
  const err = (argv: string[], root: string | undefined = ROOT): string => {
    const r = parse(argv, root)
    return r.ok ? '' : r.error
  }

  it('accepts the inline form, in any flag order, with --cc, --attach and --html', () => {
    expect(parse([...base, '--body', 'Szia!'])).toEqual({
      ok: true,
      value: { to: TO, subject: SUBJECT, html: false, body: 'Szia!' },
    })
    expect(parse(['--html', '--body', 'x', '--cc', 'c@example.invalid', '--subject', SUBJECT, '--attach', '/a/b.pdf', '--to', TO])).toEqual({
      ok: true,
      value: { to: TO, subject: SUBJECT, html: true, body: 'x', cc: 'c@example.invalid', attach: '/a/b.pdf' },
    })
  })

  it('accepts the file form (--body-file + --body-sha256) and gives back the path and the hash, no body', () => {
    const r = parse([...base, '--body-file', FILE, '--body-sha256', BODY_SHA])
    expect(r).toEqual({
      ok: true,
      value: { to: TO, subject: SUBJECT, html: false, bodyFile: FILE, bodySha256: BODY_SHA },
    })
    if (r.ok) expect('body' in r.value).toBe(false)
  })

  it('refuses both sources', () => {
    expect(err([...base, '--body', 'x', '--body-file', FILE, '--body-sha256', BODY_SHA])).toMatch(/exactly one body source/)
    expect(err([...base, '--body', 'x', '--body-file', FILE])).toMatch(/exactly one body source/)
    expect(err([...base, '--body', 'x', '--body-sha256', BODY_SHA])).toMatch(/exactly one body source/)
  })

  it('refuses neither source', () => {
    expect(err(base)).toMatch(/missing the body/)
    expect(err([...base, '--html'])).toMatch(/missing the body/)
  })

  it('refuses half of the file pair', () => {
    expect(err([...base, '--body-file', FILE])).toMatch(/go together/)
    expect(err([...base, '--body-sha256', BODY_SHA])).toMatch(/go together/)
  })

  it('refuses a bad hash form (upper case, short, long, padded) and says which flag', () => {
    for (const bad of [BODY_SHA.toUpperCase(), BODY_SHA.slice(1), `${BODY_SHA}0`, ` ${BODY_SHA}`, 'ab', 'g'.repeat(64)]) {
      expect(err([...base, '--body-file', FILE, '--body-sha256', bad]), bad).toMatch(/--body-sha256 must be 64 lower-case hex/)
    }
  })

  it('refuses a body file outside the root, in a subdirectory, relative, with ..', () => {
    for (const bad of [
      '/private/tmp/other/mail.txt',
      `${ROOT}/sub/mail.txt`,
      `${ROOT}/../mail.txt`,
      `${ROOT}/.hidden`,
      `${ROOT}/`,
      ROOT,
      'mail.txt',
      `${ROOT}//mail.txt`,
      `${ROOT}/a b.txt`,
    ]) {
      expect(err([...base, '--body-file', bad, '--body-sha256', BODY_SHA]), bad).toMatch(/--body-file must be /)
    }
  })

  it('the file form needs a valid outbox root; the inline form needs none', () => {
    const file = [...base, '--body-file', FILE, '--body-sha256', BODY_SHA]
    for (const options of [{}, { outboxRoot: '' }, { outboxRoot: `${ROOT}/` }, { outboxRoot: 'rel/x' }]) {
      const r = parseSendArgv(file, options)
      expect(r.ok, JSON.stringify(options)).toBe(false)
      expect(r.ok ? '' : r.error).toMatch(/outbox root is not a plain absolute path/)
    }
    expect(parseSendArgv([...base, '--body', 'x']).ok).toBe(true)
  })

  it('refuses a missing or empty --to / --subject', () => {
    expect(err(['--subject', SUBJECT, '--body', 'x'])).toMatch(/missing --to/)
    expect(err(['--to', TO, '--body', 'x'])).toMatch(/missing --subject/)
    expect(err(['--to', '', '--subject', '', '--body', 'x'])).toMatch(/missing --to, --subject/)
  })

  it('refuses a repeated flag, --flag=value, --bcc, a positional, a dangling flag, a value that looks like a flag', () => {
    expect(err([...base, '--to', 'b@example.invalid', '--body', 'x'])).toMatch(/--to given more than once/)
    expect(err([...base, '--body', 'x', '--body', 'y'])).toMatch(/--body given more than once/)
    expect(err([...base, '--body-file', FILE, '--body-file', FILE, '--body-sha256', BODY_SHA])).toMatch(/--body-file given more than once/)
    expect(err([...base, '--html', '--html', '--body', 'x'])).toMatch(/--html given more than once/)
    expect(err([...base, '--body=x'])).toMatch(/unexpected argument/)
    expect(err(['--to=' + TO, '--subject', SUBJECT, '--body', 'x'])).toMatch(/unexpected argument/)
    expect(err([...base, '--body', 'x', '--bcc', 'b@example.invalid'])).toMatch(/unexpected argument "--bcc"/)
    expect(err([...base, '--body', 'x', 'extra'])).toMatch(/unexpected argument "extra"/)
    expect(err([...base, '--body'])).toMatch(/--body needs a value/)
    expect(err(['--to', TO, '--subject', '--body-file', '--body', 'x'])).toMatch(/--subject needs a value, got "--body-file"/)
    expect(err([...base, '--body', '--body-file', FILE, '--body-sha256', BODY_SHA])).toMatch(/--body needs a value/)
  })

  it('the shared path vectors give the same verdict for --body-file as for --comment-file', () => {
    expect(CASES.comment_file_paths.length).toBeGreaterThanOrEqual(26)
    for (const c of CASES.comment_file_paths) {
      const path = sub(c.path, ROOT)
      expect(isOutboxCommentPath(path, ROOT), c.name).toBe(c.expect === 'ok')
      expect(parse([...base, '--body-file', path, '--body-sha256', BODY_SHA]).ok, c.name).toBe(c.expect === 'ok')
    }
  })
})

// ---------------------------------------------------------------------------
// readSendBodyFile in-process
// ---------------------------------------------------------------------------

describe('readSendBodyFile (the comment-file reader, body wording)', () => {
  it('a good file: the text is exactly the decoded bytes, the hash and the size are reported', () => {
    const root = newRoot()
    const p = put(root, 'ok.txt', BODY_TEXT)
    const got = readSendBodyFile(p, BODY_SHA, root)
    expect(got.text).toBe(BODY_TEXT)
    expect(got.sha256).toBe(BODY_SHA)
    expect(got.bytes).toBe(Buffer.byteLength(BODY_TEXT))
  })

  it('the comment reader keeps its own wording', () => {
    const root = newRoot()
    const p = put(root, 'ok.txt', SZIA)
    expect(refusal(() => readForwardCommentFile(p, sha('Szia?'), root))).toMatch(/^--comment-sha256 does not match the comment file: /)
    expect(refusal(() => readSendBodyFile(p, sha('Szia?'), root))).toMatch(/^--body-sha256 does not match the body file: /)
  })

  it('a hash mismatch names both 16-digit prefixes and no content; one changed byte is enough', () => {
    const root = newRoot()
    const text = 'Tisztelt Andi! Kérlek, nézd meg.'
    const path = put(root, 'a.txt', text)
    const other = sha(`${text} `)
    const msg = refusal(() => readSendBodyFile(path, other, root)) as string
    expect(msg).toBe(
      `--body-sha256 does not match the body file: expected ${other.slice(0, 16)}..., the file has ${sha(text).slice(0, 16)}...`,
    )
    expect(msg).not.toContain('Andi')
  })

  it('bad shapes are refused before the file system is touched', () => {
    const root = newRoot()
    const p = put(root, 'a.txt', SZIA)
    expect(refusal(() => readSendBodyFile(p, SZIA_SHA, `${root}/`))).toMatch(/not a plain absolute path/)
    expect(refusal(() => readSendBodyFile(`${root}/./a.txt`, SZIA_SHA, root))).toBe(`the body file must be ${root}/<name>`)
    expect(refusal(() => readSendBodyFile(p, SZIA_SHA.toUpperCase(), root))).toMatch(/64 lower-case hex/)
  })

  it('a file outside the root is refused', () => {
    const root = newRoot()
    const outside = put(newRoot(), 'a.txt', SZIA)
    expect(refusal(() => readSendBodyFile(outside, SZIA_SHA, root))).toBe(`the body file must be ${root}/<name>`)
  })

  it('the shared content vectors: same verdict and the same reason as the comment file', () => {
    expect(CASES.comment_file_contents.length).toBeGreaterThanOrEqual(23)
    for (const c of CASES.comment_file_contents) {
      const root = newRoot()
      const bytes = contentBytes(c)
      const path = put(root, 'a.txt', bytes)
      if (c.expect === 'ok') {
        const got = readSendBodyFile(path, c.sha256, root)
        expect(got.text, c.name).toBe(c.text ?? bytes.toString('utf-8'))
        expect(got.text, c.name).toBe(readForwardCommentFile(path, c.sha256, root).text)
      } else {
        const msg = refusal(() => readSendBodyFile(path, c.sha256, root))
        expect(msg, c.name).toMatch(DENY_REASON[c.rule])
        expect(msg, c.name).toContain('the body file ')
        expect(msg, c.name).not.toContain('comment')
      }
    }
  })

  it('the shared kind vectors (no FIFO in-process): same verdict', () => {
    for (const c of CASES.comment_file_kinds.filter((k) => k.kind !== 'fifo')) {
      const s = setupKind(c.kind)
      const msg = refusal(() => readSendBodyFile(s.path, SZIA_SHA, s.root))
      if (c.expect === 'ok') expect(msg, c.name).toBeNull()
      else expect(msg, c.name).toMatch(KIND_REASON[c.kind])
    }
  })
})

// ---------------------------------------------------------------------------
// The CLI as a subprocess
// ---------------------------------------------------------------------------

const FETCH_STUB = [
  "import { appendFileSync } from 'node:fs'",
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/sendMail')) kind = 'sendmail'",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  '  appendFileSync(process.env.SB_FETCH_LOG, JSON.stringify({ kind, method, url, body }) + "\\n")',
  "  if (kind === 'token') return new Response(JSON.stringify({ access_token: process.env.SB_TOKEN, token_type: 'Bearer', expires_in: 3600 }), { status: 200, headers: { 'content-type': 'application/json' } })",
  "  if (kind === 'sendmail') return new Response(null, { status: 202 })",
  "  throw new Error('fetch stub: unexpected ' + kind + ' call')",
  '}',
  '',
].join('\n')
const STUB = join(BASE, 'fetch-stub.mjs')
writeFileSync(STUB, FETCH_STUB)

interface FetchCall {
  kind: string
  method: string
  url: string
  body: string | null
}
interface CliRun {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  calls: FetchCall[]
}
const OUTPUTS: string[] = []
let runSeq = 0

/** Run the CLI of this checkout. `outbox`: the GRAPH_MAIL_OUTBOX_DIR value. */
function runCli(args: string[], outbox: string, extraEnv: Record<string, string> = {}, timeout = 60_000): CliRun {
  const n = ++runSeq
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    NODE_ENV: 'production',
    MARVEEN_MAIL_CREDS: CREDS,
    SB_FETCH_LOG: logPath,
    SB_TOKEN: FAKE_TOKEN,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(STUB).href}`.trim(),
    ...extraEnv,
  }
  env[OUTBOX_ENV] = outbox
  const r = spawnSync(TSX, [join(ROOT, 'scripts', 'graph-mail.ts'), ...args], { cwd: ROOT, env, encoding: 'utf-8', timeout })
  const calls = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FetchCall)
    : []
  OUTPUTS.push(`${r.stdout}\n${r.stderr}`)
  return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, calls }
}

const kinds = (r: CliRun): string[] => r.calls.map((c) => c.kind)
const posted = (r: CliRun): { message: Record<string, any>; saveToSentItems: boolean } | undefined => {
  const post = r.calls.find((c) => c.kind === 'sendmail')
  return post?.body ? JSON.parse(post.body) : undefined
}
const fileArgs = (path: string, hex: string, extra: string[] = []): string[] => [
  'send',
  '--to',
  TO,
  '--subject',
  SUBJECT,
  '--body-file',
  path,
  '--body-sha256',
  hex,
  ...extra,
]
/** A refusal: exit 2, "Nothing was sent", and not a single fetch (not even the token). */
function expectRefused(r: CliRun): void {
  expect(r.signal, 'the CLI hung and was killed').toBeNull()
  expect(r.status).toBe(2)
  expect(r.stderr).toContain('Nothing was sent')
  expect(r.calls).toEqual([])
}

describe('graph-mail CLI, send --body-file (subprocess, stubbed fetch, fake credentials)', () => {
  describe('usage and header', () => {
    it('the usage and the file header show both body forms', () => {
      const r = runCli([], newRoot())
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('send    --to a@b.hu[,c@d.hu] --subject "..." --body "..."')
      expect(r.stderr).toContain('--body-file <outbox>/<name> --body-sha256 <hex>')
      expect(r.calls).toEqual([])
      const head = readFileSync(CLI, 'utf-8').split('\nimport ')[0]
      expect(head).toContain('--subject "..." --body-file <outbox>/<name> --body-sha256 <hex>')
      expect(head).toContain('exactly ONE body source')
    })
  })

  describe('a good send', () => {
    it('--body-file: exit 0, token -> sendMail, and the body is the file text exactly (LF, TAB, accents)', () => {
      const root = newRoot()
      const path = put(root, '20261019-ajanlat.txt', BODY_TEXT)
      const r = runCli(fileArgs(path, BODY_SHA), root)
      expect(r.status).toBe(0)
      expect(r.stdout).toContain(`sent to ${TO}`)
      expect(kinds(r)).toEqual(['token', 'sendmail'])
      expect(r.calls[1].url).toBe(`${GRAPH}/users/${MAILBOX_ENC}/sendMail`)
      const p = posted(r) as NonNullable<ReturnType<typeof posted>>
      expect(p.message.body).toEqual({ contentType: 'Text', content: BODY_TEXT })
      expect(p.message.subject).toBe(SUBJECT)
      expect(p.message.toRecipients).toEqual([{ emailAddress: { address: TO } }])
    })

    it('--body-file with --cc and --html keeps working', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', '<p>Szia!</p>')
      const r = runCli(fileArgs(path, sha('<p>Szia!</p>'), ['--cc', 'c@example.invalid', '--html']), root)
      expect(r.status).toBe(0)
      const p = posted(r) as NonNullable<ReturnType<typeof posted>>
      expect(p.message.body).toEqual({ contentType: 'HTML', content: '<p>Szia!</p>' })
      expect(p.message.ccRecipients).toEqual([{ emailAddress: { address: 'c@example.invalid' } }])
    })

    it('the inline --body still works as before', () => {
      const r = runCli(['send', '--to', TO, '--subject', SUBJECT, '--body', 'Egy sor.'], newRoot())
      expect(r.status).toBe(0)
      expect(kinds(r)).toEqual(['token', 'sendmail'])
      expect((posted(r) as NonNullable<ReturnType<typeof posted>>).message.body).toEqual({ contentType: 'Text', content: 'Egy sor.' })
    })

    it('a trailing LF is part of the body and of the hash', () => {
      const root = newRoot()
      const path = put(root, 'lf.txt', 'Szia!\n')
      const ok = runCli(fileArgs(path, sha('Szia!\n')), root)
      expect(ok.status).toBe(0)
      expect((posted(ok) as NonNullable<ReturnType<typeof posted>>).message.body.content).toBe('Szia!\n')
      expectRefused(runCli(fileArgs(path, sha('Szia!')), root))
    })
  })

  describe('exactly one body source: exit 2, no fetch', () => {
    it('--body and --body-file together (with and without a hash)', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const t = ['send', '--to', TO, '--subject', SUBJECT]
      const both = runCli([...t, '--body', 'x', '--body-file', path, '--body-sha256', SZIA_SHA], root)
      expectRefused(both)
      expect(both.stderr).toMatch(/exactly one body source/)
      expectRefused(runCli([...t, '--body', 'x', '--body-file', path], root))
      expectRefused(runCli([...t, '--body', 'x', '--body-sha256', SZIA_SHA], root))
    })

    it('neither', () => {
      const r = runCli(['send', '--to', TO, '--subject', SUBJECT], newRoot())
      expectRefused(r)
      expect(r.stderr).toMatch(/missing the body/)
    })

    it('--body-file without a hash, and a hash without a file', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const t = ['send', '--to', TO, '--subject', SUBJECT]
      const noHash = runCli([...t, '--body-file', path], root)
      expectRefused(noHash)
      expect(noHash.stderr).toMatch(/go together/)
      expectRefused(runCli([...t, '--body-sha256', SZIA_SHA], root))
    })

    it('a malformed hash (upper case, short)', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      for (const bad of [SZIA_SHA.toUpperCase(), SZIA_SHA.slice(1)]) {
        const r = runCli(fileArgs(path, bad), root)
        expectRefused(r)
        expect(r.stderr).toMatch(/--body-sha256 must be 64 lower-case hex/)
      }
    })

    it('--bcc, a repeated --to, --body=x, a positional: the CLI only knows what the gate sees', () => {
      const t = ['send', '--to', TO, '--subject', SUBJECT, '--body', 'x']
      for (const extra of [['--bcc', 'b@example.invalid'], ['--to', 'b@example.invalid'], ['--cc=c@example.invalid'], ['extra']]) {
        expectRefused(runCli([...t, ...extra], newRoot()))
      }
    })

    it('a missing --to or --subject', () => {
      expectRefused(runCli(['send', '--subject', SUBJECT, '--body', 'x'], newRoot()))
      expectRefused(runCli(['send', '--to', TO, '--body', 'x'], newRoot()))
    })
  })

  describe('a mismatched hash: exit 2 before any network call', () => {
    it('both 16-digit prefixes, no content in the output', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const wrong = sha('Szia!!')
      const r = runCli(fileArgs(path, wrong), root)
      expectRefused(r)
      expect(r.stderr).toContain(`--body-file refused: --body-sha256 does not match the body file: expected ${wrong.slice(0, 16)}..., the file has ${SZIA_SHA.slice(0, 16)}...`)
      expect(r.stderr).not.toContain(SZIA)
    })
  })

  describe('the file must be in the outbox: exit 2, no fetch', () => {
    it('outside the root, in a subdirectory, with .., relative', () => {
      const root = newRoot()
      const other = put(newRoot(), 'a.txt', SZIA)
      mkdirSync(join(root, 'sub'))
      put(join(root, 'sub'), 'a.txt', SZIA)
      for (const path of [other, `${root}/sub/a.txt`, `${root}/../${root.split('/').pop()}/a.txt`, 'a.txt']) {
        const r = runCli(fileArgs(path, SZIA_SHA), root)
        expectRefused(r)
        expect(r.stderr, path).toContain(`--body-file must be ${root}/<name>`)
      }
    })

    it('the shared path vectors', () => {
      for (const c of CASES.comment_file_paths) {
        const root = newRoot()
        const path = sub(c.path, root)
        if (c.expect === 'ok') put(root, path.slice(root.length + 1), SZIA)
        const r = runCli(fileArgs(path, SZIA_SHA), root)
        if (c.expect === 'ok') {
          expect(r.status, c.name).toBe(0)
          expect(posted(r)?.message.body.content, c.name).toBe(SZIA)
        } else {
          expect(r.status, c.name).toBe(2)
          expect(r.calls, c.name).toEqual([])
        }
      }
    })

    it.each([
      ['empty', ''],
      ['relative', 'store/mail-outbox'],
      ['space', '/private/tmp/a b'],
    ])('GRAPH_MAIL_OUTBOX_DIR %s: exit 2, no fetch', (_label, value) => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const r = runCli(fileArgs(path, SZIA_SHA), value)
      expectRefused(r)
      expect(r.stderr).toContain('outbox root is not a plain absolute path')
    })

    it('a symlink as the body file (inside or outside the outbox)', () => {
      for (const kind of ['symlink_inside', 'symlink_outside']) {
        const s = setupKind(kind)
        const r = runCli(fileArgs(s.path, SZIA_SHA), s.root)
        expectRefused(r)
        expect(r.stderr, kind).toMatch(KIND_REASON[kind])
      }
    })
  })

  describe('the shared vectors through the CLI: exit 2, no fetch', () => {
    it('contents: same verdict as the comment file; accepted ones go out character for character', () => {
      for (const c of CASES.comment_file_contents) {
        const root = newRoot()
        const bytes = contentBytes(c)
        const path = put(root, 'a.txt', bytes)
        const r = runCli(fileArgs(path, c.sha256), root)
        if (c.expect === 'ok') {
          expect(r.status, c.name).toBe(0)
          expect(posted(r)?.message.body.content, c.name).toBe(c.text ?? bytes.toString('utf-8'))
        } else {
          expect(r.status, c.name).toBe(2)
          expect(r.stderr, c.name).toContain('send: --body-file refused: ')
          expect(r.stderr, c.name).toMatch(DENY_REASON[c.rule])
          expect(r.calls, c.name).toEqual([])
        }
      }
    }, 240_000)

    it.each(CASES.comment_file_kinds.map((c) => [c.name, c] as const))(
      'kind %s',
      (_name, c) => {
        const s = setupKind(c.kind)
        const r = runCli(fileArgs(s.path, SZIA_SHA), s.root, {}, FIFO_TIMEOUT_MS)
        expect(r.signal, 'the CLI hung and was killed').toBeNull()
        if (c.expect === 'ok') {
          expect(r.status).toBe(0)
          expect(posted(r)?.message.body.content).toBe(SZIA)
        } else {
          expect(r.status).toBe(2)
          expect(r.stderr).toMatch(KIND_REASON[c.kind])
          expect(r.stderr).toContain('Nothing was sent.')
          expect(r.calls).toEqual([])
        }
      },
      20_000,
    )
  })

  describe('the body never shows up in the output', () => {
    const MARK_HEAD = 'MARKERHEAD7q2'
    const MARK_TAIL = 'MARKERTAIL9z4'
    const body = `${MARK_HEAD} Tisztelt Ügyfelünk! ${'Csatoltan küldjük az ajánlatot. '.repeat(8)}${MARK_TAIL} Üdvözlettel!\n`

    it.each([
      ['success', 'good', 0],
      ['hash mismatch', 'wrong-hash', 2],
      ['forbidden character', 'zwsp', 2],
    ] as const)('%s', (_label, file, code) => {
      const root = newRoot()
      const text = file === 'zwsp' ? `${body}${String.fromCodePoint(0x200b)}` : body
      const path = put(root, 'a.txt', text)
      const hex = file === 'wrong-hash' ? sha(`${text}x`) : sha(text)
      const r = runCli(fileArgs(path, hex), root)
      expect(r.status).toBe(code)
      for (const out of [r.stdout, r.stderr]) {
        expect(out).not.toContain(MARK_HEAD)
        expect(out).not.toContain(MARK_TAIL)
        expect(out).not.toContain('Tisztelt')
      }
      if (code === 0) expect(posted(r)?.message.body.content).toBe(text)
    })
  })

  describe('no credential in any output', () => {
    it('no CLI run printed the client secret or the access token (stdout + stderr, logger included)', () => {
      expect(OUTPUTS.length).toBeGreaterThan(60)
      expect(OUTPUTS.some((o) => o.includes('graph-mail: sent'))).toBe(true)
      expect(OUTPUTS.filter((o) => o.includes(FAKE_SECRET) || o.includes(FAKE_TOKEN))).toEqual([])
    })
  })
})
