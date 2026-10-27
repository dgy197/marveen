import { describe, it, expect, beforeAll } from 'vitest'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { STUB_HELPER } from './graph-cli-root.js'
import { createHash } from 'node:crypto'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import { isOutboxCommentPath, isOutboxRoot, isSha256Hex, parseForwardArgv } from '../graph-forward-validate.js'
import {
  FORWARD_COMMENT_FORBIDDEN_RANGES,
  FORWARD_COMMENT_MAX_BYTES,
  ForwardCommentFileError,
  OUTBOX_ENV,
  readForwardCommentFile,
  resolveOutboxRoot,
} from '../graph-forward-comment-file.js'

// graph-mail `forward --comment-file <root>/<name> --comment-sha256 <hex>`
// (card graph-forward, Brainy 3011, node N3b; spec-delta KA, KB, KE, KF, KG).
// Three layers:
//   - in-process: the pure validators (KA1-KA4, KF1) on the shared vectors
//     (comment_file_argv, comment_file_paths), and readForwardCommentFile
//     (KB1-KB10) on comment_file_contents and comment_file_kinds;
//   - the reader in a child process for the FIFO case, under a 5 s timeout;
//   - the real CLI as a subprocess (tsx) with a preloaded fetch stub, a fake
//     credentials file and a throwaway outbox root (KE1-KE6).
// No real credentials file, no Vault, no network.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const CLI_REL = join('scripts', 'graph-mail.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const GRAPH = 'https://graph.microsoft.com/v1.0'
const FIFO_TIMEOUT_MS = 5000

interface ArgvCase {
  name: string
  argv: string[]
  expect: 'ok' | 'exit2'
  rule: string
}
interface PathCase {
  name: string
  path: string
  expect: 'ok' | 'deny'
  rule: string
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
  chars?: number
}
interface KindCase {
  name: string
  kind: string
  expect: 'ok' | 'deny'
  rule: string
  timeout_s?: number
}
interface Cases {
  comment_file_argv: ArgvCase[]
  comment_file_paths: PathCase[]
  comment_file_contents: ContentCase[]
  comment_file_kinds: KindCase[]
}
const CASES = JSON.parse(readFileSync(join(REPO, 'scripts', 'hooks', 'graph-forward-cases.json'), 'utf-8')) as Cases

const cp = (...codes: number[]): string => String.fromCodePoint(...codes)
const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')

/** The bytes a content vector stands for: `text` (UTF-8), `bytes_hex`, or `prefix_text` padded with ASCII `a`. */
function contentBytes(c: ContentCase): Buffer {
  if (c.text !== undefined) return Buffer.from(c.text, 'utf-8')
  if (c.bytes_hex !== undefined) return Buffer.from(c.bytes_hex, 'hex')
  if (c.prefix_text !== undefined && c.total_bytes !== undefined) {
    const prefix = Buffer.from(c.prefix_text, 'utf-8')
    return Buffer.concat([prefix, Buffer.alloc(c.total_bytes - prefix.length, 'a')])
  }
  throw new Error(`content vector ${c.name} has no content`)
}

// Fake secrets: E8 greps every CLI output for these two strings.
const FAKE_SECRET = `FAKE-gf-client-secret-${'w4n8'.repeat(4)}`
const FAKE_TOKEN = `FAKE-gf-access-token-${'r2t6'.repeat(4)}`
const MAILBOX = 'gf-test-box@example.invalid'
const MAILBOX_ENC = encodeURIComponent(MAILBOX)

const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const TO = 'kovacs@fireeng.hu'
const SUBJECT = 'Tárgy'
const SZIA = 'Szia!'
const SZIA_SHA = sha(SZIA)

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'gf-n3b-test-')))
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
const sub = (s: string, root: string): string => s.split('{ROOT}').join(root)

/** The refusal message of readForwardCommentFile, or null when it accepted. */
function refusal(fn: () => unknown): string | null {
  try {
    fn()
    return null
  } catch (err) {
    expect(err).toBeInstanceOf(ForwardCommentFileError)
    return (err as Error).message
  }
}

// ---------------------------------------------------------------------------
// Pure validators: KA3, KF1, KA4 (comment_file_paths), KA1-KA4 (comment_file_argv)
// ---------------------------------------------------------------------------

describe('pure validators (KA1-KA4, KF1)', () => {
  const ROOT = '/private/tmp/gf-n3b-pure/store/mail-outbox'

  it('KA3: isSha256Hex takes exactly 64 lower-case hex digits', () => {
    expect(isSha256Hex(SZIA_SHA)).toBe(true)
    for (const bad of [
      SZIA_SHA.toUpperCase(),
      SZIA_SHA.slice(1),
      `${SZIA_SHA}0`,
      `g${SZIA_SHA.slice(1)}`,
      `${SZIA_SHA} `,
      `${SZIA_SHA}\n`,
      ` ${SZIA_SHA}`,
      '',
      undefined,
      42,
    ]) {
      expect(isSha256Hex(bad)).toBe(false)
    }
  })

  it('KF1: isOutboxRoot takes a plain, normal absolute path only', () => {
    for (const ok of [ROOT, '/a', '/Users/x/store/mail-outbox', '/private/tmp/a.b_c-d']) expect(isOutboxRoot(ok)).toBe(true)
    for (const bad of [
      '',
      '/',
      'store/mail-outbox',
      './x',
      '/a/',
      '/a//b',
      '/a/./b',
      '/a/../b',
      '/a/.',
      '/a b',
      `/a${cp(0xe1)}`,
      '/a\n',
      '/a/$x',
      '~/x',
      undefined,
    ]) {
      expect(isOutboxRoot(bad)).toBe(false)
    }
  })

  it('KF1: resolveOutboxRoot is <repo>/store/mail-outbox, and the env override is taken verbatim (even empty)', () => {
    expect(resolveOutboxRoot('/r/repo', {})).toBe('/r/repo/store/mail-outbox')
    expect(OUTBOX_ENV).toBe('GRAPH_MAIL_OUTBOX_DIR')
    expect(resolveOutboxRoot('/r/repo', { [OUTBOX_ENV]: '/x/y' })).toBe('/x/y')
    expect(resolveOutboxRoot('/r/repo', { [OUTBOX_ENV]: '' })).toBe('')
    expect(resolveOutboxRoot('/r/repo', { [OUTBOX_ENV]: 'rel/x' })).toBe('rel/x')
  })

  it('the shared path vectors carry the spec-delta KG2 list (2 ok, 24 deny)', () => {
    expect(CASES.comment_file_paths.filter((c) => c.expect === 'ok')).toHaveLength(2)
    expect(CASES.comment_file_paths.filter((c) => c.expect === 'deny')).toHaveLength(24)
  })

  it.each(CASES.comment_file_paths.map((c) => [c.name, c] as const))('KA4 path %s', (_name, c) => {
    const path = sub(c.path, ROOT)
    expect(isOutboxCommentPath(path, ROOT)).toBe(c.expect === 'ok')
    // the same verdict through the argv parser
    const r = parseForwardArgv(
      ['--id', ID, '--to', TO, '--comment-file', path, '--comment-sha256', SZIA_SHA, '--orig-subject', SUBJECT],
      { outboxRoot: ROOT },
    )
    expect(r.ok).toBe(c.expect === 'ok')
  })

  it('the shared argv vectors carry the spec-delta KG1 list (3 ok, the rest exit2)', () => {
    expect(CASES.comment_file_argv.filter((c) => c.expect === 'ok')).toHaveLength(3)
    expect(CASES.comment_file_argv.filter((c) => c.expect === 'exit2').length).toBeGreaterThanOrEqual(11)
  })

  it.each(CASES.comment_file_argv.map((c) => [c.name, c] as const))('KA1-KA3 argv %s', (_name, c) => {
    const argv = c.argv.map((a) => sub(a, ROOT))
    const r = parseForwardArgv(argv, { outboxRoot: ROOT })
    expect(r.ok).toBe(c.expect === 'ok')
    if (r.ok) {
      const at = (flag: string) => argv[argv.indexOf(flag) + 1]
      expect(r.value).toEqual({
        id: at('--id'),
        to: at('--to'),
        origSubject: at('--orig-subject'),
        commentFile: at('--comment-file'),
        commentSha256: at('--comment-sha256'),
      })
      expect('comment' in r.value).toBe(false)
    }
  })

  it('the file form needs a valid outbox root; the inline form needs none', () => {
    const file = ['--id', ID, '--to', TO, '--comment-file', `${ROOT}/a.txt`, '--comment-sha256', SZIA_SHA, '--orig-subject', SUBJECT]
    expect(parseForwardArgv(file).ok).toBe(false)
    expect(parseForwardArgv(file, { outboxRoot: `${ROOT}/` }).ok).toBe(false)
    expect(parseForwardArgv(file, { outboxRoot: '' }).ok).toBe(false)
    const inline = ['--id', ID, '--to', TO, '--comment', SZIA, '--orig-subject', SUBJECT]
    expect(parseForwardArgv(inline)).toEqual({ ok: true, value: { id: ID, to: TO, comment: SZIA, origSubject: SUBJECT } })
  })

  it('the error lines name the rule', () => {
    const base = ['--id', ID, '--to', TO, '--orig-subject', SUBJECT]
    const err = (argv: string[]) => {
      const r = parseForwardArgv(argv, { outboxRoot: ROOT })
      return r.ok ? '' : r.error
    }
    expect(err([...base, '--comment', 'x', '--comment-file', `${ROOT}/a.txt`])).toMatch(/exactly one comment source/)
    expect(err(base)).toMatch(/missing the comment/)
    expect(err([...base, '--comment-file', `${ROOT}/a.txt`])).toMatch(/go together/)
    expect(err([...base, '--comment-file', `${ROOT}/a.txt`, '--comment-sha256', 'ab'])).toMatch(/64 lower-case hex/)
    expect(err([...base, '--comment-file', '/tmp/a.txt', '--comment-sha256', SZIA_SHA])).toMatch(/--comment-file must be/)
  })
})

// ---------------------------------------------------------------------------
// readForwardCommentFile in-process: KB3-KB9 on comment_file_contents
// ---------------------------------------------------------------------------

const DENY_REASON: Record<string, RegExp> = {
  KB4: /is larger than 16384 bytes/,
  KB6: /is not valid UTF-8/,
  KB7: /contains the forbidden character U\+[0-9A-F]{4} at position \d+/,
  KB8: /is blank/,
}

describe('readForwardCommentFile: contents (KB3-KB9, comment_file_contents)', () => {
  it('the vectors are self-consistent (byte length and sha256 recomputed)', () => {
    expect(CASES.comment_file_contents.length).toBeGreaterThanOrEqual(23)
    for (const c of CASES.comment_file_contents) {
      const b = contentBytes(c)
      expect(b.length, c.name).toBe(c.byte_len)
      expect(sha(b), c.name).toBe(c.sha256)
    }
    expect(FORWARD_COMMENT_MAX_BYTES).toBe(16384)
  })

  it.each(CASES.comment_file_contents.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const root = newRoot()
    const bytes = contentBytes(c)
    const path = put(root, 'a.txt', bytes)
    if (c.expect === 'ok') {
      const got = readForwardCommentFile(path, c.sha256, root)
      // KB9: no normalisation; the text is exactly the decoded bytes
      expect(got.text).toBe(c.text ?? bytes.toString('utf-8'))
      expect(got.bytes).toBe(c.byte_len)
      expect(got.sha256).toBe(c.sha256)
      if (c.chars !== undefined) expect([...got.text].length).toBe(c.chars)
    } else {
      const msg = refusal(() => readForwardCommentFile(path, c.sha256, root))
      expect(msg).not.toBeNull()
      expect(msg).toMatch(DENY_REASON[c.rule])
    }
  })

  it('KB7: a leading BOM is seen at position 0 (ignoreBOM keeps it), CR is named', () => {
    const root = newRoot()
    const bom = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('Szia!')])
    expect(refusal(() => readForwardCommentFile(put(root, 'bom.txt', bom), sha(bom), root))).toMatch(
      /forbidden character U\+FEFF at position 0$/,
    )
    const crlf = Buffer.from('Szia!\r\nKöszönöm!')
    expect(refusal(() => readForwardCommentFile(put(root, 'crlf.txt', crlf), sha(crlf), root))).toMatch(
      /U\+000D at position 5$/,
    )
  })

  it('KB7: the position counts code points (an astral character is one), like Python str indexing', () => {
    const root = newRoot()
    const b = Buffer.from(`a${cp(0x1f600)}${cp(0x200b)}b`)
    expect(refusal(() => readForwardCommentFile(put(root, 'p.txt', b), sha(b), root))).toMatch(/U\+200B at position 2$/)
  })

  it('KB7: the forbidden list is exactly the spec list; every listed code point is refused, the neighbours pass', () => {
    // Restated from spec-delta KB7 on purpose, not imported.
    const SPEC: Array<[number, number]> = [
      [0x0000, 0x0008],
      [0x000b, 0x001f],
      [0x007f, 0x009f],
      [0x200b, 0x200f],
      [0x2028, 0x202e],
      [0x2060, 0x2064],
      [0x2066, 0x2069],
      [0xfeff, 0xfeff],
    ]
    expect(FORWARD_COMMENT_FORBIDDEN_RANGES.map(([lo, hi]) => [lo, hi])).toEqual(SPEC)
    const root = newRoot()
    let n = 0
    const check = (code: number): string | null => {
      const b = Buffer.from(`Szia ${cp(code)} Andi`, 'utf-8')
      return refusal(() => readForwardCommentFile(put(root, `c${n++}.txt`, b), sha(b), root))
    }
    let refused = 0
    for (const [lo, hi] of SPEC) {
      for (let code = lo; code <= hi; code++) {
        const name = `U+${code.toString(16).toUpperCase().padStart(4, '0')}`
        expect(check(code), name).toBe(`the comment file ${root}/c${n - 1}.txt contains the forbidden character ${name} at position 5`)
        refused++
      }
    }
    expect(refused).toBe(85)
    const allowed = [0x09, 0x0a, 0x20, 0x7e, 0xa0, 0xad, 0x200a, 0x2010, 0x2027, 0x202f, 0x205f, 0x2065, 0x206a, 0xfefe, 0xfffd, 0x1f600]
    for (const code of allowed) expect(check(code), code.toString(16)).toBeNull()
  })

  it('KB5: a hash mismatch names both 16-digit prefixes and no content; one changed byte is enough', () => {
    const root = newRoot()
    const text = 'Szia Andi! Kérlek, nézd meg.'
    const path = put(root, 'a.txt', text)
    const other = sha(`${text} `)
    const msg = refusal(() => readForwardCommentFile(path, other, root)) as string
    expect(msg).toBe(
      `--comment-sha256 does not match the comment file: expected ${other.slice(0, 16)}..., the file has ${sha(text).slice(0, 16)}...`,
    )
    expect(msg).not.toContain('Andi')
    writeFileSync(path, text.replace('Andi', 'Andj'))
    expect(refusal(() => readForwardCommentFile(path, sha(text), root))).toMatch(/does not match/)
  })

  it('KB9: a trailing LF is part of the text and of the hash', () => {
    const root = newRoot()
    const withLf = 'Szia!\n'
    const p = put(root, 'lf.txt', withLf)
    expect(readForwardCommentFile(p, sha(withLf), root).text).toBe(withLf)
    expect(refusal(() => readForwardCommentFile(p, sha('Szia!'), root))).toMatch(/does not match/)
  })
})

// ---------------------------------------------------------------------------
// readForwardCommentFile in-process: KB1-KB3, KF2 on comment_file_kinds
// ---------------------------------------------------------------------------

interface KindSetup {
  root: string
  path: string
  /** Checked after the call (e.g. the missing root must not have been created). */
  after?: () => void
}

/** Builds the file system state of one comment_file_kinds vector; the content is always "Szia!". */
function setupKind(kind: string): KindSetup {
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
      // A child process makes the FIFO (spec-delta KG4).
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
      return { root: missing, path: join(missing, 'a.txt'), after: () => expect(existsSync(missing)).toBe(false) }
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
  symlink_inside: /^the comment file .*\/a\.txt is a symlink$/,
  symlink_outside: /^the comment file .*\/a\.txt is a symlink$/,
  hardlink: /has 2 hard links; it must have exactly 1$/,
  directory: /is a directory$/,
  fifo: /is a FIFO$/,
  root_symlink: /^the outbox root .* is a symlink$/,
  root_mode_0775: /is group- or world-writable \(mode 775\); it must be 0700$/,
  root_missing: /^a kimenő-mappa hiányzik \(.*\); egyszer létre kell hozni 0700-as joggal$/,
  root_under_symlink_parent: /is not a canonical path \(a parent is a symlink\)$/,
}

describe('readForwardCommentFile: file kinds and the root (KB1-KB3, KF2, comment_file_kinds)', () => {
  it('the kinds vectors are the spec-delta KG4 list, each with a setup here', () => {
    expect(CASES.comment_file_kinds.map((c) => c.kind).sort()).toEqual(
      [
        'directory',
        'fifo',
        'hardlink',
        'regular',
        'root_missing',
        'root_mode_0775',
        'root_symlink',
        'root_under_symlink_parent',
        'symlink_inside',
        'symlink_outside',
      ].sort(),
    )
    expect(CASES.comment_file_kinds.find((c) => c.kind === 'fifo')?.timeout_s).toBe(FIFO_TIMEOUT_MS / 1000)
  })

  // The FIFO is read in a child process below: if it ever blocked, an
  // in-process call would hang the test worker instead of failing.
  it.each(CASES.comment_file_kinds.filter((c) => c.kind !== 'fifo').map((c) => [c.name, c] as const))(
    '%s',
    (_name, c) => {
      const s = setupKind(c.kind)
      const msg = refusal(() => readForwardCommentFile(s.path, SZIA_SHA, s.root))
      if (c.expect === 'ok') expect(msg).toBeNull()
      else expect(msg).toMatch(KIND_REASON[c.kind])
      s.after?.()
    },
  )

  it('KB1: only the write bits of group and other matter (0750 and 0755 pass, 0702 and 0720 do not)', () => {
    for (const [mode, ok] of [
      [0o750, true],
      [0o755, true],
      [0o702, false],
      [0o720, false],
    ] as const) {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      chmodSync(root, mode)
      const msg = refusal(() => readForwardCommentFile(p, SZIA_SHA, root))
      if (ok) expect(msg, mode.toString(8)).toBeNull()
      else expect(msg, mode.toString(8)).toMatch(/group- or world-writable/)
    }
  })

  it('a missing file and a root that is a regular file are refused', () => {
    const root = newRoot()
    expect(refusal(() => readForwardCommentFile(join(root, 'nope.txt'), SZIA_SHA, root))).toMatch(/does not exist$/)
    const fileRoot = put(root, 'plain', SZIA)
    expect(refusal(() => readForwardCommentFile(join(fileRoot, 'a.txt'), SZIA_SHA, fileRoot))).toMatch(
      /is not a directory$/,
    )
  })

  it('bad shapes are refused before the file system is touched (KF1, KA4, KA3)', () => {
    const root = newRoot()
    const p = put(root, 'a.txt', SZIA)
    expect(refusal(() => readForwardCommentFile(p, SZIA_SHA, `${root}/`))).toMatch(/not a plain absolute path/)
    expect(refusal(() => readForwardCommentFile(`${root}/./a.txt`, SZIA_SHA, root))).toMatch(/must be .*\/<name>$/)
    expect(refusal(() => readForwardCommentFile(p, SZIA_SHA.toUpperCase(), root))).toMatch(/64 lower-case hex/)
    // the missing-root message would win if the shape check came after KB1
    const missing = join(root, 'missing')
    expect(refusal(() => readForwardCommentFile(`${missing}/a b.txt`, SZIA_SHA, missing))).toMatch(/must be/)
  })

  describe('KB2 after the open (TOCTOU seam: the file system is changed right after the open)', () => {
    it('the name now points at another file: refused (dev, ino)', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      const other = put(root, 'other.txt', SZIA)
      const msg = refusal(() => readForwardCommentFile(p, SZIA_SHA, root, { afterOpen: () => renameSync(other, p) }))
      expect(msg).toMatch(/was replaced while it was opened$/)
    })

    it('the name is now a symlink to the very file: refused', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      const msg = refusal(() =>
        readForwardCommentFile(p, SZIA_SHA, root, {
          afterOpen: () => {
            renameSync(p, join(root, 'moved.txt'))
            symlinkSync(join(root, 'moved.txt'), p)
          },
        }),
      )
      expect(msg).toMatch(/was replaced while it was opened$/)
    })

    it('the name is gone: refused', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      const msg = refusal(() => readForwardCommentFile(p, SZIA_SHA, root, { afterOpen: () => unlinkSync(p) }))
      expect(msg).toMatch(/changed while it was opened \(ENOENT\)$/)
    })

    it('the root was swapped for a symlink to the old directory: refused', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      const msg = refusal(() =>
        readForwardCommentFile(p, SZIA_SHA, root, {
          afterOpen: () => {
            renameSync(root, `${root}-moved`)
            symlinkSync(`${root}-moved`, root)
          },
        }),
      )
      expect(msg).toMatch(/^the outbox root .* changed while the comment file was opened$/)
    })

    it('the root was swapped for another real directory holding the same name: refused', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      const msg = refusal(() =>
        readForwardCommentFile(p, SZIA_SHA, root, {
          afterOpen: () => {
            renameSync(root, `${root}-old`)
            mkdirSync(root, { mode: 0o700 })
            put(root, 'a.txt', SZIA)
          },
        }),
      )
      expect(msg).toMatch(/^the outbox root .* changed while the comment file was opened$/)
    })

    it('without a change the seam is harmless', () => {
      const root = newRoot()
      const p = put(root, 'a.txt', SZIA)
      expect(readForwardCommentFile(p, SZIA_SHA, root, { afterOpen: () => undefined }).text).toBe(SZIA)
    })
  })

  it(
    'KB3: a FIFO is refused without blocking (the reader in a child process, 5 s timeout)',
    () => {
      const s = setupKind('fifo')
      const script = join(BASE, 'read-one.mjs')
      writeFileSync(
        script,
        [
          'const [mod, path, hex, root] = process.argv.slice(2)',
          'const m = await import(mod)',
          'try {',
          '  m.readForwardCommentFile(path, hex, root)',
          "  console.log(JSON.stringify({ ok: true }))",
          '} catch (e) {',
          "  console.log(JSON.stringify({ ok: false, name: e.name, message: e.message }))",
          '}',
          '',
        ].join('\n'),
      )
      const mod = pathToFileURL(join(REPO, 'src', 'graph-forward-comment-file.ts')).href
      const started = Date.now()
      const r = spawnSync(TSX, [script, mod, s.path, SZIA_SHA, s.root], { encoding: 'utf-8', timeout: FIFO_TIMEOUT_MS })
      expect(r.signal, 'the reader blocked on the FIFO and was killed').toBeNull()
      expect(r.status).toBe(0)
      expect(Date.now() - started).toBeLessThan(FIFO_TIMEOUT_MS)
      const out = JSON.parse(r.stdout.trim().split('\n').pop() as string) as { ok: boolean; name?: string; message?: string }
      expect(out).toEqual({ ok: false, name: 'ForwardCommentFileError', message: `the comment file ${s.path} is a FIFO` })
    },
    20_000,
  )
})

// ---------------------------------------------------------------------------
// The CLI as a subprocess (KE1-KE6, KA/KB through the CLI)
// ---------------------------------------------------------------------------

// Preloaded into the CLI process: replaces global fetch, answers from the
// scenario file, records every call. `mutate` changes the comment file while
// the GET is in flight, i.e. AFTER the CLI read it (KE1).
const FETCH_STUB = [
  "import { appendFileSync, readFileSync, renameSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'",
  "const scenario = JSON.parse(readFileSync(process.env.GF_FETCH_SCENARIO, 'utf8'))",
  'const logPath = process.env.GF_FETCH_LOG',
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/forward')) kind = 'forward'",
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  '  let mutated = false',
  "  if (kind === 'message' && scenario.mutate) {",
  '    const m = scenario.mutate',
  "    if (m.action === 'rewrite') writeFileSync(m.path, m.content)",
  "    else if (m.action === 'symlink') { renameSync(m.path, m.path + '.moved'); symlinkSync(m.target, m.path) }",
  "    else if (m.action === 'unlink') unlinkSync(m.path)",
  '    mutated = true',
  '  }',
  '  appendFileSync(logPath, JSON.stringify({ kind, method, url, body, mutated }) + "\\n")',
  '  const reply = scenario[kind]',
  "  if (!reply) throw new Error('fetch stub: unexpected ' + kind + ' call')",
  "  if (reply.throw === 'abort') throw new DOMException('This operation was aborted', 'AbortError')",
  "  if (reply.throw === 'network') throw new TypeError('fetch failed')",
  "  const text = reply.body === undefined ? null : typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body)",
  "  return new Response(text, { status: reply.status ?? 200, headers: { 'content-type': 'application/json' } })",
  '}',
  '',
].join('\n')

interface Reply {
  status?: number
  body?: unknown
  throw?: 'network' | 'abort'
}
interface Scenario {
  token?: Reply
  message?: Reply
  forward?: Reply
  mutate?: { action: 'rewrite' | 'symlink' | 'unlink'; path: string; content?: string; target?: string }
}
interface FetchCall {
  kind: string
  method: string
  url: string
  body: string | null
  mutated: boolean
}
interface CliRun {
  status: number | null
  signal: NodeJS.Signals | null
  stdout: string
  stderr: string
  calls: FetchCall[]
}

const TOKEN_OK: Reply = { status: 200, body: { access_token: FAKE_TOKEN, token_type: 'Bearer', expires_in: 3600 } }
const msgReply = (subject: unknown): Reply => ({ status: 200, body: { id: ID, subject } })
const SUCCESS: Scenario = { token: TOKEN_OK, message: msgReply(SUBJECT), forward: { status: 202 } }

const STUB = join(BASE, 'fetch-stub.mjs')
writeFileSync(STUB, FETCH_STUB)
const OUTPUTS: string[] = []
let runSeq = 0

/**
 * Run the CLI copy in `root`. `outbox`: the GRAPH_MAIL_OUTBOX_DIR value, or
 * null to leave it unset (the CLI then uses <root>/store/mail-outbox).
 */
function runCli(
  root: string,
  args: string[],
  outbox: string | null,
  scenario: Scenario = {},
  timeout = 60_000,
): CliRun {
  const n = ++runSeq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    // JSON logger lines on stdout, written synchronously: KE4/E8 grep them too.
    NODE_ENV: 'production',
    MARVEEN_MAIL_CREDS: CREDS,
    GF_FETCH_SCENARIO: scenarioPath,
    GF_FETCH_LOG: logPath,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(STUB).href}`.trim(),
  }
  delete env[OUTBOX_ENV]
  if (outbox !== null) env[OUTBOX_ENV] = outbox
  const r = spawnSync(TSX, [join(root, CLI_REL), ...args], { cwd: root, env, encoding: 'utf-8', timeout })
  const calls = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FetchCall)
    : []
  OUTPUTS.push(`${r.stdout}\n${r.stderr}`)
  return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, calls }
}

const cliLines = (stdout: string): string[] => stdout.split('\n').filter((l) => l !== '' && !l.startsWith('{'))
const kinds = (r: CliRun): string[] => r.calls.map((c) => c.kind)
const postedComment = (r: CliRun): unknown => {
  const post = r.calls.find((c) => c.kind === 'forward')
  return post?.body ? (JSON.parse(post.body) as { comment?: unknown }).comment : undefined
}
const fileArgs = (path: string, hex: string): string[] => [
  'forward',
  '--id',
  ID,
  '--to',
  TO,
  '--comment-file',
  path,
  '--comment-sha256',
  hex,
  '--orig-subject',
  SUBJECT,
]

// --- checkout roots for E6/KE2 -------------------------------------------------
//
// The real hooks of the worktree are copied as they are. The variant line that
// sets or removes FORWARD_COMMENT_FILE in the extractor copy is TEST-ONLY.

type ExtractVariant = 'file' | 'no-file' | 'bool' | 'two'

const VARIANT_LINE: Record<ExtractVariant, string> = {
  file: 'FORWARD_COMMENT_FILE = 1',
  'no-file': 'globals().pop("FORWARD_COMMENT_FILE", None)',
  bool: 'FORWARD_COMMENT_FILE = True',
  two: 'FORWARD_COMMENT_FILE = 2',
}

function makeCheckout(extract: ExtractVariant = 'file'): string {
  const root = realpathSync(mkdtempSync(join(BASE, 'co-')))
  const hooks = join(root, 'scripts', 'hooks')
  mkdirSync(hooks, { recursive: true })
  mkdirSync(join(root, '.claude'))
  mkdirSync(join(root, 'store'))
  copyFileSync(join(REPO, CLI_REL), join(root, CLI_REL))
  // card efa58ad2: the CLI asks the send authorizer of ITS checkout; these runs use an allow stub.
  writeFileSync(join(hooks, 'email_send_authorize.py'), STUB_HELPER)
  copyFileSync(join(REPO, 'package.json'), join(root, 'package.json'))
  symlinkSync(join(REPO, 'src'), join(root, 'src'))
  symlinkSync(join(REPO, 'node_modules'), join(root, 'node_modules'))

  copyFileSync(join(REPO, 'scripts', 'hooks', 'outgoing-copy-gate.py'), join(hooks, 'outgoing-copy-gate.py'))

  let ext = readFileSync(join(REPO, 'scripts', 'hooks', 'email_extract.py'), 'utf-8')
  ext += `\n# --- TEST-ONLY KE2 variant: ${extract} ---\n${VARIANT_LINE[extract]}\n`
  writeFileSync(join(hooks, 'email_extract.py'), ext)

  copyFileSync(join(REPO, '.claude', 'settings.json'), join(root, '.claude', 'settings.json'))
  return root
}

describe('graph-mail CLI, --comment-file (subprocess, stubbed fetch, fake credentials)', () => {
  let co: string

  beforeAll(() => {
    co = makeCheckout('file')
  })

  describe('usage and header (KE6)', () => {
    it('the usage shows both comment forms', () => {
      const r = runCli(co, [], null)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('forward --id <message id> --to <one @fireeng.hu address> --comment "..."')
      expect(r.stderr).toContain(
        'forward --id <message id> --to <one @fireeng.hu address> --comment-file <outbox>/<name> --comment-sha256 <hex>',
      )
      expect(r.calls).toEqual([])
    })

    it('the file header documents the file form, its root and its limits', () => {
      const head = readFileSync(join(REPO, CLI_REL), 'utf-8').split('\nimport ')[0]
      expect(head).toContain(
        'graph-mail.ts forward --id <message id> --to <one @fireeng.hu address> --comment-file <outbox>/<name> --comment-sha256 <hex>',
      )
      expect(head).toContain('<repo>/store/mail-outbox')
      expect(head).toContain('16384 bytes')
      expect(head).toContain('reads it exactly once')
    })
  })

  describe('a good file forward (KE1, KE3)', () => {
    it('exit 0, the usual result line, token -> GET -> POST, and the POST comment is the file text exactly', () => {
      const root = newRoot()
      const text = 'Szia Kovács Béla!\n\nGyuri most úton van, ezért továbbítom neked ezt a levelet.\n\tJavasolt válasz:\n\tKöszönjük, hétfőn jelentkezünk.\n'
      const path = put(root, '20261018-213000-kovacs.txt', text)
      const r = runCli(co, fileArgs(path, sha(text)), root, SUCCESS)
      expect(r.status).toBe(0)
      expect(cliLines(r.stdout)).toEqual([`forwarded ${ID.slice(0, 16)}... "${SUBJECT}" -> ${TO}`])
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
      expect(r.calls[2].url).toBe(`${GRAPH}/users/${MAILBOX_ENC}/messages/${encodeURIComponent(ID)}/forward`)
      expect(postedComment(r)).toBe(text)
      expect(JSON.parse(r.calls[2].body as string)).toEqual({
        comment: text,
        toRecipients: [{ emailAddress: { address: TO } }],
      })
    })

    it('KE1: the file changed in place after the read: the POST still carries what was read and hashed', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const r = runCli(co, fileArgs(path, SZIA_SHA), root, {
        ...SUCCESS,
        mutate: { action: 'rewrite', path, content: 'Szia! Ezt senki nem hagyta jóvá.' },
      })
      expect(r.status).toBe(0)
      expect(r.calls.find((c) => c.kind === 'message')?.mutated).toBe(true)
      expect(readFileSync(path, 'utf-8')).toBe('Szia! Ezt senki nem hagyta jóvá.')
      expect(postedComment(r)).toBe(SZIA)
    })

    it('KE1: the file swapped for a symlink after the read: the POST still carries what was read', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const evil = put(newRoot(), 'evil.txt', 'Szia! Más szöveg.')
      const r = runCli(co, fileArgs(path, SZIA_SHA), root, { ...SUCCESS, mutate: { action: 'symlink', path, target: evil } })
      expect(r.status).toBe(0)
      expect(r.calls.find((c) => c.kind === 'message')?.mutated).toBe(true)
      expect(postedComment(r)).toBe(SZIA)
    })

    it('KE1: the file deleted after the read: the POST still carries what was read', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const r = runCli(co, fileArgs(path, SZIA_SHA), root, { ...SUCCESS, mutate: { action: 'unlink', path } })
      expect(r.status).toBe(0)
      expect(existsSync(path)).toBe(false)
      expect(postedComment(r)).toBe(SZIA)
    })
  })

  describe('KA through the CLI: exit 2, not a single fetch (KE5)', () => {
    it.each(CASES.comment_file_argv.map((c) => [c.name, c] as const))('%s', (_name, c) => {
      const root = newRoot()
      put(root, 'a.txt', SZIA)
      const r = runCli(co, ['forward', ...c.argv.map((a) => sub(a, root))], root, SUCCESS)
      if (c.expect === 'ok') {
        expect(r.status).toBe(0)
        expect(kinds(r)).toEqual(['token', 'message', 'forward'])
        expect(postedComment(r)).toBe(SZIA)
      } else {
        expect(r.status).toBe(2)
        expect(r.stderr).toContain('Nothing was sent')
        expect(r.calls).toEqual([])
      }
    })

    it.each(CASES.comment_file_paths.map((c) => [c.name, c] as const))('path %s', (_name, c) => {
      const root = newRoot()
      const path = sub(c.path, root)
      if (c.expect === 'ok') put(root, path.slice(root.length + 1), SZIA)
      const r = runCli(co, fileArgs(path, SZIA_SHA), root, SUCCESS)
      if (c.expect === 'ok') {
        expect(r.status).toBe(0)
        expect(postedComment(r)).toBe(SZIA)
      } else {
        expect(r.status).toBe(2)
        expect(r.calls).toEqual([])
      }
    })

    it.each([
      ['empty', ''],
      ['relative', 'store/mail-outbox'],
      ['trailing slash', 'TRAILING'],
      ['space', '/private/tmp/a b'],
    ])('GRAPH_MAIL_OUTBOX_DIR %s: exit 2, no fetch', (_label, value) => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const outbox = value === 'TRAILING' ? `${root}/` : value
      const r = runCli(co, fileArgs(path, SZIA_SHA), outbox, SUCCESS)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('outbox root is not a plain absolute path')
      expect(r.calls).toEqual([])
    })
  })

  describe('KB through the CLI: exit 2, not a single fetch (KB10, KE5)', () => {
    it.each(CASES.comment_file_contents.map((c) => [c.name, c] as const))('content %s', (_name, c) => {
      const root = newRoot()
      const bytes = contentBytes(c)
      const path = put(root, 'a.txt', bytes)
      const r = runCli(co, fileArgs(path, c.sha256), root, SUCCESS)
      if (c.expect === 'ok') {
        expect(r.status).toBe(0)
        // KE3: character for character, LF, TAB and accents intact
        expect(postedComment(r)).toBe(c.text ?? bytes.toString('utf-8'))
      } else {
        expect(r.status).toBe(2)
        expect(r.stderr).toContain('forward: --comment-file refused: ')
        expect(r.stderr).toMatch(DENY_REASON[c.rule])
        expect(r.calls).toEqual([])
      }
    })

    it.each(CASES.comment_file_kinds.map((c) => [c.name, c] as const))(
      'kind %s',
      (_name, c) => {
        const s = setupKind(c.kind)
        const r = runCli(co, fileArgs(s.path, SZIA_SHA), s.root, SUCCESS, FIFO_TIMEOUT_MS)
        expect(r.signal, 'the CLI hung and was killed').toBeNull()
        if (c.expect === 'ok') {
          expect(r.status).toBe(0)
          expect(postedComment(r)).toBe(SZIA)
        } else {
          expect(r.status).toBe(2)
          // the reader's message, inside the CLI's "refused: <msg>. Nothing was sent." line
          expect(r.stderr).toMatch(new RegExp(KIND_REASON[c.kind].source.replace(/^\^/, '').replace(/\$$/, '')))
          expect(r.stderr).toContain('Nothing was sent.')
          expect(r.calls).toEqual([])
        }
        s.after?.()
      },
      20_000,
    )

    it('a hash mismatch: exit 2, both 16-digit prefixes, no fetch', () => {
      const root = newRoot()
      const path = put(root, 'a.txt', SZIA)
      const wrong = sha('Szia!!')
      const r = runCli(co, fileArgs(path, wrong), root, SUCCESS)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain(`expected ${wrong.slice(0, 16)}..., the file has ${SZIA_SHA.slice(0, 16)}...`)
      expect(r.calls).toEqual([])
    })
  })

  describe('KF1/KF2: the default root comes from the CLI location', () => {
    it('no env: <checkout>/store/mail-outbox missing -> exit 2 with the KF2 text, and it is not created', () => {
      const c2 = makeCheckout('file')
      const def = join(c2, 'store', 'mail-outbox')
      const r = runCli(c2, fileArgs(join(def, 'a.txt'), SZIA_SHA), null, SUCCESS)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain(`a kimenő-mappa hiányzik (${def}); egyszer létre kell hozni 0700-as joggal`)
      expect(r.calls).toEqual([])
      expect(existsSync(def)).toBe(false)
    })

    it('no env: a file in <checkout>/store/mail-outbox (0700) goes out; a file in another valid root does not', () => {
      const c2 = makeCheckout('file')
      const def = join(c2, 'store', 'mail-outbox')
      mkdirSync(def, { mode: 0o700 })
      const ok = runCli(c2, fileArgs(put(def, 'a.txt', SZIA), SZIA_SHA), null, SUCCESS)
      expect(ok.status).toBe(0)
      expect(postedComment(ok)).toBe(SZIA)
      const elsewhere = put(newRoot(), 'a.txt', SZIA)
      const no = runCli(c2, fileArgs(elsewhere, SZIA_SHA), null, SUCCESS)
      expect(no.status).toBe(2)
      expect(no.stderr).toContain(`--comment-file must be ${def}/<name>`)
      expect(no.calls).toEqual([])
    })
  })

  describe('KE2: the gate must know --comment-file (checked before any network call)', () => {
    it.each([['no-file'], ['bool'], ['two']] as const)(
      'extractor variant %s: the file form exits 2, the inline form still works',
      (variant) => {
        const c2 = makeCheckout(variant)
        const root = newRoot()
        const path = put(root, 'a.txt', SZIA)
        const r = runCli(c2, fileArgs(path, SZIA_SHA), root, SUCCESS)
        expect(r.status).toBe(2)
        expect(r.stderr).toContain(
          'forward: a kapu nem ismeri a --comment-file-t (email_extract.py does not export FORWARD_COMMENT_FILE = 1). Nothing was sent.',
        )
        expect(r.calls).toEqual([])
        const inline = runCli(
          c2,
          ['forward', '--id', ID, '--to', TO, '--comment', SZIA, '--orig-subject', SUBJECT],
          root,
          SUCCESS,
        )
        expect(inline.status).toBe(0)
        expect(postedComment(inline)).toBe(SZIA)
      },
    )

    it('the gate check comes before the file: a missing file in an unknowing checkout says "gate", not "file"', () => {
      const c2 = makeCheckout('no-file')
      const root = newRoot()
      const r = runCli(c2, fileArgs(join(root, 'a.txt'), SZIA_SHA), root, SUCCESS)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('a kapu nem ismeri a --comment-file-t')
      expect(r.stderr).not.toContain('does not exist')
    })
  })

  describe('KE4: the comment never shows up in the output', () => {
    const MARK_HEAD = 'MARKERHEAD7q2'
    const MARK_TAIL = 'MARKERTAIL9z4'
    const body = `${MARK_HEAD} Szia Andi! ${'Gyuri most úton van, ezért továbbítom neked. '.repeat(6)}${MARK_TAIL} Köszönöm!\n`

    it('the markers sit at the start and after the 200th character', () => {
      expect(body.indexOf(MARK_HEAD)).toBe(0)
      expect(body.indexOf(MARK_TAIL)).toBeGreaterThan(200)
    })

    it.each([
      ['success', 'good', SUCCESS, 0],
      ['hash mismatch', 'wrong-hash', SUCCESS, 2],
      ['forbidden character', 'zwsp', SUCCESS, 2],
      ['subject mismatch', 'good', { ...SUCCESS, message: msgReply('Más tárgy') }, 2],
      ['GET 404', 'good', { ...SUCCESS, message: { status: 404, body: { error: { code: 'ErrorItemNotFound' } } } }, 1],
      ['POST 500', 'good', { ...SUCCESS, forward: { status: 500, body: { error: { code: 'ErrorInternalServerError' } } } }, 1],
      ['POST network error', 'good', { ...SUCCESS, forward: { throw: 'network' } }, 3],
    ] as const)('%s: the expected exit code, no marker on stdout or stderr', (_label, file, scenario, code) => {
      const root = newRoot()
      const text = file === 'zwsp' ? `${body}${cp(0x200b)}` : body
      const path = put(root, 'a.txt', text)
      const hex = file === 'wrong-hash' ? sha(`${text}x`) : sha(text)
      const r = runCli(co, fileArgs(path, hex), root, scenario as Scenario)
      expect(r.status).toBe(code)
      for (const out of [r.stdout, r.stderr]) {
        expect(out).not.toContain(MARK_HEAD)
        expect(out).not.toContain(MARK_TAIL)
        expect(out).not.toContain('Gyuri most')
      }
      if (code === 0) expect(postedComment(r)).toBe(text)
    })
  })

  describe('E8: no credential in any output', () => {
    it('no CLI run printed the client secret or the access token (stdout + stderr, logger included)', () => {
      expect(OUTPUTS.length).toBeGreaterThan(80)
      expect(OUTPUTS.some((o) => o.includes('graph-mail: forwarded'))).toBe(true)
      expect(OUTPUTS.filter((o) => o.includes(FAKE_SECRET) || o.includes(FAKE_TOKEN))).toEqual([])
    })
  })
})
