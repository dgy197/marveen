import { describe, it, expect, beforeAll, afterAll, afterEach, vi } from 'vitest'
import {
  chmodSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawnSync } from 'node:child_process'
import { STUB_HELPER } from './graph-cli-root.js'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import {
  isForwardRecipient,
  isGraphMessageId,
  parseForwardArgv,
  parseShowArgv,
  quoteForDisplay,
} from '../graph-forward-validate.js'

// graph-mail `forward`, `show` and `list` + id (card graph-forward, Brainy 2958,
// node N3; spec D1-D3, E1-E9). Two layers:
//   - in-process: the pure validators on the shared vector file, and
//     getMessage/forwardMail with a stubbed global fetch;
//   - the real CLI as a subprocess (tsx), with a preloaded fetch stub that
//     answers from a scenario file and records every call. No socket is
//     opened anywhere, and the credentials are a throwaway file.
// No real credentials file, no Vault, no network.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const CLI_REL = join('scripts', 'graph-mail.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const GRAPH = 'https://graph.microsoft.com/v1.0'

interface Cases {
  recipients: { accept: string[]; reject: string[] }
  ids: { accept: string[]; reject: string[]; path_encoding: Array<{ id: string; encoded: string }> }
  argv: Array<{ name: string; argv: string[]; expect: 'ok' | 'exit2'; rule: string }>
}
const CASES = JSON.parse(readFileSync(join(REPO, 'scripts', 'hooks', 'graph-forward-cases.json'), 'utf-8')) as Cases

// Fake secrets: E8 greps every output for these two strings.
const FAKE_SECRET = `FAKE-gf-client-secret-${'q7x9'.repeat(4)}`
const FAKE_TOKEN = `FAKE-gf-access-token-${'z3k1'.repeat(4)}`
const MAILBOX = 'gf-test-box@example.invalid'
const MAILBOX_ENC = encodeURIComponent(MAILBOX)

const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const ID_ENC = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ%3D%3D'
const TO = 'kovacs@fireeng.hu'
const SUBJECT = 'Tárgy'
const COMMENT = 'Szia! Kérlek, nézd meg.'
const OK_ARGS = ['--id', ID, '--to', TO, '--comment', COMMENT, '--orig-subject', SUBJECT]

const cp = (...codes: number[]): string => String.fromCodePoint(...codes)

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'gf-n3-test-')))
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

// ---------------------------------------------------------------------------
// D1, D2: recipient validator on the shared vectors
// ---------------------------------------------------------------------------

describe('isForwardRecipient (D1, D2: shared vectors)', () => {
  it('the vector file carries the spec D2 list (5 accept, 40 reject, 64/65-char local parts)', () => {
    expect(CASES.recipients.accept).toHaveLength(5)
    expect(CASES.recipients.reject).toHaveLength(40)
    expect(CASES.recipients.accept.some((a) => a.split('@')[0].length === 64)).toBe(true)
    expect(CASES.recipients.reject.some((a) => a.split('@')[0].length === 65)).toBe(true)
  })

  it.each(CASES.recipients.accept)('accepts %j', (addr) => {
    expect(isForwardRecipient(addr)).toBe(true)
  })

  it.each(CASES.recipients.reject)('rejects %j', (addr) => {
    expect(isForwardRecipient(addr)).toBe(false)
  })

  it('rejects non-strings, CR, and non-ASCII letters that case-fold onto ASCII', () => {
    for (const v of [undefined, null, 42, ['a@fireeng.hu'], { a: 1 }]) expect(isForwardRecipient(v)).toBe(false)
    expect(isForwardRecipient('a@fireeng.hu\r')).toBe(false)
    // U+0130 (I with dot above) lowercases to "i" + a combining dot
    expect(isForwardRecipient(`a@f${cp(0x130)}reeng.hu`)).toBe(false)
    expect(isForwardRecipient(`a@fireeng.h${cp(0x16b)}`)).toBe(false)
    expect(isForwardRecipient('A_B@Fireeng.hU')).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// E2: message id
// ---------------------------------------------------------------------------

describe('isGraphMessageId (E2: shared vectors)', () => {
  it('the bounds are 16..512 characters', () => {
    const lens = (xs: string[]) => xs.map((x) => x.length)
    expect(lens(CASES.ids.accept)).toEqual(expect.arrayContaining([16, 512]))
    expect(lens(CASES.ids.reject)).toEqual(expect.arrayContaining([15, 513]))
  })

  it.each(CASES.ids.accept.map((id) => [id.length > 40 ? `${id.slice(0, 20)}..(${id.length})` : id, id]))(
    'accepts %s',
    (_label, id) => {
      expect(isGraphMessageId(id)).toBe(true)
    },
  )

  it.each(CASES.ids.reject.map((id) => [JSON.stringify(id.length > 40 ? `${id.slice(0, 20)}..(${id.length})` : id), id]))(
    'rejects %s',
    (_label, id) => {
      expect(isGraphMessageId(id)).toBe(false)
    },
  )

  it.each(CASES.ids.path_encoding)('path form of $id is $encoded', ({ id, encoded }) => {
    expect(encodeURIComponent(id)).toBe(encoded)
  })
})

// ---------------------------------------------------------------------------
// E1: argv parser
// ---------------------------------------------------------------------------

describe('parseForwardArgv (E1 + D1, E2, B5 on the shared argv vectors)', () => {
  it.each(CASES.argv.map((c) => [c.name, c] as const))('%s', (_name, c) => {
    const r = parseForwardArgv(c.argv)
    expect(r.ok).toBe(c.expect === 'ok')
    if (r.ok) {
      const at = (flag: string) => c.argv[c.argv.indexOf(flag) + 1]
      expect(r.value).toEqual({
        id: at('--id'),
        to: at('--to'),
        comment: at('--comment'),
        origSubject: at('--orig-subject'),
      })
    }
  })

  it('takes the values verbatim (no trim) and refuses a value that is itself a flag', () => {
    const r = parseForwardArgv(['--id', ID, '--to', TO, '--comment', ' x ', '--orig-subject', ` ${SUBJECT} `])
    expect(r).toEqual({ ok: true, value: { id: ID, to: TO, comment: ' x ', origSubject: ` ${SUBJECT} ` } })
    expect(parseForwardArgv(['--id', ID, '--to', TO, '--comment', '--x', '--orig-subject', SUBJECT]).ok).toBe(false)
    expect(parseForwardArgv(['--id', ID, '--to', TO, '--comment', 'x', '--orig-subject', SUBJECT, '--']).ok).toBe(false)
    expect(parseForwardArgv(['--__proto__', 'x', ...OK_ARGS]).ok).toBe(false)
  })

  it('parseShowArgv takes exactly --id <id>', () => {
    expect(parseShowArgv(['--id', ID])).toEqual({ ok: true, value: { id: ID } })
    for (const argv of [[], ['--id'], ['--id', '../x'], [ID], ['--id', ID, 'x'], ['--id=' + ID], ['--to', ID]]) {
      expect(parseShowArgv(argv).ok).toBe(false)
    }
  })
})

describe('quoteForDisplay', () => {
  it('keeps accented letters readable and stays valid JSON', () => {
    expect(quoteForDisplay(SUBJECT)).toBe(`"${SUBJECT}"`)
    expect(quoteForDisplay('a"b\\c\nd')).toBe('"a\\"b\\\\c\\nd"')
  })

  it('escapes every invisible or reordering character, and JSON.parse gives back the original', () => {
    const tricky = [
      `a${cp(0x200b)}b`, // zero-width space
      `a${cp(0x202e)}b`, // right-to-left override
      `a${cp(0x7f)}b`, // DEL
      `a${cp(0x9b)}b`, // C1 CSI
      `a${cp(0x2028)}b`, // line separator
      `a${cp(0xad)}b`, // soft hyphen
      `a${cp(0xfeff)}b`, // BOM
      `a${cp(0xe0041)}b`, // tag character (astral)
      `a${cp(0x1b)}[31mb`, // ESC
    ]
    for (const s of tricky) {
      const q = quoteForDisplay(s)
      expect(JSON.parse(q)).toBe(s)
      expect(q).toMatch(/^"[\x20-\x7e]*"$/)
    }
    expect(quoteForDisplay(`x${cp(0x202e)}`)).toBe('"x\\u202e"')
    expect(quoteForDisplay(`x${cp(0xe0041)}`)).toBe('"x\\udb40\\udc41"')
  })
})

// ---------------------------------------------------------------------------
// getMessage / forwardMail in-process, global fetch stubbed (E2, E3, E4, E5, E8)
// ---------------------------------------------------------------------------

interface Call {
  url: string
  method: string
  auth: string | null
  body: string | null
}

describe('getMessage / forwardMail (stubbed fetch)', () => {
  let gm: typeof import('../graph-mail.js')
  let loggerMod: typeof import('../logger.js')
  let calls: Call[] = []
  const logged: string[] = []

  /** Install a fetch stub: the token endpoint always answers, graph calls go to `graph`. */
  function stubFetch(graph: (call: Call) => Response | Promise<Response>): void {
    calls = []
    vi.stubGlobal('fetch', async (input: unknown, init: RequestInit = {}) => {
      const url = String(input)
      const method = String(init.method ?? 'GET').toUpperCase()
      if (url.startsWith('https://login.microsoftonline.com/')) {
        return new Response(JSON.stringify({ access_token: FAKE_TOKEN, expires_in: 3600 }), { status: 200 })
      }
      const call: Call = {
        url,
        method,
        auth: new Headers(init.headers ?? {}).get('authorization'),
        body: typeof init.body === 'string' ? init.body : null,
      }
      calls.push(call)
      return graph(call)
    })
  }

  beforeAll(async () => {
    // CREDS_PATH is read when the module loads, so the env goes first.
    process.env.MARVEEN_MAIL_CREDS = CREDS
    gm = await import('../graph-mail.js')
    loggerMod = await import('../logger.js')
    for (const level of ['info', 'warn', 'error', 'debug'] as const) {
      vi.spyOn(loggerMod.logger, level).mockImplementation(((...args: unknown[]) => {
        logged.push(JSON.stringify(args))
      }) as never)
    }
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  afterAll(() => {
    vi.restoreAllMocks()
  })

  it.each(CASES.ids.path_encoding)('E4: forward POST goes to the encoded path of $id with the exact body', async ({ id, encoded }) => {
    stubFetch(() => new Response(null, { status: 202 }))
    await gm.forwardMail({ id, to: TO, comment: COMMENT })
    expect(calls).toHaveLength(1)
    expect(calls[0].method).toBe('POST')
    expect(calls[0].url).toBe(`${GRAPH}/users/${MAILBOX_ENC}/messages/${encoded}/forward`)
    expect(calls[0].body).toBe(
      `{"comment":${JSON.stringify(COMMENT)},"toRecipients":[{"emailAddress":{"address":"${TO}"}}]}`,
    )
    expect(calls[0].auth).toBe(`Bearer ${FAKE_TOKEN}`)
  })

  it('D3: the recipient goes to Graph unchanged (case kept, no trim)', async () => {
    stubFetch(() => new Response(null, { status: 202 }))
    await gm.forwardMail({ id: ID, to: 'Kovacs.Bela@FIREENG.HU', comment: 'x' })
    expect(JSON.parse(calls[0].body as string).toRecipients).toEqual([
      { emailAddress: { address: 'Kovacs.Bela@FIREENG.HU' } },
    ])
  })

  it('refuses a bad recipient, a bad id or a blank comment before any request', async () => {
    stubFetch(() => new Response(null, { status: 202 }))
    await expect(gm.forwardMail({ id: ID, to: 'a@evil.com', comment: 'x' })).rejects.toThrow(/recipient/)
    await expect(gm.forwardMail({ id: ID, to: `${TO},b@fireeng.hu`, comment: 'x' })).rejects.toThrow(/recipient/)
    await expect(gm.forwardMail({ id: '../x', to: TO, comment: 'x' })).rejects.toThrow(/message id/)
    await expect(gm.forwardMail({ id: ID, to: TO, comment: ' \n ' })).rejects.toThrow(/empty comment/)
    await expect(gm.getMessage('../xxxxxxxxxxxxxxxxxx')).rejects.toThrow(/message id/)
    await expect(gm.getMessage(ID, ['subject', 'body' as never])).rejects.toThrow(/\$select/)
    expect(calls).toHaveLength(0)
  })

  it.each([401, 403, 404, 500])('E5: a %i answer throws GraphRequestError once, without the body and without retry', async (status) => {
    stubFetch(
      () =>
        new Response(JSON.stringify({ error: { code: 'ErrorAccessDenied', message: `echo ${FAKE_TOKEN} ${FAKE_SECRET}` } }), {
          status,
        }),
    )
    const err = await gm.forwardMail({ id: ID, to: TO, comment: COMMENT }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(gm.GraphRequestError)
    expect((err as InstanceType<typeof gm.GraphRequestError>).status).toBe(status)
    expect((err as Error).message).toBe(`graph-mail: forward failed (${status} ErrorAccessDenied)`)
    expect(calls).toHaveLength(1)
  })

  it('E5: a non-identifier error code is not passed on', async () => {
    stubFetch(() => new Response(JSON.stringify({ error: { code: `x ${FAKE_TOKEN}\n` } }), { status: 400 }))
    await expect(gm.forwardMail({ id: ID, to: TO, comment: COMMENT })).rejects.toThrow('(400 unknown)')
    stubFetch(() => new Response('not json', { status: 502 }))
    await expect(gm.forwardMail({ id: ID, to: TO, comment: COMMENT })).rejects.toThrow('(502 unknown)')
  })

  it.each([
    ['network error', () => Promise.reject(new TypeError('fetch failed'))],
    ['abort', () => Promise.reject(new DOMException('This operation was aborted', 'AbortError'))],
  ] as const)('E5: %s on the POST is ForwardOutcomeUnknownError, sent once', async (_label, fail) => {
    stubFetch(fail)
    const err = await gm.forwardMail({ id: ID, to: TO, comment: COMMENT }).catch((e: unknown) => e)
    expect(err).toBeInstanceOf(gm.ForwardOutcomeUnknownError)
    expect(calls).toHaveLength(1)
  })

  it('E3: getMessage selects id,subject by default, and the show fields on request', async () => {
    stubFetch(() => new Response(JSON.stringify({ id: ID, subject: SUBJECT }), { status: 200 }))
    expect(await gm.getMessage(ID)).toEqual({ id: ID, subject: SUBJECT })
    await gm.getMessage(ID, ['id', 'subject', 'from', 'receivedDateTime', 'hasAttachments'])
    expect(calls.map((c) => [c.method, c.url])).toEqual([
      ['GET', `${GRAPH}/users/${MAILBOX_ENC}/messages/${ID_ENC}?$select=id,subject`],
      ['GET', `${GRAPH}/users/${MAILBOX_ENC}/messages/${ID_ENC}?$select=id,subject,from,receivedDateTime,hasAttachments`],
    ])
  })

  it('getMessage: a 404 is a GraphRequestError with the Graph code only', async () => {
    stubFetch(() => new Response(JSON.stringify({ error: { code: 'ErrorItemNotFound', message: FAKE_TOKEN } }), { status: 404 }))
    await expect(gm.getMessage(ID)).rejects.toThrow('graph-mail: getMessage failed (404 ErrorItemNotFound)')
  })

  it('E8: the logger saw the forward, and no logged line carries the secret or the token', () => {
    expect(logged.some((l) => l.includes('graph-mail: forwarded'))).toBe(true)
    expect(logged.some((l) => l.includes(`"messageId":"${ID.slice(0, 16)}..."`))).toBe(true)
    for (const l of logged) {
      expect(l).not.toContain(FAKE_SECRET)
      expect(l).not.toContain(FAKE_TOKEN)
    }
  })
})

// ---------------------------------------------------------------------------
// The CLI as a subprocess (E1-E9)
// ---------------------------------------------------------------------------

// Preloaded into the CLI process: replaces global fetch, answers from the
// scenario file, records every call (the token request's body is not recorded).
const FETCH_STUB = [
  "import { appendFileSync, readFileSync } from 'node:fs'",
  "const scenario = JSON.parse(readFileSync(process.env.GF_FETCH_SCENARIO, 'utf8'))",
  'const logPath = process.env.GF_FETCH_LOG',
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/forward')) kind = 'forward'",
  "  else if (method === 'GET' && url.includes('/mailFolders/')) kind = 'list'",
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  const auth = new Headers(init.headers || {}).get('authorization')",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  "  appendFileSync(logPath, JSON.stringify({ kind, method, url, auth, body }) + '\\n')",
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
  list?: Reply
}
interface FetchCall {
  kind: string
  method: string
  url: string
  auth: string | null
  body: string | null
}
interface CliRun {
  status: number | null
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

function runCli(root: string, args: string[], scenario: Scenario = {}, extraEnv: Record<string, string> = {}): CliRun {
  const n = ++runSeq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    // JSON logger lines on stdout, written synchronously: E8 greps them too.
    NODE_ENV: 'production',
    MARVEEN_MAIL_CREDS: CREDS,
    GF_FETCH_SCENARIO: scenarioPath,
    GF_FETCH_LOG: logPath,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(STUB).href}`.trim(),
    ...extraEnv,
  }
  const r = spawnSync(TSX, [join(root, CLI_REL), ...args], { cwd: root, env, encoding: 'utf-8', timeout: 60_000 })
  const calls = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FetchCall)
    : []
  OUTPUTS.push(`${r.stdout}\n${r.stderr}`)
  return { status: r.status, stdout: r.stdout, stderr: r.stderr, calls }
}

/** stdout without the JSON logger lines: what the CLI itself printed. */
const cliLines = (stdout: string): string[] => stdout.split('\n').filter((l) => l !== '' && !l.startsWith('{'))
const kinds = (r: CliRun): string[] => r.calls.map((c) => c.kind)
/** stderr without Node's own runtime warnings (tsx on this Node prints a module.register() deprecation). */
const ownStderr = (stderr: string): string[] =>
  stderr.split('\n').filter((l) => l !== '' && !/^\(node:\d+\) /.test(l) && !l.startsWith('(Use `node --trace-'))

// --- checkout roots for E6 -----------------------------------------------------
//
// `real` copies the worktree's own hooks (they know `forward`). `old` is a copy
// of a hook from before the forward support: a TEST-ONLY override appended to
// the real file makes the copy gate stop classifying forward as a send, or the
// extractor stop building the `forward` field.

type HookVariant = 'old' | 'real' | 'missing'
type SettingsVariant = 'real' | 'no-copy-gate' | 'no-approval-gate' | 'missing' | 'invalid'

const OLD_COPY_GATE = [
  '',
  '# --- TEST-ONLY: a classifier from before the forward support (graph-mail-forward.test.ts) ---',
  '_gf_orig_is_send = is_send_invocation',
  'def is_send_invocation(cmd, *a, **k):',
  '    if "forward" in str(cmd):',
  '        return False',
  '    return _gf_orig_is_send(cmd, *a, **k)',
  '',
].join('\n')
const OLD_EXTRACT = [
  '',
  '# --- TEST-ONLY: an extractor from before the forward field (graph-mail-forward.test.ts) ---',
  '_gf_orig_collect = collect_email_envelope',
  'def collect_email_envelope(tool_name, tool_input):',
  '    env = _gf_orig_collect(tool_name, tool_input)',
  '    if isinstance(env, dict):',
  '        env.pop("forward", None)',
  '    return env',
  '',
].join('\n')

function makeRoot(copyGate: HookVariant, extract: HookVariant, settings: SettingsVariant): string {
  const root = realpathSync(mkdtempSync(join(BASE, 'root-')))
  const hooks = join(root, 'scripts', 'hooks')
  mkdirSync(hooks, { recursive: true })
  mkdirSync(join(root, '.claude'))
  // An existing store/, so a copy-gate log line WOULD land here if the probe wrote one.
  mkdirSync(join(root, 'store'))
  copyFileSync(join(REPO, CLI_REL), join(root, CLI_REL))
  // card efa58ad2: the CLI asks the send authorizer of ITS checkout; these runs use an allow stub.
  writeFileSync(join(hooks, 'email_send_authorize.py'), STUB_HELPER)
  copyFileSync(join(REPO, 'package.json'), join(root, 'package.json'))
  symlinkSync(join(REPO, 'src'), join(root, 'src'))
  symlinkSync(join(REPO, 'node_modules'), join(root, 'node_modules'))

  if (copyGate !== 'missing') {
    const src = readFileSync(join(REPO, 'scripts', 'hooks', 'outgoing-copy-gate.py'), 'utf-8')
    writeFileSync(join(hooks, 'outgoing-copy-gate.py'), copyGate === 'old' ? src + OLD_COPY_GATE : src)
  }
  if (extract !== 'missing') {
    const src = readFileSync(join(REPO, 'scripts', 'hooks', 'email_extract.py'), 'utf-8')
    writeFileSync(join(hooks, 'email_extract.py'), extract === 'old' ? src + OLD_EXTRACT : src)
  }

  const settingsPath = join(root, '.claude', 'settings.json')
  if (settings === 'invalid') writeFileSync(settingsPath, '{ "hooks": ')
  else if (settings !== 'missing') {
    const json = JSON.parse(readFileSync(join(REPO, '.claude', 'settings.json'), 'utf-8')) as {
      hooks: { PreToolUse: Array<{ matcher?: string; hooks: Array<{ command: string }> }> }
    }
    const drop = settings === 'no-copy-gate' ? 'outgoing-copy-gate.py' : settings === 'no-approval-gate' ? 'email-approval-gate.py' : null
    if (drop) {
      for (const entry of json.hooks.PreToolUse) {
        if (entry.matcher === 'Bash') entry.hooks = entry.hooks.filter((h) => !h.command.includes(drop))
      }
    }
    writeFileSync(settingsPath, JSON.stringify(json, null, 2))
  }
  return root
}

describe('graph-mail CLI (subprocess, stubbed fetch, fake credentials)', () => {
  let good: string

  beforeAll(() => {
    good = makeRoot('real', 'real', 'real')
  })

  describe('usage (E9)', () => {
    it('no subcommand: exit 2, usage names show and forward', () => {
      const r = runCli(good, [])
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('<verify|list|show|send|forward>')
      expect(r.stderr).toContain('show    --id <message id>')
      expect(r.stderr).toContain('forward --id <message id> --to <one @fireeng.hu address>')
      expect(r.calls).toEqual([])
    })

    it.each([['FORWARD'], ['--'], ['fwd']])('unknown subcommand %j: exit 2, no request', (cmd) => {
      const r = runCli(good, [cmd, ...OK_ARGS], SUCCESS)
      expect(r.status).toBe(2)
      expect(r.calls).toEqual([])
    })

    it('the file header documents show and forward', () => {
      const head = readFileSync(join(REPO, CLI_REL), 'utf-8').split('\nimport ')[0]
      expect(head).toContain('graph-mail.ts show --id <message id>')
      expect(head).toContain('graph-mail.ts forward --id <message id> --to <one @fireeng.hu address>')
      expect(head).toMatch(/3 {2}the forward request got no answer: the outcome is UNKNOWN/)
    })
  })

  describe('E1: argv vectors through the real CLI', () => {
    it.each(CASES.argv.filter((c) => c.expect === 'exit2').map((c) => [c.name, c] as const))(
      'refused: %s -> exit 2, no request',
      (_name, c) => {
        const r = runCli(good, ['forward', ...c.argv], SUCCESS)
        expect(r.status).toBe(2)
        expect(r.stderr).toContain('Nothing was sent')
        expect(r.calls).toEqual([])
      },
    )

    it.each(CASES.argv.filter((c) => c.expect === 'ok').map((c) => [c.name, c] as const))(
      'accepted: %s -> forwarded',
      (_name, c) => {
        const r = runCli(good, ['forward', ...c.argv], SUCCESS)
        expect(r.status).toBe(0)
        expect(kinds(r)).toEqual(['token', 'message', 'forward'])
      },
    )
  })

  describe('E2: id through the real CLI', () => {
    const bad = ['../x', 'AAMkAGFm ZXN0MDEyMzQ1', 'A'.repeat(15), 'A'.repeat(513), `AAMkAGFmZXN0MDEyMzQ1${cp(0xe9)}`, 'AAMkAGFmZXN0MDEyMzQ1%2F']
    it.each(bad.map((id) => [JSON.stringify(id.slice(0, 30)), id]))('refused id %s -> exit 2, no request', (_l, id) => {
      const args = [...OK_ARGS]
      args[1] = id
      const r = runCli(good, ['forward', ...args], SUCCESS)
      expect(r.status).toBe(2)
      expect(r.calls).toEqual([])
    })

    it('an id with / + = is percent-encoded in both the GET and the POST path', () => {
      const id = 'AAMk/AG+Z=-_xxxxxxxxxx'
      const args = [...OK_ARGS]
      args[1] = id
      const r = runCli(good, ['forward', ...args], SUCCESS)
      expect(r.status).toBe(0)
      expect(r.calls.slice(1).map((c) => c.url)).toEqual([
        `${GRAPH}/users/${MAILBOX_ENC}/messages/AAMk%2FAG%2BZ%3D-_xxxxxxxxxx?$select=id,subject`,
        `${GRAPH}/users/${MAILBOX_ENC}/messages/AAMk%2FAG%2BZ%3D-_xxxxxxxxxx/forward`,
      ])
    })
  })

  describe('E3: subject check before the POST', () => {
    it.each([
      ['trailing space', `${SUBJECT} `, `"${SUBJECT} "`],
      ['decomposed accent (NFD)', `Ta${cp(0x301)}rgy`, null],
      ['zero-width space', `${SUBJECT}${cp(0x200b)}`, `"${SUBJECT}\\u200b"`],
      ['other case', 'tárgy', '"tárgy"'],
      ['null subject', null, 'null'],
    ] as const)('%s: exit 2, the real subject is printed JSON-quoted, no POST', (_l, actual, shown) => {
      const r = runCli(good, ['forward', ...OK_ARGS], { ...SUCCESS, message: msgReply(actual) })
      expect(r.status).toBe(2)
      expect(kinds(r)).toEqual(['token', 'message'])
      expect(r.stderr).toContain('--orig-subject does not match the message subject. Nothing was sent.')
      const line = r.stderr.split('\n').find((l) => l.startsWith('  actual subject: ')) as string
      expect(line).toBeDefined()
      const printed = line.slice('  actual subject: '.length)
      expect(JSON.parse(printed)).toBe(actual)
      if (shown !== null) expect(printed).toBe(shown)
    })
  })

  describe('E4: the forward request and the result line', () => {
    it('exact GET and POST, exact body, one result line, exit 0', () => {
      const r = runCli(good, ['forward', ...OK_ARGS], SUCCESS)
      expect(r.status).toBe(0)
      // card f90928e3 (B): the best-effort daily-log entry after the forward finds no dashboard
      // token in this world: one fixed stderr note, no request, nothing else changes.
      expect(ownStderr(r.stderr)).toEqual([
        'graph-mail: a levél elment, de a napló-bejegyzés nem készült el (cannot read dashboard token file)',
      ])
      expect(cliLines(r.stdout)).toEqual([`forwarded ${ID.slice(0, 16)}... "${SUBJECT}" -> ${TO}`])
      expect(r.calls.map((c) => [c.kind, c.method, c.url])).toEqual([
        ['token', 'POST', 'https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/oauth2/v2.0/token'],
        ['message', 'GET', `${GRAPH}/users/${MAILBOX_ENC}/messages/${ID_ENC}?$select=id,subject`],
        ['forward', 'POST', `${GRAPH}/users/${MAILBOX_ENC}/messages/${ID_ENC}/forward`],
      ])
      expect(r.calls[2].body).toBe(
        `{"comment":"${COMMENT}","toRecipients":[{"emailAddress":{"address":"${TO}"}}]}`,
      )
      expect(r.calls[1].auth).toBe(`Bearer ${FAKE_TOKEN}`)
      expect(r.calls[2].auth).toBe(`Bearer ${FAKE_TOKEN}`)
    })

    it('a multi-line accented comment and an upper-case address reach Graph unchanged', () => {
      const comment = 'Szia Andi!\nGyuri most úton van, ezért továbbítom neked ezt a levelet.\nKöszönöm!'
      const args = ['--orig-subject', SUBJECT, '--comment', comment, '--to', 'Kovacs.Bela@FIREENG.HU', '--id', ID]
      const r = runCli(good, ['forward', ...args], SUCCESS)
      expect(r.status).toBe(0)
      expect(r.calls[2].body).toBe(JSON.stringify({ comment, toRecipients: [{ emailAddress: { address: 'Kovacs.Bela@FIREENG.HU' } }] }))
      expect(cliLines(r.stdout)).toEqual([`forwarded ${ID.slice(0, 16)}... "${SUBJECT}" -> Kovacs.Bela@FIREENG.HU`])
    })
  })

  describe('E5: exit codes, no retry', () => {
    it.each([401, 403, 404, 500])('POST answered %i: exit 1, one POST', (status) => {
      const r = runCli(good, ['forward', ...OK_ARGS], {
        ...SUCCESS,
        forward: { status, body: { error: { code: 'ErrorAccessDenied', message: `echo ${FAKE_TOKEN}` } } },
      })
      expect(r.status).toBe(1)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
      expect(r.stderr).toContain(`forward failed (${status} ErrorAccessDenied)`)
      expect(r.stderr.includes('check Sent Items')).toBe(status >= 500)
      expect(cliLines(r.stdout)).toEqual([])
    })

    it.each([['network'], ['abort']] as const)('POST %s: exit 3, outcome unknown, one POST', (kind) => {
      const r = runCli(good, ['forward', ...OK_ARGS], { ...SUCCESS, forward: { throw: kind } })
      expect(r.status).toBe(3)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
      expect(r.stderr).toContain('kimenet ismeretlen: nézd meg az Elküldött elemeket, ne küldd újra vakon')
      expect(cliLines(r.stdout)).toEqual([])
    })

    it('GET network error: exit 1, no POST', () => {
      const r = runCli(good, ['forward', ...OK_ARGS], { ...SUCCESS, message: { throw: 'network' } })
      expect(r.status).toBe(1)
      expect(kinds(r)).toEqual(['token', 'message'])
    })

    it('GET 404: exit 1, no POST', () => {
      const r = runCli(good, ['forward', ...OK_ARGS], {
        ...SUCCESS,
        message: { status: 404, body: { error: { code: 'ErrorItemNotFound' } } },
      })
      expect(r.status).toBe(1)
      expect(r.stderr).toContain('getMessage failed (404 ErrorItemNotFound)')
      expect(kinds(r)).toEqual(['token', 'message'])
    })

    it('token refused (body echoes the secret): exit 1, no Graph call, secret not printed', () => {
      const r = runCli(good, ['forward', ...OK_ARGS], {
        ...SUCCESS,
        token: { status: 401, body: { error: 'invalid_client', error_description: `bad secret ${FAKE_SECRET}` } },
      })
      expect(r.status).toBe(1)
      expect(r.stderr).toContain('token request failed (401 invalid_client)')
      expect(kinds(r)).toEqual(['token'])
    })
  })

  describe('E6: gate capability, checked before any network call', () => {
    it('this checkout (the real hooks know forward): the probe passes, the forward goes out', () => {
      // `good` is a copy of this checkout's real hooks plus the allow-stub authorizer (card efa58ad2).
      const r = runCli(good, ['forward', ...OK_ARGS], SUCCESS)
      expect(r.status).toBe(0)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
    })

    it('environment variables cannot point the check at another tree', () => {
      // A decoy root whose classifier is old: if the env could redirect the probe, it would exit 2.
      const decoy = makeRoot('old', 'old', 'real')
      const r = runCli(good, ['forward', ...OK_ARGS], SUCCESS, {
        CLAUDE_PROJECT_DIR: decoy,
        PYTHONPATH: join(decoy, 'scripts', 'hooks'),
        PYTHONHOME: join(decoy, 'nope'),
        OUTGOING_COPY_GATE_RULES: join(decoy, 'rules.json'),
      })
      expect(r.status).toBe(0)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
    })

    it('the same environment does not break a checkout whose gate knows forward', () => {
      const r = runCli(good, ['forward', ...OK_ARGS], SUCCESS, {
        PYTHONPATH: join(BASE, 'nope'),
        PYTHONHOME: join(BASE, 'nope'),
      })
      expect(r.status).toBe(0)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
    })

    it.each([
      ['old classifier', 'old', 'real', 'real', 'does not classify forward as a send'],
      ['extractor without the forward field', 'real', 'old', 'real', 'does not build the forward field'],
      ['copy gate file missing', 'missing', 'real', 'real', 'the gate probe failed'],
      ['extractor file missing', 'real', 'missing', 'real', 'the gate probe failed'],
      ['copy gate not wired on Bash', 'real', 'real', 'no-copy-gate', 'outgoing-copy-gate.py is not wired'],
      ['approval gate not wired on Bash', 'real', 'real', 'no-approval-gate', 'email-approval-gate.py is not wired'],
      ['settings.json missing', 'real', 'real', 'missing', 'missing or unreadable'],
      ['settings.json invalid', 'real', 'real', 'invalid', 'missing or unreadable'],
    ] as const)('%s: exit 2, no request', (_l, copyGate, extract, settings, reason) => {
      const root = makeRoot(copyGate, extract, settings)
      const r = runCli(root, ['forward', ...OK_ARGS], SUCCESS)
      expect(r.status).toBe(2)
      expect(r.stderr).toContain('a kapu nem ismeri a forwardot')
      expect(r.stderr).toContain(reason)
      expect(r.calls).toEqual([])
    })

    // BE-B1 (card c3c32903, test setup): the gate probe and the authorizer run python by absolute
    // path, never from PATH. This used to be "no python3 on PATH: exit 2" (the probe resolved
    // python3 through PATH); the safe behaviour is that a python3 shim first on PATH is never
    // started, and that PATH has no say in the verdict.
    it('a python3 shim first on PATH is never used: the probe and the authorizer run the trusted interpreter', () => {
      const bin = mkdtempSync(join(BASE, 'bin-'))
      symlinkSync(process.execPath, join(bin, 'node'))
      const marker = join(bin, 'shim-was-run')
      const shim = join(bin, 'python3')
      writeFileSync(shim, `#!/bin/sh\necho ran > '${marker}'\nexit 1\n`)
      chmodSync(shim, 0o755)
      const r = runCli(good, ['forward', ...OK_ARGS], SUCCESS, { PATH: bin })
      expect(existsSync(marker)).toBe(false)
      expect(r.status).toBe(0)
      expect(kinds(r)).toEqual(['token', 'message', 'forward'])
    })

    it('the probe writes no copy-gate log line into the checkout store', () => {
      expect(existsSync(join(good, 'store'))).toBe(true)
      expect(existsSync(join(good, 'store', 'outgoing-copy-gate.log'))).toBe(false)
    })
  })

  describe('E7: list prints the id as the new last line of each block', () => {
    it('golden output', () => {
      const r = runCli(good, ['list', '--top', '2'], {
        token: TOKEN_OK,
        list: {
          status: 200,
          body: {
            value: [
              {
                id: ID,
                subject: SUBJECT,
                from: { emailAddress: { address: 'kuldo@example.invalid' } },
                receivedDateTime: '2026-10-18T17:00:00Z',
                bodyPreview: 'Előnézet',
                isRead: false,
              },
              { id: 'AAMkAGFmZXN0MDEyMzQ1Njc4OR==', receivedDateTime: '2026-10-18T16:00:00Z', isRead: true },
            ],
          },
        },
      })
      expect(r.status).toBe(0)
      expect(r.stdout).toBe(
        [
          `${cp(0x25cf)} 2026-10-18T17:00:00Z  kuldo@example.invalid`,
          `    ${SUBJECT}`,
          '    Előnézet',
          `    id: ${ID}`,
          '',
          '  2026-10-18T16:00:00Z  ?',
          '    (no subject)',
          '    ',
          '    id: AAMkAGFmZXN0MDEyMzQ1Njc4OR==',
          '',
          '',
        ].join('\n'),
      )
      expect(kinds(r)).toEqual(['token', 'list'])
    })
  })

  describe('show: read-only, exact subject', () => {
    it('prints id, JSON-quoted subject and sender, time, attachment flag; GET only', () => {
      const r = runCli(good, ['show', '--id', ID], {
        token: TOKEN_OK,
        message: {
          status: 200,
          body: {
            id: ID,
            subject: `Ajánlatkérés: "Teszt" ${cp(0x202e)}utca`,
            from: { emailAddress: { name: 'Kovács Béla', address: 'bela@example.invalid' } },
            receivedDateTime: '2026-10-18T17:00:00Z',
            hasAttachments: true,
          },
        },
      })
      expect(r.status).toBe(0)
      expect(r.stdout).toBe(
        [
          `id: ${ID}`,
          'subject: "Ajánlatkérés: \\"Teszt\\" \\u202eutca"',
          'from: "Kovács Béla" <"bela@example.invalid">',
          'received: 2026-10-18T17:00:00Z',
          'attachments: yes',
          '',
        ].join('\n'),
      )
      expect(r.calls.map((c) => [c.kind, c.method, c.url])).toEqual([
        ['token', 'POST', 'https://login.microsoftonline.com/00000000-0000-4000-8000-000000000001/oauth2/v2.0/token'],
        ['message', 'GET', `${GRAPH}/users/${MAILBOX_ENC}/messages/${ID_ENC}?$select=id,subject,from,receivedDateTime,hasAttachments`],
      ])
    })

    it.each([[[]], [['--id']], [['--id', '../x']], [['--id', ID, '--to', TO]], [[`--id=${ID}`]]])(
      'show %j: exit 2, no request',
      (args) => {
        const r = runCli(good, ['show', ...args], SUCCESS)
        expect(r.status).toBe(2)
        expect(r.calls).toEqual([])
      },
    )
  })

  describe('E8: no credential in any output', () => {
    it('the success runs logged the forward through the JSON logger', () => {
      expect(OUTPUTS.some((o) => o.includes('graph-mail: forwarded'))).toBe(true)
    })

    it('no CLI run printed the client secret or the access token (stdout + stderr, logger included)', () => {
      expect(OUTPUTS.length).toBeGreaterThan(50)
      const leaks = OUTPUTS.filter((o) => o.includes(FAKE_SECRET) || o.includes(FAKE_TOKEN))
      expect(leaks).toEqual([])
    })
  })
})
