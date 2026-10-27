import { describe, it, expect } from 'vitest'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { connect } from 'node:net'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import Database from 'better-sqlite3'
import {
  authorizeSend,
  buildForwardEnvelope,
  buildSendEnvelope,
  consumedNote,
  refusalText,
  sendText,
  type SendEnvelope,
} from '../graph-send-authorize.js'
import { makeCliRoot, stubRequests } from './graph-cli-root.js'

// Card efa58ad2 (cli-send-enforce), node N2: scripts/graph-mail.ts `send` and
// `forward` ask scripts/hooks/email_send_authorize.py of their own checkout before
// the Graph POST. Layers:
//   - envelope builders and authorizeSend in-process, against a stub helper;
//   - the real CLI as a subprocess (tsx) in a throwaway root with a stub helper:
//     every refusal / crash / timeout / garbage is exit 2 with no POST, a token
//     failure never reaches the helper, the envelope is built from the bytes sent;
//   - the real CLI with the REAL helper copy, a temp DB and an approval whose
//     content_hash was computed by the hook's own content_anchor for the same
//     command (anchor parity).
// No real credentials, store, Vault or keychain; fetch is a stub; run under the
// deny-net sandbox (self-checked below).
//
// HOW TO RUN: under the deny-net sandbox, from the repo root:
//   /Users/gyorgydecsi/marveen/agents/ezermester/.claude/sandbox/run-sandboxed.sh \
//     npx vitest run src/__tests__/graph-send-authorize.test.ts
// The first test is the self-check (a non-loopback connect must be refused, not
// time out); outside the sandbox it fails with a timeout, by design.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'cse-n2-')))

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')
const FAKE_SECRET = `FAKE-cse-client-secret-${'k3m7'.repeat(4)}`
const FAKE_TOKEN = `FAKE-cse-access-token-${'p9d2'.repeat(4)}`
const MAILBOX = 'cse-test-box@example.invalid'
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

const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const TO = 'ugyfel@example.hu'
const SUBJ = 'Teszt tárgy'
const BODY = 'Kedves Ügyfelünk! Törzs.'
const FWD_TO = 'kovacs@fireeng.hu'
const FWD_SUBJ = 'Ajánlatkérés: iroda átalakítás'
const COMMENT = 'Szia Béla! Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm!'

// --- self-check: the deny-net sandbox is around this run ----------------------------

describe('harness self-check', () => {
  it('a non-loopback connect is refused', async () => {
    const outcome = await new Promise<string>((done) => {
      const sock = connect({ host: '192.0.2.1', port: 9 })
      const timer = setTimeout(() => {
        sock.destroy()
        done('timeout')
      }, 3000)
      sock.on('connect', () => {
        clearTimeout(timer)
        sock.destroy()
        done('connected')
      })
      sock.on('error', (e: NodeJS.ErrnoException) => {
        clearTimeout(timer)
        done(e.code ?? 'error')
      })
    })
    expect(outcome).not.toBe('connected')
    expect(outcome).not.toBe('timeout')
  })
})

// --- envelope builders --------------------------------------------------------------

describe('envelope builders', () => {
  it('sendText follows the command-line order of --subject and --body / --body-file', () => {
    expect(sendText(['--to', 'a', '--subject', 's', '--body', 'b'], 's', 'b')).toBe('s\nb')
    expect(sendText(['--body', 'b', '--to', 'a', '--subject', 's'], 's', 'b')).toBe('b\ns')
    expect(sendText(['--body-file', '/x/f', '--body-sha256', 'h', '--subject', 's'], 's', 'b')).toBe('b\ns')
  })

  it('send: to and cc are ONE raw entry each (a comma list is not split), no bcc, attachments as given', () => {
    const att = [{ name: 'a.pdf', sha256: sha('x'), size: 1 }]
    const env = buildSendEnvelope(
      { argv: ['--to', 'a@b.hu,c@d.hu', '--subject', 's', '--body', 'b', '--cc', 'e@f.hu'], to: 'a@b.hu,c@d.hu', cc: 'e@f.hu', subject: 's', body: 'b', attachments: att },
      'ref-1',
    )
    expect(env).toEqual({ kind: 'send', to: ['a@b.hu,c@d.hu'], cc: ['e@f.hu'], bcc: [], text: 's\nb', attachments: att, ref: 'ref-1' })
    const plain = buildSendEnvelope({ argv: ['--subject', 's', '--body', 'b'], to: 'a@b.hu', subject: 's', body: 'b' }, 'r')
    expect(plain.cc).toEqual([])
    expect('attachments' in plain).toBe(false)
  })

  it('forward: the real subject, the comment, inline and file provenance', () => {
    const inline = buildForwardEnvelope({ id: ID, to: FWD_TO, subject: FWD_SUBJ, comment: COMMENT }, 'r')
    expect(inline).toMatchObject({
      kind: 'forward',
      to: [FWD_TO],
      cc: [],
      bcc: [],
      text: COMMENT,
      forward: { message_id: ID, subject: FWD_SUBJ },
      comment_source: 'inline',
      comment_sha256: sha(COMMENT),
    })
    expect('comment_file' in inline).toBe(false)
    const file = buildForwardEnvelope({ id: ID, to: FWD_TO, subject: FWD_SUBJ, comment: COMMENT, file: { path: '/o/mail-outbox/c.txt', sha256: 'f'.repeat(64) } }, 'r')
    expect(file).toMatchObject({ comment_source: 'file', comment_sha256: 'f'.repeat(64), comment_file: 'c.txt' })
  })

  it('the refusal text starts with the machine line; the consumed note says a new approval is needed', () => {
    const t = refusalText({ allowed: false, reason: 'none', detail: 'd\nx', verdict: { decision: 'refuse', reason: 'none', approval_id: null, anchor: 'a'.repeat(64), standing: null, detail: null, note: null, level: 2 } })
    expect(t.split('\n')[0]).toBe('graph-mail: REFUSED none')
    expect(t).toContain('a'.repeat(64))
    expect(t).not.toContain('d\nx')
    const v = { decision: 'allow' as const, reason: 'approval', approval_id: 'x', anchor: null, standing: null, detail: null, note: null, level: 2 }
    expect(consumedNote(v)).toMatch(/CONSUMED.*new email_send approval is needed/)
    expect(consumedNote({ ...v, reason: 'standing' })).not.toMatch(/CONSUMED/)
  })
})

// --- authorizeSend in-process, stub helper ----------------------------------------------

function withMode<T>(mode: string, fn: () => T, extra: Record<string, string> = {}): T {
  const keys = { GS_MODE: mode, ...extra }
  const old: Record<string, string | undefined> = {}
  for (const [k, v] of Object.entries(keys)) {
    old[k] = process.env[k]
    process.env[k] = v
  }
  try {
    return fn()
  } finally {
    for (const k of Object.keys(keys)) {
      if (old[k] === undefined) delete process.env[k]
      else process.env[k] = old[k]
    }
  }
}

const ENV: SendEnvelope = buildSendEnvelope({ argv: ['--subject', SUBJ, '--body', BODY], to: TO, subject: SUBJ, body: BODY }, 'ref-x')

describe('authorizeSend (stub helper)', () => {
  it('exit 0 + allow -> allowed; the request is consume mode and ASCII-only on the wire', () => {
    const root = makeCliRoot(REPO, BASE)
    const a = withMode('allow', () => authorizeSend(ENV, root))
    expect(a.allowed).toBe(true)
    const raw = readFileSync(join(root, 'scripts', 'hooks', 'stub-requests.jsonl'), 'utf-8')
    // eslint-disable-next-line no-control-regex
    expect(/^[\u0000-\u007f]*$/.test(raw)).toBe(true)
    const req = stubRequests(root)[0]
    expect(req).toMatchObject({ mode: 'consume', tool: 'graph-mail', kind: 'send', to: [TO], cc: [], bcc: [], text: `${SUBJ}\n${BODY}`, ref: 'ref-x' })
  })

  it('a reason from the helper is passed on (exit 2 + refuse)', () => {
    const root = makeCliRoot(REPO, BASE)
    const a = withMode('refuse', () => authorizeSend(ENV, root), { GS_REASON: 'consumed' })
    expect(a).toMatchObject({ allowed: false, reason: 'consumed' })
  })

  it.each(['crash', 'garbage', 'empty', 'exit1', 'allow_exit2', 'refuse_exit0', 'two_lines', 'bad_reason', 'no_decision'])(
    'helper misbehaviour %s -> refused as authorizer_failed',
    (mode) => {
      const root = makeCliRoot(REPO, BASE)
      const a = withMode(mode, () => authorizeSend(ENV, root))
      expect(a.allowed).toBe(false)
      if (!a.allowed) expect(a.reason).toBe('authorizer_failed')
    },
  )

  it('a helper that hangs is killed at the timeout and refused', () => {
    const root = makeCliRoot(REPO, BASE)
    const t0 = Date.now()
    const a = withMode('hang', () => authorizeSend(ENV, root, { timeoutMs: 600 }))
    expect(a).toMatchObject({ allowed: false, reason: 'authorizer_failed' })
    expect(Date.now() - t0).toBeLessThan(8000)
  })

  it('a missing helper is a refusal, and EMAIL_APPROVAL_GATE_STORE is not handed over', () => {
    const none = makeCliRoot(REPO, BASE, 'none')
    expect(authorizeSend(ENV, none)).toMatchObject({ allowed: false, reason: 'authorizer_failed' })
  })
})

// --- the CLI as a subprocess ------------------------------------------------------------

const FETCH_STUB = [
  "import { appendFileSync, readFileSync } from 'node:fs'",
  "const scenario = JSON.parse(readFileSync(process.env.CSE_SCENARIO, 'utf8'))",
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/sendMail')) kind = 'sendmail'",
  "  else if (method === 'POST' && url.endsWith('/forward')) kind = 'forward'",
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  "  appendFileSync(process.env.CSE_LOG, JSON.stringify({ kind, method, url, body }) + '\\n')",
  '  const reply = scenario[kind]',
  "  if (!reply) throw new Error('fetch stub: unexpected ' + kind + ' call')",
  "  if (reply.throw === 'network') throw new TypeError('fetch failed')",
  "  const text = reply.body === undefined ? null : typeof reply.body === 'string' ? reply.body : JSON.stringify(reply.body)",
  "  return new Response(text, { status: reply.status ?? 200, headers: { 'content-type': 'application/json' } })",
  '}',
  '',
].join('\n')
const STUB = join(BASE, 'fetch-stub.mjs')
writeFileSync(STUB, FETCH_STUB)

interface Reply {
  status?: number
  body?: unknown
  throw?: 'network'
}
type Scenario = Partial<Record<'token' | 'message' | 'sendmail' | 'forward', Reply>>
interface Call {
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
  calls: Call[]
}
const TOKEN_OK: Reply = { status: 200, body: { access_token: FAKE_TOKEN, token_type: 'Bearer', expires_in: 3600 } }
const SEND_OK: Scenario = { token: TOKEN_OK, sendmail: { status: 202 } }
const FWD_OK: Scenario = { token: TOKEN_OK, message: { status: 200, body: { id: ID, subject: FWD_SUBJ } }, forward: { status: 202 } }

const OUTBOX = join(BASE, 'outbox')
mkdirSync(OUTBOX, { mode: 0o700 })
chmodSync(OUTBOX, 0o700)
const ATTACH = join(BASE, 'attach')
mkdirSync(ATTACH, { mode: 0o700 })
function put(dir: string, name: string, content: string | Buffer): string {
  const p = join(dir, name)
  writeFileSync(p, content, { mode: 0o600 })
  return p
}

const OUTPUTS: string[] = []
let seq = 0
function runCli(root: string, args: string[], scenario: Scenario, extraEnv: Record<string, string> = {}, timeout = 60_000): CliRun {
  const n = ++seq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  const env: Record<string, string> = {
    ...(process.env as Record<string, string>),
    NODE_ENV: 'production',
    MARVEEN_MAIL_CREDS: CREDS,
    GRAPH_MAIL_OUTBOX_DIR: OUTBOX,
    GRAPH_MAIL_ATTACH_DIR: ATTACH,
    CSE_SCENARIO: scenarioPath,
    CSE_LOG: logPath,
    NODE_OPTIONS: `${process.env.NODE_OPTIONS ?? ''} --import=${pathToFileURL(STUB).href}`.trim(),
    ...extraEnv,
  }
  const r = spawnSync(TSX, [join(root, 'scripts', 'graph-mail.ts'), ...args], { cwd: root, env, encoding: 'utf-8', timeout })
  const calls = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as Call)
    : []
  OUTPUTS.push(`${r.stdout}\n${r.stderr}`)
  return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, calls }
}

const kinds = (r: CliRun): string[] => r.calls.map((c) => c.kind)
/** stderr without Node's own runtime warnings (tsx on this Node prints a module.register() deprecation). */
const ownStderr = (stderr: string): string[] =>
  stderr.split('\n').filter((l) => l !== '' && !/^\(node:\d+\) /.test(l) && !l.startsWith('(Use `node --trace-'))
const SEND_ARGS = ['send', '--to', TO, '--subject', SUBJ, '--body', BODY]
const FWD_ARGS = ['forward', '--id', ID, '--to', FWD_TO, '--comment', COMMENT, '--orig-subject', FWD_SUBJ]

const REASONS = ['none', 'pending', 'consumed', 'expired', 'race', 'level1', 'qa_failed', 'db_unavailable', 'config_invalid', 'unreadable', 'standing_not_live', 'trace_unwritable']

describe('graph-mail CLI + stub authorizer', () => {
  it('allow: send posts exactly once, ONE helper call, in consume mode', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, SEND_ARGS, SEND_OK)
    expect(r.status).toBe(0)
    expect(kinds(r)).toEqual(['token', 'sendmail'])
    expect(stubRequests(root)).toHaveLength(1)
    expect(stubRequests(root)[0].mode).toBe('consume')
    const posted = JSON.parse(r.calls[1].body as string)
    expect(posted.message.body.content).toBe(BODY)
  })

  it('allow: forward posts exactly once; the envelope carries the REAL subject from Graph', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, FWD_ARGS, FWD_OK)
    expect(r.status).toBe(0)
    expect(kinds(r)).toEqual(['token', 'message', 'forward'])
    const req = stubRequests(root)[0]
    expect(req).toMatchObject({ kind: 'forward', to: [FWD_TO], text: COMMENT, forward: { message_id: ID, subject: FWD_SUBJ }, comment_source: 'inline' })
  })

  it.each(REASONS)('send: helper refuses (%s) -> exit 2, REFUSED line first, no POST', (reason) => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, SEND_ARGS, SEND_OK, { GS_MODE: 'refuse', GS_REASON: reason })
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe(`graph-mail: REFUSED ${reason}`)
    expect(kinds(r)).toEqual(['token'])
    expect(r.stdout).not.toContain('sent to')
  })

  it.each(REASONS)('forward: helper refuses (%s) -> exit 2, REFUSED line first, no POST', (reason) => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, FWD_ARGS, FWD_OK, { GS_MODE: 'refuse', GS_REASON: reason })
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe(`graph-mail: REFUSED ${reason}`)
    expect(kinds(r)).toEqual(['token', 'message'])
  })

  it.each(['crash', 'garbage', 'empty', 'exit1', 'allow_exit2', 'refuse_exit0'])(
    'helper misbehaviour %s: exit 2 authorizer_failed, no POST (send and forward)',
    (mode) => {
      for (const [args, scenario, expected] of [
        [SEND_ARGS, SEND_OK, ['token']],
        [FWD_ARGS, FWD_OK, ['token', 'message']],
      ] as const) {
        const root = makeCliRoot(REPO, BASE)
        const r = runCli(root, [...args], scenario, { GS_MODE: mode })
        expect(r.status).toBe(2)
        expect(ownStderr(r.stderr)[0]).toBe('graph-mail: REFUSED authorizer_failed')
        expect(kinds(r)).toEqual(expected)
      }
    },
  )

  it('a helper that hangs: the CLI gives up at its 10 s timeout, exit 2, no POST', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, SEND_ARGS, SEND_OK, { GS_MODE: 'hang' })
    expect(r.signal).toBeNull()
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe('graph-mail: REFUSED authorizer_failed')
    expect(kinds(r)).toEqual(['token'])
  }, 40_000)

  it('no helper in the checkout: exit 2, the path is not env-overridable', () => {
    const none = makeCliRoot(REPO, BASE, 'none')
    const decoy = makeCliRoot(REPO, BASE) // has a stub; an env var must not be able to point at it
    const r = runCli(none, SEND_ARGS, SEND_OK, {
      CLAUDE_PROJECT_DIR: decoy,
      PYTHONPATH: join(decoy, 'scripts', 'hooks'),
      EMAIL_APPROVAL_GATE_STORE: join(decoy, 'store'),
    })
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe('graph-mail: REFUSED authorizer_failed')
    expect(kinds(r)).toEqual(['token'])
    expect(stubRequests(decoy)).toEqual([])
  })

  it('token failure: the helper is never called (send and forward), exit 1, nothing posted', () => {
    const bad: Reply = { status: 401, body: { error: 'invalid_client' } }
    const s = makeCliRoot(REPO, BASE)
    const rs = runCli(s, SEND_ARGS, { token: bad, sendmail: { status: 202 } })
    expect(rs.status).toBe(1)
    expect(kinds(rs)).toEqual(['token'])
    expect(stubRequests(s)).toEqual([])
    expect(rs.stderr).toContain('Nothing was sent')
    const f = makeCliRoot(REPO, BASE)
    const rf = runCli(f, FWD_ARGS, { token: bad })
    expect(rf.status).toBe(1)
    expect(stubRequests(f)).toEqual([])
    expect(kinds(rf)).toEqual(['token'])
  })

  it('forward subject mismatch: exit 2 before the helper', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, FWD_ARGS, { ...FWD_OK, message: { status: 200, body: { id: ID, subject: 'Mas targy' } } })
    expect(r.status).toBe(2)
    expect(stubRequests(root)).toEqual([])
    expect(kinds(r)).toEqual(['token', 'message'])
  })

  it('argument and body-file refusals never reach the helper or the network', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, ['send', '--to', TO, '--subject', SUBJ, '--body-file', join(OUTBOX, 'nincs.txt'), '--body-sha256', 'a'.repeat(64)], SEND_OK)
    expect(r.status).toBe(2)
    expect(r.calls).toEqual([])
    expect(stubRequests(root)).toEqual([])
  })

  it('send envelope: text from the hashed body-file bytes in flag order, attachment digest/size from the bytes sent', () => {
    const root = makeCliRoot(REPO, BASE)
    const text = 'Árvíztűrő tükörfúrógép.\nMásodik sor.'
    const file = put(OUTBOX, 'level1.txt', text)
    const att = put(ATTACH, 'ajanlat.pdf', Buffer.from([0x25, 0x50, 0x44, 0x46, 0x00, 0xff, 0x10]))
    const r = runCli(
      root,
      ['send', '--body-file', file, '--body-sha256', sha(text), '--to', TO, '--cc', 'masik@example.hu', '--subject', SUBJ, '--attach', att],
      SEND_OK,
    )
    expect(r.status).toBe(0)
    const req = stubRequests(root)[0]
    expect(req.text).toBe(`${text}\n${SUBJ}`)
    expect(req.to).toEqual([TO])
    expect(req.cc).toEqual(['masik@example.hu'])
    expect(req.attachments).toEqual([{ name: 'ajanlat.pdf', sha256: sha(readFileSync(att)), size: 7 }])
    const sent = JSON.parse(r.calls[1].body as string)
    expect(sent.message.body.content).toBe(text)
    expect(Buffer.from(sent.message.attachments[0].contentBytes, 'base64').equals(readFileSync(att))).toBe(true)
  })

  it('forward envelope with a comment file: provenance and hash from the bytes read', () => {
    const root = makeCliRoot(REPO, BASE)
    const file = put(OUTBOX, 'komment1.txt', COMMENT)
    const r = runCli(root, ['forward', '--id', ID, '--to', FWD_TO, '--comment-file', file, '--comment-sha256', sha(COMMENT), '--orig-subject', FWD_SUBJ], FWD_OK)
    expect(r.status).toBe(0)
    expect(stubRequests(root)[0]).toMatchObject({
      kind: 'forward',
      text: COMMENT,
      comment_source: 'file',
      comment_sha256: sha(COMMENT),
      comment_file: 'komment1.txt',
      forward: { message_id: ID, subject: FWD_SUBJ },
    })
  })

  it('Graph failure AFTER an approval allow: exit 1, the line says CONSUMED and a new approval is needed', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, SEND_ARGS, { token: TOKEN_OK, sendmail: { status: 500, body: 'boom' } })
    expect(r.status).toBe(1)
    expect(r.stderr).toMatch(/approval was CONSUMED/)
    expect(r.stderr).toMatch(/new email_send approval is needed/)
    const f = makeCliRoot(REPO, BASE)
    const rf = runCli(f, FWD_ARGS, { ...FWD_OK, forward: { status: 503, body: { error: { code: 'ServiceUnavailable' } } } })
    expect(rf.status).toBe(1)
    expect(rf.stderr).toMatch(/approval was CONSUMED/)
    const u = makeCliRoot(REPO, BASE)
    const ru = runCli(u, FWD_ARGS, { ...FWD_OK, forward: { throw: 'network' } })
    expect(ru.status).toBe(3)
    expect(ru.stderr).toMatch(/approval was CONSUMED/)
  })

  it('Graph failure after a standing / level 3 allow does not claim a consumed approval', () => {
    const root = makeCliRoot(REPO, BASE)
    const r = runCli(root, SEND_ARGS, { token: TOKEN_OK, sendmail: { status: 500, body: 'boom' } }, { GS_ALLOW_REASON: 'standing' })
    expect(r.status).toBe(1)
    expect(r.stderr).not.toMatch(/CONSUMED/)
  })

  it('the header documents exit codes 0 1 2 3 and the REFUSED line', () => {
    const head = readFileSync(join(REPO, 'scripts', 'graph-mail.ts'), 'utf-8').split('\nimport ')[0]
    expect(head).toMatch(/Exit codes of `send` and `forward`:/)
    for (const code of ['0', '1', '2', '3']) expect(head).toMatch(new RegExp(`\\n//   ${code}  `))
    expect(head).toContain('graph-mail: REFUSED <reason>')
    expect(head).toMatch(/CONSUMED/)
  })

  it('no run printed the client secret or the access token', () => {
    for (const o of OUTPUTS) {
      expect(o).not.toContain(FAKE_SECRET)
      expect(o).not.toContain(FAKE_TOKEN)
    }
  })
})

// --- anchor parity: the CLI-built envelope into the REAL helper ----------------------------

const DRIVER = join(BASE, 'seed-approval.py')
writeFileSync(
  DRIVER,
  [
    'import importlib.util, json, os, sqlite3, sys, time',
    'hooks, store, cmd, level = sys.argv[1:5]',
    'def load(name, fname):',
    '    spec = importlib.util.spec_from_file_location(name, os.path.join(hooks, fname))',
    '    mod = importlib.util.module_from_spec(spec)',
    '    spec.loader.exec_module(mod)',
    '    return mod',
    "ext = load('seed_ext', 'email_extract.py')",
    "gate = load('seed_gate', 'email-approval-gate.py')",
    "env = ext.collect_email_envelope('Bash', {'command': cmd})",
    "assert not env.get('unreadable_reason'), env",
    'anchor = gate.content_anchor(env)',
    'os.makedirs(store, exist_ok=True)',
    "with open(os.path.join(store, 'autonomy-config.json'), 'w', encoding='utf-8') as fh:",
    "    json.dump({'version': 1, 'categories': [{'key': 'email_send', 'level': int(level)}]}, fh)",
    "con = sqlite3.connect(os.path.join(store, 'claudeclaw.db'))",
    "con.execute('CREATE TABLE IF NOT EXISTS approvals (id TEXT PRIMARY KEY, agent_id TEXT, category TEXT NOT NULL, action_description TEXT, status TEXT NOT NULL DEFAULT \\'pending\\', requested_at INTEGER, resolved_at INTEGER, resolved_by TEXT, content_hash TEXT, consumed_at INTEGER, consumed_by TEXT, consumed_ref TEXT)')",
    "con.execute(\"\"\"CREATE TABLE IF NOT EXISTS approval_events (id INTEGER PRIMARY KEY AUTOINCREMENT, approval_id TEXT NOT NULL, event TEXT NOT NULL CHECK(event IN ('consumed','consume_refused','consumed_backfill')), reason TEXT, actor TEXT, ref TEXT, created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)))\"\"\")",
    'now = int(time.time())',
    "con.execute(\"INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by, content_hash) VALUES (hex(randomblob(6)), 'x', 'email_send', 'parity', 'approved', ?, ?, 'gazda', ?)\", (now - 60, now, anchor))",
    'con.commit()',
    'con.close()',
    'print(json.dumps({"anchor": anchor}))',
    '',
  ].join('\n'),
)

const shq = (s: string): string => `'${s}'`
/** The command the hook sees for these CLI args: `npx tsx scripts/graph-mail.ts <verb> --flag 'value' ...` */
function commandFor(args: string[]): string {
  const rest = args.slice(1).map((a) => (a.startsWith('--') ? a : shq(a)))
  return `npx tsx scripts/graph-mail.ts ${args[0]} ${rest.join(' ')}`
}

function seedApproval(root: string, args: string[], level = 2): string {
  const r = spawnSync('python3', ['-I', DRIVER, join(root, 'scripts', 'hooks'), join(root, 'store'), commandFor(args), String(level)], {
    encoding: 'utf-8',
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'en_US.UTF-8', GRAPH_MAIL_OUTBOX_DIR: OUTBOX },
    timeout: 30_000,
  })
  expect(r.status, r.stderr).toBe(0)
  return (JSON.parse(r.stdout) as { anchor: string }).anchor
}

function approvalRows(root: string): Array<{ content_hash: string; consumed_at: number | null; consumed_by: string | null; consumed_ref: string | null }> {
  const db = new Database(join(root, 'store', 'claudeclaw.db'), { readonly: true })
  try {
    return db.prepare("SELECT content_hash, consumed_at, consumed_by, consumed_ref FROM approvals WHERE category='email_send'").all() as never
  } finally {
    db.close()
  }
}

describe('anchor parity: CLI envelope into the REAL helper (temp DB, hook-computed content_hash)', () => {
  const body2 = 'Tisztelt Uram!\nKérem, nézze meg a mellékletet.\nÜdvözlettel: Brainy'
  const cases: Array<{ name: string; mk: () => string[]; scenario: Scenario; verb: 'sendmail' | 'forward' }> = [
    { name: 'send, inline, --cc, --html-free', mk: () => ['send', '--to', TO, '--subject', SUBJ, '--body', BODY, '--cc', 'masik@example.hu'], scenario: SEND_OK, verb: 'sendmail' },
    {
      name: 'send, body-file first, attachment',
      mk: () => {
        const file = put(OUTBOX, `p-${seq}-b.txt`, body2)
        const att = put(ATTACH, `p-${seq}-a.pdf`, Buffer.from([1, 2, 3, 250]))
        return ['send', '--body-file', file, '--body-sha256', sha(body2), '--to', TO, '--subject', SUBJ, '--attach', att]
      },
      scenario: SEND_OK,
      verb: 'sendmail',
    },
    { name: 'forward, inline comment', mk: () => [...FWD_ARGS], scenario: FWD_OK, verb: 'forward' },
    {
      name: 'forward, comment file',
      mk: () => {
        const file = put(OUTBOX, `p-${seq}-c.txt`, COMMENT)
        return ['forward', '--id', ID, '--to', FWD_TO, '--comment-file', file, '--comment-sha256', sha(COMMENT), '--orig-subject', FWD_SUBJ]
      },
      scenario: FWD_OK,
      verb: 'forward',
    },
  ]

  it.each(cases)('$name: allowed on the hook-computed anchor, posted once, consumed once, replay refused', ({ mk, scenario, verb }) => {
    const root = makeCliRoot(REPO, BASE, 'real')
    const args = mk()
    const anchor = seedApproval(root, args)
    const r = runCli(root, args, scenario)
    expect(r.stderr).not.toContain('REFUSED')
    expect(r.status).toBe(0)
    expect(r.calls.filter((c) => c.kind === verb)).toHaveLength(1)
    const rows = approvalRows(root)
    expect(rows).toHaveLength(1)
    expect(rows[0].content_hash).toBe(anchor)
    expect(rows[0].consumed_at).not.toBeNull()
    expect(rows[0].consumed_by).toBe('graph-mail')
    expect(rows[0].consumed_ref).toMatch(/^graph-mail:(send|forward):[0-9a-f-]{36}$/)
    // single use: the same command again finds the approval spent
    const again = runCli(root, args, scenario)
    expect(again.status).toBe(2)
    expect(ownStderr(again.stderr)[0]).toBe('graph-mail: REFUSED consumed')
    expect(again.calls.filter((c) => c.kind === verb)).toHaveLength(0)
  }, 90_000)

  it('a different body is another anchor: REFUSED none, the approval stays unspent, no POST', () => {
    const root = makeCliRoot(REPO, BASE, 'real')
    seedApproval(root, SEND_ARGS)
    const other = [...SEND_ARGS]
    other[other.indexOf(BODY)] = `${BODY} Egy szóval több.`
    const r = runCli(root, other, SEND_OK)
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe('graph-mail: REFUSED none')
    expect(r.stderr).toMatch(/[0-9a-f]{64}/)
    expect(kinds(r)).toEqual(['token'])
    expect(approvalRows(root)[0].consumed_at).toBeNull()
  }, 60_000)

  it('no approval and no config: level unreadable counts as level 1, REFUSED level1', () => {
    const root = makeCliRoot(REPO, BASE, 'real')
    const r = runCli(root, SEND_ARGS, SEND_OK)
    expect(r.status).toBe(2)
    expect(ownStderr(r.stderr)[0]).toBe('graph-mail: REFUSED level1')
    expect(kinds(r)).toEqual(['token'])
  }, 60_000)
})
