import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { spawn } from 'node:child_process'
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs'
import { createServer, type Server } from 'node:http'
import type { AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { makeCliRoot, stubRequests } from './graph-cli-root.js'

// Card f90928e3 part B: after a SUCCESSFUL `graph-mail.ts send` or `forward` one
// daily-log entry is posted for agent brainy. The shipped CLI runs in a throwaway
// root (graph-cli-root.ts) whose src/graph-mail.ts is a stub transport (no Graph,
// no credential); the dashboard is a mock HTTP server on a loopback ephemeral
// port. The entry can never change the send: exit code and stdout are compared
// with and without it, and the send authorizer (the approval-consuming helper)
// is asked exactly once per run, entry or no entry (AC16, AC18).
const ROOT = join(__dirname, '..', '..')
const TSX = join(ROOT, 'node_modules', '.bin', 'tsx')
// The live CDP browser ports: no test may ever talk to them.
const FORBIDDEN_PORTS = [18800, 18899]

const BODY_TEXT = 'Kedves Ügyfél, ez a levél törzse, titkos-torzs-szoveg.'
const LONG_SUBJECT = 'A'.repeat(100)
const FWD_ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const FWD_TO = 'kovacs@fireeng.hu'
const FWD_SUBJECT = 'Ajánlatkérés: iroda átalakítás'
const FWD_COMMENT = 'Szia Béla, Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm.'

const STUB_GRAPH_MAIL = [
  'export class GraphRequestError extends Error { status = 0 }',
  'export class ForwardOutcomeUnknownError extends Error {}',
  'export function assertAttachmentsWithinLimit() {}',
  'export async function ensureToken() {}',
  'export async function listMessages() { return [] }',
  "export async function verifyAccess() { return { mailbox: 'stub', messageCount: 0 } }",
  `export async function getMessage() { return { id: 'x', subject: process.env.STUB_SUBJECT ?? ${JSON.stringify(FWD_SUBJECT)} } }`,
  // Fault injection for the token-leak tests: a foreign fetch error that echoes the token.
  'function maybeBreakFetch() {',
  '  if (process.env.STUB_FETCH_THROWS) {',
  '    const echoed = process.env.STUB_FETCH_THROWS',
  "    globalThis.fetch = async () => { throw new TypeError('invalid header value: Bearer ' + echoed, { cause: new Error(echoed) }) }",
  '  }',
  '}',
  'export async function sendMail(o: { to: string[]; cc?: string[]; subject: string; body: string }) {',
  "  if (process.env.STUB_SEND_FAILS) throw new Error('stub: graph refused the send')",
  "  console.log('STUB-SENT ' + JSON.stringify({ to: o.to, cc: o.cc }))",
  '  maybeBreakFetch()',
  '}',
  'export async function forwardMail(o: { id: string; to: string; comment: string }) {',
  "  if (process.env.STUB_SEND_FAILS) throw new Error('stub: graph refused the forward')",
  "  console.log('STUB-FORWARDED ' + JSON.stringify({ to: o.to }))",
  '  maybeBreakFetch()',
  '}',
  '',
].join('\n')

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'graph-daily-log-')))
let realRoot = '' // byte copy of the real hooks: the REAL approval-consuming helper
let stubRoot = '' // an allow/refuse stub helper that logs every request it gets
type Run = { status: number | null; stdout: string; stderr: string }
type Hit = { auth: string | undefined; body: { agent_id: string; content: string } }

/** A throwaway CLI root whose src/ is the real tree with graph-mail.ts swapped for the stub. */
function makeRoot(kind: 'real' | 'stub'): string {
  const root = makeCliRoot(ROOT, BASE, kind)
  unlinkSync(join(root, 'src')) // makeCliRoot symlinked the whole real src
  mkdirSync(join(root, 'src'))
  for (const f of readdirSync(join(ROOT, 'src'))) {
    if (f !== 'graph-mail.ts') symlinkSync(join(ROOT, 'src', f), join(root, 'src', f))
  }
  writeFileSync(join(root, 'src', 'graph-mail.ts'), STUB_GRAPH_MAIL)
  mkdirSync(join(root, 'store', 'mail-attachments'))
  return root
}

function run(root: string, verb: 'send' | 'forward', args: string[], env: NodeJS.ProcessEnv = {}): Promise<Run> {
  return new Promise((done) => {
    const child = spawn(TSX, [join(root, 'scripts', 'graph-mail.ts'), verb, ...args], {
      env: { ...process.env, ...env, WEB_PORT: '' },
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d) => { stdout += d })
    child.stderr.on('data', (d) => { stderr += d })
    child.on('close', (status) => done({ status, stdout, stderr }))
  })
}
const send = (root: string, args: string[], env: NodeJS.ProcessEnv = {}) => run(root, 'send', args, env)
const forward = (root: string, args: string[], env: NodeJS.ProcessEnv = {}) => run(root, 'forward', args, env)
function letter(subject = 'Tárgy', to = 'a@example.com') {
  return ['--to', to, '--subject', subject, '--body', BODY_TEXT]
}
function fwdArgs(subject = FWD_SUBJECT) {
  return ['--id', FWD_ID, '--to', FWD_TO, '--comment', FWD_COMMENT, '--orig-subject', subject]
}
function writeLevel(root: string, level: 1 | 2 | 3) {
  writeFileSync(join(root, 'store', 'autonomy-config.json'),
    JSON.stringify({ version: 1, categories: [{ key: 'email_send', level }] }))
}
function pointDashboardAt(root: string, port: number) {
  writeFileSync(join(root, '.env'), `WEB_PORT=${port}\n`)
  writeFileSync(join(root, 'store', '.dashboard-token'), 'test-token-not-a-secret\n')
}
function db(root: string) {
  return new Database(join(root, 'store', 'claudeclaw.db'))
}

let hits: Hit[] = []
let server: Server | null = null
let serverPort = 0
function startServer(root: string, handler: (respond: (code: number) => void, hang: () => void) => void): Promise<void> {
  return new Promise((ready) => {
    server = createServer((req, res) => {
      let raw = ''
      req.on('data', (d) => { raw += d })
      req.on('end', () => {
        if (req.method === 'POST' && req.url === '/api/daily-log') {
          hits.push({ auth: req.headers.authorization, body: JSON.parse(raw) })
        }
        handler((code) => { res.statusCode = code; res.end('{}') }, () => { /* never answer */ })
      })
    })
    server.listen(0, '127.0.0.1', () => {
      serverPort = (server!.address() as AddressInfo).port
      expect(FORBIDDEN_PORTS).not.toContain(serverPort)
      pointDashboardAt(root, serverPort)
      ready()
    })
  })
}
const closeServer = () => new Promise<void>((r) => server!.close(() => r()))

beforeAll(() => {
  realRoot = makeRoot('real')
  stubRoot = makeRoot('stub')
  const d = db(realRoot)
  d.exec(`CREATE TABLE approvals (id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, category TEXT NOT NULL,
    action_description TEXT NOT NULL, action_payload TEXT, status TEXT NOT NULL DEFAULT 'pending',
    timeout_at INTEGER, telegram_message_id INTEGER,
    requested_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    resolved_at INTEGER, resolved_by TEXT, content_hash TEXT, consumed_at INTEGER)`)
  d.close()
}, 60_000)
afterAll(() => { rmSync(BASE, { recursive: true, force: true }) })
beforeEach(() => {
  hits = []
  for (const root of [realRoot, stubRoot]) {
    writeLevel(root, 3)
    rmSync(join(root, 'store', 'verified-recipients.json'), { force: true })
    rmSync(join(root, 'store', '.dashboard-token'), { force: true })
    rmSync(join(root, '.env'), { force: true })
  }
  rmSync(join(stubRoot, 'scripts', 'hooks', 'stub-requests.jsonl'), { force: true })
  const d = db(realRoot)
  d.exec('DELETE FROM approvals')
  d.close()
})
afterEach(async () => {
  if (server) await closeServer()
  server = null
})

describe('graph-mail.ts send: daily-log entry after a successful send', () => {
  it('posts exactly one entry for brainy with recipient, truncated subject and local time, and no body', async () => {
    await startServer(realRoot, (respond) => respond(200))
    const r = await send(realRoot, letter(LONG_SUBJECT))
    expect(r.status, r.stderr).toBe(0)
    expect(hits).toHaveLength(1)
    expect(hits[0].auth).toBe('Bearer test-token-not-a-secret')
    expect(hits[0].body.agent_id).toBe('brainy')
    const c = hits[0].body.content
    expect(c).toMatch(/^\[Levél elküldve\] a@example\.com, tárgy: A{79}…, \d{4}-\d{2}-\d{2} \d{2}:\d{2}$/)
    expect(Array.from(c.split('tárgy: ')[1].split(', ')[0])).toHaveLength(80)
    expect(c).not.toContain('titkos-torzs-szoveg')
    expect(c).not.toContain('Kedves')
    expect(JSON.stringify(hits[0].body)).not.toContain(BODY_TEXT)
    expect(c).not.toContain('message-id')
    expect(c).not.toContain('approval')
  })

  it('keeps a subject of exactly 80 characters whole, lists only the to-recipients, never cc or an attachment name', async () => {
    await startServer(realRoot, (respond) => respond(200))
    writeFileSync(join(realRoot, 'store', 'mail-attachments', 'titkos-melleklet.pdf'), 'PDF-BYTES')
    const subject = 'B'.repeat(80)
    const r = await send(realRoot, [...letter(subject, 'a@example.com,b@example.com'),
      '--cc', 'cc-ember@example.com', '--attach', 'titkos-melleklet.pdf'])
    expect(r.status, r.stderr).toBe(0)
    expect(hits).toHaveLength(1)
    const c = hits[0].body.content
    expect(c).toContain(`a@example.com, b@example.com, tárgy: ${subject}, `)
    expect(c).not.toContain('…')
    expect(c).not.toContain('cc-ember')
    expect(c).not.toContain('melleklet')
  })

  for (const [name, start] of [
    ['dashboard answers 500', () => startServer(realRoot, (respond) => respond(500))],
    ['dashboard never answers (timeout)', () => startServer(realRoot, (_respond, hang) => hang())],
    ['connection refused', async () => {
      await startServer(realRoot, (respond) => respond(200))
      await closeServer()
      server = null
    }],
  ] as const) {
    it(`${name}: send exit 0, stdout identical to a send without the entry, one stderr note`, async () => {
      // Baseline: no token file at all (the entry fails fast), same stub send.
      const baseline = await send(realRoot, letter())
      expect(baseline.status, baseline.stderr).toBe(0)
      await start()
      const r = await send(realRoot, letter())
      expect(r.status, r.stderr).toBe(0)
      expect(r.stdout).toBe(baseline.stdout)
      expect(r.stdout).toBe('STUB-SENT {"to":["a@example.com"]}\nsent to a@example.com\n')
      expect(r.stderr).toContain('a levél elment, de a napló-bejegyzés nem készült el')
    }, 30_000)
  }

  it('a missing dashboard token only costs a stderr note', async () => {
    const r = await send(realRoot, letter())
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout).toBe('STUB-SENT {"to":["a@example.com"]}\nsent to a@example.com\n')
    expect(r.stderr).toContain('napló-bejegyzés nem készült el')
  })

  it('no entry when the transport fails (exit 1, nothing sent)', async () => {
    await startServer(realRoot, (respond) => respond(200))
    const r = await send(realRoot, letter(), { STUB_SEND_FAILS: '1' })
    expect(r.status).toBe(1)
    expect(r.stdout).not.toContain('sent to')
    expect(hits).toHaveLength(0)
  })

  it('no entry when the level refuses the send (level 1, exit 2)', async () => {
    await startServer(realRoot, (respond) => respond(200))
    writeLevel(realRoot, 1)
    const r = await send(realRoot, letter())
    expect(r.status, r.stderr).toBe(2)
    expect(r.stdout).not.toContain('sent to')
    expect(hits).toHaveLength(0)
  })

  it('no entry for a level-2 send without approval, with a pending one, or with an expired one', async () => {
    await startServer(realRoot, (respond) => respond(200))
    writeLevel(realRoot, 2)
    const first = await send(realRoot, letter())
    expect(first.status, first.stderr).toBe(2)
    const anchor = first.stderr.match(/\b([0-9a-f]{64})\b/)?.[1]
    expect(anchor, first.stderr).toBeTruthy()
    const d = db(realRoot)
    d.prepare(`INSERT INTO approvals (id, agent_id, category, action_description, status, resolved_at, content_hash)
      VALUES ('ap-p', 'agent-a', 'email_send', 'x', 'pending', NULL, ?)`).run(anchor)
    d.close()
    const pending = await send(realRoot, letter())
    expect(pending.status, pending.stderr).toBe(2)
    const d2 = db(realRoot)
    d2.exec('DELETE FROM approvals')
    d2.prepare(`INSERT INTO approvals (id, agent_id, category, action_description, status, resolved_at, content_hash)
      VALUES ('ap-e', 'agent-a', 'email_send', 'x', 'approved', CAST(strftime('%s','now') AS INTEGER) - 100000, ?)`).run(anchor)
    d2.close()
    const expired = await send(realRoot, letter())
    expect(expired.status, expired.stderr).toBe(2)
    expect(hits).toHaveLength(0)
    for (const r of [first, pending, expired]) expect(r.stdout).not.toContain('sent to')
  })

  it('no entry for a rejected approval or one already consumed (AC18)', async () => {
    await startServer(realRoot, (respond) => respond(200))
    writeLevel(realRoot, 2)
    const anchor = (await send(realRoot, letter())).stderr.match(/\b([0-9a-f]{64})\b/)![1]
    const d = db(realRoot)
    d.prepare(`INSERT INTO approvals (id, agent_id, category, action_description, status, resolved_at, content_hash)
      VALUES ('ap-r', 'agent-a', 'email_send', 'x', 'rejected', CAST(strftime('%s','now') AS INTEGER), ?)`).run(anchor)
    d.prepare(`INSERT INTO approvals (id, agent_id, category, action_description, status, resolved_at, content_hash, consumed_at)
      VALUES ('ap-c', 'agent-a', 'email_send', 'x', 'approved', CAST(strftime('%s','now') AS INTEGER),
        ?, CAST(strftime('%s','now') AS INTEGER))`).run(anchor)
    d.close()
    const r = await send(realRoot, letter())
    expect(r.status, r.stderr).toBe(2)
    expect(r.stdout).not.toContain('sent to')
    expect(hits).toHaveLength(0)
  })

  it('level 2 with a live approval: sent and ONE entry; the approval is consumed exactly as before', async () => {
    await startServer(realRoot, (respond) => respond(200))
    writeLevel(realRoot, 2)
    const anchor = (await send(realRoot, letter())).stderr.match(/\b([0-9a-f]{64})\b/)![1]
    const d = db(realRoot)
    d.prepare(`INSERT INTO approvals (id, agent_id, category, action_description, status, resolved_at, content_hash)
      VALUES ('ap-1', 'agent-a', 'email_send', 'x', 'approved', CAST(strftime('%s','now') AS INTEGER), ?)`).run(anchor)
    d.close()
    const ok = await send(realRoot, letter())
    expect(ok.status, ok.stderr).toBe(0)
    expect(hits).toHaveLength(1)
    const d2 = db(realRoot)
    const row = d2.prepare('SELECT consumed_at FROM approvals WHERE id=?').get('ap-1') as { consumed_at: number | null }
    d2.close()
    expect(row.consumed_at).toBeTruthy()
    const replay = await send(realRoot, letter())
    expect(replay.status).toBe(2)
    expect(hits).toHaveLength(1)
  })
})

describe('graph-mail.ts forward: daily-log entry after a successful forward', () => {
  it('posts one entry with the original subject and the one recipient, never the comment', async () => {
    await startServer(realRoot, (respond) => respond(200))
    const r = await forward(realRoot, fwdArgs())
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout).toContain('STUB-FORWARDED')
    expect(hits).toHaveLength(1)
    expect(hits[0].body.agent_id).toBe('brainy')
    const c = hits[0].body.content
    expect(c).toMatch(new RegExp(`^\\[Levél elküldve\\] ${FWD_TO.replace('.', '\\.')}, tárgy: ${FWD_SUBJECT}, \\d{4}-\\d{2}-\\d{2} \\d{2}:\\d{2}$`))
    expect(JSON.stringify(hits[0].body)).not.toContain('Gyuri most úton van')
  })

  it('a failing entry leaves the forward exit code and stdout untouched', async () => {
    const baseline = await forward(realRoot, fwdArgs())
    await startServer(realRoot, (respond) => respond(500))
    const r = await forward(realRoot, fwdArgs())
    expect(baseline.status, baseline.stderr).toBe(0)
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout).toBe(baseline.stdout)
    expect(r.stderr).toContain('(HTTP 500)')
  }, 30_000)

  it('no entry when the transport fails, or the level refuses the forward', async () => {
    await startServer(realRoot, (respond) => respond(200))
    const failed = await forward(realRoot, fwdArgs(), { STUB_SEND_FAILS: '1' })
    expect(failed.status).toBe(1)
    writeLevel(realRoot, 1)
    const refused = await forward(realRoot, fwdArgs())
    expect(refused.status, refused.stderr).toBe(2)
    expect(hits).toHaveLength(0)
  })

  it('no entry when the subject does not match (nothing sent, exit 2)', async () => {
    await startServer(realRoot, (respond) => respond(200))
    const r = await forward(realRoot, fwdArgs('Valami mas targy'))
    expect(r.status, r.stderr).toBe(2)
    expect(hits).toHaveLength(0)
  })
})

// AC16: the authorizer (the approval-consuming helper) is asked exactly once per
// run, at the same point, whatever the entry does; a refused run asks once and
// writes nothing. The stub helper logs one line per request it gets.
describe('the send authorizer is asked exactly once per run, entry or no entry (AC16, AC18)', () => {
  const calls = () => stubRequests(stubRoot).length

  it('send: one request on success with a working entry, with a failing entry, and with none configured', async () => {
    await startServer(stubRoot, (respond) => respond(200))
    expect((await send(stubRoot, letter())).status).toBe(0)
    expect(calls()).toBe(1)
    expect(hits).toHaveLength(1)
    await closeServer()
    server = null
    expect((await send(stubRoot, letter())).status).toBe(0) // connection refused
    expect(calls()).toBe(2)
    rmSync(join(stubRoot, 'store', '.dashboard-token'), { force: true })
    expect((await send(stubRoot, letter())).status).toBe(0) // no token
    expect(calls()).toBe(3)
  }, 30_000)

  it('forward: one request on success, with a failing entry too', async () => {
    await startServer(stubRoot, (respond) => respond(500))
    expect((await forward(stubRoot, fwdArgs())).status).toBe(0)
    expect(calls()).toBe(1)
    expect((await forward(stubRoot, fwdArgs())).status).toBe(0)
    expect(calls()).toBe(2)
  }, 30_000)

  it('a refused send / forward asks once, exits 2, writes no entry', async () => {
    await startServer(stubRoot, (respond) => respond(200))
    const s = await send(stubRoot, letter(), { GS_MODE: 'refuse', GS_REASON: 'none' })
    expect(s.status, s.stderr).toBe(2)
    expect(calls()).toBe(1)
    const f = await forward(stubRoot, fwdArgs(), { GS_MODE: 'refuse', GS_REASON: 'none' })
    expect(f.status, f.stderr).toBe(2)
    expect(calls()).toBe(2)
    expect(hits).toHaveLength(0)
  }, 30_000)

  it('a crashed authorizer is a refusal: no send, no entry', async () => {
    await startServer(stubRoot, (respond) => respond(200))
    const s = await send(stubRoot, letter(), { GS_MODE: 'crash' })
    expect(s.status).not.toBe(0)
    expect(s.stdout).not.toContain('STUB-SENT')
    expect(hits).toHaveLength(0)
  })

  it('the entry code sits after the send and the authorizer call in the source (order pinned)', () => {
    const src = readFileSync(join(ROOT, 'scripts', 'graph-mail.ts'), 'utf-8')
    const auth = [...src.matchAll(/authorizeSend\(/g)].map((m) => m.index!)
    const entry = [...src.matchAll(/await postSentEntry\(/g)].map((m) => m.index!)
    expect(auth).toHaveLength(2) // send and forward, one call each: no third call site
    expect(entry).toHaveLength(2)
    for (const e of entry) expect(auth.some((a) => a < e)).toBe(true)
    // the entry is awaited only after the "sent to" / "forwarded" line
    expect(src).toMatch(/console\.log\(`sent to \$\{args\.to\}`\)\n\s+await postSentEntry\(/)
    expect(src).toMatch(/-> \$\{to\}`\)\n\s+await postSentEntry\(/)
  })
})

// Card f90928e3 B-B1: the dashboard bearer token must not reach stdout or
// stderr on ANY error branch of the entry. A header-validation error from
// fetch echoes the header value, so the token is checked up front and only
// our own fixed messages or a bare exception type name are ever printed.
describe('graph-mail.ts send: the dashboard token never reaches the output', () => {
  const CORE = 'abc123XYZ'
  const TOKEN = `SECRETTOKEN-${CORE}`
  const EXPECTED_STDOUT = 'STUB-SENT {"to":["a@example.com"]}\nsent to a@example.com\n'

  function setToken(content: string) {
    writeFileSync(join(realRoot, 'store', '.dashboard-token'), content)
  }
  function expectNoLeak(r: Run, note: RegExp) {
    expect(r.status, r.stderr).toBe(0)
    expect(r.stdout).toBe(EXPECTED_STDOUT)
    for (const out of [r.stdout, r.stderr]) {
      expect(out).not.toContain(TOKEN)
      expect(out).not.toContain(CORE)
    }
    // Other stderr lines (sender check, gates) are not ours; the entry's note is exactly one line.
    const notes = r.stderr.split('\n').filter((l) => l.includes('napló-bejegyzés nem készült el'))
    expect(notes, r.stderr).toHaveLength(1)
    expect(notes[0]).toMatch(note)
  }

  for (const [name, content] of [
    ['CR/LF injected', `${TOKEN}\r\nX-Evil: 1`],
    ['LF injected', `${TOKEN}\nX-Evil: 1`],
    ['NUL', `${TOKEN}${String.fromCharCode(0)}tail`],
    ['non-ASCII char', `${TOKEN}-é`],
    ['a space', `${TOKEN} tail`],
  ] as const) {
    it(`token with ${name}: fixed "invalid dashboard token format", no request, send untouched`, async () => {
      await startServer(realRoot, (respond) => respond(200))
      setToken(content)
      const r = await send(realRoot, letter())
      expectNoLeak(r, /\(invalid dashboard token format\)/)
      expect(hits).toHaveLength(0)
    })
  }

  it('empty token: fixed message', async () => {
    await startServer(realRoot, (respond) => respond(200))
    setToken('\n')
    expectNoLeak(await send(realRoot, letter()), /\(empty dashboard token\)/)
    expect(hits).toHaveLength(0)
  })

  it('missing token file: fixed message', async () => {
    expectNoLeak(await send(realRoot, letter()), /\(cannot read dashboard token file\)/)
  })

  it('a valid token still goes out as the Bearer header', async () => {
    await startServer(realRoot, (respond) => respond(200))
    setToken(`${TOKEN}\n`)
    const r = await send(realRoot, letter())
    expect(r.status, r.stderr).toBe(0)
    expect(hits).toHaveLength(1)
    expect(hits[0].auth).toBe(`Bearer ${TOKEN}`)
    expect(r.stderr).not.toContain('napló-bejegyzés nem készült el')
  })

  it('a foreign fetch error that echoes the token: only the type name is printed', async () => {
    await startServer(realRoot, (respond) => respond(200))
    setToken(TOKEN)
    const r = await send(realRoot, letter(), { STUB_FETCH_THROWS: TOKEN })
    expectNoLeak(r, /\(TypeError\)/)
  })

  it('dashboard answers 500: "HTTP 500", no token', async () => {
    await startServer(realRoot, (respond) => respond(500))
    setToken(TOKEN)
    expectNoLeak(await send(realRoot, letter()), /\(HTTP 500\)/)
  }, 30_000)

  it('dashboard never answers: "timeout", no token', async () => {
    await startServer(realRoot, (_respond, hang) => hang())
    setToken(TOKEN)
    expectNoLeak(await send(realRoot, letter()), /\(timeout\)/)
  }, 30_000)

  it('connection refused: a bare type name, no token', async () => {
    await startServer(realRoot, (respond) => respond(200))
    await closeServer()
    server = null
    setToken(TOKEN)
    expectNoLeak(await send(realRoot, letter()), /\(TypeError\)/)
  }, 30_000)

  it('bad WEB_PORT: fixed message, no token', async () => {
    setToken(TOKEN)
    writeFileSync(join(realRoot, '.env'), 'WEB_PORT=not-a-port\n')
    expectNoLeak(await send(realRoot, letter()), /\(bad WEB_PORT\)/)
  })

  // 18899 only: a regression must never send a request to the live CDP browser on 18800.
  it('WEB_PORT on the CDP deny list: refused, no request, no token', async () => {
    setToken(TOKEN)
    writeFileSync(join(realRoot, '.env'), 'WEB_PORT=18899\n')
    expectNoLeak(await send(realRoot, letter()), /\(refused WEB_PORT 18899\)/)
  })

  it('the deny list covers the live CDP port 18800 as well', () => {
    const src = readFileSync(join(ROOT, 'scripts', 'graph-mail.ts'), 'utf-8')
    expect(src).toMatch(/FORBIDDEN_PORTS = new Set\(\[18800, 18899\]\)/)
  })
})
