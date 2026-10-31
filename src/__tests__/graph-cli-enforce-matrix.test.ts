import { describe, it, expect, afterAll } from 'vitest'
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { connect, type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import Database from 'better-sqlite3'
import { makeCliRoot } from './graph-cli-root.js'

// Card efa58ad2 (cli-send-enforce), node N4: the end-to-end enforcement matrix.
//
// scripts/graph-mail.ts `send` / `forward` decide for themselves whether a letter
// may go out, however the command was typed. Here the REAL CLI (tsx) runs in a
// throwaway root with a byte copy of the REAL hooks (so the REAL email_send_authorize.py
// helper), a temp approvals DB, a stubbed Graph fetch (a --import preload that
// answers from a scenario file and records every call), a fake credentials file.
// No live store, Vault, keychain or dashboard. The one socket any child opens is
// the standing trace's daily-log post, and that goes to a stub server of this test
// on an ephemeral loopback port (never 3420, 11434, 4010, 18800, 18899); in every
// other world there is no dashboard token, so the helper cannot even try.
//
// `npx` / `tsx` on the PATH of the children are two tiny wrappers around the repo's
// own node_modules/.bin/tsx (no registry lookup); the shapes under test are the
// ones that reach them: `bash -c --`, `bash -ec`, `tcsh -c` (when installed),
// `env -S`, a glob in the script path, a quoted head.
//
// HOW TO RUN: this suite must run under the deny-net sandbox, from the repo root:
//   /Users/gyorgydecsi/marveen/agents/ezermester/.claude/sandbox/run-sandboxed.sh \
//     npx vitest run src/__tests__/graph-cli-enforce-matrix.test.ts
// The first self-check proves the sandbox (a non-loopback connect is refused); run
// outside it that test fails with a timeout (nothing answers on 192.0.2.1), which
// is the self-check doing its job, not a product failure.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const HOOKS = join(REPO, 'scripts', 'hooks')
const APPROVAL_GATE = join(HOOKS, 'email-approval-gate.py')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const FORBIDDEN_PORTS = [3420, 11434, 4010, 18800, 18899]
const T = 120_000
const HAS_TCSH = existsSync('/bin/tcsh')

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')
const FAKE_SECRET = `FAKE-mx-client-secret-${'k3m7'.repeat(4)}`
const FAKE_TOKEN = `FAKE-mx-access-token-${'p9d2'.repeat(4)}`
const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'cse-n4-')))
const CREDS = join(BASE, 'fake-mail-creds')
writeFileSync(
  CREDS,
  [
    'TENANT_ID=00000000-0000-4000-8000-000000000001',
    'CLIENT_ID=00000000-0000-4000-8000-000000000002',
    `CLIENT_SECRET=${FAKE_SECRET}`,
    'MAILBOX=mx-test-box@example.invalid',
  ].join('\n'),
  { mode: 0o600 },
)

afterAll(() => {
  if (basename(BASE).startsWith('cse-n4-') && dirname(BASE) === realpathSync(tmpdir())) rmSync(BASE, { recursive: true, force: true })
})

// No `!` anywhere: tcsh runs history expansion even inside single quotes.
const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const TO = 'ugyfel@example.hu'
const STANDING_TO = 'kovacs@fireeng.hu'
const SUBJ = 'Teszt tárgy'
const BODY = 'Kedves Ügyfelünk, köszönjük a megkeresést. Üdvözlettel: Brainy'
const FWD_SUBJ = 'Ajánlatkérés: iroda átalakítás'
const COMMENT = 'Szia Béla, Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm.'
const HEAD = 'npx tsx scripts/graph-mail.ts'

const sendCmd = (head: string, to = TO): string => `${head} send --to ${to} --subject '${SUBJ}' --body '${BODY}'`
const fwdCmd = (head: string): string =>
  `${head} forward --id ${ID} --to ${STANDING_TO} --comment '${COMMENT}' --orig-subject '${FWD_SUBJ}'`

// --- tiny wrappers so `npx tsx ...` / `tsx ...` reach the repo's tsx without the network ---------
const BIN = join(BASE, 'bin')
mkdirSync(BIN)
writeFileSync(join(BIN, 'npx'), `#!/bin/sh\nif [ "$1" = tsx ]; then shift; fi\nexec "${TSX}" "$@"\n`, { mode: 0o755 })
writeFileSync(join(BIN, 'tsx'), `#!/bin/sh\nexec "${TSX}" "$@"\n`, { mode: 0o755 })
chmodSync(join(BIN, 'npx'), 0o755)
chmodSync(join(BIN, 'tsx'), 0o755)

// --- fetch stub, preloaded into the CLI: answers from a scenario, records every call -------------
const FETCH_STUB = [
  "import { appendFileSync, readFileSync } from 'node:fs'",
  "const scenario = JSON.parse(readFileSync(process.env.MX_SCENARIO, 'utf8'))",
  'globalThis.fetch = async (input, init = {}) => {',
  "  const url = String(input && typeof input === 'object' && 'url' in input ? input.url : input)",
  "  const method = String(init.method || 'GET').toUpperCase()",
  "  let kind = 'other'",
  "  if (url.startsWith('https://login.microsoftonline.com/')) kind = 'token'",
  "  else if (method === 'POST' && url.endsWith('/sendMail')) kind = 'sendmail'",
  "  else if (method === 'POST' && url.endsWith('/forward')) kind = 'forward'",
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  "  appendFileSync(process.env.MX_LOG, JSON.stringify({ kind, method, url, body }) + '\\n')",
  '  const reply = scenario[kind]',
  "  if (!reply) throw new Error('fetch stub: unexpected ' + kind + ' call')",
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
}
type Scenario = Partial<Record<'token' | 'message' | 'sendmail' | 'forward', Reply>>
const TOKEN_OK: Reply = { status: 200, body: { access_token: FAKE_TOKEN, token_type: 'Bearer', expires_in: 3600 } }
const SEND_OK: Scenario = { token: TOKEN_OK, sendmail: { status: 202 } }
const FWD_OK: Scenario = { token: TOKEN_OK, message: { status: 200, body: { id: ID, subject: FWD_SUBJ } }, forward: { status: 202 } }

// --- a world: throwaway CLI root (real hook copy) whose store/ holds the temp DB -------------------
interface World {
  dir: string
  root: string
  store: string
  outbox: string
  home: string
  webPort: number
}
const NOW_S = "CAST(strftime('%s','now') AS INTEGER)"
let worldSeq = 0

function newWorld(o: { level?: number; standing?: string[]; live?: string[]; webPort?: number } = {}): World {
  const dir = realpathSync(mkdtempSync(join(BASE, `w${++worldSeq}-`)))
  const root = makeCliRoot(REPO, dir, 'real')
  const store = join(root, 'store')
  const outbox = join(dir, 'mail-outbox')
  const home = join(dir, 'home')
  mkdirSync(outbox, { mode: 0o700 })
  chmodSync(outbox, 0o700)
  mkdirSync(home)
  writeFileSync(
    join(store, 'autonomy-config.json'),
    JSON.stringify({ version: 1, categories: [{ key: 'email_send', label: 'Email', level: o.level ?? 2, locked: false }] }),
  )
  const db = new Database(join(store, 'claudeclaw.db'))
  db.exec(`CREATE TABLE approvals (
    id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, category TEXT NOT NULL,
    action_description TEXT NOT NULL, action_payload TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    timeout_at INTEGER, telegram_message_id INTEGER,
    requested_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)),
    resolved_at INTEGER, resolved_by TEXT,
    content_hash TEXT, consumed_at INTEGER, consumed_by TEXT, consumed_ref TEXT);
    CREATE TABLE approval_events (id INTEGER PRIMARY KEY AUTOINCREMENT, approval_id TEXT NOT NULL,
      event TEXT NOT NULL CHECK(event IN ('consumed','consume_refused','consumed_backfill')),
      reason TEXT, actor TEXT, ref TEXT, created_at INTEGER NOT NULL DEFAULT (CAST(strftime('%s','now') AS INTEGER)))`)
  db.close()
  if (o.standing) writeFileSync(join(store, 'email-standing-recipients.json'), JSON.stringify({ recipients: o.standing }))
  const w: World = { dir, root, store, outbox, home, webPort: o.webPort ?? 9 }
  for (const addr of o.live ?? []) {
    withDb(w, (d) =>
      d
        .prepare(
          `INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by, content_hash)
           VALUES (hex(randomblob(6)), 'marveen', 'email_standing_recipient', 'test activation', 'approved', ${NOW_S}-60, ${NOW_S}, 'owner', ?)`,
        )
        .run(sha(addr.trim().toLowerCase())),
    )
  }
  if (o.webPort !== undefined) writeFileSync(join(store, '.dashboard-token'), 'FAKE-dashboard-token-for-the-stub', { mode: 0o600 })
  return w
}

function withDb<T>(w: World, fn: (db: Database.Database) => T): T {
  const db = new Database(join(w.store, 'claudeclaw.db'))
  try {
    return fn(db)
  } finally {
    db.close()
  }
}

interface Row {
  consumed_at: number | null
  consumed_by: string | null
  consumed_ref: string | null
}
const letterRows = (w: World): Row[] =>
  withDb(w, (d) => d.prepare("SELECT consumed_at, consumed_by, consumed_ref FROM approvals WHERE category='email_send'").all()) as Row[]
const standingLog = (w: World): string => {
  const p = join(w.store, 'email-standing-sends.log')
  return existsSync(p) ? readFileSync(p, 'utf-8') : ''
}

// The anchor the hook itself computes for a command; the same one the CLI computes from its envelope.
const ANCHOR_DRIVER = join(BASE, 'anchor.py')
writeFileSync(
  ANCHOR_DRIVER,
  [
    'import importlib.util, json, os, sys',
    'hooks, cmd = sys.argv[1:3]',
    'def load(name, fname):',
    '    spec = importlib.util.spec_from_file_location(name, os.path.join(hooks, fname))',
    '    mod = importlib.util.module_from_spec(spec)',
    '    spec.loader.exec_module(mod)',
    '    return mod',
    "ext = load('mx_ext', 'email_extract.py')",
    "gate = load('mx_gate', 'email-approval-gate.py')",
    "env = ext.collect_email_envelope('Bash', {'command': cmd})",
    "assert not env.get('unreadable_reason'), env",
    'print(json.dumps({"anchor": gate.content_anchor(env)}))',
    '',
  ].join('\n'),
)

function approve(w: World, plainCommand: string): string {
  const r = spawnSync('python3', ['-I', ANCHOR_DRIVER, join(w.root, 'scripts', 'hooks'), plainCommand], {
    encoding: 'utf-8',
    env: { PATH: '/usr/bin:/bin', LC_ALL: 'en_US.UTF-8', GRAPH_MAIL_OUTBOX_DIR: w.outbox },
    timeout: 30_000,
  })
  expect(r.status, r.stderr).toBe(0)
  const anchor = (JSON.parse(r.stdout) as { anchor: string }).anchor
  withDb(w, (d) =>
    d
      .prepare(
        `INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by, content_hash)
         VALUES (hex(randomblob(6)), 'marveen', 'email_send', 'test letter', 'approved', ${NOW_S}-60, ${NOW_S}, 'owner', ?)`,
      )
      .run(anchor),
  )
  return anchor
}

// --- running things ---------------------------------------------------------------------------------
interface Call {
  kind: string
  method: string
  url: string
  body: string | null
}
interface Run {
  status: number | null
  stdout: string
  stderr: string
  calls: Call[]
}
const OUTPUTS: string[] = []
let runSeq = 0

function childEnv(w: World, scenario: Scenario): { env: Record<string, string>; logPath: string } {
  const n = ++runSeq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  return {
    logPath,
    env: {
      PATH: `${BIN}:${dirname(process.execPath)}:/usr/bin:/bin`,
      // tsx puts its IPC pipe under TMPDIR; without it the pipe lands in /tmp, which safe-vitest.sb denies
      ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
      HOME: w.home,
      LC_ALL: 'en_US.UTF-8',
      NODE_ENV: 'production',
      MARVEEN_MAIL_CREDS: CREDS,
      GRAPH_MAIL_OUTBOX_DIR: w.outbox,
      WEB_PORT: String(w.webPort),
      MX_SCENARIO: scenarioPath,
      MX_LOG: logPath,
      NODE_OPTIONS: `--import=${pathToFileURL(STUB).href}`,
    },
  }
}

function spawnRun(prog: string, args: string[], w: World, scenario: Scenario): Promise<Run> {
  const { env, logPath } = childEnv(w, scenario)
  return new Promise((done, fail) => {
    const child = spawn(prog, args, { env, cwd: w.root, stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => child.kill('SIGKILL'), 90_000)
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf-8')))
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf-8')))
    child.on('error', fail)
    child.on('close', (status) => {
      clearTimeout(timer)
      const calls = existsSync(logPath)
        ? readFileSync(logPath, 'utf-8')
            .split('\n')
            .filter(Boolean)
            .map((l) => JSON.parse(l) as Call)
        : []
      OUTPUTS.push(`${stdout}\n${stderr}`)
      done({ status, stdout, stderr, calls })
    })
  })
}

/** How a command line reaches the CLI. */
interface Shape {
  name: string
  skip?: boolean
  /** program + args that run `command` the way this shape does. */
  argv: (command: string) => [string, string[]]
  /** The head of the command line (default `npx tsx scripts/graph-mail.ts`). */
  head?: string
}
const SHAPES: Shape[] = [
  { name: 'bash -c -- <cli>', argv: (c) => ['bash', ['-c', '--', c]] },
  { name: 'bash -ec <cli>', argv: (c) => ['bash', ['-ec', c]] },
  { name: 'tcsh -c <cli>', skip: !HAS_TCSH, argv: (c) => ['/bin/tcsh', ['-c', c]] },
  { name: 'env -S <cli>', argv: (c) => ['env', ['-S', c]] },
  { name: 'glob script path (scripts/graph-mai?.ts)', head: 'npx tsx scripts/graph-mai?.ts', argv: (c) => ['bash', ['-c', c]] },
  { name: "quoted head ('npx' tsx ...)", head: "'npx' tsx scripts/graph-mail.ts", argv: (c) => ['bash', ['-c', c]] },
  { name: 'direct argv, no shell', argv: (c) => ['bash', ['-c', `exec ${c}`]] },
]

/** The PreToolUse approval hook (peek on graph-mail) for a Bash command, against the world's store. */
function hookRun(w: World, command: string): { status: number | null; stdout: string; stderr: string } {
  const r = spawnSync('python3', ['-I', APPROVAL_GATE], {
    input: JSON.stringify({ tool_name: 'Bash', tool_input: { command } }),
    encoding: 'utf-8',
    env: {
      PATH: '/usr/bin:/bin',
      HOME: w.home,
      LC_ALL: 'en_US.UTF-8',
      EMAIL_APPROVAL_GATE_STORE: w.store,
      EMAIL_APPROVAL_WINDOW_S: '1800',
      GRAPH_MAIL_OUTBOX_DIR: w.outbox,
      WEB_PORT: String(w.webPort),
    },
    timeout: 30_000,
  })
  return { status: r.status, stdout: r.stdout, stderr: r.stderr }
}

const runShape = (shape: Shape, w: World, command: string, scenario: Scenario): Promise<Run> => {
  const [prog, args] = shape.argv(command)
  return spawnRun(prog, args, w, scenario)
}
const count = (r: Run, kind: string): number => r.calls.filter((c) => c.kind === kind).length
/** stderr without Node's own runtime warnings. */
const ownStderr = (stderr: string): string[] =>
  stderr.split('\n').filter((l) => l !== '' && !/^\(node:\d+\) /.test(l) && !l.startsWith('(Use `node --trace-'))
const firstLine = (r: Run): string => ownStderr(r.stderr)[0] ?? ''

// --- self-checks ----------------------------------------------------------------------------------------
describe('harness self-checks', () => {
  it('a non-loopback connect is refused (the deny-net sandbox is around this run)', async () => {
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

  it('worlds are separate roots with their own store, and no stub port is a service port', () => {
    const a = newWorld()
    const b = newWorld()
    expect(a.store).not.toBe(b.store)
    expect(a.store.startsWith(BASE)).toBe(true)
    expect(existsSync(join(a.store, '.dashboard-token'))).toBe(false)
    expect(FORBIDDEN_PORTS).not.toContain(a.webPort)
  })
})

// --- the invocation-shape matrix ------------------------------------------------------------------------
describe('the CLI enforces identically whatever the invocation shape', () => {
  for (const shape of SHAPES) {
    const head = shape.head ?? HEAD
    const test = shape.skip ? it.skip : it
    test(
      `${shape.name}: no approval -> exit 2, REFUSED none, zero POSTs; with an approval -> exactly one POST`,
      async () => {
        const denied = newWorld()
        const none = await runShape(shape, denied, sendCmd(head), SEND_OK)
        expect(none.status, none.stderr).toBe(2)
        expect(firstLine(none)).toBe('graph-mail: REFUSED none')
        expect(count(none, 'sendmail')).toBe(0)

        const w = newWorld()
        approve(w, sendCmd(HEAD))
        const ok = await runShape(shape, w, sendCmd(head), SEND_OK)
        expect(ok.status, ok.stderr).toBe(0)
        expect(count(ok, 'sendmail')).toBe(1)
        const rows = letterRows(w)
        expect(rows).toHaveLength(1)
        expect(rows[0].consumed_at).not.toBeNull()
        expect(rows[0].consumed_by).toBe('graph-mail')
      },
      T,
    )
  }
})

// --- single use, races, the hook peek, Graph failures, fail-closed ------------------------------------
describe('send: single use and fail-closed', () => {
  it('an approved letter goes out exactly once; the same command again is REFUSED consumed', async () => {
    const w = newWorld()
    approve(w, sendCmd(HEAD))
    const shape = SHAPES[0]
    const first = await runShape(shape, w, sendCmd(HEAD), SEND_OK)
    expect(first.status, first.stderr).toBe(0)
    expect(count(first, 'sendmail')).toBe(1)
    const again = await runShape(shape, w, sendCmd(HEAD), SEND_OK)
    expect(again.status).toBe(2)
    expect(firstLine(again)).toBe('graph-mail: REFUSED consumed')
    expect(count(again, 'sendmail')).toBe(0)
    expect(letterRows(w)).toHaveLength(1)
  }, T)

  it('two parallel CLI runs on one approval: exactly one sends, the other is refused', async () => {
    const w = newWorld()
    approve(w, sendCmd(HEAD))
    const [a, b] = await Promise.all([runShape(SHAPES[0], w, sendCmd(HEAD), SEND_OK), runShape(SHAPES[1], w, sendCmd(HEAD), SEND_OK)])
    expect(count(a, 'sendmail') + count(b, 'sendmail')).toBe(1)
    expect([a.status, b.status].sort()).toEqual([0, 2])
    const loser = a.status === 2 ? a : b
    expect(firstLine(loser)).toMatch(/^graph-mail: REFUSED (race|consumed)$/)
    expect(letterRows(w).filter((r) => r.consumed_at !== null)).toHaveLength(1)
  }, T)

  it('the hook only peeks, the CLI then sends and spends', async () => {
    const w = newWorld()
    approve(w, sendCmd(HEAD))
    const hook = hookRun(w, sendCmd(HEAD))
    expect(hook.status, hook.stderr).toBe(0)
    expect(letterRows(w).map((r) => r.consumed_at)).toEqual([null]) // peek: nothing spent
    const r = await runShape(SHAPES[0], w, sendCmd(HEAD), SEND_OK)
    expect(r.status, r.stderr).toBe(0)
    expect(count(r, 'sendmail')).toBe(1)
    expect(letterRows(w)[0].consumed_by).toBe('graph-mail')
    // hook, then CLI, a second time: the hook now sees the spent row and denies; no second send
    const hook2 = hookRun(w, sendCmd(HEAD))
    expect(hook2.status).toBe(2)
    expect(hook2.stderr).toContain('FEL LETT HASZNALVA')
  }, T)

  it('Graph 500 after the consumption: exit 1 and a CONSUMED line; the rerun is REFUSED consumed with no POST', async () => {
    const w = newWorld()
    approve(w, sendCmd(HEAD))
    const failing: Scenario = { token: TOKEN_OK, sendmail: { status: 500, body: 'boom' } }
    const first = await runShape(SHAPES[0], w, sendCmd(HEAD), failing)
    expect(first.status).toBe(1)
    expect(count(first, 'sendmail')).toBe(1)
    expect(first.stderr).toContain('CONSUMED')
    expect(first.stderr).toContain("a new email_send approval is needed")
    expect(letterRows(w)[0].consumed_at).not.toBeNull()
    const rerun = await runShape(SHAPES[0], w, sendCmd(HEAD), SEND_OK)
    expect(rerun.status).toBe(2)
    expect(firstLine(rerun)).toBe('graph-mail: REFUSED consumed')
    expect(count(rerun, 'sendmail')).toBe(0)
  }, T)

  it('the DB is missing: exit 2, REFUSED db_unavailable, no Graph POST (only the token request ran)', async () => {
    const w = newWorld()
    approve(w, sendCmd(HEAD))
    rmSync(join(w.store, 'claudeclaw.db'))
    const r = await runShape(SHAPES[0], w, sendCmd(HEAD), SEND_OK)
    expect(r.status).toBe(2)
    expect(firstLine(r)).toBe('graph-mail: REFUSED db_unavailable')
    expect(r.calls.map((c) => c.kind)).toEqual(['token'])
  }, T)

  it('level 1 refuses even with an approval; level 3 sends without spending anything', async () => {
    const w1 = newWorld({ level: 1 })
    approve(w1, sendCmd(HEAD))
    const r1 = await runShape(SHAPES[0], w1, sendCmd(HEAD), SEND_OK)
    expect(r1.status).toBe(2)
    expect(firstLine(r1)).toBe('graph-mail: REFUSED level1')
    expect(count(r1, 'sendmail')).toBe(0)
    expect(letterRows(w1)[0].consumed_at).toBeNull()

    const w3 = newWorld({ level: 3 })
    approve(w3, sendCmd(HEAD, 'masik@example.hu')) // an unrelated approval: it must stay unspent
    const r3 = await runShape(SHAPES[0], w3, sendCmd(HEAD), SEND_OK)
    expect(r3.status, r3.stderr).toBe(0)
    expect(count(r3, 'sendmail')).toBe(1)
    expect(letterRows(w3).map((r) => r.consumed_at)).toEqual([null])
  }, T)
})

// --- standing recipients ----------------------------------------------------------------------------------
describe('standing recipient', () => {
  it('activated: goes out, one standing log line, one host-notification call, no approval spent', async () => {
    const received: Array<{ auth: string | undefined; body: { content?: string } }> = []
    const server: Server = createServer((req, res) => {
      let raw = ''
      req.on('data', (d: Buffer) => (raw += d.toString('utf-8')))
      req.on('end', () => {
        received.push({ auth: req.headers.authorization, body: JSON.parse(raw) as { content?: string } })
        res.writeHead(200, { 'content-type': 'application/json' })
        res.end('{"ok":true}')
      })
    })
    await new Promise<void>((ok) => server.listen(0, '127.0.0.1', ok))
    const port = (server.address() as AddressInfo).port
    try {
      expect(FORBIDDEN_PORTS).not.toContain(port)
      const w = newWorld({ standing: [STANDING_TO], live: [STANDING_TO], webPort: port })
      const r = await runShape(SHAPES[0], w, sendCmd(HEAD, STANDING_TO), SEND_OK)
      expect(r.status, r.stderr).toBe(0)
      expect(count(r, 'sendmail')).toBe(1)
      const log = standingLog(w)
      expect(log.trim().split('\n')).toHaveLength(1)
      expect(log).toContain('allando cimzett, jovahagyas nelkuli kuldes')
      expect(log).toContain(`cimzett=${STANDING_TO}`)
      expect(log).toContain('gazda-ertesites=ok')
      expect(received).toHaveLength(1)
      expect(received[0].auth).toBe('Bearer FAKE-dashboard-token-for-the-stub')
      expect(received[0].body.content ?? '').toContain(`Cimzett: ${STANDING_TO}`)
      expect(letterRows(w)).toEqual([])
    } finally {
      await new Promise<void>((done) => server.close(() => done()))
    }
  }, T)

  it('listed but not activated: exit 2 standing_not_live, no POST, no trace', async () => {
    const w = newWorld({ standing: [STANDING_TO] })
    const r = await runShape(SHAPES[0], w, sendCmd(HEAD, STANDING_TO), SEND_OK)
    expect(r.status).toBe(2)
    expect(firstLine(r)).toBe('graph-mail: REFUSED standing_not_live')
    expect(count(r, 'sendmail')).toBe(0)
    expect(standingLog(w)).toBe('')
  }, T)
})

// --- forward, same enforcement ----------------------------------------------------------------------------
describe('forward', () => {
  it('without an approval: exit 2, no forward POST; with one, under `bash -ec`: exactly one forward POST, spent once', async () => {
    const denied = newWorld()
    const none = await runShape(SHAPES[1], denied, fwdCmd(HEAD), FWD_OK)
    expect(none.status, none.stderr).toBe(2)
    expect(firstLine(none)).toBe('graph-mail: REFUSED none')
    expect(count(none, 'forward')).toBe(0)

    const w = newWorld()
    approve(w, fwdCmd(HEAD))
    const ok = await runShape(SHAPES[1], w, fwdCmd(HEAD), FWD_OK)
    expect(ok.status, ok.stderr).toBe(0)
    expect(count(ok, 'forward')).toBe(1)
    const again = await runShape(SHAPES[1], w, fwdCmd(HEAD), FWD_OK)
    expect(again.status).toBe(2)
    expect(count(again, 'forward')).toBe(0)
    expect(letterRows(w)[0].consumed_by).toBe('graph-mail')
  }, T)
})

// --- S1: local preconditions run BEFORE the authorizer (spend nothing) -----------------------------------
describe('S1: an oversized attachment is refused before the approval is touched', () => {
  it('> 3 MB base64: exit 2, a clear message, no POST, the approval row stays unconsumed', async () => {
    const w = newWorld()
    const dropDir = join(w.root, 'store', 'mail-attachments')
    mkdirSync(dropDir, { recursive: true })
    const big = join(dropDir, 'big.bin')
    writeFileSync(big, Buffer.alloc(2_500_000, 7)) // 2.5 MB -> 3.33 MB of base64, over the 3 MiB cap
    const cmd = `${HEAD} send --to ${TO} --subject '${SUBJ}' --body '${BODY}' --attach ${big}`
    approve(w, cmd)
    expect(letterRows(w)).toHaveLength(1)
    const r = await runShape(SHAPES[0], w, cmd, SEND_OK)
    expect(r.status, r.stderr).toBe(2)
    expect(ownStderr(r.stderr).join('\n')).toMatch(/attachments too large/)
    expect(ownStderr(r.stderr).join('\n')).toMatch(/spent no approval/)
    expect(count(r, 'sendmail')).toBe(0)
    expect(count(r, 'token')).toBe(0)
    const rows = letterRows(w)
    expect(rows).toHaveLength(1)
    expect(rows[0].consumed_at).toBeNull()
    expect(withDb(w, (d) => d.prepare('SELECT COUNT(*) AS n FROM approval_events').get() as { n: number }).n).toBe(0)
  }, T)

  it('a missing attachment is also exit 2 with the approval untouched', async () => {
    const w = newWorld()
    mkdirSync(join(w.root, 'store', 'mail-attachments'), { recursive: true })
    approve(w, sendCmd(HEAD))
    const [prog, args] = [TSX, ['scripts/graph-mail.ts', 'send', '--to', TO, '--subject', SUBJ, '--body', BODY, '--attach', 'nincs.pdf']]
    const r = await spawnRun(prog, args, w, SEND_OK)
    expect(r.status, r.stderr).toBe(2)
    expect(count(r, 'sendmail')).toBe(0)
    expect(letterRows(w)[0].consumed_at).toBeNull()
  }, T)
})

// --- S2: --to/--cc accept only bare address lists, before any network call ----------------------------------
describe('S2: non-bare recipient lists are refused by the CLI (exit 2, zero POSTs, approval unconsumed)', () => {
  const BAD = [
    '"a,evil@x.com,b" <kovacs@fireeng.hu>',
    'Name <kovacs@fireeng.hu>',
    'kovacs@fireeng.hu (x)',
    '<kovacs@fireeng.hu>',
    'kovacs@fireeng.hu;evil@x.com',
    'kovacs@fireeng.hu, ,b@x.hu',
  ]
  for (const bad of BAD) {
    for (const flag of ['--to', '--cc'] as const) {
      it(`${flag} ${JSON.stringify(bad)}`, async () => {
        const w = newWorld({ standing: [STANDING_TO], live: [STANDING_TO] })
        approve(w, sendCmd(HEAD))
        const args =
          flag === '--to'
            ? ['scripts/graph-mail.ts', 'send', '--to', bad, '--subject', SUBJ, '--body', BODY]
            : ['scripts/graph-mail.ts', 'send', '--to', STANDING_TO, '--cc', bad, '--subject', SUBJ, '--body', BODY]
        const r = await spawnRun(TSX, args, w, SEND_OK)
        expect(r.status, r.stderr).toBe(2)
        expect(ownStderr(r.stderr).join('\n')).toMatch(/bare addresses/)
        expect(r.calls).toEqual([])
        expect(letterRows(w).every((x) => x.consumed_at === null)).toBe(true)
        expect(standingLog(w)).toBe('')
      }, T)
    }
  }

  it('a bare two-address list still goes through with its approval', async () => {
    const w = newWorld()
    const two = 'ugyfel@example.hu,masik@example.hu'
    approve(w, sendCmd(HEAD, two))
    const r = await runShape(SHAPES[0], w, sendCmd(HEAD, two), SEND_OK)
    expect(r.status, r.stderr).toBe(0)
    expect(count(r, 'sendmail')).toBe(1)
  }, T)
})

describe('no credential in any output', () => {
  it('no CLI run printed the client secret or the access token', () => {
    expect(OUTPUTS.length).toBeGreaterThan(10)
    expect(OUTPUTS.filter((o) => o.includes(FAKE_SECRET) || o.includes(FAKE_TOKEN))).toEqual([])
  })
})
