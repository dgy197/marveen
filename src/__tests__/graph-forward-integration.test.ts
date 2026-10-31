import { describe, it, expect, afterAll } from 'vitest'
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs'
import { spawn, spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { createServer, type Server } from 'node:http'
import { connect, type AddressInfo } from 'node:net'
import { tmpdir } from 'node:os'
import { basename, dirname, join, resolve } from 'node:path'
import { fileURLToPath, pathToFileURL } from 'node:url'
import Database from 'better-sqlite3'
import { makeCliRoot } from './graph-cli-root.js'

// graph-forward chain test (card graph-forward, Brainy 2958, node N4; updated for
// card efa58ad2, cli-send-enforce).
//
// The real chain, end to end, in one flow:
//   PreToolUse JSON -> `python3 -I` outgoing-copy-gate.py
//                   -> `python3 -I` email-approval-gate.py (throwaway store)
//                   -> only if BOTH exit 0: the CLI (scripts/graph-mail.ts) with
//                      the argv a real bash would hand it, a stubbed fetch and
//                      a fake credentials file.
// The sub-agent gate (scripts/email-send-gate.mjs) is run on the same payloads.
//
// Contract since card efa58ad2: on a graph-mail command the approval hook only
// PEEKS (it never spends an approval and never writes the standing trace); the CLI
// asks scripts/hooks/email_send_authorize.py of ITS checkout right before the
// Graph POST, and THAT run spends the approval / writes the standing trace. So
// every world here owns a throwaway CLI root with a byte copy of the REAL hooks
// (the helper derives store/ from its own realpath), and the world's store IS that
// root's store/: the hook (EMAIL_APPROVAL_GATE_STORE) and the CLI's helper see the
// same temp DB. The copy gate still runs on every call.
//
// HOW TO RUN: this suite must run under the deny-net sandbox, from the repo root:
//   /Users/gyorgydecsi/marveen/agents/ezermester/.claude/sandbox/run-sandboxed.sh \
//     npx vitest run src/__tests__/graph-forward-integration.test.ts
// The first self-check proves the sandbox (a non-loopback connect is refused); run
// outside it that test fails with a timeout (nothing answers on 192.0.2.1), which
// is the self-check doing its job, not a product failure.
//
// Nothing here talks to a real service: no real credentials, no Vault, no real
// store/, no real dashboard. The fetch of the CLI is a stub. The one socket the
// hooks open is the standing trace's daily-log post, and that goes to a stub
// server of this test on an ephemeral loopback port (never 3420, 11434, 4010,
// 18800, 18899); every other world has no dashboard token, so the hook cannot
// even try. The spawned python/node processes run under the caller's
// run-sandboxed.sh (deny-net); the self-test at the top proves the sandbox.

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = resolve(HERE, '..', '..')
const HOOKS = join(REPO, 'scripts', 'hooks')
const COPY_GATE = join(HOOKS, 'outgoing-copy-gate.py')
const APPROVAL_GATE = join(HOOKS, 'email-approval-gate.py')
const EXTRACT = join(HOOKS, 'email_extract.py')
const SUBAGENT_GATE = join(REPO, 'scripts', 'email-send-gate.mjs')
const CLI = join(REPO, 'scripts', 'graph-mail.ts')
const TSX = join(REPO, 'node_modules', '.bin', 'tsx')
const GRAPH = 'https://graph.microsoft.com/v1.0'
const FORBIDDEN_PORTS = [3420, 11434, 4010, 18800, 18899]
const T = 90_000

const sha = (b: Buffer | string): string => createHash('sha256').update(b).digest('hex')

// Fake secrets: the last test greps every CLI output for these.
const FAKE_SECRET = `FAKE-gf-client-secret-${'k3m7'.repeat(4)}`
const FAKE_TOKEN = `FAKE-gf-access-token-${'p9d2'.repeat(4)}`
const MAILBOX = 'gf-test-box@example.invalid'

const ID = 'AAMkAGFmZXN0MDEyMzQ1Njc4OQ=='
const ID2 = 'AAMkAGFmZXN0OTg3NjU0MzIxMA=='
const TO = 'kovacs@fireeng.hu'
const TO2 = 'molnara@fireeng.hu'
const SUBJECT = 'Ajánlatkérés: iroda átalakítás'
const COMMENT = 'Szia Béla! Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm!'
const HEAD = 'npx tsx scripts/graph-mail.ts forward'

const BASE = realpathSync(mkdtempSync(join(tmpdir(), 'gf-n4-')))
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

afterAll(() => {
  // Only our own throwaway tree, and only if it still looks like it.
  if (basename(BASE).startsWith('gf-n4-') && dirname(BASE) === realpathSync(tmpdir())) {
    rmSync(BASE, { recursive: true, force: true })
  }
})

// ---------------------------------------------------------------------------
// A world: throwaway store (config, approvals DB, standing list) + outbox root
// ---------------------------------------------------------------------------

interface World {
  dir: string
  /** The throwaway CLI root (real hook copy); `store` is its store/. */
  root: string
  store: string
  outbox: string
  home: string
  /** Port of the daily-log stub, when this world has one. */
  webPort: number
}

const NOW_S = "CAST(strftime('%s','now') AS INTEGER)"
let worldSeq = 0

interface WorldOpts {
  level?: number
  /** Addresses on the standing list. */
  standing?: string[]
  /** Addresses of the standing list the owner has activated (approved row). */
  live?: string[]
  /** Daily-log stub port (and a fake dashboard token); default none. */
  webPort?: number
}

function newWorld(o: WorldOpts = {}): World {
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
  for (const addr of o.live ?? []) approveStanding(w, addr)
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

/** The owner's one-time approval that makes a listed address live. */
function approveStanding(w: World, addr: string): void {
  withDb(w, (db) =>
    db
      .prepare(
        `INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by, content_hash)
         VALUES (hex(randomblob(6)), 'marveen', 'email_standing_recipient', 'test activation', 'approved', ${NOW_S}-60, ${NOW_S}, 'owner', ?)`,
      )
      .run(sha(addr.trim().toLowerCase())),
  )
}

/** A per-letter approval for the given anchor, approved just now. */
function approveLetter(w: World, anchor: string): void {
  withDb(w, (db) =>
    db
      .prepare(
        `INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by, content_hash)
         VALUES (hex(randomblob(6)), 'marveen', 'email_send', 'test letter', 'approved', ${NOW_S}-60, ${NOW_S}, 'owner', ?)`,
      )
      .run(anchor),
  )
}

const letterRows = (w: World): Array<{ status: string; consumed_at: number | null }> =>
  withDb(w, (db) => db.prepare("SELECT status, consumed_at FROM approvals WHERE category='email_send'").all()) as Array<{
    status: string
    consumed_at: number | null
  }>

const standingLog = (w: World): string => {
  const p = join(w.store, 'email-standing-sends.log')
  return existsSync(p) ? readFileSync(p, 'utf-8') : ''
}

/** The 64-hex anchor of a deny message (the letter anchor, or the address anchor of a not-live standing address). */
function anchorOf(stderr: string): string {
  const m = stderr.match(/\b([0-9a-f]{64})\b/)
  if (!m) throw new Error(`no anchor in: ${stderr}`)
  return m[1]
}

// ---------------------------------------------------------------------------
// Files in the outbox, commands
// ---------------------------------------------------------------------------

function putFile(w: World, name: string, content: Buffer | string): { path: string; hex: string } {
  const path = join(w.outbox, name)
  writeFileSync(path, content, { mode: 0o600 })
  return { path, hex: sha(typeof content === 'string' ? Buffer.from(content, 'utf-8') : content) }
}

const q = (s: string): string => `'${s}'`

function inlineCmd(o: { id?: string; to?: string; comment?: string; subject?: string } = {}): string {
  return `${HEAD} --id ${o.id ?? ID} --to ${o.to ?? TO} --comment ${q(o.comment ?? COMMENT)} --orig-subject ${q(o.subject ?? SUBJECT)}`
}

function fileCmd(path: string, hex: string, o: { id?: string; to?: string; subject?: string } = {}): string {
  return `${HEAD} --id ${o.id ?? ID} --to ${o.to ?? TO} --comment-file ${path} --comment-sha256 ${hex} --orig-subject ${q(o.subject ?? SUBJECT)}`
}

const FILE_TEXT =
  'Szia Béla!\n\nGyuri most úton van, ezért továbbítom neked ezt a levelet.\nA határidő péntek, kérlek, nézd meg még ma.\n\nJavasolt válasz:\nKöszönjük a megkeresést, hétfőn jelentkezünk a részletekkel.\n\nKöszönöm!\nBrainy, Gyuri AI asszisztense\n'

// ---------------------------------------------------------------------------
// The hooks
// ---------------------------------------------------------------------------

interface HookRun {
  status: number | null
  stdout: string
  stderr: string
}

function runChild(cmd: string, args: string[], env: Record<string, string>, stdin: string, cwd?: string): Promise<HookRun> {
  return new Promise((resolveRun, reject) => {
    const child = spawn(cmd, args, { env, cwd, stdio: ['pipe', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    const timer = setTimeout(() => child.kill('SIGKILL'), 30_000)
    child.stdout.on('data', (d: Buffer) => (stdout += d.toString('utf-8')))
    child.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf-8')))
    child.on('error', reject)
    child.on('close', (status) => {
      clearTimeout(timer)
      resolveRun({ status, stdout, stderr })
    })
    child.stdin.end(stdin)
  })
}

function hookEnv(w: World): Record<string, string> {
  return {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    HOME: w.home,
    LC_ALL: 'en_US.UTF-8',
    EMAIL_APPROVAL_GATE_STORE: w.store,
    EMAIL_APPROVAL_WINDOW_S: '1800',
    OUTGOING_COPY_GATE_RULES: join(w.store, 'no-rules.json'),
    GRAPH_MAIL_OUTBOX_DIR: w.outbox,
    WEB_PORT: String(w.webPort),
  }
}

const payloadOf = (command: string): string => JSON.stringify({ tool_name: 'Bash', tool_input: { command } })

interface Gates {
  copy: HookRun
  approval: HookRun
  /** Both exited 0: the harness would run the command. */
  passed: boolean
}

async function gates(w: World, command: string): Promise<Gates> {
  const payload = payloadOf(command)
  const env = hookEnv(w)
  const copy = await runChild('python3', ['-I', COPY_GATE], env, payload)
  const approval = await runChild('python3', ['-I', APPROVAL_GATE], env, payload)
  return { copy, approval, passed: copy.status === 0 && approval.status === 0 }
}

/** The sub-agent gate on the same payload: a deny decision on stdout, exit 0. */
async function subagentGate(w: World, command: string): Promise<{ status: number | null; deny: boolean; stdout: string }> {
  const r = await runChild('node', [SUBAGENT_GATE], { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: w.home }, payloadOf(command), REPO)
  let deny = false
  try {
    deny = (JSON.parse(r.stdout) as { hookSpecificOutput?: { permissionDecision?: string } }).hookSpecificOutput?.permissionDecision === 'deny'
  } catch {
    deny = false
  }
  return { status: r.status, deny, stdout: r.stdout }
}

// ---------------------------------------------------------------------------
// The CLI, with the argv a real bash hands over
// ---------------------------------------------------------------------------

/**
 * The words bash passes to the program for the part of `command` after
 * `forward`: the same shell parsing as the real command, with printf in place
 * of the program. Only ever called with commands the gates accepted (no `$`,
 * backtick, backslash, newline operator or other metacharacter outside quotes).
 */
function bashArgv(command: string): string[] {
  const head = command.match(/^[ \t]*(?:npx[ \t]+)?tsx[ \t]+\S*graph-mail\.ts[ \t]+forward(?=[ \t])/)
  expect(head, command).not.toBeNull()
  const rest = command.slice((head as RegExpMatchArray)[0].length)
  const r = spawnSync('/bin/bash', ['-c', `printf '%s\\0' ${rest}`], { encoding: 'buffer', env: { PATH: '/usr/bin:/bin' }, timeout: 10_000 })
  expect(r.status).toBe(0)
  const words = r.stdout.toString('utf-8').split('\0')
  words.pop() // the empty tail after the last NUL
  return words
}

// Preloaded into the CLI process: replaces global fetch, answers from the
// scenario file, records every call.
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
  "  else if (method === 'GET' && url.includes('/messages/')) kind = 'message'",
  "  const body = kind === 'token' ? null : typeof init.body === 'string' ? init.body : null",
  '  appendFileSync(logPath, JSON.stringify({ kind, method, url, body }) + "\\n")',
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
interface Scenario {
  token?: Reply
  message?: Reply
  forward?: Reply
}
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

const TOKEN_OK: Reply = { status: 200, body: { access_token: FAKE_TOKEN, token_type: 'Bearer', expires_in: 3600 } }
const msgReply = (subject: string): Reply => ({ status: 200, body: { id: ID, subject } })
const SUCCESS: Scenario = { token: TOKEN_OK, message: msgReply(SUBJECT), forward: { status: 202 } }

const OUTPUTS: string[] = []
let runSeq = 0

function cliSpec(w: World, scenario: Scenario): { env: Record<string, string>; logPath: string } {
  const n = ++runSeq
  const scenarioPath = join(BASE, `scenario-${n}.json`)
  const logPath = join(BASE, `fetch-${n}.jsonl`)
  writeFileSync(scenarioPath, JSON.stringify(scenario))
  const env: Record<string, string> = {
    PATH: process.env.PATH ?? '/usr/bin:/bin',
    // tsx puts its IPC pipe under TMPDIR; without it the pipe lands in /tmp, which safe-vitest.sb denies
    ...(process.env.TMPDIR ? { TMPDIR: process.env.TMPDIR } : {}),
    HOME: w.home,
    NODE_ENV: 'production', // JSON logger lines on stdout: the secret grep reads them too
    MARVEEN_MAIL_CREDS: CREDS,
    GRAPH_MAIL_OUTBOX_DIR: w.outbox,
    WEB_PORT: String(w.webPort), // the helper's standing trace posts the owner's daily log here
    GF_FETCH_SCENARIO: scenarioPath,
    GF_FETCH_LOG: logPath,
    NODE_OPTIONS: `--import=${pathToFileURL(STUB).href}`,
  }
  return { env, logPath }
}

function finishRun(logPath: string, r: { status: number | null; signal: NodeJS.Signals | null; stdout: string; stderr: string }): CliRun {
  const calls = existsSync(logPath)
    ? readFileSync(logPath, 'utf-8')
        .split('\n')
        .filter(Boolean)
        .map((l) => JSON.parse(l) as FetchCall)
    : []
  OUTPUTS.push(`${r.stdout}\n${r.stderr}`)
  return { status: r.status, signal: r.signal, stdout: r.stdout, stderr: r.stderr, calls }
}

/** The CLI of the world's own root, synchronously (blocks this process: no stub server of this test can answer meanwhile). */
function runCli(w: World, argv: string[], scenario: Scenario = SUCCESS): CliRun {
  const { env, logPath } = cliSpec(w, scenario)
  const r = spawnSync(TSX, [join(w.root, 'scripts', 'graph-mail.ts'), ...argv], { cwd: w.root, env, encoding: 'utf-8', timeout: 60_000 })
  return finishRun(logPath, r)
}

/** The same, asynchronously: the event loop stays free for a loopback stub server. */
async function runCliAsync(w: World, argv: string[], scenario: Scenario = SUCCESS): Promise<CliRun> {
  const { env, logPath } = cliSpec(w, scenario)
  const r = await runChild(TSX, [join(w.root, 'scripts', 'graph-mail.ts'), ...argv], env, '', w.root)
  return finishRun(logPath, { ...r, signal: null })
}

const kinds = (r: CliRun): string[] => r.calls.map((c) => c.kind)
const postedComment = (r: CliRun): unknown => {
  const post = r.calls.find((c) => c.kind === 'forward')
  return post?.body ? (JSON.parse(post.body) as { comment?: unknown }).comment : undefined
}

interface Chain extends Gates {
  /** null: a gate blocked, the command never ran. */
  cli: CliRun | null
}

/** Gates, and only when both pass, the CLI on the argv bash would pass. */
async function chain(w: World, command: string, scenario: Scenario = SUCCESS): Promise<Chain> {
  const g = await gates(w, command)
  if (!g.passed) return { ...g, cli: null }
  return { ...g, cli: await runCliAsync(w, cliArgv(command), scenario) }
}

/** The CLI's argv: the subcommand and the words bash passed. */
const cliArgv = (command: string): string[] => ['forward', ...bashArgv(command)]

/** The gate's own reading of a forward command (parse_forward_command), for the bash differential. */
function gateFields(w: World, command: string): { fields: Record<string, string> | null; reason: string | null } {
  const script = join(BASE, 'gate-fields.py')
  if (!existsSync(script)) {
    writeFileSync(
      script,
      [
        'import importlib.util, json, sys',
        'spec = importlib.util.spec_from_file_location("gf_extract", sys.argv[1])',
        'mod = importlib.util.module_from_spec(spec)',
        'spec.loader.exec_module(mod)',
        'fields, reason = mod.parse_forward_command(sys.stdin.read())',
        'print(json.dumps({"fields": fields, "reason": reason}, ensure_ascii=False))',
        '',
      ].join('\n'),
    )
  }
  const r = spawnSync('python3', ['-I', script, EXTRACT], {
    input: command,
    encoding: 'utf-8',
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', LC_ALL: 'en_US.UTF-8', GRAPH_MAIL_OUTBOX_DIR: w.outbox },
    timeout: 15_000,
  })
  expect(r.status, r.stderr).toBe(0)
  return JSON.parse(r.stdout) as { fields: Record<string, string> | null; reason: string | null }
}

// ---------------------------------------------------------------------------
// Self-tests: the sandbox is on, the stub port is not a forbidden one
// ---------------------------------------------------------------------------

describe('test harness self-checks', () => {
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
  })

  it('a world without a stub has no dashboard token and a port that is not a service port', () => {
    const w = newWorld()
    expect(existsSync(join(w.store, '.dashboard-token'))).toBe(false)
    expect(FORBIDDEN_PORTS).not.toContain(w.webPort)
  })
})

// ---------------------------------------------------------------------------
// Inline comment: the standing / approval matrix
// ---------------------------------------------------------------------------

describe('inline forward through the real chain', () => {
  it(
    'standing address, activated: both gates pass, the trace is written, the CLI posts exactly the comment',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      // the hooks alone (peek): they pass, and they leave NO standing trace behind
      const g = await gates(w, inlineCmd())
      expect(g.copy.status, g.copy.stderr).toBe(0)
      expect(g.approval.status, g.approval.stderr).toBe(0)
      expect(g.approval.stdout).toContain('allando cimzett')
      expect(standingLog(w)).toBe('')
      // the CLI run writes the trace (exactly once) and sends
      const cli = runCli(w, cliArgv(inlineCmd()))
      expect(cli.status, cli.stderr).toBe(0)
      expect(kinds(cli)).toEqual(['token', 'message', 'forward'])
      expect(JSON.parse(cli.calls[2].body as string)).toEqual({
        comment: COMMENT,
        toRecipients: [{ emailAddress: { address: TO } }],
      })
      // KC5: the local trace says "allowed", never "sent", and carries the facts
      const log = standingLog(w)
      expect(log).toContain('tovabbitas engedelyezve jovahagyas nelkul')
      expect(log).toContain('a tenyleges kuldest a CLI kimenete igazolja')
      expect(log).toContain(`cimzett=${TO}`)
      expect(log).toContain('komment-forras=inline')
      expect(log).toContain(`komment-sha256=${sha(COMMENT)}`)
      expect(log).toContain(`komment-hossz=${[...COMMENT].length}`)
      expect(log).toContain(`tovabbitott-targy=${JSON.stringify(SUBJECT).replace(/^"|"$/g, "'")}`)
      expect(log).toContain(`id=${ID.slice(0, 16)}...`)
      expect(log).not.toMatch(/\bment ki\b/)
      expect(log.trim().split('\n')).toHaveLength(1)
      // no approval was spent
      expect(letterRows(w)).toEqual([])
    },
    T,
  )

  it(
    'not on any list: deny with the anchor -> approval written -> passes -> the same call is denied again (consumed)',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] }) // TO is live, but we forward to TO2
      const first = await chain(w, inlineCmd({ to: TO2 }))
      expect(first.approval.status).toBe(2)
      expect(first.approval.stderr).toContain('NINCS jovahagyas')
      expect(first.approval.stderr).toContain('to+cc+komment+a tovabbitott level azonositoja es targya')
      expect(first.cli).toBeNull()
      const anchor = anchorOf(first.approval.stderr)

      approveLetter(w, anchor)
      const second = await chain(w, inlineCmd({ to: TO2 }))
      expect(second.approval.status, second.approval.stderr).toBe(0)
      // the hook only peeks: the CLI is the one that spends the approval, at the send
      expect(second.approval.stdout).toContain('a CLI egyszer-hasznalatosan fogyasztja')
      const cli = second.cli as CliRun
      expect(cli.status, cli.stderr).toBe(0)
      expect(kinds(cli)).toEqual(['token', 'message', 'forward'])
      expect(letterRows(w).map((r) => r.consumed_at !== null)).toEqual([true])

      // spent: the hook already says so, and a CLI started anyway is refused too
      const third = await chain(w, inlineCmd({ to: TO2 }))
      expect(third.approval.status).toBe(2)
      expect(third.approval.stderr).toContain('FEL LETT HASZNALVA')
      expect(third.cli).toBeNull()
      const direct = runCli(w, cliArgv(inlineCmd({ to: TO2 })))
      expect(direct.status).toBe(2)
      expect(direct.stderr).toContain('graph-mail: REFUSED consumed')
      expect(kinds(direct)).not.toContain('forward')
    },
    T,
  )

  it(
    'a listed but not activated address is denied with its own anchor; the approval of the letter does not open that path',
    async () => {
      const w = newWorld({ standing: [TO] }) // listed, never activated
      const first = await chain(w, inlineCmd())
      expect(first.approval.status).toBe(2)
      expect(first.approval.stderr).toContain('NINCS')
      expect(first.approval.stderr).toContain('ELESITVE')
      expect(first.cli).toBeNull()
      expect(standingLog(w)).toBe('') // no trace: nothing was authorised
      // the anchor in this deny is the ADDRESS anchor, not the letter's
      expect(anchorOf(first.approval.stderr)).toBe(sha(TO))
    },
    T,
  )

  it(
    'CURRENT BEHAVIOUR (same for a plain send, not graph-forward code): for a listed but not activated address even a matching per-letter approval is not consulted',
    async () => {
      // the letter anchor, taken from a world where the address is not listed
      const plain = newWorld()
      const letterAnchor = anchorOf((await chain(plain, inlineCmd())).approval.stderr)
      const w = newWorld({ standing: [TO] })
      approveLetter(w, letterAnchor)
      const c = await chain(w, inlineCmd())
      expect(c.approval.status).toBe(2)
      expect(c.approval.stderr).toContain('ELESITVE')
      expect(letterRows(w).map((r) => r.consumed_at)).toEqual([null]) // the approval was not spent either
      expect(c.cli).toBeNull()
    },
    T,
  )

  it(
    'messageId swap: an approval for one message cannot forward another; the approved one still works afterwards',
    async () => {
      const w = newWorld()
      const first = await chain(w, inlineCmd({ id: ID }))
      expect(first.approval.status).toBe(2)
      approveLetter(w, anchorOf(first.approval.stderr))

      const swapped = await chain(w, inlineCmd({ id: ID2 }))
      expect(swapped.approval.status).toBe(2)
      expect(swapped.approval.stderr).toContain('NINCS jovahagyas')
      expect(swapped.cli).toBeNull()
      expect(letterRows(w).map((r) => r.consumed_at)).toEqual([null]) // not spent by the wrong call

      const ok = await chain(w, inlineCmd({ id: ID }))
      expect(ok.approval.status, ok.approval.stderr).toBe(0)
      expect((ok.cli as CliRun).status).toBe(0)
    },
    T,
  )

  it(
    'subject swap in the command: the anchor covers --orig-subject, so the approval does not match',
    async () => {
      const w = newWorld()
      const first = await chain(w, inlineCmd())
      approveLetter(w, anchorOf(first.approval.stderr))
      const swapped = await chain(w, inlineCmd({ subject: 'Teljesen más tárgy' }))
      expect(swapped.approval.status).toBe(2)
      expect(swapped.approval.stderr).toContain('NINCS jovahagyas')
      expect(swapped.cli).toBeNull()
    },
    T,
  )

  it(
    'subject swap at the message: the gates pass, the CLI exits 2 and posts nothing',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const c = await chain(w, inlineCmd(), { ...SUCCESS, message: msgReply('Egy másik levél tárgya') })
      expect(c.passed).toBe(true)
      const cli = c.cli as CliRun
      expect(cli.status).toBe(2)
      expect(cli.stderr).toContain('--orig-subject does not match the message subject. Nothing was sent.')
      expect(kinds(cli)).toEqual(['token', 'message'])
      expect(kinds(cli)).not.toContain('forward')
    },
    T,
  )

  it(
    'approval and subject swap: an approved forward whose message subject differs posts nothing and keeps the approval; the right subject then goes out',
    async () => {
      const w = newWorld()
      const first = await chain(w, inlineCmd())
      approveLetter(w, anchorOf(first.approval.stderr))
      const c = await chain(w, inlineCmd(), { ...SUCCESS, message: msgReply('Más tárgy') })
      expect(c.passed).toBe(true)
      expect((c.cli as CliRun).status).toBe(2)
      expect(kinds(c.cli as CliRun)).not.toContain('forward')
      // the subject check comes BEFORE the authorizer, and only the CLI spends: the approval is untouched
      expect(letterRows(w).map((r) => r.consumed_at)).toEqual([null])
      const retry = await chain(w, inlineCmd())
      expect(retry.passed).toBe(true)
      expect((retry.cli as CliRun).status).toBe(0)
      expect(kinds(retry.cli as CliRun)).toEqual(['token', 'message', 'forward'])
      expect(letterRows(w).map((r) => r.consumed_at !== null)).toEqual([true])
    },
    T,
  )

  it.each([
    ['foreign domain', `${HEAD} --id ${ID} --to ext@example.com --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['fireeng.hu lookalike domain', `${HEAD} --id ${ID} --to ext@fireeng.hu.example.com --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['cc', `${HEAD} --id ${ID} --to ${TO} --cc ${TO2} --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['bcc', `${HEAD} --id ${ID} --to ${TO} --bcc ${TO2} --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['two --to flags', `${HEAD} --id ${ID} --to ${TO} --to ${TO2} --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['two addresses in one --to', `${HEAD} --id ${ID} --to ${q(`${TO},${TO2}`)} --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
    ['attachment', `${HEAD} --id ${ID} --to ${TO} --attach /private/tmp/x.pdf --comment ${q(COMMENT)} --orig-subject ${q(SUBJECT)}`],
  ])('%s: the approval gate denies at every level, even for an activated standing address', async (_label, command) => {
    for (const level of [2, 3]) {
      const w = newWorld({ level, standing: [TO, TO2], live: [TO, TO2] })
      const c = await chain(w, command)
      expect(c.approval.status, `level ${level}`).toBe(2)
      expect(c.approval.stderr).toContain('Graph-mail kapu (graph-mail parancs)')
      expect(c.cli, `level ${level}`).toBeNull()
      expect(standingLog(w)).toBe('')
    }
  }, T)

  it(
    'level 1 denies a valid forward to an activated standing address; level 3 lets it through the approval gate',
    async () => {
      const w1 = newWorld({ level: 1, standing: [TO], live: [TO] })
      const c1 = await chain(w1, inlineCmd())
      expect(c1.approval.status).toBe(2)
      expect(c1.cli).toBeNull()
      const w3 = newWorld({ level: 3 })
      const c3 = await chain(w3, inlineCmd())
      expect(c3.approval.status, c3.approval.stderr).toBe(0)
      expect((c3.cli as CliRun).status).toBe(0)
    },
    T,
  )

  it(
    'a send approval for the same to and text does not authorise a forward',
    async () => {
      const w = newWorld()
      // the anchor of a plain send with the same recipient and text
      const sendCmd = `npx tsx scripts/graph-mail.ts send --to ${TO} --subject ${q(SUBJECT)} --body ${q(COMMENT)}`
      const denied = await gates(w, sendCmd)
      expect(denied.approval.status).toBe(2)
      approveLetter(w, anchorOf(denied.approval.stderr))
      const fwd = await chain(w, inlineCmd())
      expect(fwd.approval.status).toBe(2)
      expect(fwd.approval.stderr).toContain('NINCS jovahagyas')
      expect(fwd.cli).toBeNull()
    },
    T,
  )

  it(
    'the sub-agent gate denies the same commands the main-agent gates accept',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const inline = inlineCmd()
      const f = putFile(w, 'a.txt', FILE_TEXT)
      const file = fileCmd(f.path, f.hex)
      for (const command of [inline, file]) {
        const g = await gates(w, command)
        expect(g.passed).toBe(true) // the main agent would run it ...
        const sub = await subagentGate(w, command)
        expect(sub.status).toBe(0)
        expect(sub.deny, sub.stdout).toBe(true) // ... a sub-agent may not
      }
    },
    T,
  )
})

// ---------------------------------------------------------------------------
// File comment
// ---------------------------------------------------------------------------

describe('file forward through the real chain', () => {
  it(
    'activated standing address: gates pass, the trace follows KC5, the POST comment is the file text exactly',
    async () => {
      // the trace's daily-log post goes to a stub of this test, on a loopback port of its own
      const received: Array<{ auth: string | undefined; body: { content?: string; agent_id?: string } }> = []
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
        const w = newWorld({ standing: [TO], live: [TO], webPort: port })
        const f = putFile(w, '20261018-213000-kovacs.txt', FILE_TEXT)
        const c = await chain(w, fileCmd(f.path, f.hex))
        expect(c.copy.status, c.copy.stderr).toBe(0)
        expect(c.approval.status, c.approval.stderr).toBe(0)
        const cli = c.cli as CliRun
        expect(cli.status, cli.stderr).toBe(0)
        // card f90928e3 (B): after the forward the CLI makes ONE best-effort fetch to the dashboard
        // daily log; this world's fetch stub has no answer for it, which only costs a stderr note.
        expect(kinds(cli)).toEqual(['token', 'message', 'forward', 'other'])
        expect(cli.calls[3].url).toBe(`http://127.0.0.1:${port}/api/daily-log`)
        expect(postedComment(cli)).toBe(FILE_TEXT)

        const log = standingLog(w)
        expect(log).toContain('tovabbitas engedelyezve jovahagyas nelkul')
        expect(log).toContain('komment-forras=file')
        expect(log).toContain(`komment-sha256=${f.hex}`)
        expect(log).toContain(`komment-hossz=${[...FILE_TEXT].length}`)
        expect(log).toContain('gazda-ertesites=ok')
        // at most 120 characters of the text head, never the whole comment
        expect(log).toContain('Szia Béla!')
        expect(log).not.toContain('Brainy, Gyuri AI asszisztense')

        // the same facts in the owner's daily log
        expect(received).toHaveLength(1)
        expect(received[0].auth).toBe('Bearer FAKE-dashboard-token-for-the-stub')
        const entry = received[0].body.content ?? ''
        expect(entry).toContain('Tovabbitas engedelyezve jovahagyas nelkul')
        expect(entry).toContain('komment-forras=file')
        expect(entry).toContain(`komment-sha256=${f.hex}`)
        expect(entry).toContain(`komment-hossz=${[...FILE_TEXT].length}`)
        expect(entry).toContain(`Cimzett: ${TO}`)
        expect(entry).toContain(SUBJECT)
        expect(entry).not.toContain('Brainy, Gyuri AI asszisztense')
      } finally {
        await new Promise<void>((done) => server.close(() => done()))
      }
    },
    T,
  )

  it(
    'unapproved file forward: the deny shows the facts and the anchor, not the whole text; approval -> passes',
    async () => {
      const w = newWorld()
      const marker = 'MARKERTAIL9z4'
      const text = `${FILE_TEXT}${'Ez egy hosszú, ékezetes bekezdés a levél végén. '.repeat(8)}${marker} Köszönöm!\n`
      const f = putFile(w, 'a.txt', text)
      const first = await chain(w, fileCmd(f.path, f.hex))
      expect(first.approval.status).toBe(2)
      expect(first.approval.stderr).toContain('Komment: fajl a.txt')
      expect(first.approval.stderr).toContain(`sha256: ${f.hex.slice(0, 16)}`)
      expect(first.approval.stderr).not.toContain(marker)
      expect(first.cli).toBeNull()
      approveLetter(w, anchorOf(first.approval.stderr.replace(f.hex, '')))
      const second = await chain(w, fileCmd(f.path, f.hex))
      expect(second.approval.status, second.approval.stderr).toBe(0)
      expect(postedComment(second.cli as CliRun)).toBe(text)
    },
    T,
  )

  it(
    'hash mismatch between the command and the file: both gates deny, nothing runs',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const f = putFile(w, 'a.txt', FILE_TEXT)
      const c = await chain(w, fileCmd(f.path, sha(`${FILE_TEXT} `)))
      expect(c.approval.status).toBe(2)
      expect(c.approval.stderr).toContain('sha256-ja nem egyezik')
      expect(c.copy.status).toBe(2)
      expect(c.cli).toBeNull()
      expect(standingLog(w)).toBe('')
    },
    T,
  )

  describe('TOCTOU: the gates pass, then the file changes before the CLI runs', () => {
    it(
      'rewritten in place: the CLI exits 2 without a single fetch',
      async () => {
        const w = newWorld({ standing: [TO], live: [TO] })
        const f = putFile(w, 'a.txt', FILE_TEXT)
        const command = fileCmd(f.path, f.hex)
        const g = await gates(w, command)
        expect(g.passed).toBe(true)
        writeFileSync(f.path, 'Szia! Ezt senki nem hagyta jóvá.')
        const cli = runCli(w, cliArgv(command))
        expect(cli.status).toBe(2)
        expect(cli.stderr).toContain('--comment-sha256 does not match the comment file')
        expect(cli.calls).toEqual([])
      },
      T,
    )

    it(
      'replaced by a symlink to another file: the CLI exits 2 without a single fetch',
      async () => {
        const w = newWorld({ standing: [TO], live: [TO] })
        const f = putFile(w, 'a.txt', FILE_TEXT)
        const evil = join(newWorld().dir, 'evil.txt')
        writeFileSync(evil, FILE_TEXT) // even the SAME bytes: a link is refused outright
        const command = fileCmd(f.path, f.hex)
        const g = await gates(w, command)
        expect(g.passed).toBe(true)
        renameSync(f.path, `${f.path}.moved`)
        symlinkSync(evil, f.path)
        const cli = runCli(w, cliArgv(command))
        expect(cli.status).toBe(2)
        expect(cli.stderr).toContain('is a symlink')
        expect(cli.calls).toEqual([])
      },
      T,
    )

    it(
      'deleted: the CLI exits 2 without a single fetch',
      async () => {
        const w = newWorld({ standing: [TO], live: [TO] })
        const f = putFile(w, 'a.txt', FILE_TEXT)
        const command = fileCmd(f.path, f.hex)
        expect((await gates(w, command)).passed).toBe(true)
        unlinkSync(f.path)
        const cli = runCli(w, cliArgv(command))
        expect(cli.status).toBe(2)
        expect(cli.stderr).toContain('does not exist')
        expect(cli.calls).toEqual([])
      },
      T,
    )

    it(
      'turned into a hard-linked file: the CLI exits 2 without a single fetch',
      async () => {
        const w = newWorld({ standing: [TO], live: [TO] })
        const f = putFile(w, 'a.txt', FILE_TEXT)
        const command = fileCmd(f.path, f.hex)
        expect((await gates(w, command)).passed).toBe(true)
        linkSync(f.path, join(w.outbox, 'b.txt'))
        const cli = runCli(w, cliArgv(command))
        expect(cli.status).toBe(2)
        expect(cli.stderr).toContain('2 hard links')
        expect(cli.calls).toEqual([])
      },
      T,
    )
  })

  describe('the gates deny a bad file; the CLI never starts', () => {
    const cases: Array<{ label: string; make: (w: World) => { command: string }; reason: RegExp }> = [
      {
        label: 'a path outside the outbox root',
        make: (w) => {
          const other = join(newWorld().dir, 'a.txt')
          writeFileSync(other, FILE_TEXT)
          return { command: fileCmd(other, sha(FILE_TEXT)) }
        },
        reason: /nem pontosan <kimeno-mappa>\/<nev> alaku/,
      },
      {
        label: '16385 bytes',
        make: (w) => {
          const big = Buffer.from(`${'a'.repeat(16384)}b`)
          const f = putFile(w, 'big.txt', big)
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /nagyobb, mint 16384 bajt/,
      },
      {
        label: 'invalid UTF-8',
        make: (w) => {
          const bad = Buffer.concat([Buffer.from('Szia, ezért '), Buffer.from([0xc3, 0x28]), Buffer.from(' köszönöm.')])
          const f = putFile(w, 'bad.txt', bad)
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /nem ervenyes UTF-8/,
      },
      {
        label: 'a zero-width space in the text',
        make: (w) => {
          const f = putFile(w, 'zw.txt', `Szia Béla!\u200b Köszönöm a segítséget.`)
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /tiltott karakter a komment-fajlban: U\+200B/,
      },
      {
        label: 'a blank file',
        make: (w) => {
          const f = putFile(w, 'blank.txt', ' \n\t\n')
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /ures vagy csak whitespace/,
      },
      {
        label: 'a symlink in the outbox',
        make: (w) => {
          const real = join(w.dir, 'real.txt')
          writeFileSync(real, FILE_TEXT)
          const link = join(w.outbox, 'link.txt')
          symlinkSync(real, link)
          return { command: fileCmd(link, sha(FILE_TEXT)) }
        },
        reason: /nem nyithato meg symlink-kovetes nelkul/,
      },
      {
        label: 'a missing outbox root',
        make: (w) => {
          const f = putFile(w, 'a.txt', FILE_TEXT)
          renameSync(w.outbox, `${w.outbox}-gone`)
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /a kimeno-mappa hianyzik/,
      },
      {
        label: 'a group-writable outbox root',
        make: (w) => {
          const f = putFile(w, 'a.txt', FILE_TEXT)
          chmodSync(w.outbox, 0o770)
          return { command: fileCmd(f.path, f.hex) }
        },
        reason: /csoport- vagy mindenki-irhato/,
      },
    ]
    it.each(cases.map((c) => [c.label, c] as const))('%s', async (_label, c) => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const { command } = c.make(w)
      const r = await chain(w, command)
      expect(r.approval.status, r.approval.stderr).toBe(2)
      expect(r.approval.stderr).toMatch(c.reason)
      expect(r.copy.status, r.copy.stderr).toBe(2)
      expect(r.cli).toBeNull()
      expect(standingLog(w)).toBe('')
    }, T)
  })

  it(
    'the 16384-byte limit itself passes both gates and the CLI posts all of it',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const para = 'Szia Béla! Gyuri most úton van, ezért továbbítom neked ezt a levelet. Köszönöm a segítségedet.\n'
      let text = para.repeat(Math.floor(16384 / Buffer.byteLength(para)))
      text += 'a'.repeat(16384 - Buffer.byteLength(text))
      expect(Buffer.byteLength(text)).toBe(16384)
      const f = putFile(w, 'limit.txt', text)
      const c = await chain(w, fileCmd(f.path, f.hex))
      expect(c.copy.status, c.copy.stderr).toBe(0)
      expect(c.approval.status, c.approval.stderr).toBe(0)
      const cli = c.cli as CliRun
      expect(cli.status, cli.stderr).toBe(0)
      expect(postedComment(cli)).toBe(text)
    },
    T,
  )

  it(
    'the copy gate denies an accentless file while the approval gate alone would have let it pass',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const text =
        'Szia Bela! Gyuri most uton van, ezert tovabbitom neked ezt a levelet. A hatarido pentek, kerlek, nezd meg meg ma. Koszonom a segitseget!\n'
      const f = putFile(w, 'plain.txt', text)
      const c = await chain(w, fileCmd(f.path, f.hex))
      expect(c.copy.status).toBe(2)
      expect(c.copy.stderr).toContain('KIMENO-SZOVEG KAPU')
      expect(c.approval.status).toBe(0) // the standing path allows: this is what the copy gate stands in front of
      expect(c.cli).toBeNull() // the chain stops: not both gates passed
      expect(c.passed).toBe(false)
    },
    T,
  )

  it(
    'a copy-gate-clean file with an em dash is denied by the copy gate',
    async () => {
      const w = newWorld({ standing: [TO], live: [TO] })
      const f = putFile(w, 'dash.txt', 'Szia Béla! Gyuri úton van — kérlek, nézd meg ezt a levelet még ma.\n')
      const c = await chain(w, fileCmd(f.path, f.hex))
      expect(c.copy.status).toBe(2)
      expect(c.cli).toBeNull()
    },
    T,
  )
})

// ---------------------------------------------------------------------------
// Bash differential: what the gate read is what bash passes to the CLI
// ---------------------------------------------------------------------------

describe('bash differential (no `$` in any vector)', () => {
  const w = newWorld()
  const f = putFile(w, 'diff.txt', FILE_TEXT)
  const f2 = putFile(w, 'diff-2.txt', 'Szia! Kérlek, nézd meg.\n')

  const inline: Array<[string, string]> = [
    ['single-quoted comment and subject', `${HEAD} --id ${ID} --to ${TO} --comment 'Szia Andi! Kérlek, nézd meg.' --orig-subject 'Tárgy: egy'`],
    ['double-quoted comment and subject', `${HEAD} --id ${ID} --to ${TO} --comment "Szia Andi! Kérlek, nézd meg." --orig-subject "Tárgy: egy"`],
    ['bare words', `${HEAD} --id ${ID} --to ${TO} --comment Szia --orig-subject Targy`],
    ['several spaces', `${HEAD}   --id   ${ID}   --to   ${TO}   --comment   'a'   --orig-subject   'b'`],
    ['no npx, the pinned repo-relative path (Q2: any other path is refused)', `tsx scripts/graph-mail.ts forward --id ${ID} --to ${TO} --comment 'Szia' --orig-subject 'T'`],
    ['flags in reverse order', `${HEAD} --orig-subject 'T' --comment 'Szia Béla' --to ${TO} --id ${ID}`],
    ['shell operators inside quotes', `${HEAD} --id ${ID} --to ${TO} --comment 'a; b | c && d > e < f & g' --orig-subject 'T'`],
    ['glob and hash characters inside quotes', `${HEAD} --id ${ID} --to ${TO} --comment 'a * b ? c [d] # e ~ f {g}' --orig-subject 'T'`],
    ['an apostrophe inside double quotes', `${HEAD} --id ${ID} --to ${TO} --comment "it's fine" --orig-subject 'T'`],
    ['a double quote inside single quotes', `${HEAD} --id ${ID} --to ${TO} --comment 'she said "hi"' --orig-subject 'T'`],
    ['an upper-case address', `${HEAD} --id ${ID} --to Kovacs@FIREENG.HU --comment 'Szia' --orig-subject 'T'`],
    ['an empty subject', `${HEAD} --id ${ID} --to ${TO} --comment 'Szia' --orig-subject ''`],
  ]
  const file: Array<[string, string]> = [
    ['file form', fileCmd(f.path, f.hex)],
    ['file form, reversed', `${HEAD} --orig-subject 'T' --comment-sha256 ${f2.hex} --comment-file ${f2.path} --to ${TO} --id ${ID}`],
    ['file form, quoted path and hash', `${HEAD} --id ${ID} --to ${TO} --comment-file '${f.path}' --comment-sha256 "${f.hex}" --orig-subject 'T'`],
  ]
  // The gate is free to refuse these; whatever it accepts must still match bash.
  const trouble: Array<[string, string]> = [
    // r3 (Brainy 3092): a comment is ONE line in the command; a multi-line comment is a --comment-file
    ['a newline inside the comment (refused since r3)', `${HEAD} --id ${ID} --to ${TO} --comment 'Szia!\nKöszönöm.' --orig-subject 'T'`],
    ['TAB separators (the extractor regex wants spaces)', `${HEAD}\t--id\t${ID}\t--to\t${TO}\t--comment\t'a b'\t--orig-subject\t'c d'`],
    ['a comment that spells a flag after a space', `${HEAD} --id ${ID} --to ${TO} --comment 'see the --to line' --orig-subject 'T'`],
    ['a flag written inside another value', `${HEAD} --id ${ID} --to ${TO} --comment 'x --to evil@fireeng.hu' --orig-subject 'T'`],
    ['adjacent quotes joined by bash', `${HEAD} --id ${ID} --to ${TO} --comment 'a''b' --orig-subject 'T'`],
    ['a flag glued to its value with =', `${HEAD} --id ${ID} --to=${TO} --comment 'a' --orig-subject 'T'`],
    ['a quoted flag', `${HEAD} --id ${ID} '--to' ${TO} --comment 'a' --orig-subject 'T'`],
    ['a quoted flag name in two halves', `${HEAD} --id ${ID} --t'o' ${TO} --comment 'a' --orig-subject 'T'`],
    ['a second command', `${HEAD} --id ${ID} --to ${TO} --comment 'a' --orig-subject 'T'; echo hi`],
    ['a redirect', `${HEAD} --id ${ID} --to ${TO} --comment 'a' --orig-subject 'T' > /private/tmp/x`],
    ['a glob outside quotes', `${HEAD} --id ${ID} --to ${TO} --comment a* --orig-subject 'T'`],
    ['a tilde', `${HEAD} --id ${ID} --to ${TO} --comment ~ --orig-subject 'T'`],
    ['a brace expansion', `${HEAD} --id ${ID} --to ${TO} --comment {a,b} --orig-subject 'T'`],
    ['a comment and a comment file together', `${HEAD} --id ${ID} --to ${TO} --comment 'a' --comment-file ${f.path} --comment-sha256 ${f.hex} --orig-subject 'T'`],
  ]

  it('every vector has no dollar sign, backtick or backslash', () => {
    for (const [, cmd] of [...inline, ...file, ...trouble]) expect(cmd).not.toMatch(/[$`\\]/)
  })

  it(
    'for every command the gate accepts, the argv bash passes equals the gate reading, field by field',
    () => {
      let accepted = 0
      const acceptedLabels: string[] = []
      for (const [label, command] of [...inline, ...file, ...trouble]) {
        const { fields, reason } = gateFields(w, command)
        if (fields === null) {
          expect(reason, label).not.toBeNull()
          continue
        }
        accepted++
        acceptedLabels.push(label)
        const argv = bashArgv(command)
        const at = (flag: string): string | undefined => {
          const i = argv.indexOf(flag)
          return i < 0 ? undefined : argv[i + 1]
        }
        // each flag exactly once in what bash passes
        for (const flag of argv.filter((a, i) => i % 2 === 0)) expect(argv.filter((a, i) => i % 2 === 0 && a === flag), label).toHaveLength(1)
        expect(at('--id'), label).toBe(fields.id)
        expect(at('--to'), label).toBe(fields.to)
        expect(at('--orig-subject'), label).toBe(fields.subject)
        if (fields.source === 'inline') {
          expect(at('--comment'), label).toBe(fields.comment)
          expect(at('--comment-file'), label).toBeUndefined()
          expect(sha(at('--comment') as string), label).toBe(fields.comment_sha256)
        } else {
          expect(fields.source, label).toBe('file')
          expect(at('--comment-file'), label).toBe(join(w.outbox, fields.comment_file))
          expect(at('--comment-sha256'), label).toBe(fields.comment_sha256)
          expect(at('--comment'), label).toBeUndefined()
          // and the file the CLI will read holds the text the gate read
          expect(sha(readFileSync(at('--comment-file') as string)), label).toBe(fields.comment_sha256)
          expect(readFileSync(at('--comment-file') as string, 'utf-8'), label).toBe(fields.comment)
        }
      }
      // not vacuous: exactly the plain vectors are accepted, and they were all compared
      expect(acceptedLabels).toEqual([...inline, ...file].map(([label]) => label))
      expect(accepted).toBe(inline.length + file.length)
    },
    T,
  )

  it('the troublemakers are refused by the gate (a refused command is never run, so bash never sees it)', () => {
    for (const [label, command] of trouble) {
      const { fields, reason } = gateFields(w, command)
      expect(fields, label).toBeNull()
      expect(reason, label).not.toBeNull()
    }
  })
})

// ---------------------------------------------------------------------------
// No credential in any output of any CLI run in this file
// ---------------------------------------------------------------------------

describe('E8: no credential in any CLI output', () => {
  it('no CLI run printed the client secret or the access token', () => {
    expect(OUTPUTS.length).toBeGreaterThan(10)
    expect(OUTPUTS.some((o) => o.includes('forwarded'))).toBe(true)
    expect(OUTPUTS.filter((o) => o.includes(FAKE_SECRET) || o.includes(FAKE_TOKEN))).toEqual([])
  })
})
