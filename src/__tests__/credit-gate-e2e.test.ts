import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach, vi } from 'vitest'
import net from 'node:net'
import { EventEmitter } from 'node:events'
import { spawn, type ChildProcess } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  appendFileSync, chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'

// Credit gate, node N6 (card fec6335f): the PR-B nodes together, offline.
// Blueprint N6 (section 7), 3, 4, 6, 8 and 11; written from the scenarios
// there, not from the code. Every scenario runs on the dashboard's own wiring:
//   - startCreditGateRuntime() exactly as web.ts calls it (the gate, the N2c
//     approval processor and the N5 audit notifier on db.ts's database), its
//     own refresh step driven by the test's fake clock;
//   - startHeadlessRuntime() exactly as web.ts calls it (the N4a runner, the
//     reconcile and the startup settle of N4b);
//   - the approvals through the real POST /api/approvals route, the owner's
//     button pressed through the installed plugin block
//     (telegram-plugin-patches/approval-callback.ts) on a fake grammY ctx,
//     its fetch bridged into the route -- the strict path of card 345f34e2;
//   - the credit-gate HTTP API (status, reservations, runs) in-process;
//   - the child is fake-claude.mjs behind a tmp launcher.
// N5 is checked on every flow: each audit row gets exactly one message (an
// authenticated directive only for an INCIDENT or a low-calibration request),
// a daily line when its class asks for one, and the status shows the state.
//
// No real API, key, Vault, child `claude`, tmux, Telegram, live store or live
// dashboard: everything is under a tmp directory; the key is a dummy that the
// test checks never leaks into a message, a log line, the DB or an answer.
// A process-level guard refuses every non-loopback connect() and the live CDP
// ports (18800, 18899) BEFORE the connect, self-tested against this file's own
// blocked port 18993 (never 18800); the children preload loopback-guard.cjs.

const state = vi.hoisted(() => ({
  token: '',
  allowedChatId: '',
  stateDir: '',
  channelToken: null as string | null,
  directives: [] as string[],
}))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return {
    ...real,
    MAIN_AGENT_ID: 'marveen',
    get TELEGRAM_BOT_TOKEN() { return state.token },
    get ALLOWED_CHAT_ID() { return state.allowedChatId },
  }
})

vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  // The live access.json never decides a test: no file, only the .env owner.
  const read = () => { throw new Error('ENOENT') }
  return {
    ...real,
    resolveOwnerChatId: vi.fn((_read?: unknown, configured?: string | null) => real.resolveOwnerChatId(read, configured)),
    resolveAlertOwnerChat: vi.fn((_read?: unknown, configured?: string | null) => real.resolveAlertOwnerChat(read, configured)),
  }
})

vi.mock('../channel-provider.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../channel-provider.js')>()
  return {
    ...real,
    channelStateDir: vi.fn((provider: Parameters<typeof real.channelStateDir>[0], agentDir?: string) =>
      provider === 'telegram' && !agentDir ? state.stateDir : real.channelStateDir(provider, agentDir)),
    readChannelToken: vi.fn((_provider: string, _path: string) => state.channelToken),
  }
})

// The tmux injection is the only thing replaced: the anchor row is written by
// db.ts exactly as the real sendSystemDirective does, before the injection.
vi.mock('../web/system-directive.js', async () => {
  const db = await import('../db.js')
  return {
    sendSystemDirective: async (to: string, _session: string, text: string) => {
      const m = db.createAgentMessage('system', to, text)
      db.markMessageDelivered(m.id)
      state.directives.push(text)
      return 'sent'
    },
  }
})

import { PROJECT_ROOT } from '../config.js'
import { initDatabase, getDb, getApproval } from '../db.js'
import { logger } from '../logger.js'
import { tryHandleApprovals, ownerNotificationsSettled, setOwnerNotificationSleep } from '../web/routes/approvals.js'
import { tryHandleCreditGate } from '../web/routes/credit-gate.js'
import { marveenApprovalCallback, MARVEEN_APV_TOAST, type MarveenApvCtx, type MarveenApvDeps } from '../telegram-plugin-patches/approval-callback.js'
import { startCreditGateRuntime, getCreditGateRuntime, setCreditGateRuntime, type CreditGateRuntime } from '../web/credit-gate/runtime.js'
import { startHeadlessRuntime, getHeadlessRunner, type HeadlessRuntimeHandle } from '../web/credit-gate/headless/reconcile.js'
import type { HeadlessRunner, ProcInfo, Spawner } from '../web/credit-gate/headless/runner.js'
import { calibrationSource, approvedCanary } from '../web/credit-gate/calibration.js'
import { classifyEvent } from '../web/credit-gate/audit.js'
import { defaultNotifyDeps } from '../web/credit-gate/notify.js'
import type { RouteContext } from '../web/routes/types.js'
import { configObject, pricingText, pyLine, HOUR } from './fixtures/credit-gate/gate-harness.js'
import { alive, FAKE_CLAUDE, until } from './fixtures/credit-gate/headless-harness.js'

const OWNER = '1000000001'
const BOT_TOKEN = '7000000001:AAsendSECRETpartXYZ'
const CHANNEL_TOKEN = '7000000001:AAchannelSECRETpartQRS'
const DASHBOARD_TOKEN = 'n6-dashboard-token-' + 'beef'.repeat(8)
const INSTALL_STATE_DIR = join(PROJECT_ROOT, '.claude', 'channels', 'telegram')
const MAIN = 'marveen'
const ROOT = resolve(__dirname, '..', '..')
const FIX = join(__dirname, 'fixtures', 'credit-gate')
/** 2026-10-16 08:00:00Z: the fake "now" every scenario starts at. */
const T0 = Date.UTC(2026, 9, 16, 8, 0, 0)
const MIN = 60_000

// --- network guard (self-tested) ----------------------------------------------------

const BLOCKED_PORTS = new Set([18800, 18899, 18993])
const LOOPBACK = new Set(['127.0.0.1', '::1', 'localhost'])
const origConnect = net.Socket.prototype.connect
const origFetch = globalThis.fetch

function guardTarget(args: unknown[]): { host: string; port: number } | null {
  const first = Array.isArray(args[0]) ? (args[0] as unknown[])[0] : args[0]
  if (typeof first === 'object' && first !== null) {
    const o = first as { host?: unknown; port?: unknown; path?: unknown }
    if (typeof o.path === 'string') return { host: 'unix', port: 0 }
    const port = Number(o.port)
    if (o.host !== undefined && typeof o.host !== 'string') return null
    return Number.isInteger(port) ? { host: (o.host as string | undefined) ?? 'localhost', port } : null
  }
  const port = Number(first)
  if (!Number.isInteger(port)) return null
  return { host: typeof args[1] === 'string' ? args[1] : 'localhost', port }
}

beforeAll(() => {
  net.Socket.prototype.connect = function guarded(this: net.Socket, ...args: unknown[]) {
    const t = guardTarget(args)
    if (t === null || (t.host !== 'unix' && (!LOOPBACK.has(t.host) || BLOCKED_PORTS.has(t.port)))) {
      throw new Error(`credit-gate N6 test guard: connect to ${t ? `${t.host}:${t.port}` : 'an unreadable target'} refused`)
    }
    return (origConnect as (...a: unknown[]) => net.Socket).apply(this, args)
  } as typeof net.Socket.prototype.connect
  globalThis.fetch = (() => { throw new Error('credit-gate N6 test guard: fetch is not allowed') }) as typeof fetch
})

afterAll(() => {
  net.Socket.prototype.connect = origConnect
  globalThis.fetch = origFetch
})

describe('the network guard of this file (self-test)', () => {
  it('refuses a non-loopback address and the blocked test port before any connect', () => {
    expect(() => net.connect({ host: '127.0.0.1', port: 18993 })).toThrow(/refused/)
    expect(() => net.connect({ host: '192.0.2.1', port: 443 })).toThrow(/refused/)
    expect(() => net.connect(443, 'api.anthropic.com')).toThrow(/refused/)
    expect(() => new net.Socket().connect(18993, '::1')).toThrow(/refused/)
    // Inside a test the global fetch is the fake Telegram; without the stub it throws.
    expect(globalThis.fetch).toBe(fakeTelegram)
    vi.unstubAllGlobals()
    try {
      expect(() => fetch('https://api.telegram.org/')).toThrow(/not allowed/)
    } finally {
      vi.stubGlobal('fetch', fakeTelegram)
    }
  })
})

// --- payloads (blueprint 3.7) -------------------------------------------------------

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

/** Python json.dumps(sort_keys=True, separators=(",", ":")) for these ASCII values. */
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

const stamp = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z')

interface GrantIn { granted: string; expires: string; original_usd: string; remaining_usd: string }
const p2 = (remaining: string): GrantIn => ({ granted: '2026-10-14', expires: '2026-11-17', original_usd: '200.00', remaining_usd: remaining })
const p1 = (remaining: string): GrantIn => ({ granted: '2026-10-10', expires: '2026-10-17', original_usd: '200.00', remaining_usd: remaining })

function calPayload(lbMs: number, grants: GrantIn[], over: { V?: string; R?: string } = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_calibration',
    captured_at_lb: stamp(lbMs),
    grants,
    protected: { R: { remaining_usd: over.R ?? '3.63', expires: '2027-01-31' }, V: { remaining_usd: over.V ?? '10.00' } },
    screenshot: '/Volumes/8T/00 CLOUD/console/n6-e2e.png',
  }
}

// --- fake Telegram, the plugin block, the routes ------------------------------------

type TgCall = { url: string; body: { chat_id: string; text: string; reply_markup?: any } }
let tgCalls: TgCall[] = []
let nextMessageId = 7000

const fakeTelegram = vi.fn(async (url: string, init: { body: string }) => {
  tgCalls.push({ url, body: JSON.parse(init.body) })
  const messageId = nextMessageId++
  return { ok: true, status: 200, text: async () => '', json: async () => ({ ok: true, result: { message_id: messageId } }) }
})

interface Out { status: number; body: any }
type Auth = RouteContext['auth']
const AS_EZERMESTER: Auth = { kind: 'token', agent: 'ezermester' }

/** One request through a route handler, with a streamed body like node's http. */
async function callRoute(handler: (ctx: RouteContext) => Promise<boolean>, method: string, path: string, raw: string, auth: Auth): Promise<Out & { raw: string }> {
  const out = { status: 0, body: null as any, raw: '' }
  let resolveDone!: () => void
  const done = new Promise<void>((r) => { resolveDone = r })
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    setHeader() { /* unused */ },
    end(chunk?: string) { if (chunk) { out.raw = chunk; out.body = JSON.parse(chunk) } resolveDone() },
  }
  const req: any = new EventEmitter()
  req.headers = {}
  req.destroy = () => { /* noop */ }
  setImmediate(() => {
    if (raw) req.emit('data', Buffer.from(raw))
    req.emit('end')
  })
  const ctx = { req, res, path, method, url: new URL(`http://localhost:3420${path}`), auth } as RouteContext
  expect(await handler(ctx)).toBe(true)
  await done
  return out
}

const gateApi = (method: string, path: string, body?: unknown, auth: Auth = AS_EZERMESTER) =>
  callRoute(tryHandleCreditGate, method, path, body === undefined ? '' : JSON.stringify(body), auth)

const bridgeFetch = vi.fn(async (input: unknown, init?: RequestInit) => {
  const u = new URL(String(input))
  expect(u.origin).toBe('http://127.0.0.1:3420')
  expect(u.pathname).toMatch(/^\/api\/approvals\/[0-9a-f-]{36}\/telegram$/)
  const out = await callRoute(tryHandleApprovals, 'POST', u.pathname, String(init?.body), undefined)
  return new Response(out.raw, { status: out.status, headers: { 'content-type': 'application/json' } })
})

function pluginDeps(): MarveenApvDeps {
  const files: Record<string, string> = {
    [`${PROJECT_ROOT}/store/.dashboard-token`]: `${DASHBOARD_TOKEN}\n`,
    [`${PROJECT_ROOT}/.env`]: 'WEB_PORT=3420\n',
  }
  return {
    stateDir: INSTALL_STATE_DIR,
    readFileSync: (p: string) => {
      const v = files[p]
      if (v === undefined) throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
      return v
    },
    fetch: bridgeFetch as unknown as typeof fetch,
    loadAccess: () => ({ allowFrom: [OWNER] }),
    env: {},
    envAtLoad: {},
  }
}

/**
 * Brainy asks for the approval through POST /api/approvals; the owner presses
 * approve on the Telegram message the dashboard sent. Returns the approval id.
 */
async function ownerApproves(category: string, payload: Record<string, unknown>): Promise<string> {
  const text = canon(payload)
  const before = tgCalls.length
  const created = await callRoute(tryHandleApprovals, 'POST', '/api/approvals', JSON.stringify({
    agent_id: 'brainy', category, action_description: 'n6 e2e', action_payload: text, content_hash: sha(text), timeout_seconds: 3600,
  }), undefined)
  expect(created.status, JSON.stringify(created.body)).toBe(201)
  const id = created.body.id as string
  await ownerNotificationsSettled()
  const call = tgCalls.slice(before).find((c) => c.body.reply_markup)
  expect(call, 'the owner got a button message').toBeTruthy()
  expect(call!.body.chat_id).toBe(OWNER)
  const row = getApproval(id)!
  const shown = { messageId: row.telegram_message_id!, text: call!.body.text, keyboard: call!.body.reply_markup, answers: [] as (string | undefined)[] }
  const ctx: MarveenApvCtx = {
    from: { id: Number(OWNER) },
    callbackQuery: { message: { message_id: shown.messageId, chat: { id: Number(OWNER), type: 'private' }, text: shown.text } },
    answerCallbackQuery: async (other?: { text?: string }) => { shown.answers.push(other?.text) },
    editMessageText: async (t: string, other?: { reply_markup?: any }) => { shown.text = t; shown.keyboard = other?.reply_markup ?? null },
    editMessageReplyMarkup: async (other?: { reply_markup?: any }) => { shown.keyboard = other?.reply_markup ?? null },
  }
  await marveenApprovalCallback(ctx, shown.keyboard.inline_keyboard[0][0].callback_data, pluginDeps())
  expect(shown.answers.at(-1)).toBe(MARVEEN_APV_TOAST.approved)
  expect(getApproval(id)).toMatchObject({ status: 'approved', resolved_by: `owner:telegram:${OWNER}` })
  return id
}

// --- the dashboard on a tmp install -------------------------------------------------------

const BATCH = { kind: 'batch', model: 'claude-haiku-5-5', input_tokens_total: 1000, max_output_tokens_total: 0, request_count: 1, caller: 'rag-gold-label' }

class Dashboard {
  readonly real: string
  readonly storeDir: string
  readonly gateDir: string
  readonly configPath: string
  readonly usagePath: string
  readonly stopPath: string
  readonly guardPath: string
  readonly dbPath: string
  readonly wtRoot: string
  readonly worktree: string
  readonly runsDir: string
  readonly installRoot: string
  readonly bin: string
  readonly binSha: string
  readonly key: string
  readonly spawnCalls: string[] = []
  readonly workers: ChildProcess[] = []
  readonly strays: number[] = []
  /** Processes a test lets the runner "see" (ps is not used here): pid -> its argv. */
  readonly visible = new Map<number, string[]>()
  clock = T0
  rt!: CreditGateRuntime
  handle: HeadlessRuntimeHandle | undefined
  private refresh: (() => void) | null = null
  private obsN = 0

  constructor() {
    this.real = realpathSync(mkdtempSync(join(tmpdir(), 'credit-e2e-')))
    this.storeDir = join(this.real, 'store')
    this.gateDir = join(this.storeDir, 'credit-gate')
    mkdirSync(this.gateDir, { recursive: true, mode: 0o700 })
    chmodSync(this.storeDir, 0o700)
    chmodSync(this.gateDir, 0o700)
    this.configPath = join(this.gateDir, 'config.json')
    this.usagePath = join(this.real, 'usage.jsonl')
    writeFileSync(this.usagePath, '')
    mkdirSync(join(this.real, 'batch'))
    this.stopPath = join(this.real, 'batch', 'STOP')
    this.guardPath = join(this.storeDir, 'interactive-key-guard-events.jsonl')
    this.dbPath = join(this.storeDir, 'claudeclaw.db')
    this.wtRoot = join(this.real, 'wt')
    this.worktree = join(this.wtRoot, 'proj')
    mkdirSync(this.worktree, { recursive: true })
    writeFileSync(join(this.worktree, '.git'), 'gitdir: /nowhere/.git/worktrees/proj\n')
    this.runsDir = join(this.real, 'runs')
    this.installRoot = join(this.real, 'install')
    mkdirSync(join(this.installRoot, 'store'), { recursive: true })
    writeFileSync(join(this.installRoot, '.git'), 'gitdir: /nowhere\n')
    mkdirSync(join(this.real, 'bin'))
    this.bin = join(this.real, 'bin', 'claude-fake.mjs')
    writeFileSync(this.bin, `#!${process.execPath}\nimport ${JSON.stringify(FAKE_CLAUDE)}\n`)
    chmodSync(this.bin, 0o755)
    this.binSha = createHash('sha256').update(readFileSync(this.bin)).digest('hex')
    this.key = `sk-ant-TEST-DUMMY-${randomBytes(16).toString('hex')}`
    this.writeConfig()
    this.writePricing('2026-10-16')
    initDatabase(this.dbPath)
  }

  writePricing(verifiedAt: string): void {
    const pricing = join(this.gateDir, 'pricing.json')
    writeFileSync(pricing, pricingText(verifiedAt), { mode: 0o600 })
    chmodSync(pricing, 0o600)
  }

  writeConfig(): void {
    writeFileSync(this.configPath, JSON.stringify(configObject(this.usagePath, this.stopPath, {
      headless: {
        allowedCallers: ['ezermester'], cwdRoots: [this.wtRoot], forbiddenCwds: [this.installRoot],
        runsDir: this.runsDir, claudeBin: this.bin, claudeBinSha256: this.binSha,
        models: ['claude-opus-5-5', 'claude-sonnet-5-5'], maxBudgetUsd: '5.00', wallClockMin: 90,
      },
    })), { mode: 0o600 })
    chmodSync(this.configPath, 0o600)
  }

  /**
   * The dashboard starts: what web.ts does, in its order. The gate's own
   * refresh step (tick, approvals, tick, audit delivery) is taken from its
   * timer and driven by cycle(); the timer itself is stopped.
   */
  start(mode: string): void {
    const spy = vi.spyOn(globalThis, 'setInterval')
    let interval: NodeJS.Timeout | undefined
    try {
      interval = startCreditGateRuntime({
        webOnly: false,
        modeValue: mode,
        storeDir: this.storeDir,
        now: () => this.clock,
        notify: { ...defaultNotifyDeps(), now: () => this.clock },
      })
      this.refresh = (spy.mock.calls[0]?.[0] as (() => void) | undefined) ?? null
    } finally {
      spy.mockRestore()
    }
    if (interval) clearInterval(interval)
    this.rt = getCreditGateRuntime()
    const spawner: Spawner = (file, args, options) => {
      if (!file.startsWith(this.real + '/')) throw new Error(`test spawner: refusing ${file}`)
      this.spawnCalls.push(file)
      const child = spawn(file, args, options)
      return child
    }
    this.handle = startHeadlessRuntime({
      runtime: this.rt,
      getKey: () => this.key,
      installRoot: this.installRoot,
      listProcesses: () => this.procs(),
      kill: (pid, sig) => { process.kill(pid, sig) },
      runnerDeps: {
        spawner,
        now: () => this.clock,
        procStart: (pid) => (alive(pid) ? this.startOf(pid) : null),
        killGraceMs: 300,
        pollMs: 50,
        installSignalHandlers: false,
      },
    })
  }

  /** The dashboard goes away (its timers; a run it owns is killed, as on a clean shutdown). */
  stop(): void {
    this.handle?.stop()
    this.handle = undefined
    this.refresh = null
    setCreditGateRuntime(null)
  }

  /** What ps would show for the processes a test made visible (the fake's own argv). */
  procs(): ProcInfo[] {
    const out: ProcInfo[] = []
    for (const [pid, argv] of this.visible) {
      if (!alive(pid)) continue
      out.push({ pid, pgid: pid, start: this.startOf(pid), command: [process.execPath, this.bin, ...argv].join(' ') })
    }
    return out
  }

  /** A start time that stays the same for a pid: the one a run row recorded, if any. */
  startOf(pid: number): string {
    const r = getDb().prepare('SELECT pid_start FROM credit_headless_runs WHERE pid = ? AND pid_start IS NOT NULL ORDER BY started_at DESC LIMIT 1').get(pid) as { pid_start: string } | undefined
    return r?.pid_start ?? 'e2e-start'
  }

  get runner(): HeadlessRunner {
    const r = getHeadlessRunner()
    if (r === null) throw new Error('no headless runner')
    return r
  }

  /** One refresh of the running dashboard, and its audit delivery settled. */
  async cycle(): Promise<{ state: string; reason: string }> {
    if (!this.refresh) throw new Error('the dashboard is not running')
    this.refresh()
    await this.deliveriesSettled()
    return this.state()
  }

  /** Refresh until every audit row is delivered (bounded). */
  async drain(): Promise<void> {
    for (let i = 0; i < 6 && this.undelivered() > 0; i++) await this.cycle()
    expect(this.undelivered(), 'every audit row delivered').toBe(0)
  }

  undelivered(): number {
    return (getDb().prepare(`SELECT COUNT(*) AS n FROM credit_gate_events WHERE notify_state IS NULL OR notify_state IN ('sending', 'retry')`).get() as { n: number }).n
  }

  async deliveriesSettled(): Promise<void> {
    for (let i = 0; i < 100; i++) {
      await new Promise((r) => setTimeout(r, 5))
      const n = (getDb().prepare(`SELECT COUNT(*) AS n FROM credit_gate_events WHERE notify_state = 'sending'`).get() as { n: number }).n
      if (n === 0) return
    }
  }

  state(): { state: string; reason: string } {
    return getDb().prepare('SELECT state, reason FROM credit_gate_state WHERE id = 1').get() as { state: string; reason: string }
  }

  async status(): Promise<any> {
    const s = await gateApi('GET', '/api/credit-gate/status')
    expect(s.status).toBe(200)
    expect(s.raw).not.toContain(this.key)
    return s.body
  }

  /** The owner approves a reading, and the dashboard processes it. */
  async calibrate(lbMs: number, grants: GrantIn[], over: { V?: string; R?: string } = {}): Promise<string> {
    const id = await ownerApproves('credit_gate_calibration', calPayload(lbMs, grants, over))
    await this.cycle()
    return id
  }

  prompt(mode: string, extra: Record<string, unknown> = {}): { prompt: string; observe: string } {
    const observe = join(this.real, `obs-${++this.obsN}.json`)
    return { prompt: `FAKE ${JSON.stringify({ mode, observe, ...extra })}\nDo the node.\n`, observe }
  }

  body(prompt: string, over: Record<string, unknown> = {}): Record<string, unknown> {
    return { node_id: 'N9x', model: 'claude-sonnet-5-5', effort: 'high', budget_usd: '0.40', cwd: this.worktree, prompt, mode: 'normal', ...over }
  }

  async run(prompt: string, over: Record<string, unknown> = {}): Promise<Out> {
    return gateApi('POST', '/api/credit-gate/runs', this.body(prompt, over))
  }

  async done(runId: string): Promise<void> {
    const r = this.runner
    if (r.activeIds().includes(runId)) await r.whenDone(runId)
  }

  /** The canary the owner approves for exactly this prompt (blueprint 3.7, BE-4b P6). */
  async canaryApproval(beforeId: string, prompt: string): Promise<string> {
    return ownerApproves('credit_gate_canary', {
      v: 1, kind: 'credit_gate_canary', config_hash: this.runner.configHash(), model: 'claude-sonnet-5-5',
      budget_usd: '0.90', min_expected_usd: '0.10', before_calibration_id: beforeId,
      node: 'N9x', cwd: this.worktree, prompt_sha256: sha(prompt),
    })
  }

  /**
   * B-4 dry: before-reading (the one in force), the canary approval, the run,
   * and the after-reading with `after` grants. Returns the canary approval id.
   */
  async canary(beforeId: string, beforeLbMs: number, after: GrantIn[], over: { V?: string; R?: string } = {}): Promise<{ approval: string; runId: string }> {
    const c = this.prompt('success')
    const approval = await this.canaryApproval(beforeId, c.prompt)
    const out = await this.run(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: approval })
    expect(out.status, JSON.stringify(out.body)).toBe(202)
    const runId = out.body.run_id as string
    // K-01: the batch path stays on the gate's STOP while the canary runs...
    expect(this.stopOwner()).toBe('gate')
    await this.done(runId)
    // ...and after its run, until its after-reading is recorded (N7B1).
    expect(this.stopOwner()).toBe('gate')
    expect(this.rt.gate?.status().canary_window).toMatchObject({ run_id: runId })
    this.clock += 10 * MIN
    await this.calibrate(Math.max(beforeLbMs + MIN, this.clock - 5 * MIN), after, over)
    return { approval, runId }
  }

  /** Enforce, a first reading, and the hash a successful canary approved: normal runs may start. */
  async openWithApprovedHash(remaining = '70.00', after = '69.89'): Promise<void> {
    const lb = this.clock - 2 * HOUR
    const before = await this.calibrate(lb, [p2(remaining)])
    expect(this.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    const { approval } = await this.canary(before, lb, [p2(after)])
    expect(this.canaryRow(approval)).toMatchObject({ status: 'success' })
    expect(approvedCanary(getDb())?.config_hash).toBe(this.runner.configHash())
    expect(this.state().state).toBe('OPEN')
    // The after-reading closed the canary window: in OPEN the STOP is gone.
    expect(this.rt.gate?.status().canary_window).toBeNull()
    expect(this.stopOwner()).toBeNull()
  }

  canaryRow(approvalId: string): Record<string, unknown> | undefined {
    return getDb().prepare('SELECT * FROM credit_canaries WHERE approval_id = ?').get(approvalId) as Record<string, unknown> | undefined
  }

  runRow(id: string): Record<string, unknown> {
    return getDb().prepare('SELECT * FROM credit_headless_runs WHERE id = ?').get(id) as Record<string, unknown>
  }

  ledgerRows(runId: string): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_ledger_entries WHERE run_id = ?').all(runId) as Array<Record<string, unknown>>
  }

  reservations(): Array<Record<string, unknown>> {
    return getDb().prepare('SELECT * FROM credit_reservations ORDER BY created_at, id').all() as Array<Record<string, unknown>>
  }

  events(): Array<Record<string, any>> {
    return getDb().prepare('SELECT * FROM credit_gate_events ORDER BY id').all() as Array<Record<string, any>>
  }

  stopOwner(): 'gate' | 'other' | null {
    if (!existsSync(this.stopPath)) return null
    return readFileSync(this.stopPath, 'utf8').startsWith('credit-gate v1 ') ? 'gate' : 'other'
  }

  /** One usage.jsonl row the way batch_client.py writes it. */
  usage(model: string, input: number, output: number): void {
    appendFileSync(this.usagePath, pyLine({ ts: Math.floor(this.clock / 1000), month: '2026-10', caller: 'rag-gold-label', model, in: input, out: output }))
  }

  cleanup(): void {
    for (const w of this.workers.splice(0)) {
      try { w.kill('SIGKILL') } catch { /* gone */ }
    }
    for (const pid of [...this.strays.splice(0), ...this.visible.keys()]) {
      try { process.kill(pid, 'SIGKILL') } catch { /* gone */ }
    }
    this.stop()
    rmSync(this.real, { recursive: true, force: true })
  }
}

// --- N5: what reached the main agent -------------------------------------------------------

interface Delivered {
  /** Event ids with an authenticated directive. */
  directives: number[]
  /** Event ids with an info message. */
  infos: number[]
}

/**
 * Every audit row: exactly one message when its class asks for one (L-01), a
 * directive only for an INCIDENT or a low-calibration request, a daily line
 * when its class asks for one; no message for a silent row; no message twice.
 */
function expectAuditDelivered(d: Dashboard): Delivered {
  const msgs = getDb().prepare(`SELECT id, from_agent, to_agent, content FROM agent_messages
      WHERE from_agent = 'system' AND to_agent = ? AND content LIKE '[KREDIT-KAPU]%' ORDER BY id`).all(MAIN) as Array<{ id: number; content: string }>
  const daily = (getDb().prepare('SELECT content FROM daily_logs WHERE agent_id = ? ORDER BY id').all(MAIN) as Array<{ content: string }>).map((r) => r.content)
  const out: Delivered = { directives: [], infos: [] }
  let expectedMessages = 0
  for (const ev of d.events()) {
    // A transition is a change of state, or of the reason a closed gate gives; never OPEN -> OPEN.
    if (ev.kind === 'transition') expect(`${ev.from_state}->${ev.to_state}`, `event #${ev.id} ${ev.reason}`).not.toBe('OPEN->OPEN')
    const tag = `esemeny: #${ev.id} `
    const own = msgs.filter((m) => m.content.includes(tag))
    const plan = classifyEvent(ev as { kind: string; to_state: string | null; reason: string | null })
    // The spec's rule, not the code's table: the directive is for an INCIDENT or a lowcal request only.
    const wantsDirective = (ev.to_state === 'INCIDENT' && (ev.kind === 'transition' || ev.kind === 'incident_cause')) || ev.kind === 'lowcal_request'
    expect(plan.notify === 'directive', `event #${ev.id} ${ev.kind} ${ev.reason}: directive class`).toBe(wantsDirective)
    if (plan.notify === 'none') {
      expect(ev.notify_state, `event #${ev.id} ${ev.kind}`).toBe('skipped')
      expect(own).toHaveLength(0)
    } else if (ev.notify_state === 'coalesced') {
      expect(own).toHaveLength(0)
    } else {
      expect(ev.notify_state, `event #${ev.id} ${ev.kind} ${ev.reason}`).toBe('sent')
      expect(own, `event #${ev.id} ${ev.kind}: one message`).toHaveLength(1)
      expect(ev.notified_msg_id).toBe(own[0]!.id)
      const isDirective = state.directives.includes(own[0]!.content)
      expect(isDirective, `event #${ev.id} ${ev.kind} ${ev.reason}: delivered as a directive`).toBe(wantsDirective)
      if (wantsDirective) expect(own[0]!.content).toMatch(/TEENDO:/)
      ;(isDirective ? out.directives : out.infos).push(ev.id)
      expectedMessages++
    }
    if (plan.daily) {
      expect(ev.daily_logged, `event #${ev.id} ${ev.kind}: a daily line`).toBe(1)
      expect(daily.filter((t) => t.includes(tag)), `event #${ev.id} ${ev.kind}: one daily line`).toHaveLength(1)
    }
  }
  expect(msgs).toHaveLength(expectedMessages)
  // Nothing secret anywhere the main agent or the audit reads.
  const all = JSON.stringify([msgs, daily, d.events(), getDb().prepare('SELECT * FROM approvals').all()])
  expect(all).not.toContain(d.key)
  expect(all).not.toContain('sk-ant-TEST-DUMMY')
  return out
}

function eventsOf(d: Dashboard, kind: string, reason?: string): Array<Record<string, any>> {
  return d.events().filter((e) => e.kind === kind && (reason === undefined || e.reason === reason))
}

// --- per-test setup --------------------------------------------------------------------------

let logged: unknown[][] = []
let d: Dashboard | undefined

beforeEach(() => {
  state.token = BOT_TOKEN
  state.allowedChatId = OWNER
  state.stateDir = INSTALL_STATE_DIR
  state.channelToken = CHANNEL_TOKEN
  state.directives = []
  tgCalls = []
  nextMessageId = 7000
  fakeTelegram.mockClear()
  bridgeFetch.mockClear()
  vi.stubGlobal('fetch', fakeTelegram)
  setOwnerNotificationSleep(async () => {})
  logged = []
  for (const level of ['info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { logged.push([level, ...args]) }) as never)
  }
})

afterEach(async () => {
  await ownerNotificationsSettled()
  const key = d?.key
  d?.cleanup()
  d = undefined
  if (key) expect(JSON.stringify(logged)).not.toContain(key)
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

// =====================================================================================
// 1. shadow -> first calibration -> status; enforce -> open -> run -> threshold -> STOP -> 409
// =====================================================================================

describe('N6: shadow, the first reading, enforce, a run, the threshold, the STOP (blueprint N6, 9 B-2..B-5)', () => {
  it('the whole chain on the dashboard\'s own wiring', async () => {
    d = new Dashboard()

    // --- B-1/B-2: shadow mode, the first reading by the owner's button.
    d.start('shadow')
    expect(d.rt.calibrations).toBeTruthy()
    const shadowLb = d.clock - 2 * HOUR
    await d.calibrate(shadowLb, [p2('70.00')])
    let st = await d.status()
    expect(st).toMatchObject({
      mode: 'shadow', enforced: false, state: 'CLOSED', reason: 'shadow_mode',
      r_est_usd: '70.00', ledger: { l_usd: '0.00', error: null },
      reservations: { open_count: 0, open_usd: '0.00' },
      calibration: { captured_at_lb: new Date(shadowLb).toISOString(), grants: [{ granted: '2026-10-14', expires: '2026-11-17', remaining_usd: '70.00' }] },
      close_at: '2026-11-16T22:00:00.000Z',
      stop: { present: false, owner: 'none' },
      notify: { failed: 0 },
      canary: { approved_hash: null, match: false },
    })
    expect(st.thresholds).toMatchObject({ t_close_usd: '20.00', t_reopen_usd: '50.00', t_lowcal_usd: '60.00' })
    // Shadow: the batch client keeps today's path, no run starts, the STOP is never written.
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200, body: { enforced: false } })
    expect(await d.run(d.prompt('success').prompt)).toMatchObject({ status: 409, body: { reason: 'gate_shadow' } })
    expect(existsSync(d.stopPath)).toBe(false)
    expect(eventsOf(d, 'calibration')).toHaveLength(1)
    await d.drain()
    expectAuditDelivered(d)

    // --- B-3: enforce (a .env change and a dashboard restart). The reading in force opens it at the first tick.
    d.stop()
    d.clock += 5 * MIN
    d.start('enforce')
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    expect(existsSync(d.stopPath)).toBe(false)

    // --- B-4: the canary approves the runner's config hash; until then a normal run is refused.
    expect(await d.run(d.prompt('success').prompt)).toMatchObject({ status: 409, body: { reason: 'hash_not_approved' } })
    const beforeId = getApproval((getDb().prepare('SELECT approval_id FROM credit_calibrations ORDER BY id DESC LIMIT 1').get() as { approval_id: string }).approval_id)!.id
    const { approval: canaryId, runId: canaryRun } = await d.canary(beforeId, shadowLb, [p2('69.89')])
    expect(d.canaryRow(canaryId)).toMatchObject({ status: 'success', run_id: canaryRun })
    expect(d.state()).toMatchObject({ state: 'OPEN' })

    // --- a normal headless run: reserved, run, settled once, visible to its caller.
    const n = d.prompt('success')
    const started = await d.run(n.prompt)
    expect(started).toMatchObject({ status: 202, body: { mode: 'normal', status: 'running' } })
    const runId = started.body.run_id as string
    await d.done(runId)
    const view = await gateApi('GET', `/api/credit-gate/runs/${runId}`)
    expect(view).toMatchObject({ status: 200, body: { status: 'succeeded', done: true, est_usd: '0.114535', cli_usd: '0.074983', is_error: false, num_turns: 3, basis: 'headless_json' } })
    expect(JSON.stringify(view.body)).not.toContain('Do the node')
    expect(d.ledgerRows(runId)).toMatchObject([{ est_micro: 114_535, cli_micro: 74_983 }])
    expect(d.reservations().filter((r) => r.ref === runId)).toMatchObject([{ kind: 'headless', status: 'settled', amount_micro: 600_000 }])
    expect(d.reservations().filter((r) => r.status === 'open')).toHaveLength(0)
    await d.cycle()
    st = await d.status()
    // 69.89 (the after-reading) - 0.114535 (this run; the canary is before the reading's lower bound).
    expect(st).toMatchObject({ mode: 'enforce', enforced: true, state: 'OPEN', r_est_usd: '69.775465', ledger: { l_usd: '0.114535' } })
    expect(st.canary).toEqual({ approved_hash: d.runner.configHash(), current_hash: d.runner.configHash(), match: true })
    expect(st.canary.current_hash).toMatch(/^[0-9a-f]{64}$/)
    // The fake was given only the allowlisted env, and never the key in argv.
    const seen = JSON.parse(readFileSync(n.observe, 'utf8')) as { argv: string[]; envNames: string[]; keySource: string }
    expect(seen.argv.join(' ')).not.toContain(d.key)
    expect(seen.keySource).toBe('helper')
    for (const name of ['CLAUDECODE', 'CLAUDE_CODE_ENTRYPOINT', 'CLAUDE_CODE_OAUTH_TOKEN', 'TMUX', 'NODE_OPTIONS', 'ANTHROPIC_API_KEY']) {
      expect(seen.envNames).not.toContain(name)
    }

    // --- the threshold: a batch spends 50.00 USD (12.5 M Opus input tokens) -> R_est 19.77 <= 20 -> CLOSED, the gate's STOP.
    d.clock += MIN
    d.usage('claude-opus-5-5', 12_500_000, 0)
    expect(await d.cycle()).toEqual({ state: 'CLOSED', reason: 'threshold' })
    expect(d.stopOwner()).toBe('gate')
    st = await d.status()
    expect(st).toMatchObject({ state: 'CLOSED', reason: 'threshold', r_est_usd: '19.775465', stop: { present: true, owner: 'gate' }, latch: { reason: 'threshold' } })
    // The batch client and the runner are refused while closed.
    const refused = await gateApi('POST', '/api/credit-gate/reservations', BATCH)
    expect(refused.status).toBe(409)
    expect(refused.body).toMatchObject({ enforced: true, reason: 'gate_closed' })
    expect(await d.run(d.prompt('success').prompt)).toMatchObject({ status: 409, body: { reason: 'gate_closed', detail: 'threshold' } })
    // C-05: the same reading does not reopen it.
    d.clock += MIN
    expect((await d.cycle()).state).toBe('CLOSED')

    // --- N5 on this flow.
    await d.drain()
    const del = expectAuditDelivered(d)
    const lowcal = eventsOf(d, 'lowcal_request')
    expect(lowcal).toHaveLength(1)
    expect(del.directives).toEqual(lowcal.map((e) => e.id))
    const transitions = eventsOf(d, 'transition').map((e) => `${e.from_state}->${e.to_state}:${e.reason}`)
    expect(transitions).toEqual(expect.arrayContaining(['CLOSED->OPEN:opened', 'OPEN->CLOSED:threshold']))
    for (const e of eventsOf(d, 'transition')) expect(del.infos).toContain(e.id)
    expect(eventsOf(d, 'stop_placed').length).toBeGreaterThanOrEqual(1)
    expect(eventsOf(d, 'reservation_rejected').length).toBeGreaterThanOrEqual(1)
    expect(eventsOf(d, 'canary_evaluated')).toHaveLength(1)
    st = await d.status()
    expect(st.notify).toMatchObject({ failed: 0, pending: 0 })
    expect(st.last_event).toBeTruthy()
  }, 120_000)
})

// =====================================================================================
// 2. human STOP
// =====================================================================================

describe('N6: a human STOP closes the gate; no reopening while it is there (A-05, blueprint 3.6, 8)', () => {
  it('human STOP -> CLOSED; a newer reading does not reopen while the STOP is there; the gate never touches it', async () => {
    d = new Dashboard()
    d.start('enforce')
    const lb = d.clock - 2 * HOUR
    await d.calibrate(lb, [p2('200.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })

    // `touch STOP` by a human: empty, not the gate's.
    writeFileSync(d.stopPath, '')
    const ino = lstatSync(d.stopPath).ino
    d.clock += MIN
    expect(await d.cycle()).toEqual({ state: 'CLOSED', reason: 'human_stop' })
    expect((await d.status()).stop).toMatchObject({ present: true, owner: 'human' })
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { reason: 'gate_closed' } })

    // A newer, owner-approved reading: still CLOSED while the human STOP is there.
    d.clock += 10 * MIN
    await d.calibrate(d.clock - MIN, [p2('199.00')])
    expect(d.state().state).toBe('CLOSED')
    for (let i = 0; i < 2; i++) {
      d.clock += MIN
      expect((await d.cycle()).state).toBe('CLOSED')
    }
    // Untouched: same inode, same (empty) content.
    expect(lstatSync(d.stopPath).ino).toBe(ino)
    expect(readFileSync(d.stopPath, 'utf8')).toBe('')

    // The human takes it away: the gate's own STOP goes down while it stays closed; only a newer reading opens.
    rmSync(d.stopPath)
    d.clock += MIN
    expect((await d.cycle()).state).toBe('CLOSED')
    expect(d.stopOwner()).toBe('gate')
    d.clock += 10 * MIN
    await d.calibrate(d.clock - MIN, [p2('199.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    expect(d.stopOwner()).toBeNull()

    await d.drain()
    const del = expectAuditDelivered(d)
    expect(del.directives).toEqual([])
    expect(eventsOf(d, 'transition').map((e) => `${e.from_state}->${e.to_state}:${e.reason}`))
      .toEqual(expect.arrayContaining(['CLOSED->OPEN:opened', 'OPEN->CLOSED:human_stop']))
  }, 60_000)
})

// =====================================================================================
// 3. guard events from PR-A
// =====================================================================================

describe('N6: a PR-A guard event -> INCIDENT -> incident-clear + a reading -> OPEN (I-03, I-04, blueprint 3.5)', () => {
  it('the TS and the Python writer\'s lines are one INCIDENT cause each; two clears and a new reading open it', async () => {
    d = new Dashboard()
    d.start('enforce')
    const lb = d.clock - 2 * HOUR
    await d.calibrate(lb, [p2('200.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })

    // recordGuardEvent (src/web/interactive-key-guard.ts): JSON.stringify, ISO ts with milliseconds.
    d.clock += MIN
    appendFileSync(d.guardPath, JSON.stringify({
      ts: new Date(d.clock).toISOString(), source: 'launch-guard', where: 'startAgentProcess:launch-cmd', names: ['ANTHROPIC_API_KEY'], agent: 'fejleszto',
    }) + '\n')
    // channels.sh main_settings_key_scan: Python json.dumps (", " and ": "), and an unreadable settings file.
    appendFileSync(d.guardPath, pyLine({
      ts: new Date(d.clock).toISOString(), source: 'main-launch-guard', where: '/Users/x/marveen/.claude/settings.json', names: ['<unreadable>'], agent: 'marveen',
    }))
    expect(await d.cycle()).toMatchObject({ state: 'INCIDENT', reason: 'guard_event' })
    expect(d.stopOwner()).toBe('gate')
    const guardEvents = eventsOf(d, 'guard_event')
    expect(guardEvents).toHaveLength(2)
    expect(guardEvents.map((e) => JSON.parse(e.detail_json))).toEqual([
      { ts: expect.any(String), source: 'launch-guard', where: 'startAgentProcess:launch-cmd', names: ['ANTHROPIC_API_KEY'], agent: 'fejleszto' },
      { ts: expect.any(String), source: 'main-launch-guard', where: '/Users/x/marveen/.claude/settings.json', names: ['<unreadable>'], agent: 'marveen' },
    ])
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409 })

    // A reading alone does not open an INCIDENT.
    d.clock += MIN
    await d.calibrate(d.clock - 30_000, [p2('200.00')])
    expect(d.state().state).toBe('INCIDENT')

    // Each cause is cleared by its own owner approval, the newest first.
    for (let i = 0; i < 2; i++) {
      const row = getDb().prepare('SELECT incident_event_id FROM credit_gate_state WHERE id = 1').get() as { incident_event_id: number }
      d.clock += MIN
      await ownerApproves('credit_gate_incident_clear', { v: 1, kind: 'credit_gate_incident_clear', incident_event_id: row.incident_event_id })
      await d.cycle()
    }
    expect(d.state().state).toBe('CLOSED')
    // Only a reading captured after the clear opens.
    d.clock += MIN
    await d.calibrate(d.clock - 30_000, [p2('200.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    expect(d.stopOwner()).toBeNull()

    await d.drain()
    const del = expectAuditDelivered(d)
    const incident = d.events().filter((e) => e.to_state === 'INCIDENT' && (e.kind === 'transition' || e.kind === 'incident_cause'))
    expect(incident).toHaveLength(2)
    expect(del.directives.sort()).toEqual(incident.map((e) => e.id).sort())
    // The owner's review sees which names (never values) were found, the unreadable marker too.
    const texts = (getDb().prepare(`SELECT content FROM agent_messages WHERE content LIKE '[KREDIT-KAPU]%'`).all() as Array<{ content: string }>).map((m) => m.content).join('\n')
    expect(texts).toContain('names=ANTHROPIC_API_KEY')
    expect(texts).toContain('names=<unreadable>')
  }, 60_000)
})

// =====================================================================================
// 4. P1 expiry with a fake clock
// =====================================================================================

describe('N6: the P1 grant expires on the fake clock (D-04, C-06, blueprint 3.4 test vector)', () => {
  it('R_est drops by P1\'s remainder at 2026-10-17T00:00:00Z; the lowcal request is one directive; the last expiry closes', async () => {
    d = new Dashboard()
    d.start('enforce')
    const lb = d.clock - 2 * HOUR
    await d.calibrate(lb, [p1('195.64'), p2('45.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    let st = await d.status()
    expect(st).toMatchObject({ r_est_usd: '240.64', next_expiry: '2026-10-17T00:00:00.000Z', close_at: '2026-11-16T22:00:00.000Z' })

    d.clock = Date.UTC(2026, 9, 16, 23, 59, 59)
    expect((await d.cycle()).state).toBe('OPEN')
    expect((await d.status()).r_est_usd).toBe('240.64')
    expect(eventsOf(d, 'lowcal_request')).toHaveLength(0)

    d.clock = Date.UTC(2026, 9, 17, 0, 0, 0)
    expect((await d.cycle()).state).toBe('OPEN')
    st = await d.status()
    expect(st).toMatchObject({ r_est_usd: '45.00', next_expiry: '2026-11-17T00:00:00.000Z' })
    expect(eventsOf(d, 'lowcal_request')).toHaveLength(1)
    d.clock += MIN
    await d.cycle()
    expect(eventsOf(d, 'lowcal_request')).toHaveLength(1)

    // A month on, the price table is stale (30 days): the gate closes on it. Re-verified, it does not
    // reopen: R_est 45.00 is below T_reopen 50.00 (the hysteresis).
    d.clock = Date.UTC(2026, 10, 16, 21, 0, 0)
    expect(await d.cycle()).toEqual({ state: 'CLOSED', reason: 'pricing_stale' })
    d.writePricing('2026-11-16')
    d.clock = Date.UTC(2026, 10, 16, 21, 59, 59)
    expect(await d.cycle()).toEqual({ state: 'CLOSED', reason: 'below_reopen' })
    // C-06: two hours before the last grant's expiry the reason is the expiry.
    d.clock = Date.UTC(2026, 10, 16, 22, 0, 0)
    expect(await d.cycle()).toEqual({ state: 'CLOSED', reason: 'expired' })
    expect(d.stopOwner()).toBe('gate')

    await d.drain()
    const del = expectAuditDelivered(d)
    expect(del.directives).toEqual(eventsOf(d, 'lowcal_request').map((e) => e.id))
  }, 60_000)
})

// =====================================================================================
// 5. the canary, dry: all four outcomes
// =====================================================================================

describe('N6: the canary dry run -- before-reading, approval, run, after-reading (K-01..K-03, blueprint 9 B-4)', () => {
  const cases = [
    { name: 'success: P2 fell by the run\'s cost', after: '199.89', over: {}, canary: 'success', gate: 'OPEN' },
    { name: 'INCIDENT: V fell', after: '199.89', over: { V: '9.99' }, canary: 'incident', gate: 'INCIDENT' },
    { name: 'INCIDENT: no grant fell', after: '200.00', over: {}, canary: 'incident', gate: 'INCIDENT' },
    { name: 'undecidable: the fall does not match the run', after: '199.50', over: {}, canary: 'undecidable', gate: 'HOLD' },
  ] as const
  for (const c of cases) {
    it(c.name, async () => {
      d = new Dashboard()
      d.start('enforce')
      const lb = d.clock - 2 * HOUR
      const before = await d.calibrate(lb, [p2('200.00')])
      expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
      const { approval, runId } = await d.canary(before, lb, [p2(c.after)], c.over)
      expect(d.canaryRow(approval)).toMatchObject({ status: c.canary, run_id: runId })
      expect(d.state().state).toBe(c.gate)
      // N7B1: the after-reading closed the window whatever the verdict; the STOP follows the state.
      expect((await d.status()).canary_window).toBeNull()
      expect(d.stopOwner()).toBe(c.gate === 'OPEN' ? null : 'gate')
      expect(approvedCanary(getDb())?.config_hash ?? null).toBe(c.canary === 'success' ? d.runner.configHash() : null)
      const n = d.prompt('success')
      const next = await d.run(n.prompt)
      if (c.canary === 'success') expect(next.status).toBe(202)
      else expect(next.status).toBe(409)
      if (next.status === 202) await d.done(next.body.run_id as string)

      await d.drain()
      const del = expectAuditDelivered(d)
      expect(eventsOf(d, 'canary_evaluated')).toHaveLength(1)
      expect(del.infos).toContain(eventsOf(d, 'canary_evaluated')[0]!.id)
      expect(del.directives.length > 0).toBe(c.gate === 'INCIDENT')
      expect((await d.status()).state).toBe(c.gate)
    }, 60_000)
  }
})

describe('N7B1: a dashboard restart between the canary\'s run and its after-reading (K-01)', () => {
  it('the window survives the restart: the STOP stays, nothing is admitted; the after-reading closes it', async () => {
    d = new Dashboard()
    d.start('enforce')
    const lb = d.clock - 2 * HOUR
    const before = await d.calibrate(lb, [p2('200.00')])
    expect(d.state()).toEqual({ state: 'OPEN', reason: 'opened' })
    const c = d.prompt('success')
    const approval = await d.canaryApproval(before, c.prompt)
    const out = await d.run(c.prompt, { mode: 'canary', budget_usd: '0.90', canary_approval_id: approval })
    expect(out.status, JSON.stringify(out.body)).toBe(202)
    const runId = out.body.run_id as string
    await d.done(runId)
    expect(d.stopOwner()).toBe('gate')

    d.stop()
    d.clock += MIN
    d.start('enforce')
    await d.cycle()
    expect(d.state().state).toBe('OPEN')
    expect(d.stopOwner()).toBe('gate')
    const st = await d.status()
    expect(st).toMatchObject({ canary_in_progress: false, canary_window: { run_id: runId }, stop: { owner: 'gate' } })
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409, body: { enforced: true, reason: 'canary_window_open' } })
    expect(await d.run(d.prompt('success').prompt)).toMatchObject({ status: 409, body: { reason: 'canary_window_open' } })
    await d.cycle()
    expect(d.stopOwner()).toBe('gate')

    d.clock += 10 * MIN
    await d.calibrate(d.clock - 5 * MIN, [p2('199.89')])
    expect(d.canaryRow(approval)).toMatchObject({ status: 'success', run_id: runId })
    expect(d.state().state).toBe('OPEN')
    expect((await d.status()).canary_window).toBeNull()
    expect(d.stopOwner()).toBeNull()
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 200 })
  }, 60_000)
})

// =====================================================================================
// 6. a dashboard restart during a run
// =====================================================================================

interface Up { run_id: string; pid: number; grandchild: number | null; worker: number }

/** A stand-in dashboard (its own OS process on this database) starts one run; then it is SIGKILLed. */
function startWorker(dash: Dashboard, mode: string): Promise<{ up: Up; observe: string; proc: ChildProcess; exited: Promise<unknown> }> {
  const { prompt, observe } = dash.prompt(mode)
  const keyFile = join(dash.real, 'dummy-key')
  writeFileSync(keyFile, dash.key, { mode: 0o600 })
  const specPath = join(dash.real, `spec-${Date.now()}.json`)
  writeFileSync(specPath, JSON.stringify({
    dbPath: dash.dbPath, storeDir: dash.storeDir, nowMs: dash.clock, cal: calibrationSource(getDb())(), tmpRoot: dash.real, keyFile,
    forbiddenRoots: [dash.installRoot, dash.storeDir], request: dash.body(prompt), observe, fakeProcStart: 'worker-start',
  }))
  const proc = spawn(process.execPath, ['--require', join(FIX, 'loopback-guard.cjs'), '--import', 'tsx', join(FIX, 'headless-worker.ts'), specPath], {
    cwd: ROOT,
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? '/tmp', TMPDIR: process.env.TMPDIR ?? '/tmp', NODE_ENV: 'production' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  dash.workers.push(proc)
  let out = ''
  let err = ''
  const exited = new Promise((r) => { proc.on('exit', (code, signal) => r({ code, signal })) })
  return new Promise((resolveUp, reject) => {
    proc.stdout!.on('data', (chunk) => {
      out += String(chunk)
      const line = out.split('\n').find((l) => l.startsWith('UP '))
      if (!line) return
      const o = JSON.parse(line.slice(3)) as Up & { error?: string }
      if (o.error) reject(new Error(`worker refused: ${o.error}`))
      else resolveUp({ up: o, observe, proc, exited })
    })
    proc.stderr!.on('data', (chunk) => { err += String(chunk) })
    void exited.then((e) => reject(new Error(`worker exited early ${JSON.stringify(e)}: ${err.slice(-2000)}`)))
  })
}

describe('N6: a dashboard restart during a run (B-04, N4a reconcile, N4b startup settle)', () => {
  it('the dashboard dies (SIGKILL) under a live run: the next start re-attaches it, and its result is booked once', async () => {
    d = new Dashboard()
    d.start('enforce')
    await d.openWithApprovedHash()
    const { up, observe, proc, exited } = await startWorker(d, 'wait_usr2')
    d.strays.push(up.pid)
    proc.kill('SIGKILL')
    await exited
    expect(alive(up.pid)).toBe(true)
    expect(d.runRow(up.run_id)).toMatchObject({ status: 'running', pid: up.pid, pid_start: 'worker-start' })
    const reservation = d.reservations().find((r) => r.ref === up.run_id)!
    expect(reservation).toMatchObject({ kind: 'headless', status: 'open' })

    // The restart: the processes the new dashboard "sees" (ps) include the live run.
    d.visible.set(up.pid, (JSON.parse(readFileSync(observe, 'utf8')) as { argv: string[] }).argv)
    d.stop()
    d.clock += MIN
    d.start('enforce')
    expect(d.runner.activeIds()).toEqual([up.run_id])
    expect((await d.status()).reservations).toMatchObject({ open_count: 1, open_usd: '0.60' })
    // Its own caller sees the re-attached run.
    expect(await gateApi('GET', `/api/credit-gate/runs/${up.run_id}`)).toMatchObject({ status: 200, body: { status: 'running', done: false } })

    process.kill(up.pid, 'SIGUSR2')
    await d.done(up.run_id)
    expect(d.runRow(up.run_id)).toMatchObject({ status: 'succeeded', basis: 'headless_json' })
    expect(d.state()).toMatchObject({ state: 'OPEN' })
    expect(d.ledgerRows(up.run_id)).toMatchObject([{ est_micro: 114_535, cli_micro: 74_983 }])
    expect(d.reservations().filter((r) => r.ref === up.run_id)).toMatchObject([{ status: 'settled' }])
    expect(existsSync(join(d.runsDir, up.run_id, 'key'))).toBe(false)
    await d.cycle()
    expect(d.state().state).toBe('OPEN')
    await d.drain()
    expectAuditDelivered(d)
  }, 120_000)

  it('a run that closed while its settle failed: the next start settles it once (BE-4b N1), with the whole reservation', async () => {
    d = new Dashboard()
    d.start('enforce')
    await d.openWithApprovedHash()
    const w = d.prompt('wait_usr2')
    const out = await d.run(w.prompt)
    expect(out.status).toBe(202)
    const runId = out.body.run_id as string
    await until(() => existsSync(w.observe), 10_000, 'the fake to start')
    // The config becomes unreadable (0644) right when the run ends: the settle cannot book.
    chmodSync(d.configPath, 0o644)
    process.kill((JSON.parse(readFileSync(w.observe, 'utf8')) as { pid: number }).pid, 'SIGUSR2')
    await until(() => !['starting', 'running'].includes(String(d!.runRow(runId).status)), 10_000, 'the run row to close')
    expect(d.reservations().filter((r) => r.ref === runId)).toMatchObject([{ status: 'open' }])
    expect(d.ledgerRows(runId)).toHaveLength(0)

    // Restart with the config back: the startup settles the closed run's reservation, once.
    d.stop()
    chmodSync(d.configPath, 0o600)
    d.clock += MIN
    d.start('enforce')
    expect(d.reservations().filter((r) => r.ref === runId)).toMatchObject([{ status: 'settled' }])
    const rows = d.ledgerRows(runId)
    expect(rows).toHaveLength(1)
    expect(Math.max(Number(rows[0]!.est_micro), Number(rows[0]!.cli_micro ?? 0))).toBe(600_000)
    d.stop()
    d.start('enforce')
    expect(d.ledgerRows(runId)).toHaveLength(1)
    await d.drain()
    expectAuditDelivered(d)
  }, 120_000)
})

// =====================================================================================
// 7. credit-too-low from the fake claude
// =====================================================================================

describe('N6: credit-too-low from the headless run -> INCIDENT (blueprint 3.5, N4a)', () => {
  it('the run\'s is_error + the credit message signals the gate; INCIDENT, the gate\'s STOP, one directive', async () => {
    d = new Dashboard()
    d.start('enforce')
    await d.openWithApprovedHash()
    const c = d.prompt('credit_too_low')
    const out = await d.run(c.prompt)
    expect(out.status).toBe(202)
    const runId = out.body.run_id as string
    await d.done(runId)
    expect(d.runRow(runId)).toMatchObject({ status: 'failed' })
    expect(d.state()).toMatchObject({ state: 'INCIDENT', reason: 'credit_balance_too_low' })
    await d.cycle()
    expect(d.state().state).toBe('INCIDENT')
    expect(d.stopOwner()).toBe('gate')
    expect(await gateApi('POST', '/api/credit-gate/reservations', BATCH)).toMatchObject({ status: 409 })
    expect(await d.run(d.prompt('success').prompt)).toMatchObject({ status: 409, body: { reason: 'gate_closed' } })
    const view = await gateApi('GET', `/api/credit-gate/runs/${runId}`)
    expect(view.body).toMatchObject({ is_error: true })
    await d.drain()
    const del = expectAuditDelivered(d)
    const incident = d.events().filter((e) => e.to_state === 'INCIDENT' && (e.kind === 'transition' || e.kind === 'incident_cause'))
    expect(incident.map((e) => e.reason)).toEqual(['credit_balance_too_low'])
    expect(del.directives).toEqual(incident.map((e) => e.id))
    const text = (getDb().prepare('SELECT content FROM agent_messages WHERE id = ?').get(incident[0]!.notified_msg_id) as { content: string }).content
    // B10: the source stays in the signal's own audit row; the directive names that row, no caller-chosen word.
    const signals = d.events().filter((e) => e.kind === 'signal' && e.reason === 'credit_balance_too_low')
    expect(signals).toHaveLength(1)
    expect(JSON.parse(String(signals[0]!.detail_json))).toMatchObject({ source: 'headless-runner' })
    expect(text).toContain(`signal_event_id=${signals[0]!.id}`)
    expect(text).not.toContain('source=')
  }, 120_000)
})
