// Poll loop of the permission-bot relay (card d7f586bf, spec F2.3, F4, F5):
// 409 pause with a >= 5 min retry (fake clock), webhook refusal without
// deleteWebhook, offset only after the handler, crash redelivery, K3 backlog
// drop, SIGTERM drain, 0600 files, token corpus search over every log line,
// status/offset file and exit value. Loopback only (socket guard, self-tested);
// fake token, no Vault, no real Telegram.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { EventEmitter } from 'node:events'
import { mkdtempSync, readFileSync, rmSync, statSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createBotApi, type BotApi, type TelegramUpdate } from '../permission-bot-relay/bot-api.js'
import { OffsetStore, StatusFile, readStatusFile, relayPaths, type RelayPaths } from '../permission-bot-relay/offset-store.js'
import { acquireRelayLock } from '../permission-bot-relay/lock.js'
import { fingerprintCommand, isPidAlive } from '../permission-bot-relay/process-identity.js'
import { PollLoop, attachShutdownSignals, CONFLICT_RETRY_MS, type Clock, type HandlerOutcome, type PollLoopOptions, type RelayLog, type UpdateHandler } from '../permission-bot-relay/poll-loop.js'
import { FakeBotApi } from './helpers/fake-bot-api.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'

const TOKEN = '424242424:FAKEtokenSECRETforRelayTests_0123456789ab'
const SECRET = TOKEN.split(':')[1]!

function leaks(text: string): string[] {
  const hits: string[] = []
  if (text.includes(TOKEN)) hits.push('token')
  for (let i = 0; i + 8 <= SECRET.length; i++) if (text.includes(SECRET.slice(i, i + 8))) hits.push(SECRET.slice(i, i + 8))
  return hits
}

interface LogLine { level: 'info' | 'warn' | 'error'; obj: Record<string, unknown>; msg: string }
const allLogText: string[] = []

function captureLog(): { log: RelayLog; lines: LogLine[] } {
  const lines: LogLine[] = []
  const push = (level: LogLine['level']) => (obj: Record<string, unknown>, msg: string): void => {
    lines.push({ level, obj, msg })
    allLogText.push(JSON.stringify({ level, obj, msg }))
  }
  return { log: { info: push('info'), warn: push('warn'), error: push('error') }, lines }
}

function fakeClock(start = 1_700_000_000_000): Clock & { sleeps: number[]; t(): number } {
  let t = start
  const sleeps: number[] = []
  return {
    sleeps,
    t: () => t,
    now: () => t,
    async sleep(ms, signal) {
      sleeps.push(ms)
      if (!signal.aborted) t += ms
      await new Promise((r) => setImmediate(r))
    },
  }
}

async function waitFor(cond: () => boolean, what: string, ms = 10_000): Promise<void> {
  const end = Date.now() + ms
  while (!cond()) {
    if (Date.now() > end) throw new Error(`timeout waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 5))
  }
}

let guard: LoopbackGuard
let fake: FakeBotApi
let dir: string
let paths: RelayPaths
const extraCorpus: string[] = []

beforeAll(async () => {
  guard = installLoopbackGuard()
  await selfTestLoopbackGuard(guard)
})
afterAll(() => {
  expect(leaks(allLogText.join('\n') + extraCorpus.join('\n'))).toEqual([])
  guard.uninstall()
})
beforeEach(async () => {
  fake = new FakeBotApi(TOKEN)
  await fake.start()
  dir = mkdtempSync(join(tmpdir(), 'pbr-loop-'))
  paths = relayPaths(dir)
})
afterEach(async () => {
  for (const p of [paths.offset, paths.status]) if (existsSync(p)) extraCorpus.push(readFileSync(p, 'utf8'))
  await fake.close()
  rmSync(dir, { recursive: true, force: true })
})

interface Harness {
  loop: PollLoop
  lines: LogLine[]
  offsets: OffsetStore
  status: StatusFile
  clock: ReturnType<typeof fakeClock>
  getUpdatesAt: number[]
}

function harness(handler: UpdateHandler, opts: Partial<PollLoopOptions> = {}): Harness {
  const base = createBotApi({ token: TOKEN, apiBase: fake.url })
  const clock = fakeClock()
  const getUpdatesAt: number[] = []
  const api: BotApi = {
    ...base,
    getUpdates: (p, s) => { getUpdatesAt.push(clock.now()); return base.getUpdates(p, s) },
  }
  const { log, lines } = captureLog()
  const offsets = new OffsetStore(paths.offset)
  const status = new StatusFile(paths.status, clock.now, log)
  const loop = new PollLoop({ api, offsets, status, handler, log, clock, longPollTimeoutSec: 1, dropBacklogAtStart: false, ...opts })
  return { loop, lines, offsets, status, clock, getUpdatesAt }
}

const okHandler = (outcome: HandlerOutcome = 'processed'): UpdateHandler & { seen: number[] } => {
  const seen: number[] = []
  const h = (async (u: TelegramUpdate, ctx) => {
    seen.push(u.update_id)
    await ctx.api.answerCallbackQuery(u.callback_query!.id, { text: 'ok' })
    return outcome
  }) as UpdateHandler & { seen: number[] }
  h.seen = seen
  return h
}

describe('offset commit (F4.1, F4.4)', () => {
  it('the offset is written only after the handler returned; inflight is set while it runs', async () => {
    const observed: unknown[] = []
    const offsets = new OffsetStore(paths.offset)
    const handler: UpdateHandler = async (u, ctx) => {
      observed.push(offsets.read())
      await ctx.api.answerCallbackQuery(u.callback_query!.id, { text: 'ok' })
      observed.push(offsets.read())
      return 'processed'
    }
    const h = harness(handler)
    const id = fake.pushCallback('apv:a:x:y')
    void h.loop.run()
    await waitFor(() => h.offsets.read().offset === id + 1, 'offset commit')
    expect(observed).toEqual([
      { offset: null, inflight: id, corrupt: false },
      { offset: null, inflight: id, corrupt: false },
    ])
    expect(h.offsets.read()).toEqual({ offset: id + 1, inflight: null, corrupt: false })
    expect(h.status.snapshot.counters.processed).toBe(1)
    expect(fake.callsOf('answerCallbackQuery')).toHaveLength(1)
    await h.loop.stop(2000)
    expect(readStatusFile(paths.status)?.state).toBe('stopped')
  })

  it('a throwing handler keeps the offset; the same update comes again; it is skipped after maxHandlerAttempts', async () => {
    let calls = 0
    const handler: UpdateHandler = async () => { calls++; throw new Error(`boom data=apv:a:${'0'.repeat(32)}:secret-nonce`) }
    const h = harness(handler, { maxHandlerAttempts: 3 })
    const id = fake.pushCallback('apv:a:x:y')
    void h.loop.run()
    await waitFor(() => h.offsets.read().offset === id + 1, 'skip after attempts')
    expect(calls).toBe(3)
    expect(h.status.snapshot.counters.errors).toBe(3)
    // A backoff sleep before each retry (the successful re-poll resets it to the base).
    expect(h.clock.sleeps.slice(0, 2)).toEqual([1000, 1000])
    // The handler's error message (it carried callback data) is never logged.
    const text = JSON.stringify(h.lines)
    expect(text).not.toContain('secret-nonce')
    expect(text).not.toContain('apv:')
    await h.loop.stop(2000)
  })

  it('a handler that fails once and then succeeds commits only after the success', async () => {
    let calls = 0
    const seenOffsets: unknown[] = []
    const offsets = new OffsetStore(paths.offset)
    const handler: UpdateHandler = async () => {
      calls++
      seenOffsets.push(offsets.read().offset)
      if (calls === 1) throw new Error('transient')
      return 'rejected'
    }
    const h = harness(handler)
    const id = fake.pushCallback('apv:r:x:y')
    void h.loop.run()
    await waitFor(() => h.offsets.read().offset === id + 1, 'commit after retry')
    expect(calls).toBe(2)
    expect(seenOffsets).toEqual([null, null])
    expect(h.status.snapshot.counters).toMatchObject({ rejected: 1, errors: 1 })
    await h.loop.stop(2000)
  })

  it('a non-callback update never reaches the handler, but the offset moves past it', async () => {
    const handler = okHandler()
    const h = harness(handler)
    const id = fake.push({ message: { message_id: 1, chat: { id: 11, type: 'private' }, text: 'hi' } })
    void h.loop.run()
    await waitFor(() => h.offsets.read().offset === id + 1, 'offset past non-callback')
    expect(handler.seen).toEqual([])
    expect(h.status.snapshot.counters.ignored).toBe(1)
    await h.loop.stop(2000)
  })
})

describe('crash and restart (F4.2, F4.3 / K3)', () => {
  it('backlog pending at start is dropped (counted, logged), later updates are handled', async () => {
    const handler = okHandler()
    const a = fake.pushCallback('apv:a:1:1')
    const b = fake.pushCallback('apv:a:2:2')
    const h = harness(handler, { dropBacklogAtStart: true })
    void h.loop.run()
    await waitFor(() => h.lines.some((l) => l.msg.includes('backlog dropped')), 'backlog drop')
    expect(handler.seen).toEqual([])
    expect(h.offsets.read()).toEqual({ offset: b + 1, inflight: null, corrupt: false })
    expect(h.status.snapshot.counters.dropped).toBe(2)
    expect(h.lines.find((l) => l.msg.includes('backlog dropped'))!.obj).toEqual({ dropped: 2 })
    expect(a).toBeLessThan(b)
    const c = fake.pushCallback('apv:a:3:3')
    await waitFor(() => handler.seen.includes(c), 'live update handled')
    await h.loop.stop(2000)
  })

  it('crash between handler and offset write: the in-flight update comes again after restart, the rest of the backlog is dropped', async () => {
    let entered = false
    const crashing: UpdateHandler = (_u, ctx) => new Promise<HandlerOutcome>((_res, rej) => {
      entered = true
      ctx.signal.addEventListener('abort', () => rej(new Error('killed')))
    })
    const first = harness(crashing)
    const id = fake.pushCallback('apv:a:x:y')
    const run1 = first.loop.run()
    await waitFor(() => entered, 'handler entered')
    expect(first.offsets.read()).toEqual({ offset: null, inflight: id, corrupt: false })
    const r = await first.loop.stop(50)
    expect(r.drained).toBe(false)
    await run1
    // Nothing committed: the update is still pending on the server and marked in flight.
    expect(first.offsets.read()).toEqual({ offset: null, inflight: id, corrupt: false })
    expect(fake.pending()).toContain(id)

    const later = fake.pushCallback('apv:a:z:z') // arrived while the relay was down
    const handler = okHandler()
    const second = harness(handler, { dropBacklogAtStart: true })
    void second.loop.run()
    await waitFor(() => second.lines.some((l) => l.msg.includes('backlog dropped')), 'restart drain')
    expect(handler.seen).toEqual([id])
    expect(second.status.snapshot.counters).toMatchObject({ processed: 1, dropped: 1 })
    expect(second.offsets.read()).toEqual({ offset: later + 1, inflight: null, corrupt: false })
    await second.loop.stop(2000)
  })
})

describe('409 conflict (F2.3)', () => {
  it('stops polling at once, alerts once, and retries no more often than every 5 minutes', async () => {
    fake.mode = 'conflict'
    const handler = okHandler()
    const h = harness(handler)
    void h.loop.run()
    await waitFor(() => h.getUpdatesAt.length >= 4, 'four conflict polls')
    await h.loop.stop(2000)
    const times = h.getUpdatesAt.slice(0, 4)
    for (let i = 1; i < times.length; i++) expect(times[i]! - times[i - 1]!).toBeGreaterThanOrEqual(CONFLICT_RETRY_MS)
    expect(CONFLICT_RETRY_MS).toBe(300_000)
    expect(h.clock.sleeps.every((ms) => ms === CONFLICT_RETRY_MS)).toBe(true)
    expect(h.lines.filter((l) => l.obj['alert'] === 'permission_bot_relay_conflict')).toHaveLength(1)
    expect(handler.seen).toEqual([])
  })

  it('reports conflict in the status file and recovers to polling when the 409 clears', async () => {
    fake.mode = 'conflict'
    fake.modeCalls = 1
    const handler = okHandler()
    const h = harness(handler)
    void h.loop.run()
    await waitFor(() => h.getUpdatesAt.length >= 2, 'retry after conflict')
    await waitFor(() => h.loop.state === 'polling', 'polling again')
    expect(h.getUpdatesAt[1]! - h.getUpdatesAt[0]!).toBeGreaterThanOrEqual(CONFLICT_RETRY_MS)
    expect(h.lines.some((l) => l.msg.includes('conflict cleared'))).toBe(true)
    await h.loop.stop(2000)
  })
})

describe('webhook (F1.3)', () => {
  it('a webhook at start: no getUpdates at all and deleteWebhook is never called', async () => {
    fake.webhookUrl = 'https://example.invalid/hook'
    const h = harness(okHandler())
    const exit = await h.loop.run()
    expect(exit).toEqual({ kind: 'refused', reason: 'webhook_set' })
    expect(fake.callsOf('getUpdates')).toHaveLength(0)
    expect(fake.callsOf('deleteWebhook')).toHaveLength(0)
    expect(fake.webhookUrl).toBe('https://example.invalid/hook')
    expect(readStatusFile(paths.status)).toMatchObject({ state: 'refused', reason: 'webhook_set' })
  })

  it('a webhook-caused 409 mid-run: polling stops, deleteWebhook is never called', async () => {
    fake.mode = 'webhook_conflict'
    const h = harness(okHandler())
    const exit = await h.loop.run()
    expect(exit).toEqual({ kind: 'refused', reason: 'webhook_set' })
    expect(fake.callsOf('getUpdates')).toHaveLength(1)
    expect(fake.callsOf('deleteWebhook')).toHaveLength(0)
  })
})

describe('other API errors', () => {
  it('5xx: degraded with exponential backoff (1 s, 2 s, 4 s), then polling', async () => {
    fake.mode = 'error5xx'
    fake.modeCalls = 3
    const h = harness(okHandler())
    void h.loop.run()
    await waitFor(() => h.getUpdatesAt.length >= 4 && h.loop.state === 'polling', 'recovery')
    expect(h.clock.sleeps.slice(0, 3)).toEqual([1000, 2000, 4000])
    expect(h.status.snapshot.counters.errors).toBe(3)
    await h.loop.stop(2000)
  })

  it('401: fatal, refused(api_unauthorized), no further polling', async () => {
    fake.mode = 'unauthorized'
    const h = harness(okHandler())
    expect(await h.loop.run()).toEqual({ kind: 'fatal', reason: 'api_unauthorized' })
    expect(fake.callsOf('getUpdates')).toHaveLength(1)
    expect(readStatusFile(paths.status)).toMatchObject({ state: 'refused', reason: 'api_unauthorized' })
  })

  it('a 4xx that echoes the token in its description is logged masked', async () => {
    fake.mode = 'fatal_echo'
    const h = harness(okHandler())
    expect(await h.loop.run()).toEqual({ kind: 'fatal', reason: 'api_fatal' })
    const text = JSON.stringify(h.lines)
    expect(text).toContain('<token>')
    expect(leaks(text)).toEqual([])
  })
})

describe('SIGTERM drain (F4.5)', () => {
  function fakeProbeLock() {
    return {
      isAlive: isPidAlive,
      identity: (pid: number) => ({ start: `s-${pid}`, cmdSha256: fingerprintCommand(`c-${pid}`) }),
    }
  }

  it('finishes the running update, commits its offset, starts no new one, releases the lock, exits 0 within 10 s', async () => {
    const lock = acquireRelayLock(paths.lock, { probe: fakeProbeLock() })
    expect(lock.ok).toBe(true)
    if (!lock.ok) return
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    const seen: number[] = []
    const handler: UpdateHandler = async (u) => { seen.push(u.update_id); await gate; return 'processed' }
    const h = harness(handler)
    const a = fake.pushCallback('apv:a:1:1')
    fake.pushCallback('apv:a:2:2')
    const signals = new EventEmitter()
    const exits: number[] = []
    attachShutdownSignals(h.loop, {
      log: captureLog().log,
      lock: lock.lock,
      graceMs: 9000,
      signals: signals as unknown as { on: (s: 'SIGTERM' | 'SIGINT', l: () => void) => unknown; off: (s: 'SIGTERM' | 'SIGINT', l: () => void) => unknown },
      exit: (c) => exits.push(c),
    })
    void h.loop.run()
    await waitFor(() => seen.length === 1, 'first handler running')
    const pollsBefore = fake.callsOf('getUpdates').length
    const t0 = Date.now()
    signals.emit('SIGTERM')
    signals.emit('SIGTERM') // a second signal is ignored
    await new Promise((r) => setTimeout(r, 30))
    release()
    await waitFor(() => exits.length === 1, 'exit')
    expect(Date.now() - t0).toBeLessThan(10_000)
    expect(exits).toEqual([0])
    expect(seen).toEqual([a])
    expect(h.offsets.read()).toEqual({ offset: a + 1, inflight: null, corrupt: false })
    expect(existsSync(paths.lock)).toBe(false)
    expect(fake.callsOf('getUpdates').length).toBe(pollsBefore)
    expect(readStatusFile(paths.status)?.state).toBe('stopped')
  })

  it('a handler still running at the end of the grace period: exit 1, inflight kept, lock released', async () => {
    const lock = acquireRelayLock(paths.lock, { probe: fakeProbeLock() })
    if (!lock.ok) throw new Error('lock')
    let entered = false
    const handler: UpdateHandler = () => new Promise<HandlerOutcome>(() => { entered = true })
    const h = harness(handler)
    const id = fake.pushCallback('apv:a:1:1')
    const signals = new EventEmitter()
    const exits: number[] = []
    attachShutdownSignals(h.loop, {
      log: captureLog().log,
      lock: lock.lock,
      graceMs: 100,
      signals: signals as unknown as { on: (s: 'SIGTERM' | 'SIGINT', l: () => void) => unknown; off: (s: 'SIGTERM' | 'SIGINT', l: () => void) => unknown },
      exit: (c) => exits.push(c),
    })
    void h.loop.run()
    await waitFor(() => entered, 'handler entered')
    signals.emit('SIGINT')
    await waitFor(() => exits.length === 1, 'exit after grace')
    expect(exits).toEqual([1])
    expect(h.offsets.read()).toEqual({ offset: null, inflight: id, corrupt: false })
    expect(existsSync(paths.lock)).toBe(false)
  })
})

describe('files and secrets (F5.1, F5.2)', () => {
  it('offset, status and lock files are 0600; the status file holds only the allowed fields', async () => {
    const lock = acquireRelayLock(paths.lock, { probe: { isAlive: isPidAlive, identity: (pid) => ({ start: `s-${pid}`, cmdSha256: 'c' }) } })
    expect(lock.ok).toBe(true)
    const handler = okHandler()
    const h = harness(handler)
    const id = fake.pushCallback(`apv:a:${'a'.repeat(32)}:${'N'.repeat(22)}`, { from: { id: 987654321, is_bot: false } })
    void h.loop.run()
    await waitFor(() => h.offsets.read().offset === id + 1, 'processed')
    await h.loop.stop(2000)
    for (const p of [paths.offset, paths.status, paths.lock]) expect(statSync(p).mode & 0o777).toBe(0o600)
    const st = JSON.parse(readFileSync(paths.status, 'utf8'))
    expect(Object.keys(st).sort()).toEqual(['counters', 'last_poll_ok_at', 'pid', 'reason', 'state', 'updated_at', 'v'])
    expect(Object.keys(st.counters).sort()).toEqual(['dropped', 'errors', 'ignored', 'processed', 'rejected'])
    const files = readFileSync(paths.status, 'utf8') + readFileSync(paths.offset, 'utf8') + JSON.stringify(h.lines)
    expect(files).not.toContain('NNNNNNNNNN')
    expect(files).not.toContain('apv:')
    expect(files).not.toContain('987654321')
    expect(leaks(files)).toEqual([])
    if (lock.ok) lock.lock.release()
  })

  it('an unexpected reason string is never written verbatim to the status file', () => {
    const st = new StatusFile(paths.status)
    st.setState('refused', `token ${TOKEN}`)
    expect(readStatusFile(paths.status)?.reason).toBe('invalid_reason_code')
    extraCorpus.push(readFileSync(paths.status, 'utf8'))
  })
})
