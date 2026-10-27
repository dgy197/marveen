// Card 94f8d99f, memory program w3, node DW3: the keep-warm runner.
//
// The runner gets a fake fetch, a scripted monotonic and wall clock and a
// scripted embedding activity; nothing here opens a socket or reaches a real
// Ollama (the suite's NO-LIVE-OLLAMA gate stays on). The few tests that use
// the real db.ts activity stub the global fetch generateEmbedding uses.
import { describe, it, expect, vi, beforeEach, afterEach, beforeAll } from 'vitest'
import { mkdtempSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'

import { logger } from '../logger.js'
import {
  initDatabase, getDb, generateEmbedding, backfillEmbeddings, getEmbeddingActivity, isEmbeddingOutageLatched,
  isBackfillInFlight, embeddingMonoMs, saveAgentMemory, type EmbeddingActivity,
} from '../db.js'
import { EMBED_KEEPWARM_MINUTES, EMBED_KEEPWARM_MINUTES_DEFAULT, resolveEmbedKeepWarmMinutes } from '../config.js'
import { SETTINGS_REGISTRY, validateSettingValue } from '../config-registry.js'
import {
  startEmbeddingKeepWarmRunner, stopEmbeddingKeepWarmRunner, runKeepWarmTick, keepWarmRunnerSnapshot,
  type KeepWarmConfig,
} from '../web/embedding-keepwarm-runner.js'
import { KEEPWARM_FIRST_TICK_MS, KEEPWARM_TICK_MS } from '../embedding-keepwarm.js'

const MIN = 60_000
const HOUR = 60 * MIN
// A fake endpoint string only: the fake fetch answers it, no socket is opened.
const FAKE_URL = 'http://127.0.0.1:45999'

interface Clock { mono: number; wall: number }
type Answer = (url: string, init: RequestInit) => Promise<Response> | Response

class FakeOllama {
  calls: { url: string; method: string; body: any; init: RequestInit }[] = []
  /** expires_at of the loaded model (wall ms); null = not loaded. */
  expires: number | null
  name = 'bge-m3:latest'
  ps: Answer | null = null
  ping: Answer | null = null
  /** Called inside each request (e.g. to move the clock while it runs). */
  during: ((kind: 'ps' | 'ping') => void) | null = null
  constructor(private clock: Clock, remainingMs = 23 * HOUR) {
    this.expires = clock.wall + remainingMs
  }
  get psCalls() { return this.calls.filter(c => c.url.endsWith('/api/ps')) }
  get pingCalls() { return this.calls.filter(c => c.url.endsWith('/api/embeddings')) }
  fetch = vi.fn(async (url: string, init: RequestInit): Promise<Response> => {
    this.calls.push({ url, method: String(init.method), body: init.body ? JSON.parse(String(init.body)) : undefined, init })
    if (url.endsWith('/api/ps')) {
      this.during?.('ps')
      if (this.ps) return this.ps(url, init)
      const models = this.expires === null ? [] : [{ name: this.name, model: this.name, expires_at: new Date(this.expires).toISOString() }]
      return new Response(JSON.stringify({ models }), { status: 200 })
    }
    if (url.endsWith('/api/embeddings')) {
      this.during?.('ping')
      if (this.ping) return this.ping(url, init)
      // Ollama's rule: the window is reset to now + keep_alive when the request ends.
      const ka = JSON.parse(String(init.body)).keep_alive as string
      this.expires = this.clock.wall + parseInt(ka, 10) * 1000
      return new Response(JSON.stringify({ embedding: [0.1, 0.2] }), { status: 200 })
    }
    throw new Error(`unexpected URL ${url}`)
  })
}

let clock: Clock
let act: EmbeddingActivity
let ollama: FakeOllama
let info: ReturnType<typeof vi.spyOn>
let warn: ReturnType<typeof vi.spyOn>
let debug: ReturnType<typeof vi.spyOn>

function advance(ms: number) {
  clock.mono += ms
  clock.wall += ms
}

function start(config: Partial<KeepWarmConfig> = {}, fetchFn: FakeOllama['fetch'] = ollama.fetch) {
  startEmbeddingKeepWarmRunner({
    deps: { fetch: fetchFn, monoMs: () => clock.mono, wallMs: () => clock.wall, activity: () => ({ ...act }) },
    config: { minutes: 5, embedUrl: FAKE_URL, model: 'bge-m3', invalid: undefined, ...config },
  })
}

/** Move both clocks by `ms` and run one tick. */
async function tickAfter(ms: number) {
  advance(ms)
  return runKeepWarmTick()
}

const messages = (spy: ReturnType<typeof vi.spyOn>): string[] => spy.mock.calls.map((c: unknown[]) => (typeof c[0] === 'string' ? c[0] : c[1]) as string)

beforeEach(() => {
  clock = { mono: 1_000_000, wall: Date.UTC(2026, 9, 18, 18, 0, 0) }
  act = { inFlight: 0, lastDoneMono: null, successes: 0, outageLatched: false, backfillInFlight: false }
  ollama = new FakeOllama(clock)
  info = vi.spyOn(logger, 'info').mockImplementation(() => undefined as never)
  warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
  debug = vi.spyOn(logger, 'debug').mockImplementation(() => undefined as never)
})

afterEach(() => {
  stopEmbeddingKeepWarmRunner()
  vi.useRealTimers()
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe('(a) EMBED_KEEPWARM_MINUTES=0: off', () => {
  it('no timer, no call, one INFO that says it is off', async () => {
    vi.useFakeTimers()
    start({ minutes: 0 })
    expect(keepWarmRunnerSnapshot().running).toBe(false)
    expect(vi.getTimerCount()).toBe(0)
    await vi.advanceTimersByTimeAsync(24 * HOUR)
    expect(await runKeepWarmTick()).toBe('stopped')
    expect(ollama.fetch).not.toHaveBeenCalled()
    expect(messages(info)).toEqual(['Embedding keep-warm off (EMBED_KEEPWARM_MINUTES=0)'])
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('(b) a non-loopback EMBED_URL: off', () => {
  it.each(['http://192.0.2.1:11434', 'http://ollama.example:11434', 'http://127.0.0.1:11434@evil.example', 'not a url'])(
    '%s: no call, exactly one INFO, and the URL is not logged',
    async (embedUrl) => {
      start({ embedUrl })
      expect(keepWarmRunnerSnapshot().running).toBe(false)
      expect(await runKeepWarmTick()).toBe('stopped')
      expect(ollama.fetch).not.toHaveBeenCalled()
      expect(info).toHaveBeenCalledTimes(1)
      expect(messages(info)[0]).toMatch(/^Embedding keep-warm off: EMBED_URL is not a loopback address/)
      expect(JSON.stringify(info.mock.calls)).not.toContain(embedUrl)
    },
  )
})

describe('(c) recent activity: no call', () => {
  it('nothing for the interval after the start (what ran before the process is unknown)', async () => {
    start()
    expect(await tickAfter(5 * MIN - 1)).toBe('skip_recent')
    expect(ollama.fetch).not.toHaveBeenCalled()
    expect(await tickAfter(1)).toBe('ping_ok')
  })

  it('a call that finished 4:59 ago holds the ping; at 5:00 it goes', async () => {
    start()
    advance(HOUR)
    act.lastDoneMono = clock.mono - (5 * MIN - 1000)
    expect(await runKeepWarmTick()).toBe('skip_recent')
    expect(ollama.fetch).not.toHaveBeenCalled()
    expect(await tickAfter(999)).toBe('skip_recent')
    expect(await tickAfter(1)).toBe('ping_ok')
    expect(ollama.calls.map(c => c.method)).toEqual(['GET', 'POST'])
  })

  it('the interval follows the config (10 minutes)', async () => {
    start({ minutes: 10 })
    expect(await tickAfter(9 * MIN)).toBe('skip_recent')
    expect(await tickAfter(MIN)).toBe('ping_ok')
  })
})

describe('(d) an embedding call or a backfill pass in flight: no call', () => {
  it.each([
    ['a generateEmbedding call', { inFlight: 1 }],
    ['a backfill pass', { backfillInFlight: true }],
  ] as const)('%s', async (_label, patch) => {
    start()
    advance(HOUR)
    Object.assign(act, patch)
    expect(await runKeepWarmTick()).toBe('skip_inflight')
    expect(ollama.fetch).not.toHaveBeenCalled()
    Object.assign(act, { inFlight: 0, backfillInFlight: false })
    expect(await runKeepWarmTick()).toBe('ping_ok')
  })

  it('a real call that starts while /api/ps answers: no ping behind it', async () => {
    start()
    advance(HOUR)
    ollama.during = (kind) => { if (kind === 'ps') act.inFlight = 1 }
    expect(await runKeepWarmTick()).toBe('skip_inflight')
    expect(ollama.psCalls).toHaveLength(1)
    expect(ollama.pingCalls).toHaveLength(0)
  })

  it('a real call that finishes while /api/ps answers: no ping, the model was just used', async () => {
    start()
    advance(HOUR)
    ollama.during = (kind) => { if (kind === 'ps') act.lastDoneMono = clock.mono }
    expect(await runKeepWarmTick()).toBe('skip_recent')
    expect(ollama.pingCalls).toHaveLength(0)
  })
})

describe('(e) the outage latch or the own backoff: Ollama is not called at all, /api/ps neither', () => {
  it('the generateEmbedding outage latch', async () => {
    start()
    advance(HOUR)
    act.outageLatched = true
    for (let i = 0; i < 30; i++) expect(await tickAfter(MIN)).toBe('skip_outage')
    expect(ollama.fetch).not.toHaveBeenCalled()
    act.outageLatched = false
    expect(await tickAfter(MIN)).toBe('ping_ok')
  })

  it('the own backoff after a failed /api/ps', async () => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response('down', { status: 500 })
    expect(await runKeepWarmTick()).toBe('ps_failed')
    ollama.ps = null
    for (let i = 0; i < 14; i++) expect(await tickAfter(MIN)).toBe('skip_backoff')
    expect(ollama.calls).toHaveLength(1)
    expect(await tickAfter(MIN)).toBe('ping_ok')
  })
})

describe('(f) the model is not loaded: /api/ps only, never an embedding (the keep-warm never loads a model)', () => {
  it('one /api/ps per interval, no POST, no backoff', async () => {
    ollama.expires = null
    start()
    advance(HOUR)
    expect(await runKeepWarmTick()).toBe('not_loaded')
    for (let i = 0; i < 4; i++) expect(await tickAfter(MIN)).toBe('skip_recent')
    expect(await tickAfter(MIN)).toBe('not_loaded')
    expect(ollama.psCalls).toHaveLength(2)
    expect(ollama.pingCalls).toHaveLength(0)
    expect(keepWarmRunnerSnapshot().backoffFails).toBe(0)
    expect(warn).not.toHaveBeenCalled()
  })
})

describe('(g) the model name', () => {
  it.each([
    ['bge-m3', 'bge-m3:latest', 'ping_ok'],
    ['bge-m3:latest', 'bge-m3:latest', 'ping_ok'],
    ['bge-m3:567m', 'bge-m3:latest', 'not_loaded'],
    ['bge-m3', 'bge-m3:567m', 'not_loaded'],
    ['nomic-embed-text', 'bge-m3:latest', 'not_loaded'],
  ])('EMBED_MODEL %s, /api/ps lists %s: %s', async (model, listed, want) => {
    ollama.name = listed
    start({ model })
    advance(HOUR)
    expect(await runKeepWarmTick()).toBe(want)
    if (want === 'ping_ok') expect(ollama.pingCalls[0].body.model).toBe(model)
  })
})

describe('(h) a window the ping must not hold, or an answer that is not Ollama\'s: no ping', () => {
  it.each([
    ['60 s left', 60_999],
    ['10 s left', 10_000],
    ['expired', -1_000],
    ['more than 30 days left', 30 * 24 * HOUR + 1_000],
  ])('%s', async (_label, remainingMs) => {
    start()
    advance(HOUR)
    ollama.expires = clock.wall + remainingMs
    expect(await runKeepWarmTick()).toBe('window')
    expect(ollama.pingCalls).toHaveLength(0)
    expect(keepWarmRunnerSnapshot().counters!.skip_window).toBe(1)
  })

  it('61 s left: the ping goes, with keep_alive 61s', async () => {
    start()
    advance(HOUR)
    ollama.expires = clock.wall + 61_000
    expect(await runKeepWarmTick()).toBe('ping_ok')
    expect(ollama.pingCalls[0].body.keep_alive).toBe('61s')
  })

  it.each([
    ['no expires_at', JSON.stringify({ models: [{ name: 'bge-m3:latest' }] })],
    ['an unreadable expires_at', JSON.stringify({ models: [{ name: 'bge-m3:latest', expires_at: 'in a day' }] })],
  ])('%s: window', async (_label, body) => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response(body)
    expect(await runKeepWarmTick()).toBe('window')
    expect(ollama.pingCalls).toHaveLength(0)
  })

  it.each([
    ['not JSON', () => new Response('<html>proxy</html>')],
    ['JSON without models', () => new Response('{"status":"ok"}')],
    ['too large (65537 bytes)', () => new Response(JSON.stringify({ models: [], pad: 'x'.repeat(65_537) }))],
    ['too large by its declared length', () => new Response('{"models":[]}', { headers: { 'content-length': '70000' } })],
  ])('%s: a failed probe (backoff), no ping', async (_label, answer) => {
    start()
    advance(HOUR)
    ollama.ps = answer
    expect(await runKeepWarmTick()).toBe('ps_failed')
    expect(ollama.pingCalls).toHaveLength(0)
    expect(keepWarmRunnerSnapshot().backoffFails).toBe(1)
  })
})

describe('(i) the good case', () => {
  it('exactly one GET /api/ps, then exactly one POST with the model, the constant text and the seconds left (rounded down)', async () => {
    start()
    advance(HOUR)
    ollama.expires = clock.wall + 7 * HOUR + 999
    expect(await runKeepWarmTick()).toBe('ping_ok')
    expect(ollama.calls).toHaveLength(2)
    const [ps, ping] = ollama.calls
    expect(ps.url).toBe(`${FAKE_URL}/api/ps`)
    expect(ps.method).toBe('GET')
    expect(ping.url).toBe(`${FAKE_URL}/api/embeddings`)
    expect(ping.method).toBe('POST')
    expect(ping.init.redirect).toBe('error')
    expect(ping.body).toEqual({ model: 'bge-m3', prompt: 'keepwarm', keep_alive: `${7 * 3600}s` })
  })

  it('the seconds left are counted when the ping goes, not when /api/ps answered', async () => {
    start()
    advance(HOUR)
    ollama.expires = clock.wall + 2 * HOUR
    ollama.during = (kind) => { if (kind === 'ps') advance(1_500) }
    expect(await runKeepWarmTick()).toBe('ping_ok')
    expect(ollama.pingCalls[0].body.keep_alive).toBe(`${2 * 3600 - 2}s`)
  })

  it('the ping never moves expires_at later (fake Ollama: the window resets to end-of-request + keep_alive)', async () => {
    start()
    const expires0 = clock.wall + 20 * HOUR + 437
    ollama.expires = expires0
    for (let i = 0; i < 6 * 60; i++) {
      await tickAfter(MIN)
      expect(ollama.expires).toBeLessThanOrEqual(expires0)
    }
    expect(ollama.pingCalls.length).toBeGreaterThan(60)
    // Each ping's keep_alive is what was left at that moment.
    for (const c of ollama.pingCalls) expect(parseInt(c.body.keep_alive, 10)).toBeLessThanOrEqual(20 * 3600)
  })

  it('a second tick while one runs is a no-op (no second call)', async () => {
    start()
    advance(HOUR)
    let release!: () => void
    ollama.ps = () => new Promise<Response>(r => { release = () => r(new Response(JSON.stringify({ models: [] }))) })
    const first = runKeepWarmTick()
    await Promise.resolve()
    expect(await runKeepWarmTick()).toBe('busy')
    release()
    expect(await first).toBe('not_loaded')
    expect(ollama.calls).toHaveLength(1)
  })
})

describe('(j) failures: backoff 15 -> 30 -> ... -> 240 min, one WARN per episode', () => {
  async function minutesUntilNextCall(): Promise<number> {
    const before = ollama.calls.length
    for (let m = 1; m <= 600; m++) {
      await tickAfter(MIN)
      if (ollama.calls.length > before) return m
    }
    return -1
  }

  it('the gaps double to the cap, and only the first failure WARNs', async () => {
    start()
    advance(HOUR)
    ollama.ps = async () => { throw new Error('ECONNREFUSED') }
    expect(await runKeepWarmTick()).toBe('ps_failed')
    const gaps: number[] = []
    for (let i = 0; i < 6; i++) gaps.push(await minutesUntilNextCall())
    expect(gaps).toEqual([15, 30, 60, 120, 240, 240])
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0][0]).toEqual({ stage: 'ps', error: 'network', backoffMin: 15 })
    expect(debug.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm: the call failed again')).toHaveLength(6)
  })

  it('a failed ping (status, network, timeout) backs off too', async () => {
    vi.useFakeTimers()
    start()
    advance(HOUR)
    ollama.ping = () => new Response('{"error":"x"}', { status: 500 })
    expect(await runKeepWarmTick()).toBe('ping_failed')
    expect(warn.mock.calls[0][0]).toEqual({ stage: 'ping', error: 'status', status: 500, backoffMin: 15 })
    advance(15 * MIN)
    ollama.ping = async () => { throw new TypeError('fetch failed') }
    expect(await runKeepWarmTick()).toBe('ping_failed')
    advance(30 * MIN)
    ollama.ping = (_u, init) => new Promise<Response>((_r, reject) => init.signal?.addEventListener('abort', () => reject(new Error('aborted'))))
    const p = runKeepWarmTick()
    await vi.advanceTimersByTimeAsync(5_000)
    expect(await p).toBe('ping_failed')
    expect(warn).toHaveBeenCalledTimes(1)
    const again = debug.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm: the call failed again')
    expect(again.map((c: unknown[]) => (c[0] as { error: string }).error)).toEqual(['network', 'timeout'])
    // A good /api/ps in front of each failed ping does not end the episode: the pause keeps doubling.
    expect(again.map((c: unknown[]) => (c[0] as { backoffMin: number }).backoffMin)).toEqual([30, 60])
    expect(ollama.psCalls).toHaveLength(3)
  })

  it.each([
    ['not_loaded', () => { ollama.expires = null }],
    ['window', () => { ollama.expires = clock.wall + 30_000 }],
  ] as const)('a readable /api/ps (%s) ends the episode: a later outage WARNs again and starts at 15 min (DE1)', async (verdict, healthy) => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response('', { status: 503 })
    expect(await runKeepWarmTick()).toBe('ps_failed')
    ollama.ps = null
    healthy()
    advance(15 * MIN)
    expect(await runKeepWarmTick()).toBe(verdict)
    expect(keepWarmRunnerSnapshot().backoffFails).toBe(0)
    // Hours of good answers, then a new outage.
    for (let i = 0; i < 3 * 60; i++) expect(['skip_recent', verdict]).toContain(await tickAfter(MIN))
    ollama.ps = async () => { throw new Error('ECONNREFUSED') }
    let r = ''
    for (let i = 0; i < 5 && r !== 'ps_failed'; i++) r = await tickAfter(MIN)
    expect(r).toBe('ps_failed')
    expect(warn).toHaveBeenCalledTimes(2)
    expect(warn.mock.calls[1][0]).toEqual({ stage: 'ps', error: 'network', backoffMin: 15 })
    // Still at most one WARN per episode: the next failure 15 min later is debug, at 30 min.
    expect(await minutesUntilNextCall()).toBe(15)
    expect(warn).toHaveBeenCalledTimes(2)
    const again = debug.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm: the call failed again')
    expect(again.map((c: unknown[]) => (c[0] as { backoffMin: number }).backoffMin)).toEqual([30])
  })

  it('a real embedding that succeeds ends the backoff; the next failure is a new episode with a new WARN', async () => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response('', { status: 503 })
    expect(await runKeepWarmTick()).toBe('ps_failed')
    expect(await tickAfter(MIN)).toBe('skip_backoff')
    act.successes++
    act.lastDoneMono = clock.mono // a real call just went through
    // The backoff is gone (not skip_backoff), but the real call is recent.
    expect(await tickAfter(MIN)).toBe('skip_recent')
    // 7 min after the failure: the 15 min backoff would still hold, so the call proves it ended.
    expect(await tickAfter(5 * MIN)).toBe('ps_failed')
    expect(warn).toHaveBeenCalledTimes(2)
    expect(warn.mock.calls[1][0].backoffMin).toBe(15)
  })

  it('a failed real call does not end the backoff', async () => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response('', { status: 503 })
    await runKeepWarmTick()
    act.lastDoneMono = clock.mono
    expect(await tickAfter(MIN)).toBe('skip_backoff')
  })

  it('a ping that goes through after the backoff ends the episode (fails back to 0)', async () => {
    start()
    advance(HOUR)
    ollama.ps = () => new Response('', { status: 503 })
    await runKeepWarmTick()
    ollama.ps = null
    advance(15 * MIN)
    expect(await runKeepWarmTick()).toBe('ping_ok')
    expect(keepWarmRunnerSnapshot().backoffFails).toBe(0)
  })
})

describe('no ping storm', () => {
  it('a day of idleness with the model loaded: at most one /api/ps and one ping per 5 minutes', async () => {
    start()
    ollama.expires = clock.wall + 24 * HOUR
    for (let i = 0; i < 24 * 60; i++) await tickAfter(MIN)
    expect(ollama.pingCalls.length).toBeLessThanOrEqual(288)
    expect(ollama.psCalls.length).toBeLessThanOrEqual(288)
    expect(ollama.pingCalls.length).toBeGreaterThan(250)
    const pings = ollama.calls.filter(c => c.method === 'POST')
    expect(pings.every(c => parseInt(c.body.keep_alive, 10) > 60)).toBe(true)
  })

  it('a day with Ollama down (every /api/ps fails): at most a dozen calls', async () => {
    start()
    ollama.ps = async () => { throw new Error('ECONNREFUSED') }
    for (let i = 0; i < 24 * 60; i++) await tickAfter(MIN)
    expect(ollama.calls.length).toBeLessThanOrEqual(12)
    expect(warn).toHaveBeenCalledTimes(1)
  })
})

describe('(l) the hourly summary', () => {
  it('one INFO per hour, numbers only, when the hour had a keep-warm call', async () => {
    start()
    for (let i = 0; i < 60; i++) await tickAfter(MIN)
    const summaries = info.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm, last hour')
    expect(summaries).toHaveLength(1)
    const fields = summaries[0][0] as Record<string, unknown>
    expect(Object.keys(fields).sort()).toEqual([
      'last_ms', 'max_ms', 'pings_failed', 'pings_ok', 'probes', 'ps_failed', 'skip_backoff', 'skip_inflight',
      'skip_not_loaded', 'skip_outage', 'skip_recent', 'skip_window',
    ])
    for (const v of Object.values(fields)) expect(Number.isInteger(v)).toBe(true)
    // Minutes 1-59: a ping every 5 minutes (5, 10, ..., 55), the other 48 ticks skipped as recent.
    expect(fields).toMatchObject({ probes: 11, pings_ok: 11, skip_recent: 48, pings_failed: 0, ps_failed: 0 })
    // The tick at the hour mark closed the hour first, so its own ping opens the next one.
    expect(keepWarmRunnerSnapshot().counters).toMatchObject({ probes: 1, pings_ok: 1, skip_recent: 0 })
    for (let i = 0; i < 59; i++) await tickAfter(MIN)
    expect(info.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm, last hour')).toHaveLength(1)
    await tickAfter(MIN)
    expect(info.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm, last hour')).toHaveLength(2)
  })

  it('an hour without a keep-warm call (searches every minute) writes no summary', async () => {
    start()
    for (let i = 0; i < 3 * 60; i++) {
      act.lastDoneMono = clock.mono
      await tickAfter(MIN)
    }
    expect(ollama.fetch).not.toHaveBeenCalled()
    expect(info.mock.calls.filter((c: unknown[]) => c[1] === 'Embedding keep-warm, last hour')).toHaveLength(0)
  })
})

describe('(m) timers: one per start, stopped on stop, unref\'ed', () => {
  it('a second start is a no-op: one timer, one INFO', async () => {
    vi.useFakeTimers()
    start()
    start()
    expect(vi.getTimerCount()).toBe(1)
    expect(messages(info).filter(m => m.startsWith('Embedding keep-warm on'))).toHaveLength(1)
  })

  it('the first tick 2 min after start, then every minute; nothing after stop', async () => {
    vi.useFakeTimers()
    const tickSpy = vi.fn()
    ollama.during = () => tickSpy()
    start()
    advance(HOUR) // the scripted clock says idle; the timers drive the ticks
    await vi.advanceTimersByTimeAsync(KEEPWARM_FIRST_TICK_MS - 1)
    expect(ollama.fetch).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(ollama.calls).toHaveLength(2)
    expect(vi.getTimerCount()).toBe(1)
    advance(5 * MIN)
    await vi.advanceTimersByTimeAsync(KEEPWARM_TICK_MS)
    expect(ollama.calls).toHaveLength(4)
    stopEmbeddingKeepWarmRunner()
    expect(vi.getTimerCount()).toBe(0)
    advance(HOUR)
    await vi.advanceTimersByTimeAsync(24 * HOUR)
    expect(ollama.calls).toHaveLength(4)
    expect(await runKeepWarmTick()).toBe('stopped')
    expect(KEEPWARM_FIRST_TICK_MS).toBe(120_000)
    expect(KEEPWARM_TICK_MS).toBe(60_000)
  })

  it('both timers are unref\'ed (they never hold the process open)', async () => {
    start()
    const snap = keepWarmRunnerSnapshot()
    expect((snap.initialTimer as NodeJS.Timeout).hasRef()).toBe(false)
    stopEmbeddingKeepWarmRunner()
    vi.useFakeTimers()
    start()
    await vi.advanceTimersByTimeAsync(KEEPWARM_FIRST_TICK_MS)
    const interval = keepWarmRunnerSnapshot().intervalTimer as NodeJS.Timeout
    expect(interval).not.toBeNull()
    expect(interval.hasRef()).toBe(false)
  })

  it('stop while /api/ps is in flight: the call is aborted, and no ping follows', async () => {
    start()
    advance(HOUR)
    let signal: AbortSignal | undefined
    let release!: () => void
    ollama.ps = (_u, init) => {
      signal = init.signal ?? undefined
      return new Promise<Response>(r => { release = () => r(new Response(JSON.stringify({ models: [{ name: 'bge-m3:latest', expires_at: new Date(clock.wall + HOUR).toISOString() }] }))) })
    }
    const p = runKeepWarmTick()
    await Promise.resolve()
    stopEmbeddingKeepWarmRunner()
    expect(signal?.aborted).toBe(true)
    release()
    expect(await p).toBe('stopped')
    expect(ollama.pingCalls).toHaveLength(0)
  })

  it('start after stop runs again', async () => {
    start()
    stopEmbeddingKeepWarmRunner()
    start()
    expect(keepWarmRunnerSnapshot().running).toBe(true)
    expect(await tickAfter(HOUR)).toBe('ping_ok')
  })
})

describe('(o) EMBED_KEEPWARM_MINUTES', () => {
  it('defaults to 5, the value this suite runs with', () => {
    expect(EMBED_KEEPWARM_MINUTES_DEFAULT).toBe(5)
    expect(EMBED_KEEPWARM_MINUTES).toBe(5)
  })

  it.each([['0', 0], ['5', 5], ['7', 7], ['10', 10], [' 6 ', 6]])('accepts %j', (raw, want) => {
    expect(resolveEmbedKeepWarmMinutes(raw)).toEqual({ value: want })
  })

  it('unset or blank: the default, not flagged', () => {
    expect(resolveEmbedKeepWarmMinutes(undefined)).toEqual({ value: 5 })
    expect(resolveEmbedKeepWarmMinutes('  ')).toEqual({ value: 5 })
  })

  it.each(['1', '4', '11', '60', '-1', '5.5', '05', '00', '5m', 'five', '1e1', 'true'])('refuses %j: the default plus the rejected value', (raw) => {
    expect(resolveEmbedKeepWarmMinutes(raw)).toEqual({ value: 5, invalid: raw })
  })

  it('an invalid value at start: one WARN with the default, and the runner runs with it', () => {
    start({ minutes: 5, invalid: 'banana' })
    expect(warn).toHaveBeenCalledTimes(1)
    expect(warn.mock.calls[0]).toEqual([{ value: 'banana', using: 5 }, expect.stringMatching(/^EMBED_KEEPWARM_MINUTES must be 0/)])
    expect(keepWarmRunnerSnapshot().running).toBe(true)
  })

  const def = () => SETTINGS_REGISTRY.find(d => d.key === 'EMBED_KEEPWARM_MINUTES')!

  it('is in the registry: int, default 5, restart required, not secret', () => {
    expect(def()).toMatchObject({ type: 'int', default: 5, requiresRestart: true, secret: false, module: 'system' })
  })

  it.each(['0', '5', '10', 5, 0])('the Settings save accepts %j', (v) => {
    expect(validateSettingValue(def(), v).ok).toBe(true)
  })

  it.each(['1', '4', '11', '-1', '5.5', 'five', '', 3])('the Settings save refuses %j', (v) => {
    expect(validateSettingValue(def(), v).ok).toBe(false)
  })

  it('every value the save accepts, the boot accepts too', () => {
    for (const v of ['0', '1', '4', '5', '6', '7', '8', '9', '10', '11', '05', '-1', 'x', ' 5 ']) {
      if (validateSettingValue(def(), v).ok) expect({ v, boot: resolveEmbedKeepWarmMinutes(v).invalid }).toEqual({ v, boot: undefined })
    }
  })
})

describe('with the real db.ts activity (generateEmbedding counters, the outage latch, no DB access)', () => {
  beforeAll(() => {
    initDatabase(join(mkdtempSync(join(tmpdir(), 'keepwarm-db-')), 'keepwarm.db'))
  })

  /** The global fetch generateEmbedding uses: answers, fails, or holds every call until release(). */
  function stubEmbeddings(mode: 'ok' | 'down' | 'hang') {
    let released = false
    const waiters: Array<() => void> = []
    const fetchMock = vi.fn(async (..._a: unknown[]) => {
      if (mode === 'down') throw new Error('stub: embedding backend down')
      if (mode === 'hang' && !released) await new Promise<void>(r => { waiters.push(r) })
      return { json: async () => ({ embedding: [1, 0, 0, 0] }) }
    })
    vi.stubGlobal('fetch', fetchMock)
    return { fetchMock, release: () => { released = true; for (const r of waiters.splice(0)) r() } }
  }

  it('generateEmbedding counts calls in flight, the last finished call and the successes', async () => {
    const s = stubEmbeddings('hang')
    const before = getEmbeddingActivity()
    const t0 = embeddingMonoMs()
    const p = generateEmbedding('activity probe')
    await Promise.resolve()
    expect(getEmbeddingActivity().inFlight).toBe(before.inFlight + 1)
    s.release()
    expect(await p).toEqual([1, 0, 0, 0])
    const after = getEmbeddingActivity()
    expect(after.inFlight).toBe(before.inFlight)
    expect(after.successes).toBe(before.successes + 1)
    expect(after.lastDoneMono).not.toBeNull()
    expect(after.lastDoneMono!).toBeGreaterThanOrEqual(t0)
  })

  it('the activity clock is not performance.now() (finding WE1: the Server-Timing test counts its reads per search)', async () => {
    const spy = vi.spyOn(performance, 'now')
    stubEmbeddings('down')
    expect(await generateEmbedding('clock probe')).toBeNull()
    stubEmbeddings('ok') // and the latch is clear again for the tests below
    expect(await generateEmbedding('clock probe')).toEqual([1, 0, 0, 0])
    expect(spy).not.toHaveBeenCalled()
    expect(getEmbeddingActivity().lastDoneMono).not.toBeNull()
  })

  it('a failed call counts as finished but not as a success, and sets the outage latch as before', async () => {
    stubEmbeddings('down')
    const before = getEmbeddingActivity()
    expect(await generateEmbedding('activity probe')).toBeNull()
    const after = getEmbeddingActivity()
    expect(after.successes).toBe(before.successes)
    expect(after.inFlight).toBe(before.inFlight)
    expect(after.outageLatched).toBe(true)
    expect(isEmbeddingOutageLatched()).toBe(true)
    stubEmbeddings('ok')
    await generateEmbedding('activity probe')
    expect(isEmbeddingOutageLatched()).toBe(false)
  })

  it('(k) a failed ping does not set the outage latch, touches no DB, and the next real failure still WARNs first', async () => {
    stubEmbeddings('ok')
    await generateEmbedding('clear the latch')
    const prepare = vi.spyOn(getDb(), 'prepare')
    ollama.ping = () => new Response('', { status: 500 })
    startEmbeddingKeepWarmRunner({
      deps: { fetch: ollama.fetch, monoMs: () => clock.mono, wallMs: () => clock.wall }, // the real activity
      config: { minutes: 5, embedUrl: FAKE_URL, model: 'bge-m3' },
    })
    clock.mono = embeddingMonoMs() + HOUR
    expect(await runKeepWarmTick()).toBe('ping_failed')
    expect(isEmbeddingOutageLatched()).toBe(false)
    expect(prepare).not.toHaveBeenCalled()
    stubEmbeddings('down')
    warn.mockClear()
    await generateEmbedding('a real call that fails')
    expect(messages(warn).filter(m => m.startsWith('Embedding generation failed --'))).toHaveLength(1)
  })

  it('isBackfillInFlight is true while a backfill pass runs, and the runner skips then', async () => {
    stubEmbeddings('down')
    saveAgentMemory('keepwarmagent', 'a row for the backfill', 'warm', 'kw')
    await new Promise(r => setImmediate(r)) // the save's own embedding call failed: the row stays NULL
    const s2 = stubEmbeddings('hang')
    const pass = backfillEmbeddings()
    await Promise.resolve()
    expect(isBackfillInFlight()).toBe(true)
    startEmbeddingKeepWarmRunner({
      deps: { fetch: ollama.fetch, monoMs: () => clock.mono, wallMs: () => clock.wall },
      config: { minutes: 5, embedUrl: FAKE_URL, model: 'bge-m3' },
    })
    clock.mono = embeddingMonoMs() + HOUR
    expect(await runKeepWarmTick()).toBe('skip_inflight')
    expect(ollama.fetch).not.toHaveBeenCalled()
    s2.release()
    await pass
    expect(isBackfillInFlight()).toBe(false)
  })

  it('(p) a search does not wait for a ping in flight, and neither does the backfill', async () => {
    let releasePing!: () => void
    ollama.ping = () => new Promise<Response>(r => { releasePing = () => r(new Response('{}')) })
    startEmbeddingKeepWarmRunner({
      deps: { fetch: ollama.fetch, monoMs: () => clock.mono, wallMs: () => clock.wall, activity: () => ({ ...act }) },
      config: { minutes: 5, embedUrl: FAKE_URL, model: 'bge-m3' },
    })
    advance(HOUR)
    const tick = runKeepWarmTick()
    for (let i = 0; i < 50 && ollama.pingCalls.length === 0; i++) await new Promise(r => setImmediate(r))
    expect(ollama.pingCalls).toHaveLength(1)
    stubEmbeddings('ok')
    expect(await generateEmbedding('a search while the ping runs')).toEqual([1, 0, 0, 0])
    expect(await backfillEmbeddings()).toBeGreaterThanOrEqual(0)
    releasePing()
    expect(await tick).toBe('ping_ok')
  })
})

describe('(n) wiring (a runner that is never started is a silent no-op)', () => {
  const root = join(__dirname, '..', '..')
  const read = (rel: string) => readFileSync(join(root, rel), 'utf-8')

  it('index.ts starts the runner after initDatabase() in main() and stops it in shutdown()', () => {
    const src = read('src/index.ts')
    expect(src).toContain("import { startEmbeddingKeepWarmRunner, stopEmbeddingKeepWarmRunner } from './web/embedding-keepwarm-runner.js'")
    const shutdown = src.slice(src.indexOf('const shutdown = (): void => {'), src.indexOf('async function main()'))
    expect(shutdown).toContain('stopEmbeddingKeepWarmRunner()')
    const main = src.slice(src.indexOf('async function main()'))
    expect(main.indexOf('initDatabase()')).toBeGreaterThan(-1)
    expect(main.indexOf('startEmbeddingKeepWarmRunner()')).toBeGreaterThan(main.indexOf('initDatabase()'))
  })

  // The code without its comments: the comments name generateEmbedding on purpose.
  const code = (src: string) => src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')

  it('the runner reads the activity through db.ts and calls Ollama only through embedding-keepwarm.ts', () => {
    const src = code(read('src/web/embedding-keepwarm-runner.ts'))
    expect(src).toContain('activity: getEmbeddingActivity')
    expect(src).not.toMatch(/\bgenerateEmbedding\b|\bgetDb\b|\.prepare\(/)
    const core = code(read('src/embedding-keepwarm.ts'))
    expect(core).not.toMatch(/from '\.\/db\.js'|\bgenerateEmbedding\(/)
    expect(core).toContain("redirect: 'error'")
  })
})
