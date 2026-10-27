// Card 94f8d99f, memory program w3, node DW3: the pure parts of the embedding
// keep-warm (the decision, the /api/ps reading) and its two HTTP calls.
//
// Every call here goes to an injected fake fetch: nothing opens a socket, and
// nothing reaches a real Ollama (the suite's NO-LIVE-OLLAMA gate stays on).
import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  KEEPWARM_BACKOFF_BASE_MS, KEEPWARM_BACKOFF_MAX_MS, KEEPWARM_MAX_REMAINING_SEC, KEEPWARM_MIN_REMAINING_SEC,
  KEEPWARM_PING_TEXT, KEEPWARM_PING_TIMEOUT_MS, KEEPWARM_PS_MAX_BYTES, KEEPWARM_PS_TIMEOUT_MS,
  decideKeepWarm, evaluatePs, fetchPs, formatKeepWarmKeepAlive, inPingWindow, keepWarmBackoffMs,
  loopbackEndpoint, parseExpiresAt, pingEmbedding, psModelMatches, readCapped, remainingSeconds,
  type KeepWarmInput,
} from '../embedding-keepwarm.js'

afterEach(() => {
  vi.useRealTimers()
})

const BASE: KeepWarmInput = {
  enabled: true,
  loopback: true,
  nowMono: 10_000_000,
  lastDoneMono: 10_000_000 - 5 * 60_000,
  inFlight: 0,
  backfillInFlight: false,
  outageLatched: false,
  backoffUntilMono: null,
  intervalMs: 5 * 60_000,
}

describe('decideKeepWarm', () => {
  it('probes after exactly the interval without a call', () => {
    expect(decideKeepWarm(BASE)).toEqual({ action: 'probe' })
    expect(decideKeepWarm({ ...BASE, lastDoneMono: null })).toEqual({ action: 'probe' })
  })

  it('skips while the last call is younger than the interval (1 ms short)', () => {
    expect(decideKeepWarm({ ...BASE, lastDoneMono: BASE.nowMono - 5 * 60_000 + 1 })).toEqual({ action: 'skip', reason: 'recent' })
  })

  it.each([
    ['off', { enabled: false }],
    ['not_loopback', { loopback: false }],
    ['inflight', { inFlight: 1 }],
    ['inflight', { backfillInFlight: true }],
    ['outage', { outageLatched: true }],
    ['backoff', { backoffUntilMono: BASE.nowMono + 1 }],
  ] as const)('skips with %s (%j)', (reason, patch) => {
    expect(decideKeepWarm({ ...BASE, ...patch })).toEqual({ action: 'skip', reason })
  })

  it('a backoff that has ended does not hold', () => {
    expect(decideKeepWarm({ ...BASE, backoffUntilMono: BASE.nowMono })).toEqual({ action: 'probe' })
  })

  it('off and not-loopback win over everything, then in-flight, outage, backoff, recent', () => {
    const all: KeepWarmInput = {
      ...BASE, enabled: false, loopback: false, inFlight: 2, outageLatched: true,
      backoffUntilMono: BASE.nowMono + 1, lastDoneMono: BASE.nowMono,
    }
    expect(decideKeepWarm(all)).toEqual({ action: 'skip', reason: 'off' })
    expect(decideKeepWarm({ ...all, enabled: true })).toEqual({ action: 'skip', reason: 'not_loopback' })
    expect(decideKeepWarm({ ...all, enabled: true, loopback: true })).toEqual({ action: 'skip', reason: 'inflight' })
    expect(decideKeepWarm({ ...all, enabled: true, loopback: true, inFlight: 0 })).toEqual({ action: 'skip', reason: 'outage' })
    expect(decideKeepWarm({ ...all, enabled: true, loopback: true, inFlight: 0, outageLatched: false })).toEqual({ action: 'skip', reason: 'backoff' })
    expect(decideKeepWarm({ ...all, enabled: true, loopback: true, inFlight: 0, outageLatched: false, backoffUntilMono: null }))
      .toEqual({ action: 'skip', reason: 'recent' })
  })
})

describe('keepWarmBackoffMs', () => {
  it('15 min doubling to a 4 h cap', () => {
    expect([1, 2, 3, 4, 5, 6, 7, 50].map(keepWarmBackoffMs)).toEqual(
      [15, 30, 60, 120, 240, 240, 240, 240].map(m => m * 60_000),
    )
    expect(KEEPWARM_BACKOFF_BASE_MS).toBe(15 * 60_000)
    expect(KEEPWARM_BACKOFF_MAX_MS).toBe(4 * 3_600_000)
  })
})

describe('loopbackEndpoint', () => {
  it.each([
    ['http://127.0.0.1:11434', 'http://127.0.0.1:11434/api/ps'],
    ['http://localhost:11434', 'http://localhost:11434/api/ps'],
    ['http://LOCALHOST:11434', 'http://localhost:11434/api/ps'],
    ['http://[::1]:11434', 'http://[::1]:11434/api/ps'],
    ['https://127.0.0.1', 'https://127.0.0.1/api/ps'],
  ])('%s is loopback', (base, want) => {
    expect(loopbackEndpoint(base, '/api/ps')).toBe(want)
  })

  it.each([
    'http://192.0.2.1:11434',
    'http://example.com:11434',
    'http://127.0.0.1:11434@evil.example',
    'http://10.0.0.5:11434',
    'ftp://127.0.0.1:11434',
    'file:///tmp/x',
    'not a url',
    '',
  ])('%j is refused', (base) => {
    expect(loopbackEndpoint(base, '/api/ps')).toBeNull()
  })

  it('builds the URL the way generateEmbedding does (EMBED_URL + path)', () => {
    expect(loopbackEndpoint('http://127.0.0.1:11434/ollama', '/api/embeddings')).toBe('http://127.0.0.1:11434/ollama/api/embeddings')
  })
})

describe('psModelMatches', () => {
  it('an untagged EMBED_MODEL matches itself and <name>:latest', () => {
    expect(psModelMatches('bge-m3:latest', 'bge-m3')).toBe(true)
    expect(psModelMatches('bge-m3', 'bge-m3')).toBe(true)
  })

  it('a tagged EMBED_MODEL matches only exactly', () => {
    expect(psModelMatches('bge-m3:latest', 'bge-m3:latest')).toBe(true)
    expect(psModelMatches('bge-m3:latest', 'bge-m3:567m')).toBe(false)
    expect(psModelMatches('bge-m3:567m', 'bge-m3:567m')).toBe(true)
  })

  it('another tag of an untagged name, another model, a prefix, a non-string: no match', () => {
    expect(psModelMatches('bge-m3:567m', 'bge-m3')).toBe(false)
    expect(psModelMatches('nomic-embed-text:latest', 'bge-m3')).toBe(false)
    expect(psModelMatches('bge-m3-extra:latest', 'bge-m3')).toBe(false)
    expect(psModelMatches('BGE-M3:latest', 'bge-m3')).toBe(false)
    expect(psModelMatches(undefined, 'bge-m3')).toBe(false)
    expect(psModelMatches(42, 'bge-m3')).toBe(false)
    expect(psModelMatches('', '')).toBe(false)
  })

  it('a tag is read from the last path segment only (a registry host with a port is not a tag)', () => {
    expect(psModelMatches('localhost:5000/lib/bge-m3:latest', 'localhost:5000/lib/bge-m3')).toBe(true)
    expect(psModelMatches('hf.co/org/model:Q4', 'hf.co/org/model:Q4')).toBe(true)
  })
})

describe('parseExpiresAt', () => {
  it('reads Ollama\'s RFC 3339 with nanoseconds and an offset, truncated to ms', () => {
    expect(parseExpiresAt('2026-10-19T18:06:46.123456789+02:00')).toBe(Date.UTC(2026, 9, 19, 16, 6, 46, 123))
    expect(parseExpiresAt('2026-10-19T16:06:46.999999999Z')).toBe(Date.UTC(2026, 9, 19, 16, 6, 46, 999))
    expect(parseExpiresAt('2026-10-19T16:06:46Z')).toBe(Date.UTC(2026, 9, 19, 16, 6, 46, 0))
    expect(parseExpiresAt('2026-10-19T10:36:46.5-05:30')).toBe(Date.UTC(2026, 9, 19, 16, 6, 46, 500))
  })

  it.each([
    undefined, null, 1792426006123, '', 'soon', '2026-10-19', '2026-10-19 16:06:46Z', '2026-13-19T16:06:46Z',
    '2026-10-19T24:00:00Z', '2026-10-19T16:60:00Z', '2026-10-19T16:06:46.1234567890Z', '2026-10-19T16:06:46+2:00',
    '2026-10-19T16:06:46+24:00', `2026-10-19T16:06:46.${'1'.repeat(80)}Z`, '0001-01-01T00:00:00Z ',
  ])('refuses %j', (v) => {
    expect(parseExpiresAt(v)).toBeNull()
  })
})

describe('remainingSeconds and the window', () => {
  it('rounds down, so the ping can never ask for more than is left', () => {
    expect(remainingSeconds(10_999, 0)).toBe(10)
    expect(remainingSeconds(10_000, 0)).toBe(10)
    expect(remainingSeconds(9_999, 0)).toBe(9)
    expect(remainingSeconds(-1, 0)).toBe(-1)
  })

  it('holds more than 60 s and at most 30 days', () => {
    expect(inPingWindow(KEEPWARM_MIN_REMAINING_SEC)).toBe(false)
    expect(inPingWindow(KEEPWARM_MIN_REMAINING_SEC + 1)).toBe(true)
    expect(inPingWindow(KEEPWARM_MAX_REMAINING_SEC)).toBe(true)
    expect(inPingWindow(KEEPWARM_MAX_REMAINING_SEC + 1)).toBe(false)
    expect(inPingWindow(-5)).toBe(false)
    expect(inPingWindow(NaN)).toBe(false)
    expect(KEEPWARM_MIN_REMAINING_SEC).toBe(60)
    expect(KEEPWARM_MAX_REMAINING_SEC).toBe(30 * 86_400)
  })
})

describe('evaluatePs', () => {
  const NOW = Date.UTC(2026, 9, 18, 18, 0, 0)
  const iso = (ms: number) => new Date(ms).toISOString()
  const ps = (models: unknown) => JSON.stringify({ models })

  it('a loaded model with a day left: ping with the seconds left, rounded down', () => {
    const v = evaluatePs(ps([{ name: 'bge-m3:latest', model: 'bge-m3:latest', expires_at: iso(NOW + 86_399_999) }]), 'bge-m3', NOW)
    expect(v).toEqual({ kind: 'ping', expiresMs: NOW + 86_399_999, remainingSec: 86_399 })
  })

  it('the model is found by its `model` field too, and among others', () => {
    const v = evaluatePs(ps([
      { name: 'gemma3:4b', model: 'gemma3:4b', expires_at: iso(NOW + 600_000) },
      { name: 'x', model: 'bge-m3:latest', expires_at: iso(NOW + 600_000) },
    ]), 'bge-m3', NOW)
    expect(v).toEqual({ kind: 'ping', expiresMs: NOW + 600_000, remainingSec: 600 })
  })

  it('not in the list (or an empty list): not_loaded', () => {
    expect(evaluatePs(ps([]), 'bge-m3', NOW)).toEqual({ kind: 'not_loaded' })
    expect(evaluatePs(ps([{ name: 'gemma3:4b', expires_at: iso(NOW + 600_000) }]), 'bge-m3', NOW)).toEqual({ kind: 'not_loaded' })
    expect(evaluatePs(ps([null, 7, 'bge-m3:latest']), 'bge-m3', NOW)).toEqual({ kind: 'not_loaded' })
  })

  it.each([
    ['60 s left', NOW + 60_999, 60],
    ['already expired', NOW - 5_000, -5],
    ['more than 30 days (keep_alive -1)', Date.UTC(2318, 1, 23), Math.floor((Date.UTC(2318, 1, 23) - NOW) / 1000)],
  ])('%s: window, no ping', (_label, expires, remaining) => {
    expect(evaluatePs(ps([{ name: 'bge-m3:latest', expires_at: iso(expires) }]), 'bge-m3', NOW)).toEqual({ kind: 'window', remainingSec: remaining })
  })

  it('a missing or unreadable expires_at: window, no ping', () => {
    expect(evaluatePs(ps([{ name: 'bge-m3:latest' }]), 'bge-m3', NOW)).toEqual({ kind: 'window', remainingSec: null })
    expect(evaluatePs(ps([{ name: 'bge-m3:latest', expires_at: 'tomorrow' }]), 'bge-m3', NOW)).toEqual({ kind: 'window', remainingSec: null })
    expect(evaluatePs(ps([{ name: 'bge-m3:latest', expires_at: NOW + 600_000 }]), 'bge-m3', NOW)).toEqual({ kind: 'window', remainingSec: null })
  })

  it.each(['', 'not json', '[]', 'null', '42', '{"models":{}}', '{"models":"bge-m3"}', '{}'])('%j is not an Ollama answer: bad', (body) => {
    expect(evaluatePs(body, 'bge-m3', NOW)).toEqual({ kind: 'bad' })
  })
})

describe('formatKeepWarmKeepAlive', () => {
  it('the default form is the duration string the live install already sends ("<n>s")', () => {
    expect(formatKeepWarmKeepAlive(3600)).toBe('3600s')
  })

  it('the number form, for when the KP probe prefers it', () => {
    expect(formatKeepWarmKeepAlive(3600, 'number')).toBe(3600)
  })
})

describe('readCapped', () => {
  it('reads an answer up to the cap, and refuses one past it (declared or streamed)', async () => {
    expect(await readCapped(new Response('a'.repeat(100)), 100)).toBe('a'.repeat(100))
    expect(await readCapped(new Response('a'.repeat(101)), 100)).toBeNull()
    const declared = new Response('small', { headers: { 'content-length': '1000000' } })
    expect(await readCapped(declared, 100)).toBeNull()
    const stream = new ReadableStream<Uint8Array>({
      pull(c) { c.enqueue(new Uint8Array(64)) }, // never ends on its own
    })
    expect(await readCapped(new Response(stream), 1000)).toBeNull()
  })

  it('counts bytes, not characters', async () => {
    expect(await readCapped(new Response('é'.repeat(50)), 100)).toBe('é'.repeat(50))
    expect(await readCapped(new Response('é'.repeat(51)), 100)).toBeNull()
  })
})

type Call = { url: string; init: RequestInit }
function recorder(answer: (url: string, init: RequestInit) => Promise<Response>) {
  const calls: Call[] = []
  const fn = vi.fn(async (url: string, init: RequestInit) => {
    calls.push({ url, init })
    return answer(url, init)
  })
  return { fn, calls }
}

/** A fetch that never answers unless its signal aborts it. */
function hanging() {
  return (_url: string, init: RequestInit) => new Promise<Response>((_resolve, reject) => {
    init.signal?.addEventListener('abort', () => reject(new Error('aborted')), { once: true })
  })
}

describe('fetchPs', () => {
  const URL_PS = 'http://127.0.0.1:45999/api/ps'

  it('GET, no redirects followed, the body back', async () => {
    const { fn, calls } = recorder(async () => new Response('{"models":[]}'))
    expect(await fetchPs(fn, URL_PS)).toEqual({ ok: true, body: '{"models":[]}' })
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe(URL_PS)
    expect(calls[0].init.method).toBe('GET')
    expect(calls[0].init.redirect).toBe('error')
    expect(calls[0].init.body).toBeUndefined()
  })

  it('a non-2xx answer, a network error, an oversize answer: failures with a fixed word', async () => {
    expect(await fetchPs(async () => new Response('x', { status: 500 }), URL_PS)).toEqual({ ok: false, error: 'status', status: 500 })
    expect(await fetchPs(async () => { throw new Error('ECONNREFUSED 127.0.0.1:45999') }, URL_PS)).toEqual({ ok: false, error: 'network' })
    expect(await fetchPs(async () => new Response('a'.repeat(KEEPWARM_PS_MAX_BYTES + 1)), URL_PS)).toEqual({ ok: false, error: 'oversize' })
    expect((await fetchPs(async () => new Response('a'.repeat(KEEPWARM_PS_MAX_BYTES)), URL_PS)).ok).toBe(true)
  })

  it('times out after 2 s', async () => {
    vi.useFakeTimers()
    const p = fetchPs(hanging(), URL_PS)
    await vi.advanceTimersByTimeAsync(KEEPWARM_PS_TIMEOUT_MS - 1)
    let settled = false
    void p.then(() => { settled = true })
    await Promise.resolve()
    expect(settled).toBe(false)
    await vi.advanceTimersByTimeAsync(1)
    expect(await p).toEqual({ ok: false, error: 'timeout' })
    expect(KEEPWARM_PS_TIMEOUT_MS).toBe(2_000)
    expect(vi.getTimerCount()).toBe(0)
  })

  it('an outside abort (the runner stopping) ends the call as a network failure, and clears its timer', async () => {
    vi.useFakeTimers()
    const ac = new AbortController()
    const p = fetchPs(hanging(), URL_PS, ac.signal)
    ac.abort()
    expect(await p).toEqual({ ok: false, error: 'network' })
    expect(vi.getTimerCount()).toBe(0)
  })
})

describe('pingEmbedding', () => {
  const URL_EMB = 'http://127.0.0.1:45999/api/embeddings'

  it('exactly one POST with the model, the constant text and the seconds left as keep_alive; nothing else in the body', async () => {
    const { fn, calls } = recorder(async () => new Response(JSON.stringify({ embedding: [0.1, 0.2] })))
    expect(await pingEmbedding(fn, URL_EMB, 'bge-m3', 4321)).toEqual({ ok: true })
    expect(calls).toHaveLength(1)
    expect(calls[0].url).toBe(URL_EMB)
    expect(calls[0].init.method).toBe('POST')
    expect(calls[0].init.redirect).toBe('error')
    expect(JSON.parse(String(calls[0].init.body))).toEqual({ model: 'bge-m3', prompt: KEEPWARM_PING_TEXT, keep_alive: '4321s' })
    expect(KEEPWARM_PING_TEXT).toBe('keepwarm')
  })

  it('a non-2xx answer and a network error are failures', async () => {
    expect(await pingEmbedding(async () => new Response('{"error":"model not found"}', { status: 404 }), URL_EMB, 'bge-m3', 100))
      .toEqual({ ok: false, error: 'status', status: 404 })
    expect(await pingEmbedding(async () => { throw new TypeError('fetch failed') }, URL_EMB, 'bge-m3', 100))
      .toEqual({ ok: false, error: 'network' })
  })

  it('times out after 5 s', async () => {
    vi.useFakeTimers()
    const p = pingEmbedding(hanging(), URL_EMB, 'bge-m3', 100)
    await vi.advanceTimersByTimeAsync(KEEPWARM_PING_TIMEOUT_MS)
    expect(await p).toEqual({ ok: false, error: 'timeout' })
    expect(KEEPWARM_PING_TIMEOUT_MS).toBe(5_000)
  })
})
