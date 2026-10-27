// Keep-warm of the embedding model (card 94f8d99f, memory program w3, node DW3).
//
// Measured 2026-10-17 19:29: after ~79 idle minutes the first embedding call
// took 654 ms instead of the usual 84-137 ms, with the model still loaded (no
// reload), and the recall hook's hybrid budget is ~1 s. The keep_alive "24h"
// of w1 keeps the model LOADED; this keeps it WARM: after EMBED_KEEPWARM_MINUTES
// without any embedding call the dashboard sends one tiny embedding request.
//
// What it must never do (Brainy's decision, 2026-10-18, blueprint Q1-Q4):
//  - load a model: it pings only a model that GET /api/ps lists as loaded;
//  - extend the 24 h window: the ping's keep_alive is the time the model has
//    LEFT (expires_at - now, rounded down), so the window still counts from the
//    last real use (Brainy 2433);
//  - call anything while Ollama is down: not while the generateEmbedding
//    outage latch is set, not during its own backoff (15 min doubling to 4 h);
//  - reach another host: loopback EMBED_URL only, no redirects followed.
//
// This file holds the pure parts (the decision, the /api/ps reading) and the
// two HTTP calls with an injected fetch; the timers and the state live in
// web/embedding-keepwarm-runner.ts.

/** Tick of the runner, and the delay of its first tick after boot. */
export const KEEPWARM_TICK_MS = 60_000
export const KEEPWARM_FIRST_TICK_MS = 120_000
/** GET /api/ps: timeout and the largest answer read. */
export const KEEPWARM_PS_TIMEOUT_MS = 2_000
export const KEEPWARM_PS_MAX_BYTES = 64 * 1024
/** POST /api/embeddings (the ping): timeout. */
export const KEEPWARM_PING_TIMEOUT_MS = 5_000
/** A model with this little time left (or less) is let go, not pinged. */
export const KEEPWARM_MIN_REMAINING_SEC = 60
/** More than this left is not a 24 h window (keep_alive -1 shows as a far-future date): not pinged. */
export const KEEPWARM_MAX_REMAINING_SEC = 30 * 86_400
/** Backoff after a failed /api/ps or ping: 15 min, doubling, capped at 4 h. */
export const KEEPWARM_BACKOFF_BASE_MS = 15 * 60_000
export const KEEPWARM_BACKOFF_MAX_MS = 4 * 3_600_000
/** The ping's text: a constant, never user data. */
export const KEEPWARM_PING_TEXT = 'keepwarm'

/**
 * How the remaining seconds go into keep_alive. Ollama takes both a duration
 * string and a number of seconds; the string form is the one the live install
 * already sends ("24h"). The KP probe (2026-10-18, live Ollama, near the start
 * of the 24 h window) measured that neither form moves expires_at later
 * (-0.6 s number, -0.9 s string); the middle of the window was not measured.
 */
export type KeepAliveForm = 'seconds-string' | 'number'
export const KEEPWARM_KEEP_ALIVE_FORM: KeepAliveForm = 'seconds-string'

export function formatKeepWarmKeepAlive(sec: number, form: KeepAliveForm = KEEPWARM_KEEP_ALIVE_FORM): string | number {
  return form === 'number' ? sec : `${sec}s`
}

export type KeepWarmSkip = 'off' | 'not_loopback' | 'inflight' | 'outage' | 'backoff' | 'recent'

export interface KeepWarmInput {
  enabled: boolean
  loopback: boolean
  /** Monotonic clock (ms). */
  nowMono: number
  /** Last finished embedding call, the keep-warm's own calls included (monotonic ms); null = none yet. */
  lastDoneMono: number | null
  /** generateEmbedding calls running now. */
  inFlight: number
  backfillInFlight: boolean
  /** generateEmbedding's outage latch (the first failure WARNed, no success since). */
  outageLatched: boolean
  /** Own backoff end (monotonic ms); null = no backoff. */
  backoffUntilMono: number | null
  /** Idle time before a ping (EMBED_KEEPWARM_MINUTES in ms). */
  intervalMs: number
}

export type KeepWarmDecision = { action: 'skip'; reason: KeepWarmSkip } | { action: 'probe' }

/**
 * Pure: may this tick ask Ollama anything? Every skip makes no call at all,
 * not even GET /api/ps. 'probe' means: read /api/ps, then evaluatePs decides
 * whether the ping goes out.
 */
export function decideKeepWarm(i: KeepWarmInput): KeepWarmDecision {
  if (!i.enabled) return { action: 'skip', reason: 'off' }
  if (!i.loopback) return { action: 'skip', reason: 'not_loopback' }
  if (i.inFlight > 0 || i.backfillInFlight) return { action: 'skip', reason: 'inflight' }
  if (i.outageLatched) return { action: 'skip', reason: 'outage' }
  if (i.backoffUntilMono !== null && i.nowMono < i.backoffUntilMono) return { action: 'skip', reason: 'backoff' }
  if (i.lastDoneMono !== null && i.nowMono - i.lastDoneMono < i.intervalMs) return { action: 'skip', reason: 'recent' }
  return { action: 'probe' }
}

/** Pure: the backoff after the `fails`-th failure in a row. */
export function keepWarmBackoffMs(fails: number): number {
  return Math.min(KEEPWARM_BACKOFF_BASE_MS * 2 ** Math.max(0, fails - 1), KEEPWARM_BACKOFF_MAX_MS)
}

/**
 * The URL of `path` under EMBED_URL, built the way generateEmbedding builds its
 * own (`${EMBED_URL}/api/embeddings`), or null when its host is not loopback
 * (127.0.0.1, ::1, localhost after URL parsing) or it is not http(s). The host
 * is judged on the FINAL URL, the one that is fetched.
 */
export function loopbackEndpoint(embedUrl: string, path: string): string | null {
  let u: URL
  try {
    u = new URL(`${embedUrl}${path}`)
  } catch {
    return null
  }
  if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
  if (u.hostname !== '127.0.0.1' && u.hostname !== '[::1]' && u.hostname !== 'localhost') return null
  return u.href
}

/**
 * Pure: does a /api/ps entry name the configured model? An untagged
 * EMBED_MODEL ("bge-m3") also matches "<name>:latest" (that is how /api/ps
 * lists it); a tagged one matches exactly.
 */
export function psModelMatches(psName: unknown, configured: string): boolean {
  if (typeof psName !== 'string' || configured === '') return false
  const tagged = configured.slice(configured.lastIndexOf('/') + 1).includes(':')
  return psName === configured || (!tagged && psName === `${configured}:latest`)
}

const RFC3339 = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?(Z|[+-]\d{2}:\d{2})$/

/**
 * Pure: Ollama's expires_at (RFC 3339, nanoseconds, e.g.
 * "2026-10-19T18:06:46.123456789+02:00") as epoch ms, truncated (never later
 * than the real instant), or null when it is anything else.
 */
export function parseExpiresAt(value: unknown): number | null {
  if (typeof value !== 'string' || value.length > 64) return null
  const m = RFC3339.exec(value)
  if (!m) return null
  const [, y, mo, d, h, mi, s, frac, zone] = m
  const month = Number(mo), day = Number(d), hour = Number(h), min = Number(mi), sec = Number(s)
  if (month < 1 || month > 12 || day < 1 || day > 31 || hour > 23 || min > 59 || sec > 59) return null
  let offsetMin = 0
  if (zone !== 'Z') {
    const oh = Number(zone.slice(1, 3)), om = Number(zone.slice(4, 6))
    if (oh > 23 || om > 59) return null
    offsetMin = (zone[0] === '-' ? -1 : 1) * (oh * 60 + om)
  }
  const ms = frac ? Number(frac.slice(0, 3).padEnd(3, '0')) : 0
  const utc = Date.UTC(Number(y), month - 1, day, hour, min, sec, ms) - offsetMin * 60_000
  return Number.isFinite(utc) ? utc : null
}

/** Pure: whole seconds left until `expiresMs`, rounded down. */
export function remainingSeconds(expiresMs: number, nowWallMs: number): number {
  return Math.floor((expiresMs - nowWallMs) / 1000)
}

/** Pure: is `remainingSec` a window the ping may hold (more than 60 s, at most 30 days)? */
export function inPingWindow(remainingSec: number): boolean {
  return Number.isFinite(remainingSec) && remainingSec > KEEPWARM_MIN_REMAINING_SEC && remainingSec <= KEEPWARM_MAX_REMAINING_SEC
}

export type PsVerdict =
  | { kind: 'bad' }
  | { kind: 'not_loaded' }
  | { kind: 'window'; remainingSec: number | null }
  | { kind: 'ping'; expiresMs: number; remainingSec: number }

/**
 * Pure: read a /api/ps answer for `model`. 'bad' = not the shape Ollama sends
 * (counts as a failed probe); 'not_loaded' = the model is not in the list;
 * 'window' = loaded, but the time left is not one to hold (missing or
 * unreadable expires_at, 60 s or less, more than 30 days); 'ping' otherwise.
 */
export function evaluatePs(bodyText: string, model: string, nowWallMs: number): PsVerdict {
  let data: unknown
  try {
    data = JSON.parse(bodyText)
  } catch {
    return { kind: 'bad' }
  }
  const models = (data as { models?: unknown } | null)?.models
  if (!data || typeof data !== 'object' || !Array.isArray(models)) return { kind: 'bad' }
  const entry = models.find(e =>
    e !== null && typeof e === 'object'
    && (psModelMatches((e as { name?: unknown }).name, model) || psModelMatches((e as { model?: unknown }).model, model)),
  ) as { expires_at?: unknown } | undefined
  if (!entry) return { kind: 'not_loaded' }
  const expiresMs = parseExpiresAt(entry.expires_at)
  if (expiresMs === null) return { kind: 'window', remainingSec: null }
  const remainingSec = remainingSeconds(expiresMs, nowWallMs)
  if (!inPingWindow(remainingSec)) return { kind: 'window', remainingSec }
  return { kind: 'ping', expiresMs, remainingSec }
}

export type KeepWarmFetch = (url: string, init: RequestInit) => Promise<Response>

/** Why a call failed, as a fixed word: nothing from the answer goes into a log line. */
export type KeepWarmCallError = 'timeout' | 'network' | 'status' | 'oversize'

export type CallResult<T> = ({ ok: true } & T) | { ok: false; error: KeepWarmCallError; status?: number }

/**
 * Run `fetch` with a timeout made of a plain (unref'ed) setTimeout, so a test
 * clock drives it, and with an outside abort (the runner's stop). Redirects are
 * refused: the call goes to the loopback URL it was given or nowhere.
 */
async function callWithTimeout<T>(
  doFetch: KeepWarmFetch,
  url: string,
  init: RequestInit,
  timeoutMs: number,
  outer: AbortSignal | undefined,
  read: (resp: Response) => Promise<CallResult<T>>,
): Promise<CallResult<T>> {
  const ac = new AbortController()
  let timedOut = false
  const timer = setTimeout(() => { timedOut = true; ac.abort() }, timeoutMs)
  timer.unref?.()
  const onOuter = () => ac.abort()
  if (outer) {
    if (outer.aborted) ac.abort()
    else outer.addEventListener('abort', onOuter, { once: true })
  }
  try {
    const resp = await doFetch(url, { ...init, redirect: 'error', signal: ac.signal })
    if (!resp.ok) {
      await resp.body?.cancel().catch(() => undefined)
      return { ok: false, error: 'status', status: resp.status }
    }
    return await read(resp)
  } catch {
    return { ok: false, error: timedOut ? 'timeout' : 'network' }
  } finally {
    clearTimeout(timer)
    outer?.removeEventListener('abort', onOuter)
  }
}

/** The answer's text, or null past `maxBytes` (read stops there). */
export async function readCapped(resp: Response, maxBytes: number): Promise<string | null> {
  const declared = Number(resp.headers?.get?.('content-length') ?? NaN)
  if (Number.isFinite(declared) && declared > maxBytes) {
    await resp.body?.cancel().catch(() => undefined)
    return null
  }
  if (!resp.body) {
    const text = await resp.text()
    return Buffer.byteLength(text, 'utf8') > maxBytes ? null : text
  }
  const reader = resp.body.getReader()
  const chunks: Uint8Array[] = []
  let total = 0
  for (;;) {
    const { done, value } = await reader.read()
    if (done) break
    total += value.byteLength
    if (total > maxBytes) {
      await reader.cancel().catch(() => undefined)
      return null
    }
    chunks.push(value)
  }
  return Buffer.concat(chunks).toString('utf8')
}

/** GET /api/ps, size- and time-capped. */
export function fetchPs(
  doFetch: KeepWarmFetch,
  psUrl: string,
  outer?: AbortSignal,
): Promise<CallResult<{ body: string }>> {
  return callWithTimeout<{ body: string }>(doFetch, psUrl, { method: 'GET' }, KEEPWARM_PS_TIMEOUT_MS, outer, async (resp) => {
    const body = await readCapped(resp, KEEPWARM_PS_MAX_BYTES)
    return body === null ? { ok: false, error: 'oversize' } : { ok: true, body }
  })
}

/**
 * The ping: exactly one POST /api/embeddings with the constant text and the
 * remaining seconds as keep_alive. Its vector is not read (the answer is
 * dropped), and it goes around generateEmbedding on purpose: it must not touch
 * the outage latch, the EMBED_KEEP_ALIVE (24 h) or the activity a real call
 * leaves.
 */
export function pingEmbedding(
  doFetch: KeepWarmFetch,
  embeddingsUrl: string,
  model: string,
  keepAliveSec: number,
  outer?: AbortSignal,
): Promise<CallResult<Record<never, never>>> {
  const body = JSON.stringify({ model, prompt: KEEPWARM_PING_TEXT, keep_alive: formatKeepWarmKeepAlive(keepAliveSec) })
  return callWithTimeout<Record<never, never>>(
    doFetch,
    embeddingsUrl,
    { method: 'POST', headers: { 'Content-Type': 'application/json' }, body },
    KEEPWARM_PING_TIMEOUT_MS,
    outer,
    async (resp) => {
      await resp.body?.cancel().catch(() => undefined)
      return { ok: true }
    },
  )
}
