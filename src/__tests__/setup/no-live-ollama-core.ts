// Pure decision logic of the no-live-Ollama suite gate (no-live-ollama.ts).
// Kept apart from the setup file so it can be tested without opening a socket.

/** Ollama's default API port. Any host on it is treated as a real Ollama. */
export const OLLAMA_DEFAULT_PORT = 11434

export interface Endpoint {
  host: string
  port: number
}

export function normalizeHost(host: string): string {
  let h = host.trim().toLowerCase()
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1)
  if (h.startsWith('::ffff:')) h = h.slice('::ffff:'.length)
  if (h.endsWith('.')) h = h.slice(0, -1)
  return h
}

export function isLoopbackHost(host: string): boolean {
  const h = normalizeHost(host)
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0' || h === '::'
    || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
}

/** host:port of an Ollama base URL, or null when it is empty or does not parse. */
export function endpointOf(url: string | undefined): Endpoint | null {
  if (!url || !url.trim()) return null
  try {
    const u = new URL(url.trim())
    if (u.protocol !== 'http:' && u.protocol !== 'https:') return null
    const port = u.port ? Number(u.port) : (u.protocol === 'https:' ? 443 : 80)
    return { host: normalizeHost(u.hostname), port }
  } catch {
    return null
  }
}

/** The EMBED_URL / OLLAMA_URL values of a .env text (KEY=value, optionally quoted). */
export function ollamaUrlsFromDotenv(text: string): string[] {
  const out: string[] = []
  for (const line of text.split(/\r?\n/)) {
    const m = /^\s*(?:export\s+)?(EMBED_URL|OLLAMA_URL)\s*=\s*(.*?)\s*$/.exec(line)
    if (!m) continue
    let v = m[2]
    if (v.length >= 2 && ((v.startsWith('"') && v.endsWith('"')) || (v.startsWith("'") && v.endsWith("'")))) v = v.slice(1, -1)
    if (v) out.push(v)
  }
  return out
}

/**
 * Where a net.Socket#connect call is headed, from its arguments (the same
 * shapes net.connect normalises: an options object, possibly wrapped in an
 * array, or port[, host]). null = a pipe / unix socket or nothing to judge.
 */
export function connectTarget(args: unknown[]): Endpoint | null {
  let first = args[0]
  if (Array.isArray(first)) first = first[0]
  if (first && typeof first === 'object') {
    const o = first as { path?: unknown; host?: unknown; port?: unknown }
    if (typeof o.path === 'string') return null
    const port = Number(o.port)
    return Number.isInteger(port) ? { host: typeof o.host === 'string' ? o.host : 'localhost', port } : null
  }
  if (typeof first === 'string' && !/^\d+$/.test(first)) return null
  const port = Number(first)
  return Number.isInteger(port) ? { host: typeof args[1] === 'string' ? args[1] : 'localhost', port } : null
}

/** The EMBED_URL / OLLAMA_URL values of a store/config-overrides.json text (config.ts reads it first). */
export function ollamaUrlsFromOverrides(text: string): string[] {
  try {
    const o = JSON.parse(text) as Record<string, unknown>
    return ['EMBED_URL', 'OLLAMA_URL'].map(k => o?.[k]).filter((v): v is string => typeof v === 'string' && v.length > 0)
  } catch {
    return []
  }
}

/** The URL a fetch() call is headed to, or null if it cannot be read. */
export function fetchUrl(input: unknown): URL | null {
  try {
    if (typeof input === 'string') return new URL(input)
    if (input instanceof URL) return input
    if (input && typeof input === 'object' && typeof (input as { url?: unknown }).url === 'string') return new URL((input as { url: string }).url)
  } catch { /* relative or malformed: not ours to judge */ }
  return null
}

/**
 * An embedding request to a real Ollama (POST /api/embeddings or /api/embed
 * on a live endpoint): the one call the code under test makes on its own, from
 * the save path and the backfill. The gate answers it "backend down" without a
 * socket; everything else headed to an Ollama reaches the socket gate.
 */
export function isOllamaEmbeddingCall(url: URL, configured: readonly Endpoint[]): boolean {
  const ep = endpointOf(url.href)
  if (!ep || !isLiveOllamaTarget(ep, configured)) return false
  const path = url.pathname.replace(/\/+$/, '')
  return path.endsWith('/api/embeddings') || path.endsWith('/api/embed')
}

/**
 * Is host:port a real Ollama? Yes for the default port on any host, and for
 * every configured endpoint (a loopback one matches any loopback spelling).
 */
export function isLiveOllamaTarget(target: Endpoint, configured: readonly Endpoint[]): boolean {
  if (target.port === OLLAMA_DEFAULT_PORT) return true
  const h = normalizeHost(target.host)
  return configured.some(e => e.port === target.port
    && (e.host === h || (isLoopbackHost(e.host) && isLoopbackHost(h))))
}
