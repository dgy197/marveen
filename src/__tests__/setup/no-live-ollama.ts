// GLOBAL SUITE GATE: no test may reach a real Ollama.
//
// Measured 2026-10-17 (card d4e7fea7, finding MT1): suite runs on the fleet host
// reached the LIVE Ollama at 127.0.0.1:11434 -- bursts of POST /api/embeddings in
// its log while the suites ran. Nothing in the suite noticed, and nothing could:
// the embedding call swallows its own failure (generateEmbedding returns null,
// the save path's fire-and-forget catches), so a test passes the same whether
// the call died on a closed port or was answered by the operator's live model.
// The sandbox does not help either: it lets loopback through. Measured with the
// strict gate below alone: 91 tests in 15 memory test files reach the embedding
// endpoint through the code under test (saveAgentMemory, hybridSearch, backfill).
//
// "A real Ollama" is port 11434 on any host, plus the host:port of EMBED_URL /
// OLLAMA_URL as config.ts resolves them at LAUNCH (store/config-overrides.json,
// the checkout's .env, and the process env for good measure). Values a test sets
// later are not blocked, so a test that points the code at its own fake server
// keeps working. Two layers:
//
//  1. The embedding call (fetch to /api/embeddings or /api/embed there) is
//     answered "backend down" on the spot, without a socket. That is the
//     condition every one of those 91 tests was written for (no Ollama, as in
//     CI), and it means no test can ever get a real vector. Tests that need a
//     vector stub fetch (vi.stubGlobal) as before; a stub replaces this layer.
//  2. Every other connect to a real Ollama -- another path, another client, a
//     test that brought the real fetch back -- is refused before the connect,
//     recorded, and FAILS the test that made it, in afterEach, with the target
//     in the message (an attempt after a file's last test fails the file in
//     afterAll). The refusal alone would be swallowed by the same catch blocks;
//     the record is what makes it loud.
//  3. Spawned NODE children (MN6): the two layers above live in this worker
//     only. The setup appends `--require no-live-ollama-child.cjs` to
//     process.env.NODE_OPTIONS and passes the launch-time endpoints along, so
//     every node process a test spawns (and its node children) refuses the
//     same targets before the connect, and records the attempt in a file this
//     setup reads after every test -- the test that spawned it fails.
//
// LIMITS, named so nobody reads more into this than it does: a child that is
// NOT node (python3, curl, bash /dev/tcp, a compiled binary) is not covered;
// neither is a node child spawned with a scrubbed env (env: {...} without
// NODE_OPTIONS, `env -i`, the credit-gate headless env) or one that overrides
// NODE_OPTIONS. Those can still reach a real Ollama unnoticed; the sandbox
// (loopback allowed) does not stop them either.
import net from 'node:net'
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { afterAll, afterEach, expect } from 'vitest'
import {
  connectTarget, endpointOf, fetchUrl, isLiveOllamaTarget, isOllamaEmbeddingCall,
  ollamaUrlsFromDotenv, ollamaUrlsFromOverrides, type Endpoint,
} from './no-live-ollama-core.js'

interface GateState {
  configured: Endpoint[]
  attempts: string[]
  currentTest: () => string
  /** Where spawned node children record their refused attempts (layer 3), and how much of it is read. */
  childRecord: string
  childRecordRead: number
}

// One install per process, however many test files the worker runs: the state
// lives on globalThis, the prototype and fetch are wrapped once.
const STATE_KEY = Symbol.for('marveen.no-live-ollama')
const holder = globalThis as unknown as Record<symbol, GateState | undefined>

function readIfPresent(path: string): string | null {
  try { return existsSync(path) ? readFileSync(path, 'utf-8') : null } catch { return null }
}

function installGate(): GateState {
  const setupDir = dirname(fileURLToPath(import.meta.url))
  const repoRoot = join(setupDir, '..', '..', '..')
  const urls: Array<string | undefined> = [process.env.EMBED_URL, process.env.OLLAMA_URL]
  const dotenv = readIfPresent(join(repoRoot, '.env'))
  if (dotenv !== null) urls.push(...ollamaUrlsFromDotenv(dotenv))
  const overrides = readIfPresent(join(repoRoot, 'store', 'config-overrides.json'))
  if (overrides !== null) urls.push(...ollamaUrlsFromOverrides(overrides))
  const state: GateState = {
    configured: urls.map(endpointOf).filter((e): e is Endpoint => e !== null),
    attempts: [],
    currentTest: () => '(unknown test)',
    childRecord: '',
    childRecordRead: 0,
  }

  // Layer 3: the node children. The endpoints travel as resolved HERE, at
  // launch: the child must not re-read its own EMBED_URL, which a test may have
  // pointed at its own fake server.
  const recordDir = mkdtempSync(join(tmpdir(), 'no-live-ollama-'))
  state.childRecord = join(recordDir, 'child-attempts.log')
  writeFileSync(state.childRecord, '')
  process.on('exit', () => { try { rmSync(recordDir, { recursive: true, force: true }) } catch { /* best effort */ } })
  process.env.MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS = JSON.stringify(state.configured)
  process.env.MARVEEN_NO_LIVE_OLLAMA_RECORD = state.childRecord
  const childGuard = join(setupDir, 'no-live-ollama-child.cjs')
  const current = process.env.NODE_OPTIONS ?? ''
  // Quoted: NODE_OPTIONS splits on spaces, and the checkout path may have one.
  if (!current.includes(childGuard)) process.env.NODE_OPTIONS = `${current} --require ${JSON.stringify(childGuard)}`.trim()

  // Layer 2: the socket gate.
  const originalConnect = net.Socket.prototype.connect as (...args: unknown[]) => net.Socket
  net.Socket.prototype.connect = function noLiveOllamaConnect(this: net.Socket, ...args: unknown[]): net.Socket {
    const target = connectTarget(args)
    if (target && isLiveOllamaTarget(target, state.configured)) {
      const where = `${target.host}:${target.port}`
      state.attempts.push(`${where} (during "${state.currentTest()}")`)
      // Fail like a refused connection, asynchronously, so the caller sees the
      // usual 'error' path; no packet ever leaves.
      const err = Object.assign(new Error(`NO-LIVE-OLLAMA: connect to ${where} refused by the test gate (src/__tests__/setup/no-live-ollama.ts)`), { code: 'ECONNREFUSED' })
      process.nextTick(() => this.destroy(err))
      return this
    }
    return originalConnect.apply(this, args)
  } as typeof net.Socket.prototype.connect

  // Layer 1: the embedding stand-in. A plain assignment, not vi.stubGlobal, so
  // a test's own stubGlobal/unstubAllGlobals returns to THIS, not to the real fetch.
  const realFetch = globalThis.fetch
  globalThis.fetch = function noLiveOllamaFetch(input: Parameters<typeof fetch>[0], init?: Parameters<typeof fetch>[1]) {
    const url = fetchUrl(input)
    if (url && isOllamaEmbeddingCall(url, state.configured)) {
      const cause = Object.assign(new Error(`NO-LIVE-OLLAMA: ${url.host} is a real Ollama; the embedding backend is down in tests`), { code: 'ECONNREFUSED' })
      return Promise.reject(new TypeError('fetch failed', { cause }))
    }
    return realFetch(input, init)
  } as typeof fetch
  return state
}

const state = holder[STATE_KEY] ?? (holder[STATE_KEY] = installGate())
// Refreshed per test file: the expect of THIS file's module graph names its tests.
state.currentTest = () => {
  try { return expect.getState().currentTestName ?? '(outside a test)' } catch { return '(outside a test)' }
}

// The attempts node children recorded since the last look (layer 3).
function collectChildAttempts(): void {
  let text = ''
  try { text = readFileSync(state.childRecord, 'utf-8') } catch { return }
  if (text.length <= state.childRecordRead) return
  const fresh = text.slice(state.childRecordRead)
  state.childRecordRead = text.length
  for (const line of fresh.split('\n')) if (line) state.attempts.push(`${line} (during "${state.currentTest()}")`)
}

function failOnAttempts(): void {
  collectChildAttempts()
  const hits = state.attempts.splice(0)
  if (hits.length === 0) return
  const counted = new Map<string, number>()
  for (const h of hits) counted.set(h, (counted.get(h) ?? 0) + 1)
  const summary = [...counted].map(([h, n]) => (n > 1 ? `${h} x${n}` : h)).join('; ')
  throw new Error(
    `NO-LIVE-OLLAMA: a test tried to reach a real Ollama: ${summary}. ` +
    'The connection was refused before it was made. Stub fetch (vi.stubGlobal) or the client instead.',
  )
}

afterEach(failOnAttempts)
afterAll(failOnAttempts)
