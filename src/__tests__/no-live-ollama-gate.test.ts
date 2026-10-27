import { describe, it, expect, beforeAll, afterAll } from 'vitest'
import { spawn } from 'node:child_process'
import { createServer, type Server } from 'node:http'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  OLLAMA_DEFAULT_PORT, connectTarget, endpointOf, fetchUrl, isLiveOllamaTarget, isLoopbackHost,
  isOllamaEmbeddingCall, ollamaUrlsFromDotenv, ollamaUrlsFromOverrides,
} from './setup/no-live-ollama-core.js'

// MT1 (card d4e7fea7, 2026-10-17): suite runs reached the live Ollama and no test
// noticed, because the embedding path swallows its failures. The setup file
// src/__tests__/setup/no-live-ollama.ts answers the embedding call "down" without
// a socket, and refuses every other connect to a real Ollama AND fails the test
// that tried. This file proves the second half the only way a test's failure can
// be proven: from the outside, with nested vitest runs of fixture tests that
// reach "the Ollama" and swallow the error -- red with the gate, green without.
//
// The nested runs never touch a real Ollama, even with the gate broken: their
// EMBED_URL is a counting server of this test, and the default-port rule is
// tested on the pure decision function only (no socket to 11434, ever).

const ROOT = join(__dirname, '..', '..')
const read = (rel: string) => readFileSync(join(ROOT, rel), 'utf-8')

describe('the decision (pure, no socket)', () => {
  it('the Ollama default port is a real Ollama on every host spelling', () => {
    expect(OLLAMA_DEFAULT_PORT).toBe(11434)
    for (const host of ['127.0.0.1', 'localhost', '::1', '[::1]', '::ffff:127.0.0.1', '127.0.0.2', 'ollama.lan', '10.0.0.5']) {
      expect(isLiveOllamaTarget({ host, port: 11434 }, []), host).toBe(true)
    }
  })

  it('a configured endpoint is blocked; a loopback one under any loopback spelling', () => {
    const configured = [endpointOf('http://localhost:11500')!, endpointOf('https://ollama.internal')!]
    expect(configured).toEqual([{ host: 'localhost', port: 11500 }, { host: 'ollama.internal', port: 443 }])
    expect(isLiveOllamaTarget({ host: '127.0.0.1', port: 11500 }, configured)).toBe(true)
    expect(isLiveOllamaTarget({ host: '::1', port: 11500 }, configured)).toBe(true)
    expect(isLiveOllamaTarget({ host: 'OLLAMA.internal.', port: 443 }, configured)).toBe(true)
  })

  it('KONTROLL: other ports and hosts pass (the gate is not a blanket loopback ban)', () => {
    const configured = [endpointOf('http://localhost:11500')!]
    expect(isLiveOllamaTarget({ host: '127.0.0.1', port: 11501 }, configured)).toBe(false)
    expect(isLiveOllamaTarget({ host: '127.0.0.1', port: 3999 }, configured)).toBe(false)
    expect(isLiveOllamaTarget({ host: 'example.test', port: 11500 }, configured)).toBe(false)
    expect(isLoopbackHost('example.test')).toBe(false)
  })

  it('reads the connect() argument shapes net uses, and leaves pipes alone', () => {
    expect(connectTarget([{ host: '127.0.0.1', port: 11434 }])).toEqual({ host: '127.0.0.1', port: 11434 })
    expect(connectTarget([[{ port: '11434' }, () => {}]])).toEqual({ host: 'localhost', port: 11434 })
    expect(connectTarget([11434, '::1'])).toEqual({ host: '::1', port: 11434 })
    expect(connectTarget(['11434'])).toEqual({ host: 'localhost', port: 11434 })
    expect(connectTarget([{ path: '/tmp/x.sock' }])).toBeNull()
    expect(connectTarget(['/tmp/x.sock'])).toBeNull()
  })

  it('takes EMBED_URL / OLLAMA_URL from a .env and from config-overrides.json, and ignores the rest', () => {
    const text = 'BOT_NAME=x\nOLLAMA_URL="http://10.0.0.5:11500"\nexport EMBED_URL=http://localhost:11600\n# EMBED_URL=http://commented:1\nEMBED_MODEL=bge-m3\n'
    expect(ollamaUrlsFromDotenv(text)).toEqual(['http://10.0.0.5:11500', 'http://localhost:11600'])
    expect(ollamaUrlsFromOverrides('{"OLLAMA_URL":"http://box:11700","EMBED_MODEL":"x","EMBED_URL":""}')).toEqual(['http://box:11700'])
    expect(ollamaUrlsFromOverrides('not json')).toEqual([])
    expect(endpointOf('')).toBeNull()
    expect(endpointOf('not a url')).toBeNull()
  })

  it('the embedding stand-in takes only the embedding paths of a real Ollama', () => {
    const configured = [endpointOf('http://localhost:11500')!]
    const at = (u: string) => isOllamaEmbeddingCall(fetchUrl(u)!, configured)
    expect(at('http://localhost:11434/api/embeddings')).toBe(true)
    expect(at('http://127.0.0.1:11500/api/embed')).toBe(true)
    expect(at('http://localhost:11434/api/ps')).toBe(false)        // goes on to the socket gate
    expect(at('http://localhost:11434/api/generate')).toBe(false)
    expect(at('http://127.0.0.1:3999/api/embeddings')).toBe(false) // not an Ollama: untouched
    expect(fetchUrl(new Request('http://localhost:11434/api/embeddings'))?.pathname).toBe('/api/embeddings')
    expect(fetchUrl('/relative')).toBeNull()
  })

  it('is wired into the suite config (a gate that is not loaded protects nothing)', () => {
    expect(read('vitest.config.ts')).toContain("'./src/__tests__/setup/no-live-ollama.ts'")
  })
})

describe('a test that reaches the Ollama FAILS (nested vitest runs)', () => {
  let server: Server
  let port = 0
  let connections = 0
  let requests = 0
  let outDir = ''

  beforeAll(async () => {
    server = createServer((_req, res) => {
      requests++
      res.setHeader('content-type', 'application/json')
      res.end('{"embedding":[0.1]}')
    })
    server.on('connection', () => { connections++ })
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    port = (server.address() as { port: number }).port
    outDir = mkdtempSync(join(tmpdir(), 'no-live-ollama-gate-'))
  })

  afterAll(async () => {
    await new Promise<void>(r => server.close(() => r()))
    rmSync(outDir, { recursive: true, force: true })
  })

  // Async on purpose: the counting server lives in THIS process, and a
  // spawnSync would block the event loop it needs to answer the nested calls.
  async function nestedRun(label: string, withGate: boolean): Promise<{ status: number | null; tests: Map<string, { status: string; message: string }>; output: string }> {
    const env: NodeJS.ProcessEnv = {}
    for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('VITEST')) env[k] = v
    env.EMBED_URL = `http://127.0.0.1:${port}`
    env.FIXTURE_WITHOUT_GATE = withGate ? '0' : '1'
    const report = join(outDir, `${label}.json`)
    const child = spawn(process.execPath, [
      join(ROOT, 'node_modules', 'vitest', 'vitest.mjs'), 'run',
      '--root', ROOT,
      '--config', join(ROOT, 'src', '__tests__', 'fixtures', 'no-live-ollama', 'vitest.config.ts'),
      '--reporter=json', `--outputFile=${report}`,
    ], { cwd: ROOT, env, stdio: ['ignore', 'pipe', 'pipe'] })
    let output = ''
    child.stdout.on('data', (d: Buffer) => { output += d.toString() })
    child.stderr.on('data', (d: Buffer) => { output += d.toString() })
    const killer = setTimeout(() => child.kill('SIGKILL'), 90_000)
    const status = await new Promise<number | null>(r => child.on('close', code => r(code)))
    clearTimeout(killer)
    const tests = new Map<string, { status: string; message: string }>()
    try {
      const json = JSON.parse(readFileSync(report, 'utf-8')) as {
        testResults: { assertionResults: { title: string; status: string; failureMessages?: string[] }[] }[]
      }
      for (const file of json.testResults) {
        for (const a of file.assertionResults) tests.set(a.title, { status: a.status, message: (a.failureMessages ?? []).join('\n') })
      }
    } catch { /* no report: the assertions below say so */ }
    return { status, tests, output }
  }

  const FETCH_OTHER = 'fetch to a non-embedding Ollama path, failure swallowed'
  const HTTP_CLIENT = 'node:http client to the embedding path, failure swallowed'
  const EMBEDDING = 'the embedding call through fetch, the way generateEmbedding makes it'
  const STUBBED = 'a stubbed fetch never opens a socket, so the gate leaves it alone'
  const CHILD = 'a spawned node child reaches the Ollama, failure swallowed'

  it('KONTROLL without the gate: every fixture test passes AND really reaches the endpoint', async () => {
    connections = 0
    requests = 0
    const run = await nestedRun('without-gate', false)
    for (const title of [FETCH_OTHER, HTTP_CLIENT, EMBEDDING, STUBBED, CHILD]) {
      expect(run.tests.get(title)?.status, `${title}\n${run.output}`).toBe('passed')
    }
    expect(run.status, run.output).toBe(0)
    expect(requests).toBe(4) // /api/ps, the http client, the embedding call, the child's /api/ps; the stub opens nothing
    expect(connections).toBeGreaterThan(0)
  })

  it('with the gate: a test that reaches the Ollama fails loudly, and nothing reaches it', async () => {
    connections = 0
    requests = 0
    const run = await nestedRun('with-gate', true)
    for (const title of [FETCH_OTHER, HTTP_CLIENT, CHILD]) {
      const t = run.tests.get(title)
      expect(t?.status, `${title}\n${run.output}`).toBe('failed')
      expect(t?.message).toContain('NO-LIVE-OLLAMA')
      expect(t?.message).toContain(`127.0.0.1:${port}`)
    }
    // The embedding call is answered "down" by the stand-in, without a socket
    // (the fixture asserts the stand-in's message in this mode).
    expect(run.tests.get(EMBEDDING)?.status, `${run.tests.get(EMBEDDING)?.message}\n${run.output}`).toBe('passed')
    expect(run.tests.get(STUBBED)?.status, run.output).toBe('passed')
    expect(run.status).not.toBe(0)
    expect(requests).toBe(0)
    expect(connections).toBe(0)
  })
})

// MN6: a node child spawned by a test inherits the gate through NODE_OPTIONS.
// Every child that is sent at a blocked target first proves, without a socket,
// that the guard is loaded AND would refuse it (exit 3 / 4 otherwise), so a
// broken guard fails the test without ever trying the connect.
describe('spawned node children inherit the gate (NODE_OPTIONS --require)', () => {
  const CHILD_SCRIPT = `'use strict'
const net = require('node:net')
const { spawn } = require('node:child_process')
const [mode, host, port] = process.argv.slice(2)
const guard = globalThis[Symbol.for('marveen.no-live-ollama.child')]
const say = (o) => process.stdout.write(JSON.stringify(o) + '\\n')
if (!guard) { say({ result: 'no-guard' }); process.exit(3) }
if (mode === 'decide') {
  say({ result: 'decided', refused: JSON.parse(host).map(([h, p]) => guard.wouldRefuse(h, p)) })
  process.exit(0)
}
if (mode === 'grandchild') {
  const c = spawn(process.execPath, [__filename, 'expect-refuse', host, port], { stdio: 'inherit' })
  c.on('close', (code) => process.exit(code === null ? 99 : code))
} else {
  if (mode === 'expect-refuse' && !guard.wouldRefuse(host, port)) { say({ result: 'precondition' }); process.exit(4) }
  const s = net.connect({ host, port: Number(port) })
  s.on('connect', () => { say({ result: 'connected' }); s.end(); process.exit(0) })
  s.on('error', (e) => { say({ result: 'error', code: e.code, message: e.message }); process.exit(1) })
}
`
  let dir = ''
  let script = ''
  let record = ''
  let server: Server
  let port = 0
  let connections = 0

  beforeAll(async () => {
    dir = mkdtempSync(join(tmpdir(), 'no-live-ollama-child-'))
    script = join(dir, 'child.cjs')
    writeFileSync(script, CHILD_SCRIPT)
    record = join(dir, 'record.log')
    server = createServer((_req, res) => res.end('{}'))
    server.on('connection', () => { connections++ })
    await new Promise<void>(r => server.listen(0, '127.0.0.1', () => r()))
    port = (server.address() as { port: number }).port
  })

  afterAll(async () => {
    await new Promise<void>(r => server.close(() => r()))
    rmSync(dir, { recursive: true, force: true })
  })

  // The child records into a file of THIS test, not the setup's: a refusal the
  // test provokes on purpose must not fail the test through the setup.
  async function runChild(args: string[], extraEnv: NodeJS.ProcessEnv = {}): Promise<{ status: number | null; out: Record<string, unknown>[]; stderr: string }> {
    writeFileSync(record, '')
    const child = spawn(process.execPath, [script, ...args], {
      env: { ...process.env, MARVEEN_NO_LIVE_OLLAMA_RECORD: record, ...extraEnv },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (d: Buffer) => { stdout += d.toString() })
    child.stderr.on('data', (d: Buffer) => { stderr += d.toString() })
    const status = await new Promise<number | null>(r => child.on('close', code => r(code)))
    const out = stdout.split('\n').filter(Boolean).map(l => JSON.parse(l) as Record<string, unknown>)
    return { status, out, stderr }
  }

  it('the setup puts the child guard on NODE_OPTIONS and hands over the launch-time endpoints', () => {
    const guard = join(ROOT, 'src', '__tests__', 'setup', 'no-live-ollama-child.cjs')
    expect(process.env.NODE_OPTIONS).toContain(`--require ${JSON.stringify(guard)}`)
    expect(Array.isArray(JSON.parse(process.env.MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS ?? 'null'))).toBe(true)
    expect(process.env.MARVEEN_NO_LIVE_OLLAMA_RECORD).toBeTruthy()
  })

  it.each(['127.0.0.1', 'localhost', '::1'])('a spawned node child trying %s:11434 fails, before any connect, and leaves a record', async (host) => {
    const r = await runChild(['expect-refuse', host, String(OLLAMA_DEFAULT_PORT)])
    expect(r.out, r.stderr).toEqual([{ result: 'error', code: 'ECONNREFUSED', message: expect.stringContaining('NO-LIVE-OLLAMA') }])
    expect(r.status).toBe(1)
    expect(r.stderr).toContain(`NO-LIVE-OLLAMA: connect to ${host}:${OLLAMA_DEFAULT_PORT} refused in a child process`)
    expect(readFileSync(record, 'utf-8')).toContain(`${host}:${OLLAMA_DEFAULT_PORT} (child pid`)
  })

  it('a grandchild (node spawned by the node child) is refused too', async () => {
    const r = await runChild(['grandchild', '127.0.0.1', String(OLLAMA_DEFAULT_PORT)])
    expect(r.out).toEqual([{ result: 'error', code: 'ECONNREFUSED', message: expect.stringContaining('NO-LIVE-OLLAMA') }])
    expect(r.status).toBe(1)
    expect(readFileSync(record, 'utf-8')).toContain(`127.0.0.1:${OLLAMA_DEFAULT_PORT}`)
  })

  it('a launch-time endpoint is refused in the child, and nothing reaches it', async () => {
    connections = 0
    const r = await runChild(['expect-refuse', '127.0.0.1', String(port)], {
      MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS: JSON.stringify([{ host: 'localhost', port }]),
    })
    expect(r.out).toEqual([{ result: 'error', code: 'ECONNREFUSED', message: expect.stringContaining('NO-LIVE-OLLAMA') }])
    await new Promise(r2 => setTimeout(r2, 50))
    expect(connections).toBe(0)
  })

  it('KONTROLL: a test\'s own server stays reachable, even when the child\'s EMBED_URL points at it', async () => {
    connections = 0
    const r = await runChild(['connect', '127.0.0.1', String(port)], { EMBED_URL: `http://127.0.0.1:${port}` })
    expect(r.out, r.stderr).toEqual([{ result: 'connected' }])
    expect(r.status).toBe(0)
    await new Promise(r2 => setTimeout(r2, 50))
    expect(connections).toBeGreaterThan(0)
    expect(readFileSync(record, 'utf-8')).toBe('')
  })

  it('the child decides exactly like no-live-ollama-core.ts', async () => {
    const configured = [{ host: 'localhost', port: 11500 }, { host: 'ollama.internal', port: 443 }]
    const probes: Array<[string, number]> = [
      ['127.0.0.1', 11434], ['ollama.lan', 11434], ['::ffff:127.0.0.1', 11500], ['[::1]', 11500], ['127.0.0.2', 11500],
      ['OLLAMA.internal.', 443], ['example.test', 11500], ['127.0.0.1', 11501], ['127.0.0.1', 3999],
    ]
    const r = await runChild(['decide', JSON.stringify(probes)], { MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS: JSON.stringify(configured) })
    expect(r.out).toEqual([{ result: 'decided', refused: probes.map(([host, p]) => isLiveOllamaTarget({ host, port: p }, configured)) }])
    expect((r.out[0].refused as boolean[]).filter(Boolean).length).toBe(6)
  })
})
