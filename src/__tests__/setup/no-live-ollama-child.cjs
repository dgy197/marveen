// Child-process half of the no-live-Ollama suite gate (MN6).
//
// no-live-ollama.ts patches the vitest WORKER only; a test that spawns a node
// child (a script under test, tsx, a nested vitest) used to give that child a
// free hand at a real Ollama. The setup now puts this file on NODE_OPTIONS
// (--require), so every node process the worker spawns -- and their node
// children in turn -- loads it before any user code.
//
// What it does, in the child: every connect() to port 11434 on any host, or to
// one of the endpoints the setup resolved at launch (passed in
// MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS, never re-read from the child's own
// EMBED_URL / OLLAMA_URL, so a test's own fake server stays reachable), is
// refused BEFORE the connect: no packet leaves. The refusal surfaces as an
// ECONNREFUSED 'error', one line on stderr, and one line in the file named by
// MARVEEN_NO_LIVE_OLLAMA_RECORD, which the setup reads after every test and
// fails that test with -- a child that swallows the error is still caught.
//
// The decision mirrors no-live-ollama-core.ts (no TS loader here, so it is
// copied, not imported); no-live-ollama-gate.test.ts checks the two agree.
// Loading twice is a no-op. On load it checks its own decision on 11434
// (pure, no socket) and exits 70 if that would let it through.
'use strict'
const net = require('node:net')
const fs = require('node:fs')

const KEY = Symbol.for('marveen.no-live-ollama.child')
const OLLAMA_DEFAULT_PORT = 11434

function normalizeHost(host) {
  let h = String(host).trim().toLowerCase()
  if (h.startsWith('[') && h.endsWith(']')) h = h.slice(1, -1)
  if (h.startsWith('::ffff:')) h = h.slice('::ffff:'.length)
  if (h.endsWith('.')) h = h.slice(0, -1)
  return h
}

function isLoopbackHost(host) {
  const h = normalizeHost(host)
  return h === 'localhost' || h.endsWith('.localhost') || h === '::1' || h === '0.0.0.0' || h === '::'
    || /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h)
}

function connectTarget(args) {
  let first = args[0]
  if (Array.isArray(first)) first = first[0]
  if (first && typeof first === 'object') {
    if (typeof first.path === 'string') return null
    const port = Number(first.port)
    return Number.isInteger(port) ? { host: typeof first.host === 'string' ? first.host : 'localhost', port } : null
  }
  if (typeof first === 'string' && !/^\d+$/.test(first)) return null
  const port = Number(first)
  return Number.isInteger(port) ? { host: typeof args[1] === 'string' ? args[1] : 'localhost', port } : null
}

function readConfigured() {
  try {
    const list = JSON.parse(process.env.MARVEEN_NO_LIVE_OLLAMA_ENDPOINTS || '[]')
    return Array.isArray(list)
      ? list.filter(e => e && typeof e.host === 'string' && Number.isInteger(e.port)).map(e => ({ host: normalizeHost(e.host), port: e.port }))
      : []
  } catch {
    return []
  }
}

function isLiveOllamaTarget(target, configured) {
  if (target.port === OLLAMA_DEFAULT_PORT) return true
  const h = normalizeHost(target.host)
  return configured.some(e => e.port === target.port && (e.host === h || (isLoopbackHost(e.host) && isLoopbackHost(h))))
}

if (!globalThis[KEY]) {
  const configured = readConfigured()
  if (!isLiveOllamaTarget({ host: '127.0.0.1', port: OLLAMA_DEFAULT_PORT }, configured)) {
    process.stderr.write('NO-LIVE-OLLAMA child guard: self-check failed, refusing to run\n')
    process.exit(70)
  }
  const originalConnect = net.Socket.prototype.connect
  net.Socket.prototype.connect = function noLiveOllamaChildConnect(...args) {
    const target = connectTarget(args)
    if (target && isLiveOllamaTarget(target, configured)) {
      const where = `${target.host}:${target.port}`
      const line = `${where} (child pid ${process.pid}: ${process.argv.slice(1).join(' ').slice(0, 200)})`
      try {
        if (process.env.MARVEEN_NO_LIVE_OLLAMA_RECORD) fs.appendFileSync(process.env.MARVEEN_NO_LIVE_OLLAMA_RECORD, line + '\n')
      } catch { /* the stderr line and the refusal still happen */ }
      try { process.stderr.write(`NO-LIVE-OLLAMA: connect to ${where} refused in a child process (src/__tests__/setup/no-live-ollama-child.cjs)\n`) } catch { /* closed stderr */ }
      const err = Object.assign(new Error(`NO-LIVE-OLLAMA: connect to ${where} refused by the test gate (child process)`), { code: 'ECONNREFUSED' })
      process.nextTick(() => this.destroy(err))
      return this
    }
    return originalConnect.apply(this, args)
  }
  // Exposed for the gate's own tests: a child can prove the guard is loaded
  // and would refuse a target before it ever tries one.
  globalThis[KEY] = { wouldRefuse: (host, port) => isLiveOllamaTarget({ host, port: Number(port) }, configured) }
}
