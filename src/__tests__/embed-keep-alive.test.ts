// EMBED_KEEP_ALIVE: the keep_alive sent with every Ollama embedding request.
//
// Why it exists (card 94f8d99f, measured 2026-10-17): without keep_alive Ollama
// unloads the embedding model after 5 idle minutes, and the next search pays a
// cold load that does not fit the recall hook's 1.5 s budget. Brainy's decision
// (2433): "24h", NOT -1.
//
// The tests use a fake fetch only -- nothing here reaches a real Ollama.
import { describe, it, expect, vi, afterEach } from 'vitest'
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { generateEmbedding } from '../db.js'
import { EMBED_MODEL, EMBED_KEEP_ALIVE, resolveEmbedKeepAlive } from '../config.js'
import { SETTINGS_REGISTRY, validateSettingValue } from '../config-registry.js'

afterEach(() => {
  vi.unstubAllGlobals()
  vi.resetModules()
  vi.doUnmock('../logger.js')
})

function fakeFetch() {
  const fetchMock = vi.fn(async (..._args: unknown[]) => ({ json: async () => ({ embedding: [1, 2, 3] }) }))
  vi.stubGlobal('fetch', fetchMock)
  return fetchMock
}

function sentBody(fetchMock: ReturnType<typeof fakeFetch>, call = 0): Record<string, unknown> {
  const init = fetchMock.mock.calls[call][1] as { body: string }
  return JSON.parse(init.body)
}

describe('generateEmbedding request body', () => {
  it('carries keep_alive "24h" by default', async () => {
    const fetchMock = fakeFetch()
    await generateEmbedding('teszt')
    expect(sentBody(fetchMock).keep_alive).toBe('24h')
    expect(EMBED_KEEP_ALIVE).toBe('24h')
  })

  it('changes nothing else in the body: exactly model, prompt and keep_alive', async () => {
    const fetchMock = fakeFetch()
    await generateEmbedding('x'.repeat(3000))
    const body = sentBody(fetchMock)
    expect(Object.keys(body).sort()).toEqual(['keep_alive', 'model', 'prompt'])
    expect(body.model).toBe(EMBED_MODEL)
    expect(body.prompt).toBe('x'.repeat(2000))
  })

  it('never sends -1 (keep forever)', async () => {
    const fetchMock = fakeFetch()
    await generateEmbedding('teszt')
    expect(sentBody(fetchMock).keep_alive).not.toBe(-1)
    expect(sentBody(fetchMock).keep_alive).not.toBe('-1')
  })
})

describe('resolveEmbedKeepAlive', () => {
  it('defaults to 24h when unset or blank, without flagging it as invalid', () => {
    expect(resolveEmbedKeepAlive(undefined)).toEqual({ value: '24h' })
    expect(resolveEmbedKeepAlive('')).toEqual({ value: '24h' })
    expect(resolveEmbedKeepAlive('   ')).toEqual({ value: '24h' })
  })

  it.each(['24h', '30m', '90s', '500ms', '1h', '10s', '05m'])('accepts the Ollama duration %s', (v) => {
    expect(resolveEmbedKeepAlive(v)).toEqual({ value: v })
  })

  it('trims surrounding whitespace', () => {
    expect(resolveEmbedKeepAlive(' 12h ')).toEqual({ value: '12h' })
  })

  it('accepts a plain number of seconds and returns it as a number', () => {
    expect(resolveEmbedKeepAlive('3600')).toEqual({ value: 3600 })
    expect(resolveEmbedKeepAlive('10')).toEqual({ value: 10 })
  })

  // MN2: zero means "unload after every request" to Ollama -- every search cold.
  it.each(['0', '00', '0s', '0ms', '0m', '0h', '000h', ' 0s '])('rejects zero (%j): default plus the rejected value reported', (v) => {
    expect(resolveEmbedKeepAlive(v)).toEqual({ value: '24h', invalid: v.trim() })
  })

  it.each(['-1', '-5', '-1h', '1.5h', '1h30m', 'forever', 'infinity', '24 h', '24H', 'h', '1e3', '12345678901'])(
    'rejects %s: default plus the rejected value reported',
    (v) => {
      expect(resolveEmbedKeepAlive(v)).toEqual({ value: '24h', invalid: v })
    },
  )
})

describe('registry', () => {
  it('lists EMBED_KEEP_ALIVE with default 24h and requires a restart', () => {
    const def = SETTINGS_REGISTRY.find(d => d.key === 'EMBED_KEEP_ALIVE')
    expect(def?.default).toBe('24h')
    expect(def?.requiresRestart).toBe(true)
    expect(def?.secret).toBe(false)
  })

  // MN1: the Settings save is refused for exactly the values the boot would
  // discard, so a typo cannot sit in .env until the next restart's WARN.
  const def = () => SETTINGS_REGISTRY.find(d => d.key === 'EMBED_KEEP_ALIVE')!

  it.each(['24h', '30m', '90s', '500ms', '3600', ' 12h ', ''])('accepts %j at save time', (v) => {
    expect(validateSettingValue(def(), v).ok).toBe(true)
  })

  it.each(['-1', 'forever', '1.5h', '1h30m', '24H', '1e3', '12345678901'])('refuses %j at save time', (v) => {
    const r = validateSettingValue(def(), v)
    expect(r.ok).toBe(false)
    expect(r.error).toMatch(/Érvénytelen időtartam/)
  })

  it.each(['0', '0s', '0ms', '00m'])('refuses zero (%j) at save time and says why', (v) => {
    const r = validateSettingValue(def(), v)
    expect(r.ok).toBe(false)
    expect(r.error).toMatch(/0 nem elfogadott.*kiüríti/)
  })

  it('agrees with resolveEmbedKeepAlive on every probe value', () => {
    for (const v of ['24h', '30m', '500ms', '3600', '-1', 'forever', '1.5h', '24 h', 'h', '99999h', '100000h', '0', '0s', '0ms', '10s']) {
      const savable = validateSettingValue(def(), v).ok
      const bootAccepts = resolveEmbedKeepAlive(v).invalid === undefined
      expect({ v, savable }).toEqual({ v, savable: bootAccepts })
    }
  })
})

// End to end: the value comes from the install's .env (read at import time),
// so each case loads fresh config + db modules against a throw-away .env dir.
describe('EMBED_KEEP_ALIVE from the environment', () => {
  const dirs: string[] = []
  afterEach(() => {
    for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true })
    delete process.env.CLAUDECLAW_ENV_DIR
  })

  async function loadWith(envValue: string) {
    const dir = mkdtempSync(join(tmpdir(), 'embed-keep-alive-'))
    dirs.push(dir)
    writeFileSync(join(dir, '.env'), `EMBED_KEEP_ALIVE=${envValue}\n`)
    process.env.CLAUDECLAW_ENV_DIR = dir
    const logger = { info: vi.fn(), warn: vi.fn(), debug: vi.fn(), error: vi.fn() }
    vi.resetModules()
    vi.doMock('../logger.js', () => ({ logger }))
    const db = await import('../db.js')
    return { generateEmbedding: db.generateEmbedding, logger }
  }

  it('a valid duration is sent as configured, with no warning', async () => {
    const { generateEmbedding: gen, logger } = await loadWith('30m')
    const fetchMock = fakeFetch()
    await gen('teszt')
    expect(sentBody(fetchMock).keep_alive).toBe('30m')
    expect(logger.warn).not.toHaveBeenCalled()
  })

  it('a number of seconds is sent as a JSON number', async () => {
    const { generateEmbedding: gen } = await loadWith('3600')
    const fetchMock = fakeFetch()
    await gen('teszt')
    expect(sentBody(fetchMock).keep_alive).toBe(3600)
  })

  it.each(['-1', 'forever', '1.5h', '0', '0s'])('an invalid value (%s) falls back to 24h and warns exactly once', async (bad) => {
    const { generateEmbedding: gen, logger } = await loadWith(bad)
    const fetchMock = fakeFetch()
    await gen('egy')
    await gen('ketto')
    await gen('harom')
    expect(fetchMock).toHaveBeenCalledTimes(3)
    for (let i = 0; i < 3; i++) expect(sentBody(fetchMock, i).keep_alive).toBe('24h')
    expect(logger.warn).toHaveBeenCalledTimes(1)
    expect(logger.warn.mock.calls[0][0]).toEqual({ value: bad, using: '24h' })
  })
})
