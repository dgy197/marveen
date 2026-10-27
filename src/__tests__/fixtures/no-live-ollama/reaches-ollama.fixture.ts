import { it, expect, vi } from 'vitest'
import { get } from 'node:http'
import { spawn } from 'node:child_process'

// Fixture of no-live-ollama-gate.test.ts, run ONLY by the nested vitest there.
// EMBED_URL is the outer test's own counting server, standing in for the live
// Ollama, so even a broken gate cannot send anything to a real one. The first
// two and the spawned-child one pass on their own: only the gate can fail them.

it('fetch to a non-embedding Ollama path, failure swallowed', async () => {
  try { await fetch(`${process.env.EMBED_URL}/api/ps`) } catch { /* swallowed */ }
  expect(true).toBe(true)
})

it('node:http client to the embedding path, failure swallowed', async () => {
  await new Promise<void>(resolve => {
    const req = get(`${process.env.EMBED_URL}/api/embeddings`, res => { res.resume(); res.on('end', () => resolve()) })
    req.on('error', () => resolve())
  })
  expect(true).toBe(true)
})

it('the embedding call through fetch, the way generateEmbedding makes it', async () => {
  let failure = ''
  try {
    await fetch(`${process.env.EMBED_URL}/api/embeddings`, { method: 'POST', body: '{}' })
  } catch (e) {
    failure = String((e as { cause?: { message?: string } })?.cause?.message ?? e)
  }
  // With the gate the stand-in answers "down"; without it the endpoint answers.
  if (process.env.FIXTURE_WITHOUT_GATE === '1') expect(failure).toBe('')
  else expect(failure).toMatch(/^NO-LIVE-OLLAMA: 127\.0\.0\.1:\d+ is a real Ollama; the embedding backend is down in tests$/)
})

it('a spawned node child reaches the Ollama, failure swallowed', async () => {
  // The child inherits this process's env, so it sees the same EMBED_URL.
  const script = "require('node:http').get(process.env.EMBED_URL + '/api/ps', r => { r.resume(); r.on('end', () => process.exit(0)) }).on('error', () => process.exit(0))"
  await new Promise<void>(resolve => {
    const child = spawn(process.execPath, ['-e', script], { stdio: 'ignore' })
    child.on('close', () => resolve())
    child.on('error', () => resolve())
  })
  expect(true).toBe(true)
})

it('a stubbed fetch never opens a socket, so the gate leaves it alone', async () => {
  vi.stubGlobal('fetch', async () => ({ ok: true, json: async () => ({ embedding: [1, 2, 3] }) }))
  try {
    const resp = await fetch(`${process.env.EMBED_URL}/api/embeddings`)
    expect(await resp.json()).toEqual({ embedding: [1, 2, 3] })
  } finally {
    vi.unstubAllGlobals()
  }
})
