import { describe, it, expect } from 'vitest'
import { join } from 'node:path'
import { listRegistry } from '../web/funkciok-registry.js'

// Card d7b2d5c8 (S1): the four example registry files shipped under
// docs/funkciok-pelda/ (store/ is gitignored, so the examples live in docs/ and
// are copied to store/funkciok/ by the operator) must stay valid.

const DIR = join(__dirname, '..', '..', 'docs', 'funkciok-pelda')

describe('docs/funkciok-pelda example registry', () => {
  const entries = listRegistry(DIR)

  it('holds the four agreed functions and every file validates', () => {
    expect(entries.map((e) => e.slug)).toEqual(['ajanlat-kor', 'context-guard', 'levelkapu', 'szamlamento-olvasottra-jeloles'])
    for (const e of entries) expect(e.ok, `${e.slug}: ${e.ok ? '' : e.error}`).toBe(true)
  })

  it('szamlamento-olvasottra-jeloles carries the four cards and the invoice-archive repo', () => {
    const e = entries.find((x) => x.slug === 'szamlamento-olvasottra-jeloles')
    if (!e || !e.ok) throw new Error('missing or invalid')
    for (const card of ['4fbbb27c', '6a52389f', '0179078c', '17c227ea']) expect(e.funkcio.kartyak).toContain(card)
    expect(e.funkcio.repok.map((r) => r.ut)).toContain('/Volumes/8T/10_LOCAL/Brainy/main/projects/invoice-archive')
  })

  it('no example carries a credential-looking string or a mail address', () => {
    const dump = JSON.stringify(entries)
    expect(dump).not.toMatch(/\b(Bearer|password|apikey|api_key)\b/i)
    expect(dump).not.toMatch(/[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[a-z]{2,}/)
  })
})
