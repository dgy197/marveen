import { describe, it, expect } from 'vitest'
import { join } from 'node:path'
import { listRegistry, validateFunkcio } from '../web/funkciok-registry.js'

// Function page (S1): the example registry file shipped under docs/funkciok-pelda/
// (store/ is gitignored, so the example lives in docs/ and is copied to
// store/funkciok/ by the operator) must stay valid against the schema.

const DIR = join(__dirname, '..', '..', 'docs', 'funkciok-pelda')

describe('docs/funkciok-pelda example registry', () => {
  const entries = listRegistry(DIR)

  it('holds the example function and it validates', () => {
    expect(entries.map((e) => e.slug)).toEqual(['example-feature'])
    for (const e of entries) expect(e.ok, `${e.slug}: ${e.ok ? '' : e.error}`).toBe(true)
  })

  it('example-feature carries its cards and its repo', () => {
    const e = entries.find((x) => x.slug === 'example-feature')
    if (!e || !e.ok) throw new Error('missing or invalid')
    expect(e.funkcio.kartyak).toEqual(['aaaa1111', 'bbbb2222'])
    expect(e.funkcio.repok.map((r) => r.ut)).toContain('/tmp/example/example-repo')
  })

  it('the validator still rejects a broken variant of the example', () => {
    const e = entries[0]
    if (!e || !e.ok) throw new Error('missing or invalid')
    expect(validateFunkcio({ ...e.funkcio }, 'example-feature').ok).toBe(true)
    expect(validateFunkcio({ ...e.funkcio, kartyak: ['NOT-A-CARD'] }, 'example-feature').ok).toBe(false)
    expect(validateFunkcio({ ...e.funkcio, slug: 'other' }, 'example-feature').ok).toBe(false)
    expect(validateFunkcio({ ...e.funkcio, repok: [{ nev: 'x', ut: 'relative/path', pathGlobok: [], tesztGlobok: [] }] }, 'example-feature').ok).toBe(false)
  })

  it('the example carries no credential-looking string or mail address', () => {
    const dump = JSON.stringify(entries)
    expect(dump).not.toMatch(/\b(Bearer|password|apikey|api_key)\b/i)
    expect(dump).not.toMatch(/[A-Za-z0-9._-]+@[A-Za-z0-9.-]+\.[a-z]{2,}/)
  })
})
