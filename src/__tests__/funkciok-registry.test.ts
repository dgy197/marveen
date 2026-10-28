import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  MIN_TAG_LEN, SLUG_RE, checkRepoPath, getRegistryEntry, listRegistry, parseRepoAllowlist,
  resolveAllowedRepos, validateFunkcio,
} from '../web/funkciok-registry.js'
import { getSettingDefinition, validateSettingValue } from '../config-registry.js'

// Card d7b2d5c8 (S1): registry loader, schema validation, slug and repo-path fences.

let dir: string

beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'funkciok-reg-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

function good(slug: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    slug,
    nev: `Funkcio ${slug}`,
    leiras: 'Rovid leiras.',
    kartyak: ['4fbbb27c'],
    tagek: ['TAG123'],
    repok: [{ nev: 'marveen', ut: '/tmp/some-repo', pathGlobok: ['src/web/*.ts'], tesztGlobok: ['src/__tests__/*.test.ts'] }],
    tiltasok: ['Ne kuldj levelet jovahagyas nelkul.'],
    specUtak: ['/tmp/spec.md'],
    ...extra,
  }
}

function put(slug: string, doc: unknown): void {
  writeFileSync(join(dir, `${slug}.json`), typeof doc === 'string' ? doc : JSON.stringify(doc))
}

describe('validateFunkcio', () => {
  it('accepts a complete document and keeps every field', () => {
    const r = validateFunkcio(good('levelkapu'), 'levelkapu')
    expect(r.ok).toBe(true)
    if (r.ok) {
      expect(r.value.slug).toBe('levelkapu')
      expect(r.value.kartyak).toEqual(['4fbbb27c'])
      expect(r.value.repok[0].pathGlobok).toEqual(['src/web/*.ts'])
    }
  })

  it('the slug must match the file name and the slug regex', () => {
    expect(validateFunkcio(good('a'), 'b').ok).toBe(false)
    for (const bad of ['../x', 'A', 'a b', '-a', '', 'a/b', '%2e%2e']) {
      expect(validateFunkcio(good(bad), bad).ok).toBe(false)
    }
  })

  it.each([
    ['card id not hex8', { kartyak: ['xyz'] }],
    ['card id uppercase', { kartyak: ['4FBBB27C'] }],
    ['tag with whitespace', { tagek: ['two words'] }],
    ['tag with control char', { tagek: ['a\nb'] }],
    ['spec path relative', { specUtak: ['docs/spec.md'] }],
    ['spec path with ..', { specUtak: ['/a/../b'] }],
    ['repo path relative', { repok: [{ nev: 'x', ut: 'relative/repo', pathGlobok: [], tesztGlobok: [] }] }],
    ['repo path with ..', { repok: [{ nev: 'x', ut: '/a/../b', pathGlobok: [], tesztGlobok: [] }] }],
    ['glob with ..', { repok: [{ nev: 'x', ut: '/a', pathGlobok: ['../etc/*'], tesztGlobok: [] }] }],
    ['absolute glob', { repok: [{ nev: 'x', ut: '/a', pathGlobok: ['/etc/*'], tesztGlobok: [] }] }],
    ['glob with too many wildcard runs', { repok: [{ nev: 'x', ut: '/a', pathGlobok: ['*a*b*c*d*e*f*g*'], tesztGlobok: [] }] }],
    ['nev missing', { nev: undefined }],
    ['kartyak not an array', { kartyak: 'x' }],
  ])('rejects: %s', (_label, patch) => {
    expect(validateFunkcio(good('f', patch as Record<string, unknown>), 'f').ok).toBe(false)
  })

  it('B4: a tag shorter than 3 characters is a validation error, 3 characters is fine', () => {
    for (const short of ['a', 'ab', 'x1']) {
      const r = validateFunkcio(good('f', { tagek: ['GOODTAG', short] }), 'f')
      expect(r.ok).toBe(false)
      if (!r.ok) expect(r.error).toMatch(/^tagek: a tag must be at least 3 characters/)
    }
    expect(MIN_TAG_LEN).toBe(3)
    expect(validateFunkcio(good('f', { tagek: ['abc'] }), 'f').ok).toBe(true)
  })

  it('B4: a file with a too-short tag is listed with the error flag and the others still work', () => {
    put('ok-one', good('ok-one'))
    put('short-tag', good('short-tag', { tagek: ['ab'] }))
    const byslug = Object.fromEntries(listRegistry(dir).map((e) => [e.slug, e]))
    expect(byslug['ok-one'].ok).toBe(true)
    expect(byslug['short-tag']).toMatchObject({ ok: false, error: 'tagek: a tag must be at least 3 characters' })
  })

  it('a top-level array or null is rejected', () => {
    expect(validateFunkcio([], 'f').ok).toBe(false)
    expect(validateFunkcio(null, 'f').ok).toBe(false)
  })

  it('a tag or glob that starts with "-" is valid DATA (it never reaches git)', () => {
    const r = validateFunkcio(good('f', { tagek: ['--output=/tmp/x'], repok: [{ nev: 'x', ut: '/a', pathGlobok: ['-rf/*'], tesztGlobok: [] }] }), 'f')
    expect(r.ok).toBe(true)
  })
})

describe('listRegistry / getRegistryEntry', () => {
  it('S1-1 input: four valid files come back sorted by slug', () => {
    for (const s of ['levelkapu', 'szamlamento-olvasottra-jeloles', 'ajanlat-kor', 'context-guard']) put(s, good(s))
    const l = listRegistry(dir)
    expect(l.map((e) => e.slug)).toEqual(['ajanlat-kor', 'context-guard', 'levelkapu', 'szamlamento-olvasottra-jeloles'])
    expect(l.every((e) => e.ok)).toBe(true)
  })

  it('an invalid file is listed with an error and the others still work', () => {
    put('ok-one', good('ok-one'))
    put('broken-json', '{ not json')
    put('bad-schema', good('bad-schema', { kartyak: ['nope'] }))
    put('wrong-slug', good('other-slug'))
    const byslug = Object.fromEntries(listRegistry(dir).map((e) => [e.slug, e]))
    expect(byslug['ok-one'].ok).toBe(true)
    expect(byslug['broken-json']).toMatchObject({ ok: false, error: 'invalid JSON' })
    expect(byslug['bad-schema'].ok).toBe(false)
    expect(byslug['wrong-slug'].ok).toBe(false)
  })

  it('the JSON parse error never quotes the file content', () => {
    put('leaky', '{"secret": TITOK-MARKER')
    const e = getRegistryEntry(dir, 'leaky')
    expect(JSON.stringify(e)).not.toContain('TITOK-MARKER')
  })

  it('a missing directory is an empty registry', () => {
    expect(listRegistry(join(dir, 'does-not-exist'))).toEqual([])
  })

  it('files with names outside the slug regex are ignored', () => {
    put('Bad_Name', good('x'))
    put('.hidden', good('x'))
    writeFileSync(join(dir, 'notes.txt'), 'x')
    expect(listRegistry(dir)).toEqual([])
  })

  it('a symlinked registry file is refused (plain files only)', () => {
    const outside = join(dir, 'outside.txt')
    writeFileSync(outside, JSON.stringify(good('linked')))
    symlinkSync(outside, join(dir, 'linked.json'))
    const e = getRegistryEntry(dir, 'linked')
    expect(e).toMatchObject({ ok: false, error: 'not a regular file' })
  })

  it('slug traversal: ../ and %2e%2e never reach the filesystem', () => {
    mkdirSync(join(dir, 'sub'))
    writeFileSync(join(dir, 'secret.json'), JSON.stringify(good('secret')))
    for (const s of ['../secret', '..', '%2e%2e', '..%2fsecret', 'sub/../secret', 'a/b', '']) {
      expect(SLUG_RE.test(s)).toBe(false)
      expect(getRegistryEntry(join(dir, 'sub'), s)).toBeNull()
    }
  })

  it('an unknown slug is null, a known one is found', () => {
    put('here', good('here'))
    expect(getRegistryEntry(dir, 'nowhere')).toBeNull()
    expect(getRegistryEntry(dir, 'here')?.ok).toBe(true)
  })
})

describe('repo allowlist', () => {
  it('parseRepoAllowlist splits on commas and whitespace', () => {
    expect(parseRepoAllowlist('/a, /b  /c,,')).toEqual(['/a', '/b', '/c'])
    expect(parseRepoAllowlist('')).toEqual([])
  })

  it('the install root is always allowed; setting entries are added; relative and missing ones dropped', () => {
    const root = mkdtempSync(join(tmpdir(), 'funkciok-root-'))
    const extra = mkdtempSync(join(tmpdir(), 'funkciok-extra-'))
    try {
      const allowed = resolveAllowedRepos(root, `${extra}, relative/path, ${join(root, 'missing')}`)
      expect([...allowed].sort()).toEqual([realpathSync(root), realpathSync(extra)].sort())
      expect(resolveAllowedRepos(root, '').size).toBe(1)
    } finally {
      rmSync(root, { recursive: true, force: true })
      rmSync(extra, { recursive: true, force: true })
    }
  })

  it('checkRepoPath: exact realpath hit only; a subdirectory, a sibling and a missing path are refused', () => {
    const repo = mkdtempSync(join(tmpdir(), 'funkciok-repo-'))
    mkdirSync(join(repo, 'sub'))
    try {
      const allowed = new Set([realpathSync(repo)])
      expect(checkRepoPath(repo, allowed)).toEqual({ ok: true, realPath: realpathSync(repo) })
      expect(checkRepoPath(join(repo, 'sub'), allowed)).toEqual({ ok: false, error: 'repo_not_allowed' })
      expect(checkRepoPath(dir, allowed)).toEqual({ ok: false, error: 'repo_not_allowed' })
      expect(checkRepoPath(join(repo, 'nope'), allowed)).toEqual({ ok: false, error: 'repo_missing' })
    } finally {
      rmSync(repo, { recursive: true, force: true })
    }
  })

  it('a symlink to an allowlisted repo resolves to it; a symlink out of the list is refused by realpath', () => {
    const repo = mkdtempSync(join(tmpdir(), 'funkciok-repo-'))
    try {
      const allowed = new Set([realpathSync(repo)])
      const toAllowed = join(dir, 'to-allowed')
      const toOther = join(dir, 'to-other')
      symlinkSync(repo, toAllowed)
      symlinkSync(dir, toOther)
      expect(checkRepoPath(toAllowed, allowed).ok).toBe(true)
      expect(checkRepoPath(toOther, allowed)).toEqual({ ok: false, error: 'repo_not_allowed' })
    } finally {
      rmSync(repo, { recursive: true, force: true })
    }
  })
})

describe('FUNKCIO_REPO_ALLOWLIST setting', () => {
  const def = getSettingDefinition('FUNKCIO_REPO_ALLOWLIST')!

  it('is registered: empty default (install root only), string, not secret, no restart', () => {
    expect(def).toBeDefined()
    expect(def.default).toBe('')
    expect(def.type).toBe('string')
    expect(def.secret).toBe(false)
    expect(def.requiresRestart).toBe(false)
  })

  it('validates absolute paths only', () => {
    expect(validateSettingValue(def, '').ok).toBe(true)
    expect(validateSettingValue(def, '/a/b, /c/d').ok).toBe(true)
    expect(validateSettingValue(def, 'relative').ok).toBe(false)
    expect(validateSettingValue(def, '/a/../b').ok).toBe(false)
    expect(validateSettingValue(def, '/a\u0000b').ok).toBe(false)
  })

  it('adding a repo loosens (owner-only), removing one does not', () => {
    expect(def.loosens!('', '/a')).toBe(true)
    expect(def.loosens!('/a', '/a, /b')).toBe(true)
    expect(def.loosens!('/a, /b', '/a')).toBe(false)
    expect(def.loosens!('/a', '')).toBe(false)
    expect(def.loosens!('/a', '/a')).toBe(false)
  })
})
