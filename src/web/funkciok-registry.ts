import { lstatSync, readdirSync, readFileSync, realpathSync } from 'node:fs'
import { isAbsolute, join } from 'node:path'

// Card d7b2d5c8 (S1): the function registry behind "Fejlesztes > Funkciok".
//
// One JSON file per function, store/funkciok/<slug>.json, written by hand (it
// is diffable and needs no write API, so it adds no permission surface). This
// module only READS and VALIDATES it. A bad file is reported with an error flag
// and never takes the other functions down.
//
// Nothing a registry file says is ever handed to git as an option or to the
// shell: tags and globs are matched in JS (funkciok-git.ts), repo paths are
// checked against an allowlist by realpath BEFORE any process is spawned.

export const SLUG_RE = /^[a-z0-9][a-z0-9-]{0,63}$/
export const HEX8_RE = /^[0-9a-f]{8}$/

const MAX_FILE_BYTES = 64 * 1024
const MAX_CARDS = 100
const MAX_TAGS = 50
const MAX_REPOS = 10
const MAX_GLOBS = 50
const MAX_PROHIBITIONS = 100
const MAX_SPEC_PATHS = 20
const MAX_GLOB_LEN = 200
const MAX_WILDCARD_RUNS = 6

export interface FunkcioRepo {
  nev: string
  ut: string
  pathGlobok: string[]
  tesztGlobok: string[]
}

export interface Funkcio {
  slug: string
  nev: string
  leiras: string
  kartyak: string[]
  tagek: string[]
  repok: FunkcioRepo[]
  tiltasok: string[]
  specUtak: string[]
}

export type RegistryEntry =
  | { slug: string; ok: true; funkcio: Funkcio }
  | { slug: string; ok: false; error: string }

type Check<T> = { ok: true; value: T } | { ok: false; error: string }

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v)
}

function hasControlChars(s: string): boolean {
  return /[\u0000-\u001f\u007f]/.test(s)
}

function checkString(v: unknown, field: string, min: number, max: number): Check<string> {
  if (typeof v !== 'string') return { ok: false, error: `${field}: string expected` }
  const t = v.trim()
  if (t.length < min || t.length > max) return { ok: false, error: `${field}: length must be ${min}..${max}` }
  if (hasControlChars(t)) return { ok: false, error: `${field}: control characters not allowed` }
  return { ok: true, value: t }
}

function checkStringArray(v: unknown, field: string, maxItems: number, maxLen: number, each?: (s: string) => string | null): Check<string[]> {
  if (!Array.isArray(v)) return { ok: false, error: `${field}: array expected` }
  if (v.length > maxItems) return { ok: false, error: `${field}: at most ${maxItems} items` }
  const out: string[] = []
  for (const item of v) {
    const c = checkString(item, field, 1, maxLen)
    if (!c.ok) return c
    const extra = each ? each(c.value) : null
    if (extra) return { ok: false, error: `${field}: ${extra}` }
    out.push(c.value)
  }
  return { ok: true, value: out }
}

function globProblem(g: string): string | null {
  if (g.includes('..')) return 'glob must not contain ".."'
  if (g.startsWith('/')) return 'glob must be repo-relative'
  const runs = g.match(/[*?]+/g) ?? []
  if (runs.length > MAX_WILDCARD_RUNS) return `glob has more than ${MAX_WILDCARD_RUNS} wildcard runs`
  return null
}

function absPathProblem(p: string): string | null {
  if (!isAbsolute(p)) return 'absolute path expected'
  if (p.split('/').includes('..')) return 'path must not contain ".."'
  return null
}

/**
 * Validate one parsed registry document. `expectedSlug` is the file name's
 * slug: the two must agree, so a file cannot impersonate another function.
 */
export function validateFunkcio(raw: unknown, expectedSlug: string): Check<Funkcio> {
  if (!isPlainObject(raw)) return { ok: false, error: 'top level must be an object' }

  const slug = checkString(raw.slug, 'slug', 1, 64)
  if (!slug.ok) return slug
  if (!SLUG_RE.test(slug.value)) return { ok: false, error: 'slug: must match [a-z0-9][a-z0-9-]{0,63}' }
  if (slug.value !== expectedSlug) return { ok: false, error: 'slug: does not match the file name' }

  const nev = checkString(raw.nev, 'nev', 1, 120)
  if (!nev.ok) return nev
  const leiras = raw.leiras === undefined ? { ok: true as const, value: '' } : checkString(raw.leiras, 'leiras', 0, 600)
  if (!leiras.ok) return leiras

  const kartyak = checkStringArray(raw.kartyak ?? [], 'kartyak', MAX_CARDS, 8,
    (s) => (HEX8_RE.test(s) ? null : 'each card must be 8 lowercase hex characters'))
  if (!kartyak.ok) return kartyak
  const tagek = checkStringArray(raw.tagek ?? [], 'tagek', MAX_TAGS, 60,
    (s) => (/\s/.test(s) ? 'a tag must not contain whitespace' : null))
  if (!tagek.ok) return tagek
  const tiltasok = checkStringArray(raw.tiltasok ?? [], 'tiltasok', MAX_PROHIBITIONS, 400)
  if (!tiltasok.ok) return tiltasok
  const specUtak = checkStringArray(raw.specUtak ?? [], 'specUtak', MAX_SPEC_PATHS, 500, absPathProblem)
  if (!specUtak.ok) return specUtak

  const reposRaw = raw.repok ?? []
  if (!Array.isArray(reposRaw)) return { ok: false, error: 'repok: array expected' }
  if (reposRaw.length > MAX_REPOS) return { ok: false, error: `repok: at most ${MAX_REPOS} items` }
  const repok: FunkcioRepo[] = []
  for (const r of reposRaw) {
    if (!isPlainObject(r)) return { ok: false, error: 'repok: each item must be an object' }
    const rn = checkString(r.nev, 'repok.nev', 1, 60)
    if (!rn.ok) return rn
    const ru = checkString(r.ut, 'repok.ut', 1, 500)
    if (!ru.ok) return ru
    const rup = absPathProblem(ru.value)
    if (rup) return { ok: false, error: `repok.ut: ${rup}` }
    const pg = checkStringArray(r.pathGlobok ?? [], 'repok.pathGlobok', MAX_GLOBS, MAX_GLOB_LEN, globProblem)
    if (!pg.ok) return pg
    const tg = checkStringArray(r.tesztGlobok ?? [], 'repok.tesztGlobok', MAX_GLOBS, MAX_GLOB_LEN, globProblem)
    if (!tg.ok) return tg
    repok.push({ nev: rn.value, ut: ru.value, pathGlobok: pg.value, tesztGlobok: tg.value })
  }

  return {
    ok: true,
    value: { slug: slug.value, nev: nev.value, leiras: leiras.value, kartyak: kartyak.value, tagek: tagek.value, repok, tiltasok: tiltasok.value, specUtak: specUtak.value },
  }
}

function readEntry(dir: string, slug: string): RegistryEntry {
  const file = join(dir, `${slug}.json`)
  try {
    const st = lstatSync(file)
    // A symlink could point anywhere; the registry is plain files only.
    if (!st.isFile()) return { slug, ok: false, error: 'not a regular file' }
    if (st.size > MAX_FILE_BYTES) return { slug, ok: false, error: 'file too large' }
    let parsed: unknown
    try {
      parsed = JSON.parse(readFileSync(file, 'utf-8'))
    } catch {
      // The parser's own message can quote file content; keep ours fixed.
      return { slug, ok: false, error: 'invalid JSON' }
    }
    const v = validateFunkcio(parsed, slug)
    return v.ok ? { slug, ok: true, funkcio: v.value } : { slug, ok: false, error: v.error }
  } catch {
    return { slug, ok: false, error: 'unreadable' }
  }
}

/** Every well-named file in the registry dir, sorted by slug. Missing dir -> []. */
export function listRegistry(dir: string): RegistryEntry[] {
  let names: string[]
  try {
    names = readdirSync(dir)
  } catch {
    return []
  }
  const slugs = names
    .filter((n) => n.endsWith('.json'))
    .map((n) => n.slice(0, -'.json'.length))
    .filter((s) => SLUG_RE.test(s))
    .sort()
  return slugs.map((s) => readEntry(dir, s))
}

/** One function by slug. The slug is regex-checked before it touches a path. */
export function getRegistryEntry(dir: string, slug: string): RegistryEntry | null {
  if (!SLUG_RE.test(slug)) return null
  const entry = readEntry(dir, slug)
  if (!entry.ok && entry.error === 'unreadable') return null // no such file
  return entry
}

// ---------------------------------------------------------------------------
// Repo allowlist
// ---------------------------------------------------------------------------

/** Split the FUNKCIO_REPO_ALLOWLIST setting: comma or whitespace separated. */
export function parseRepoAllowlist(raw: string): string[] {
  return raw.split(/[\s,]+/).map((s) => s.trim()).filter((s) => s.length > 0)
}

function tryRealpath(p: string): string | null {
  try {
    return realpathSync(p)
  } catch {
    return null
  }
}

/**
 * The set of repo roots a registry may point git at, as realpaths: the install
 * root always, plus the entries of the setting. Entries that do not resolve are
 * dropped (nothing to allow).
 */
export function resolveAllowedRepos(installRoot: string, settingValue: string): Set<string> {
  const out = new Set<string>()
  for (const p of [installRoot, ...parseRepoAllowlist(settingValue)]) {
    if (!isAbsolute(p)) continue
    const rp = tryRealpath(p)
    if (rp) out.add(rp)
  }
  return out
}

export type RepoCheck =
  | { ok: true; realPath: string }
  | { ok: false; error: 'repo_missing' | 'repo_not_allowed' }

/** realpath the registry's repo path and require an exact allowlist hit. */
export function checkRepoPath(ut: string, allowed: ReadonlySet<string>): RepoCheck {
  const rp = tryRealpath(ut)
  if (!rp) return { ok: false, error: 'repo_missing' }
  if (!allowed.has(rp)) return { ok: false, error: 'repo_not_allowed' }
  return { ok: true, realPath: rp }
}
