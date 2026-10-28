import { execFile as nodeExecFile } from 'node:child_process'

// Card d7b2d5c8 (S1): the git side of the function page.
//
// The ONLY process this feature spawns is `git -C <realpath> log <fixed args>`
// through execFile (no shell). The repo path arrives already realpath'd and
// allowlist-checked (funkciok-registry.ts), and is absolute, so it cannot be
// read as an option. Registry strings (tags, globs, card ids) NEVER reach git:
// the log is read whole and filtered here, in JS.

export const GIT_TIMEOUT_MS = 5000
export const GIT_MAX_BUFFER = 64 * 1024 * 1024
export const GIT_MAX_COMMITS = 20000
export const GIT_CACHE_TTL_MS = 10 * 60 * 1000
const GIT_CACHE_MAX_ENTRIES = 16

// Record separator opens a commit, unit separator splits its fields; the
// --name-only file list follows the format on its own lines.
const RS = '\x1e'
const US = '\x1f'
const GIT_FORMAT = `--format=%x1e%H%x1f%h%x1f%ct%x1f%an%x1f%s%x1f%b%x1f`

export interface RawCommit {
  hash: string
  short: string
  /** Committer date, unix seconds. */
  date: number
  author: string
  subject: string
  body: string
  files: string[]
}

export type ExecFileFn = (
  file: string,
  args: string[],
  opts: { timeout: number; maxBuffer: number; env: NodeJS.ProcessEnv; encoding: 'utf8' },
) => Promise<{ stdout: string }>

const defaultExecFile: ExecFileFn = (file, args, opts) =>
  new Promise((resolve, reject) => {
    nodeExecFile(file, args, opts, (err, stdout) => {
      if (err) reject(err)
      else resolve({ stdout: String(stdout) })
    })
  })

export type GitError = 'git_timeout' | 'git_failed'

export type GitLogResult =
  | { ok: true; commits: RawCommit[] }
  | { ok: false; error: GitError }

function gitEnv(): NodeJS.ProcessEnv {
  // Minimal, explicit environment: no inherited GIT_DIR / GIT_* redirection.
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LC_ALL: 'C',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
  }
}

/** The fixed argument vector. Exported so a test can pin it. */
export function gitLogArgs(realRepo: string): string[] {
  // core.quotepath=off: non-ASCII file names come back as UTF-8, not as quoted octal escapes.
  return ['-C', realRepo, '-c', 'core.quotepath=off', 'log', '--no-color', '--no-show-signature', `--max-count=${GIT_MAX_COMMITS}`, '--name-only', GIT_FORMAT]
}

const HASH_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/

export function parseGitLog(stdout: string): RawCommit[] {
  const out: RawCommit[] = []
  for (const chunk of stdout.split(RS)) {
    if (!chunk) continue
    const fields = chunk.split(US)
    // hash, short, date, author, subject, body..., files
    if (fields.length < 7) continue
    const [hash, short, ct, author, subject] = fields
    if (!HASH_RE.test(hash)) continue
    const date = Number(ct)
    if (!Number.isFinite(date)) continue
    const filesBlock = fields[fields.length - 1]
    const body = fields.slice(5, -1).join(US)
    const files = filesBlock.split('\n').map((l) => l.trim()).filter((l) => l.length > 0)
    out.push({ hash, short, date, author, subject, body: body.trim(), files })
  }
  return out
}

interface CacheEntry { at: number; commits: RawCommit[] }

export interface GitLogReader {
  read(realRepo: string): Promise<GitLogResult>
  clear(): void
}

/**
 * The cached reader. The key is the repo alone: the filters never reach git, so
 * the git output depends on nothing else (a strictly smaller key than
 * repo+filters, same effect). Concurrent callers for one repo share one run.
 */
export function createGitLogReader(opts: { exec?: ExecFileFn; now?: () => number; ttlMs?: number } = {}): GitLogReader {
  const exec = opts.exec ?? defaultExecFile
  const now = opts.now ?? Date.now
  const ttl = opts.ttlMs ?? GIT_CACHE_TTL_MS
  const cache = new Map<string, CacheEntry>()
  const inflight = new Map<string, Promise<GitLogResult>>()

  async function run(realRepo: string): Promise<GitLogResult> {
    try {
      const { stdout } = await exec('git', gitLogArgs(realRepo), {
        timeout: GIT_TIMEOUT_MS,
        maxBuffer: GIT_MAX_BUFFER,
        env: gitEnv(),
        encoding: 'utf8',
      })
      const commits = parseGitLog(stdout)
      cache.set(realRepo, { at: now(), commits })
      while (cache.size > GIT_CACHE_MAX_ENTRIES) {
        const oldest = cache.keys().next().value
        if (oldest === undefined) break
        cache.delete(oldest)
      }
      return { ok: true, commits }
    } catch (err) {
      const e = err as { killed?: boolean; signal?: string; code?: unknown }
      // An overflowing buffer also kills the child; that is a failure, not a timeout.
      const overflow = e?.code === 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER'
      return { ok: false, error: !overflow && e && (e.killed || e.signal === 'SIGTERM') ? 'git_timeout' : 'git_failed' }
    }
  }

  return {
    async read(realRepo) {
      const hit = cache.get(realRepo)
      if (hit && now() - hit.at < ttl) return { ok: true, commits: hit.commits }
      const pending = inflight.get(realRepo)
      if (pending) return pending
      const p = run(realRepo).finally(() => { inflight.delete(realRepo) })
      inflight.set(realRepo, p)
      return p
    },
    clear() {
      cache.clear()
    },
  }
}

// ---------------------------------------------------------------------------
// Matching (pure, JS only)
// ---------------------------------------------------------------------------

export type MatchReason = 'card' | 'tag' | 'path'

const WORD_CHAR = /[A-Za-z0-9_]/

/** True when `token` occurs in `text` not glued to a word character on either side. */
export function containsToken(text: string, token: string): boolean {
  if (!token) return false
  let from = 0
  for (;;) {
    const i = text.indexOf(token, from)
    if (i === -1) return false
    const before = i === 0 ? '' : text[i - 1]
    const after = text[i + token.length] ?? ''
    const startOk = !WORD_CHAR.test(token[0]) || before === '' || !WORD_CHAR.test(before)
    const endOk = !WORD_CHAR.test(token[token.length - 1]) || after === '' || !WORD_CHAR.test(after)
    if (startOk && endOk) return true
    from = i + 1
  }
}

const globCache = new Map<string, RegExp>()

/**
 * Compile a registry glob into an anchored regex. `**` crosses directories,
 * `*` and `?` do not; a trailing `/` means "everything below". Every other
 * character is matched literally (escaped), so no registry text becomes regex
 * syntax. Wildcard runs are capped at validation time.
 */
export function globToRegExp(glob: string): RegExp {
  const cached = globCache.get(glob)
  if (cached) return cached
  let g = glob.startsWith('./') ? glob.slice(2) : glob
  if (g.endsWith('/')) g += '**'
  let re = ''
  for (let i = 0; i < g.length; ) {
    const c = g[i]
    if (c === '*') {
      let j = i
      while (g[j] === '*') j++
      if (j - i >= 2) {
        // "**/" is zero or more whole directories; a bare "**" crosses anything.
        if (g[j] === '/') { re += '(?:.*/)?'; j++ } else re += '.*'
      } else re += '[^/]*'
      i = j
    } else if (c === '?') {
      re += '[^/]'
      i++
    } else {
      re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&')
      i++
    }
  }
  const compiled = new RegExp(`^${re}$`)
  if (globCache.size > 500) globCache.clear()
  globCache.set(glob, compiled)
  return compiled
}

export function matchesAnyGlob(file: string, globs: readonly string[]): boolean {
  return globs.some((g) => globToRegExp(g).test(file))
}

const CARD_REF_RE = /\bcard\s+([0-9a-f]{8})\b/gi

/** Every `card <hex8>` reference in a commit message, lowercased. */
export function cardRefsIn(text: string): string[] {
  const out: string[] = []
  for (const m of text.matchAll(CARD_REF_RE)) out.push(m[1].toLowerCase())
  return out
}

export interface CommitFilters {
  cards: ReadonlySet<string>
  tags: readonly string[]
  pathGlobs: readonly string[]
}

export interface MatchedCommit {
  commit: RawCommit
  reason: MatchReason
  hasCardRef: boolean
}

/** Filter the raw log. Priority when several apply: card, then tag, then path. */
export function matchCommits(commits: readonly RawCommit[], f: CommitFilters): MatchedCommit[] {
  const out: MatchedCommit[] = []
  for (const c of commits) {
    const text = `${c.subject}\n${c.body}`
    const refs = cardRefsIn(text)
    let reason: MatchReason | null = null
    if (refs.some((r) => f.cards.has(r))) reason = 'card'
    else if (f.tags.some((t) => containsToken(text, t))) reason = 'tag'
    else if (f.pathGlobs.length > 0 && c.files.some((file) => matchesAnyGlob(file, f.pathGlobs))) reason = 'path'
    if (reason) out.push({ commit: c, reason, hasCardRef: refs.length > 0 })
  }
  return out
}

/** `(#1234)` PR number from a subject line, null when absent. */
export function prNumberOf(subject: string): number | null {
  let last: number | null = null
  for (const m of subject.matchAll(/\(#(\d{1,7})\)/g)) last = Number(m[1])
  return last
}
