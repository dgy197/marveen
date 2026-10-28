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

// B2 (S1 security r1): the fields are NUL-delimited. Git never prints a NUL from
// commit text (a message is a C string to it), so no commit author can write the
// delimiter, unlike the 0x1e/0x1f bytes an earlier layout used (a message
// containing them forged whole rows). Layout per commit:
// NUL H NUL h NUL ct NUL an NUL s NUL b NUL <--name-only block>, so the stream
// split on NUL is "" followed by groups of exactly FIELDS_PER_COMMIT tokens.
const FIELDS_PER_COMMIT = 7
const GIT_FORMAT = `--format=%x00%H%x00%h%x00%ct%x00%an%x00%s%x00%b%x00`

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
  /** `dropped`: records the strict parser refused (see parseGitLogStrict). */
  | { ok: true; commits: RawCommit[]; dropped: number }
  | { ok: false; error: GitError }

/** Exported so a test can pin it. */
export function gitEnv(): NodeJS.ProcessEnv {
  // Minimal, explicit environment: no inherited GIT_DIR / GIT_* redirection.
  // B1: the repo's own config must not make this process run anything. A
  // blobless partial clone would lazy-fetch (rename detection) through the
  // repo's remote.origin.uploadpack / core.sshCommand, so lazy fetch is off,
  // the system config is ignored and user-supplied protocols are not allowed.
  return {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
    LC_ALL: 'C',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    GIT_NO_LAZY_FETCH: '1',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_PROTOCOL_FROM_USER: '0',
  }
}

/** The fixed argument vector. Exported so a test can pin it. */
export function gitLogArgs(realRepo: string): string[] {
  // core.quotepath=off: non-ASCII file names come back as UTF-8, not as quoted octal escapes.
  // B1: protocol.allow=never (no transport at all), core.fsmonitor=false and
  // core.sshCommand=false override whatever the repo's own config carries;
  // --no-renames removes the object lookups that triggered the lazy fetch.
  return [
    '-C', realRepo,
    '-c', 'core.quotepath=off',
    '-c', 'protocol.allow=never',
    '-c', 'core.fsmonitor=false',
    '-c', 'core.sshCommand=false',
    'log', '--no-color', '--no-show-signature', '--no-renames',
    `--max-count=${GIT_MAX_COMMITS}`, '--name-only', GIT_FORMAT,
  ]
}

const HASH_RE = /^[0-9a-f]{40}([0-9a-f]{24})?$/

const SHORT_RE = /^[0-9a-f]{4,64}$/
const DATE_RE = /^\d{1,12}$/
// The old delimiters (and NUL) inside free text: such a record is refused, not repaired.
const CONTROL_SEPARATOR_RE = /[\x00\x1e\x1f]/

export interface ParsedGitLog { commits: RawCommit[]; dropped: number }

/**
 * Strict parse. A record is DROPPED, and counted in `dropped` (the page reports
 * the count as a repo-level error, so nothing vanishes silently), when its
 * author, subject or body carries a control separator (NUL, 0x1e, 0x1f): a
 * commit that tries to forge the old row layout loses its own row and no forged
 * row ever appears. The stream is positional, so a group whose hash, short hash
 * or date is malformed (or a tail that is not a whole group) means the
 * alignment can no longer be trusted: parsing stops there and every remaining
 * group counts as dropped (fail closed).
 */
export function parseGitLogStrict(stdout: string): ParsedGitLog {
  if (stdout === '') return { commits: [], dropped: 0 }
  const tokens = stdout.split('\x00')
  const rest = tokens.length - 1
  const groups = Math.floor(rest / FIELDS_PER_COMMIT)
  const tail = rest % FIELDS_PER_COMMIT === 0 ? 0 : 1
  if (tokens[0] !== '') return { commits: [], dropped: Math.max(1, groups) + tail }
  const out: RawCommit[] = []
  let dropped = tail
  for (let g = 0; g < groups; g++) {
    const base = 1 + g * FIELDS_PER_COMMIT
    const [hash, short, ct, author, subject, body, filesBlock] = tokens.slice(base, base + FIELDS_PER_COMMIT)
    if (!HASH_RE.test(hash) || !SHORT_RE.test(short) || !DATE_RE.test(ct)) {
      dropped += groups - g
      break
    }
    if (CONTROL_SEPARATOR_RE.test(author) || CONTROL_SEPARATOR_RE.test(subject) || CONTROL_SEPARATOR_RE.test(body)) {
      dropped++
      continue
    }
    const files = filesBlock.split('\n').map((l) => l.trim()).filter((l) => l.length > 0)
    out.push({ hash, short, date: Number(ct), author, subject, body: body.trim(), files })
  }
  return { commits: out, dropped }
}

/** The commits of a log, strictly parsed; see parseGitLogStrict for what is refused. */
export function parseGitLog(stdout: string): RawCommit[] {
  return parseGitLogStrict(stdout).commits
}

interface CacheEntry { at: number; commits: RawCommit[]; dropped: number }

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
      const { commits, dropped } = parseGitLogStrict(stdout)
      cache.set(realRepo, { at: now(), commits, dropped })
      while (cache.size > GIT_CACHE_MAX_ENTRIES) {
        const oldest = cache.keys().next().value
        if (oldest === undefined) break
        cache.delete(oldest)
      }
      return { ok: true, commits, dropped }
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
      if (hit && now() - hit.at < ttl) return { ok: true, commits: hit.commits, dropped: hit.dropped }
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
