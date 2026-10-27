import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  GIT_MAX_BUFFER, GIT_TIMEOUT_MS, containsToken, createGitLogReader, globToRegExp, gitLogArgs,
  matchCommits, matchesAnyGlob, parseGitLog, prNumberOf, cardRefsIn,
  type ExecFileFn, type RawCommit,
} from '../web/funkciok-git.js'
import { checkRepoPath } from '../web/funkciok-registry.js'

// Card d7b2d5c8 (S1): the git reader and the JS-side matchers. The git fixtures
// are REAL temp repositories (git init in tmp); nothing here touches another repo.

const GIT_ENV = {
  PATH: process.env.PATH,
  HOME: process.env.HOME,
  GIT_CONFIG_NOSYSTEM: '1',
  GIT_AUTHOR_NAME: 'Teszt Elek',
  GIT_AUTHOR_EMAIL: 'teszt@example.invalid',
  GIT_COMMITTER_NAME: 'Teszt Elek',
  GIT_COMMITTER_EMAIL: 'teszt@example.invalid',
}

interface FixtureCommit { msg: string; files: Record<string, string>; at: number }

function git(repo: string, args: string[], extraEnv: Record<string, string> = {}): void {
  execFileSync('git', ['-C', repo, '-c', 'commit.gpgsign=false', '-c', 'init.defaultBranch=main', ...args], {
    env: { ...GIT_ENV, ...extraEnv },
    stdio: 'ignore',
  })
}

function makeRepo(commits: FixtureCommit[]): string {
  const repo = mkdtempSync(join(tmpdir(), 'funkciok-git-'))
  git(repo, ['init', '-q'])
  for (const c of commits) {
    for (const [rel, content] of Object.entries(c.files)) {
      const abs = join(repo, rel)
      mkdirSync(dirname(abs), { recursive: true })
      writeFileSync(abs, content)
    }
    git(repo, ['add', '-A'])
    const date = `${c.at} +0000`
    git(repo, ['commit', '-q', '-m', c.msg], { GIT_AUTHOR_DATE: date, GIT_COMMITTER_DATE: date })
  }
  return repo
}

const T0 = 1_760_000_000
const FIXTURE: FixtureCommit[] = [
  { at: T0 + 10, msg: 'feat: first thing (card 4fbbb27c, N1)', files: { 'src/a.ts': '1', 'src/__tests__/a.test.ts': '1' } },
  { at: T0 + 20, msg: 'chore: tagged work KAPUHATOKOR822 only', files: { 'docs/readme.md': 'x' } },
  { at: T0 + 30, msg: 'fix: touches the gate file (#1234)', files: { 'src/gate/check.ts': '1', 'src/gate/check.test.ts': '1' } },
  { at: T0 + 40, msg: 'refactor: unrelated\n\nBody mentions card 6a52389f here.', files: { 'src/other.ts': '1' } },
  { at: T0 + 50, msg: 'docs: nothing relevant', files: { 'LICENSE': 'x' } },
  { at: T0 + 60, msg: 'feat: second (card 4fbbb27c)', files: { 'src/a.ts': '2', 'src/__tests__/a.test.ts': '2' } },
]

let repo: string
beforeEach(() => { repo = makeRepo(FIXTURE) })
afterEach(() => { rmSync(repo, { recursive: true, force: true }) })

describe('createGitLogReader against a real temp repo', () => {
  it('reads every commit, newest first, with subject, body, files, date and short hash', async () => {
    const r = await createGitLogReader().read(realpathSync(repo))
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.commits).toHaveLength(6)
    expect(r.commits[0].subject).toBe('feat: second (card 4fbbb27c)')
    expect(r.commits[0].date).toBe(T0 + 60)
    expect(r.commits[0].files.sort()).toEqual(['src/__tests__/a.test.ts', 'src/a.ts'])
    expect(r.commits[0].hash).toMatch(/^[0-9a-f]{40}/)
    expect(r.commits[0].short.length).toBeGreaterThanOrEqual(7)
    const withBody = r.commits.find((c) => c.subject === 'refactor: unrelated')!
    expect(withBody.body).toContain('card 6a52389f')
    expect(withBody.files).toEqual(['src/other.ts'])
    expect(r.commits[0].author).toBe('Teszt Elek')
  })

  it('a directory that is not a repo never throws: it is a git_failed result', async () => {
    const empty = mkdtempSync(join(tmpdir(), 'funkciok-nogit-'))
    try {
      // The reader's own environment is explicit, so the outcome is asserted, not the
      // mechanism: a failure carries git_failed (or, were the temp dir inside some
      // enclosing repo, a normal read). Either way the promise resolves.
      const r = await createGitLogReader().read(realpathSync(empty))
      if (!r.ok) expect(r.error).toBe('git_failed')
    } finally {
      rmSync(empty, { recursive: true, force: true })
    }
  })
})

describe('commit matching on the real fixture (card | tag | path)', () => {
  async function commits(): Promise<RawCommit[]> {
    const r = await createGitLogReader().read(realpathSync(repo))
    if (!r.ok) throw new Error('git failed')
    return r.commits
  }
  const subjects = (m: ReturnType<typeof matchCommits>) => m.map((x) => x.commit.subject)

  it('card: subject or body "card <hex8>" of a registry card', async () => {
    const m = matchCommits(await commits(), { cards: new Set(['4fbbb27c', '6a52389f']), tags: [], pathGlobs: [] })
    expect(m.every((x) => x.reason === 'card')).toBe(true)
    expect(subjects(m).sort()).toEqual([
      'feat: first thing (card 4fbbb27c, N1)',
      'feat: second (card 4fbbb27c)',
      'refactor: unrelated',
    ].sort())
  })

  it('tag: a registry tag in the message, with a word boundary', async () => {
    const all = await commits()
    expect(subjects(matchCommits(all, { cards: new Set(), tags: ['KAPUHATOKOR822'], pathGlobs: [] }))).toEqual(['chore: tagged work KAPUHATOKOR822 only'])
    // a tag that is only a prefix of a longer word does not match
    expect(matchCommits(all, { cards: new Set(), tags: ['KAPUHATOKOR82'], pathGlobs: [] })).toHaveLength(0)
  })

  it('path: a changed file matching a path glob', async () => {
    const m = matchCommits(await commits(), { cards: new Set(), tags: [], pathGlobs: ['src/gate/*.ts'] })
    expect(subjects(m)).toEqual(['fix: touches the gate file (#1234)'])
    expect(m[0].reason).toBe('path')
  })

  it('priority when several apply: card beats tag beats path', async () => {
    const m = matchCommits(await commits(), { cards: new Set(['4fbbb27c']), tags: ['first'], pathGlobs: ['src/*.ts'] })
    const first = m.find((x) => x.commit.subject.startsWith('feat: first'))!
    expect(first.reason).toBe('card')
  })

  it('hasCardRef reflects ANY "card <hex8>", not only registry cards (the traceability gap metric)', async () => {
    const m = matchCommits(await commits(), { cards: new Set(), tags: [], pathGlobs: ['src/**', 'docs/*'] })
    const byS = Object.fromEntries(m.map((x) => [x.commit.subject, x.hasCardRef]))
    expect(byS['feat: first thing (card 4fbbb27c, N1)']).toBe(true)
    expect(byS['chore: tagged work KAPUHATOKOR822 only']).toBe(false)
  })

  it('a "-"-prefixed tag or glob is harmless: plain data, matches nothing, spawns no option', async () => {
    const all = await commits()
    const calls: string[][] = []
    const spy: ExecFileFn = async (file, args, opts) => {
      calls.push(args)
      const { execFile } = await import('node:child_process')
      return new Promise((resolve, reject) => {
        execFile(file, args, opts, (e, stdout) => (e ? reject(e) : resolve({ stdout: String(stdout) })))
      })
    }
    const read = await createGitLogReader({ exec: spy }).read(realpathSync(repo))
    expect(read.ok).toBe(true)
    const m = matchCommits(all, { cards: new Set(), tags: ['--output=/tmp/x', '-rf', '--all'], pathGlobs: ['-rf/*', '--exec=x'] })
    expect(m).toHaveLength(0)
    // the argument vector was built from the repo path and fixed strings only
    expect(calls).toHaveLength(1)
    for (const a of calls[0]) {
      expect(a).not.toContain('--output')
      expect(a).not.toContain('-rf')
      expect(a).not.toContain('--exec')
    }
  })

  it('test files: those of the matched commits matching the test globs, last modifying commit first', async () => {
    const all = await commits()
    const m = matchCommits(all, { cards: new Set(['4fbbb27c']), tags: [], pathGlobs: ['src/gate/*.ts'] })
    const seen = new Map<string, string>()
    for (const x of m) for (const f of x.commit.files) {
      if (!seen.has(f) && matchesAnyGlob(f, ['src/**/*.test.ts'])) seen.set(f, x.commit.subject)
    }
    // newest first: a.test.ts was last touched by the "second" commit
    expect(seen.get('src/__tests__/a.test.ts')).toBe('feat: second (card 4fbbb27c)')
    expect(seen.get('src/gate/check.test.ts')).toBe('fix: touches the gate file (#1234)')
  })
})

describe('the git invocation is fixed and shell-free', () => {
  it('gitLogArgs: -C <repo> log with fixed options only', () => {
    const a = gitLogArgs('/some/real/repo')
    expect(a.slice(0, 3)).toEqual(['-C', '/some/real/repo', 'log'])
    expect(a).toContain('--name-only')
    expect(a).toContain('--no-color')
    expect(a.find((x) => x.startsWith('--max-count='))).toBeDefined()
    expect(a.filter((x) => x.startsWith('--format=')).length).toBe(1)
    // no pathspec separator and no free-form tail: nothing a registry string could ride on
    expect(a).not.toContain('--')
    expect(a.some((x) => x.startsWith('--grep') || x.startsWith('--author'))).toBe(false)
  })

  it('execFile is called with "git", an argument ARRAY, a timeout, a maxBuffer and a minimal env', async () => {
    const exec = vi.fn(async () => ({ stdout: '' })) as unknown as ExecFileFn & ReturnType<typeof vi.fn>
    await createGitLogReader({ exec }).read('/abs/repo')
    expect(exec).toHaveBeenCalledTimes(1)
    const [file, args, opts] = (exec as unknown as { mock: { calls: [string, string[], Record<string, unknown>][] } }).mock.calls[0]
    expect(file).toBe('git')
    expect(Array.isArray(args)).toBe(true)
    expect(opts.timeout).toBe(GIT_TIMEOUT_MS)
    expect(opts.maxBuffer).toBe(GIT_MAX_BUFFER)
    expect(opts).not.toHaveProperty('shell')
    const env = opts.env as Record<string, string | undefined>
    expect(Object.keys(env).sort()).toEqual(['GIT_OPTIONAL_LOCKS', 'GIT_TERMINAL_PROMPT', 'HOME', 'LC_ALL', 'PATH'])
  })

  it('S1-5 mechanism: a repo that is not on the allowlist is stopped BEFORE any execFile call', () => {
    const exec = vi.fn(async () => ({ stdout: '' })) as unknown as ExecFileFn
    const reader = createGitLogReader({ exec })
    const check = checkRepoPath(repo, new Set(['/definitely/not/this/repo']))
    expect(check).toEqual({ ok: false, error: 'repo_not_allowed' })
    // the caller gates on check.ok; the reader is never reached
    if (check.ok) void reader.read(check.realPath)
    expect(exec).not.toHaveBeenCalled()
  })

  it('a timeout is reported as git_timeout, a buffer overflow and other failures as git_failed', async () => {
    const killed = (async () => { throw Object.assign(new Error('x'), { killed: true, signal: 'SIGTERM' }) }) as ExecFileFn
    const overflow = (async () => { throw Object.assign(new Error('x'), { killed: true, code: 'ERR_CHILD_PROCESS_STDIO_MAXBUFFER' }) }) as ExecFileFn
    const plain = (async () => { throw Object.assign(new Error('x'), { code: 128 }) }) as ExecFileFn
    expect(await createGitLogReader({ exec: killed }).read('/r')).toEqual({ ok: false, error: 'git_timeout' })
    expect(await createGitLogReader({ exec: overflow }).read('/r')).toEqual({ ok: false, error: 'git_failed' })
    expect(await createGitLogReader({ exec: plain }).read('/r')).toEqual({ ok: false, error: 'git_failed' })
  })
})

describe('10 minute cache', () => {
  it('a second read inside the TTL does not run git; after the TTL it does; errors are not cached', async () => {
    let now = 1_000_000
    const exec = vi.fn(async () => ({ stdout: '' })) as unknown as ExecFileFn
    const reader = createGitLogReader({ exec, now: () => now })
    await reader.read('/r')
    now += 9 * 60 * 1000
    await reader.read('/r')
    expect(exec).toHaveBeenCalledTimes(1)
    now += 2 * 60 * 1000
    await reader.read('/r')
    expect(exec).toHaveBeenCalledTimes(2)

    const failing = vi.fn(async () => { throw new Error('boom') }) as unknown as ExecFileFn
    const r2 = createGitLogReader({ exec: failing, now: () => now })
    await r2.read('/x')
    await r2.read('/x')
    expect(failing).toHaveBeenCalledTimes(2)
  })

  it('concurrent reads of one repo share a single git run; different repos do not share', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    const exec = vi.fn(async () => { await gate; return { stdout: '' } }) as unknown as ExecFileFn
    const reader = createGitLogReader({ exec })
    const a = reader.read('/r1')
    const b = reader.read('/r1')
    const c = reader.read('/r2')
    release()
    await Promise.all([a, b, c])
    expect(exec).toHaveBeenCalledTimes(2)
  })
})

describe('parseGitLog', () => {
  const RS = '\x1e'
  const US = '\x1f'
  const H1 = 'a'.repeat(40)
  const H2 = 'b'.repeat(40)

  it('parses records, keeps a body that contains the field separator, and skips junk records', () => {
    const out = [
      `${RS}${H1}${US}aaaaaaa${US}1700000000${US}Name${US}subject one${US}body${US}more${US}\n\nsrc/x.ts\nsrc/y.ts\n`,
      `${RS}not-a-hash${US}x${US}1${US}n${US}s${US}b${US}\n\nz\n`,
      `${RS}${H2}${US}bbbbbbb${US}1700000100${US}Other${US}subject two${US}${US}\n\n`,
    ].join('')
    const c = parseGitLog(out)
    expect(c).toHaveLength(2)
    expect(c[0]).toMatchObject({ hash: H1, short: 'aaaaaaa', date: 1_700_000_000, author: 'Name', subject: 'subject one', files: ['src/x.ts', 'src/y.ts'] })
    expect(c[0].body).toBe(`body${US}more`)
    expect(c[1].files).toEqual([])
  })

  it('empty output is no commits', () => {
    expect(parseGitLog('')).toEqual([])
  })
})

describe('pure matchers', () => {
  it('containsToken: word boundaries, and non-word-edged tokens', () => {
    expect(containsToken('fix KAPU822 now', 'KAPU822')).toBe(true)
    expect(containsToken('fix XKAPU822 now', 'KAPU822')).toBe(false)
    expect(containsToken('fix KAPU8221 now', 'KAPU822')).toBe(false)
    expect(containsToken('KAPU822', 'KAPU822')).toBe(true)
    expect(containsToken('x --flag y', '--flag')).toBe(true)
    expect(containsToken('', 'a')).toBe(false)
    expect(containsToken('abc', '')).toBe(false)
  })

  it('globToRegExp: * stays in a segment, ** crosses, ? is one char, a trailing / means "below", the rest is literal', () => {
    expect(globToRegExp('src/*.ts').test('src/a.ts')).toBe(true)
    expect(globToRegExp('src/*.ts').test('src/sub/a.ts')).toBe(false)
    expect(globToRegExp('src/**/*.ts').test('src/sub/deep/a.ts')).toBe(true)
    expect(globToRegExp('a?c').test('abc')).toBe(true)
    expect(globToRegExp('a?c').test('a/c')).toBe(false)
    expect(globToRegExp('scripts/hooks/').test('scripts/hooks/x/y.py')).toBe(true)
    expect(globToRegExp('a.b(c)+[d]').test('a.b(c)+[d]')).toBe(true)
    expect(globToRegExp('a.b').test('aXb')).toBe(false)
  })

  it('cardRefsIn and prNumberOf', () => {
    expect(cardRefsIn('x (card 6A52389F, N6) and Card 4fbbb27c')).toEqual(['6a52389f', '4fbbb27c'])
    expect(cardRefsIn('discard 12345678')).toEqual([])
    expect(prNumberOf('fix thing (#2315)')).toBe(2315)
    expect(prNumberOf('fix (#1) then (#22)')).toBe(22)
    expect(prNumberOf('no pr')).toBeNull()
  })
})
