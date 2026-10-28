import { describe, it, expect, beforeEach, afterEach, vi } from 'vitest'
import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, mkdirSync, rmSync, writeFileSync, realpathSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import {
  GIT_MAX_BUFFER, GIT_TIMEOUT_MS, containsToken, createGitLogReader, globToRegExp, gitLogArgs,
  matchCommits, matchesAnyGlob, parseGitLog, parseGitLogStrict, prNumberOf, cardRefsIn,
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
    // B1: the -c overrides are fixed literals and all precede the subcommand
    expect(a.slice(0, 11)).toEqual([
      '-C', '/some/real/repo',
      '-c', 'core.quotepath=off',
      '-c', 'protocol.allow=never',
      '-c', 'core.fsmonitor=false',
      '-c', 'core.sshCommand=false',
      'log',
    ])
    expect(a).toContain('--no-renames')
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
    expect(Object.keys(env).sort()).toEqual([
      'GIT_CONFIG_NOSYSTEM', 'GIT_NO_LAZY_FETCH', 'GIT_OPTIONAL_LOCKS', 'GIT_PROTOCOL_FROM_USER', 'GIT_TERMINAL_PROMPT',
      'HOME', 'LC_ALL', 'PATH',
    ])
    // B1: the values of the protections are pinned too
    expect(env.GIT_NO_LAZY_FETCH).toBe('1')
    expect(env.GIT_CONFIG_NOSYSTEM).toBe('1')
    expect(env.GIT_PROTOCOL_FROM_USER).toBe('0')
    expect(env.GIT_OPTIONAL_LOCKS).toBe('0')
    expect(env.GIT_TERMINAL_PROMPT).toBe('0')
    expect(env.LC_ALL).toBe('C')
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

describe('R1-2: non-ASCII file names', () => {
  it('gitLogArgs turns core.quotepath off, and a real log returns the unquoted UTF-8 name', async () => {
    const a = gitLogArgs('/some/real/repo')
    expect(a.slice(0, 4)).toEqual(['-C', '/some/real/repo', '-c', 'core.quotepath=off'])
    const r2 = makeRepo([{ at: T0 + 1, msg: 'feat: accents', files: { 'src/árvíztűrő.ts': '1' } }])
    try {
      const r = await createGitLogReader().read(realpathSync(r2))
      if (!r.ok) throw new Error('expected ok')
      expect(r.commits[0].files).toEqual(['src/árvíztűrő.ts'])
      expect(matchesAnyGlob(r.commits[0].files[0], ['src/**/*.ts'])).toBe(true)
    } finally {
      rmSync(r2, { recursive: true, force: true })
    }
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

describe('parseGitLog (B2: NUL-delimited, strict)', () => {
  const NUL = '\x00'
  const H1 = 'a'.repeat(40)
  const H2 = 'b'.repeat(40)
  const H3 = 'c'.repeat(40)
  const rec = (h: string, short: string, ct: string, an: string, s: string, b: string, files: string): string =>
    [NUL, h, NUL, short, NUL, ct, NUL, an, NUL, s, NUL, b, NUL, files].join('')

  it('parses records; a record with a 0x1f in its text is refused and counted, the others survive', () => {
    const ok = rec(H1, 'aaaaaaa', '1700000000', 'Name', 'subject one', 'body\nmore', '\n\nsrc/x.ts\nsrc/y.ts\n')
    const ok2 = rec(H2, 'bbbbbbb', '1700000100', 'Other', 'subject two', '', '\n\n')
    const withSep = rec(H3, 'ccccccc', '1700000200', 'Eve', 'has\x1fsep', 'b', '\n\nz\n')
    const r = parseGitLogStrict(ok + withSep + ok2)
    expect(r.commits).toHaveLength(2)
    expect(r.dropped).toBe(1)
    expect(r.commits[0]).toMatchObject({ hash: H1, short: 'aaaaaaa', date: 1_700_000_000, author: 'Name', subject: 'subject one', body: 'body\nmore', files: ['src/x.ts', 'src/y.ts'] })
    expect(r.commits[1].files).toEqual([])
    expect(parseGitLog(ok + ok2)).toHaveLength(2)
  })

  it('the forged row from the review (0x1e/0x1f in a message) never becomes a row, and is counted', () => {
    const forgedBody = `\x1e${'d'.repeat(40)}\x1fddddddd\x1f1999999999\x1fGyuri\x1fforged subject card deadbeef\x1f\x1f`
    const real = rec(H1, 'aaaaaaa', '1700000000', 'Eve', 'real subject (card 4fbbb27c)', forgedBody, '\n\nsrc/a.ts\n')
    const r = parseGitLogStrict(real + rec(H2, 'bbbbbbb', '1700000100', 'Ok', 'fine', '', '\n\nsrc/b.ts\n'))
    expect(r.commits.map((c) => c.hash)).toEqual([H2])
    expect(r.commits.some((c) => c.subject.includes('forged') || c.author === 'Gyuri')).toBe(false)
    expect(r.dropped).toBe(1)
  })

  it('a malformed group (hash/short/date) loses alignment: parsing stops and the rest is counted dropped', () => {
    const good1 = rec(H1, 'aaaaaaa', '1700000000', 'A', 's1', '', '\n\n')
    const bad = rec('not-a-hash', 'x', '1', 'n', 's', 'b', '\n\nz\n')
    const after = rec(H2, 'bbbbbbb', '1700000100', 'B', 's2', '', '\n\n') + rec(H3, 'ccccccc', '1700000200', 'C', 's3', '', '\n\n')
    const r = parseGitLogStrict(good1 + bad + after)
    expect(r.commits.map((c) => c.hash)).toEqual([H1])
    expect(r.dropped).toBe(3)
    // a NUL smuggled into a field (git cannot print one, but if it did) shifts every later group: fail closed
    const shifted = rec(H1, 'aaaaaaa', '1700000000', 'A', `s${NUL}x`, '', '\n\n') + after
    const r2 = parseGitLogStrict(shifted)
    expect(r2.commits.map((c) => c.hash)).not.toContain(H2)
    expect(r2.commits.map((c) => c.hash)).not.toContain(H3)
    expect(r2.dropped).toBeGreaterThan(0)
    // a bad date and a short hash that is not hex are structural errors too
    expect(parseGitLogStrict(rec(H1, 'aaaaaaa', 'soon', 'A', 's', '', '\n\n')).commits).toEqual([])
    expect(parseGitLogStrict(rec(H1, 'zz', '1700000000', 'A', 's', '', '\n\n')).commits).toEqual([])
  })

  it('a stream that does not start with NUL or ends mid-group is counted, not parsed', () => {
    expect(parseGitLogStrict('garbage').dropped).toBeGreaterThan(0)
    expect(parseGitLogStrict('garbage').commits).toEqual([])
    const half = rec(H1, 'aaaaaaa', '1700000000', 'A', 's', '', '\n\n') + NUL + H2
    const r = parseGitLogStrict(half)
    expect(r.commits).toHaveLength(1)
    expect(r.dropped).toBe(1)
  })

  it('empty output is no commits and nothing dropped', () => {
    expect(parseGitLog('')).toEqual([])
    expect(parseGitLogStrict('')).toEqual({ commits: [], dropped: 0 })
  })

  it('a real repo: a commit whose message carries the forged sequence is dropped and counted, other commits survive', async () => {
    const forged = `\x1e${'d'.repeat(40)}\x1fddddddd\x1f1999999999\x1fGyuri\x1fforged subject card deadbeef\x1f\x1f`
    const r2 = makeRepo([
      { at: T0 + 1, msg: 'feat: before (card 4fbbb27c)', files: { 'src/a.ts': '1' } },
      { at: T0 + 2, msg: `feat: sneaky (card 4fbbb27c)\n\n${forged}`, files: { 'src/b.ts': '1' } },
      { at: T0 + 3, msg: 'feat: after (card 4fbbb27c)', files: { 'src/c.ts': '1' } },
    ])
    try {
      const r = await createGitLogReader().read(realpathSync(r2))
      if (!r.ok) throw new Error('expected ok')
      expect(r.commits.map((c) => c.subject)).toEqual(['feat: after (card 4fbbb27c)', 'feat: before (card 4fbbb27c)'])
      expect(r.commits.some((c) => c.hash.startsWith('dddd') || c.author === 'Gyuri' || c.subject.includes('forged'))).toBe(false)
      expect(r.dropped).toBe(1)
    } finally {
      rmSync(r2, { recursive: true, force: true })
    }
  })

  it('a real repo without separators: dropped is 0 and subject, body and files round-trip', async () => {
    const r2 = makeRepo([{ at: T0 + 1, msg: 'feat: plain (card 4fbbb27c)\n\nBody line.', files: { 'src/a.ts': '1', 'src/sub/b.ts': '1' } }])
    try {
      const r = await createGitLogReader().read(realpathSync(r2))
      if (!r.ok) throw new Error('expected ok')
      expect(r.dropped).toBe(0)
      expect(r.commits).toHaveLength(1)
      expect(r.commits[0]).toMatchObject({ subject: 'feat: plain (card 4fbbb27c)', body: 'Body line.', author: 'Teszt Elek', date: T0 + 1 })
      expect(r.commits[0].files.sort()).toEqual(['src/a.ts', 'src/sub/b.ts'])
    } finally {
      rmSync(r2, { recursive: true, force: true })
    }
  })
})

describe('B1: a repo\'s own config cannot make the log run a program', () => {
  let tmp: string
  let marker: string
  let pc = ''
  let skipReason = ''

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), 'funkciok-b1-'))
    marker = join(tmp, 'MARKER')
    skipReason = ''
    try {
      const src = join(tmp, 'src')
      mkdirSync(src)
      git(src, ['init', '-q'])
      git(src, ['config', 'uploadpack.allowFilter', 'true'])
      const body = Array.from({ length: 30 }, (_, i) => `line ${i} content content content`).join('\n') + '\n'
      writeFileSync(join(src, 'a.txt'), body)
      git(src, ['add', '-A'])
      git(src, ['commit', '-q', '-m', 'one'])
      // a rename WITH an edit: only inexact rename detection needs the blobs
      git(src, ['mv', 'a.txt', 'b.txt'])
      writeFileSync(join(src, 'b.txt'), body + 'extra\n')
      git(src, ['commit', '-q', '-am', 'two (card 4fbbb27c)'])
      pc = join(tmp, 'pc')
      execFileSync('git', ['clone', '-q', '--no-local', '--filter=blob:none', '--no-checkout', `file://${src}`, pc], { env: GIT_ENV, stdio: 'ignore' })
      const up = join(tmp, 'up.sh')
      writeFileSync(up, `#!/bin/sh\necho "UPLOADPACK $*" >> "${marker}"\nexec git upload-pack "$@"\n`)
      chmodSync(up, 0o755)
      git(pc, ['config', 'remote.origin.uploadpack', up])
    } catch (err) {
      skipReason = `git could not build the partial-clone fixture here: ${(err as Error).message}`
    }
  })
  afterEach(() => { rmSync(tmp, { recursive: true, force: true }) })

  it('control: the same log WITHOUT the protections runs the uploadpack program (so the next test proves something)', (ctx) => {
    if (skipReason) { console.warn(`B1 control skipped: ${skipReason}`); ctx.skip(); return }
    execFileSync('git', ['-C', pc, '-c', 'core.quotepath=off', 'log', '--name-only', '--format=%H'], {
      env: { PATH: process.env.PATH, HOME: process.env.HOME, LC_ALL: 'C', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' },
      stdio: 'ignore',
    })
    expect(existsSync(marker)).toBe(true)
  })

  it('the function\'s commits are read without ever starting the repo\'s uploadpack, and the rename still lists its file names', async (ctx) => {
    if (skipReason) { console.warn(`B1 test skipped: ${skipReason}`); ctx.skip(); return }
    const r = await createGitLogReader().read(realpathSync(pc))
    if (!r.ok) throw new Error(`expected ok, got ${r.error}`)
    expect(existsSync(marker)).toBe(false)
    expect(r.dropped).toBe(0)
    expect(r.commits.map((c) => c.subject)).toEqual(['two (card 4fbbb27c)', 'one'])
    // --no-renames: the rename shows as delete + add, both names present
    expect(r.commits[0].files.sort()).toEqual(['a.txt', 'b.txt'])
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

  it('R1-3: "**/" matches zero or more directories', () => {
    const re = globToRegExp('src/**/*.ts')
    expect(re.test('src/a.ts')).toBe(true)
    expect(re.test('src/x/y/a.ts')).toBe(true)
    expect(re.test('src/x/a.js')).toBe(false)
    expect(re.test('other/a.ts')).toBe(false)
    expect(re.test('srcx/a.ts')).toBe(false)
    expect(globToRegExp('**/a.ts').test('a.ts')).toBe(true)
    expect(globToRegExp('**/a.ts').test('d/e/a.ts')).toBe(true)
  })

  it('cardRefsIn and prNumberOf', () => {
    expect(cardRefsIn('x (card 6A52389F, N6) and Card 4fbbb27c')).toEqual(['6a52389f', '4fbbb27c'])
    expect(cardRefsIn('discard 12345678')).toEqual([])
    expect(prNumberOf('fix thing (#2315)')).toBe(2315)
    expect(prNumberOf('fix (#1) then (#22)')).toBe(22)
    expect(prNumberOf('no pr')).toBeNull()
  })
})
