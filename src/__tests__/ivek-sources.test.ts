import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as nodeFs from 'node:fs'
import {
  mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync, renameSync, utimesSync,
} from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  DEPLOY_LOG_MAX_BYTES, FINDINGS_MAX_BYTES, MAX_BRIEFS, MAX_FINDINGS_LINES,
  listBriefs, listDeployRuns, readFindingsSummary,
  type IvekFs,
} from '../web/ivek-sources.js'

// "Ivek" view (card 46e935d6, N1): the file reader. Fixtures are generated in a
// temp dir; the real 8T folders are never touched.

const MARKER = 'ZQ-MARKER-7f3a91'
const BAD_IDS = ['..', '../..', 'a/../b', '51538ebc/..', '%2e%2e', 'ABCDEF12', '51538EBC', '1234567', '123456789', '5153\0ebc', '', '.', '51538ebg']

let base: string
let ezRoot: string
let depRoot: string

beforeEach(() => {
  base = mkdtempSync(join(tmpdir(), 'ivek-src-'))
  ezRoot = join(base, 'ez')
  depRoot = join(base, 'dep')
  mkdirSync(ezRoot)
  mkdirSync(depRoot)
})
afterEach(() => { rmSync(base, { recursive: true, force: true }) })

function jl(rows: Record<string, unknown>[]): string {
  return rows.map((r) => JSON.stringify(r)).join('\n') + '\n'
}

function putCard(id: string, files: Record<string, string> = {}): string {
  const dir = join(ezRoot, id)
  mkdirSync(dir, { recursive: true })
  for (const [n, c] of Object.entries(files)) writeFileSync(join(dir, n), c)
  return dir
}

/** Counts fs calls; optionally runs a hook before a named call. */
function spyFs(before: Partial<Record<keyof IvekFs, (...a: unknown[]) => void>> = {}): { fsi: IvekFs; calls: string[] } {
  const calls: string[] = []
  const wrap = <K extends keyof IvekFs>(k: K): IvekFs[K] =>
    (((...a: unknown[]) => {
      calls.push(k)
      before[k]?.(...a)
      return (nodeFs[k] as unknown as (...x: unknown[]) => unknown)(...a)
    }) as unknown) as IvekFs[K]
  const fsi: IvekFs = {
    lstatSync: wrap('lstatSync'), realpathSync: wrap('realpathSync'), readdirSync: wrap('readdirSync'),
    openSync: wrap('openSync'), fstatSync: wrap('fstatSync'), readSync: wrap('readSync'), closeSync: wrap('closeSync'),
  }
  return { fsi, calls }
}

const d7b2Like = [
  { id: 'A1', event: 'add', round: 1, reviewer: 'ellenor', severity: 'HIGH', summary: 'x', reason: 'y', location: 'z', ts: '2026-10-30T10:00:00+01:00' },
  { id: 'A2', event: 'add', round: 1, reviewer: 'ellenor', severity: 'LOW', ts: '2026-10-30T10:01:00+01:00' },
  { id: 'A3', event: 'add', round: 2, reviewer: 'be-opus-high', severity: 'MED', ts: '2026-10-30T11:00:00+01:00' },
  { id: 'A1', event: 'close', ts: '2026-10-30T12:00:00+01:00' },
  { id: 'A3', event: 'reject', reason: 'nope', ts: '2026-10-30T12:05:00+01:00' },
]

describe('readFindingsSummary', () => {
  it('aggregates add/close/reject per round and reviewer, close joins its round by id (51538ebc shape)', () => {
    putCard('51538ebc', {
      'findings-log.jsonl': jl([
        { card: '51538ebc', event: 'add', id: 'B2', reviewer: 'be-opus-high', round: 1, severity: 'LOW', summary: 'a', ts: '2026-10-31T19:20:27+01:00' },
        { card: '51538ebc', event: 'add', id: 'B1', reviewer: 'be-opus-high', round: 1, severity: 'HIGH', summary: 'b', ts: '2026-10-31T19:21:00+01:00' },
        { card: '51538ebc', event: 'close', id: 'B1', ts: '2026-10-31T20:00:00+01:00' },
      ]),
    })
    const r = readFindingsSummary(ezRoot, '51538ebc')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.events).toEqual({ add: 2, close: 1, reject: 0 })
    expect(r.rounds).toHaveLength(1)
    expect(r.rounds[0]).toEqual({
      round: 1, reviewer: 'be-opus-high', bySeverity: { HIGH: 1, MED: 0, LOW: 1, OTHER: 0 }, add: 2, close: 1, reject: 0,
    })
    expect(r.lastTs).toBe(new Date('2026-10-31T20:00:00+01:00').toISOString())
  })

  it('handles a d7b2d5c8-shaped log: rounds 1 and 2, rows without round, reject', () => {
    putCard('d7b2d5c8', { 'findings-log.jsonl': jl(d7b2Like) })
    const r = readFindingsSummary(ezRoot, 'd7b2d5c8')
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.events).toEqual({ add: 3, close: 1, reject: 1 })
    expect(r.rounds.map((g) => [g.round, g.reviewer, g.add, g.close, g.reject])).toEqual([
      [1, 'ellenor', 2, 1, 0],
      [2, 'be-opus-high', 1, 0, 1],
    ])
  })

  it('an add without round lands in round null (sorted last); a close without a matching add too', () => {
    putCard('aaaaaaaa', {
      'findings-log.jsonl': jl([
        { id: 'N1', event: 'add', reviewer: 'r', severity: 'HIGH' },
        { id: 'N2', event: 'add', round: 1, reviewer: 'r', severity: 'WEIRD' },
        { id: 'ZZ', event: 'close' },
      ]),
    })
    const r = readFindingsSummary(ezRoot, 'aaaaaaaa')
    if (!r.ok) throw new Error('expected ok')
    expect(r.rounds[0].round).toBe(1)
    expect(r.rounds[0].bySeverity.OTHER).toBe(1)
    const nul = r.rounds.filter((g) => g.round === null)
    expect(nul.length).toBeGreaterThan(0)
    expect(r.rounds[r.rounds.length - 1].round).toBeNull()
    expect(r.lastTs).toBeNull()
  })

  it('skips malformed lines, non-objects, unknown events; does not throw', () => {
    putCard('bbbbbbbb', {
      'findings-log.jsonl': [
        '{not json', '', '[1,2]', '"str"', 'null', '123',
        JSON.stringify({ event: 'hack', id: 'X' }),
        JSON.stringify({ id: 'OK1', event: 'add', round: 1, reviewer: 'r', severity: 'low' }),
        '{"id":"OK2","event":"add","round":1,"reviewer":"r","severity":"HIGH"',
      ].join('\n'),
    })
    const r = readFindingsSummary(ezRoot, 'bbbbbbbb')
    if (!r.ok) throw new Error('expected ok')
    expect(r.events).toEqual({ add: 1, close: 0, reject: 0 })
    expect(r.rounds[0].bySeverity.LOW).toBe(1)
  })

  it('normalises hostile field values (reviewer charset/length, round range, ts)', () => {
    putCard('cccccccc', {
      'findings-log.jsonl': jl([
        { id: 'A', event: 'add', round: 5000, reviewer: `<img src=x onerror=${MARKER}>`, severity: 'HIGH', ts: 'not a date' },
        { id: 'B', event: 'add', round: 1.5, reviewer: 'x'.repeat(65), severity: 'HIGH' },
        { id: 'C', event: 'add', round: -1, reviewer: 'ok-name', severity: 7 },
      ]),
    })
    const r = readFindingsSummary(ezRoot, 'cccccccc')
    if (!r.ok) throw new Error('expected ok')
    expect(JSON.stringify(r)).not.toContain(MARKER)
    expect(JSON.stringify(r)).not.toContain('onerror')
    for (const g of r.rounds) {
      expect(g.round).toBeNull()
      expect(g.reviewer).toMatch(/^[A-Za-z0-9._-]{1,64}$/)
    }
    expect(r.lastTs).toBeNull()
  })

  it('MARKER: a marker in summary / reason / location / fingerprint never reaches the output', () => {
    putCard('dddddddd', {
      'findings-log.jsonl': jl([
        { id: 'A', event: 'add', round: 1, reviewer: 'r', severity: 'HIGH', summary: `s ${MARKER}`, reason: `r ${MARKER}`, location: `/etc/${MARKER}`, fingerprint: MARKER, kind: MARKER, class: MARKER },
        { id: 'A', event: 'reject', reason: MARKER, summary: MARKER },
      ]),
    })
    const r = readFindingsSummary(ezRoot, 'dddddddd')
    expect(r.ok).toBe(true)
    expect(JSON.stringify(r)).not.toContain(MARKER)
  })

  it('caps the number of processed lines', () => {
    const row = JSON.stringify({ id: 'A', event: 'add', round: 1, reviewer: 'r', severity: 'LOW' })
    putCard('eeeeeeee', { 'findings-log.jsonl': Array(MAX_FINDINGS_LINES + 500).fill(row).join('\n') })
    const r = readFindingsSummary(ezRoot, 'eeeeeeee')
    if (!r.ok) throw new Error('expected ok')
    expect(r.events.add).toBe(MAX_FINDINGS_LINES)
  })

  it('oversize log (1 MiB + 1) is too_large and is never opened', () => {
    putCard('ffffffff', { 'findings-log.jsonl': 'a'.repeat(FINDINGS_MAX_BYTES + 1) })
    const { fsi, calls } = spyFs()
    const r = readFindingsSummary(ezRoot, 'ffffffff', fsi)
    expect(r).toEqual({ ok: false, reason: 'too_large' })
    expect(calls).not.toContain('openSync')
    expect(calls).not.toContain('readSync')
  })

  it('a log of exactly 1 MiB is still read', () => {
    const line = JSON.stringify({ id: 'A', event: 'add', round: 1, reviewer: 'r', severity: 'LOW' })
    const pad = FINDINGS_MAX_BYTES - line.length - 1
    putCard('11111111', { 'findings-log.jsonl': ' '.repeat(pad) + '\n' + line })
    expect(Buffer.byteLength(' '.repeat(pad) + '\n' + line)).toBe(FINDINGS_MAX_BYTES)
    const r = readFindingsSummary(ezRoot, '11111111')
    expect(r.ok).toBe(true)
  })

  it('a file that grows after the stat is still bounded (read cap)', () => {
    const dir = putCard('22222222', { 'findings-log.jsonl': 'x\n' })
    const { fsi } = spyFs({
      openSync: () => { writeFileSync(join(dir, 'findings-log.jsonl'), 'a'.repeat(FINDINGS_MAX_BYTES + 10)) },
    })
    // same inode (in-place write), so only the fstat size / read cap can catch it
    const r = readFindingsSummary(ezRoot, '22222222', fsi)
    expect(r).toEqual({ ok: false, reason: 'too_large' })
  })

  it('missing card folder / missing log / missing root', () => {
    expect(readFindingsSummary(ezRoot, '33333333')).toEqual({ ok: false, reason: 'missing' })
    putCard('44444444')
    expect(readFindingsSummary(ezRoot, '44444444')).toEqual({ ok: false, reason: 'missing' })
    expect(readFindingsSummary(join(base, 'no-mount'), '44444444')).toEqual({ ok: false, reason: 'missing' })
  })

  it('a directory named findings-log.jsonl is not_regular', () => {
    const dir = putCard('55555555')
    mkdirSync(join(dir, 'findings-log.jsonl'))
    expect(readFindingsSummary(ezRoot, '55555555')).toEqual({ ok: false, reason: 'not_regular' })
  })

  it('symlink findings-log (inside and outside the root) is refused', () => {
    const outside = join(base, 'outside.jsonl')
    writeFileSync(outside, jl(d7b2Like))
    const dir = putCard('66666666')
    symlinkSync(outside, join(dir, 'findings-log.jsonl'))
    expect(readFindingsSummary(ezRoot, '66666666')).toEqual({ ok: false, reason: 'symlink' })

    const dir2 = putCard('77777777', { 'real.jsonl': jl(d7b2Like) })
    symlinkSync(join(dir2, 'real.jsonl'), join(dir2, 'findings-log.jsonl'))
    expect(readFindingsSummary(ezRoot, '77777777')).toEqual({ ok: false, reason: 'symlink' })
  })

  it('symlink card folder (to inside and to outside the root) is refused', () => {
    const outDir = join(base, 'outdir')
    mkdirSync(outDir)
    writeFileSync(join(outDir, 'findings-log.jsonl'), jl(d7b2Like))
    symlinkSync(outDir, join(ezRoot, '88888888'))
    expect(readFindingsSummary(ezRoot, '88888888')).toEqual({ ok: false, reason: 'symlink' })
    expect(listBriefs(ezRoot, '88888888')).toEqual({ ok: false, reason: 'symlink' })

    putCard('99999999', { 'findings-log.jsonl': jl(d7b2Like) })
    symlinkSync(join(ezRoot, '99999999'), join(ezRoot, 'abababab'))
    expect(readFindingsSummary(ezRoot, 'abababab')).toEqual({ ok: false, reason: 'symlink' })
  })

  it('a file swapped for another one between lstat and open is refused (inode check)', () => {
    const dir = putCard('12121212', { 'findings-log.jsonl': jl(d7b2Like) })
    const other = join(dir, 'other.jsonl')
    writeFileSync(other, jl(d7b2Like))
    const { fsi } = spyFs({
      openSync: () => { renameSync(other, join(dir, 'findings-log.jsonl')) },
    })
    expect(readFindingsSummary(ezRoot, '12121212', fsi)).toEqual({ ok: false, reason: 'unreadable' })
  })

  it('a file swapped for a symlink between lstat and open is refused (O_NOFOLLOW)', () => {
    const dir = putCard('13131313', { 'findings-log.jsonl': jl(d7b2Like) })
    const target = join(base, 'target.jsonl')
    writeFileSync(target, jl(d7b2Like))
    const { fsi } = spyFs({
      openSync: () => {
        rmSync(join(dir, 'findings-log.jsonl'))
        symlinkSync(target, join(dir, 'findings-log.jsonl'))
      },
    })
    const r = readFindingsSummary(ezRoot, '13131313', fsi)
    expect(r.ok).toBe(false)
  })

  it('the root itself may be a symlink (8T mount): its realpath counts', () => {
    putCard('14141414', { 'findings-log.jsonl': jl(d7b2Like) })
    const link = join(base, 'mount-link')
    symlinkSync(ezRoot, link)
    expect(readFindingsSummary(link, '14141414').ok).toBe(true)
  })

  it('errors carry no absolute path or errno text', () => {
    const outDir = join(base, 'secret-out')
    mkdirSync(outDir)
    symlinkSync(outDir, join(ezRoot, '15151515'))
    for (const r of [
      readFindingsSummary(ezRoot, '15151515'),
      readFindingsSummary(join(base, 'gone'), '15151515'),
      readFindingsSummary(ezRoot, '..'),
    ]) {
      expect(Object.keys(r)).toEqual(['ok', 'reason'])
      const s = JSON.stringify(r)
      expect(s).not.toContain(base)
      expect(s).not.toContain('/')
      expect(s).not.toMatch(/ENOENT|EACCES|ELOOP/)
    }
  })
})

describe('bad ids', () => {
  it.each(BAD_IDS)('id %j -> bad_id without a single fs call', (id) => {
    const a = spyFs(); const b = spyFs(); const c = spyFs()
    expect(readFindingsSummary(ezRoot, id, a.fsi)).toEqual({ ok: false, reason: 'bad_id' })
    expect(listBriefs(ezRoot, id, b.fsi)).toEqual({ ok: false, reason: 'bad_id' })
    expect(listDeployRuns(depRoot, id, c.fsi)).toEqual({ ok: false, reason: 'bad_id' })
    expect(a.calls).toEqual([])
    expect(b.calls).toEqual([])
    expect(c.calls).toEqual([])
  })

  it('non-string ids are bad_id too', () => {
    const { fsi, calls } = spyFs()
    expect(readFindingsSummary(ezRoot, undefined as unknown as string, fsi)).toEqual({ ok: false, reason: 'bad_id' })
    expect(readFindingsSummary(ezRoot, ['51538ebc'] as unknown as string, fsi)).toEqual({ ok: false, reason: 'bad_id' })
    expect(calls).toEqual([])
  })
})

describe('listBriefs', () => {
  it('lists only *brief*.md names with mtime, never opens a file, marker in content does not leak', () => {
    const dir = putCard('d7b2d5c8', {
      'brief.md': `# ${MARKER}`, 'brief-r3.md': MARKER, 'brief-r4.md': MARKER,
      'spec.md': MARKER, 'notes.txt': MARKER, 'brief.md.bak': MARKER, 'findings-log.jsonl': '',
    })
    const t = new Date('2026-10-30T12:00:00Z')
    utimesSync(join(dir, 'brief-r3.md'), t, t)
    const { fsi, calls } = spyFs()
    const r = listBriefs(ezRoot, 'd7b2d5c8', fsi)
    if (!r.ok) throw new Error('expected ok')
    expect(r.files.map((f) => f.name)).toEqual(['brief-r3.md', 'brief-r4.md', 'brief.md'])
    expect(r.files[0].mtime).toBe(t.getTime())
    expect(JSON.stringify(r)).not.toContain(MARKER)
    expect(calls).not.toContain('openSync')
    expect(calls).not.toContain('readSync')
  })

  it('skips a symlinked brief and a directory named like a brief', () => {
    const dir = putCard('16161616', { 'brief-a.md': 'x' })
    const outside = join(base, 'outside-brief.md')
    writeFileSync(outside, 'x')
    symlinkSync(outside, join(dir, 'brief-link.md'))
    mkdirSync(join(dir, 'brief-dir.md'))
    const r = listBriefs(ezRoot, '16161616')
    if (!r.ok) throw new Error('expected ok')
    expect(r.files.map((f) => f.name)).toEqual(['brief-a.md'])
  })

  it('caps at 200 files', () => {
    const files: Record<string, string> = {}
    for (let i = 0; i < MAX_BRIEFS + 30; i++) files[`brief-${String(i).padStart(4, '0')}.md`] = ''
    putCard('17171717', files)
    const r = listBriefs(ezRoot, '17171717')
    if (!r.ok) throw new Error('expected ok')
    expect(r.files).toHaveLength(MAX_BRIEFS)
  })

  it('missing card folder -> missing; no briefs -> ok with an empty list', () => {
    expect(listBriefs(ezRoot, '18181818')).toEqual({ ok: false, reason: 'missing' })
    putCard('19191919', { 'spec.md': '' })
    expect(listBriefs(ezRoot, '19191919')).toEqual({ ok: true, files: [] })
  })
})

describe('listDeployRuns', () => {
  const firstLine = 'base=4617a805562b8b469de368c65911160cb4952b17 tip=9d75d5e0de58aa6f60e6b3e667bc12784658f717 files=6 branch=main head=4617a805562b8b469de368c65911160cb4952b17\n'

  function putDeploy(folder: string, files: Record<string, string>): string {
    const dir = join(depRoot, folder)
    mkdirSync(dir, { recursive: true })
    for (const [n, c] of Object.entries(files)) writeFileSync(join(dir, n), c)
    return dir
  }

  it('51538ebc shape: 2 check + 1 apply, apply ok, base -> tip, files 6, sorted by time', () => {
    putDeploy('51538ebc', {
      'deploy-20261031-212522-apply.log': firstLine + 'M a.ts\nM b.ts\nAPPLY OK: HEAD=9d75d5e0, dist built.\n',
      'deploy-20261031-211857-check.log': firstLine + 'CHECK OK: ff-only possible, 6 files clean\n',
      'deploy-20261031-212514-check.log': firstLine + 'CHECK OK: ff-only possible, 6 files clean\n',
      'notes.txt': 'ignored',
    })
    const r = listDeployRuns(depRoot, '51538ebc')
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs.map((x) => [x.mode, x.at, x.result])).toEqual([
      ['check', '2026-10-31T21:18:57', 'ok'],
      ['check', '2026-10-31T21:25:14', 'ok'],
      ['apply', '2026-10-31T21:25:22', 'ok'],
    ])
    for (const x of r.runs) expect([x.base, x.tip, x.files]).toEqual(['4617a805', '9d75d5e0', 6])
  })

  it('multi-card folder matches by exact hex8 tokens; a longer token or prefix does not', () => {
    putDeploy('f8343ced-6308e55d', { 'deploy-20261030-100000-check.log': firstLine + 'CHECK OK\n' })
    putDeploy('51538ebc0', { 'deploy-20261030-100000-check.log': firstLine + 'CHECK OK\n' })
    putDeploy('x51538ebc', { 'deploy-20261030-100000-check.log': firstLine + 'CHECK OK\n' })
    expect(listDeployRuns(depRoot, 'f8343ced')).toMatchObject({ ok: true })
    expect(listDeployRuns(depRoot, '6308e55d')).toMatchObject({ ok: true })
    const r = listDeployRuns(depRoot, '51538ebc')
    expect(r).toEqual({ ok: false, reason: 'missing' })
    const r2 = listDeployRuns(depRoot, 'f8343ced')
    if (!r2.ok) throw new Error('expected ok')
    expect(r2.runs).toHaveLength(1)
  })

  it('status enum: refused / fail / unknown / rollback', () => {
    putDeploy('aaaa1111', {
      'deploy-20261030-100000-check.log': firstLine + 'REFUSED: tree dirty\n',
      'deploy-20261030-100100-apply.log': firstLine + 'FAIL: build broke\n',
      'deploy-20261030-100200-check.log': firstLine + 'nothing useful\n',
      'deploy-20261030-100300-rollback.log': 'garbage first line\nROLLBACK OK: reset\n',
    })
    const r = listDeployRuns(depRoot, 'aaaa1111')
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs.map((x) => x.result)).toEqual(['refused', 'fail', 'unknown', 'ok'])
    expect(r.runs[3]).toMatchObject({ mode: 'rollback', base: null, tip: null, files: null })
  })

  it('MARKER: file list, status line text and build output never leak; only enum/short hashes/count', () => {
    putDeploy('bbbb2222', {
      'deploy-20261030-100000-apply.log':
        firstLine + `M src/${MARKER}.ts\nbuild output ${MARKER}\nAPPLY OK: ${MARKER} /Users/x/${MARKER}\n`,
      'deploy-20261030-100100-check.log': `base=${'a'.repeat(40)} tip=${'b'.repeat(40)} files=3 ${MARKER}\nREFUSED: ${MARKER}\n`,
    })
    const r = listDeployRuns(depRoot, 'bbbb2222')
    expect(r.ok).toBe(true)
    expect(JSON.stringify(r)).not.toContain(MARKER)
    expect(JSON.stringify(r)).not.toContain('/Users')
  })

  it('a first line that does not match the strict shape yields nulls, not the raw text', () => {
    putDeploy('cccc3333', {
      'deploy-20261030-100000-check.log': `base=ZZZ tip=${MARKER} files=-1\nCHECK OK\n`,
    })
    const r = listDeployRuns(depRoot, 'cccc3333')
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs[0]).toMatchObject({ base: null, tip: null, files: null, result: 'ok' })
    expect(JSON.stringify(r)).not.toContain(MARKER)
  })

  it('oversize log (64 KiB + 1) is skipped without being opened', () => {
    putDeploy('dddd4444', {
      'deploy-20261030-100000-check.log': 'a'.repeat(DEPLOY_LOG_MAX_BYTES + 1),
      'deploy-20261030-100100-check.log': firstLine + 'CHECK OK\n',
    })
    const { fsi, calls } = spyFs()
    const r = listDeployRuns(depRoot, 'dddd4444', fsi)
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs).toHaveLength(1)
    expect(r.runs[0].at).toBe('2026-10-30T10:01:00')
    expect(calls.filter((c) => c === 'openSync')).toHaveLength(1)
  })

  it('symlinked deploy folder is refused; symlinked deploy log is skipped', () => {
    const outDir = join(base, 'out-deploy')
    mkdirSync(outDir)
    writeFileSync(join(outDir, 'deploy-20261030-100000-check.log'), firstLine + 'CHECK OK\n')
    symlinkSync(outDir, join(depRoot, 'eeee5555'))
    expect(listDeployRuns(depRoot, 'eeee5555')).toEqual({ ok: false, reason: 'symlink' })

    const dir = putDeploy('ffff6666', { 'deploy-20261030-100100-check.log': firstLine + 'CHECK OK\n' })
    const outside = join(base, 'outside.log')
    writeFileSync(outside, firstLine + 'APPLY OK\n')
    symlinkSync(outside, join(dir, 'deploy-20261030-100000-apply.log'))
    const r = listDeployRuns(depRoot, 'ffff6666')
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs.map((x) => x.mode)).toEqual(['check'])
  })

  it('bad timestamps in the file name are skipped', () => {
    putDeploy('abcd7777', {
      'deploy-20261340-100000-check.log': firstLine,
      'deploy-20261030-256100-check.log': firstLine,
      'deploy-20261030-100000-check.log': firstLine + 'CHECK OK\n',
    })
    const r = listDeployRuns(depRoot, 'abcd7777')
    if (!r.ok) throw new Error('expected ok')
    expect(r.runs).toHaveLength(1)
  })

  it('missing deploy root (no mount) -> missing, no throw', () => {
    expect(listDeployRuns(join(base, 'nope'), '51538ebc')).toEqual({ ok: false, reason: 'missing' })
  })
})
