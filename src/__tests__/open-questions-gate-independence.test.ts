import { describe, it, expect } from 'vitest'
import { mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

// Open questions S3-N3 (spec 5.3 / S3-5): a question authorizes NOTHING. No
// approval or authorization gate may read open_questions, so an answer in the
// panel can never open a send, a spend or a consume.
//
// Two layers, both file scans (no network, no DB):
//
//  (a) GATE SET, by a stated rule: every file under scripts/ and src/ (tests,
//      fixtures and node_modules excluded) whose BASENAME matches
//      /gate|approv|authoriz|consume|credit/i. None may mention the table.
//      The set must be non-empty and must contain the two gates the spec names
//      that exist in this tree, so an empty or renamed set cannot go green.
//      Spec-named gates NOT in this tree (graph-send-authorize.ts, credit-gate/,
//      approval-callback-data.ts): not scannable here, the security review
//      checks them by hand on the installed location.
//  (b) READER ALLOWLIST: in the non-test source (src/, scripts/, web/) only the
//      files below may mention the table or its module. A new reader turns this
//      red until it is added HERE, in review.

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..')

const GATE_NAME = /gate|approv|authoriz|consume|credit/i
const TERM = /open[_ -]?questions/i
const SKIP_DIRS = new Set(['node_modules', '__tests__', 'fixtures', 'dist', '.git'])
const TEXT_EXT = /\.(ts|mts|cts|js|mjs|cjs|py|sh|json)$/
const MAX_BYTES = 3 * 1024 * 1024

// Readers of open_questions (posix paths relative to the repo root).
const READERS = [
  /^src\/db\.ts$/,
  /^src\/web\.ts$/, // only mounts the route module
  /^src\/web\/open-questions[^/]*\.ts$/,
  /^src\/web\/routes\/open-questions\.ts$/,
  /^web\/app\.js$/, // the panel (S3-N4)
]

function walk(root: string, top: string): string[] {
  const out: string[] = []
  const visit = (dir: string): void => {
    let names: string[]
    try { names = readdirSync(dir) } catch { return }
    for (const name of names.sort()) {
      if (SKIP_DIRS.has(name)) continue
      const full = join(dir, name)
      let st
      try { st = statSync(full) } catch { continue }
      if (st.isDirectory()) visit(full)
      else if (st.isFile() && TEXT_EXT.test(name) && st.size <= MAX_BYTES) out.push(relative(root, full).split('\\').join('/'))
    }
  }
  visit(join(root, top))
  return out
}

function gateFiles(root: string): string[] {
  const base = (p: string) => p.slice(p.lastIndexOf('/') + 1)
  return [...walk(root, 'scripts'), ...walk(root, 'src')].filter((p) => GATE_NAME.test(base(p)))
}

function mentions(root: string, files: string[]): string[] {
  return files.filter((p) => TERM.test(readFileSync(join(root, p), 'utf8')))
}

function unlistedReaders(root: string): string[] {
  const all = [...walk(root, 'src'), ...walk(root, 'scripts'), ...walk(root, 'web')]
  return mentions(root, all).filter((p) => !READERS.some((re) => re.test(p)))
}

describe('gate set (a)', () => {
  const gates = gateFiles(ROOT)

  it('is non-empty and contains the spec-named gates that exist in this tree', () => {
    expect(gates.length).toBeGreaterThan(10)
    expect(gates).toContain('scripts/hooks/email-approval-gate.py')
    expect(gates).toContain('src/web/routes/approvals.ts')
    expect(gates).toContain('scripts/approval-consume.py')
  })

  it('no gate source mentions open_questions', () => {
    expect(mentions(ROOT, gates)).toEqual([])
  })
})

describe('reader allowlist (b)', () => {
  it('only the listed files mention open_questions (and the listed files exist and do)', () => {
    expect(unlistedReaders(ROOT)).toEqual([])
    const all = [...walk(ROOT, 'src'), ...walk(ROOT, 'scripts'), ...walk(ROOT, 'web')]
    const hits = mentions(ROOT, all)
    expect(hits).toContain('src/db.ts')
    expect(hits).toContain('src/web/open-questions.ts')
    expect(hits).toContain('src/web/routes/open-questions.ts')
  })

  it('the approvals route and the overview keep the direction one-way: the overview reads approvals, approvals never read questions', () => {
    const overview = readFileSync(join(ROOT, 'src/web/open-questions-overview.ts'), 'utf8')
    const cols = /prepare\(`SELECT([^`]*?)FROM approvals/.exec(overview)
    expect(cols).not.toBeNull()
    expect((cols as RegExpExecArray)[1].split(',').map((c) => c.trim())).toEqual(['id', 'agent_id', 'category', 'requested_at'])
    expect(readFileSync(join(ROOT, 'src/web/routes/approvals.ts'), 'utf8')).not.toMatch(TERM)
  })
})

describe('the scan itself is not vacuous', () => {
  it('flags a gate-named file and an unlisted reader in a synthetic tree', () => {
    const tmp = mkdtempSync(join(tmpdir(), 'oq-gate-scan-'))
    try {
      mkdirSync(join(tmp, 'scripts', 'hooks'), { recursive: true })
      mkdirSync(join(tmp, 'src', 'web'), { recursive: true })
      writeFileSync(join(tmp, 'scripts', 'hooks', 'fake-approval-gate.py'), "q = 'SELECT * FROM open_questions'\n")
      writeFileSync(join(tmp, 'scripts', 'hooks', 'clean-gate.py'), "print('ok')\n")
      writeFileSync(join(tmp, 'src', 'web', 'sneaky.ts'), "import './open-questions.js'\n")
      writeFileSync(join(tmp, 'src', 'web', 'open-questions.ts'), '// the table\n')

      const gates = gateFiles(tmp)
      expect(gates.sort()).toEqual(['scripts/hooks/clean-gate.py', 'scripts/hooks/fake-approval-gate.py'])
      expect(mentions(tmp, gates)).toEqual(['scripts/hooks/fake-approval-gate.py'])
      expect(unlistedReaders(tmp).sort()).toEqual(['scripts/hooks/fake-approval-gate.py', 'src/web/sneaky.ts'])
    } finally {
      rmSync(tmp, { recursive: true, force: true })
    }
  })
})
