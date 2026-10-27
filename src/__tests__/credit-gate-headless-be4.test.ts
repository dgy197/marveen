import { describe, it, expect, afterEach } from 'vitest'
import { chmodSync, existsSync, mkdirSync, readFileSync, readdirSync, renameSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parseCreditGateConfig } from '../web/credit-gate/config.js'
import { asMicro } from '../web/credit-gate/money.js'
import { reconcileHeadlessRuns, startHeadlessRuntime } from '../web/credit-gate/headless/reconcile.js'
import { sweepRunsDir, validateCwd, type ProcInfo, type RunOutcome } from '../web/credit-gate/headless/runner.js'
import { setCreditGateRuntime } from '../web/credit-gate/runtime.js'
import { alive, HeadlessHarness, until } from './fixtures/credit-gate/headless-harness.js'
import { configObject } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N4a, the BE-4 round (security review) and the reviewer's
// points. Every test here failed on 9c60a1ac (or, for reviewer 8, on its M4
// mutant) before the fix it pins. No real CLI, no network, no real store;
// processes are injected unless a test says otherwise.

let hh: HeadlessHarness | undefined
/** Real processes a failing test could leave behind (killed after every test). */
const strays: number[] = []
afterEach(() => {
  for (const pid of strays.splice(0)) {
    try { process.kill(pid, 'SIGKILL') } catch { /* gone */ }
  }
  setCreditGateRuntime(null)
  hh?.cleanup()
  hh = undefined
})

type Kill = [number, string | number]

/** A kill spy: signal 0 answers per `aliveSet`, nothing is really signalled. */
function killSpy(kills: Kill[], aliveSet: Set<number> = new Set()) {
  return (pid: number, sig: NodeJS.Signals | 0): void => {
    kills.push([pid, sig])
    if (sig === 0 && !aliveSet.has(pid)) throw Object.assign(new Error('no such process'), { code: 'ESRCH' })
  }
}

const realKills = (kills: Kill[]) => kills.filter(([, s]) => s !== 0)

/** A run id in the generated shape (hr-<uuid>): the only names the sweep enters. */
const RID = (n: number) => `hr-00000000-0000-4000-8000-${String(n).padStart(12, '0')}`

/** The argv a real run's CLI shows in ps: the pinned binary, then the template. */
function leaderCommand(bin: string, runDir: string): string {
  return `${bin} -p --bare --restricted --model claude-sonnet-5-5 --effort high --max-budget-usd 0.40 --output-format json `
    + `--no-session-persistence --settings ${runDir}/settings.json --tools Read --allowedTools Read --permission-mode dontAsk`
}


/** An open run row with its own headless reservation (ref = the row id). */
function insertRow(h: HeadlessHarness, o: { id: string; status: string; pid?: number | null; pgid?: number | null; pidStart?: string | null; runDir?: string }): void {
  const res = h.h.gate.reserve({ kind: 'headless', budget_micro: asMicro(400_000), model: 'claude-sonnet-5-5', ref: o.id, caller: 'ezermester' })
  if (!('ok' in res) || !res.ok) throw new Error(`reserve failed: ${JSON.stringify(res)}`)
  h.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
      config_hash, key_mode, pid, pid_start, pgid, status, started_at, deadline_at, run_dir)
    VALUES (?, 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, 'h', 'helper', ?, ?, ?, ?, ?, ?, ?)`)
    .run(o.id, res.reservation_id, h.worktree, o.pid ?? null, o.pidStart ?? null, o.pgid ?? null, o.status, h.h.now, h.h.now + 60_000, o.runDir ?? h.runDir(o.id))
}

function startOk(h: HeadlessHarness, prompt: string, runner = h.runner) {
  const r = runner.start(h.request(prompt), { caller: 'ezermester' })
  if (!r.ok) throw new Error(`start refused: ${r.reason} ${r.detail ?? ''}`)
  return r
}

describe('BE-4 1: reconcile does not trust the row', () => {
  it('P1: a run_dir outside the runs dir -- lost and booked in full, nothing touched, the gate signalled', () => {
    hh = new HeadlessHarness()
    const victim = join(hh.real, 'victim')
    mkdirSync(join(victim, 'config'), { recursive: true })
    mkdirSync(join(victim, 'home'), { recursive: true })
    writeFileSync(join(victim, 'config', 'precious.txt'), 'user data\n')
    writeFileSync(join(victim, 'notes.md'), 'docs: Anthropic keys start with sk-ant- ...\n')
    const kills: Kill[] = []
    const runner = hh.makeRunner({ listProcesses: () => [], kill: killSpy(kills) })
    insertRow(hh, { id: 'hr-evil', status: 'running', pid: 999999, pgid: 999999, pidStart: 'x', runDir: victim })
    expect(reconcileHeadlessRuns(runner)).toMatchObject({ closed: ['hr-evil'] })
    expect(hh.runRow('hr-evil')).toMatchObject({ status: 'lost', basis: 'headless_reservation', est_micro: 600_000 })
    expect(String(hh.runRow('hr-evil').reason)).toMatch(/^untrusted_row/)
    expect(readdirSync(victim).sort()).toEqual(['config', 'home', 'notes.md'])
    expect(readFileSync(join(victim, 'config', 'precious.txt'), 'utf8')).toBe('user data\n')
    expect(realKills(kills)).toEqual([])
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })

  it('P1b: a forged pid -- members of that process group are never signalled', () => {
    hh = new HeadlessHarness()
    const kills: Kill[] = []
    const procs: ProcInfo[] = [
      { pid: 4242, pgid: 777777, start: 'Mon', command: '/usr/bin/vim notes' },
      { pid: 4343, pgid: 777777, start: 'Mon', command: '/bin/zsh' },
    ]
    const runner = hh.makeRunner({ listProcesses: () => procs, kill: killSpy(kills), procStart: () => null })
    insertRow(hh, { id: 'hr-pg', status: 'running', pid: 777777, pgid: 777777, pidStart: 'x' })
    reconcileHeadlessRuns(runner)
    expect(realKills(kills)).toEqual([])
    expect(hh.runRow('hr-pg')).toMatchObject({ status: 'lost' })
  })

  it('a row id that is not a run id, a pgid that is not the pid, a reservation of another run: untrusted', () => {
    hh = new HeadlessHarness()
    // Three open reservations at once: maxConcurrent above BE-4b's default of 1.
    hh.writeHeadlessConfig({ maxConcurrent: 4 })
    const kills: Kill[] = []
    const runner = hh.makeRunner({ listProcesses: () => [], kill: killSpy(kills), procStart: () => null })
    insertRow(hh, { id: 'hr.dot', status: 'running', pid: 5000, pgid: 5000, pidStart: 'x' })
    insertRow(hh, { id: 'hr-pgid', status: 'running', pid: 5001, pgid: 5002, pidStart: 'x' })
    insertRow(hh, { id: 'hr-own', status: 'running', pid: 5003, pgid: 5003, pidStart: 'x' })
    // hr-steal names hr-own's reservation.
    const own = hh.h.db.prepare(`SELECT reservation_id FROM credit_headless_runs WHERE id = 'hr-own'`).get() as { reservation_id: string }
    hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, status, started_at, run_dir) VALUES ('hr-steal', 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?,
        'normal', ?, 'h', 'helper', 'spawning', ?, ?)`).run(own.reservation_id, hh.worktree, hh.h.now, hh.runDir('hr-steal'))
    reconcileHeadlessRuns(runner)
    for (const id of ['hr.dot', 'hr-pgid', 'hr-steal']) expect([id, String(hh.runRow(id).reason)]).toEqual([id, expect.stringMatching(/^untrusted_row/)])
    expect(hh.runRow('hr-own')).toMatchObject({ status: 'lost', reason: 'process_gone' })
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })
})

describe('BE-4 2: only a linked worktree, and no symlink out of it', () => {
  it('P4: a .git directory (a clone) is refused; a .git file (a linked worktree) is accepted', () => {
    hh = new HeadlessHarness()
    const rules = { roots: [hh.wtRoot], forbidden: [hh.installRoot], runsDir: hh.runsDir }
    const clone = join(hh.wtRoot, 'liveclone')
    mkdirSync(join(clone, '.git', 'hooks'), { recursive: true })
    expect(validateCwd(clone, rules)).toEqual({ ok: false, reason: 'cwd_not_linked_worktree' })
    expect(validateCwd(hh.worktree, rules)).toMatchObject({ ok: true, cwd: hh.worktree })
  })

  it('P4: a symlink that resolves outside the worktree (also a dangling one) is refused; one inside is fine', () => {
    hh = new HeadlessHarness()
    const rules = { roots: [hh.wtRoot], forbidden: [hh.installRoot], runsDir: hh.runsDir }
    mkdirSync(join(hh.worktree, 'src', 'deep'), { recursive: true })
    writeFileSync(join(hh.worktree, 'src', 'a.ts'), 'x\n')
    symlinkSync('../a.ts', join(hh.worktree, 'src', 'deep', 'inside-link'))
    expect(validateCwd(hh.worktree, rules)).toMatchObject({ ok: true })
    symlinkSync(join(hh.installRoot, 'store'), join(hh.worktree, 'src', 'deep', 'store-link'))
    expect(validateCwd(hh.worktree, rules)).toEqual({ ok: false, reason: 'cwd_symlink_escape' })
    const { prompt } = hh.prompt('success')
    expect(hh.runner.start(hh.request(prompt), { caller: 'ezermester' })).toMatchObject({ ok: false, reason: 'cwd_symlink_escape' })
    expect(hh.h.reservations()).toHaveLength(0)
  })

  it('P4: a dangling symlink pointing outside, and a tree above the limits, are refused', () => {
    hh = new HeadlessHarness()
    const rules = { roots: [hh.wtRoot], forbidden: [hh.installRoot], runsDir: hh.runsDir }
    symlinkSync('/nonexistent/elsewhere', join(hh.worktree, 'dangling'))
    expect(validateCwd(hh.worktree, rules)).toEqual({ ok: false, reason: 'cwd_symlink_escape' })
    const big = join(hh.wtRoot, 'big')
    mkdirSync(big)
    writeFileSync(join(big, '.git'), 'gitdir: /x\n')
    for (let i = 0; i < 30; i++) writeFileSync(join(big, `f${i}`), '')
    expect(validateCwd(big, { ...rules, treeLimits: { maxEntries: 20, maxDepth: 8 } })).toEqual({ ok: false, reason: 'cwd_tree_too_large' })
    let deep = join(hh.wtRoot, 'deep')
    mkdirSync(deep)
    writeFileSync(join(deep, '.git'), 'gitdir: /x\n')
    for (let i = 0; i < 6; i++) { deep = join(deep, `d${i}`); mkdirSync(deep) }
    expect(validateCwd(join(hh.wtRoot, 'deep'), { ...rules, treeLimits: { maxEntries: 1000, maxDepth: 3 } })).toEqual({ ok: false, reason: 'cwd_tree_too_large' })
  })

  it('a symlink that appears after the start check is caught right before the spawn', async () => {
    hh = new HeadlessHarness()
    const runner = hh.makeRunner({ hooks: { afterPrepare: () => symlinkSync(hh!.installRoot, join(hh!.worktree, 'late-link')) } })
    const { prompt } = hh.prompt('success')
    const out = await startOk(hh, prompt, runner).done
    expect(out).toMatchObject({ status: 'refused', reason: 'cwd_symlink_escape' })
    expect(hh.spawnCalls).toHaveLength(0)
  })
})

describe('BE-4 3: the pid before ps; a ps failure is not "gone"', () => {
  it('the pid is in the row before ps runs, and a ps failure at launch signals the gate', async () => {
    hh = new HeadlessHarness()
    let rowAtPs: unknown
    let psCalls = 0
    const runner = hh.makeRunner({
      procStart: (pid) => {
        // The FIRST call is the one right after the spawn (later ticks retry).
        if (psCalls++ === 0) rowAtPs = hh!.h.db.prepare('SELECT status, pid, pgid FROM credit_headless_runs WHERE pid = ?').get(pid) ?? null
        throw new Error('ps is not usable: EPERM')
      },
    })
    const { prompt, observe } = hh.prompt('success')
    const out = await startOk(hh, prompt, runner).done
    const pid = hh.observed(observe).pid
    expect(rowAtPs).toEqual({ status: 'running', pid, pgid: pid })
    expect(out.status).toBe('succeeded')
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })

  it('ps unusable at restart: the row stays open, the gate is signalled, a later tick decides', async () => {
    hh = new HeadlessHarness()
    let psOk = false
    const aliveSet = new Set([4242])
    const kills: Kill[] = []
    const runDir = hh.runDir('hr-ps')
    const runner = hh.makeRunner({
      procStart: (pid) => {
        if (!psOk) throw new Error('ps is not usable: EPERM')
        return aliveSet.has(pid) ? 'S' : null
      },
      listProcesses: () => {
        if (!psOk) throw new Error('ps is not usable: EPERM')
        return aliveSet.has(4242) ? [{ pid: 4242, pgid: 4242, start: 'S', command: leaderCommand(hh!.bin, runDir) }] : []
      },
      kill: killSpy(kills, aliveSet),
    })
    insertRow(hh, { id: 'hr-ps', status: 'running', pid: 4242, pgid: 4242, pidStart: 'S' })
    const rep = reconcileHeadlessRuns(runner)
    expect(rep).toMatchObject({ reattached: [], closed: [], pending: ['hr-ps'] })
    expect(hh.runRow('hr-ps')).toMatchObject({ status: 'running' })
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
    psOk = true
    await until(() => runner.activeCount() === 1, 5_000, 'the re-attach on a later tick')
    aliveSet.delete(4242)
    const out = await runner.whenDone('hr-ps')
    expect(out).toMatchObject({ status: 'lost', basis: 'headless_reservation' })
    expect(realKills(kills)).toEqual([])
  })

  it('ps unusable for good: after the retry limit the row is closed, booked in full, nobody signalled', async () => {
    hh = new HeadlessHarness()
    const kills: Kill[] = []
    const runner = hh.makeRunner({
      procStart: () => { throw new Error('ps is not usable: EPERM') },
      listProcesses: () => { throw new Error('ps is not usable: EPERM') },
      kill: killSpy(kills, new Set([4242])),
      psRetryLimit: 3,
    })
    insertRow(hh, { id: 'hr-psx', status: 'running', pid: 4242, pgid: 4242, pidStart: 'S' })
    expect(reconcileHeadlessRuns(runner)).toMatchObject({ pending: ['hr-psx'] })
    await until(() => hh!.runRow('hr-psx').status !== 'running', 5_000, 'the retry limit')
    expect(hh.runRow('hr-psx')).toMatchObject({ status: 'lost', reason: 'unverifiable', basis: 'headless_reservation' })
    expect(realKills(kills)).toEqual([])
  })
})

describe('BE-4 5: the answer is not left on disk', () => {
  it('stdout.json and stderr.txt are gone; result_json has cost, usage and the filtered answer', async () => {
    hh = new HeadlessHarness()
    const hex = 'ab'.repeat(32)
    const { prompt } = hh.prompt('success', { result: { result: `done. key={KEY} marker=sk-ant-api03-XYZ token=${hex} end` } })
    const r = startOk(hh, prompt)
    const out = await r.done
    expect(out.status).toBe('secret_residue') // the answer carried the key: the run is flagged
    expect(existsSync(join(hh.runDir(r.run_id), 'stdout.json'))).toBe(false)
    expect(existsSync(join(hh.runDir(r.run_id), 'stderr.txt'))).toBe(false)
    const res = JSON.parse(hh.runRow(r.run_id).result_json as string) as Record<string, unknown>
    expect(res).toMatchObject({ total_cost_usd: 0.0749821, usage: { input_tokens: 8, output_tokens: 647 } })
    const text = res.result as string
    expect(text).toContain('done. key=')
    expect(text).toContain('end')
    for (const bad of [hh.key, hh.key.slice(-20), 'sk-ant-', hex]) expect(text).not.toContain(bad)
  })

  it('a clean answer is kept in result_json, capped', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success', { result: { result: 'x'.repeat(100_000) } })
    const r = startOk(hh, prompt)
    expect((await r.done).status).toBe('succeeded')
    const text = (JSON.parse(hh.runRow(r.run_id).result_json as string) as { result: string }).result
    expect(text.length).toBeLessThanOrEqual(64 * 1024 + 32)
    expect(text.endsWith('[truncated]')).toBe(true)
    expect(existsSync(hh.runDir(r.run_id))).toBe(false)
  })
})

describe('BE-4 6 / reviewer 10: the startup cleanup, in every mode', () => {
  function seedRuns(h: HeadlessHarness): { a: string; b: string } {
    mkdirSync(h.runsDir, { mode: 0o700 })
    chmodSync(h.runsDir, 0o700)
    const a = h.runDir(RID(1))
    const b = h.runDir(RID(2))
    for (const d of [a, b]) {
      mkdirSync(d, { mode: 0o700 })
      writeFileSync(join(d, 'key'), h.key, { mode: 0o600 })
    }
    return { a, b }
  }

  it('off mode: every key file under the runs dir is deleted, and the processes of a run are stopped', () => {
    hh = new HeadlessHarness()
    const { a, b } = seedRuns(hh)
    const kills: Kill[] = []
    const aliveSet = new Set([5151, 6161])
    const procs: ProcInfo[] = [
      { pid: 5151, pgid: 5151, start: 'S', command: leaderCommand(hh.bin, a) },
      { pid: 5152, pgid: 5151, start: 'S', command: `bash -c x CLAUDE_CONFIG_DIR=${a}/config PATH=/usr/bin:/bin` },
      { pid: 6161, pgid: 6161, start: 'S', command: `vim ${b}/notes CLAUDE_CONFIG_DIR=${b}/configx` },
    ]
    const handle = startHeadlessRuntime({
      runtime: { mode: { mode: 'off', raw: null, unknown: false }, gate: null, storeDir: hh.h.storeDir, db: null, startError: null },
      installRoot: hh.installRoot,
      listProcesses: () => procs,
      kill: killSpy(kills, aliveSet),
    })
    expect(handle).toBeUndefined()
    expect(existsSync(join(a, 'key'))).toBe(false)
    expect(existsSync(join(b, 'key'))).toBe(false)
    const signalled = new Set(realKills(kills).map(([pid]) => pid))
    expect(signalled).toEqual(new Set([5151, 5152]))
  })

  it('a web-only instance touches nothing', () => {
    hh = new HeadlessHarness()
    const { a } = seedRuns(hh)
    const kills: Kill[] = []
    startHeadlessRuntime({
      runtime: { mode: { mode: 'enforce', raw: 'enforce', unknown: false }, gate: null, storeDir: hh.h.storeDir, db: null, startError: 'web_only' },
      installRoot: hh.installRoot,
      listProcesses: () => [{ pid: 5151, pgid: 5151, start: 'S', command: leaderCommand(hh!.bin, a) }],
      kill: killSpy(kills, new Set([5151])),
    })
    expect(existsSync(join(a, 'key'))).toBe(true)
    expect(realKills(kills)).toEqual([])
  })

  it('reviewer 10: a spawning row without a pid -- the processes that carry its run dir are killed, the row is lost', () => {
    hh = new HeadlessHarness()
    const kills: Kill[] = []
    const runDir = hh.runDir('hr-spawning')
    const procs: ProcInfo[] = [
      { pid: 7171, pgid: 7171, start: 'S', command: leaderCommand(hh.bin, runDir) },
      { pid: 7272, pgid: 1, start: 'S', command: 'unrelated' },
    ]
    const runner = hh.makeRunner({ listProcesses: () => procs, kill: killSpy(kills, new Set([7171, 7272])) })
    insertRow(hh, { id: 'hr-spawning', status: 'spawning' })
    expect(reconcileHeadlessRuns(runner)).toMatchObject({ closed: ['hr-spawning'] })
    expect(realKills(kills)).toEqual([[7171, 'SIGKILL']])
    expect(hh.runRow('hr-spawning')).toMatchObject({ status: 'lost', basis: 'headless_reservation' })
  })
})

describe('BE-4 7: the caller and the canary hash come from the context, not the request', () => {
  it('the request carries no caller; the context decides', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    const { caller: _ignored, ...req } = hh.request(prompt) as unknown as Record<string, unknown> & { caller?: string }
    expect(hh.runner.start({ ...req, caller: 'ezermester' } as never, { caller: 'fejleszto' })).toMatchObject({ ok: false, reason: 'caller_not_allowed' })
    const r = hh.runner.start(req as never, { caller: 'ezermester' })
    expect(r).toMatchObject({ ok: true })
    if (r.ok) await r.done
    expect(hh.runRow((r as { run_id: string }).run_id)).toMatchObject({ caller: 'ezermester' })
  })

  it('a canary needs an approval id whose consumed approval names the hash; a raw hash is not taken', async () => {
    hh = new HeadlessHarness()
    const runner = hh.makeRunner({ canaryApprovedHash: (id) => (id === 'ap-1' ? hh!.approved : null) })
    const { prompt } = hh.prompt('success')
    const canary = { mode: 'canary' as const, budget_usd: '0.90' }
    expect(runner.start(hh.request(prompt, canary), { caller: 'ezermester', canaryApprovedHash: hh.approved } as never))
      .toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(runner.start(hh.request(prompt, canary), { caller: 'ezermester', canaryApprovalId: 'ap-2' })).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    const r = runner.start(hh.request(prompt, canary), { caller: 'ezermester', canaryApprovalId: 'ap-1' })
    expect(r).toMatchObject({ ok: true })
    if (r.ok) await r.done
    expect(hh.h.reservations().map((x) => x.kind)).toEqual(['canary'])
  })
})

describe('reviewer 8 and 9: the group after a clean exit; a throw inside the launch', () => {
  it('8: a child that exits 0 and leaves a grandchild -- the group SIGKILL stops the grandchild', async () => {
    hh = new HeadlessHarness()
    const { prompt, observe } = hh.prompt('success_orphan')
    const out = await startOk(hh, prompt).done
    expect(out.status).toBe('succeeded')
    const g = hh.observed(observe).grandchild as number
    strays.push(g)
    await until(() => !alive(g), 5_000, 'the grandchild to die')
  })

  it('9: a throw before the spawn -- key file gone, settled at zero, not active, the gate signalled', async () => {
    hh = new HeadlessHarness()
    let keyThere = false
    const runner = hh.makeRunner({
      hooks: {
        beforeSpawn: (dir: string) => {
          keyThere = existsSync(join(dir, 'key'))
          throw Object.assign(new Error('EIO: i/o error, read'), { code: 'EIO' })
        },
      },
    })
    const { prompt } = hh.prompt('success')
    const r = startOk(hh, prompt, runner)
    const out: RunOutcome = await r.done
    expect(keyThere).toBe(true)
    expect(out).toMatchObject({ status: 'refused', reason: 'launch_threw' })
    expect(existsSync(join(hh.runDir(r.run_id), 'key'))).toBe(false)
    expect(runner.activeCount()).toBe(0)
    expect(hh.h.reservations()).toMatchObject([{ status: 'settled' }])
    expect(hh.ledgerRows()).toHaveLength(0)
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })

  it('9: a throw after the spawn -- the group is killed and the run booked by B-04', async () => {
    hh = new HeadlessHarness()
    const runner = hh.makeRunner({ hooks: { afterSpawn: () => { throw new Error('boom after spawn') } } })
    const { prompt, observe } = hh.prompt('hang')
    const r = startOk(hh, prompt, runner)
    const out = await r.done
    expect(out).toMatchObject({ status: 'killed', reason: 'launch_threw', basis: 'headless_reservation' })
    if (existsSync(observe)) {
      const seen = hh.observed(observe)
      strays.push(seen.pid as number, seen.grandchild as number)
      await until(() => !alive(seen.pid as number) && !alive(seen.grandchild as number), 5_000, 'the group to die')
    }
    expect(existsSync(join(hh.runDir(r.run_id), 'key'))).toBe(false)
    expect(runner.activeCount()).toBe(0)
  })
})

describe('config: the pin, the key mode and the tool profile (Ezermester, 2026-10-16)', () => {
  const base = (headless: Record<string, unknown>) => {
    const c = configObject('/x/usage.jsonl', '/x/STOP') as Record<string, unknown> & { headless: Record<string, unknown> }
    return JSON.stringify({ ...c, headless: { ...c.headless, ...headless } })
  }

  it('claudeBinSha256 is required with a headless part; keyMode is helper (default) or env; toolProfile is read only', () => {
    const pin = 'c'.repeat(64)
    const ok = parseCreditGateConfig(base({ claudeBinSha256: pin }))
    expect(ok).toMatchObject({ ok: true, config: { headless: { claudeBinSha256: pin, keyMode: 'helper', toolProfile: 'read' } } })
    expect(parseCreditGateConfig(base({ claudeBinSha256: pin, keyMode: 'env', toolProfile: 'read' }))).toMatchObject({ ok: true, config: { headless: { keyMode: 'env' } } })
    const without = JSON.parse(base({})) as { headless: Record<string, unknown> }
    delete without.headless.claudeBinSha256
    expect(parseCreditGateConfig(JSON.stringify(without))).toMatchObject({ ok: false, reason: 'invalid' })
    for (const bad of [{ claudeBinSha256: 'C'.repeat(64) }, { claudeBinSha256: pin, keyMode: 'file' }, { claudeBinSha256: pin, toolProfile: 'edit' }]) {
      expect([bad, parseCreditGateConfig(base(bad)).ok]).toEqual([bad, false])
    }
  })
})

// ---------------------------------------------------------------- BE-4 round 2 (four LOWs on 34cd7b19)

describe('BE-4 round 2, 1: the whole cwd check right before the spawn, and the cwd identity after it', () => {
  it('P4b: the worktree swapped for a symlink after start() -- refused before the spawn', async () => {
    hh = new HeadlessHarness()
    const wt = hh.worktree
    const runner = hh.makeRunner({ hooks: { beforeSpawn: () => { renameSync(wt, `${wt}.moved`); symlinkSync(hh!.installRoot, wt) } } })
    const { prompt } = hh.prompt('success')
    const out = await startOk(hh, prompt, runner).done
    expect(out).toMatchObject({ status: 'refused', reason: 'cwd_not_canonical' })
    expect(hh.spawnCalls).toHaveLength(0)
  })

  it('swapped between the last check and the spawn -- the child is stopped, the run booked by B-04', async () => {
    hh = new HeadlessHarness()
    const wt = hh.worktree
    const h = hh
    const runner = hh.makeRunner({
      spawner: (file, args, options) => {
        renameSync(wt, `${wt}.moved`)
        symlinkSync(h.installRoot, wt)
        return h.spawner(file, args, options)
      },
    })
    const { prompt, observe } = hh.prompt('hang')
    const r = startOk(hh, prompt, runner)
    const out = await r.done
    expect(out).toMatchObject({ status: 'killed', reason: 'cwd_changed_during_spawn', basis: 'headless_reservation' })
    if (existsSync(observe)) {
      const seen = hh.observed(observe)
      strays.push(seen.pid as number, seen.grandchild as number)
      await until(() => !alive(seen.pid as number) && !alive(seen.grandchild as number), 5_000, 'the group to die')
    }
  })
})

describe('BE-4 round 2, 2: a run_dir or pgid fault books only the row\'s own reservation', () => {
  it('P1c: a forged row naming another run\'s reservation -- that reservation is not touched', () => {
    hh = new HeadlessHarness()
    const other = hh.h.gate.reserve({ kind: 'headless', budget_micro: asMicro(400_000), model: 'claude-sonnet-5-5', ref: 'hr-legit', caller: 'ezermester' })
    if (!('ok' in other) || !other.ok) throw new Error('reserve')
    for (const [id, runDir, pid, pgid] of [['hr-forged', join(hh.real, 'elsewhere'), 999999, 999999], ['hr-forged2', hh.runDir('hr-forged2'), 999998, 1]] as const) {
      hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
          config_hash, key_mode, pid, pid_start, pgid, status, started_at, deadline_at, run_dir)
        VALUES (?, 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, 'h', 'helper', ?, 'x', ?, 'running', ?, ?, ?)`)
        .run(id, other.reservation_id, hh.worktree, pid, pgid, hh.h.now, hh.h.now + 60_000, runDir)
    }
    const runner = hh.makeRunner({ listProcesses: () => [], procStart: () => null })
    reconcileHeadlessRuns(runner)
    expect(hh.h.reservations()).toMatchObject([{ ref: 'hr-legit', status: 'open' }])
    expect(hh.ledgerRows()).toHaveLength(0)
    expect(String(hh.runRow('hr-forged').reason)).toBe('untrusted_row:run_dir')
    expect(String(hh.runRow('hr-forged2').reason)).toBe('untrusted_row:pgid')
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'disarm' })
  })
})

describe('BE-4 round 2, 3: the sweep checks the runs dir like ensureRunsDir and enters hr-<uuid> dirs only', () => {
  const off = (h: HeadlessHarness) => ({ mode: { mode: 'off' as const, raw: null, unknown: false }, gate: null, storeDir: h.h.storeDir, db: null, startError: null })

  it('P7: a runs dir open to group/others (or a symlink) is not swept at all', () => {
    hh = new HeadlessHarness()
    const notRuns = join(hh.real, 'some-user-dir')
    mkdirSync(join(notRuns, RID(1)), { recursive: true })
    chmodSync(notRuns, 0o755)
    writeFileSync(join(notRuns, RID(1), 'key'), 'precious key material, not a run')
    hh.writeHeadlessConfig({ runsDir: notRuns })
    startHeadlessRuntime({ runtime: off(hh), installRoot: hh.installRoot, listProcesses: () => [], kill: () => {} })
    expect(existsSync(join(notRuns, RID(1), 'key'))).toBe(true)
    const link = join(hh.real, 'runs-link')
    chmodSync(notRuns, 0o700)
    symlinkSync(notRuns, link)
    expect(sweepRunsDir(link, { keep: new Set(), claudeBin: hh.bin, listProcesses: () => [], kill: () => {} })).toMatchObject({ keysRemoved: 0 })
    expect(existsSync(join(notRuns, RID(1), 'key'))).toBe(true)
  })

  it('P7: inside a proper runs dir, only hr-<uuid> directories are entered', () => {
    hh = new HeadlessHarness()
    mkdirSync(hh.runsDir, { mode: 0o700 })
    chmodSync(hh.runsDir, 0o700)
    for (const d of [RID(1), 'project-x', 'hr-short']) {
      mkdirSync(join(hh.runsDir, d), { mode: 0o700 })
      writeFileSync(join(hh.runsDir, d, 'key'), 'k', { mode: 0o600 })
    }
    startHeadlessRuntime({ runtime: off(hh), installRoot: hh.installRoot, listProcesses: () => [], kill: () => {} })
    expect(existsSync(join(hh.runsDir, RID(1), 'key'))).toBe(false)
    expect(existsSync(join(hh.runsDir, 'project-x', 'key'))).toBe(true)
    expect(existsSync(join(hh.runsDir, 'hr-short', 'key'))).toBe(true)
  })
})

describe('BE-4 round 2, 4: a run process is the pinned binary with the run dir in its place', () => {
  it('a mention in argv or env is not enough; the leader and the env-carrying members of its group are', () => {
    hh = new HeadlessHarness()
    mkdirSync(hh.runsDir, { mode: 0o700 })
    chmodSync(hh.runsDir, 0o700)
    const dir = join(hh.runsDir, RID(7))
    mkdirSync(dir, { mode: 0o700 })
    const procs: ProcInfo[] = [
      // grep / pgrep with the run dir as an argument
      { pid: 8001, pgid: 8001, start: 'S', command: `/usr/bin/grep -r --settings ${dir}/settings.json .` },
      // the pinned binary, but the run dir not where the template puts it
      { pid: 8002, pgid: 8002, start: 'S', command: `${hh.bin} --settings ${dir}/settings.json -p` },
      // an env value that merely contains the needle, in another group
      { pid: 8003, pgid: 8003, start: 'S', command: `/opt/x/node a.js FOO=y CLAUDE_CONFIG_DIR=${dir}/config` },
      // the real leader, and a member of its group carrying the run's env
      { pid: 8100, pgid: 8100, start: 'S', command: leaderCommand(hh.bin, dir) },
      { pid: 8101, pgid: 8100, start: 'S', command: `/opt/x/node tool.js PATH=/usr/bin:/bin CLAUDE_CONFIG_DIR=${dir}/config` },
      // a member of the leader's group without the env
      { pid: 8102, pgid: 8100, start: 'S', command: '/opt/x/node other.js' },
    ]
    const kills: Kill[] = []
    const rep = sweepRunsDir(hh.runsDir, { keep: new Set(), claudeBin: hh.bin, listProcesses: () => procs, kill: killSpy(kills) })
    expect([...rep.stopped].sort()).toEqual([8100, 8101])
    expect(new Set(realKills(kills).map(([pid]) => pid))).toEqual(new Set([8100, 8101]))
  })

  it('a node launcher of the pinned file counts (argv[1]); the template positions still apply', () => {
    hh = new HeadlessHarness()
    const dir = hh.runDir(RID(8))
    const procs: ProcInfo[] = [
      { pid: 8200, pgid: 8200, start: 'S', command: `/opt/homebrew/bin/node ${leaderCommand(hh.bin, dir)}` },
      { pid: 8201, pgid: 8201, start: 'S', command: `/opt/homebrew/bin/node /tmp/other.mjs ${leaderCommand('/x', dir).slice(3)}` },
    ]
    const kills: Kill[] = []
    insertRow(hh, { id: RID(8), status: 'spawning' })
    const runner = hh.makeRunner({ listProcesses: () => procs, kill: killSpy(kills, new Set([8200, 8201])) })
    reconcileHeadlessRuns(runner)
    expect(realKills(kills)).toEqual([[8200, 'SIGKILL']])
  })
})

describe('BE-4b N1: a settle the restart forgot (the retry queue lives in memory)', () => {
  /** What a failed settle and a restart leave behind: a closed run row, its own reservation still open. */
  function closedRow(h: HeadlessHarness, id: string, status: string, reservation: 'open' | 'unknown' = 'open'): void {
    insertRow(h, { id, status: 'running' })
    h.h.db.prepare(`UPDATE credit_headless_runs SET status = ?, ended_at = ?, reason = 'n1 test' WHERE id = ?`).run(status, h.h.now, id)
    if (reservation === 'unknown') h.h.db.prepare(`UPDATE credit_reservations SET status = 'unknown', reason = 'stale' WHERE ref = ?`).run(id)
  }

  const resOf = (h: HeadlessHarness, ref: string) =>
    h.h.db.prepare('SELECT status, amount_micro FROM credit_reservations WHERE ref = ?').get(ref) as { status: string; amount_micro: number }
  const ledgerOf = (h: HeadlessHarness, runId: string) => h.ledgerRows().filter((r) => r.run_id === runId)

  it('the startup reconcile settles them: booked by B-04 (the whole reservation), a refused one at zero, a stale (unknown) one too; once', () => {
    hh = new HeadlessHarness()
    hh.writeHeadlessConfig({ maxConcurrent: 4 })
    closedRow(hh, RID(1), 'failed')
    closedRow(hh, RID(2), 'refused')
    closedRow(hh, RID(3), 'succeeded', 'unknown')
    const kills: Kill[] = []
    const runner = hh.makeRunner({ listProcesses: () => [], kill: killSpy(kills) })
    expect(reconcileHeadlessRuns(runner)).toMatchObject({ settled: [RID(1), RID(2), RID(3)], retrying: [] })
    for (const id of [RID(1), RID(2), RID(3)]) expect([id, resOf(hh, id).status]).toEqual([id, 'settled'])
    expect(ledgerOf(hh, RID(1))).toMatchObject([{ basis: 'headless_reservation', est_micro: 600_000 }])
    expect(ledgerOf(hh, RID(3))).toMatchObject([{ basis: 'headless_reservation', est_micro: 600_000 }])
    expect(ledgerOf(hh, RID(2))).toEqual([])
    expect(hh.runRow(RID(1))).toMatchObject({ status: 'failed', basis: 'headless_reservation', est_micro: 600_000 })
    expect(hh.runRow(RID(2))).toMatchObject({ status: 'refused', basis: null })
    // Idempotent: a second pass (another restart) finds nothing, and nothing is booked twice.
    expect(reconcileHeadlessRuns(hh.makeRunner({ listProcesses: () => [], kill: killSpy(kills) }))).toMatchObject({ settled: [], retrying: [] })
    expect(ledgerOf(hh, RID(1))).toHaveLength(1)
    expect(realKills(kills)).toEqual([])
  })

  it('never a live or a foreign row: a running row, a row naming another run\'s reservation, an id that is not a run id stay as they are', () => {
    hh = new HeadlessHarness()
    hh.writeHeadlessConfig({ maxConcurrent: 4 })
    insertRow(hh, { id: RID(4), status: 'running', pid: 5004, pgid: 5004, pidStart: 'x' })
    closedRow(hh, 'hr.dot', 'lost')
    const live = hh.h.db.prepare('SELECT reservation_id FROM credit_headless_runs WHERE id = ?').get(RID(4)) as { reservation_id: string }
    hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, status, started_at, ended_at, run_dir) VALUES (?, 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?,
        'normal', ?, 'h', 'helper', 'failed', ?, ?, ?)`).run(RID(5), live.reservation_id, hh.worktree, hh.h.now, hh.h.now, hh.runDir(RID(5)))
    const runner = hh.makeRunner({ listProcesses: () => [], kill: killSpy([]) })
    expect(runner.settleClosedRows()).toEqual({ settled: [], retrying: [] })
    expect(resOf(hh, RID(4)).status).toBe('open')
    expect(resOf(hh, 'hr.dot').status).toBe('open')
    expect(hh.ledgerRows()).toEqual([])
    expect(hh.runRow(RID(4))).toMatchObject({ status: 'running' })
  })

  it('a settle that fails at startup goes to the tick\'s retry; when the gate takes it, the reservation is settled and the row gets its booking', async () => {
    hh = new HeadlessHarness()
    closedRow(hh, RID(6), 'cancelled')
    const gate = hh.h.gate
    let failing = true
    let tries = 0
    const runner = hh.makeRunner({
      listProcesses: () => [],
      kill: killSpy([]),
      gate: {
        reserve: (r) => gate.reserve(r),
        settleHeadless: (id, run, now) => {
          tries++
          return failing ? { ok: false, code: 409, reason: 'ledger_error' } : gate.settleHeadless(id, run, now)
        },
        signal: (kind, source, detail, now) => gate.signal(kind, source, detail, now),
      },
    })
    expect(reconcileHeadlessRuns(runner)).toMatchObject({ settled: [], retrying: [RID(6)] })
    expect(resOf(hh, RID(6)).status).toBe('open')
    await until(() => tries >= 3, 10_000, 'the tick to retry')
    failing = false
    await until(() => resOf(hh!, RID(6)).status === 'settled', 10_000, 'the retried settle')
    expect(ledgerOf(hh, RID(6))).toMatchObject([{ basis: 'headless_reservation' }])
    expect(hh.runRow(RID(6))).toMatchObject({ status: 'cancelled', basis: 'headless_reservation', est_micro: 600_000 })
  })
})
