import { describe, it, expect, afterEach } from 'vitest'
import { spawn, type ChildProcess } from 'node:child_process'
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { reconcileHeadlessRuns, startHeadlessRuntime } from '../web/credit-gate/headless/reconcile.js'
import { listProcessesPs, procStartOf, sweepRunsDir } from '../web/credit-gate/headless/runner.js'
import { setCreditGateRuntime } from '../web/credit-gate/runtime.js'
import { alive, HeadlessHarness, until } from './fixtures/credit-gate/headless-harness.js'

// Credit gate, node N4a: the runner across processes. A worker (a stand-in
// dashboard, its own OS process on the test's SQLite file) starts one run of
// fake-claude.mjs; the test then signals or kills the worker:
//  - SIGTERM, SIGINT, SIGHUP: the run's whole process group dies with it, and
//    the run is closed (key file deleted, B-04 booking) before it goes;
//  - SIGKILL (nothing can run): the run survives, and the next start's
//    reconcile re-attaches a live pid or closes a dead one (B-04).
// The workers run with loopback-guard.cjs preloaded and a minimal env.

const ROOT = join(__dirname, '..', '..')
const FIX = join(__dirname, 'fixtures', 'credit-gate')

/**
 * Re-attaching needs a real process identity (`ps -o lstart=`). Measured
 * 2026-10-16: under sandbox-exec (the agents' run-sandboxed.sh) the exec of
 * the setuid /bin/ps is denied, so the tests that need it are skipped there,
 * by name, instead of failing; everywhere else they run.
 */
const PS_USABLE = (() => {
  try {
    return procStartOf(process.pid) !== null
  } catch {
    return false
  }
})()
const itPs = it.skipIf(!PS_USABLE)
/** The real process identity (the harness default is a ps-free stand-in). */
const REAL_PS = { procStart: procStartOf, listProcesses: listProcessesPs }

interface Up { run_id: string; pid: number; grandchild: number | null; worker: number }

let hh: HeadlessHarness | undefined
const workers: ChildProcess[] = []
const strays: number[] = []
afterEach(() => {
  for (const w of workers.splice(0)) {
    try { w.kill('SIGKILL') } catch { /* gone */ }
  }
  for (const pid of strays.splice(0)) {
    try { process.kill(pid, 'SIGKILL') } catch { /* gone */ }
  }
  setCreditGateRuntime(null)
  hh?.cleanup()
  hh = undefined
})

function startWorker(h: HeadlessHarness, mode: string, extra: Record<string, unknown> = {}): Promise<{ up: Up; proc: ChildProcess; exited: Promise<{ code: number | null; signal: NodeJS.Signals | null }> }> {
  const { prompt, observe } = h.prompt(mode)
  const keyFile = join(h.real, 'dummy-key')
  writeFileSync(keyFile, h.key, { mode: 0o600 })
  const specPath = join(h.real, `spec-${Date.now()}-${Math.random().toString(36).slice(2)}.json`)
  writeFileSync(specPath, JSON.stringify({
    dbPath: h.h.dbPath, storeDir: h.h.storeDir, nowMs: h.h.now, cal: h.h.cal, tmpRoot: h.real, keyFile,
    forbiddenRoots: [h.installRoot, join(h.real, 'store')], request: h.request(prompt), observe, ...extra,
  }))
  const proc = spawn(process.execPath, ['--require', join(FIX, 'loopback-guard.cjs'), '--import', 'tsx', join(FIX, 'headless-worker.ts'), specPath], {
    cwd: ROOT,
    env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? '/tmp', TMPDIR: process.env.TMPDIR ?? '/tmp', NODE_ENV: 'production' },
    stdio: ['ignore', 'pipe', 'pipe'],
  })
  workers.push(proc)
  let out = ''
  let err = ''
  const exited = new Promise<{ code: number | null; signal: NodeJS.Signals | null }>((resolve) => {
    proc.on('exit', (code, signal) => resolve({ code, signal }))
  })
  const up = new Promise<Up>((resolve, reject) => {
    proc.stdout!.on('data', (d) => {
      out += String(d)
      const line = out.split('\n').find((l) => l.startsWith('UP '))
      if (line) {
        const o = JSON.parse(line.slice(3)) as Up & { error?: string }
        if (o.error) reject(new Error(`worker refused: ${o.error}`))
        else resolve(o)
      }
    })
    proc.stderr!.on('data', (d) => { err += String(d) })
    void exited.then((e) => reject(new Error(`worker exited early ${JSON.stringify(e)}: ${err.slice(-2000)}`)))
  })
  return up.then((u) => {
    strays.push(u.pid)
    if (u.grandchild) strays.push(u.grandchild)
    return { up: u, proc, exited }
  })
}

describe('the parent dies by a signal: no orphan, the run is closed', () => {
  for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP'] as const) {
    it(`${sig}`, async () => {
      hh = new HeadlessHarness()
      const { up, proc, exited } = await startWorker(hh, 'hang')
      expect(alive(up.pid) && alive(up.grandchild as number)).toBe(true)
      proc.kill(sig)
      const e = await exited
      // The runner re-raised the signal: the worker died of it (default action).
      expect(e.signal).toBe(sig)
      await until(() => !alive(up.pid) && !alive(up.grandchild as number), 5_000, 'the run group to die')
      const row = hh.runRow(up.run_id)
      expect(row).toMatchObject({ status: 'killed' })
      expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(false)
      expect(existsSync(join(hh.runDir(up.run_id), 'config'))).toBe(false)
      expect(hh.h.reservations()).toMatchObject([{ ref: up.run_id, status: 'settled' }])
      expect(hh.ledgerRows()).toMatchObject([{ run_id: up.run_id, basis: 'headless_reservation', est_micro: 600_000 }])
    }, 60_000)
  }

  it('SIGTERM with the dashboard\'s own shutdown listener: the group still dies', async () => {
    hh = new HeadlessHarness()
    const { up, proc, exited } = await startWorker(hh, 'hang', { ownShutdown: true })
    proc.kill('SIGTERM')
    expect(await exited).toMatchObject({ code: 0 })
    await until(() => !alive(up.pid) && !alive(up.grandchild as number), 5_000, 'the run group to die')
    expect(hh.runRow(up.run_id)).toMatchObject({ status: 'killed' })
  }, 60_000)
})

describe('reconcile after a dashboard restart (the worker got SIGKILL)', () => {
  itPs('a live pid is re-attached, and its JSON result is booked when it ends', async () => {
    hh = new HeadlessHarness()
    const { up, proc, exited } = await startWorker(hh, 'wait_usr2')
    proc.kill('SIGKILL')
    await exited
    expect(alive(up.pid)).toBe(true)
    expect(hh.runRow(up.run_id)).toMatchObject({ status: 'running', pid: up.pid })
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(true)

    hh.runner = hh.makeRunner(REAL_PS)
    const rep = reconcileHeadlessRuns(hh.runner)
    expect(rep).toMatchObject({ reattached: [up.run_id], closed: [] })
    // Still running: the key file stays for the helper's refresh.
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(true)
    process.kill(up.pid, 'SIGUSR2')
    const out = await hh.runner.whenDone(up.run_id)
    expect(out).toMatchObject({ status: 'succeeded', exit_code: null, basis: 'headless_json', est_micro: 114_535 })
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(false)
    expect(hh.h.reservations()).toMatchObject([{ ref: up.run_id, status: 'settled' }])
  }, 60_000)

  itPs('a dead pid is closed by B-04, and its orphaned grandchild is killed', async () => {
    hh = new HeadlessHarness()
    const { up, proc, exited } = await startWorker(hh, 'hang')
    proc.kill('SIGKILL')
    await exited
    process.kill(up.pid, 'SIGKILL')
    await until(() => !alive(up.pid), 5_000, 'the leader to die')
    expect(alive(up.grandchild as number)).toBe(true)

    hh.runner = hh.makeRunner(REAL_PS)
    const rep = reconcileHeadlessRuns(hh.runner)
    expect(rep).toMatchObject({ reattached: [], closed: [up.run_id] })
    expect(hh.runRow(up.run_id)).toMatchObject({ status: 'lost' })
    await until(() => !alive(up.grandchild as number), 5_000, 'the orphan to die')
    expect(hh.ledgerRows()).toMatchObject([{ run_id: up.run_id, basis: 'headless_reservation', est_micro: 600_000 }])
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(false)
  }, 60_000)

  itPs('a re-attached run past its wall clock is stopped: SIGTERM, SIGKILL, timeout', async () => {
    hh = new HeadlessHarness()
    const { up, proc, exited } = await startWorker(hh, 'hang')
    proc.kill('SIGKILL')
    await exited
    hh.h.db.prepare('UPDATE credit_headless_runs SET deadline_at = ? WHERE id = ?').run(hh.h.now - 1, up.run_id)
    hh.runner = hh.makeRunner({ ...REAL_PS, killGraceMs: 300, pollMs: 50 })
    expect(reconcileHeadlessRuns(hh.runner)).toMatchObject({ reattached: [up.run_id] })
    const out = await hh.runner.whenDone(up.run_id)
    expect(out).toMatchObject({ status: 'timeout', basis: 'headless_reservation' })
    await until(() => !alive(up.pid) && !alive(up.grandchild as number), 5_000, 'the group to die')
  }, 60_000)

  itPs('a reused pid (another start time) is neither re-attached nor signalled', () => {
    hh = new HeadlessHarness()
    const res = hh.h.gate.reserve({ kind: 'headless', budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-reused', caller: 'ezermester' })
    if (!('ok' in res) || !res.ok) throw new Error('reserve failed')
    hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, pid, pid_start, pgid, status, started_at, deadline_at, run_dir)
      VALUES ('hr-reused', 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, ?, 'helper', ?, 'Thu Jan  1 00:00:00 1970', ?, 'running', ?, ?, ?)`)
      .run(res.reservation_id, hh.worktree, hh.approved, process.pid, process.pid, hh.h.now, hh.h.now + 60_000, hh.runDir('hr-reused'))
    expect(procStartOf(process.pid)).not.toBe('Thu Jan  1 00:00:00 1970')
    hh.runner = hh.makeRunner(REAL_PS)
    expect(reconcileHeadlessRuns(hh.runner)).toMatchObject({ reattached: [], closed: ['hr-reused'] })
    expect(hh.runRow('hr-reused')).toMatchObject({ status: 'lost', reason: 'process_gone' })
    expect(hh.h.reservations()).toMatchObject([{ ref: 'hr-reused', status: 'settled' }])
  })

  itPs('BE-4 6: an off-mode start deletes the key file and stops the leftover run (real ps, by argv/env)', async () => {
    hh = new HeadlessHarness()
    const { up, proc, exited } = await startWorker(hh, 'hang')
    proc.kill('SIGKILL')
    await exited
    expect(alive(up.pid) && alive(up.grandchild as number)).toBe(true)
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(true)
    const handle = startHeadlessRuntime({
      runtime: { mode: { mode: 'off', raw: null, unknown: false }, gate: null, storeDir: hh.h.storeDir, db: null, startError: null },
      installRoot: hh.installRoot,
    })
    expect(handle).toBeUndefined()
    expect(existsSync(join(hh.runDir(up.run_id), 'key'))).toBe(false)
    await until(() => !alive(up.pid) && !alive(up.grandchild as number), 5_000, 'the leftover run to stop')
    // Off mode touches no table: the row waits for a gate to close it.
    expect(hh.runRow(up.run_id)).toMatchObject({ status: 'running' })
  }, 60_000)

  itPs('BE-4 round 2, 4 (P6, real ps): processes that only mention the run dir in argv or env are not stopped', async () => {
    hh = new HeadlessHarness()
    mkdirSync(hh.runsDir, { mode: 0o700 })
    chmodSync(hh.runsDir, 0o700)
    const dir = join(hh.runsDir, 'hr-00000000-0000-4000-8000-000000000006')
    mkdirSync(dir, { mode: 0o700 })
    const keep = ['--require', join(FIX, 'loopback-guard.cjs'), '-e', 'setInterval(() => {}, 1000)']
    const opts = { stdio: 'ignore' as const, env: { PATH: '/usr/bin:/bin' } }
    const kids = [
      spawn(process.execPath, [...keep, `x\n1 1 Fri Oct 16 13:00:00 2026 --settings ${dir}/settings.json`], opts),
      spawn(process.execPath, [...keep, '--settings', `${dir}/settings.json`], opts),
      spawn(process.execPath, keep, { ...opts, env: { PATH: '/usr/bin:/bin', FOO: `y\n1 1 Fri Oct 16 13:00:00 2026 CLAUDE_CONFIG_DIR=${dir}/config` } }),
    ]
    for (const k of kids) strays.push(k.pid as number)
    await new Promise((r) => setTimeout(r, 400))
    const kills: Array<[number, string | number]> = []
    const rep = sweepRunsDir(hh.runsDir, {
      keep: new Set(), claudeBin: hh.bin, listProcesses: listProcessesPs,
      kill: (pid, sig) => { kills.push([pid, sig]); if (sig === 0) process.kill(pid, 0) },
    })
    expect(rep).toMatchObject({ psUsable: true, stopped: [] })
    expect(kills.filter(([, sig]) => sig !== 0)).toEqual([])
  }, 30_000)

  it('a run that never reached the spawn is settled at zero', () => {
    hh = new HeadlessHarness()
    const res = hh.h.gate.reserve({ kind: 'headless', budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-starting', caller: 'ezermester' })
    if (!('ok' in res) || !res.ok) throw new Error('reserve failed')
    hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, status, started_at, run_dir)
      VALUES ('hr-starting', 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, ?, 'helper', 'starting', ?, ?)`)
      .run(res.reservation_id, hh.worktree, hh.approved, hh.h.now, hh.runDir('hr-starting'))
    expect(reconcileHeadlessRuns(hh.runner)).toMatchObject({ closed: ['hr-starting'] })
    expect(hh.runRow('hr-starting')).toMatchObject({ status: 'refused', reason: 'interrupted_before_spawn' })
    expect(hh.ledgerRows()).toHaveLength(0)
    expect(hh.h.reservations()).toMatchObject([{ ref: 'hr-starting', status: 'settled' }])
  })

  it('startHeadlessRuntime: no gate -> nothing; with a gate -> reconcile runs once at start', () => {
    hh = new HeadlessHarness()
    expect(startHeadlessRuntime({ runtime: { mode: { mode: 'off', raw: null, unknown: false }, gate: null, storeDir: hh.h.storeDir, db: null, startError: null } })).toBeUndefined()
    const res = hh.h.gate.reserve({ kind: 'headless', budget_micro: 400_000 as never, model: 'claude-sonnet-5-5', ref: 'hr-boot', caller: 'ezermester' })
    if (!('ok' in res) || !res.ok) throw new Error('reserve failed')
    hh.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, status, started_at, run_dir)
      VALUES ('hr-boot', 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, ?, 'helper', 'starting', ?, ?)`)
      .run(res.reservation_id, hh.worktree, hh.approved, hh.h.now, hh.runDir('hr-boot'))
    const handle = startHeadlessRuntime({
      runtime: { mode: hh.h.mode, gate: hh.h.gate, storeDir: hh.h.storeDir, db: hh.h.db, startError: null },
      getKey: () => hh!.key,
      installRoot: hh.installRoot,
    })
    expect(handle).toBeDefined()
    handle!.stop()
    expect(hh.runRow('hr-boot')).toMatchObject({ status: 'refused' })
  })
})
