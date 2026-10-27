// Test harness of the headless runner (card fec6335f, N4a). On top of the
// gate harness (tmp store, config, price table, SQLite, an OPEN gate): a fake
// git worktree, a runs directory, a tmp launcher for fake-claude.mjs with its
// pinned sha256, and a dummy key. Every path is canonical (realpath), because
// the runner refuses any working directory that is not.
//
// Nothing here reads a real key, the real store or the Vault, and no real
// `claude` binary is ever started: the spawner refuses any file outside this
// harness's tmp directory (blueprint 6.4).

import { spawn as realSpawn } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import { chmodSync, existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { Harness, simpleCal, type HarnessOptions } from './gate-harness.js'
import { HeadlessRunner, type HeadlessRunnerDeps, type HeadlessRunRequest, type Spawner } from '../../../web/credit-gate/headless/runner.js'
import { computeRunnerConfigHash } from '../../../web/credit-gate/headless/config-hash.js'
import { loadCreditGateConfigFile } from '../../../web/credit-gate/config.js'

export const FAKE_CLAUDE = join(__dirname, 'fake-claude.mjs')

export interface SpawnCall {
  readonly file: string
  readonly args: readonly string[]
  readonly options: Record<string, unknown>
}

export class HeadlessHarness {
  readonly h: Harness
  readonly real: string
  readonly wtRoot: string
  readonly worktree: string
  readonly runsDir: string
  readonly installRoot: string
  readonly bin: string
  readonly binSha: string
  readonly key: string
  readonly spawnCalls: SpawnCall[] = []
  approved: string | null = null
  runner: HeadlessRunner
  private readonly runners: HeadlessRunner[] = []
  private obsN = 0

  constructor(o: HarnessOptions & { runner?: Partial<HeadlessRunnerDeps> } = {}) {
    this.h = new Harness({ cal: simpleCal(1, '95.00'), ...o })
    this.real = realpathSync(this.h.dir)
    this.wtRoot = join(this.real, 'wt')
    this.worktree = join(this.wtRoot, 'proj')
    mkdirSync(this.worktree, { recursive: true })
    writeFileSync(join(this.worktree, '.git'), 'gitdir: /nowhere/.git/worktrees/proj\n')
    this.runsDir = join(this.real, 'runs')
    this.installRoot = join(this.real, 'install')
    mkdirSync(join(this.installRoot, 'store'), { recursive: true })
    writeFileSync(join(this.installRoot, '.git'), 'gitdir: /nowhere\n')
    mkdirSync(join(this.real, 'bin'))
    this.bin = join(this.real, 'bin', 'claude-fake.mjs')
    writeFileSync(this.bin, `#!${process.execPath}\nimport ${JSON.stringify(FAKE_CLAUDE)}\n`)
    chmodSync(this.bin, 0o755)
    this.binSha = createHash('sha256').update(readFileSync(this.bin)).digest('hex')
    this.key = `sk-ant-TEST-DUMMY-${randomBytes(16).toString('hex')}`
    this.writeHeadlessConfig()
    const t = this.h.gate.tick()
    if (t.state !== 'OPEN') throw new Error(`headless harness: the gate is ${t.state} (${t.reason})`)
    this.runner = this.makeRunner(o.runner)
    this.approved = this.runner.configHash()
  }

  writeHeadlessConfig(over: Record<string, unknown> = {}): void {
    this.h.writeConfig({
      headless: {
        allowedCallers: ['ezermester'], cwdRoots: [this.wtRoot], forbiddenCwds: [this.installRoot],
        runsDir: this.runsDir, claudeBin: this.bin, claudeBinSha256: this.binSha, models: ['claude-opus-5-5', 'claude-sonnet-5-5', 'claude-haiku-5-5'],
        maxBudgetUsd: '5.00', wallClockMin: 90, ...over,
      },
    })
  }

  /** A spawner that refuses any file outside this harness and records every call. */
  readonly spawner: Spawner = (file, args, options) => {
    if (!file.startsWith(this.real + '/')) throw new Error(`test spawner: refusing ${file}`)
    this.spawnCalls.push({ file, args: [...args], options: { ...options } })
    return realSpawn(file, args, options)
  }

  makeRunner(over: Partial<HeadlessRunnerDeps> = {}): HeadlessRunner {
    const r = new HeadlessRunner({
      db: this.h.db,
      gate: this.h.gate,
      loadConfig: () => loadCreditGateConfigFile(join(this.h.gateDir, 'config.json')),
      getKey: () => this.key,
      approvedHash: () => this.approved,
      forbiddenRoots: [this.installRoot, realpathSync(this.h.storeDir)],
      spawner: this.spawner,
      // In-process tests do not depend on a usable ps (sandbox-exec denies it):
      // a live pid has a fixed start time, and no process list. Tests that
      // need the real ones pass procStartOf / listProcessesPs.
      procStart: (pid) => (alive(pid) ? 'harness-start' : null),
      listProcesses: () => [],
      now: () => this.h.now,
      killGraceMs: 300,
      pollMs: 50,
      installSignalHandlers: false,
      ...over,
    })
    this.runners.push(r)
    return r
  }

  hashFor(keyMode: 'helper' | 'env' = 'helper'): string {
    return computeRunnerConfigHash({ keyMode, toolProfile: 'read' })
  }

  /** A fresh observe path and the prompt that tells the fake what to do. */
  prompt(mode: string, extra: Record<string, unknown> = {}): { prompt: string; observe: string } {
    const observe = join(this.real, `obs-${++this.obsN}.json`)
    return { prompt: `FAKE ${JSON.stringify({ mode, observe, ...extra })}\nDo the node.\n`, observe }
  }

  request(prompt: string, over: Partial<HeadlessRunRequest> = {}): HeadlessRunRequest {
    return {
      node_id: 'N9x', model: 'claude-sonnet-5-5', effort: 'high', budget_usd: '0.40',
      cwd: this.worktree, prompt, mode: 'normal', ...over,
    }
  }

  observed(path: string): Record<string, unknown> {
    return JSON.parse(readFileSync(path, 'utf8')) as Record<string, unknown>
  }

  runRow(id: string): Record<string, unknown> {
    return this.h.db.prepare('SELECT * FROM credit_headless_runs WHERE id = ?').get(id) as Record<string, unknown>
  }

  ledgerRows(): Array<Record<string, unknown>> {
    return this.h.db.prepare('SELECT * FROM credit_ledger_entries ORDER BY id').all() as Array<Record<string, unknown>>
  }

  runDir(id: string): string {
    return join(this.runsDir, id)
  }

  exists(p: string): boolean {
    return existsSync(p)
  }

  cleanup(): void {
    for (const r of this.runners) r.stop()
    this.h.cleanup()
  }
}

/** Wait until `fn` is true (polling), or throw after `ms`. */
export async function until(fn: () => boolean, ms = 10_000, what = 'condition'): Promise<void> {
  const end = Date.now() + ms
  while (!fn()) {
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`)
    await new Promise((r) => setTimeout(r, 25))
  }
}

/** True while a process with this pid exists (a zombie counts as gone for our purpose only once reaped). */
export function alive(pid: number): boolean {
  try {
    process.kill(pid, 0)
    return true
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === 'EPERM'
  }
}
