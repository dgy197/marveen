import { describe, it, expect, afterEach, vi } from 'vitest'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, readdirSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { logger } from '../logger.js'
import { asMicro } from '../web/credit-gate/money.js'
import {
  assertRunArgs,
  buildRunArgs,
  TOOL_PROFILES,
  usdArg,
} from '../web/credit-gate/headless/args.js'
import { configHashOf, computeRunnerConfigHash } from '../web/credit-gate/headless/config-hash.js'
import { buildRunEnv, buildRunSettings, runEnvNames, runPaths } from '../web/credit-gate/headless/env.js'
import { cliVersionOf, parseHeadlessResult, scanResidue, spawnHeadless, type ProcInfo, type RunOutcome, type RunRow } from '../web/credit-gate/headless/runner.js'
import { alive, HeadlessHarness, until } from './fixtures/credit-gate/headless-harness.js'

// Credit gate, node N4a: the headless `claude -p` runner (spec E-01..E-05,
// I-05, B-04, C-06b; blueprint 4.3 and N4a). The child is fake-claude.mjs
// behind a tmp launcher; no real CLI, no network, no real key or store.

let hh: HeadlessHarness | undefined
afterEach(() => {
  vi.restoreAllMocks()
  hh?.cleanup()
  hh = undefined
})

/** Every env name of blueprint 4.3 that must NOT reach the child. */
const POLLUTION: Record<string, string> = {
  CLAUDE_CODE_OAUTH_TOKEN: 'oauth-x', ANTHROPIC_AUTH_TOKEN: 'auth-x', ANTHROPIC_BASE_URL: 'http://127.0.0.1:9',
  CLAUDECODE: '1', CLAUDE_CODE_ENTRYPOINT: 'cli', TMUX: '/tmp/tmux-1/default,1,0', TELEGRAM_BOT_TOKEN: 'bot-x',
  SLACK_BOT_TOKEN: 'slack-x', SSH_AUTH_SOCK: '/tmp/ssh.sock', GH_TOKEN: 'gh-x', GITHUB_TOKEN: 'gh-y',
  NODE_OPTIONS: '--require /tmp/evil.js', DYLD_INSERT_LIBRARIES: '/tmp/evil.dylib', BASH_ENV: '/tmp/evil.sh', ENV: '/tmp/evil.sh',
  PYTHONPATH: '/tmp/evil', npm_config_registry: 'http://127.0.0.1:9', MARVEEN_SSH_DIR: '/tmp/x', USER: 'someone',
  LOGNAME: 'someone', LANG: 'hu_HU.UTF-8', ANTHROPIC_API_KEY: 'sk-ant-PARENT-POLLUTION-0000000000',
}

/** The canary's measured env (2026-10-16, 2.1.299), with the key in the env. */
const CANARY_ENV = [
  'ANTHROPIC_API_KEY', 'CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC', 'CLAUDE_CONFIG_DIR', 'DISABLE_AUTOUPDATER',
  'DISABLE_TELEMETRY', 'HOME', 'PATH', 'TELEGRAM_STATE_DIR', 'TMPDIR',
]
const HELPER_ENV = CANARY_ENV.filter((n) => n !== 'ANTHROPIC_API_KEY')

/**
 * The env names the child saw, minus the one a macOS process sets for itself
 * at startup: measured 2026-10-16, `env -i /usr/bin/env` prints nothing, but a
 * node child spawned with env {A} sees A and __CF_USER_TEXT_ENCODING
 * (CoreFoundation inside the child). It does not come from the parent; what
 * the parent hands over is checked separately, on the spawn call.
 */
function childEnvNames(seen: Record<string, unknown>): string[] {
  const names = seen.envNames as string[]
  return process.platform === 'darwin' ? names.filter((n) => n !== '__CF_USER_TEXT_ENCODING') : names
}

function pollute(): () => void {
  const saved = new Map<string, string | undefined>()
  for (const [k, v] of Object.entries(POLLUTION)) {
    saved.set(k, process.env[k])
    process.env[k] = v
  }
  return () => {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k]
      else process.env[k] = v
    }
  }
}

function captureLogs(): unknown[][] {
  const logged: unknown[][] = []
  for (const level of ['info', 'warn', 'error', 'debug'] as const) {
    vi.spyOn(logger, level).mockImplementation(((...args: unknown[]) => { logged.push([level, ...args]) }) as never)
  }
  return logged
}

/** The trusted context of a start (the route fills it, N4b). */
const CTX = { caller: 'ezermester' }

function startOk(h: HeadlessHarness, prompt: string, over = {}) {
  const r = h.runner.start(h.request(prompt, over), CTX)
  if (!r.ok) throw new Error(`start refused: ${r.reason} ${r.detail ?? ''}`)
  return r
}

describe('env, args and the config hash (blueprint 4.3)', () => {
  it('the child env is exactly the allowlist, whatever the parent has', () => {
    const restore = pollute()
    try {
      const p = runPaths('/x/runs/r1')
      const helper = buildRunEnv(p, 'helper', null)
      expect(Object.keys(helper).sort()).toEqual(HELPER_ENV)
      expect(runEnvNames('helper')).toEqual(HELPER_ENV)
      expect(helper).toMatchObject({
        PATH: '/usr/bin:/bin', HOME: '/x/runs/r1/home', TMPDIR: '/x/runs/r1/tmp', CLAUDE_CONFIG_DIR: '/x/runs/r1/config',
        TELEGRAM_STATE_DIR: '/x/runs/r1/empty-state', DISABLE_AUTOUPDATER: '1', CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
        DISABLE_TELEMETRY: '1',
      })
      const env = buildRunEnv(p, 'env', 'sk-ant-TEST-DUMMY-abcdefabcdefabcdef')
      expect(Object.keys(env).sort()).toEqual(CANARY_ENV)
      expect(env.ANTHROPIC_API_KEY).toBe('sk-ant-TEST-DUMMY-abcdefabcdefabcdef')
      expect(() => buildRunEnv(p, 'env', null)).toThrow()
      expect(() => buildRunEnv(p, 'helper', 'sk-ant-TEST-DUMMY-abcdefabcdefabcdef')).toThrow()
    } finally {
      restore()
    }
  })

  it('the args are the measured command, -p first, the key and the prompt never in them', () => {
    const args = buildRunArgs({ model: 'claude-sonnet-5-5', effort: 'high', budgetMicro: asMicro(400_000), settingsPath: '/x/r/settings.json', toolProfile: 'read' })
    expect(args[0]).toBe('-p')
    expect(args).toEqual([
      '-p', '--bare', '--restricted', '--model', 'claude-sonnet-5-5', '--effort', 'high', '--max-budget-usd', '0.40',
      '--output-format', 'json', '--no-session-persistence', '--settings', '/x/r/settings.json',
      '--tools', 'Read', '--allowedTools', 'Read', '--permission-mode', 'dontAsk', '--permission-prompts', 'none',
      '--strict-mcp-config', '--disable-slash-commands',
    ])
    for (const f of ['--continue', '-c', '--resume', '-r', '--channels', '--dangerously-skip-permissions', '--fallback-model', '--mcp-config', '--max-turns']) {
      expect(args).not.toContain(f)
    }
    expect(TOOL_PROFILES.edit).toBe('Read,Edit,Write')
    expect(usdArg(asMicro(5_000_000))).toBe('5.00')
    expect(() => usdArg(asMicro(1))).toThrow()
  })

  it('assertRunArgs: no -p, a second -p or an extra flag is refused (I-05)', () => {
    const args = buildRunArgs({ model: 'claude-opus-5-5', effort: 'xhigh', budgetMicro: asMicro(1_000_000), settingsPath: '/x/settings.json', toolProfile: 'edit' })
    expect(() => assertRunArgs(args, 'edit')).not.toThrow()
    expect(() => assertRunArgs(args.slice(1), 'edit')).toThrow(/-p/)
    expect(() => assertRunArgs(args.filter((a) => a !== '-p').concat('-p'), 'edit')).toThrow(/-p/)
    expect(() => assertRunArgs([...args, '--continue'], 'edit')).toThrow()
    expect(() => assertRunArgs([...args, '--dangerously-skip-permissions'], 'edit')).toThrow()
    expect(() => assertRunArgs(args, 'read')).toThrow()
    const noBare = args.filter((a) => a !== '--bare')
    expect(() => assertRunArgs(noBare, 'edit')).toThrow()
    expect(() => assertRunArgs(args.map((a) => (a === 'xhigh' ? 'max' : a)), 'edit')).toThrow()
  })

  it('the hash: changes with a flag, the key mode and the settings; not with the run paths, the per-run values or the CLI version', () => {
    const base = computeRunnerConfigHash({ keyMode: 'helper', toolProfile: 'read' })
    expect(base).toMatch(/^[0-9a-f]{64}$/)
    expect(computeRunnerConfigHash({ keyMode: 'helper', toolProfile: 'read' })).toBe(base)
    expect(computeRunnerConfigHash({ keyMode: 'env', toolProfile: 'read' })).not.toBe(base)
    expect(computeRunnerConfigHash({ keyMode: 'helper', toolProfile: 'edit' })).not.toBe(base)

    const concrete = (root: string, model: string, effort: 'high' | 'xhigh', budget: number, extra: string[] = [], settingsOver = {}) => {
      const p = runPaths(root)
      return configHashOf({
        args: [...buildRunArgs({ model, effort, budgetMicro: asMicro(budget), settingsPath: p.settings, toolProfile: 'read' }), ...extra],
        env: buildRunEnv(p, 'helper', null),
        settings: { ...buildRunSettings(p, 'helper'), ...settingsOver },
        keyMode: 'helper',
        runDir: p.root,
      })
    }
    // Two runs: other paths, model, effort and budget -- the same hash, and it is the template's.
    const a = concrete('/s/runs/hr-a', 'claude-sonnet-5-5', 'high', 400_000)
    const b = concrete('/other/place/hr-b', 'claude-opus-5-5', 'xhigh', 5_000_000)
    expect(a).toBe(b)
    expect(a).toBe(base)
    expect(concrete('/s/runs/hr-a', 'claude-sonnet-5-5', 'high', 400_000, ['--verbose'])).not.toBe(base)
    expect(concrete('/s/runs/hr-a', 'claude-sonnet-5-5', 'high', 400_000, [], { model: 'x' })).not.toBe(base)
  })

  it('the hash does not depend on the binary: two runners on other CLI paths and pins agree', () => {
    hh = new HeadlessHarness()
    const before = hh.runner.configHash()
    hh.writeHeadlessConfig({ claudeBin: join(hh.real, 'bin', 'versions', '9.9.9'), claudeBinSha256: 'a'.repeat(64) })
    expect(hh.runner.configHash()).toBe(before)
    hh.writeHeadlessConfig({ keyMode: 'env' })
    expect(hh.runner.configHash()).not.toBe(before)
    expect(cliVersionOf('/Users/x/.local/share/claude/versions/2.1.299')).toBe('2.1.299')
    expect(cliVersionOf(hh.bin)).toBe('unknown')
  })
})

describe('refusals before anything is spent (E-02, E-04, E-05)', () => {
  it('model allowlist: Haiku and [1m] are refused even when the config lists them', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    for (const model of ['claude-haiku-5-5', 'claude-opus-5-5[1m]', 'claude-opus-5-5-20261001', 'gpt-6']) {
      const r = hh.runner.start(hh.request(prompt, { model }), CTX)
      expect(r).toMatchObject({ ok: false, reason: 'model_not_allowed' })
    }
    hh.writeHeadlessConfig({ models: ['claude-opus-5-5'] })
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'model_not_allowed' })
    expect(hh.h.reservations()).toHaveLength(0)
    expect(hh.spawnCalls).toHaveLength(0)
  })

  it('budget: above the config maximum, malformed, zero, and a canary at 1.00 or more', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    expect(hh.runner.start(hh.request(prompt, { budget_usd: '5.01' }), CTX)).toMatchObject({ ok: false, reason: 'budget_over_max' })
    for (const b of ['5', '-1.00', '0.4', ' 0.40', '1e1', '0.00']) {
      expect(hh.runner.start(hh.request(prompt, { budget_usd: b }), CTX)).toMatchObject({ ok: false, reason: 'budget_invalid' })
    }
    const canary = { mode: 'canary' as const, budget_usd: '1.00' }
    const canaryRunner = hh.makeRunner({ canaryApprovedHash: () => hh!.approved })
    expect(canaryRunner.start(hh.request(prompt, canary), { ...CTX, canaryApprovalId: 'ap-1' })).toMatchObject({ ok: false, reason: 'budget_over_canary' })
    expect(hh.h.reservations()).toHaveLength(0)
  })

  it('cwd: install root, store, "..", symlink escapes, no worktree, outside the roots, relative', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    const outside = join(hh.real, 'outside')
    mkdirSync(outside)
    writeFileSync(join(outside, '.git'), 'gitdir: /x\n')
    symlinkSync(outside, join(hh.wtRoot, 'escape'))
    symlinkSync(hh.worktree, join(hh.wtRoot, 'alias'))
    mkdirSync(join(hh.wtRoot, 'plain'))
    hh.writeHeadlessConfig({ cwdRoots: [hh.wtRoot, hh.real] })
    const cases: Array<[string, string]> = [
      [hh.installRoot, 'cwd_forbidden'],
      [join(hh.installRoot, 'store'), 'cwd_forbidden'],
      [hh.real, 'cwd_forbidden'], // a parent of the install root
      [realStore(hh), 'cwd_forbidden'],
      [`${hh.wtRoot}/proj/../proj`, 'cwd_not_canonical'],
      [join(hh.wtRoot, 'escape'), 'cwd_not_canonical'],
      [join(hh.wtRoot, 'alias'), 'cwd_not_canonical'],
      [join(hh.wtRoot, 'plain'), 'cwd_not_worktree'],
      ['/usr/bin', 'cwd_outside_roots'],
      ['proj', 'cwd_invalid'],
      [hh.runsDir, 'cwd_forbidden'],
    ]
    mkdirSync(hh.runsDir, { mode: 0o700 })
    writeFileSync(join(hh.runsDir, '.git'), 'gitdir: /x\n')
    for (const [cwd, reason] of cases) {
      expect([cwd, hh.runner.start(hh.request(prompt, { cwd }), CTX)]).toMatchObject([cwd, { ok: false, reason }])
    }
    hh.writeHeadlessConfig({ cwdRoots: [hh.wtRoot] })
    expect(hh.runner.start(hh.request(prompt, { cwd: hh.wtRoot }), CTX)).toMatchObject({ ok: false, reason: 'cwd_outside_roots' })
    expect(hh.h.reservations()).toHaveLength(0)
    expect(hh.spawnCalls).toHaveLength(0)
  })

  it('caller, node id, prompt size, effort', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    expect(hh.runner.start(hh.request(prompt), { caller: 'fejleszto' })).toMatchObject({ ok: false, reason: 'caller_not_allowed' })
    expect(hh.runner.start(hh.request(prompt, { node_id: 'N 4a; rm -rf' }), CTX)).toMatchObject({ ok: false, reason: 'node_id_invalid' })
    expect(hh.runner.start(hh.request('x'.repeat(256 * 1024 + 1)), CTX)).toMatchObject({ ok: false, reason: 'prompt_invalid' })
    expect(hh.runner.start(hh.request(''), CTX)).toMatchObject({ ok: false, reason: 'prompt_invalid' })
    expect(hh.runner.start(hh.request(prompt, { effort: 'max' }), CTX)).toMatchObject({ ok: false, reason: 'effort_not_allowed' })
    expect(hh.h.reservations()).toHaveLength(0)
  })

  it('a hash that is not approved does not start (normal mode); a canary needs the matching approved hash', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    hh.approved = null
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    hh.approved = 'f'.repeat(64)
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(hh.runner.start(hh.request(prompt, { mode: 'canary', budget_usd: '0.90' }), CTX)).toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(hh.makeRunner({ canaryApprovedHash: () => 'e'.repeat(64) }).start(hh.request(prompt, { mode: 'canary', budget_usd: '0.90' }), { ...CTX, canaryApprovalId: 'ap-1' }))
      .toMatchObject({ ok: false, reason: 'hash_not_approved' })
    expect(hh.h.reservations()).toHaveLength(0)
    expect(hh.spawnCalls).toHaveLength(0)
  })

  it('E-05: a missing or malformed key, a closed, shadow or absent gate -- nothing is reserved or started', () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    for (const key of [null, '', 'short', 'sk-ant-has a space-000000000000']) {
      const r = hh.makeRunner({ getKey: () => key })
      expect(r.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'key_missing' })
    }
    expect(hh.makeRunner({ gate: null }).start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'gate_off' })
    const shadow = hh.h.makeGate(hh.h.db, { mode: 'shadow', raw: 'shadow', unknown: false })
    expect(hh.makeRunner({ gate: shadow }).start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'gate_shadow' })
    hh.h.gate.signal('disarm', 'test', null)
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'gate_closed' })
    expect(hh.h.reservations()).toHaveLength(0)
    expect(hh.spawnCalls).toHaveLength(0)
  })

  it('the binary: unpinned, a symlink, or a sha256 that changed before the spawn', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    hh.writeHeadlessConfig({ claudeBinSha256: undefined })
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'config_invalid' })
    hh.writeHeadlessConfig()
    const link = join(hh.real, 'bin', 'claude-link')
    symlinkSync(hh.bin, link)
    hh.writeHeadlessConfig({ claudeBin: link })
    expect(hh.runner.start(hh.request(prompt), CTX)).toMatchObject({ ok: false, reason: 'binary_not_regular' })
    hh.writeHeadlessConfig()
    // Swapped between the reservation and the spawn: the last hash catches it.
    const r = hh.makeRunner({ hooks: { afterPrepare: () => writeFileSync(hh!.bin, '#!/bin/sh\necho evil\n') } }).start(hh.request(prompt), CTX)
    expect(r).toMatchObject({ ok: true })
    const out = await (r as { done: Promise<RunOutcome> }).done
    expect(out).toMatchObject({ status: 'refused', reason: 'binary_sha256_mismatch' })
    expect(hh.spawnCalls).toHaveLength(0)
    // Nothing ran: the reservation is settled at zero, no ledger row.
    expect(hh.h.reservations().map((x) => x.status)).toEqual(['settled'])
    expect(hh.ledgerRows()).toHaveLength(0)
  })
})

describe('a run with the fake CLI', () => {
  it('success: exact env, key only through the helper, prompt on stdin, shell:false, booked once, everything wiped', async () => {
    hh = new HeadlessHarness()
    const modes: Record<string, number> = {}
    hh.runner = hh.makeRunner({
      hooks: {
        afterPrepare: (dir) => {
          for (const [k, f] of [['root', ''], ['key', 'key'], ['prompt', 'prompt.txt'], ['settings', 'settings.json'], ['config', 'config']]) {
            modes[k] = statSync(join(dir, f)).mode & 0o777
          }
        },
      },
    })
    const logs = captureLogs()
    const restore = pollute()
    let out: RunOutcome
    let id: string
    const { prompt, observe } = hh.prompt('success')
    try {
      const r = startOk(hh, prompt)
      id = r.run_id
      expect(r.config_hash).toBe(hh.approved)
      out = await r.done
    } finally {
      restore()
    }
    const seen = hh.observed(observe)
    expect(Object.keys(hh.spawnCalls[0].options.env as Record<string, string>).sort()).toEqual(HELPER_ENV)
    expect(childEnvNames(seen)).toEqual(HELPER_ENV)
    expect(seen.keySource).toBe('helper')
    expect(seen.keySha256).toBe(createHash('sha256').update(hh.key).digest('hex'))
    expect(seen.cwd).toBe(hh.worktree)
    expect(seen.stdinBytes).toBe(Buffer.byteLength(prompt))
    const argv = seen.argv as string[]
    expect(argv[0]).toBe('-p')
    expect(argv.join('\n')).not.toContain(hh.key)
    expect(argv.join('\n')).not.toContain('Do the node')
    // The spawn itself: shell:false, its own process group, the pinned file.
    expect(hh.spawnCalls).toHaveLength(1)
    const call = hh.spawnCalls[0]
    expect(call.file).toBe(hh.bin)
    expect(call.options.shell).toBe(false)
    expect(call.options.detached).toBe(true)
    expect(JSON.stringify(call)).not.toContain(hh.key)

    expect(out).toMatchObject({ status: 'succeeded', exit_code: 0, basis: 'headless_json', est_micro: 114_535, cli_micro: 74_983 })
    const rows = hh.ledgerRows()
    expect(rows).toHaveLength(1)
    expect(rows[0]).toMatchObject({ source: 'headless', run_id: id, basis: 'headless_json', est_micro: 114_535, cli_micro: 74_983 })
    expect(hh.h.reservations()).toMatchObject([{ kind: 'headless', ref: id, status: 'settled', amount_micro: 600_000 }])
    // The headless run never writes usage.jsonl (no double count).
    expect(readFileSync(hh.h.usagePath, 'utf8')).toBe('')

    const dir = hh.runDir(id)
    // Nothing of the run stays on disk (BE-4 5): the answer is in the row.
    expect(existsSync(dir)).toBe(false)
    expect(modes).toEqual({ root: 0o700, key: 0o600, prompt: 0o600, settings: 0o600, config: 0o700 })

    const row = hh.runRow(id)
    expect(row).toMatchObject({
      node_id: 'N9x', caller: 'ezermester', model: 'claude-sonnet-5-5', effort: 'high', budget_micro: 400_000, mode: 'normal',
      cwd: hh.worktree, config_hash: hh.approved, status: 'succeeded', exit_code: 0, est_micro: 114_535, cli_micro: 74_983,
      cli_version: 'unknown', key_mode: 'helper',
    })
    const result = JSON.parse(row.result_json as string) as Record<string, unknown>
    expect(result).toMatchObject({ subtype: 'success', is_error: false, num_turns: 3, total_cost_usd: 0.0749821 })
    expect(result.result).toBe('A synthetic summary of the input file.')
    // The key is nowhere: logs, the run row, the ledger, the run dir.
    const all = JSON.stringify(logs) + JSON.stringify(row) + JSON.stringify(rows)
    expect(all).not.toContain(hh.key)
    expect(all).not.toContain(hh.key.slice(-20))
    // The CLI version is logged on every run.
    expect(logs.some((l) => JSON.stringify(l).includes('"cli_version":"unknown"'))).toBe(true)
  })

  it('the key in the env (keyMode env): the canary\'s measured env, still not in argv, and its own hash', async () => {
    hh = new HeadlessHarness()
    hh.writeHeadlessConfig({ keyMode: 'env' })
    const runner = hh.runner
    expect(runner.configHash()).toBe(hh.hashFor('env'))
    expect(runner.configHash()).not.toBe(hh.approved)
    hh.approved = runner.configHash()
    const { prompt, observe } = hh.prompt('success')
    const r = runner.start(hh.request(prompt), CTX)
    if (!r.ok) throw new Error(r.reason)
    expect(await r.done).toMatchObject({ status: 'succeeded' })
    const seen = hh.observed(observe)
    expect(Object.keys(hh.spawnCalls[0].options.env as Record<string, string>).sort()).toEqual(CANARY_ENV)
    expect(childEnvNames(seen)).toEqual(CANARY_ENV)
    expect(seen.keySource).toBe('env')
    expect((seen.argv as string[]).join(' ')).not.toContain(hh.key)
    expect(existsSync(hh.runDir(r.run_id))).toBe(false)
  })

  it('is_error + credit-too-low: a signal (INCIDENT), the cost booked from the JSON', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('credit_too_low')
    const r = startOk(hh, prompt)
    const out = await r.done
    expect(out).toMatchObject({ status: 'failed', exit_code: 1, credit_too_low: true })
    expect(hh.h.state()).toMatchObject({ state: 'INCIDENT', reason: 'credit_balance_too_low' })
    expect(hh.h.events('signal').map((e) => e.reason)).toEqual(['credit_balance_too_low'])
    expect(existsSync(join(hh.runDir(r.run_id), 'key'))).toBe(false)
  })

  it('is_error + authentication_error: the 401 signal closes the gate', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('auth_error')
    const out = await startOk(hh, prompt).done
    expect(out).toMatchObject({ status: 'failed', auth_error: true })
    expect(hh.h.state()).toMatchObject({ state: 'CLOSED', reason: 'auth_401' })
  })

  it('B-04: no JSON -> the transcript, one message id once', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('nojson_transcript')
    const r = startOk(hh, prompt)
    const out = await r.done
    // msg_1 (twice in the file) and msg_2: 2000 input x 2.00 + 150 output x 10.00 USD/MTok.
    expect(out).toMatchObject({ status: 'failed', exit_code: 1, basis: 'headless_transcript', est_micro: 5_500, cli_micro: null })
    expect(existsSync(join(hh.runDir(r.run_id), 'config'))).toBe(false)
  })

  it('B-04: neither JSON nor transcript -> the whole reservation', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('nojson')
    const out = await startOk(hh, prompt).done
    expect(out).toMatchObject({ status: 'failed', basis: 'headless_reservation', est_micro: 600_000 })
  })

  it('the wall clock: SIGTERM to the group, then SIGKILL; no child or grandchild left, the key file gone', async () => {
    // 3 s: the fake must have installed its SIGTERM handler first (node
    // starts in well under that, even with the whole suite in parallel).
    hh = new HeadlessHarness()
    hh.runner = hh.makeRunner({ wallClockMs: 3_000, killGraceMs: 400 })
    const { prompt, observe } = hh.prompt('hang')
    const r = startOk(hh, prompt)
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    const seen = hh.observed(observe)
    const out = await r.done
    expect(readFileSync(observe + '.signals', 'utf8')).toContain('TERM')
    expect(out).toMatchObject({ status: 'timeout', signal: 'SIGKILL', basis: 'headless_reservation', est_micro: 600_000 })
    await until(() => !alive(seen.pid as number) && !alive(seen.grandchild as number), 5_000, 'the group to die')
    expect(existsSync(join(hh.runDir(r.run_id), 'key'))).toBe(false)
    expect(hh.runRow(r.run_id)).toMatchObject({ status: 'timeout', signal: 'SIGKILL' })
  })

  it('the wall clock: a child that obeys SIGTERM ends with it', async () => {
    hh = new HeadlessHarness()
    hh.runner = hh.makeRunner({ wallClockMs: 3_000, killGraceMs: 5_000 })
    const { prompt, observe } = hh.prompt('hang_term')
    const r = startOk(hh, prompt)
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    const out = await r.done
    expect(readFileSync(observe + '.signals', 'utf8')).toBe('TERM\n')
    expect(out).toMatchObject({ status: 'timeout', exit_code: 143, signal: null })
  })

  it('cancel: SIGTERM then SIGKILL, status cancelled, B-04 booking', async () => {
    hh = new HeadlessHarness()
    hh.runner = hh.makeRunner({ killGraceMs: 300 })
    const { prompt, observe } = hh.prompt('hang')
    const r = startOk(hh, prompt)
    await until(() => existsSync(observe), 10_000, 'the fake to start')
    const seen = hh.observed(observe)
    expect(hh.runner.cancel(r.run_id)).toBe(true)
    expect(hh.runner.cancel('hr-nope')).toBe(false)
    expect(await r.done).toMatchObject({ status: 'cancelled', basis: 'headless_reservation' })
    await until(() => !alive(seen.grandchild as number), 5_000, 'the grandchild to die')
  })

  it('residue: the key in config/ and its tail in the run dir -- only the file names are logged, the files are gone', async () => {
    hh = new HeadlessHarness()
    const logs = captureLogs()
    const { prompt } = hh.prompt('leak')
    const r = startOk(hh, prompt)
    const out = await r.done
    expect(out.status).toBe('secret_residue')
    expect(out.residue).toEqual(['config/leak.json', 'stray.txt'])
    const dir = hh.runDir(r.run_id)
    expect(existsSync(dir)).toBe(false)
    const row = hh.runRow(r.run_id)
    expect(JSON.parse(row.residue_json as string)).toEqual(['config/leak.json', 'stray.txt'])
    const text = JSON.stringify(logs) + JSON.stringify(row)
    expect(text).toContain('config/leak.json')
    expect(text).not.toContain(hh.key)
    expect(text).not.toContain(hh.key.slice(-20))
    // The spend still counts.
    expect(hh.ledgerRows()).toMatchObject([{ basis: 'headless_json', run_id: r.run_id }])
  })

  it('a .credentials.json in the run config/ stops the start; nothing ran, nothing booked', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    const runner = hh.makeRunner({ hooks: { afterPrepare: (dir) => writeFileSync(join(dir, 'config', '.credentials.json'), '{}') } })
    const r = runner.start(hh.request(prompt), CTX)
    if (!r.ok) throw new Error(r.reason)
    expect(await r.done).toMatchObject({ status: 'refused', reason: 'credentials_present' })
    expect(hh.spawnCalls).toHaveLength(0)
    expect(hh.ledgerRows()).toHaveLength(0)
    expect(hh.h.reservations().map((x) => x.status)).toEqual(['settled'])
    expect(existsSync(hh.runDir(r.run_id))).toBe(false)
  })

  it('the key file is gone after a thrown exception: in preparation, in the spawner, in the booking', async () => {
    hh = new HeadlessHarness()
    const { prompt } = hh.prompt('success')
    let keySeen = false
    const prep = hh.makeRunner({ hooks: { afterPrepare: (dir) => { keySeen = existsSync(join(dir, 'key')); throw new Error('boom in preparation') } } })
    const r1 = prep.start(hh.request(prompt), CTX)
    if (!r1.ok) throw new Error(r1.reason)
    expect(await r1.done).toMatchObject({ status: 'refused', reason: 'prepare_failed' })
    expect(keySeen).toBe(true)
    expect(existsSync(join(hh.runDir(r1.run_id), 'key'))).toBe(false)

    const spawnFails = hh.makeRunner({ spawner: () => { throw new Error('spawn exploded') } })
    const r2 = spawnFails.start(hh.request(prompt), CTX)
    if (!r2.ok) throw new Error(r2.reason)
    expect(await r2.done).toMatchObject({ status: 'spawn_failed' })
    expect(existsSync(join(hh.runDir(r2.run_id), 'key'))).toBe(false)

    // The gate's booking throws: the key file goes first anyway, the run row says why.
    const throwingGate = new Proxy(hh.h.gate, {
      get(t, p, rcv) {
        if (p === 'settleHeadless') return () => { throw new Error('settle exploded') }
        const v = Reflect.get(t, p, rcv)
        return typeof v === 'function' ? v.bind(t) : v
      },
    })
    const settleFails = hh.makeRunner({ gate: throwingGate })
    const r3 = settleFails.start(hh.request(prompt), CTX)
    if (!r3.ok) throw new Error(r3.reason)
    const out3 = await r3.done
    expect(out3.status).toBe('succeeded')
    expect(out3.errors).toContain('settle')
    expect(existsSync(join(hh.runDir(r3.run_id), 'key'))).toBe(false)
    expect(existsSync(join(hh.runDir(r3.run_id), 'config'))).toBe(false)
    expect(hh.h.reservations().filter((x) => x.ref === r3.run_id).map((x) => x.status)).toEqual(['open'])
  })

  it('spawnHeadless refuses without -p, with a shell, or not detached -- before the spawner runs', () => {
    const calls: string[] = []
    const spy = ((file: string) => { calls.push(file); throw new Error('must not be reached') }) as never
    const args = buildRunArgs({ model: 'claude-sonnet-5-5', effort: 'high', budgetMicro: asMicro(400_000), settingsPath: '/x/settings.json', toolProfile: 'read' })
    const opts = { cwd: '/x', env: {}, detached: true, shell: false as const, stdio: 'ignore' as const }
    expect(() => spawnHeadless(spy, '/x/claude', args.slice(1), 'read', opts)).toThrow(/-p/)
    expect(() => spawnHeadless(spy, '/x/claude', args, 'read', { ...opts, shell: true as never })).toThrow(/shell/)
    expect(() => spawnHeadless(spy, '/x/claude', args, 'read', { ...opts, detached: false })).toThrow(/detached/)
    expect(() => spawnHeadless(spy, 'claude', args, 'read', opts)).toThrow(/absolute/)
    expect(calls).toEqual([])
  })

  it('two runs at once are independent; each is booked once', async () => {
    hh = new HeadlessHarness()
    // Two at once: maxConcurrent 2 (BE-4b's default is 1).
    hh.writeHeadlessConfig({ maxConcurrent: 2 })
    const a = hh.prompt('success')
    const b = hh.prompt('nojson')
    const ra = startOk(hh, a.prompt)
    const rb = startOk(hh, b.prompt, { model: 'claude-opus-5-5', effort: 'xhigh', budget_usd: '1.00' })
    const [oa, ob] = await Promise.all([ra.done, rb.done])
    expect(oa.status).toBe('succeeded')
    expect(ob).toMatchObject({ basis: 'headless_reservation', est_micro: 1_500_000 })
    expect(hh.ledgerRows().map((r) => r.run_id).sort()).toEqual([ra.run_id, rb.run_id].sort())
    expect(hh.runner.activeCount()).toBe(0)
  })
})

describe('the JSON result and the restart helpers (unit)', () => {
  const ok = (over: Record<string, unknown> = {}) => Buffer.from(JSON.stringify({
    type: 'result', subtype: 'success', is_error: false, num_turns: 2, total_cost_usd: 0.5, result: 'text',
    usage: { input_tokens: 1, output_tokens: 2, cache_creation_input_tokens: 3, cache_read_input_tokens: 4 },
    modelUsage: { 'claude-opus-5-5': { inputTokens: 1, outputTokens: 2, cacheReadInputTokens: 4, cacheCreationInputTokens: 3, costUSD: 0.5 } },
    ...over,
  }))

  it('modelUsage is the ledger input; one missing count makes the JSON unusable (the fallback books more)', () => {
    expect(parseHeadlessResult(ok(), '', 'claude-sonnet-5-5')?.ledger).toEqual({
      total_cost_usd: 0.5, usage: [{ model: 'claude-opus-5-5', input_tokens: 1, output_tokens: 2, cache_write_tokens: 3, cache_read_tokens: 4 }],
    })
    const missing = ok({ modelUsage: { 'claude-opus-5-5': { inputTokens: 1, outputTokens: 2, cacheCreationInputTokens: 3, costUSD: 0.5 } } })
    expect(parseHeadlessResult(missing, '', 'claude-sonnet-5-5')?.ledger).toBeNull()
    const negative = ok({ modelUsage: { 'claude-opus-5-5': { inputTokens: -1, outputTokens: 2, cacheReadInputTokens: 4, cacheCreationInputTokens: 3 } } })
    expect(parseHeadlessResult(negative, '', 'claude-sonnet-5-5')?.ledger).toBeNull()
    // No modelUsage: the totals, on the run's own model.
    expect(parseHeadlessResult(ok({ modelUsage: {} }), '', 'claude-sonnet-5-5')?.ledger?.usage)
      .toEqual([{ model: 'claude-sonnet-5-5', input_tokens: 1, output_tokens: 2, cache_write_tokens: 3, cache_read_tokens: 4 }])
    expect(parseHeadlessResult(Buffer.from('not json'), '', 'claude-sonnet-5-5')).toBeNull()
    expect(parseHeadlessResult(null, '', 'claude-sonnet-5-5')).toBeNull()
  })

  it('a successful answer that talks about credit is not a signal; is_error or stderr is', () => {
    const talk = ok({ result: 'Your credit balance is too low to access the Anthropic API. authentication_error' })
    expect(parseHeadlessResult(talk, '', 'claude-sonnet-5-5')).toMatchObject({ creditTooLow: false, authError: false })
    expect(parseHeadlessResult(ok({ is_error: true, result: 'Credit balance too low · Add funds' }), '', 'x')).toMatchObject({ creditTooLow: true })
    expect(parseHeadlessResult(null, 'Credit balance too low', 'x')).toMatchObject({ creditTooLow: true, ledger: null })
    const summary = parseHeadlessResult(ok(), '', 'x')?.summary as Record<string, unknown>
    expect(summary).not.toHaveProperty('result')
    expect(summary).toMatchObject({ subtype: 'success', is_error: false, num_turns: 2, total_cost_usd: 0.5 })
  })

  function insertRunning(h: HeadlessHarness, id: string, pid: number, start: string): RunRow {
    const res = h.h.gate.reserve({ kind: 'headless', budget_micro: asMicro(400_000), model: 'claude-sonnet-5-5', ref: id, caller: 'ezermester' })
    if (!('ok' in res) || !res.ok) throw new Error('reserve failed')
    h.h.db.prepare(`INSERT INTO credit_headless_runs (id, node_id, caller, model, effort, budget_micro, reservation_id, mode, cwd,
        config_hash, key_mode, pid, pid_start, pgid, status, started_at, deadline_at, run_dir)
      VALUES (?, 'N9x', 'ezermester', 'claude-sonnet-5-5', 'high', 400000, ?, 'normal', ?, ?, 'helper', ?, ?, ?, 'running', ?, ?, ?)`)
      .run(id, res.reservation_id, h.worktree, h.approved, pid, start, pid, h.h.now, h.h.now + 60_000, h.runDir(id))
    return h.runner.openRows().find((r) => r.id === id) as RunRow
  }

  it('leftovers of a dead run are killed only when their argv/env names the run dir; a group id alone is not enough', () => {
    hh = new HeadlessHarness()
    const kills: Array<[number, string | number]> = []
    const dirOf = (id: string) => hh!.runDir(id)
    let procs: ProcInfo[] = [
      { pid: 4242, pgid: 4242, start: 'Other start', command: '/usr/bin/vim notes' },
      { pid: 4243, pgid: 4242, start: 'x', command: '/bin/zsh' },
      { pid: 77, pgid: 1, start: 'y', command: 'launchd' },
    ]
    const runner = hh.makeRunner({
      listProcesses: () => procs,
      procStart: (pid) => procs.find((p) => p.pid === pid)?.start ?? null,
      kill: (pid, sig) => {
        kills.push([pid, sig])
        if (sig === 0 && !procs.some((p) => p.pid === pid)) throw Object.assign(new Error('no such process'), { code: 'ESRCH' })
      },
    })
    // The leader's pid is alive but started at another time: a reused pid.
    const reused = insertRunning(hh, 'hr-reused-leader', 4242, 'Run start')
    expect(runner.processMatches(4242, 'Run start')).toBe(false)
    expect(runner.reconcileRow(reused)).toBe('closed')
    expect(kills.filter(([, s]) => s !== 0)).toEqual([])

    // The leader is gone; one member names the run dir in its env, one only shares the group id.
    procs = [
      { pid: 4343, pgid: 4300, start: 'x', command: `/opt/x/node tool.js CLAUDE_CONFIG_DIR=${dirOf('hr-dead-leader')}/config PATH=/usr/bin:/bin` },
      { pid: 4344, pgid: 4300, start: 'x', command: '/opt/x/node other.js' },
      { pid: 77, pgid: 1, start: 'y', command: 'launchd' },
    ]
    const dead = insertRunning(hh, 'hr-dead-leader', 4300, 'Run start')
    expect(runner.reconcileRow(dead)).toBe('closed')
    expect(kills.filter(([, s]) => s !== 0)).toEqual([[4343, 'SIGKILL']])
    expect(hh.runRow('hr-dead-leader')).toMatchObject({ status: 'lost', basis: 'headless_reservation' })
  })

  it('ps unusable: the launch goes on without a start time; an unverifiable pid is never re-attached or signalled', async () => {
    hh = new HeadlessHarness()
    const kills: Array<[number, string | number]> = []
    const runner = hh.makeRunner({
      procStart: () => { throw new Error('ps is not usable: EPERM') },
      kill: (pid, sig) => { kills.push([pid, sig]); process.kill(pid, sig) },
    })
    const { prompt } = hh.prompt('success')
    const r = runner.start(hh.request(prompt), CTX)
    if (!r.ok) throw new Error(r.reason)
    expect(await r.done).toMatchObject({ status: 'succeeded' })
    expect(hh.runRow(r.run_id)).toMatchObject({ pid_start: null })
    expect(runner.processMatches(process.pid, 'any start')).toBe(false)
    expect(runner.processMatches(process.pid, null)).toBe(false)
    expect(kills.filter(([pid, sig]) => pid === process.pid && sig !== 0)).toEqual([])
  })
})

function realStore(h: HeadlessHarness): string {
  return join(h.real, 'store')
}
