// The headless runner's config hash (card fec6335f, spec E-04, K-01;
// blueprint 4.3, node N4a): sha256 of a canonical JSON of everything that
// decides HOW the CLI is started -- the argv template, the env names and
// their fixed values, the settings file, the key mode and the runner's code
// version. A canary approves one hash; a normal run starts only under the
// approved hash, and any change of a flag, an env value or the settings is a
// new hash, so it needs a new canary.
//
// Not in the hash, on purpose:
//  - the per-run values (model, effort, budget: the canary approval binds
//    model and budget itself; the run directory; the key);
//  - the CLI: its path, its sha256 and its version (Brainy, 2026-10-16). The
//    binary is pinned by sha256 and checked right before every spawn, and the
//    version is logged and stored with every run, but a CLI update does not
//    by itself ask for a new canary.
//
// One hash per launch mode: the key mode (`helper` or `env`) changes the env
// names and the settings file, so the two modes hash differently and each
// needs its own canary. The canary of 2026-10-16 measured `env`; `helper`, the
// default, has not been approved by any canary yet.
//
// Canonical JSON: keys sorted, no whitespace, UTF-8 (the approval payloads of
// blueprint 3.7 use the same form).

import { createHash } from 'node:crypto'
import { ARG_PLACEHOLDERS, argSlots, buildRunArgs, type ToolProfile } from './args.js'
import { buildRunEnv, buildRunSettings, runPaths, type KeyMode } from './env.js'
import type { Micro } from '../types.js'

/** Bumped whenever the runner changes how it starts or confines the CLI. */
export const RUNNER_CODE_VERSION = 'credit-headless-runner/1'

const RUN_PLACEHOLDER = '<run>'
const KEY_PLACEHOLDER = '<key>'
/** A stand-in run dir for the template; any absolute path would do. */
const TEMPLATE_RUN_DIR = '/credit-gate-run'

export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') return JSON.stringify(v)
  if (typeof v === 'number') {
    if (!Number.isFinite(v)) throw new Error('canonicalJson: not a finite number')
    return JSON.stringify(v)
  }
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(',')}]`
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>
    const keys = Object.keys(o).sort()
    return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(o[k])}`).join(',')}}`
  }
  throw new Error('canonicalJson: unsupported value')
}

export interface ConcreteRun {
  readonly args: readonly string[]
  readonly env: Readonly<Record<string, string>>
  readonly settings: unknown
  readonly keyMode: KeyMode
  /** The run directory: every occurrence becomes `<run>`. */
  readonly runDir: string
}

function deRun(s: string, runDir: string): string {
  return s.split(runDir).join(RUN_PLACEHOLDER)
}

function deRunDeep(v: unknown, runDir: string): unknown {
  if (typeof v === 'string') return deRun(v, runDir)
  if (Array.isArray(v)) return v.map((x) => deRunDeep(x, runDir))
  if (v !== null && typeof v === 'object') {
    return Object.fromEntries(Object.entries(v as Record<string, unknown>).map(([k, x]) => [k, deRunDeep(x, runDir)]))
  }
  return v
}

/**
 * The hash of what is about to be started: the run's own argv, env and
 * settings, with the run directory, the key and the per-run values replaced
 * by placeholders. Equal to computeRunnerConfigHash() exactly when the run is
 * started the way the template says.
 */
export function configHashOf(run: ConcreteRun): string {
  if (typeof run.runDir !== 'string' || !run.runDir.startsWith('/') || run.runDir.length < 2) throw new Error('configHashOf: runDir must be absolute')
  const slots = argSlots(run.args)
  const args = run.args.map((a, i) => {
    const prev = i > 0 ? run.args[i - 1] : null
    if (slots && prev === '--model') return ARG_PLACEHOLDERS.model
    if (slots && prev === '--effort') return ARG_PLACEHOLDERS.effort
    if (slots && prev === '--max-budget-usd') return ARG_PLACEHOLDERS.budget
    return deRun(a, run.runDir)
  })
  const env: Record<string, string> = {}
  for (const [k, v] of Object.entries(run.env)) env[k] = k === 'ANTHROPIC_API_KEY' ? KEY_PLACEHOLDER : deRun(v, run.runDir)
  const doc = {
    v: RUNNER_CODE_VERSION,
    keyMode: run.keyMode,
    prompt: 'stdin',
    args,
    env,
    settings: deRunDeep(run.settings, run.runDir),
  }
  return createHash('sha256').update(canonicalJson(doc), 'utf8').digest('hex')
}

/** The hash of the runner's template for a key mode and a tool profile. */
export function computeRunnerConfigHash(o: { readonly keyMode: KeyMode; readonly toolProfile: ToolProfile }): string {
  const p = runPaths(TEMPLATE_RUN_DIR)
  return configHashOf({
    args: buildRunArgs({ model: 'claude-sonnet-5-5', effort: 'high', budgetMicro: 10_000 as Micro, settingsPath: p.settings, toolProfile: o.toolProfile }),
    env: buildRunEnv(p, o.keyMode, o.keyMode === 'env' ? KEY_PLACEHOLDER : null),
    settings: buildRunSettings(p, o.keyMode),
    keyMode: o.keyMode,
    runDir: p.root,
  })
}
