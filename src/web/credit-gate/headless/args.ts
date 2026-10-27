// The headless run's argv (card fec6335f, spec E-02, I-05; blueprint 4.3,
// node N4a).
//
// The template is the command the canary ran successfully on 2026-10-16 (CLI
// 2.1.299):
//   -p --bare --restricted --model <m> --max-budget-usd <b> --output-format json
//   --no-session-persistence --tools Read --allowedTools Read
//   --permission-mode dontAsk --permission-prompts none --strict-mcp-config
//   --disable-slash-commands
// plus two flags of the same --help: --effort (N0 3.8) and --settings (the
// key helper, env.ts). The prompt is NOT in argv: it goes on stdin, from a
// file, so it cannot be mistaken for a value of the variadic --tools /
// --allowedTools, and it is not visible in `ps`.
//
//  - `-p` is always the first argument, exactly once (I-05: never an
//    interactive session). assertRunArgs() re-checks the whole argv against
//    the template right before the spawn; anything missing or extra throws.
//  - `--restricted` (--help): no command tools (Bash), no WebFetch, the file
//    tools confined to the working directory, the user/project/local settings
//    files ignored. `--bare`: no hooks, plugins, auto-memory, CLAUDE.md
//    discovery or keychain; the key only from the env or the helper.
//  - Never: --continue, --resume, --channels, --dangerously-skip-permissions,
//    --fallback-model (the model allowlist), --mcp-config, --add-dir. The
//    pinned CLI's --help has no --max-turns; the budget is the cap.
//  - Tools: a closed profile. `read` is the canary's (Read only), and the only
//    one enabled: the config (headless.toolProfile) accepts nothing else, and
//    the runner refuses anything else. `edit` (Read, Edit, Write) is defined
//    for the hash only; it stays off until a canary measures what the CLI does
//    with it under --restricted (BE-4, 2026-10-16).

import type { Micro } from '../types.js'

export type Effort = 'high' | 'xhigh'
export const EFFORTS: readonly Effort[] = ['high', 'xhigh']

export type ToolProfile = 'read' | 'edit'
export const TOOL_PROFILES: Readonly<Record<ToolProfile, string>> = Object.freeze({
  read: 'Read',
  edit: 'Read,Edit,Write',
})

export interface RunArgsOptions {
  readonly model: string
  readonly effort: Effort
  /** The --max-budget-usd cap: a whole number of cents. */
  readonly budgetMicro: Micro
  readonly settingsPath: string
  readonly toolProfile: ToolProfile
}

/** micro-USD as the CLI's two-decimal USD string; only whole cents. */
export function usdArg(micro: Micro): string {
  if (!Number.isSafeInteger(micro) || micro <= 0 || micro % 10_000 !== 0) throw new RangeError('usdArg: not a positive whole-cent amount')
  const whole = Math.floor(micro / 1_000_000)
  const cents = (micro % 1_000_000) / 10_000
  return `${whole}.${String(cents).padStart(2, '0')}`
}

/** Placeholders of the per-run values in the template (config-hash.ts). */
export const ARG_PLACEHOLDERS = Object.freeze({ model: '<model>', effort: '<effort>', budget: '<budget>' })

function template(o: { model: string; effort: string; budget: string; settingsPath: string; tools: string }): string[] {
  return [
    '-p',
    '--bare',
    '--restricted',
    '--model', o.model,
    '--effort', o.effort,
    '--max-budget-usd', o.budget,
    '--output-format', 'json',
    '--no-session-persistence',
    '--settings', o.settingsPath,
    // The variadic tool lists are followed by options only, never by a
    // positional (the canary's note): there is no positional at all.
    '--tools', o.tools,
    '--allowedTools', o.tools,
    '--permission-mode', 'dontAsk',
    '--permission-prompts', 'none',
    '--strict-mcp-config',
    '--disable-slash-commands',
  ]
}

/**
 * Where `--settings` stands in the argv, counted from `-p` (= 0): a process is
 * a run's CLI only with the run's settings file in exactly this place
 * (runner.ts, runLeaderOf). Taken from the template, so it cannot drift.
 */
export const SETTINGS_ARG_INDEX = template({ model: 'm', effort: 'e', budget: 'b', settingsPath: '/s', tools: 't' }).indexOf('--settings')

export function buildRunArgs(o: RunArgsOptions): string[] {
  if (!EFFORTS.includes(o.effort)) throw new Error('buildRunArgs: effort not allowed')
  const tools = TOOL_PROFILES[o.toolProfile]
  if (typeof tools !== 'string') throw new Error('buildRunArgs: unknown tool profile')
  if (typeof o.model !== 'string' || !/^[a-z0-9][a-z0-9.-]{0,63}$/.test(o.model)) throw new Error('buildRunArgs: model id not allowed')
  if (typeof o.settingsPath !== 'string' || !o.settingsPath.startsWith('/')) throw new Error('buildRunArgs: settings path must be absolute')
  return template({ model: o.model, effort: o.effort, budget: usdArg(o.budgetMicro), settingsPath: o.settingsPath, tools })
}

/** The per-run values of an argv in template positions, or null when it does not fit. */
export function argSlots(args: readonly string[]): { model: string; effort: string; budget: string; settingsPath: string } | null {
  const at = (flag: string): string | null => {
    const i = args.indexOf(flag)
    return i >= 0 && i + 1 < args.length ? args[i + 1] : null
  }
  const model = at('--model')
  const effort = at('--effort')
  const budget = at('--max-budget-usd')
  const settingsPath = at('--settings')
  if (model === null || effort === null || budget === null || settingsPath === null) return null
  return { model, effort, budget, settingsPath }
}

/**
 * The last check before the spawn: `-p` first and only once, and the whole
 * argv equal to the template with this run's values. Throws otherwise.
 */
export function assertRunArgs(args: readonly string[], toolProfile: ToolProfile): void {
  if (!Array.isArray(args) || args.length === 0 || args[0] !== '-p') throw new Error('headless run refused: -p must be the first argument')
  if (args.filter((a) => a === '-p' || a === '--print').length !== 1) throw new Error('headless run refused: -p exactly once')
  const slots = argSlots(args)
  if (slots === null) throw new Error('headless run refused: the argv does not fit the template')
  if (!EFFORTS.includes(slots.effort as Effort)) throw new Error('headless run refused: effort not allowed')
  if (!/^(0|[1-9][0-9]{0,5})\.[0-9]{2}$/.test(slots.budget)) throw new Error('headless run refused: budget not a USD amount')
  const tools = TOOL_PROFILES[toolProfile]
  if (typeof tools !== 'string') throw new Error('headless run refused: unknown tool profile')
  const want = template({ ...slots, tools })
  if (args.length !== want.length || args.some((a, i) => a !== want[i])) throw new Error('headless run refused: the argv differs from the template')
}
