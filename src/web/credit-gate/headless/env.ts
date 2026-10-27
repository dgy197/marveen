// The headless run's environment, its paths and its settings file (card
// fec6335f, spec E-01, I-05; blueprint 4.3, node N4a).
//
// The child's env is built from NOTHING but the run's own paths and fixed
// values: buildRunEnv takes no parent env at all, so no name the dashboard
// carries (CLAUDE_CODE_OAUTH_TOKEN, ANTHROPIC_AUTH_TOKEN, ANTHROPIC_BASE_URL,
// CLAUDECODE, CLAUDE_CODE_ENTRYPOINT, TMUX, *_BOT_TOKEN, SSH_AUTH_SOCK,
// GH_TOKEN, NODE_OPTIONS, DYLD_*, BASH_ENV, PYTHONPATH, npm_config_*,
// MARVEEN_*, ...) can reach it, not even by mistake.
//
// The list is the canary's (2026-10-16, CLI 2.1.299; it ran and succeeded
// with exactly these names): HOME, PATH, TMPDIR, CLAUDE_CONFIG_DIR,
// TELEGRAM_STATE_DIR, DISABLE_AUTOUPDATER=1,
// CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1, DISABLE_TELEMETRY=1, and the
// key. Blueprint 4.3 also listed USER, LOGNAME, LANG, the other channels'
// state dirs, CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY and
// CLAUDE_CODE_ENABLE_PROMPT_SUGGESTION; they are left out because the
// measured run did without them (--bare loads no channel plugin, and
// NONESSENTIAL_TRAFFIC already turns surveys off, N0 4.5).
//
// The key (decision, N4a; config headless.keyMode, default `helper`): by
// default it does NOT go into the env. It sits in a 0600 file of the 0700 run
// dir, and the run's own settings.json names an apiKeyHelper that prints it
// (`--bare` reads Anthropic auth only from ANTHROPIC_API_KEY or from an
// apiKeyHelper of --settings, N0 3.9). What that buys, and what it does not:
//  - NOT a defence against a process of the same user: such a process can
//    list the runs dir and read the file for the whole run (BE-4 P3, measured),
//    just as it can read an env value with `ps -E` -- or the Vault itself;
//  - it keeps the key out of the env of every child the CLI starts (an env
//    value is inherited; the helper's output stays in the CLI process), out of
//    `ps -E` listings and crash reports, and out of the worktree: the run dir
//    lies outside it, where the confined Read tool cannot open it;
//  - the file is deleted at the end of every run, and at every dashboard start
//    (reconcile.ts).
// TODO(kanári): if the CLI runs the helper only once (no refresh within a
// run), the key file could be deleted right after the first read. That has
// to be measured on the pinned CLI first; until then the file stays for the
// whole run (the helper's cache lifetime is 5 minutes, N0 4.1).
//
// Each key mode is its own config hash (config-hash.ts hashes keyMode, the env
// names and the settings file), so each needs its OWN canary: the canary of
// 2026-10-16 measured the env mode only, and its approval does not cover
// `helper`. A helper that does not work fails as an auth error -- before any
// spend.

import { join } from 'node:path'

export type KeyMode = 'helper' | 'env'
export const KEY_MODES: readonly KeyMode[] = ['helper', 'env']

/** PATH of the child: the system directories only (the helper is /bin/cat). */
export const RUN_ENV_PATH = '/usr/bin:/bin'

/** Fixed values, the same on every run. */
const FIXED_ENV: Readonly<Record<string, string>> = Object.freeze({
  PATH: RUN_ENV_PATH,
  DISABLE_AUTOUPDATER: '1',
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC: '1',
  DISABLE_TELEMETRY: '1',
})

/** A run directory never holds a path that would need shell quoting. */
const SAFE_PATH_RE = /^\/[A-Za-z0-9_./-]+$/

export interface RunPaths {
  readonly root: string
  readonly prompt: string
  readonly settings: string
  readonly key: string
  readonly stdout: string
  readonly stderr: string
  readonly config: string
  readonly home: string
  readonly tmp: string
  readonly emptyState: string
}

/** The fixed layout of one run directory. */
export function runPaths(root: string): RunPaths {
  return Object.freeze({
    root,
    prompt: join(root, 'prompt.txt'),
    settings: join(root, 'settings.json'),
    key: join(root, 'key'),
    stdout: join(root, 'stdout.json'),
    stderr: join(root, 'stderr.txt'),
    config: join(root, 'config'),
    home: join(root, 'home'),
    tmp: join(root, 'tmp'),
    emptyState: join(root, 'empty-state'),
  })
}

/** Subdirectories the child may write into; removed after every run. */
export const WIPED_SUBDIRS = ['config', 'home', 'tmp', 'empty-state'] as const

/** The env names of a run, sorted. */
export function runEnvNames(keyMode: KeyMode): readonly string[] {
  const names = [...Object.keys(FIXED_ENV), 'HOME', 'TMPDIR', 'CLAUDE_CONFIG_DIR', 'TELEGRAM_STATE_DIR']
  if (keyMode === 'env') names.push('ANTHROPIC_API_KEY')
  return Object.freeze(names.sort())
}

/**
 * The child's whole environment. `key` must be given exactly in `env` mode
 * (and is then the only secret in it); in `helper` mode it must be null.
 */
export function buildRunEnv(paths: RunPaths, keyMode: KeyMode, key: string | null): Record<string, string> {
  if (!KEY_MODES.includes(keyMode)) throw new Error('buildRunEnv: unknown key mode')
  if ((keyMode === 'env') !== (key !== null)) throw new Error('buildRunEnv: the key belongs in the env exactly in env mode')
  const env: Record<string, string> = {
    ...FIXED_ENV,
    HOME: paths.home,
    TMPDIR: paths.tmp,
    CLAUDE_CONFIG_DIR: paths.config,
    // Empty and private: a channel plugin, should one load, finds no bot
    // state here and cannot fall back to the main agent's (flotta-CLAUDE.md).
    TELEGRAM_STATE_DIR: paths.emptyState,
  }
  if (key !== null) env.ANTHROPIC_API_KEY = key
  const names = Object.keys(env).sort()
  const want = runEnvNames(keyMode)
  if (names.length !== want.length || names.some((n, i) => n !== want[i])) throw new Error('buildRunEnv: not the allowlist')
  for (const v of Object.values(env)) {
    if (typeof v !== 'string' || v.includes('\0')) throw new Error('buildRunEnv: a value is not a plain string')
  }
  return env
}

/**
 * The run's own settings.json (passed with --settings). In helper mode it
 * names the helper that prints the key file; nothing else is set, so the
 * flag-level settings stay as small as the measured command's.
 */
export function buildRunSettings(paths: RunPaths, keyMode: KeyMode): Record<string, string> {
  if (keyMode === 'env') return {}
  if (!SAFE_PATH_RE.test(paths.key)) throw new Error('buildRunSettings: the key path needs quoting; refusing')
  return { apiKeyHelper: `/bin/cat '${paths.key}'` }
}

/** True when a run directory path is safe to name in the helper command. */
export function isSafeRunPath(p: string): boolean {
  return SAFE_PATH_RE.test(p) && !p.split('/').includes('..')
}
