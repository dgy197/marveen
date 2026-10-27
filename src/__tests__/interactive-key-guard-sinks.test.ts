// fec6335f N3a: the launch-sink inventory for the interactive-key guard.
//
// Every place in src/ and scripts/ that hands a command to `tmux new-session` or
// `tmux respawn-pane` is listed below with its status. The scan fails on any
// sink the list does not name, so a NEW launch path cannot ship without either
// the guard or an explicit, reviewed entry here (pattern: root-sandbox-every-
// launch.test.ts, and the "5th launch sink" lesson in model-id-injection.test.ts).
//
//   n3a      -- a sub-agent path, guarded by node N3a; its guard markers are
//               checked next to it.
//   n3b      -- a MAIN-agent path, guarded by node N3b; the same marker check.
//               (No status means "pending" any more: every claude sink below
//               carries its guard, and a test says so.)
//   no-claude-- starts no claude (a placeholder window, the codex runner).
//   text     -- the words appear in a message, not in a command.
import { describe, it, expect } from 'vitest'
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')

type Status = 'n3a' | 'n3b' | 'no-claude' | 'text'
interface Entry {
  file: string
  match: string
  count?: number
  status: Status
  // n3a/n3b: every marker must appear within `window` lines BEFORE the sink
  // (or within `after` lines after it: a pane command on a continuation line).
  // Checked at EVERY occurrence when count > 1.
  guard?: string[]
  window?: number
  after?: number
  note: string
}

export const INVENTORY: Entry[] = [
  // ---- N3a: sub-agent, worker, background, cron watchdog ----
  {
    file: 'src/web/agent-process.ts', match: "runTmux(startTarget, ['new-session', '-d', '-s', session, buildLaunchCmd(dir)]", status: 'n3a',
    guard: ['const buildLaunchCmd = (launchCwd: string) => {', 'const cmd = `${keyUnsetPrefix}${umaskPrefix}', 'assertLaunchCmdClean(cmd, { policy: keyPolicy, firstParty: keyGuardFirstParty })'], window: 40,
    note: 'startAgentProcess: start button, restart, context guard, auto-restart, reconcile, reauth-healer, model-fallback, schedule-runner autostart',
  },
  {
    file: 'src/web/agent-process.ts', match: "runTmux(null, ['new-session', '-d', '-s', session, buildLaunchCmd(fallbackCwd)]", status: 'n3a',
    guard: ['assertLaunchCmdClean(cmd, { policy: keyPolicy, firstParty: keyGuardFirstParty })'], window: 160,
    note: 'startAgentProcess EPERM /tmp fallback (same buildLaunchCmd)',
  },
  {
    file: 'src/web/agent-process.ts', match: "runTmux(host, ['new-session', '-d', '-s', session, cmd]", status: 'n3a',
    guard: ['const keyGuard = decideInteractiveLaunch(keyGuardInput)', 'const cmd = keyGuard.unsetPrefix + buildRemoteLaunchCommand(', 'assertLaunchCmdClean(cmd, {'], window: 25,
    note: 'startRemoteAgentProcess (ssh)',
  },
  {
    file: 'src/web/agent-worker.ts', match: "execFileSync(TMUX, ['new-session', '-d', '-s', ctx.session, '-c', ctx.home, 'bash', '-lc', launch]", status: 'n3a',
    guard: ['workerKeyUnset +', 'assertLaunchCmdClean(launch, { policy: keyPolicy, firstParty: workerFirstParty })'], window: 30,
    note: 'worker sessions (slow + fast)',
  },
  {
    file: 'src/web/routes/background-tasks.ts', match: "'new-session', '-d', '-s', session, '-x', '200', '-y', '50',", status: 'n3a',
    guard: ["const shellCmd = (keyPolicy === 'forbid' ? INTERACTIVE_UNSET : '') + [", 'assertLaunchCmdClean(shellCmd, { policy: keyPolicy, firstParty: true })'], window: 15,
    note: 'background claude -p tasks (the env is filtered by backgroundTaskEnv)',
  },
  {
    file: 'scripts/watchdog.sh', match: 'tmux new-session -d -s "$SESSION_NAME" "$CMD"', status: 'n3a',
    guard: ['KEY_DECISION="$(interactive_key_decision "$AGENT_DIR" "$MODEL")"', 'unset) CMD="unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && ${CMD}" ;;'], window: 15,
    note: 'cron sub-agent restart',
  },
  // ---- N3b: the main agent ----
  {
    file: 'src/web/channel-monitor.ts', match: "execFileSync(tmuxBin(), ['respawn-pane', '-k', '-t', exactTmuxTarget(MAIN_CHANNELS_SESSION), claudeCmd]", count: 3, status: 'n3b',
    guard: ['const claudeCmd = buildMainSessionRespawnCmd({', 'config: resolveMainConfigDecision(),'], window: 30,
    note: 'main-session respawn (fresh, continue, keep-alive/stuck recovery) via buildMainSessionRespawnCmd (unset + assert inside, checked below); resolveMainConfigDecision runs the settings scan',
  },
  {
    file: 'scripts/channels.sh', match: '$TMUX new-session -d -s "$SESSION" -c "$INSTALL_DIR"', status: 'n3b',
    guard: ['"${AUTH_PANE_ENV}${KEY_UNSET_ENV}${STATE_DIR_ENV}'], window: 0, after: 1,
    note: 'main channels boot (the forbid-mode KEY_UNSET_ENV, -g -u and .env/inherited unset are checked below)',
  },
  {
    file: 'scripts/channels.sh', match: '$TMUX new-session -d -s "$SESSION" -c "$_CHANNELS_STARTDIR"', status: 'n3b',
    guard: ['"${AUTH_PANE_ENV}${KEY_UNSET_ENV}${STATE_DIR_ENV}'], window: 0, after: 1,
    note: 'main channels EPERM fallback',
  },
  {
    file: 'scripts/channel-watchdog.sh', match: '"$TMUX_BIN" respawn-pane -k -t "=$SESSION:" "$RESPAWN_CMD"', status: 'n3b',
    guard: ['KEY_POLICY="$(bash "$INSTALL_DIR/scripts/channels.sh" --interactive-key-policy', '[ "$KEY_POLICY" = allow ] || KEY_UNSET_ENV="unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && "', 'RESPAWN_CMD="${KEY_UNSET_ENV}export PATH='], window: 25,
    note: 'main channels watchdog respawn',
  },
  {
    file: 'scripts/stuck-modal-guard.sh', match: '"$TMUX_BIN" respawn-pane -k -t "=$SESSION:" "$RESPAWN_CMD"', status: 'n3b',
    guard: ['KEY_POLICY="$(bash "$INSTALL_DIR/scripts/channels.sh" --interactive-key-policy', '[ "$KEY_POLICY" = allow ] || KEY_UNSET_ENV="unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && "', 'local RESPAWN_CMD="${KEY_UNSET_ENV}export PATH='], window: 25,
    note: 'main channels stuck-modal respawn (not in the blueprint N3b file list; found by this scan, added to N3b)',
  },
  // ---- no claude started ----
  { file: 'scripts/monitor_agents.sh', match: 'tmux new-session -d -s "$SESSION" -n _placeholder', status: 'no-claude', note: 'iTerm monitor: placeholder window, agent windows are link-window' },
  { file: 'scripts/rembrandt.sh', match: 'tmux new-session -d -s "$SESSION" -c "$WORKDIR" "$RUNNER"', status: 'no-claude', note: 'codex review runner' },
  // ---- message text ----
  { file: 'src/web/channel-monitor.ts', match: 'Kézi ellenőrzés javasolt: \\`tmux attach', status: 'text', note: 'operator alert text' },
  { file: 'src/web/channel-monitor.ts', match: "error: 'hard restart failed: tmux respawn-pane failed'", status: 'text', note: 'error message' },
]

const SINK_RX = [
  // argv element: ['new-session', ...] / 'respawn-pane', (TS, JS, Python)
  /['"](?:new-session|respawn-pane)['"]\s*[,\]]/,
  // shell form: tmux / $TMUX / "$TMUX_BIN" [-S sock] new-session|respawn-pane
  /(?:\btmux\b|\$\{?TMUX\w*\}?)"?\s+(?:-\S+\s+\S+\s+)*(?:new-session|respawn-pane)\b/,
]
const SCANNED_EXT = /\.(ts|mts|cts|js|mjs|cjs|sh|bash|py)$/

function* walk(d: string): Generator<string> {
  for (const n of readdirSync(d)) {
    if (n === '__tests__' || n === 'node_modules' || n === 'dist') continue
    const p = join(d, n)
    if (statSync(p).isDirectory()) yield* walk(p)
    else if (SCANNED_EXT.test(n)) yield p
  }
}

export interface Hit { file: string; line: number; text: string }

/** Every non-comment line under <root>/src and <root>/scripts that hands a command to tmux. */
export function findSinks(root: string): Hit[] {
  const hits: Hit[] = []
  for (const top of ['src', 'scripts']) {
    for (const f of walk(join(root, top))) {
      const lines = readFileSync(f, 'utf-8').split('\n')
      lines.forEach((l, i) => {
        const t = l.trim()
        if (t.startsWith('//') || t.startsWith('#') || t.startsWith('*') || t.startsWith('/*')) return
        if (SINK_RX.some((rx) => rx.test(l))) hits.push({ file: relative(root, f).split(sep).join('/'), line: i, text: l })
      })
    }
  }
  return hits
}

/** Hits no inventory entry accounts for, and entries whose count does not match. */
export function auditSinks(hits: Hit[], inventory: Entry[]): { unlisted: Hit[]; miscounted: string[] } {
  const unlisted = hits.filter((h) => !inventory.some((e) => e.file === h.file && h.text.includes(e.match)))
  const miscounted = inventory
    .filter((e) => hits.filter((h) => h.file === e.file && h.text.includes(e.match)).length !== (e.count ?? 1))
    .map((e) => `${e.file}: ${e.match}`)
  return { unlisted, miscounted }
}

describe('the launch-sink inventory', () => {
  const hits = findSinks(ROOT)

  it('the scan sees the known sinks at all (a scanner matching nothing would pass everything)', () => {
    expect(hits.length).toBeGreaterThanOrEqual(15)
  })

  it('every tmux new-session / respawn-pane in src/ and scripts/ is listed, and every entry still exists exactly as often', () => {
    const { unlisted, miscounted } = auditSinks(hits, INVENTORY)
    expect(unlisted.map((h) => `${h.file}:${h.line + 1}: ${h.text.trim()}`)).toEqual([])
    expect(miscounted).toEqual([])
  })

  it('every n3a and n3b sink carries its guard right at it (each occurrence)', () => {
    for (const e of INVENTORY.filter((x) => x.status === 'n3a' || x.status === 'n3b')) {
      const lines = readFileSync(join(ROOT, e.file), 'utf-8').split('\n')
      const ats = lines.flatMap((l, i) => (l.includes(e.match) ? [i] : []))
      expect(ats.length, e.file).toBe(e.count ?? 1)
      for (const at of ats) {
        expect(at, e.file).toBeGreaterThan(0)
        const near = lines.slice(Math.max(0, at - (e.window ?? 20)), at + 1 + (e.after ?? 0)).join('\n')
        for (const g of e.guard ?? []) expect(near, `${e.file}:${at + 1}: ${g}`).toContain(g)
      }
    }
  })

  it('no claude launch sink is pending: every n3a/n3b entry names its guard markers', () => {
    const guarded = INVENTORY.filter((x) => x.status === 'n3a' || x.status === 'n3b')
    const pending = guarded.filter((x) => !x.guard || x.guard.length === 0)
    expect(pending.map((x) => `${x.file}: ${x.match}`)).toEqual([])
    expect(guarded.filter((x) => x.status === 'n3b')).toHaveLength(5)
  })

  it('buildMainSessionRespawnCmd, the one builder of all three main respawns, prefixes the unset under forbid and asserts what it returns', () => {
    const cm = readFileSync(join(ROOT, 'src/web/channel-monitor.ts'), 'utf-8')
    const at = cm.indexOf('export function buildMainSessionRespawnCmd(opts: {')
    expect(at).toBeGreaterThan(0)
    const body = cm.slice(at, cm.indexOf('\n}\n', at))
    expect(body).toContain("const keyPolicy = opts.keyPolicy ?? interactiveKeyPolicy()")
    expect(body).toContain("const cmd = (keyPolicy === 'forbid' ? INTERACTIVE_UNSET : '') + [")
    expect(body).toMatch(/assertLaunchCmdClean\(cmd, \{ policy: keyPolicy, firstParty: true \}\)[\s\S]*\n  return cmd$/)
  })

  it('channels.sh: under forbid the .env key is not exported, the inherited one is unset, the tmux globals are -u, and KEY_UNSET_ENV is built', () => {
    const sh = readFileSync(join(ROOT, 'scripts/channels.sh'), 'utf-8')
    expect(sh).toContain('INTERACTIVE_KEY_POLICY="$(interactive_key_policy)"')
    expect(sh).toMatch(/if \[ "\$INTERACTIVE_KEY_POLICY" != forbid \]; then\n    _api_key="\$\(grep -E '\^ANTHROPIC_API_KEY='/)
    expect(sh).toMatch(/if \[ "\$INTERACTIVE_KEY_POLICY" = forbid \]; then\n  unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN\nfi/)
    expect(sh).toContain('$TMUX set-environment -g -u ANTHROPIC_API_KEY')
    expect(sh).toContain('$TMUX set-environment -g -u ANTHROPIC_AUTH_TOKEN')
    expect(sh).toMatch(/if \[ "\$INTERACTIVE_KEY_POLICY" = forbid \] && \[ -z "\$CUSTOM_PROVIDER_ENV" \]; then\n  KEY_UNSET_ENV="unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && "/)
  })

  it('buildLaunchCmd, the one builder both local sinks use, asserts the command it returns', () => {
    const ap = readFileSync(join(ROOT, 'src/web/agent-process.ts'), 'utf-8')
    const at = ap.indexOf('const buildLaunchCmd = (launchCwd: string) => {')
    expect(at).toBeGreaterThan(0)
    const body = ap.slice(at, ap.indexOf('\n    }\n', at))
    expect(body).toMatch(/const cmd = `\$\{keyUnsetPrefix\}[^\n]*\n\s+assertLaunchCmdClean\(cmd, \{ policy: keyPolicy, firstParty: keyGuardFirstParty \}\)\n\s+return cmd$/)
  })
})

// ---- direct claude -p processes in scripts/ (no tmux) ----------------------
// A shell script that runs claude itself (not in a pane) inherits the script's
// env, and a script that exports the whole .env hands it ANTHROPIC_API_KEY.
// Scanned per LOGICAL line (backslash continuations joined), scripts/**/*.sh
// only; the TS/JS direct launches have their own section below.
interface DirectEntry { file: string; match: string; status: 'n3a' | 'strips-keys'; guard: string[]; note: string }
export const DIRECT_INVENTORY: DirectEntry[] = [
  {
    // v1.45.0 (MORNTIMER2197): the call now also drops the subscription tokens, so $KEY_UNSET sits on the
    // continuation line; the match is that line's tail (unique, and the same text in the raw and the joined line).
    file: 'scripts/morning-briefing.sh', match: '-u CLAUDE_CODE_OAUTH_TOKEN -u ANTHROPIC_AUTH_TOKEN $KEY_UNSET', status: 'n3a',
    guard: ['KEY_UNSET=""', 'if [ "$(interactive_key_policy)" = forbid ]; then KEY_UNSET="-u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN"; fi'],
    note: 'reggeli napindito fallback: exports the whole .env, then claude -p',
  },
  {
    // BE2-2 (c3c32903, security review): the sandbox e2e's child claude (a real, Haiku-model run) now
    // drops both key names too, in every mode; it authenticates with CLAUDE_CODE_OAUTH_TOKEN only.
    file: 'scripts/bash-sandbox-e2e.sh', match: '-u CLAUDE_CODE_CHILD_SESSION -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN', status: 'strips-keys',
    guard: [], note: 'bash sandbox e2e: the child claude -p strips both key names, in every mode',
  },
  {
    file: 'scripts/fix-avx.sh', match: 'env -u CLAUDE_CODE_OAUTH_TOKEN -u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN', status: 'strips-keys',
    guard: [], note: 'AVX probe: already strips both names, in every mode',
  },
]

const DIRECT_RX = /(?:^|[\s;&|(`])(?:"?\$\{?CLAUDE(?:_BIN)?\}?"?|claude)\s(?:.*?\s)?(?:-p|--print)(?:\s|$)/

export function findDirectClaudePrint(root: string): Hit[] {
  const hits: Hit[] = []
  const shells = [...walk(join(root, 'scripts'))].filter((f) => /\.(sh|bash)$/.test(f))
  for (const f of shells) {
    const lines = readFileSync(f, 'utf-8').split('\n')
    for (let i = 0; i < lines.length; i++) {
      const start = i
      let buf = lines[i]
      while (buf.endsWith('\\') && i + 1 < lines.length) { i += 1; buf = buf.slice(0, -1) + ' ' + lines[i] }
      if (buf.trim().startsWith('#')) continue
      if (DIRECT_RX.test(buf)) hits.push({ file: relative(root, f).split(sep).join('/'), line: start, text: buf })
    }
  }
  return hits
}

describe('direct claude -p processes in scripts/', () => {
  const hits = findDirectClaudePrint(ROOT)

  it('every one is listed, and every entry still exists', () => {
    expect(hits.filter((h) => !DIRECT_INVENTORY.some((e) => e.file === h.file && h.text.includes(e.match))).map((h) => `${h.file}:${h.line + 1}`)).toEqual([])
    for (const e of DIRECT_INVENTORY) expect(hits.filter((h) => h.file === e.file && h.text.includes(e.match)), e.file).toHaveLength(1)
  })

  it('the guarded ones carry their guard, and the stripping ones strip both names', () => {
    for (const e of DIRECT_INVENTORY) {
      const src = readFileSync(join(ROOT, e.file), 'utf-8')
      const at = src.indexOf(e.match)
      for (const g of e.guard) {
        const gi = src.indexOf(g)
        expect(gi, `${e.file}: ${g}`).toBeGreaterThan(0)
        expect(gi, `${e.file}: ${g} before the call`).toBeLessThan(at)
      }
      if (e.status === 'strips-keys') expect(e.match).toMatch(/-u ANTHROPIC_API_KEY -u ANTHROPIC_AUTH_TOKEN/)
    }
  })

  it('self-test: a new continued `$CLAUDE ... \\ -p` line is found, a comment is not', () => {
    const root = mkdtempSync(join(tmpdir(), 'ikg-direct-'))
    try {
      mkdirSync(join(root, 'scripts'), { recursive: true })
      writeFileSync(join(root, 'scripts', 'y.sh'), '#!/bin/bash\n# claude -p "x"\n$CLAUDE --model m \\\n  -p "hi"\nclaude mcp list\n')
      expect(findDirectClaudePrint(root).map((h) => `${h.file}:${h.line + 1}`)).toEqual(['scripts/y.sh:3'])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

// ---- direct claude processes started from TS/JS (no tmux) -------------------
// (N3c, from the N3a review.) A module that spawns claude itself hands it the
// env it builds, and `{ ...process.env }` carries whatever key the dashboard
// has. Two shapes are searched in src/ and scripts/: an argv that starts with
// -p/--print followed by a prompt literal, and the Agent SDK's query() in a file
// that imports the SDK. `filtered` = the env goes through the forbid-mode
// filter (markers checked next to the call); `strips-keys` = the call already
// drops both names in every mode.
interface TsDirectEntry {
  file: string
  match: string
  count?: number
  status: 'filtered' | 'strips-keys'
  guard: string[]
  before: number
  after: number
  note: string
}
export const TS_DIRECT_INVENTORY: TsDirectEntry[] = [
  {
    file: 'src/web/claude-credentials-guard.ts', match: "['-p', 'Reply with exactly: OK', '--model', LIVE_TEST_MODEL],", count: 2, status: 'filtered',
    guard: ['probeChildEnv(', 'interactiveKeyPolicy()'], before: 12, after: 6,
    note: 'liveTestToken (fleet-token live test) and liveProbeAuth (onboarding / boot-pass probe)',
  },
  {
    file: 'src/web/cli-update.ts', match: "spawn(bin, ['-p', 'ping', '--max-turns', '1', '--output-format', 'json']", status: 'strips-keys',
    guard: ['delete env.ANTHROPIC_API_KEY', 'delete env.ANTHROPIC_AUTH_TOKEN'], before: 8, after: 0,
    note: 'post-update launch probe: auth-free on purpose',
  },
  {
    file: 'src/agent.ts', match: 'const events = query({', status: 'filtered',
    guard: ['const sdkEnv = sdkChildEnv(process.env, env, interactiveKeyPolicy())', '...(sdkEnv ? { env: sdkEnv } : {}),'], before: 6, after: 12,
    note: 'runAgent legacy SDK path (MARVEEN_AGENT_BACKEND=sdk, or the worker-auth fallback)',
  },
]

const TS_ARGV_RX = /\[\s*['"](?:-p|--print)['"]\s*,\s*['"`]/
const TS_SDK_RX = /\bquery\(\s*\{/
const TS_EXT = /\.(ts|mts|cts|js|mjs|cjs)$/

export function findTsDirectClaude(root: string): Hit[] {
  const hits: Hit[] = []
  for (const top of ['src', 'scripts']) {
    for (const f of walk(join(root, top))) {
      if (!TS_EXT.test(f)) continue
      const src = readFileSync(f, 'utf-8')
      const sdk = src.includes('@anthropic-ai/claude-agent-sdk')
      src.split('\n').forEach((l, i) => {
        const t = l.trim()
        if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) return
        if (TS_ARGV_RX.test(l) || (sdk && TS_SDK_RX.test(l))) hits.push({ file: relative(root, f).split(sep).join('/'), line: i, text: l })
      })
    }
  }
  return hits
}

describe('direct claude processes started from TS/JS', () => {
  const hits = findTsDirectClaude(ROOT)

  it('every one is listed, and every entry still exists exactly as often', () => {
    expect(hits.filter((h) => !TS_DIRECT_INVENTORY.some((e) => e.file === h.file && h.text.includes(e.match))).map((h) => `${h.file}:${h.line + 1}: ${h.text.trim()}`)).toEqual([])
    for (const e of TS_DIRECT_INVENTORY) expect(hits.filter((h) => h.file === e.file && h.text.includes(e.match)), e.file).toHaveLength(e.count ?? 1)
  })

  it('each occurrence carries its filter right at the call', () => {
    for (const e of TS_DIRECT_INVENTORY) {
      const lines = readFileSync(join(ROOT, e.file), 'utf-8').split('\n')
      const ats = lines.flatMap((l, i) => (l.includes(e.match) ? [i] : []))
      expect(ats.length, e.file).toBe(e.count ?? 1)
      for (const at of ats) {
        const near = lines.slice(Math.max(0, at - e.before), at + 1 + e.after).join('\n')
        for (const g of e.guard) expect(near, `${e.file}:${at + 1}: ${g}`).toContain(g)
      }
    }
  })

  it('self-test: an argv -p/--print call and an SDK query() are found; ps -p, tmux -p and comments are not', () => {
    const root = mkdtempSync(join(tmpdir(), 'ikg-tsdirect-'))
    try {
      mkdirSync(join(root, 'src', 'web'), { recursive: true })
      mkdirSync(join(root, 'scripts'), { recursive: true })
      writeFileSync(join(root, 'src', 'web', 'probe.ts'), [
        "// spawn(bin, ['-p', 'x']) -- a comment",
        "execFileSync('/bin/ps', ['-p', String(pid), '-o', 'comm='])",
        "captureTmux(t, ['display-message', '-p', '-t', s])",
        "const c = spawn(bin, ['--print', 'hello', '--model', m], { env: { ...process.env } })",
      ].join('\n'))
      writeFileSync(join(root, 'src', 'sdk.ts'), "import { query } from '@anthropic-ai/claude-agent-sdk'\nconst e = query({ prompt: p, options: {} })\n")
      writeFileSync(join(root, 'src', 'nosdk.ts'), 'const rows = query({ sql })\n')
      writeFileSync(join(root, 'scripts', 'x.mjs'), "execFile(claude, ['-p', `hi`])\n")
      expect(findTsDirectClaude(root).map((h) => `${h.file}:${h.line + 1}`).sort()).toEqual(['scripts/x.mjs:1', 'src/sdk.ts:2', 'src/web/probe.ts:4'])
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})

describe('the scanner itself flags a new, unlisted sink (self-test on a fixture tree)', () => {
  it('TS argv, a bash tmux line and a $TMUX line are found and reported unlisted; comments are not', () => {
    const root = mkdtempSync(join(tmpdir(), 'ikg-sinks-'))
    try {
      mkdirSync(join(root, 'src', 'web'), { recursive: true })
      mkdirSync(join(root, 'scripts'), { recursive: true })
      writeFileSync(join(root, 'src', 'web', 'new-launcher.ts'), [
        "// runTmux(null, ['new-session', '-d', cmd]) -- a comment, not a sink",
        "execFileSync('tmux', ['new-session', '-d', '-s', s, cmd])",
        "execFileSync(tmuxBin(), [\n  'respawn-pane', '-k', cmd])",
      ].join('\n'))
      writeFileSync(join(root, 'scripts', 'x.sh'), '#!/bin/bash\n# tmux new-session in a comment\ntmux -S /s new-session -d -s a "$CMD"\n"$TMUX_BIN" respawn-pane -k -t x "$C"\n')
      const hits = findSinks(root)
      expect(hits.map((h) => `${h.file}:${h.line + 1}`).sort()).toEqual(['scripts/x.sh:3', 'scripts/x.sh:4', 'src/web/new-launcher.ts:2', 'src/web/new-launcher.ts:4'])
      expect(auditSinks(hits, INVENTORY).unlisted).toHaveLength(4)
    } finally {
      rmSync(root, { recursive: true, force: true })
    }
  })
})
