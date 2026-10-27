// fec6335f N3a: the interactive-key guard on the launch paths that do not go
// through startAgentProcess -- the worker sessions, background tasks and the
// cron watchdog. Same rules as the launcher harness: scratch HOME/PROJECT_ROOT/
// STORE_DIR, a recording execFileSync (no tmux, no claude), an injected Vault,
// a pinned policy, and a per-run dummy key that must appear nowhere.
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, copyFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

type Call = { file: string; args: string[]; env?: Record<string, string | undefined> }
const H = vi.hoisted(() => ({
  root: '',
  calls: [] as { file: string; args: string[]; env?: Record<string, string | undefined> }[],
  secretReads: [] as string[],
  bgCreated: [] as string[],
  dummy: '',
  providers: {} as Record<string, { id: string; label: string; baseUrl: string; authHeader: 'x-api-key' | 'Bearer' | 'none'; vaultKey: string | null }>,
}))

vi.mock('node:os', async (orig) => {
  const a = await orig<typeof import('node:os')>()
  return { ...a, homedir: () => `${H.root}/home` }
})
vi.mock('node:child_process', async (orig) => {
  const a = await orig<typeof import('node:child_process')>()
  const execFileSync = (file: string, args: readonly string[] = [], opts?: { env?: Record<string, string | undefined> }) => {
    H.calls.push({ file, args: [...args], env: opts?.env })
    if (['list-sessions', 'has-session', 'kill-session', 'capture-pane'].includes(args[0])) {
      throw Object.assign(new Error('no server running'), { status: 1, stderr: Buffer.from('') })
    }
    return ''
  }
  return { ...a, execFileSync }
})
vi.mock('../config.js', async (orig) => {
  const a = await orig<typeof import('../config.js')>()
  return { ...a, PROJECT_ROOT: H.root, STORE_DIR: `${H.root}/store` }
})
vi.mock('../platform.js', async (orig) => {
  const a = await orig<typeof import('../platform.js')>()
  return { ...a, resolveFromPath: (n: string) => `/stub/bin/${n}`, tryResolveFromPath: (n: string) => `/stub/bin/${n}` }
})
vi.mock('../web/vault.js', async (orig) => {
  const a = await orig<typeof import('../web/vault.js')>()
  return { ...a, getSecret: (id: string) => { H.secretReads.push(id); return H.dummy } }
})
vi.mock('../web/custom-providers.js', async (orig) => {
  const a = await orig<typeof import('../web/custom-providers.js')>()
  return { ...a, loadCustomProvider: (id: string) => H.providers[id] ?? null }
})
vi.mock('../web/claude-cli-version.js', async (orig) => {
  const a = await orig<typeof import('../web/claude-cli-version.js')>()
  const v = { version: '9.9.999', measuredAt: 0, error: null, source: 'env' as const }
  return { ...a, measureClaudeCliVersion: async () => v, measureClaudeCliVersionSync: () => v }
})
vi.mock('../notify.js', async (orig) => {
  const a = await orig<typeof import('../notify.js')>()
  return { ...a, notifyChannel: async () => undefined }
})
vi.mock('../db.js', async (orig) => {
  const a = await orig<typeof import('../db.js')>()
  return {
    ...a,
    createBackgroundTaskAtomic: (id: string, agentId: string, prompt: string, session: string) => {
      H.bgCreated.push(id)
      return { id, agent_id: agentId, prompt, status: 'running', tmux_session: session, started_at: 0, finished_at: null, output: null }
    },
    finishBackgroundTask: () => undefined,
  }
})

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
H.root = mkdtempSync(join(tmpdir(), 'ikg-paths-'))
H.dummy = ['sk', 'ant', 'TEST', 'DUMMY', randomBytes(6).toString('hex')].join('-')
process.env.CLAUDECLAW_ENV_DIR = join(H.root, 'envdir')
mkdirSync(join(H.root, 'envdir'), { recursive: true })
mkdirSync(join(H.root, 'store'), { recursive: true })
mkdirSync(join(H.root, 'agents'), { recursive: true })

const W = await import('../web/agent-worker.js')
const BG = await import('../web/routes/background-tasks.js')
const G = await import('../web/interactive-key-guard.js')
const { MAIN_AGENT_ID } = await import('../config.js')
const { logger } = await import('../logger.js')
const { execFileSync: realExec } = await vi.importActual<typeof import('node:child_process')>('node:child_process')

const EVENTS = join(H.root, 'store', 'interactive-key-guard-events.jsonl')
const events = (): Array<Record<string, unknown>> =>
  existsSync(EVENTS) ? readFileSync(EVENTS, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []
const workerLaunches = (): string[] =>
  H.calls.filter((c: Call) => c.args[0] === 'new-session' && c.args[6] === 'bash').map((c: Call) => c.args[8])
const logged: string[] = []

function setMainCustomProvider(id: string | null): void {
  const dir = join(H.root, 'agents', MAIN_AGENT_ID)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'agent-config.json'), JSON.stringify(id ? { model: 'gpt-x', customProvider: id } : {}))
}

beforeEach(() => {
  H.calls.length = 0
  H.secretReads.length = 0
  H.bgCreated.length = 0
  H.providers = {}
  logged.length = 0
  rmSync(join(H.root, 'home'), { recursive: true, force: true })
  mkdirSync(join(H.root, 'home', '.claude'), { recursive: true })
  rmSync(EVENTS, { force: true })
  setMainCustomProvider(null)
  for (const lvl of ['error', 'warn', 'info'] as const) {
    vi.spyOn(logger, lvl).mockImplementation(((...a: unknown[]) => { logged.push(JSON.stringify(a)) }) as never)
  }
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
  G.setInteractiveKeyPolicyForTest(null)
  for (const l of logged) expect(l).not.toContain(H.dummy)
  if (existsSync(EVENTS)) expect(readFileSync(EVENTS, 'utf-8')).not.toContain(H.dummy)
})
afterAll(() => rmSync(H.root, { recursive: true, force: true }))

describe('worker sessions (agent-worker.ts)', () => {
  it('Claude worker: forbid = INTERACTIVE_UNSET_OR_EXIT + the allow launch, for both sessions', () => {
    G.setInteractiveKeyPolicyForTest('allow')
    W.startWorkerSession()
    const allow = workerLaunches()
    expect(allow).toHaveLength(2)
    for (const l of allow) expect(l).not.toContain('ANTHROPIC_API_KEY')
    H.calls.length = 0
    G.setInteractiveKeyPolicyForTest('forbid')
    W.startWorkerSession()
    const forbid = workerLaunches()
    expect(forbid).toEqual(allow.map((l) => G.INTERACTIVE_UNSET_OR_EXIT + l))
    expect(events()).toEqual([])
  })

  it('the unset runs AFTER the login shell rc files (bash -lc): a key exported in .bash_profile is gone', () => {
    const home = mkdtempSync(join(tmpdir(), 'ikg-rc-'))
    try {
      writeFileSync(join(home, '.bash_profile'), `export ANTHROPIC_API_KEY=${H.dummy}\nexport ANTHROPIC_AUTH_TOKEN=${H.dummy}\n`)
      const run = (prefix: string) => realExec('bash', ['-lc', `${prefix}printf '[%s][%s]' "\${ANTHROPIC_API_KEY-unset}" "\${ANTHROPIC_AUTH_TOKEN-unset}"`], {
        env: { HOME: home, PATH: '/usr/bin:/bin' }, encoding: 'utf-8', stdio: ['ignore', 'pipe', 'pipe'],
      })
      expect(run('')).toBe(`[${H.dummy}][${H.dummy}]`) // control: the rc file really sets it
      expect(run(G.INTERACTIVE_UNSET_OR_EXIT)).toBe('[unset][unset]')
      // A key the shell cannot unset ends the shell instead of reaching claude.
      writeFileSync(join(home, '.bash_profile'), `readonly ANTHROPIC_API_KEY=${H.dummy}\n`)
      let status = 0
      try { run(`${G.INTERACTIVE_UNSET_OR_EXIT}echo REACHED-CLAUDE; `) } catch (e) { status = (e as { status: number }).status }
      expect(status).toBe(1)
    } finally {
      rmSync(home, { recursive: true, force: true })
    }
  })

  it('forbid + a main-agent custom provider that is Anthropic: no worker, no key read, a guard event', () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    H.providers.direct = { id: 'direct', label: 'd', baseUrl: 'https://api.anthropic.com', authHeader: 'x-api-key', vaultKey: 'DIRECT_KEY' }
    setMainCustomProvider('direct')
    W.startWorkerSession()
    expect(workerLaunches()).toEqual([])
    expect(H.secretReads).not.toContain('DIRECT_KEY')
    expect(events().map((e) => e.where)).toEqual(['agent-worker:first-party-custom-provider', 'agent-worker:first-party-custom-provider'])
  })

  it('forbid + a LiteLLM main-agent provider: the worker launch is byte-identical to allow', () => {
    H.providers.litellm = { id: 'litellm', label: 'l', baseUrl: 'http://127.0.0.1:4010', authHeader: 'Bearer', vaultKey: 'lk' }
    setMainCustomProvider('litellm')
    G.setInteractiveKeyPolicyForTest('allow')
    W.startWorkerSession()
    const allow = workerLaunches()
    H.calls.length = 0
    G.setInteractiveKeyPolicyForTest('forbid')
    W.startWorkerSession()
    expect(workerLaunches()).toEqual(allow)
    expect(allow).toHaveLength(2)
    for (const l of allow) expect(l).not.toContain(H.dummy)
  })

  it('forbid + an auth key in the worker\'s own settings.json: refused, names only', () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    for (const v of ['slow', 'fast'] as const) {
      const cfg = join(W.workerHomeFor(MAIN_AGENT_ID, v), '.claude-config')
      mkdirSync(cfg, { recursive: true })
      writeFileSync(join(cfg, 'settings.json'), JSON.stringify({ env: { ANTHROPIC_API_KEY: H.dummy } }))
    }
    W.startWorkerSession()
    expect(workerLaunches()).toEqual([])
    expect(events().map((e) => e.names)).toEqual([['ANTHROPIC_API_KEY'], ['ANTHROPIC_API_KEY']])
  })
})

describe('background tasks (routes/background-tasks.ts)', () => {
  const bgCalls = () => H.calls.filter((c: Call) => c.args[0] === 'new-session' && String(c.args[3]).startsWith('bg-'))

  it('allow: the command and the tmux-client env are exactly as before', () => {
    G.setInteractiveKeyPolicyForTest('allow')
    vi.useFakeTimers()
    process.env.ANTHROPIC_API_KEY = H.dummy
    try {
      BG.spawnBackgroundTask('a1', 'do x')
    } finally {
      delete process.env.ANTHROPIC_API_KEY
    }
    const [c] = bgCalls()
    expect(c.args[8]).toMatch(/^export PATH="[^"]*" && \/stub\/bin\/claude -p "\$BG_PROMPT" --output-format text 2>&1; echo '___BG_DONE___'; sleep 5$/)
    expect(c.env?.ANTHROPIC_API_KEY).toBe(H.dummy) // today's behaviour: the parent env is passed on whole
    expect(c.env?.BG_PROMPT).toBe('do x')
  })

  it('forbid: the command starts with the unset and the key names are not handed to tmux', () => {
    G.setInteractiveKeyPolicyForTest('allow')
    vi.useFakeTimers()
    BG.spawnBackgroundTask('a2', 'do y')
    const allowCmd = bgCalls()[0].args[8]
    H.calls.length = 0
    G.setInteractiveKeyPolicyForTest('forbid')
    process.env.ANTHROPIC_API_KEY = H.dummy
    process.env.ANTHROPIC_AUTH_TOKEN = H.dummy
    try {
      BG.spawnBackgroundTask('a2', 'do y')
    } finally {
      delete process.env.ANTHROPIC_API_KEY
      delete process.env.ANTHROPIC_AUTH_TOKEN
    }
    const [c] = bgCalls()
    expect(c.args[8]).toBe(G.INTERACTIVE_UNSET + allowCmd)
    expect(c.env && 'ANTHROPIC_API_KEY' in c.env).toBe(false)
    expect(c.env && 'ANTHROPIC_AUTH_TOKEN' in c.env).toBe(false)
    expect(c.env?.BG_PROMPT).toBe('do y')
  })

  it('forbid + an auth key in the shared ~/.claude/settings.json: refused before any task row or session, names only', () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const shared = join(H.root, 'home', '.claude', 'settings.json')
    writeFileSync(shared, JSON.stringify({ env: { ANTHROPIC_AUTH_TOKEN: H.dummy }, apiKeyHelper: 'x' }))
    vi.useFakeTimers()
    const r = BG.spawnBackgroundTask('a3', 'do z')
    expect(r).toEqual({ error: 'interactive-key-guard: settings-auth-key (INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid)' })
    expect(bgCalls()).toEqual([])
    expect(H.bgCreated).toEqual([])
    expect(events()).toEqual([expect.objectContaining({ source: 'launch-guard', where: shared, names: ['ANTHROPIC_AUTH_TOKEN', 'apiKeyHelper'], agent: 'a3' })])
    // allow: the same settings start the task as today.
    G.setInteractiveKeyPolicyForTest('allow')
    BG.spawnBackgroundTask('a3', 'do z')
    expect(bgCalls()).toHaveLength(1)
    expect(H.bgCreated).toHaveLength(1)
  })

  it('backgroundTaskSettingsPaths: shared user scope, CLAUDE_CONFIG_DIR when set, and the cwd project scope', () => {
    expect(BG.backgroundTaskSettingsPaths({}, '/w', '/h')).toEqual(['/h/.claude/settings.json', '/w/.claude/settings.json', '/w/.claude/settings.local.json'])
    expect(BG.backgroundTaskSettingsPaths({ CLAUDE_CONFIG_DIR: '/c' }, '/w', '/h'))
      .toEqual(['/h/.claude/settings.json', '/c/settings.json', '/w/.claude/settings.json', '/w/.claude/settings.local.json'])
    expect(BG.backgroundTaskSettingsPaths({ CLAUDE_CONFIG_DIR: '/h/.claude' }, '/w', '/h')).toHaveLength(3)
  })

  it('backgroundTaskEnv: forbid drops exactly the two names, allow copies the parent', () => {
    const parent = { A: '1', ANTHROPIC_API_KEY: H.dummy, ANTHROPIC_AUTH_TOKEN: H.dummy, ANTHROPIC_BASE_URL: 'u', CLAUDE_CODE_OAUTH_TOKEN: 't' }
    expect(BG.backgroundTaskEnv(parent, 'p', 'allow')).toEqual({ ...parent, BG_PROMPT: 'p' })
    expect(BG.backgroundTaskEnv(parent, 'p', 'forbid')).toEqual({ A: '1', ANTHROPIC_BASE_URL: 'u', CLAUDE_CODE_OAUTH_TOKEN: 't', BG_PROMPT: 'p' })
    expect(parent.ANTHROPIC_API_KEY).toBe(H.dummy) // the parent object is not mutated
  })
})

describe('scripts/watchdog.sh (cron sub-agent restarts)', () => {
  const install = join(H.root, 'wd-install')
  mkdirSync(join(install, 'scripts'), { recursive: true })
  copyFileSync(join(REPO, 'scripts', 'watchdog.sh'), join(install, 'scripts', 'watchdog.sh'))
  const wd = join(install, 'scripts', 'watchdog.sh')
  const agentDir = (cfg: Record<string, unknown> | string) => {
    const d = mkdtempSync(join(install, 'agent-'))
    writeFileSync(join(d, 'agent-config.json'), typeof cfg === 'string' ? cfg : JSON.stringify(cfg))
    return d
  }
  const decide = (env: string | null, dir: string, model: string) => {
    if (env === null) rmSync(join(install, '.env'), { force: true })
    else writeFileSync(join(install, '.env'), env)
    return realExec('bash', [wd, '--interactive-key-decision', dir, model], { encoding: 'utf-8', env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: wdHome } }).trim()
  }
  const wdHome = join(install, 'home')
  const wdShared = join(wdHome, '.claude', 'settings.json')
  const wdToken = join(install, 'store', '.claude-oauth-token')
  const F = 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n'
  const resetWd = () => {
    rmSync(wdHome, { recursive: true, force: true })
    mkdirSync(join(wdHome, '.claude'), { recursive: true })
    rmSync(join(install, 'store'), { recursive: true, force: true })
    mkdirSync(join(install, 'store'), { recursive: true })
  }

  it('the decision per agent shape', () => {
    resetWd()
    const shared = agentDir({ model: 'claude-opus-5-5' })
    const api = agentDir({ model: 'claude-opus-5-5', authMode: 'api' })
    const broken = agentDir('{ not json')
    expect(decide(F, shared, 'claude-opus-5-5')).toBe('unset')
    expect(decide(F, api, 'claude-opus-5-5')).toBe('refuse:auth-mode-api')
    // BE-1 (4): this launcher exports no provider URL, so whatever the model
    // NAME (an alias like `opus`, or anything else), the session reaches
    // Anthropic's endpoint: under forbid the key names are always unset.
    expect(decide(F, api, 'chatgpt/gpt-6-astra')).toBe('unset')
    expect(decide(F, shared, 'opus')).toBe('unset')
    expect(decide(F, shared, 'sonnet')).toBe('unset')
    expect(decide(null, shared, 'opus')).toBe('allow')
    expect(decide(F, broken, 'claude-opus-5-5')).toBe('unset')
    expect(decide(null, api, 'claude-opus-5-5')).toBe('allow')
  })

  it('the settings scan runs whatever the model name: an alias refuses exactly like a claude- name (a settings env beats the unset)', () => {
    resetWd()
    const a = agentDir({ model: 'opus' })
    writeFileSync(wdShared, JSON.stringify({ env: { ANTHROPIC_API_KEY: H.dummy } }))
    for (const m of ['opus', 'claude-opus-5', 'sonnet', 'chatgpt/gpt-6-astra']) expect(decide(F, a, m), m).toBe('refuse:settings-auth-key')
    writeFileSync(wdShared, '{}')
    expect(decide(F, a, 'opus')).toBe(decide(F, a, 'claude-opus-5'))
    expect(decide(F, a, 'opus')).toBe('unset')
    mkdirSync(join(a, '.claude'), { recursive: true })
    writeFileSync(join(a, '.claude', 'settings.local.json'), JSON.stringify({ apiKeyHelper: '/bin/echo x' }))
    expect(decide(F, a, 'opus')).toBe('refuse:settings-auth-key')
    expect(decide(F, a, 'claude-opus-5')).toBe('refuse:settings-auth-key')
    expect(decide(null, a, 'opus')).toBe('allow')
  })

  it('a customProvider does not make a claude- agent non-first-party here (this launcher exports no provider URL)', () => {
    resetWd()
    const customShared = agentDir({ model: 'claude-opus-5-5', customProvider: 'litellm' })
    const customApi = agentDir({ model: 'claude-opus-5-5', customProvider: 'litellm', authMode: 'api' })
    const customGpt = agentDir({ model: 'chatgpt/gpt-6-astra', customProvider: 'litellm', authMode: 'api' })
    expect(decide(F, customShared, 'claude-opus-5-5')).toBe('unset')
    expect(decide(F, customApi, 'claude-opus-5-5')).toBe('refuse:auth-mode-api')
    expect(decide(F, customGpt, 'chatgpt/gpt-6-astra')).toBe('unset')
  })

  it('a key name in the settings this launch loads refuses; settings it does not load do not count', () => {
    const keyed = JSON.stringify({ env: { ANTHROPIC_API_KEY: H.dummy } })
    // No fleet token -> the launch has no CLAUDE_CONFIG_DIR -> ~/.claude is the user scope.
    resetWd()
    const a = agentDir({ model: 'claude-opus-5-5' })
    mkdirSync(join(a, '.claude-config'), { recursive: true })
    writeFileSync(join(a, '.claude-config', 'settings.json'), keyed)
    expect(decide(F, a, 'claude-opus-5-5')).toBe('unset') // .claude-config is not loaded without the token
    writeFileSync(wdShared, keyed)
    expect(decide(F, a, 'claude-opus-5-5')).toBe('refuse:settings-auth-key')
    // Fleet token present -> the launch exports CLAUDE_CONFIG_DIR=<agent>/.claude-config.
    resetWd()
    writeFileSync(wdToken, 'sk-ant-oat01-FAKE-fleet-token-for-tests\n')
    const b = agentDir({ model: 'claude-opus-5-5' })
    mkdirSync(join(b, '.claude-config'), { recursive: true })
    writeFileSync(join(b, '.claude-config', 'settings.json'), JSON.stringify({ env: { ANTHROPIC_AUTH_TOKEN: H.dummy } }))
    writeFileSync(wdShared, keyed) // not loaded on this launch
    expect(decide(F, b, 'claude-opus-5-5')).toBe('refuse:settings-auth-key')
    writeFileSync(join(b, '.claude-config', 'settings.json'), JSON.stringify({ env: { OTHER: '1' } }))
    expect(decide(F, b, 'claude-opus-5-5')).toBe('unset')
    // Project scope: settings.local.json apiKeyHelper, and a broken settings.json naming a key.
    resetWd()
    const c = agentDir({ model: 'claude-opus-5-5' })
    mkdirSync(join(c, '.claude'), { recursive: true })
    writeFileSync(join(c, '.claude', 'settings.local.json'), JSON.stringify({ apiKeyHelper: '/bin/echo x' }))
    expect(decide(F, c, 'claude-opus-5-5')).toBe('refuse:settings-auth-key')
    rmSync(join(c, '.claude', 'settings.local.json'))
    writeFileSync(join(c, '.claude', 'settings.json'), `{ "env": { "ANTHROPIC_API_KEY": "${H.dummy}", } broken`)
    expect(decide(F, c, 'claude-opus-5-5')).toBe('refuse:settings-auth-key')
    // Exists but unreadable -> refuse (the CLI would have read it).
    writeFileSync(join(c, '.claude', 'settings.json'), '{}')
    chmodSync(join(c, '.claude', 'settings.json'), 0o000)
    try {
      expect(decide(F, c, 'claude-opus-5-5')).toBe('refuse:settings-unreadable')
    } finally {
      chmodSync(join(c, '.claude', 'settings.json'), 0o600)
    }
    // Allow: none of this is looked at.
    writeFileSync(wdShared, keyed)
    expect(decide(null, c, 'claude-opus-5-5')).toBe('allow')
  })

  it('reads the policy exactly like the TS side (readInteractiveKeyPolicy) for the same .env text', () => {
    resetWd()
    const shared = agentDir({ model: 'claude-opus-5-5' })
    const texts = [
      '', 'OTHER=1\n', 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\n', 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n',
      'INTERACTIVE_ANTHROPIC_KEY_POLICY="allow"\n', "INTERACTIVE_ANTHROPIC_KEY_POLICY='forbid'\n", 'INTERACTIVE_ANTHROPIC_KEY_POLICY=\n',
      'INTERACTIVE_ANTHROPIC_KEY_POLICY=Allow\n', 'INTERACTIVE_ANTHROPIC_KEY_POLICY=frobid\n', '  INTERACTIVE_ANTHROPIC_KEY_POLICY = allow  \n',
      '# INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n', 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\nINTERACTIVE_ANTHROPIC_KEY_POLICY=allow\n',
      'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\nINTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n', 'INTERACTIVE_ANTHROPIC_KEY_POLICY="\n',
      'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow # comment\n',
    ]
    for (const t of texts) {
      const want = G.readInteractiveKeyPolicy(t) === 'forbid' ? 'unset' : 'allow'
      expect(decide(t, shared, 'claude-opus-5-5'), JSON.stringify(t)).toBe(want)
    }
  })

  it('the loop applies it: unset prepended after the CMD line, a refusal skips new-session', () => {
    const src = readFileSync(wd, 'utf-8')
    const cmdLine = src.indexOf('  CMD="${ISO_ENV}export PATH=')
    const decision = src.indexOf('KEY_DECISION="$(interactive_key_decision "$AGENT_DIR" "$MODEL")"')
    const prepend = src.indexOf('unset) CMD="unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && ${CMD}" ;;')
    const refuse = src.indexOf('refuse:*)')
    const sink = src.indexOf('tmux new-session -d -s "$SESSION_NAME" "$CMD"')
    for (const i of [cmdLine, decision, prepend, refuse, sink]) expect(i).toBeGreaterThan(0)
    expect(cmdLine).toBeLessThan(decision)
    expect(decision).toBeLessThan(sink)
    expect(prepend).toBeLessThan(sink)
    expect(src.slice(refuse, prepend)).toMatch(/continue ;;/)
  })
})

describe('scripts/morning-briefing.sh (a direct claude -p after exporting the whole .env)', () => {
  // The hermetic shape of scripts/__tests__/morning-briefing-no-poller.test.sh:
  // a fixture install, a stub claude (CLAUDE_BIN seam) that records only WHETHER
  // the key names reach it, and no sentinel, so nothing is delivered.
  const run = (policyLine: string): string => {
    const dir = mkdtempSync(join(H.root, 'mb-'))
    mkdirSync(join(dir, 'scripts', 'lib'), { recursive: true })
    mkdirSync(join(dir, 'store'), { recursive: true })
    mkdirSync(join(dir, 'bin'), { recursive: true })
    mkdirSync(join(dir, '.claude', 'channels', 'telegram'), { recursive: true })
    copyFileSync(join(REPO, 'scripts', 'morning-briefing.sh'), join(dir, 'scripts', 'morning-briefing.sh'))
    for (const f of ['owner-chat.sh', 'send-telegram.sh']) copyFileSync(join(REPO, 'scripts', 'lib', f), join(dir, 'scripts', 'lib', f))
    writeFileSync(join(dir, '.env'), `ALLOWED_CHAT_ID=1234\nTELEGRAM_BOT_TOKEN=tok-from-dotenv\nANTHROPIC_API_KEY=${H.dummy}\nANTHROPIC_AUTH_TOKEN=${H.dummy}\n${policyLine}`)
    writeFileSync(join(dir, '.claude', 'channels', 'telegram', '.env'), 'TELEGRAM_BOT_TOKEN=tok-from-statedir\n')
    writeFileSync(join(dir, 'bin', 'claude'), [
      '#!/bin/bash',
      'OUT="$(dirname "$0")/../store/keys"',
      'for v in ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN; do if printenv "$v" >/dev/null; then echo "$v=set"; else echo "$v=unset"; fi; done > "$OUT"',
      'echo "stub: not sending"',
      '',
    ].join('\n'), { mode: 0o755 })
    try {
      realExec('bash', [join(dir, 'scripts', 'morning-briefing.sh')], {
        env: { HOME: dir, PATH: '/usr/bin:/bin', CLAUDE_BIN: join(dir, 'bin', 'claude'), MORNING_FORCE: '1' },
        stdio: ['ignore', 'pipe', 'pipe'],
      })
    } catch { /* the stub refuses: the script may exit non-zero, what it handed claude is the point */ }
    const keysPath = join(dir, 'store', 'keys')
    return existsSync(keysPath) ? readFileSync(keysPath, 'utf-8').trim() : '<claude never ran>'
  }

  it('allow (no policy line): the exported key names reach claude, exactly as today', () => {
    expect(run('')).toBe('ANTHROPIC_API_KEY=set\nANTHROPIC_AUTH_TOKEN=set')
  })

  it('forbid: neither name reaches claude, though the .env exports both', () => {
    expect(run('INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')).toBe('ANTHROPIC_API_KEY=unset\nANTHROPIC_AUTH_TOKEN=unset')
  })

  it('an unknown policy value is forbid (fail-closed), parity with the TS reader', () => {
    expect(G.readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY=frobid\n')).toBe('forbid')
    expect(run('INTERACTIVE_ANTHROPIC_KEY_POLICY=frobid\n')).toBe('ANTHROPIC_API_KEY=unset\nANTHROPIC_AUTH_TOKEN=unset')
  })
})
