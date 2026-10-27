// fec6335f N3a: the interactive-key guard on the sub-agent launcher, driven end
// to end through the REAL startAgentProcess / restartAgentProcess.
//
// Nothing real is touched: PROJECT_ROOT, STORE_DIR and HOME point at a scratch
// tree (templates/scripts/.claude are read-only symlinks into this checkout),
// execFileSync is a recorder (no tmux, no claude, no ssh), the Vault getter is
// injected and returns a per-run dummy, and the policy is pinned per test (no
// .env is read). The dummy value is asserted ABSENT from every launch command,
// the guard-event file and every logger call.
import { describe, it, expect, vi, beforeEach, afterEach, afterAll } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, symlinkSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'

type Call = { file: string; args: string[] }
const H = vi.hoisted(() => ({
  root: '',
  calls: [] as { file: string; args: string[] }[],
  pane: '',
  secretReads: [] as string[],
  dummy: '',
  providers: {} as Record<string, { id: string; label: string; baseUrl: string; authHeader: 'x-api-key' | 'Bearer' | 'none'; vaultKey: string | null }>,
}))

vi.mock('node:os', async (orig) => {
  const a = await orig<typeof import('node:os')>()
  return { ...a, homedir: () => `${H.root}/home` }
})
vi.mock('node:child_process', async (orig) => {
  const a = await orig<typeof import('node:child_process')>()
  const execFileSync = (file: string, args: readonly string[] = []) => {
    H.calls.push({ file, args: [...args] })
    const sub = args[0]
    if (sub === 'capture-pane') return H.pane
    if (['list-sessions', 'has-session', 'kill-session', 'list-panes', 'display-message'].includes(sub)) {
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
vi.mock('../web/vault.js', async (orig) => {
  const a = await orig<typeof import('../web/vault.js')>()
  return {
    ...a,
    getSecret: (id: string) => { H.secretReads.push(id); return H.dummy },
    setSecret: () => { throw new Error('test: no Vault writes on the launch path') },
    deleteSecret: () => { throw new Error('test: no Vault writes on the launch path') },
  }
})
vi.mock('../web/custom-providers.js', async (orig) => {
  const a = await orig<typeof import('../web/custom-providers.js')>()
  return { ...a, loadCustomProvider: (id: string) => H.providers[id] ?? null, listCustomProviders: () => Object.values(H.providers) }
})
vi.mock('../web/channel-poller-reap.js', async (orig) => {
  const a = await orig<typeof import('../web/channel-poller-reap.js')>()
  return { ...a, reapChannelOrphans: () => undefined, reapDetachedChannelClaudes: () => undefined }
})
vi.mock('../web/claude-credentials-guard.js', async (orig) => {
  const a = await orig<typeof import('../web/claude-credentials-guard.js')>()
  return { ...a, renameSharedCredentialsIfSafe: () => undefined }
})
vi.mock('../web/claude-cli-version.js', async (orig) => {
  const a = await orig<typeof import('../web/claude-cli-version.js')>()
  const v = { version: '2.1.300', measuredAt: 0, error: null, source: 'env' as const }
  return { ...a, measureClaudeCliVersion: async () => v, measureClaudeCliVersionSync: () => v }
})
vi.mock('../web/channel-plugin-unlock.js', async (orig) => {
  const a = await orig<typeof import('../web/channel-plugin-unlock.js')>()
  return { ...a, schedulePluginUnlockAfterRespawn: () => undefined }
})
vi.mock('../notify.js', async (orig) => {
  const a = await orig<typeof import('../notify.js')>()
  return { ...a, notifyChannel: async () => undefined, notifyOwner: async () => undefined, alertIsRedirected: () => false }
})
vi.mock('../web/restart-recovery-brief.js', async (orig) => {
  const a = await orig<typeof import('../web/restart-recovery-brief.js')>()
  return { ...a, scheduleRecoveryBrief: () => undefined }
})

// ---- scratch install --------------------------------------------------------
const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
H.root = mkdtempSync(join(tmpdir(), 'ikg-launch-'))
H.dummy = ['sk', 'ant', 'TEST', 'DUMMY', randomBytes(6).toString('hex')].join('-')
process.env.CLAUDECLAW_ENV_DIR = join(H.root, 'envdir')
mkdirSync(join(H.root, 'envdir'), { recursive: true })
for (const d of ['templates', 'scripts', '.claude', 'plugins', 'config-examples', 'seed-config']) {
  if (existsSync(join(REPO, d))) symlinkSync(join(REPO, d), join(H.root, d))
}
mkdirSync(join(H.root, 'store'), { recursive: true })
mkdirSync(join(H.root, 'agents'), { recursive: true })

const AP = await import('../web/agent-process.js')
const G = await import('../web/interactive-key-guard.js')
const { logger } = await import('../logger.js')
const { encodeClaudeProjectDir } = await import('../claude-project-dir.js')

const EVENTS = join(H.root, 'store', 'interactive-key-guard-events.jsonl')
const SHARED_SETTINGS = join(H.root, 'home', '.claude', 'settings.json')
const FLEET_TOKEN = join(H.root, 'store', '.claude-oauth-token')
const logged: string[] = []

function safe(v: unknown): string {
  try { return JSON.stringify(v) ?? String(v) } catch { return String(v) }
}

function agent(name: string, cfg: Record<string, unknown>, opts: { channel?: boolean; prior?: boolean } = {}): string {
  const dir = join(H.root, 'agents', name)
  mkdirSync(dir, { recursive: true })
  writeFileSync(join(dir, 'agent-config.json'), JSON.stringify(cfg))
  writeFileSync(join(dir, 'CLAUDE.md'), `# ${name}\n`)
  writeFileSync(join(dir, 'SOUL.md'), `# ${name}\n`)
  if (opts.channel) {
    const ch = join(dir, '.claude', 'channels', 'telegram')
    mkdirSync(ch, { recursive: true })
    writeFileSync(join(ch, '.env'), 'TELEGRAM_BOT_TOKEN=000000:FAKE-test-bot-token\n')
  }
  if (opts.prior) {
    mkdirSync(join(H.root, 'home', '.claude', 'projects', encodeClaudeProjectDir(dir)), { recursive: true })
  }
  return dir
}

const launches = (name: string): string[] =>
  H.calls.filter((c: Call) => c.args[0] === 'new-session' && c.args[3] === `agent-${name}`).map((c: Call) => c.args[4])
const events = (): Array<Record<string, unknown>> =>
  existsSync(EVENTS) ? readFileSync(EVENTS, 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)) : []

function noDummyAnywhere(): void {
  for (const c of H.calls) expect(c.args.join(' ')).not.toContain(H.dummy)
  if (existsSync(EVENTS)) expect(readFileSync(EVENTS, 'utf-8')).not.toContain(H.dummy)
  for (const l of logged) expect(l).not.toContain(H.dummy)
}

beforeEach(() => {
  H.calls.length = 0
  H.secretReads.length = 0
  H.pane = ''
  H.providers = {}
  logged.length = 0
  rmSync(join(H.root, 'home'), { recursive: true, force: true })
  mkdirSync(join(H.root, 'home', '.claude'), { recursive: true })
  writeFileSync(SHARED_SETTINGS, JSON.stringify({ enabledPlugins: {} }))
  rmSync(EVENTS, { force: true })
  rmSync(FLEET_TOKEN, { force: true })
  for (const lvl of ['error', 'warn', 'info'] as const) {
    vi.spyOn(logger, lvl).mockImplementation(((...args: unknown[]) => { logged.push(args.map(safe).join(' ')) }) as never)
  }
})
afterEach(() => {
  vi.restoreAllMocks()
  vi.useRealTimers()
  G.setInteractiveKeyPolicyForTest(null)
})
afterAll(() => {
  rmSync(H.root, { recursive: true, force: true })
})

describe('forbid: a first-party agent with authMode api never starts (I-03)', () => {
  const cases: Array<[string, () => Promise<{ ok: boolean; error?: string }>, { prior?: boolean }]> = [
    ['plain start', () => AP.startAgentProcess('api1'), {}],
    ['--continue (prior session on disk)', () => AP.startAgentProcess('api1'), { prior: true }],
    ['fresh', () => AP.startAgentProcess('api1', { fresh: true }), { prior: true }],
    ['restartAgentProcess (context guard / auto-restart / button)', () => AP.restartAgentProcess('api1', { fresh: true }), {}],
    ['restartAgentProcess --continue', () => AP.restartAgentProcess('api1'), { prior: true }],
  ]
  for (const [label, run, opts] of cases) {
    it(label, async () => {
      G.setInteractiveKeyPolicyForTest('forbid')
      agent('api1', { model: 'claude-opus-5-5', authMode: 'api' }, opts)
      const r = await run()
      expect(r).toEqual({ ok: false, error: 'interactive-key-guard: auth-mode-api' })
      expect(launches('api1')).toEqual([])
      // Refused BEFORE the key is read or parked in a launch-secret file.
      expect(H.secretReads).not.toContain('agent-api1-api-key')
      const ev = events()
      expect(ev).toHaveLength(1)
      expect(ev[0]).toMatchObject({ source: 'launch-guard', where: 'startAgentProcess:auth-mode-api', names: ['ANTHROPIC_API_KEY'], agent: 'api1' })
      expect(Object.keys(ev[0]).sort()).toEqual(['agent', 'names', 'source', 'ts', 'where'])
      noDummyAnywhere()
    })
  }

  it('the same agent under allow starts exactly as today: on its own key, by reference, no unset', async () => {
    G.setInteractiveKeyPolicyForTest('allow')
    agent('api2', { model: 'claude-opus-5-5', authMode: 'api' })
    const r = await AP.startAgentProcess('api2')
    expect(r.ok).toBe(true)
    const [cmd] = launches('api2')
    expect(cmd).toMatch(/export ANTHROPIC_API_KEY="\$\(cat '[^']+'\)" && /)
    expect(cmd).not.toContain('unset ANTHROPIC_API_KEY')
    expect(events()).toEqual([])
    noDummyAnywhere()
  })
})

describe('forbid: a custom provider that is Anthropic itself never starts', () => {
  it('baseUrl api.anthropic.com', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    H.providers.direct = { id: 'direct', label: 'd', baseUrl: 'https://api.anthropic.com', authHeader: 'x-api-key', vaultKey: 'MY_DIRECT_KEY' }
    agent('cp1', { model: 'claude-opus-5-5', customProvider: 'direct' })
    expect(await AP.startAgentProcess('cp1')).toEqual({ ok: false, error: 'interactive-key-guard: first-party-custom-provider' })
    expect(launches('cp1')).toEqual([])
    expect(H.secretReads).not.toContain('MY_DIRECT_KEY')
    expect(events()[0]).toMatchObject({ where: 'startAgentProcess:first-party-custom-provider', agent: 'cp1' })
    noDummyAnywhere()
  })

  it('vaultKey ANTHROPIC_API_KEY_BATCH behind a non-Anthropic URL', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    H.providers.proxy = { id: 'proxy', label: 'p', baseUrl: 'http://127.0.0.1:4010', authHeader: 'Bearer', vaultKey: 'ANTHROPIC_API_KEY_BATCH' }
    agent('cp2', { model: 'gpt-x', customProvider: 'proxy' })
    expect(await AP.startAgentProcess('cp2')).toEqual({ ok: false, error: 'interactive-key-guard: first-party-custom-provider' })
    expect(launches('cp2')).toEqual([])
    expect(H.secretReads).not.toContain('ANTHROPIC_API_KEY_BATCH')
  })
})

describe('forbid: a first-party agent that may start, starts with the key names unset', () => {
  it('shared mode: the forbid command is exactly INTERACTIVE_UNSET + the allow command', async () => {
    agent('fp1', { model: 'claude-opus-5-5' })
    G.setInteractiveKeyPolicyForTest('allow')
    expect((await AP.startAgentProcess('fp1')).ok).toBe(true)
    G.setInteractiveKeyPolicyForTest('forbid')
    expect((await AP.startAgentProcess('fp1')).ok).toBe(true)
    const [allowCmd, forbidCmd] = launches('fp1')
    expect(allowCmd).not.toContain('ANTHROPIC_API_KEY')
    expect(forbidCmd).toBe(G.INTERACTIVE_UNSET + allowCmd)
    expect(events()).toEqual([])
  })

  it('--continue keeps the unset (and the continue)', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    agent('fp2', { model: 'claude-sonnet-5-5' }, { prior: true })
    expect((await AP.startAgentProcess('fp2')).ok).toBe(true)
    const [cmd] = launches('fp2')
    expect(cmd.startsWith(G.INTERACTIVE_UNSET)).toBe(true)
    expect(cmd).toContain(' --continue ')
  })

  it('the unset really clears an inherited key before claude runs (evaluated by sh)', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    agent('fp3', { model: 'claude-opus-5-5' })
    await AP.startAgentProcess('fp3')
    const [cmd] = launches('fp3')
    const { execFileSync: realExec } = await vi.importActual<typeof import('node:child_process')>('node:child_process')
    // Only the prefix is executed (the rest would start claude): the shell sees the
    // key in its env, and the command's own unset removes it.
    const out = realExec('/bin/sh', ['-c', `${cmd.slice(0, G.INTERACTIVE_UNSET.length)}printf '[%s][%s]' "\${ANTHROPIC_API_KEY-unset}" "\${ANTHROPIC_AUTH_TOKEN-unset}"`], {
      env: { PATH: '/usr/bin:/bin', ANTHROPIC_API_KEY: H.dummy, ANTHROPIC_AUTH_TOKEN: H.dummy },
      encoding: 'utf-8',
    })
    expect(out).toBe('[unset][unset]')
  })

  it('EPERM /tmp fallback: the relaunch carries the unset too', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    agent('fp4', { model: 'claude-opus-5-5' }, { channel: true })
    vi.useFakeTimers({ toFake: ['setTimeout', 'setInterval'] })
    H.pane = 'Error: EPERM: operation not permitted, open ...'
    expect((await AP.startAgentProcess('fp4')).ok).toBe(true)
    await vi.advanceTimersByTimeAsync(1600)
    const cmds = launches('fp4')
    expect(cmds).toHaveLength(2)
    for (const c of cmds) expect(c.startsWith(G.INTERACTIVE_UNSET)).toBe(true)
    expect(cmds[1]).toMatch(/cd "[^"]*marveen-agent-fp4-[^"]*"/)
    noDummyAnywhere()
  })
})

describe('forbid: an auth key in the settings the session loads refuses the start', () => {
  it('shared ~/.claude/settings.json env (no isolation without a fleet token)', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    writeFileSync(SHARED_SETTINGS, JSON.stringify({ env: { ANTHROPIC_AUTH_TOKEN: H.dummy, OTHER: 'x' } }))
    agent('st1', { model: 'claude-opus-5-5' })
    expect(await AP.startAgentProcess('st1')).toEqual({ ok: false, error: 'interactive-key-guard: settings-auth-key' })
    expect(launches('st1')).toEqual([])
    expect(events()).toEqual([expect.objectContaining({ source: 'launch-guard', where: SHARED_SETTINGS, names: ['ANTHROPIC_AUTH_TOKEN'], agent: 'st1' })])
    noDummyAnywhere()
  })

  it('project-scope settings.local.json apiKeyHelper', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    const dir = agent('st2', { model: 'claude-opus-5-5' })
    mkdirSync(join(dir, '.claude'), { recursive: true })
    writeFileSync(join(dir, '.claude', 'settings.local.json'), JSON.stringify({ apiKeyHelper: '/bin/echo x' }))
    expect(await AP.startAgentProcess('st2')).toEqual({ ok: false, error: 'interactive-key-guard: settings-auth-key' })
    expect(events()[0]).toMatchObject({ names: ['apiKeyHelper'] })
  })

  it('allow: the same settings start as today', async () => {
    G.setInteractiveKeyPolicyForTest('allow')
    writeFileSync(SHARED_SETTINGS, JSON.stringify({ env: { ANTHROPIC_AUTH_TOKEN: H.dummy } }))
    agent('st3', { model: 'claude-opus-5-5' })
    expect((await AP.startAgentProcess('st3')).ok).toBe(true)
    expect(events()).toEqual([])
  })
})

describe('isolated provisioning (fleet token present): forbid keeps the key names out of a first-party agent', () => {
  const shared = () => ({ env: { ANTHROPIC_API_KEY: H.dummy, ANTHROPIC_AUTH_TOKEN: H.dummy, KEEP_ME: '1' }, apiKeyHelper: '/bin/echo x', enabledPlugins: {} })

  it('forbid: the isolated settings.json carries neither name nor apiKeyHelper, the rest survives, and the agent starts', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    writeFileSync(FLEET_TOKEN, 'sk-ant-oat01-FAKE-fleet-token-for-tests\n', { mode: 0o600 })
    writeFileSync(SHARED_SETTINGS, JSON.stringify(shared()))
    const dir = agent('iso1', { model: 'claude-opus-5-5' })
    expect((await AP.startAgentProcess('iso1')).ok).toBe(true)
    const own = JSON.parse(readFileSync(join(dir, '.claude-config', 'settings.json'), 'utf-8'))
    expect(own.env).toEqual({ KEEP_ME: '1' })
    expect('apiKeyHelper' in own).toBe(false)
    const [cmd] = launches('iso1')
    expect(cmd.startsWith(G.INTERACTIVE_UNSET)).toBe(true)
    expect(events()).toEqual([expect.objectContaining({ source: 'isolated-provisioning', names: ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'apiKeyHelper'], agent: 'iso1' })])
    noDummyAnywhere()
  })

  it('allow: the copy is today\'s (the names reach the isolated file)', async () => {
    G.setInteractiveKeyPolicyForTest('allow')
    writeFileSync(FLEET_TOKEN, 'sk-ant-oat01-FAKE-fleet-token-for-tests\n', { mode: 0o600 })
    writeFileSync(SHARED_SETTINGS, JSON.stringify(shared()))
    const dir = agent('iso2', { model: 'claude-opus-5-5' })
    expect((await AP.startAgentProcess('iso2')).ok).toBe(true)
    const own = JSON.parse(readFileSync(join(dir, '.claude-config', 'settings.json'), 'utf-8'))
    expect(Object.keys(own.env).sort()).toEqual(['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'KEEP_ME'])
    expect(own.apiKeyHelper).toBe('/bin/echo x')
    expect(events()).toEqual([])
  })
})

describe('non-first-party agents: the forbid command is byte-identical to allow', () => {
  const shapes: Array<[string, Record<string, unknown>, (() => void)?]> = [
    // fejleszto / tartalek shape [S40]: a LiteLLM custom provider.
    ['litellm (fejleszto/tartalek)', { model: 'chatgpt/gpt-6-astra', customProvider: 'litellm-chatgpt' }, () => {
      H.providers['litellm-chatgpt'] = { id: 'litellm-chatgpt', label: 'LiteLLM', baseUrl: 'http://127.0.0.1:4010', authHeader: 'Bearer', vaultKey: 'litellm-master-key' }
    }],
    ['litellm, api authMode', { model: 'chatgpt/gpt-6.1-sol', customProvider: 'litellm-chatgpt', authMode: 'api' }, () => {
      H.providers['litellm-chatgpt'] = { id: 'litellm-chatgpt', label: 'LiteLLM', baseUrl: 'http://127.0.0.1:4010', authHeader: 'x-api-key', vaultKey: 'litellm-master-key' }
    }],
    ['openrouter', { model: 'openai/gpt-5.5' }],
    ['deepseek', { model: 'deepseek-v4-pro', authMode: 'api' }],
    ['ollama', { model: 'qwen3.6:27b' }],
  ]
  for (const [label, cfg, setup] of shapes) {
    it(label, async () => {
      setup?.()
      const name = `np-${label.replace(/[^a-z]/g, '').slice(0, 12)}`
      agent(name, cfg)
      G.setInteractiveKeyPolicyForTest('allow')
      expect((await AP.startAgentProcess(name)).ok).toBe(true)
      G.setInteractiveKeyPolicyForTest('forbid')
      expect((await AP.startAgentProcess(name)).ok).toBe(true)
      const [allowCmd, forbidCmd] = launches(name)
      expect(allowCmd).toBeTruthy()
      expect(forbidCmd).toBe(allowCmd)
      expect(forbidCmd).not.toContain('unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN')
      expect(events()).toEqual([])
      noDummyAnywhere()
    })
  }
})

describe('remote agents take the same decision', () => {
  it('forbid + api: refused, no remote new-session', async () => {
    G.setInteractiveKeyPolicyForTest('forbid')
    agent('rem1', { model: 'claude-opus-5-5', authMode: 'api', remoteHost: 'devbox', remoteWorkdir: '/home/x/agents/rem1' })
    expect(await AP.startAgentProcess('rem1')).toEqual({ ok: false, error: 'interactive-key-guard: auth-mode-api' })
    expect(H.calls.some((c: Call) => c.args.join(' ').includes('new-session'))).toBe(false)
  })

  it('forbid + shared: the remote command starts with the unset; allow: unchanged', async () => {
    agent('rem2', { model: 'claude-opus-5-5', remoteHost: 'devbox', remoteWorkdir: '/home/x/agents/rem2' })
    G.setInteractiveKeyPolicyForTest('allow')
    expect((await AP.startAgentProcess('rem2')).ok).toBe(true)
    G.setInteractiveKeyPolicyForTest('forbid')
    expect((await AP.startAgentProcess('rem2')).ok).toBe(true)
    const remote = H.calls.filter((c: Call) => c.args.join(' ').includes('new-session')).map((c: Call) => c.args.join(' '))
    expect(remote).toHaveLength(2)
    expect(remote[0]).not.toContain('unset ANTHROPIC_API_KEY')
    expect(remote[1]).toContain('unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && export PATH=')
  })

  it('BE-1 (4): a remote agent on a model ALIAS (no customProvider) gets the unset too -- the remote launch exports no provider URL', async () => {
    for (const model of ['opus', 'sonnet', 'some-other-name']) {
      H.calls.length = 0
      agent('rem3', { model, remoteHost: 'devbox', remoteWorkdir: '/home/x/agents/rem3' })
      G.setInteractiveKeyPolicyForTest('forbid')
      expect((await AP.startAgentProcess('rem3')).ok, model).toBe(true)
      const remote = H.calls.filter((c: Call) => c.args.join(' ').includes('new-session')).map((c: Call) => c.args.join(' '))
      expect(remote, model).toHaveLength(1)
      expect(remote[0], model).toContain('unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && ')
    }
  })
})
