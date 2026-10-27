// fec6335f N3a: the interactive-key guard module, unit by unit. Every key below
// is a per-run dummy; no .env, Vault or store file is read or written (the
// event file is redirected to a scratch dir).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { randomBytes } from 'node:crypto'
import {
  policyFromValue,
  readInteractiveKeyPolicy,
  isAnthropicBaseUrl,
  isAnthropicFirstParty,
  interactiveKeyNamesInSettingsText,
  scanSettingsForInteractiveKeys,
  decideInteractiveLaunch,
  refusalNames,
  assertLaunchCmdClean,
  InteractiveKeyGuardError,
  recordGuardEvent,
  setGuardEventsPathForTest,
  INTERACTIVE_UNSET,
  INTERACTIVE_UNSET_OR_EXIT,
  UNREADABLE_SETTINGS,
  type InteractiveLaunchCtx,
} from '../web/interactive-key-guard.js'
import { logger } from '../logger.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DUMMY = ['sk', 'ant', 'TEST', 'DUMMY', randomBytes(6).toString('hex')].join('-')

describe('policy: absent/empty/allow -> allow, anything else -> forbid (fail-closed)', () => {
  it('policyFromValue', () => {
    for (const v of [undefined, '', '   ', 'allow', ' allow ']) expect(policyFromValue(v), String(v)).toBe('allow')
    for (const v of ['forbid', 'Forbid', 'ALLOW', 'deny', 'off', '0', 'allow # x', 'allowed']) expect(policyFromValue(v), v).toBe('forbid')
  })

  it('readInteractiveKeyPolicy parses .env text like env-parse: last line wins, quotes, comments', () => {
    expect(readInteractiveKeyPolicy('')).toBe('allow')
    expect(readInteractiveKeyPolicy('OTHER=1\n')).toBe('allow')
    expect(readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')).toBe('forbid')
    expect(readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY="allow"\n')).toBe('allow')
    expect(readInteractiveKeyPolicy("INTERACTIVE_ANTHROPIC_KEY_POLICY='forbid'\n")).toBe('forbid')
    expect(readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY=\n')).toBe('allow')
    expect(readInteractiveKeyPolicy('# INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')).toBe('allow')
    expect(readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\nINTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')).toBe('forbid')
    expect(readInteractiveKeyPolicy('INTERACTIVE_ANTHROPIC_KEY_POLICY=frobid\n')).toBe('forbid')
  })
})

describe('first-party: whose traffic is Anthropic\'s own', () => {
  it('isAnthropicBaseUrl: host match only, fail-closed on anything unparseable', () => {
    for (const u of ['https://api.anthropic.com', 'https://API.Anthropic.com./v1', 'http://anthropic.com', 'https://eu.api.anthropic.com:443/x']) {
      expect(isAnthropicBaseUrl(u), u).toBe(true)
    }
    for (const u of ['http://127.0.0.1:4010', 'https://openrouter.ai/api', 'https://anthropic.com.evil.example', 'https://evil.example/api.anthropic.com', 'https://notanthropic.com']) {
      expect(isAnthropicBaseUrl(u), u).toBe(false)
    }
    // Not judgeable as an http(s) host -> treated as Anthropic.
    for (const u of ['', 'api.anthropic.com', 'localhost:4010', 'file:///x', 'ftp://api.example']) expect(isAnthropicBaseUrl(u), u).toBe(true)
  })

  it('isAnthropicFirstParty: the launcher discriminators', () => {
    const def = (baseUrl: string, vaultKey: string | null = 'k') => ({ baseUrl, vaultKey })
    expect(isAnthropicFirstParty({ isCustom: false, customProviderDef: null, model: 'claude-opus-5-5' })).toBe(true)
    expect(isAnthropicFirstParty({ isCustom: false, customProviderDef: null, model: 'claude-opus-5-5[1m]' })).toBe(true)
    for (const m of ['chatgpt/gpt-6-astra', 'anthropic/claude-opus-5', 'deepseek-v4-pro', 'qwen3.6:27b', 'minimax-m3']) {
      expect(isAnthropicFirstParty({ isCustom: false, customProviderDef: null, model: m }), m).toBe(false)
    }
    // A custom provider wins over the model pattern, both ways.
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: def('http://127.0.0.1:4010'), model: 'claude-opus-5-5' })).toBe(false)
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: def('https://api.anthropic.com'), model: 'gpt-x' })).toBe(true)
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: def('http://127.0.0.1:4010', 'ANTHROPIC_API_KEY_BATCH'), model: 'gpt' })).toBe(true)
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: def('http://127.0.0.1:4010', ' ANTHROPIC_API_KEY_BATCH '), model: 'gpt' })).toBe(true)
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: null, model: 'gpt' })).toBe(true)
  })
})

describe('decideInteractiveLaunch', () => {
  const base: InteractiveLaunchCtx = { policy: 'forbid', isCustom: false, customProviderDef: null, model: 'claude-opus-5-5', authMode: 'shared' }

  it('allow: always the no-op answer, even for the configs forbid refuses', () => {
    const allow = { ...base, policy: 'allow' as const }
    for (const c of [allow, { ...allow, authMode: 'api' as const }, { ...allow, settingsFindings: [{ path: 'p', names: ['ANTHROPIC_API_KEY'] }] },
      { ...allow, isCustom: true, customProviderDef: { baseUrl: 'https://api.anthropic.com', vaultKey: 'x' } }]) {
      expect(decideInteractiveLaunch(c)).toEqual({ ok: true, unsetPrefix: '' })
    }
  })

  it('forbid, first-party: shared and own_team start with the unset; api, a settings key and a first-party custom provider refuse', () => {
    expect(decideInteractiveLaunch(base)).toEqual({ ok: true, unsetPrefix: INTERACTIVE_UNSET })
    expect(decideInteractiveLaunch({ ...base, authMode: 'own_team' })).toEqual({ ok: true, unsetPrefix: INTERACTIVE_UNSET })
    expect(decideInteractiveLaunch({ ...base, settingsFindings: [] })).toEqual({ ok: true, unsetPrefix: INTERACTIVE_UNSET })
    expect(decideInteractiveLaunch({ ...base, authMode: 'api' })).toEqual({ ok: false, reason: 'auth-mode-api' })
    expect(decideInteractiveLaunch({ ...base, settingsFindings: [{ path: 'p', names: ['apiKeyHelper'] }] })).toEqual({ ok: false, reason: 'settings-auth-key' })
    expect(decideInteractiveLaunch({ ...base, isCustom: true, customProviderDef: { baseUrl: 'https://api.anthropic.com', vaultKey: 'x' } }))
      .toEqual({ ok: false, reason: 'first-party-custom-provider' })
  })

  it('forbid, not first-party: unchanged, whatever the authMode or settings', () => {
    const gpt = { ...base, model: 'chatgpt/gpt-6-astra', authMode: 'api' as const, settingsFindings: [{ path: 'p', names: ['ANTHROPIC_AUTH_TOKEN'] }] }
    expect(decideInteractiveLaunch(gpt)).toEqual({ ok: true, unsetPrefix: '' })
    const litellm = { ...base, isCustom: true, customProviderDef: { baseUrl: 'http://127.0.0.1:4010', vaultKey: 'litellm' }, authMode: 'api' as const }
    expect(decideInteractiveLaunch(litellm)).toEqual({ ok: true, unsetPrefix: '' })
  })

  it('refusalNames: names, never values', () => {
    expect(refusalNames('auth-mode-api')).toEqual(['ANTHROPIC_API_KEY'])
    expect(refusalNames('first-party-custom-provider')).toEqual(['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN'])
    expect(refusalNames('settings-auth-key', [{ path: 'a', names: ['apiKeyHelper'] }, { path: 'b', names: ['apiKeyHelper', 'ANTHROPIC_API_KEY'] }]))
      .toEqual(['apiKeyHelper', 'ANTHROPIC_API_KEY'])
  })
})

describe('settings scan: names only', () => {
  it('env names and a top-level apiKeyHelper; nothing else counts', () => {
    expect(interactiveKeyNamesInSettingsText(JSON.stringify({ env: { ANTHROPIC_API_KEY: DUMMY, ANTHROPIC_AUTH_TOKEN: DUMMY }, apiKeyHelper: 'x' })))
      .toEqual(['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'apiKeyHelper'])
    expect(interactiveKeyNamesInSettingsText(JSON.stringify({ env: { ANTHROPIC_BASE_URL: 'u', CLAUDE_CODE_OAUTH_TOKEN: DUMMY, anthropic_api_key: DUMMY } }))).toEqual([])
    expect(interactiveKeyNamesInSettingsText(JSON.stringify({ env: { apiKeyHelper: 'x' } }))).toEqual([])
    expect(interactiveKeyNamesInSettingsText('{"env":{"__proto__":{"ANTHROPIC_API_KEY":"x"}}}')).toEqual([])
    expect(interactiveKeyNamesInSettingsText('[]')).toEqual([])
    expect(interactiveKeyNamesInSettingsText('null')).toEqual([])
  })

  it('a text that does not parse is scanned for the quoted names (a broken file can only add a finding)', () => {
    expect(interactiveKeyNamesInSettingsText(`{ "env": { "ANTHROPIC_API_KEY": "${DUMMY}", } // trailing`)).toEqual(['ANTHROPIC_API_KEY'])
    expect(interactiveKeyNamesInSettingsText('{ broken "apiKeyHelper" : 1')).toEqual(['apiKeyHelper'])
    expect(interactiveKeyNamesInSettingsText('{ broken')).toEqual([])
  })

  it('scanSettingsForInteractiveKeys: absent = no finding, unreadable = a finding, values never returned', () => {
    const files: Record<string, string | Error> = {
      '/a': JSON.stringify({ env: { ANTHROPIC_AUTH_TOKEN: DUMMY } }),
      '/clean': JSON.stringify({ env: { FOO: 'bar' } }),
      '/missing': Object.assign(new Error('x'), { code: 'ENOENT' }),
      '/notdir': Object.assign(new Error('x'), { code: 'ENOTDIR' }),
      '/denied': Object.assign(new Error('x'), { code: 'EACCES' }),
    }
    const read = (p: string) => { const v = files[p]; if (v instanceof Error) throw v; return v }
    const out = scanSettingsForInteractiveKeys(Object.keys(files), read)
    expect(out).toEqual([{ path: '/a', names: ['ANTHROPIC_AUTH_TOKEN'] }, { path: '/denied', names: [UNREADABLE_SETTINGS] }])
    expect(JSON.stringify(out)).not.toContain(DUMMY)
  })
})

describe('assertLaunchCmdClean: the last check before a sink', () => {
  const fp = { policy: 'forbid' as const, firstParty: true }
  const clean = `${INTERACTIVE_UNSET}export PATH="/usr/bin" && cd "/a" && claude --model 'claude-opus-5-5'`

  it('passes a clean first-party command (both unset forms)', () => {
    expect(() => assertLaunchCmdClean(clean, fp)).not.toThrow()
    expect(() => assertLaunchCmdClean(`${INTERACTIVE_UNSET_OR_EXIT}export X=1; claude`, fp)).not.toThrow()
    // A different name that merely starts the same is not a hit.
    expect(() => assertLaunchCmdClean(`${clean} && export ANTHROPIC_API_KEY_BATCH_ID=1`, fp)).not.toThrow()
  })

  it('throws on a key export, an apiKeyHelper or a missing unset, naming names only', () => {
    const bad: Array<[string, string[]]> = [
      [`${INTERACTIVE_UNSET}export ANTHROPIC_API_KEY="$(cat '/s')" && claude`, ['ANTHROPIC_API_KEY']],
      [`${INTERACTIVE_UNSET}export ANTHROPIC_AUTH_TOKEN=${DUMMY} && claude`, ['ANTHROPIC_AUTH_TOKEN']],
      [`${INTERACTIVE_UNSET}env ANTHROPIC_API_KEY =x claude`, ['ANTHROPIC_API_KEY']],
      [`${INTERACTIVE_UNSET}claude --settings '{"apiKeyHelper":"x"}'`, ['apiKeyHelper']],
      [`export PATH=/x && claude`, ['missing-unset']],
    ]
    for (const [cmd, names] of bad) {
      let err: unknown
      try { assertLaunchCmdClean(cmd, fp) } catch (e) { err = e }
      expect(err, cmd).toBeInstanceOf(InteractiveKeyGuardError)
      expect((err as InteractiveKeyGuardError).names).toEqual(names)
      expect((err as Error).message).not.toContain(DUMMY)
    }
  })

  it('allow, and a non-first-party agent under forbid: never throws (their commands stay as they are)', () => {
    const litellm = `export ANTHROPIC_BASE_URL="http://127.0.0.1:4010" && export ANTHROPIC_AUTH_TOKEN="$(cat '/s')" && claude`
    expect(() => assertLaunchCmdClean(litellm, { policy: 'allow', firstParty: true })).not.toThrow()
    expect(() => assertLaunchCmdClean(litellm, { policy: 'forbid', firstParty: false })).not.toThrow()
  })
})

describe('recordGuardEvent', () => {
  let dir: string
  let path: string
  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'ikg-ev-'))
    path = join(dir, 'sub', 'interactive-key-guard-events.jsonl')
    setGuardEventsPathForTest(path)
  })
  afterEach(() => {
    setGuardEventsPathForTest(null)
    vi.restoreAllMocks()
    rmSync(dir, { recursive: true, force: true })
  })

  it('appends {ts, source, where, names, agent?} lines, 0600, and logs the same names', () => {
    const logs: unknown[] = []
    vi.spyOn(logger, 'error').mockImplementation(((...a: unknown[]) => { logs.push(a) }) as never)
    recordGuardEvent({ source: 'launch-guard', where: 'w1', names: ['ANTHROPIC_API_KEY'], agent: 'a1' })
    recordGuardEvent({ source: 'isolated-provisioning', where: 'w2', names: ['apiKeyHelper', UNREADABLE_SETTINGS] })
    const lines = readFileSync(path, 'utf-8').trim().split('\n').map((l) => JSON.parse(l))
    expect(lines).toHaveLength(2)
    expect(Object.keys(lines[0]).sort()).toEqual(['agent', 'names', 'source', 'ts', 'where'])
    expect(lines[0]).toMatchObject({ source: 'launch-guard', where: 'w1', names: ['ANTHROPIC_API_KEY'], agent: 'a1' })
    expect(Number.isNaN(Date.parse(lines[0].ts))).toBe(false)
    expect(Object.keys(lines[1]).sort()).toEqual(['names', 'source', 'ts', 'where'])
    expect(lines[1].names).toEqual(['apiKeyHelper', UNREADABLE_SETTINGS])
    expect(statSync(path).mode & 0o777).toBe(0o600)
    expect(JSON.stringify(logs)).toContain('ANTHROPIC_API_KEY')
  })

  it('a value smuggled in as a "name" is dropped from the file and the log', () => {
    const logs: unknown[] = []
    vi.spyOn(logger, 'error').mockImplementation(((...a: unknown[]) => { logs.push(a) }) as never)
    recordGuardEvent({ source: 's', where: 'w', names: ['ANTHROPIC_API_KEY', DUMMY, `ANTHROPIC_API_KEY=${DUMMY}`] })
    expect(readFileSync(path, 'utf-8')).not.toContain(DUMMY)
    expect(JSON.stringify(logs)).not.toContain(DUMMY)
    expect(JSON.parse(readFileSync(path, 'utf-8')).names).toEqual(['ANTHROPIC_API_KEY'])
  })

  it('never throws when the file cannot be written (the refusal must still reach its caller)', () => {
    vi.spyOn(logger, 'error').mockImplementation((() => undefined) as never)
    setGuardEventsPathForTest('/dev/null/not-a-dir/events.jsonl')
    expect(() => recordGuardEvent({ source: 's', where: 'w', names: ['ANTHROPIC_API_KEY'] })).not.toThrow()
    expect(existsSync('/dev/null/not-a-dir')).toBe(false)
  })
})

describe('BE-1 (4): a launcher that exports no provider URL reaches Anthropic whatever the model name', () => {
  it('directAnthropic: an alias or any other name without a customProvider is first-party; a customProvider still decides by itself', () => {
    for (const model of ['opus', 'sonnet', 'fable', 'gpt-x', '']) {
      expect(isAnthropicFirstParty({ isCustom: false, customProviderDef: null, model }), model).toBe(false)
      expect(isAnthropicFirstParty({ isCustom: false, customProviderDef: null, model, directAnthropic: true }), model).toBe(true)
      expect(decideInteractiveLaunch({ policy: 'forbid', isCustom: false, customProviderDef: null, model, directAnthropic: true, authMode: 'shared' }), model)
        .toEqual({ ok: true, unsetPrefix: INTERACTIVE_UNSET })
      expect(decideInteractiveLaunch({ policy: 'allow', isCustom: false, customProviderDef: null, model, directAnthropic: true, authMode: 'shared' }), model)
        .toEqual({ ok: true, unsetPrefix: '' })
    }
    const litellm = { baseUrl: 'http://127.0.0.1:4010', vaultKey: 'lk' }
    expect(isAnthropicFirstParty({ isCustom: true, customProviderDef: litellm, model: 'opus', directAnthropic: true })).toBe(false)
  })

  it('the worker and the remote launcher pass directAnthropic (MARVEEN_WORKER_MODEL / the remote model may be an alias)', () => {
    const root = join(__dirname, '..', '..')
    const worker = readFileSync(join(root, 'src/web/agent-worker.ts'), 'utf-8')
    expect(worker).toMatch(/const guardInput = \{[^}]*directAnthropic: true[^}]*\}/)
    const proc = readFileSync(join(root, 'src/web/agent-process.ts'), 'utf-8')
    const remote = proc.slice(proc.indexOf('const keyGuardInput = {', proc.indexOf('const remoteCustomId')))
    expect(remote.slice(0, remote.indexOf('}'))).toContain('directAnthropic: true')
  })
})

describe('BE-1 (6): the new writers do not write through a planted symlink', () => {
  it('recordGuardEvent: a symlink at the event path is not followed (the target is untouched, the error is logged)', async () => {
    const { symlinkSync, writeFileSync: wf } = await import('node:fs')
    const dir = mkdtempSync(join(tmpdir(), 'ikg-nofollow-'))
    try {
      const target = join(dir, 'target.txt')
      wf(target, 'ORIGINAL\n')
      const ev = join(dir, 'events.jsonl')
      symlinkSync(target, ev)
      setGuardEventsPathForTest(ev)
      const err = vi.spyOn(logger, 'error').mockImplementation(() => undefined as never)
      recordGuardEvent({ source: 'launch-guard', where: 'x', names: ['ANTHROPIC_API_KEY'] })
      expect(readFileSync(target, 'utf-8')).toBe('ORIGINAL\n')
      expect(err.mock.calls.some((c) => String(c[1]).includes('could not append the guard event file'))).toBe(true)
    } finally {
      setGuardEventsPathForTest(null)
      rmSync(dir, { recursive: true, force: true })
    }
  })
})
