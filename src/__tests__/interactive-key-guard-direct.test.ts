// fec6335f N3c (the N3a review's lead): the claude processes TS starts ITSELF,
// outside tmux -- the credential probes (liveTestToken, liveProbeAuth) and the
// legacy Agent SDK path of runAgent. Each used to hand its child the dashboard's
// whole process.env; under INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid neither
// ANTHROPIC_API_KEY nor ANTHROPIC_AUTH_TOKEN may reach it, under allow nothing
// changes. The sink inventory (interactive-key-guard-sinks.test.ts) makes sure
// a new such call cannot appear unlisted; this file checks what the listed ones
// actually hand over.
//
// The "claude" here is a script in a scratch dir that records env NAMES only and
// answers OK; the SDK is mocked. The policy is pinned per test (no .env read).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { randomBytes } from 'node:crypto'

const { sdkCalls } = vi.hoisted(() => ({ sdkCalls: [] as Array<{ options: Record<string, unknown> }> }))
vi.mock('@anthropic-ai/claude-agent-sdk', () => ({
  query: (args: { options: Record<string, unknown> }) => {
    sdkCalls.push({ options: args.options })
    return (async function* () {
      yield { type: 'result', subtype: 'success', is_error: false, result: 'ok' }
    })()
  },
}))

import { liveProbeAuth, liveTestToken, probeChildEnv } from '../web/claude-credentials-guard.js'
import { runAgent, sdkChildEnv } from '../agent.js'
import { setInteractiveKeyPolicyForTest } from '../web/interactive-key-guard.js'
import { logger } from '../logger.js'

const DUMMY = ['sk', 'ant', 'TEST', 'DUMMY', randomBytes(6).toString('hex')].join('-')

let tmp = ''
let fake = ''
let out = ''
beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'ikg-direct-'))
  fake = join(tmp, 'claude')
  out = join(tmp, 'names.txt')
  // Names only: `env` piped through cut, never a value.
  writeFileSync(fake, `#!/bin/sh\nenv | cut -d= -f1 > "${out}"\necho OK\n`)
  chmodSync(fake, 0o755)
  sdkCalls.length = 0
})
afterEach(() => {
  setInteractiveKeyPolicyForTest(null)
  vi.unstubAllEnvs()
  vi.restoreAllMocks()
  rmSync(tmp, { recursive: true, force: true })
})

const seen = (): string[] => (existsSync(out) ? readFileSync(out, 'utf-8').split('\n').filter(Boolean) : [])

describe('probeChildEnv', () => {
  it('allow: the very same object; forbid: a copy without the two names, and which were dropped', () => {
    const env = { PATH: '/bin', ANTHROPIC_API_KEY: DUMMY, ANTHROPIC_AUTH_TOKEN: DUMMY, ANTHROPIC_API_KEY_BATCH: 'x' }
    expect(probeChildEnv(env, 'allow')).toEqual({ env, dropped: [] })
    expect(probeChildEnv(env, 'allow').env).toBe(env)
    const f = probeChildEnv(env, 'forbid')
    expect(f.env).toEqual({ PATH: '/bin', ANTHROPIC_API_KEY_BATCH: 'x' })
    expect(f.dropped).toEqual(['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN'])
    expect(env.ANTHROPIC_API_KEY).toBe(DUMMY) // the input is not mutated
  })
})

describe('liveTestToken (the fleet-token live test, a real `claude -p`)', () => {
  it('forbid: the child gets the token under test but neither key name from the dashboard env', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', DUMMY)
    vi.stubEnv('ANTHROPIC_AUTH_TOKEN', DUMMY)
    setInteractiveKeyPolicyForTest('forbid')
    expect(liveTestToken('tok', fake)).toBe(true)
    const names = seen()
    expect(names).toContain('CLAUDE_CODE_OAUTH_TOKEN')
    expect(names).not.toContain('ANTHROPIC_API_KEY')
    expect(names).not.toContain('ANTHROPIC_AUTH_TOKEN')
  })

  it('allow: unchanged -- the inherited names still reach it, as today', () => {
    vi.stubEnv('ANTHROPIC_API_KEY', DUMMY)
    setInteractiveKeyPolicyForTest('allow')
    expect(liveTestToken('tok', fake)).toBe(true)
    expect(seen()).toContain('ANTHROPIC_API_KEY')
  })
})

describe('liveProbeAuth (the onboarding and boot-pass probe)', () => {
  it('forbid: an inherited ANTHROPIC_AUTH_TOKEN does not reach an OAuth probe; the log names it, never its value', async () => {
    vi.stubEnv('ANTHROPIC_AUTH_TOKEN', DUMMY)
    setInteractiveKeyPolicyForTest('forbid')
    const warn = vi.spyOn(logger, 'warn')
    expect(await liveProbeAuth({ CLAUDE_CODE_OAUTH_TOKEN: 'tok' }, fake)).toBe('ok')
    expect(seen()).toContain('CLAUDE_CODE_OAUTH_TOKEN')
    expect(seen()).not.toContain('ANTHROPIC_AUTH_TOKEN')
    expect(JSON.stringify(warn.mock.calls)).toContain('ANTHROPIC_AUTH_TOKEN')
    expect(JSON.stringify(warn.mock.calls)).not.toContain(DUMMY)
  })

  it('forbid: a probe OF an API key does not run at all, and reads as inconclusive (not as a verdict)', async () => {
    setInteractiveKeyPolicyForTest('forbid')
    expect(await liveProbeAuth({ ANTHROPIC_API_KEY: DUMMY }, fake)).toBe('inconclusive')
    expect(existsSync(out)).toBe(false)
  })

  it('allow: unchanged -- an API-key probe runs with the key, an inherited auth token is passed through', async () => {
    vi.stubEnv('ANTHROPIC_AUTH_TOKEN', DUMMY)
    setInteractiveKeyPolicyForTest('allow')
    expect(await liveProbeAuth({ ANTHROPIC_API_KEY: DUMMY }, fake)).toBe('ok')
    expect(seen()).toContain('ANTHROPIC_API_KEY')
    expect(seen()).toContain('ANTHROPIC_AUTH_TOKEN')
  })
})

describe('runAgent, legacy SDK path (MARVEEN_AGENT_BACKEND=sdk)', () => {
  it('sdkChildEnv: allow is today\'s (no option without a caller env, else the merge); forbid is always explicit and key-free', () => {
    const pe = { PATH: '/bin', ANTHROPIC_API_KEY: DUMMY } as NodeJS.ProcessEnv
    expect(sdkChildEnv(pe, undefined, 'allow')).toBeUndefined()
    expect(sdkChildEnv(pe, { X: '1' }, 'allow')).toEqual({ PATH: '/bin', ANTHROPIC_API_KEY: DUMMY, X: '1' })
    expect(sdkChildEnv(pe, undefined, 'forbid')).toEqual({ PATH: '/bin' })
    expect(sdkChildEnv(pe, { ANTHROPIC_AUTH_TOKEN: DUMMY, X: '1' }, 'forbid')).toEqual({ PATH: '/bin', X: '1' })
  })

  it('forbid: the SDK is handed an env without either name, even when the caller passes one', async () => {
    vi.stubEnv('MARVEEN_AGENT_BACKEND', 'sdk')
    vi.stubEnv('ANTHROPIC_API_KEY', DUMMY)
    setInteractiveKeyPolicyForTest('forbid')
    const r = await runAgent('hi', undefined, undefined, false, tmp, { ANTHROPIC_AUTH_TOKEN: DUMMY })
    expect(r.text).toBe('ok')
    const env = sdkCalls[0].options.env as Record<string, string | undefined>
    expect(env).toBeDefined()
    expect(Object.keys(env)).not.toContain('ANTHROPIC_API_KEY')
    expect(Object.keys(env)).not.toContain('ANTHROPIC_AUTH_TOKEN')
  })

  it('allow: unchanged -- no env option when the caller gives none (the SDK inherits process.env)', async () => {
    vi.stubEnv('MARVEEN_AGENT_BACKEND', 'sdk')
    setInteractiveKeyPolicyForTest('allow')
    await runAgent('hi', undefined, undefined, false, tmp)
    expect('env' in sdkCalls[0].options).toBe(false)
  })
})
