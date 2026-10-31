// Start-up gates of the permission-bot relay (card d7f586bf, spec F1, F5): every
// F1.2 refusal reason is its own case, plus the switch and the owner. A refusal
// never polls (no getUpdates, and getMe only where the gate needs it), names its
// reason without a value, writes refused:<reason> to the status file and gives a
// non-zero exit code. Loopback only (socket guard, self-tested); fake token and
// an injected Vault reader, never the Keychain or a real bot token.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { StatusFile, readStatusFile, relayPaths } from '../permission-bot-relay/offset-store.js'
import { runStartupGates, tokenBotId, REFUSED_EXIT_CODE, type StartupDeps, type StartupRefusal } from '../permission-bot-relay/startup.js'
import type { RelayLog } from '../permission-bot-relay/poll-loop.js'
import { FakeBotApi } from './helpers/fake-bot-api.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'

const PIN = '424242424'
const TOKEN = `${PIN}:FAKEtokenSECRETforRelayTests_0123456789ab`
const SECRET = TOKEN.split(':')[1]!
const OTHER_TOKEN = '515151515:OTHERbotSECRETforRelayTests_9876543210zz'
const OWNER = '1591000001'
const MAIN_ID = '777777777'

function leaks(text: string): string[] {
  const hits: string[] = []
  if (text.includes(TOKEN)) hits.push('token')
  for (let i = 0; i + 8 <= SECRET.length; i++) if (text.includes(SECRET.slice(i, i + 8))) hits.push(SECRET.slice(i, i + 8))
  if (text.includes(OTHER_TOKEN.split(':')[1]!.slice(0, 12))) hits.push('other-token')
  return hits
}

const allText: string[] = []
function captureLog(): { log: RelayLog; text: () => string } {
  const lines: string[] = []
  const push = (level: string) => (obj: Record<string, unknown>, msg: string): void => {
    const s = JSON.stringify({ level, obj, msg })
    lines.push(s)
    allText.push(s)
  }
  return { log: { info: push('info'), warn: push('warn'), error: push('error') }, text: () => lines.join('\n') }
}

let guard: LoopbackGuard
let fake: FakeBotApi
let dir: string
let status: StatusFile
let statusPath: string

beforeAll(async () => {
  guard = installLoopbackGuard()
  await selfTestLoopbackGuard(guard)
  fake = new FakeBotApi(TOKEN)
  await fake.start()
})
afterAll(async () => {
  await fake.close()
  expect(leaks(allText.join('\n'))).toEqual([])
  guard.uninstall()
})
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pbr-startup-'))
  statusPath = relayPaths(dir).status
  status = new StatusFile(statusPath)
  fake.calls.length = 0
  fake.mode = 'normal'
  fake.botId = Number(PIN)
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function deps(over: Partial<StartupDeps> = {}): StartupDeps & { logText: () => string } {
  const { log, text } = captureLog()
  return {
    enabled: '1',
    pinnedBotId: PIN,
    mainBotIds: () => [MAIN_ID],
    readToken: () => TOKEN,
    resolveOwner: () => OWNER,
    status,
    log,
    apiBase: fake.url,
    shortCallTimeoutMs: 2000,
    ...over,
    logText: text,
  }
}

async function expectRefused(d: ReturnType<typeof deps>, reason: StartupRefusal, getMeCalls: number): Promise<void> {
  const r = await runStartupGates(d)
  expect(r).toEqual({ kind: 'refused', reason, exitCode: REFUSED_EXIT_CODE })
  expect(REFUSED_EXIT_CODE).not.toBe(0)
  expect(fake.callsOf('getUpdates')).toHaveLength(0)
  expect(fake.callsOf('getMe')).toHaveLength(getMeCalls)
  const st = readStatusFile(statusPath)
  expect(st?.state).toBe('refused')
  expect(st?.reason).toBe(reason)
  const log = d.logText()
  expect(log).toContain(`"reason":"${reason}"`)
  // By name, never with a value.
  for (const value of [PIN, OWNER, MAIN_ID, TOKEN, SECRET, '515151515']) expect(log).not.toContain(value)
  expect(readFileSync(statusPath, 'utf8')).not.toContain(PIN)
}

describe('switch (F1.4)', () => {
  for (const v of [undefined, '', '0', 'true', 'yes', ' 2', '11']) {
    it(`enabled=${JSON.stringify(v)} -> disabled, no Bot-API call, no Vault read`, async () => {
      let tokenReads = 0
      const d = deps({ enabled: v, readToken: () => { tokenReads++; return TOKEN } })
      const r = await runStartupGates(d)
      expect(r).toEqual({ kind: 'disabled' })
      expect(fake.calls).toHaveLength(0)
      expect(tokenReads).toBe(0)
      expect(readStatusFile(statusPath)?.state).toBe('disabled')
    })
  }
})

describe('F1.2 refusals, each by name', () => {
  it('pin missing -> bot_id_missing', async () => {
    await expectRefused(deps({ pinnedBotId: undefined }), 'bot_id_missing', 0)
  })
  it('pin empty/whitespace -> bot_id_missing', async () => {
    await expectRefused(deps({ pinnedBotId: '   ' }), 'bot_id_missing', 0)
  })
  for (const bad of ['0424242424', '-424242424', '42424a242', '4242424242424242424', '424 242']) {
    it(`pin ${JSON.stringify(bad)} -> bot_id_invalid`, async () => {
      await expectRefused(deps({ pinnedBotId: bad }), 'bot_id_invalid', 0)
    })
  }
  it('token missing (null) -> token_missing', async () => {
    await expectRefused(deps({ readToken: () => null }), 'token_missing', 0)
  })
  it('token empty -> token_missing', async () => {
    await expectRefused(deps({ readToken: () => '  ' }), 'token_missing', 0)
  })
  it('Vault reader throws -> token_missing (fail-closed)', async () => {
    await expectRefused(deps({ readToken: () => { throw new Error(`keychain locked ${TOKEN}`) } }), 'token_missing', 0)
  })
  it('token malformed -> token_malformed', async () => {
    await expectRefused(deps({ readToken: () => `${PIN}:` }), 'token_malformed', 0)
  })
  it('token prefix is another bot -> token_bot_mismatch', async () => {
    await expectRefused(deps({ readToken: () => OTHER_TOKEN }), 'token_bot_mismatch', 0)
  })
  it('pin is the main bot -> same_as_main_bot', async () => {
    await expectRefused(deps({ mainBotIds: () => [MAIN_ID, PIN] }), 'same_as_main_bot', 0)
  })
  it('main bot unknown -> main_bot_unresolved', async () => {
    await expectRefused(deps({ mainBotIds: () => [] }), 'main_bot_unresolved', 0)
  })
  it('getMe answers another id -> getme_mismatch', async () => {
    fake.botId = 515151515
    await expectRefused(deps(), 'getme_mismatch', 1)
  })
  it('getMe 401 -> getme_unauthorized', async () => {
    // The fake answers 401 to any token but its own: a token with the right
    // prefix but another secret.
    await expectRefused(deps({ readToken: () => `${PIN}:WRONGsecretWRONGsecretWRONGsecret00` }), 'getme_unauthorized', 1)
  })
  it('getMe unreachable -> getme_unavailable', async () => {
    const closed = new FakeBotApi(TOKEN)
    await closed.start()
    const base = closed.url
    await closed.close()
    await expectRefused(deps({ apiBase: base }), 'getme_unavailable', 0)
  })
})

describe('owner (F1.5)', () => {
  it('owner unresolved (null) -> owner_unresolved, no Vault read', async () => {
    let tokenReads = 0
    await expectRefused(deps({ resolveOwner: () => null, readToken: () => { tokenReads++; return TOKEN } }), 'owner_unresolved', 0)
    expect(tokenReads).toBe(0)
  })
  it('owner resolver throws -> owner_unresolved', async () => {
    await expectRefused(deps({ resolveOwner: () => { throw new Error('access.json unreadable') } }), 'owner_unresolved', 0)
  })
  for (const bad of ['-1001234567', '0', 'abc', '']) {
    it(`owner ${JSON.stringify(bad)} (group / not a user id) -> owner_unresolved`, async () => {
      await expectRefused(deps({ resolveOwner: () => bad }), 'owner_unresolved', 0)
    })
  }
})

describe('pass', () => {
  it('all gates hold -> ready with an api bound to the pinned bot, still no getUpdates', async () => {
    const d = deps()
    const r = await runStartupGates(d)
    expect(r.kind).toBe('ready')
    if (r.kind !== 'ready') return
    expect(r.botId).toBe(PIN)
    expect(Object.keys(r)).not.toContain('token')
    expect(fake.callsOf('getMe')).toHaveLength(1)
    expect(fake.callsOf('getUpdates')).toHaveLength(0)
    expect((await r.api.getMe()).id).toBe(Number(PIN))
  })
  it('tokenBotId parses only the id before the colon', () => {
    expect(tokenBotId(TOKEN)).toBe(PIN)
    expect(tokenBotId(':abc')).toBeNull()
    expect(tokenBotId('123:')).toBeNull()
    expect(tokenBotId('123:a b')).toBeNull()
    expect(tokenBotId(null)).toBeNull()
  })
})
