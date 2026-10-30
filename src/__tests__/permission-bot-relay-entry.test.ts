// Entry point, status command and installer of the permission-bot relay (card d7f586bf N3).
//
// - main-bot id list: only digits, both sources kept, malformed skipped
// - --status: reads the status file only (loopback guard proves no socket), warns on a stale pid
// - TELEGRAM_USER_ID_RE in startup.ts is pinned to the dashboard's original
// - installer, run in a throwaway project + HOME with a fake `launchctl` on PATH:
//   plist label / KeepAlive / ProgramArguments without a token, no launchctl call
//   by default, --load and --uninstall call it, a missing build refuses
// Fake tokens only; no network, no Keychain, no real launchctl.
import { describe, it, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest'
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { spawnSync } from 'node:child_process'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  EXIT_NO_STATUS, formatStatus, mainBotIdsFromTokens, parseRelayArgs, runStatusCommand,
} from '../permission-bot-relay.js'
import { StatusFile, relayPaths, type RelayStatus } from '../permission-bot-relay/offset-store.js'
import { TELEGRAM_USER_ID_RE } from '../permission-bot-relay/startup.js'
import { installLoopbackGuard, selfTestLoopbackGuard, type LoopbackGuard } from './helpers/loopback-guard.js'

const HERE = dirname(fileURLToPath(import.meta.url))
const REPO = join(HERE, '..', '..')

const MAIN_ID = '777777777'
const MAIN_TOKEN = `${MAIN_ID}:FAKEmainBotSECRETforEntryTests_0123456789`
const CHANNEL_ID = '888888888'
const CHANNEL_TOKEN = `${CHANNEL_ID}:FAKEchannelSECRETforEntryTests_abcdefghij`

let dir: string
beforeEach(() => { dir = mkdtempSync(join(tmpdir(), 'pbr-entry-')) })
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

describe('mainBotIdsFromTokens', () => {
  it('returns only the digits before the colon, never the secret part', () => {
    const ids = mainBotIdsFromTokens([MAIN_TOKEN])
    expect(ids).toEqual([MAIN_ID])
    expect(JSON.stringify(ids)).not.toContain('FAKEmainBotSECRET')
  })

  it('keeps two different ids and collapses duplicates', () => {
    expect(mainBotIdsFromTokens([MAIN_TOKEN, CHANNEL_TOKEN, MAIN_TOKEN])).toEqual([MAIN_ID, CHANNEL_ID])
  })

  it('skips missing and malformed tokens; nothing resolvable gives an empty list (fail-closed upstream)', () => {
    expect(mainBotIdsFromTokens([null, undefined, '', 'nocolon', ':abc', '0123:abc', 'abc:def'])).toEqual([])
    expect(mainBotIdsFromTokens([null, MAIN_TOKEN])).toEqual([MAIN_ID])
  })
})

describe('parseRelayArgs', () => {
  it('maps the command line', () => {
    expect(parseRelayArgs([])).toEqual({ kind: 'run' })
    expect(parseRelayArgs(['--status'])).toEqual({ kind: 'status' })
    expect(parseRelayArgs(['--status', 'x'])).toEqual({ kind: 'bad', arg: '--status' })
    expect(parseRelayArgs(['--load'])).toEqual({ kind: 'bad', arg: '--load' })
  })
})

describe('--status', () => {
  let guard: LoopbackGuard
  beforeAll(async () => {
    guard = installLoopbackGuard()
    await selfTestLoopbackGuard(guard)
  })
  afterAll(() => { guard.uninstall() })

  it('prints the status file without touching the network', () => {
    const paths = relayPaths(dir)
    const status = new StatusFile(paths.status)
    status.setState('polling', null)
    status.pollOk()
    status.bump('processed', 2)
    status.bump('dropped')
    const before = guard.blocked.length
    const out: string[] = []
    const rc = runStatusCommand(paths.status, (l) => out.push(l), () => true)
    expect(rc).toBe(0)
    expect(out[0]).toBe('state: polling')
    expect(out.join('\n')).toContain('processed=2')
    expect(out.join('\n')).toContain('dropped=1')
    expect(out.join('\n')).toContain('(running)')
    expect(out.join('\n')).not.toContain('WARNING')
    expect(guard.blocked.length).toBe(before)
  })

  it('shows a refusal reason by code', () => {
    const paths = relayPaths(dir)
    new StatusFile(paths.status).setState('refused', 'main_bot_unresolved')
    const out: string[] = []
    expect(runStatusCommand(paths.status, (l) => out.push(l), () => true)).toBe(0)
    expect(out[0]).toBe('state: refused (main_bot_unresolved)')
  })

  it('warns when the recorded process is gone', () => {
    const paths = relayPaths(dir)
    new StatusFile(paths.status).setState('polling', null)
    const out: string[] = []
    runStatusCommand(paths.status, (l) => out.push(l), () => false)
    expect(out.join('\n')).toContain('not running')
    expect(out.join('\n')).toContain('WARNING')
  })

  it('does not warn for a stopped relay whose process is gone', () => {
    const paths = relayPaths(dir)
    new StatusFile(paths.status).setState('stopped', null)
    const out: string[] = []
    runStatusCommand(paths.status, (l) => out.push(l), () => false)
    expect(out.join('\n')).not.toContain('WARNING')
  })

  it('missing or unreadable status file: exit code 1 and a plain line', () => {
    const out: string[] = []
    expect(runStatusCommand(join(dir, 'nope.json'), (l) => out.push(l))).toBe(EXIT_NO_STATUS)
    expect(out[0]).toMatch(/^state: unknown/)
    writeFileSync(join(dir, 'bad.json'), '{not json')
    expect(runStatusCommand(join(dir, 'bad.json'), (l) => out.push(l))).toBe(EXIT_NO_STATUS)
  })

  it('formatStatus carries only code and counter fields', () => {
    const s: RelayStatus = {
      v: 1, state: 'degraded', reason: 'api_transient', last_poll_ok_at: null,
      counters: { processed: 0, rejected: 1, ignored: 2, dropped: 3, errors: 4 }, pid: 4242, updated_at: '2026-10-30T10:00:00.000Z',
    }
    expect(formatStatus(s, true)).toEqual([
      'state: degraded (api_transient)',
      'last_poll_ok_at: never',
      'updated_at: 2026-10-30T10:00:00.000Z',
      'pid: 4242 (running)',
      'counters: processed=0 rejected=1 ignored=2 dropped=3 errors=4',
    ])
  })
})

describe('TELEGRAM_USER_ID_RE pin', () => {
  it('equals the dashboard route original (approvals.ts), copied not imported', () => {
    const src = readFileSync(join(REPO, 'src', 'web', 'routes', 'approvals.ts'), 'utf8')
    const m = /^const TELEGRAM_USER_ID_RE = \/(.+)\/$/m.exec(src)
    expect(m, 'original TELEGRAM_USER_ID_RE not found in approvals.ts').not.toBeNull()
    expect(TELEGRAM_USER_ID_RE.source).toBe(m![1])
    expect(TELEGRAM_USER_ID_RE.flags).toBe('')
  })
})

describe('install-permission-bot-relay.sh', () => {
  const FAKE_ENV_TOKEN = '555555555:FAKEenvTokenSECRETforInstallerTest_zzzz'
  let project: string
  let home: string
  let binDir: string
  let argvLog: string

  beforeEach(() => {
    project = join(dir, 'project')
    home = join(dir, 'home')
    binDir = join(dir, 'bin')
    argvLog = join(dir, 'launchctl-argv.log')
    mkdirSync(join(project, 'scripts'), { recursive: true })
    mkdirSync(join(project, 'dist'), { recursive: true })
    mkdirSync(home, { recursive: true })
    mkdirSync(binDir, { recursive: true })
    for (const f of ['install-permission-bot-relay.sh', 'launchd-label.sh']) {
      copyFileSync(join(REPO, 'scripts', f), join(project, 'scripts', f))
    }
    writeFileSync(join(project, 'dist', 'permission-bot-relay.js'), '// stub build artifact\n')
    writeFileSync(join(project, '.env'), `SERVICE_ID=testsvc\nTELEGRAM_BOT_TOKEN=${FAKE_ENV_TOKEN}\n`)
    // Fake launchctl: records its argv, does nothing else.
    const fake = join(binDir, 'launchctl')
    writeFileSync(fake, `#!/bin/bash\nprintf '%s\\n' "$*" >> '${argvLog}'\nexit 0\n`)
    chmodSync(fake, 0o755)
  })

  function run(args: string[], extraEnv: Record<string, string> = {}): { rc: number | null; out: string } {
    const r = spawnSync('bash', [join(project, 'scripts', 'install-permission-bot-relay.sh'), ...args], {
      env: { PATH: `${binDir}:${process.env['PATH'] ?? '/usr/bin:/bin'}`, HOME: home, TELEGRAM_BOT_TOKEN: FAKE_ENV_TOKEN, ...extraEnv },
      encoding: 'utf8',
    })
    return { rc: r.status, out: `${r.stdout}${r.stderr}` }
  }

  const plistPath = (): string => join(home, 'Library', 'LaunchAgents', 'com.testsvc.permission-bot-relay.plist')
  const launchctlCalls = (): string[] => (existsSync(argvLog) ? readFileSync(argvLog, 'utf8').split('\n').filter(Boolean) : [])

  it('--print-label gives com.<SERVICE_ID>.permission-bot-relay and writes nothing', () => {
    const r = run(['--print-label'])
    expect(r.rc).toBe(0)
    expect(r.out.trim()).toBe('com.testsvc.permission-bot-relay')
    expect(existsSync(plistPath())).toBe(false)
  })

  it('default run: plist with the label, KeepAlive and a token-free command line; no launchctl call', () => {
    const r = run([])
    expect(r.rc, r.out).toBe(0)
    expect(r.out).toContain('NOT loaded')
    const plist = readFileSync(plistPath(), 'utf8')
    expect(plist).toContain('<string>com.testsvc.permission-bot-relay</string>')
    expect(plist).toMatch(/<key>KeepAlive<\/key>\s*<true\/>/)
    const args = /<key>ProgramArguments<\/key>\s*<array>([\s\S]*?)<\/array>/.exec(plist)![1]!
    const strings = [...args.matchAll(/<string>(.*?)<\/string>/g)].map((m) => m[1])
    expect(strings).toHaveLength(2)
    expect(strings[1]).toBe(join(project, 'dist', 'permission-bot-relay.js'))
    // No token anywhere: not the env token, not its secret part, no token-like env key.
    expect(plist).not.toContain(FAKE_ENV_TOKEN)
    expect(plist).not.toContain('FAKEenvTokenSECRET')
    expect(plist).not.toMatch(/TOKEN/i)
    expect(r.out).not.toContain('FAKEenvTokenSECRET')
    // The Vault is the only token source; the plist does not carry the bot id either.
    expect(plist).not.toContain('PERMISSION_BOT_ID')
    expect(launchctlCalls()).toEqual([])
  })

  it('passes the main channel state dir through when it is known, and omits it otherwise', () => {
    run([])
    expect(readFileSync(plistPath(), 'utf8')).not.toContain('TELEGRAM_STATE_DIR')
    const stateDir = join(project, '.claude', 'channels', 'telegram')
    mkdirSync(stateDir, { recursive: true })
    writeFileSync(join(stateDir, '.env'), `TELEGRAM_BOT_TOKEN=${FAKE_ENV_TOKEN}\n`)
    const r = run([])
    expect(r.rc, r.out).toBe(0)
    const plist = readFileSync(plistPath(), 'utf8')
    expect(plist).toContain('<key>TELEGRAM_STATE_DIR</key>')
    expect(plist).toContain(`<string>${stateDir}</string>`)
    expect(plist).not.toContain('FAKEenvTokenSECRET')
  })

  it('--load calls launchctl load on the plist', () => {
    const r = run(['--load'])
    expect(r.rc, r.out).toBe(0)
    expect(launchctlCalls()).toContain(`load ${plistPath()}`)
  })

  it('--uninstall unloads and removes the plist; running it twice is harmless', () => {
    expect(run([]).rc).toBe(0)
    expect(existsSync(plistPath())).toBe(true)
    const r = run(['--uninstall'])
    expect(r.rc, r.out).toBe(0)
    expect(existsSync(plistPath())).toBe(false)
    expect(launchctlCalls().length).toBeGreaterThan(0)
    expect(run(['--uninstall']).rc).toBe(0)
  })

  it('refuses without a build artifact and writes no plist', () => {
    rmSync(join(project, 'dist'), { recursive: true, force: true })
    const r = run([])
    expect(r.rc).toBe(1)
    expect(r.out).toContain('npm run build')
    expect(existsSync(plistPath())).toBe(false)
    expect(launchctlCalls()).toEqual([])
  })

  it('rejects an unknown option', () => {
    const r = run(['--bogus'])
    expect(r.rc).toBe(64)
    expect(existsSync(plistPath())).toBe(false)
  })
})
