// fec6335f N3b: the interactive-key guard on the MAIN agent's in-process launch
// paths -- buildMainSessionRespawnCmd (every respawn-pane sink builds its command
// there) and the settings scan resolveMainConfigDecision() runs for each launch.
// The shell paths (channels.sh, channel-watchdog.sh, stuck-modal-guard.sh, the
// custom-provider helper) are covered by
// scripts/__tests__/channels-interactive-key-guard.test.sh; the shell/TS policy
// parity is checked here.
//
// Nothing real is touched: the policy is pinned per test (no .env is read), the
// settings fixtures, the guard-event file and HOME live in a temp dir, notify is
// injected, and the commands run with a fake claude that records env NAMES only.
// A per-run dummy key is asserted absent from every command, event, alert and
// logger call.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, existsSync, chmodSync, copyFileSync, statSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'
import { randomBytes } from 'node:crypto'
import { buildMainSessionRespawnCmd } from '../web/channel-monitor.js'
import { mainConfigDecisionForTest } from '../web/main-config-decision.js'
import {
  INTERACTIVE_UNSET,
  InteractiveKeyGuardError,
  readInteractiveKeyPolicy,
  setGuardEventsPathForTest,
  setInteractiveKeyPolicyForTest,
  scanSettingsForInteractiveKeys,
  type SettingsFinding,
} from '../web/interactive-key-guard.js'
import {
  mainAgentSettingsPaths,
  reportMainAgentSettingsKeys,
  resetMainSettingsKeyAlertsForTest,
  setOwnerAlertLedgerPathForTest,
  claimMainOwnerAlert,
} from '../web/main-agent-key-guard.js'
import { logger } from '../logger.js'

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const DUMMY = `sk-ant-TEST-DUMMY-${randomBytes(8).toString('hex')}`

let tmp = ''
beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'ikg-main-'))
  setGuardEventsPathForTest(join(tmp, 'events.jsonl'))
  setOwnerAlertLedgerPathForTest(join(tmp, 'store', 'owner-alerts.json'))
  resetMainSettingsKeyAlertsForTest()
})
afterEach(() => {
  setGuardEventsPathForTest(null)
  setOwnerAlertLedgerPathForTest(null)
  setInteractiveKeyPolicyForTest(null)
  vi.restoreAllMocks()
  rmSync(tmp, { recursive: true, force: true })
})

const BASE = {
  claudePath: '/usr/local/bin/claude',
  pluginId: 'telegram@claude-plugins-official',
  model: 'claude-opus-5-5[1m]',
  channelStateEnv: { name: 'TELEGRAM_STATE_DIR', dir: '/opt/m/.claude/channels/telegram' },
  extraPluginIds: ['discord@claude-plugins-official'],
  extraSettingsPath: '/opt/m/store/main-extra-plugins.settings.json',
}
// The four config branches of the builder (own credentials, plan token, plain
// isolated dir with the fleet token, fleet token alone) plus the shared root.
const CONFIGS = {
  ownCredentials: () => mainConfigDecisionForTest({ isolatedConfigDir: '/opt/m/own-cfg', ownCredentials: true }),
  tokenSecretId: () => mainConfigDecisionForTest({ isolatedConfigDir: '/opt/m/.channels-config', tokenSecretId: 'plan-a' }),
  isolated: () => mainConfigDecisionForTest({ isolatedConfigDir: '/opt/m/.channels-config', fleetToken: true }),
  fleetToken: () => mainConfigDecisionForTest({ fleetToken: true }),
  sharedRoot: () => mainConfigDecisionForTest(),
}

describe('buildMainSessionRespawnCmd under INTERACTIVE_ANTHROPIC_KEY_POLICY', () => {
  for (const [branch, config] of Object.entries(CONFIGS)) {
    for (const continueSession of [true, false]) {
      it(`${branch}, continue=${continueSession}: forbid = INTERACTIVE_UNSET + the allow command, byte for byte`, () => {
        const allow = buildMainSessionRespawnCmd({ ...BASE, continueSession, config: config(), keyPolicy: 'allow' })
        const forbid = buildMainSessionRespawnCmd({ ...BASE, continueSession, config: config(), keyPolicy: 'forbid' })
        expect(allow.startsWith('export PATH=')).toBe(true)
        expect(allow).not.toContain('unset ANTHROPIC_API_KEY')
        expect(forbid).toBe(INTERACTIVE_UNSET + allow)
        expect(forbid.startsWith('unset ANTHROPIC_API_KEY ANTHROPIC_AUTH_TOKEN && export PATH=')).toBe(true)
      })
    }
  }

  it('without keyPolicy the dashboard process policy decides (no call site can forget it)', () => {
    setInteractiveKeyPolicyForTest('forbid')
    expect(buildMainSessionRespawnCmd({ ...BASE, continueSession: false, config: CONFIGS.sharedRoot() }).startsWith(INTERACTIVE_UNSET)).toBe(true)
    setInteractiveKeyPolicyForTest('allow')
    expect(buildMainSessionRespawnCmd({ ...BASE, continueSession: false, config: CONFIGS.sharedRoot() })).not.toContain('unset ANTHROPIC')
  })

  it('forbid: a command that would set a key is refused (assertLaunchCmdClean), with a guard event; allow lets the same string through', () => {
    const hostile = `x' && export ANTHROPIC_API_KEY=${DUMMY} && echo '`
    expect(() => buildMainSessionRespawnCmd({ ...BASE, model: hostile, continueSession: false, config: CONFIGS.sharedRoot(), keyPolicy: 'forbid' }))
      .toThrow(InteractiveKeyGuardError)
    const events = readFileSync(join(tmp, 'events.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l))
    expect(events).toHaveLength(1)
    expect(events[0]).toMatchObject({ source: 'main-launch-guard', where: 'buildMainSessionRespawnCmd:launch-cmd', names: ['ANTHROPIC_API_KEY'] })
    expect(readFileSync(join(tmp, 'events.jsonl'), 'utf-8')).not.toContain(DUMMY)
    expect(() => buildMainSessionRespawnCmd({ ...BASE, model: hostile, continueSession: false, config: CONFIGS.sharedRoot(), keyPolicy: 'allow' })).not.toThrow()
  })

  // What the respawned claude actually gets, run the way tmux runs a pane
  // command (default-shell -c), with the tmux server's global env simulated as
  // carrying both keys. zsh is the macOS default shell, bash the Linux one.
  for (const shell of ['/bin/zsh', '/bin/bash']) {
    it.skipIf(!existsSync(shell))(`the forbid command reaches claude without either key (${shell}); the allow one with both, as today`, () => {
      const fake = join(tmp, 'claude')
      const out = join(tmp, 'claude.out')
      writeFileSync(fake, '#!/bin/sh\nprintf "API=%s AUTH=%s" "${ANTHROPIC_API_KEY:+set}" "${ANTHROPIC_AUTH_TOKEN:+set}" > "$FAKE_CLAUDE_OUT"\n')
      chmodSync(fake, 0o755)
      const run = (keyPolicy: 'allow' | 'forbid') => {
        rmSync(out, { force: true })
        const cmd = buildMainSessionRespawnCmd({ ...BASE, claudePath: fake, extraSettingsPath: null, continueSession: false, config: CONFIGS.sharedRoot(), keyPolicy })
        spawnSync(shell, ['-c', cmd], {
          env: { PATH: '/usr/bin:/bin', HOME: tmp, FAKE_CLAUDE_OUT: out, ANTHROPIC_API_KEY: DUMMY, ANTHROPIC_AUTH_TOKEN: DUMMY },
          stdio: 'ignore',
          timeout: 10_000,
        })
        return existsSync(out) ? readFileSync(out, 'utf-8') : 'claude-not-reached'
      }
      expect(run('forbid')).toBe('API= AUTH=')
      expect(run('allow')).toBe('API=set AUTH=set')
    })
  }
})

describe('reportMainAgentSettingsKeys: the main agent starts anyway, loudly (blueprint 12.8)', () => {
  function fixture(): { cfg: string; proj: string; home: string } {
    const cfg = join(tmp, 'cfg')
    const proj = join(tmp, 'proj')
    const home = join(tmp, 'home')
    mkdirSync(cfg, { recursive: true })
    mkdirSync(join(proj, '.claude'), { recursive: true })
    mkdirSync(join(home, '.claude'), { recursive: true })
    writeFileSync(join(cfg, 'settings.json'), JSON.stringify({ env: { ANTHROPIC_API_KEY: DUMMY, OTHER: 'x' }, apiKeyHelper: `echo ${DUMMY}` }))
    writeFileSync(join(proj, '.claude', 'settings.local.json'), `{"env":{"ANTHROPIC_AUTH_TOKEN":"${DUMMY}"}`) // broken JSON on purpose
    writeFileSync(join(home, '.claude', 'settings.json'), JSON.stringify({ apiKeyHelper: 'x' }))
    return { cfg, proj, home }
  }

  it('the paths: the decision\'s config dir (else ~/.claude) and the project scope', () => {
    expect(mainAgentSettingsPaths('/c', '/p', '/h')).toEqual(['/c/settings.json', '/p/.claude/settings.json', '/p/.claude/settings.local.json'])
    expect(mainAgentSettingsPaths(null, '/p', '/h')[0]).toBe('/h/.claude/settings.json')
  })

  it('allow: nothing is read, nothing is written, nobody is alerted', () => {
    const scan = vi.fn(() => [] as SettingsFinding[])
    const notify = vi.fn(async () => {})
    expect(reportMainAgentSettingsKeys('/c', { policy: 'allow', scan, notify })).toEqual([])
    expect(scan).not.toHaveBeenCalled()
    expect(notify).not.toHaveBeenCalled()
    expect(existsSync(join(tmp, 'events.jsonl'))).toBe(false)
  })

  it('forbid: one guard event per file, one alert, names and paths only -- never the value', () => {
    const { cfg, proj, home } = fixture()
    const logSpies = [vi.spyOn(logger, 'error'), vi.spyOn(logger, 'warn'), vi.spyOn(logger, 'info')]
    const notify = vi.fn(async (_t: string) => {})
    const found = reportMainAgentSettingsKeys(cfg, { policy: 'forbid', notify, projectRoot: proj, home, now: () => 1_000 })
    expect(found).toEqual([
      { path: join(cfg, 'settings.json'), names: ['ANTHROPIC_API_KEY', 'apiKeyHelper'] },
      { path: join(proj, '.claude', 'settings.local.json'), names: ['ANTHROPIC_AUTH_TOKEN'] },
    ])
    const events = readFileSync(join(tmp, 'events.jsonl'), 'utf-8').trim().split('\n').map((l) => JSON.parse(l))
    expect(events.map((e) => [e.source, e.where, e.names])).toEqual([
      ['main-launch-guard', join(cfg, 'settings.json'), ['ANTHROPIC_API_KEY', 'apiKeyHelper']],
      ['main-launch-guard', join(proj, '.claude', 'settings.local.json'), ['ANTHROPIC_AUTH_TOKEN']],
    ])
    expect(notify).toHaveBeenCalledTimes(1)
    const text = notify.mock.calls[0][0]
    expect(text).toContain(join(cfg, 'settings.json'))
    expect(text).toContain('apiKeyHelper')
    expect(text).toContain('INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid')
    // the shared ~/.claude is NOT the user scope when the decision has a dir
    expect(text).not.toContain(join(home, '.claude'))
    for (const blob of [readFileSync(join(tmp, 'events.jsonl'), 'utf-8'), text, JSON.stringify(logSpies.map((s) => s.mock.calls))]) {
      expect(blob).not.toContain(DUMMY)
    }
  })

  it('forbid, no config dir: the shared ~/.claude is the user scope', () => {
    const { proj, home } = fixture()
    const found = reportMainAgentSettingsKeys(null, { policy: 'forbid', notify: async () => {}, projectRoot: proj, home })
    expect(found[0]).toEqual({ path: join(home, '.claude', 'settings.json'), names: ['apiKeyHelper'] })
  })

  it('the alert repeats once a day for the same finding, a changed one after the hourly cap; the event is written every time', () => {
    const { cfg, proj, home } = fixture()
    const notify = vi.fn(async (_t: string) => {})
    let now = 0
    const go = () => reportMainAgentSettingsKeys(cfg, { policy: 'forbid', notify, projectRoot: proj, home, now: () => now })
    go(); now += 60_000; go()
    expect(notify).toHaveBeenCalledTimes(1)
    now += 24 * 60 * 60 * 1000; go()
    expect(notify).toHaveBeenCalledTimes(2)
    writeFileSync(join(cfg, 'settings.json'), JSON.stringify({ apiKeyHelper: 'y' }))
    now += 1; go()
    expect(notify).toHaveBeenCalledTimes(2) // inside the hour: capped
    now += 60 * 60 * 1000; go()
    expect(notify).toHaveBeenCalledTimes(3)
    expect(readFileSync(join(tmp, 'events.jsonl'), 'utf-8').trim().split('\n').length).toBe(10)
  })

  it('an unreadable settings file is a finding, not a silent pass', () => {
    const cfg = join(tmp, 'cfg')
    mkdirSync(cfg, { recursive: true })
    const read = (p: string) => {
      if (p === join(cfg, 'settings.json')) throw Object.assign(new Error('EACCES'), { code: 'EACCES' })
      throw Object.assign(new Error('ENOENT'), { code: 'ENOENT' })
    }
    const found = reportMainAgentSettingsKeys(cfg, { policy: 'forbid', notify: async () => {}, scan: (p) => scanSettingsForInteractiveKeys(p, read), projectRoot: tmp, home: tmp })
    expect(found).toEqual([{ path: join(cfg, 'settings.json'), names: ['<unreadable>'] }])
  })

  it('a guard must not be the reason a respawn fails: a throwing scan or a rejecting alert is contained', async () => {
    expect(reportMainAgentSettingsKeys('/c', { policy: 'forbid', scan: () => { throw new Error('boom') } })).toEqual([])
    const { cfg, proj, home } = fixture()
    const warn = vi.spyOn(logger, 'warn')
    reportMainAgentSettingsKeys(cfg, { policy: 'forbid', notify: () => Promise.reject(new Error('telegram down')), projectRoot: proj, home })
    await new Promise((r) => setTimeout(r, 0))
    expect(warn.mock.calls.some((c) => String(c[1]).includes('owner alert not delivered'))).toBe(true)
  })

  it('every in-process respawn runs it: resolveMainConfigDecision() reports the settings before it returns', () => {
    const src = readFileSync(join(ROOT, 'src/web/main-config-decision.ts'), 'utf-8')
    const fn = src.slice(src.indexOf('export function resolveMainConfigDecision(): MainConfigDecision {'))
    const body = fn.slice(0, fn.indexOf('\n}\n'))
    expect(body).toMatch(/noteState\(d\)[\s\S]*reportMainAgentSettingsKeys\(d\.isolatedConfigDir\)\n\s+return d as MainConfigDecision$/)
  })
})

describe('claimMainOwnerAlert: once a day per finding, across a dashboard restart', () => {
  const DAY = 24 * 60 * 60 * 1000
  const T = 1_800_000_000_000
  const HOUR = 60 * 60 * 1000
  const f = (names: string[], source = 'main-launch-guard', agent = 'tmain') => [{ source, agent, names }]
  const F = f(['apiKeyHelper', 'ANTHROPIC_API_KEY'])
  const ledger = () => join(tmp, 'store', 'owner-alerts.json')
  // A dashboard restart = a fresh module: the in-memory map is empty again.
  const restart = () => resetMainSettingsKeyAlertsForTest()

  it('once in 24 hours for the same finding; again at 24 hours; a changed finding after the hourly cap', () => {
    expect(claimMainOwnerAlert(F, T)).toBe(true)
    expect(claimMainOwnerAlert(F, T + 1)).toBe(false)
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY', 'apiKeyHelper']), T + 2)).toBe(false) // name order is not a change
    expect(claimMainOwnerAlert(F, T + DAY - 1)).toBe(false)
    expect(claimMainOwnerAlert(f(['apiKeyHelper']), T + 3)).toBe(false) // a new finding, inside the hour: capped
    expect(claimMainOwnerAlert(f(['apiKeyHelper']), T + HOUR)).toBe(true) // ... and not lost
    expect(claimMainOwnerAlert(F, T + DAY)).toBe(true)
  })

  it('BE-1: the key is (source, agent, names) -- no path or other free text; at most one alert an hour', () => {
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY']), T)).toBe(true)
    // the same source/agent/names, whatever else differed in the event: no new key
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY']), T + 2 * HOUR)).toBe(false)
    // a different source or agent is a different finding, but still waits for the hourly cap
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY'], 'launch-guard'), T + 10 * 60_000)).toBe(false)
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY'], 'launch-guard'), T + HOUR)).toBe(true)
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY'], 'launch-guard', 'other'), T + HOUR + 1)).toBe(false)
    expect(claimMainOwnerAlert(f(['ANTHROPIC_API_KEY'], 'launch-guard', 'other'), T + 2 * HOUR)).toBe(true)
  })

  it('a dashboard restart does not alert the owner again inside the day (the ledger is a file)', () => {
    expect(claimMainOwnerAlert(F, T)).toBe(true)
    restart()
    expect(claimMainOwnerAlert(F, T + 60_000)).toBe(false)
    restart()
    expect(claimMainOwnerAlert(F, T + DAY)).toBe(true)
  })

  it('the ledger file is 0600, names and ids only, and drops entries older than a day', () => {
    claimMainOwnerAlert(f(['apiKeyHelper'], 'launch-guard'), T)
    claimMainOwnerAlert(F, T + DAY + 5)
    expect(statSync(ledger()).mode & 0o777).toBe(0o600)
    const j = JSON.parse(readFileSync(ledger(), 'utf-8'))
    expect(j.v).toBe(1)
    expect(Object.keys(j.alerts).sort()).toEqual([JSON.stringify(['main-launch-guard', 'tmain', ['ANTHROPIC_API_KEY', 'apiKeyHelper']]), '__any__'].sort())
    expect(readdirSync(join(tmp, 'store'))).toEqual(['owner-alerts.json']) // no tmp file left behind
  })

  it('an unreadable ledger degrades to the per-process dedupe, not to an alert on every launch', () => {
    mkdirSync(join(tmp, 'store'), { recursive: true })
    writeFileSync(ledger(), '{not json')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    expect(claimMainOwnerAlert(F, T)).toBe(true)
    expect(claimMainOwnerAlert(F, T + 1)).toBe(false)
    expect(JSON.parse(readFileSync(ledger(), 'utf-8')).alerts).toBeTruthy() // rewritten clean
    expect(warn.mock.calls.some((c) => String(c[1]).includes('owner-alert ledger unreadable'))).toBe(true)
  })

  it('a ledger that cannot be written still alerts, once per process', () => {
    setOwnerAlertLedgerPathForTest(join(tmp, 'is-a-file', 'owner-alerts.json'))
    writeFileSync(join(tmp, 'is-a-file'), 'x')
    const warn = vi.spyOn(logger, 'warn').mockImplementation(() => undefined as never)
    expect(claimMainOwnerAlert(F, T)).toBe(true)
    expect(claimMainOwnerAlert(F, T + 1)).toBe(false)
    expect(warn.mock.calls.some((c) => String(c[1]).includes('owner-alert ledger not saved'))).toBe(true)
  })

  it('reportMainAgentSettingsKeys: one owner alert across a restart, a guard event on every launch', async () => {
    const cfg = join(tmp, 'cfg')
    mkdirSync(cfg, { recursive: true })
    writeFileSync(join(cfg, 'settings.json'), JSON.stringify({ apiKeyHelper: 'x' }))
    const notify = vi.fn(async (_t: string) => {})
    const opts = { policy: 'forbid' as const, notify, projectRoot: join(tmp, 'noproj'), home: join(tmp, 'nohome') }
    reportMainAgentSettingsKeys(cfg, { ...opts, now: () => T })
    restart()
    reportMainAgentSettingsKeys(cfg, { ...opts, now: () => T + 6 * 60_000 })
    expect(notify).toHaveBeenCalledTimes(1)
    expect(readFileSync(join(tmp, 'events.jsonl'), 'utf-8').trim().split('\n')).toHaveLength(2)
  })
})

// The BE-1 cases, each with the answer BOTH readers must give: a line that names
// the key but is not a plain `KEY=value` line, or a value with anything but ASCII
// whitespace around it, is forbid (fail-closed), never a silent allow.
const UNICODE_CASES: Record<string, string> = {
  'BOM + forbid on line 1': '\ufeffINTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\nFOO=1',
  'BOM + allow on line 1': '\ufeffINTERACTIVE_ANTHROPIC_KEY_POLICY=allow',
  'NBSP before the key': '\u00a0INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
  'NBSP before =': 'INTERACTIVE_ANTHROPIC_KEY_POLICY\u00a0=forbid',
  'U+2028 before the key': '\u2028INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
  'NBSP after allow': 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\u00a0',
  'NBSP-indented allow': '\u00a0INTERACTIVE_ANTHROPIC_KEY_POLICY=allow',
  'export prefix': 'export INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
  'valid allow, then a mangled line': 'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\nexport INTERACTIVE_ANTHROPIC_KEY_POLICY=allow',
}
const UNICODE_WANT: Record<string, 'allow' | 'forbid'> = {
  'BOM + forbid on line 1': 'forbid',
  'BOM + allow on line 1': 'allow',
  'NBSP before the key': 'forbid',
  'NBSP before =': 'forbid',
  'U+2028 before the key': 'forbid',
  'NBSP after allow': 'forbid',
  'NBSP-indented allow': 'forbid',
  'export prefix': 'forbid',
  'valid allow, then a mangled line': 'forbid',
}

describe('the policy is read the same way by the dashboard and by the shell launchers', () => {
  const CASES = [
    '',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY="allow"',
    "INTERACTIVE_ANTHROPIC_KEY_POLICY='allow'",
    'INTERACTIVE_ANTHROPIC_KEY_POLICY="allow',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY="',
    '  INTERACTIVE_ANTHROPIC_KEY_POLICY = allow \r',
    '# INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=Allow',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow\nINTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\nINTERACTIVE_ANTHROPIC_KEY_POLICY=allow',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY_X=forbid',
    'X_INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow=1',
    // Whitespace INSIDE the quotes: policyFromValue() trims again after the
    // quote pair is stripped, so the shell readers must too (review finding:
    // `" allow "` was forbid in the shell and allow in TS).
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=" allow "',
    "INTERACTIVE_ANTHROPIC_KEY_POLICY=' allow'",
    'INTERACTIVE_ANTHROPIC_KEY_POLICY="allow\t"',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY = "  allow  " \r',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=" "',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=" forbid "',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY="\tallow\t"\r',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=\'allow"',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=""allow""',
    '\tINTERACTIVE_ANTHROPIC_KEY_POLICY\t=\tallow',
    'INTERACTIVE_ANTHROPIC_KEY_POLICY=allow # comment',
    // BE-1 review (proof parity/run.sh): Unicode around the key or the value.
    // JS String.trim() strips these, sed's [[:space:]] in the C locale does
    // not, so the two readers split -- partly in the fail-OPEN direction.
    ...Object.values(UNICODE_CASES),
  ]
  // The three shell copies of the reader: channels.sh through its seam, and the
  // byte-identical functions of watchdog.sh and morning-briefing.sh cut out and
  // run on their own (they read $INSTALL_DIR/.env).
  function shellFunction(script: string): string {
    const src = readFileSync(join(ROOT, 'scripts', script), 'utf-8')
    const start = src.indexOf('interactive_key_policy() {')
    expect(start, `${script}: interactive_key_policy not found`).toBeGreaterThan(-1)
    return src.slice(start, src.indexOf('\n}\n', start) + 3)
  }
  it.each(['watchdog.sh', 'morning-briefing.sh'])('%s carries the same reader as channels.sh, byte for byte', (script) => {
    expect(shellFunction(script)).toBe(shellFunction('channels.sh'))
  })
  // The shell readers run in the C locale (a launchd/systemd job has no LANG)
  // and in a UTF-8 one: the answer must not depend on it.
  const LOCALES: Record<string, Record<string, string>> = { C: {}, 'UTF-8': { LANG: 'en_US.UTF-8', LC_ALL: 'en_US.UTF-8' } }
  function shellPolicies(text: string): Record<string, string> {
    const out: Record<string, string> = {}
    const root = join(tmp, 'install')
    mkdirSync(join(root, 'scripts'), { recursive: true })
    copyFileSync(join(ROOT, 'scripts', 'channels.sh'), join(root, 'scripts', 'channels.sh'))
    writeFileSync(join(root, '.env'), text + '\n')
    for (const [loc, extra] of Object.entries(LOCALES)) {
      const base = { PATH: '/usr/bin:/bin', HOME: tmp, ...extra }
      const ch = spawnSync('/bin/bash', [join(root, 'scripts', 'channels.sh'), '--interactive-key-policy'], { encoding: 'utf-8', env: base, timeout: 10_000 })
      out[`channels.sh/${loc}`] = ch.status === 0 ? ch.stdout.trim() : `exit ${ch.status}`
      for (const script of ['watchdog.sh', 'morning-briefing.sh']) {
        const r = spawnSync('/bin/bash', ['-c', `${shellFunction(script)}\ninteractive_key_policy`], { encoding: 'utf-8', env: { ...base, INSTALL_DIR: root }, timeout: 10_000 })
        out[`${script}/${loc}`] = r.status === 0 ? r.stdout.trim() : `exit ${r.status}`
      }
    }
    return out
  }
  const every = (v: string) => Object.fromEntries(Object.keys(shellPolicies('')).map((k) => [k, v]))
  it.each(CASES)('%j: TS readInteractiveKeyPolicy = all three shell readers, C and UTF-8 locale', (text) => {
    expect(shellPolicies(text)).toEqual(every(readInteractiveKeyPolicy(text + '\n')))
  })
  it.each(Object.keys(UNICODE_CASES))('BE-1 %s: TS and every shell reader give the fail-closed answer', (name) => {
    const text = UNICODE_CASES[name] as string
    expect(readInteractiveKeyPolicy(text + '\n')).toBe(UNICODE_WANT[name])
    expect(shellPolicies(text)).toEqual(every(UNICODE_WANT[name] as string))
  })
})
