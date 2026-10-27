// fec6335f: channels.sh refuses the main agent (forbid + an Anthropic customProvider,
// the helper's exit 3) and holds the refusal behind store/.channels-key-guard-refused
// (its side: scripts/__tests__/channels-interactive-key-guard.test.sh). This is the
// dashboard's side of that marker.
//
// BE-1 review: the marker is written by channels.sh, but any same-uid process can
// write the store. It may only count under forbid, as a regular file of our own
// uid, with no future time, and while the decision's inputs hash the same BY
// CONTENT -- and it may never make the dashboard skip starting channels.sh.
//
// Nothing real is spawned or sent: spawn is a recorder, sendRoutineAlert and
// notifyChannel are spies, the marker and the inputs live in a temp dir, and the
// respawn stamp write is swallowed (it would land in the checkout's store/).
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, utimesSync, writeFileSync, readFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { spawnSync } from 'node:child_process'

const spawned: string[][] = []
vi.mock('node:child_process', async (orig) => {
  const actual = await orig<typeof import('node:child_process')>()
  return {
    ...actual,
    spawn: vi.fn((file: string, args: readonly string[]) => {
      spawned.push([file, ...args])
      return { unref() {} }
    }),
  }
})
vi.mock('node:fs', async (orig) => {
  const actual = await orig<typeof import('node:fs')>()
  return {
    ...actual,
    writeFileSync: ((path: unknown, ...rest: unknown[]) => {
      if (String(path).endsWith('.channel-last-respawn')) return
      return (actual.writeFileSync as (...a: unknown[]) => void)(path, ...rest)
    }) as typeof actual.writeFileSync,
  }
})
const routine: string[] = []
vi.mock('../web/routine-alert.js', () => ({
  sendRoutineAlert: vi.fn((key: string) => { routine.push(key); return true }),
}))
const owner: string[] = []
vi.mock('../notify.js', () => ({
  notifyChannel: vi.fn(async (t: string) => { owner.push(t) }),
}))

const { createMainChannelsSession } = await import('../web/channel-monitor.js')
const K = await import('../web/main-agent-key-guard.js')
const G = await import('../web/interactive-key-guard.js')

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..')
const MIN = 60_000
let tmp = ''
let marker = ''
let inputs: string[] = []
const realNow = Date.now()
const past = new Date(realNow - 3600_000)

function writeMarker(atS: number, hash = K.keyGuardInputsHash(inputs) as string, mtime: Date = past): void {
  writeFileSync(marker, `${atS} ${hash}\n`)
  utimesSync(marker, mtime, mtime)
}

beforeEach(() => {
  tmp = mkdtempSync(join(tmpdir(), 'ikg-hold-'))
  mkdirSync(join(tmp, 'store'), { recursive: true })
  mkdirSync(join(tmp, 'agents', 'tmain'), { recursive: true })
  marker = join(tmp, 'store', '.channels-key-guard-refused')
  inputs = [join(tmp, '.env'), join(tmp, 'agents', 'tmain', 'agent-config.json'), join(tmp, 'store', 'custom-providers.json'), join(tmp, 'absent.js')]
  writeFileSync(inputs[0] as string, 'INTERACTIVE_ANTHROPIC_KEY_POLICY=forbid\n')
  writeFileSync(inputs[1] as string, '{"customProvider":"anth"}\n')
  writeFileSync(inputs[2] as string, '{"providers":[]}\n')
  K.setKeyGuardRefusalPathsForTest({ marker, inputs })
  K.setOwnerAlertLedgerPathForTest(join(tmp, 'store', 'owner-alerts.json'))
  K.resetMainSettingsKeyAlertsForTest()
  G.setInteractiveKeyPolicyForTest('forbid')
  spawned.length = 0
  routine.length = 0
  owner.length = 0
})
afterEach(() => {
  K.setKeyGuardRefusalPathsForTest(null)
  K.setOwnerAlertLedgerPathForTest(null)
  G.setInteractiveKeyPolicyForTest(null)
  vi.restoreAllMocks()
  rmSync(tmp, { recursive: true, force: true })
})

describe('mainKeyGuardRefusal: when the channels.sh marker counts (BE-1)', () => {
  const nowMs = realNow
  const nowS = Math.floor(nowMs / 1000)
  it('a well-formed marker of our own, under forbid, inputs unchanged: a refusal (held inside 300 s)', () => {
    writeMarker(nowS - 10)
    expect(K.mainKeyGuardRefusal(nowMs)).toEqual({ ageS: 10, held: true })
    writeMarker(nowS - 300)
    expect(K.mainKeyGuardRefusal(nowMs)).toEqual({ ageS: 300, held: false })
  })
  it('allow: the marker has no effect at all', () => {
    writeMarker(nowS - 10)
    expect(K.mainKeyGuardRefusal(nowMs, { policy: 'allow' })).toBeNull()
  })
  it('an mtime in the future is ignored (it used to defeat the "input changed" release)', () => {
    writeMarker(nowS - 10, undefined, new Date(nowMs + 3600_000))
    expect(K.mainKeyGuardRefusal(nowMs)).toBeNull()
  })
  it('a time in the future is ignored', () => {
    writeMarker(nowS + 60)
    expect(K.mainKeyGuardRefusal(nowMs)).toBeNull()
  })
  it('a changed input releases it -- by CONTENT, even with the old mtime put back', () => {
    writeMarker(nowS - 10)
    writeFileSync(inputs[1] as string, '{"customProvider":"litellm"}\n')
    utimesSync(inputs[1] as string, past, past)
    expect(K.mainKeyGuardRefusal(nowMs)).toBeNull()
  })
  it('a marker that is a symlink is ignored, even to a valid marker', () => {
    const real = join(tmp, 'elsewhere')
    writeFileSync(real, `${nowS - 10} ${K.keyGuardInputsHash(inputs)}\n`)
    utimesSync(real, past, past)
    symlinkSync(real, marker)
    expect(K.mainKeyGuardRefusal(nowMs)).toBeNull()
  })
  it('a marker owned by another uid is ignored', () => {
    writeMarker(nowS - 10)
    expect(K.mainKeyGuardRefusal(nowMs, { uid: (process.getuid?.() ?? 0) + 1 })).toBeNull()
  })
  it('the old epoch-only format, garbage and a wrong hash are ignored', () => {
    for (const text of [`${nowS - 10}\n`, 'garbage\n', `${nowS - 10} ${'0'.repeat(64)}\n`]) {
      writeFileSync(marker, text)
      utimesSync(marker, past, past)
      expect(K.mainKeyGuardRefusal(nowMs), text).toBeNull()
    }
  })
  it('the TS input hash is the one channels.sh writes (_kg_inputs_hash cut out of channels.sh)', () => {
    const src = readFileSync(join(ROOT, 'scripts', 'channels.sh'), 'utf-8')
    const fn = (name: string) => src.slice(src.indexOf(`    ${name}() {`), src.indexOf('\n    }\n', src.indexOf(`    ${name}() {`)) + 7)
    const script = `${fn('_kg_sha')}\n${fn('_kg_inputs_hash')}\n_kg_inputs_hash`
    const r = spawnSync('/bin/bash', ['-c', script], {
      encoding: 'utf-8',
      // the same four paths, laid out the way channels.sh builds them
      env: { PATH: '/usr/bin:/bin', INSTALL_DIR: tmp, MAIN_AGENT_ID: 'tmain' },
    })
    expect(r.status).toBe(0)
    const shellInputs = [join(tmp, '.env'), join(tmp, 'agents', 'tmain', 'agent-config.json'), join(tmp, 'store', 'custom-providers.json'), join(tmp, 'dist', 'web', 'interactive-key-guard.js')]
    expect(r.stdout).toMatch(/^[0-9a-f]{64}$/)
    expect(r.stdout).toBe(K.keyGuardInputsHash(shellInputs))
  })
})

describe('keyGuardRefusalStands: a held refusal, or one the previous channels.sh start would have renewed', () => {
  const HOLD = 300
  const nowMs = 1_000_000_000_000
  it('held: always stands, with or without a previous start', () => {
    expect(K.keyGuardRefusalStands({ ageS: 10, held: true }, nowMs, 0)).toBe(true)
    expect(K.keyGuardRefusalStands({ ageS: 10, held: true }, nowMs, nowMs - 3600_000)).toBe(true)
  })
  it('past the hold with no previous start in this process: does not stand', () => {
    expect(K.keyGuardRefusalStands({ ageS: HOLD, held: false }, nowMs, 0)).toBe(false)
  })
  it('past the hold: stands while younger than the hold measured back from the previous start', () => {
    expect(K.keyGuardRefusalStands({ ageS: HOLD + 360, held: false }, nowMs, nowMs - 361_000)).toBe(true)
    expect(K.keyGuardRefusalStands({ ageS: HOLD + 361, held: false }, nowMs, nowMs - 361_000)).toBe(false)
    expect(K.keyGuardRefusalStands({ ageS: 10 * 24 * 3600, held: false }, nowMs, nowMs - 361_000)).toBe(false)
  })
  it('a previous start in the future (clock went backwards) counts as no time passed', () => {
    expect(K.keyGuardRefusalStands({ ageS: HOLD + 1, held: false }, nowMs, nowMs + 3600_000)).toBe(false)
  })
})

describe('createMainChannelsSession with a channels.sh key-guard refusal', () => {
  it('channels.sh is started every time (the decision is never skipped); no "session gone" alert; the owner hears once a day', () => {
    let now = realNow
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    writeMarker(Math.floor(now / 1000) - 10)
    let started = 0
    for (let i = 0; i < 240; i++) { // a day of 6-minute grace windows
      if (createMainChannelsSession() === 'started') started++
      // what the channels.sh just started does with a standing refusal: past the
      // hold it rewrites the marker (inside it, it stays quiet). No launchd here,
      // so every check sees the marker just past its hold.
      const nowS = Math.floor(now / 1000)
      if (nowS - Number(readFileSync(marker, 'utf-8').split(' ')[0]) >= K.KEY_GUARD_REFUSAL_HOLD_S) writeMarker(nowS)
      now += 6 * MIN + 1_000
    }
    expect(started).toBe(240)
    expect(spawned).toHaveLength(240)
    expect(routine).toEqual([])
    expect(owner).toHaveLength(1)
    expect(owner[0]).toContain('nem indul')
    now += 24 * 60 * MIN
    createMainChannelsSession()
    expect(owner).toHaveLength(2)
  })

  it('allow: a marker changes nothing -- the "session gone" alert as before', () => {
    G.setInteractiveKeyPolicyForTest('allow')
    let now = realNow + 100 * 24 * 60 * MIN
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    writeMarker(Math.floor(now / 1000) - 10)
    expect(createMainChannelsSession()).toBe('started')
    expect(routine).toEqual(['main-session-recreate'])
    expect(owner).toEqual([])
  })

  it('a forged marker (future mtime, or a stale input hash) changes nothing either', () => {
    let now = realNow + 200 * 24 * 60 * MIN
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    writeMarker(Math.floor(now / 1000) - 10, undefined, new Date(now + 3600_000))
    expect(createMainChannelsSession()).toBe('started')
    now += 7 * MIN
    writeMarker(Math.floor(now / 1000) - 10, 'f'.repeat(64))
    expect(createMainChannelsSession()).toBe('started')
    expect(routine).toEqual(['main-session-recreate', 'main-session-recreate'])
    expect(owner).toEqual([])
  })

  it('a stale marker (channels.sh exited before the helper, so nothing rewrote or removed it) stops suppressing the "session gone" alert within two grace windows', () => {
    let now = realNow + 300 * 24 * 60 * MIN
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    writeMarker(Math.floor(now / 1000) - 10)
    const seen: number[] = []
    for (let i = 0; i < 5; i++) {
      expect(createMainChannelsSession()).toBe('started')
      seen.push(routine.length)
      now += 6 * MIN + 1_000
    }
    // 1st: held; 2nd: the previous start may still have sat inside the hold; from the 3rd on: gone
    expect(seen).toEqual([0, 0, 1, 2, 3])
    expect(spawned).toHaveLength(5)
  })

  it('the owner alert says it rests on the marker, names the marker\'s path, and how to tell a forged one (a same-uid writer can rehash it)', () => {
    // Its own day, after the tests above: the channel monitor keeps a respawn grace across calls.
    const now = realNow + 400 * 24 * 60 * MIN
    vi.spyOn(Date, 'now').mockImplementation(() => now)
    writeMarker(Math.floor(now / 1000) - 10)
    createMainChannelsSession()
    expect(owner).toHaveLength(1)
    expect(owner[0]).toContain(`jelolo alapjan (${marker})`)
    expect(owner[0]).toContain('channels-failures.log')
    expect(owner[0]).toContain('eltunt')
    expect(K.mainSessionHeldAlertText()).toContain(marker)
  })
})
