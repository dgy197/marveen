// Single-instance lock of the permission-bot relay (card d7f586bf, spec F2.1-F2.2).
// Network-free: no socket is opened in this file. Process identity comes from an
// injected probe (the default /bin/ps probe is EPERM under the test sandbox);
// one test exercises the default probe and accepts either outcome.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { spawn, spawnSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync, utimesSync, writeFileSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { acquireRelayLock } from '../permission-bot-relay/lock.js'
import {
  defaultProcessProbe,
  fingerprintCommand,
  isPidAlive,
  parsePsLine,
  type ProcessIdentity,
  type ProcessProbe,
} from '../permission-bot-relay/process-identity.js'

const ROOT = fileURLToPath(new URL('../../', import.meta.url))
const TSX = join(ROOT, 'node_modules/.bin/tsx')
const CHILD = join(ROOT, 'src/__tests__/helpers/permission-bot-relay-lock-child.ts')

// Deterministic identities; overrides let a test fake a recycled pid.
function fakeProbe(overrides: Map<number, ProcessIdentity | null> = new Map()): ProcessProbe {
  return {
    isAlive: isPidAlive,
    identity(pid) {
      if (overrides.has(pid)) return overrides.get(pid) ?? null
      return { start: `start-${pid}`, cmdSha256: fingerprintCommand(`cmd-${pid}`) }
    },
  }
}

function deadPid(): number {
  const r = spawnSync(process.execPath, ['-e', '0'])
  expect(r.pid).toBeGreaterThan(0)
  expect(isPidAlive(r.pid)).toBe(false)
  return r.pid
}

function writeRecord(path: string, pid: number, start: string, cmd: string): string {
  const raw = JSON.stringify({ v: 1, pid, start, cmd_sha256: fingerprintCommand(cmd), nonce: 'f'.repeat(32), created_at: new Date(0).toISOString() }) + '\n'
  writeFileSync(path, raw, { mode: 0o600 })
  return raw
}

let dir: string
let lockPath: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pbr-lock-'))
  lockPath = join(dir, 'permission-bot-relay.lock')
})
afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('acquireRelayLock: basic', () => {
  it('creates a 0600 lock with pid, start and command fingerprint, and releases it', () => {
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.tookOver).toBe(false)
    expect(statSync(lockPath).mode & 0o777).toBe(0o600)
    const rec = JSON.parse(readFileSync(lockPath, 'utf8'))
    expect(rec).toMatchObject({ v: 1, pid: process.pid, start: `start-${process.pid}`, cmd_sha256: fingerprintCommand(`cmd-${process.pid}`) })
    expect(rec.nonce).toMatch(/^[0-9a-f]{32}$/)
    expect(r.lock.release()).toBe(true)
    expect(existsSync(lockPath)).toBe(false)
    expect(r.lock.release()).toBe(false)
    // No temp or takeover leftovers.
    expect(readdirSync(dir)).toEqual([])
  })

  it('live own process (same pid, same identity) -> already_running', () => {
    const first = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(first.ok).toBe(true)
    const second = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(second).toEqual({ ok: false, reason: 'already_running' })
    expect(existsSync(`${lockPath}.takeover`)).toBe(false)
  })

  it('live foreign process with matching start time and command -> already_running, lock untouched', () => {
    const pid = process.ppid
    expect(isPidAlive(pid)).toBe(true)
    const raw = writeRecord(lockPath, pid, `start-${pid}`, `cmd-${pid}`)
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r).toEqual({ ok: false, reason: 'already_running' })
    expect(readFileSync(lockPath, 'utf8')).toBe(raw)
  })

  it('live foreign pid with a DIFFERENT start time (recycled pid) -> takeover', () => {
    const pid = process.ppid
    writeRecord(lockPath, pid, 'start-of-an-older-process', `cmd-${pid}`)
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.tookOver).toBe(true)
    expect(JSON.parse(readFileSync(lockPath, 'utf8')).pid).toBe(process.pid)
    expect(statSync(lockPath).mode & 0o777).toBe(0o600)
  })

  it('live foreign pid with a different command fingerprint -> takeover', () => {
    const pid = process.ppid
    writeRecord(lockPath, pid, `start-${pid}`, 'some other program')
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok && r.tookOver).toBe(true)
  })

  it('dead pid -> takeover', () => {
    writeRecord(lockPath, deadPid(), 'whatever', 'whatever')
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok && r.tookOver).toBe(true)
  })

  it('corrupt lock file -> takeover', () => {
    writeFileSync(lockPath, '{"v":1,"pid":', { mode: 0o600 })
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok && r.tookOver).toBe(true)
  })

  it('live holder whose identity cannot be read -> lock_unverifiable (fail-closed), lock untouched', () => {
    const pid = process.ppid
    const raw = writeRecord(lockPath, pid, `start-${pid}`, `cmd-${pid}`)
    const r = acquireRelayLock(lockPath, { probe: fakeProbe(new Map([[pid, null]])) })
    expect(r).toEqual({ ok: false, reason: 'lock_unverifiable' })
    expect(readFileSync(lockPath, 'utf8')).toBe(raw)
  })

  it('own identity unavailable -> lock_identity_unavailable, no file written', () => {
    const r = acquireRelayLock(lockPath, { probe: fakeProbe(new Map([[process.pid, null]])) })
    expect(r).toEqual({ ok: false, reason: 'lock_identity_unavailable' })
    expect(existsSync(lockPath)).toBe(false)
  })

  it('a takeover mutex held by someone else -> lock_busy; a crashed (old) one is cleared for the next attempt', () => {
    writeRecord(lockPath, deadPid(), 'x', 'x')
    const mutex = `${lockPath}.takeover`
    writeFileSync(mutex, 'other\n', { mode: 0o600 })
    expect(acquireRelayLock(lockPath, { probe: fakeProbe() })).toEqual({ ok: false, reason: 'lock_busy' })
    expect(existsSync(mutex)).toBe(true)
    const old = new Date(Date.now() - 120_000)
    utimesSync(mutex, old, old)
    expect(acquireRelayLock(lockPath, { probe: fakeProbe() })).toEqual({ ok: false, reason: 'lock_busy' })
    expect(existsSync(mutex)).toBe(false)
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok && r.tookOver).toBe(true)
  })

  it('release() never deletes a lock that another instance took over', () => {
    const r = acquireRelayLock(lockPath, { probe: fakeProbe() })
    expect(r.ok).toBe(true)
    if (!r.ok) return
    const foreign = writeRecord(lockPath, process.ppid, 'a', 'b')
    expect(r.lock.release()).toBe(false)
    expect(readFileSync(lockPath, 'utf8')).toBe(foreign)
  })
})

describe('process identity probe', () => {
  it('parses the fixed-width ps line and fingerprints the command (no raw command kept)', () => {
    const id = parsePsLine('Thu Oct 29 11:03:12 2026     node dist/permission-bot-relay.js\n')
    expect(id).toEqual({ start: 'Thu Oct 29 11:03:12 2026', cmdSha256: fingerprintCommand('node dist/permission-bot-relay.js') })
    expect(parsePsLine('')).toBeNull()
    expect(parsePsLine('short')).toBeNull()
  })

  it('kill(pid,0) liveness: self alive, exited child dead, invalid pids dead', () => {
    expect(isPidAlive(process.pid)).toBe(true)
    expect(isPidAlive(deadPid())).toBe(false)
    expect(isPidAlive(0)).toBe(false)
    expect(isPidAlive(-1)).toBe(false)
  })

  it('default probe: stable identity for this process, or null (ps denied) -> lock refuses', () => {
    const a = defaultProcessProbe.identity(process.pid)
    if (a === null) {
      expect(acquireRelayLock(lockPath)).toEqual({ ok: false, reason: 'lock_identity_unavailable' })
      return
    }
    expect(a.start.length).toBeGreaterThan(0)
    expect(a.cmdSha256).toMatch(/^[0-9a-f]{64}$/)
    expect(defaultProcessProbe.identity(process.pid)).toEqual(a)
  })

  it('the ps child gets a fixed, minimal environment (never the parent env)', () => {
    const src = readFileSync(join(ROOT, 'src/permission-bot-relay/process-identity.ts'), 'utf8')
    expect(src).toContain("env: { PATH: '/bin:/usr/bin', LC_ALL: 'C' }")
    expect(src).not.toMatch(/process\.env/)
  })
})

// Two (here: four) parallel child starts: exactly one gets the lock.
async function race(n: number): Promise<Array<{ name: string; ok: boolean; reason: string | null }>> {
  const sync = mkdtempSync(join(dir, 'sync-'))
  const kids = Array.from({ length: n }, (_, i) =>
    spawn(TSX, [CHILD, lockPath, sync, `c${i}`], { stdio: ['ignore', 'pipe', 'pipe'], env: process.env }),
  )
  const outs = kids.map((k) => {
    let s = ''
    k.stdout!.on('data', (d) => { s += String(d) })
    k.stderr!.on('data', () => { /* ignored */ })
    return () => s
  })
  const exits = kids.map((k) => new Promise<number | null>((res) => k.on('exit', (c) => res(c))))
  const deadline = Date.now() + 60_000
  const waitFiles = async (prefix: string): Promise<void> => {
    while (Array.from({ length: n }, (_, i) => existsSync(join(sync, `${prefix}-c${i}`))).some((x) => !x)) {
      if (Date.now() > deadline) throw new Error(`children did not reach ${prefix}`)
      await new Promise((r) => setTimeout(r, 10))
    }
  }
  await waitFiles('ready')
  writeFileSync(join(sync, 'go'), '')
  await waitFiles('done')
  writeFileSync(join(sync, 'release'), '')
  const codes = await Promise.all(exits)
  expect(codes).toEqual(Array(n).fill(0))
  return outs.map((o) => JSON.parse(o().trim()))
}

describe('acquireRelayLock: parallel starts', () => {
  it('fresh lock: exactly one of four simultaneous children wins', async () => {
    const results = await race(4)
    expect(results.filter((r) => r.ok)).toHaveLength(1)
    for (const r of results.filter((x) => !x.ok)) expect(['already_running', 'lock_busy']).toContain(r.reason)
    expect(existsSync(lockPath)).toBe(false) // the winner released it
  }, 90_000)

  it('stale lock (dead pid): exactly one of four simultaneous children takes it over', async () => {
    writeRecord(lockPath, deadPid(), 'dead', 'dead')
    const results = await race(4)
    expect(results.filter((r) => r.ok)).toHaveLength(1)
    for (const r of results.filter((x) => !x.ok)) expect(['already_running', 'lock_busy']).toContain(r.reason)
    expect(existsSync(`${lockPath}.takeover`)).toBe(false)
  }, 90_000)
})
