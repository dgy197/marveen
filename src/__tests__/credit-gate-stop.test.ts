import { describe, it, expect, afterEach } from 'vitest'
import {
  existsSync,
  lstatSync,
  mkdirSync,
  readFileSync,
  readlinkSync,
  renameSync,
  statSync,
  symlinkSync,
  unlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import Database from 'better-sqlite3'
import { readCreditGateMode } from '../web/credit-gate/config.js'
import {
  inspectStop,
  nodeStopFs,
  parseStopOwner,
  placeStop,
  releaseStop,
  stopContent,
  type StopFs,
} from '../web/credit-gate/stop-file.js'
import { inactiveStatus, setCreditGateRuntime } from '../web/credit-gate/runtime.js'
import { Harness, simpleCal, type HarnessOptions } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a: the STOP protocol (card fec6335f; spec A-03, A-05,
// A-06; blueprint 3.6, 8 "STOP: emberi STOP-hoz a kapu nem nyúl", 14).
//
// The rule under test: the gate never deletes, overwrites or renames-away a
// STOP that is not exactly the one it wrote, and a human STOP keeps the gate
// closed (disarm). Every fixture lives in a tmp directory.

const NONCE = 'a'.repeat(32)
const NONCE2 = 'b'.repeat(32)

let h: Harness
function harness(o: HarnessOptions = {}): Harness {
  h = new Harness(o)
  return h
}
afterEach(() => {
  setCreditGateRuntime(null)
  h?.cleanup()
})

interface Snap { content: string | null; ino: number; mtimeMs: number; kind: string }
function snap(p: string): Snap {
  const st = lstatSync(p)
  const kind = st.isSymbolicLink() ? 'symlink' : st.isDirectory() ? 'dir' : 'file'
  return { content: kind === 'file' ? readFileSync(p, 'utf8') : null, ino: st.ino, mtimeMs: st.mtimeMs, kind }
}

/** A StopFs that records every mutating call, to prove the STOP name is never unlinked. */
function recordingFs(base: StopFs = nodeStopFs): { fs: StopFs; calls: string[] } {
  const calls: string[] = []
  const fs: StopFs = {
    ...base,
    link: (a, b) => { calls.push(`link ${a} ${b}`); base.link(a, b) },
    unlink: (p) => { calls.push(`unlink ${p}`); base.unlink(p) },
    rename: (a, b) => { calls.push(`rename ${a} ${b}`); base.rename(a, b) },
  }
  return { fs, calls }
}

describe('stop-file: the protocol itself', () => {
  it('placeStop writes `credit-gate v1 <nonce>` (0600) through link and leaves no tmp file; inspect says gate', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    expect(r.placed).toBe(true)
    if (!r.placed) return
    expect(readFileSync(h.stopPath, 'utf8')).toBe(stopContent(NONCE))
    expect(statSync(h.stopPath).mode & 0o777).toBe(0o600)
    expect(h.batchDirEntries()).toEqual(['STOP'])
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ kind: 'gate' })
    expect(parseStopOwner(JSON.stringify(r.rec))).toEqual(r.rec)
    expect(parseStopOwner('{"v":1}')).toBeNull()
    expect(parseStopOwner('not json')).toBeNull()
  })

  it('EEXIST: a STOP already there is never overwritten, and the gate does not own it', () => {
    harness()
    writeFileSync(h.stopPath, 'kezzel tettem le\n')
    const before = snap(h.stopPath)
    expect(placeStop(nodeStopFs, h.stopPath, NONCE, 1)).toMatchObject({ placed: false, why: 'exists' })
    expect(snap(h.stopPath)).toEqual(before)
    expect(h.batchDirEntries()).toEqual(['STOP'])
  })

  it('an absent STOP is absent; a STOP without a record is human', () => {
    harness()
    expect(inspectStop(nodeStopFs, h.stopPath, null)).toEqual({ kind: 'absent' })
    writeFileSync(h.stopPath, '')
    expect(inspectStop(nodeStopFs, h.stopPath, null)).toEqual({ kind: 'human', why: 'no_record' })
  })

  it('every way a STOP can differ from the gate\'s makes it human', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    // touch: only the mtime changes
    const t = new Date(Date.now() + 5000)
    utimesSync(h.stopPath, t, t)
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ kind: 'human', why: 'mtime' })
    // same content, other inode
    unlinkSync(h.stopPath)
    writeFileSync(h.stopPath, stopContent(NONCE))
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toMatchObject({ kind: 'human' })
    // other content
    unlinkSync(h.stopPath)
    writeFileSync(h.stopPath, 'stop\n')
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toMatchObject({ kind: 'human' })
    // symlink (even to the gate's own content)
    unlinkSync(h.stopPath)
    const target = join(h.dir, 'elsewhere')
    writeFileSync(target, stopContent(NONCE))
    symlinkSync(target, h.stopPath)
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ kind: 'human', why: 'symlink' })
    // directory
    unlinkSync(h.stopPath)
    mkdirSync(h.stopPath)
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ kind: 'human', why: 'directory' })
  })

  it('releaseStop removes the gate\'s own STOP and leaves nothing behind', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    expect(releaseStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ released: true, how: 'unlinked' })
    expect(h.batchDirEntries()).toEqual([])
  })

  it('releaseStop refuses a touched STOP and does not move it', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    const t = new Date(Date.now() + 5000)
    utimesSync(h.stopPath, t, t)
    const before = snap(h.stopPath)
    const { fs, calls } = recordingFs()
    expect(releaseStop(fs, h.stopPath, r.rec)).toMatchObject({ released: false, why: 'not_owner' })
    expect(snap(h.stopPath)).toEqual(before)
    expect(calls).toEqual([])
  })

  it('a swap between the check and the rename: nothing is deleted, the swapped-in STOP is put back (raced)', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    const { fs: rec, calls } = recordingFs()
    // Right before the gate's rename, a person replaces the STOP with theirs.
    const fs: StopFs = {
      ...rec,
      rename: (a, b) => {
        if (a === h.stopPath) {
          unlinkSync(h.stopPath)
          writeFileSync(h.stopPath, 'ember: allj\n')
        }
        rec.rename(a, b)
      },
    }
    const out = releaseStop(fs, h.stopPath, r.rec)
    expect(out).toMatchObject({ released: false, why: 'raced', restored: true, bothPresent: false })
    expect(readFileSync(h.stopPath, 'utf8')).toBe('ember: allj\n')
    expect(calls.filter((c) => c.startsWith(`unlink ${h.stopPath}`) && c === `unlink ${h.stopPath}`)).toEqual([])
    // The human's file was never unlinked: what is gone is only the release name it passed through.
    expect(h.batchDirEntries()).toEqual(['STOP'])
  })

  it('a swap AND a newer STOP under the name meanwhile: both are kept', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    const fs: StopFs = {
      ...nodeStopFs,
      rename: (a, b) => {
        if (a === h.stopPath) {
          unlinkSync(h.stopPath)
          writeFileSync(h.stopPath, 'elso ember\n')
          nodeStopFs.rename(a, b)
          // ...and a second person puts down another STOP before the re-check.
          writeFileSync(h.stopPath, 'masodik ember\n')
          return
        }
        nodeStopFs.rename(a, b)
      },
    }
    const out = releaseStop(fs, h.stopPath, r.rec)
    expect(out).toMatchObject({ released: false, why: 'raced', restored: false, bothPresent: true })
    if (out.released || out.why !== 'raced') return
    expect(readFileSync(h.stopPath, 'utf8')).toBe('masodik ember\n')
    expect(readFileSync(out.releasePath, 'utf8')).toBe('elso ember\n')
  })

  it('a symlink swapped in during the release is put back as the symlink, its target untouched', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    const target = join(h.dir, 'target')
    writeFileSync(target, 'cel\n')
    const fs: StopFs = {
      ...nodeStopFs,
      rename: (a, b) => {
        if (a === h.stopPath) {
          unlinkSync(h.stopPath)
          symlinkSync(target, h.stopPath)
        }
        nodeStopFs.rename(a, b)
      },
    }
    expect(releaseStop(fs, h.stopPath, r.rec)).toMatchObject({ released: false, why: 'raced', restored: true })
    expect(lstatSync(h.stopPath).isSymbolicLink()).toBe(true)
    expect(readlinkSync(h.stopPath)).toBe(target)
    expect(readFileSync(target, 'utf8')).toBe('cel\n')
  })
})

describe('K5: the gate and a human STOP', () => {
  const humanStops: Array<[string, (p: string, dir: string) => void]> = [
    ['an empty touch', (p) => writeFileSync(p, '')],
    ['human content', (p) => writeFileSync(p, 'STOP - Gyuri\n')],
    ['a symlink', (p, dir) => { writeFileSync(join(dir, 'tgt'), 'x'); symlinkSync(join(dir, 'tgt'), p) }],
    ['a directory', (p) => mkdirSync(p)],
  ]

  for (const [name, make] of humanStops) {
    it(`${name}: the gate does not touch it and does not open (disarm)`, () => {
      harness({ cal: simpleCal(1, '100.00') })
      make(h.stopPath, h.dir)
      const before = snap(h.stopPath)
      const { fs, calls } = recordingFs()
      h.stopFs = fs
      h.gate = h.makeGate()
      expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'human_stop' })
      h.now += 30_000
      expect(h.gate.tick().state).toBe('CLOSED')
      expect(snap(h.stopPath)).toEqual(before)
      expect(calls).toEqual([])
      // Not even for a moment: no transition into OPEN was ever written.
      expect(h.events('transition').some((e) => e.to_state === 'OPEN')).toBe(false)
      expect(h.gate.status().stop).toMatchObject({ present: true, owner: 'human' })
      expect(h.gate.reserve({ kind: 'headless', budget_micro: 1_000_000 as never, model: 'claude-opus-5-5', ref: 'n', caller: 'ezermester' }))
        .toMatchObject({ ok: false })
    })
  }

  it('a touch on the gate\'s own STOP makes it human: never removed, and the gate stays closed', () => {
    harness({ cal: null })
    expect(h.gate.tick().state).toBe('CLOSED')
    expect(readFileSync(h.stopPath, 'utf8')).toMatch(/^credit-gate v1 /)
    const t = new Date(Date.now() + 5000)
    utimesSync(h.stopPath, t, t)
    const before = snap(h.stopPath)
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'human_stop' })
    expect(snap(h.stopPath)).toEqual(before)
    expect(h.events('transition').some((e) => e.to_state === 'OPEN')).toBe(false)
  })

  it('the human STOP removed: the gate stays closed until a newer calibration (A-05), then opens', () => {
    harness({ cal: simpleCal(1, '100.00') })
    writeFileSync(h.stopPath, '')
    expect(h.gate.tick().state).toBe('CLOSED')
    unlinkSync(h.stopPath)
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'human_stop' })
    // Closed, so the gate puts its OWN STOP down where the human one was.
    expect(readFileSync(h.stopPath, 'utf8')).toMatch(/^credit-gate v1 /)
    h.cal = simpleCal(2, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(existsSync(h.stopPath)).toBe(false)
  })

  it('the gate\'s own STOP: put down while closed, taken away when it opens, nothing left behind', () => {
    harness({ cal: null })
    h.gate.tick()
    expect(readFileSync(h.stopPath, 'utf8')).toMatch(/^credit-gate v1 [0-9a-f]{32}$/)
    expect(h.gate.status().stop).toMatchObject({ present: true, owner: 'gate' })
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    expect(h.gate.tick().state).toBe('OPEN')
    expect(h.batchDirEntries()).toEqual([])
    expect(h.gate.status().stop).toMatchObject({ present: false, owner: 'none' })
  })

  it('a human STOP that appears between the tick\'s check and its STOP step on an OPEN gate closes it (latched)', () => {
    harness({ cal: simpleCal(1, '100.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    let n = 0
    h.stopFs = {
      ...nodeStopFs,
      lstat: (p) => {
        if (p === h.stopPath && ++n === 2) writeFileSync(h.stopPath, 'ember, epp most\n')
        return nodeStopFs.lstat(p)
      },
    }
    h.gate = h.makeGate()
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'human_stop' })
    expect(readFileSync(h.stopPath, 'utf8')).toBe('ember, epp most\n')
    h.stopFs = undefined
    h.gate = h.makeGate()
    unlinkSync(h.stopPath)
    h.now += 30_000
    expect(h.gate.tick().state).toBe('CLOSED')
  })

  it('a swap during the gate\'s own release: no deletion, HOLD', () => {
    harness({ cal: null })
    h.gate.tick()
    const swapped = { done: false }
    h.stopFs = {
      ...nodeStopFs,
      rename: (a, b) => {
        if (a === h.stopPath && !swapped.done) {
          swapped.done = true
          unlinkSync(h.stopPath)
          writeFileSync(h.stopPath, 'ember\n')
        }
        nodeStopFs.rename(a, b)
      },
    }
    h.gate = h.makeGate()
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    h.gate.tick()
    expect(swapped.done).toBe(true)
    expect(h.state()).toMatchObject({ state: 'HOLD', reason: 'stop_race' })
    expect(readFileSync(h.stopPath, 'utf8')).toBe('ember\n')
    expect(h.events('stop_race')).toHaveLength(1)
  })

  it('EEXIST at the gate: the existing STOP stays as it was, and the gate records that it is not the owner', () => {
    harness({ cal: null })
    // A STOP appears between the gate's inspection and its link().
    let armed = true
    h.stopFs = {
      ...nodeStopFs,
      link: (a, b) => {
        if (armed && b === h.stopPath) {
          armed = false
          writeFileSync(h.stopPath, 'kozben jott\n')
        }
        nodeStopFs.link(a, b)
      },
    }
    h.gate = h.makeGate()
    h.gate.tick()
    expect(readFileSync(h.stopPath, 'utf8')).toBe('kozben jott\n')
    expect(h.events('stop_exists')).toHaveLength(1)
    expect(h.state().stop_owner_json).toBeNull()
    expect(h.batchDirEntries()).toEqual(['STOP'])
    h.cal = simpleCal(1, '100.00')
    h.now += 30_000
    expect(h.gate.tick()).toMatchObject({ state: 'CLOSED', reason: 'human_stop' })
    expect(readFileSync(h.stopPath, 'utf8')).toBe('kozben jott\n')
  })

  it('shadow: the gate never writes a STOP', () => {
    harness({ cal: null, mode: 'shadow' })
    h.gate.tick()
    h.gate.signal('disarm', 'operator', null)
    expect(existsSync(h.stopPath)).toBe(false)
  })

  it('switching to off leaves the gate\'s STOP where it is, and the status still names its owner', () => {
    harness({ cal: null })
    h.gate.tick()
    const before = snap(h.stopPath)
    // Restart in off mode: no gate object, no tick.
    setCreditGateRuntime({ mode: readCreditGateMode('off'), gate: null, storeDir: h.storeDir, db: h.db, startError: null })
    const st = inactiveStatus({ mode: readCreditGateMode('off'), gate: null, storeDir: h.storeDir, db: h.db, startError: null })
    expect(st).toMatchObject({ mode: 'off', enforced: false, stop: { present: true, owner: 'gate' } })
    expect(snap(h.stopPath)).toEqual(before)
  })

  it('off mode without the gate tables: the status does not create them', () => {
    harness()
    const fresh = new Database(join(h.dir, 'fresh.sqlite'))
    try {
      const st = inactiveStatus({ mode: readCreditGateMode(undefined), gate: null, storeDir: h.storeDir, db: fresh, startError: null })
      expect(st.mode).toBe('off')
      const tables = fresh.prepare("SELECT name FROM sqlite_master WHERE name LIKE 'credit_%'").all()
      expect(tables).toEqual([])
    } finally {
      fresh.close()
    }
  })

  it('a recorded owner of another nonce is not this STOP', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    expect(inspectStop(nodeStopFs, h.stopPath, { ...r.rec, nonce: NONCE2 })).toMatchObject({ kind: 'human' })
  })

  it('renameSync of the STOP by a person to a release name is not mistaken for the gate\'s own release', () => {
    harness()
    const r = placeStop(nodeStopFs, h.stopPath, NONCE, 1)
    if (!r.placed) throw new Error('place')
    renameSync(h.stopPath, join(h.batchDir, 'STOP.old'))
    expect(inspectStop(nodeStopFs, h.stopPath, r.rec)).toEqual({ kind: 'absent' })
    expect(releaseStop(nodeStopFs, h.stopPath, r.rec)).toMatchObject({ released: false })
    expect(existsSync(join(h.batchDir, 'STOP.old'))).toBe(true)
  })
})
