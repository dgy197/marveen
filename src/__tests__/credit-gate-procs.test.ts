import { describe, it, expect, afterEach } from 'vitest'
import { spawn } from 'node:child_process'
import { join } from 'node:path'
import { Harness, simpleCal, T0, USD } from './fixtures/credit-gate/gate-harness.js'

// Credit gate, node N2a, K3 (C-01): two separate OS processes, each with its
// own connection to the SAME SQLite file, reserve at the same instant. The
// room is 75 USD (R_est 95, T_close 20); each process tries 60 reservations
// of 1 USD. Whatever the interleaving, at most 75 may be admitted, and the
// rows in the database are exactly the admitted ones.
//
// The children run reserve-worker.ts through tsx, with loopback-guard.cjs
// preloaded (no non-loopback connect, no 18800/18899; self-tested at load),
// a minimal environment, and only the test's tmp directory to work in.

const ROOT = join(__dirname, '..', '..')
const FIX = join(__dirname, 'fixtures', 'credit-gate')

interface ChildOut { tag: string; pid: number; readyAt: number; started: number; ended: number; ok: number; reasons: Record<string, number> }

let h: Harness | undefined
afterEach(() => {
  h?.cleanup()
  h = undefined
})

function child(args: string[]): Promise<{ code: number | null; out: string; err: string }> {
  return new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--require', join(FIX, 'loopback-guard.cjs'), '--import', 'tsx', join(FIX, 'reserve-worker.ts'), ...args], {
      cwd: ROOT,
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? '/tmp', TMPDIR: process.env.TMPDIR ?? '/tmp', NODE_ENV: 'production' },
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    let out = ''
    let err = ''
    p.stdout.on('data', (d) => { out += String(d) })
    p.stderr.on('data', (d) => { err += String(d) })
    p.on('error', reject)
    p.on('close', (code) => resolve({ code, out, err }))
  })
}

describe('K3: two processes, one database file, at the same time', () => {
  it('never admits more than the room, and every admitted reservation is a row', async () => {
    h = new Harness({ cal: simpleCal(1, '95.00') })
    expect(h.gate.tick().state).toBe('OPEN')
    const cal = JSON.stringify(h.cal)
    const startAt = Date.now() + 8000
    const common = [h.dbPath, h.storeDir, String(T0 + 1000), String(startAt), '60']
    const [a, b] = await Promise.all([child([...common, 'a', cal]), child([...common, 'b', cal])])
    for (const c of [a, b]) expect(c.code, c.err).toBe(0)
    const outs = [a, b].map((c) => JSON.parse(c.out.trim().split('\n').pop() as string) as ChildOut)

    // Both were ready before the common start, and their work overlapped in time.
    for (const o of outs) expect(o.readyAt).toBeLessThan(startAt)
    expect(outs[0].started).toBeLessThan(outs[1].ended)
    expect(outs[1].started).toBeLessThan(outs[0].ended)

    const rows = h.reservations()
    const admitted = outs[0].ok + outs[1].ok
    expect(rows).toHaveLength(admitted)
    const total = rows.reduce((s, r) => s + (r.amount_micro as number), 0)
    expect(total).toBeLessThanOrEqual(75 * USD)
    // No lock trouble (no gate_busy): then exactly the room was filled, by both
    // processes. The 75th leaves R_est at T_close, so the gate closes behind it
    // (C-04) and later attempts read gate_closed.
    expect(outs.flatMap((o) => Object.keys(o.reasons)).filter((k) => k !== 'below_threshold' && k !== 'gate_closed')).toEqual([])
    expect(admitted).toBe(75)
    expect(outs[0].ok).toBeGreaterThan(0)
    expect(outs[1].ok).toBeGreaterThan(0)
    expect(new Set(rows.map((r) => r.caller))).toEqual(new Set(['proc-a', 'proc-b']))
  }, 60_000)
})
