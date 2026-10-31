// Card acdb8045 K4: a worker restarts itself ONCE per fleet-token change, inside
// its request lock, with a loop guard; a digest line, and a hazmester message at
// the 2nd restart within an hour. Seams only: no tmux, no store, no DB. The
// fingerprints are marker strings so a leak is greppable.
import { describe, it, expect, beforeEach } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import {
  createWorkerTokenRestarter,
  drainWorkerRestartDigestNotes,
  peekWorkerRestartDigestNotes,
  queueWorkerRestartDigestNote,
  WORKER_TOKEN_RESTART_HAZMESTER,
  WORKER_TOKEN_RESTART_MAX_PER_WINDOW,
  WORKER_TOKEN_RESTART_WINDOW_MS,
  type WorkerTokenRestartDeps,
} from '../web/worker-token-restart.js'
import { makeWorkerCtx, restartOnTokenSwap, withWorkerLockFor } from '../web/agent-worker.js'
import { buildHeartbeatDigestFromBlock } from '../web/heartbeat-direct-digest.js'
import { renderHeartbeatMetricsBlock } from '../web/heartbeat-metrics-inject.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const SESSION = 'test-worker'
const FP_A = '00aa11bb22cc33dd'
const FP_B = '99ee88ff77aa66bb'
const FP_C = '1234abcd5678ef90'
const ALL_FPS = [FP_A, FP_B, FP_C]

function harness(opts: { restartWorks?: boolean; alive?: boolean; allowed?: boolean; stamp?: string | null; current?: string | null } = {}) {
  const st = {
    current: opts.current === undefined ? FP_A : opts.current,
    stamp: opts.stamp === undefined ? FP_A : opts.stamp,
    restartWorks: opts.restartWorks ?? true,
    alive: opts.alive ?? true,
    allowed: opts.allowed ?? true,
    now: 1_000_000,
    restarts: 0,
    notes: [] as string[],
    hazmester: [] as string[],
    logs: [] as string[],
  }
  const deps: WorkerTokenRestartDeps = {
    currentFingerprint: () => st.current,
    launchFingerprint: () => st.stamp,
    restart: () => { st.restarts++; if (st.restartWorks) st.stamp = st.current },
    sessionAlive: () => st.alive,
    allowed: () => st.allowed,
    now: () => st.now,
    timeLabel: (ms) => `T${ms}`,
    addDigestNote: (l) => { st.notes.push(l) },
    notifyHazmester: (t) => { st.hazmester.push(t) },
    info: (o, m) => { st.logs.push(JSON.stringify(o) + m) },
    warn: (o, m) => { st.logs.push(JSON.stringify(o) + m) },
  }
  return { st, restarter: createWorkerTokenRestarter(deps) }
}

describe('worker token-swap restart: decision', () => {
  it('no change -> no restart', () => {
    const { st, restarter } = harness()
    expect(restarter.check(SESSION)).toBe('none')
    expect(restarter.check(SESSION)).toBe('none')
    expect(st.restarts).toBe(0)
    expect(st.notes).toEqual([])
  })

  it('change detected -> exactly one restart; later requests do not restart again', () => {
    const { st, restarter } = harness()
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('restarted')
    expect(restarter.check(SESSION)).toBe('none')
    expect(restarter.check(SESSION)).toBe('none')
    expect(st.restarts).toBe(1)
  })

  it('a second change -> one more restart', () => {
    const { st, restarter } = harness()
    st.current = FP_B
    restarter.check(SESSION)
    st.now += 5 * 60_000
    st.current = FP_C
    expect(restarter.check(SESSION)).toBe('restarted')
    expect(restarter.check(SESSION)).toBe('none')
    expect(st.restarts).toBe(2)
  })

  it('unknown never restarts: no stamp, or an unreadable / empty current token', () => {
    const noStamp = harness({ stamp: null, current: FP_B })
    expect(noStamp.restarter.check(SESSION)).toBe('none')
    const noCurrent = harness({ stamp: FP_A, current: null })
    expect(noCurrent.restarter.check(SESSION)).toBe('none')
    expect(noStamp.st.restarts + noCurrent.st.restarts).toBe(0)
  })

  it('a dead session is not restarted here (the lazy start stamps the new token)', () => {
    const { st, restarter } = harness({ alive: false })
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('skipped')
    expect(st.restarts).toBe(0)
  })

  it('WEB_ONLY (not allowed) never restarts', () => {
    const { st, restarter } = harness({ allowed: false })
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('skipped')
    expect(st.restarts).toBe(0)
  })

  it('slow and fast sessions are guarded separately', () => {
    const stamps: Record<string, string> = { slow: FP_A, fast: FP_A }
    let restarts = 0
    const restarter = createWorkerTokenRestarter({
      currentFingerprint: () => FP_B,
      launchFingerprint: (s) => stamps[s] ?? null,
      restart: (s) => { restarts++; stamps[s] = FP_B },
      sessionAlive: () => true,
      allowed: () => true,
      now: () => 1,
      timeLabel: () => 't',
      addDigestNote: () => {},
      notifyHazmester: () => {},
      info: () => {},
      warn: () => {},
    })
    expect(restarter.check('slow')).toBe('restarted')
    expect(restarter.check('fast')).toBe('restarted')
    expect(restarter.check('slow')).toBe('none')
    expect(restarter.check('fast')).toBe('none')
    expect(restarts).toBe(2)
  })
})

describe('worker token-swap restart: loop guard', () => {
  it('a failed restart is not retried for the same fingerprint, on any number of requests', () => {
    const { st, restarter } = harness({ restartWorks: false })
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('failed')
    for (let i = 0; i < 10; i++) expect(restarter.check(SESSION)).toBe('skipped')
    expect(st.restarts).toBe(1)
    expect(st.notes).toEqual([]) // no "restarted" digest line for a failed restart
  })

  it('a half-written (unreadable) token read in between does not reset the guard', () => {
    const { st, restarter } = harness({ restartWorks: false })
    st.current = FP_B
    restarter.check(SESSION)
    st.current = null
    restarter.check(SESSION)
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('skipped')
    expect(st.restarts).toBe(1)
  })

  it('after the failed fingerprint goes away and comes back, one new attempt is allowed', () => {
    const { st, restarter } = harness({ restartWorks: false })
    st.current = FP_B
    restarter.check(SESSION)
    st.current = FP_A // token changed back: matches the old stamp
    expect(restarter.check(SESSION)).toBe('none')
    st.current = FP_B
    expect(restarter.check(SESSION)).toBe('failed')
    expect(st.restarts).toBe(2)
  })

  it('a flapping token is bounded per hour, then allowed again once the window passes', () => {
    const { st, restarter } = harness()
    let attempts = 0
    for (let i = 0; i < 20; i++) {
      st.current = i % 2 === 0 ? FP_B : FP_A
      st.now += 60_000
      const r = restarter.check(SESSION)
      if (r === 'restarted') attempts++
    }
    expect(attempts).toBe(WORKER_TOKEN_RESTART_MAX_PER_WINDOW)
    expect(st.restarts).toBe(WORKER_TOKEN_RESTART_MAX_PER_WINDOW)
    // window passes: the next real change restarts again
    st.now += WORKER_TOKEN_RESTART_WINDOW_MS
    st.current = FP_C
    expect(restarter.check(SESSION)).toBe('restarted')
  })

  it('never throws: a throwing dep ends as none, with an error class only in the log', () => {
    const logs: string[] = []
    const restarter = createWorkerTokenRestarter({
      currentFingerprint: () => { throw new Error(`boom ${FP_A}`) },
      launchFingerprint: () => FP_A,
      restart: () => {},
      sessionAlive: () => true,
      allowed: () => true,
      now: () => 1,
      timeLabel: () => 't',
      addDigestNote: () => {},
      notifyHazmester: () => {},
      info: () => {},
      warn: (o, m) => { logs.push(JSON.stringify(o) + m) },
    })
    expect(restarter.check(SESSION)).toBe('none')
    expect(logs.join('\n')).not.toContain(FP_A)
  })
})

describe('worker token-swap restart: reporting', () => {
  it('writes ONE digest line (session, time, reason: token swap), no fingerprint anywhere', () => {
    const { st, restarter } = harness()
    st.current = FP_B
    restarter.check(SESSION)
    expect(st.notes).toHaveLength(1)
    expect(st.notes[0]).toContain(SESSION)
    expect(st.notes[0]).toContain(`T${st.now}`)
    expect(st.notes[0]).toContain('token swap')
    expect(st.hazmester).toEqual([]) // one restart: no message to hazmester
    const everything = [...st.notes, ...st.hazmester, ...st.logs].join('\n')
    for (const fp of ALL_FPS) expect(everything).not.toContain(fp)
  })

  it('the 2nd restart within an hour sends exactly one hazmester message; the 3rd sends none', () => {
    const { st, restarter } = harness()
    st.current = FP_B
    restarter.check(SESSION)
    expect(st.hazmester).toHaveLength(0)
    st.now += 20 * 60_000
    st.current = FP_C
    restarter.check(SESSION)
    expect(st.hazmester).toHaveLength(1)
    expect(st.hazmester[0]).toContain(SESSION)
    expect(st.hazmester[0]).toContain('token swap')
    st.now += 5 * 60_000
    st.current = FP_A
    restarter.check(SESSION)
    expect(st.hazmester).toHaveLength(1)
    expect(st.notes).toHaveLength(3)
    for (const fp of ALL_FPS) expect([...st.hazmester, ...st.logs].join('\n')).not.toContain(fp)
  })

  it('two restarts more than an hour apart send no message', () => {
    const { st, restarter } = harness()
    st.current = FP_B
    restarter.check(SESSION)
    st.now += WORKER_TOKEN_RESTART_WINDOW_MS + 1
    st.current = FP_C
    restarter.check(SESSION)
    expect(st.hazmester).toHaveLength(0)
  })

  it('the message goes to hazmester', () => {
    expect(WORKER_TOKEN_RESTART_HAZMESTER).toBe('hazmester')
  })
})

describe('worker token-swap restart: lock', () => {
  it('two concurrent requests on one ctx: single restart, the second one runs after the first finished', async () => {
    const { st, restarter } = harness()
    st.current = FP_B
    const ctx = makeWorkerCtx(SESSION, '/tmp/unused-worker-home')
    const order: string[] = []
    const run = (name: string) => withWorkerLockFor(ctx, async () => {
      order.push(`${name}:start`)
      restartOnTokenSwap(ctx, restarter)
      await new Promise(r => setTimeout(r, 15))
      order.push(`${name}:end`)
    })
    await Promise.all([run('r1'), run('r2')])
    expect(st.restarts).toBe(1)
    expect(order).toEqual(['r1:start', 'r1:end', 'r2:start', 'r2:end'])
  })
})

describe('worker token-swap restart: wiring pins', () => {
  const src = readFileSync(join(__dirname, '..', 'web', 'agent-worker.ts'), 'utf-8')

  it('runViaWorker checks the token swap INSIDE the lock, before the first attempt', () => {
    const lock = src.indexOf('return withWorkerLockFor(ctx, async () => {')
    const check = src.indexOf('restartOnTokenSwap(ctx)', lock)
    const attempt = src.indexOf('runWorkerAttempt(ctx, message, timeoutMs)', lock)
    expect(lock).toBeGreaterThan(-1)
    expect(check).toBeGreaterThan(lock)
    expect(attempt).toBeGreaterThan(check)
  })

  it('the launch stamp is written BEFORE tmux new-session, from the same fleet-token decision', () => {
    const stamp = src.indexOf('stampWorkerLaunch(ctx.session, exportsFleetToken)')
    const newSession = src.indexOf("execFileSync(TMUX, ['new-session'")
    expect(stamp).toBeGreaterThan(-1)
    expect(newSession).toBeGreaterThan(stamp)
    expect(src).toContain('(exportsFleetToken ? `export CLAUDE_CODE_OAUTH_TOKEN="$(cat ')
  })

  it('the restart logic never touches the main agent id', () => {
    const mod = readFileSync(join(__dirname, '..', 'web', 'worker-token-restart.ts'), 'utf-8')
    expect(mod).not.toMatch(/MAIN_AGENT_ID/)
  })
})

describe('worker token-swap restart: digest section', () => {
  beforeEach(() => { drainWorkerRestartDigestNotes() })

  it('queue is drained once', () => {
    queueWorkerRestartDigestNote('- a')
    queueWorkerRestartDigestNote('- b')
    expect(peekWorkerRestartDigestNotes()).toHaveLength(2)
    expect(drainWorkerRestartDigestNotes()).toEqual(['- a', '- b'])
    expect(drainWorkerRestartDigestNotes()).toEqual([])
  })

  it('the heartbeat block carries the section only when there are lines, and the digest keeps it', () => {
    const plain = renderHeartbeatMetricsBlock(null, 'x')
    expect(plain).not.toContain('Flotta-token')
    const line = `- ${SESSION} (worker): ujrainditva T1, ok: token swap`
    const block = renderHeartbeatMetricsBlock(null, 'x', [line])
    expect(block).toContain('### Flotta-token\n' + line)
    const digest = buildHeartbeatDigestFromBlock(block, 'Europe/Budapest', 'FALLBACK')
    expect(digest).toContain(line)
  })
})
