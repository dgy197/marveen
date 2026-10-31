// Card acdb8045 K6: POST /api/agents/fleet-token/restart-stale. Owner session
// only; the sweep is sequential, re-detects before each step, never touches the
// main agent. No tmux, no real restart, no real sleeps: every primitive is a seam.
// Fingerprints in this file are made-up 16-hex words, not derived from any token.
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { Readable } from 'node:stream'
import { initDatabase, getDb, createDashboardUser, getRecentConfigChanges } from '../db.js'
import { createSession, revokeSession, _clearSessionCacheForTest } from '../web/auth-sessions.js'
import { isBlockedCrossOriginWrite } from '../web/csrf-origin.js'
import { requiresAuth } from '../web/auth-gate.js'
import { operatorGateDecision } from '../web/operator-gate.js'
import {
  RESTART_STALE_FORBIDDEN_BODY,
  RESTART_STALE_PATH,
  __resetRestartStaleSweep,
  handleFleetTokenRestartStale,
  restartStaleAgents,
  type RestartStaleDeps,
} from '../web/fleet-token-restart.js'
import type { LaunchRegistry } from '../web/fleet-token-fingerprint.js'
import type { RouteContext } from '../web/routes/types.js'

// Wiring test goes through the real router; the live binding is replaced so no
// tmux / agent-process primitive can run.
const live = vi.hoisted(() => ({ factory: vi.fn() }))
vi.mock('../web/fleet-token-restart-live.js', () => ({ liveRestartStaleDeps: live.factory }))
const { tryHandleAgents } = await import('../web/routes/agents.js')

type Auth = RouteContext['auth']
const TOKEN: Auth = { kind: 'token' }
const TOKEN_ALFA: Auth = { kind: 'token', agent: 'alfa' }
const DEVICE_FULL: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'full' }
const DEVICE_OP: Auth = { kind: 'device', device: 'teszt-telefon', deviceId: 1, scope: 'operator' }
const FEDERATION: Auth = { kind: 'federation', peer: 'teszt-peer' }
const SESSION: Auth = { kind: 'session', user: 'tulaj-teszt' }

const NOW_FP = 'cccccccccccccccc'
const OLD_FP = 'aaaaaaaaaaaaaaaa'

interface World {
  deps: RestartStaleDeps
  restarts: string[]
  sleeps: number[]
  makeDeps: ReturnType<typeof vi.fn<() => RestartStaleDeps>>
  /** agent -> stamp fingerprint; NOW_FP = current, OLD_FP = stale */
  stamps: Record<string, string>
  running: Set<string>
  blocked: Record<string, string>
  onRestart: (name: string) => Promise<{ ok: boolean }>
}

function world(stamps: Record<string, string>, opts: { fleetTokenAgents?: string[] } = {}): World {
  const w: World = {
    restarts: [],
    sleeps: [],
    stamps: { ...stamps },
    running: new Set(Object.keys(stamps)),
    blocked: {},
    makeDeps: vi.fn<() => RestartStaleDeps>(),
    onRestart: async () => ({ ok: true }),
    deps: undefined as unknown as RestartStaleDeps,
  }
  const fleet = new Set(opts.fleetTokenAgents ?? Object.keys(stamps))
  w.deps = {
    drift: {
      listAgents: () => Object.keys(w.stamps),
      usesFleetToken: (n) => fleet.has(n),
      isRunning: (n) => w.running.has(n),
      currentFingerprint: () => NOW_FP,
      registry: () => {
        const reg: LaunchRegistry = Object.create(null)
        for (const [n, fp] of Object.entries(w.stamps)) reg[`agent:${n}`] = { fp, at: 1 }
        return reg
      },
      sessionCreatedMs: () => null,
      tokenMtimeMs: () => null,
    },
    isMain: (n) => n === 'brainy',
    blockReason: (n) => w.blocked[n] ?? null,
    restart: async (n) => {
      w.restarts.push(n)
      return w.onRestart(n)
    },
    sleep: async (ms) => { w.sleeps.push(ms) },
    gapMs: 5000,
  }
  w.makeDeps.mockImplementation(() => w.deps)
  return w
}

type Out = { status: number; body: any }

function mkCtx(auth: Auth | null, cookie?: string, extra: Record<string, string> = {}) {
  const out: Out = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const headers: Record<string, string> = { ...extra }
  if (cookie) headers.cookie = cookie
  // A body that must stay untouched: the route never reads one.
  const req: any = Object.assign(Readable.from([Buffer.from('{"x":1}', 'utf8')]), { headers })
  const url = new URL(`http://localhost:3420${RESTART_STALE_PATH}`)
  const ctx = { req, res, path: url.pathname, method: 'POST', url, auth: auth ?? undefined } as RouteContext
  return { ctx, out, req }
}

async function call(w: World, auth: Auth | null, cookie?: string): Promise<Out & { bodyRead: boolean }> {
  const { ctx, out, req } = mkCtx(auth, cookie)
  await handleFleetTokenRestartStale(ctx, w.makeDeps)
  return { ...out, bodyRead: req.readableDidRead as boolean }
}

const sessionCookie = (name = 'tulaj-teszt') => {
  const u = createDashboardUser(name, '$scrypt$ln=16,r=8,p=1$c2FsdA==$a2V5')
  return createSession({ userId: u.id, username: u.username })
}
const asCookie = (v: string) => `mv_session=${v}`

beforeEach(() => {
  initDatabase(':memory:')
  _clearSessionCacheForTest()
  __resetRestartStaleSweep()
  live.factory.mockReset()
})

describe('refused principals: one uniform 403, body untouched, nothing built, 0 restarts', () => {
  it('bare Bearer (with and without an X-Agent-Id claim) and no principal at all', async () => {
    for (const auth of [TOKEN, TOKEN_ALFA, null]) {
      const w = world({ levente: OLD_FP })
      const r = await call(w, auth)
      expect(r.status).toBe(403)
      expect(r.body).toEqual(RESTART_STALE_FORBIDDEN_BODY)
      expect(r.bodyRead).toBe(false)
      expect(w.makeDeps).not.toHaveBeenCalled()
      expect(w.restarts).toEqual([])
    }
  })

  it('Bearer + an unknown, garbage or empty cookie', async () => {
    for (const cookie of [asCookie('not-a-real-session'), asCookie(''), 'other=1', 'mv_session']) {
      const w = world({ levente: OLD_FP })
      const r = await call(w, TOKEN, cookie)
      expect(r.status).toBe(403)
      expect(r.body).toEqual(RESTART_STALE_FORBIDDEN_BODY)
      expect(w.restarts).toEqual([])
    }
  })

  it('Bearer + a revoked session cookie', async () => {
    const v = sessionCookie()
    revokeSession(v)
    const w = world({ levente: OLD_FP })
    const r = await call(w, TOKEN, asCookie(v))
    expect(r.status).toBe(403)
    expect(r.body).toEqual(RESTART_STALE_FORBIDDEN_BODY)
    expect(w.restarts).toEqual([])
  })

  it('Bearer + an expired session cookie', async () => {
    const v = sessionCookie()
    // Age the durable row far past any session lifetime, then drop the cache.
    getDb().prepare('UPDATE auth_sessions SET created_at = 1, last_seen_at = 1').run()
    _clearSessionCacheForTest()
    const w = world({ levente: OLD_FP })
    const r = await call(w, TOKEN, asCookie(v))
    expect(r.status).toBe(403)
    expect(w.restarts).toEqual([])
  })

  it('device keys (full and operator) and federation, even with a valid cookie lying around', async () => {
    const v = sessionCookie()
    for (const auth of [DEVICE_FULL, DEVICE_OP, FEDERATION]) {
      for (const cookie of [undefined, asCookie(v)]) {
        const w = world({ levente: OLD_FP })
        const r = await call(w, auth, cookie)
        expect(r.status).toBe(403)
        expect(r.body).toEqual(RESTART_STALE_FORBIDDEN_BODY)
        expect(r.bodyRead).toBe(false)
        expect(w.restarts).toEqual([])
      }
    }
  })

  it('the forbidden body names no agent and no fingerprint', () => {
    expect(JSON.stringify(RESTART_STALE_FORBIDDEN_BODY)).not.toMatch(/[0-9a-f]{16}/)
  })
})

describe('accepted: a valid owner session', () => {
  it('Bearer + a valid session cookie restarts only the stale agents, in order, with the gap', async () => {
    const w = world({ zita: OLD_FP, anna: OLD_FP, bela: NOW_FP, csaba: OLD_FP })
    const r = await call(w, TOKEN, asCookie(sessionCookie()))
    expect(r.status).toBe(200)
    expect(w.restarts).toEqual(['anna', 'csaba', 'zita'])
    expect(w.sleeps).toEqual([5000, 5000]) // between restarts, none before the first
    expect(r.body.restarted).toEqual(['anna', 'csaba', 'zita'])
    expect(r.body.skipped).toEqual([])
    expect(r.body.failed).toEqual([])
    expect(r.body.ok).toBe(true)
    expect(JSON.stringify(r.body)).not.toMatch(/[0-9a-f]{16}/)
  })

  it('a cookie-only session (auth already kind:session) is accepted too', async () => {
    const w = world({ anna: OLD_FP })
    const r = await call(w, SESSION)
    expect(r.status).toBe(200)
    expect(w.restarts).toEqual(['anna'])
  })

  it('nothing stale: 200, no restart, no sleep', async () => {
    const w = world({ anna: NOW_FP })
    const r = await call(w, SESSION)
    expect(r.status).toBe(200)
    expect(r.body.steps).toEqual([])
    expect(w.restarts).toEqual([])
    expect(w.sleeps).toEqual([])
  })
})

describe('the sweep itself', () => {
  it('the main agent is never restarted, even when the registry says it is stale', async () => {
    const w = world({ brainy: OLD_FP, anna: OLD_FP })
    const r = await call(w, SESSION)
    expect(r.status).toBe(200)
    expect(w.restarts).toEqual(['anna'])
    expect(r.body.skipped).toEqual(['brainy'])
    expect(r.body.steps).toContainEqual({ agent: 'brainy', result: 'skipped', reason: 'main-agent' })
    expect(w.sleeps).toEqual([]) // a skipped main costs no gap
  })

  it('a stopped-not-desired agent (stopped between detection and its step) is skipped, not started', async () => {
    const w = world({ anna: OLD_FP, bela: OLD_FP, csaba: OLD_FP })
    w.onRestart = async (n) => {
      if (n === 'anna') w.blocked.bela = 'stopped-not-desired'
      return { ok: true }
    }
    const r = await call(w, SESSION)
    expect(w.restarts).toEqual(['anna', 'csaba'])
    expect(r.body.steps).toContainEqual({ agent: 'bela', result: 'skipped', reason: 'stopped-not-desired' })
  })

  it('re-detects before each step: an agent that became current in the meantime is skipped', async () => {
    const w = world({ anna: OLD_FP, bela: OLD_FP, csaba: OLD_FP })
    w.onRestart = async (n) => {
      w.stamps[n] = NOW_FP // the restart re-stamps it
      if (n === 'anna') w.stamps.bela = NOW_FP // someone else restarted bela meanwhile
      return { ok: true }
    }
    const r = await call(w, SESSION)
    expect(w.restarts).toEqual(['anna', 'csaba'])
    expect(r.body.steps).toContainEqual({ agent: 'bela', result: 'skipped', reason: 'no-longer-stale' })
  })

  it('an agent that stopped running in the meantime is not restarted', async () => {
    const w = world({ anna: OLD_FP, bela: OLD_FP })
    w.onRestart = async (n) => {
      if (n === 'anna') w.running.delete('bela')
      return { ok: true }
    }
    await call(w, SESSION)
    expect(w.restarts).toEqual(['anna'])
  })

  it('a failed or throwing restart is recorded with a fixed word and the sweep goes on', async () => {
    const w = world({ anna: OLD_FP, bela: OLD_FP, csaba: OLD_FP })
    w.onRestart = async (n) => {
      if (n === 'anna') return { ok: false }
      if (n === 'bela') throw new Error('tmux said something with a path /secret/place')
      return { ok: true }
    }
    const r = await call(w, SESSION)
    expect(r.status).toBe(200)
    expect(r.body.ok).toBe(false)
    expect(w.restarts).toEqual(['anna', 'bela', 'csaba'])
    expect(r.body.steps).toEqual([
      { agent: 'anna', result: 'failed', reason: 'restart-failed' },
      { agent: 'bela', result: 'failed', reason: 'restart-threw' },
      { agent: 'csaba', result: 'restarted' },
    ])
    expect(JSON.stringify(r.body)).not.toContain('secret')
  })

  it('an unmeasurable token (no current fingerprint) restarts nothing and says so', async () => {
    const w = world({ anna: OLD_FP })
    w.deps.drift.currentFingerprint = () => null
    const r = await call(w, SESSION)
    expect(r.status).toBe(200)
    expect(r.body.measurable).toBe(false)
    expect(w.restarts).toEqual([])
  })

  it('restartStaleAgents alone: the order and the gap are the deps', async () => {
    const w = world({ b: OLD_FP, a: OLD_FP })
    w.deps.gapMs = 123
    const o = await restartStaleAgents(w.deps)
    expect(o.steps.map((s) => s.agent)).toEqual(['a', 'b'])
    expect(w.sleeps).toEqual([123])
  })
})

describe('single flight', () => {
  it('a second call while the first runs is 409 and restarts nothing; the flag clears afterwards', async () => {
    const w = world({ anna: OLD_FP })
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    w.onRestart = async () => { await gate; return { ok: true } }
    const first = call(w, SESSION)
    await vi.waitFor(() => expect(w.restarts).toEqual(['anna']))
    const second = await call(w, SESSION)
    expect(second.status).toBe(409)
    expect(second.body.code).toBe('restart_stale_in_progress')
    expect(w.restarts).toEqual(['anna'])
    release()
    expect((await first).status).toBe(200)
    // After the first finished, a new sweep may run again.
    w.onRestart = async () => ({ ok: true })
    w.stamps.anna = OLD_FP
    expect((await call(w, SESSION)).status).toBe(200)
  })

  it('a refused caller never trips or reads the flag (403, not 409, while a sweep runs)', async () => {
    const w = world({ anna: OLD_FP })
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    w.onRestart = async () => { await gate; return { ok: true } }
    const first = call(w, SESSION)
    await vi.waitFor(() => expect(w.restarts).toEqual(['anna']))
    expect((await call(w, TOKEN)).status).toBe(403)
    release()
    await first
  })

  it('the flag clears when the sweep itself blows up', async () => {
    const w = world({ anna: OLD_FP })
    w.makeDeps.mockImplementationOnce(() => { throw new Error('deps broke') })
    expect((await call(w, SESSION)).status).toBe(500)
    expect((await call(w, SESSION)).status).toBe(200)
  })
})

describe('audit', () => {
  it('writes a start row and a done row with names only', async () => {
    const w = world({ anna: OLD_FP, brainy: OLD_FP })
    await call(w, SESSION)
    const rows = getRecentConfigChanges().filter((r) => r.key === 'fleet_token.restart_stale').reverse()
    expect(rows).toHaveLength(2)
    expect(rows[0].new_value).toBe('start by=tulaj-teszt stale=anna,brainy')
    expect(rows[1].new_value).toBe('done restarted=anna skipped=brainy failed=-')
    expect(JSON.stringify(rows)).not.toMatch(/[0-9a-f]{16}/)
  })

  it('a refused call writes no row', async () => {
    await call(world({ anna: OLD_FP }), TOKEN)
    expect(getRecentConfigChanges().filter((r) => r.key === 'fleet_token.restart_stale')).toHaveLength(0)
  })
})

describe('wiring: the real router, the existing gates', () => {
  async function viaRouter(auth: Auth | null, cookie?: string) {
    const { ctx, out } = mkCtx(auth, cookie)
    expect(await tryHandleAgents(ctx, '/nonexistent-web-dir')).toBe(true)
    return out
  }

  it('Bearer through tryHandleAgents is 403 and the live binding is never built', async () => {
    const out = await viaRouter(TOKEN)
    expect(out.status).toBe(403)
    expect(out.body).toEqual(RESTART_STALE_FORBIDDEN_BODY)
    expect(live.factory).not.toHaveBeenCalled()
  })

  it('a valid session through tryHandleAgents runs the sweep on the live binding', async () => {
    const w = world({ anna: OLD_FP })
    live.factory.mockImplementation(() => w.deps)
    const out = await viaRouter(TOKEN, asCookie(sessionCookie()))
    expect(out.status).toBe(200)
    expect(w.restarts).toEqual(['anna'])
  })

  it('a foreign Origin is rejected by the existing CSRF gate (web.ts runs it before routing)', () => {
    const allowed = new Set(['http://localhost:3420'])
    expect(isBlockedCrossOriginWrite('POST', 'https://evil.example', 'localhost:3420', undefined, allowed)).toBe(true)
    expect(isBlockedCrossOriginWrite('POST', 'http://localhost:3420', 'localhost:3420', undefined, allowed)).toBe(false)
  })

  it('the dashboard gate: the path needs auth and an operator key is denied there', () => {
    expect(requiresAuth(RESTART_STALE_PATH, 'POST')).toBe(true)
    expect(operatorGateDecision({ kind: 'device', scope: 'operator' }, RESTART_STALE_PATH, () => ({ enabled: true, capabilities: {} as never, commands: [] }))).toBe('operator credential: not an operator endpoint')
  })
})
