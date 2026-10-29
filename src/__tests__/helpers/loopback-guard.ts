// Loopback-only socket guard for network tests (card d7f586bf).
//
// Patches net.Socket.prototype.connect so that, inside the test process, a TCP
// connect to anything but 127.0.0.1 / ::1 / localhost throws BEFORE any socket
// I/O, and so does a loopback connect to a blocklisted port: the live CDP
// browser (18800), 18899, and GUARD_SELFTEST_PORT, which exists only so the
// self-test can prove the port block without touching a real service.
// fetch (undici) builds its sockets through net.connect, so it is covered too;
// the self-test in each suite proves that for the running Node version.

import net from 'node:net'

export const GUARD_SELFTEST_PORT = 18977
export const BLOCKED_LOOPBACK_PORTS: ReadonlySet<number> = new Set([18800, 18899, GUARD_SELFTEST_PORT])
const LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost', '::ffff:127.0.0.1'])

export class LoopbackGuardError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'LoopbackGuardError'
  }
}

interface ConnectTarget { host?: string; port?: number; path?: string }

function targetOf(args: unknown[]): ConnectTarget {
  let first = args[0]
  // net.connect() normalizes into [options, cb] and calls socket.connect(array).
  if (Array.isArray(first)) first = first[0]
  if (typeof first === 'object' && first !== null) {
    const o = first as { host?: unknown; port?: unknown; path?: unknown }
    return {
      host: typeof o.host === 'string' ? o.host : undefined,
      port: o.port === undefined ? undefined : Number(o.port),
      path: typeof o.path === 'string' ? o.path : undefined,
    }
  }
  if (typeof first === 'number' || (typeof first === 'string' && /^\d+$/.test(first))) {
    return { port: Number(first), host: typeof args[1] === 'string' ? args[1] : undefined }
  }
  if (typeof first === 'string') return { path: first }
  return {}
}

export interface LoopbackGuard {
  blocked: string[]
  uninstall(): void
}

let installed: LoopbackGuard | null = null

export function installLoopbackGuard(): LoopbackGuard {
  if (installed) return installed
  const proto = net.Socket.prototype as unknown as { connect: (...a: unknown[]) => unknown }
  const original = proto.connect
  const blocked: string[] = []
  proto.connect = function guardedConnect(this: unknown, ...args: unknown[]): unknown {
    const t = targetOf(args)
    if (t.path === undefined) {
      const host = (t.host ?? 'localhost').replace(/^\[|\]$/g, '')
      if (!LOOPBACK_HOSTS.has(host) || (t.port !== undefined && BLOCKED_LOOPBACK_PORTS.has(t.port))) {
        const what = `${host}:${t.port ?? '?'}`
        blocked.push(what)
        throw new LoopbackGuardError(`loopback-guard: connect to ${what} denied`)
      }
    }
    return original.apply(this, args)
  }
  installed = {
    blocked,
    uninstall(): void {
      proto.connect = original
      installed = null
    },
  }
  return installed
}

// Proves the guard on this Node version: a non-loopback connect and a connect
// to the blocklisted self-test port are refused before any I/O, also via fetch.
export async function selfTestLoopbackGuard(guard: LoopbackGuard): Promise<void> {
  const before = guard.blocked.length
  let threw = 0
  for (const target of [{ host: '192.0.2.1', port: 80 }, { host: '127.0.0.1', port: GUARD_SELFTEST_PORT }]) {
    try {
      const s = net.connect(target)
      s.destroy()
    } catch (err) {
      if (err instanceof LoopbackGuardError) threw++
    }
  }
  if (threw !== 2) throw new Error(`loopback guard self-test: expected 2 refusals, got ${threw}`)
  let fetchRefused = false
  try {
    await fetch(`http://127.0.0.1:${GUARD_SELFTEST_PORT}/`)
  } catch (err) {
    const cause = (err as { cause?: unknown }).cause
    fetchRefused = cause instanceof LoopbackGuardError || String(cause).includes('loopback-guard')
  }
  if (!fetchRefused) throw new Error('loopback guard self-test: fetch to the blocked port was not refused by the guard')
  if (guard.blocked.length < before + 3) throw new Error('loopback guard self-test: refusals not recorded')
}
