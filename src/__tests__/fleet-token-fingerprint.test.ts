// Card acdb8045 K2: token fingerprint + launch registry. Tokens are assembled at
// runtime (never a literal token-shaped string in the source). The canary token
// must appear nowhere: not in the registry file, not in any return value, not in
// the logger, not in an error string.
import { describe, it, expect, afterAll, vi } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync, readdirSync, mkdirSync, chmodSync } from 'node:fs'
import { createHash } from 'node:crypto'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import {
  clearLaunch,
  createdAfterTokenChange,
  fingerprintFleetToken,
  fingerprintOfToken,
  fleetTokenState,
  fleetTokenStateFor,
  isLaunchKey,
  launchFingerprint,
  readLaunchRegistry,
  recordLaunch,
  type FleetTokenIO,
} from '../web/fleet-token-fingerprint.js'
import { logger } from '../logger.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const tmpRoot = mkdtempSync(join(tmpdir(), 'marveen-fleet-fp-test-'))
afterAll(() => rmSync(tmpRoot, { recursive: true, force: true }))

const canary = (tag: string) => ['canary', 'fleet', 'tok', tag, 'zq9x7w'].join('-')
const sha16 = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 16)

let n = 0
function fresh() {
  const dir = join(tmpRoot, `case-${n++}`)
  mkdirSync(dir, { recursive: true })
  return { dir, token: join(dir, '.claude-oauth-token'), reg: join(dir, 'fleet-token-launch.json') }
}

describe('fingerprint', () => {
  it('is the first 16 hex of sha256 of the trimmed token', () => {
    const t = canary('a')
    expect(fingerprintOfToken(t)).toBe(sha16(t))
    expect(fingerprintOfToken(t)).toMatch(/^[0-9a-f]{16}$/)
  })

  it('two different tokens give two different fingerprints', () => {
    expect(fingerprintOfToken(canary('a'))).not.toBe(fingerprintOfToken(canary('b')))
  })

  it('identical content with a newline / surrounding whitespace difference is the same fingerprint', () => {
    const t = canary('a')
    expect(fingerprintOfToken(`${t}\n`)).toBe(fingerprintOfToken(t))
    expect(fingerprintOfToken(`  ${t}\r\n`)).toBe(fingerprintOfToken(t))
  })

  it('empty or whitespace-only value is null', () => {
    expect(fingerprintOfToken('')).toBeNull()
    expect(fingerprintOfToken(' \n\t')).toBeNull()
  })

  it('fingerprintFleetToken: file content, newline-insensitive, missing/empty file is null', () => {
    const c = fresh()
    expect(fingerprintFleetToken(c.token)).toBeNull() // missing
    writeFileSync(c.token, '')
    expect(fingerprintFleetToken(c.token)).toBeNull() // empty
    writeFileSync(c.token, canary('a'))
    const a = fingerprintFleetToken(c.token)
    expect(a).toBe(sha16(canary('a')))
    writeFileSync(c.token, `${canary('a')}\n`)
    expect(fingerprintFleetToken(c.token)).toBe(a)
    writeFileSync(c.token, canary('b'))
    expect(fingerprintFleetToken(c.token)).not.toBe(a)
  })

  it('an unreadable file is null and does not throw', () => {
    const io: FleetTokenIO = { readFile: () => { throw new Error(`EACCES ${canary('leak')}`) }, writeAtomic: () => {}, mtimeMs: () => null }
    expect(fingerprintFleetToken('/x', io)).toBeNull()
  })
})

describe('launch registry', () => {
  it('records a stamp, reads it back, and writes the file 0600', () => {
    const c = fresh()
    const fp = sha16(canary('a'))
    expect(recordLaunch('agent:dev', fp, 1234, c.reg)).toEqual({ ok: true })
    expect(launchFingerprint('agent:dev', c.reg)).toBe(fp)
    expect(readLaunchRegistry(c.reg)['agent:dev']).toEqual({ fp, at: 1234 })
    expect(statSync(c.reg).mode & 0o777).toBe(0o600)
  })

  it('stays 0600 after a rewrite, and leaves no tmp file behind', () => {
    const c = fresh()
    recordLaunch('agent:dev', sha16('x'), 1, c.reg)
    chmodSync(c.reg, 0o644) // someone loosened it; the next atomic write restores 0600
    recordLaunch('worker:brainy-worker', sha16('y'), 2, c.reg)
    expect(statSync(c.reg).mode & 0o777).toBe(0o600)
    expect(readdirSync(c.dir).filter((f) => f.endsWith('.tmp'))).toEqual([])
    expect(Object.keys(readLaunchRegistry(c.reg)).sort()).toEqual(['agent:dev', 'worker:brainy-worker'])
  })

  it('a re-stamp replaces the old fingerprint; clearLaunch removes it', () => {
    const c = fresh()
    recordLaunch('agent:dev', sha16('x'), 1, c.reg)
    recordLaunch('agent:dev', sha16('y'), 2, c.reg)
    expect(launchFingerprint('agent:dev', c.reg)).toBe(sha16('y'))
    expect(clearLaunch('agent:dev', c.reg)).toEqual({ ok: true })
    expect(launchFingerprint('agent:dev', c.reg)).toBeNull()
    expect(clearLaunch('agent:never', c.reg)).toEqual({ ok: true }) // no-op
  })

  it('rejects a malformed key or fingerprint with a fixed error and writes nothing', () => {
    const c = fresh()
    expect(recordLaunch('dev', sha16('x'), 1, c.reg)).toEqual({ ok: false, error: 'fleet token launch key invalid' })
    expect(recordLaunch('agent:../etc', sha16('x'), 1, c.reg)).toMatchObject({ ok: false })
    expect(recordLaunch('agent:dev', 'not-a-fingerprint', 1, c.reg)).toEqual({ ok: false, error: 'fleet token fingerprint invalid' })
    expect(recordLaunch('agent:dev', canary('a'), 1, c.reg)).toMatchObject({ ok: false }) // a raw token is not a fingerprint
    expect(() => readFileSync(c.reg)).toThrow()
    expect(isLaunchKey('agent:dev')).toBe(true)
    expect(isLaunchKey('worker:brainy-worker-fast')).toBe(true)
    expect(isLaunchKey('main:dev')).toBe(false)
  })

  it('reading is tolerant: missing, garbage, wrong shape and bad entries are dropped', () => {
    const c = fresh()
    expect(readLaunchRegistry(c.reg)).toEqual({})
    writeFileSync(c.reg, '{not json')
    expect(readLaunchRegistry(c.reg)).toEqual({})
    writeFileSync(c.reg, JSON.stringify({ v: 1, entries: [1, 2] }))
    expect(readLaunchRegistry(c.reg)).toEqual({})
    writeFileSync(c.reg, JSON.stringify({
      v: 1,
      entries: {
        'agent:ok': { fp: sha16('x'), at: 5 },
        'agent:bad-fp': { fp: canary('a'), at: 5 },
        'agent:bad-at': { fp: sha16('x'), at: 'now' },
        'nope:x': { fp: sha16('x'), at: 5 },
        '__proto__': { fp: sha16('x'), at: 5 },
      },
    }))
    expect(Object.keys(readLaunchRegistry(c.reg))).toEqual(['agent:ok'])
  })

  it('a failing write returns a fixed string that carries no exception text', () => {
    const io: FleetTokenIO = {
      readFile: () => { throw new Error('ENOENT') },
      writeAtomic: () => { throw new Error(`EACCES /store/${canary('leak')}`) },
      mtimeMs: () => null,
    }
    const r = recordLaunch('agent:dev', sha16('x'), 1, '/x/reg.json', io)
    expect(r).toEqual({ ok: false, error: 'fleet token launch registry write failed' })
    expect(JSON.stringify(r)).not.toContain(canary('leak'))
  })
})

describe('fleetTokenState', () => {
  it('current / stale / unknown', () => {
    const a = sha16('a')
    const b = sha16('b')
    expect(fleetTokenState(a, a)).toBe('current')
    expect(fleetTokenState(a, b)).toBe('stale')
    expect(fleetTokenState(null, b)).toBe('unknown') // started before the stamping deploy
    expect(fleetTokenState(undefined, b)).toBe('unknown')
    expect(fleetTokenState(a, null)).toBe('unknown') // empty / half-written token file never means stale
  })

  it('end to end on real files: swap makes it stale, re-stamp makes it current again', () => {
    const c = fresh()
    writeFileSync(c.token, canary('old'))
    recordLaunch('agent:dev', fingerprintFleetToken(c.token) as string, 1, c.reg)
    expect(fleetTokenStateFor('agent:dev', c.token, c.reg)).toBe('current')
    writeFileSync(c.token, canary('new'))
    expect(fleetTokenStateFor('agent:dev', c.token, c.reg)).toBe('stale')
    writeFileSync(c.token, '')
    expect(fleetTokenStateFor('agent:dev', c.token, c.reg)).toBe('unknown')
    writeFileSync(c.token, canary('new'))
    recordLaunch('agent:dev', fingerprintFleetToken(c.token) as string, 2, c.reg)
    expect(fleetTokenStateFor('agent:dev', c.token, c.reg)).toBe('current')
    expect(fleetTokenStateFor('agent:nostamp', c.token, c.reg)).toBe('unknown')
  })

  it('createdAfterTokenChange is a label-only estimate', () => {
    expect(createdAfterTokenChange(2000, 1000)).toBe(true)
    expect(createdAfterTokenChange(1000, 2000)).toBe(false)
    expect(createdAfterTokenChange(null, 1000)).toBe(false)
    expect(createdAfterTokenChange(1000, null)).toBe(false)
  })
})

describe('the token never leaks', () => {
  it('canary token is absent from the registry file, return values and the logger', () => {
    const spies = (['trace', 'debug', 'info', 'warn', 'error', 'fatal'] as const).map((l) => vi.spyOn(logger, l))
    const c = fresh()
    const tok = canary('secret')
    writeFileSync(c.token, tok)
    const fp = fingerprintFleetToken(c.token) as string
    const results = [
      fp,
      recordLaunch('agent:dev', fp, 1, c.reg),
      recordLaunch('worker:brainy-worker', fp, 2, c.reg),
      clearLaunch('agent:gone', c.reg),
      launchFingerprint('agent:dev', c.reg),
      readLaunchRegistry(c.reg),
      fleetTokenStateFor('agent:dev', c.token, c.reg),
      fleetTokenState(fp, null),
    ]
    expect(JSON.stringify(results)).not.toContain(tok)
    expect(readFileSync(c.reg, 'utf-8')).not.toContain(tok)
    // The registry holds the 16-hex fingerprint only, never the full hash.
    const full = createHash('sha256').update(tok, 'utf8').digest('hex')
    expect(readFileSync(c.reg, 'utf-8')).not.toContain(full)
    expect(readFileSync(c.reg, 'utf-8')).toContain(fp)
    for (const s of spies) expect(s).not.toHaveBeenCalled()
    for (const s of spies) s.mockRestore()
  })

  it('the module imports no logger and builds no message from an exception', () => {
    const src = readFileSync(join(__dirname, '..', 'web', 'fleet-token-fingerprint.ts'), 'utf-8')
    expect(src).not.toMatch(/from '\.\.\/logger\.js'/)
    expect(src).not.toMatch(/console\./)
    expect(src).not.toMatch(/\berr(or)?\.message\b/)
  })

  it('the side-car is a known system file for the store watcher, not a sensitive one', () => {
    const src = readFileSync(join(__dirname, '..', 'store-watcher.ts'), 'utf-8')
    const system = src.slice(src.indexOf('const SYSTEM_FILES'), src.indexOf('const SYSTEM_RE'))
    const sensitive = src.slice(src.indexOf('const SENSITIVE_NAMES'), src.indexOf('// --- Agent attribution slot'))
    expect(system).toContain("'fleet-token-launch.json'")
    expect(sensitive).not.toContain('fleet-token-launch.json')
  })
})
