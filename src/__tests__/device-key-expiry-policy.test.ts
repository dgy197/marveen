// Card 053f4e66 B, E1-E7 / R1-R2: a device key minted over the HTTP API always
// expires. Contract under test:
//   - a full key (no scope, or scope 'full') defaults to 90 days and lives at
//     most 365; an explicit "no expiry" (null, 0) is a 400, as it already was
//     for an operator key; the operator rule is unchanged;
//   - no 201 from POST /api/auth/device-keys ever carries expires_at: null, for
//     any input, scope or admitted caller (token with the switch open, session);
//   - the full ceiling never exceeds the operator ceiling (the full key reaches
//     more, so it must not outlive the weaker one);
//   - Bridge pairing still mints its key without an expiry (K1 = a), and is only
//     reachable behind the credential-admin gate (credential-admin-gate.test.ts);
//   - nothing is retroactive: keys stored before this rule (no expiry, or one
//     longer than the new ceiling) resolve, list and survive the sweep exactly
//     as before, and no new UPDATE/DELETE/ALTER on the credential tables exists.
//
// The token caller needs the install .env switch open
// (BEARER_CREDENTIAL_ADMIN_ENABLED=1, credential-admin.ts), so this file runs
// against a throwaway install whose .env opens it. CLAUDECLAW_ENV_DIR must be
// set before any app module loads. The owner notification of a token mint is
// stubbed: it must never reach a live channel from a test.
import { describe, it, expect, beforeAll, beforeEach, afterEach, vi } from 'vitest'
import type http from 'node:http'
import { Readable } from 'node:stream'
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash, randomBytes, randomUUID } from 'node:crypto'

const ENV = await vi.hoisted(async () => {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'device-key-expiry-env-')))
  process.env.CLAUDECLAW_ENV_DIR = dir
  for (const k of ['BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE']) delete process.env[k]
  return { file: path.join(dir, '.env') }
})
vi.mock('../notify.js', () => ({
  notifyChannel: vi.fn(async () => {}),
  notifyTelegram: vi.fn(async () => {}),
  notifySecurityEvent: vi.fn(async () => {}),
}))

import { initDatabase, getDb } from '../db.js'
import { tryHandleAuth } from '../web/routes/auth.js'
import {
  resolveDeviceKey,
  listDeviceKeys,
  sweepExpiredDeviceKeys,
  findDeviceKeyByInstallId,
  _clearDeviceKeyCacheForTest,
  FULL_KEY_DEFAULT_EXPIRY_DAYS,
  FULL_KEY_MAX_EXPIRY_DAYS,
  OPERATOR_KEY_DEFAULT_EXPIRY_DAYS,
  OPERATOR_KEY_MAX_EXPIRY_DAYS,
  type DeviceKeyInfo,
} from '../web/auth-device-keys.js'
import { bridgeEnroll } from '../web/bridge-enroll.js'
import type { RouteContext } from '../web/routes/types.js'

const DAY = 86400
const TOKEN_AUTH: RouteContext['auth'] = { kind: 'token' }
const SESSION_AUTH: RouteContext['auth'] = { kind: 'session', user: 'op' }
const CALLERS: Array<[string, RouteContext['auth']]> = [['token (switch open)', TOKEN_AUTH], ['session', SESSION_AUTH]]

function nowSec(): number {
  return Math.floor(Date.now() / 1000)
}

function rowCount(): number {
  return (getDb().prepare('SELECT COUNT(*) AS c FROM device_keys').get() as { c: number }).c
}

// `raw` is sent byte for byte: JSON.stringify cannot produce 1e309 (it writes
// Infinity as null), and that literal is exactly the case to pin.
async function mint(auth: RouteContext['auth'], body: Record<string, unknown> | { raw: string }): Promise<{ status: number; body: Record<string, any> }> {
  const text = 'raw' in body && typeof body.raw === 'string' ? body.raw : JSON.stringify(body)
  const req = Readable.from([Buffer.from(text)]) as unknown as http.IncomingMessage
  req.headers = { 'content-type': 'application/json' }
  const out = { status: 0, text: '' }
  const res = {
    setHeader() { return res },
    writeHead(s: number) { out.status = s; return res },
    end(c?: string) { if (c) out.text += c },
  }
  const path = '/api/auth/device-keys'
  const ctx: RouteContext = { req, res: res as unknown as http.ServerResponse, path, method: 'POST', url: new URL(`http://127.0.0.1:3420${path}`), auth }
  expect(await tryHandleAuth(ctx)).toBe(true)
  return { status: out.status, body: JSON.parse(out.text || '{}') }
}

beforeAll(() => {
  process.env.NODE_ENV = 'test'
  initDatabase(':memory:')
})

beforeEach(() => {
  writeFileSync(ENV.file, 'BEARER_CREDENTIAL_ADMIN_ENABLED=1\n')
  _clearDeviceKeyCacheForTest()
  getDb().prepare('DELETE FROM device_keys').run()
})

describe('the expiry constants (D5, E6)', () => {
  it('a full key defaults to 90 days and lives at most 365', () => {
    expect(FULL_KEY_DEFAULT_EXPIRY_DAYS).toBe(90)
    expect(FULL_KEY_MAX_EXPIRY_DAYS).toBe(365)
    expect(FULL_KEY_DEFAULT_EXPIRY_DAYS).toBeGreaterThan(0)
    expect(FULL_KEY_DEFAULT_EXPIRY_DAYS).toBeLessThanOrEqual(FULL_KEY_MAX_EXPIRY_DAYS)
  })
  it('the full key, which reaches more, never outlives the operator key (E6)', () => {
    expect(FULL_KEY_MAX_EXPIRY_DAYS).toBeLessThanOrEqual(OPERATOR_KEY_MAX_EXPIRY_DAYS)
  })
  it('the old 3650-day full ceiling is gone from the route', () => {
    const src = readFileSync(join(dirname(fileURLToPath(import.meta.url)), '..', 'web', 'routes', 'auth.ts'), 'utf8')
    expect(src).not.toMatch(/\b3650\b/)
    expect(src).not.toContain('DEVICE_KEY_MAX_EXPIRY_DAYS')
  })
})

describe.each(CALLERS)('a full key minted by %s (E1-E3)', (_label, auth) => {
  for (const scope of [undefined, 'full'] as const) {
    const withScope = (extra: Record<string, unknown>) => (scope === undefined ? { name: 'phone', ...extra } : { name: 'phone', scope, ...extra })

    it(`scope ${scope ?? '(absent)'}: no expires_in_days -> 90 days`, async () => {
      const before = nowSec()
      const r = await mint(auth, withScope({}))
      expect(r.status).toBe(201)
      expect(r.body.scope).toBe('full')
      expect(r.body.expires_at - r.body.created_at).toBe(90 * DAY)
      expect(Math.abs(r.body.expires_at - (before + 90 * DAY))).toBeLessThanOrEqual(5)
      expect(listDeviceKeys()[0]!.expiresAt).toBe(r.body.expires_at)
    })

    it(`scope ${scope ?? '(absent)'}: null and 0 ("no expiry") are a 400, no row`, async () => {
      for (const v of [null, 0]) {
        const r = await mint(auth, withScope({ expires_in_days: v }))
        expect(r.status).toBe(400)
        expect(r.body).toEqual({ error: 'A full key must expire' })
        expect(rowCount()).toBe(0)
      }
    })

    it(`scope ${scope ?? '(absent)'}: "0", -1, "abc" and 1e309 are a 400, no row`, async () => {
      for (const v of ['0', -1, 'abc']) {
        const r = await mint(auth, withScope({ expires_in_days: v }))
        expect(r.status).toBe(400)
        expect(r.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
        expect(rowCount()).toBe(0)
      }
      const scopePart = scope === undefined ? '' : `,"scope":"${scope}"`
      const inf = await mint(auth, { raw: `{"name":"phone"${scopePart},"expires_in_days":1e309}` })
      expect(inf.status).toBe(400)
      expect(inf.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
      expect(rowCount()).toBe(0)
    })

    it(`scope ${scope ?? '(absent)'}: below one day (0.001, 1e-9, 0.5, 0.999) is a 400, no row`, async () => {
      for (const v of [0.001, 1e-9, 0.5, 0.999]) {
        const r = await mint(auth, withScope({ expires_in_days: v }))
        expect(r.status, `expires_in_days=${v}`).toBe(400)
        expect(r.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
        expect(rowCount()).toBe(0)
      }
    })

    it(`scope ${scope ?? '(absent)'}: 1, 30 and 365 days are honoured`, async () => {
      for (const days of [1, 30, 365]) {
        const r = await mint(auth, withScope({ expires_in_days: days }))
        expect(r.status).toBe(201)
        expect(r.body.expires_at - r.body.created_at).toBe(days * DAY)
      }
      expect(rowCount()).toBe(3)
    })

    it(`scope ${scope ?? '(absent)'}: 366 and 3650 are past the ceiling, a 400, no row`, async () => {
      for (const days of [366, 3650]) {
        const r = await mint(auth, withScope({ expires_in_days: days }))
        expect(r.status).toBe(400)
        expect(r.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
      }
      expect(rowCount()).toBe(0)
    })
  }
})

describe.each(CALLERS)('an operator key minted by %s keeps its rule (E5)', (_label, auth) => {
  it('absent -> 90 days; null / 0 -> 400; 365 -> 201; 366 -> 400', async () => {
    const dflt = await mint(auth, { name: 'it-op', scope: 'operator' })
    expect(dflt.status).toBe(201)
    expect(dflt.body.expires_at - dflt.body.created_at).toBe(90 * DAY)
    for (const v of [null, 0]) {
      const r = await mint(auth, { name: 'it-op', scope: 'operator', expires_in_days: v })
      expect(r.status).toBe(400)
      expect(r.body).toEqual({ error: 'An operator key must expire' })
    }
    const max = await mint(auth, { name: 'it-op', scope: 'operator', expires_in_days: 365 })
    expect(max.status).toBe(201)
    expect(max.body.expires_at - max.body.created_at).toBe(365 * DAY)
    const over = await mint(auth, { name: 'it-op', scope: 'operator', expires_in_days: 366 })
    expect(over.status).toBe(400)
    expect(over.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
    expect(rowCount()).toBe(2)
  })

  it('below one day (0.001, 1e-9, 0.5) is a 400, like every other out-of-range value', async () => {
    for (const v of [0.001, 1e-9, 0.5]) {
      const r = await mint(auth, { name: 'it-op', scope: 'operator', expires_in_days: v })
      expect(r.status, `expires_in_days=${v}`).toBe(400)
      expect(r.body).toEqual({ error: 'Invalid expires_in_days (1-365)' })
    }
    expect(rowCount()).toBe(0)
  })
})

describe('no 201 ever carries expires_at: null (E4)', () => {
  // Every JSON shape the Number() reading could meet, the table's inputs first.
  const INPUTS: Array<[string, string | undefined]> = [
    ['absent', undefined], ['null', 'null'], ['0', '0'], ['-0', '-0'], ['"0"', '"0"'], ['-1', '-1'],
    ['"abc"', '"abc"'], ['1e309', '1e309'], ['-1e309', '-1e309'], ['1', '1'], ['30', '30'], ['365', '365'],
    ['366', '366'], ['3650', '3650'], ['0.5', '0.5'], ['1e-9', '1e-9'], ['0.001', '0.001'], ['0.999', '0.999'],
    ['1.5', '1.5'], ['365.5', '365.5'], ['1e308', '1e308'],
    ['"30"', '"30"'], ['" 30 "', '" 30 "'], ['""', '""'], ['" "', '" "'], ['"0x10"', '"0x10"'], ['"Infinity"', '"Infinity"'],
    ['"NaN"', '"NaN"'], ['true', 'true'], ['false', 'false'], ['[]', '[]'], ['[5]', '[5]'], ['[0]', '[0]'],
    ['{}', '{}'], ['"1e309"', '"1e309"'],
  ]
  const SCOPES = [undefined, 'full', 'operator'] as const

  it('across every input, both scopes and both admitted callers', async () => {
    let created = 0
    let refused = 0
    for (const [, auth] of CALLERS) {
      for (const scope of SCOPES) {
        const max = scope === 'operator' ? OPERATOR_KEY_MAX_EXPIRY_DAYS : FULL_KEY_MAX_EXPIRY_DAYS
        for (const [label, literal] of INPUTS) {
          const parts = ['"name":"prop"']
          if (scope !== undefined) parts.push(`"scope":"${scope}"`)
          if (literal !== undefined) parts.push(`"expires_in_days":${literal}`)
          const before = rowCount()
          const r = await mint(auth, { raw: `{${parts.join(',')}}` })
          const where = `${auth!.kind} scope=${scope ?? '(absent)'} expires_in_days=${label}`
          if (r.status === 201) {
            created++
            expect(r.body.expires_at, where).not.toBeNull()
            expect(Number.isInteger(r.body.expires_at), where).toBe(true)
            expect(r.body.expires_at, where).toBeGreaterThanOrEqual(r.body.created_at)
            // At least one day (BB3): a sub-day value is a 400, not a key that dies at once.
            expect(r.body.expires_at - r.body.created_at, where).toBeGreaterThanOrEqual(DAY)
            expect(r.body.expires_at - r.body.created_at, where).toBeLessThanOrEqual(max * DAY)
            expect(rowCount(), where).toBe(before + 1)
          } else {
            refused++
            expect(r.status, where).toBe(400)
            expect(r.body, where).not.toHaveProperty('key')
            expect(rowCount(), where).toBe(before)
          }
        }
      }
    }
    // Not vacuous: both branches ran.
    expect(created).toBeGreaterThan(20)
    expect(refused).toBeGreaterThan(20)
    // And the store agrees with the responses: no stored row without an end date.
    expect(getDb().prepare('SELECT COUNT(*) AS c FROM device_keys WHERE expires_at IS NULL').get()).toEqual({ c: 0 })
  })
})

describe('Bridge pairing still mints a key without an expiry (E7, K1 = a)', () => {
  let sshDir: string
  beforeEach(() => { sshDir = mkdtempSync(join(tmpdir(), 'device-key-expiry-ssh-')) })
  afterEach(() => { rmSync(sshDir, { recursive: true, force: true }) })

  it('bridgeEnroll with injected deps and the real createDeviceKey', async () => {
    const installId = randomUUID()
    const type = Buffer.from('ssh-ed25519', 'utf8')
    const blob = Buffer.concat([Buffer.from([0, 0, 0, type.length]), type, Buffer.from([0, 0, 0, 32]), randomBytes(32)])
    const hostKey = Buffer.concat([Buffer.from([0, 0, 0, 11]), type, Buffer.from([0, 0, 0, 32]), randomBytes(32)]).toString('base64')
    const outcome = await bridgeEnroll(
      { keyLine: `ssh-ed25519 ${blob.toString('base64')} marveen-remote:${installId}`, name: 'Bridge laptop' },
      { sshDir, readFile: () => null, keyscan: async () => `127.0.0.1 ssh-ed25519 ${hostKey}` },
    )
    expect(outcome.installId).toBe(installId)
    const key = findDeviceKeyByInstallId(outcome.installId)
    expect(key).not.toBeNull()
    expect(key!.id).toBe(outcome.deviceKeyId)
    expect(key!.scope).toBe('full')
    // Deliberate (K1 = a): changing this is a decision, not a side effect.
    expect(key!.expiresAt).toBeNull()
  })
})

describe('nothing is retroactive (R1, R2)', () => {
  // Rows as an older build stored them: written with SQL, not through today's
  // createDeviceKey, so the new rule cannot have shaped them.
  function seed(name: string, expiresAt: number | null, scope: 'full' | 'operator', installId: string | null): { id: number; raw: string } {
    const raw = 'mvdk_' + randomBytes(32).toString('base64url')
    const hash = createHash('sha256').update(raw).digest('hex')
    const created = nowSec() - 400 * DAY
    const info = getDb()
      .prepare('INSERT INTO device_keys (key_hash, name, created_at, last_used_at, expires_at, install_id, scope) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(hash, name, created, null, expiresAt, installId, scope)
    return { id: Number(info.lastInsertRowid), raw }
  }

  it('old keys resolve, list and survive the sweep the same before and after new mints', async () => {
    const now = nowSec()
    const old = [
      seed('GYURI WINDOWS', null, 'full', `marveen-remote:${randomUUID()}`), // Bridge key, no expiry
      seed('api-no-expiry', null, 'full', null), // pre-rule API mint, no expiry
      seed('api-3000d', now + 3000 * DAY, 'full', null), // longer than the new 365-day ceiling
      seed('api-2', now + 5 * DAY, 'full', null), // expiring soon, still valid
      seed('it-op', now + 30 * DAY, 'operator', null),
    ]
    const oldIds = new Set(old.map(o => o.id))
    const snapshot = (): DeviceKeyInfo[] => listDeviceKeys().filter(k => oldIds.has(k.id)).sort((a, b) => a.id - b.id)

    for (const o of old) expect(resolveDeviceKey(o.raw)?.id).toBe(o.id)
    const before = snapshot()
    expect(before.map(k => k.expiresAt)).toEqual([null, null, now + 3000 * DAY, now + 5 * DAY, now + 30 * DAY])
    expect(sweepExpiredDeviceKeys()).toBe(0)

    // New mints under the new rule, accepted and refused, by both callers.
    for (const [, auth] of CALLERS) {
      expect((await mint(auth, { name: 'new-default' })).status).toBe(201)
      expect((await mint(auth, { name: 'new-null', expires_in_days: null })).status).toBe(400)
      expect((await mint(auth, { name: 'new-3650', expires_in_days: 3650 })).status).toBe(400)
      expect((await mint(auth, { name: 'new-op', scope: 'operator' })).status).toBe(201)
    }

    _clearDeviceKeyCacheForTest() // a restart: the old rows come back from SQLite
    for (const o of old) expect(resolveDeviceKey(o.raw)?.id).toBe(o.id)
    expect(snapshot()).toEqual(before)
    expect(sweepExpiredDeviceKeys()).toBe(0)
    expect(snapshot()).toEqual(before)
    expect(rowCount()).toBe(old.length + 4)
  })
})

describe('no new UPDATE / DELETE / ALTER on the credential tables (R1, static)', () => {
  const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')
  function sourceFiles(dir: string): string[] {
    const out: string[] = []
    for (const name of readdirSync(dir)) {
      const p = join(dir, name)
      if (statSync(p).isDirectory()) {
        if (name !== '__tests__') out.push(...sourceFiles(p))
      } else if (/\.(ts|mts|cts|js|mjs)$/.test(name) && !/\.test\./.test(name)) {
        out.push(p)
      }
    }
    return out
  }

  it('the statements are exactly today\'s, file by file', () => {
    const re = /\b(UPDATE|DELETE\s+FROM|ALTER\s+TABLE|DROP\s+TABLE(\s+IF\s+EXISTS)?)\s+(device_keys|dashboard_users|auth_sessions)\b[^'`"]*/gi
    const found: Record<string, string[]> = {}
    for (const p of sourceFiles(SRC)) {
      const hits = readFileSync(p, 'utf8').match(re)
      if (hits) found[relative(SRC, p).split(sep).join('/')] = hits.map(h => h.replace(/\s+/g, ' ').trim())
    }
    expect(found).toEqual({
      'db.ts': [
        'ALTER TABLE device_keys ADD COLUMN install_id TEXT',
        'ALTER TABLE device_keys ADD COLUMN scope TEXT NOT NULL DEFAULT',
        'UPDATE dashboard_users SET password_hash = ?, updated_at = ? WHERE id = ?',
        'DELETE FROM dashboard_users WHERE username = ? COLLATE NOCASE',
      ],
      'web/auth-sessions.ts': [
        'DELETE FROM auth_sessions WHERE id_hash = ?',
        'UPDATE auth_sessions SET last_seen_at = ? WHERE id_hash = ?',
        'DELETE FROM auth_sessions WHERE user_id = ? AND id_hash != ?',
        'DELETE FROM auth_sessions WHERE user_id = ?',
        'DELETE FROM auth_sessions',
        'DELETE FROM auth_sessions WHERE last_seen_at < ? OR created_at < ?',
      ],
      'web/auth-device-keys.ts': [
        'DELETE FROM device_keys WHERE key_hash = ?',
        'UPDATE device_keys SET last_used_at = ? WHERE key_hash = ?',
        'DELETE FROM device_keys WHERE id = ?',
        'DELETE FROM device_keys',
        'DELETE FROM device_keys WHERE expires_at IS NOT NULL AND expires_at < ?',
      ],
    })
  })
})
