// Card 053f4e66 B, G7 / D11: an inventory of every place under src/ that can
// issue a credential. The bearer-credential-admin gate (credential-admin.ts)
// sits in front of the routes that call these today; a NEW caller -- a new
// route, a new helper, an alias, a re-export -- would be a way around it. So
// the set is pinned here: any new reference, a vanished one or a new raw SQL
// writer of the credential tables turns this red, and the new issuing path
// becomes a review decision instead of an accident. scripts/dashboard-user.ts
// is not under src/ on purpose: whoever runs a command on the machine is the
// root credential (docs/dashboard-auth-recovery.md).
//
// Also S5: the three switch key names appear under src/ only in admin-switch.ts
// (the definition) and credential-admin.ts (the gate), never in config.ts, the
// settings registry or any other module a Bearer-reachable writer could use.

import { describe, it, expect } from 'vitest'
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { dirname, join, relative, sep } from 'node:path'
import { fileURLToPath } from 'node:url'

const SRC = join(dirname(fileURLToPath(import.meta.url)), '..')

function sourceFiles(dir: string): string[] {
  const out: string[] = []
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name === '__tests__') continue
      out.push(...sourceFiles(p))
    } else if (/\.(ts|mts|cts|js|mjs)$/.test(name) && !/\.test\./.test(name)) {
      out.push(p)
    }
  }
  return out
}

const FILES = sourceFiles(SRC).map(p => ({ rel: relative(SRC, p).split(sep).join('/'), text: readFileSync(p, 'utf8') }))

// A line that is only a comment does not count; anything else does (import,
// call, alias, re-export, property access).
function codeLines(text: string): string[] {
  return text.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l))
}

const MINTERS = ['createDashboardUser', 'createDeviceKey', 'updateDashboardUserPassword', 'createSession'] as const

describe('credential issuers under src/ (G7, D11)', () => {
  it('every reference to a minting function is one of today\'s, file by file', () => {
    const found: Record<string, Record<string, number>> = {}
    for (const f of FILES) {
      for (const name of MINTERS) {
        const re = new RegExp(`\\b${name}\\b`, 'g')
        const n = codeLines(f.text).reduce((acc, l) => acc + (l.match(re)?.length ?? 0), 0)
        if (n > 0) (found[f.rel] ??= {})[name] = n
      }
    }
    expect(found).toEqual({
      // definitions
      'db.ts': { createDashboardUser: 1, updateDashboardUserPassword: 1 },
      'web/auth-sessions.ts': { createSession: 1 },
      'web/auth-device-keys.ts': { createDeviceKey: 1 },
      // import + call: Bridge pairing (gated in routes/security.ts)
      'web/bridge-enroll.ts': { createDeviceKey: 2 },
      // import + call each: login (session), first user, device key, password
      'web/routes/auth.ts': { createSession: 2, createDeviceKey: 2, createDashboardUser: 2, updateDashboardUserPassword: 2 },
    })
  })

  // Brainy 2097: rewriting an enrolled key's permitopen list widens an existing
  // credential, so the authorized_keys writers are pinned like the minters.
  // removeEnrolledKey (revocation) only narrows and is not listed.
  it('every reference to an SSH-grant writer (authorized_keys) is one of today\'s', () => {
    const WIDENERS = ['enrollAuthorizedKey', 'updateEnrolledServicePorts'] as const
    const found: Record<string, Record<string, number>> = {}
    for (const f of FILES) {
      for (const name of WIDENERS) {
        const re = new RegExp(`\\b${name}\\b`, 'g')
        const n = codeLines(f.text).reduce((acc, l) => acc + (l.match(re)?.length ?? 0), 0)
        if (n > 0) (found[f.rel] ??= {})[name] = n
      }
    }
    expect(found).toEqual({
      // definitions
      'remote-enroll-fs.ts': { enrollAuthorizedKey: 1, updateEnrolledServicePorts: 1 },
      // import + call: Bridge pairing (gated in routes/security.ts)
      'web/bridge-enroll.ts': { enrollAuthorizedKey: 2 },
      // import + call: PUT /api/bridge/service-ports (gated in the route itself)
      'web/routes/bridge-service-ports.ts': { updateEnrolledServicePorts: 2 },
    })
  })

  it('every route module that issues or widens a credential calls the gate', () => {
    for (const rel of ['web/routes/auth.ts', 'web/routes/security.ts', 'web/routes/bridge-service-ports.ts']) {
      const code = codeLines(FILES.find(f => f.rel === rel)!.text).join('\n')
      expect(code, rel).toMatch(/\badmitBearerCredentialAdmin\(ctx, '[a-z_.]+'\)/)
    }
  })

  it('the raw SQL writers of the credential tables are today\'s', () => {
    const writers: Record<string, number> = {}
    const re = /\b(INSERT\s+(OR\s+\w+\s+)?INTO|REPLACE\s+INTO)\s+(dashboard_users|device_keys|auth_sessions)\b|\bUPDATE\s+dashboard_users\s+SET\s+password_hash\b/gi
    for (const f of FILES) {
      const n = f.text.match(re)?.length ?? 0
      if (n > 0) writers[f.rel] = n
    }
    expect(writers).toEqual({
      'db.ts': 2, // INSERT INTO dashboard_users, UPDATE dashboard_users SET password_hash
      'web/auth-sessions.ts': 1,
      'web/auth-device-keys.ts': 1,
    })
  })
})

describe('the switch key names live only in the gate (S5)', () => {
  it.each(['BEARER_CREDENTIAL_ADMIN_ENABLED', 'BEARER_CREDENTIAL_ADMIN_UNTIL', 'BEARER_CREDENTIAL_ADMIN_NONCE'])('%s', (key) => {
    const where = FILES.filter(f => f.text.includes(key)).map(f => f.rel).sort()
    expect(where.length).toBeGreaterThan(0)
    for (const rel of where) expect(['web/admin-switch.ts', 'web/credential-admin.ts']).toContain(rel)
    expect(FILES.find(f => f.rel === 'web/admin-switch.ts')!.text).toContain(`'${key}'`)
    expect(FILES.find(f => f.rel === 'config.ts')!.text).not.toContain(key)
  })
})
