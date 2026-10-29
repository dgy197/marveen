// Card 89df7a00: an inventory of where the code-exec gate (code-exec-admin.ts)
// and its switch live. The same idea as credential-call-sites.test.ts: the
// protected key name appears under src/ only in the definition (admin-switch.ts)
// and the gate (code-exec-admin.ts), never in config.ts, the settings registry
// or any other module a Bearer-reachable writer could use, and the gate reuses
// the credential gate's bare-token rule instead of copying it.
//
// Node N1 pins only that. The route call-site pins (the exec/spawn sites of
// connectors.ts, dashboard-settings.ts and command-task.ts, the
// writeScheduledTask and .mcp.json writers, and the admitCodeExecAdmin calls
// per action) are added by the nodes that wire the gate into those routes.

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
const file = (rel: string) => FILES.find(f => f.rel === rel)!

// A line that is only a comment does not count; anything else does.
function codeLines(text: string): string[] {
  return text.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l))
}

describe('the code-exec switch key name lives only in the gate (SW2)', () => {
  const KEY = 'BEARER_CODE_EXEC_ADMIN_ENABLED'

  it('appears under src/ only in admin-switch.ts and code-exec-admin.ts', () => {
    const where = FILES.filter(f => f.text.includes(KEY)).map(f => f.rel).sort()
    expect(where).toEqual(['web/admin-switch.ts', 'web/code-exec-admin.ts'])
    expect(file('web/admin-switch.ts').text).toContain(`'${KEY}'`)
  })

  it('is not in config.ts', () => {
    expect(file('config.ts').text).not.toContain(KEY)
  })

  it('no other module spells a lower-case or prefix-less variant of it', () => {
    const where = FILES.filter(f => /bearer_code_exec/i.test(f.text) && !['web/admin-switch.ts', 'web/code-exec-admin.ts'].includes(f.rel))
    expect(where.map(f => f.rel)).toEqual([])
  })

  it('the credential switch names do not appear in the code-exec gate (two switches, two keys)', () => {
    expect(file('web/code-exec-admin.ts').text).not.toMatch(/BEARER_CREDENTIAL_ADMIN/)
  })
})

describe('the gate module reuses the credential gate\'s bare-token rule', () => {
  it('imports bareTokenNeedsSwitch from routes/auth.js and does not read the session cookie itself', () => {
    const lines = codeLines(file('web/code-exec-admin.ts').text).join('\n')
    expect(lines).toMatch(/import \{ bareTokenNeedsSwitch \} from '\.\/routes\/auth\.js'/)
    expect(lines).not.toMatch(/resolveSession|SESSION_COOKIE_NAME|parseCookies|carriesOwnerSessionCookie/)
  })

  it('reads the switch only through isAdminSwitchOn (the .env, per request), never the environment or the config', () => {
    const lines = codeLines(file('web/code-exec-admin.ts').text).join('\n')
    expect(lines).toContain('isAdminSwitchOn(')
    expect(lines).not.toMatch(/process\.env|readEnvFile|cfg\(|config-overrides/)
  })
})
