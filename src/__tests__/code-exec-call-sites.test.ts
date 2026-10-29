// Card 89df7a00: an inventory of where the code-exec gate (code-exec-admin.ts)
// and its switch live. The same idea as credential-call-sites.test.ts: the
// protected key name appears under src/ only in the definition (admin-switch.ts)
// and the gate (code-exec-admin.ts), never in config.ts, the settings registry
// or any other module a Bearer-reachable writer could use, and the gate reuses
// the credential gate's bare-token rule instead of copying it.
//
// N1 pinned the switch name and the gate module. N2 adds the connector routes:
// the `claude mcp` and git/npm exec sites of connectors.ts and
// dashboard-settings.ts, and one admitCodeExecAdmin call per action. The pins
// for command-task.ts, the writeScheduledTask and .mcp.json writers and the
// remaining actions are added by the nodes that wire those routes (N3, N4).

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

describe('connectors.ts: every route that reaches `claude mcp add` or a clone is gated (N2, G1/G10)', () => {
  const code = () => codeLines(file('web/routes/connectors.ts').text).join('\n')

  it('`claude mcp add` is reached from exactly four call sites; a new one turns this red', () => {
    expect(code().match(/await runClaudeMcp\(/g)).toHaveLength(4)
    // definition, the serialising wrapper, and the two uninstall `mcp remove` calls
    expect(code().match(/execClaudeMcp\(/g)).toHaveLength(4)
    expect(code().match(/\bspawn(Sync)?\(|\bexecSync\(|\bexecFileSync\(/g) ?? []).toHaveLength(0)
  })

  it('dashboard-settings.ts runs git and npm from a fixed set of sites', () => {
    const c = codeLines(file('web/dashboard-settings.ts').text).join('\n')
    expect(c.match(/\bexecFileSync\(/g)).toHaveLength(3)
    expect(c.match(/\bexecSync\(/g)).toHaveLength(2)
    expect(c.match(/\bspawn(Sync)?\(/g) ?? []).toHaveLength(0)
  })

  it('the four entry points each call the gate once, under their own action, behind execGateApplies', () => {
    const c = code()
    for (const action of ['connectors.add', 'mcp_catalog.install', 'connectors.github_repo.add', 'connectors.github_repo.update']) {
      expect(c.match(new RegExp(`admitCodeExecAdmin\\(ctx, '${action.replace(/\./g, '\\.')}'\\)`, 'g')), action).toHaveLength(1)
    }
    expect(c.match(/admitCodeExecAdmin\(/g)).toHaveLength(4)
    expect(c.match(/execGateApplies\(ctx\.auth, req\)/g)).toHaveLength(4)
  })

  it('the gate stands before the first body read or catalog lookup of its handler', () => {
    const lines = codeLines(file('web/routes/connectors.ts').text)
    const handlers: Array<[string, string]> = [
      ['connectors.add', "path === '/api/connectors' && method === 'POST'"],
      ['mcp_catalog.install', "catalogInstallMatch && method === 'POST'"],
      ['connectors.github_repo.add', "path === '/api/connectors/github-repos' && method === 'POST'"],
      ['connectors.github_repo.update', "githubRepoMatch && method === 'PATCH'"],
    ]
    for (const [action, header] of handlers) {
      const head = lines.findIndex(l => l.includes(header))
      const gate = lines.findIndex(l => l.includes(`admitCodeExecAdmin(ctx, '${action}')`))
      const firstRead = lines.findIndex((l, i) => i > head && /readBody\(|loadMcpCatalog\(/.test(l))
      expect(head, `${action}: handler found`).toBeGreaterThan(-1)
      expect(gate, `${action}: gate inside the handler`).toBeGreaterThan(head)
      expect(firstRead, `${action}: gate before the first read`).toBeGreaterThan(gate)
    }
  })

  it('imports the gate from code-exec-admin.js and never reads the switch itself', () => {
    const c = code()
    expect(c).toMatch(/from '\.\.\/code-exec-admin\.js'/)
    expect(c).not.toMatch(/isAdminSwitchOn|BEARER_CODE_EXEC|readEnvFile/)
  })
})
