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
    for (const action of ['connectors.add', 'mcp_catalog.install', 'connectors.github_repo.add', 'connectors.github_repo.update', 'vault.bindings.add', 'connectors.external_paths.add']) {
      expect(c.match(new RegExp(`admitCodeExecAdmin\\(ctx, '${action.replace(/\./g, '\\.')}'\\)`, 'g')), action).toHaveLength(1)
    }
    expect(c.match(/admitCodeExecAdmin\(/g)).toHaveLength(6)
    expect(c.match(/execGateApplies\(ctx\.auth, req\)/g)).toHaveLength(6)
  })

  it('the gate stands before the first body read or catalog lookup of its handler', () => {
    const lines = codeLines(file('web/routes/connectors.ts').text)
    const handlers: Array<[string, string]> = [
      ['connectors.add', "path === '/api/connectors' && method === 'POST'"],
      ['mcp_catalog.install', "catalogInstallMatch && method === 'POST'"],
      ['connectors.github_repo.add', "path === '/api/connectors/github-repos' && method === 'POST'"],
      ['connectors.github_repo.update', "githubRepoMatch && method === 'PATCH'"],
      ['vault.bindings.add', "path === '/api/vault/bindings' && method === 'POST'"],
      ['connectors.external_paths.add', "path === '/api/connectors/external-paths' && method === 'POST'"],
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

describe('schedules.ts / agents.ts: the exec-field and .mcp.json writers are gated (N3, G2/G3/G10)', () => {
  const routeFiles = () => FILES.filter(f => f.rel.startsWith('web/routes/'))

  it('writeScheduledTask is called under web/routes/ only from schedules.ts, from exactly two sites (create: fixed fields; update: gated)', () => {
    const where = routeFiles().filter(f => /\bwriteScheduledTask\(/.test(codeLines(f.text).join('\n'))).map(f => f.rel)
    expect(where).toEqual(['web/routes/schedules.ts'])
    expect(codeLines(file('web/routes/schedules.ts').text).join('\n').match(/\bwriteScheduledTask\(/g)).toHaveLength(2)
  })

  it('the create handler passes no command/preCheck, so POST needs no gate', () => {
    const lines = codeLines(file('web/routes/schedules.ts').text)
    const start = lines.findIndex(l => l.includes("path === '/api/schedules' && method === 'POST'"))
    const end = lines.findIndex((l, i) => i > start && l.includes('scheduleUpdateMatch = '))
    expect(start).toBeGreaterThan(-1)
    expect(end).toBeGreaterThan(start)
    const create = lines.slice(start, end).join('\n')
    expect(create).toMatch(/writeScheduledTask\(name, \{/)
    expect(create).not.toMatch(/\bcommand\b|preCheck/)
  })

  it('the schedule PUT gates once, under its own action, after the body checks and before refuseIfForeign and the write', () => {
    const c = codeLines(file('web/routes/schedules.ts').text)
    const text = c.join('\n')
    expect(text.match(/admitCodeExecAdmin\(/g)).toHaveLength(1)
    expect(text).toMatch(/admitCodeExecAdmin\(ctx, 'schedules\.exec_fields'\)/)
    expect(text.match(/execGateApplies\(ctx\.auth, req\)/g)).toHaveLength(1)
    const idx = (re: RegExp) => c.findIndex(l => re.test(l))
    const preCheckType = idx(/preCheck must be a string/)
    const gate = idx(/admitCodeExecAdmin\(ctx, 'schedules\.exec_fields'\)/)
    const foreign = idx(/if \(refuseIfForeign\(res, name\)\) return true/)
    const write = idx(/const written = writeScheduledTask\(name, data\)/)
    expect(preCheckType).toBeGreaterThan(-1)
    expect(gate).toBeGreaterThan(preCheckType)
    expect(foreign).toBeGreaterThan(gate)
    expect(write).toBeGreaterThan(foreign)
  })

  it('the three exec triggers are all in the diff expression (command key, type -> command, preCheck change)', () => {
    const text = codeLines(file('web/routes/schedules.ts').text).join('\n')
    expect(text).toMatch(/hasKey\('command'\)/)
    expect(text).toMatch(/data\.type === 'command' && current\?\.type !== 'command'/)
    expect(text).toMatch(/hasKey\('preCheck'\) && normPre\(data\.preCheck\) !== normPre\(current\?\.preCheck\)/)
  })

  it('the only writer of a .mcp.json under web/routes/ is the agents PUT, behind the gate', () => {
    const writers = routeFiles().flatMap(f =>
      codeLines(f.text).filter(l => /\.mcp\.json/.test(l) && /atomicWriteFileSync|writeFileSync|renameSync|copyFileSync/.test(l)).map(l => `${f.rel}: ${l.trim()}`))
    expect(writers).toEqual(["web/routes/agents.ts: if (data.mcpJson !== undefined) atomicWriteFileSync(join(agentDir(name), '.mcp.json'), data.mcpJson)"])
  })

  it('the agents PUT gates mcpJson once, before the first write of the handler', () => {
    const c = codeLines(file('web/routes/agents.ts').text)
    const text = c.join('\n')
    expect(text.match(/admitCodeExecAdmin\(ctx, 'agents\.mcp_json'\)/g)).toHaveLength(1)
    const idx = (re: RegExp) => c.findIndex(l => re.test(l))
    const fields = idx(/checkAgentPutFields\(name, data\)/)
    const keyRefusal = idx(/interactiveKeyRefusalForAgentChange\(name, data\)/)
    const gate = idx(/admitCodeExecAdmin\(ctx, 'agents\.mcp_json'\)/)
    const firstWrite = idx(/writeAgentMemoryIsolation\(name, data\.memoryIsolation === true\)/)
    const mcpWrite = idx(/atomicWriteFileSync\(join\(agentDir\(name\), '\.mcp\.json'\)/)
    expect(fields).toBeGreaterThan(-1)
    expect(keyRefusal).toBeGreaterThan(-1)
    expect(gate).toBeGreaterThan(fields)
    expect(gate).toBeGreaterThan(keyRefusal)
    expect(firstWrite).toBeGreaterThan(gate)
    expect(mcpWrite).toBeGreaterThan(gate)
    expect(text).toMatch(/data\.mcpJson !== undefined && execGateApplies\(ctx\.auth, req\)/)
  })
})

describe('agents.ts: the bundle import replaces a whole agent dir behind the gate (N5, BE B1)', () => {
  it('bundle importers are called under web/routes/ only from agents.ts, once each, both with the admit callback', () => {
    const routeFiles = FILES.filter(f => f.rel.startsWith('web/routes/'))
    const where = routeFiles.filter(f => /\bimport(AgentBundle|AllAgentsBundle)\(/.test(codeLines(f.text).join('\n'))).map(f => f.rel)
    expect(where).toEqual(['web/routes/agents.ts'])
    const text = codeLines(file('web/routes/agents.ts').text).join('\n')
    expect(text.match(/\bimportAgentBundle\(bundle, \{[^}]*\badmit\b[^}]*\}\)/g)).toHaveLength(1)
    expect(text.match(/\bimportAllAgentsBundle\(bundle, \{[^}]*\badmit\b[^}]*\}\)/g)).toHaveLength(1)
    expect(text.match(/\bimport(AgentBundle|AllAgentsBundle)\(/g)).toHaveLength(2)
  })

  it('the importer asks admit before it removes or writes any agent dir', () => {
    const lines = codeLines(file('web/agent-bundle.ts').text)
    const idx = (re: RegExp, from = 0) => lines.findIndex((l, i) => i >= from && re.test(l))
    const single = idx(/^export function importAgentBundle\(/)
    const singleAdmit = idx(/opts\.admit\(\{ channelState: hasChannelState\(stagedAgentDir\), names: \[name\] \}\)/, single)
    const singleRm = idx(/installStagedAgent\(stagedAgentDir, dest, exists\)/, single)
    expect(singleAdmit).toBeGreaterThan(single)
    expect(singleRm).toBeGreaterThan(singleAdmit)
    const fleet = idx(/^export function importAllAgentsBundle\(/)
    const fleetAdmit = idx(/opts\.admit\(\{ channelState, names \}\)/, fleet)
    const fleetRm = idx(/installStagedAgent\(stagedAgentDir, dest, exists\)/, fleet)
    expect(fleetAdmit).toBeGreaterThan(fleet)
    expect(fleetRm).toBeGreaterThan(fleetAdmit)
  })

  it('D4: a NEW agent (bundle import, fleet bundle, fleet transfer) gets its settings from the default profile, an overwrite does not', () => {
    const agents = codeLines(file('web/routes/agents.ts').text).join('\n')
    const head = agents.indexOf("path === '/api/agents/import' && method === 'POST'")
    const importHandler = agents.slice(head)
    expect(importHandler).toMatch(/if \(!result\.overwritten\) writeAgentSettingsFromProfile\(result\.name, loadProfileTemplate\('default'\)\)/)
    expect(importHandler).toMatch(/if \(!a\.overwritten\) writeAgentSettingsFromProfile\(a\.name, loadProfileTemplate\('default'\)\)/)
    const fleet = codeLines(file('web/routes/fleet.ts').text).join('\n')
    expect(fleet).toMatch(/for \(const a of result\.imported\.newAgents\) writeAgentSettingsFromProfile\(a\.name, loadProfileTemplate\('default'\)\)/)
    // the transfer importer itself never writes the package's settings
    expect(codeLines(file('web/fleet-transfer.ts').text).join('\n')).not.toMatch(/JSON\.stringify\(agent\.settings/)
  })

  it('the import handler gates once under its own action, behind execGateApplies, before the body is read', () => {
    const c = codeLines(file('web/routes/agents.ts').text)
    const text = c.join('\n')
    expect(text.match(/admitCodeExecAdmin\(ctx, 'agents\.import'\)/g)).toHaveLength(1)
    expect(text).toMatch(/const importGated = execGateApplies\(ctx\.auth, req\)/)
    const head = c.findIndex(l => l.includes("path === '/api/agents/import' && method === 'POST'"))
    const gate = c.findIndex(l => l.includes("admitCodeExecAdmin(ctx, 'agents.import')"))
    const read = c.findIndex((l, i) => i > head && /readBody\(req\)/.test(l))
    expect(head).toBeGreaterThan(-1)
    expect(gate).toBeGreaterThan(head)
    expect(read).toBeGreaterThan(gate)
  })
})

// N6 (BE B2 / E3): the audit row and the notification are written BEFORE the first
// write of a gated operation (trail.start), and the outcome after (ok / failed). A
// recorder placed after the write is what left a half-done install without a trace.
describe('the audit start stands before the first write, the outcome after (N6, BE B2/E3)', () => {
  it('the importer admit starts the trail only after the channel gate, and the old post-hoc recordImport is gone', () => {
    const c = codeLines(file('web/routes/agents.ts').text)
    const text = c.join('\n')
    const idx = (re: RegExp, from = 0) => c.findIndex((l, i) => i >= from && re.test(l))
    expect(text).not.toMatch(/recordImport/)
    const head = idx(/path === '\/api\/agents\/import' && method === 'POST'/)
    const channelGate = idx(/channelCredentialGate\(ctx, 'agents\.import\.channel'\)/, head)
    const start = idx(/trail\.start\(/, head)
    const single = idx(/importAgentBundle\(bundle, /, head)
    expect(head).toBeGreaterThan(-1)
    expect(channelGate).toBeGreaterThan(head)
    expect(start).toBeGreaterThan(channelGate)
    expect(single).toBeGreaterThan(start)
    expect(text.match(/trail\.start\(/g)).toHaveLength(1)
    // ok only after the context-guard seed (both shapes), failed in the catch, a net in finally
    expect(text.match(/trail\.ok\(/g)).toHaveLength(2)
    const seeds = c.map((l, i) => (/seedContextGuardForNewAgent\(/.test(l) && i > head ? i : -1)).filter(i => i > -1)
    const oks = c.map((l, i) => (/trail\.ok\(/.test(l) ? i : -1)).filter(i => i > -1)
    expect(oks.every(o => seeds.some(s => s < o && o - s < 4))).toBe(true)
    expect(text.match(/trail\.failed\(/g)).toHaveLength(2)
  })

  it('connectors.ts records through the trail only: no direct recordCodeExecAdmin, no after-the-fact audit helper', () => {
    const text = codeLines(file('web/routes/connectors.ts').text).join('\n')
    expect(text).not.toMatch(/recordCodeExecAdmin|auditGatedInstall/)
    expect(text.match(/codeExecAuditTrail\(/g)).toHaveLength(5)
  })

  it('every `claude mcp add` of the install routes has trail.start on the line before it', () => {
    const c = codeLines(file('web/routes/connectors.ts').text)
    const adds = c.map((l, i) => (/await runClaudeMcp\(\['mcp', 'add'/.test(l) ? i : -1)).filter(i => i > -1)
    expect(adds).toHaveLength(4)
    for (const i of adds) expect(c[i - 1], c[i]).toMatch(/trail\.start\(/)
  })

  it('github add: the start stands before the first write (the vaulted env secret and the clone)', () => {
    const c = codeLines(file('web/routes/connectors.ts').text)
    const idx = (re: RegExp, from = 0) => c.findIndex((l, i) => i >= from && re.test(l))
    const head = idx(/path === '\/api\/connectors\/github-repos' && method === 'POST'/)
    const start = idx(/trail\.start\(/, head)
    const secret = idx(/setSecret\(vaultId/, head)
    const clone = idx(/installGitHubRepo\(/, head)
    expect(start).toBeGreaterThan(head)
    expect(secret).toBeGreaterThan(start)
    expect(clone).toBeGreaterThan(start)
  })

  it('github update: the start stands before the pull', () => {
    const c = codeLines(file('web/routes/connectors.ts').text)
    const idx = (re: RegExp, from = 0) => c.findIndex((l, i) => i >= from && re.test(l))
    const head = idx(/githubRepoMatch && method === 'PATCH'/)
    const start = idx(/trail\.start\(repoNameForAudit\(name\)\)/, head)
    const pull = idx(/updateGitHubRepo\(name/, head)
    expect(start).toBeGreaterThan(head)
    expect(pull).toBeGreaterThan(start)
  })

  it('the trail never takes an error message: the outcome recorder reads only the error class', () => {
    const text = codeLines(file('web/code-exec-admin.ts').text).join('\n')
    expect(text).not.toMatch(/\.message\b|String\(err\)|\$\{err\}/)
  })
})

// Card 24e137ef: privilege-widening routes that outlive a token rotation.
describe('security / capabilities / skills.assign / fleet.import are gated before the body is read (card 24e137ef)', () => {
  const cases: Array<[string, string, string]> = [
    ['agents.security', 'web/routes/agents.ts', "secGetMatch && method === 'PUT'"],
    ['agents.capabilities', 'web/routes/fleet-q.ts', "capMatch && method === 'PUT'"],
    ['skills.assign', 'web/routes/skills.ts', "globalSkillAssignMatch && method === 'POST'"],
    ['fleet.import', 'web/routes/fleet.ts', "path === '/api/fleet/import' && method === 'POST'"],
  ]
  for (const [action, rel, header] of cases) {
    it(`${action}: one admitCodeExecAdmin call in ${rel}, after the handler header and before its first readBody`, () => {
      const lines = codeLines(file(rel).text)
      const text = lines.join('\n')
      expect(text.match(new RegExp(`admitCodeExecAdmin\\(ctx, '${action.replace(/\./g, '\\.')}'\\)`, 'g')), action).toHaveLength(1)
      const head = lines.findIndex(l => l.includes(header))
      const gate = lines.findIndex(l => l.includes(`admitCodeExecAdmin(ctx, '${action}')`))
      const firstRead = lines.findIndex((l, i) => i > head && /readBody\(/.test(l))
      expect(head, `${action}: handler found`).toBeGreaterThan(-1)
      expect(gate, `${action}: gate inside the handler`).toBeGreaterThan(head)
      expect(firstRead, `${action}: gate before the first read`).toBeGreaterThan(gate)
    })
  }
})
