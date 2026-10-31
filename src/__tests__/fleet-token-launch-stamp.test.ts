// Card acdb8045 K3: the launch stamp. Tokens are assembled at runtime (never a
// literal token-shaped string in the source).
import { describe, it, expect, afterAll } from 'vitest'
import { mkdtempSync, rmSync, writeFileSync, readFileSync, statSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { tmpdir } from 'node:os'
import {
  fingerprintOfToken,
  fleetTokenFilePath,
  launchFingerprint,
  launchWithStamp,
  readLaunchRegistry,
  stampAgentLaunch,
  clearLaunch,
} from '../web/fleet-token-fingerprint.js'
import { ownOauthTokenExport } from '../web/agent-oauth-token-file.js'
import { FLEET_OAUTH_TOKEN_PATH } from '../web/agent-process.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const tmpRoot = mkdtempSync(join(tmpdir(), 'marveen-fleet-stamp-test-'))
afterAll(() => rmSync(tmpRoot, { recursive: true, force: true }))

const canary = (tag: string) => ['canary', 'stamp', 'tok', tag, 'k3q8w2'].join('-')

function fixture(tag: string) {
  const dir = mkdtempSync(join(tmpRoot, `${tag}-`))
  const tokenPath = join(dir, '.claude-oauth-token')
  const registryPath = join(dir, 'fleet-token-launch.json')
  const token = canary(tag)
  writeFileSync(tokenPath, token)
  const fleetEnv = `export CLAUDE_CODE_OAUTH_TOKEN="$(cat '${tokenPath}')" && `
  return { dir, tokenPath, registryPath, token, fleetEnv }
}

describe('stampAgentLaunch (K3)', () => {
  it('stamps agent:<name> with the fleet token fingerprint when the launcher exports the fleet file', () => {
    const f = fixture('fleet')
    const out = stampAgentLaunch('levente', f.fleetEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath, nowMs: 1234 })
    expect(out).toBe('stamped')
    const reg = readLaunchRegistry(f.registryPath)
    expect(reg['agent:levente']).toEqual({ fp: fingerprintOfToken(f.token), at: 1234 })
    expect(statSync(f.registryPath).mode & 0o777).toBe(0o600)
  })

  it('writes nothing for an own-token-file launch (and drops an older stamp)', () => {
    const f = fixture('own')
    const ownEnv = ownOauthTokenExport(join(f.dir, 'own-agent-token'))
    expect(stampAgentLaunch('a', ownEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('cleared')
    expect(launchFingerprint('agent:a', f.registryPath)).toBeNull()
    // an older fleet stamp is dropped when the same agent now launches with its own token
    expect(stampAgentLaunch('a', f.fleetEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('stamped')
    expect(stampAgentLaunch('a', ownEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('cleared')
    expect(launchFingerprint('agent:a', f.registryPath)).toBeNull()
  })

  it('writes nothing for BYO / custom / own_team launches (empty oauthTokenEnv)', () => {
    const f = fixture('byo')
    expect(stampAgentLaunch('byo', '', { tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('cleared')
    expect(readLaunchRegistry(f.registryPath)['agent:byo']).toBeUndefined()
  })

  it('never stamps the main agent', () => {
    const f = fixture('main')
    expect(stampAgentLaunch('brainy', f.fleetEnv, { isMain: true, tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('skipped-main')
    expect(Object.keys(readLaunchRegistry(f.registryPath))).toEqual([])
  })

  it('an unreadable / empty fleet token file gives no stamp, not a stale one', () => {
    const f = fixture('empty')
    writeFileSync(f.tokenPath, '  \n')
    expect(stampAgentLaunch('e', f.fleetEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath })).toBe('cleared')
    expect(launchFingerprint('agent:e', f.registryPath)).toBeNull()
  })

  it('a registry write failure is a fixed label and does not throw', () => {
    const f = fixture('fail')
    const out = stampAgentLaunch('x', f.fleetEnv, {
      tokenPath: f.tokenPath,
      registryPath: f.registryPath,
      io: {
        readFile: (p) => readFileSync(p, 'utf-8'),
        writeAtomic: () => { throw new Error(`disk full ${f.token}`) },
        mtimeMs: () => null,
      },
    })
    expect(out).toBe('failed')
  })

  it('the launcher fleet-export shape is what the stamp condition looks for (same path, same template)', () => {
    expect(FLEET_OAUTH_TOKEN_PATH).toBe(fleetTokenFilePath())
    const src = readFileSync(join(__dirname, '..', 'web', 'agent-process.ts'), 'utf-8')
    expect(src).toContain('export CLAUDE_CODE_OAUTH_TOKEN="$(cat \'${FLEET_OAUTH_TOKEN_PATH}\')" && ')
  })
})

describe('launchWithStamp ordering (K3)', () => {
  it('the stamp is written before the launch callback runs', () => {
    const f = fixture('order')
    const seen: string[] = []
    launchWithStamp('ord', f.fleetEnv, () => {
      // at launch time the stamp must already be on disk
      seen.push(launchFingerprint('agent:ord', f.registryPath) ? 'stamp-present' : 'stamp-missing')
      seen.push('new-session')
    }, { tokenPath: f.tokenPath, registryPath: f.registryPath })
    expect(seen).toEqual(['stamp-present', 'new-session'])
  })

  it('a failed stamp still launches (and reports the outcome label only)', () => {
    const f = fixture('order-fail')
    const labels: string[] = []
    let launched = false
    launchWithStamp('o2', f.fleetEnv, () => { launched = true }, {
      tokenPath: f.tokenPath,
      registryPath: f.registryPath,
      io: { readFile: (p) => readFileSync(p, 'utf-8'), writeAtomic: () => { throw new Error('boom') }, mtimeMs: () => null },
      onStamp: (o) => labels.push(o),
    })
    expect(launched).toBe(true)
    expect(labels).toEqual(['failed'])
  })

  it('stop clears the stamp (clearLaunch on agent:<name>)', () => {
    const f = fixture('stop')
    stampAgentLaunch('s', f.fleetEnv, { tokenPath: f.tokenPath, registryPath: f.registryPath })
    expect(launchFingerprint('agent:s', f.registryPath)).not.toBeNull()
    expect(clearLaunch('agent:s', f.registryPath).ok).toBe(true)
    expect(launchFingerprint('agent:s', f.registryPath)).toBeNull()
  })
})

describe('agent-process.ts wiring (K3 source guard)', () => {
  const src = readFileSync(join(__dirname, '..', 'web', 'agent-process.ts'), 'utf-8')

  it('both new-session sites run inside launchWithStamp, with the main agent excluded', () => {
    const sites = [...src.matchAll(/launchWithStamp\(name, oauthTokenEnv, \(\) => \{\s*runTmux\([^\n]*'new-session'[^\n]*\n\s*\}, \{ isMain: name === MAIN_AGENT_ID, onStamp: stampAgent \}\)/g)]
    expect(sites.length).toBe(2)
    // no new-session outside a stamp wrapper in the launcher
    const all = [...src.matchAll(/\['new-session', '-d', '-s', session, buildLaunchCmd\(/g)]
    expect(all.length).toBe(2)
  })

  it('stopAgentProcess clears the agent stamp, the main agent excluded', () => {
    const stop = src.slice(src.indexOf('export async function stopAgentProcess'))
    const body = stop.slice(0, stop.indexOf('export function getAgentProcessInfo'))
    expect(body).toContain("if (name !== MAIN_AGENT_ID) clearLaunch(`agent:${name}`)")
  })

  it('the stamp log line carries no fingerprint or token', () => {
    expect(src).toContain("logger.warn({ name }, 'fleet token launch stamp failed')")
  })
})
