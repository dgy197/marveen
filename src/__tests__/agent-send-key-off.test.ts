import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, existsSync, mkdirSync, readdirSync, symlinkSync, lstatSync, writeFileSync, chmodSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { execFileSync } from 'node:child_process'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import {
  provisionAgentSendKey,
  provisionMainAgentSendKey,
  mainAgentKeyFilePath,
  sweepAgentSendKeysWhenOff,
  agentSendKeysEnabled,
  AGENT_KEYS_DIR,
} from '../web/agent-process.js'
import { MESSAGE_SENDER_AUTH } from '../config.js'

// Card 3f6500e6 -- MESSAGE_SENDER_AUTH=off makes the key feature fully inert:
//   - off: no key minted, no file written, no env in the launch strings, no DB row;
//   - off: the boot / agent-start sweep revokes every hash and removes the key files with the verified-dir unlink,
//     and refuses quietly through a symlinked dir (nothing outside is touched);
//   - shadow (the default) is unchanged.

let dir: string
const keyRows = () => (getDb().prepare('SELECT COUNT(*) AS n FROM agent_send_keys').get() as { n: number }).n

beforeEach(() => {
  initDatabase(':memory:')
  dir = mkdtempSync(join(tmpdir(), 'agent-keys-off-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

describe('off: nothing is provisioned', () => {
  it('the test run itself is in the default shadow mode', () => {
    expect(MESSAGE_SENDER_AUTH).toBe('shadow')
    expect(agentSendKeysEnabled()).toBe(true)
    expect(agentSendKeysEnabled('off')).toBe(false)
  })

  it('provisionAgentSendKey(off) throws before it touches anything: no dir, no file, no row', () => {
    const keysDir = join(dir, '.agent-keys')
    expect(() => provisionAgentSendKey('iroda', keysDir, undefined, 'off')).toThrow(/off/)
    expect(existsSync(keysDir)).toBe(false)
    expect(keyRows()).toBe(0)
  })

  it('provisionMainAgentSendKey(off) returns null and leaves the real keys dir and the table alone', () => {
    const before = existsSync(AGENT_KEYS_DIR) ? readdirSync(AGENT_KEYS_DIR) : null
    expect(provisionMainAgentSendKey('off')).toBeNull()
    expect(keyRows()).toBe(0)
    expect(existsSync(AGENT_KEYS_DIR) ? readdirSync(AGENT_KEYS_DIR) : null).toEqual(before)
  })

  it('the respawn launcher gets no path in off, and the path in shadow', () => {
    expect(mainAgentKeyFilePath('off')).toBeNull()
    expect(mainAgentKeyFilePath('shadow')).toMatch(/\.agent-keys\//)
  })

  it('the start path sweeps instead of provisioning in off, and the launch env stays empty', () => {
    const src = readFileSync(join(__dirname, '..', 'web', 'agent-process.ts'), 'utf-8')
    expect(src).toMatch(/let agentKeyEnv = ''\s*if \(!agentSendKeysEnabled\(\)\) \{\s*sweepAgentSendKeysWhenOff\(\)[^\n]*\n\s*\} else if \(name !== MAIN_AGENT_ID\) \{\s*try \{\s*agentKeyEnv = agentKeyLaunchEnv\(provisionAgentSendKey\(name\)\)/)
  })

  it('boot sweeps right after the main-agent provisioning', () => {
    const idx = readFileSync(join(__dirname, '..', 'index.ts'), 'utf-8')
    expect(idx.indexOf('sweepAgentSendKeysWhenOff()')).toBeGreaterThan(idx.indexOf('  provisionMainAgentSendKey()'))
  })

  it('channels.sh gates the export on the mode (not on file existence) and refuses a symlinked path', () => {
    const sh = readFileSync(join(__dirname, '..', '..', 'scripts', 'channels.sh'), 'utf-8')
    expect(sh).toMatch(/if \[ "\$_ak_mode" != "off" \] && \[ ! -L "\$INSTALL_DIR\/store\/\.agent-keys\/\$_ak_id" \]; then\s*\n\s*AGENT_KEY_ENV="export MARVEEN_AGENT_KEY_FILE=/)
    expect(sh).not.toMatch(/\[ -f "\$INSTALL_DIR\/store\/\.agent-keys/)
  })

  // Behavioural: run the real block extracted from channels.sh against a scratch install dir.
  const runBlock = (envLine: string | null, mkLink: boolean): string => {
    const sh = readFileSync(join(__dirname, '..', '..', 'scripts', 'channels.sh'), 'utf-8')
    const start = sh.indexOf('AGENT_KEY_ENV=""')
    const end = sh.indexOf('# P1 FIX: put the Claude auth token')
    const block = sh.slice(start, end)
    const inst = join(dir, 'inst')
    mkdirSync(join(inst, 'store', '.agent-keys'), { recursive: true })
    if (envLine !== null) writeFileSync(join(inst, '.env'), envLine + '\n')
    if (mkLink) symlinkSync('/nonexistent', join(inst, 'store', '.agent-keys', 'marveen'))
    const script = `sh_single_quote() { printf "'%s'" "$1"; }\nINSTALL_DIR='${inst}'\nMAIN_AGENT_ID=marveen\n${block}\nprintf '%s' "$AGENT_KEY_ENV"\n`
    const f = join(dir, 'blk.sh')
    writeFileSync(f, script)
    return execFileSync('bash', [f], { encoding: 'utf-8' })
  }

  it('shadow (and unset) + key file missing: the path is exported', () => {
    expect(runBlock('MESSAGE_SENDER_AUTH=shadow', false)).toContain('MARVEEN_AGENT_KEY_FILE=')
    expect(runBlock(null, false)).toContain('MARVEEN_AGENT_KEY_FILE=')
  })

  it('off: nothing is exported', () => {
    expect(runBlock('MESSAGE_SENDER_AUTH=off', false)).toBe('')
    expect(runBlock('MESSAGE_SENDER_AUTH="OFF"', false)).toBe('')
  })

  it('the path is a symlink: nothing is exported', () => {
    expect(runBlock('MESSAGE_SENDER_AUTH=shadow', true)).toBe('')
  })
})

describe('off: the sweep', () => {
  it('shadow: the sweep is a no-op (rows and files stay)', () => {
    const keysDir = join(dir, '.agent-keys')
    const p = provisionAgentSendKey('iroda', keysDir, undefined, 'shadow')
    expect(sweepAgentSendKeysWhenOff(keysDir, 'shadow')).toBeNull()
    expect(existsSync(p)).toBe(true)
    expect(keyRows()).toBe(1)
  })

  it('off: revokes every row and removes the key files and temp leftovers, only those', () => {
    const keysDir = join(dir, '.agent-keys')
    const a = provisionAgentSendKey('iroda', keysDir, undefined, 'shadow')
    const b = provisionAgentSendKey('feszek', keysDir, undefined, 'shadow')
    writeFileSync(join(keysDir, '.tmp.1.2.abcd'), 'x', { mode: 0o600 })
    writeFileSync(join(keysDir, '.keep-me'), 'y', { mode: 0o600 }) // not a key name, not a temp: left alone
    mkdirSync(join(keysDir, 'subdir'))
    expect(keyRows()).toBe(2)
    const r = sweepAgentSendKeysWhenOff(keysDir, 'off')
    expect(r).toEqual({ revoked: 2, removed: 3 })
    expect(existsSync(a)).toBe(false)
    expect(existsSync(b)).toBe(false)
    expect(readdirSync(keysDir).sort()).toEqual(['.keep-me', 'subdir'])
    expect(keyRows()).toBe(0)
  })

  it('off: a missing keys dir is fine (rows are still revoked)', () => {
    getDb().prepare("INSERT INTO agent_send_keys (agent_id, key_hash, created_at, last_used_at) VALUES ('iroda', 'h', 1, 1)").run()
    expect(sweepAgentSendKeysWhenOff(join(dir, '.agent-keys'), 'off')).toEqual({ revoked: 1, removed: 0 })
    expect(keyRows()).toBe(0)
  })

  it('off: a symlinked keys dir is refused quietly, the link target keeps its files, rows are still revoked', () => {
    const target = join(dir, 'elsewhere')
    mkdirSync(target)
    writeFileSync(join(target, 'iroda'), 'KEEP', { mode: 0o600 })
    const keysDir = join(dir, '.agent-keys')
    symlinkSync(target, keysDir)
    getDb().prepare("INSERT INTO agent_send_keys (agent_id, key_hash, created_at, last_used_at) VALUES ('iroda', 'h', 1, 1)").run()
    expect(() => sweepAgentSendKeysWhenOff(keysDir, 'off')).not.toThrow()
    expect(readFileSync(join(target, 'iroda'), 'utf-8')).toBe('KEEP')
    expect(lstatSync(keysDir).isSymbolicLink()).toBe(true)
    expect(keyRows()).toBe(0)
  })

  it('off: a symlink entry inside the dir is not followed or removed through', () => {
    const keysDir = join(dir, '.agent-keys')
    provisionAgentSendKey('feszek', keysDir, undefined, 'shadow')
    const outside = join(dir, 'outside')
    writeFileSync(outside, 'KEEP')
    symlinkSync(outside, join(keysDir, 'iroda'))
    const r = sweepAgentSendKeysWhenOff(keysDir, 'off')
    expect(r?.removed).toBe(1) // only the real file
    expect(readFileSync(outside, 'utf-8')).toBe('KEEP')
    expect(lstatSync(join(keysDir, 'iroda')).isSymbolicLink()).toBe(true) // left in place
  })

  it('off: a group-writable parent chain is refused quietly, nothing is unlinked', () => {
    const keysDir = join(dir, '.agent-keys')
    const p = provisionAgentSendKey('iroda', keysDir, undefined, 'shadow')
    chmodSync(dir, 0o770)
    expect(() => sweepAgentSendKeysWhenOff(keysDir, 'off')).not.toThrow()
    expect(existsSync(p)).toBe(true)
    chmodSync(dir, 0o700)
  })
})
