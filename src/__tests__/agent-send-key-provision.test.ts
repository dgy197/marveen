import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, readFileSync, statSync, existsSync, mkdirSync, chmodSync, readdirSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import { resolveAgentSendKey } from '../web/agent-send-keys.js'
import {
  provisionAgentSendKey,
  clearAgentSendKey,
  agentKeyFilePath,
  agentKeyLaunchEnv,
  mainAgentKeyFilePath,
  provisionMainAgentSendKey,
  AGENT_KEYS_DIR_MODE,
  AGENT_KEY_FILE_MODE,
  AGENT_KEY_FILE_ENV,
} from '../web/agent-process.js'

// Card 0d7e2c04 N2 -- key distribution at launch. Contract under test:
//   - the key file is 0600 inside a 0700 dir (a pre-existing 0755 dir is tightened);
//   - the file holds a ready "X-Agent-Key:" header line that resolves to the agent;
//   - the launch env carries the PATH only, never the key value;
//   - stop (clearAgentSendKey) deletes the file and revokes the hash;
//   - the agent id is validated before it becomes a path component;
//   - the main agent goes through the same code path (K3).

let dir: string

beforeEach(() => {
  initDatabase(':memory:')
  dir = mkdtempSync(join(tmpdir(), 'agent-keys-'))
})

afterEach(() => {
  rmSync(dir, { recursive: true, force: true })
})

function keyFrom(path: string): string {
  const line = readFileSync(path, 'utf-8')
  const m = /^X-Agent-Key: (mvak_[A-Za-z0-9_-]+)\n$/.exec(line)
  expect(m, 'file must be exactly one ready header line').not.toBeNull()
  return m![1]
}

describe('provisionAgentSendKey', () => {
  it('writes a 0600 file in a 0700 dir and returns only the path', () => {
    const keysDir = join(dir, '.agent-keys')
    const path = provisionAgentSendKey('feszek', keysDir)
    expect(path).toBe(join(keysDir, 'feszek'))
    expect(statSync(path).mode & 0o777).toBe(AGENT_KEY_FILE_MODE)
    expect(statSync(keysDir).mode & 0o777).toBe(AGENT_KEYS_DIR_MODE)
    const raw = keyFrom(path)
    expect(path).not.toContain(raw)
    expect(resolveAgentSendKey(raw)).toEqual({ agentId: 'feszek', which: 'current' })
  })

  it('tightens a pre-existing 0755 dir to 0700', () => {
    const keysDir = join(dir, '.agent-keys')
    mkdirSync(keysDir, { recursive: true })
    chmodSync(keysDir, 0o755)
    expect(statSync(keysDir).mode & 0o777).toBe(0o755) // positive control: it really was loose
    provisionAgentSendKey('iroda', keysDir)
    expect(statSync(keysDir).mode & 0o777).toBe(0o700)
  })

  it('leaves no tmp file behind and re-provisioning rotates the key (old one stays prev)', () => {
    const keysDir = join(dir, '.agent-keys')
    const path = provisionAgentSendKey('iroda', keysDir)
    const first = keyFrom(path)
    provisionAgentSendKey('iroda', keysDir)
    const second = keyFrom(path)
    expect(second).not.toBe(first)
    expect(readdirSync(keysDir)).toEqual(['iroda'])
    expect(resolveAgentSendKey(second)?.which).toBe('current')
    expect(resolveAgentSendKey(first)?.which).toBe('prev')
  })

  it('the DB holds only the hash, not the key written to the file', () => {
    const path = provisionAgentSendKey('hajcsar', join(dir, '.agent-keys'))
    const raw = keyFrom(path)
    const rows = getDb().prepare('SELECT * FROM agent_send_keys').all()
    expect(JSON.stringify(rows)).not.toContain(raw)
  })

  it.each(['..', '.', '', '../x', 'a/b', '.hidden', 'a\0b', 'x'.repeat(65), 'a b'])(
    'rejects the unsafe agent id %j before touching the filesystem',
    (bad) => {
      const keysDir = join(dir, '.agent-keys')
      expect(() => provisionAgentSendKey(bad, keysDir)).toThrow()
      expect(existsSync(keysDir)).toBe(false)
      expect(getDb().prepare('SELECT COUNT(*) AS n FROM agent_send_keys').get()).toEqual({ n: 0 })
    },
  )

  it('accepts ordinary fleet ids', () => {
    for (const id of ['brainy', 'marveen', 'tuzvedelem', 'agent_1', 'a.b-c']) {
      expect(agentKeyFilePath(id, dir)).toBe(join(dir, id))
    }
  })
})

describe('launch string', () => {
  it('exports only the PATH, never the key value', () => {
    const keysDir = join(dir, '.agent-keys')
    const path = provisionAgentSendKey('feszek', keysDir)
    const raw = keyFrom(path)
    const env = agentKeyLaunchEnv(path)
    expect(env).toBe(`export ${AGENT_KEY_FILE_ENV}='${path}' && `)
    expect(env).not.toContain(raw)
    expect(env).not.toContain('mvak_')
    expect(AGENT_KEY_FILE_ENV).toBe('MARVEEN_AGENT_KEY_FILE')
  })
})

describe('clearAgentSendKey (agent stop)', () => {
  it('deletes the file and revokes the hash, current and prev', () => {
    const keysDir = join(dir, '.agent-keys')
    const path = provisionAgentSendKey('feszek', keysDir)
    const first = keyFrom(path)
    provisionAgentSendKey('feszek', keysDir)
    const second = keyFrom(path)
    clearAgentSendKey('feszek', keysDir)
    expect(existsSync(path)).toBe(false)
    expect(resolveAgentSendKey(second)).toBeNull()
    expect(resolveAgentSendKey(first)).toBeNull()
  })

  it('is a no-op for a missing file or an invalid id (never throws)', () => {
    const keysDir = join(dir, '.agent-keys')
    expect(() => clearAgentSendKey('nincs-ilyen', keysDir)).not.toThrow()
    expect(() => clearAgentSendKey('../etc', keysDir)).not.toThrow()
  })

  it('only touches the named agent', () => {
    const keysDir = join(dir, '.agent-keys')
    const a = provisionAgentSendKey('iroda', keysDir)
    const b = provisionAgentSendKey('feszek', keysDir)
    clearAgentSendKey('iroda', keysDir)
    expect(existsSync(a)).toBe(false)
    expect(resolveAgentSendKey(keyFrom(b))?.agentId).toBe('feszek')
  })
})

describe('main agent path (K3)', () => {
  it('the dashboard-side provisioner writes the main agent key through the same code', async () => {
    const { MAIN_AGENT_ID } = await import('../config.js')
    const { AGENT_KEYS_DIR } = await import('../web/agent-process.js')
    const path = provisionMainAgentSendKey()
    try {
      expect(path).toBe(join(AGENT_KEYS_DIR, MAIN_AGENT_ID))
      expect(statSync(path!).mode & 0o777).toBe(0o600)
      expect(resolveAgentSendKey(keyFrom(path!))?.agentId).toBe(MAIN_AGENT_ID)
      expect(mainAgentKeyFilePath()).toBe(path)
    } finally {
      clearAgentSendKey(MAIN_AGENT_ID)
    }
  })

  it('the respawn launcher and channels.sh export the path, with no key fetch', () => {
    const cm = readFileSync(join(__dirname, '..', 'web', 'channel-monitor.ts'), 'utf-8')
    expect(cm).toContain('AGENT_KEY_FILE_ENV')
    const sh = readFileSync(join(__dirname, '..', '..', 'scripts', 'channels.sh'), 'utf-8')
    expect(sh).toContain('MARVEEN_AGENT_KEY_FILE=')
    expect(sh.match(/\$\{STATE_DIR_ENV\}\$\{AGENT_KEY_ENV\}/g)?.length).toBe(2) // both new-session launches
    const keyLines = sh.split('\n').filter((l) => /AGENT_KEY_ENV=|\.agent-keys/.test(l) && !l.trim().startsWith('#'))
    for (const l of keyLines) expect(l).not.toMatch(/curl|api\//)
  })
})

describe('wiring in startAgentProcess / stopAgentProcess', () => {
  const src = readFileSync(join(__dirname, '..', 'web', 'agent-process.ts'), 'utf-8')

  it('the launch command interpolates the path env, and provisioning skips the main agent', () => {
    expect(src).toContain('${apiKeyEnv}${agentKeyEnv}${claudeConfigEnv}')
    expect(src).toMatch(/if \(name !== MAIN_AGENT_ID\) \{\s*try \{\s*agentKeyEnv = agentKeyLaunchEnv\(provisionAgentSendKey\(name\)\)/)
  })

  it('stopAgentProcess clears the key next to the launch secrets', () => {
    const stop = src.slice(src.indexOf('export async function stopAgentProcess'))
    const body = stop.slice(0, stop.indexOf('\n}\n'))
    expect(body.indexOf('clearLaunchSecrets(name)')).toBeGreaterThan(-1)
    expect(body.indexOf('clearAgentSendKey(name)')).toBeGreaterThan(body.indexOf('clearLaunchSecrets(name)'))
  })

  it('store/.agent-keys is covered by .gitignore (store/)', () => {
    const gi = readFileSync(join(__dirname, '..', '..', '.gitignore'), 'utf-8').split('\n')
    expect(gi).toContain('store/')
  })
})
