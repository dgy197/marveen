import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { mkdtempSync, rmSync, mkdirSync, chmodSync, readdirSync, symlinkSync, lstatSync, linkSync, renameSync, existsSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { initDatabase, getDb } from '../db.js'
import { provisionAgentSendKey, agentKeyFsSeam } from '../web/agent-process.js'

// Card ed5fc02c -- enforce prerequisites for the per-agent sender keys (residuals Q3 of card 0d7e2c04):
//   a. the keys dir swapped between the check and the rename (Node has no openat) -> refused, nothing written through;
//   b. the parent chain root -> store -> .agent-keys must be real, own, not group/other-writable dirs;
//   c. the final key file is re-opened O_NOFOLLOW: regular, nlink 1, own, 0600, same device and inode as written.
// Every refusal leaves no live hash behind (the agent then starts unsigned).

let root: string
let storeDir: string
let keysDir: string

const keyRows = () => (getDb().prepare('SELECT COUNT(*) AS n FROM agent_send_keys').get() as { n: number }).n

beforeEach(() => {
  initDatabase(':memory:')
  root = mkdtempSync(join(tmpdir(), 'agent-keys-hard-'))
  storeDir = join(root, 'store')
  keysDir = join(storeDir, '.agent-keys')
  mkdirSync(storeDir)
})

afterEach(() => {
  agentKeyFsSeam.uid = undefined
  agentKeyFsSeam.beforeRename = undefined
  agentKeyFsSeam.afterRename = undefined
  rmSync(root, { recursive: true, force: true })
})

describe('Q3a: the keys dir is swapped inside the write window', () => {
  it('positive control: an untouched chain provisions', () => {
    const path = provisionAgentSendKey('iroda', keysDir, root)
    expect(lstatSync(path).isFile()).toBe(true)
    expect(keyRows()).toBe(1)
  })

  it('swapped for another real dir BEFORE the rename -> refused, the new dir stays empty, no hash', () => {
    provisionAgentSendKey('feszek', keysDir, root) // creates the dir; revoked below by the failing call's own hash only
    getDb().prepare('DELETE FROM agent_send_keys').run()
    const moved = join(storeDir, 'moved-away')
    agentKeyFsSeam.beforeRename = () => {
      renameSync(keysDir, moved)
      mkdirSync(keysDir, { mode: 0o700 })
    }
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/swapped/)
    expect(readdirSync(keysDir)).toEqual([])
    expect(keyRows()).toBe(0)
  })

  it('swapped for a symlink BEFORE the rename -> refused, the link target stays empty, no hash', () => {
    const target = join(root, 'attacker')
    mkdirSync(target, { mode: 0o700 })
    agentKeyFsSeam.beforeRename = () => {
      renameSync(keysDir, join(storeDir, 'moved-away'))
      symlinkSync(target, keysDir)
    }
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/symlink/)
    expect(readdirSync(target)).toEqual([])
    expect(keyRows()).toBe(0)
  })

  it('swapped AFTER the rename -> refused, nothing is left in the new dir, no hash', () => {
    agentKeyFsSeam.afterRename = () => {
      renameSync(keysDir, join(storeDir, 'moved-away'))
      mkdirSync(keysDir, { mode: 0o700 })
    }
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/swapped/)
    expect(readdirSync(keysDir)).toEqual([])
    expect(keyRows()).toBe(0)
  })

  it('the dir turned group-writable inside the window -> refused, the new file is unlinked, no hash', () => {
    agentKeyFsSeam.afterRename = () => chmodSync(keysDir, 0o770)
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/mode/)
    expect(existsSync(join(keysDir, 'iroda'))).toBe(false)
    expect(keyRows()).toBe(0)
  })

  it('a foreign owner (uid seam) on the keys dir -> refused before anything is written', () => {
    mkdirSync(keysDir, { mode: 0o700 })
    agentKeyFsSeam.uid = () => (process.getuid?.() ?? 0) + 4242
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/owner|owned/)
    expect(readdirSync(keysDir)).toEqual([])
    expect(keyRows()).toBe(0)
  })
})

describe('Q3c: the final key file is re-checked', () => {
  it('an extra hard link appears -> refused, the key file is unlinked, no hash', () => {
    agentKeyFsSeam.afterRename = () => linkSync(join(keysDir, 'iroda'), join(root, 'stolen-link'))
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/hard links/)
    expect(existsSync(join(keysDir, 'iroda'))).toBe(false)
    expect(keyRows()).toBe(0)
  })

  it('the file mode drifts from 0600 -> refused, unlinked, no hash', () => {
    agentKeyFsSeam.afterRename = () => chmodSync(join(keysDir, 'iroda'), 0o644)
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/0600/)
    expect(existsSync(join(keysDir, 'iroda'))).toBe(false)
    expect(keyRows()).toBe(0)
  })

  it('the file is replaced by a symlink after the rename -> refused (O_NOFOLLOW), the foreign target is NOT unlinked', () => {
    const victim = join(root, 'victim')
    writeFileSync(victim, 'KEEP')
    agentKeyFsSeam.afterRename = () => {
      rmSync(join(keysDir, 'iroda'))
      symlinkSync(victim, join(keysDir, 'iroda'))
    }
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow()
    expect(existsSync(victim)).toBe(true)
    expect(keyRows()).toBe(0)
  })

  it('the file is replaced by a different regular file -> refused, that other file is left alone', () => {
    agentKeyFsSeam.afterRename = () => {
      rmSync(join(keysDir, 'iroda'))
      writeFileSync(join(keysDir, 'iroda'), 'OTHER', { mode: 0o600 })
    }
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/not the file/)
    expect(existsSync(join(keysDir, 'iroda'))).toBe(true) // dev/ino differ from what we wrote: not ours to unlink
    expect(keyRows()).toBe(0)
  })
})

describe('Q3b: the parent chain', () => {
  it('a symlinked store/ -> refused, nothing created behind the link, no hash', () => {
    const real = join(root, 'real-store')
    mkdirSync(real, { mode: 0o700 })
    rmSync(storeDir, { recursive: true })
    symlinkSync(real, storeDir)
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/parent is a symlink/)
    expect(readdirSync(real)).toEqual([])
    expect(keyRows()).toBe(0)
  })

  it('a symlinked install root -> refused', () => {
    const link = join(tmpdir(), `agent-keys-hard-link-${process.pid}-${Date.now()}`)
    symlinkSync(root, link)
    try {
      expect(() => provisionAgentSendKey('iroda', join(link, 'store', '.agent-keys'), link)).toThrow(/parent is a symlink/)
      expect(readdirSync(storeDir)).toEqual([])
      expect(keyRows()).toBe(0)
    } finally {
      rmSync(link)
    }
  })

  it('a group-writable store/ -> refused', () => {
    chmodSync(storeDir, 0o775)
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/writable/)
    expect(existsSync(keysDir)).toBe(false)
    expect(keyRows()).toBe(0)
  })

  it('an other-writable install root -> refused', () => {
    chmodSync(root, 0o757)
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/writable/)
    expect(keyRows()).toBe(0)
  })

  it('a foreign-owned parent (uid seam) -> refused', () => {
    agentKeyFsSeam.uid = () => (process.getuid?.() ?? 0) + 4242
    expect(() => provisionAgentSendKey('iroda', keysDir, root)).toThrow(/owned/)
    expect(keyRows()).toBe(0)
  })

  it('a missing store/ is created by us and the strict second pass accepts it', () => {
    rmSync(storeDir, { recursive: true })
    const path = provisionAgentSendKey('iroda', keysDir, root)
    expect(lstatSync(path).isFile()).toBe(true)
    expect(keyRows()).toBe(1)
  })

  it('a keys dir outside the given root -> refused', () => {
    const elsewhere = mkdtempSync(join(tmpdir(), 'agent-keys-elsewhere-'))
    try {
      expect(() => provisionAgentSendKey('iroda', join(elsewhere, '.agent-keys'), root)).toThrow(/outside/)
      expect(keyRows()).toBe(0)
    } finally {
      rmSync(elsewhere, { recursive: true, force: true })
    }
  })
})
