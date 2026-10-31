// The presser log tag is an HMAC keyed with a per-install secret (card d7f586bf,
// R2 fix B1) and a toast is cut to 200 code points (A2). No network.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { cutToast, loadOrCreatePresserKey, presserTag } from '../permission-bot-relay/apv-handler.js'

let dir: string
let keyPath: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pbr-presser-key-'))
  keyPath = join(dir, 'permission-bot-relay.presser-key')
})
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

describe('presserTag (B1)', () => {
  const K1 = Buffer.alloc(32, 1)
  const K2 = Buffer.alloc(32, 2)
  it('is stable for one key, 12 hex, differs per key and per id', () => {
    const a = presserTag(1591000001, K1)
    expect(a).toMatch(/^[0-9a-f]{12}$/)
    expect(presserTag(1591000001, K1)).toBe(a)
    expect(presserTag(1591000001, K2)).not.toBe(a)
    expect(presserTag(1591000002, K1)).not.toBe(a)
  })
  it('without a valid key there is no tag (never an unkeyed hash)', () => {
    expect(presserTag(1591000001, null)).toBeNull()
    expect(presserTag(1591000001, undefined)).toBeNull()
    expect(presserTag(1591000001, Buffer.alloc(31, 1))).toBeNull()
    expect(presserTag('x', K1)).toBeNull()
  })
})

describe('loadOrCreatePresserKey (B1)', () => {
  it('creates a 32-byte 0600 file and reads the same key back later', () => {
    const k1 = loadOrCreatePresserKey(keyPath)
    expect(k1).not.toBeNull()
    expect(k1!.length).toBe(32)
    expect(statSync(keyPath).mode & 0o777).toBe(0o600)
    expect(readFileSync(keyPath).equals(k1!)).toBe(true)
    const k2 = loadOrCreatePresserKey(keyPath)
    expect(k2!.equals(k1!)).toBe(true)
  })
  it('wrong mode, wrong size or an unusable location -> null, the file is not overwritten', () => {
    writeFileSync(keyPath, Buffer.alloc(32, 7), { mode: 0o600 })
    chmodSync(keyPath, 0o644)
    expect(loadOrCreatePresserKey(keyPath)).toBeNull()
    expect(readFileSync(keyPath).equals(Buffer.alloc(32, 7))).toBe(true)
    chmodSync(keyPath, 0o600)
    writeFileSync(keyPath, Buffer.alloc(16, 7))
    chmodSync(keyPath, 0o600)
    expect(loadOrCreatePresserKey(keyPath)).toBeNull()
    expect(loadOrCreatePresserKey(join(dir, 'permission-bot-relay.presser-key', 'x'))).toBeNull()
  })
  it('an unreadable key (mode 0) -> no key, so no tag', () => {
    const k = loadOrCreatePresserKey(keyPath)
    expect(k).not.toBeNull()
    chmodSync(keyPath, 0o000)
    const again = loadOrCreatePresserKey(keyPath)
    expect(again).toBeNull()
    expect(presserTag(1591000001, again)).toBeNull()
  })
})

describe('cutToast (A2)', () => {
  it('keeps short text, cuts to 200 code points, empty -> null', () => {
    expect(cutToast('ok')).toBe('ok')
    expect(Array.from(cutToast('é'.repeat(300))!).length).toBe(200)
    expect(Array.from(cutToast('🙂'.repeat(201))!).length).toBe(200)
    expect(cutToast('')).toBeNull()
    expect(cutToast(' '.repeat(10))).toBeNull()
  })
})
