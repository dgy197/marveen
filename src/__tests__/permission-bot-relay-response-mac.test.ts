// The signed answer of the permission-bot route (card 0c15f6f7 A1): the response
// key file (0600, exclusive create, never rewritten) and the MAC itself. No network.
import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import { chmodSync, mkdtempSync, readFileSync, rmSync, statSync, symlinkSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import {
  RESPONSE_KEY_FILE_NAME, RESPONSE_MAC_HEADER, loadOrCreateResponseKey, responseKeyPath, responseMac, verifyResponseMac,
} from '../permission-bot-relay/response-mac.js'

let dir: string
let keyPath: string
beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), 'pbr-response-key-'))
  keyPath = responseKeyPath(dir)
})
afterEach(() => { rmSync(dir, { recursive: true, force: true }) })

describe('response key file', () => {
  it('the shared path helper joins the store dir and the fixed file name', () => {
    expect(keyPath).toBe(join(dir, RESPONSE_KEY_FILE_NAME))
    expect(RESPONSE_KEY_FILE_NAME).toBe('permission-bot-relay.response-key')
  })
  it('is created 0600 with 32 bytes; a second load returns the same bytes', () => {
    const a = loadOrCreateResponseKey(keyPath)!
    expect(a).toHaveLength(32)
    expect(statSync(keyPath).mode & 0o777).toBe(0o600)
    expect(loadOrCreateResponseKey(keyPath)!.equals(a)).toBe(true)
    expect(readFileSync(keyPath).equals(a)).toBe(true)
  })
  it('a file with mode 0644 is unusable and left as it is', () => {
    writeFileSync(keyPath, Buffer.alloc(32, 5), { mode: 0o600 })
    chmodSync(keyPath, 0o644)
    expect(loadOrCreateResponseKey(keyPath)).toBeNull()
    expect(readFileSync(keyPath).equals(Buffer.alloc(32, 5))).toBe(true)
  })
  it('a file of the wrong size is unusable and not rewritten', () => {
    writeFileSync(keyPath, Buffer.alloc(31, 5), { mode: 0o600 })
    expect(loadOrCreateResponseKey(keyPath)).toBeNull()
    expect(readFileSync(keyPath)).toHaveLength(31)
  })
  it('a symlink is unusable', () => {
    const target = join(dir, 'real-key')
    writeFileSync(target, Buffer.alloc(32, 5), { mode: 0o600 })
    symlinkSync(target, keyPath)
    expect(loadOrCreateResponseKey(keyPath)).toBeNull()
  })
})

describe('response MAC', () => {
  const K = Buffer.alloc(32, 3)
  const ID = 'a'.repeat(32)
  const NONCE = 'n'.repeat(22)
  const BODY = '{"ok":true}'
  const mac = (): string => responseMac(K, ID, NONCE, 200, BODY)!

  it('is 64 hex and verifies for the same id, nonce, status and body', () => {
    expect(mac()).toMatch(/^[0-9a-f]{64}$/)
    expect(verifyResponseMac(K, mac(), ID, NONCE, 200, BODY)).toBe(true)
    expect(RESPONSE_MAC_HEADER).toBe('x-marveen-relay-mac')
  })
  it('does not verify for another id, nonce, status, body or key', () => {
    expect(verifyResponseMac(K, mac(), 'b'.repeat(32), NONCE, 200, BODY)).toBe(false)
    expect(verifyResponseMac(K, mac(), ID, 'm'.repeat(22), 200, BODY)).toBe(false)
    expect(verifyResponseMac(K, mac(), ID, NONCE, 409, BODY)).toBe(false)
    expect(verifyResponseMac(K, mac(), ID, NONCE, 200, '{"ok":false}')).toBe(false)
    expect(verifyResponseMac(Buffer.alloc(32, 4), mac(), ID, NONCE, 200, BODY)).toBe(false)
  })
  // Card 3bc4a33e B2: fields are length-prefixed, so splitting one into the next cannot collide.
  it('a field-splitting forgery cannot reuse the MAC of another (nonce, status, body) tuple', () => {
    const real = responseMac(K, ID, 'N', 200, 'P\n409\nB')!
    expect(responseMac(K, ID, 'N\n200\nP', 409, 'B')).not.toBe(real)
    expect(verifyResponseMac(K, real, ID, 'N\n200\nP', 409, 'B')).toBe(false)
    expect(responseMac(K, ID, 'N', 2, '00P')).not.toBe(responseMac(K, ID, 'N2', 0, '0P'))
    expect(responseMac(K, 'ab', 'c', 200, BODY)).not.toBe(responseMac(K, 'a', 'bc', 200, BODY))
    expect(responseMac(K, ID, 'é', 200, BODY)).not.toBe(responseMac(K, ID, 'e', 200, BODY))
  })
  it('a missing, short, upper-case or non-hex header never verifies; no key, no MAC', () => {
    for (const h of [null, undefined, '', 'abc', mac().toUpperCase(), 'z'.repeat(64), `${mac()}00`]) {
      expect(verifyResponseMac(K, h, ID, NONCE, 200, BODY)).toBe(false)
    }
    expect(responseMac(null, ID, NONCE, 200, BODY)).toBeNull()
    expect(responseMac(Buffer.alloc(31, 1), ID, NONCE, 200, BODY)).toBeNull()
    expect(verifyResponseMac(null, mac(), ID, NONCE, 200, BODY)).toBe(false)
  })
})
