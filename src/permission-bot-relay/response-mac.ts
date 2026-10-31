// The signed answer of the dashboard's permission-bot route (card 0c15f6f7 A1).
//
// The relay forwards the owner's press to http://127.0.0.1:<port>. With the
// dashboard down, any other local process could listen on that port and answer
// 200 {ok:true}, and the owner would see a false "decided" toast. So the route
// signs every answer it produces with a per-install key (a 0600 file in store/
// that both processes read), and the relay shows a decision toast only for an
// answer whose MAC verifies. The key is never sent in a request and never logged.
//
// MAC = HMAC-SHA256(key, field(tag) + field(id32) + field(nonce) + field(status) + field(body)),
// hex, in the RESPONSE_MAC_HEADER header, where field(x) = "<utf8 byte length>:" + x.
// The length prefix makes the input unambiguous: no separator exists that a field
// could contain to split or merge into another (id32, nonce, status, body) tuple
// (card 3bc4a33e B2). id32 is the approval id without dashes, nonce the request
// body's nonce ('' when absent or not a callback nonce), body the exact JSON text
// of the response.

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import { closeSync, constants as fsConstants, fchmodSync, fstatSync, mkdirSync, openSync, readSync, writeSync } from 'node:fs'
import { dirname, join } from 'node:path'

export const KEY_BYTES = 32
export const RESPONSE_KEY_FILE_NAME = 'permission-bot-relay.response-key'
export const RESPONSE_MAC_HEADER = 'x-marveen-relay-mac'
const MAC_HEX_RE = /^[0-9a-f]{64}$/
const MAC_TAG = 'permission-bot-response:v2'

function macField(value: string): Buffer {
  const bytes = Buffer.from(value, 'utf8')
  return Buffer.concat([Buffer.from(`${bytes.length}:`, 'utf8'), bytes])
}

/** The one path both sides use for the response key: <storeDir>/permission-bot-relay.response-key. */
export function responseKeyPath(storeDir: string): string {
  return join(storeDir, RESPONSE_KEY_FILE_NAME)
}

function readKeyFile(path: string): Buffer | null {
  let fd: number | null = null
  try {
    fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW)
    const st = fstatSync(fd)
    if (!st.isFile() || (st.mode & 0o777) !== 0o600 || st.size !== KEY_BYTES) return null
    const buf = Buffer.alloc(KEY_BYTES)
    if (readSync(fd, buf, 0, KEY_BYTES, 0) !== KEY_BYTES) return null
    return buf
  } catch {
    return null
  } finally {
    if (fd !== null) { try { closeSync(fd) } catch { /* best effort */ } }
  }
}

/**
 * 32 random bytes, 0600, exclusive create; read back on later runs. Missing and
 * not creatable, or wrong mode/size/symlink: null, the file is never rewritten.
 * Never throws and never reports the secret.
 */
export function loadOrCreateKeyFile(path: string): Buffer | null {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const fd = openSync(path, 'wx', 0o600)
    try {
      fchmodSync(fd, 0o600)
      if (writeSync(fd, randomBytes(KEY_BYTES)) !== KEY_BYTES) return null
    } finally {
      closeSync(fd)
    }
  } catch {
    // EEXIST (already created) or not creatable: fall through to the read-back.
  }
  return readKeyFile(path)
}

export function loadOrCreateResponseKey(path: string): Buffer | null {
  return loadOrCreateKeyFile(path)
}

/**
 * Read-only variant for the relay's lazy reload (card 3bc4a33e B3): the same checks
 * as the startup read (0600, regular file, exact size, no symlink), never creates.
 */
export function readResponseKey(path: string): Buffer | null {
  return readKeyFile(path)
}

/** Hex MAC of one answer; null without a valid key. */
export function responseMac(key: Buffer | null | undefined, id32: string, nonce: string, status: number, bodyText: string): string | null {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) return null
  const h = createHmac('sha256', key)
  for (const f of [MAC_TAG, id32, nonce, String(status), bodyText]) h.update(macField(f))
  return h.digest('hex')
}

/** Constant-time check of a received header value against the recomputed MAC. */
export function verifyResponseMac(
  key: Buffer | null | undefined,
  header: string | null | undefined,
  id32: string,
  nonce: string,
  status: number,
  bodyText: string,
): boolean {
  if (typeof header !== 'string' || !MAC_HEX_RE.test(header)) return false
  const expected = responseMac(key, id32, nonce, status, bodyText)
  if (expected == null) return false
  const a = Buffer.from(header, 'utf8')
  const b = Buffer.from(expected, 'utf8')
  return a.length === b.length && timingSafeEqual(a, b)
}
