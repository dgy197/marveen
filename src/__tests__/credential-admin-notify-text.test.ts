import { describe, it, expect, vi, beforeEach } from 'vitest'

// Card 053f4e66 B: the owner notification for a token-minted credential goes
// through formatForTelegram (Markdown-ish -> Telegram HTML). Underscores in
// expires_at and BEARER_CREDENTIAL_ADMIN_ENABLED used to become <i> tags.
const notified = vi.hoisted(() => [] as string[])
vi.mock('../notify.js', () => ({
  notifySecurityEvent: async (text: string) => { notified.push(text) },
}))
vi.mock('../db.js', () => ({ logConfigChange: vi.fn() }))

import { recordBearerCredentialMint } from '../web/credential-admin.js'
import { formatForTelegram } from '../format.js'

const ADMISSION = { mode: 'manual' } as Parameters<typeof recordBearerCredentialMint>[1]

describe('recordBearerCredentialMint notification text', () => {
  beforeEach(() => { notified.length = 0 })

  it('device key: underscores stay literal after formatForTelegram, no <i> tag', () => {
    recordBearerCredentialMint(
      'auth.device_keys.create',
      ADMISSION,
      'key="my_key_name" id=7 scope=full expires_at=2027-01-01T00:00:00.000Z',
    )
    expect(notified).toHaveLength(1)
    const html = formatForTelegram(notified[0]!)
    expect(html).toContain('expires_at=2027-01-01T00:00:00.000Z')
    expect(html).toContain('BEARER_CREDENTIAL_ADMIN_ENABLED')
    expect(html).toContain('my_key_name')
    expect(html).not.toMatch(/<\/?i>/)
  })

  it('user: a name with underscores, <, > and & is escaped and literal', () => {
    recordBearerCredentialMint('auth.users.create', ADMISSION, 'user="a_b_c<x>&y" id=3')
    const html = formatForTelegram(notified[0]!)
    expect(html).toContain('a_b_c&lt;x&gt;&amp;y')
    expect(html).not.toMatch(/<\/?i>/)
    expect(html).not.toContain('<x>')
  })

  it('a backtick or newline in the subject cannot break out of the code span', () => {
    recordBearerCredentialMint('auth.users.create', ADMISSION, 'user="ev`il\nline_two" id=3')
    const html = formatForTelegram(notified[0]!)
    expect(html).not.toMatch(/<\/?i>/)
    expect(html).toContain('line_two')
    // Exactly the two intended code spans (subject + switch name) in the output.
    expect(html.match(/<code>/g)).toHaveLength(2)
  })
})
