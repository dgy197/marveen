import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

// Credit gate, node N5 against the dashboard's real database layer (db.ts):
//   - a credit-gate approval the system closed because its payload changed
//     after the owner's message went out (resolved_by system:payload_mismatch,
//     N2b BE-3b LOW-2) becomes an audit event, an info message for the main
//     agent with a fixed, secret-free reason text, and a line in the status;
//   - the default deliverers: the info message is a queue row from `system`
//     to the main agent; the directive counts only when the anchor row exists
//     AND the tmux injection says `sent`.
// No Telegram, no tmux, no network: the directive sender is mocked at the
// module boundary, the global fetch throws.

const logSpy = vi.hoisted(() => ({ info: vi.fn(), warn: vi.fn(), error: vi.fn(), debug: vi.fn() }))
vi.mock('../logger.js', () => ({ logger: logSpy, PRETTY_OPTIONS: {} }))

const directive = vi.hoisted(() => ({ outcome: 'sent' as string, calls: [] as Array<{ to: string; session: string; text: string }>, createRow: true }))
vi.mock('../web/system-directive.js', async () => {
  const db = await import('../db.js')
  return {
    sendSystemDirective: async (to: string, session: string, text: string) => {
      directive.calls.push({ to, session, text })
      // As the real one: the anchor row first (from `system`), the injection second.
      if (directive.createRow) {
        const m = db.createAgentMessage('system', to, text)
        db.markMessageDelivered(m.id)
      }
      return directive.outcome
    },
  }
})

const { createHash } = await import('node:crypto')
const { initDatabase, getDb, createApproval, getApproval, resolveApprovalFromTelegram, PAYLOAD_MISMATCH_RESOLVER } = await import('../db.js')
const { MAIN_AGENT_ID } = await import('../config.js')
const { applyCreditGateSchema } = await import('../web/credit-gate/schema.js')
const audit = await import('../web/credit-gate/audit.js')
const { AuditNotifier, defaultNotifyDeps } = await import('../web/credit-gate/notify.js')
type NotifyDeps = import('../web/credit-gate/notify.js').NotifyDeps

const origFetch = globalThis.fetch
const NOW = Date.UTC(2026, 9, 16, 9, 0, 0)
const PAYLOAD_MARKER = 'PAYLOAD-MARKER-do-not-echo-7731'
const OWNER = '1591883559'

beforeEach(() => {
  globalThis.fetch = (() => { throw new Error('credit-gate test guard: fetch is not allowed') }) as typeof fetch
  initDatabase(':memory:')
  applyCreditGateSchema(getDb())
  for (const f of Object.values(logSpy)) f.mockClear()
  directive.outcome = 'sent'
  directive.calls = []
  directive.createRow = true
})
afterEach(() => {
  globalThis.fetch = origFetch
})

function deps(over: Partial<NotifyDeps> = {}) {
  const sent = { info: [] as string[], daily: [] as string[] }
  let id = 900
  const d: NotifyDeps = {
    now: () => NOW,
    sendInfo: (text) => { sent.info.push(text); return id++ },
    sendDirective: async () => id++,
    dailyLog: (text) => { sent.daily.push(text) },
    ...over,
  }
  return { d, sent }
}

/** A pending credit-gate approval whose stored payload does not bind its hash, closed by a genuine press. */
function mismatchedApproval(id: string, category = 'credit_gate_calibration'): void {
  createApproval({
    id, agent_id: 'brainy', category, action_description: 'test',
    action_payload: `{"v":1,"note":"${PAYLOAD_MARKER}"`, // broken JSON: never binds
    timeout_at: Math.floor(Date.now() / 1000) + 3600,
    content_hash: createHash('sha256').update('something else').digest('hex'),
  })
  const r = resolveApprovalFromTelegram({
    id, status: 'approved', ownerId: OWNER, messageId: 5, nonceHash: createHash('sha256').update('n').digest('hex'),
  })
  expect(r).toMatchObject({ ok: false, reason: 'payload_mismatch' })
}

describe('payload_mismatch: the auto-rejected approval is visible', () => {
  it('becomes one audit event, one info message with a fixed reason text, a daily line and a status count', async () => {
    const id = '3f2b8e1a-0000-4000-8000-00000000aaaa'
    mismatchedApproval(id)
    expect(getApproval(id)).toMatchObject({ status: 'rejected', resolved_by: PAYLOAD_MISMATCH_RESOLVER })

    const { d, sent } = deps()
    const res = await new AuditNotifier(getDb(), d).deliver()
    expect(res).toMatchObject({ sent: 1, failed: 0 })

    const ev = getDb().prepare("SELECT * FROM credit_gate_events WHERE kind = 'approval_payload_mismatch'").all() as Array<Record<string, any>>
    expect(ev).toHaveLength(1)
    expect(ev[0]).toMatchObject({ reason: 'payload_mismatch', notify_state: 'sent', daily_logged: 1 })
    expect(JSON.parse(ev[0]!.detail_json)).toEqual({ approval_id: id, category: 'credit_gate_calibration' })

    expect(sent.info).toHaveLength(1)
    const text = sent.info[0]!
    expect(text.startsWith('[KREDIT-KAPU]')).toBe(true)
    expect(text).toContain(audit.PAYLOAD_MISMATCH_TEXT)
    expect(audit.PAYLOAD_MISMATCH_TEXT).toMatch(/megvaltozott/)
    expect(audit.PAYLOAD_MISMATCH_TEXT).toMatch(/elutasitotta/)
    expect(text).toContain(`approval: ${id}`)
    expect(text).toContain('kategoria: credit_gate_calibration')
    expect(text).not.toContain('TEENDO')
    expect(sent.daily).toHaveLength(1)
    expect(JSON.stringify([sent, logSpy.info.mock.calls, logSpy.warn.mock.calls])).not.toContain(PAYLOAD_MARKER)

    const view = audit.auditStatus(getDb(), NOW)
    expect(view.approvals.payload_mismatch).toEqual({ count: 1, last_at: expect.any(String) })
    expect(view.last_event).toMatchObject({ kind: 'approval_payload_mismatch' })
  })

  it('is recorded once, however often the sweep runs, and again for a second approval', async () => {
    mismatchedApproval('3f2b8e1a-0000-4000-8000-00000000aaa1')
    const { d, sent } = deps()
    const n = new AuditNotifier(getDb(), d)
    await n.deliver()
    await n.deliver()
    expect(audit.recordApprovalMismatches(getDb(), NOW)).toBe(0)
    mismatchedApproval('3f2b8e1a-0000-4000-8000-00000000aaa2', 'credit_gate_canary')
    await n.deliver()
    expect(sent.info).toHaveLength(2)
    expect(audit.auditStatus(getDb(), NOW).approvals.payload_mismatch.count).toBe(2)
  })

  it('the event carries the time the system closed the approval, not the time of the sweep', async () => {
    mismatchedApproval('3f2b8e1a-0000-4000-8000-00000000aab1')
    const closedAt = (getApproval('3f2b8e1a-0000-4000-8000-00000000aab1')!.resolved_at as number) * 1000
    audit.recordApprovalMismatches(getDb(), NOW + 3_600_000)
    const ev = getDb().prepare("SELECT at FROM credit_gate_events WHERE kind = 'approval_payload_mismatch'").get() as { at: number }
    expect(ev.at).toBe(closedAt)
  })

  it('an owner decision, another system rejection, or a non credit-gate row is not a payload mismatch', async () => {
    const db = getDb()
    const ins = (id: string, category: string, resolvedBy: string, status = 'rejected') => db.prepare(
      'INSERT INTO approvals (id, agent_id, category, action_description, status, requested_at, resolved_at, resolved_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
    ).run(id, 'brainy', category, 'x', status, 1, 2, resolvedBy)
    ins('owner-rejected', 'credit_gate_calibration', `owner:telegram:${OWNER}`)
    ins('sweeper', 'credit_gate_calibration', 'system:timeout', 'timeout')
    ins('mail', 'email_send', PAYLOAD_MISMATCH_RESOLVER)
    expect(audit.recordApprovalMismatches(db, NOW)).toBe(0)
    const { d, sent } = deps()
    await new AuditNotifier(db, d).deliver()
    expect(sent.info).toEqual([])
    expect(audit.auditStatus(db, NOW).approvals.payload_mismatch.count).toBe(0)
  })

  it('a database without an approvals table (the gate on another handle) is not an error', async () => {
    const Database = (await import('better-sqlite3')).default
    const other = new Database(':memory:')
    try {
      applyCreditGateSchema(other)
      expect(audit.recordApprovalMismatches(other, NOW)).toBe(0)
      const { d } = deps()
      await expect(new AuditNotifier(other, d).deliver()).resolves.toMatchObject({ failed: 0 })
    } finally {
      other.close()
    }
  })
})

describe('the default deliverers', () => {
  const countMessages = () => (getDb().prepare('SELECT COUNT(*) AS n FROM agent_messages').get() as { n: number }).n

  it('info: a queue row from system to the main agent, and its id comes back', () => {
    const d = defaultNotifyDeps()
    const id = d.sendInfo('hello info')
    expect(typeof id).toBe('number')
    const m = getDb().prepare('SELECT * FROM agent_messages WHERE id = ?').get(id) as Record<string, any>
    expect(m).toMatchObject({ from_agent: 'system', to_agent: MAIN_AGENT_ID, content: 'hello info', status: 'pending' })
  })

  it('directive: counted only with the anchor row and a `sent` injection; the id is the anchor row\'s', async () => {
    const d = defaultNotifyDeps()
    const id = await d.sendDirective('do the thing')
    expect(directive.calls).toHaveLength(1)
    expect(directive.calls[0]).toMatchObject({ to: MAIN_AGENT_ID, text: 'do the thing' })
    expect(directive.calls[0]!.session.length).toBeGreaterThan(0)
    const m = getDb().prepare('SELECT * FROM agent_messages WHERE id = ?').get(id) as Record<string, any>
    expect(m).toMatchObject({ from_agent: 'system', to_agent: MAIN_AGENT_ID, content: 'do the thing' })
  })

  it('directive: the id of the right row when older rows with the same text exist', async () => {
    const d = defaultNotifyDeps()
    const first = await d.sendDirective('same text')
    const second = await d.sendDirective('same text')
    expect(second).toBeGreaterThan(first as number)
    expect(countMessages()).toBe(2)
  })

  it('directive: an injection that was not `sent` (busy, locked) returns no id, so the delivery is retried', async () => {
    const d = defaultNotifyDeps()
    for (const outcome of ['aborted-busy', 'skipped-locked']) {
      directive.outcome = outcome
      expect(await d.sendDirective('x')).toBeNull()
    }
  })

  it('directive: a sender that throws, or leaves no anchor row, returns no id', async () => {
    const d = defaultNotifyDeps()
    directive.createRow = false
    expect(await d.sendDirective('no row')).toBeNull()
    directive.createRow = true
    directive.outcome = 'sent'
    const throwing = defaultNotifyDeps({ sendSystemDirective: async () => { throw new Error('tmux gone') } })
    await expect(throwing.sendDirective('x')).rejects.toThrow('tmux gone')
  })

  it('the daily line goes to the main agent\'s log', () => {
    const d = defaultNotifyDeps()
    d.dailyLog('## 10:00 -- kredit-kapu\nline')
    const r = getDb().prepare('SELECT agent_id, content FROM daily_logs').get() as { agent_id: string; content: string }
    expect(r).toEqual({ agent_id: MAIN_AGENT_ID, content: '## 10:00 -- kredit-kapu\nline' })
  })
})
