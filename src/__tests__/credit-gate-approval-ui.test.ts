import { describe, it, expect, vi } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// Credit gate, node N2b (card fec6335f, BE-3b LOW-2): the dashboard's
// approvals page shows a credit_gate_* request but offers no decision on it.
// The gate accepts only the owner's Telegram button (owner:telegram: with the
// trace of isOwnerVerified), so a dashboard approve would be a decision that
// counts for nothing. The helpers are cut out of web/app.js and run with stubs
// (the house idiom reads the frontend as text; here the logic also runs).

const APP = readFileSync(join(__dirname, '../../web/app.js'), 'utf-8')
const HU = readFileSync(join(__dirname, '../../web/lang/hu.js'), 'utf-8')
const EN = readFileSync(join(__dirname, '../../web/lang/en.js'), 'utf-8')

// The source of one top-level function of app.js, braces balanced.
function fnSource(name: string): string {
  const head = APP.search(new RegExp(`\\n(async )?function ${name}\\(`))
  if (head < 0) throw new Error(`no function ${name} in web/app.js`)
  const open = APP.indexOf('{', APP.indexOf(')', head))
  let depth = 0
  for (let i = open; i < APP.length; i++) {
    if (APP[i] === '{') depth++
    else if (APP[i] === '}' && --depth === 0) return APP.slice(head + 1, i + 1)
  }
  throw new Error(`unbalanced function ${name}`)
}

type Row = { id: string; category: unknown; status: string; resolved_by?: string | null; resolved_at?: number | null; requested_at?: number }

const isTelegramOnly = new Function(`${fnSource('_approvalIsTelegramOnly')}; return _approvalIsTelegramOnly`)() as (a: unknown) => boolean
const actionsHtml = new Function('t', 'escapeAttr', 'escapeHtml',
  `${fnSource('_approvalIsTelegramOnly')}\n${fnSource('_approvalActionsHtml')}; return _approvalActionsHtml`,
)((k: string) => `T(${k})`, (s: string) => s, (s: string) => s) as (a: Row) => string

describe('the dashboard approvals page and credit_gate_* requests (N2b, BE-3b LOW-2)', () => {
  it('_approvalIsTelegramOnly: every credit_gate_ category, nothing else', () => {
    for (const c of ['credit_gate_calibration', 'credit_gate_canary', 'credit_gate_incident_clear', 'credit_gate_future']) {
      expect(isTelegramOnly({ category: c })).toBe(true)
    }
    for (const c of ['email_send', 'kanban_move', 'credit-gate-calibration', '', undefined, 42, null]) {
      expect(isTelegramOnly({ category: c })).toBe(false)
    }
    expect(isTelegramOnly(null)).toBe(false)
  })

  it('a pending credit-gate row gets the view-only note and no decide button; any other pending row keeps both buttons', () => {
    const cg = actionsHtml({ id: 'a1', category: 'credit_gate_canary', status: 'pending' })
    expect(cg).not.toContain('approvals-decide')
    expect(cg).toContain('T(approvals.telegram_only)')
    const other = actionsHtml({ id: 'a2', category: 'email_send', status: 'pending' })
    expect(other.match(/approvals-decide/g)).toHaveLength(2)
    expect(other).toContain('data-decision="approved"')
    expect(other).toContain('data-decision="rejected"')
  })

  it('a decided row of any category shows who decided it, as before', () => {
    const html = actionsHtml({ id: 'a3', category: 'credit_gate_calibration', status: 'rejected', resolved_by: 'system:payload_mismatch', resolved_at: 1_792_000_000, requested_at: 1_791_999_000 })
    expect(html).toContain('system:payload_mismatch')
    expect(html).not.toContain('approvals-decide')
  })

  it('the table renders its actions through the helper', () => {
    const render = fnSource('_renderApprovalsTable')
    expect(render).toContain('const actions = _approvalActionsHtml(a)')
    expect(render).not.toContain('data-decision="approved"')
  })

  it('_resolveApproval sends no PATCH for a credit-gate row, and still does for any other', async () => {
    const fetchSpy = vi.fn(async () => ({ ok: true, json: async () => ({}) }))
    const toasts: string[] = []
    const all: Row[] = [
      { id: 'cg', category: 'credit_gate_incident_clear', status: 'pending' },
      { id: 'em', category: 'email_send', status: 'pending' },
    ]
    const resolve = new Function('fetch', 'showToast', 't', '_approvalsAll', '_renderApprovalsStats', '_renderApprovalsTable',
      `${fnSource('_approvalIsTelegramOnly')}\n${fnSource('_resolveApproval')}; return _resolveApproval`,
    )(fetchSpy, (m: string) => toasts.push(m), (k: string) => k, all, () => {}, () => {}) as (id: string, d: string) => Promise<void>
    await resolve('cg', 'approved')
    expect(fetchSpy).not.toHaveBeenCalled()
    expect(toasts).toEqual(['approvals.telegram_only'])
    await resolve('em', 'approved')
    expect(fetchSpy).toHaveBeenCalledTimes(1)
  })

  it('the note exists in both languages', () => {
    expect(HU).toMatch(/'approvals\.telegram_only':\s+'[^']+'/)
    expect(EN).toMatch(/'approvals\.telegram_only':\s+'[^']+'/)
  })
})
