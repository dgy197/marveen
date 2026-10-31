import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, mailToolAction, manageEmailOpClosed, manageEmailOpKey, manageEmailOpOutbound } from '../../scripts/email-send-gate.mjs'

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
  classifier_edges: Array<{ tool: unknown; expected: 'send' | 'draft' | null; note: string }>
}
const AS_CLASS: Record<Expected, 'send' | 'draft' | null> = { send: 'send', draft: 'draft', nonsend: null }

// One python process for every name: stdin carries the names, stdout the classes.
function pythonActions(names: unknown[]): Array<string | null> {
  const out = execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
from email_extract import mail_tool_action
print(json.dumps([mail_tool_action(n) for n in json.load(sys.stdin)]))
`], { encoding: 'utf-8', input: JSON.stringify(names) })
  return JSON.parse(out.trim())
}

const RECIPIENT_FIELDS = ['to', 'cc', 'bcc', 'recipients', 'recipient', 'recipient_email']
const hasRecipient = (input: Record<string, unknown>) =>
  RECIPIENT_FIELDS.some((f) => input[f] !== undefined && input[f] !== null && input[f] !== '')

describe('mail-tool action: python and JS agree with the shared contract', () => {
  const caseNames = VECTORS.cases.map((c) => c.tool)
  const edgeNames = VECTORS.classifier_edges.map((e) => e.tool)
  const py = pythonActions([...caseNames, ...edgeNames])

  VECTORS.cases.forEach((c, i) => {
    it(`${c.tool} -> ${c.expected}`, () => {
      expect(mailToolAction(c.tool), 'JS').toBe(AS_CLASS[c.expected])
      expect(py[i], 'python').toBe(AS_CLASS[c.expected])
    })
  })

  VECTORS.classifier_edges.forEach((e, i) => {
    it(`edge ${JSON.stringify(e.tool)} -> ${e.expected} (${e.note})`, () => {
      expect(mailToolAction(e.tool), 'JS').toBe(e.expected)
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
    it(`${JSON.stringify(r.op)}: ${r.outbound ? 'draft-required' : 'passes'}`, () => {
      const v = gateDecision(ME, { operation: r.op, to: ['a@b.hu'], body: 'Kedves Ugyfelunk!' }, () => true)
      expect(v).toEqual(r.outbound ? { deny: true, kind: 'draft-required' } : { deny: false })
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

  it('a missing or non-string operation keeps the pre-r5 reading (String(), not outbound unless it spells one)', () => {
    for (const v of [undefined, null, 123, {}, true]) {
      expect(gateDecision(ME, { operation: v, to: ['a@b.hu'] }, () => true), String(v)).toEqual({ deny: false })
    }
    // String(['reply_all']) is 'reply_all': an array holding one outbound name was outbound before, too.
    expect(gateDecision(ME, { operation: ['reply_all'], to: ['a@b.hu'] }, () => true).kind).toBe('draft-required')
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

  it('a draft-path call with no recipient (a label) is not blocked', () => {
    expect(gateDecision('mcp__gmail__create_label', { name: 'Ugyfel' }, () => false)).toEqual({ deny: false })
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
