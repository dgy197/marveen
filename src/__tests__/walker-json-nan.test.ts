import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// @ts-expect-error -- plain .mjs hook script, no types
import { gateDecision, hasForwardKey, hasForwardKeyName, mailEndpointWrite, mailToolAction, NO_EXEMPT } from '../../scripts/email-send-gate.mjs'

// card 5e3c31c5 N0 (RED first): a JSON-looking string whose JSON holds a bare NaN / Infinity / -Infinity
// literal. Python json.loads accepts the literals, so the three forward / write walkers of the python
// twin walk the string; JSON.parse throws and the JS walkers used to step over it (allow), a twin
// mismatch. The rows are the `name_independent.walker_json` block of the shared fixture; the python
// twin runs the same rows in scripts/__tests__/mail-tool-action.test.py. The forward key is hidden by a
// unicode escape, so only the parsed walk can see it. Reader corpus: walker-json-cases.test.ts.

const ROOT = join(__dirname, '..', '..')
const EXTRACT_DIR = join(ROOT, 'scripts', 'hooks')
type Walker = 'hasForwardKey' | 'hasForwardKeyName' | 'mailEndpointWrite'
const WJ = (JSON.parse(readFileSync(join(EXTRACT_DIR, 'mail-tool-action-cases.json'), 'utf-8')) as {
  name_independent: {
    walker_json: {
      direct: Array<{ walker: Walker; label: string; input: unknown; expected: boolean }>
      actions: Array<{ tool: string; input: unknown; expected: 'send' | 'draft' | null; note: string }>
    }
  }
}).name_independent.walker_json

const WALKERS: Record<Walker, (input: unknown) => boolean> = {
  hasForwardKey: (input) => hasForwardKey(input),
  hasForwardKeyName: (input) => hasForwardKeyName(input, true, false, NO_EXEMPT),
  mailEndpointWrite: (input) => mailEndpointWrite(input),
}

describe('walker JSON strings with NaN / Infinity (card 5e3c31c5)', () => {
  it('the block covers all three walkers, with signal and control rows', () => {
    expect(new Set(WJ.direct.map((r) => r.walker))).toEqual(new Set(Object.keys(WALKERS)))
    expect(new Set(WJ.direct.map((r) => r.expected))).toEqual(new Set([true, false]))
    expect(WJ.actions.length).toBeGreaterThan(0)
  })

  WJ.direct.forEach((r) => {
    it(`direct: ${r.label}`, () => {
      expect(WALKERS[r.walker](r.input)).toBe(r.expected)
    })
  })

  WJ.actions.forEach((a, i) => {
    it(`action ${i}: ${a.tool} ${a.expected}: ${a.note.slice(0, 90)}`, () => {
      expect(mailToolAction(a.tool, a.input)).toBe(a.expected)
    })
  })
})

// card 5e3c31c5 R1 (review E1/B1): a B-class endpoint in a JSON string whose body / method key holds a bare
// NaN / Infinity / -Infinity. Python reads a float (a body is non-empty), so the walker decides "write"; the
// JS reader used to give null (an empty body) and let it through. The DECISIONS of both twins are compared,
// not only the parsed structure: mailEndpointWrite / mail_endpoint_write true, mailToolAction /
// mail_tool_action send, gateDecision deny (JS only; the python side has no gate function).
const ENF = (JSON.parse(readFileSync(join(EXTRACT_DIR, 'mail-tool-action-cases.json'), 'utf-8')) as {
  name_independent: { walker_json: { endpoint_nonfinite: { tools: string[]; rows: Array<{ label: string; input: unknown }> } } }
}).name_independent.walker_json.endpoint_nonfinite

describe('B-class endpoint with a non-finite body / method: both twins decide the same (card 5e3c31c5 R1)', () => {
  const pairs = ENF.tools.flatMap((tool) => ENF.rows.map((r) => ({ tool, label: r.label, input: r.input })))
  const py = JSON.parse(execFileSync('python3', ['-I', '-c', `
import json, sys
sys.path.insert(0, ${JSON.stringify(EXTRACT_DIR)})
import email_extract as ee
print(json.dumps([[ee.mail_endpoint_write(p['input']), ee.mail_tool_action(p['tool'], p['input'])] for p in json.load(sys.stdin)]))
`], { input: JSON.stringify(pairs), encoding: 'utf-8' })) as Array<[boolean, string | null]>

  it('the block holds body and method rows for NaN, Infinity and -Infinity', () => {
    expect(ENF.tools).toHaveLength(3)
    expect(ENF.rows).toHaveLength(12)
    for (const key of ['body', 'method']) for (const tok of ['NaN', 'Infinity', '-Infinity']) {
      expect(ENF.rows.some((r) => (r.input as { request: string }).request.endsWith(`"${key}": ${tok}}`)), `${key} ${tok}`).toBe(true)
    }
    expect(py).toHaveLength(pairs.length)
  })

  pairs.forEach((p, i) => {
    it(`${p.tool}: ${p.label}`, () => {
      expect(mailEndpointWrite(p.input), 'JS mailEndpointWrite').toBe(true)
      expect(py[i][0], 'python mail_endpoint_write').toBe(true)
      expect(mailToolAction(p.tool, p.input), 'JS mailToolAction').toBe('send')
      expect(py[i][1], 'python mail_tool_action').toBe('send')
      expect(gateDecision(p.tool, p.input, () => false).deny, 'JS gateDecision deny').toBe(true)
    })
  })
})
