import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import { hasForwardKey, hasForwardKeyName, mailEndpointWrite, mailToolAction, NO_EXEMPT } from '../../scripts/email-send-gate.mjs'

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
