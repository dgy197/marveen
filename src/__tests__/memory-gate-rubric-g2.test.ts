/**
 * Memory write gate, rubric g2 (card 3e9f6c28, b2): the shadow week showed 21 of 49 decided rows with a
 * non-CREATE op below its threshold, nearly all for a merely RELATED earlier entry. g2 tells the model that
 * related is not the same and that a low-confidence link is a CREATE; the parser downgrades a non-CREATE
 * answer whose own reason says the entries do not overlap.
 */
import { describe, it, expect } from 'vitest'
import { buildSystem, RUBRIC } from '../memory-gate/prompt.js'
import { parseGateOutput } from '../memory-gate/parse.js'

const NONCE = '0123456789abcdef'
const LABELS = ['C1', 'C2']
const ans = (op: string, target: string | null, confidence: number, reason: string) =>
  JSON.stringify({ op, target, confidence, reason })

describe('g2 rubric text', () => {
  const sys = buildSystem(NONCE)
  it('is rubric g2', () => {
    expect(RUBRIC).toBe('g2')
  })
  it('says a related entry is a CREATE, not a link', () => {
    expect(sys).toMatch(/related is not the same/i)
    expect(sys).toMatch(/same project, person or topic is not enough/i)
  })
  it('says a non-CREATE operation needs confidence 0.7 or more, otherwise CREATE', () => {
    expect(sys).toMatch(/below 0\.7.*CREATE/i)
  })
  it('says the reason must agree with the operation', () => {
    expect(sys).toMatch(/if your reason says the entries differ.*CREATE/i)
  })
})

describe('g2 parser: a non-CREATE op whose reason says there is no overlap becomes CREATE', () => {
  it.each([
    ['REINFORCE', 'A NEW a képes bemenet mérését írja le; nincs közvetlen átfedés az egyikkel sem'],
    ['SUPERSEDE', 'The two concern different settings; no overlap with C1'],
    ['REINFORCE', 'Related topic, but not the same fact as C2'],
    ['SUPERSEDE', 'A new lesson that does not clearly replace C1'],
    ['REINFORCE', 'Nem ugyanaz a tény, csak rokon téma'],
  ])('%s with "%s"', (op, reason) => {
    const r = parseGateOutput(ans(op, 'C1', 0.4, reason), LABELS, NONCE)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.decision.op).toBe('CREATE')
    expect(r.decision.target).toBeNull()
    expect(r.decision.downgraded).toBe('reason_says_new')
  })

  it.each([
    ['REINFORCE', 'The new entry restates the same rule as C1'],
    ['SUPERSEDE', 'same setting, newer value'],
    ['SUPERSEDE', 'The C-REACQ export replaces the earlier C export as the current backup'],
    ['CONTRADICT', 'incompatible with C2 about the same deadline'],
  ])('keeps %s when the reason agrees: "%s"', (op, reason) => {
    const r = parseGateOutput(ans(op, 'C2', 0.9, reason), LABELS, NONCE)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.decision.op).toBe(op)
    expect(r.decision.target).toBe('C2')
    expect(r.decision.downgraded).toBeUndefined()
  })

  it('a CREATE is never marked', () => {
    const r = parseGateOutput(ans('CREATE', null, 0.8, 'no overlap with any earlier entry'), LABELS, NONCE)
    expect(r.ok && r.decision.downgraded).toBeFalsy()
  })
})
