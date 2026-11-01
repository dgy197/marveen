import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

import * as gate from '../../scripts/email-send-gate.mjs'

// card 5e3c31c5 N0: the reader corpus of the walker JSON reader (parseWalkerJson, N1). Each row says whether
// the reader must accept the text; the python reader (_walker_json_loads in scripts/hooks/email_extract.py)
// runs the same rows in scripts/__tests__/walker-json-cases.test.py. Until N1 exports parseWalkerJson the
// block is skipped (not green by accident, reported as skipped).

const ROOT = join(__dirname, '..', '..')
type Row = { label: string; text?: string; repeat?: string; count?: number; template?: string; accept: boolean }
const CORPUS = (JSON.parse(readFileSync(join(ROOT, 'scripts', 'hooks', 'walker-json-cases.json'), 'utf-8')) as { rows: Row[] }).rows
const reader = (gate as Record<string, unknown>).parseWalkerJson as ((v: string) => unknown) | undefined

export function rowText(r: Row): string {
  if (r.template !== undefined) return r.template.replace('%s', (r.repeat ?? '').repeat(r.count ?? 0))
  return r.text ?? ''
}

describe.skipIf(typeof reader !== 'function')('parseWalkerJson accepts exactly what the python reader accepts (card 5e3c31c5)', () => {
  CORPUS.forEach((r) => {
    it(`${r.accept ? 'accepts' : 'rejects'}: ${r.label}`, () => {
      const text = rowText(r)
      if (r.accept) {
        expect(() => reader!(text)).not.toThrow()
      } else {
        expect(() => reader!(text)).toThrow(SyntaxError)
      }
    })
  })
})
