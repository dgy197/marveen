import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// @ts-expect-error -- plain .mjs hook script, no types
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

// N3: twin parity. The python reader gets every corpus text in one process (stdin -> stdout); accept / reject and
// the parsed structure must equal the JS reader's. NaN / Infinity / -Infinity are null on both sides (python
// non-finite floats are mapped to None, JSON.stringify writes a non-finite number as null).
describe.skipIf(typeof reader !== 'function')('python _walker_json_loads and parseWalkerJson agree on every corpus row (card 5e3c31c5)', () => {
  it('the same accept / reject and the same structure', () => {
    const texts = CORPUS.map(rowText)
    const out = execFileSync('python3', ['-I', '-c', `
import json, math, sys
sys.path.insert(0, ${JSON.stringify(join(ROOT, 'scripts', 'hooks'))})
from email_extract import _walker_json_loads
def norm(x):
    if isinstance(x, float):
        return x if math.isfinite(x) else None
    if isinstance(x, dict):
        return {k: norm(v) for k, v in x.items()}
    if isinstance(x, list):
        return [norm(v) for v in x]
    return x
res = []
for t in json.load(sys.stdin):
    try:
        res.append({'ok': True, 'v': norm(_walker_json_loads(t))})
    except ValueError:
        res.append({'ok': False})
print(json.dumps(res))
`], { input: JSON.stringify(texts), encoding: 'utf-8' })
    const py = JSON.parse(out) as Array<{ ok: boolean; v?: unknown }>
    expect(py.length).toBe(texts.length)
    texts.forEach((t, k) => {
      let js: { ok: boolean; v?: unknown }
      try { js = { ok: true, v: JSON.parse(JSON.stringify(reader!(t))) } } catch { js = { ok: false } }
      expect(js.ok, `accept / reject: ${CORPUS[k].label}`).toBe(py[k].ok)
      expect(js.ok, `shared column: ${CORPUS[k].label}`).toBe(CORPUS[k].accept)
      if (js.ok) expect(js.v, `structure: ${CORPUS[k].label}`).toEqual(JSON.parse(JSON.stringify(py[k].v))) // both sides through JSON text: -0 and 0 are one value there
    })
  })
})

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
