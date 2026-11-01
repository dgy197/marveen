import { describe, it, expect } from 'vitest'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

// @ts-expect-error -- plain .mjs hook script, no types
import * as gate from '../../scripts/email-send-gate.mjs'

// card 5e3c31c5 N0: the reader corpus of the walker JSON reader (parseWalkerJson, N1). Each row says whether
// the reader must accept the text; the python reader (_walker_json_loads in scripts/hooks/email_extract.py)
// runs the same rows in scripts/__tests__/walker-json-cases.test.py. A missing parseWalkerJson export fails
// (no skip: card 5e3c31c5 review E3).

const ROOT = join(__dirname, '..', '..')
type Row = { label: string; text?: string; repeat?: string; count?: number; template?: string; accept: boolean }
const CORPUS = (JSON.parse(readFileSync(join(ROOT, 'scripts', 'hooks', 'walker-json-cases.json'), 'utf-8')) as { rows: Row[] }).rows
const reader = (gate as Record<string, unknown>).parseWalkerJson as (v: string) => unknown

export function rowText(r: Row): string {
  if (r.template !== undefined) return r.template.replace('%s', (r.repeat ?? '').repeat(r.count ?? 0))
  return r.text ?? ''
}

// A non-finite number is compared as a tagged value, never as null (card 5e3c31c5 R1, review E1/B1): a null on one
// side and a number on the other must fail. The tag is {"$nonfinite": "Infinity" | "-Infinity"}. JS cannot hold
// a NaN read from 1e999 (the reader turns NaN into 1e999, which JSON.parse reads as Infinity), so JS Infinity
// stands for python nan and inf alike: python maps nan and inf to "Infinity", -inf to "-Infinity".
function tagJs(x: unknown): unknown {
  if (typeof x === 'number') return Number.isFinite(x) ? x : { $nonfinite: x > 0 ? 'Infinity' : '-Infinity' }
  if (Array.isArray(x)) return x.map(tagJs)
  if (typeof x === 'object' && x !== null) return Object.fromEntries(Object.entries(x).map(([k, v]) => [k, tagJs(v)]))
  return x
}

// N3: twin parity. The python reader gets every corpus text in one process (stdin -> stdout); accept / reject and
// the parsed structure (non-finite numbers tagged, see tagJs) must equal the JS reader's.
describe('python _walker_json_loads and parseWalkerJson agree on every corpus row (card 5e3c31c5)', () => {
  it('parseWalkerJson is exported by the gate script', () => {
    expect(typeof reader).toBe('function')
  })

  it('the same accept / reject and the same structure', () => {
    const texts = CORPUS.map(rowText)
    const out = execFileSync('python3', ['-I', '-c', `
import json, math, sys
sys.path.insert(0, ${JSON.stringify(join(ROOT, 'scripts', 'hooks'))})
from email_extract import _walker_json_loads
def norm(x):
    if isinstance(x, float):
        if math.isfinite(x):
            return x
        return {'$nonfinite': 'Infinity' if (x > 0 or x != x) else '-Infinity'}
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
      try { js = { ok: true, v: JSON.parse(JSON.stringify(tagJs(reader(t)))) } } catch { js = { ok: false } }
      expect(js.ok, `accept / reject: ${CORPUS[k].label}`).toBe(py[k].ok)
      expect(js.ok, `shared column: ${CORPUS[k].label}`).toBe(CORPUS[k].accept)
      if (js.ok) expect(js.v, `structure: ${CORPUS[k].label}`).toEqual(JSON.parse(JSON.stringify(py[k].v))) // both sides through JSON text: -0 and 0 are one value there
    })
  })
})

describe('parseWalkerJson accepts exactly what the python reader accepts (card 5e3c31c5)', () => {
  CORPUS.forEach((r) => {
    it(`${r.accept ? 'accepts' : 'rejects'}: ${r.label}`, () => {
      const text = rowText(r)
      if (r.accept) {
        expect(() => reader(text)).not.toThrow()
      } else {
        expect(() => reader(text)).toThrow(SyntaxError)
      }
    })
  })
})
