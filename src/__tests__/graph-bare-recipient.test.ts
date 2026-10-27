import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { isBareAddress, isBareAddressList, parseSendArgv } from '../graph-forward-validate.js'

// Card efa58ad2 (S2): the TypeScript half of the bare-recipient rule. The Python
// half (email_extract.bare_address_list_ok, used by the hook grammar and the
// authorizer helper) is tested in scripts/__tests__/email-send-authorize.test.py
// against the SAME vectors file.

const HERE = dirname(fileURLToPath(import.meta.url))
const VECT = JSON.parse(
  readFileSync(join(resolve(HERE, '..', '..'), 'scripts', 'hooks', 'graph-bare-recipient-cases.json'), 'utf-8'),
) as { valid: string[]; invalid: string[] }

describe('isBareAddressList on the shared vectors', () => {
  it('accepts every valid list', () => {
    expect(VECT.valid.filter((v) => !isBareAddressList(v))).toEqual([])
  })
  it('refuses every invalid list', () => {
    expect(VECT.invalid.filter((v) => isBareAddressList(v))).toEqual([])
  })
  it('refuses non-strings', () => {
    for (const v of [undefined, null, 5, ['a@b.hu']]) expect(isBareAddressList(v)).toBe(false)
    expect(isBareAddress('a@b.hu')).toBe(true)
  })
})

describe('parseSendArgv recipient rule', () => {
  const rest = ['--subject', 'S', '--body', 'B']
  it('accepts a bare list for --to and --cc', () => {
    expect(parseSendArgv(['--to', 'a@fireeng.hu,b@fireeng.hu', '--cc', 'c@fireeng.hu', ...rest]).ok).toBe(true)
  })
  it('refuses a non-bare --to or --cc with a clear error', () => {
    for (const bad of VECT.invalid.filter((v) => v !== '')) {
      for (const argv of [
        ['--to', bad, ...rest],
        ['--to', 'a@fireeng.hu', '--cc', bad, ...rest],
      ]) {
        // a value starting with "--" or an empty --to is refused earlier, by another rule; both are refusals
        const r = parseSendArgv(argv)
        expect(r.ok, JSON.stringify(argv)).toBe(false)
      }
    }
    const r = parseSendArgv(['--to', 'Name <a@fireeng.hu>', ...rest])
    expect(r.ok === false && /bare addresses/.test(r.error)).toBe(true)
  })
  it('refuses an empty --cc', () => {
    expect(parseSendArgv(['--to', 'a@fireeng.hu', '--cc', '', ...rest]).ok).toBe(false)
  })
})
