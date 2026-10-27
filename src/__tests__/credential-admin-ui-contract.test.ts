// Card 053f4e66 B, node N4. The shared Bearer token may not issue credentials
// unless the install switch is open; the dashboard then answers 403 with the
// stable code `bearer_credential_admin_off`. This file pins the UI side:
//  1. the device-key expiry field mirrors the server rule (max = the TS
//     constant, placeholder names 90 and 365, in both languages);
//  2. credentialAdminErrorText, evaluated out of web/app.js with a stub t(),
//     translates the known code per action, falls back to the server's sentence
//     for an unknown code, then to the generic message, and never shows a raw
//     key name;
//  3. every mint / create call site really goes through that function, and the
//     Bridge reaches its own key through bridgeEnrollErrorText;
//  4. MUTATION CONTROLS show the assertions can go red.
import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'
import { FULL_KEY_MAX_EXPIRY_DAYS, FULL_KEY_DEFAULT_EXPIRY_DAYS } from '../web/auth-device-keys.js'
import { BEARER_CREDENTIAL_ADMIN_OFF } from '../web/credential-admin.js'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '../..')
const APP = readFileSync(join(ROOT, 'web/app.js'), 'utf-8')

let hu: Record<string, string>
let en: Record<string, string>

beforeAll(async () => {
  ;(globalThis as unknown as { window: Record<string, unknown> }).window ||= {} as Record<string, unknown>
  await import(/* @vite-ignore */ '../../web/lang/hu.js' as string)
  await import(/* @vite-ignore */ '../../web/lang/en.js' as string)
  const i18n = (globalThis as unknown as { window: { _i18n: Record<string, Record<string, string>> } }).window._i18n
  hu = i18n.hu
  en = i18n.en
})

const KINDS = ['device', 'operator', 'user'] as const

function loadErrorText(dict: Record<string, string>, source = APP) {
  const start = source.indexOf('const CREDENTIAL_ADMIN_ERR_KEYS')
  expect(start, 'CREDENTIAL_ADMIN_ERR_KEYS not found in web/app.js').toBeGreaterThan(-1)
  const fnStart = source.indexOf('function credentialAdminErrorText(data, kind) {', start)
  expect(fnStart, 'credentialAdminErrorText not found in web/app.js').toBeGreaterThan(-1)
  const end = source.indexOf('\n}', fnStart) + 2
  const src = source.slice(start, end)
  const t = (key: string) => dict[key] ?? key
  return new Function('t', `${src}; return credentialAdminErrorText`)(t) as (d: unknown, k?: string) => string
}

describe('N4 -- device-key expiry field mirrors the server rule (U2)', () => {
  it('authDevExpiry max equals FULL_KEY_MAX_EXPIRY_DAYS, and the old 3650 is gone', () => {
    const m = APP.match(/<input id="authDevExpiry"[^>]*>/)
    expect(m, 'authDevExpiry input not found').not.toBeNull()
    const input = m![0]
    expect(input).toContain(`max="${FULL_KEY_MAX_EXPIRY_DAYS}"`)
    expect(input).toContain('min="1"')
    expect(input).not.toContain('3650')
  })

  it('the placeholder names the default and the maximum in both languages', () => {
    for (const dict of [hu, en]) {
      const p = dict['auth.devices.expiry_placeholder']
      expect(p).toContain(String(FULL_KEY_DEFAULT_EXPIRY_DAYS))
      expect(p).toContain(String(FULL_KEY_MAX_EXPIRY_DAYS))
    }
    expect(hu['auth.devices.expiry_placeholder']).toBe('Lejárat (nap, üresen 90, legfeljebb 365)')
    expect(en['auth.devices.expiry_placeholder']).toBe('Expiry (days, empty = 90, max 365)')
  })

  it('the placeholder no longer promises a key that never expires', () => {
    expect(hu['auth.devices.expiry_placeholder']).not.toMatch(/nincs/)
    expect(en['auth.devices.expiry_placeholder']).not.toMatch(/none|never/i)
  })

  it('MUTATION CONTROL: a max of 3650 would be caught', () => {
    const mutated = APP.replace('id="authDevExpiry" type="number" min="1" max="365"', 'id="authDevExpiry" type="number" min="1" max="3650"')
    expect(mutated).not.toBe(APP)
    const input = mutated.match(/<input id="authDevExpiry"[^>]*>/)![0]
    expect(input.includes(`max="${FULL_KEY_MAX_EXPIRY_DAYS}"`)).toBe(false)
  })
})

describe('N4 -- the gate refusal is explained, never raw (U1)', () => {
  it('the code the UI translates is the code the server sends', () => {
    expect(BEARER_CREDENTIAL_ADMIN_OFF).toBe('bearer_credential_admin_off')
    expect(APP).toContain(`${BEARER_CREDENTIAL_ADMIN_OFF}: 'off'`)
  })

  it('every action has a hu and an en message, and hu differs from en', () => {
    for (const k of KINDS) {
      const key = `auth.credadmin.off.${k}`
      expect(hu, `hu is missing ${key}`).toHaveProperty(key)
      expect(en, `en is missing ${key}`).toHaveProperty(key)
      expect(hu[key]).not.toBe(en[key])
    }
    expect(hu).toHaveProperty(`auth.bridge.err.${BEARER_CREDENTIAL_ADMIN_OFF}`)
    expect(en).toHaveProperty(`auth.bridge.err.${BEARER_CREDENTIAL_ADMIN_OFF}`)
  })

  it('device, operator and Bridge tell the owner to log in with the password in a private window', () => {
    for (const k of ['device', 'operator'] as const) {
      expect(hu[`auth.credadmin.off.${k}`]).toMatch(/privát/)
      expect(en[`auth.credadmin.off.${k}`]).toMatch(/private/)
    }
    expect(hu[`auth.bridge.err.${BEARER_CREDENTIAL_ADMIN_OFF}`]).toMatch(/privát/)
    expect(en[`auth.bridge.err.${BEARER_CREDENTIAL_ADMIN_OFF}`]).toMatch(/private/)
  })

  it('the first-user text names the command to run on the machine, without a spaced double hyphen', () => {
    expect(hu['auth.credadmin.off.user']).toContain('npx tsx scripts/dashboard-user.ts add')
    expect(en['auth.credadmin.off.user']).toContain('npx tsx scripts/dashboard-user.ts add')
    expect(hu['auth.credadmin.off.user']).not.toMatch(/\s--\s/)
    expect(en['auth.credadmin.off.user']).not.toMatch(/\s--\s/)
  })

  it('the known code renders the translated text for each action, in both languages', () => {
    for (const dict of [hu, en]) {
      const f = loadErrorText(dict)
      for (const k of KINDS) {
        const out = f({ error: 'Credential administration with the shared token is off (set BEARER_CREDENTIAL_ADMIN_ENABLED)', code: BEARER_CREDENTIAL_ADMIN_OFF }, k)
        expect(out).toBe(dict[`auth.credadmin.off.${k}`])
        expect(out).not.toContain('BEARER_CREDENTIAL_ADMIN_ENABLED')
        expect(out).not.toContain('auth.credadmin')
      }
    }
  })

  it('an unknown code falls back to the server sentence, never to a raw key', () => {
    const f = loadErrorText(hu)
    const out = f({ error: 'something new the server added', code: 'not_translated_yet' }, 'device')
    expect(out).toBe('something new the server added')
    expect(out).not.toContain('auth.credadmin')
  })

  it('no code still shows the server sentence; an empty body shows the generic message', () => {
    const f = loadErrorText({ ...hu, 'auth.card.err_generic': 'A művelet nem sikerült.' })
    expect(f({ error: 'Invalid expires_in_days (1-365)' }, 'device')).toBe('Invalid expires_in_days (1-365)')
    expect(f({}, 'device')).toBe('A művelet nem sikerült.')
    expect(f(null, 'device')).toBe('A művelet nem sikerült.')
  })

  it('an unknown kind or a prototype-chain code never produces a raw key', () => {
    const f = loadErrorText(hu)
    expect(f({ error: 'srv', code: BEARER_CREDENTIAL_ADMIN_OFF }, 'nonsense')).toBe('srv')
    expect(f({ error: 'srv', code: 'constructor' }, 'device')).toBe('srv')
    expect(f({ error: 'srv', code: '__proto__' }, 'device')).toBe('srv')
  })

  it('MUTATION CONTROL: a misspelled code in the UI map turns the known-code test red', () => {
    const mutated = APP.replace(`${BEARER_CREDENTIAL_ADMIN_OFF}: 'off'`, `bearer_credential_admin_of: 'off'`)
    expect(mutated).not.toBe(APP)
    const f = loadErrorText(hu, mutated)
    const out = f({ error: 'server sentence', code: BEARER_CREDENTIAL_ADMIN_OFF }, 'device')
    expect(out).not.toBe(hu['auth.credadmin.off.device'])
  })

  it('MUTATION CONTROL: with an empty dictionary the known code degrades to the server sentence', () => {
    const f = loadErrorText({})
    expect(f({ error: 'server sentence', code: BEARER_CREDENTIAL_ADMIN_OFF }, 'device')).toBe('server sentence')
  })
})

describe('N4 -- every credential-issuing call site uses the translator', () => {
  const body = (start: string) => {
    const i = APP.indexOf(start)
    expect(i, `${start} not found`).toBeGreaterThan(-1)
    return APP.slice(i, APP.indexOf('\n}\n', i))
  }

  it('mintDeviceKey, mintOperatorKey and the first-user form call credentialAdminErrorText with their kind', () => {
    expect(body('async function mintDeviceKey()')).toContain(`credentialAdminErrorText(data, 'device')`)
    expect(body('async function mintOperatorKey()')).toContain(`credentialAdminErrorText(data, 'operator')`)
    expect(body('function renderCreateLoginForm(body)')).toContain(`credentialAdminErrorText(data, 'user')`)
  })

  it('none of the three prints the raw server error any more', () => {
    for (const fn of ['async function mintDeviceKey()', 'async function mintOperatorKey()', 'function renderCreateLoginForm(body)']) {
      expect(body(fn)).not.toMatch(/textContent = data\.error \|\|/)
    }
  })

  it('the Bridge pairing keeps going through bridgeEnrollErrorText', () => {
    expect(body('async function bridgeEnrollFromUi()')).toContain('bridgeEnrollErrorText(data)')
  })
})
