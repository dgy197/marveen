import { describe, it, expect, beforeEach } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  CANARY_BUDGET_LIMIT_MICRO,
  CREDIT_GATE_APPROVAL_CATEGORIES,
  MAX_GRANTS,
  MAX_GRANTS_TOTAL_USD_MICRO,
  MAX_GRANT_USD_MICRO,
  MAX_PAYLOAD_CHARS,
  claimsCreditGatePrefix,
  creditGateBinding,
  creditGateContentHash,
  isCreditGateCategory,
  parseCreditGatePayload,
  type CreditGatePayload,
} from '../web/credit-gate/approval-payload.js'
import { MAX_GRANT_MICRO, MAX_GRANTS_TOTAL_MICRO } from '../web/credit-gate/gate.js'
import {
  buildCreditGateApprovalText,
  buildCreditGatePlainText,
  formatCreditGateOutcomeText,
} from '../web/approval-telegram-text.js'
import { TEST_RUN_PREFIX } from '../test-run-marker.js'
import {
  initDatabase, createApproval, getApproval, getDb,
  setApprovalCallbackNonceHashes, setApprovalTelegramMessageId, resolveApprovalFromTelegram,
} from '../db.js'

// Credit gate, node N2b (card fec6335f, blueprint 3.7): the bound payloads of
// the three credit_gate_* approvals. A payload is accepted only in its
// canonical form (keys sorted, no whitespace, UTF-8), the content_hash is the
// sha256 of exactly that text, every number is a strict two-decimal string,
// and nothing is free text. No network: the only child process is a local
// python3 -I that computes the reference canonical form (the requester side
// builds the payload with Python's json.dumps).

const sha = (s: string) => createHash('sha256').update(s, 'utf8').digest('hex')

// Python's json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
// computed by Python itself, plus the sha256 of its UTF-8 bytes.
function pythonCanonical(values: unknown[]): Array<{ text: string; sha: string }> {
  const prog = [
    'import hashlib, json, sys',
    'out = []',
    'for v in json.load(sys.stdin):',
    '    t = json.dumps(v, ensure_ascii=False, sort_keys=True, separators=(",", ":"))',
    '    out.append({"text": t, "sha": hashlib.sha256(t.encode("utf-8")).hexdigest()})',
    'sys.stdout.write(json.dumps(out))',
  ].join('\n')
  const res = spawnSync('python3', ['-I', '-c', prog], { input: JSON.stringify(values), encoding: 'utf-8', timeout: 60_000 })
  if (res.status !== 0) throw new Error(`python3 exit ${res.status}: ${res.stderr}`)
  return JSON.parse(res.stdout) as Array<{ text: string; sha: string }>
}

// A test-local canonical form (keys sorted, no whitespace) for building inputs.
function canon(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canon).join(',')}]`
  if (v !== null && typeof v === 'object') {
    return `{${Object.keys(v).sort().map((k) => `${JSON.stringify(k)}:${canon((v as Record<string, unknown>)[k])}`).join(',')}}`
  }
  return JSON.stringify(v)
}

const CAL_ID = '6b7e1c2a-3d4f-4a5b-8c6d-7e8f9a0b1c2d'

function grant(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { granted: '2026-10-10', expires: '2026-10-17', original_usd: '200.00', remaining_usd: '195.64', ...over }
}

function calibration(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_calibration',
    captured_at_lb: '2026-10-15T08:00:00Z',
    grants: [grant(), grant({ granted: '2026-10-14', expires: '2026-11-17', remaining_usd: '200.00' })],
    protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.00' } },
    screenshot: '/Volumes/8T/console/2026-10-15.png',
    ...over,
  }
}

function canary(over: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    v: 1,
    kind: 'credit_gate_canary',
    config_hash: 'ab'.repeat(32),
    model: 'claude-sonnet-5-5',
    budget_usd: '0.90',
    min_expected_usd: '0.10',
    before_calibration_id: CAL_ID,
    node: 'N4b',
    cwd: '/Volumes/8T/10_LOCAL/Brainy/credit-fallback',
    prompt_sha256: 'cd'.repeat(32),
    ...over,
  }
}

function incidentClear(over: Record<string, unknown> = {}): Record<string, unknown> {
  return { v: 1, kind: 'credit_gate_incident_clear', incident_event_id: 42, ...over }
}

const parse = (category: string, payload: unknown) => parseCreditGatePayload(category, canon(payload))
const fieldOf = (r: ReturnType<typeof parseCreditGatePayload>) => (r.ok ? 'OK' : r.field)

describe('the credit_gate_* categories', () => {
  it('are exactly the three of blueprint 3.7, and the prefix is recognised regardless of case and whitespace', () => {
    expect([...CREDIT_GATE_APPROVAL_CATEGORIES]).toEqual(['credit_gate_calibration', 'credit_gate_canary', 'credit_gate_incident_clear'])
    for (const c of CREDIT_GATE_APPROVAL_CATEGORIES) expect(isCreditGateCategory(c)).toBe(true)
    for (const c of ['credit_gate_open', 'Credit_Gate_Calibration', ' credit_gate_canary', 'email_send', '', null, 1]) {
      expect(isCreditGateCategory(c)).toBe(false)
    }
    for (const c of ['credit_gate_open', ' Credit_Gate_Calibration ', 'CREDIT_GATE_X', 'credit_gate_ canary']) expect(claimsCreditGatePrefix(c)).toBe(true)
    for (const c of ['credit gate', 'creditgate_x', 'email_send', 'kanban_move']) expect(claimsCreditGatePrefix(c)).toBe(false)
  })

  it('use the same grant bounds as the gate (a reading the gate would refuse is not offered either)', () => {
    expect(MAX_GRANT_USD_MICRO).toBe(MAX_GRANT_MICRO)
    expect(MAX_GRANTS_TOTAL_USD_MICRO).toBe(MAX_GRANTS_TOTAL_MICRO)
    expect(MAX_GRANTS).toBe(16)
  })
})

describe('parseCreditGatePayload: the valid payloads', () => {
  it.each([
    ['credit_gate_calibration', calibration()],
    ['credit_gate_canary', canary()],
    ['credit_gate_incident_clear', incidentClear()],
  ])('%s: accepted in canonical form; the content hash is the sha256 of exactly that text', (category, payload) => {
    const text = canon(payload)
    const r = parseCreditGatePayload(category, text)
    expect(r.ok).toBe(true)
    if (!r.ok) return
    expect(r.canonical).toBe(text)
    expect(r.contentHash).toBe(sha(text))
    expect(creditGateContentHash(text)).toBe(sha(text))
    expect(r.payload).toEqual(payload)
  })

  it('the canonical form and its hash equal Python\'s json.dumps(sort_keys, compact, ensure_ascii=False), non-ASCII paths included', () => {
    const payloads = [
      calibration(),
      // Hungarian accented letters (NFC), the only non-ASCII a path may carry.
      calibration({ screenshot: '/Volumes/8T/00 CLOUD/Képernyőfotó 2026-10-15 9.41.23.png' }),
      calibration({ screenshot: '/Users/x/ÁÉÍÓÖŐÚÜŰ áéíóöőúüű.png' }),
      calibration({ grants: Array.from({ length: 16 }, (_, i) => grant({ remaining_usd: `${100 + i}.0${i % 10}` })) }),
      canary(),
      incidentClear({ incident_event_id: Number.MAX_SAFE_INTEGER }),
    ]
    const ref = pythonCanonical(payloads)
    payloads.forEach((p, i) => {
      const category = p.kind as string
      const r = parseCreditGatePayload(category, ref[i]!.text)
      expect(r.ok, `payload ${i}`).toBe(true)
      if (!r.ok) return
      expect(r.canonical).toBe(ref[i]!.text)
      expect(r.contentHash).toBe(ref[i]!.sha)
    })
  })

  it('accepts a grant date with a time of day, and the boundary amounts', () => {
    expect(fieldOf(parse('credit_gate_calibration', calibration({ grants: [grant({ expires: '2026-10-17T00:00:00Z' })] })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '0.00' })] })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '200.00' })] })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ grants: [grant({ original_usd: '10000.00', remaining_usd: '10000.00' })] })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ grants: [grant({ granted: '2026-10-15T08:00:00Z' })] })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ screenshot: `/${'é'.repeat(64)}.png` })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_calibration', calibration({ screenshot: `/${'a'.repeat(299)}` })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_canary', canary({ budget_usd: '0.99', min_expected_usd: '0.99' })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_canary', canary({ budget_usd: '0.10', min_expected_usd: '0.10' })))).toBe('OK')
    expect(fieldOf(parse('credit_gate_incident_clear', incidentClear({ incident_event_id: 1 })))).toBe('OK')
  })
})

describe('parseCreditGatePayload: everything else is refused, naming the field', () => {
  const tooMany = Array.from({ length: 17 }, () => grant())
  const cases: Array<[string, string, unknown, string]> = [
    // calibration
    ['captured_at_lb date only', 'credit_gate_calibration', calibration({ captured_at_lb: '2026-10-15' }), 'captured_at_lb'],
    ['captured_at_lb with an offset', 'credit_gate_calibration', calibration({ captured_at_lb: '2026-10-15T10:00:00+02:00' }), 'captured_at_lb'],
    ['captured_at_lb with milliseconds', 'credit_gate_calibration', calibration({ captured_at_lb: '2026-10-15T08:00:00.000Z' }), 'captured_at_lb'],
    ['captured_at_lb not a calendar day', 'credit_gate_calibration', calibration({ captured_at_lb: '2026-02-30T08:00:00Z' }), 'captured_at_lb'],
    ['no grants', 'credit_gate_calibration', calibration({ grants: [] }), 'grants'],
    ['17 grants', 'credit_gate_calibration', calibration({ grants: tooMany }), 'grants'],
    ['grants not a list', 'credit_gate_calibration', calibration({ grants: grant() }), 'grants'],
    ['a grant with an extra key', 'credit_gate_calibration', calibration({ grants: [grant({ note: 'x' })] }), 'grants[0].keys'],
    ['a grant without remaining_usd', 'credit_gate_calibration', calibration({ grants: [{ granted: '2026-10-10', expires: '2026-10-17', original_usd: '200.00' }] }), 'grants[0].keys'],
    ['a grant credited after the screenshot', 'credit_gate_calibration', calibration({ grants: [grant({ granted: '2026-10-16' })] }), 'grants[0].granted'],
    ['a grant expiring when credited', 'credit_gate_calibration', calibration({ grants: [grant({ expires: '2026-10-10' })] }), 'grants[0].expires'],
    ['a grant date that is no day', 'credit_gate_calibration', calibration({ grants: [grant({ expires: '2026-13-01' })] }), 'grants[0].expires'],
    ['original 0.00', 'credit_gate_calibration', calibration({ grants: [grant({ original_usd: '0.00', remaining_usd: '0.00' })] }), 'grants[0].original_usd'],
    ['original above 10 000', 'credit_gate_calibration', calibration({ grants: [grant({ original_usd: '10000.01' })] }), 'grants[0].original_usd'],
    ['remaining above original', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '200.01' })] }), 'grants[0].remaining_usd'],
    ['"195.6"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '195.6' })] }), 'grants[0].remaining_usd'],
    ['"195,64"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '195,64' })] }), 'grants[0].remaining_usd'],
    ['"-1.00"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '-1.00' })] }), 'grants[0].remaining_usd'],
    ['"1e2"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '1e2' })] }), 'grants[0].remaining_usd'],
    ['" 1.00"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: ' 1.00' })] }), 'grants[0].remaining_usd'],
    ['"01.00"', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '01.00' })] }), 'grants[0].remaining_usd'],
    ['a full-width digit', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: '\uFF11.00' })] }), 'grants[0].remaining_usd'],
    ['a number, not a string', 'credit_gate_calibration', calibration({ grants: [grant({ remaining_usd: 195.64 })] }), 'grants[0].remaining_usd'],
    ['grants above 20 000 in total', 'credit_gate_calibration',
      calibration({ grants: [grant({ original_usd: '10000.00', remaining_usd: '0.00' }), grant({ original_usd: '10000.00', remaining_usd: '0.00' }), grant({ original_usd: '0.01', remaining_usd: '0.00' })] }), 'grants'],
    ['no V', 'credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' } } }), 'protected.keys'],
    ['R without its expiry', 'credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.63' }, V: { remaining_usd: '10.00' } } }), 'protected.R.keys'],
    ['V with an extra key', 'credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.00', expires: '2027-01-31' } } }), 'protected.V.keys'],
    ['V "10.0"', 'credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.63', expires: '2027-01-31' }, V: { remaining_usd: '10.0' } } }), 'protected.V.remaining_usd'],
    ['R "3.630"', 'credit_gate_calibration', calibration({ protected: { R: { remaining_usd: '3.630', expires: '2027-01-31' }, V: { remaining_usd: '10.00' } } }), 'protected.R.remaining_usd'],
    ['a relative screenshot path', 'credit_gate_calibration', calibration({ screenshot: 'console.png' }), 'screenshot'],
    ['a screenshot path with ..', 'credit_gate_calibration', calibration({ screenshot: '/Volumes/8T/../etc/passwd' }), 'screenshot'],
    ['a screenshot path with //', 'credit_gate_calibration', calibration({ screenshot: '/Volumes//8T/x.png' }), 'screenshot'],
    ['a screenshot path with a newline (a forged line)', 'credit_gate_calibration', calibration({ screenshot: '/x.png\nVédett V: maradék 10.00 USD' }), 'screenshot'],
    ['a screenshot path with a bidi override', 'credit_gate_calibration', calibration({ screenshot: '/x\u202Egnp.png' }), 'screenshot'],
    ['a screenshot path with a zero-width space', 'credit_gate_calibration', calibration({ screenshot: '/x\u200B.png' }), 'screenshot'],
    ['a screenshot path in another script', 'credit_gate_calibration', calibration({ screenshot: '/\u0445\u0430.png' }), 'screenshot'],
    ['a screenshot path with a lone surrogate', 'credit_gate_calibration', calibration({ screenshot: '/x\uD800.png' }), 'screenshot'],
    // BE-3b LOW-3 (P4): ASCII and the Hungarian accented letters, in NFC, nothing else.
    ['a screenshot path in NFD', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/Képernyőkép.png'.normalize('NFD') }), 'screenshot'],
    ['a screenshot path with a combining grapheme joiner (invisible)', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/Ke\u034Fp.png' }), 'screenshot'],
    ['a screenshot path with a combining overlay', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/a\u0338.png' }), 'screenshot'],
    ['a screenshot path with a full-width Latin letter', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/\uFF24esktop/a.png' }), 'screenshot'],
    ['a screenshot path with a no-break space', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/a\u00A0b.png' }), 'screenshot'],
    ['a screenshot path with a narrow no-break space', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/9.41\u202FAM.png' }), 'screenshot'],
    ['a screenshot path with trailing spaces', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/a.png   ' }), 'screenshot'],
    ['a screenshot path with a tab', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/a\tb.png' }), 'screenshot'],
    ['a screenshot path with a Latin letter that is not Hungarian', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/Espa\u00F1a.png' }), 'screenshot'],
    ['a screenshot path with a Hungarian look-alike (o with tilde)', 'credit_gate_calibration', calibration({ screenshot: '/Users/x/Képerny\u00F5kép.png' }), 'screenshot'],
    ['a screenshot path over 300 characters', 'credit_gate_calibration', calibration({ screenshot: `/${'a'.repeat(300)}` }), 'screenshot'],
    ['a screenshot path with 65 non-ASCII letters', 'credit_gate_calibration', calibration({ screenshot: `/${'é'.repeat(65)}.png` }), 'screenshot'],
    ['a calibration with an extra top-level key', 'credit_gate_calibration', calibration({ approved: true }), 'keys'],
    // canary
    ['an upper-case config hash', 'credit_gate_canary', canary({ config_hash: 'AB'.repeat(32) }), 'config_hash'],
    ['a 63-hex config hash', 'credit_gate_canary', canary({ config_hash: 'a'.repeat(63) }), 'config_hash'],
    ['a model that is not claude-*', 'credit_gate_canary', canary({ model: 'gpt-6-astra' }), 'model'],
    ['a model with capitals', 'credit_gate_canary', canary({ model: 'claude-Sonnet-5-5' }), 'model'],
    ['a model with a space', 'credit_gate_canary', canary({ model: 'claude-sonnet 5' }), 'model'],
    ['a budget of 0.00', 'credit_gate_canary', canary({ budget_usd: '0.00', min_expected_usd: '0.00' }), 'budget_usd'],
    ['a budget of 1.00 (K-01: below 1 USD)', 'credit_gate_canary', canary({ budget_usd: '1.00' }), 'budget_usd'],
    ['a budget "0.9"', 'credit_gate_canary', canary({ budget_usd: '0.9' }), 'budget_usd'],
    ['an expected minimum of 0.09 (K-01: at least 0.10)', 'credit_gate_canary', canary({ min_expected_usd: '0.09' }), 'min_expected_usd'],
    ['an expected minimum above the budget', 'credit_gate_canary', canary({ budget_usd: '0.40', min_expected_usd: '0.50' }), 'min_expected_usd'],
    ['an upper-case before-calibration id', 'credit_gate_canary', canary({ before_calibration_id: CAL_ID.toUpperCase() }), 'before_calibration_id'],
    ['a numeric before-calibration id', 'credit_gate_canary', canary({ before_calibration_id: 7 }), 'before_calibration_id'],
    ['a canary with a note', 'credit_gate_canary', canary({ note: 'mehet' }), 'keys'],
    // incident clear
    ['an incident id of 0', 'credit_gate_incident_clear', incidentClear({ incident_event_id: 0 }), 'incident_event_id'],
    ['a negative incident id', 'credit_gate_incident_clear', incidentClear({ incident_event_id: -4 }), 'incident_event_id'],
    ['a fractional incident id', 'credit_gate_incident_clear', incidentClear({ incident_event_id: 1.5 }), 'incident_event_id'],
    ['an incident id as a string', 'credit_gate_incident_clear', incidentClear({ incident_event_id: '42' }), 'incident_event_id'],
    ['an incident id beyond 2^53', 'credit_gate_incident_clear', incidentClear({ incident_event_id: 2 ** 53 }), 'incident_event_id'],
    // common
    ['v as a string', 'credit_gate_incident_clear', incidentClear({ v: '1' }), 'v'],
    ['v 2', 'credit_gate_incident_clear', incidentClear({ v: 2 }), 'v'],
    ['kind of another category', 'credit_gate_incident_clear', incidentClear({ kind: 'credit_gate_canary' }), 'kind'],
    ['the payload of another category', 'credit_gate_canary', calibration(), 'kind'],
    ['a list', 'credit_gate_incident_clear', [incidentClear()], 'json'],
    ['an unknown category', 'credit_gate_open', incidentClear(), 'category'],
  ]

  it.each(cases)('%s', (_name, category, payload, field) => {
    expect(fieldOf(parse(category, payload))).toBe(field)
  })

  it('any text that is not the canonical form of what it parses to', () => {
    const p = canon(canary())
    const nonCanonical = [
      JSON.stringify(canary()), // key order as written
      JSON.stringify(JSON.parse(p), null, 1), // whitespace
      `${p}\n`, // a trailing newline
      ` ${p}`,
      p.replace('"budget_usd":"0.90"', '"budget_usd":"\\u0030.90"'), // an escape spelling
      p.replace('"model":"claude-sonnet-5-5"', '"model":"claude\\u002dsonnet-5-5"'), // another escape spelling
      p.replace('"budget_usd":"0.90"', '"budget_usd":"0.50","budget_usd":"0.90"'), // a duplicated key (JSON.parse keeps the last)
      canon(incidentClear()).replace('"v":1', '"v":1.0'),
      canon(incidentClear()).replace('"incident_event_id":42', '"incident_event_id":4.2e1'),
    ]
    for (const text of nonCanonical) {
      const category = text.includes('credit_gate_incident_clear') ? 'credit_gate_incident_clear' : 'credit_gate_canary'
      expect(fieldOf(parseCreditGatePayload(category, text)), text).toBe('canonical_form')
    }
  })

  it('a payload that is not a string, empty, not JSON, or too long', () => {
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', canary()))).toBe('action_payload')
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', ''))).toBe('action_payload')
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', null))).toBe('action_payload')
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', '{"v":1'))).toBe('json')
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', 'null'))).toBe('json')
    expect(fieldOf(parseCreditGatePayload('credit_gate_canary', ' '.repeat(MAX_PAYLOAD_CHARS + 1)))).toBe('size')
    expect(CANARY_BUDGET_LIMIT_MICRO).toBe(1_000_000)
  })
})

describe('creditGateBinding: the payload is the one its content_hash approves', () => {
  const text = canon(canary())
  const row = (over: Partial<{ category: string; content_hash: string | null; action_payload: string | null }> = {}) =>
    ({ category: 'credit_gate_canary', content_hash: sha(text), action_payload: text, ...over })

  it('bound only on an exact match', () => {
    const b = creditGateBinding(row())
    expect(b.bound).toBe(true)
    if (b.bound) expect(b.payload).toEqual(canary())
  })

  it.each([
    ['not_credit_gate', row({ category: 'email_send' })],
    ['no_content_hash', row({ content_hash: null })],
    ['no_content_hash', row({ content_hash: 'AB'.repeat(32) })],
    ['no_payload', row({ action_payload: null })],
    ['no_payload', row({ action_payload: '' })],
    ['bad_payload', row({ action_payload: JSON.stringify(canary()) })],
    ['bad_payload', row({ category: 'credit_gate_calibration' })],
    ['hash_mismatch', row({ content_hash: sha(canon(canary({ budget_usd: '0.99' }))) })],
    ['hash_mismatch', row({ action_payload: canon(canary({ budget_usd: '0.99' })) })],
  ])('%s', (reason, r) => {
    expect(creditGateBinding(r)).toEqual({ bound: false, reason })
  })
})

describe('the owner\'s text of a credit-gate approval (plain text, bound fields only)', () => {
  const meta = { agentId: 'brainy', category: 'credit_gate_incident_clear', shortId: '1a2b3c4d', hash16: '0123456789abcdef', timeoutAt: null }

  it('incident clear, line by line: the event\'s reason and time come from the gate\'s own event row', () => {
    const p = incidentClear() as unknown as CreditGatePayload
    const incident = { reason: 'credit_balance_too_low', atMs: Date.UTC(2026, 9, 15, 6, 30, 0) }
    expect(buildCreditGateApprovalText(p, { ...meta, incident })).toBe([
      '[JÓVÁHAGYÁS KELL] brainy | credit_gate_incident_clear',
      'Kredit-kapu: INCIDENT feloldása',
      'Kérés: 1a2b3c4d, tartalom-hash: 0123456789abcdef',
      'INCIDENT esemény: #42',
      'Az INCIDENT oka: credit_balance_too_low',
      'Az INCIDENT kezdete: 2026-10-15T06:30:00Z (Budapest: 2026. 10. 15. 8:30:00)',
      'Csak ezt az okot oldja fel: ha más ok is nyitva van, az INCIDENT marad.',
      'A feloldás után a kapu csak egy új, a feloldás után készült, jóváhagyott kalibrációval nyithat.',
      'Lejárat: nincs',
      'Jóváhagyás után a kredit-kapu dolgozza fel, egyszer.',
    ].join('\n'))
    // Without the event row the text says so (the notifier withholds the buttons then).
    expect(buildCreditGateApprovalText(p, meta)).toContain('\nAz INCIDENT oka és kezdete: nem található a kapu eseménysorában\n')
  })

  it('every field is shown in the closed alphabet: anything else is escaped, and a non-ASCII path is flagged', () => {
    const text = buildCreditGateApprovalText(calibration({ screenshot: '/x/Képő.png' }) as unknown as CreditGatePayload,
      { ...meta, category: 'credit_gate_calibration', hash16: '0123\uFF14567', agentId: 'b\u00A0x' })
    expect(text).toContain('\nKérés: 1a2b3c4d, tartalom-hash: 0123<U+FF14>567\n')
    expect(text.split('\n')[0]).toBe('[JÓVÁHAGYÁS KELL] b<U+00A0>x | credit_gate_calibration')
    expect(text).toContain('\nKépernyőkép: /x/Képő.png\nFIGYELEM: nem-ASCII karakter az útvonalban: /x/K<U+00E9>p<U+0151>.png\n')
    // An ASCII path has no warning line.
    const plain = buildCreditGateApprovalText(calibration() as unknown as CreditGatePayload, { ...meta, category: 'credit_gate_calibration' })
    expect(plain).not.toContain('FIGYELEM')
  })

  it('every reading of a calibration, in order, and the hash prefix; the identifying fields go through visible()', () => {
    const p = calibration() as unknown as CreditGatePayload
    const text = buildCreditGateApprovalText(p, { ...meta, category: 'credit_gate_calibration', agentId: 'bra\u202Einy\nx' })
    expect(text.split('\n')[0]).toBe('[JÓVÁHAGYÁS KELL] bra<U+202E>iny<U+000A>x | credit_gate_calibration')
    const lines = text.split('\n')
    expect(lines.slice(1, 10)).toEqual([
      'Kredit-kapu: Console-leolvasás (kalibráció) jóváhagyása',
      'Kérés: 1a2b3c4d, tartalom-hash: 0123456789abcdef',
      'A képernyőkép legkorábbi ideje: 2026-10-15T08:00:00Z (Budapest: 2026. 10. 15. 10:00:00)',
      'Team-grantok (2 db):',
      '1. jóváírva 2026-10-10, lejár 2026-10-17: maradék 195.64 USD / eredeti 200.00 USD',
      '2. jóváírva 2026-10-14, lejár 2026-11-17: maradék 200.00 USD / eredeti 200.00 USD',
      'Védett R: maradék 3.63 USD, lejár 2027-01-31',
      'Védett V: maradék 10.00 USD',
      'Képernyőkép: /Volumes/8T/console/2026-10-15.png',
    ])
  })

  it('a canary shows the full config hash and the before-calibration id', () => {
    const text = buildCreditGateApprovalText(canary() as unknown as CreditGatePayload, { ...meta, category: 'credit_gate_canary', timeoutAt: 1_792_000_000 })
    expect(text).toContain(`Futtató-konfiguráció (hash): ${'ab'.repeat(32)}`)
    expect(text).toContain(`Előtte-kalibráció (jóváhagyás-azonosító): ${CAL_ID}`)
    expect(text).toContain('Költségplafon: 0.90 USD')
    expect(text).toContain('Várt minimum költés: 0.10 USD')
    expect(text).toMatch(/\nLejárat: \d{4}\. \d{2}\. \d{2}\. \d{1,2}:\d{2}:\d{2}\n/)
  })

  it('the largest calibration (16 grants, the longest amounts and path) fits one button message with the outcome reserve', () => {
    const p = calibration({
      grants: Array.from({ length: 16 }, () => grant({ granted: '2026-10-10T23:59:59Z', expires: '2026-12-31T23:59:59Z', original_usd: '1250.00', remaining_usd: '1249.99' })),
      protected: { R: { remaining_usd: '99999.99', expires: '2027-01-31T23:59:59Z' }, V: { remaining_usd: '99999.99' } },
      // The most escapes a valid path can carry: 64 non-ASCII letters, 300 characters.
      screenshot: `/${'ő'.repeat(64)}${'a'.repeat(235)}`,
      captured_at_lb: '2026-10-15T08:00:00Z',
    })
    const parsed = parse('credit_gate_calibration', p)
    expect(parsed.ok).toBe(true)
    const text = buildCreditGateApprovalText(p as unknown as CreditGatePayload, { ...meta, agentId: 'a'.repeat(50), category: 'credit_gate_calibration', timeoutAt: 1_792_000_000 })
    expect(text.length + 300).toBeLessThanOrEqual(4096 - TEST_RUN_PREFIX.length)
  })

  it('the plain notice and the outcome lines', () => {
    const plain = buildCreditGatePlainText({ agentId: 'brainy', category: 'credit_gate_canary', id: CAL_ID, timeoutAt: null })
    expect(plain).toBe([
      '[JÓVÁHAGYÁS KELL] brainy | credit_gate_canary',
      `Kredit-kapu jóváhagyás (id: ${CAL_ID}).`,
      'Gomb nélkül ment ki, ezért így érvényesen nem dönthető el: a kredit-kapu csak a Telegram-gombos döntést fogadja el.',
      'Lejárat: nincs',
    ].join('\n'))
    expect(formatCreditGateOutcomeText('approved', 1_792_000_000)).toMatch(/^✅ Jóváhagyva: .+ \(Budapest\)\. A kredit-kapu dolgozza fel, egyszer\.$/)
    expect(formatCreditGateOutcomeText('rejected', 1_792_000_000)).toMatch(/^❌ Elutasítva: .+ \(Budapest\)\.$/)
    expect(formatCreditGateOutcomeText('approved', 1_792_000_000).length).toBeLessThanOrEqual(300)
  })
})

describe('the DB side: which rows a button may bind and decide (N2b)', () => {
  const OWNER = '1000000001'
  const MSG = 4242
  const NOW = Math.floor(Date.now() / 1000)
  const nonce = () => randomBytes(16).toString('base64url')

  beforeEach(() => {
    initDatabase(':memory:')
  })

  function pending(id: string, category: string, payload: string | null, hash: string | null) {
    createApproval({ id, agent_id: 'brainy', category, action_description: 'x', action_payload: payload, content_hash: hash, timeout_at: NOW + 600 })
  }

  function bind(id: string) {
    const a = nonce()
    const r = nonce()
    const ok = setApprovalCallbackNonceHashes(id, { approved: sha(a), rejected: sha(r) })
    if (ok) expect(setApprovalTelegramMessageId(id, MSG)).toBe(true)
    return { ok, approve: sha(a), reject: sha(r) }
  }

  it.each(CREDIT_GATE_APPROVAL_CATEGORIES)('%s: the nonces bind, and the owner\'s press decides it once', (category) => {
    const text = canon(category === 'credit_gate_calibration' ? calibration() : category === 'credit_gate_canary' ? canary() : incidentClear())
    pending('c1', category, text, sha(text))
    const b = bind('c1')
    expect(b.ok).toBe(true)
    const r = resolveApprovalFromTelegram({ id: 'c1', status: 'approved', ownerId: OWNER, messageId: MSG, nonceHash: b.approve, nowS: NOW })
    expect(r.ok).toBe(true)
    expect(getApproval('c1')).toMatchObject({ status: 'approved', resolved_by: `owner:telegram:${OWNER}`, action_payload: text })
    const again = resolveApprovalFromTelegram({ id: 'c1', status: 'rejected', ownerId: OWNER, messageId: MSG, nonceHash: b.reject, nowS: NOW })
    expect(again).toMatchObject({ ok: false, reason: 'already_resolved' })
  })

  it('a look-alike category is not a button category: the nonces do not bind, a press is wrong_category', () => {
    const text = canon(incidentClear())
    for (const [i, category] of ['credit_gate_incident_clear ', 'Credit_Gate_Incident_Clear', 'kanban_move'].entries()) {
      const id = `w${i}`
      pending(id, category, text, sha(text))
      expect(bind(id).ok).toBe(false)
      // Bound by hand, the way only a direct DB writer could.
      getDb().prepare('UPDATE approvals SET callback_nonce_hash_approve = ?, telegram_message_id = ? WHERE id = ?').run(sha('n'), MSG, id)
      expect(resolveApprovalFromTelegram({ id, status: 'approved', ownerId: OWNER, messageId: MSG, nonceHash: sha('n'), nowS: NOW }))
        .toMatchObject({ ok: false, reason: 'wrong_category' })
    }
  })

  it('a wrong nonce on a bound credit-gate row is bad_nonce, an unbound one not_bound (the old reasons, unchanged)', () => {
    const text = canon(canary())
    pending('n1', 'credit_gate_canary', text, sha(text))
    pending('n2', 'credit_gate_canary', text, sha(text))
    const b = bind('n1')
    expect(resolveApprovalFromTelegram({ id: 'n1', status: 'approved', ownerId: OWNER, messageId: MSG, nonceHash: b.reject, nowS: NOW }))
      .toMatchObject({ ok: false, reason: 'bad_nonce' })
    expect(resolveApprovalFromTelegram({ id: 'n1', status: 'approved', ownerId: OWNER, messageId: MSG + 1, nonceHash: b.approve, nowS: NOW }))
      .toMatchObject({ ok: false, reason: 'message_mismatch' })
    expect(resolveApprovalFromTelegram({ id: 'n2', status: 'approved', ownerId: OWNER, messageId: MSG, nonceHash: b.approve, nowS: NOW }))
      .toMatchObject({ ok: false, reason: 'not_bound' })
    expect(getApproval('n1')!.status).toBe('pending')
  })
})
