/**
 * Memory write gate (card 3e9f6c28, node G2a): normalisation, masking, residue check.
 *
 * All credential-shaped fixtures are assembled at run time from fragments, so this
 * file does not itself trip the repo's secret gate (the shapes are the subject here,
 * the literals never appear in the source).
 */
import { describe, it, expect } from 'vitest'
import { prepareForGate, normaliseForGate, residueFindings, REDACTED } from '../memory-gate/mask.js'
import { SECRET_PATTERNS, TRANSCRIPT_PATTERNS } from '../security/secret-gate.js'

const hex = (n: number) => 'a1b2c3d4'.repeat(Math.ceil(n / 8)).slice(0, n)
const HEX64 = hex(64)

// One synthetic sample per SECRET_PATTERNS entry, keyed by the entry's name.
const S = {
  priv: ['-----BEGIN ', 'RSA PRIVATE', ' KEY-----'].join(''),
  stripe: ['s', 'k_', 'live_', 'A'.repeat(24)].join(''),
  elevenHeader: ['xi-api', '-key: ', 'B'.repeat(24)].join(''),
  elevenLiteral: ['s', 'k_', hex(40)].join(''),
  bearer: ['Bea', 'rer ', 'C'.repeat(30)].join(''),
  jwt: ['ey', 'J', 'D'.repeat(12), '.ey', 'J', 'E'.repeat(20), '.', 'F'.repeat(20)].join(''),
  github: ['g', 'hp_', 'G'.repeat(36)].join(''),
  slack: ['x', 'oxb-', '1234567890-', 'H'.repeat(8)].join(''),
  openai: ['s', 'k-proj-', 'I'.repeat(30)].join(''),
  generic: ['s', 'k-', 'J'.repeat(30)].join(''),
  aws: ['AK', 'IA', 'K'.repeat(16)].join(''),
  tg: ['123456789', ':', 'L'.repeat(35)].join(''),
  tgHalf: ['TELEGRAM_BOT_', 'TOKEN=', 'M'.repeat(35)].join(''),
  supaJwt: ['service', '_role: ey', 'J', 'N'.repeat(10)].join(''),
  sbp: ['sb', 'p_', hex(40)].join(''),
}
const SAMPLE_BY_PATTERN: Record<string, string> = {
  'private key block': S.priv,
  'Stripe secret/restricted key': S.stripe,
  'ElevenLabs key header': S.elevenHeader,
  'ElevenLabs key literal': S.elevenLiteral,
  'bearer token literal': S.bearer,
  'JWT': S.jwt,
  'GitHub token': S.github,
  'Slack token': S.slack,
  'OpenAI project key': S.openai,
  'generic vendor secret key (sk_ or sk-)': S.generic,
  'AWS access key id': S.aws,
  'Telegram bot token': S.tg,
  'Telegram bot token secret half': S.tgHalf,
  'Supabase service_role JWT hint': S.supaJwt,
  'Supabase personal access token': S.sbp,
}

describe('normaliseForGate', () => {
  it('NFKC: full-width digits and ligatures fold to plain characters', () => {
    expect(normaliseForGate('\uFF14\uFF15\uFF11\uFF12 \uFB01x')).toBe('4512 fix')
  })

  it('deletes Cc and Cf, keeps \\n and \\t, turns \\r and \\r\\n into \\n', () => {
    expect(normaliseForGate('a\u200Bb\u200Dc\uFEFFd\u00ADe\u202Ef\u0007g\u001Bh')).toBe('abcdefgh')
    expect(normaliseForGate('x\ty\nz')).toBe('x\ty\nz')
    expect(normaliseForGate('a\r\nb\rc\u0085d\u2028e\u2029f')).toBe('a\nb\nc\nd\ne\nf')
  })

  it('tolerates non-strings', () => {
    for (const v of [undefined, null, 5, {}, []]) expect(prepareForGate(v)).toBe('')
  })
})

describe('the reviewer probe: five shapes the old mask let through', () => {
  const cases: Array<[string, string]> = [
    ['a dashboard tokenje: ' + HEX64, HEX64],
    ['token: ' + HEX64, HEX64],
    ['kulcs ' + HEX64, HEX64],
    ['PIN: 4512', '4512'],
    ['riasztokod 4512', '4512'],
  ]
  for (const [input, leak] of cases) {
    it(`masks: ${input.replace(HEX64, '<hex64>')}`, () => {
      const out = prepareForGate(input)
      expect(out).not.toContain(leak)
      expect(out).toContain(REDACTED)
      expect(residueFindings(out)).toEqual([])
    })
  }
})

describe('PIN / kod label stem (r3, reviewer three sentences)', () => {
  for (const s of ['Az iroda riaszt\u00F3 k\u00F3dja: 4512', 'k\u00F3d: 4512', 'PIN-k\u00F3dja 4512', 'Az iroda riaszt\u00F3 k\u00F3dja: 4512']) {
    it(`masks the number in: ${s}`, () => {
      const out = prepareForGate(s)
      expect(out).not.toContain('4512')
      expect(out).toContain(REDACTED)
    })
  }

  it('the exact reviewer sentence "Az iroda riaszto kodja: 4512" keeps its words and loses the number', () => {
    expect(prepareForGate('Az iroda riaszt\u00F3 k\u00F3dja: 4512')).toBe(`Az iroda riaszt\u00F3 k\u00F3dja: ${REDACTED}`)
  })

  it('negative controls: fewer than 4 digits, or the plain word, stay untouched', () => {
    for (const s of ['k\u00F3d: A12', 'a k\u00F3d a GitHubon van', 'k\u00F3d 123', 'PIN: 12', 'a k\u00F3dol\u00E1s gyors volt']) {
      expect(prepareForGate(s), s).toBe(s)
    }
  })

  it('works with full-width digits, zero-width separators, no accents, inflections', () => {
    const variants = [
      'k\u00F3d: \uFF14\uFF15\uFF11\uFF12',
      'PIN: 4\u200B5\u200B1\u200B2',
      'PI\u200BN: 4512',
      'riasztokod 4512',
      'riaszt\u00F3k\u00F3d: 4512',
      'pinje 0412',
      'PIN-k\u00F3dja 0412',
      'KOD = 4512',
      'k\u00F3d a 4512',
    ]
    for (const v of variants) {
      const out = prepareForGate(v)
      expect(out, JSON.stringify(v)).not.toMatch(/4512|0412/)
      expect(out, JSON.stringify(v)).toContain(REDACTED)
    }
  })
})

describe('labelled secrets, Hungarian and English, inflected, with and without accents', () => {
  const values = ['x7Qp9', 'hunter22', 'Kutya1234']
  const lines: Array<(v: string) => string> = [
    v => `a jelszava: ${v}`,
    v => `jelszav\u00E1t ${v} tartja`,
    v => `jelszo: ${v}`,
    v => `Jelsz\u00F3 = ${v}`,
    v => `wifijelsz\u00F3: ${v}`,
    v => `app-jelsz\u00F3: ${v}`,
    v => `kulcs\u00E1t ${v}`,
    v => `a kulcs: ${v}`,
    v => `titok: ${v}`,
    v => `a titka ${v}`,
    v => `token: ${v}`,
    v => `tokenje ${v}`,
    v => `secret=${v}`,
    v => `password: ${v}`,
    v => `passwd ${v}`,
    v => `pw=${v}`,
    v => `api key: ${v}`,
    v => `API_KEY=${v}`,
    v => `apikey ${v}`,
    v => `a jelszava legyen ${v}`,
    v => `jelszo: "${v}"`,
  ]
  for (const mk of lines) {
    it(mk('<V>'), () => {
      for (const v of values) {
        const out = prepareForGate(mk(v))
        expect(out, mk(v)).not.toContain(v)
        expect(out, mk(v)).toContain(REDACTED)
        expect(residueFindings(out)).toEqual([])
      }
    })
  }

  it('a value that is itself a label word does not shield the next value', () => {
    const out = prepareForGate('jelszo titok: hunter22')
    expect(out).not.toContain('hunter22')
  })

  it('values shorter than 4 characters stay (spec: 4 characters or more)', () => {
    expect(prepareForGate('jelszo: abc')).toBe('jelszo: abc')
  })

  it('"pass" and "pw" need word boundaries ("passage", "pwned" are prose)', () => {
    expect(prepareForGate('the passage describes everything')).toBe('the passage describes everything')
    expect(prepareForGate('pwned accounts listing')).toBe('pwned accounts listing')
  })

  it('already-masked values are not masked twice', () => {
    const once = prepareForGate('token: ' + HEX64)
    expect(prepareForGate(once)).toBe(once)
  })
})

describe('hex, entropy, Luhn', () => {
  it('any hex run of 32 or more is masked, 31 is not', () => {
    expect(prepareForGate(`id ${hex(32)} end`)).toBe(`id ${REDACTED} end`)
    expect(prepareForGate(`id ${hex(31)} end`)).toBe(`id ${hex(31)} end`)
    expect(prepareForGate(`x${hex(40)}y`)).toBe(`x${REDACTED}y`)
  })

  it('entropy: >= 32 chars with >= 3 classes is masked; a long plain word or 2-class run is not', () => {
    const mixed = 'Abc123+/'.repeat(5)
    expect(prepareForGate(`k ${mixed} z`)).toBe(`k ${REDACTED} z`)
    const longWord = 'z'.repeat(40)
    const twoClass = 'xyz789'.repeat(7)
    expect(prepareForGate(longWord)).toBe(longWord)
    expect(prepareForGate(twoClass)).toBe(twoClass)
  })

  it('Luhn-valid 13-19 digit numbers are masked, invalid ones and short numbers are not', () => {
    expect(prepareForGate('card 4111 1111 1111 1111 ok')).toBe(`card ${REDACTED} ok`)
    expect(prepareForGate('card 4111-1111-1111-1111')).toBe(`card ${REDACTED}`)
    expect(prepareForGate('card 4111 1111 1111 1112 ok')).toBe('card 4111 1111 1111 1112 ok')
    expect(prepareForGate('hivjon: +36 30 123 4567')).toBe('hivjon: +36 30 123 4567')
  })
})

describe('negative controls: ordinary company text survives', () => {
  const keep = [
    'A projekt M-2026-044, T-1234 sz\u00E1m\u00FA, hat\u00E1rid\u0151: 2026-10-23.',
    'Telefon: +36 30 123 4567, e-mail: info@fireeng.hu, oldal: https://fireeng.hu/projektek/alpha',
    'A szerz\u0151d\u00E9s \u00F6sszege 1 250 000 Ft, a sz\u00E1mla kelte 2026.10.01.',
    'Lasd a GitHub repositoryt: https://github.com/Fireeng/Repo-Name',
  ]
  for (const s of keep) it(s.slice(0, 40), () => expect(prepareForGate(s)).toBe(s))
})

describe('every SECRET_PATTERNS entry has a sample and is masked', () => {
  it('the sample table covers exactly the repo detector list (a new pattern fails here)', () => {
    expect(Object.keys(SAMPLE_BY_PATTERN).sort()).toEqual(SECRET_PATTERNS.map(p => p.name).sort())
  })

  for (const { name, pattern } of SECRET_PATTERNS) {
    it(`positive control + masked: ${name}`, () => {
      const sample = SAMPLE_BY_PATTERN[name]
      expect(pattern.test(sample), 'the sample must trip the detector, else the control proves nothing').toBe(true)
      const wrapped = `before ${sample} after`
      expect(residueFindings(wrapped).length).toBeGreaterThan(0)
      const out = prepareForGate(wrapped)
      expect(out).not.toContain(sample)
      expect(residueFindings(out), name).toEqual([])
    })
  }
})

describe('residueFindings', () => {
  it('reports codes, never the matched text', () => {
    const f = residueFindings('x ' + S.github + ' y token: ' + HEX64)
    expect(f.length).toBeGreaterThan(0)
    expect(f.join(' ')).not.toContain('G'.repeat(10))
    expect(f.join(' ')).not.toContain(HEX64)
    expect(f.every(c => /^[a-z0-9_:]+$/.test(c))).toBe(true)
  })

  it('a text the masker cannot repair stays a finding: quoted channel material (TRANSCRIPT_PATTERNS)', () => {
    const quoted = 'sorry: ' + ['message', '_id 12345: hello'].join('')
    const out = prepareForGate(quoted)
    expect(out).toBe(quoted) // the masker leaves it alone ...
    expect(residueFindings(out)).toContain('transcript_gate:quoted_channel_message') // ... so the residue check stops the item
    expect(TRANSCRIPT_PATTERNS.length).toBeGreaterThan(0)
  })

  it('clean prose has no findings', () => {
    expect(residueFindings('A szerz\u0151d\u00E9s \u00FAj verzi\u00F3ja j\u00F3v\u00E1hagyva, a hat\u00E1rid\u0151 p\u00E9ntek.')).toEqual([])
  })
})

describe('prepareForGate properties', () => {
  const corpus = [
    'token: ' + HEX64,
    'PIN-k\u00F3dja 4512 \u00E9s a jelszava: x7Qp9',
    S.github + ' ' + S.jwt,
    'plain text without anything special',
    'card 4111 1111 1111 1111 and k\u00F3d: 98765',
    '\uFF4B\uFF55\uFF4C\uFF43\uFF53 ' + HEX64,
  ]
  it('is idempotent', () => {
    for (const c of corpus) {
      const once = prepareForGate(c)
      expect(prepareForGate(once), c).toBe(once)
    }
  })
  it('never leaves a finding behind', () => {
    for (const c of corpus) expect(residueFindings(prepareForGate(c)), c).toEqual([])
  })
})
