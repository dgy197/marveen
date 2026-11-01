// Card e487f46c, security review B1: an external_message (SMS) approval that names a
// content_hash must carry the canonical {kind, number, text} envelope as action_payload,
// and the server checks on create that the hash is the sha256 of it. The owner's
// notification shows the payload's number and text. Other categories are unchanged.
//
// The canonical form is the one scripts/sms/seeme-send.py hashes (Python's json.dumps with
// ensure_ascii=False, sort_keys=True, separators=(",", ":")): the parity test below runs
// python3 itself on the same vectors.
import { describe, it, expect, beforeEach, vi } from 'vitest'
import { spawnSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))

const sendSpy = vi.hoisted(() => vi.fn(async (_token: string, _chatId: string, _text: string): Promise<number | null> => 4242))

vi.mock('../config.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../config.js')>()
  return { ...real, MAIN_AGENT_ID: 'agent-a', TELEGRAM_BOT_TOKEN: 'test-token', CHANNEL_PROVIDER: 'telegram' }
})
vi.mock('../owner-chat.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../owner-chat.js')>()
  return { ...real, resolveOwnerChatId: () => '777' }
})
vi.mock('../web/telegram.js', async (importOriginal) => {
  const real = await importOriginal<typeof import('../web/telegram.js')>()
  return { ...real, sendTelegramMessage: sendSpy }
})

import { initDatabase, getApproval, listApprovals } from '../db.js'
import { tryHandleApprovals, buildOwnerApprovalText } from '../web/routes/approvals.js'
import { boundSmsEnvelope, parseSmsPayload, hasForbiddenSmsChar } from '../web/external-message-payload.js'
import { canonicalJson } from '../approval-envelope.js'
import type { RouteContext } from '../web/routes/types.js'

const NUM = '36301234567'
const TEXT = 'Kedves Ügyfelünk! A szerződés "aláírva", köszönjük.\nÜdv: Fireeng'

function canon(number: string, text: string): string {
  return canonicalJson({ kind: 'sms', number, text }) as string
}
function sha(s: string): string {
  return createHash('sha256').update(s, 'utf8').digest('hex')
}

function fakeReq(method: 'POST', path: string, body: unknown): { ctx: RouteContext; out: { status: number; body: any } } {
  const out: { status: number; body: any } = { status: 0, body: null }
  const res: any = {
    writeHead(status: number) { out.status = status; return res },
    end(chunk?: string) { if (chunk) out.body = JSON.parse(chunk) },
  }
  const url = new URL(`http://localhost:3420${path}`)
  const bodyStr = JSON.stringify(body)
  const req: any = {
    on(event: string, cb: (chunk?: Buffer) => void) {
      if (event === 'data') cb(Buffer.from(bodyStr))
      if (event === 'end') cb()
    },
  }
  return { ctx: { req, res, path: url.pathname, method, url, auth: { kind: 'session', user: 'owner' } } as RouteContext, out }
}

async function post(body: unknown) {
  const { ctx, out } = fakeReq('POST', '/api/approvals', body)
  expect(await tryHandleApprovals(ctx)).toBe(true)
  await new Promise(r => setImmediate(r))
  return out
}

function smsRequest(over: Record<string, unknown> = {}) {
  const payload = canon(NUM, TEXT)
  return {
    agent_id: 'agent-b',
    category: 'external_message',
    action_description: `SMS-t küldenék a ${NUM} számra (SeeMe).`,
    action_payload: payload,
    content_hash: sha(payload),
    timeout_seconds: 3600,
    ...over,
  }
}

describe('canonical SMS envelope (parity with seeme-send.py)', () => {
  it('canonicalJson + sha256 equal Python json.dumps(sort_keys, compact, ensure_ascii=False) on the same vectors', () => {
    const vectors: Array<[string, string]> = [
      [NUM, TEXT],
      [NUM, 'Holnap 10-kor.\n\nÁrvíztűrő "tükörfúrógép" \\ backslash, záró szóköz '],
      [NUM, 'emoji \u{1F600} astral, árvíztűrő tükörfúrógép'],
      ['36701234567', 'x'],
    ]
    const prog = [
      'import hashlib, json, sys',
      'out = []',
      'for number, text in json.load(sys.stdin):',
      '    c = json.dumps({"kind": "sms", "number": number, "text": text}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))',
      '    out.append([c, hashlib.sha256(c.encode("utf-8")).hexdigest()])',
      'sys.stdout.write(json.dumps(out))',
    ].join('\n')
    const res = spawnSync('python3', ['-I', '-c', prog], { input: JSON.stringify(vectors), encoding: 'utf-8', timeout: 60_000 })
    expect(res.status).toBe(0)
    const py = JSON.parse(res.stdout) as Array<[string, string]>
    vectors.forEach(([number, text], i) => {
      expect(canon(number, text)).toBe(py[i][0])
      const parsed = parseSmsPayload(py[i][0])
      expect(parsed.ok).toBe(true)
      if (parsed.ok) expect(parsed.contentHash).toBe(py[i][1])
    })
  })
})

describe('parseSmsPayload', () => {
  it('accepts the canonical envelope and returns the sha256 of it', () => {
    const p = canon(NUM, TEXT)
    const r = parseSmsPayload(p)
    expect(r).toMatchObject({ ok: true, contentHash: sha(p), envelope: { kind: 'sms', number: NUM, text: TEXT } })
  })

  it('refuses everything that is not exactly the canonical {kind, number, text}', () => {
    const good = canon(NUM, TEXT)
    const cases: unknown[] = [
      undefined, null, '', 42, {}, '[]', 'not json', '{}',
      good.replace(',', ', '),                                                  // whitespace
      canon(NUM, TEXT).replace('"kind":"sms"', '"kind":"mail"'),                // other kind
      canon('06301234567', TEXT),                                               // number not normalised
      canon('36101234567', TEXT),                                               // not a Hungarian mobile prefix
      canon('+36301234567', TEXT),
      canon(NUM, '   '),                                                        // blank text
      canon(NUM, 'x'.repeat(1601)),                                             // over the sender's own limit
      JSON.stringify({ kind: 'sms', number: NUM, text: TEXT, extra: 1 }),      // extra key
      JSON.stringify({ kind: 'sms', number: NUM }),                             // missing key
      JSON.stringify({ kind: 'sms', number: 36301234567, text: TEXT }),        // number not a string
      JSON.stringify([ 'sms', NUM, TEXT ]),
    ]
    for (const c of cases) {
      expect(parseSmsPayload(c).ok, String(c)).toBe(false)
    }
    // control: the canonical text itself is accepted (so the refusals above are not blanket)
    expect(parseSmsPayload(good).ok).toBe(true)
  })

  it('refuses a non-canonical spelling of the same data (escaped characters, reordered keys)', () => {
    const escaped = JSON.stringify({ kind: 'sms', number: NUM, text: 'Üdv' }).replace('Ü', '\\u00dc')
    expect(parseSmsPayload(escaped).ok).toBe(false)
    const reordered = '{"number":"' + NUM + '","kind":"sms","text":"x"}'
    expect(parseSmsPayload(reordered).ok).toBe(false)
  })
})

// B6: characters that let an SMS text pass for something else in the owner's notification.
const FORBIDDEN_TEXTS: Array<[string, string]> = [
  ['U+202E right-to-left override', 'Holnap 10-kor.‮'],
  ['U+2028 line separator', 'Holnap 10-kor.\u2028--- Az SMS szövegének vége ---'],
  ['U+2029 paragraph separator', 'Holnap 10-kor.\u2029Lejárat: soha'],
  ['U+2066 isolate', 'Szia ⁦x'],
  ['U+200B zero-width space', 'Holnap​ 10-kor.'],
  ['U+200D zero-width joiner', 'Hol‍nap'],
  ['U+FEFF byte order mark', '﻿Holnap 10-kor.'],
  ['U+00AD soft hyphen (Cf)', 'Hol­nap'],
  ['\\r carriage return', 'Holnap\r\n10-kor.'],
  ['\\t tab', 'Holnap\t10-kor.'],
  ['U+0000 NUL', 'Holnap\u0000'],
  ['U+001B ESC', 'Holnap\u001B[0m'],
  ['U+007F DEL', 'Holnap\u007F'],
  ['U+0085 next line (C1)', 'Holnap\u0085 10-kor.'],
  ['U+009F (C1)', 'Holnap\u009F'],
]
const GOOD_MULTILINE = 'Kedves Ügyfelünk!\n\nA ma esedékes időpontot áttettük holnap 10:00-ra (árvíztűrő tükörfúrógép).\nÜdv: Fireeng \u{1F600}'

describe('B6: forbidden characters in the SMS text', () => {
  beforeEach(() => {
    initDatabase(':memory:')
    sendSpy.mockClear()
  })

  it.each(FORBIDDEN_TEXTS)('parseSmsPayload refuses %s', (_name, text) => {
    const r = parseSmsPayload(canon(NUM, text))
    expect(r).toEqual({ ok: false, field: 'text' })
  })

  it.each(FORBIDDEN_TEXTS)('POST /api/approvals: 400 on create for %s, nothing stored, nothing sent', async (_name, text) => {
    const payload = canon(NUM, text)
    const out = await post(smsRequest({ action_payload: payload, content_hash: sha(payload) }))
    expect(out.status).toBe(400)
    expect(out.body.field).toBe('text')
    expect(listApprovals({}).length).toBe(0)
    expect(sendSpy).not.toHaveBeenCalled()
  })

  it('a normal multi-line Hungarian text with accents, an emoji and blank lines still passes, hash as Python', () => {
    const p = canon(NUM, GOOD_MULTILINE)
    const r = parseSmsPayload(p)
    expect(r).toMatchObject({ ok: true, contentHash: sha(p) })
    const prog = [
      'import hashlib, json, sys',
      'number, text = json.load(sys.stdin)',
      'c = json.dumps({"kind": "sms", "number": number, "text": text}, ensure_ascii=False, sort_keys=True, separators=(",", ":"))',
      'sys.stdout.write(c + "\\n" + hashlib.sha256(c.encode("utf-8")).hexdigest())',
    ].join('\n')
    const res = spawnSync('python3', ['-I', '-c', prog], { input: JSON.stringify([NUM, GOOD_MULTILINE]), encoding: 'utf-8', timeout: 60_000 })
    expect(res.status).toBe(0)
    expect(res.stdout).toBe(`${p}\n${sha(p)}`)
  })

  it('server and consumer refuse the same code points (every code point 0..10FFFF, parity with seeme-send.py)', () => {
    const prog = [
      'import importlib.util, json, sys',
      'spec = importlib.util.spec_from_file_location("seeme_send", sys.argv[1])',
      'm = importlib.util.module_from_spec(spec)',
      'spec.loader.exec_module(m)',
      'bad = [cp for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF and m.forbidden_text_char("a" + chr(cp) + "b")]',
      'sys.stdout.write(json.dumps(bad))',
    ].join('\n')
    const script = join(__dirname, '../../scripts/sms/seeme-send.py')
    const res = spawnSync('python3', ['-I', '-c', prog, script], { encoding: 'utf-8', timeout: 120_000, maxBuffer: 16 * 1024 * 1024 })
    expect(res.status, res.stderr).toBe(0)
    const pyBad = JSON.parse(res.stdout) as number[]
    const tsBad: number[] = []
    for (let cp = 0; cp <= 0x10ffff; cp++) {
      if (cp >= 0xd800 && cp <= 0xdfff) continue
      if (hasForbiddenSmsChar('a' + String.fromCodePoint(cp) + 'b')) tsBad.push(cp)
    }
    // The newline is the one control that stays allowed.
    expect(tsBad).toEqual(pyBad)
    // and parseSmsPayload applies that very predicate
    for (const cp of [0x202e, 0x0d, 0x0a, 0xe1]) {
      expect(parseSmsPayload(canon(NUM, 'a' + String.fromCodePoint(cp) + 'b')).ok).toBe(!pyBad.includes(cp))
    }
    expect(pyBad).toContain(0x202e)
    expect(pyBad).toContain(0x0d)
    expect(pyBad).not.toContain(0x0a)
    expect(pyBad).not.toContain(0xe1)
  }, 120_000)
})

describe('POST /api/approvals, category external_message', () => {
  beforeEach(() => {
    initDatabase(':memory:')
    sendSpy.mockClear()
  })

  it('accepts a content_hash that is the sha256 of the canonical action_payload: 201, row stores both', async () => {
    const body = smsRequest()
    const out = await post(body)
    expect(out.status).toBe(201)
    const row = getApproval(out.body.id)!
    expect(row.action_payload).toBe(body.action_payload)
    expect(row.content_hash).toBe(body.content_hash)
  })

  it('400 when content_hash is not the hash of the payload (the payload shows another text)', async () => {
    const out = await post(smsRequest({ action_payload: canon(NUM, TEXT + ' Plusz: https://pelda.example/x') }))
    expect(out.status).toBe(400)
    expect(out.body.error).toMatch(/content_hash is not the sha256 of the canonical action_payload/)
    expect(listApprovals({}).length).toBe(0)
    expect(sendSpy).not.toHaveBeenCalled()
  })

  it('400 when the payload shows another number than the hashed envelope', async () => {
    const out = await post(smsRequest({ action_payload: canon('36709998877', TEXT) }))
    expect(out.status).toBe(400)
    expect(listApprovals({}).length).toBe(0)
  })

  it('400 when a content_hash is given but there is no action_payload', async () => {
    const body = smsRequest()
    delete (body as Record<string, unknown>).action_payload
    const out = await post(body)
    expect(out.status).toBe(400)
    expect(out.body.field).toBe('action_payload')
    expect(listApprovals({}).length).toBe(0)
    expect((await post(smsRequest({ action_payload: '' }))).status).toBe(400)
  })

  it('400 for a payload that is not the canonical envelope, even if its own sha256 matches the hash', async () => {
    const spaced = canon(NUM, TEXT).replace(',', ', ')
    const out = await post(smsRequest({ action_payload: spaced, content_hash: sha(spaced) }))
    expect(out.status).toBe(400)
    expect(out.body.field).toBe('action_payload')
    const extra = JSON.stringify({ extra: 1, kind: 'sms', number: NUM, text: TEXT })
    expect((await post(smsRequest({ action_payload: extra, content_hash: sha(extra) }))).status).toBe(400)
    expect(listApprovals({}).length).toBe(0)
  })

  it('without a content_hash the request is unchanged (nothing binds it; the sender refuses it)', async () => {
    const body = smsRequest()
    delete (body as Record<string, unknown>).content_hash
    delete (body as Record<string, unknown>).action_payload
    const out = await post(body)
    expect(out.status).toBe(201)
    expect(getApproval(out.body.id)!.content_hash).toBeNull()
  })

  it('other categories are unchanged: a content_hash needs no SMS payload', async () => {
    const hash = 'a'.repeat(64)
    const out = await post({ agent_id: 'agent-b', category: 'memory_maintenance', action_description: 'x', content_hash: hash })
    expect(out.status).toBe(201)
    expect(getApproval(out.body.id)!.content_hash).toBe(hash)
    const out2 = await post({ agent_id: 'agent-b', category: 'email_send', action_description: 'x', content_hash: hash, action_payload: 'free text' })
    expect(out2.status).toBe(201)
    expect(getApproval(out2.body.id)!.action_payload).toBe('free text')
  })
})

// The dashboard cell: helpers cut out of web/app.js and run with stubs (house idiom of
// credit-gate-approval-ui.test.ts).
const APP = readFileSync(join(__dirname, '../../web/app.js'), 'utf-8')
function fnSource(name: string): string {
  const head = APP.search(new RegExp(`\\n(async )?function ${name}\\(`))
  if (head < 0) throw new Error(`no function ${name} in web/app.js`)
  const open = APP.indexOf('{', APP.indexOf(')', head))
  let depth = 0
  for (let i = open; i < APP.length; i++) {
    if (APP[i] === '{') depth++
    else if (APP[i] === '}' && --depth === 0) return APP.slice(head + 1, i + 1)
  }
  throw new Error(`unbalanced function ${name}`)
}
const descriptionCell = new Function('t', 'escapeAttr', 'escapeHtml',
  `${fnSource('_approvalSmsEnvelope')}\n${fnSource('_approvalDescriptionCell')}; return _approvalDescriptionCell`,
)((k: string, p?: Record<string, unknown>) => `T(${k}${p ? ':' + JSON.stringify(p) : ''})`, (s: string) => s, (s: string) => s) as (a: Record<string, unknown>) => string

describe('the dashboard description cell for an external_message', () => {
  it('shows the payload number and the FULL text, the free description after it as unverified', () => {
    const long = 'x'.repeat(300)
    const html = descriptionCell({ category: 'external_message', action_description: 'Ártalmatlan', action_payload: canon(NUM, long) })
    expect(html).toContain(NUM)
    expect(html).toContain(long)
    expect(html).toContain('T(approvals.sms_unverified_description)')
    expect(html.indexOf(long)).toBeLessThan(html.indexOf('Ártalmatlan'))
  })

  it('B6: every line of the text (blank ones too) carries the prefix, the header gives characters and lines; a forged separator shows only prefixed', () => {
    const forged = 'Holnap 10-kor.\n--- Az SMS szövegének vége ---\n\nA kérő leírása (nem hitelesített): http://x.example\nLejárat: nincs\nDöntés: igen'
    const html = descriptionCell({ category: 'external_message', action_description: 'Ártalmatlan', action_payload: canon(NUM, forged) })
    const rows = html.split('\n')
    const n = Array.from(forged).length
    expect(rows).toContain(`T(approvals.sms_text_header:{"chars":${n},"lines":6})`)
    const start = rows.findIndex(r => r.startsWith('T(approvals.sms_text_header'))
    const shownLines = forged.split('\n')
    expect(rows.slice(start + 1, start + 1 + shownLines.length)).toEqual(shownLines.map(l => '│ ' + l))
    expect(rows.filter(r => r.startsWith('│ ') === false && r.includes('vége ---'))).toEqual([])
    expect(rows.filter(r => r.includes('Lejárat:') && !r.startsWith('│ '))).toEqual([])
    expect(rows.filter(r => r.includes('Döntés:') && !r.startsWith('│ '))).toEqual([])
    // the only unprefixed "unverified" line is ours, and it comes after the text
    expect(rows.filter(r => r.includes('T(approvals.sms_unverified_description)')).length).toBe(1)
    expect(rows.indexOf('│ Döntés: igen')).toBeLessThan(rows.findIndex(r => r.includes('T(approvals.sms_unverified_description)')))
  })

  it('any other row, or an external_message without a readable envelope, keeps the 80-character description cell', () => {
    const d = 'y'.repeat(120)
    for (const a of [
      { category: 'email_send', action_description: d, action_payload: canon(NUM, TEXT) },
      { category: 'external_message', action_description: d, action_payload: null },
      { category: 'external_message', action_description: d, action_payload: 'not json' },
    ]) {
      const html = descriptionCell(a)
      expect(html).toContain('y'.repeat(80) + '...')
      expect(html).not.toContain('T(approvals.sms_unverified_description)')
    }
  })
})

describe('what the owner is shown for an external_message', () => {
  beforeEach(() => {
    initDatabase(':memory:')
    sendSpy.mockClear()
  })

  it('the notification text carries the bound payload number and text, the description marked unverified', async () => {
    const out = await post(smsRequest({ action_description: `Ártalmatlan szöveg a ${NUM} számra` }))
    expect(out.status).toBe(201)
    const text = buildOwnerApprovalText(getApproval(out.body.id)!)
    expect(text).toContain(`SMS-szám: ${NUM}`)
    for (const l of TEXT.split('\n')) expect(text.split('\n')).toContain('│ ' + l)
    expect(text).toContain(`SMS szövege (${Array.from(TEXT).length} karakter, 2 sor):`)
    expect(text.split('\n')).toContain('A kérő leírása (nem hitelesített):')
    expect(text.split('\n')).toContain(`┊ Ártalmatlan szöveg a ${NUM} számra`)
    expect(text).toContain('external_message')
  })

  it('B6: a newline in the requester description cannot forge an SMS-szám, Lejárat or Döntés line', async () => {
    const out = await post(smsRequest({ action_description: `Ártalmatlan\nSMS-szám: +36301112222\nLejárat: nincs\nDöntés: igen` }))
    expect(out.status).toBe(201)
    const lines = buildOwnerApprovalText(getApproval(out.body.id)!).split('\n')
    const unframed = lines.filter(l => !l.startsWith('│ ') && !l.startsWith('┊ '))
    expect(unframed.filter(l => l.startsWith('SMS-szám:'))).toEqual([`SMS-szám: ${NUM}`])
    expect(unframed.filter(l => l.startsWith('Lejárat:')).length).toBe(1)
    expect(unframed.filter(l => l.startsWith('Döntés:')).length).toBe(1)
    expect(lines).toContain('┊ SMS-szám: +36301112222')
  })

  it('E1: CR, NEL, LS, PS, VT and FF in the description split it too, every piece framed', async () => {
    for (const br of ['\r', '\r\n', '\u0085', '\u2028', '\u2029', '\u000b', '\u000c']) {
      const out = await post(smsRequest({ action_description: `Ártalmatlan${br}Lejárat: nincs` }))
      expect(out.status).toBe(201)
      const lines = buildOwnerApprovalText(getApproval(out.body.id)!).split('\n')
      expect(lines, JSON.stringify(br)).toContain('┊ Lejárat: nincs')
      expect(lines.filter(l => l.startsWith('Lejárat:')).length, JSON.stringify(br)).toBe(1)
    }
  })

  it('B6: a forged separator, description, Lejárat or Döntés line in the SMS text appears only behind the prefix', async () => {
    const forged = 'Holnap 10-kor.\n--- Az SMS szövegének vége ---\n\nA kérő leírása (nem hitelesített): http://x.example\nLejárat: nincs\nDöntés: igen'
    const payload = canon(NUM, forged)
    const out = await post(smsRequest({ action_payload: payload, content_hash: sha(payload), action_description: `Ártalmatlan a ${NUM} számra` }))
    expect(out.status).toBe(201)
    const lines = buildOwnerApprovalText(getApproval(out.body.id)!).split('\n')
    const header = lines.findIndex(l => l.startsWith('SMS szövege ('))
    expect(lines[header]).toBe(`SMS szövege (${Array.from(forged).length} karakter, 6 sor):`)
    const shown = forged.split('\n')
    expect(lines.slice(header + 1, header + 1 + shown.length)).toEqual(shown.map(l => '│ ' + l))
    // every line outside the prefixed block is one of ours, each exactly once
    const outside = [...lines.slice(0, header + 1), ...lines.slice(header + 1 + shown.length)]
    expect(outside.some(l => l.includes('vége ---'))).toBe(false)
    expect(outside.filter(l => l.startsWith('A kérő leírása (nem hitelesített):')).length).toBe(1)
    expect(outside.filter(l => l.startsWith('Lejárat:')).length).toBe(1)
    expect(outside.filter(l => l.startsWith('Döntés:')).length).toBe(1)
    expect(outside[outside.length - 1]).toMatch(/^Döntés: Dashboard/)
    expect(lines.filter(l => l.includes('vége ---') && !l.startsWith('│ '))).toEqual([])
  })

  it('an unbound or hash-less external_message shows the plain description, as before', () => {
    const base = {
      id: 'i', agent_id: 'agent-b', category: 'external_message', action_description: 'Szabad szöveg',
      status: 'pending', timeout_at: null, telegram_message_id: null, requested_at: 1, resolved_at: null,
      resolved_by: null, consumed_at: null, consumed_by: null, consumed_ref: null,
    }
    const noHash = buildOwnerApprovalText({ ...base, action_payload: canon(NUM, TEXT), content_hash: null } as any)
    expect(noHash).toContain('Szabad szöveg')
    expect(noHash).not.toContain('SMS-szám')
    const wrongHash = buildOwnerApprovalText({ ...base, action_payload: canon(NUM, TEXT), content_hash: 'b'.repeat(64) } as any)
    expect(wrongHash).not.toContain('SMS-szám')
    expect(boundSmsEnvelope({ category: 'email_send', content_hash: sha(canon(NUM, TEXT)), action_payload: canon(NUM, TEXT) })).toBeNull()
  })
})
