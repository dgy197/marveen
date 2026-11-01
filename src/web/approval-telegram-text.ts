// Owner-facing Telegram text for a BOUND email approval (card 345f34e2, N1b).
// Pure functions, no I/O: the caller (the notifier) decides whether the
// envelope is bound and what to send. Plain text, proper accents: this is
// outgoing copy, same house style as buildOwnerApprovalText in
// routes/approvals.ts.
//
// The owner approves a letter by reading it, so the text is shown WITHOUT
// truncation: when it does not fit one message it is split into numbered
// chunks, followed by one short final message that identifies the letter on
// its own (recipients, subject, short ids, expiry).
// BE-3: the notifier puts buttons ONLY under the single-message form (zero
// chunks): a chunk without buttons can be rewritten in the owner's chat before
// the decision, the button message cannot be edited without losing its buttons.
// A letter that needs chunks gets the plain, button-less notification instead.

import {
  CREDIT_GATE_TEXT_CHARS,
  type CalibrationPayload, type CanaryPayload, type CreditGatePayload, type EnforcePayload, type IncidentClearPayload,
} from './credit-gate/approval-payload.js'

// The view the notifier builds from the verified envelope. Declared here so
// this module does not depend on the envelope parser.
export interface EnvelopeView {
  to: string[]
  cc: string[]
  bcc: string[]
  text: string
  // The payload's subject. Shown ONLY if it is exactly the FIRST line of
  // `text` (everything before the first "\n"): the subject is not covered by
  // the content hash on its own, and the gate's extractor joins a subject that
  // comes first (the --subject flag before --body, a JSON payload's subject
  // field) to the body with one "\n". Anywhere else in the text it could be
  // any line of the body, so it is not shown at all. Even a first-line match
  // is shown as "the first line, the requester says it is the subject".
  subjectHint?: string
  htmlSha256?: string
  attachments?: { name: string; sha256: string; size?: number }[]
}

export interface BoundApprovalMeta {
  agentId: string
  // First 8 chars of the approval UUID.
  shortId: string
  // First 8 chars of the envelope content hash.
  hash8: string
  // Epoch seconds (approvals.timeout_at); null = no expiry.
  timeoutAt: number | null
  // How long after approval the letter may be sent (once).
  windowMinutes: number
}

export interface BoundMessageOpts {
  // Per-message budget in UTF-16 code units, already net of TEST_RUN_PREFIX
  // (the caller passes 4096 - TEST_RUN_PREFIX.length).
  limit: number
  // Headroom kept free for the outcome text the plugin appends later.
  reserve: number
}

export type BoundApprovalMessages = { chunks: string[]; final: string } | { unfit: true }

const HASH_PREFIX_LEN = 16

function formatBudapest(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString('hu-HU', { timeZone: 'Europe/Budapest' })
}

// Control, format and line/paragraph-separator characters (bidi overrides,
// zero-width, C0/C1, U+2028/U+2029) must not reach the owner's screen raw in
// any identifying line: a newline in a field would forge a line, a bidi
// override would reorder what is displayed. Shown as <U+XXXX> instead. The
// letter body itself is NOT passed through this (it is shown verbatim).
const UNSAFE_CHAR = /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u

function visible(s: string): string {
  let out = ''
  for (const ch of s) {
    out += UNSAFE_CHAR.test(ch) ? `<U+${hex(ch)}>` : ch
  }
  return out
}

function hex(ch: string): string {
  return (ch.codePointAt(0) as number).toString(16).toUpperCase().padStart(4, '0')
}

function escapeNonAscii(s: string): string {
  let out = ''
  for (const ch of s) {
    out += (ch.codePointAt(0) as number) > 0x7f || UNSAFE_CHAR.test(ch) ? `<U+${hex(ch)}>` : ch
  }
  return out
}

function hasNonAscii(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 0x7f) return true
  return false
}

function list(label: string, addrs: string[]): string {
  return `${label}: ${addrs.length > 0 ? addrs.map(visible).join(', ') : 'nincs'}`
}

// The first line of the hashed text, exactly as the extractor joined it:
// everything before the first "\n" (a "\r" stays part of the line).
function firstLine(text: string): string {
  const nl = text.indexOf('\n')
  return nl === -1 ? text : text.slice(0, nl)
}

// The match proves only that the hint is the text's first line, not that the
// line is a subject: when the body came first (MCP, --body before --subject)
// it is the body's first line. So the label names what is proven and who
// claims the rest.
function subjectLine(view: EnvelopeView): string {
  const hint = view.subjectHint
  if (typeof hint === 'string' && hint.length > 0 && hint === firstLine(view.text)) {
    return `Első sor (a kérő szerint tárgy): ${visible(hint)}`
  }
  return 'Tárgy: a levél szövegében szerepel (nem külön hitelesített mező)'
}

// Everything the owner needs to identify the letter, without the body.
function identityLines(view: EnvelopeView, meta: BoundApprovalMeta): string[] {
  const lines = [
    `[JÓVÁHAGYÁS KELL] ${meta.agentId} | email_send`,
    `Levél jóváhagyása (id: ${meta.shortId}, boríték: ${meta.hash8})`,
    list('Címzett', view.to),
    list('Cc', view.cc),
    list('Bcc', view.bcc),
    subjectLine(view),
  ]
  const html = view.htmlSha256
  const atts = view.attachments ?? []
  if (html || atts.length > 0) {
    if (html) lines.push(`HTML-törzs sha256: ${visible(html.slice(0, HASH_PREFIX_LEN))}`)
    for (const a of atts) {
      lines.push(`Melléklet: ${visible(a.name)} | sha256: ${visible(a.sha256.slice(0, HASH_PREFIX_LEN))}`)
    }
    lines.push('A HTML-törzs és a mellékletek tartalma itt nem látszik, csak az ujjlenyomatuk.')
  }
  const odd = [...view.to, ...view.cc, ...view.bcc].filter(
    a => hasNonAscii(a) || UNSAFE_CHAR.test(a),
  )
  if (odd.length > 0) {
    lines.push(
      `FIGYELEM: nem-ASCII vagy irányvezérlő karakter van a címben: ${odd.map(escapeNonAscii).join(', ')}`,
    )
  }
  return lines
}

function tailLines(meta: BoundApprovalMeta): string[] {
  const expires = meta.timeoutAt != null ? formatBudapest(meta.timeoutAt) : 'nincs'
  return [
    `Lejárat: ${expires}`,
    `Jóváhagyás után ${meta.windowMinutes} percig, egyszer küldhető el.`,
  ]
}

function chunkHeader(shortId: string, i: number, n: number): string {
  return `[JÓVÁHAGYÁS ${shortId} | ${i}/${n}]\n`
}

// Split `text` into bodies of at most `bodyLimit` UTF-16 units. Never cuts a
// surrogate pair; prefers a line break when one sits in the second half of the
// window. The bodies concatenate to exactly `text`.
function splitText(text: string, bodyLimit: number): string[] {
  const bodies: string[] = []
  let pos = 0
  while (pos < text.length) {
    let end = Math.min(pos + bodyLimit, text.length)
    if (end < text.length) {
      const last = text.charCodeAt(end - 1)
      const next = text.charCodeAt(end)
      if (last >= 0xd800 && last <= 0xdbff && next >= 0xdc00 && next <= 0xdfff) end--
      const nl = text.lastIndexOf('\n', end - 1)
      if (nl >= pos && nl + 1 - pos >= bodyLimit / 2) end = nl + 1
    }
    bodies.push(text.slice(pos, end))
    pos = end
  }
  return bodies
}

export function buildBoundApprovalMessages(
  view: EnvelopeView,
  meta: BoundApprovalMeta,
  opts: BoundMessageOpts,
): BoundApprovalMessages {
  const { limit, reserve } = opts
  // Every identifying field is untrusted until proven otherwise (agent_id only
  // gets a "non-empty" check at the POST): sanitize once, use everywhere.
  meta = { ...meta, agentId: visible(meta.agentId), shortId: visible(meta.shortId), hash8: visible(meta.hash8) }
  const identity = identityLines(view, meta)
  const tail = tailLines(meta)

  // One message: the whole letter plus identification, with headroom left.
  const single = [
    ...identity,
    '--- A levél szövege ---',
    view.text,
    '--- A levél szövegének vége ---',
    ...tail,
  ].join('\n')
  if (single.length + reserve <= limit) return { chunks: [], final: single }

  // Chunked: find a digit width for the "i/n" counters that holds for the
  // resulting n (the header length depends on it, n depends on the header).
  let digits = 1
  let bodies: string[] = []
  for (;;) {
    const bodyLimit = limit - chunkHeader(meta.shortId, 10 ** digits - 1, 10 ** digits - 1).length
    if (bodyLimit < 2) return { unfit: true }
    bodies = splitText(view.text, bodyLimit)
    if (String(bodies.length).length <= digits) break
    digits++
  }
  const n = bodies.length
  const chunks = bodies.map((b, i) => chunkHeader(meta.shortId, i + 1, n) + b)
  const final = [
    ...identity,
    ...(n > 0 ? [`A levél teljes szövege az előző ${n} üzenetben van.`] : []),
    ...tail,
  ].join('\n')
  if (final.length > limit) return { unfit: true }
  return { chunks, final }
}

// --- Credit-gate approvals (card fec6335f, N2b) ---------------------------------
//
// The button message of a credit_gate_* approval shows the BOUND payload and
// nothing else from the requester: every line is a fixed label plus a field of
// the payload its content_hash approves (numbers exactly as the strict decimal
// strings the gate parses), the request's short id and the hash prefix, and
// for an incident clear the INCIDENT's reason and time from the gate's own
// event row. The action_description (free text) never appears. The
// requester's agent id is shown, but the route accepts only a bare id for these
// categories. Plain text, like every other approval message
// (sendTelegramMessage sets no parse_mode): nothing is markdown- or
// HTML-escaped. BE-3b LOW-3: every field goes through cgVisible(), which shows
// only printable ASCII and the Hungarian accented letters (the payload's own
// alphabet) and anything else as <U+XXXX>; a path that carries a non-ASCII
// letter also gets a line with every such letter escaped.

export interface CreditGateIncidentView {
  // credit_gate_events.reason of the transition that entered INCIDENT.
  reason: string
  // credit_gate_events.at (epoch ms).
  atMs: number
}

export interface CreditGateApprovalMeta {
  agentId: string
  category: string
  // First 8 chars of the approval UUID.
  shortId: string
  // First 16 chars of the content hash.
  hash16: string
  // Epoch seconds (approvals.timeout_at); null = no expiry.
  timeoutAt: number | null
  // Incident clear only: the gate's own event row; null/absent = not found.
  incident?: CreditGateIncidentView | null
}

// The outcome line of a request the press closed because its content changed
// after the button message went out (BE-3b LOW-2).
export const CREDIT_GATE_CHANGED_OUTCOME = '❌ A kérés tartalma megváltozott, elutasítva.'

const CG_ALLOWED_CHAR = new RegExp(`^[${CREDIT_GATE_TEXT_CHARS}]$`)

function cgVisible(s: string): string {
  let out = ''
  for (const ch of s) out += CG_ALLOWED_CHAR.test(ch) ? ch : `<U+${hex(ch)}>`
  return out
}

function budapestOfStamp(stamp: string): string | null {
  const ms = Date.parse(stamp)
  return Number.isFinite(ms) ? formatBudapest(Math.floor(ms / 1000)) : null
}

function calibrationLines(p: CalibrationPayload): string[] {
  const local = budapestOfStamp(p.captured_at_lb)
  const lines = [
    'Kredit-kapu: Console-leolvasás (kalibráció) jóváhagyása',
    `A képernyőkép legkorábbi ideje: ${cgVisible(p.captured_at_lb)}${local ? ` (Budapest: ${local})` : ''}`,
    `Team-grantok (${p.grants.length} db):`,
  ]
  p.grants.forEach((g, i) => {
    lines.push(
      `${i + 1}. jóváírva ${cgVisible(g.granted)}, lejár ${cgVisible(g.expires)}: ` +
        `maradék ${cgVisible(g.remaining_usd)} USD / eredeti ${cgVisible(g.original_usd)} USD`,
    )
  })
  lines.push(
    `Védett R: maradék ${cgVisible(p.protected.R.remaining_usd)} USD, lejár ${cgVisible(p.protected.R.expires)}`,
    `Védett V: maradék ${cgVisible(p.protected.V.remaining_usd)} USD`,
    `Képernyőkép: ${cgVisible(p.screenshot)}`,
  )
  if (hasNonAscii(p.screenshot)) {
    lines.push(`FIGYELEM: nem-ASCII karakter az útvonalban: ${escapeNonAscii(p.screenshot)}`)
  }
  return lines
}

function canaryLines(p: CanaryPayload): string[] {
  const lines = [
    'Kredit-kapu: kanári-futás jóváhagyása',
    `Modell: ${cgVisible(p.model)}`,
    `Költségplafon: ${cgVisible(p.budget_usd)} USD`,
    `Várt minimum költés: ${cgVisible(p.min_expected_usd)} USD`,
    `Futtató-konfiguráció (hash): ${cgVisible(p.config_hash)}`,
    `Előtte-kalibráció (jóváhagyás-azonosító): ${cgVisible(p.before_calibration_id)}`,
    // BE-4b P6: the run this approval is for.
    `Node: ${cgVisible(p.node)}`,
    `Munkakönyvtár: ${cgVisible(p.cwd)}`,
    `Prompt (sha256 eleje): ${cgVisible(p.prompt_sha256.slice(0, 16))}`,
  ]
  if (hasNonAscii(p.cwd)) lines.push(`FIGYELEM: nem-ASCII karakter a munkakönyvtárban: ${escapeNonAscii(p.cwd)}`)
  return lines
}

// Card 40e03382: the one button of the grant_model calibration. The owner sees
// what the press binds: the config hash, enforce, and the canary's terms.
function enforceLines(p: EnforcePayload): string[] {
  const c = p.canary
  const lines = [
    'Kredit-kapu: grant-modell bekapcsolása (enforce + kanári, egy gomb)',
    `Grant-modell hash: ${cgVisible(p.grant_model_hash)}`,
    `Üzemmód: ${cgVisible(p.mode)}`,
    'Kanári-futás (ugyanebből a jóváhagyásból indulhat):',
    `Modell: ${cgVisible(c.model)}`,
    `Költségplafon: ${cgVisible(c.budget_usd)} USD`,
    `Várt minimum költés: ${cgVisible(c.min_expected_usd)} USD`,
    `Futtató-konfiguráció (hash): ${cgVisible(c.config_hash)}`,
    `Node: ${cgVisible(c.node)}`,
    `Munkakönyvtár: ${cgVisible(c.cwd)}`,
    `Prompt (sha256 eleje): ${cgVisible(c.prompt_sha256.slice(0, 16))}`,
    'A konfiguráció bármilyen változása után új gomb kell.',
  ]
  if (hasNonAscii(c.cwd)) lines.push(`FIGYELEM: nem-ASCII karakter a munkakönyvtárban: ${escapeNonAscii(c.cwd)}`)
  return lines
}

function utcStampOfMs(ms: number): string {
  return new Date(ms).toISOString().replace(/\.[0-9]{3}Z$/, 'Z')
}

function incidentClearLines(p: IncidentClearPayload, incident: CreditGateIncidentView | null | undefined): string[] {
  const lines = ['Kredit-kapu: INCIDENT feloldása', `INCIDENT esemény: #${String(p.incident_event_id)}`]
  if (incident) {
    lines.push(
      `Az INCIDENT oka: ${cgVisible(incident.reason)}`,
      `Az INCIDENT kezdete: ${utcStampOfMs(incident.atMs)} (Budapest: ${formatBudapest(Math.floor(incident.atMs / 1000))})`,
    )
  } else {
    lines.push('Az INCIDENT oka és kezdete: nem található a kapu eseménysorában')
  }
  lines.push('Csak ezt az okot oldja fel: ha más ok is nyitva van, az INCIDENT marad.')
  lines.push('A feloldás után a kapu csak egy új, a feloldás után készült, jóváhagyott kalibrációval nyithat.')
  return lines
}

/** The one button message of a bound credit-gate approval. */
export function buildCreditGateApprovalText(payload: CreditGatePayload, meta: CreditGateApprovalMeta): string {
  const body =
    payload.kind === 'credit_gate_calibration' ? calibrationLines(payload)
      : payload.kind === 'credit_gate_canary' ? canaryLines(payload)
        : payload.kind === 'credit_gate_enforce' ? enforceLines(payload)
          : incidentClearLines(payload, meta.incident)
  const expires = meta.timeoutAt != null ? formatBudapest(meta.timeoutAt) : 'nincs'
  return [
    `[JÓVÁHAGYÁS KELL] ${cgVisible(meta.agentId)} | ${cgVisible(meta.category)}`,
    body[0] as string,
    `Kérés: ${cgVisible(meta.shortId)}, tartalom-hash: ${cgVisible(meta.hash16)}`,
    ...body.slice(1),
    `Lejárat: ${expires}`,
    'Jóváhagyás után a kredit-kapu dolgozza fel, egyszer.',
  ].join('\n')
}

/**
 * The plain notification of a credit-gate approval that goes out WITHOUT
 * buttons: no payload, no free text. Without the button no valid decision
 * exists for it (the gate accepts only owner:telegram:), so it says so.
 */
export function buildCreditGatePlainText(meta: { agentId: string; category: string; id: string; timeoutAt: number | null }): string {
  const expires = meta.timeoutAt != null ? formatBudapest(meta.timeoutAt) : 'nincs'
  return [
    `[JÓVÁHAGYÁS KELL] ${cgVisible(meta.agentId)} | ${cgVisible(meta.category)}`,
    `Kredit-kapu jóváhagyás (id: ${cgVisible(meta.id)}).`,
    'Gomb nélkül ment ki, ezért így érvényesen nem dönthető el: a kredit-kapu csak a Telegram-gombos döntést fogadja el.',
    `Lejárat: ${expires}`,
  ].join('\n')
}

/** The outcome line under a decided credit-gate button message. */
export function formatCreditGateOutcomeText(status: 'approved' | 'rejected', resolvedAt: number): string {
  const when = formatBudapest(resolvedAt)
  if (status === 'approved') return `✅ Jóváhagyva: ${when} (Budapest). A kredit-kapu dolgozza fel, egyszer.`
  return `❌ Elutasítva: ${when} (Budapest).`
}

// Outcome line the server returns and the plugin appends under the buttons'
// message. Same locale and zone as the request text.
export function formatOutcomeText(
  status: 'approved' | 'rejected',
  resolvedAt: number,
  windowMinutes = 30,
): string {
  const when = formatBudapest(resolvedAt)
  if (status === 'approved') {
    return `✅ Jóváhagyva: ${when} (Budapest). A levél ${windowMinutes} percen belül, egyszer küldhető el.`
  }
  return `❌ Elutasítva: ${when} (Budapest).`
}
