import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { dirname, join } from 'node:path'
import { parseFragment } from 'parse5'

// UI contract of the Fejlesztes > Ivek sub-view (card 46e935d6).
// The REAL render functions are cut out of web/app.js (brace matching, as
// app-js-html-sinks.test.ts does) and run against a tiny fake DOM. Every
// element the render code creates is serialized with proper escaping and
// parsed back with parse5: a server string that escaped its text node would
// show up as an extra element or attribute.
const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '..', '..')
const APP = readFileSync(join(ROOT, 'web', 'app.js'), 'utf8')
const HTML = readFileSync(join(ROOT, 'web', 'index.html'), 'utf8')
const CSS = readFileSync(join(ROOT, 'web', 'style.css'), 'utf8')
const LANG: Record<string, string> = Object.fromEntries(
  ['hu', 'en'].map(l => [l, readFileSync(join(ROOT, 'web', 'lang', `${l}.js`), 'utf8')]),
)

function extractFn(name: string): string {
  const re = new RegExp(`(?:async\\s+)?function ${name}\\s*\\([^)]*\\)\\s*\\{`)
  const m = re.exec(APP)
  if (!m) throw new Error(`${name} missing from web/app.js`)
  let depth = 0
  for (let j = m.index + m[0].length - 1; j < APP.length; j++) {
    if (APP[j] === '{') depth++
    else if (APP[j] === '}' && --depth === 0) return APP.slice(m.index, j + 1)
  }
  throw new Error(`${name}: unbalanced braces`)
}

// --- the Ivek section as shipped -------------------------------------------
const SECTION_START = APP.indexOf('// === Fejlesztes > Ivek (card 46e935d6) ===')
const SECTION_END = APP.indexOf('// === Fejlesztes > Funkciok (S1) ===')
if (SECTION_START < 0 || SECTION_END < SECTION_START) throw new Error('Ivek section missing from web/app.js')
const SECTION = APP.slice(SECTION_START, SECTION_END)
const CONST_START = SECTION.indexOf('let devIvekSelected')
const CONST_END = SECTION.indexOf('// null for a usable value')
const CONSTS = SECTION.slice(CONST_START, CONST_END)

const FNS = [
  'devEl', 'devBlock', 'devEmpty',
  'devIvekGap', 'devIvekItems', 'devIvekText', 'devIvekMs', 'devIvekTime', 'devIvekAge',
  'devIvekPhase', 'devIvekPhaseLabel', 'devIvekPhaseText', 'devIvekPhaseBar',
  'loadIvek', 'renderIvekList', 'devIvekStacked', 'selectIvek',
  'devIvekGapNote', 'devIvekListBlock', 'devIvekCount', 'renderIvekDetail',
]

// --- fake DOM --------------------------------------------------------------
class FakeNode {
  tagName: string
  className = ''
  attrs: Record<string, string> = {}
  dataset: Record<string, string> = {}
  style: Record<string, string> = {}
  children: FakeNode[] = []
  text = ''
  hidden = false
  type = ''
  title = ''
  tabIndex = 0
  listeners: Record<string, Array<() => void>> = {}
  scrolled = 0
  constructor(tag: string) { this.tagName = tag.toLowerCase() }
  get classList() {
    const self = this
    const names = () => self.className.split(/\s+/).filter(Boolean)
    return {
      add(n: string) { if (!names().includes(n)) self.className = [...names(), n].join(' ') },
      toggle(n: string, force?: boolean) {
        const has = names().includes(n)
        const want = force === undefined ? !has : force
        self.className = (want ? (has ? names() : [...names(), n]) : names().filter(x => x !== n)).join(' ')
      },
      contains(n: string) { return names().includes(n) },
    }
  }
  set textContent(v: unknown) { this.text = v == null ? '' : String(v); this.children = [] }
  get textContent(): string { return this.text + this.children.map(c => c.textContent).join('') }
  appendChild(c: FakeNode) { this.children.push(c); return c }
  replaceChildren(...nodes: FakeNode[]) { this.children = nodes; this.text = '' }
  hasChildNodes() { return this.children.length > 0 }
  setAttribute(k: string, v: string) { this.attrs[k] = String(v) }
  addEventListener(ev: string, fn: () => void) { (this.listeners[ev] ||= []).push(fn) }
  scrollIntoView() { this.scrolled++ }
  click() { for (const fn of this.listeners.click || []) fn() }
  all(): FakeNode[] { return [this, ...this.children.flatMap(c => c.all())] }
}

const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')

function serialize(n: FakeNode): string {
  const attrs: Record<string, string> = { ...n.attrs }
  if (n.className) attrs.class = n.className
  if (n.type) attrs.type = n.type
  if (n.title) attrs.title = n.title
  if (n.hidden) attrs.hidden = ''
  for (const [k, v] of Object.entries(n.dataset)) attrs[`data-${k}`] = v
  if (n.style.width) attrs.style = `width: ${n.style.width}`
  const a = Object.entries(attrs).map(([k, v]) => ` ${k}="${esc(v)}"`).join('')
  return `<${n.tagName}${a}>${esc(n.text)}${n.children.map(serialize).join('')}</${n.tagName}>`
}

type P5 = { nodeName: string; attrs?: Array<{ name: string; value: string }>; childNodes?: P5[]; value?: string }
function walk(node: P5, out: P5[] = []): P5[] {
  if (node.nodeName && !node.nodeName.startsWith('#')) out.push(node)
  for (const c of node.childNodes || []) walk(c, out)
  return out
}

const ALLOWED_TAGS = new Set(['div', 'span', 'button', 'h2', 'h3', 'strong', 'section'])
const ALLOWED_ATTRS = new Set(['class', 'type', 'title', 'role', 'aria-label', 'data-id', 'style', 'hidden'])
const CLASS_TOKEN = /^[a-z0-9_-]+$/

// Parses what the render code built: structure must equal the fake tree, only
// whitelisted tags and attributes, no handler attributes, no href.
function assertStructure(root: FakeNode) {
  const html = serialize(root)
  const frag = parseFragment(html) as unknown as P5
  const els = walk(frag)
  const fakeCount = root.all().length
  expect(els.length).toBe(fakeCount)
  for (const el of els) {
    expect(ALLOWED_TAGS.has(el.nodeName)).toBe(true)
    for (const at of el.attrs || []) {
      expect(ALLOWED_ATTRS.has(at.name)).toBe(true)
      expect(at.name.startsWith('on')).toBe(false)
      if (at.name === 'class') for (const tok of at.value.split(/\s+/).filter(Boolean)) expect(tok).toMatch(CLASS_TOKEN)
    }
  }
  // no link anywhere: the attribute whitelist has no href/src, and no value is a script URL
  for (const el of els) for (const at of el.attrs || []) expect(at.value).not.toMatch(/^\s*javascript:/i)
  return html
}

// --- harness ---------------------------------------------------------------
function makeI18n(lang: 'hu' | 'en') {
  const win: Record<string, any> = { _i18n: {}, _lang: lang }
  for (const l of ['en', 'hu']) new Function('window', LANG[l])(win)
  const t = (key: string, params: Record<string, unknown> = {}) => {
    const str = win._i18n[lang]?.[key] ?? win._i18n.en?.[key] ?? key
    return str.replace(/\{(\w+)\}/g, (_: string, k: string) => (params[k] != null ? String(params[k]) : `{${k}}`))
  }
  return { win, t }
}

interface Fetched { url: string; resolve: (v: { ok: boolean; status: number; json: () => Promise<unknown> }) => void }

function makeHarness(opts: { lang?: 'hu' | 'en'; stacked?: boolean } = {}) {
  const { win, t } = makeI18n(opts.lang || 'hu')
  const nodes: Record<string, FakeNode> = {
    devIvekList: new FakeNode('div'),
    devIvekDetail: new FakeNode('div'),
  }
  const fakeDocument = {
    getElementById: (id: string) => nodes[id] || null,
    createElement: (tag: string) => new FakeNode(tag),
    querySelectorAll: () => [] as FakeNode[],
  }
  const fakeWindow = { matchMedia: () => ({ matches: !!opts.stacked }) }
  const fetched: Fetched[] = []
  const fakeFetch = (url: string) => new Promise(resolve => { fetched.push({ url, resolve: resolve as Fetched['resolve'] }) })
  const body = `${CONSTS}\n${FNS.map(extractFn).join('\n')}\nreturn { loadIvek, renderIvekList, renderIvekDetail, selectIvek, devIvekPhaseText, devIvekPhase, devIvekTime, getSelected: () => devIvekSelected, setSelected: (v) => { devIvekSelected = v } }`
  const api = new Function('document', 'window', 't', 'fetch', 'wireDevTabs', body)(fakeDocument, fakeWindow, t, fakeFetch, () => {}) as {
    loadIvek: () => Promise<void>
    renderIvekList: (items: unknown) => void
    renderIvekDetail: (root: FakeNode, data: unknown) => void
    selectIvek: (id: string) => Promise<void>
    devIvekPhaseText: (p: unknown, now?: number) => string
    devIvekPhase: (p: unknown) => { key: string; round: number | null; sinceMs: number | null } | null
    devIvekTime: (v: unknown) => string
    getSelected: () => string | null
    setSelected: (v: string | null) => void
  }
  return { api, nodes, fetched, t, win }
}

const ok = (data: unknown) => ({ ok: true, status: 200, json: async () => data })
const bad = (status: number) => ({ ok: false, status, json: async () => ({}) })

const PAYLOAD = `"><img src=x onerror=alert(1)>'`
const NO_DATA = 'nincs adat'

function hostileDetail() {
  return {
    id: PAYLOAD, title: PAYLOAD, status: PAYLOAD, assignee: PAYLOAD,
    phase: { phase: PAYLOAD, since: 1_700_000_000 },
    events: [{ from_status: PAYLOAD, to_status: PAYLOAD, actor: PAYLOAD, created_at: 1_700_000_000 }],
    briefs: { ok: true, files: [{ name: PAYLOAD, mtime: 1_700_000_000_000 }] },
    reviews: {
      ok: true,
      rounds: [{ round: 2, reviewer: PAYLOAD, bySeverity: { HIGH: 1, MED: PAYLOAD, LOW: 0, OTHER: 0 } }, { round: PAYLOAD, reviewer: PAYLOAD, bySeverity: PAYLOAD }],
      events: { add: PAYLOAD, close: 3, reject: 1 }, lastTs: PAYLOAD,
    },
    commits: { ok: true, commits: [{ hash: PAYLOAD, date: 1_700_000_000, subject: PAYLOAD }] },
    deploys: { ok: true, runs: [{ mode: PAYLOAD, at: PAYLOAD, base: PAYLOAD, tip: PAYLOAD, files: PAYLOAD, result: PAYLOAD }] },
    children: [{ id: PAYLOAD, title: PAYLOAD, status: PAYLOAD }, { id: 'aaaaaaaa', title: 'x', status: 'done' }],
  }
}

describe('Ivek view: server strings are text, never markup', () => {
  it('detail: a hostile string in every slot adds no element, attribute or handler', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, hostileDetail())
    const html = assertStructure(root)
    // the payload is present only as escaped text
    expect(html).toContain('&quot;&gt;&lt;img src=x onerror=alert(1)&gt;')
    expect(root.textContent).toContain(PAYLOAD)
  })

  it('list: a hostile string in every slot adds no element, attribute or handler', () => {
    const { api, nodes } = makeHarness()
    api.renderIvekList([{ id: PAYLOAD, title: PAYLOAD, status: PAYLOAD, assignee: PAYLOAD, phase: { phase: 'r2', since: 1_700_000_000 } }, null, 'x'])
    assertStructure(nodes.devIvekList)
    expect(nodes.devIvekList.textContent).toContain(PAYLOAD)
  })

  it('quotes and apostrophes in names, reviewers and subjects stay inside the text node', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    const detail = hostileDetail()
    detail.briefs = { ok: true, files: [{ name: `a"b'c.md`, mtime: 1_700_000_000 }] }
    api.renderIvekDetail(root, detail)
    assertStructure(root)
    expect(root.textContent).toContain(`a"b'c.md`)
  })

  it('class names and chips come from whitelists, not from data', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, hostileDetail())
    const classes = root.all().map(n => n.className).join(' ')
    expect(classes).toContain('dev-ivek-result-unknown')
    expect(classes).not.toContain('img')
    expect(classes).not.toContain('onerror')
    for (const mode of ['check', 'apply', 'rollback']) {
      const r = new FakeNode('div')
      api.renderIvekDetail(r, { id: 'a', deploys: [{ mode, result: 'ok' }] })
      expect(r.all().some(n => n.className === 'dev-chip dev-ivek-result-ok')).toBe(true)
      expect(r.textContent).toContain(mode === 'check' ? 'ellenőrzés' : mode === 'apply' ? 'élesítés' : 'visszaállítás')
    }
  })

  it('there is no link: no href, no javascript: scheme, no inline handler in the Ivek source', () => {
    expect(SECTION).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write|\.href\b|setAttribute\('(href|on)/)
    expect(SECTION).not.toMatch(/onclick|onerror/i)
  })

  it('the view is read-only: only GET fetches, no write method or form control', () => {
    expect(SECTION).not.toMatch(/method:\s*'(POST|PUT|PATCH|DELETE)'/)
    expect(SECTION).not.toMatch(/createElement\('(input|textarea|select|form)'\)|devEl\('(input|textarea|select|form)'/)
    expect(SECTION).not.toMatch(/localStorage|document\.cookie/)
  })
})

describe('Ivek view: every field or block may be "nincs adat"', () => {
  const MISSING_VARIANTS: Array<[string, unknown]> = [
    ['null', null],
    ['undefined', undefined],
    ['ok:false object', { ok: false, reason: 'missing' }],
    ['nincs_adat object', { nincs_adat: true }],
    ['marker string', 'nincs adat'],
    ['wrong type', 42],
  ]

  for (const [label, v] of MISSING_VARIANTS) {
    it(`all six blocks render "${NO_DATA}" for ${label}`, () => {
      const { api } = makeHarness()
      const root = new FakeNode('div')
      api.renderIvekDetail(root, { id: 'abcdef12', title: 't', status: 'in_progress', assignee: 'ezermester', phase: v, events: v, briefs: v, reviews: v, commits: v, deploys: v, children: v })
      const sections = root.all().filter(n => n.tagName === 'section')
      expect(sections.length).toBe(6)
      for (const s of sections) expect(s.textContent).toContain(NO_DATA)
      assertStructure(root)
    })
  }

  it('a card with every field missing still renders (header fields show the marker)', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, {})
    expect(root.textContent).toContain(NO_DATA)
    expect(root.all().filter(n => n.tagName === 'section').length).toBe(6)
    assertStructure(root)
  })

  it('a non-object response renders the marker, not an exception', () => {
    const { api } = makeHarness()
    for (const bogus of [null, undefined, 'x', 7]) {
      const root = new FakeNode('div')
      api.renderIvekDetail(root, bogus)
      expect(root.textContent).toBe(NO_DATA)
    }
  })

  it('one missing block does not blank the others', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    const d = hostileDetail()
    ;(d as Record<string, unknown>).reviews = { ok: false, reason: 'too_large' }
    d.commits = { ok: true, commits: [{ hash: 'abc1234', date: 1_700_000_000, subject: 'fix: ok' }] }
    api.renderIvekDetail(root, d)
    const text = root.textContent
    expect(text).toContain('nincs adat (too_large)')
    expect(text).toContain('abc1234')
    expect(text).toContain('fix: ok')
  })

  it('a reason code shows only when it is a short lower-case code', () => {
    const { api } = makeHarness()
    for (const reason of [PAYLOAD, 'A'.repeat(5), 'x'.repeat(40), '../etc', '/Users/x']) {
      const root = new FakeNode('div')
      api.renderIvekDetail(root, { id: 'a', briefs: { ok: false, reason } })
      expect(root.textContent).not.toContain(reason)
    }
    const root = new FakeNode('div')
    api.renderIvekDetail(root, { id: 'a', briefs: { ok: false, reason: 'not_regular' } })
    expect(root.textContent).toContain('(not_regular)')
  })

  it('an empty list is shown as "nincs adat" too', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, { id: 'a', events: [], briefs: { ok: true, files: [] }, children: [] })
    const sections = root.all().filter(n => n.tagName === 'section')
    expect(sections[0].textContent).toContain(NO_DATA)
    expect(sections[1].textContent).toContain(NO_DATA)
  })

  it('list: missing fields show the marker, an empty list shows the empty text', () => {
    const { api, nodes } = makeHarness()
    api.renderIvekList([{}])
    expect(nodes.devIvekList.textContent).toContain(NO_DATA)
    api.renderIvekList([])
    expect(nodes.devIvekList.textContent).toBe('Nincs megjeleníthető ív.')
    assertStructure(nodes.devIvekList)
  })
})

describe('Ivek view: phase, age and values', () => {
  const NOW = Date.UTC(2026, 9, 31, 12, 0, 0)
  const SINCE = (NOW - 3 * 86_400_000 - 5 * 60_000) / 1000

  it('"r2, 3 napja" for round 2 started three days ago (phase key and round field)', () => {
    const { api } = makeHarness()
    expect(api.devIvekPhaseText({ phase: 'review', round: 2, since: SINCE }, NOW)).toBe('r2, 3 napja')
    expect(api.devIvekPhaseText({ phase: 'r2', since: SINCE }, NOW)).toBe('r2, 3 napja')
  })

  it('every step has a label, "nincs_jel" is "nincs gépi jel", unknown is "nincs adat"', () => {
    const { api } = makeHarness()
    expect(api.devIvekPhaseText({ phase: 'brief', since: NOW / 1000 - 600 }, NOW)).toBe('brief, 10 perce')
    expect(api.devIvekPhaseText({ phase: 'vegrehajtas', since: NOW / 1000 - 7200 }, NOW)).toBe('végrehajtás, 2 órája')
    expect(api.devIvekPhaseText({ phase: 'deploy_jelolt', since: SINCE }, NOW)).toBe('deploy-jelölt, 3 napja')
    expect(api.devIvekPhaseText({ phase: 'elesitve', since: SINCE }, NOW)).toBe('élesítve, 3 napja')
    expect(api.devIvekPhaseText({ phase: 'nincs_jel' }, NOW)).toBe('nincs gépi jel')
    for (const bad of [null, undefined, 'zzz', {}, { phase: 7 }, { phase: 'constructor' }, { phase: '__proto__' }, { phase: 'toString' }]) {
      expect(api.devIvekPhaseText(bad, NOW)).toBe(NO_DATA)
    }
  })

  it('a phase without a usable since shows the label only', () => {
    const { api } = makeHarness()
    expect(api.devIvekPhaseText({ phase: 'brief', since: 'nincs adat' }, NOW)).toBe('brief')
    expect(api.devIvekPhaseText({ phase: 'brief', since: null }, NOW)).toBe('brief')
  })

  it('timestamps: seconds, milliseconds, ISO and the deploy file-name stamp; junk is "nincs adat"', () => {
    const { api } = makeHarness()
    const a = api.devIvekTime(1_700_000_000)
    expect(api.devIvekTime(1_700_000_000_000)).toBe(a)
    expect(api.devIvekTime('2023-11-14T22:13:20.000Z')).toBe(a)
    expect(api.devIvekTime('20261031-211800')).not.toBe(NO_DATA)
    for (const junk of [null, undefined, 0, -5, NaN, '', 'soon', {}, PAYLOAD]) expect(api.devIvekTime(junk)).toBe(NO_DATA)
  })

  it('phase bar highlights the steps up to the current one and nothing for no signal', () => {
    const { api, nodes } = makeHarness()
    api.renderIvekList([
      { id: 'a', title: 'x', phase: { phase: 'review', round: 1 } },
      { id: 'b', title: 'x', phase: { phase: 'nincs_jel' } },
    ])
    const bars = nodes.devIvekList.all().filter(n => n.className === 'dev-ivek-bar')
    expect(bars.length).toBe(2)
    expect(bars[0].children.map(s => s.className)).toEqual([
      'dev-ivek-step reached', 'dev-ivek-step reached', 'dev-ivek-step reached current', 'dev-ivek-step', 'dev-ivek-step',
    ])
    expect(bars[1].children.every(s => s.className === 'dev-ivek-step')).toBe(true)
  })

  it('review rounds, add/close/reject counts, deploy range and child summary are shown', () => {
    const { api } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, {
      id: '51538ebc', title: 'T', status: 'done', assignee: 'ezermester',
      reviews: { ok: true, rounds: [{ round: 1, reviewer: 'ellenor', bySeverity: { HIGH: 2, MED: 1, LOW: 0, OTHER: 0 } }, { round: null, reviewer: 'ellenor', bySeverity: { HIGH: 0, MED: 0, LOW: 1, OTHER: 0 } }], events: { add: 2, close: 1, reject: 0 }, lastTs: null },
      deploys: { ok: true, runs: [{ mode: 'apply', at: '20261031-211800', base: '4617a805', tip: '9d75d5e0', files: 6, result: 'ok' }] },
      children: [{ id: 'aaaaaaaa', title: 'a', status: 'done' }, { id: 'bbbbbbbb', title: 'b', status: 'planned' }],
    })
    const text = root.textContent
    expect(text).toContain('Megállapítások: új 2 | lezárt 1 | elvetett 0')
    expect(text).toContain('r1')
    expect(text).toContain('kör nélkül')
    expect(text).toContain('magas 2 | közepes 1 | alacsony 0 | egyéb 0')
    expect(text).toContain('base: 4617a805 | tip: 9d75d5e0 | fájl: 6')
    expect(text).toContain('élesítés')
    expect(text).toContain('rendben')
    expect(text).toContain('Kész: 1 / 2')
    const fill = root.all().find(n => n.className === 'dev-ivek-childfill')!
    expect(fill.style.width).toBe('50.0%')
  })
})

describe('Ivek view: loading, stale answers, mobile', () => {
  it('a stale detail response is dropped (the later selection wins)', async () => {
    const { api, nodes, fetched } = makeHarness()
    const first = api.selectIvek('aaaaaaaa')
    const second = api.selectIvek('bbbbbbbb')
    expect(fetched.map(f => f.url)).toEqual(['/api/ivek/aaaaaaaa', '/api/ivek/bbbbbbbb'])
    fetched[1].resolve(ok({ id: 'bbbbbbbb', title: 'second' }))
    await second
    fetched[0].resolve(ok({ id: 'aaaaaaaa', title: 'first' }))
    await first
    expect(nodes.devIvekDetail.textContent).toContain('second')
    expect(nodes.devIvekDetail.textContent).not.toContain('first')
  })

  it('a stale list response is dropped too', async () => {
    const { api, nodes, fetched } = makeHarness()
    const first = api.loadIvek()
    const second = api.loadIvek()
    fetched[1].resolve(ok({ ivek: [{ id: 'bbbbbbbb', title: 'newer' }] }))
    await second
    fetched[0].resolve(ok({ ivek: [{ id: 'aaaaaaaa', title: 'older' }] }))
    await first
    expect(nodes.devIvekList.textContent).toContain('newer')
    expect(nodes.devIvekList.textContent).not.toContain('older')
  })

  it('only GET requests on the two read endpoints, the id is URL-encoded', async () => {
    const { api, fetched } = makeHarness()
    const p = api.selectIvek('../x?y=1')
    expect(fetched[0].url).toBe('/api/ivek/..%2Fx%3Fy%3D1')
    fetched[0].resolve(bad(404))
    await p
    expect(APP.slice(SECTION_START, SECTION_END).match(/fetch\(/g)?.length).toBe(2)
  })

  it('HTTP errors show a Hungarian error line with the status, not a stack', async () => {
    const { api, nodes, fetched } = makeHarness()
    const p = api.loadIvek()
    fetched[0].resolve(bad(403))
    await p
    expect(nodes.devIvekList.textContent).toBe('Az ívek nem tölthetők be (403).')
    const d = api.selectIvek('aaaaaaaa')
    fetched[1].resolve(bad(404))
    await d
    expect(nodes.devIvekDetail.textContent).toBe('Az ívek nem tölthetők be (404).')
  })

  it('the list body is accepted as { ivek: [...] }; a malformed body shows the empty text', async () => {
    const { api, nodes, fetched } = makeHarness()
    const p = api.loadIvek()
    fetched[0].resolve(ok({ ivek: 'nope' }))
    await p
    expect(nodes.devIvekList.textContent).toBe('Nincs megjeleníthető ív.')
  })

  it('on a 390 px (stacked) screen the detail is scrolled into view; on desktop it is not', async () => {
    for (const stacked of [true, false]) {
      const { api, nodes, fetched } = makeHarness({ stacked })
      const p = api.selectIvek('aaaaaaaa')
      fetched[0].resolve(ok({ id: 'aaaaaaaa', title: 'x' }))
      await p
      expect(nodes.devIvekDetail.scrolled).toBe(stacked ? 1 : 0)
    }
  })

  it('the back button scrolls to the list and exists in every detail', () => {
    const { api, nodes } = makeHarness()
    const root = new FakeNode('div')
    api.renderIvekDetail(root, { id: 'a', title: 'x' })
    const back = root.all().find(n => n.className.includes('dev-ivek-back'))!
    expect(back.tagName).toBe('button')
    expect(back.type).toBe('button')
    back.click()
    expect(nodes.devIvekList.scrolled).toBe(1)
  })

  it('the selected card is re-selected after a reload only when it is still listed', async () => {
    const { api, fetched } = makeHarness()
    api.setSelected('aaaaaaaa')
    const p = api.loadIvek()
    fetched[0].resolve(ok({ ivek: [{ id: 'bbbbbbbb', title: 'x' }] }))
    await p
    expect(fetched.length).toBe(1)
    const q = api.loadIvek()
    fetched[1].resolve(ok({ ivek: [{ id: 'aaaaaaaa', title: 'x' }] }))
    await q
    expect(fetched.length).toBe(3)
    expect(fetched[2].url).toBe('/api/ivek/aaaaaaaa')
  })
})

describe('Ivek view: tab wiring and the existing views', () => {
  function runSetDevView(view: string) {
    const ids = ['devFunkciokView', 'devMunkanaploView', 'devKerdesekView', 'devIvekView']
    const tabs = ['devTabFunkciok', 'devTabKerdesek', 'devTabMunkanaplo', 'devTabIvek']
    const views: Record<string, FakeNode> = Object.fromEntries([...ids, ...tabs].map(i => [i, new FakeNode(ids.includes(i) ? 'div' : 'button')]))
    const calls: string[] = []
    const doc = { getElementById: (id: string) => views[id] || null }
    const fn = new Function('document', 'loadWorklog', 'loadDevQuestions', 'loadIvek', `let devActiveView = 'funkciok'\n${extractFn('setDevView')}\nreturn { setDevView, active: () => devActiveView }`)(
      doc, () => calls.push('wl'), () => calls.push('q'), () => calls.push('iv'),
    ) as { setDevView: (v: string) => void; active: () => string }
    fn.setDevView(view)
    return { views, calls, active: fn.active() }
  }

  it('ivek: only the Ivek view is visible, its tab is active, loadIvek runs', () => {
    const r = runSetDevView('ivek')
    expect(r.active).toBe('ivek')
    expect(r.views.devIvekView.hidden).toBe(false)
    expect(r.views.devFunkciokView.hidden).toBe(true)
    expect(r.views.devMunkanaploView.hidden).toBe(true)
    expect(r.views.devKerdesekView.hidden).toBe(true)
    expect(r.views.devTabIvek.className).toContain('active')
    expect(r.calls).toEqual(['iv'])
  })

  it('funkciok stays the default for unknown or empty views and loads nothing extra', () => {
    for (const v of ['funkciok', '', 'nope', 'constructor', undefined as unknown as string]) {
      const r = runSetDevView(v)
      expect(r.active).toBe('funkciok')
      expect(r.views.devFunkciokView.hidden).toBe(false)
      expect(r.views.devIvekView.hidden).toBe(true)
      expect(r.views.devTabFunkciok.className).toContain('active')
      expect(r.views.devTabIvek.className).not.toContain('active')
      expect(r.calls).toEqual([])
    }
  })

  it('munkanaplo and kerdesek still switch and load their own data only', () => {
    const w = runSetDevView('munkanaplo')
    expect(w.calls).toEqual(['wl'])
    expect(w.views.devMunkanaploView.hidden).toBe(false)
    expect(w.views.devIvekView.hidden).toBe(true)
    const q = runSetDevView('kerdesek')
    expect(q.calls).toEqual(['q'])
    expect(q.views.devKerdesekView.hidden).toBe(false)
    expect(q.views.devIvekView.hidden).toBe(true)
  })

  it('index.html: the tab button and the list + detail container exist, hidden by default', () => {
    expect(HTML).toMatch(/<button[^>]*id="devTabIvek"[^>]*data-dev-view="ivek"[^>]*data-i18n="dev\.tab\.ivek"[^>]*>Ívek<\/button>/)
    expect(HTML).toMatch(/<div class="dev-layout" id="devIvekView" hidden>\s*<div class="dev-list" id="devIvekList"><\/div>\s*<div class="dev-detail" id="devIvekDetail"><\/div>\s*<\/div>/)
    // the Funkciok tab stays the active one
    expect(HTML).toContain('class="view-btn active" id="devTabFunkciok"')
    expect(HTML).toContain('id="devFunkciokView"')
  })

  it('the 390 px layout: single column at <=768px, no fixed width, the back button is shown only there', () => {
    expect(CSS).toMatch(/@media \(max-width: 768px\) \{\s*\.dev-layout \{ grid-template-columns: minmax\(0, 1fr\); \}/)
    expect(CSS).toMatch(/\.dev-ivek-bar \{[^}]*repeat\(5, minmax\(0, 1fr\)\)/)
    expect(CSS).toMatch(/\.dev-ivek-back \{ display: none;/)
    expect(CSS).toMatch(/@media \(max-width: 768px\) \{\s*\.dev-ivek-back \{ display: inline-flex;/)
    const ivekCss = CSS.slice(CSS.indexOf('/* === Fejlesztes > Ivek'), CSS.indexOf('/* === Fejlesztes > Kerdesek'))
    expect(ivekCss).not.toMatch(/\bwidth:\s*\d+px|min-width:\s*\d{3,}px|white-space:\s*nowrap/)
  })
})

describe('Ivek view: i18n', () => {
  const usedKeys = new Set<string>()
  // keys ending in a dot are dynamic prefixes (covered by DYNAMIC below)
  for (const m of SECTION.matchAll(/t\('(dev\.ivek\.[a-z_.]*[a-z_])'/g)) usedKeys.add(m[1])
  const DYNAMIC = [
    ...['brief', 'vegrehajtas', 'review', 'deploy_jelolt', 'elesitve', 'nincs_jel'].map(k => `dev.ivek.phase.${k}`),
    ...['check', 'apply', 'rollback'].map(k => `dev.ivek.deploy.mode.${k}`),
    ...['ok', 'refused', 'fail', 'unknown'].map(k => `dev.ivek.deploy.result.${k}`),
    'dev.ivek.sev.high', 'dev.ivek.sev.med', 'dev.ivek.sev.low', 'dev.ivek.sev.other', 'dev.tab.ivek',
  ]

  it('the section uses i18n keys and every one exists in hu and en', () => {
    expect(usedKeys.size).toBeGreaterThan(10)
    for (const lang of ['hu', 'en'] as const) {
      const { win } = makeI18n(lang)
      for (const k of [...usedKeys, ...DYNAMIC]) expect(win._i18n[lang][k], `${lang}:${k}`).toBeTypeOf('string')
    }
  })

  it('the tab reads "Ívek" in Hungarian and the Hungarian labels keep the tab tone', () => {
    const { t } = makeI18n('hu')
    expect(t('dev.tab.ivek')).toBe('Ívek')
    expect(t('dev.ivek.no_data')).toBe(NO_DATA)
    expect(t('dev.ivek.phase.nincs_jel')).toBe('nincs gépi jel')
  })
})
