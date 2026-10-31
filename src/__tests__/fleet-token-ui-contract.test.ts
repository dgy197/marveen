// Card acdb8045 K7: UI contract for the "régi token" badge and the owner-only
// "restart all stale" button in web/app.js. The block is evaluated out of the
// source with a tiny fake DOM and a stub fetch (no browser, no network):
//  1. hostile agent names and result strings reach the DOM as text only;
//  2. the sweep button is hidden when no agent is stale, shown when one is;
//  3. a 403 shows the owner-only message and is never retried;
//  4. the button disables itself while the sweep runs.
import { describe, it, expect, beforeAll } from 'vitest'
import { readFileSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = dirname(fileURLToPath(import.meta.url))
const ROOT = join(__dirname, '../..')
const APP = readFileSync(join(ROOT, 'web/app.js'), 'utf-8')

let hu: Record<string, string>
beforeAll(async () => {
  ;(globalThis as unknown as { window: Record<string, unknown> }).window ||= {} as Record<string, unknown>
  await import(/* @vite-ignore */ '../../web/lang/hu.js' as string)
  hu = (globalThis as unknown as { window: { _i18n: Record<string, Record<string, string>> } }).window._i18n.hu
})

class El {
  tagName: string
  id = ''
  className = ''
  title = ''
  disabled = false
  dataset: Record<string, string> = {}
  style: Record<string, string> = {}
  children: El[] = []
  parentNode: El | null = null
  listeners: Record<string, Array<() => unknown>> = {}
  private _text = ''
  constructor(tag: string) { this.tagName = tag }
  set textContent(v: string) { this._text = v; this.children = [] }
  get textContent(): string { return this._text + this.children.map((c) => c.textContent).join('') }
  get firstChild(): El | null { return this.children[0] ?? null }
  appendChild(c: El) { c.parentNode = this; this.children.push(c); return c }
  insertBefore(c: El, ref: El) { c.parentNode = this; this.children.splice(this.children.indexOf(ref), 0, c); return c }
  remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((x) => x !== this) }
  addEventListener(ev: string, fn: () => unknown) { (this.listeners[ev] ||= []).push(fn) }
  querySelector(sel: string): El | null {
    const cls = sel.startsWith('.') ? sel.slice(1) : null
    const walk = (n: El): El | null => {
      for (const c of n.children) {
        if (cls && c.className.split(' ').includes(cls)) return c
        const r = walk(c)
        if (r) return r
      }
      return null
    }
    return walk(this)
  }
}

interface Env {
  api: {
    refreshFleetTokenUi: () => Promise<void>
    runFleetTokenSweep: (b: El, box: El) => Promise<void>
  }
  bar: () => El | null
  cards: Record<string, El>
  calls: string[]
}

function build(opts: {
  agents: Array<{ name: string; running: boolean }>
  states: Record<string, string>
  sweep?: (calls: string[]) => Promise<{ ok: boolean; status: number; json: () => Promise<unknown> }>
}): Env {
  const start = APP.indexOf('// FLEETTOKENUI acdb8045 K7')
  const end = APP.indexOf('async function loadAgents() {')
  expect(start, 'K7 block not found').toBeGreaterThan(-1)
  expect(end).toBeGreaterThan(start)
  const src = APP.slice(start, end)

  const root = new El('div')
  const view = new El('div'); view.id = 'agentsGridView'
  root.appendChild(view)
  const cards: Record<string, El> = {}
  for (const a of opts.agents) {
    const card = new El('div'); card.className = 'agent-card'
    const footer = new El('div'); footer.className = 'agent-card-footer'
    card.appendChild(footer)
    cards[a.name] = card
  }
  const calls: string[] = []
  const document = {
    getElementById: (id: string) => (id === 'agentsGridView' ? view : root.children.find((c) => c.id === id) ?? null),
    createElement: (tag: string) => new El(tag),
    querySelector: (sel: string) => {
      const m = sel.match(/data-name="(.*)"\]$/)
      const name = m ? m[1].replace(/\\(.)/g, '$1') : ''
      return cards[name] ?? null
    },
  }
  const fetch = async (url: string, init?: { method?: string }) => {
    calls.push(`${init?.method ?? 'GET'} ${url}`)
    if (url.endsWith('/restart-stale')) return opts.sweep!(calls)
    const m = url.match(/\/api\/agents\/([^/]+)\/status/)
    const name = decodeURIComponent(m![1])
    return { ok: true, status: 200, json: async () => ({ fleetToken: opts.states[name] }) }
  }
  const t = (k: string) => hu[k] ?? k
  const agents = opts.agents
  const factory = new Function(
    'document', 'fetch', 't', 'agents', 'mainAgentId', 'CSS', 'AbortController', 'setTimeout', 'clearTimeout',
    `${src}; return { refreshFleetTokenUi, runFleetTokenSweep }`,
  )
  const api = factory(document, fetch, t, agents, () => 'marveen', { escape: (s: string) => s }, AbortController, setTimeout, clearTimeout)
  return { api, bar: () => root.children.find((c) => c.id === 'fleetTokenBar') ?? null, cards, calls }
}

describe('K7 -- fleet token badge and sweep button', () => {
  it('badges only stale and unknown agents, and the button is hidden when none is stale', async () => {
    const env = build({
      agents: [{ name: 'a', running: true }, { name: 'b', running: true }],
      states: { a: 'current', b: 'unknown' },
    })
    await env.api.refreshFleetTokenUi()
    expect(env.cards.a.querySelector('.fleet-token-badge')).toBeNull()
    expect(env.cards.b.querySelector('.fleet-token-badge')!.textContent).toBe(hu['agents.fleet_token.unknown'])
    expect(env.bar()!.style.display).toBe('none')
  })

  it('shows the button when one agent is stale, label is the Hungarian text', async () => {
    const env = build({ agents: [{ name: 'a', running: true }], states: { a: 'stale' } })
    await env.api.refreshFleetTokenUi()
    expect(env.cards.a.querySelector('.fleet-token-badge')!.textContent).toBe('régi token')
    expect(env.bar()!.style.display).toBe('')
    expect(env.bar()!.children[0].textContent).toBe('Mindet sorban újraindítani (régi token)')
  })

  it('renders hostile agent names and results as text only', async () => {
    const evil = '<img src=x onerror=alert(1)>'
    const env = build({
      agents: [{ name: 'a', running: true }],
      states: { a: 'stale' },
      sweep: async () => ({ ok: true, status: 200, json: async () => ({ restarted: [evil], skipped: [], failed: ['"><script>x</script>'] }) }),
    })
    await env.api.refreshFleetTokenUi()
    const box = env.bar()!.children[1]
    await env.api.runFleetTokenSweep(env.bar()!.children[0], box)
    expect(box.textContent).toContain(evil)
    expect(box.children.every((c) => c.tagName === 'div')).toBe(true)
    expect(APP.slice(APP.indexOf('// FLEETTOKENUI'), APP.indexOf('async function loadAgents() {'))).not.toMatch(/innerHTML|insertAdjacentHTML/)
  })

  it('403 shows the owner-only message, no retry, button re-enabled', async () => {
    let n = 0
    const env = build({
      agents: [{ name: 'a', running: true }],
      states: { a: 'stale' },
      sweep: async () => { n++; return { ok: false, status: 403, json: async () => ({}) } },
    })
    await env.api.refreshFleetTokenUi()
    const btn = env.bar()!.children[0]
    const box = env.bar()!.children[1]
    await env.api.runFleetTokenSweep(btn, box)
    expect(box.textContent).toBe('Csak bejelentkezett tulajdonos indíthatja')
    expect(n).toBe(1)
    expect(btn.disabled).toBe(false)
  })

  it('disables the button while the sweep runs', async () => {
    let release!: () => void
    const gate = new Promise<void>((r) => { release = r })
    const env = build({
      agents: [{ name: 'a', running: true }],
      states: { a: 'stale' },
      sweep: async () => { await gate; return { ok: true, status: 200, json: async () => ({ restarted: ['a'], skipped: [], failed: [] }) } },
    })
    await env.api.refreshFleetTokenUi()
    const btn = env.bar()!.children[0]
    const box = env.bar()!.children[1]
    const p = env.api.runFleetTokenSweep(btn, box)
    expect(btn.disabled).toBe(true)
    // a second click while running must not start a second sweep
    await env.api.runFleetTokenSweep(btn, box)
    expect(env.calls.filter((c) => c.endsWith('/restart-stale')).length).toBe(1)
    release()
    await p
    expect(btn.disabled).toBe(false)
    expect(box.textContent).toBe('Újraindítva: a')
  })

  it('has a long client timeout for the sweep', () => {
    const m = APP.match(/FLEET_TOKEN_SWEEP_TIMEOUT_MS = (\d+) \* (\d+) \* (\d+)/)
    expect(m).not.toBeNull()
    expect(Number(m![1]) * Number(m![2]) * Number(m![3])).toBeGreaterThanOrEqual(10 * 60 * 1000)
  })
})
