// Function page S2-C: the Dontesek block, the record form and the context
// package button on the function page. Same approach as funkciok-s1.spec.ts:
// static web/, every /api call answered by routes, external hosts aborted.
import { test, expect, type Page } from '@playwright/test'

const XSS = '<img src=x onerror="window.__xss=1">'

const LIST = { funkciok: [{ slug: 'charlie-feature', nev: 'Charlie feature', last_change: 1761700000, open_cards: 0 }] }

const DECISIONS = [
  { id: 4, slug: 'charlie-feature', quote_short: 'Az uj dontes felulirja a regit', tg_chat: '1000000001', tg_msg_id: '3001', msg_id: null, card_id: 'aaaa1111', decided_at: 1761690000, recorded_by: 'session:mallory', supersedes: 1, superseded_by: null, source_status: 'verified', created_at: 1761690001 },
  { id: 3, slug: 'charlie-feature', quote_short: `Ez XSS: ${XSS}`, tg_chat: '1000000001', tg_msg_id: '3000', msg_id: null, card_id: null, decided_at: 1761680000, recorded_by: 'agent-a', supersedes: null, superseded_by: null, source_status: 'verified_at_record', created_at: 1761680001 },
  { id: 2, slug: 'charlie-feature', quote_short: 'Forras nem talalhato', tg_chat: '1000000001', tg_msg_id: '2999', msg_id: null, card_id: null, decided_at: 1761670000, recorded_by: 'agent-a', supersedes: null, superseded_by: null, source_status: 'not_found', created_at: 1761670001 },
  { id: 5, slug: 'charlie-feature', quote_short: 'Belso uzenet a forras', tg_chat: null, tg_msg_id: null, msg_id: 4242, card_id: null, decided_at: 1761660000, recorded_by: 'agent-a', supersedes: null, superseded_by: null, source_status: 'none', created_at: 1761660001 },
]

const PAGE = {
  slug: 'charlie-feature', nev: 'Charlie feature', leiras: 'Kapu', last_change: 1761700000, open_cards: 0,
  commits_without_card: 0, commits_total: 0, cards: [], cards_missing: [], messages: [], commits: [], tests: [],
  repos: [], tiltasok: [], specUtak: [], decisions: DECISIONS,
}

const MARKDOWN = `# Charlie feature\n\n\`\`\`text\n${XSS}\n\`\`\`\n`

type Post = { body: unknown }

async function open(page: Page, postStatus = 201, postBody: unknown = { id: 6 }) {
  const errors: string[] = []
  const posts: Post[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.route((u) => u.hostname !== '127.0.0.1', (r) => r.abort())
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
  const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/api/funkciok', (r) => r.fulfill(json(LIST)))
  await page.route('**/api/funkciok/charlie-feature', (r) => r.fulfill(json(PAGE)))
  await page.route('**/api/funkciok/charlie-feature/decisions', (r) => {
    const req = r.request()
    posts.push({ body: JSON.parse(req.postData() || '{}') })
    return r.fulfill(json(postBody, postStatus))
  })
  await page.route('**/api/funkciok/charlie-feature/context', (r) =>
    r.fulfill({ status: 200, contentType: 'text/markdown; charset=utf-8', body: MARKDOWN }))
  await page.addInitScript(() => { try { localStorage.setItem('marveen.lang', 'hu') } catch { /* ignore */ } })
  await page.goto('/index.html#dev')
  await page.locator('#devFunkciokList .dev-list-item[data-slug="charlie-feature"]').click()
  await expect(page.locator('#devFunkcioDetail h2')).toHaveText('Charlie feature')
  return { errors, posts }
}

test.describe('S2-C Fejlesztes > Dontesek', () => {
  test('decisions render with each source status, date, recorded_by and the supersedes marker', async ({ page }) => {
    const { errors } = await open(page)
    const block = page.locator('#devFunkcioDetail .dev-dec-block')
    await expect(block.locator('h3')).toContainText('Döntések')
    await expect(block.locator('.dev-dec-row')).toHaveCount(4)
    const row = (id: number) => block.locator(`.dev-dec-row[data-dec-id="${id}"]`)
    await expect(row(4)).toContainText('forrás ellenőrizve')
    await expect(row(4)).toContainText('javítja: #1')
    await expect(row(4)).toContainText('tg 1000000001/3001')
    await expect(row(4)).toContainText('session:mallory')
    await expect(row(3)).toContainText('forrás ellenőrizve a rögzítéskor')
    await expect(row(2)).toContainText('forrás nem található')
    await expect(row(5)).toContainText('nincs tg-forrás')
    await expect(row(5)).toContainText('msg #4242')
    await expect(row(4).locator('.dev-row-sub').first()).not.toHaveText('')
    expect(errors).toEqual([])
  })

  test('a page without a decisions key shows an empty block', async ({ page }) => {
    await page.route((u) => u.hostname !== '127.0.0.1', (r) => r.abort())
    await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
    await page.route('**/api/funkciok/charlie-feature', (r) => {
      const { decisions: _d, ...rest } = PAGE
      return r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(rest) })
    })
    await page.route('**/api/funkciok', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(LIST) }))
    await page.addInitScript(() => { try { localStorage.setItem('marveen.lang', 'hu') } catch { /* ignore */ } })
    await page.goto('/index.html#dev')
    await page.locator('#devFunkciokList .dev-list-item[data-slug="charlie-feature"]').click()
    await expect(page.locator('.dev-dec-block')).toContainText('Még nincs rögzített döntés')
  })

  test('form success: POST body has exactly the filled keys, then the page reloads', async ({ page }) => {
    const { posts, errors } = await open(page)
    const form = page.locator('.dev-dec-form')
    await form.locator('textarea[name="quote_short"]').fill('  Ujabb dontes  ')
    await form.locator('input[name="tg_msg_id"]').fill('3002')
    await form.locator('input[name="card_id"]').fill('bbbb2222')
    await form.locator('select[name="supersedes"]').selectOption('4')
    await form.locator('button[type="submit"]').click()
    await expect.poll(() => posts.length).toBe(1)
    expect(posts[0].body).toEqual({ quote_short: 'Ujabb dontes', tg_msg_id: '3002', card_id: 'bbbb2222', supersedes: 4 })
    // reloaded detail: a fresh form, no error left
    await expect(page.locator('.dev-dec-msg')).toBeHidden()
    expect(errors).toEqual([])
  })

  test('msg_id goes out as a number', async ({ page }) => {
    const { posts } = await open(page)
    const form = page.locator('.dev-dec-form')
    await form.locator('textarea[name="quote_short"]').fill('Belso')
    await form.locator('input[name="msg_id"]').fill('4242')
    await form.locator('button[type="submit"]').click()
    await expect.poll(() => posts.length).toBe(1)
    expect(posts[0].body).toEqual({ quote_short: 'Belso', msg_id: 4242 })
  })

  test('no source: blocked client-side with a message, nothing is sent', async ({ page }) => {
    const { posts } = await open(page)
    const form = page.locator('.dev-dec-form')
    await form.locator('textarea[name="quote_short"]').fill('Forras nelkul')
    await form.locator('button[type="submit"]').click()
    await expect(form.locator('.dev-dec-msg')).toContainText('Forrás kell')
    expect(posts.length).toBe(0)
  })

  test('409 and 422 are shown inline, translated, not the raw server text', async ({ page }) => {
    for (const [status, text] of [[409, 'Ütközés'], [422, 'nem létezik']] as const) {
      const { posts } = await open(page, status, { error: 'RAW SERVER TEXT' })
      const form = page.locator('.dev-dec-form')
      await form.locator('textarea[name="quote_short"]').fill('Hibas')
      await form.locator('input[name="msg_id"]').fill('999')
      await form.locator('button[type="submit"]').click()
      await expect(form.locator('.dev-dec-msg')).toBeVisible()
      await expect(form.locator('.dev-dec-msg')).toContainText(text)
      await expect(form.locator('.dev-dec-msg')).not.toContainText('RAW SERVER TEXT')
      expect(posts.length).toBe(1)
      await page.unrouteAll({ behavior: 'ignoreErrors' })
    }
  })

  test('live counter, 280 accepted, 281 blocked client-side', async ({ page }) => {
    const { posts } = await open(page)
    const form = page.locator('.dev-dec-form')
    const q = form.locator('textarea[name="quote_short"]')
    const submit = form.locator('button[type="submit"]')
    await expect(submit).toBeDisabled()
    await q.fill('a'.repeat(280))
    await expect(form.locator('.dev-dec-counter')).toHaveText('280/280')
    await expect(submit).toBeEnabled()
    await q.fill('a'.repeat(281))
    await expect(form.locator('.dev-dec-counter')).toHaveText('281/280')
    await expect(submit).toBeDisabled()
    await form.locator('input[name="msg_id"]').fill('1')
    await q.press('Enter')
    await form.evaluate((f) => (f as HTMLFormElement).requestSubmit())
    expect(posts.length).toBe(0)
    // 280 emoji = 280 code points (560 UTF-16 units) are accepted
    await q.fill('😀'.repeat(280))
    await expect(form.locator('.dev-dec-counter')).toHaveText('280/280')
    await expect(submit).toBeEnabled()
  })

  test('an XSS payload in a quote renders as text only', async ({ page }) => {
    const { errors } = await open(page)
    await expect(page.locator('.dev-dec-row[data-dec-id="3"]')).toContainText(XSS)
    await expect(page.locator('#devPage img')).toHaveCount(0)
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined()
    expect(errors).toEqual([])
  })

  test('context button shows the markdown as text in a read-only pre', async ({ page }) => {
    const { errors } = await open(page)
    const out = page.locator('.dev-dec-ctx-out')
    await expect(out).toBeHidden()
    await page.locator('.dev-dec-ctx-btn').click()
    await expect(out).toBeVisible()
    await expect(out).toContainText('# Charlie feature')
    await expect(out).toContainText(XSS)
    expect(await out.evaluate((e) => e.tagName)).toBe('PRE')
    await expect(page.locator('#devPage img')).toHaveCount(0)
    expect(errors).toEqual([])
  })

  test('mobile 390px: no horizontal page scroll with the form open', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await open(page)
    await page.locator('.dev-dec-ctx-btn').click()
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
