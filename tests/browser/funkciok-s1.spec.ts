// Card d7b2d5c8, S1-8: the Fejlesztes > Funkciok tab. Static web/ like the other
// specs here (a second dashboard on this host would take the process lock from
// the live one), so every /api call is answered by routes. External hosts
// (CDN scripts) are aborted: nothing leaves 127.0.0.1.
import { test, expect, type Page } from '@playwright/test'

const XSS = '<img src=x onerror="window.__xss=1">'

const LIST = {
  funkciok: [
    { slug: 'ajanlat-kor', nev: 'Ajanlat-kor', last_change: 1761600000, open_cards: 1 },
    { slug: 'context-guard', nev: 'Context-guard', last_change: 1761500000, open_cards: 0 },
    { slug: 'levelkapu', nev: 'Levelkapu', last_change: 1761700000, open_cards: 2 },
    { slug: 'rossz-fajl', nev: null, last_change: null, open_cards: null, error: 'schema: nev missing' },
  ],
}

const PAGE = {
  slug: 'levelkapu',
  nev: 'Levelkapu',
  leiras: 'Kimeno level jovahagyasi kapu',
  last_change: 1761700000,
  open_cards: 2,
  commits_without_card: 3,
  commits_total: 2,
  cards: [
    {
      seq: 101, id: 'aaaa1111', title: `Kapu ${XSS}`, status: 'in_progress', assignee: 'ezermester',
      parent_id: null, created_at: 1761000000, last_status_at: 1761600000, archived: false,
      events: [{ from_status: 'planned', to_status: 'in_progress', actor: 'brainy', created_at: 1761100000 }],
    },
  ],
  cards_missing: [],
  messages: [
    {
      id: 4242, from_agent: 'brainy', to_agent: 'ezermester', status: 'done', created_at: 1761100000,
      completed_at: 1761200000, reason: 'card', content_excerpt: `Csinald meg #101 ${XSS}`, result_excerpt: 'Kesz.',
    },
  ],
  commits: [
    { repo: 'marveen', hash: 'abc1234', date: 1761700000, author: 'E', subject: `feat: kapu ${XSS} (#77)`, pr: 77, reason: 'card' },
    { repo: 'marveen', hash: 'def5678', date: 1761600000, author: 'E', subject: 'fix: tag', pr: null, reason: 'tag' },
  ],
  tests: [{ repo: 'marveen', path: 'tests/kapu.test.ts', last_commit: 'abc1234', last_date: 1761700000 }],
  repos: [
    { nev: 'marveen', error: null, commits: 2 },
    { nev: 'kulso-repo', error: 'repo_not_allowed', commits: 0 },
  ],
  tiltasok: ['Ne kuldj levelet jovahagyas nelkul'],
  specUtak: ['/Volumes/8T/spec/levelkapu.md'],
}

const FULL = {
  id: 4242, from_agent: 'brainy', to_agent: 'ezermester', status: 'done', created_at: 1761100000, completed_at: 1761200000,
  content: `A TELJES PROMPT SZOVEG ${XSS}`, result: 'A TELJES VALASZ SZOVEG',
}

async function open(page: Page, lang: 'hu' | 'en' = 'hu') {
  const errors: string[] = []
  const requested: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.route((u) => u.hostname !== '127.0.0.1', (r) => r.abort())
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
  const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/api/funkciok', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(LIST)) })
  await page.route('**/api/funkciok/levelkapu', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(PAGE)) })
  await page.route('**/api/funkciok/levelkapu/messages/*', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(FULL)) })
  await page.route('**/api/funkciok/rossz-fajl', (r) => r.fulfill(json({ error: 'Invalid registry file', slug: 'rossz-fajl', reason: 'nev missing' }, 422)))
  await page.addInitScript((l) => { try { localStorage.setItem('marveen.lang', l) } catch { /* ignore */ } }, lang)
  await page.goto('/index.html#dev')
  return { errors, requested }
}

test.describe('S1-8 Fejlesztes > Funkciok', () => {
  test('tab opens: three sub-views, two disabled with the "hamarosan" label, 4 functions listed', async ({ page }) => {
    const { errors } = await open(page)
    await expect(page.locator('#devPage')).toBeVisible()
    await expect(page.locator('#devTabFunkciok')).toBeEnabled()
    await expect(page.locator('#devTabKerdesek')).toBeDisabled()
    await expect(page.locator('#devTabMunkanaplo')).toBeDisabled()
    await expect(page.locator('#devTabKerdesek')).toContainText('hamarosan')
    await expect(page.locator('#devFunkciokList .dev-list-item')).toHaveCount(4)
    // the invalid registry entry carries its error flag
    await expect(page.locator('#devFunkciokList .dev-list-item[data-slug="rossz-fajl"] .dev-badge')).toBeVisible()
    // R1-5: the raw server error code is not shown; a translated generic text is
    const bad = page.locator('#devFunkciokList .dev-list-item[data-slug="rossz-fajl"]')
    await expect(bad).toContainText('hibás regiszterfájl')
    await expect(bad).not.toContainText('schema:')
    // open card count of the first valid function is on its row
    await expect(page.locator('#devFunkciokList .dev-list-item[data-slug="levelkapu"]')).toContainText('nyitott kártya: 2')
    expect(errors).toEqual([])
  })

  test('the sidebar link opens the tab as well', async ({ page }) => {
    await open(page)
    await page.goto('/index.html')
    await page.locator('.sb-link[data-page="dev"]').click()
    await expect(page.locator('#devPage')).toBeVisible()
    await expect(page.locator('#devFunkciokList .dev-list-item')).toHaveCount(4)
  })

  test('click a function: header and the five blocks are visible; block error stays inside its block', async ({ page }) => {
    const { errors, requested } = await open(page)
    await page.locator('#devFunkciokList .dev-list-item[data-slug="levelkapu"]').click()
    const detail = page.locator('#devFunkcioDetail')
    await expect(detail.locator('h2')).toHaveText('Levelkapu')
    await expect(detail).toContainText('Kártya nélküli commitok: 3')
    const blocks = detail.locator('section.dev-block')
    await expect(blocks).toHaveCount(5)
    for (const title of ['Kártyák', 'Promptok és válaszok', 'Commitok', 'Tesztek', 'Tiltások']) {
      await expect(blocks.filter({ has: page.locator('h3', { hasText: title }) })).toBeVisible()
    }
    // card timeline incl. the status event
    await expect(blocks.nth(0)).toContainText('planned -> in_progress')
    // commit row: repo, hash, reason, PR number
    await expect(blocks.nth(2)).toContainText('abc1234')
    await expect(blocks.nth(2)).toContainText('PR #77')
    await expect(blocks.nth(2)).toContainText('kártya')
    // tests and prohibitions
    await expect(blocks.nth(3)).toContainText('tests/kapu.test.ts')
    await expect(blocks.nth(4)).toContainText('Ne kuldj levelet jovahagyas nelkul')
    await expect(blocks.nth(4)).toContainText('/Volumes/8T/spec/levelkapu.md')
    // the allowlist error of one repo is inside the Commitok and Tesztek blocks, the rest still renders
    await expect(blocks.nth(2).locator('.dev-error')).toContainText('kulso-repo')
    await expect(blocks.nth(2).locator('.dev-error')).toContainText('engedélyezési listán')
    await expect(blocks.nth(3).locator('.dev-error')).toContainText('kulso-repo')
    await expect(blocks.nth(0).locator('.dev-error')).toHaveCount(0)
    expect(requested).toContain('/api/funkciok/levelkapu')
    expect(errors).toEqual([])
  })

  test('a message row click loads and shows the full text, a second click hides it', async ({ page }) => {
    const { requested } = await open(page)
    await page.locator('#devFunkciokList .dev-list-item[data-slug="levelkapu"]').click()
    const row = page.locator('.dev-msg-row[data-msg-id="4242"]')
    const full = row.locator('.dev-msg-full')
    await expect(full).toBeHidden()
    await row.locator('.dev-row-head').click()
    await expect(full).toBeVisible()
    await expect(full).toContainText('A TELJES PROMPT SZOVEG')
    await expect(full).toContainText('A TELJES VALASZ SZOVEG')
    expect(requested).toContain('/api/funkciok/levelkapu/messages/4242')
    await row.locator('.dev-row-head').click()
    await expect(full).toBeHidden()
  })

  test('an invalid registry entry shows its reason instead of a page', async ({ page }) => {
    await open(page)
    await page.locator('#devFunkciokList .dev-list-item[data-slug="rossz-fajl"]').click()
    await expect(page.locator('#devFunkcioDetail .dev-error')).toContainText('nev missing')
  })

  test('data strings are text: an <img onerror> payload creates no element and runs nothing', async ({ page }) => {
    const { errors } = await open(page)
    await page.locator('#devFunkciokList .dev-list-item[data-slug="levelkapu"]').click()
    await expect(page.locator('#devFunkcioDetail h2')).toHaveText('Levelkapu')
    await page.locator('.dev-msg-row[data-msg-id="4242"] .dev-row-head').click()
    await expect(page.locator('.dev-msg-full')).toContainText('A TELJES PROMPT SZOVEG')
    await expect(page.locator('#devPage img')).toHaveCount(0)
    // the payload is visible as literal text in the card title, message excerpt, full text and commit subject
    await expect(page.locator('#devFunkcioDetail')).toContainText('<img src=x onerror="window.__xss=1">')
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined()
    expect(errors).toEqual([])
  })

  test('mobile 390px: list above the page, no horizontal page scroll', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await open(page)
    await page.locator('#devFunkciokList .dev-list-item[data-slug="levelkapu"]').click()
    await expect(page.locator('#devFunkcioDetail h2')).toHaveText('Levelkapu')
    const listBox = await page.locator('#devFunkciokList').boundingBox()
    const detailBox = await page.locator('#devFunkcioDetail').boundingBox()
    expect(listBox && detailBox && detailBox.y >= listBox.y + listBox.height - 1).toBe(true)
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
