// Card d7b2d5c8, S4-C: the Fejlesztes > Munkanaplo sub-view. Static web/ with
// every /api call answered by routes (same approach as funkciok-s1.spec.ts);
// external hosts are aborted so nothing leaves 127.0.0.1.
import { test, expect, type Page } from '@playwright/test'

const XSS = '<img src=x onerror="window.__xss=1">'
const DAY0 = 1761606000 // arbitrary local-midnight-ish anchor, only used for relative positions
const DAY1 = DAY0 + 86400

const RANGE = {
  tz: 'Europe/Budapest',
  from: '2026-10-27',
  to: '2026-10-28',
  days: [
    {
      date: '2026-10-27', me_minutes: 95, me_segments: 3, ai_minutes: 240, ai_segments: 5,
      ai_by_agent: [{ agent: 'ezermester', minutes: 200 }, { agent: `bad${XSS}`, minutes: 60 }],
      prompts_owner: 4, prompts_agent: 2, sources: { token_usage: true, tool_call_log: true },
    },
    {
      date: '2026-10-28', me_minutes: 10, me_segments: 1, ai_minutes: 0, ai_segments: 0,
      ai_by_agent: [], prompts_owner: 1, prompts_agent: 0, sources: { token_usage: true, tool_call_log: false },
    },
  ],
}

const DETAIL = {
  date: '2026-10-27', tz: 'Europe/Budapest', day_start: DAY0, day_end: DAY1,
  me: [{ start: DAY0 + 3600, end: DAY0 + 7200 }],
  ai: [{ start: DAY0 + 3600, end: DAY0 + 10800 }, { start: DAY0 + 40000, end: DAY0 + 41000 }],
  ai_by_agent: [{ agent: 'ezermester', segments: 3 }, { agent: `bad${XSS}`, segments: 1 }],
  prompts: [
    { ts: DAY0 + 3700, kind: 'owner', agent: 'ezermester', from_agent: null, to_agent: 'ezermester' },
    { ts: DAY0 + 5000, kind: 'agent', agent: 'brainy', from_agent: 'brainy', to_agent: `x${XSS}` },
  ],
  sources: { token_usage: true, tool_call_log: true },
}

const DETAIL_NODATA = {
  date: '2026-10-28', tz: 'Europe/Budapest', day_start: DAY1, day_end: DAY1 + 86400,
  me: [], ai: [], ai_by_agent: [], prompts: [], sources: { token_usage: true, tool_call_log: false },
}

async function open(page: Page) {
  const errors: string[] = []
  const requested: string[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.route((u) => u.hostname !== '127.0.0.1', (r) => r.abort())
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
  const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/api/funkciok', (r) => r.fulfill(json({ funkciok: [] })))
  await page.route('**/api/worklog', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(RANGE)) })
  await page.route('**/api/worklog/2026-10-27', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(DETAIL)) })
  await page.route('**/api/worklog/2026-10-28', (r) => { requested.push(new URL(r.request().url()).pathname); return r.fulfill(json(DETAIL_NODATA)) })
  await page.addInitScript(() => { try { localStorage.setItem('marveen.lang', 'hu') } catch { /* ignore */ } })
  await page.goto('/index.html#dev')
  return { errors, requested }
}

test.describe('S4-C Fejlesztes > Munkanaplo', () => {
  test('sub-view is enabled and lists the days, newest first, with counts', async ({ page }) => {
    const { errors, requested } = await open(page)
    const tab = page.locator('#devTabMunkanaplo')
    await expect(tab).toBeEnabled()
    await expect(tab).not.toContainText('hamarosan')
    await tab.click()
    await expect(page.locator('#devMunkanaploView')).toBeVisible()
    await expect(page.locator('#devFunkciokView')).toBeHidden()
    const rows = page.locator('#devWorklogList .wl-day')
    await expect(rows).toHaveCount(2)
    await expect(rows.nth(0)).toHaveAttribute('data-date', '2026-10-28')
    await expect(rows.nth(1)).toContainText('Én: 95 perc')
    await expect(rows.nth(1)).toContainText('AI: 240 perc')
    await expect(rows.nth(1)).toContainText('Gyuri 4, ügynök 2')
    expect(requested).toContain('/api/worklog')
    // switching back shows the function view again
    await page.locator('#devTabFunkciok').click()
    await expect(page.locator('#devFunkciokView')).toBeVisible()
    await expect(page.locator('#devMunkanaploView')).toBeHidden()
    expect(errors).toEqual([])
  })

  test('day click: Én / AI / per-agent bars and the prompt metadata list', async ({ page }) => {
    const { errors, requested } = await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    const detail = page.locator('#devWorklogDetail')
    await expect(detail.locator('h2')).toHaveText('2026-10-27')
    await expect(detail.locator('.wl-seg-me')).toHaveCount(1)
    await expect(detail.locator('.wl-seg-ai')).toHaveCount(2)
    await expect(detail.locator('.wl-agent-row')).toHaveCount(2)
    await expect(detail.locator('.wl-agent-row').first()).toContainText('ezermester: 3 szakasz, 200 perc')
    await expect(detail.locator('.wl-dot')).toHaveCount(2)
    const prompts = detail.locator('.wl-prompt')
    await expect(prompts).toHaveCount(2)
    await expect(prompts.nth(0)).toContainText('Gyuri')
    await expect(prompts.nth(0)).toContainText('-> ezermester')
    await expect(prompts.nth(1)).toContainText('brainy ->')
    // the bar position is a percentage of the day span
    const left = await detail.locator('.wl-seg-me').evaluate((el) => (el as HTMLElement).style.left)
    expect(parseFloat(left)).toBeCloseTo((3600 / 86400) * 100, 1)
    expect(requested).toContain('/api/worklog/2026-10-27')
    expect(errors).toEqual([])
  })

  test('a day whose sources did not cover it carries the "nincs adat" marker', async ({ page }) => {
    await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await expect(page.locator('#devWorklogList .wl-day[data-date="2026-10-28"] .wl-nodata')).toContainText('nincs adat')
    await expect(page.locator('#devWorklogList .wl-day[data-date="2026-10-27"] .wl-nodata')).toHaveCount(0)
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-28"]').click()
    await expect(page.locator('#devWorklogDetail .wl-nodata-note')).toBeVisible()
  })

  test('data strings are text: an <img onerror> agent name creates no element', async ({ page }) => {
    const { errors } = await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    await expect(page.locator('#devWorklogDetail .wl-agent-row')).toHaveCount(2)
    await expect(page.locator('#devWorklogDetail')).toContainText('<img src=x onerror="window.__xss=1">')
    await expect(page.locator('#devPage img')).toHaveCount(0)
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined()
    expect(errors).toEqual([])
  })

  test('mobile 390px: no horizontal page scroll with the timeline open', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    await expect(page.locator('#devWorklogDetail h2')).toHaveText('2026-10-27')
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(0)
  })
})
