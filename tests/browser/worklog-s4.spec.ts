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

  test('S4-M1: heatmap has one labelled cell per day with 5 levels; segment counts are listed', async ({ page }) => {
    const { errors } = await open(page)
    await page.locator('#devTabMunkanaplo').click()
    const cells = page.locator('#devWorklogList .wl-heat .wl-heat-cell')
    await expect(cells).toHaveCount(2)
    await expect(cells.nth(0)).toHaveAttribute('data-date', '2026-10-27')
    await expect(cells.nth(0)).toHaveAttribute('aria-label', '2026-10-27: 95 perc')
    await expect(cells.nth(0)).toHaveClass(/wl-heat-3/)
    await expect(cells.nth(1)).toHaveAttribute('aria-label', '2026-10-28: 10 perc')
    await expect(cells.nth(1)).toHaveClass(/wl-heat-1/)
    await expect(page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]')).toContainText('Szakaszok: én 3, AI 5')
    expect(errors).toEqual([])
  })

  test('S4-M1: only the last 30 days get a heatmap cell, levels 0 and 4 exist', async ({ page }) => {
    const days = Array.from({ length: 35 }, (_, i) => ({
      date: new Date(Date.UTC(2026, 8, 1 + i)).toISOString().slice(0, 10),
      me_minutes: i === 34 ? 600 : i === 33 ? 0 : 5, me_segments: 0, ai_minutes: 0, ai_segments: 0,
      ai_by_agent: [], prompts_owner: 0, prompts_agent: 0, sources: { token_usage: true, tool_call_log: true },
    }))
    await open(page)
    await page.route('**/api/worklog', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...RANGE, days }) }))
    await page.locator('#devTabMunkanaplo').click()
    const cells = page.locator('#devWorklogList .wl-heat .wl-heat-cell')
    await expect(cells).toHaveCount(30)
    await expect(cells.last()).toHaveClass(/wl-heat-4/)
    await expect(cells.nth(28)).toHaveClass(/wl-heat-0/)
  })

  test('S4-M2: per-agent minutes sit in their own labelled block, not in the 24 h timeline', async ({ page }) => {
    await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    const detail = page.locator('#devWorklogDetail')
    await expect(detail.locator('.wl-agent-block h3')).toHaveText('Percek ügynökönként')
    await expect(detail.locator('.wl-agent-block .wl-agent-row')).toHaveCount(2)
    await expect(detail.locator('section.dev-block').first().locator('.wl-agent-row')).toHaveCount(0)
    await expect(detail.locator('section.dev-block').first().locator('.wl-seg-agent')).toHaveCount(0)
  })

  test('S4-M3: a truncated prompt list shows the translated note, a normal one does not', async ({ page }) => {
    await open(page)
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    await expect(page.locator('#devWorklogDetail h2')).toHaveText('2026-10-27')
    await expect(page.locator('#devWorklogDetail .wl-truncated-note')).toHaveCount(0)
    await page.route('**/api/worklog/2026-10-27', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify({ ...DETAIL, truncated: true }) }))
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-28"]').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-27"]').click()
    await expect(page.locator('#devWorklogDetail .wl-truncated-note')).toContainText('Csak az első 2 prompt látszik')
  })

  test('S4-N3: a 25 h DST day (2026-10-25) positions the bars against its real length', async ({ page }) => {
    const D = 1792881600 // arbitrary anchor, only the 25 h span matters
    const dst = {
      date: '2026-10-25', tz: 'Europe/Budapest', day_start: D, day_end: D + 25 * 3600,
      me: [{ start: D + 13 * 3600, end: D + 14 * 3600 }], ai: [{ start: D + 24 * 3600, end: D + 25 * 3600 }],
      ai_by_agent: [], prompts: [], sources: { token_usage: true, tool_call_log: true },
    }
    const range = { ...RANGE, days: [{ ...RANGE.days[0], date: '2026-10-25' }] }
    await open(page)
    await page.route('**/api/worklog', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(range) }))
    await page.route('**/api/worklog/2026-10-25', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: JSON.stringify(dst) }))
    await page.locator('#devTabMunkanaplo').click()
    await page.locator('#devWorklogList .wl-day[data-date="2026-10-25"]').click()
    const me = page.locator('#devWorklogDetail .wl-seg-me')
    await expect(me).toHaveCount(1)
    const st = await me.evaluate((el) => ({ left: (el as HTMLElement).style.left, width: (el as HTMLElement).style.width }))
    expect(parseFloat(st.left)).toBeCloseTo((13 / 25) * 100, 2)
    expect(parseFloat(st.width)).toBeCloseTo((1 / 25) * 100, 2)
    const ai = await page.locator('#devWorklogDetail .wl-seg-ai').evaluate((el) => (el as HTMLElement).style.left)
    expect(parseFloat(ai)).toBeCloseTo((24 / 25) * 100, 2)
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
