// S3-N4: Fejlesztes > Kerdesek. Same approach as funkciok-s1/s2: the static
// web/ folder, every /api call answered by routes, external hosts aborted
// (nothing leaves 127.0.0.1). All data is invented.
import { test, expect, type Page } from '@playwright/test'

const XSS = '<img src=x onerror="window.__xss=1">'
const TOKEN_KEY = 'marveen-dashboard-token'
const TOKEN_VALUE = 'test-token-not-a-secret'

const NOW = 1761700000

const OVERVIEW = {
  agents: [
    {
      agent_id: 'alfa', agent_running: true,
      questions: [
        { id: 11, agent_id: 'alfa', card_id: '0a0b0c0d', msg_id: null, kind: 'info', question_short: 'Elkeszult a csomag, tudomasul veszed?', status: 'open', answer_short: null, answered_via: null, answered_at: null, created_at: NOW - 3600, expires_at: NOW + 86400, source: 'agent', card_seq: 77, funkcio_slug: 'charlie-feature' },
        { id: 12, agent_id: 'alfa', card_id: null, msg_id: null, kind: 'yesno', question_short: `Mehet a kiadas? ${XSS}`, status: 'open', answer_short: null, answered_via: null, answered_at: null, created_at: NOW - 1800, expires_at: NOW + 86400, source: 'agent', card_seq: null, funkcio_slug: null },
      ],
    },
    {
      agent_id: 'beta', agent_running: false,
      questions: [
        { id: 21, agent_id: 'beta', card_id: '0a0b0c0e', msg_id: null, kind: 'free', question_short: 'Milyen nevet adjunk neki?', status: 'open', answer_short: null, answered_via: null, answered_at: null, created_at: NOW - 600, expires_at: NOW + 172800, source: 'agent', card_seq: 88, funkcio_slug: null },
      ],
    },
  ],
  pending_approvals: [
    { id: 'aa11bb22', agent_id: 'alfa', category: 'email_send', status: 'pending', requested_at: NOW - 120, link: '#approvals' },
  ],
}

const FUNKCIOK = { funkciok: [{ slug: 'charlie-feature', nev: 'Charlie feature', last_change: NOW, open_cards: 1 }] }
const FUNKCIO_PAGE = {
  slug: 'charlie-feature', nev: 'Charlie feature', leiras: 'Teszt', last_change: NOW, open_cards: 1,
  commits_without_card: 0, commits_total: 0, cards: [], cards_missing: [], messages: [], commits: [], tests: [],
  repos: [], tiltasok: [], specUtak: [], decisions: [],
}

type Post = { url: string; body: unknown; cookie: string | undefined; authorization: string | undefined }

async function open(page: Page, answer: { status: number; body: unknown } = { status: 200, body: {} }, overview: unknown = OVERVIEW) {
  const errors: string[] = []
  const posts: Post[] = []
  page.on('pageerror', (e) => errors.push(e.message))
  await page.route((u) => u.hostname !== '127.0.0.1', (r) => r.abort())
  await page.route('**/api/**', (r) => r.fulfill({ status: 200, contentType: 'application/json', body: '{}' }))
  const json = (body: unknown, status = 200) => ({ status, contentType: 'application/json', body: JSON.stringify(body) })
  await page.route('**/api/funkciok', (r) => r.fulfill(json(FUNKCIOK)))
  await page.route('**/api/funkciok/charlie-feature', (r) => r.fulfill(json(FUNKCIO_PAGE)))
  await page.route('**/api/questions/overview', (r) => r.fulfill(json(overview)))
  await page.route('**/api/questions/*/answer', (r) => {
    const req = r.request()
    const h = req.headers()
    posts.push({ url: new URL(req.url()).pathname, body: JSON.parse(req.postData() || '{}'), cookie: h['cookie'], authorization: h['authorization'] })
    return r.fulfill(json(answer.body, answer.status))
  })
  await page.context().addCookies([{ name: 'mv_session', value: 'sess-test', url: 'http://127.0.0.1:3999' }])
  await page.addInitScript(([k, v]) => {
    try { localStorage.setItem('marveen.lang', 'hu'); localStorage.setItem(k, v) } catch { /* ignore */ }
  }, [TOKEN_KEY, TOKEN_VALUE])
  await page.goto('/index.html#dev')
  await page.locator('#devTabKerdesek').click()
  await expect(page.locator('#devKerdesekView')).toBeVisible()
  return { errors, posts }
}

const row = (page: Page, id: number) => page.locator(`.dev-q-row[data-qid="${id}"]`)

test.describe('S3-N4 Fejlesztes > Kerdesek', () => {
  test('groups per agent render with run state, kind badge, text, card link and expiry', async ({ page }) => {
    const { errors } = await open(page)
    await expect(page.locator('#devTabKerdesek')).toHaveClass(/active/)
    await expect(page.locator('#devFunkciokView')).toBeHidden()
    const groups = page.locator('.dev-q-group')
    await expect(groups).toHaveCount(2)
    await expect(groups.nth(0)).toContainText('alfa')
    await expect(groups.nth(0).locator('.dev-q-run')).toHaveText('fut')
    await expect(groups.nth(0).locator('.dev-q-row')).toHaveCount(2)
    await expect(groups.nth(1)).toContainText('beta')
    await expect(groups.nth(1).locator('.dev-q-run')).toHaveText('nem fut')
    await expect(row(page, 11).locator('.dev-q-kind')).toHaveText('tájékoztatás')
    await expect(row(page, 12).locator('.dev-q-kind')).toHaveText('igen/nem')
    await expect(row(page, 21).locator('.dev-q-kind')).toHaveText('szabad szöveg')
    await expect(row(page, 11).locator('.dev-q-text')).toHaveText('Elkeszult a csomag, tudomasul veszed?')
    await expect(row(page, 11)).toContainText('Lejár:')
    // card with a function: a link; without a function: plain text; without a card: nothing
    await expect(row(page, 11).locator('a.dev-q-card')).toHaveText('#77')
    await expect(row(page, 21).locator('.dev-q-card')).toHaveText('#88')
    expect(await row(page, 21).locator('.dev-q-card').evaluate((e) => e.tagName)).toBe('SPAN')
    await expect(row(page, 12).locator('.dev-q-card')).toHaveCount(0)
    expect(errors).toEqual([])
  })

  test('the card link opens the function page', async ({ page }) => {
    await open(page)
    await row(page, 11).locator('a.dev-q-card').click()
    await expect(page.locator('#devFunkciokView')).toBeVisible()
    await expect(page.locator('#devFunkcioDetail h2')).toHaveText('Charlie feature')
  })

  test('info: Tudomasul vettem posts {answer:ack}, the row shows the result', async ({ page }) => {
    const { posts, errors } = await open(page, { status: 200, body: { id: 11, status: 'ack', kind: 'info' } })
    await row(page, 11).getByRole('button', { name: 'Tudomásul vettem' }).click()
    await expect(row(page, 11).locator('.dev-q-result')).toHaveText('Tudomásul véve')
    await expect(row(page, 11).locator('button')).toHaveCount(0)
    expect(posts.length).toBe(1)
    expect(posts[0].url).toBe('/api/questions/11/answer')
    expect(posts[0].body).toEqual({ answer: 'ack' })
    expect(errors).toEqual([])
  })

  test('yesno: Igen and Nem post yes and no', async ({ page }) => {
    const { posts } = await open(page, { status: 200, body: { id: 12, status: 'yes', kind: 'yesno' } })
    await row(page, 12).getByRole('button', { name: 'Igen' }).click()
    await expect(row(page, 12).locator('.dev-q-result')).toHaveText('Válasz: Igen')
    expect(posts[0].body).toEqual({ answer: 'yes' })
    await page.unrouteAll({ behavior: 'ignoreErrors' })
    const second = await open(page, { status: 200, body: { id: 12, status: 'no', kind: 'yesno' } })
    await row(page, 12).getByRole('button', { name: 'Nem' }).click()
    await expect(row(page, 12).locator('.dev-q-result')).toHaveText('Válasz: Nem')
    expect(second.posts[0].body).toEqual({ answer: 'no' })
  })

  test('free: live code-point counter, 1000 accepted, 1001 and empty blocked, body {answer:text,text}', async ({ page }) => {
    const { posts } = await open(page, { status: 200, body: { id: 21, status: 'answered', kind: 'free', answer_short: 'Piri' } })
    const r = row(page, 21)
    const area = r.locator('textarea')
    const send = r.getByRole('button', { name: 'Válasz küldése' })
    await expect(send).toBeDisabled()
    await expect(r.locator('.dev-q-counter')).toHaveText('0/1000')
    await area.fill('😀'.repeat(1000))
    await expect(r.locator('.dev-q-counter')).toHaveText('1000/1000')
    await expect(send).toBeEnabled()
    await area.fill('a'.repeat(1001))
    await expect(r.locator('.dev-q-counter')).toHaveText('1001/1000')
    await expect(send).toBeDisabled()
    await area.fill('   ')
    await expect(send).toBeDisabled()
    await area.fill('  Piri  ')
    await expect(r.locator('.dev-q-counter')).toHaveText('4/1000')
    await send.click()
    await expect(r.locator('.dev-q-result')).toHaveText('Válasz: Piri')
    expect(posts.length).toBe(1)
    expect(posts[0].url).toBe('/api/questions/21/answer')
    expect(posts[0].body).toEqual({ answer: 'text', text: 'Piri' })
  })

  test('the answer request carries the session cookie next to the stored token', async ({ page }) => {
    const { posts } = await open(page, { status: 200, body: { id: 11, status: 'ack' } })
    await row(page, 11).getByRole('button', { name: 'Tudomásul vettem' }).click()
    await expect.poll(() => posts.length).toBe(1)
    expect(posts[0].cookie).toContain('mv_session=sess-test')
    expect(posts[0].authorization).toBe('Bearer ' + TOKEN_VALUE)
  })

  test('403 owner_session_required: translated login hint, stored token stays, controls usable again', async ({ page }) => {
    const { posts } = await open(page, { status: 403, body: { error: 'RAW SERVER TEXT', code: 'owner_session_required' } })
    await row(page, 12).getByRole('button', { name: 'Igen' }).click()
    const msg = row(page, 12).locator('.dev-q-msg')
    await expect(msg).toBeVisible()
    await expect(msg).toContainText('Jelentkezz be a dashboardra a válaszhoz')
    await expect(msg).not.toContainText('RAW SERVER TEXT')
    expect(await page.evaluate((k) => localStorage.getItem(k), TOKEN_KEY)).toBe(TOKEN_VALUE)
    await expect(row(page, 12).getByRole('button', { name: 'Igen' })).toBeEnabled()
    expect(posts.length).toBe(1)
  })

  test('a plain 403 (no code) shows the generic text, not the login hint', async ({ page }) => {
    await open(page, { status: 403, body: { error: 'Forbidden for this credential' } })
    await row(page, 11).getByRole('button', { name: 'Tudomásul vettem' }).click()
    const msg = row(page, 11).locator('.dev-q-msg')
    await expect(msg).toContainText('nincs jogosultság')
    await expect(msg).not.toContainText('Jelentkezz be')
  })

  test('409 and 410 are translated and settle the row', async ({ page }) => {
    for (const [status, text] of [[409, 'Már megválaszolva'], [410, 'A kérdés lejárt']] as const) {
      await open(page, { status, body: { error: 'RAW SERVER TEXT' } })
      await row(page, 11).getByRole('button', { name: 'Tudomásul vettem' }).click()
      const msg = row(page, 11).locator('.dev-q-msg')
      await expect(msg).toContainText(text)
      await expect(msg).not.toContainText('RAW SERVER TEXT')
      await expect(row(page, 11).locator('button')).toHaveCount(0)
      await page.unrouteAll({ behavior: 'ignoreErrors' })
    }
  })

  test('the approvals block lists pending items read-only: no button, link to the approvals page', async ({ page }) => {
    await open(page)
    const block = page.locator('.dev-q-approvals')
    await expect(block.locator('h3')).toContainText('Jóváhagyásra vár')
    await expect(block.locator('.dev-q-approval')).toHaveCount(1)
    await expect(block.locator('.dev-q-approval')).toContainText('email_send')
    await expect(block.locator('.dev-q-approval')).toContainText('függőben')
    await expect(block.locator('button, input, textarea, select')).toHaveCount(0)
    await expect(block.locator('a.dev-q-approvals-link')).toHaveAttribute('href', '#approvals')
    await block.locator('a.dev-q-approvals-link').click()
    await expect(page.locator('#approvalsPage')).toBeVisible()
  })

  test('an XSS payload in a question renders as text only', async ({ page }) => {
    const { errors } = await open(page)
    await expect(row(page, 12).locator('.dev-q-text')).toContainText(XSS)
    await expect(page.locator('#devPage img')).toHaveCount(0)
    expect(await page.evaluate(() => (window as unknown as { __xss?: number }).__xss)).toBeUndefined()
    expect(errors).toEqual([])
  })

  test('an empty overview shows the empty text and the (empty) approvals block', async ({ page }) => {
    await open(page, undefined, { agents: [], pending_approvals: [] })
    await expect(page.locator('.dev-q-empty')).toHaveText('Nincs nyitott kérdés.')
    await expect(page.locator('.dev-q-approvals')).toContainText('Nincs függő jóváhagyás.')
  })

  test('mobile 390px: no horizontal page scroll, with an open free-text row', async ({ page }) => {
    await page.setViewportSize({ width: 390, height: 800 })
    await open(page)
    await row(page, 21).locator('textarea').fill('x'.repeat(900))
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth)
    expect(overflow).toBeLessThanOrEqual(0)
    const box = await row(page, 21).boundingBox()
    expect(box && box.x + box.width).toBeLessThanOrEqual(390)
  })

  test('S3-R1: a stopped agent\'s question shows the delivery warning before answering; a running agent\'s does not', async ({ page }) => {
    const { errors } = await open(page)
    await expect(row(page, 21).locator('.dev-q-warn')).toHaveText(/Az ügynök most nem fut; a válasz 60 percig vár a kézbesítésre/)
    await expect(row(page, 21).locator('.dev-q-warn')).toBeVisible()
    await expect(row(page, 11).locator('.dev-q-warn')).toHaveCount(0)
    await expect(row(page, 12).locator('.dev-q-warn')).toHaveCount(0)
    // the warning sits ahead of the controls
    const order = await row(page, 21).evaluate((r) => Array.from(r.children).map((c) => c.className.split(' ').find((k) => k === 'dev-q-warn' || k === 'dev-q-controls') || '').filter(Boolean))
    expect(order).toEqual(['dev-q-warn', 'dev-q-controls'])
    expect(errors).toEqual([])
  })

  test('S3-B1: 403 owner_login_required shows the translated "no dashboard user yet" hint', async ({ page }) => {
    await open(page, { status: 403, body: { error: 'RAW SERVER TEXT', code: 'owner_login_required' } })
    await row(page, 12).getByRole('button', { name: 'Igen' }).click()
    const msg = row(page, 12).locator('.dev-q-msg')
    await expect(msg).toContainText('Még nincs dashboard-felhasználó')
    await expect(msg).not.toContainText('RAW SERVER TEXT')
    await expect(msg).not.toContainText('nincs jogosultság')
    expect(await page.evaluate((k) => localStorage.getItem(k), TOKEN_KEY)).toBe(TOKEN_VALUE)
  })

  test('S3-R4: truncated flags show a note for the questions and for the approvals; absent flags show none', async ({ page }) => {
    await open(page, undefined, { ...OVERVIEW, questions_truncated: true, approvals_truncated: true })
    await expect(page.locator('.dev-q-trunc')).toContainText('Csak az első 3 kérdés látszik')
    await expect(page.locator('.dev-q-approvals-trunc')).toContainText('Csak a legfrissebb 1 jóváhagyás látszik')
    await page.unrouteAll({ behavior: 'ignoreErrors' })
    await open(page)
    await expect(page.locator('.dev-q-trunc')).toHaveCount(0)
    await expect(page.locator('.dev-q-approvals-trunc')).toHaveCount(0)
  })

  test('the Funkciok tab switches back', async ({ page }) => {
    await open(page)
    await page.locator('#devTabFunkciok').click()
    await expect(page.locator('#devFunkciokView')).toBeVisible()
    await expect(page.locator('#devKerdesekView')).toBeHidden()
  })
})
