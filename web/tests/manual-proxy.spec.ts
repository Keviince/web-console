import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

const fixturePath = process.env.WEBCONSOLE_PROXY_BROWSER_FIXTURE

test('manual proxy form and script navigation stay on the device domain', async ({ page }) => {
  test.skip(!fixturePath, 'Generate backend page with TestManualProxyOriginalLogin')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8')) as { origin: string; page: string }
  const submissions: string[] = []
  const escapedRequests: string[] = []
  await page.route('**/*', route => {
    const req = route.request()
    const url = new URL(req.url())
    if (url.origin !== fixture.origin) {
      escapedRequests.push(req.url())
      return route.abort()
    }
    if (url.pathname === '/') return route.fulfill({ contentType: 'text/html; charset=utf-8', body: fixture.page })
    if (url.pathname === '/login') {
      submissions.push(req.postData() ?? '')
      expect(req.headers().origin).toBe(fixture.origin)
      return route.fulfill({ status: 302, headers: { Location: fixture.origin + '/home' } })
    }
    return route.fulfill({ contentType: 'text/html', body: '<h1>Manual login complete</h1>' })
  })
  await page.goto(fixture.origin + '/')
  expect(submissions).toHaveLength(0)
  await page.locator('[name=user]').fill('fixture-user')
  await page.locator('[name=password]').fill('fixture-password')
  await page.getByRole('button', { name: '登录', exact: true }).click()
  await expect(page).toHaveURL(fixture.origin + '/home')
  expect(submissions).toEqual(['user=fixture-user&password=fixture-password'])
  await page.goto(fixture.origin + '/')
  await page.evaluate(() => (window as unknown as { enter: () => void }).enter())
  await expect(page).toHaveURL(fixture.origin + '/home')
  expect(escapedRequests).toEqual([])
})
