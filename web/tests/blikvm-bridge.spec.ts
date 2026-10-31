import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

const fixturePath = process.env.WEBCONSOLE_BLI_BROWSER_FIXTURE
test('BliKVM 3 native page restores viewer permissions and logs out without browser tokens', async ({ page, context }) => {
  test.skip(!fixturePath, 'Generate the native fixture with TestBlikvmNativePageAndBrowserFixtures')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8')) as { html: string; module: string; me: string }
  let loggedOut = false
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/*', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/') await route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': "script-src 'self'" }, body: fixture.html })
    else if (path === '/assets/main.js') await route.fulfill({ contentType: 'text/javascript', body: fixture.module })
    else if (path === '/api/v1/auth/me') await route.fulfill({ status: loggedOut ? 401 : 200, contentType: 'application/json', body: loggedOut ? '{"ok":false,"error":"missing token"}' : fixture.me })
    else if (path === '/api/v1/auth/logout') {
      expect(route.request().method()).toBe('POST')
      loggedOut = true
      await route.fulfill({ contentType: 'application/json', body: '{"ok":true}' })
    } else await route.abort()
  })
  await page.goto('/')
  await expect(page.locator('#app')).toContainText('admin:viewer:kvm.view')
  expect(await page.evaluate(() => localStorage.getItem('token'))).toBeNull()
  expect((await context.cookies()).some(cookie => cookie.name === 'blikvm_session')).toBe(false)
  await page.getByRole('button', { name: 'Logout' }).click()
  await expect(page.locator('#app')).toHaveText('Login')
  expect(loggedOut).toBe(true)
  expect(errors).toEqual([])
})
