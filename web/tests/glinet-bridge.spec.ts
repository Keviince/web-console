import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

const fixturePath = process.env.WEBCONSOLE_GL_BROWSER_FIXTURE

test('GLKVM native router opens the desktop with a gateway auth marker', async ({ page }) => {
  test.skip(!fixturePath, 'Generate with TestGlinetBridgeBrowserFixture')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8')) as { html: string; bootstrap: string }
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/*', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/') await route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': "script-src 'self'" }, body: fixture.html })
    else if (path === '/__webconsole/native/bootstrap.js') await route.fulfill({ contentType: 'text/javascript', body: fixture.bootstrap })
    else if (path === '/assets/main.js') await route.fulfill({ contentType: 'text/javascript', body: `
      const token = JSON.parse(localStorage.getItem('gl-kvm-token-keys') || '{}').glkvm;
      const response = await fetch('/api/auth/check', {headers: {token}});
      const status = await response.json();
      if (status.ok) document.querySelector('#app').textContent = 'GLKVM desktop';
      else location.hash = '/login';
    ` })
    else if (path === '/api/auth/check') {
      expect(route.request().headers().token).toBe('webconsole-session')
      await route.fulfill({ json: { ok: true, result: {} } })
    } else await route.abort()
  })
  await page.goto('/#/')
  await expect(page.locator('#app')).toHaveText('GLKVM desktop')
  await expect(page).toHaveURL(/\/#\/$/)
  expect(await page.evaluate(() => localStorage.getItem('gl-kvm-token-key'))).toBe('webconsole-session')
  await page.reload()
  await expect(page.locator('#app')).toHaveText('GLKVM desktop')
  expect(errors).toEqual([])
})
