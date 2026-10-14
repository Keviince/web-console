import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

const fixturePath = process.env.WEBCONSOLE_BLI_BROWSER_FIXTURE
test('native SPA restores account role and logs out without exposing JWT', async ({ page }) => {
  test.skip(!fixturePath, 'Generate the real bridge fixture with TestBlikvmBridgeAndBrowserFixtures')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8')) as { html: string; bootstrap: string; app: string }
  let logoutBody: unknown
  const errors: string[] = []
  page.on('pageerror', error => errors.push(error.message))
  await page.route('**/*', async route => {
    const path = new URL(route.request().url()).pathname
    if (path === '/matrix') await route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': "script-src 'self'" }, body: fixture.html })
    else if (path === '/__webconsole/blikvm/bootstrap.js') await route.fulfill({ contentType: 'text/javascript', body: fixture.bootstrap })
    else if (path === '/__webconsole/blikvm/app.js') await route.fulfill({ contentType: 'text/javascript', body: fixture.app })
    else if (path === '/assets/main.js') await route.fulfill({ contentType: 'text/javascript', body: `
      const store={account:{user:'',userRole:''},loginDialog:true,async initializeApp(){document.querySelector('#app').textContent=this.account.user+':'+this.account.userRole+':'+localStorage.getItem('token');}};
      export function useStore(){return store;}
    ` })
    else if (path === '/__webconsole/blikvm/logout') { logoutBody = route.request().postDataJSON(); await route.fulfill({ status: 204 }) }
    else await route.abort()
  })
  await page.goto('/matrix')
  await expect(page.locator('#app')).toHaveText('admin:admin:webconsole-session')
  expect(await page.evaluate(() => localStorage.getItem('token'))).toBe('webconsole-session')
  const logout = page.waitForRequest(r => r.url().endsWith('/__webconsole/blikvm/logout'))
  await page.evaluate(() => localStorage.removeItem('token'))
  await logout
  await expect.poll(() => logoutBody).toHaveProperty('csrf')
  expect(await page.evaluate(() => localStorage.getItem('token'))).toBeNull()
  expect(errors).toEqual([])
})
