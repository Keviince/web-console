import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'

const fixturePath = process.env.WEBCONSOLE_NATIVE_BROWSER_FIXTURE
for (const kind of ['pve', 'esxi', 'tplink', 'xiaomi']) {
  test(`${kind} native page bootstrap preserves browser session boundaries`, async ({ page }) => {
    test.skip(!fixturePath, 'Generate backend fixtures with TestNativeBrowserFixtures')
    const fixtures = JSON.parse(readFileSync(fixturePath!, 'utf8')) as Record<string, string>

    if (kind === 'esxi') await page.addInitScript(() => {
      localStorage.setItem('vmware_esx_host_state', JSON.stringify({ filters: ['old-session-filter'], longpoll_version: 'old-session-version', settings: { theme: 'dark' } }))
    })
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await page.route('**/*', async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/native') await route.fulfill({ contentType: 'text/html', headers: { 'Content-Security-Policy': "script-src 'self'" }, body: '<html><head><script src="/__webconsole/native/bootstrap.js"></script></head><body>Device</body></html>' })
      else if (path === '/__webconsole/native/bootstrap.js') await route.fulfill({ contentType: 'text/javascript', body: fixtures[kind] })
      else if (path === '/__webconsole/native/logout') await route.fulfill({ status: 204 })
      else await route.abort()
    })
    await page.goto('/native')
    if (kind === 'pve') {
      expect(await page.evaluate(() => document.cookie)).toContain('PVEAuthCookie=webconsole-session')
      const logout = page.waitForRequest(r => r.url().endsWith('/__webconsole/native/logout'))
      await page.evaluate(() => { document.cookie = 'PVEAuthCookie=;path=/;expires=Thu, 01 Jan 1970 00:00:00 GMT' })
      expect((await logout).postDataJSON()).toHaveProperty('csrf')
    }
    if (kind === 'tplink') {
      expect(await page.evaluate(() => localStorage.getItem('token'))).toBe('webconsole-session')
      const logout = page.waitForRequest(r => r.url().endsWith('/__webconsole/native/logout'))
      await page.evaluate(() => localStorage.removeItem('token'))
      expect((await logout).postDataJSON()).toHaveProperty('csrf')
    }
    if (kind === 'esxi') {
      const state = await page.evaluate(() => JSON.parse(localStorage.getItem('vmware_esx_host_state')!))
      expect(state).toMatchObject({ vmware_esx_host: '127.0.0.1:5173', csrf_token: 'webconsole-session' })
      expect(state).toMatchObject({ filters: [], longpoll_version: '', settings: { theme: 'dark' } })
      expect(state.webconsoleSession).toBeTruthy()
      expect(await page.evaluate(() => document.cookie)).toContain('vmware_esx_host=127.0.0.1%3A5173')
      expect(await page.evaluate(() => document.cookie)).not.toContain('vmware_soap_session')
    }
    expect(errors).toEqual([])
  })
}

for (const [origin, host] of [
  ['https://esxi.console.example.com', 'esxi.console.example.com:443'],
  ['https://esxi.console.example.com:8443', 'esxi.console.example.com:8443'],
  ['http://esxi.console.example.com', 'esxi.console.example.com:80'],
] as const) {
  test(`ESXi supplies the Host Client port at ${origin}`, async ({ page }) => {
    test.skip(!fixturePath, 'Generate backend fixtures with TestNativeBrowserFixtures')
    const fixtures = JSON.parse(readFileSync(fixturePath!, 'utf8')) as Record<string, string>
    await page.route('**/*', async route => {
      const path = new URL(route.request().url()).pathname
      if (path === '/native') await route.fulfill({ contentType: 'text/html', body: '<html><head><script src="/__webconsole/native/bootstrap.js"></script></head><body>Device</body></html>' })
      else if (path === '/__webconsole/native/bootstrap.js') await route.fulfill({ contentType: 'text/javascript', body: fixtures.esxi })
      else await route.abort()
    })
    await page.goto(`${origin}/native`)
    const storedHost = await page.evaluate(() => JSON.parse(localStorage.getItem('vmware_esx_host_state')!).vmware_esx_host as string)
    expect(storedHost).toBe(host)
    // Match the actual Host Client's getHostAndPort -> createVimService path.
    const [hostname, port] = storedHost.split(':')
    expect(new URL(`https://${hostname}:${port}/sdk/`).port).toBe(port === '443' ? '' : port)
    expect(await page.evaluate(() => document.cookie)).toContain(`vmware_esx_host=${encodeURIComponent(host)}`)
  })
}
