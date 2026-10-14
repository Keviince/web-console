import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'

const fixturePath = process.env.WEBCONSOLE_PROXY_BROWSER_FIXTURE

test('manual proxy form and script navigation stay on the device domain', async ({ page }) => {
  test.skip(!fixturePath, 'Generate backend page with TestManualProxyOriginalLogin')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8')) as { origin: string; page: string }
  const submissions: { body: string; origin?: string }[] = []
  const escapedRequests: string[] = []
  let origin = ''
  // Use real HTTP for POST -> 302 -> GET; routed redirects vary by Chromium build.
  const server = createServer(async (req, res) => {
    const path = new URL(req.url!, origin).pathname
    if (path === '/') {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' })
      res.end(fixture.page.replaceAll(fixture.origin, origin))
    } else if (path === '/login') {
      let body = ''
      for await (const chunk of req) body += chunk
      submissions.push({ body, origin: req.headers.origin })
      if (req.method !== 'POST' || req.headers.origin !== origin) res.writeHead(403).end()
      else res.writeHead(302, { Location: origin + '/home' }).end()
    } else if (path === '/home') {
      res.writeHead(200, { 'Content-Type': 'text/html' }).end('<h1>Manual login complete</h1>')
    } else res.writeHead(404).end()
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  origin = `http://${new URL(fixture.origin).hostname}:${(server.address() as AddressInfo).port}`
  page.on('request', req => {
    if (new URL(req.url()).origin !== origin) escapedRequests.push(req.url())
  })
  try {
    await page.goto(origin + '/')
    expect(submissions).toHaveLength(0)
    await page.locator('[name=user]').fill('fixture-user')
    await page.locator('[name=password]').fill('fixture-password')
    await page.getByRole('button', { name: '登录', exact: true }).click()
    await expect(page).toHaveURL(origin + '/home')
    await expect(page.getByRole('heading', { name: 'Manual login complete' })).toBeVisible()
    expect(submissions).toEqual([{ body: 'user=fixture-user&password=fixture-password', origin }])
    await page.goto(origin + '/')
    await page.evaluate(() => (window as unknown as { enter: () => void }).enter())
    await expect(page).toHaveURL(origin + '/home')
    expect(escapedRequests).toEqual([])
  } finally {
    server.closeAllConnections()
    await new Promise<void>((resolve, reject) => server.close(err => err ? reject(err) : resolve()))
  }
})
