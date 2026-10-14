import { test, expect } from '@playwright/test'
import { readFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { AddressInfo } from 'node:net'

const fixturePath = process.env.WEBCONSOLE_MANUAL_BROWSER_FIXTURE

test('manual fallback and the original login form retain Origin without leaking the launch ticket', async ({ page }) => {
  test.skip(!fixturePath, 'Generate backend pages with TestManualLoginOriginalForms')
  const fixture = JSON.parse(readFileSync(fixturePath!, 'utf8'))
  let origin = ''
  const submissions: { origin?: string; referer?: string; csrf?: string }[] = []
  // A real HTTP server covers the entire POST -> 303 -> GET navigation chain.
  const server = createServer(async (req, res) => {
    const path = new URL(req.url!, origin).pathname
    if (req.method === 'POST') {
      let body = ''
      for await (const chunk of req) body += chunk
      const form = new URLSearchParams(body)
      submissions.push({ origin: req.headers.origin, referer: req.headers.referer, csrf: form.get('csrf') ?? undefined })
      if (req.headers.origin !== origin) {
        res.writeHead(403).end('请求无效')
        return
      }
      if (path === '/__webconsole/manual') {
        if (form.get('csrf') !== fixture.csrf) res.writeHead(403).end('请求无效')
        else res.writeHead(303, { Location: fixture.entryPath }).end()
        return
      }
      const valid = path === fixture.entryPath && form.get('luci_username') === 'fixture-user' && form.get('luci_password') === 'fixture-password'
      res.writeHead(valid ? 200 : 403, { 'Content-Type': 'text/plain' }).end(valid ? 'Manual login complete' : 'Invalid login form')
      return
    }
    const response = path === '/__webconsole/start' ? fixture.fallback : path === fixture.entryPath ? fixture.native : null
    if (response) res.writeHead(response.status, response.headers).end(response.body)
    else res.writeHead(404).end()
  })
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve))
  origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`

  try {
    const start = new URL(fixture.startUrl)
    await page.goto(origin + start.pathname + start.search)
    await page.getByRole('button', { name: '使用原页面手动登录' }).click()
    await expect(page).toHaveURL(origin + fixture.entryPath)
    await page.locator('[name=luci_username]').fill('fixture-user')
    await page.locator('[name=luci_password]').fill('fixture-password')
    await page.getByRole('button', { name: '登录', exact: true }).click()
    await expect(page.getByText('Manual login complete')).toBeVisible()
    expect(submissions).toHaveLength(2)
    expect(submissions[0].csrf).toBe(fixture.csrf)
    for (const submission of submissions) {
      expect(submission.origin).toBe(origin)
      expect(submission.referer).toBe(origin + '/')
      expect(submission.referer).not.toContain('ticket')
    }
  } finally {
    server.closeAllConnections()
    await new Promise<void>((resolve, reject) => server.close(err => err ? reject(err) : resolve()))
  }
})
