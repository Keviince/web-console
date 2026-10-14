import { test, expect } from '@playwright/test'

test('TP-Link devices share the SLP dropdown and preserve the protocol when saved', async ({ page }) => {
  let saved: unknown
  await page.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path === '/api/me') return route.fulfill({ json: { name: 'Kevin', csrfToken: 'test-csrf', deviceDomain: 'console.example.com' } })
    if (request.method() === 'POST') {
      saved = request.postDataJSON()
      return route.fulfill({ json: { ...saved as object, id: 'tplink', hasCredentials: true } })
    }
    return route.fulfill({ json: [] })
  })
  await page.goto('/')
  await page.getByRole('button', { name: '添加设备', exact: true }).click()
  await page.getByRole('dialog').getByRole('button', { name: 'TP-Link', exact: true }).click()
  const protocol = page.getByLabel('TP-Link 快速登录协议')
  await expect(protocol).toHaveValue('slp')
  await expect(protocol.locator('option')).toHaveCount(1)
  await expect(page.getByRole('dialog')).toContainText('TL-R479G+、TL-ER3229G、TL-AC200')
  await page.getByLabel('设备名称').fill('TP-Link ER3229G')
  await page.getByLabel('设备内网地址').fill('http://192.168.1.2/login.htm')
  await page.getByLabel('访问子域名').fill('er3229g')
  await page.getByLabel('账号', { exact: true }).fill('admin')
  await page.getByLabel('密码', { exact: true }).fill('fixture-password')
  await page.getByRole('button', { name: '保存设备' }).click()
  expect(saved).toMatchObject({ type: 'tplink', tplinkProtocol: 'slp', upstreamUrl: 'http://192.168.1.2/login.htm' })
})
