import { useEffect, useRef, useState, type FormEvent } from 'react'
import { Activity, ArrowUpRight, Check, ChevronRight, CircleHelp, CircuitBoard, Folder, Globe, LayoutGrid, Link2, LoaderCircle, LockKeyhole, LogOut, Monitor, MoreHorizontal, Network, Plus, Search, Server, Settings2, ShieldCheck, X } from 'lucide-react'

type Kind = 'pikvm' | 'nanokvm' | 'blikvm' | 'glinet' | 'openwrt' | 'pve' | 'esxi' | 'tplink' | 'xiaomi' | 'proxy' | 'link'
type Service = { id: string; name: string; slug: string; type: Kind; upstreamUrl: string; entryPath: string; group: string; notes: string; trustedCa?: string; certificatePin?: string; ignoreCertificateTime?: boolean; hasCredentials: boolean; tplinkProtocol?: 'slp' }
type Me = { name: string; csrfToken: string; deviceDomain: string }
type Notice = { text: string; error?: boolean }
const labels = { pikvm: 'PiKVM', nanokvm: 'NanoKVM', blikvm: 'BliKVM', glinet: 'GL.iNet KVM', openwrt: 'OpenWrt', pve: 'PVE', esxi: 'ESXi', tplink: 'TP-Link', xiaomi: '小米路由器', proxy: '手动登录代理', link: '普通链接' }
const storesCredentials = (type: Kind) => type !== 'link' && type !== 'proxy'
const empty: Service = { id: '', name: '', slug: '', type: 'pikvm', upstreamUrl: '', entryPath: '', group: '', notes: '', hasCredentials: false }

export default function App() {
  const [me, setMe] = useState<Me | null>(null)
  const [ready, setReady] = useState(false)
  const [services, setServices] = useState<Service[]>([])
  const [search, setSearch] = useState('')
  const [group, setGroup] = useState('全部设备')
  const [kind, setKind] = useState('all')
  const [editing, setEditing] = useState<Service | null>(null)
  const [notice, setNotice] = useState<Notice | null>(null)
  const [busy, setBusy] = useState<string | null>(null)
  const [tested, setTested] = useState<Record<string, boolean>>({})
  const [menu, setMenu] = useState<string | null>(null)
  const [deleting, setDeleting] = useState<Service | null>(null)
  const [help, setHelp] = useState(false)

  async function api<T>(path: string, method = 'GET', body?: unknown): Promise<T> {
    const response = await fetch(path, { method, credentials: 'same-origin', headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(method !== 'GET' ? { 'X-CSRF-Token': me?.csrfToken ?? '' } : {}) }, body: body === undefined ? undefined : JSON.stringify(body) })
    if (response.status === 401) { setMe(null); setServices([]); throw new Error('登录已过期，请重新登录 Authentik') }
    const result = await response.json()
    if (!response.ok) throw new Error(result.error || '请求失败，请稍后重试')
    return result as T
  }
  async function load() { setServices(await api<Service[]>('/api/services')) }
  useEffect(() => {
    let cancelled = false
    fetch('/api/me').then(async r => {
      if (r.status === 401) return
      if (!r.ok) throw new Error('无法连接门户服务')
      const user = await r.json() as Me
      const response = await fetch('/api/services')
      if (!response.ok) throw new Error('无法读取设备列表')
      const devices = await response.json() as Service[]
      if (!cancelled) { setMe(user); setServices(devices) }
    }).catch(e => { if (!cancelled) setNotice({ text: e.message, error: true }) }).finally(() => { if (!cancelled) setReady(true) })
    return () => { cancelled = true }
  }, [])
  useEffect(() => { if (!notice) return; const timer = setTimeout(() => setNotice(null), 6500); return () => clearTimeout(timer) }, [notice])
  useEffect(() => { if (!menu) return; const dismiss = () => setMenu(null); window.addEventListener('click', dismiss); return () => window.removeEventListener('click', dismiss) }, [menu])

  async function openDevice(service: Service) {
    // Open synchronously in the user's gesture so browsers do not block the new tab.
    const tab = window.open('about:blank', '_blank')
    if (!tab) { setNotice({ text: '浏览器阻止了新标签页，请允许此网站打开弹出窗口', error: true }); return }
    tab.opener = null
    setBusy(service.id + ':open')
    try { const result = await api<{ url: string }>(`/api/services/${service.id}/launch`, 'POST'); tab.location.replace(result.url) }
    catch (e) { tab.close(); setNotice({ text: (e as Error).message, error: true }) }
    finally { setBusy(null) }
  }
  async function testDevice(service: Service) {
    setMenu(null); setBusy(service.id + ':test')
    try { const result = await api<{ message: string }>(`/api/services/${service.id}/test`, 'POST'); setTested(t => ({ ...t, [service.id]: true })); setNotice({ text: `${service.name}：${result.message}` }) }
    catch (e) { setTested(t => ({ ...t, [service.id]: false })); setNotice({ text: (e as Error).message, error: true }) }
    finally { setBusy(null) }
  }
  async function deleteDevice(service: Service) {
    setBusy(service.id + ':delete')
    try { await api(`/api/services/${service.id}`, 'DELETE'); await load(); setDeleting(null); setNotice({ text: '设备已移除' }) }
    catch (e) { setNotice({ text: (e as Error).message, error: true }) }
    finally { setBusy(null) }
  }
  async function logout() { try { await api('/api/logout', 'POST'); setMe(null); setServices([]) } catch (e) { setNotice({ text: (e as Error).message, error: true }) } }
  const groups = [...new Set(services.map(s => s.group).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'))
  const filtered = services.filter(s => (group === '全部设备' || (group === '未分组' ? !s.group : s.group === group)) && (kind === 'all' || s.type === kind) && `${s.name} ${s.group} ${s.upstreamUrl} ${s.notes}`.toLowerCase().includes(search.toLowerCase())).sort((a, b) => a.name.localeCompare(b.name, 'zh-CN'))
  const automatic = services.filter(s => storesCredentials(s.type) && s.hasCredentials).length

  if (!ready) return <div className="loading"><LoaderCircle className="spin" /><span>正在连接工作台…</span></div>
  if (!me) return <div className="login-page"><div className="login-grid" /><main className="login-card"><Brand /><div className="login-icon"><ShieldCheck size={36} /></div><div className="eyebrow">YOUR INFRASTRUCTURE, ONE PLACE</div><h1>所有设备，一个入口。</h1><p>连接你的管理后台，让每次访问更简单。<br />使用 Authentik 登录设备工作台。</p><a className="button primary login-button" href="/auth/login"><LockKeyhole size={17} />使用 Authentik 登录<ArrowUpRight size={17} /></a><div className="login-foot"><ShieldCheck size={14} />你的设备仍使用原有认证</div></main>{notice && <Toast notice={notice} close={() => setNotice(null)} />}</div>

  return <div className="app-shell">
    <aside className="sidebar"><Brand /><div className="workspace"><span className="workspace-icon"><Network size={19} /></span><div><strong>个人工作空间</strong><small>设备管理门户</small></div><span className="status-dot" /></div><div className="nav-label">工作台</div><button className={`nav-item ${group === '全部设备' ? 'active' : ''}`} onClick={() => setGroup('全部设备')}><LayoutGrid size={18} />全部设备<span className="nav-count">{services.length}</span></button><div className="nav-label group-label">设备分组<span>{groups.length}</span></div>{groups.map(g => <button className={`nav-item ${group === g ? 'active' : ''}`} key={g} onClick={() => setGroup(g)}><Folder size={17} />{g}<span className="nav-count">{services.filter(s => s.group === g).length}</span></button>)}{services.some(s => !s.group) && <button className={`nav-item ${group === '未分组' ? 'active' : ''}`} onClick={() => setGroup('未分组')}><Folder size={17} />未分组</button>}<div className="sidebar-bottom"><div className="security-note"><ShieldCheck size={20} /><div><strong>统一身份认证</strong><small>通过 Authentik 连接</small></div></div><button className="nav-item" onClick={() => setHelp(true)}><CircleHelp size={17} />使用说明<ArrowUpRight size={14} /></button><div className="user-row"><div className="avatar">{me.name.slice(0, 1).toUpperCase()}</div><div><strong>{me.name}</strong><small>个人管理员</small></div><button className="icon-button" aria-label="退出登录" title="退出登录" onClick={logout}><LogOut size={17} /></button></div></div></aside>
    <div className="main-shell"><header className="topbar"><div><span>工作空间</span><ChevronRight size={14} /><strong>设备工作台</strong></div><div className="topbar-right"><button className="icon-button mobile-logout" aria-label="退出登录" title="退出登录" onClick={logout}><LogOut size={17} /></button><span className="auth-badge"><ShieldCheck size={14} />Authentik 已连接</span><button className="icon-button" aria-label="使用说明" onClick={() => setHelp(true)}><CircleHelp size={19} /></button></div></header><main className="content"><div className="page-title"><div><div className="eyebrow">DEVICE WORKSPACE</div><h1>你的设备工作台<span className="title-dot">.</span></h1><p>集中管理，轻松进入每一个后台。</p></div><button className="button primary" onClick={() => setEditing({ ...empty })}><Plus size={18} />添加设备</button></div>
      <section className="stats" aria-label="设备统计"><Stat icon={<Server size={20} />} label="已接入设备" value={services.length} detail="你的所有管理入口" /><Stat icon={<LockKeyhole size={20} />} label="自动登录已配置" value={automatic} detail="已保存设备登录凭据" /><Stat icon={<Folder size={20} />} label="设备分组" value={groups.length} detail="让设备井然有序" /></section>
      <section className="devices-section"><div className="section-heading"><div><h2>{group}<span>{filtered.length}</span></h2><p>点击进入原管理后台，在独立标签页中打开。</p></div><div className="view-label"><LayoutGrid size={15} />卡片视图</div></div><div className="toolbar"><select className="mobile-groups" aria-label="筛选分组" value={group} onChange={e => setGroup(e.target.value)}><option value="全部设备">全部设备</option>{groups.map(g => <option value={g} key={g}>{g}</option>)}{services.some(s => !s.group) && <option value="未分组">未分组</option>}</select><div className="type-tabs" role="group" aria-label="设备类型"><button className={kind === 'all' ? 'selected' : ''} onClick={() => setKind('all')}>全部</button>{(Object.keys(labels) as Kind[]).map(k => <button key={k} className={kind === k ? 'selected' : ''} onClick={() => setKind(k)}>{labels[k]}</button>)}</div><label className="search-box"><Search size={17} /><input aria-label="搜索设备" placeholder="搜索设备、地址或分组…" value={search} onChange={e => setSearch(e.target.value)} />{search && <button className="icon-button" aria-label="清除搜索" onClick={() => setSearch('')}><X size={14} /></button>}</label></div>
      <div className="device-grid">{filtered.map(s => <article className="device-card" key={s.id}><div className="card-top"><div className={`device-icon ${s.type}`}><DeviceIcon type={s.type} /></div><div className="card-menu"><button className="icon-button" aria-label={`管理 ${s.name}`} onClick={e => { e.stopPropagation(); setMenu(menu === s.id ? null : s.id) }}><MoreHorizontal size={20} /></button>{menu === s.id && <div className="dropdown" onClick={e => e.stopPropagation()}><button onClick={() => { setEditing(s); setMenu(null) }}><Settings2 size={14} />编辑设备</button>{s.type !== 'link' && <button disabled={!!busy} onClick={() => testDevice(s)}><Activity size={14} />测试连接</button>}<button className="danger-text" onClick={() => { setDeleting(s); setMenu(null) }}><X size={14} />移除设备</button></div>}</div></div><div className="card-description"><div className="device-type">{labels[s.type]}<span> / {s.group || '未分组'}</span></div><h3>{s.name}</h3><div className="device-address"><Globe size={12} /><span>{s.upstreamUrl}</span></div><p>{s.notes || (s.type === 'pikvm' || s.type === 'nanokvm' || s.type === 'blikvm' ? '远程画面与键鼠控制' : s.type === 'pve' || s.type === 'esxi' ? '虚拟机与主机管理' : s.type === 'openwrt' || s.type === 'tplink' || s.type === 'xiaomi' ? '网络与路由配置管理' : '在浏览器中访问此服务')}</p></div><div className="card-status">{busy === s.id + ':test' ? <><LoaderCircle size={13} className="spin" />正在测试连接</> : tested[s.id] === false ? <span className="failed"><span className="status-dot" />最近测试失败</span> : tested[s.id] === true ? <><span className="status-dot" />最近测试通过</> : s.type === 'proxy' ? <><ShieldCheck size={13} />代理访问 · 手动登录</> : s.type === 'link' ? <><Link2 size={13} />直接打开原地址</> : s.hasCredentials ? <><LockKeyhole size={13} />自动登录已配置</> : <span className="needs-setup"><LockKeyhole size={13} />待配置登录凭据</span>}</div><button className="open-button" disabled={!!busy} onClick={() => openDevice(s)}>{busy === s.id + ':open' ? <LoaderCircle size={15} className="spin" /> : <span>进入管理后台</span>}<ArrowUpRight size={17} /></button></article>)}{!search && kind === 'all' && <button className="add-card" onClick={() => setEditing({ ...empty, group: group === '全部设备' || group === '未分组' ? '' : group })}><span><Plus size={24} /></span><strong>接入新设备</strong><small>把下一个管理入口放在这里</small></button>}</div>{filtered.length === 0 && (search || kind !== 'all') && <div className="empty-results"><Search size={27} /><h3>没有找到匹配的设备</h3><p>试试其他关键词或设备类型。</p><button className="button secondary" onClick={() => { setSearch(''); setKind('all') }}>清除筛选</button></div>}</section><footer className="content-footer"><span><ShieldCheck size={14} />设备凭据加密保存</span><span>web-console <span className="footer-divider">/</span> 你的基础设施工作台</span></footer></main></div>
    {editing && <Editor service={editing} domain={me.deviceDomain} groups={groups} busy={busy === 'save'} close={() => setEditing(null)} save={async (service, username, password) => { setBusy('save'); try { const payload = { ...service, ...(storesCredentials(service.type) && (username || password) ? { credentials: { username, password } } : {}) }; const saved = await api<Service>(service.id ? `/api/services/${service.id}` : '/api/services', service.id ? 'PUT' : 'POST', payload); await load(); setTested(t => { const next = { ...t }; delete next[saved.id]; return next }); setEditing(null); setNotice({ text: service.id ? '设备配置已更新，请重新打开设备标签页' : '设备已接入工作台' }) } catch (e) { await load().catch(() => {}); throw e } finally { setBusy(null) } }} />}
    {deleting && <Modal title="移除设备" close={() => setDeleting(null)}><p className="modal-text">将从门户移除「{deleting.name}」，并撤销相关代理会话。设备本身的配置不受影响。</p><div className="modal-actions"><button className="button secondary" onClick={() => setDeleting(null)}>取消</button><button className="button danger" disabled={!!busy} onClick={() => deleteDevice(deleting)}>移除设备</button></div></Modal>}
    {help && <Modal title="使用你的设备工作台" close={() => setHelp(false)}><div className="help-content"><h3>1. 接入设备</h3><p>选择设备类型，支持 KVM、OpenWrt、PVE、ESXi、TP-Link 和小米路由器。其他后台可选择手动登录代理，通过子域名访问并自行登录；普通链接直接打开填写的地址。代理设备使用独立子域名，DNS 与反向代理需指向 web-console。</p><h3>2. 配置自动登录</h3><p>输入设备原有账号密码，保存后使用「测试连接」验证。凭据只用于后端登录，不会回显。</p><h3>3. 一键进入后台</h3><p>管理页面在新标签页打开。验证码或二次验证需要在原页面手动完成。PiKVM 画面可使用 Direct H.264 或 MJPEG；WebRTC 还取决于你的网络连通性。</p><h3>退出时</h3><p>门户退出会撤销关联的设备代理访问并关闭长连接。设备通过原内网地址访问时仍保留原来的登录方式。</p></div></Modal>}
    {notice && <Toast notice={notice} close={() => setNotice(null)} />}
  </div>
}

function Brand() { return <div className="brand"><span className="brand-icon"><Monitor size={23} /><i /></span><span>web-console<small>DEVICE ACCESS</small></span></div> }
function DeviceIcon({ type }: { type: Kind }) { return type === 'pikvm' || type === 'nanokvm' || type === 'blikvm' || type === 'glinet' ? <Monitor size={23} /> : type === 'pve' || type === 'esxi' ? <Server size={23} /> : type === 'openwrt' || type === 'tplink' || type === 'xiaomi' ? <CircuitBoard size={23} /> : <Link2 size={23} /> }
function Stat({ icon, label, value, detail }: { icon: React.ReactNode; label: string; value: number; detail: string }) { return <div className="stat"><div><span>{label}</span><strong>{value.toString().padStart(2, '0')}</strong><small>{detail}</small></div><div className="stat-icon">{icon}</div></div> }
function Toast({ notice, close }: { notice: Notice; close: () => void }) { return <div role={notice.error ? 'alert' : 'status'} className={`toast ${notice.error ? 'error' : ''}`}>{notice.error ? <CircleHelp size={19} /> : <Check size={19} />}<span>{notice.text}</span><button className="icon-button" aria-label="关闭提示" onClick={close}><X size={16} /></button></div> }
function Modal({ title, children, close }: { title: string; children: React.ReactNode; close: () => void }) {
  const ref = useRef<HTMLDialogElement>(null)
  useEffect(() => { const dialog = ref.current!; dialog.showModal(); return () => dialog.close() }, [])
  return <dialog ref={ref} className="modal" onCancel={e => { e.preventDefault(); close() }} onClick={e => { if (e.target === ref.current) close() }}><div className="modal-header"><h2>{title}</h2><button className="icon-button" aria-label="关闭窗口" onClick={close}><X size={20} /></button></div>{children}</dialog>
}
function Editor({ service, domain, groups, busy, close, save }: { service: Service; domain: string; groups: string[]; busy: boolean; close: () => void; save: (s: Service, username: string, password: string) => Promise<void> }) {
  const [draft, setDraft] = useState({ ...service })
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [advanced, setAdvanced] = useState(false)
  const [tlsMode, setTlsMode] = useState(service.certificatePin ? 'pin' : 'ca')
  const patch = <K extends keyof Service,>(field: K, value: Service[K]) => setDraft(s => ({ ...s, [field]: value }))
  async function submit(e: FormEvent) { e.preventDefault(); if (busy) return; setError(''); const account = (draft.type === 'xiaomi' || draft.type === 'glinet') && password ? 'admin' : username; if (storesCredentials(draft.type) && (!!account !== !!password)) { setError('更新凭据时，请同时填写账号和密码'); return } try { await save({ ...draft, ...(draft.type === 'tplink' ? { tplinkProtocol: 'slp' as const } : {}) }, account, password) } catch (e) { setError((e as Error).message) } }
  return <Modal title={service.id ? '编辑设备' : '添加设备'} close={() => { if (!busy) close() }}><form onSubmit={submit}><div className="editor-body"><div className="field"><label htmlFor="device-type">设备类型</label><div className="kind-picker">{(Object.keys(labels) as Kind[]).map(k => <button key={k} type="button" className={draft.type === k ? 'chosen' : ''} onClick={() => { patch('type', k); patch('entryPath', ''); setUsername(''); setPassword('') }}><DeviceIcon type={k} />{labels[k]}{draft.type === k && <Check size={13} />}</button>)}</div></div>{draft.type === 'tplink' && <Field label="TP-Link 快速登录协议" id="tplink-protocol"><select id="tplink-protocol" value={draft.tplinkProtocol || 'slp'} onChange={() => patch('tplinkProtocol', 'slp')}><option value="slp">国内商用 SLP（路由器 / AC）</option></select><small>支持 TL-R479G+、TL-ER3229G、TL-AC200；相同协议共用适配。</small></Field>}<div className="field-row"><Field label="设备名称" id="device-name"><input id="device-name" required maxLength={120} placeholder="例如：机房 PiKVM" value={draft.name} onChange={e => patch('name', e.target.value)} /></Field><Field label="分组" id="device-group"><input id="device-group" list="device-groups" maxLength={80} placeholder="例如：机房设备" value={draft.group} onChange={e => patch('group', e.target.value)} /><datalist id="device-groups">{groups.map(g => <option value={g} key={g} />)}</datalist></Field></div><Field label={draft.type === 'link' ? '访问地址' : '设备内网地址'} id="device-url"><input id="device-url" required type="url" placeholder="https://192.168.1.100" value={draft.upstreamUrl} onChange={e => patch('upstreamUrl', e.target.value)} /></Field><Field label="访问子域名" id="device-slug"><div className="domain-input"><input id="device-slug" required pattern="[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?" placeholder="pikvm" value={draft.slug} onChange={e => patch('slug', e.target.value.toLowerCase())} /><span>.{domain}</span></div><small>{draft.type === 'link' ? '用作设备唯一标识；普通链接直接打开原地址。' : '此域名的 DNS、证书和反向代理需配置到 web-console。'}</small></Field>{draft.type === 'proxy' && <p className="modal-text">通过设备子域名访问原页面，手动输入账号密码。不会自动登录，设备内网地址的跳转会改为代理域名。</p>}{storesCredentials(draft.type) && <div className="credential-box"><div><LockKeyhole size={16} /><strong>设备登录凭据</strong><span>{service.hasCredentials ? '已保存 · 留空保留' : '加密保存'}</span></div><div className="field-row"><Field label="账号" id="device-user"><input id="device-user" autoComplete="off" maxLength={256} placeholder={draft.type === 'pve' ? 'root@pam / user@pve' : 'admin / root'} readOnly={draft.type === 'xiaomi' || draft.type === 'glinet'} value={draft.type === 'xiaomi' || draft.type === 'glinet' ? 'admin' : username} onChange={e => setUsername(e.target.value)} /></Field><Field label="密码" id="device-password"><input id="device-password" type="password" autoComplete="new-password" maxLength={4096} placeholder={service.hasCredentials ? '已保存，不回显' : '输入设备原有密码'} value={password} onChange={e => setPassword(e.target.value)} /></Field></div><small>不修改设备原来的登录方式。未保存凭据时仍可手动登录。</small></div>}<Field label="备注" id="device-notes"><input id="device-notes" maxLength={2000} placeholder="帮助你记住这台设备的用途" value={draft.notes} onChange={e => patch('notes', e.target.value)} /></Field>{draft.type !== 'link' && <><button type="button" className="advanced-toggle" onClick={() => setAdvanced(!advanced)}><Settings2 size={14} />{advanced ? '收起高级配置' : '高级配置：入口路径与可信证书'}</button>{advanced && <><Field label="入口路径" id="device-entry"><input id="device-entry" placeholder={draft.type === 'pikvm' ? '/kvm/' : draft.type === 'nanokvm' || draft.type === 'glinet' ? '/#/' : draft.type === 'blikvm' ? '/matrix' : draft.type === 'pve' || draft.type === 'tplink' || draft.type === 'proxy' ? '/' : draft.type === 'esxi' ? '/ui/' : draft.type === 'xiaomi' ? '/cgi-bin/luci/;stok=webconsole-session/web/home' : '/cgi-bin/luci/'} value={draft.entryPath} onChange={e => patch('entryPath', e.target.value)} /></Field><Field label="证书验证方式" id="device-tls-mode"><select id="device-tls-mode" value={tlsMode} onChange={e => { setTlsMode(e.target.value); patch('trustedCa', ''); patch('certificatePin', ''); patch('ignoreCertificateTime', false) }}><option value="ca">默认校验 / 信任 CA 证书</option><option value="pin">固定设备证书 SHA-256 指纹</option></select></Field>{tlsMode === 'pin' ? <><Field label="设备证书 SHA-256 指纹" id="device-pin"><input id="device-pin" required maxLength={95} placeholder="64 位十六进制指纹" value={draft.certificatePin ?? ''} onChange={e => patch('certificatePin', e.target.value)} /><small>仅接受此证书，适合没有 SAN 的自签名设备。证书更换后需重新核对指纹。</small></Field><div className="field"><label className="checkbox-field" htmlFor="device-ignore-certificate-time"><input id="device-ignore-certificate-time" type="checkbox" checked={draft.ignoreCertificateTime ?? false} onChange={e => patch('ignoreCertificateTime', e.target.checked)} />忽略证书有效期</label><small>允许已过期或尚未生效的证书，仍须匹配上方 SHA-256 指纹。</small></div></> : <Field label="可信 CA / 设备证书（PEM）" id="device-ca"><textarea id="device-ca" rows={5} placeholder="-----BEGIN CERTIFICATE-----" value={draft.trustedCa ?? ''} onChange={e => patch('trustedCa', e.target.value)} /><small>保持 TLS 校验。自签名设备需导入证书，并确保设备地址匹配证书名称或 IP。</small></Field>}</>}</>}{error && <div className="form-error" role="alert">{error}</div>}</div><div className="modal-actions"><button type="button" className="button secondary" disabled={busy} onClick={close}>取消</button><button className="button primary" disabled={busy}>{busy ? <LoaderCircle size={16} className="spin" /> : <Check size={16} />}{busy ? '正在保存…' : '保存设备'}</button></div></form></Modal>
}
function Field({ label, id, children }: { label: string; id: string; children: React.ReactNode }) { return <div className="field"><label htmlFor={id}>{label}</label>{children}</div> }




