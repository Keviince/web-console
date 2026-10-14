package app

import (
	"bufio"
	"context"
	"crypto/sha256"
	"errors"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

func (a *App) serveDevice(w http.ResponseWriter, r *http.Request, s Service) {
	// Form POSTs need their Origin for CSRF validation. no-referrer makes
	// browsers send Origin: null; strict-origin also keeps launch tickets
	// and upstream paths out of Referer headers.
	w.Header().Set("Referrer-Policy", "strict-origin")
	if s.Type == "link" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/__webconsole/start" {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		g := a.sessions.redeem(r.URL.Query().Get("ticket"), s.ID)
		if g == nil {
			http.Error(w, "访问票据无效或已过期，请从门户重新打开设备", 403)
			return
		}
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(g.ctx, cancel)
		defer stop()
		defer cancel()
		r = r.WithContext(ctx)
		a.cookie(w, gatewayCookie, g.ID, g.Expires)
		w.Header().Set("Cache-Control", "no-store")
		if s.Type == "proxy" {
			g.authMu.Lock()
			g.Manual = true
			g.authMu.Unlock()
		}
		if err := a.ensureLogin(r.Context(), s, g, nil); err != nil {
			a.deviceError(w, r, s, g, err)
			return
		}
		a.publishDeviceCookies(w, s, g)
		http.Redirect(w, r, s.EntryPath, http.StatusSeeOther)
		return
	}
	g := a.sessions.gateway(a.readCookie(r, gatewayCookie), s.ID)
	if g == nil {
		if r.Method == "GET" && !isWebSocket(r) && documentNavigation(r) {
			http.Redirect(w, r, a.cfg.PortalURL+"/auth/launch?device="+url.QueryEscape(s.Slug), http.StatusFound)
		} else {
			http.Error(w, "设备访问会话已失效，请从门户重新打开", 401)
		}
		return
	}
	if r.URL.Path == "/__webconsole/manual" {
		if r.Method != "POST" || r.Header.Get("Origin") != a.cfg.deviceOrigin(s.Slug) || !constantEqual(r.FormValue("csrf"), g.CSRF) {
			http.Error(w, "请求无效", 403)
			return
		}
		g.authMu.Lock()
		g.Manual = true
		if s.Type == "blikvm" {
			saveBlikvmSession(&http.Client{Jar: g.Jar}, s, blikvmAuth{})
		}
		if quickLoginKind(s.Type) {
			clearNativeSession(&http.Client{Jar: g.Jar}, s)
		}
		g.authMu.Unlock()
		entry := manualEntry(s)
		http.Redirect(w, r, entry, http.StatusSeeOther)
		return
	}
	if s.Type == "blikvm" && a.serveBlikvmBridge(w, r, s, g) {
		return
	}
	if quickLoginKind(s.Type) && a.serveNativeBridge(w, r, s, g) {
		return
	}
	if strings.HasPrefix(r.URL.Path, "/__webconsole/") {
		http.NotFound(w, r)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	stop := context.AfterFunc(g.ctx, cancel)
	defer stop()
	defer cancel()
	r = r.WithContext(ctx)
	// Validate browser origins before converting them to the upstream origin.
	if origin := r.Header.Get("Origin"); origin != "" && origin != a.cfg.deviceOrigin(s.Slug) {
		http.Error(w, "跨站请求已拒绝", 403)
		return
	}
	if !safeRequest(r) && r.Header.Get("Origin") == "" {
		ref, err := url.Parse(r.Referer())
		if err != nil || ref.Scheme+"://"+ref.Host != a.cfg.deviceOrigin(s.Slug) {
			http.Error(w, "缺少可信请求来源", 403)
			return
		}
	}
	if quickLoginKind(s.Type) {
		a.consumeNativeLogoutMarker(w, r, s, g)
		if r.Method == "GET" && documentNavigation(r) {
			if err := a.prepareNativePage(r, s, g); err != nil {
				a.deviceError(w, r, s, g, err)
				return
			}
			g.authMu.Lock()
			manual := g.Manual
			g.authMu.Unlock()
			if !manual && nativeEntryRedirect(s, r) && r.URL.RequestURI() != s.EntryPath {
				http.Redirect(w, r, s.EntryPath, http.StatusSeeOther)
				return
			}
		}
		a.ensureESXiCSRF(s, g)
		r = prepareNativeRequest(r, s, g)
	}
	if s.Type == "blikvm" && r.Method == "GET" && documentNavigation(r) {
		if err := a.prepareBlikvmPage(r.Context(), s, g); err != nil {
			a.deviceError(w, r, s, g, err)
			return
		}
		g.authMu.Lock()
		manual := g.Manual
		g.authMu.Unlock()
		if !manual && r.URL.Path == "/" && s.EntryPath != "/" {
			http.Redirect(w, r, s.EntryPath, http.StatusSeeOther)
			return
		}
	}
	// NanoKVM's hash router guards the desktop with a readable auth marker.
	// Restore it after a real account check, including a reload after WS expiry.
	if s.Type == "nanokvm" && r.Method == "GET" && r.URL.Path == "/" && documentNavigation(r) {
		g.authMu.Lock()
		manual := g.Manual
		g.authMu.Unlock()
		if !manual {
			if err := a.ensureLogin(r.Context(), s, g, nil); err != nil {
				a.deviceError(w, r, s, g, err)
				return
			}
			a.publishNanoMarker(w.Header(), g.Expires)
		}
	}
	t, err := a.proxyTransport(s)
	if err != nil {
		a.deviceError(w, r, s, g, err)
		return
	}
	upstream, _ := url.Parse(s.UpstreamURL)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(p *httputil.ProxyRequest) {
			p.SetURL(upstream)
			p.Out.Host = upstream.Host
			// Forwarded headers from the browser are removed by ReverseProxy.Rewrite.
			p.Out.Header.Set("X-Forwarded-Proto", strings.Split(a.cfg.PortalURL, ":")[0])
			p.Out.Header.Set("X-Forwarded-Host", r.Host)
			if s.Type != "proxy" {
				p.Out.Header.Del("Authorization")
			}
			if s.Type == "proxy" {
				p.Out.Header.Set("Accept-Encoding", "identity")
				// Always rewrite a complete fresh page instead of reusing a cached
				// upstream representation containing private-address URLs.
				p.Out.Header.Del("If-None-Match")
				p.Out.Header.Del("If-Modified-Since")
			}
			if s.Type == "blikvm" {
				p.Out.Header.Del("Username")
				if documentNavigation(r) || r.URL.Path == "/api/login" {
					p.Out.Header.Set("Accept-Encoding", "identity")
				}
			}
			if quickLoginKind(s.Type) {
				p.Out.Header.Set("Accept-Encoding", "identity")
			}
			for key := range p.Out.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-authentik-") {
					p.Out.Header.Del(key)
				}
			}
			if p.Out.Header.Get("Origin") != "" {
				p.Out.Header.Set("Origin", s.UpstreamURL)
			}
			if ref, err := url.Parse(p.Out.Referer()); err == nil && ref.Host == r.Host {
				ref.Scheme = upstream.Scheme
				ref.Host = upstream.Host
				p.Out.Header.Set("Referer", ref.String())
			}
		},
		Transport:     &deviceRoundTripper{app: a, service: s, session: g, base: t},
		FlushInterval: -1,
		ModifyResponse: func(resp *http.Response) error {
			resp.Header.Del("Alt-Svc")
			if s.Type == "tplink" {
				cacheTPLinkStatic(resp)
			}
			if s.Type == "proxy" {
				if err := rewriteManualProxyResponse(resp, s, a.cfg.deviceOrigin(s.Slug)); err != nil {
					return err
				}
			}
			if s.Type == "blikvm" && documentNavigation(r) {
				if err := bridgeBlikvmHTML(resp, s, g, t); err != nil {
					return err
				}
			}
			if quickLoginKind(s.Type) {
				if err := bridgeNativeResponse(resp, s, g); err != nil {
					return err
				}
				if location := resp.Header.Get("Location"); location != "" {
					resp.Header.Set("Location", nativeRedirectLocation(location, s, g))
				}
			}
			if location := resp.Header.Get("Location"); location != "" {
				u, err := url.Parse(location)
				if err == nil && u.Host == upstream.Host {
					origin, _ := url.Parse(a.cfg.deviceOrigin(s.Slug))
					u.Scheme = origin.Scheme
					u.Host = origin.Host
					resp.Header.Set("Location", u.String())
				}
			}
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, cookie := range cookies {
				if internalCookie(cookie.Name) {
					continue
				}
				cookie.Domain = ""
				cookie.Secure = !a.cfg.DevHTTP
				resp.Header.Add("Set-Cookie", cookie.String())
			}
			if quickLoginKind(s.Type) {
				nativeGatewayCookies(resp.Header, s, a.cfg.DevHTTP)
			}
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			var loginErr *proxyLoginError
			if errors.As(err, &loginErr) {
				if errors.Is(loginErr.err, errBliProtocol) || errors.Is(loginErr.err, errNativeProtocol) {
					requestID := logDeviceFailure(a.log, "device page bridge failed", s, "page_bridge", loginErr.err)
					w.Header().Set("X-WebConsole-Request-ID", requestID)
				}
				a.deviceError(w, r, s, g, loginErr.err)
			} else {
				connection := connectionError(err)
				requestID := logDeviceFailure(a.log, "device connection failed", s, "proxy", connection)
				w.Header().Set("X-WebConsole-Request-ID", requestID)
				a.deviceError(w, r, s, g, connection)
			}
		},
	}
	proxy.ServeHTTP(&trackingWriter{ResponseWriter: w, session: g}, r)
}

type cachedTransport struct {
	fingerprint [32]byte
	transport   *http.Transport
}

func (a *App) dropProxyTransport(id string) {
	a.transportMu.Lock()
	defer a.transportMu.Unlock()
	if entry, ok := a.transports[id]; ok {
		entry.transport.CloseIdleConnections()
		delete(a.transports, id)
	}
}

func (a *App) proxyTransport(s Service) (*http.Transport, error) {
	fingerprint := sha256.Sum256([]byte(s.UpstreamURL + "\x00" + s.TrustedCA + "\x00" + s.CertificatePin))
	a.transportMu.Lock()
	defer a.transportMu.Unlock()
	if a.transports == nil {
		a.transports = map[string]cachedTransport{}
	}
	if entry, ok := a.transports[s.ID]; ok {
		if entry.fingerprint == fingerprint {
			return entry.transport, nil
		}
		entry.transport.CloseIdleConnections()
	}
	t, err := newTransport(s)
	if err != nil {
		return nil, err
	}
	t.MaxIdleConnsPerHost = 8
	a.transports[s.ID] = cachedTransport{fingerprint: fingerprint, transport: t}
	return t, nil
}
func internalCookie(name string) bool {
	return strings.HasPrefix(name, "__Host-wc_") || strings.HasPrefix(name, "wc_")
}
func isWebSocket(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket")
}
func documentNavigation(r *http.Request) bool {
	dest := r.Header.Get("Sec-Fetch-Dest")
	return dest == "document" || dest == "" && strings.Contains(r.Header.Get("Accept"), "text/html")
}
func safeRequest(r *http.Request) bool {
	return (r.Method == "GET" || r.Method == "HEAD") && (r.Body == nil || r.Body == http.NoBody)
}

type proxyLoginError struct{ err error }

func (e *proxyLoginError) Error() string { return "device session recovery failed" }

type deviceRoundTripper struct {
	app     *App
	service Service
	session *gatewaySession
	base    http.RoundTripper
}

func (t *deviceRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) {
	g := t.session
	g.authMu.Lock()
	version, manual := g.Version, g.Manual
	g.authMu.Unlock()
	if nativeInfo(r).Logout {
		g.authMu.Lock()
		g.Manual = true
		g.authMu.Unlock()
	}
	if t.service.Type == "nanokvm" && r.Method == "POST" && r.URL.Path == "/api/auth/logout" {
		g.authMu.Lock()
		g.Manual = true
		g.authMu.Unlock()
	}
	resp, err := t.send(r)
	if err != nil {
		return nil, err
	}
	if t.service.Type == "proxy" || manual || nativeInfo(r).Logout || !adapterFor(t.service.Type).Expired(resp) {
		return resp, nil
	}
	if !safeDeviceRequest(r) {
		resp.Header.Set("X-WebConsole-Session-Expired", "true")
		return resp, nil
	}
	finish(resp)
	if err := t.app.ensureLogin(r.Context(), t.service, g, &version); err != nil {
		return nil, &proxyLoginError{err}
	}
	// Only GET/HEAD and explicitly recognized native read operations reach this branch.
	resp, err = t.send(r)
	if err == nil {
		t.addSessionCookies(resp)
		if t.service.Type == "nanokvm" && !adapterFor(t.service.Type).Expired(resp) {
			t.app.publishNanoMarker(resp.Header, g.Expires)
		}
	}
	return resp, err
}
func (t *deviceRoundTripper) send(r *http.Request) (*http.Response, error) {
	if t.session.isClosed() {
		return nil, &proxyLoginError{errors.New("设备访问会话已撤销")}
	}
	out := r.Clone(r.Context())
	out.Header = r.Header.Clone()
	if r.GetBody != nil {
		var err error
		out.Body, err = r.GetBody()
		if err != nil {
			return nil, err
		}
	}
	cookies := map[string]*http.Cookie{}
	for _, c := range out.Cookies() {
		if !internalCookie(c.Name) {
			cookies[c.Name] = c
		}
	}
	for _, c := range t.session.Jar.Cookies(out.URL) {
		if !internalCookie(c.Name) {
			cookies[c.Name] = c
		}
	}
	out.Header.Del("Cookie")
	for _, c := range cookies {
		out.AddCookie(c)
	}
	if t.service.Type == "blikvm" {
		applyBlikvmAuth(out, t.service, t.session)
	}
	if quickLoginKind(t.service.Type) {
		applyNativeAuth(out, t.service, t.session)
	}
	resp, err := t.base.RoundTrip(out)
	if err == nil {
		cs := []*http.Cookie{}
		for _, c := range resp.Cookies() {
			if !internalCookie(c.Name) {
				cs = append(cs, c)
			}
		}
		t.session.Jar.SetCookies(out.URL, cs)
		if quickLoginKind(t.service.Type) {
			if captureErr := t.captureNativeResponse(resp); captureErr != nil {
				_ = resp.Body.Close()
				return nil, &proxyLoginError{captureErr}
			}
		}
		if t.service.Type == "blikvm" && out.Method == "POST" && out.URL.Path == "/api/login" && resp.StatusCode == 200 {
			if captureErr := captureBlikvmLogin(resp, t.service, t.session); captureErr != nil {
				return nil, &proxyLoginError{captureErr}
			}
		}
	}
	return resp, err
}
func (t *deviceRoundTripper) addSessionCookies(resp *http.Response) {
	u := resp.Request.URL
	for _, c := range t.session.Jar.Cookies(u) {
		if authCookie(c.Name) {
			c.Path = "/"
			c.HttpOnly = true
			c.Secure = !t.app.cfg.DevHTTP
			c.SameSite = http.SameSiteLaxMode
			resp.Header.Add("Set-Cookie", c.String())
		}
	}
}
func authCookie(name string) bool { return name == "auth_token" || strings.HasPrefix(name, "sysauth") }
func (a *App) publishDeviceCookies(w http.ResponseWriter, s Service, g *gatewaySession) {
	if s.Type == "nanokvm" {
		a.publishNanoMarker(w.Header(), g.Expires)
		return
	}
	u, _ := url.Parse(s.UpstreamURL + s.EntryPath)
	for _, c := range g.Jar.Cookies(u) {
		if authCookie(c.Name) {
			c.Path = "/"
			c.HttpOnly = true
			c.Secure = !a.cfg.DevHTTP
			c.SameSite = http.SameSiteLaxMode
			http.SetCookie(w, c)
		}
	}
}
func (a *App) publishNanoMarker(header http.Header, expires time.Time) {
	cookie := &http.Cookie{Name: "nano-kvm-auth", Value: "1", Path: "/", Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteStrictMode, Expires: expires}
	header.Add("Set-Cookie", cookie.String())
}

type trackingWriter struct {
	http.ResponseWriter
	session *gatewaySession
}

func (w *trackingWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
func (w *trackingWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("websocket unavailable")
	}
	conn, rw, err := h.Hijack()
	if err != nil {
		return nil, nil, err
	}
	if !w.session.track(conn) {
		return nil, nil, errors.New("session revoked")
	}
	return &trackedConn{Conn: conn, session: w.session, original: conn}, rw, nil
}
func (w *trackingWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

type trackedConn struct {
	net.Conn
	session  *gatewaySession
	original net.Conn
}

func (c *trackedConn) Close() error { c.session.untrack(c.original); return c.Conn.Close() }

var deviceErrorPage = template.Must(template.New("error").Parse(`<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{{.Name}} · web-console</title><style>body{font:16px system-ui;background:#eef2f6;color:#152a3b;padding:8vh 24px}main{max-width:520px;margin:auto;background:white;padding:36px;border-radius:16px;box-shadow:0 10px 50px #14304212}h1{font-size:24px}p{line-height:1.8;color:#586978}a,button{display:inline-block;background:#087c69;color:white;border:0;border-radius:8px;padding:12px 18px;text-decoration:none;font:inherit;cursor:pointer}form{display:inline-block;margin:12px 8px 0 0}.secondary{background:#e8edf2;color:#233847}</style><main><small>WEBCONSOLE / 设备访问</small><h1>{{.Name}} 暂时无法自动进入</h1><p>{{.Message}}</p><form method="post" action="/__webconsole/manual"><input type="hidden" name="csrf" value="{{.CSRF}}"><button>使用原页面手动登录</button></form><a class="secondary" href="{{.Portal}}">返回门户</a><p><small>手动登录仍经过门户授权。设备账号、验证码和二次验证保持原有要求。</small></p></main></html>`))

func (a *App) deviceError(w http.ResponseWriter, r *http.Request, s Service, g *gatewaySession, err error) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(http.StatusBadGateway)
	_ = deviceErrorPage.Execute(w, map[string]string{"Name": s.Name, "Message": err.Error(), "CSRF": g.CSRF, "Portal": a.cfg.PortalURL})
}

// revokeUpstream is best effort; gateway authorization is revoked even when the device is offline.
func (a *App) revokeUpstream(g *gatewaySession) {
	s, err := a.store.Get(context.Background(), g.ServiceID)
	if err != nil || s.Type == "proxy" {
		return
	}
	c, err := clientFor(s, g)
	if err != nil {
		return
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = adapterFor(s.Type).Logout(ctx, c, s)
}

var _ io.ReadWriteCloser = (*trackedConn)(nil)
