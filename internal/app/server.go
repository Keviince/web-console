package app

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type App struct {
	cfg         Config
	store       *Store
	sessions    *sessionStore
	auth        *authenticator
	log         *slog.Logger
	cancel      context.CancelFunc
	transportMu sync.Mutex
	transports  map[string]cachedTransport
}

func New(ctx context.Context, cfg Config, log *slog.Logger) (*App, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	store, err := OpenStore(cfg.DataDir, cfg.Key)
	if err != nil {
		return nil, err
	}
	auth, err := newAuthenticator(ctx, cfg)
	if err != nil {
		store.Close()
		return nil, errors.New("无法读取 OIDC discovery，请检查 Authentik 地址和网络")
	}
	log.Info("oidc provider configured", "signing_algorithms", auth.signingAlgorithms)
	if cfg.SessionTTL == 0 {
		cfg.SessionTTL = 8 * time.Hour
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &App{cfg: cfg, store: store, sessions: newSessions(), auth: auth, log: log, cancel: cancel}
	go func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				a.sessions.prune()
			}
		}
	}()
	return a, nil
}
func (a *App) Close() error {
	a.cancel()
	a.RevokeAll()
	a.transportMu.Lock()
	for _, entry := range a.transports {
		entry.transport.CloseIdleConnections()
	}
	a.transports = nil
	a.transportMu.Unlock()
	return a.store.Close()
}
func (a *App) RevokeAll() { a.sessions.revokeAll() }
func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	host := strings.ToLower(r.Host)
	healthHost, _ := url.Parse("http://" + host)
	var healthIP net.IP
	if healthHost != nil {
		healthIP = net.ParseIP(healthHost.Hostname())
	}
	if r.URL.Path == "/healthz" && (host == a.cfg.portalHost() || healthIP != nil && healthIP.IsLoopback()) {
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		if err := a.store.db.PingContext(r.Context()); err != nil {
			http.Error(w, "not ready", 503)
			return
		}
		jsonReply(w, 200, map[string]string{"status": "ok"})
		return
	}
	if host != a.cfg.portalHost() {
		u, err := url.Parse("http://" + host)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		portal, _ := url.Parse(a.cfg.PortalURL)
		if u.Port() != portal.Port() {
			http.NotFound(w, r)
			return
		}
		suffix := "." + a.cfg.DeviceDomain
		if !strings.HasSuffix(u.Hostname(), suffix) {
			http.NotFound(w, r)
			return
		}
		slug := strings.TrimSuffix(u.Hostname(), suffix)
		if !validSlug(slug) {
			http.NotFound(w, r)
			return
		}
		s, err := a.store.BySlug(r.Context(), slug)
		if err != nil {
			http.NotFound(w, r)
			return
		}
		a.serveDevice(w, r, s)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
	switch r.URL.Path {
	case "/auth/login":
		a.login(w, r)
	case "/auth/callback":
		a.callback(w, r)
	case "/auth/launch":
		if r.Method != "GET" {
			w.WriteHeader(405)
			return
		}
		a.launchRedirect(w, r)
	default:
		if strings.HasPrefix(r.URL.Path, "/api/") {
			a.api(w, r)
		} else {
			a.static(w, r)
		}
	}
}
func (a *App) static(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" && r.Method != "HEAD" {
		w.WriteHeader(405)
		return
	}
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/assets/") && r.URL.Path != "/favicon.svg" {
		http.NotFound(w, r)
		return
	}
	name := strings.TrimPrefix(r.URL.Path, "/")
	if name == "" {
		name = "index.html"
		w.Header().Set("Cache-Control", "no-cache")
	}
	if strings.Contains(name, "..") || strings.Contains(name, "\\") {
		http.NotFound(w, r)
		return
	}
	path := filepath.Join(a.cfg.WebRoot, filepath.FromSlash(name))
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, path)
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 128<<10)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		jsonError(w, 400, "请求格式无效或字段不支持")
		return false
	}
	if err := d.Decode(&struct{}{}); err != io.EOF {
		jsonError(w, 400, "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}
func (a *App) api(w http.ResponseWriter, r *http.Request) {
	p := a.portalAuth(w, r)
	if p == nil {
		return
	}
	if r.URL.Path == "/api/me" && r.Method == "GET" {
		jsonReply(w, 200, map[string]string{"name": p.Name, "csrfToken": p.CSRF, "deviceDomain": a.cfg.DeviceDomain})
		return
	}
	if r.URL.Path == "/api/logout" && r.Method == "POST" {
		a.sessions.mu.Lock()
		gs := []*gatewaySession{}
		for _, g := range a.sessions.gateways {
			if g.PortalID == p.ID {
				gs = append(gs, g)
			}
		}
		a.sessions.mu.Unlock()
		a.sessions.revokePortal(p.ID)
		for _, g := range gs {
			go a.revokeUpstream(g)
		}
		a.clearCookie(w, portalCookie)
		jsonReply(w, 200, map[string]bool{"ok": true})
		return
	}
	if r.URL.Path == "/api/services" {
		switch r.Method {
		case "GET":
			items, err := a.store.List(r.Context())
			if err != nil {
				jsonError(w, 500, "无法读取设备列表")
				return
			}
			jsonReply(w, 200, items)
		case "POST":
			var input serviceInput
			if !decode(w, r, &input) {
				return
			}
			s := input.Service
			if err := validateCredentials(input.Credentials); err != nil {
				jsonError(w, 400, err.Error())
				return
			}
			s.ID = token()
			if err := validateService(&s, a.cfg); err != nil {
				jsonError(w, 400, err.Error())
				return
			}
			if err := a.store.SaveWithCredentials(r.Context(), s, input.Credentials); err != nil {
				jsonError(w, 409, "保存失败，请检查设备子域名是否重复")
				return
			}
			s.HasCredentials = input.Credentials != nil && storesCredentials(s.Type)
			jsonReply(w, 201, s)
		default:
			w.WriteHeader(405)
		}
		return
	}
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/")
	if !strings.HasPrefix(r.URL.Path, "/api/services/") || len(parts) > 2 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	s, err := a.store.Get(r.Context(), parts[0])
	if errors.Is(err, sql.ErrNoRows) {
		jsonError(w, 404, "设备不存在")
		return
	}
	if err != nil {
		jsonError(w, 500, "读取设备失败")
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case "PUT":
			var input serviceInput
			if !decode(w, r, &input) {
				return
			}
			next := input.Service
			if err := validateCredentials(input.Credentials); err != nil {
				jsonError(w, 400, err.Error())
				return
			}
			next.ID = s.ID
			if err := validateService(&next, a.cfg); err != nil {
				jsonError(w, 400, err.Error())
				return
			}
			if err := a.store.SaveWithCredentials(r.Context(), next, input.Credentials); err != nil {
				jsonError(w, 409, "保存失败，请检查设备子域名是否重复")
				return
			}
			a.sessions.revokeDevice(s.ID)
			a.dropProxyTransport(s.ID)
			next.HasCredentials = storesCredentials(next.Type) && (s.HasCredentials || input.Credentials != nil)
			jsonReply(w, 200, next)
		case "DELETE":
			if err := a.store.Delete(r.Context(), s.ID); err != nil {
				jsonError(w, 500, "删除失败")
				return
			}
			a.sessions.revokeDevice(s.ID)
			a.dropProxyTransport(s.ID)
			jsonReply(w, 200, map[string]bool{"ok": true})
		default:
			w.WriteHeader(405)
		}
		return
	}
	switch parts[1] {
	case "credentials":
		if r.Method != "PUT" {
			w.WriteHeader(405)
			return
		}
		if !storesCredentials(s.Type) {
			jsonError(w, 400, "此类型不保存账号密码")
			return
		}
		var cred Credentials
		if !decode(w, r, &cred) {
			return
		}
		if cred.Username == "" || cred.Password == "" || len(cred.Username) > 256 || len(cred.Password) > 4096 {
			jsonError(w, 400, "账号和密码必填且长度须在限制内")
			return
		}
		if err := a.store.SetCredentials(r.Context(), s.ID, cred); err != nil {
			jsonError(w, 500, "保存凭据失败")
			return
		}
		a.sessions.revokeDevice(s.ID)
		jsonReply(w, 200, map[string]bool{"ok": true})
	case "launch":
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if s.Type == "link" {
			jsonReply(w, 200, map[string]string{"url": s.UpstreamURL})
			return
		}
		ticket := a.sessions.ticket(p, s.ID)
		jsonReply(w, 200, map[string]string{"url": a.cfg.deviceOrigin(s.Slug) + "/__webconsole/start?ticket=" + url.QueryEscape(ticket)})
	case "test":
		if r.Method != "POST" {
			w.WriteHeader(405)
			return
		}
		if s.Type == "link" {
			jsonReply(w, 200, map[string]string{"message": "普通链接将直接在浏览器打开，未进行代登录检查"})
			return
		}
		a.testDevice(w, r, s)
	default:
		http.NotFound(w, r)
	}
}
func (a *App) testDevice(w http.ResponseWriter, r *http.Request, s Service) {
	stage, err := checkDeviceConnection(r.Context(), s, func() (Credentials, error) { return a.store.Credentials(r.Context(), s.ID) })
	if err != nil {
		a.deviceTestError(w, s, stage, err)
		return
	}
	a.log.Info("device test successful", "service", s.ID)
	message := "连接与自动登录验证通过"
	if s.Type == "proxy" {
		message = "代理连接通过，请在原页面手动登录"
	}
	jsonReply(w, 200, map[string]string{"message": message})
}
