package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type fakeBlikvm struct {
	server     *httptest.Server
	generation atomic.Int32
	logins     atomic.Int32
	logouts    atomic.Int32
	posts      atomic.Int32
	mfa        atomic.Bool
	limited    atomic.Bool
	disabled   atomic.Bool
}

const fakeBlikvmHTML = `<!doctype html><html><head><script type="module" crossorigin src="/assets/main.js"></script></head><body><div id="app"></div></body></html>`

// Minimal native client: account permissions come from /auth/me, not a patched
// Pinia export or a token in localStorage.
const fakeBlikvmModule = `
const root=document.querySelector('#app');
const response=await fetch('/api/v1/auth/me');
if(response.ok){const {data}=await response.json();root.textContent=data.username+':'+data.role+':'+data.permissions.join(',');const button=document.createElement('button');button.textContent='Logout';button.onclick=async()=>{await fetch('/api/v1/auth/logout',{method:'POST'});location.reload();};root.append(button);}
else root.textContent='Login';`

func newBlikvm(t *testing.T) *fakeBlikvm {
	t.Helper()
	f := &fakeBlikvm{}
	f.generation.Store(1)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			if internalCookie(c.Name) {
				t.Error("internal credentials/cookie reached upstream")
			}
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Username") != "" || r.URL.Query().Has("token") {
			t.Error("obsolete/browser bearer credentials reached upstream")
		}
		switch r.URL.Path {
		case "/", "/matrix":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Header().Set("Content-Security-Policy", "script-src 'self'")
			_, _ = io.WriteString(w, fakeBlikvmHTML)
			return
		case "/assets/main.js":
			w.Header().Set("Content-Type", "text/javascript")
			_, _ = io.WriteString(w, fakeBlikvmModule)
			return
		case "/api/v1/auth/state":
			jsonReply(w, 200, map[string]any{"ok": true, "data": map[string]bool{"enabled": !f.disabled.Load()}})
			return
		case "/api/v1/auth/login":
			f.logins.Add(1)
			var input struct {
				Username, Password string
				RememberDevice     bool   `json:"rememberDevice"`
				Code               string `json:"code"`
			}
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&input) != nil || input.RememberDevice {
				t.Error("BliKVM login must submit the native JSON protocol without a persistent device login")
			}
			if r.Header.Get("Origin") != f.server.URL {
				t.Error("login origin not rewritten")
			}
			if f.limited.Load() {
				w.WriteHeader(429)
				return
			}
			if input.Username != "admin" || input.Password != "password" {
				jsonReply(w, 401, map[string]any{"ok": false, "error": "invalid credentials"})
				return
			}
			if f.mfa.Load() && input.Code != "123456" {
				jsonReply(w, 401, map[string]any{"ok": false, "error": "2fa code required"})
				return
			}
			http.SetCookie(w, &http.Cookie{Name: blikvmSessionCookie, Value: f.jwt(), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
			jsonReply(w, 200, map[string]any{"ok": true, "data": map[string]any{"user": blikvmUser{"admin", "viewer"}, "rememberDevice": false}})
			return
		}
		if r.Method == "POST" {
			f.posts.Add(1)
		}
		cookie, err := r.Cookie(blikvmSessionCookie)
		if !f.disabled.Load() && (err != nil || cookie.Value != f.jwt()) {
			jsonReply(w, 401, map[string]any{"ok": false, "error": "missing or expired token"})
			return
		}
		switch r.URL.Path {
		case "/api/v1/session/ws", "/api/v1/stream/webrtc/signaling":
			if r.URL.Query().Get("clientSession") != "client-id" {
				t.Error("native clientSession missing")
			}
			conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				kind, message, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if conn.WriteMessage(kind, message) != nil {
					return
				}
			}
		case "/api/v1/auth/me":
			jsonReply(w, 200, map[string]any{"ok": true, "data": map[string]any{"username": "admin", "role": "viewer", "permissions": []string{"kvm.view"}, "authEnabled": !f.disabled.Load()}})
		case "/api/v1/auth/logout":
			f.logouts.Add(1)
			http.SetCookie(w, &http.Cookie{Name: blikvmSessionCookie, Path: "/", MaxAge: -1})
			jsonReply(w, 200, map[string]any{"ok": true})
		case "/api/v1/power":
			w.WriteHeader(403)
		case "/api/v1/stream/mjpeg":
			w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
			_, _ = io.WriteString(w, "--frame\r\nContent-Type: image/jpeg\r\n\r\nframe\r\n")
		default:
			jsonReply(w, 200, map[string]any{"ok": true, "data": map[string]string{"value": "native"}})
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeBlikvm) jwt() string { return fmt.Sprintf("header.%d.signature", f.generation.Load()) }
func addBlikvm(t *testing.T, a *App, f *fakeBlikvm, slug string) Service {
	t.Helper()
	s := Service{ID: token(), Name: slug, Slug: slug, Type: "blikvm", UpstreamURL: f.server.URL}
	if err := validateService(&s, a.cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"admin", "password"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func blikvmDocument(a *App, s Service, g *gatewaySession, path string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+path, nil)
	r.Header.Set("Sec-Fetch-Dest", "document")
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func blikvmSubmit(a *App, s Service, g *gatewaySession, path, body, contentType string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", a.cfg.deviceOrigin(s.Slug)+path, strings.NewReader(body))
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	r.Header.Set("Origin", a.cfg.deviceOrigin(s.Slug))
	r.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestBlikvmLoginIsolationRecoveryAndUnsafeRequests(t *testing.T) {
	a := testApp(t)
	f, other := newBlikvm(t), newBlikvm(t)
	s, second := addBlikvm(t, a, f, "native"), addBlikvm(t, a, other, "other")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	if s.EntryPath != "/" {
		t.Fatal("wrong native entry")
	}
	if gatewayRequest(a, second, g, "GET", "/api/v1/auth/me", nil).Code != 401 || other.logins.Load() != 0 {
		t.Fatal("gateway accepted another device session")
	}
	f.generation.Add(1)
	before := f.logins.Load()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil); got.Code != 200 {
				t.Errorf("refresh failed: %d", got.Code)
			}
		}()
	}
	wg.Wait()
	if f.logins.Load() != before+1 {
		t.Fatal("concurrent refresh was not merged")
	}
	f.generation.Add(1)
	before = f.logins.Load()
	got := gatewayRequest(a, s, g, "POST", "/api/v1/hid", strings.NewReader(`{"key":"test"}`))
	if got.Code != 401 || got.Header().Get("X-WebConsole-Session-Expired") != "true" || f.posts.Load() != 1 || f.logins.Load() != before {
		t.Fatal("unsafe control request was replayed")
	}
	if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || f.logins.Load() != before+1 {
		t.Fatal("SPA reload did not renew backend session", got.Code)
	}
	before = f.logins.Load()
	if got := gatewayRequest(a, s, g, "GET", "/api/v1/power", nil); got.Code != 403 || f.logins.Load() != before {
		t.Fatal("viewer authorization failure triggered password replay")
	}
	if got := gatewayRequest(a, s, g, "GET", "/api/v1/stream/mjpeg", nil); got.Code != 200 || !strings.Contains(got.Body.String(), "--frame") {
		t.Fatal("cookie-authenticated stream proxy failed")
	}
}

func TestBlikvmNativePageAndBrowserFixtures(t *testing.T) {
	a := testApp(t)
	f := newBlikvm(t)
	s := addBlikvm(t, a, f, "native")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	page := blikvmDocument(a, s, g, "/")
	if page.Code != 200 || page.Body.String() != fakeBlikvmHTML || page.Header().Get("Content-Security-Policy") != "script-src 'self'" {
		t.Fatal("native page was patched or rejected")
	}
	me := gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil)
	if me.Code != 200 || !strings.Contains(me.Body.String(), `"permissions":["kvm.view"]`) || me.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("native account/permissions not preserved")
	}
	for _, response := range []*httptest.ResponseRecorder{page, me} {
		if strings.Contains(response.Body.String(), f.jwt()) || strings.Contains(response.Header().Get("Set-Cookie"), blikvmSessionCookie) {
			t.Fatal("upstream session leaked to browser")
		}
	}
	for _, path := range []string{"/__webconsole/blikvm/bootstrap.js", "/__webconsole/blikvm/app.js"} {
		if got := gatewayRequest(a, s, g, "GET", path, nil); got.Code != 404 {
			t.Fatal("obsolete bridge is still active")
		}
	}
	if path := os.Getenv("WEBCONSOLE_BLI_BROWSER_FIXTURE"); path != "" {
		fixture, _ := json.Marshal(map[string]string{"html": page.Body.String(), "module": fakeBlikvmModule, "me": me.Body.String()})
		if err := os.WriteFile(path, fixture, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestBlikvmFailedLoginStopsAndManualMFA(t *testing.T) {
	for _, mode := range []string{"password", "mfa", "limited"} {
		t.Run(mode, func(t *testing.T) {
			a := testApp(t)
			f := newBlikvm(t)
			s := addBlikvm(t, a, f, "native")
			if mode == "password" {
				_ = a.store.SetCredentials(context.Background(), s.ID, Credentials{"admin", "wrong"})
			}
			f.mfa.Store(mode == "mfa")
			f.limited.Store(mode == "limited")
			p, _ := owner(a)
			g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
			err := a.ensureLogin(context.Background(), s, g, nil)
			if err == nil {
				t.Fatal("rejected login accepted")
			}
			if mode == "mfa" && !errors.Is(err, errBliInteractive) {
				t.Fatal("MFA not classified", err)
			}
			if mode == "limited" && (!errors.Is(err, errBliRateLimit) || time.Until(g.RetryAfter) < 4*time.Minute) {
				t.Fatal("rate limit not respected")
			}
			before := f.logins.Load()
			_ = a.ensureLogin(context.Background(), s, g, nil)
			if before != 1 || f.logins.Load() != before {
				t.Fatal("rejected password/MFA was resubmitted")
			}
			manual := blikvmSubmit(a, s, g, "/__webconsole/manual", "csrf="+g.CSRF, "application/x-www-form-urlencoded")
			if manual.Code != 303 || manual.Header().Get("Location") != "/" {
				t.Fatal("manual login did not open native root")
			}
			if mode == "mfa" {
				login := blikvmSubmit(a, s, g, "/api/v1/auth/login", `{"username":"admin","password":"password","rememberDevice":false,"code":"123456"}`, "application/json")
				if login.Code != 200 || strings.Contains(login.Body.String(), f.jwt()) || strings.Contains(login.Header().Get("Set-Cookie"), blikvmSessionCookie) {
					t.Fatal("manual OTP login not captured safely", login.Code)
				}
				if got := gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil); got.Code != 200 {
					t.Fatal("manual cookie missing upstream", got.Code)
				}
				f.generation.Add(1)
				before = f.logins.Load()
				if got := gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil); got.Code != 401 || f.logins.Load() != before {
					t.Fatal("manual MFA session was automatically replayed")
				}
				if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || blikvmCookie(&http.Client{Jar: g.Jar}, s) != nil {
					t.Fatal("expired manual session did not return to login")
				}
			}
		})
	}
}

func TestBlikvmWebSocketAndNativeLogout(t *testing.T) {
	a := testApp(t)
	f := newBlikvm(t)
	s := addBlikvm(t, a, f, "native")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	proxy := httptest.NewServer(a)
	defer proxy.Close()
	headers := http.Header{"Host": {strings.TrimPrefix(a.cfg.deviceOrigin(s.Slug), "http://")}, "Origin": {a.cfg.deviceOrigin(s.Slug)}, "Cookie": {"wc_gateway=" + g.ID + "; blikvm_session=forged"}, "Authorization": {"Bearer forged"}, "Username": {"forged"}}
	var connections []*websocket.Conn
	for _, path := range []string{"/api/v1/session/ws", "/api/v1/stream/webrtc/signaling"} {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http")+path+"?token=obsolete&clientSession=client-id&codec=h264", headers)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		connections = append(connections, conn)
		if conn.WriteMessage(websocket.TextMessage, []byte("ping")) != nil {
			t.Fatal("websocket write failed")
		}
		_, reply, err := conn.ReadMessage()
		if err != nil || string(reply) != "ping" {
			t.Fatal("cookie-authenticated websocket failed")
		}
	}
	bad := httptest.NewRequest("POST", a.cfg.deviceOrigin(s.Slug)+"/api/v1/auth/logout", nil)
	bad.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	bad.Header.Set("Origin", "http://untrusted.localhost")
	denied := httptest.NewRecorder()
	a.ServeHTTP(denied, bad)
	if denied.Code != 403 || f.logouts.Load() != 0 {
		t.Fatal("native logout accepted invalid origin")
	}
	logout := blikvmSubmit(a, s, g, "/api/v1/auth/logout", "", "application/json")
	if logout.Code != 200 || !g.Manual || f.logouts.Load() != 1 {
		t.Fatal("native logout not forwarded/recorded")
	}
	for _, conn := range connections {
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		if _, _, err := conn.ReadMessage(); err == nil {
			t.Fatal("native logout kept connection open")
		}
	}
	if blikvmCookie(&http.Client{Jar: g.Jar}, s) != nil {
		t.Fatal("logout retained cookie")
	}
	before := f.logins.Load()
	if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || f.logins.Load() != before {
		t.Fatal("logout immediately restored login")
	}
	spoof := httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/api/v1/auth/me", nil)
	spoof.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	spoof.AddCookie(&http.Cookie{Name: blikvmSessionCookie, Value: f.jwt()})
	denied = httptest.NewRecorder()
	a.ServeHTTP(denied, spoof)
	if denied.Code != 401 {
		t.Fatal("browser session cookie overrode gateway logout")
	}
	a.sessions.revokePortal(p.ID)
	if got := gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil); got.Code != 401 {
		t.Fatal("revoked portal still authorizes device")
	}
}

func TestBlikvmProtocolPreflightAndDisabledAuth(t *testing.T) {
	for _, body := range []string{`{"code":0,"data":{"auth":true}}`, `{"ok":true}`, `not JSON`} {
		t.Run(body, func(t *testing.T) {
			var posts atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == "POST" {
					posts.Add(1)
				}
				_, _ = io.WriteString(w, body)
			}))
			defer upstream.Close()
			a := testApp(t)
			p, _ := owner(a)
			g := a.sessions.redeem(a.sessions.ticket(p, "protocol"), "protocol")
			s := Service{UpstreamURL: upstream.URL}
			c, _ := clientFor(s, g)
			defer c.CloseIdleConnections()
			if err := (blikvmAdapter{}).Login(context.Background(), c, s, Credentials{"admin", "password"}); !errors.Is(err, errBliProtocol) || posts.Load() != 0 {
				t.Fatal("password sent to incompatible protocol", err)
			}
		})
	}
	a := testApp(t)
	f := newBlikvm(t)
	f.disabled.Store(true)
	s := addBlikvm(t, a, f, "native")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	if f.logins.Load() != 0 || gatewayRequest(a, s, g, "GET", "/api/v1/auth/me", nil).Code != 200 {
		t.Fatal("disabled authentication attempted password login")
	}
}

// Opt-in regression against a real BliKVM. Credentials and certificate trust
// are supplied only through the environment, never committed as fixtures.
func TestBlikvmLive(t *testing.T) {
	upstream := os.Getenv("WEBCONSOLE_BLI_LIVE_URL")
	if upstream == "" {
		t.Skip("set WEBCONSOLE_BLI_LIVE_URL to test a real device")
	}
	a := testApp(t)
	s := Service{ID: token(), Name: "BliKVM live", Slug: "native", Type: "blikvm", UpstreamURL: upstream, CertificatePin: os.Getenv("WEBCONSOLE_BLI_LIVE_PIN")}
	if err := validateService(&s, a.cfg); err != nil {
		t.Fatal(err)
	}
	cred := Credentials{os.Getenv("WEBCONSOLE_BLI_LIVE_USERNAME"), os.Getenv("WEBCONSOLE_BLI_LIVE_PASSWORD")}
	if err := validateCredentials(&cred); err != nil {
		t.Fatal("live credentials required")
	}
	if err := a.store.SaveWithCredentials(context.Background(), s, &cred); err != nil {
		t.Fatal(err)
	}
	p, _ := owner(a)
	g := enter(t, a, p, s)
	if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || !strings.Contains(got.Body.String(), `type="module"`) || strings.Contains(got.Body.String(), "/__webconsole/blikvm/") {
		t.Fatal("live native page failed", got.Code)
	}
	for _, path := range []string{"/api/v1/auth/me", "/api/v1/capabilities", "/api/v1/stream/status"} {
		got := gatewayRequest(a, s, g, "GET", path, nil)
		if got.Code != 200 || strings.Contains(got.Header().Get("Set-Cookie"), blikvmSessionCookie) {
			t.Fatal("live API failed or exposed session", path, got.Code)
		}
		var result struct {
			OK bool `json:"ok"`
		}
		if json.Unmarshal(got.Body.Bytes(), &result) != nil || !result.OK {
			t.Fatal("live API rejected", path)
		}
	}
	proxy := httptest.NewServer(a)
	defer proxy.Close()
	headers := http.Header{"Host": {strings.TrimPrefix(a.cfg.deviceOrigin(s.Slug), "http://")}, "Origin": {a.cfg.deviceOrigin(s.Slug)}, "Cookie": {"wc_gateway=" + g.ID}}
	for _, path := range []string{"/api/v1/session/ws", "/api/v1/stream/webrtc/signaling"} {
		conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http")+path+"?clientSession=webconsole-protocol-test", headers)
		if err != nil {
			t.Fatal("live websocket failed", path, err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if path != "/api/v1/session/ws" {
			if err := conn.WriteMessage(websocket.TextMessage, []byte("ping")); err != nil {
				conn.Close()
				t.Fatal(err)
			}
		}
		found := false
		for range 20 {
			_, message, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var state struct {
				Data json.RawMessage `json:"data"`
			}
			if string(message) == "pong" || path == "/api/v1/session/ws" && json.Unmarshal(message, &state) == nil && len(state.Data) > 0 {
				found = true
				break
			}
		}
		conn.Close()
		if !found {
			t.Fatal("live websocket did not deliver native state/heartbeat", path)
		}
	}
	c := &http.Client{Jar: g.Jar}
	if err := (blikvmAdapter{}).Logout(context.Background(), c, s); err != nil || blikvmCookie(c, s) != nil {
		t.Fatal("local session cleanup failed")
	}
}
