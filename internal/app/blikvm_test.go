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
	posts      atomic.Int32
	mfa        atomic.Bool
	limited    atomic.Bool
}

const fakeBlikvmHTML = `<!doctype html><html><head><script type="module" crossorigin src="./assets/main.js"></script></head><body><div id="app"></div></body></html>`
const fakeBlikvmModule = `const native=Bw("app",{});export{native as useStore};`

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
		case "/api/auth/state":
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]bool{"auth": true}})
			return
		case "/api/login":
			f.logins.Add(1)
			var input struct {
				Username, Password string
				TwoFA              any `json:"twoFaCode"`
			}
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&input) != nil {
				t.Error("BliKVM login must submit original JSON protocol")
			}
			if f.limited.Load() {
				w.WriteHeader(429)
				return
			}
			if input.Username != "admin" || input.Password != "password" {
				jsonReply(w, 200, map[string]any{"code": 100, "msg": "The username or password is incorrect!"})
				return
			}
			if f.mfa.Load() && input.TwoFA != "123456" {
				jsonReply(w, 200, map[string]any{"code": 100, "msg": "Two factor auth verify failed"})
				return
			}
			jsonReply(w, 200, map[string]any{"code": 0, "data": blikvmAuth{f.jwt(), "admin", "admin"}})
			return
		}
		if r.Method == "POST" {
			f.posts.Add(1)
		}
		if r.Header.Get("Authorization") != "Bearer "+f.jwt() || r.Header.Get("Username") != "admin" {
			jsonReply(w, 401, map[string]any{"code": 102})
			return
		}
		switch r.URL.Path {
		case "/wss":
			if r.URL.Query().Get("token") != f.jwt() {
				t.Error("native websocket auth query missing")
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
		case "/api/update/stream":
			if r.URL.Query().Get("token") != f.jwt() {
				t.Error("SSE token was not replaced on upstream request")
			}
			_, _ = io.WriteString(w, "data: ready\n\n")
		case "/api/forbidden":
			w.WriteHeader(403)
		default:
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"value": "native"}})
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
	if s.EntryPath != "/matrix" {
		t.Fatal("wrong native entry")
	}
	if gatewayRequest(a, second, g, "GET", "/api/check/token", nil).Code != 401 {
		t.Fatal("gateway accepted another device session")
	}
	if other.logins.Load() != 0 {
		t.Fatal("isolated device received a login")
	}
	f.generation.Add(1)
	before := f.logins.Load()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if got := gatewayRequest(a, s, g, "GET", "/api/check/token", nil); got.Code != 200 {
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
	got := gatewayRequest(a, s, g, "POST", "/api/hid", strings.NewReader(`{"key":"test"}`))
	if got.Code != 401 || got.Header().Get("X-WebConsole-Session-Expired") != "true" || f.posts.Load() != 1 || f.logins.Load() != before {
		t.Fatal("unsafe control request was replayed")
	}
	if got := blikvmDocument(a, s, g, "/matrix"); got.Code != 200 || f.logins.Load() != before+1 {
		t.Fatal("public SPA reload did not renew actual backend session", got.Code)
	}
	before = f.logins.Load()
	if got := gatewayRequest(a, s, g, "GET", "/api/forbidden", nil); got.Code != 403 || f.logins.Load() != before {
		t.Fatal("authorization failure triggered password replay")
	}
	if got := gatewayRequest(a, s, g, "GET", "/api/update/stream?token=browser-marker&extra=kept", nil); got.Code != 200 || got.Body.String() != "data: ready\n\n" {
		t.Fatal("stream proxy failed")
	}
}

func TestBlikvmBridgeAndBrowserFixtures(t *testing.T) {
	a := testApp(t)
	f := newBlikvm(t)
	s := addBlikvm(t, a, f, "native")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	page := blikvmDocument(a, s, g, "/matrix")
	if page.Code != 200 || !strings.Contains(page.Body.String(), "/__webconsole/blikvm/bootstrap.js") || !strings.Contains(page.Body.String(), "/__webconsole/blikvm/app.js?") {
		t.Fatal("missing native SPA bridge", page.Body.String())
	}
	if page.Header().Get("Content-Security-Policy") != "script-src 'self'" {
		t.Fatal("native CSP was changed")
	}
	boot := gatewayRequest(a, s, g, "GET", "/__webconsole/blikvm/bootstrap.js", nil)
	app := gatewayRequest(a, s, g, "GET", "/__webconsole/blikvm/app.js?module=%2Fassets%2Fmain.js&store=useStore", nil)
	if boot.Code != 200 || app.Code != 200 || !strings.Contains(boot.Body.String(), blikvmBrowserMarker) || !strings.Contains(app.Body.String(), "store.account.userRole") {
		t.Fatal("native role/bootstrap missing")
	}
	for _, response := range []*httptest.ResponseRecorder{page, boot, app} {
		if strings.Contains(response.Body.String(), f.jwt()) || strings.Contains(response.Header().Get("Set-Cookie"), "signature") {
			t.Fatal("upstream JWT leaked to browser")
		}
		if response.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("session bootstrap can be cached")
		}
	}
	if boot.Header().Get("Cross-Origin-Resource-Policy") != "same-origin" {
		t.Fatal("bootstrap permits sibling script inclusion")
	}
	if got := gatewayRequest(a, s, g, "GET", "/__webconsole/blikvm/app.js?module=https://elsewhere/main.js&store=useStore", nil); got.Code != 400 {
		t.Fatal("foreign module accepted")
	}
	unauthorized := httptest.NewRecorder()
	a.ServeHTTP(unauthorized, httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/__webconsole/blikvm/bootstrap.js", nil))
	if unauthorized.Code != 401 {
		t.Fatal("bootstrap lacks gateway authorization")
	}
	// Optional browser fixtures contain only dummy identities and the real
	// generated bridge scripts, never a device JWT or saved credentials.
	if path := os.Getenv("WEBCONSOLE_BLI_BROWSER_FIXTURE"); path != "" {
		fixture, _ := json.Marshal(map[string]string{"html": page.Body.String(), "bootstrap": boot.Body.String(), "app": app.Body.String()})
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
				t.Fatal("MFA not classified")
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
				login := blikvmSubmit(a, s, g, "/api/login", `{"username":"admin","password":"password","twoFaCode":"123456"}`, "application/json")
				if login.Code != 200 || strings.Contains(login.Body.String(), f.jwt()) || !strings.Contains(login.Body.String(), blikvmBrowserMarker) {
					t.Fatal("manual OTP login not captured safely", login.Code)
				}
				if got := gatewayRequest(a, s, g, "GET", "/api/check/token", nil); got.Code != 200 {
					t.Fatal("manual JWT missing upstream", got.Code)
				}
				f.generation.Add(1)
				before = f.logins.Load()
				if got := gatewayRequest(a, s, g, "GET", "/api/check/token", nil); got.Code != 401 || f.logins.Load() != before {
					t.Fatal("manual MFA session was automatically replayed")
				}
				if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || strings.Contains(got.Body.String(), "/__webconsole/blikvm/app.js?") {
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
	headers := http.Header{"Host": {strings.TrimPrefix(a.cfg.deviceOrigin(s.Slug), "http://")}, "Origin": {a.cfg.deviceOrigin(s.Slug)}, "Cookie": {"wc_gateway=" + g.ID}, "Authorization": {"Bearer forged-browser-token"}, "Username": {"forged-user"}}
	conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(proxy.URL, "http")+"/wss?token="+blikvmBrowserMarker, headers)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if conn.WriteMessage(websocket.TextMessage, []byte("echo")) != nil {
		t.Fatal("websocket write failed")
	}
	_, reply, err := conn.ReadMessage()
	if err != nil || string(reply) != "echo" {
		t.Fatal("authenticated websocket failed")
	}
	bad := gatewayRequest(a, s, g, "POST", "/__webconsole/blikvm/logout", strings.NewReader(`{"csrf":"wrong"}`))
	if bad.Code != 403 {
		t.Fatal("native logout accepted invalid CSRF")
	}
	logout := gatewayRequest(a, s, g, "POST", "/__webconsole/blikvm/logout", strings.NewReader(`{"csrf":"`+g.CSRF+`"}`))
	if logout.Code != 204 || !g.Manual {
		t.Fatal("native logout not recorded")
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := conn.ReadMessage(); err == nil {
		t.Fatal("native logout kept control connection open")
	}
	if auth := blikvmSession(&http.Client{Jar: g.Jar}, s); auth.Token != "" {
		t.Fatal("logout retained bearer credentials")
	}
	before := f.logins.Load()
	if got := blikvmDocument(a, s, g, "/"); got.Code != 200 || f.logins.Load() != before {
		t.Fatal("logout immediately restored login")
	}
	a.sessions.revokePortal(p.ID)
	if got := gatewayRequest(a, s, g, "GET", "/__webconsole/blikvm/bootstrap.js", nil); got.Code != 401 {
		t.Fatal("revoked portal still authorizes bridge")
	}
}

func TestBlikvmPublicBundleExport(t *testing.T) {
	if got, err := blikvmStoreExport([]byte(fakeBlikvmModule)); err != nil || got != "useStore" {
		t.Fatal("store export not detected")
	}
	if _, err := blikvmStoreExport([]byte(`const native=Bw("app",{});export{other as useStore};`)); err == nil {
		t.Fatal("incompatible bundle accepted")
	}
	// Optional check against the public bundle fetched from the actual device.
	if path := os.Getenv("WEBCONSOLE_BLI_PUBLIC_BUNDLE"); path != "" {
		code, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		export, err := blikvmStoreExport(code)
		if err != nil || !javascriptIdentifier.MatchString(export) {
			t.Fatal("actual BliKVM bundle incompatible", err)
		}
	}
	for _, module := range []string{"//elsewhere/main.js", "/assets/../main.js", "/assets/main.js?token=private", "https://device/main.js"} {
		if validBlikvmModule(module) {
			t.Fatal("invalid bundle path accepted")
		}
	}
}
