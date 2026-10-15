package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type fakeGlinet struct {
	server     *httptest.Server
	generation atomic.Int32
	logins     atomic.Int32
	actions    atomic.Int32
	logouts    atomic.Int32
	mode       atomic.Int32 // 1: MFA, 2: uninitialized, 3: unknown protocol, 4: rate limit
}

func (f *fakeGlinet) token() string {
	return fmt.Sprintf("glkvm_session_token_generation_%d", f.generation.Load())
}

func newGlinet(t *testing.T) *fakeGlinet {
	t.Helper()
	f := &fakeGlinet{}
	f.generation.Store(1)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, cookie := range r.Cookies() {
			if internalCookie(cookie.Name) || cookie.Value == nativeBrowserMarker {
				t.Error("gateway credential or browser marker reached GLKVM")
			}
		}
		if r.Header.Get("token") == nativeBrowserMarker || r.URL.Query().Get("auth_token") == nativeBrowserMarker {
			t.Error("browser auth marker was not replaced")
		}
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!doctype html><html><head><script type="module" src="/assets/main.js"></script></head><body><div id="app"></div></body></html>`)
			return
		case "/api/init/is_inited":
			jsonReply(w, 200, map[string]any{"ok": true, "result": map[string]any{"is_inited": f.mode.Load() != 2, "country_code": "CN"}})
			return
		case "/api/2fa/is_enabled":
			if f.mode.Load() == 3 {
				jsonReply(w, 200, map[string]any{"ok": true, "result": map[string]any{"unknown": false}})
			} else {
				jsonReply(w, 200, map[string]any{"ok": true, "result": map[string]any{"enabled": f.mode.Load() == 1}})
			}
			return
		case "/api/auth/login":
			f.logins.Add(1)
			if r.Method != "POST" || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("GLKVM login did not use the native form protocol")
			}
			if f.mode.Load() == 4 {
				jsonReply(w, 429, map[string]any{"ok": false, "result": map[string]int{"remaining_time": 300}})
				return
			}
			password := "password"
			if f.mode.Load() == 1 {
				password += "123456"
			}
			if r.FormValue("user") != "admin" || r.FormValue("passwd") != password {
				jsonReply(w, 403, map[string]any{"ok": false, "result": map[string]string{"error": "ForbiddenError"}})
				return
			}
			if f.mode.Load() == 1 {
				http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: f.token(), Path: "/", HttpOnly: true})
			}
			jsonReply(w, 200, map[string]any{"ok": true, "result": map[string]string{"token": f.token(), "extra": "preserved"}})
			return
		}
		if r.Method == "POST" || r.URL.Path == "/api/upgrade/reboot" || r.URL.Path == "/api/unknown_action" {
			f.actions.Add(1)
		}
		cookie, cookieErr := r.Cookie("auth_token")
		if r.Header.Get("token") != f.token() || cookieErr != nil || cookie.Value != f.token() {
			jsonReply(w, 401, map[string]any{"ok": false, "result": map[string]string{"error": "UnauthorizedError"}})
			return
		}
		switch r.URL.Path {
		case "/ws", "/api/ws", "/janus/ws":
			cookie, err := r.Cookie("auth_token")
			if err != nil || cookie.Value != f.token() || r.URL.Query().Get("auth_token") != f.token() || r.URL.Query().Get("extra") != "kept" {
				t.Error("native WebSocket query/cookie authentication missing")
			}
			conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				kind, data, err := conn.ReadMessage()
				if err != nil || conn.WriteMessage(kind, data) != nil {
					return
				}
			}
		case "/api/auth/logout":
			f.logouts.Add(1)
		case "/api/forbidden":
			w.WriteHeader(403)
			return
		case "/api/msd/read":
			if r.URL.Query().Get("auth_token") != f.token() {
				t.Error("native download query authentication missing")
			}
		}
		jsonReply(w, 200, map[string]any{"ok": true, "result": map[string]string{"user": "admin"}})
	}))
	t.Cleanup(f.server.Close)
	return f
}

func addGlinet(t *testing.T, a *App, f *fakeGlinet, slug string) Service {
	t.Helper()
	s := Service{ID: token(), Name: slug, Slug: slug, Type: "glinet", UpstreamURL: f.server.URL}
	if err := validateService(&s, a.cfg); err != nil {
		t.Fatal(err)
	}
	if s.EntryPath != "/#/" {
		t.Fatal("wrong GLKVM default entry")
	}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"admin", "password"}); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGlinetSessionRecoveryAndControlRequests(t *testing.T) {
	a, f := testApp(t), newGlinet(t)
	s := addGlinet(t, a, f, "glkvm")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	other := addGlinet(t, a, newGlinet(t), "other")
	if gatewayRequest(a, other, g, "GET", "/api/info", nil).Code != 401 {
		t.Fatal("cross-device gateway accepted")
	}
	f.generation.Add(1)
	before := f.logins.Load()
	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			if got := gatewayRequest(a, s, g, "GET", "/api/info", nil); got.Code != 200 {
				t.Errorf("session recovery failed: %d", got.Code)
			}
		})
	}
	wg.Wait()
	if f.logins.Load() != before+1 {
		t.Fatal("concurrent session recovery submitted multiple passwords")
	}
	for _, tc := range []struct{ method, path string }{{"POST", "/api/atx/click"}, {"GET", "/api/upgrade/reboot"}, {"GET", "/api/unknown_action"}} {
		f.generation.Add(1)
		before, actions := f.logins.Load(), f.actions.Load()
		got := gatewayRequest(a, s, g, tc.method, tc.path, nil)
		if got.Code != 401 || got.Header().Get("X-WebConsole-Session-Expired") != "true" || f.logins.Load() != before || f.actions.Load() != actions+1 {
			t.Fatal("control or unknown GET was automatically replayed", tc)
		}
		if page := blikvmDocument(a, s, g, "/"); page.Code != 200 || f.logins.Load() != before+1 {
			t.Fatal("page reload failed to restore GLKVM session")
		}
	}
	before = f.logins.Load()
	if got := gatewayRequest(a, s, g, "GET", "/api/forbidden", nil); got.Code != 403 || f.logins.Load() != before {
		t.Fatal("permission failure replayed credentials")
	}
	for _, path := range []string{"/api/auth/check", "/api/msd/read?auth_token=webconsole-session"} {
		if got := gatewayRequest(a, s, g, "GET", path, nil); got.Code != 200 {
			t.Fatal("native check/download failed", path)
		}
	}
}

func TestGlinetPreflightAndLoginFailures(t *testing.T) {
	a, f := testApp(t), newGlinet(t)
	s := addGlinet(t, a, f, "glkvm")
	p, _ := owner(a)
	for _, tc := range []struct {
		mode int32
		want error
	}{{1, errGLInteractive}, {2, nil}, {3, errGLProtocol}, {4, errGLRateLimit}} {
		f.mode.Store(tc.mode)
		g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
		before := f.logins.Load()
		err := a.ensureLogin(context.Background(), s, g, nil)
		if err == nil || tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatal("wrong preflight/login error", tc.mode, err)
		}
		if tc.mode != 4 && f.logins.Load() != before {
			t.Fatal("password submitted before preflight succeeded")
		}
		if tc.mode == 4 {
			_ = a.ensureLogin(context.Background(), s, g, nil)
			if f.logins.Load() != before+1 || time.Until(g.RetryAfter) < 4*time.Minute {
				t.Fatal("rate limit did not pause automatic attempts")
			}
		}
	}
	f.mode.Store(0)
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"admin", "wrong"}); err != nil {
		t.Fatal(err)
	}
	g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
	if err := a.ensureLogin(context.Background(), s, g, nil); !errors.Is(err, errLogin) {
		t.Fatal("wrong password was accepted", err)
	}
	before := f.logins.Load()
	_ = a.ensureLogin(context.Background(), s, g, nil)
	if f.logins.Load() != before {
		t.Fatal("wrong password was immediately retried")
	}
}

func TestGlinetManualMFAAndLogout(t *testing.T) {
	a, f := testApp(t), newGlinet(t)
	s := addGlinet(t, a, f, "glkvm")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	f.mode.Store(1)
	manual := blikvmSubmit(a, s, g, "/__webconsole/manual", url.Values{"csrf": {g.CSRF}}.Encode(), "application/x-www-form-urlencoded")
	if manual.Code != 303 || nativeSession(&http.Client{Jar: g.Jar}, s).Token != "" {
		t.Fatal("switching to manual mode retained credentials")
	}
	if page := blikvmDocument(a, s, g, "/"); page.Code != 200 {
		t.Fatal("manual page was blocked by MFA")
	}
	got := blikvmSubmit(a, s, g, "/api/auth/login", url.Values{"user": {"admin"}, "passwd": {"password123456"}}.Encode(), "application/x-www-form-urlencoded")
	if got.Code != 200 || strings.Contains(got.Body.String(), f.token()) || !strings.Contains(got.Body.String(), nativeBrowserMarker) || !strings.Contains(got.Body.String(), "preserved") {
		t.Fatal("manual MFA login was not captured/masked")
	}
	for _, cookie := range got.Result().Cookies() {
		if cookie.Name == "auth_token" && cookie.Value != nativeBrowserMarker {
			t.Fatal("real GLKVM cookie exposed")
		}
	}
	if got := gatewayRequest(a, s, g, "GET", "/api/auth/check", nil); got.Code != 200 {
		t.Fatal("manual session was not usable")
	}
	before := f.logins.Load()
	if got := gatewayRequest(a, s, g, "POST", "/api/auth/logout", nil); got.Code != 200 || f.logouts.Load() != 1 {
		t.Fatal("native logout was not forwarded")
	}
	if page := blikvmDocument(a, s, g, "/"); page.Code != 200 || f.logins.Load() != before || nativeSession(&http.Client{Jar: g.Jar}, s).Token != "" {
		t.Fatal("logout caused an automatic login")
	}
	stage, err := checkDeviceConnection(context.Background(), s, func() (Credentials, error) { return Credentials{"admin", "password"}, nil })
	if stage != "login" || !errors.Is(err, errGLInteractive) || f.logouts.Load() != 1 {
		t.Fatal("connection test ignored MFA or changed another session")
	}
}

func TestGlinetWebSocketsAndRevocation(t *testing.T) {
	a, f := testApp(t), newGlinet(t)
	s := addGlinet(t, a, f, "glkvm")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	f.generation.Add(1)
	before := f.logins.Load()
	server := httptest.NewServer(a)
	defer server.Close()
	for _, path := range []string{"/api/ws", "/janus/ws"} {
		header := http.Header{"Host": {strings.TrimPrefix(a.cfg.deviceOrigin(s.Slug), "http://")}, "Origin": {a.cfg.deviceOrigin(s.Slug)}, "Cookie": {"wc_gateway=" + g.ID + "; auth_token=" + nativeBrowserMarker}, "token": {nativeBrowserMarker}}
		conn, resp, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http")+path+"?auth_token="+nativeBrowserMarker+"&extra=kept", header)
		if err != nil {
			t.Fatal("GLKVM WebSocket failed", err, resp)
		}
		if err := conn.WriteMessage(websocket.TextMessage, []byte("native-event")); err != nil {
			t.Fatal(err)
		}
		_, data, err := conn.ReadMessage()
		if err != nil || string(data) != "native-event" {
			t.Fatal("native WebSocket data was not forwarded")
		}
		if f.logins.Load() != before+1 {
			t.Fatal("expired WebSocket handshake did not recover the session once")
		}
		if path == "/janus/ws" {
			a.sessions.revokeDevice(s.ID)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, _, err := conn.ReadMessage(); err == nil {
				t.Fatal("revoked gateway kept a live WebSocket")
			}
		}
		_ = conn.Close()
	}
}

func TestGlinetBridgeBrowserFixture(t *testing.T) {
	a, f := testApp(t), newGlinet(t)
	s := addGlinet(t, a, f, "glkvm")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	page := blikvmDocument(a, s, g, "/")
	bootstrap := gatewayRequest(a, s, g, "GET", "/__webconsole/native/bootstrap.js", nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "/__webconsole/native/bootstrap.js") || bootstrap.Code != 200 {
		t.Fatal("native bootstrap was not injected")
	}
	if strings.Contains(page.Body.String()+bootstrap.Body.String()+page.Header().Get("Set-Cookie"), f.token()) {
		t.Fatal("real GLKVM token was published")
	}
	if path := os.Getenv("WEBCONSOLE_GL_BROWSER_FIXTURE"); path != "" {
		b, _ := json.Marshal(map[string]string{"html": page.Body.String(), "bootstrap": bootstrap.Body.String()})
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := f.logouts.Load()
	if _, err := checkDeviceConnection(context.Background(), s, func() (Credentials, error) { return Credentials{"admin", "password"}, nil }); err != nil || f.logouts.Load() != before {
		t.Fatal("connection test logged out another native session", err)
	}
}
