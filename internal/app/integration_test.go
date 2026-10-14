package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/gorilla/websocket"
)

type fakeOIDC struct {
	server                 *httptest.Server
	mu                     sync.Mutex
	codes                  map[string]map[string]string
	subject, nonceOverride string
	pkce                   atomic.Bool
	lastIDToken, lastCode  string
}

func newOIDC(t *testing.T) *fakeOIDC {
	return newOIDCWithOptions(t, oidcFixtureOptions{})
}

type oidcFixtureOptions struct {
	algorithm            jose.SignatureAlgorithm
	advertisedAlgorithms []string
	signingSecret        string
	claimOverrides       map[string]any
	missingIDToken       bool
	exchangeError        string
	jwksStatus           int
	tamperSignature      bool
	rawIDToken           string
}

func newOIDCWithOptions(t *testing.T, options oidcFixtureOptions) *fakeOIDC {
	t.Helper()
	if options.algorithm == "" {
		options.algorithm = jose.RS256
	}
	if options.advertisedAlgorithms == nil {
		options.advertisedAlgorithms = []string{string(options.algorithm)}
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var signingKey any = key
	if options.algorithm == jose.HS256 {
		signingKey = []byte(options.signingSecret)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: options.algorithm, Key: signingKey}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "test"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeOIDC{codes: map[string]map[string]string{}, subject: "owner"}
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			jsonReply(w, 200, map[string]any{"issuer": f.server.URL, "authorization_endpoint": f.server.URL + "/authorize", "token_endpoint": f.server.URL + "/token", "jwks_uri": f.server.URL + "/keys", "id_token_signing_alg_values_supported": options.advertisedAlgorithms})
		case "/keys":
			if options.jwksStatus != 0 {
				http.Error(w, "sensitive-upstream-body", options.jwksStatus)
				return
			}
			if options.algorithm == jose.HS256 {
				jsonReply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{}})
				return
			}
			jsonReply(w, 200, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &key.PublicKey, KeyID: "test", Algorithm: "RS256", Use: "sig"}}})
		case "/authorize":
			q := r.URL.Query()
			code := token()
			f.mu.Lock()
			f.codes[code] = map[string]string{"nonce": q.Get("nonce"), "challenge": q.Get("code_challenge")}
			f.lastCode = code
			f.mu.Unlock()
			target, _ := url.Parse(q.Get("redirect_uri"))
			params := url.Values{"code": {code}, "state": {q.Get("state")}}
			target.RawQuery = params.Encode()
			http.Redirect(w, r, target.String(), 302)
		case "/token":
			_ = r.ParseForm()
			if options.exchangeError != "" {
				jsonReply(w, 400, map[string]any{"error": options.exchangeError, "error_description": "sensitive-upstream-body"})
				return
			}
			f.mu.Lock()
			code, ok := f.codes[r.Form.Get("code")]
			delete(f.codes, r.Form.Get("code"))
			sub, nonceOverride := f.subject, f.nonceOverride
			f.mu.Unlock()
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != code["challenge"] {
				http.Error(w, "invalid verifier", 400)
				return
			}
			f.pkce.Store(true)
			nonce := code["nonce"]
			if nonceOverride != "" {
				nonce = nonceOverride
			}
			claims := map[string]any{"iss": f.server.URL, "aud": "webconsole", "sub": sub, "nonce": nonce, "name": "测试管理员", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Unix()}
			for name, value := range options.claimOverrides {
				claims[name] = value
			}
			payload, _ := json.Marshal(claims)
			signature, _ := signer.Sign(payload)
			jwt, _ := signature.CompactSerialize()
			if options.tamperSignature {
				parts := strings.Split(jwt, ".")
				decoded, _ := base64.RawURLEncoding.DecodeString(parts[2])
				decoded[0] ^= 1
				parts[2] = base64.RawURLEncoding.EncodeToString(decoded)
				jwt = strings.Join(parts, ".")
			}
			if options.rawIDToken != "" {
				jwt = options.rawIDToken
			}
			f.mu.Lock()
			f.lastIDToken = jwt
			f.mu.Unlock()
			response := map[string]any{"access_token": "sensitive-access-token", "token_type": "Bearer", "expires_in": 3600}
			if !options.missingIDToken {
				response["id_token"] = jwt
			}
			jsonReply(w, 200, response)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func testApp(t *testing.T) *App {
	t.Helper()
	issuer := newOIDC(t)
	cfg := Config{PortalURL: "http://console.localhost:8080", DeviceDomain: "console.localhost", Issuer: issuer.server.URL, ClientID: "webconsole", ClientSecret: "secret", AllowedSub: "owner", DataDir: t.TempDir(), WebRoot: t.TempDir(), Key: bytes.Repeat([]byte{1}, 32), DevHTTP: true, SessionTTL: time.Hour}
	a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	return a
}
func request(a *App, method, target string, body io.Reader, cookie *http.Cookie, csrf string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, target, body)
	r.Header.Set("Accept", "text/html")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if method != "GET" {
		r.Header.Set("Origin", a.cfg.PortalURL)
		r.Header.Set("X-CSRF-Token", csrf)
		r.Header.Set("Content-Type", "application/json")
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}
func owner(a *App) (*portalSession, *http.Cookie) {
	p := a.sessions.addPortal("owner", "Owner", time.Hour)
	return p, &http.Cookie{Name: "wc_portal", Value: p.ID}
}

func TestOIDCCodePKCEAndAccountRestriction(t *testing.T) {
	for _, tc := range []struct {
		name, subject, nonce string
		status               int
	}{{"owner", "owner", "", 303}, {"other user", "stranger", "", 403}, {"invalid nonce", "owner", "incorrect", 401}} {
		t.Run(tc.name, func(t *testing.T) {
			issuer := newOIDC(t)
			issuer.subject = tc.subject
			issuer.nonceOverride = tc.nonce
			cfg := Config{PortalURL: "http://console.localhost:8080", DeviceDomain: "console.localhost", Issuer: issuer.server.URL, ClientID: "webconsole", ClientSecret: "secret", AllowedSub: "owner", DataDir: t.TempDir(), Key: bytes.Repeat([]byte{1}, 32), DevHTTP: true, SessionTTL: time.Hour}
			a, err := New(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			start := request(a, "GET", cfg.PortalURL+"/auth/login", nil, nil, "")
			if start.Code != 302 {
				t.Fatal(start.Code)
			}
			browserCookie := start.Result().Cookies()[0]
			if browserCookie.Domain != "" || !browserCookie.HttpOnly {
				t.Fatal("unscoped transaction cookie")
			}
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Get(start.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			callback := resp.Header.Get("Location")
			got := request(a, "GET", callback, nil, browserCookie, "")
			if got.Code != tc.status {
				t.Fatalf("callback %d: %s", got.Code, got.Body.String())
			}
			if !issuer.pkce.Load() {
				t.Fatal("PKCE not checked")
			}
			if tc.status == 303 {
				var portal *http.Cookie
				for _, c := range got.Result().Cookies() {
					if c.Name == "wc_portal" {
						portal = c
					}
				}
				if portal == nil {
					t.Fatal("missing session")
				}
				me := request(a, "GET", cfg.PortalURL+"/api/me", nil, portal, "")
				if me.Code != 200 || strings.Contains(me.Body.String(), "access_token") {
					t.Fatal(me.Body.String())
				}
			}
			if again := request(a, "GET", callback, nil, browserCookie, ""); again.Code != 400 {
				t.Fatal("replayed callback accepted")
			}
		})
	}
}
func TestOIDCBrowserBinding(t *testing.T) {
	a := testApp(t)
	start := request(a, "GET", a.cfg.PortalURL+"/auth/login", nil, nil, "")
	target, _ := url.Parse(start.Header().Get("Location"))
	got := request(a, "GET", a.cfg.PortalURL+"/auth/callback?state="+target.Query().Get("state")+"&code=invalid", nil, &http.Cookie{Name: "wc_oidc", Value: "different-browser"}, "")
	if got.Code != 400 {
		t.Fatal("state accepted from another browser")
	}
}

func TestCredentialUpdateRevokesGateway(t *testing.T) {
	a := testApp(t)
	f := newPiKVM(t)
	s := addPi(t, a, f, "one")
	p, cookie := owner(a)
	g := enter(t, a, p, s)
	response := request(a, "PUT", a.cfg.PortalURL+"/api/services/"+s.ID+"/credentials", strings.NewReader(`{"username":"admin","password":"replacement-secret"}`), cookie, p.CSRF)
	if response.Code != 200 || !g.isClosed() || a.sessions.gateway(g.ID, s.ID) != nil {
		t.Fatal("credential change did not revoke gateway")
	}
	cred, err := a.store.Credentials(context.Background(), s.ID)
	if err != nil || cred.Password != "replacement-secret" {
		t.Fatal("credential change failed")
	}
	list := request(a, "GET", a.cfg.PortalURL+"/api/services", nil, cookie, "")
	if strings.Contains(list.Body.String(), "replacement-secret") {
		t.Fatal("credential leaked through list")
	}
}

func TestAPIAuthenticationCSRFAndWriteOnlyCredentials(t *testing.T) {
	a := testApp(t)
	p, cookie := owner(a)
	if request(a, "GET", a.cfg.PortalURL+"/api/services", nil, nil, "").Code != 401 {
		t.Fatal("unprotected list")
	}
	data := `{"name":"KVM","slug":"kvm","type":"pikvm","upstreamUrl":"http://127.0.0.1:1234","entryPath":"/kvm/","group":"Rack","notes":"","credentials":{"username":"admin","password":"unique-secret"}}`
	if request(a, "POST", a.cfg.PortalURL+"/api/services", strings.NewReader(data), cookie, "").Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	saved := request(a, "POST", a.cfg.PortalURL+"/api/services", strings.NewReader(data), cookie, p.CSRF)
	if saved.Code != 201 {
		t.Fatal(saved.Code, saved.Body.String())
	}
	if strings.Contains(saved.Body.String(), "unique-secret") {
		t.Fatal("password reflected")
	}
	var s Service
	_ = json.Unmarshal(saved.Body.Bytes(), &s)
	if !s.HasCredentials {
		t.Fatal("credentials not persisted atomically")
	}
	if request(a, "GET", a.cfg.PortalURL+"/api/services/"+s.ID+"/credentials", nil, cookie, "").Code != 405 {
		t.Fatal("credentials readable")
	}
	r := httptest.NewRequest("POST", a.cfg.PortalURL+"/api/services/"+s.ID+"/launch", nil)
	r.AddCookie(cookie)
	r.Header.Set("Origin", "http://kvm.console.localhost:8080")
	r.Header.Set("X-CSRF-Token", p.CSRF)
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("sibling origin accepted")
	}
}

type fakePiKVM struct {
	server     *httptest.Server
	loginCount atomic.Int32
	generation atomic.Int32
	posts      atomic.Int32
	leaked     atomic.Bool
	requestMu  sync.Mutex
	lastCookie string
}

func newPiKVM(t *testing.T) *fakePiKVM {
	f := &fakePiKVM{}
	f.generation.Store(1)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			if internalCookie(c.Name) {
				f.leaked.Store(true)
			}
		}
		if r.URL.Path == "/api/auth/login" {
			f.loginCount.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("passwd") != "password" {
				http.Error(w, "wrong", 403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "auth_token", Value: fmt.Sprint(f.generation.Load()), Path: "/"})
			jsonReply(w, 200, map[string]bool{"ok": true})
			return
		}
		if r.URL.Path == "/api/auth/logout" {
			http.SetCookie(w, &http.Cookie{Name: "auth_token", Path: "/", MaxAge: -1})
			w.WriteHeader(200)
			return
		}
		cookie, err := r.Cookie("auth_token")
		valid := err == nil && cookie.Value == fmt.Sprint(f.generation.Load())
		if r.Method == "POST" {
			f.posts.Add(1)
		}
		if !valid {
			http.Error(w, "expired", 401)
			return
		}
		f.requestMu.Lock()
		f.lastCookie = r.Header.Get("Cookie")
		f.requestMu.Unlock()
		switch r.URL.Path {
		case "/api/ws":
			conn, err := (&websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}).Upgrade(w, r, nil)
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				kind, msg, err := conn.ReadMessage()
				if err != nil {
					return
				}
				if conn.WriteMessage(kind, msg) != nil {
					return
				}
			}
		case "/stream":
			w.Header().Set("Content-Type", "multipart/x-mixed-replace; boundary=frame")
			_, _ = io.WriteString(w, "--frame\r\nfirst-frame\r\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		case "/redirect":
			w.Header().Set("Location", f.server.URL+"/kvm/")
			w.WriteHeader(302)
		case "/api/upload":
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
		default:
			_, _ = io.WriteString(w, "device-page")
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func addPi(t *testing.T, a *App, f *fakePiKVM, slug string) Service {
	t.Helper()
	s := Service{ID: token(), Name: slug, Slug: slug, Type: "pikvm", UpstreamURL: f.server.URL, EntryPath: "/kvm/"}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"admin", "password"}); err != nil {
		t.Fatal(err)
	}
	return s
}
func enter(t *testing.T, a *App, p *portalSession, s Service) *gatewaySession {
	t.Helper()
	ticket := a.sessions.ticket(p, s.ID)
	got := request(a, "GET", a.cfg.deviceOrigin(s.Slug)+"/__webconsole/start?ticket="+ticket, nil, nil, "")
	if got.Code != 303 {
		t.Fatal(got.Code, got.Body.String())
	}
	for _, c := range got.Result().Cookies() {
		if c.Name == "wc_gateway" {
			return a.sessions.gateway(c.Value, s.ID)
		}
	}
	t.Fatal("missing gateway session")
	return nil
}
func gatewayRequest(a *App, s Service, g *gatewaySession, method, path string, body io.Reader) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, a.cfg.deviceOrigin(s.Slug)+path, body)
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	r.AddCookie(&http.Cookie{Name: "wc_portal", Value: "must-not-leak"})
	if method != "GET" {
		r.Header.Set("Origin", a.cfg.deviceOrigin(s.Slug))
	}
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	return w
}

func TestGatewayTicketIsolationRefreshAndNoUnsafeReplay(t *testing.T) {
	a := testApp(t)
	f := newPiKVM(t)
	s := addPi(t, a, f, "one")
	p, _ := owner(a)
	ticket := a.sessions.ticket(p, s.ID)
	if a.sessions.redeem(ticket, "other") != nil {
		t.Fatal("cross-device ticket accepted")
	}
	g := a.sessions.redeem(ticket, s.ID)
	if g == nil || a.sessions.redeem(ticket, s.ID) != nil {
		t.Fatal("ticket not single-use")
	}
	if err := a.ensureLogin(context.Background(), s, g, nil); err != nil {
		t.Fatal(err)
	}
	if f.loginCount.Load() != 1 {
		t.Fatal("initial login")
	}
	if got := gatewayRequest(a, s, g, "GET", "/kvm/", nil); got.Code != 200 || got.Body.String() != "device-page" {
		t.Fatal(got.Code, got.Body.String())
	}
	if f.leaked.Load() {
		t.Fatal("portal cookie forwarded")
	}
	f.generation.Store(2)
	before := f.loginCount.Load()
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got := gatewayRequest(a, s, g, "GET", "/api/info", nil)
			if got.Code != 200 {
				t.Errorf("refresh: %d %s", got.Code, got.Body.String())
			}
		}()
	}
	wg.Wait()
	if f.loginCount.Load() != before+1 {
		t.Fatalf("refresh was not coalesced: %d", f.loginCount.Load())
	}
	f.generation.Store(3)
	before = f.loginCount.Load()
	got := gatewayRequest(a, s, g, "POST", "/api/upload", strings.NewReader("firmware"))
	if got.Code != 401 || f.posts.Load() != 1 || f.loginCount.Load() != before {
		t.Fatal("unsafe request replayed or auto logged in")
	}
	got = gatewayRequest(a, s, g, "GET", "/api/info", nil)
	if got.Code != 200 {
		t.Fatal("read did not recover")
	}
	got = gatewayRequest(a, s, g, "POST", "/api/upload", strings.NewReader("payload-unchanged"))
	if got.Code != 200 || got.Body.String() != "payload-unchanged" {
		t.Fatal("upload corrupted")
	}
	got = gatewayRequest(a, s, g, "GET", "/redirect", nil)
	if got.Header().Get("Location") != a.cfg.deviceOrigin(s.Slug)+"/kvm/" {
		t.Fatal("redirect leaked upstream host")
	}
	other := addPi(t, a, f, "two")
	if a.sessions.gateway(g.ID, other.ID) != nil {
		t.Fatal("gateway cookie accepted for other device")
	}
	a.sessions.revokePortal(p.ID)
	if !g.isClosed() || a.sessions.gateway(g.ID, s.ID) != nil {
		t.Fatal("logout did not revoke")
	}
}
func TestDirectDeviceAndUnknownHost(t *testing.T) {
	a := testApp(t)
	s := addPi(t, a, newPiKVM(t), "one")
	got := request(a, "GET", a.cfg.deviceOrigin(s.Slug)+"/kvm/", nil, nil, "")
	if got.Code != 302 || !strings.HasPrefix(got.Header().Get("Location"), a.cfg.PortalURL+"/auth/launch") {
		t.Fatal("direct navigation did not authenticate")
	}
	if request(a, "GET", "http://unknown.example/api/services", nil, nil, "").Code != 404 {
		t.Fatal("unknown host served")
	}
	if request(a, "GET", a.cfg.deviceOrigin(s.Slug)+"/healthz", nil, nil, "").Code == 200 {
		t.Fatal("device path bypassed gateway authorization")
	}
	for _, dest := range []string{"image", "script", "empty"} {
		r := httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/kvm/", nil)
		r.Header.Set("Sec-Fetch-Dest", dest)
		w := httptest.NewRecorder()
		a.ServeHTTP(w, r)
		if w.Code != 401 || w.Header().Get("Location") != "" {
			t.Fatal("background resource restarted SSO", dest)
		}
	}
}
func TestBadPasswordStopsRetryAndManualFallback(t *testing.T) {
	a := testApp(t)
	f := newPiKVM(t)
	s := addPi(t, a, f, "one")
	_ = a.store.SetCredentials(context.Background(), s.ID, Credentials{"admin", "wrong"})
	p, _ := owner(a)
	g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
	for range 3 {
		if a.ensureLogin(context.Background(), s, g, nil) == nil {
			t.Fatal("wrong password accepted")
		}
	}
	if f.loginCount.Load() != 1 {
		t.Fatal("repeated failing login")
	}
	r := httptest.NewRequest("POST", a.cfg.deviceOrigin(s.Slug)+"/__webconsole/manual", strings.NewReader(url.Values{"csrf": {g.CSRF}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", a.cfg.deviceOrigin(s.Slug))
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if w.Code != 303 || !g.Manual {
		t.Fatal("manual fallback failed")
	}
}

func TestWebSocketAndStreamClosedOnLogout(t *testing.T) {
	a := testApp(t)
	f := newPiKVM(t)
	s := addPi(t, a, f, "one")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	server := httptest.NewServer(a)
	defer server.Close()
	proxyURL, _ := url.Parse(server.URL)
	dialer := websocket.Dialer{NetDialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, proxyURL.Host)
	}}
	header := http.Header{"Cookie": []string{"wc_gateway=" + g.ID}, "Origin": []string{a.cfg.deviceOrigin(s.Slug)}}
	ws, resp, err := dialer.Dial(strings.Replace(a.cfg.deviceOrigin(s.Slug), "http://", "ws://", 1)+"/api/ws", header)
	if err != nil {
		if resp != nil {
			t.Log(resp.Status)
		}
		t.Fatal(err)
	}
	defer ws.Close()
	if err = ws.WriteMessage(websocket.TextMessage, []byte("keyboard")); err != nil {
		t.Fatal(err)
	}
	_, body, err := ws.ReadMessage()
	if err != nil || string(body) != "keyboard" {
		t.Fatal("websocket did not pass through", err)
	}
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, proxyURL.Host)
	}}}
	req, _ := http.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/stream", nil)
	req.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	stream, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Body.Close()
	frame := make([]byte, len("--frame\r\nfirst-frame\r\n"))
	if _, err = io.ReadFull(stream.Body, frame); err != nil {
		t.Fatal(err)
	}
	logout := request(a, "POST", a.cfg.PortalURL+"/api/logout", nil, &http.Cookie{Name: "wc_portal", Value: p.ID}, p.CSRF)
	if logout.Code != 200 {
		t.Fatal("logout failed", logout.Code)
	}
	_ = ws.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err = ws.ReadMessage(); err == nil {
		t.Fatal("websocket stayed open")
	}
	done := make(chan error, 1)
	go func() { _, err := io.ReadAll(stream.Body); done <- err }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP stream stayed open")
	}
}
