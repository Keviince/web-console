package app

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
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

type fakeNano struct {
	server      *httptest.Server
	generation  atomic.Int32
	logins      atomic.Int32
	logouts     atomic.Int32
	posts       atomic.Int32
	legacy      bool
	direct2FA   atomic.Bool
	requires2FA atomic.Bool
	limited     atomic.Bool
}

func newNano(t *testing.T, legacy bool) *fakeNano {
	t.Helper()
	f := &fakeNano{legacy: legacy}
	f.generation.Store(1)
	f.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tok := fmt.Sprintf("header.%d.signature", f.generation.Load())
		if r.URL.Path == "/api/auth/login/2fa-direct" {
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]bool{"enabled": f.direct2FA.Load()}})
			return
		}
		if r.URL.Path == "/api/auth/login" {
			f.logins.Add(1)
			if r.Header.Get("Content-Type") != "application/json" {
				t.Error("NanoKVM login must use JSON")
			}
			var cred Credentials
			if json.NewDecoder(r.Body).Decode(&cred) != nil || cred.Username != "admin" || cred.Password != "password" {
				jsonReply(w, 200, map[string]any{"code": -2, "msg": "invalid user"})
				return
			}
			if f.limited.Load() {
				jsonReply(w, 200, map[string]any{"code": -5, "data": map[string]any{"rateLimited": true, "retryAfter": 180}})
				return
			}
			if f.requires2FA.Load() {
				jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]any{"requires2FA": true, "challenge": "private-otp-challenge"}})
				return
			}
			if f.legacy {
				jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"token": tok}})
			} else {
				http.SetCookie(w, &http.Cookie{Name: "nano-kvm-session", Value: tok, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
				jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"token": "cookie"}})
			}
			return
		}
		// The original SPA shell is public, even after authentication expires.
		if r.URL.Path == "/" {
			_, _ = io.WriteString(w, "<html>NanoKVM hash router</html>")
			return
		}
		cookieName := "nano-kvm-session"
		if f.legacy {
			cookieName = "nano-kvm-token"
		}
		cookie, err := r.Cookie(cookieName)
		if r.Method == "POST" {
			f.posts.Add(1)
		}
		if err != nil || cookie.Value != tok {
			http.Error(w, `"unauthorized"`, 401)
			return
		}
		switch r.URL.Path {
		case "/api/auth/account":
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"username": "admin"}})
		case "/api/auth/logout":
			f.logouts.Add(1)
			f.generation.Add(1)
			http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1})
			jsonReply(w, 200, map[string]any{"code": 0})
		case "/api/ws":
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
		default:
			jsonReply(w, 200, map[string]any{"code": 0, "data": map[string]string{"value": "native"}})
		}
	}))
	t.Cleanup(f.server.Close)
	return f
}
func addNano(t *testing.T, a *App, f *fakeNano, slug string) Service {
	t.Helper()
	s := Service{ID: token(), Name: slug, Slug: slug, Type: "nanokvm", UpstreamURL: f.server.URL}
	if err := validateService(&s, a.cfg); err != nil {
		t.Fatal(err)
	}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"admin", "password"}); err != nil {
		t.Fatal(err)
	}
	return s
}
func TestNanoLoginCookieAndLegacyTokenRenewal(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			a := testApp(t)
			f := newNano(t, legacy)
			s := addNano(t, a, f, "nano")
			p, _ := owner(a)
			if s.EntryPath != "/#/" {
				t.Fatal("wrong NanoKVM entry")
			}
			start := request(a, "GET", a.cfg.deviceOrigin(s.Slug)+"/__webconsole/start?ticket="+a.sessions.ticket(p, s.ID), nil, nil, "")
			if start.Code != 303 {
				t.Fatal(start.Code, start.Body.String())
			}
			var g *gatewaySession
			marker := false
			for _, c := range start.Result().Cookies() {
				if c.Name == "wc_gateway" {
					g = a.sessions.gateway(c.Value, s.ID)
				}
				if c.Name == "nano-kvm-auth" {
					marker = c.Value == "1" && !c.HttpOnly && c.Domain == ""
				}
				if strings.Contains(c.Value, "signature") {
					t.Fatal("auto-login JWT published to browser")
				}
			}
			if g == nil || !marker {
				t.Fatal("missing session or readable non-secret marker")
			}
			f.generation.Add(1)
			before := f.logins.Load()
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() {
					defer wg.Done()
					if got := gatewayRequest(a, s, g, "GET", "/api/auth/account", nil); got.Code != 200 {
						t.Errorf("refresh failed: %d", got.Code)
					}
				}()
			}
			wg.Wait()
			if f.logins.Load() != before+1 {
				t.Fatal("NanoKVM refresh was not coalesced")
			}
			f.generation.Add(1)
			before = f.logins.Load()
			got := gatewayRequest(a, s, g, "POST", "/api/vm/gpio", strings.NewReader(`{"type":"power"}`))
			if got.Code != 401 || f.logins.Load() != before || f.posts.Load() != 1 {
				t.Fatal("power request was replayed")
			}
			// A public SPA reload must check the account and restore the marker.
			r := httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/", nil)
			r.Header.Set("Sec-Fetch-Dest", "document")
			r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != 200 || f.logins.Load() != before+1 {
				t.Fatal("hash-router reload did not recover")
			}
			if !strings.Contains(w.Header().Get("Set-Cookie"), "nano-kvm-auth=1") {
				t.Fatal("marker not restored")
			}
		})
	}
}
func TestNanoMFAAndRateLimit(t *testing.T) {
	for _, mode := range []string{"direct", "challenge", "limited", "wrong password"} {
		t.Run(mode, func(t *testing.T) {
			a := testApp(t)
			f := newNano(t, false)
			f.direct2FA.Store(mode == "direct")
			f.requires2FA.Store(mode == "challenge")
			f.limited.Store(mode == "limited")
			s := addNano(t, a, f, "nano")
			p, _ := owner(a)
			g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
			if mode == "wrong password" {
				_ = a.store.SetCredentials(context.Background(), s.ID, Credentials{"admin", "wrong"})
			}
			err := a.ensureLogin(context.Background(), s, g, nil)
			if err == nil {
				t.Fatal("interactive or denied login accepted")
			}
			for range 3 {
				_ = a.ensureLogin(context.Background(), s, g, nil)
			}
			if mode == "direct" {
				if f.logins.Load() != 0 || !errors.Is(err, errNanoInteractive) {
					t.Fatal("password submitted in direct OTP mode")
				}
			} else if f.logins.Load() != 1 {
				t.Fatal("repeated failing password submission")
			}
			if mode == "limited" && time.Until(g.RetryAfter) < 170*time.Second {
				t.Fatal("server lockout ignored")
			}
		})
	}
}
func TestNanoTestAndPortalLogoutDoNotRevokeOtherDeviceSessions(t *testing.T) {
	a := testApp(t)
	f := newNano(t, false)
	s := addNano(t, a, f, "nano")
	p, cookie := owner(a)
	g := enter(t, a, p, s)
	got := request(a, "POST", a.cfg.PortalURL+"/api/services/"+s.ID+"/test", nil, cookie, p.CSRF)
	if got.Code != 200 {
		t.Fatal(got.Code, got.Body.String())
	}
	if f.logouts.Load() != 0 || gatewayRequest(a, s, g, "GET", "/api/auth/account", nil).Code != 200 {
		t.Fatal("connection test logged out an existing session")
	}
	got = request(a, "POST", a.cfg.PortalURL+"/api/logout", nil, cookie, p.CSRF)
	if got.Code != 200 || !g.isClosed() {
		t.Fatal("gateway not revoked")
	}
	if f.logouts.Load() != 0 {
		t.Fatal("portal logout invoked global device logout")
	}
}
func TestNanoOriginalLogoutStopsAutomaticLogin(t *testing.T) {
	a := testApp(t)
	f := newNano(t, false)
	s := addNano(t, a, f, "nano")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	got := gatewayRequest(a, s, g, "POST", "/api/auth/logout", nil)
	if got.Code != 200 {
		t.Fatal(got.Code)
	}
	before := f.logins.Load()
	r := httptest.NewRequest("GET", a.cfg.deviceOrigin(s.Slug)+"/", nil)
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	r.Header.Set("Sec-Fetch-Dest", "document")
	w := httptest.NewRecorder()
	a.ServeHTTP(w, r)
	if !g.Manual || f.logins.Load() != before || strings.Contains(w.Header().Get("Set-Cookie"), "nano-kvm-auth=1") {
		t.Fatal("device logout was immediately undone")
	}
}

func bareCertificate(t *testing.T, expired bool) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	end := time.Now().Add(time.Hour)
	if expired {
		end = time.Now().Add(-time.Hour)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "localhost"}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: end, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, cert
}
func TestCertificatePinWithoutSAN(t *testing.T) {
	for _, mode := range []string{"correct", "wrong", "expired", "default"} {
		t.Run(mode, func(t *testing.T) {
			cert, leaf := bareCertificate(t, mode == "expired")
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
			server.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
			server.StartTLS()
			defer server.Close()
			hash := sha256.Sum256(leaf.Raw)
			s := Service{UpstreamURL: server.URL, CertificatePin: hex.EncodeToString(hash[:])}
			if mode == "wrong" {
				s.CertificatePin = strings.Repeat("00", 32)
			}
			if mode == "default" {
				s.CertificatePin = ""
			}
			transport, err := newTransport(s)
			if err != nil {
				t.Fatal(err)
			}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
			resp, err := client.Get(server.URL)
			if mode == "correct" {
				if err != nil {
					t.Fatal(err)
				}
				finish(resp)
			} else if err == nil {
				finish(resp)
				t.Fatal("invalid certificate accepted")
			}
			if mode == "wrong" && !errors.Is(err, errCertificatePin) {
				t.Fatal("pin mismatch not detected")
			}
			if mode == "expired" && !errors.Is(err, errPinnedCertificateTime) {
				t.Fatal("expired pin accepted")
			}
		})
	}
}
func TestPinValidationAndCacheInvalidation(t *testing.T) {
	cfg := Config{PortalURL: "https://control.example.com", DeviceDomain: "devices.example.com"}
	for _, pin := range []string{"ignore", "00", strings.Repeat("z", 64)} {
		s := Service{Name: "nano", Slug: "nano", Type: "nanokvm", UpstreamURL: "https://192.168.1.11", CertificatePin: pin}
		if validateService(&s, cfg) == nil {
			t.Fatal("invalid pin accepted")
		}
	}
	a := testApp(t)
	s := Service{ID: "nano", UpstreamURL: "https://192.168.1.11", CertificatePin: strings.Repeat("01", 32)}
	first, err := a.proxyTransport(s)
	if err != nil {
		t.Fatal(err)
	}
	s.CertificatePin = strings.Repeat("02", 32)
	second, err := a.proxyTransport(s)
	if err != nil || first == second {
		t.Fatal("certificate pin change reused old transport")
	}
}
func TestLiveNanoReadOnly(t *testing.T) {
	raw := os.Getenv("WEBCONSOLE_LIVE_NANO_URL")
	pin := os.Getenv("WEBCONSOLE_LIVE_NANO_PIN")
	if raw == "" || pin == "" {
		t.Skip("optional live read-only check requires URL and certificate pin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Hostname() == "" {
		t.Fatal("invalid live URL")
	}
	transport, err := newTransport(Service{UpstreamURL: raw, CertificatePin: pin})
	if err != nil {
		t.Fatal(err)
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(strings.TrimRight(raw, "/") + "/api/auth/account")
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 401 {
		finish(resp)
		t.Fatal("unexpected unauthenticated account response")
	}
	finish(resp)
	resp, err = client.Get(strings.TrimRight(raw, "/") + "/api/auth/login/2fa-direct")
	if err != nil {
		t.Fatal(err)
	}
	data, err := nanoRead(resp)
	if err != nil || *data.Code != 0 {
		t.Fatal("login-mode read failed", err)
	}
}
