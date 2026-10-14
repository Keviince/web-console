package app

import (
	"context"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestLuCIOriginalFormHiddenFieldsCookiePathAndRenewal(t *testing.T) {
	var generation, logins atomic.Int32
	generation.Store(1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/cgi-bin/luci/admin/logout" {
			http.SetCookie(w, &http.Cookie{Name: "sysauth_http", Path: "/cgi-bin/luci/", MaxAge: -1})
			w.WriteHeader(200)
			return
		}
		cookie, err := r.Cookie("sysauth_http")
		if err == nil && cookie.Value == string(rune('0'+generation.Load())) {
			_, _ = io.WriteString(w, `<html><script>window.env={token:"native-csrf-token"}</script>router-state</html>`)
			return
		}
		if r.Method == "POST" {
			logins.Add(1)
			_ = r.ParseForm()
			if r.Form.Get("luci_username") != "root" || r.Form.Get("luci_password") != "password" || r.Form.Get("csrf") != "hidden-value" {
				t.Errorf("original form fields not preserved: username=%s", r.Form.Get("luci_username"))
				w.WriteHeader(403)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "sysauth_http", Value: string(rune('0' + generation.Load())), Path: "/cgi-bin/luci/", HttpOnly: true})
			http.Redirect(w, r, "/cgi-bin/luci/admin/status", 303)
			return
		}
		w.Header().Set("X-LuCI-Login-Required", "yes")
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `<form method="post" action="/cgi-bin/luci/"><input type="hidden" name="csrf" value="hidden-value"><input name="luci_username"><input type="password" name="luci_password"></form>`)
	}))
	defer server.Close()
	a := testApp(t)
	s := Service{ID: token(), Name: "Router", Slug: "router", Type: "openwrt", UpstreamURL: server.URL, EntryPath: "/cgi-bin/luci/"}
	if err := a.store.SaveWithCredentials(context.Background(), s, &Credentials{"root", "password"}); err != nil {
		t.Fatal(err)
	}
	p, _ := owner(a)
	g := enter(t, a, p, s)
	if logins.Load() != 1 {
		t.Fatal("initial login failed")
	}
	got := gatewayRequest(a, s, g, "GET", "/cgi-bin/luci/admin/status", nil)
	if got.Code != 200 || !strings.Contains(got.Body.String(), "native-csrf-token") {
		t.Fatal("page token was changed")
	}
	generation.Store(2)
	got = gatewayRequest(a, s, g, "GET", "/cgi-bin/luci/admin/status", nil)
	if got.Code != 200 || logins.Load() != 2 {
		t.Fatal("luci refresh failed", got.Code, got.Body.String())
	}
	// LuCI session cookies must remain scoped to this gateway host.
	for _, c := range got.Result().Cookies() {
		if c.Domain != "" {
			t.Fatal("cookie domain shared")
		}
	}
}
func TestLuCIChallengeNeverSubmitsStoredPassword(t *testing.T) {
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			posts.Add(1)
		}
		w.Header().Set("X-LuCI-Login-Required", "yes")
		w.WriteHeader(403)
		_, _ = io.WriteString(w, `<form><input name="luci_username"><input name="luci_password" type="password"><input name="otp" type="text"></form>`)
	}))
	defer server.Close()
	a := testApp(t)
	s := Service{ID: "mfa", Type: "openwrt", UpstreamURL: server.URL}
	p, _ := owner(a)
	g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
	c, err := clientFor(s, g)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	err = (luciAdapter{}).Login(context.Background(), c, s, Credentials{"root", "secret"})
	if err == nil || posts.Load() != 0 {
		t.Fatal("MFA form auto submitted")
	}
}
func TestTLSVerificationAndCustomTrust(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	s := Service{UpstreamURL: server.URL}
	p := newSessions().addPortal("owner", "", time.Hour)
	ss := newSessions()
	ss.portals[p.ID] = p
	g := ss.redeem(ss.ticket(p, "tls"), "tls")
	defer g.close()
	c, err := clientFor(s, g)
	if err != nil {
		t.Fatal(err)
	}
	_, err = call(context.Background(), c, "GET", server.URL, nil)
	c.Transport.(*http.Transport).CloseIdleConnections()
	if err == nil {
		t.Fatal("untrusted certificate accepted")
	}
	s.TrustedCA = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}))
	c, err = clientFor(s, g)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	resp, err := call(context.Background(), c, "GET", server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	finish(resp)
}
func TestTicketExpiry(t *testing.T) {
	ss := newSessions()
	p := ss.addPortal("owner", "", time.Hour)
	id := ss.ticket(p, "one")
	ss.mu.Lock()
	ticket := ss.tickets[id]
	ticket.Expires = time.Now().Add(-time.Second)
	ss.tickets[id] = ticket
	ss.mu.Unlock()
	if ss.redeem(id, "one") != nil {
		t.Fatal("expired ticket accepted")
	}
}
