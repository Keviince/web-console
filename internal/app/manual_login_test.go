package app

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestManualLoginRequestValidation(t *testing.T) {
	a := testApp(t)
	s := addPi(t, a, newPiKVM(t), "manual")
	p, _ := owner(a)
	origin := a.cfg.deviceOrigin(s.Slug)
	for _, tc := range []struct {
		name, method, origin, csrf string
		status                     int
	}{
		{"valid", "POST", origin, "valid", 303},
		{"missing origin", "POST", "", "valid", 403},
		{"null origin", "POST", "null", "valid", 403},
		{"foreign origin", "POST", "https://example.com", "valid", 403},
		{"sibling device", "POST", a.cfg.deviceOrigin("other"), "valid", 403},
		{"missing csrf", "POST", origin, "", 403},
		{"wrong csrf", "POST", origin, "wrong", 403},
		{"get", "GET", origin, "valid", 403},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := a.sessions.redeem(a.sessions.ticket(p, s.ID), s.ID)
			csrf := tc.csrf
			if csrf == "valid" {
				csrf = g.CSRF
			}
			r := httptest.NewRequest(tc.method, origin+"/__webconsole/manual", strings.NewReader(url.Values{"csrf": {csrf}}.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", tc.origin)
			r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
			w := httptest.NewRecorder()
			a.ServeHTTP(w, r)
			if w.Code != tc.status || g.Manual != (tc.status == 303) {
				t.Fatalf("status=%d manual=%v", w.Code, g.Manual)
			}
		})
	}
}

func TestManualLoginOriginalForms(t *testing.T) {
	a := testApp(t)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == "POST" {
			if r.Header.Get("Origin") != "http://"+r.Host || r.FormValue("luci_username") != "fixture-user" || r.FormValue("luci_password") != "fixture-password" {
				t.Error("native login form did not preserve its fields and upstream origin")
			}
			_, _ = io.WriteString(w, "Manual login complete")
			return
		}
		_, _ = io.WriteString(w, `<form method="post"><input name="luci_username"><input name="luci_password" type="password"><button>登录</button></form>`)
	}))
	defer upstream.Close()
	s := Service{ID: token(), Name: "Router", Slug: "manual", Type: "openwrt", UpstreamURL: upstream.URL, EntryPath: "/cgi-bin/luci/"}
	if err := a.store.SaveWithCredentials(context.Background(), s, nil); err != nil {
		t.Fatal(err)
	}
	p, _ := owner(a)
	origin := a.cfg.deviceOrigin(s.Slug)
	startURL := origin + "/__webconsole/start?ticket=" + a.sessions.ticket(p, s.ID)
	fallback := request(a, "GET", startURL, nil, nil, "")
	if fallback.Code != 502 || !strings.Contains(fallback.Body.String(), "使用原页面手动登录") {
		t.Fatal("missing manual login fallback")
	}
	g := a.sessions.gateway(fallback.Result().Cookies()[0].Value, s.ID)
	if g == nil {
		t.Fatal("fallback did not establish gateway authorization")
	}
	r := httptest.NewRequest("POST", origin+"/__webconsole/manual", strings.NewReader(url.Values{"csrf": {g.CSRF}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	manual := httptest.NewRecorder()
	a.ServeHTTP(manual, r)
	if manual.Code != 303 || manual.Header().Get("Location") != s.EntryPath {
		t.Fatal("manual login did not open the original page")
	}
	native := gatewayRequest(a, s, g, "GET", s.EntryPath, nil)
	if native.Code != 200 {
		t.Fatal("original login page unavailable")
	}
	r = httptest.NewRequest("POST", origin+s.EntryPath, strings.NewReader("luci_username=fixture-user&luci_password=fixture-password"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.AddCookie(&http.Cookie{Name: "wc_gateway", Value: g.ID})
	submitted := httptest.NewRecorder()
	a.ServeHTTP(submitted, r)
	if submitted.Code != 200 || submitted.Body.String() != "Manual login complete" {
		t.Fatal("native login form submission failed")
	}
	// Export the actual backend pages and headers, using only fixture identities.
	if path := os.Getenv("WEBCONSOLE_MANUAL_BROWSER_FIXTURE"); path != "" {
		page := func(w *httptest.ResponseRecorder) map[string]any {
			headers := map[string]string{}
			for name := range w.Header() {
				headers[name] = w.Header().Get(name)
			}
			delete(headers, "Set-Cookie")
			return map[string]any{"body": w.Body.String(), "headers": headers, "status": w.Code}
		}
		b, err := json.Marshal(map[string]any{"startUrl": startURL, "entryPath": s.EntryPath, "csrf": g.CSRF, "fallback": page(fallback), "native": page(native)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
	}
}
