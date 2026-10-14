package app

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestManualProxyURLs(t *testing.T) {
	s := Service{UpstreamURL: "https://192.168.1.1"}
	origin := "https://router.console.example"
	rewrite := manualProxyURLRewriter(s, origin)
	for _, tc := range [][2]string{
		{"https://192.168.1.1/home?x=1#status", origin + "/home?x=1#status"},
		{"http://192.168.1.1/home", origin + "/home"},
		{"//192.168.1.1/home", origin + "/home"},
		{"https://192.168.1.1:443/", origin + "/"},
		{`window.location="https://192.168.1.1"`, `window.location="` + origin + `"`},
		{`{"url":"https:\/\/192.168.1.1\/home"}`, `{"url":"https:\/\/router.console.example\/home"}`},
		{"wss://192.168.1.1/ws", "wss://router.console.example/ws"},
		{"https://192.168.1.10/home", "https://192.168.1.10/home"},
		{"https://192.168.1.1.evil.example/home", "https://192.168.1.1.evil.example/home"},
		{"https://192.168.1.1:8443/home", "https://192.168.1.1:8443/home"},
		{"/home", "/home"},
	} {
		if got := rewrite(tc[0]); got != tc[1] {
			t.Errorf("rewrite(%q)=%q, want %q", tc[0], got, tc[1])
		}
	}
	for _, tc := range []struct{ upstream, source, want string }{
		{"https://[::1]:443", "https://[::1]/login", origin + "/login"},
		{"http://192.168.1.1:8080", "http://192.168.1.1:8080/login", origin + "/login"},
		{"https://router.lan", "https://ROUTER.LAN/login", origin + "/login"},
	} {
		if got := manualProxyURLRewriter(Service{UpstreamURL: tc.upstream}, origin)(tc.source); got != tc.want {
			t.Errorf("rewrite(%q)=%q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestManualProxyOriginalLogin(t *testing.T) {
	a := testApp(t)
	var requests atomic.Int32
	var upstream *httptest.Server
	upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.URL.Path == "/private" {
			w.WriteHeader(401)
			return
		}
		if r.URL.Path == "/login" {
			if r.Method != "POST" || r.FormValue("user") != "fixture-user" || r.FormValue("password") != "fixture-password" || r.Header.Get("Origin") != upstream.URL {
				t.Error("manual form fields or upstream origin changed")
			}
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "fixture-session", Domain: "127.0.0.1", Path: "/", HttpOnly: true})
			http.Redirect(w, r, upstream.URL+"/home", 302)
			return
		}
		if r.URL.Path == "/home" {
			if cookie, err := r.Cookie("session"); err != nil || cookie.Value != "fixture-session" {
				t.Error("manual session cookie was lost")
			}
			if r.Header.Get("Authorization") != "Bearer fixture-browser-token" {
				t.Error("browser authentication was not forwarded")
			}
			_, _ = io.WriteString(w, "Manual login complete")
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, `<form method="post" action="`+upstream.URL+`/login"><input name="user"><input type="password" name="password"><button>登录</button></form><script>function enter(){location.href="`+upstream.URL+`/home"}</script>`)
	}))
	defer upstream.Close()
	s := Service{ID: token(), Name: "Manual router", Slug: "manual-proxy", Type: "proxy", UpstreamURL: upstream.URL}
	if err := validateService(&s, a.cfg); err != nil || s.EntryPath != "/" {
		t.Fatalf("invalid proxy config: %v", err)
	}
	if err := a.store.Save(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	p, cookie := owner(a)
	launch := request(a, "POST", a.cfg.PortalURL+"/api/services/"+s.ID+"/launch", nil, cookie, p.CSRF)
	var target map[string]string
	if err := json.Unmarshal(launch.Body.Bytes(), &target); err != nil || launch.Code != 200 || strings.HasPrefix(target["url"], upstream.URL) {
		t.Fatal("launch did not use the device domain")
	}
	start := request(a, "GET", target["url"], nil, nil, "")
	if start.Code != 303 || start.Header().Get("Location") != "/" || requests.Load() != 0 {
		t.Fatal("launch attempted upstream authentication")
	}
	g := a.sessions.gateway(start.Result().Cookies()[0].Value, s.ID)
	page := gatewayRequest(a, s, g, "GET", "/", nil)
	origin := a.cfg.deviceOrigin(s.Slug)
	if page.Code != 200 || strings.Contains(page.Body.String(), upstream.URL) || !strings.Contains(page.Body.String(), origin+"/login") {
		t.Fatal("page navigation URLs escaped the proxy")
	}
	r := httptest.NewRequest("POST", origin+"/login", strings.NewReader("user=fixture-user&password=fixture-password"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.AddCookie(start.Result().Cookies()[0])
	login := httptest.NewRecorder()
	a.ServeHTTP(login, r)
	if login.Code != 302 || login.Header().Get("Location") != origin+"/home" {
		t.Fatalf("login status=%d location=%q, want proxy navigation", login.Code, login.Header().Get("Location"))
	}
	for _, c := range login.Result().Cookies() {
		if c.Domain != "" {
			t.Fatal("cookie escaped the proxy host")
		}
	}
	r = httptest.NewRequest("GET", origin+"/home", nil)
	r.AddCookie(start.Result().Cookies()[0])
	r.Header.Set("Authorization", "Bearer fixture-browser-token")
	home := httptest.NewRecorder()
	a.ServeHTTP(home, r)
	if home.Code != 200 || home.Body.String() != "Manual login complete" {
		t.Fatal("manual session did not survive navigation")
	}
	before := requests.Load()
	private := gatewayRequest(a, s, g, "GET", "/private", nil)
	if private.Code != 401 || requests.Load() != before+1 {
		t.Fatal("401 triggered automatic login or replay")
	}
	a.revokeUpstream(g)
	if requests.Load() != before+1 {
		t.Fatal("gateway revoke attempted an adapter logout")
	}
	if path := os.Getenv("WEBCONSOLE_PROXY_BROWSER_FIXTURE"); path != "" {
		data, _ := json.Marshal(map[string]string{"origin": origin, "page": page.Body.String()})
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func TestManualProxyCredentialsAndConnection(t *testing.T) {
	a := testApp(t)
	s := addPi(t, a, newPiKVM(t), "convert-proxy")
	p, cookie := owner(a)
	s.Type, s.EntryPath = "proxy", "/"
	data, _ := json.Marshal(s)
	updated := request(a, "PUT", a.cfg.PortalURL+"/api/services/"+s.ID, bytes.NewReader(data), cookie, p.CSRF)
	var result Service
	_ = json.Unmarshal(updated.Body.Bytes(), &result)
	if updated.Code != 200 || result.HasCredentials {
		t.Fatal("conversion retained credentials")
	}
	if _, err := a.store.Credentials(context.Background(), s.ID); err == nil {
		t.Fatal("credentials were not erased")
	}
	cred := Credentials{Username: "fixture-user", Password: "fixture-password"}
	if err := a.store.SetCredentials(context.Background(), s.ID, cred); err == nil {
		t.Fatal("proxy accepted saved credentials")
	}
	data, _ = json.Marshal(cred)
	rejected := request(a, "PUT", a.cfg.PortalURL+"/api/services/"+s.ID+"/credentials", bytes.NewReader(data), cookie, p.CSRF)
	if rejected.Code != 400 {
		t.Fatal("credentials endpoint accepted proxy credentials")
	}
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Method != "GET" {
			t.Error("reachability test submitted a login")
		}
		w.Header().Set("Location", "https://192.168.1.1/login")
		w.WriteHeader(302)
	}))
	defer upstream.Close()
	s.UpstreamURL = upstream.URL
	if stage, err := checkDeviceConnection(context.Background(), s, func() (Credentials, error) { t.Fatal("read saved credentials"); return Credentials{}, nil }); err != nil || stage != "connection" || hits.Load() != 1 {
		t.Fatalf("reachability test failed: %s %v", stage, err)
	}
}

func TestManualProxyCompressedTextAndBinary(t *testing.T) {
	s := Service{UpstreamURL: "http://192.168.1.1"}
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	_, _ = io.WriteString(writer, `location.href="http://192.168.1.1/home"`)
	_ = writer.Close()
	resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/javascript"}, "Content-Encoding": {"gzip"}, "Refresh": {"0; url=http://192.168.1.1/home"}}, Body: io.NopCloser(&compressed)}
	if err := rewriteManualProxyResponse(resp, s, "https://router.console.example"); err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "192.168.1.1") || resp.Header.Get("Content-Encoding") != "" || resp.Header.Get("Refresh") != "0; url=https://router.console.example/home" {
		t.Fatal("compressed script or refresh escaped the proxy")
	}
	for _, contentType := range []string{"application/octet-stream", "text/event-stream", "multipart/x-mixed-replace"} {
		original := io.NopCloser(strings.NewReader("http://192.168.1.1/binary"))
		resp := &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {contentType}}, Body: original}
		if err := rewriteManualProxyResponse(resp, s, "https://router.console.example"); err != nil || resp.Body != original {
			t.Fatal("binary or streaming response was buffered")
		}
	}
}
