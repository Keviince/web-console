package app

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTPLinkVariableProtocolLogin(t *testing.T) {
	a := testApp(t)
	f := newNative(t, "tplink")
	f.variablePassword = true
	s := addNative(t, a, f, "tplink")
	p, _ := owner(a)
	g := enter(t, a, p, s)
	if f.logins.Load() != 1 || nativeRead(a, s, g, false).Code != 200 {
		t.Fatal("ER3229 SLP login and authenticated read failed")
	}
}

func TestTPLinkStaticCacheBoundary(t *testing.T) {
	for _, tc := range []struct {
		url    string
		cookie bool
		cache  bool
	}{
		{"http://router/web-static/js/su/su.js?random=20240826212817", false, true},
		{"http://router/web-static/js/su/su.js", false, false},
		{"http://router/web-static/js/su/su.js?random=20240826212817&_=123", false, false},
		{"http://router/web-static/localResult.js?random=20240826212817", true, false},
		{"http://router/stok=marker/ds?random=20240826212817", false, false},
		{"http://router/index.html?random=20240826212817", false, false},
	} {
		r := httptest.NewRequest("GET", tc.url, nil)
		response := &http.Response{StatusCode: 200, Request: r, Header: make(http.Header)}
		response.Header.Set("Cache-Control", "no-cache")
		if tc.cookie {
			response.Header.Set("Set-Cookie", "session=fixture")
		}
		cacheTPLinkStatic(response)
		if strings.Contains(response.Header.Get("Cache-Control"), "immutable") != tc.cache {
			t.Fatalf("unexpected cache policy: %s", tc.url)
		}
	}
}

func TestTPLinkProtocolRejectsUnknownExpressions(t *testing.T) {
	for _, expression := range []string{`"abc" + fetch('/secret')`, `"abc" + unknown`, `"short"`} {
		source := fmt.Sprintf(`orgAuthPwd=function(p){var salt=%q;var dic=%s;return this.securityEncode(p,salt,dic);}`, slpSalt, expression)
		if _, _, err := tplinkProtocol(source); err == nil {
			t.Fatal("accepted an unknown password expression")
		}
	}
	source := fmt.Sprintf(`orgAuthPwd=function(p){var salt=%q;var dic=%q;return this.securityEncode(p,dic,salt);}`, slpSalt, slpAlphabet)
	if _, _, err := tplinkProtocol(source); err == nil {
		t.Fatal("accepted swapped protocol parameters")
	}
}

func TestTPLinkPublicFirmwareProtocols(t *testing.T) {
	root := os.Getenv("WEBCONSOLE_TPLINK_PUBLIC_FIXTURES")
	if root == "" {
		t.Skip("requires captured public firmware scripts")
	}
	for _, name := range []string{"100-1-su.js", "100-2-su.js", "r479-su.js"} {
		source, err := os.ReadFile(filepath.Join(root, name))
		if err != nil {
			t.Fatal(err)
		}
		salt, alphabet, err := tplinkProtocol(string(source))
		if err != nil || salt != slpSalt || alphabet != slpAlphabet {
			t.Fatalf("%s: actual SLP protocol mismatch", name)
		}
	}
}

func TestTPLinkLoginURLAndProtocolValidation(t *testing.T) {
	cfg := Config{PortalURL: "https://portal.example", DeviceDomain: "devices.example"}
	s := Service{Name: "TP-Link", Slug: "tplink", Type: "tplink", UpstreamURL: "http://192.168.1.2/login.htm"}
	if err := validateService(&s, cfg); err != nil || s.UpstreamURL != "http://192.168.1.2" || s.EntryPath != "/" || s.TPLinkProtocol != "slp" {
		t.Fatalf("login URL normalization failed: %v", err)
	}
	s.TPLinkProtocol = "unknown"
	if validateService(&s, cfg) == nil {
		t.Fatal("accepted an unsupported protocol")
	}
	s.Type = "proxy"
	if err := validateService(&s, cfg); err != nil || strings.Contains(s.TPLinkProtocol, "unknown") {
		t.Fatal("protocol retained after changing type")
	}
}
