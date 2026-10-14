package app

import (
	"bytes"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestSecureHostOnlyCookies(t *testing.T) {
	a := &App{cfg: Config{}}
	for _, name := range []string{portalCookie, gatewayCookie, transactionCookie} {
		w := httptest.NewRecorder()
		a.cookie(w, name, "opaque", time.Now().Add(time.Hour))
		cookies := w.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("missing cookie")
		}
		c := cookies[0]
		if c.Domain != "" || c.Path != "/" || !c.HttpOnly || !c.Secure {
			t.Fatalf("insecure cookie %s", name)
		}
	}
}

func TestDeviceDomainLayouts(t *testing.T) {
	for _, tc := range []struct {
		name, portal, domain, device string
		valid                        bool
	}{
		{"portal as parent", "https://console.xxx.com", "console.xxx.com", "https://yyy.console.xxx.com", true},
		{"separate device suffix", "https://control.example.com", "devices.example.com", "https://yyy.devices.example.com", true},
		{"localhost with port", "http://console.localhost:8080", "console.localhost", "http://yyy.console.localhost:8080", true},
		{"portal in device namespace", "https://portal.console.xxx.com", "console.xxx.com", "", false},
		{"mixed case portal in device namespace", "https://Portal.Console.xxx.com", "console.xxx.com", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := Config{PortalURL: tc.portal, DeviceDomain: tc.domain, Issuer: "https://auth.xxx.com/application/o/webconsole/", ClientID: "id", ClientSecret: "secret", AllowedSub: "owner", Key: bytes.Repeat([]byte{1}, 32), DevHTTP: tc.domain == "console.localhost"}
			if err := c.Validate(); (err == nil) != tc.valid {
				t.Fatalf("unexpected domain validation: %v", err)
			}
			if tc.valid && c.deviceOrigin("yyy") != tc.device {
				t.Fatalf("device URL = %s, want %s", c.deviceOrigin("yyy"), tc.device)
			}
		})
	}
}

func TestParentPortalCookieIsolation(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: Config{PortalURL: "https://console.xxx.com", DeviceDomain: "console.xxx.com"}}
	for _, tc := range []struct{ origin, name, value string }{
		{a.cfg.PortalURL, portalCookie, "portal-session"},
		{a.cfg.deviceOrigin("one"), gatewayCookie, "one-session"},
		{a.cfg.deviceOrigin("two"), gatewayCookie, "two-session"},
	} {
		origin, _ := url.Parse(tc.origin)
		w := httptest.NewRecorder()
		a.cookie(w, tc.name, tc.value, time.Now().Add(time.Hour))
		jar.SetCookies(origin, w.Result().Cookies())
	}
	for _, tc := range []struct{ origin, name, value string }{
		{a.cfg.PortalURL, portalCookie, "portal-session"},
		{a.cfg.deviceOrigin("one"), gatewayCookie, "one-session"},
		{a.cfg.deviceOrigin("two"), gatewayCookie, "two-session"},
	} {
		origin, _ := url.Parse(tc.origin)
		cookies := jar.Cookies(origin)
		if len(cookies) != 1 || cookies[0].Name != tc.name || cookies[0].Value != tc.value {
			t.Fatalf("cookies crossed origins at %s: %v", tc.origin, cookies)
		}
	}
}

func TestProductionRequiresHTTPSAndExplicitSubject(t *testing.T) {
	c := Config{PortalURL: "https://console.xxx.com", DeviceDomain: "console.xxx.com", Issuer: "https://auth.xxx.com/application/o/webconsole/", ClientID: "id", ClientSecret: "secret", AllowedSub: "owner", Key: bytes.Repeat([]byte{1}, 32)}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	c.AllowedSub = ""
	if c.Validate() == nil {
		t.Fatal("missing account restriction accepted")
	}
	c.AllowedSub = "owner"
	c.PortalURL = "http://console.xxx.com"
	if c.Validate() == nil {
		t.Fatal("HTTP production accepted")
	}
	c.DevHTTP = true
	if c.Validate() == nil {
		t.Fatal("DEV_HTTP allowed remote domains")
	}
}
