package app

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const nativeAuthCookie = "wc_native_session"
const nativeCredentialPath = "/__webconsole/credentials/"
const nativeBrowserMarker = "webconsole-session"

var errNativeProtocol = errors.New("设备登录协议与当前适配器不兼容，请使用原页面手动登录")
var errNativeInteractive = errors.New("设备要求验证码或二次验证，请在原页面手动完成")
var errNativeRateLimit = errors.New("设备限制了登录尝试或已有其他管理会话，请稍后再试")
var nativeTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

type nativeAuth struct {
	Token             string            `json:"token,omitempty"`
	Username          string            `json:"username,omitempty"`
	CSRF              string            `json:"csrf,omitempty"`
	SessionID         string            `json:"sessionId,omitempty"`
	Version           string            `json:"version,omitempty"`
	SessionManager    string            `json:"sessionManager,omitempty"`
	PropertyCollector string            `json:"propertyCollector,omitempty"`
	References        map[string]string `json:"references,omitempty"`
}

func quickLoginKind(kind string) bool {
	return kind == "pve" || kind == "esxi" || kind == "tplink" || kind == "xiaomi" || kind == "glinet"
}

func nativeSession(c *http.Client, s Service) nativeAuth {
	u, _ := url.Parse(s.UpstreamURL + nativeCredentialPath)
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == nativeAuthCookie {
			b, err := base64.RawURLEncoding.DecodeString(cookie.Value)
			var auth nativeAuth
			if err == nil && json.Unmarshal(b, &auth) == nil {
				return auth
			}
		}
	}
	return nativeAuth{}
}

func saveNativeSession(c *http.Client, s Service, auth nativeAuth) {
	u, _ := url.Parse(s.UpstreamURL + nativeCredentialPath)
	b, _ := json.Marshal(auth)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: nativeAuthCookie, Value: base64.RawURLEncoding.EncodeToString(b), Path: nativeCredentialPath, HttpOnly: true, Secure: u.Scheme == "https"}})
}

func clearNativeSession(c *http.Client, s Service) {
	saveNativeSession(c, s, nativeAuth{})
	u, _ := url.Parse(s.UpstreamURL + "/")
	for _, name := range []string{"PVEAuthCookie", "vmware_soap_session"} {
		c.Jar.SetCookies(u, []*http.Cookie{{Name: name, Path: "/", MaxAge: -1}})
	}
	if s.Type == "glinet" {
		c.Jar.SetCookies(u, []*http.Cookie{{Name: "auth_token", Path: "/", MaxAge: -1}})
	}
}

func nativeJSON(resp *http.Response, output any) error {
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, (128<<10)+1))
	if err != nil || len(b) > 128<<10 || json.Unmarshal(b, output) != nil {
		return errNativeProtocol
	}
	return nil
}

func nativeJSONCall(r *http.Request, c *http.Client, input any) (*http.Response, error) {
	b, err := json.Marshal(input)
	if err != nil {
		return nil, errNativeProtocol
	}
	r.Body = io.NopCloser(bytes.NewReader(b))
	r.ContentLength = int64(len(b))
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(r)
	if err != nil {
		return nil, connectionError(err)
	}
	return resp, nil
}

type prefixReadCloser struct {
	io.Reader
	io.Closer
}

// Inspect a bounded prefix of a finite API error, preserving the full response.
func responsePrefix(resp *http.Response, limit int64) []byte {
	if resp.Body == nil {
		return nil
	}
	original := resp.Body
	b, _ := io.ReadAll(io.LimitReader(original, limit))
	resp.Body = &prefixReadCloser{Reader: io.MultiReader(bytes.NewReader(b), original), Closer: original}
	return b
}

func pveChallenge(ticket string) bool {
	return strings.HasPrefix(ticket, "PVE:!tfa!") || strings.HasPrefix(ticket, "PVE:tfa!")
}
