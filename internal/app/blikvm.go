package app

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Native BliKVM v2 uses /api/login and bearer tokens. BliKVM hardware
// running PiKVM firmware must continue to use the PiKVM adapter.
type blikvmAdapter struct{}

const blikvmSessionCookie = "wc_blikvm_session"
const blikvmCredentialPath = "/__webconsole/credentials/"
const blikvmBrowserMarker = "webconsole-session"

var errBliProtocol = errors.New("BliKVM 响应不兼容当前登录协议，请使用原页面手动登录")
var errBliInteractive = errors.New("BliKVM 要求二次验证，请在原页面手动完成")
var errBliRateLimit = errors.New("BliKVM 限制了登录尝试，请稍后再试或使用原页面登录")
var blikvmJWT = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)

type blikvmAuth struct {
	Token    string `json:"token"`
	Username string `json:"username"`
	Role     string `json:"role"`
}

type blikvmResponse struct {
	Code *int       `json:"code"`
	Msg  string     `json:"msg"`
	Data blikvmAuth `json:"data"`
}

func blikvmRead(resp *http.Response) (blikvmResponse, error) {
	defer resp.Body.Close()
	var result blikvmResponse
	b, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &result) != nil || result.Code == nil {
		return result, errBliProtocol
	}
	return result, nil
}

func blikvmSession(c *http.Client, s Service) blikvmAuth {
	u, _ := url.Parse(s.UpstreamURL + blikvmCredentialPath)
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == blikvmSessionCookie {
			b, err := base64.RawURLEncoding.DecodeString(cookie.Value)
			var auth blikvmAuth
			if err == nil && json.Unmarshal(b, &auth) == nil {
				return auth
			}
		}
	}
	return blikvmAuth{}
}

func saveBlikvmSession(c *http.Client, s Service, auth blikvmAuth) {
	u, _ := url.Parse(s.UpstreamURL + blikvmCredentialPath)
	b, _ := json.Marshal(auth)
	cookie := &http.Cookie{Name: blikvmSessionCookie, Value: base64.RawURLEncoding.EncodeToString(b), Path: blikvmCredentialPath, HttpOnly: true, Secure: u.Scheme == "https"}
	if auth.Token == "" {
		cookie.MaxAge = -1
	}
	// This synthetic cookie is only an in-memory credential container. It
	// is never sent to the upstream or published to a browser.
	c.Jar.SetCookies(u, []*http.Cookie{cookie})
}

func validBlikvmAuth(auth blikvmAuth) bool {
	return len(auth.Token) <= 16<<10 && blikvmJWT.MatchString(auth.Token) && auth.Username != "" && len(auth.Username) <= 256 && !strings.ContainsAny(auth.Username, "\r\n") && len(auth.Role) <= 80
}

func (blikvmAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	// The public state endpoint verifies the protocol and TLS before sending
	// a password. Per-user MFA is not public; a rejection is never retried.
	preflight, err := call(ctx, c, "GET", s.UpstreamURL+"/api/auth/state", nil)
	if err != nil {
		return err
	}
	if preflight.StatusCode != 200 {
		finish(preflight)
		return errBliProtocol
	}
	status, err := blikvmRead(preflight)
	if err != nil || *status.Code != 0 {
		return errBliProtocol
	}
	body, _ := json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TwoFA    any    `json:"twoFaCode"`
	}{cred.Username, cred.Password, nil})
	r, err := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+"/api/login", bytes.NewReader(body))
	if err != nil {
		return errBliProtocol
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(r)
	if err != nil {
		return connectionError(err)
	}
	if resp.StatusCode == 429 {
		finish(resp)
		return errBliRateLimit
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errLogin
	}
	data, err := blikvmRead(resp)
	if err != nil {
		return err
	}
	if *data.Code != 0 {
		if strings.Contains(strings.ToLower(data.Msg), "two factor") {
			return errBliInteractive
		}
		return errLogin
	}
	if !validBlikvmAuth(data.Data) || data.Data.Username != cred.Username {
		return errBliProtocol
	}
	saveBlikvmSession(c, s, data.Data)
	return nil
}

func (blikvmAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	auth := blikvmSession(c, s)
	if auth.Token == "" {
		return errNeedsLogin
	}
	r, _ := http.NewRequestWithContext(ctx, "GET", s.UpstreamURL+"/api/check/token", nil)
	r.Header.Set("Authorization", "Bearer "+auth.Token)
	r.Header.Set("Username", auth.Username)
	resp, err := c.Do(r)
	if err != nil {
		return connectionError(err)
	}
	if resp.StatusCode == 401 {
		finish(resp)
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errors.New("BliKVM 会话检查失败")
	}
	data, err := blikvmRead(resp)
	if err != nil {
		return err
	}
	if *data.Code == 100 || *data.Code == 101 || *data.Code == 102 {
		return errNeedsLogin
	}
	if *data.Code != 0 {
		return errors.New("BliKVM 会话检查失败")
	}
	return nil
}

func (blikvmAdapter) Expired(resp *http.Response) bool { return resp.StatusCode == 401 }
func (blikvmAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	// Native firmware implements logout by discarding the JWT. Do not call
	// account/auth configuration endpoints to simulate a logout.
	saveBlikvmSession(c, s, blikvmAuth{})
	return nil
}

func applyBlikvmAuth(r *http.Request, s Service, g *gatewaySession) {
	auth := blikvmSession(&http.Client{Jar: g.Jar}, s)
	r.Header.Del("Authorization")
	r.Header.Del("Username")
	if auth.Token != "" {
		r.Header.Set("Authorization", "Bearer "+auth.Token)
		r.Header.Set("Username", auth.Username)
	}
	switch r.URL.Path {
	case "/wss", "/janus", "/ssh", "/serial", "/api/update/stream":
		q := r.URL.Query()
		q.Del("token")
		if auth.Token != "" {
			q.Set("token", auth.Token)
		}
		r.URL.RawQuery = q.Encode()
	}
}

// A native manual login stays interactive, including twoFaCode. The issued
// JWT is retained on the gateway; the SPA receives an inert auth marker.
func captureBlikvmLogin(resp *http.Response, s Service, g *gatewaySession) error {
	body, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	_ = resp.Body.Close()
	var data blikvmResponse
	if err != nil || len(body) > 64<<10 || json.Unmarshal(body, &data) != nil || data.Code == nil {
		return errBliProtocol
	}
	if *data.Code == 0 {
		if !validBlikvmAuth(data.Data) {
			return errBliProtocol
		}
		g.authMu.Lock()
		saveBlikvmSession(&http.Client{Jar: g.Jar}, s, data.Data)
		g.Manual = true
		g.Version++
		g.authMu.Unlock()
		var envelope map[string]json.RawMessage
		_ = json.Unmarshal(body, &envelope)
		data.Data.Token = blikvmBrowserMarker
		envelope["data"], _ = json.Marshal(data.Data)
		body, _ = json.Marshal(envelope)
	}
	resp.Body = io.NopCloser(bytes.NewReader(body))
	resp.ContentLength = int64(len(body))
	resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	resp.Header.Set("Cache-Control", "no-store")
	resp.Header.Del("ETag")
	resp.Header.Del("Content-MD5")
	return nil
}

func (a *App) prepareBlikvmPage(ctx context.Context, s Service, g *gatewaySession) error {
	g.authMu.Lock()
	if !g.Manual {
		g.authMu.Unlock()
		return a.ensureLogin(ctx, s, g, nil)
	}
	defer g.authMu.Unlock()
	c, err := clientFor(s, g)
	if err != nil {
		return err
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	err = (blikvmAdapter{}).Check(ctx, c, s)
	if errors.Is(err, errNeedsLogin) {
		saveBlikvmSession(c, s, blikvmAuth{})
		return nil
	}
	if err != nil {
		logDeviceFailure(a.log, "device session check failed", s, "manual_session_check", err)
	}
	return err
}
