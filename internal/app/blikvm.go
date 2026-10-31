package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// BliKVM 3 uses the /api/v1 API and an HttpOnly session cookie. The native
// page restores its own account and permissions through /auth/me.
type blikvmAdapter struct{}

const blikvmSessionCookie = "blikvm_session"
const blikvmAPI = "/api/v1"

var errBliProtocol = errors.New("BliKVM 响应不兼容当前登录协议，请使用原页面手动登录")
var errBliInteractive = errors.New("BliKVM 要求二次验证，请在原页面手动完成")
var errBliRateLimit = errors.New("BliKVM 限制了登录尝试，请稍后再试或使用原页面登录")

type blikvmUser struct {
	Username string `json:"username"`
	Role     string `json:"role"`
}

type blikvmResponse struct {
	OK    *bool  `json:"ok"`
	Error string `json:"error"`
	Data  struct {
		Enabled     *bool      `json:"enabled"`
		AuthEnabled *bool      `json:"authEnabled"`
		User        blikvmUser `json:"user"`
		Username    string     `json:"username"`
	} `json:"data"`
}

func blikvmRead(resp *http.Response) (blikvmResponse, error) {
	defer resp.Body.Close()
	var result blikvmResponse
	b, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 || json.Unmarshal(b, &result) != nil || result.OK == nil {
		return result, errBliProtocol
	}
	return result, nil
}

func blikvmCookie(c *http.Client, s Service) *http.Cookie {
	u, _ := url.Parse(s.UpstreamURL + "/")
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == blikvmSessionCookie && cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

func clearBlikvmSession(c *http.Client, s Service) {
	u, _ := url.Parse(s.UpstreamURL + "/")
	c.Jar.SetCookies(u, []*http.Cookie{{Name: blikvmSessionCookie, Path: "/", MaxAge: -1}})
}

func (blikvmAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	// Check the public protocol and TLS before sending a password. Per-account
	// 2FA is interactive; a rejected password or OTP is never resubmitted here.
	preflight, err := call(ctx, c, "GET", s.UpstreamURL+blikvmAPI+"/auth/state", nil)
	if err != nil {
		return err
	}
	if preflight.StatusCode == http.StatusTooManyRequests {
		finish(preflight)
		return errBliRateLimit
	}
	if preflight.StatusCode != http.StatusOK {
		finish(preflight)
		return errBliProtocol
	}
	state, err := blikvmRead(preflight)
	if err != nil || !*state.OK || state.Data.Enabled == nil {
		return errBliProtocol
	}
	if !*state.Data.Enabled {
		return nil
	}
	clearBlikvmSession(c, s)
	body, _ := json.Marshal(struct {
		Username       string `json:"username"`
		Password       string `json:"password"`
		RememberDevice bool   `json:"rememberDevice"`
	}{cred.Username, cred.Password, false})
	r, err := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+blikvmAPI+"/auth/login", bytes.NewReader(body))
	if err != nil {
		return errBliProtocol
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", s.UpstreamURL)
	resp, err := c.Do(r)
	if err != nil {
		return connectionError(err)
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		finish(resp)
		return errBliRateLimit
	}
	status := resp.StatusCode
	data, err := blikvmRead(resp)
	if err != nil {
		clearBlikvmSession(c, s)
		return err
	}
	if status != http.StatusOK || !*data.OK {
		clearBlikvmSession(c, s)
		if strings.Contains(strings.ToLower(data.Error), "2fa") {
			return errBliInteractive
		}
		return errLogin
	}
	if data.Data.User.Username != cred.Username || blikvmCookie(c, s) == nil {
		clearBlikvmSession(c, s)
		return errBliProtocol
	}
	return nil
}

func (blikvmAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+blikvmAPI+"/auth/me", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		finish(resp)
		return errNeedsLogin
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		finish(resp)
		return errBliRateLimit
	}
	if resp.StatusCode != http.StatusOK {
		finish(resp)
		return errors.New("BliKVM 会话检查失败")
	}
	data, err := blikvmRead(resp)
	if err != nil {
		return err
	}
	if !*data.OK || data.Data.Username == "" && (data.Data.AuthEnabled == nil || *data.Data.AuthEnabled) {
		return errBliProtocol
	}
	return nil
}

func (blikvmAdapter) Expired(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized && resp.Request.URL.Path != blikvmAPI+"/auth/login" && resp.Request.URL.Path != blikvmAPI+"/auth/logout"
}

func (blikvmAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	// Portal revocation and connection tests only discard this gateway's cookie.
	// An explicit logout in the native page is still forwarded to the device.
	clearBlikvmSession(c, s)
	return nil
}

func applyBlikvmAuth(r *http.Request) {
	r.Header.Del("Authorization")
	r.Header.Del("Username")
	q := r.URL.Query()
	if q.Has("token") {
		q.Del("token")
		r.URL.RawQuery = q.Encode()
	}
}

func captureBlikvmResponse(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.Request.Method != "POST" {
		return nil
	}
	path := resp.Request.URL.Path
	if path != blikvmAPI+"/auth/login" && path != blikvmAPI+"/auth/logout" {
		return nil
	}
	resp.Header.Set("Cache-Control", "no-store")
	if path == blikvmAPI+"/auth/logout" && resp.StatusCode == http.StatusUnauthorized {
		clearBlikvmSession(&http.Client{Jar: g.Jar}, s)
		g.disconnect()
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body := responsePrefix(resp, (64<<10)+1)
	var data blikvmResponse
	if len(body) > 64<<10 || json.Unmarshal(body, &data) != nil || data.OK == nil {
		return errBliProtocol
	}
	if !*data.OK {
		return nil
	}
	g.authMu.Lock()
	defer g.authMu.Unlock()
	if path == blikvmAPI+"/auth/login" {
		if data.Data.User.Username == "" || blikvmCookie(&http.Client{Jar: g.Jar}, s) == nil {
			return errBliProtocol
		}
		g.Manual = true
		g.Version++
	} else {
		clearBlikvmSession(&http.Client{Jar: g.Jar}, s)
		g.disconnect()
	}
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
	if blikvmCookie(c, s) == nil {
		return nil
	}
	err = (blikvmAdapter{}).Check(ctx, c, s)
	if errors.Is(err, errNeedsLogin) {
		clearBlikvmSession(c, s)
		return nil
	}
	if err != nil {
		logDeviceFailure(a.log, "device session check failed", s, "manual_session_check", err)
	}
	return err
}
