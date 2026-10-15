package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

// GLKVM uses KVMD-style forms, plus GL.iNet's token header, auth_token
// query parameter and password+OTP login. Keep it separate from PiKVM.
type glinetAdapter struct{}

var errGLProtocol = errors.New("GL.iNet KVM 响应不兼容当前登录协议，请使用原页面手动登录")
var errGLInteractive = errors.New("GL.iNet KVM 已开启双因素认证，请在原页面输入密码和验证码")
var errGLRateLimit = errors.New("GL.iNet KVM 限制了登录尝试，请稍后再试或使用原页面登录")
var glinetTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{16,256}$`)

type glinetResponse struct {
	OK     *bool           `json:"ok"`
	Result json.RawMessage `json:"result"`
}

func saveGlinetSession(c *http.Client, s Service, value string) {
	saveNativeSession(c, s, nativeAuth{Token: value, Username: "admin"})
	// The native frontend sets this cookie itself. Token-only login responses
	// must replace any previous cookie before the backend checks the session.
	u, _ := url.Parse(s.UpstreamURL)
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "auth_token", Value: value, Path: "/", HttpOnly: true, Secure: u.Scheme == "https"}})
}

func glinetRead(resp *http.Response) (glinetResponse, error) {
	var data glinetResponse
	if err := nativeJSON(resp, &data); err != nil || data.OK == nil || len(data.Result) == 0 || data.Result[0] != '{' {
		return data, errGLProtocol
	}
	return data, nil
}

func glinetPublicFlag(ctx context.Context, c *http.Client, s Service, path, field string) (bool, error) {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+path, nil)
	if err != nil {
		return false, err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		finish(resp)
		return false, errGLRateLimit
	}
	if resp.StatusCode != http.StatusOK {
		finish(resp)
		return false, errGLProtocol
	}
	data, err := glinetRead(resp)
	if err != nil || !*data.OK {
		return false, errGLProtocol
	}
	var flags map[string]json.RawMessage
	var value bool
	if json.Unmarshal(data.Result, &flags) != nil || string(flags[field]) == "null" || json.Unmarshal(flags[field], &value) != nil {
		return false, errGLProtocol
	}
	return value, nil
}

func (glinetAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	// These public endpoints validate the protocol/TLS and MFA mode before
	// submitting a password. Never append or guess an OTP automatically.
	inited, err := glinetPublicFlag(ctx, c, s, "/api/init/is_inited", "is_inited")
	if err != nil {
		return err
	}
	if !inited {
		return errors.New("GL.iNet KVM 尚未初始化，请先在原页面设置管理员密码")
	}
	enabled, err := glinetPublicFlag(ctx, c, s, "/api/2fa/is_enabled", "enabled")
	if err != nil {
		return err
	}
	if enabled {
		return errGLInteractive
	}
	if cred.Username != "admin" {
		return errors.New("GL.iNet KVM 的本地管理员账号为 admin")
	}
	resp, err := call(ctx, c, "POST", s.UpstreamURL+"/api/auth/login", url.Values{"user": {cred.Username}, "passwd": {cred.Password}})
	if err != nil {
		return err
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		finish(resp)
		return errGLRateLimit
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		finish(resp)
		return errLogin
	}
	if resp.StatusCode != http.StatusOK {
		finish(resp)
		return errGLProtocol
	}
	data, err := glinetRead(resp)
	if err != nil {
		return err
	}
	if !*data.OK {
		return errLogin
	}
	var result struct {
		Token string `json:"token"`
	}
	if json.Unmarshal(data.Result, &result) != nil || !glinetTokenPattern.MatchString(result.Token) {
		return errGLProtocol
	}
	saveGlinetSession(c, s, result.Token)
	return nil
}

func (glinetAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	auth := nativeSession(c, s)
	if auth.Token == "" {
		return errNeedsLogin
	}
	r, _ := http.NewRequestWithContext(ctx, "GET", s.UpstreamURL+"/api/auth/check", nil)
	r.Header.Set("token", auth.Token)
	resp, err := c.Do(r)
	if err != nil {
		return connectionError(err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		finish(resp)
		return errNeedsLogin
	}
	if resp.StatusCode == http.StatusTooManyRequests {
		finish(resp)
		return errGLRateLimit
	}
	if resp.StatusCode != http.StatusOK {
		finish(resp)
		return errors.New("GL.iNet KVM 会话检查失败")
	}
	data, err := glinetRead(resp)
	if err != nil {
		return err
	}
	if !*data.OK {
		return errNeedsLogin
	}
	return nil
}

func (glinetAdapter) Expired(resp *http.Response) bool {
	return resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden && resp.Request.URL.Path == "/api/auth/check"
}

func (glinetAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	// Dropping this gateway's credentials avoids affecting another browser's
	// device session. An explicit logout in the native UI is still forwarded.
	clearNativeSession(c, s)
	return nil
}

func applyGlinetAuth(r *http.Request, s Service, g *gatewaySession) {
	auth := nativeSession(&http.Client{Jar: g.Jar}, s)
	for _, name := range []string{"token", "X-KVMD-User", "X-KVMD-Passwd"} {
		r.Header.Del(name)
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, cookie := range cookies {
		if cookie.Name != "auth_token" {
			r.AddCookie(cookie)
		}
	}
	if auth.Token != "" {
		r.Header.Set("token", auth.Token)
		r.AddCookie(&http.Cookie{Name: "auth_token", Value: auth.Token})
	}
	q := r.URL.Query()
	if q.Has("auth_token") {
		q.Del("auth_token")
		if auth.Token != "" {
			q.Set("auth_token", auth.Token)
		}
		r.URL.RawQuery = q.Encode()
	}
}

func captureGlinetLogin(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body := responsePrefix(resp, (128<<10)+1)
	var data glinetResponse
	if len(body) > 128<<10 || json.Unmarshal(body, &data) != nil || data.OK == nil {
		return errGLProtocol
	}
	if !*data.OK {
		return nil
	}
	var envelope, result map[string]json.RawMessage
	var value string
	if json.Unmarshal(body, &envelope) != nil || json.Unmarshal(data.Result, &result) != nil || json.Unmarshal(result["token"], &value) != nil || !glinetTokenPattern.MatchString(value) {
		return errGLProtocol
	}
	g.authMu.Lock()
	saveGlinetSession(&http.Client{Jar: g.Jar}, s, value)
	g.Manual = true
	g.Version++
	g.authMu.Unlock()
	result["token"], _ = json.Marshal(nativeBrowserMarker)
	envelope["result"], _ = json.Marshal(result)
	body, _ = json.Marshal(envelope)
	replaceResponseBody(resp, body)
	return nil
}

func glinetSafeRequest(r *http.Request) bool {
	if !safeRequest(r) {
		return false
	}
	if path.Clean(r.URL.Path) != r.URL.Path {
		return false
	}
	if r.URL.Path == "/" || strings.HasPrefix(r.URL.Path, "/assets/") {
		return true
	}
	if isWebSocket(r) && (r.URL.Path == "/api/ws" || r.URL.Path == "/ws" || r.URL.Path == "/janus/ws") {
		return true
	}
	// GLKVM also exposes power, reset, firmware and storage actions as GETs.
	// Only observed read endpoints qualify for automatic session recovery.
	switch r.URL.Path {
	case "/streamer/stream", "/streamer/snapshot", "/api/auth/check", "/api/init/is_inited", "/api/2fa/is_enabled", "/api/2fa/show", "/api/info",
		"/api/streamer", "/api/streamer/snapshot", "/api/hid", "/api/atx", "/api/msd", "/api/msd/partition_show",
		"/api/system/get_config", "/api/system/get_param", "/api/system/get_network_config", "/api/system/get_hostname",
		"/api/system/time", "/api/system/timezone/list", "/api/system/ssl_cert", "/api/system/otg_functions",
		"/api/upgrade/version", "/api/upgrade/compare", "/api/upgrade/download_info", "/api/upgrade/get_edid",
		"/api/repeater/get_status", "/api/repeater/get_saved_ap_list", "/api/ap/status", "/api/switch", "/api/turn/get_turn":
		return true
	}
	return false
}
