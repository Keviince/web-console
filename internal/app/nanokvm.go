package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// This adapter matches the JSON username/password protocol observed on the
// user's NanoKVM. Older encrypted-password frontends need another adapter;
// passwords are never guessed or resubmitted in another format.
type nanokvmAdapter struct{}

type nanoResponse struct {
	Code *int `json:"code"`
	Data struct {
		Token       string  `json:"token"`
		Username    string  `json:"username"`
		Enabled     bool    `json:"enabled"`
		Requires2FA bool    `json:"requires2FA"`
		Challenge   string  `json:"challenge"`
		RateLimited bool    `json:"rateLimited"`
		RetryAfter  float64 `json:"retryAfter"`
	} `json:"data"`
}

var errNanoInteractive = errors.New("NanoKVM 要求二次验证，请在原页面手动完成")

func nanoRead(resp *http.Response) (nanoResponse, error) {
	defer resp.Body.Close()
	var result nanoResponse
	b, err := io.ReadAll(io.LimitReader(resp.Body, (64<<10)+1))
	if err != nil || len(b) > 64<<10 {
		return result, errors.New("读取 NanoKVM 响应失败")
	}
	if err = json.Unmarshal(b, &result); err != nil || result.Code == nil {
		return result, errors.New("NanoKVM 响应不兼容当前登录协议，请手动登录")
	}
	return result, nil
}
func (nanokvmAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	// Read the public login-mode flag first. 404 supports firmware without
	// direct-2FA mode; when enabled no stored password is submitted.
	preflight, err := call(ctx, c, "GET", s.UpstreamURL+"/api/auth/login/2fa-direct", nil)
	if err != nil {
		return err
	}
	if preflight.StatusCode == 200 {
		status, err := nanoRead(preflight)
		if err != nil {
			return err
		}
		if *status.Code != 0 {
			return errLogin
		}
		if status.Data.Enabled {
			return errNanoInteractive
		}
	} else {
		status := preflight.StatusCode
		finish(preflight)
		if status != 404 {
			return errors.New("无法检查 NanoKVM 登录模式，请手动登录")
		}
	}
	body, _ := json.Marshal(cred)
	r, err := http.NewRequestWithContext(ctx, "POST", s.UpstreamURL+"/api/auth/login", bytes.NewReader(body))
	if err != nil {
		return errors.New("NanoKVM 登录地址无效")
	}
	r.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(r)
	if err != nil {
		return connectionError(err)
	}
	if resp.StatusCode == 429 {
		finish(resp)
		return &nanoRateLimitError{retry: 5 * time.Minute}
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errLogin
	}
	issuedTokenCookie := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "nano-kvm-token" && cookie.Value != "" && cookie.MaxAge >= 0 {
			issuedTokenCookie = true
		}
	}
	data, err := nanoRead(resp)
	if err != nil {
		return err
	}
	if data.Data.RateLimited || *data.Code == -4 || *data.Code == -5 {
		retry := 5 * time.Minute
		if data.Data.RetryAfter > 0 && !math.IsInf(data.Data.RetryAfter, 0) {
			retry = time.Duration(math.Min(data.Data.RetryAfter, 24*60*60)) * time.Second
		}
		return &nanoRateLimitError{retry: retry}
	}
	if *data.Code != 0 {
		return errLogin
	}
	if data.Data.Requires2FA || data.Data.Challenge != "" {
		return errNanoInteractive
	}
	// Current firmware sends an HttpOnly session cookie. Some plaintext-JSON
	// firmware instead returns a JWT for the legacy nano-kvm-token cookie.
	if !issuedTokenCookie && data.Data.Token != "" && data.Data.Token != "disabled" && strings.Count(data.Data.Token, ".") == 2 {
		u, _ := url.Parse(s.UpstreamURL)
		c.Jar.SetCookies(u, []*http.Cookie{{Name: "nano-kvm-token", Value: data.Data.Token, Path: "/", HttpOnly: true, Secure: u.Scheme == "https"}})
	}
	return (nanokvmAdapter{}).Check(ctx, c, s)
}
func (nanokvmAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/api/auth/account", nil)
	if err != nil {
		return err
	}
	if resp.StatusCode == 401 {
		finish(resp)
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errors.New("NanoKVM 会话检查失败")
	}
	data, err := nanoRead(resp)
	if err != nil {
		return err
	}
	if *data.Code != 0 || data.Data.Username == "" {
		return errNeedsLogin
	}
	return nil
}
func (nanokvmAdapter) Expired(resp *http.Response) bool { return resp.StatusCode == 401 }
func (nanokvmAdapter) Logout(_ context.Context, _ *http.Client, _ Service) error {
	// Some firmwares rotate their global JWT secret on logout, ending other
	// browsers' sessions. Revoke the gateway, close connections and discard
	// its cookie jar instead of calling that endpoint automatically.
	return nil
}

type nanoRateLimitError struct{ retry time.Duration }

func (*nanoRateLimitError) Error() string {
	return "NanoKVM 限制了登录尝试，请稍后再试或使用原页面登录"
}
