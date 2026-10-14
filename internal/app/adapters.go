package app

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type deviceAdapter interface {
	Login(context.Context, *http.Client, Service, Credentials) error
	Check(context.Context, *http.Client, Service) error
	Logout(context.Context, *http.Client, Service) error
	Expired(*http.Response) bool
}

var errNeedsLogin = errors.New("设备会话已失效")
var errLogin = errors.New("设备账号密码错误或需要二次验证，请检查凭据或手动登录")

func adapterFor(kind string) deviceAdapter {
	if kind == "pikvm" {
		return pikvmAdapter{}
	}
	if kind == "nanokvm" {
		return nanokvmAdapter{}
	}
	if kind == "blikvm" {
		return blikvmAdapter{}
	}
	switch kind {
	case "pve":
		return pveAdapter{}
	case "esxi":
		return esxiAdapter{}
	case "tplink":
		return tplinkAdapter{}
	case "xiaomi":
		return xiaomiAdapter{}
	}
	return luciAdapter{}
}

func newTransport(s Service) (*http.Transport, error) {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	t.DialContext = (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	t.ResponseHeaderTimeout = 20 * time.Second
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if s.CertificatePin != "" {
		if s.TrustedCA != "" {
			return nil, errors.New("可信 CA 与固定证书指纹只能选择一种")
		}
		pin, err := hex.DecodeString(normalizePin(s.CertificatePin))
		if err != nil || len(pin) != sha256.Size {
			return nil, errors.New("证书指纹必须是 64 位 SHA-256 十六进制文本")
		}
		// The configured certificate is the trust anchor. No other certificate,
		// including one issued for the same hostname, is accepted in this mode.
		t.TLSClientConfig.InsecureSkipVerify = true
		t.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return errCertificatePin
			}
			leaf := state.PeerCertificates[0]
			hash := sha256.Sum256(leaf.Raw)
			if subtle.ConstantTimeCompare(hash[:], pin) != 1 {
				return errCertificatePin
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return errPinnedCertificateTime
			}
			return nil
		}
	}
	if s.TrustedCA != "" {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM([]byte(s.TrustedCA)) {
			return nil, errors.New("可信证书必须是 PEM 格式的 CA 或设备证书")
		}
		t.TLSClientConfig.RootCAs = pool
	}
	return t, nil
}
func clientFor(s Service, g *gatewaySession) (*http.Client, error) {
	t, err := newTransport(s)
	if err != nil {
		return nil, err
	}
	origin, _ := url.Parse(s.UpstreamURL)
	return &http.Client{Transport: t, Jar: g.Jar, Timeout: 20 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error {
		if len(via) > 8 {
			return errDeviceRedirectLimit
		}
		if r.URL.User != nil || !sameDeviceOrigin(r.URL, origin) {
			if origin.Scheme == "http" && r.URL.Scheme == "https" && strings.EqualFold(r.URL.Hostname(), origin.Hostname()) {
				return errDeviceHTTPSRedirect
			}
			return errDeviceRedirectOrigin
		}
		return nil
	}}, nil
}
func call(ctx context.Context, c *http.Client, method, target string, form url.Values) (*http.Response, error) {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	r, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		return nil, errors.New("设备请求无效")
	}
	if form != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, connectionError(err)
	}
	return resp, nil
}
func connectionError(err error) error {
	var diagnosed *deviceConnectionError
	if errors.As(err, &diagnosed) {
		return diagnosed
	}
	reason, message := classifyDeviceConnection(err)
	return &deviceConnectionError{reason: reason, message: message, cause: err}
}

var errCertificatePin = errors.New("certificate fingerprint mismatch")
var errPinnedCertificateTime = errors.New("pinned certificate outside validity period")

func normalizePin(pin string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(pin), ":", ""))
}
func finish(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close()
}

type pikvmAdapter struct{}

func (pikvmAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	resp, err := call(ctx, c, "POST", s.UpstreamURL+"/api/auth/login", url.Values{"user": {cred.Username}, "passwd": {cred.Password}})
	if err != nil {
		return err
	}
	defer finish(resp)
	if resp.StatusCode != http.StatusOK {
		return errLogin
	}
	u, _ := url.Parse(s.UpstreamURL)
	for _, cookie := range c.Jar.Cookies(u) {
		if cookie.Name == "auth_token" && cookie.Value != "" {
			return nil
		}
	}
	return errors.New("PiKVM 未返回有效登录会话，请手动登录")
}
func (pikvmAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/api/auth/check", nil)
	if err != nil {
		return err
	}
	defer finish(resp)
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		return errors.New("PiKVM 登录检查失败")
	}
	return nil
}
func (pikvmAdapter) Logout(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "POST", s.UpstreamURL+"/api/auth/logout", nil)
	if err == nil {
		finish(resp)
	}
	return err
}
func (pikvmAdapter) Expired(r *http.Response) bool {
	return r.StatusCode == 401 || (r.StatusCode == 403 && strings.HasPrefix(r.Request.URL.Path, "/api/"))
}

type luciAdapter struct{}

func (luciAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/cgi-bin/luci/", nil)
	if err != nil {
		return err
	}
	base := resp.Request.URL
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	resp.Body.Close()
	if err != nil {
		return errors.New("读取 LuCI 登录页面失败")
	}
	form, action, challenge, found := luciForm(body)
	if challenge {
		return errors.New("LuCI 要求验证码或二次验证，请手动登录")
	}
	if !found {
		return errors.New("此 LuCI 登录页面不兼容自动登录，请手动登录")
	}
	form.Set("luci_username", cred.Username)
	form.Set("luci_password", cred.Password)
	u, err := url.Parse(action)
	if err != nil {
		return errors.New("LuCI 登录地址无效")
	}
	target := base.ResolveReference(u)
	root, _ := url.Parse(s.UpstreamURL)
	if target.Scheme != root.Scheme || target.Host != root.Host {
		return errors.New("LuCI 登录地址不能指向其他主机")
	}
	resp, err = call(ctx, c, "POST", target.String(), form)
	if err != nil {
		return err
	}
	defer finish(resp)
	if resp.StatusCode != 200 || resp.Header.Get("X-LuCI-Login-Required") == "yes" {
		return errLogin
	}
	return (luciAdapter{}).Check(ctx, c, s)
}
func (luciAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/cgi-bin/luci/", nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.Header.Get("X-LuCI-Login-Required") == "yes" || resp.StatusCode == 401 {
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		return errors.New("LuCI 登录检查失败")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return errors.New("读取 LuCI 状态失败")
	}
	_, _, _, found := luciForm(body)
	if found {
		return errNeedsLogin
	}
	return nil
}
func (luciAdapter) Logout(ctx context.Context, c *http.Client, s Service) error {
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/cgi-bin/luci/admin/logout", nil)
	if err == nil {
		finish(resp)
	}
	return err
}
func (luciAdapter) Expired(r *http.Response) bool {
	return r.StatusCode == 401 || r.Header.Get("X-LuCI-Login-Required") == "yes"
}

// Only standard LuCI password forms are submitted; extra interactive fields are never guessed.
func luciForm(body []byte) (url.Values, string, bool, bool) {
	doc, err := html.Parse(strings.NewReader(string(body)))
	if err != nil {
		return nil, "", false, false
	}
	var result url.Values
	var action string
	var challenge bool
	var visit func(*html.Node)
	visit = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "form" && result == nil {
			fields := url.Values{}
			hasUser, hasPass, needs := false, false, false
			var inputs func(*html.Node)
			inputs = func(i *html.Node) {
				if i.Type == html.ElementNode && i.Data == "input" {
					attrs := map[string]string{}
					for _, v := range i.Attr {
						attrs[v.Key] = v.Val
					}
					name, kind := attrs["name"], attrs["type"]
					if name == "luci_username" {
						hasUser = true
					}
					if name == "luci_password" {
						hasPass = true
					}
					if kind == "hidden" && name != "" {
						fields.Add(name, attrs["value"])
					}
					if name != "" && name != "luci_username" && name != "luci_password" && kind != "hidden" && kind != "submit" && kind != "button" && kind != "checkbox" {
						needs = true
					}
				}
				for child := i.FirstChild; child != nil; child = child.NextSibling {
					inputs(child)
				}
			}
			inputs(n)
			if hasUser && hasPass {
				result = fields
				challenge = needs
				for _, v := range n.Attr {
					if v.Key == "action" {
						action = v.Val
					}
				}
			}
		}
		for child := n.FirstChild; child != nil; child = child.NextSibling {
			visit(child)
		}
	}
	visit(doc)
	return result, action, challenge, result != nil
}

func (a *App) ensureLogin(ctx context.Context, s Service, g *gatewaySession, failedVersion *uint64) error {
	g.authMu.Lock()
	defer g.authMu.Unlock()
	if g.isClosed() {
		return errors.New("设备访问会话已撤销，请从门户重新打开")
	}
	if g.Manual || s.Type == "proxy" {
		return nil
	}
	if failedVersion != nil && g.Version != *failedVersion {
		return g.LastError
	}
	c, err := clientFor(s, g)
	if err != nil {
		logDeviceFailure(a.log, "device login failed", s, "transport", err)
		return err
	}
	defer c.Transport.(*http.Transport).CloseIdleConnections()
	if failedVersion == nil {
		err = adapterFor(s.Type).Check(ctx, c, s)
		if err == nil {
			return nil
		}
		if !errors.Is(err, errNeedsLogin) {
			logDeviceFailure(a.log, "device session check failed", s, "session_check", err)
			return err
		}
	}
	if g.LastError != nil && time.Now().Before(g.RetryAfter) {
		return g.LastError
	}
	if time.Since(g.LastAttempt) < 30*time.Second && g.LastError != nil {
		return g.LastError
	}
	g.LastAttempt = time.Now()
	cred, err := a.store.Credentials(ctx, s.ID)
	stage := "credentials"
	if err == nil {
		stage = "login"
		err = adapterFor(s.Type).Login(ctx, c, s, cred)
	}
	if err == nil {
		stage = "session_check"
		err = adapterFor(s.Type).Check(ctx, c, s)
	}
	g.LastError = err
	if err != nil {
		g.RetryAfter = time.Now().Add(30 * time.Second)
		var limited *nanoRateLimitError
		if errors.As(err, &limited) {
			g.RetryAfter = time.Now().Add(limited.retry)
		}
		if errors.Is(err, errBliRateLimit) || errors.Is(err, errNativeRateLimit) {
			g.RetryAfter = time.Now().Add(5 * time.Minute)
		}
	} else {
		g.RetryAfter = time.Time{}
	}
	g.Version++
	if err != nil {
		logDeviceFailure(a.log, "device login failed", s, stage, err)
	} else {
		a.log.Info("device login successful", "service", s.ID)
	}
	return err
}
