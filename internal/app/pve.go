package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

type pveAdapter struct{}
type pveLoginResponse struct {
	Data struct {
		Ticket   string `json:"ticket"`
		Username string `json:"username"`
		CSRF     string `json:"CSRFPreventionToken"`
	} `json:"data"`
}

func validPVETicket(ticket string) bool {
	return strings.HasPrefix(ticket, "PVE:") && !pveChallenge(ticket) && len(ticket) < 32<<10 && !strings.ContainsAny(ticket, "\r\n\x00 \";")
}

func (pveAdapter) Login(ctx context.Context, c *http.Client, s Service, cred Credentials) error {
	user := cred.Username
	if !strings.Contains(user, "@") {
		user += "@pam"
	}
	resp, err := call(ctx, c, "POST", s.UpstreamURL+"/api2/json/access/ticket", url.Values{"username": {user}, "password": {cred.Password}, "new-format": {"1"}})
	if err != nil {
		return err
	}
	if resp.StatusCode == 429 {
		finish(resp)
		return errNativeRateLimit
	}
	if resp.StatusCode != 200 {
		finish(resp)
		return errLogin
	}
	var result pveLoginResponse
	if err := nativeJSON(resp, &result); err != nil {
		return err
	}
	if pveChallenge(result.Data.Ticket) {
		return errNativeInteractive
	}
	if !validPVETicket(result.Data.Ticket) || result.Data.Username != user || result.Data.CSRF == "" || strings.ContainsAny(result.Data.CSRF, "\r\n") {
		return errNativeProtocol
	}
	storePVETicket(c, s, nativeAuth{Token: result.Data.Ticket, Username: user, CSRF: result.Data.CSRF})
	return nil
}

func storePVETicket(c *http.Client, s Service, auth nativeAuth) {
	saveNativeSession(c, s, auth)
	u, _ := url.Parse(s.UpstreamURL + "/")
	c.Jar.SetCookies(u, []*http.Cookie{{Name: "PVEAuthCookie", Value: auth.Token, Path: "/", HttpOnly: true, Secure: u.Scheme == "https"}})
}

func (pveAdapter) Check(ctx context.Context, c *http.Client, s Service) error {
	if nativeSession(c, s).Token == "" {
		return errNeedsLogin
	}
	resp, err := call(ctx, c, "GET", s.UpstreamURL+"/api2/json/access/permissions", nil)
	if err != nil {
		return err
	}
	defer finish(resp)
	if resp.StatusCode == 401 {
		return errNeedsLogin
	}
	if resp.StatusCode != 200 {
		return errors.New("PVE 会话检查失败")
	}
	return nil
}
func (pveAdapter) Logout(_ context.Context, c *http.Client, s Service) error {
	clearNativeSession(c, s)
	return nil
}
func (pveAdapter) Expired(resp *http.Response) bool { return resp.StatusCode == 401 }

func pveLoginPath(path string) bool {
	return path == "/api2/json/access/ticket" || path == "/api2/extjs/access/ticket"
}

func capturePVELogin(resp *http.Response, s Service, g *gatewaySession) error {
	if resp.StatusCode != 200 {
		return nil
	}
	b := responsePrefix(resp, (128<<10)+1)
	var result pveLoginResponse
	if len(b) > 128<<10 || json.Unmarshal(b, &result) != nil {
		return errNativeProtocol
	}
	if result.Data.Ticket == "" {
		return nil
	}
	g.authMu.Lock()
	defer g.authMu.Unlock()
	c := &http.Client{Jar: g.Jar}
	auth := nativeSession(c, s)
	if result.Data.Username != "" {
		auth.Username = result.Data.Username
	}
	if result.Data.CSRF != "" {
		auth.CSRF = result.Data.CSRF
	}
	if pveChallenge(result.Data.Ticket) {
		auth.Token = ""
		saveNativeSession(c, s, auth)
		return nil // Native MFA needs its challenge; this is not an authenticated ticket.
	}
	if !validPVETicket(result.Data.Ticket) || auth.Username == "" || auth.CSRF == "" {
		return errNativeProtocol
	}
	auth.Token = result.Data.Ticket
	storePVETicket(c, s, auth)
	var envelope map[string]json.RawMessage
	_ = json.Unmarshal(b, &envelope)
	var data map[string]json.RawMessage
	_ = json.Unmarshal(envelope["data"], &data)
	data["ticket"], _ = json.Marshal(nativeBrowserMarker)
	envelope["data"], _ = json.Marshal(data)
	out, _ := json.Marshal(envelope)
	replaceResponseBody(resp, out)
	g.Version++
	return nil
}
