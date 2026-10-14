package app

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type authenticator struct {
	oauth             oauth2.Config
	verifier          *oidc.IDTokenVerifier
	signingAlgorithms []string
}

func newAuthenticator(ctx context.Context, cfg Config) (*authenticator, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	ctx = oidc.ClientContext(ctx, &http.Client{Timeout: 15 * time.Second})
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, err
	}
	var metadata struct {
		JWKS       string   `json:"jwks_uri"`
		Algorithms []string `json:"id_token_signing_alg_values_supported"`
	}
	if err := provider.Claims(&metadata); err != nil {
		return nil, errors.New("cannot read OIDC discovery metadata")
	}
	for _, raw := range []string{provider.Endpoint().AuthURL, provider.Endpoint().TokenURL, metadata.JWKS} {
		u, err := url.Parse(raw)
		if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && !(cfg.DevHTTP && u.Scheme == "http" && isLoopback(u.Hostname()))) {
			return nil, errors.New("OIDC discovery endpoints require HTTPS")
		}
	}
	algorithms := allowedOIDCAlgorithms(metadata.Algorithms)
	verifier := provider.Verifier(&oidc.Config{ClientID: cfg.ClientID})
	for _, algorithm := range algorithms {
		if algorithm == "HS256" {
			verifier = oidc.NewVerifier(cfg.Issuer, &oidcSigningKeys{remote: oidc.NewRemoteKeySet(ctx, metadata.JWKS), secret: []byte(cfg.ClientSecret), algorithms: algorithms}, &oidc.Config{ClientID: cfg.ClientID, SupportedSigningAlgs: algorithms})
			break
		}
	}
	return &authenticator{oauth: oauth2.Config{ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Endpoint: provider.Endpoint(), RedirectURL: cfg.PortalURL + "/auth/callback", Scopes: []string{oidc.ScopeOpenID, "profile"}}, verifier: verifier, signingAlgorithms: algorithms}, nil
}
func (a *App) cookie(w http.ResponseWriter, name, value string, expires time.Time) {
	if a.cfg.DevHTTP {
		name = strings.TrimPrefix(name, "__Host-")
	}
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteLaxMode, Expires: expires})
}
func (a *App) readCookie(r *http.Request, name string) string {
	if a.cfg.DevHTTP {
		name = strings.TrimPrefix(name, "__Host-")
	}
	c, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return c.Value
}
func (a *App) clearCookie(w http.ResponseWriter, name string) {
	if a.cfg.DevHTTP {
		name = strings.TrimPrefix(name, "__Host-")
	}
	http.SetCookie(w, &http.Cookie{Name: name, Path: "/", HttpOnly: true, Secure: !a.cfg.DevHTTP, SameSite: http.SameSiteLaxMode, MaxAge: -1})
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	returnTo := "/"
	if slug := r.URL.Query().Get("device"); slug != "" {
		if _, err := a.store.BySlug(r.Context(), slug); err == nil {
			returnTo = "/auth/launch?device=" + url.QueryEscape(slug)
		}
	}
	t := authTransaction{State: token(), Nonce: token(), Verifier: oauth2.GenerateVerifier(), Browser: token(), ReturnTo: returnTo, Expires: time.Now().Add(5 * time.Minute)}
	a.sessions.mu.Lock()
	a.sessions.transactions[t.State] = t
	a.sessions.mu.Unlock()
	a.cookie(w, transactionCookie, t.Browser, t.Expires)
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, a.auth.oauth.AuthCodeURL(t.State, oauth2.S256ChallengeOption(t.Verifier), oidc.Nonce(t.Nonce)), http.StatusFound)
}
func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	state := r.URL.Query().Get("state")
	browser := a.readCookie(r, transactionCookie)
	a.sessions.mu.Lock()
	t, ok := a.sessions.transactions[state]
	if ok && constantEqual(browser, t.Browser) {
		delete(a.sessions.transactions, state)
	} else {
		ok = false
	}
	a.sessions.mu.Unlock()
	a.clearCookie(w, transactionCookie)
	if !ok {
		reason := "transaction_missing"
		switch {
		case state == "":
			reason = "state_missing"
		case browser == "":
			reason = "browser_cookie_missing"
		case t.Browser != "":
			reason = "browser_cookie_mismatch"
		}
		a.oidcFailure(w, "callback", reason, http.StatusBadRequest, "登录请求已失效，请重新登录")
		return
	}
	if !time.Now().Before(t.Expires) {
		a.oidcFailure(w, "callback", "transaction_expired", http.StatusBadRequest, "登录请求已失效，请重新登录")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		a.oidcFailure(w, "authorization", "provider_"+safeOAuthError(providerError), http.StatusUnauthorized, "Authentik 未完成授权，请重新登录")
		return
	}
	code := r.URL.Query().Get("code")
	if code == "" {
		a.oidcFailure(w, "callback", "code_missing", http.StatusBadRequest, "登录响应缺少授权码，请重新登录")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	access, err := a.auth.oauth.Exchange(ctx, code, oauth2.VerifierOption(t.Verifier))
	if err != nil {
		reason, status := oidcExchangeReason(err)
		a.oidcFailure(w, "token_exchange", reason, http.StatusBadGateway, "Authentik 登录失败，请重新登录", "upstream_status", status)
		return
	}
	raw, ok := access.Extra("id_token").(string)
	if !ok || raw == "" {
		a.oidcFailure(w, "token_response", "id_token_missing", http.StatusBadGateway, "登录响应缺少身份令牌")
		return
	}
	id, err := a.auth.verifier.Verify(ctx, raw)
	if err != nil {
		a.oidcFailure(w, "id_token_verification", oidcVerificationReason(err), http.StatusUnauthorized, "身份验证失败，请查看服务日志")
		return
	}
	if !constantEqual(id.Nonce, t.Nonce) {
		a.oidcFailure(w, "nonce", "nonce_mismatch", http.StatusUnauthorized, "身份验证失败，请重新发起登录")
		return
	}
	if !constantEqual(id.Subject, a.cfg.AllowedSub) {
		a.oidcFailure(w, "account", "subject_not_allowed", http.StatusForbidden, "此账号没有访问权限", "subject", id.Subject)
		return
	}
	var claims struct {
		Name              string `json:"name"`
		PreferredUsername string `json:"preferred_username"`
	}
	_ = id.Claims(&claims)
	name := claims.Name
	if name == "" {
		name = claims.PreferredUsername
	}
	if name == "" {
		name = "管理员"
	}
	if old := a.sessions.portal(a.readCookie(r, portalCookie)); old != nil {
		a.sessions.revokePortal(old.ID)
	}
	p := a.sessions.addPortal(id.Subject, name, a.cfg.SessionTTL)
	a.cookie(w, portalCookie, p.ID, p.Expires)
	a.log.Info("portal login successful")
	http.Redirect(w, r, t.ReturnTo, http.StatusSeeOther)
}
func constantEqual(a, b string) bool {
	return a != "" && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
func (a *App) portalAuth(w http.ResponseWriter, r *http.Request) *portalSession {
	p := a.sessions.portal(a.readCookie(r, portalCookie))
	if p == nil {
		jsonError(w, http.StatusUnauthorized, "请先登录 Authentik")
		return nil
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		if r.Header.Get("Origin") != a.cfg.PortalURL || !constantEqual(r.Header.Get("X-CSRF-Token"), p.CSRF) {
			jsonError(w, http.StatusForbidden, "请求来源或安全令牌无效")
			return nil
		}
	}
	return p
}
func (a *App) launchRedirect(w http.ResponseWriter, r *http.Request) {
	p := a.sessions.portal(a.readCookie(r, portalCookie))
	slug := r.URL.Query().Get("device")
	s, err := a.store.BySlug(r.Context(), slug)
	if err != nil || s.Type == "link" {
		http.NotFound(w, r)
		return
	}
	if p == nil {
		http.Redirect(w, r, "/auth/login?device="+url.QueryEscape(slug), http.StatusFound)
		return
	}
	t := a.sessions.ticket(p, s.ID)
	http.Redirect(w, r, a.cfg.deviceOrigin(s.Slug)+"/__webconsole/start?ticket="+url.QueryEscape(t), http.StatusSeeOther)
}
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func jsonError(w http.ResponseWriter, status int, message string) {
	jsonReply(w, status, map[string]string{"error": message})
}
