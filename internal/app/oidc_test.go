package app

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

const oidcFixtureSecret = "confidential-fixture-client-secret-32bytes"

func TestOIDCHS256AndFailureDiagnostics(t *testing.T) {
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"owner"}`)) + "."
	for _, tc := range []struct {
		name    string
		options oidcFixtureOptions
		status  int
		reason  string
	}{
		{"HS256 owner", oidcFixtureOptions{algorithm: jose.HS256}, 303, ""},
		{"HS256 not advertised", oidcFixtureOptions{algorithm: jose.HS256, advertisedAlgorithms: []string{"RS256"}}, 401, "signing_algorithm_unsupported"},
		{"wrong shared secret", oidcFixtureOptions{algorithm: jose.HS256, signingSecret: "different-fixture-client-secret-32bytes"}, 401, "signature_invalid"},
		{"wrong issuer", oidcFixtureOptions{algorithm: jose.HS256, claimOverrides: map[string]any{"iss": "https://wrong-provider.example/"}}, 401, "issuer_mismatch"},
		{"wrong audience", oidcFixtureOptions{algorithm: jose.HS256, claimOverrides: map[string]any{"aud": "different-client"}}, 401, "audience_mismatch"},
		{"expired", oidcFixtureOptions{algorithm: jose.HS256, claimOverrides: map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}}, 401, "token_expired"},
		{"nonce mismatch", oidcFixtureOptions{algorithm: jose.HS256, claimOverrides: map[string]any{"nonce": "sensitive-nonce"}}, 401, "nonce_mismatch"},
		{"forged RSA signature", oidcFixtureOptions{tamperSignature: true}, 401, "signature_invalid"},
		{"JWKS failure", oidcFixtureOptions{jwksStatus: 503}, 401, "jwks_fetch_failed"},
		{"no identity token", oidcFixtureOptions{missingIDToken: true}, 502, "id_token_missing"},
		{"token endpoint error", oidcFixtureOptions{exchangeError: "invalid_client"}, 502, "token_invalid_client"},
		{"token endpoint untrusted error", oidcFixtureOptions{exchangeError: "sensitive-arbitrary-error"}, 502, "token_provider_error"},
		{"unsigned token", oidcFixtureOptions{rawIDToken: unsigned}, 401, "signing_algorithm_unsupported"},
		{"malformed token", oidcFixtureOptions{rawIDToken: "sensitive-malformed-token"}, 401, "token_malformed"},
		{"account denied", oidcFixtureOptions{claimOverrides: map[string]any{"sub": "stranger"}}, 403, "subject_not_allowed"},
		{"RSA with both algorithms advertised", oidcFixtureOptions{advertisedAlgorithms: []string{"HS256", "RS256"}}, 303, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := tc.options
			if options.algorithm == jose.HS256 && options.signingSecret == "" {
				options.signingSecret = oidcFixtureSecret
			}
			issuer := newOIDCWithOptions(t, options)
			var logs bytes.Buffer
			cfg := Config{PortalURL: "http://console.localhost:8080", DeviceDomain: "console.localhost", Issuer: issuer.server.URL, ClientID: "webconsole", ClientSecret: oidcFixtureSecret, AllowedSub: "owner", DataDir: t.TempDir(), Key: bytes.Repeat([]byte{1}, 32), DevHTTP: true, SessionTTL: time.Hour}
			a, err := New(context.Background(), cfg, slog.New(slog.NewJSONHandler(&logs, nil)))
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			start := request(a, "GET", cfg.PortalURL+"/auth/login", nil, nil, "")
			if start.Code != 302 {
				t.Fatal(start.Code)
			}
			browserCookie := start.Result().Cookies()[0]
			client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			resp, err := client.Get(start.Header().Get("Location"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			callback := resp.Header.Get("Location")
			got := request(a, "GET", callback, nil, browserCookie, "")
			if got.Code != tc.status {
				t.Fatalf("callback %d: %s", got.Code, got.Body.String())
			}
			if got.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("authentication response can be cached")
			}
			if tc.reason == "" {
				var portal *http.Cookie
				for _, cookie := range got.Result().Cookies() {
					if cookie.Name == "wc_portal" {
						portal = cookie
					}
				}
				if portal == nil || request(a, "GET", cfg.PortalURL+"/api/me", nil, portal, "").Code != 200 {
					t.Fatal("verified owner did not get a portal session")
				}
			} else {
				requestID := got.Header().Get("X-WebConsole-Request-ID")
				if requestID == "" || !strings.Contains(got.Body.String(), requestID) || !strings.Contains(got.Body.String(), tc.reason) {
					t.Fatalf("failure page has no corresponding diagnostic: %s", got.Body.String())
				}
				decoder := json.NewDecoder(bytes.NewReader(logs.Bytes()))
				found := false
				for {
					var event map[string]any
					if err := decoder.Decode(&event); err == io.EOF {
						break
					} else if err != nil {
						t.Fatal(err)
					}
					if event["reason"] == tc.reason && event["request_id"] == requestID && event["level"] == "WARN" {
						found = true
					}
				}
				if !found {
					t.Fatalf("no matching failure log: %s", logs.String())
				}
				for _, cookie := range got.Result().Cookies() {
					if cookie.Name == "wc_portal" && cookie.Value != "" {
						t.Fatal("failed authentication created a portal session")
					}
				}
			}
			target, _ := url.Parse(callback)
			for _, secret := range []string{oidcFixtureSecret, "sensitive-access-token", "sensitive-upstream-body", "sensitive-nonce", "sensitive-malformed-token", "sensitive-arbitrary-error", issuer.lastIDToken, issuer.lastCode, browserCookie.Value, target.Query().Get("state")} {
				if secret != "" && strings.Contains(logs.String(), secret) {
					t.Fatal("authentication log exposed sensitive data")
				}
			}
		})
	}
}

func TestOIDCCallbackFailuresAreLogged(t *testing.T) {
	for _, tc := range []struct {
		name, reason, providerError string
		missingState, unknownState  bool
		missingCookie, wrongCookie  bool
		expired, missingCode        bool
	}{
		{name: "missing state", reason: "state_missing", missingState: true},
		{name: "unknown transaction", reason: "transaction_missing", unknownState: true},
		{name: "missing browser cookie", reason: "browser_cookie_missing", missingCookie: true},
		{name: "wrong browser cookie", reason: "browser_cookie_mismatch", wrongCookie: true},
		{name: "expired transaction", reason: "transaction_expired", expired: true},
		{name: "authorization declined", reason: "provider_access_denied", providerError: "access_denied"},
		{name: "untrusted provider error", reason: "provider_provider_error", providerError: "sensitive-provider-error"},
		{name: "missing code", reason: "code_missing", missingCode: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			a := &App{cfg: Config{DevHTTP: true}, sessions: newSessions(), log: slog.New(slog.NewJSONHandler(&logs, nil))}
			transaction := authTransaction{State: token(), Browser: token(), Expires: time.Now().Add(time.Minute)}
			if tc.expired {
				transaction.Expires = time.Now().Add(-time.Minute)
			}
			a.sessions.transactions[transaction.State] = transaction
			params := url.Values{"state": {transaction.State}, "code": {"sensitive-code"}}
			if tc.missingState {
				params.Del("state")
			}
			if tc.unknownState {
				params.Set("state", "unknown-state")
			}
			if tc.missingCode {
				params.Del("code")
			}
			if tc.providerError != "" {
				params.Set("error", tc.providerError)
				params.Set("error_description", "sensitive-provider-description")
			}
			r := httptest.NewRequest("GET", "http://console.localhost:8080/auth/callback?"+params.Encode(), nil)
			if !tc.missingCookie {
				value := transaction.Browser
				if tc.wrongCookie {
					value = "sensitive-wrong-browser"
				}
				r.AddCookie(&http.Cookie{Name: "wc_oidc", Value: value})
			}
			w := httptest.NewRecorder()
			a.callback(w, r)
			var event map[string]any
			if err := json.Unmarshal(logs.Bytes(), &event); err != nil {
				t.Fatal(err)
			}
			if w.Code < 400 || event["reason"] != tc.reason || event["request_id"] != w.Header().Get("X-WebConsole-Request-ID") {
				t.Fatalf("incorrect callback failure: %d %s", w.Code, logs.String())
			}
			for _, secret := range []string{transaction.State, transaction.Browser, "sensitive-code", "sensitive-wrong-browser", "sensitive-provider-description", "sensitive-provider-error"} {
				if strings.Contains(logs.String(), secret) {
					t.Fatal("callback failure log exposed sensitive data")
				}
			}
		})
	}
}

func TestOIDCSigningRejectsPublicKeyAsHMACSecret(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: publicDER}, nil)
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"iss": "https://auth.example/", "aud": "webconsole", "sub": "owner", "exp": time.Now().Add(time.Hour).Unix()})
	signed, err := signer.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := signed.CompactSerialize()
	keys := &oidcSigningKeys{remote: &oidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}, secret: []byte(oidcFixtureSecret), algorithms: []string{"HS256", "RS256"}}
	verifier := oidc.NewVerifier("https://auth.example/", keys, &oidc.Config{ClientID: "webconsole", SupportedSigningAlgs: keys.algorithms})
	if _, err := verifier.Verify(context.Background(), raw); err == nil {
		t.Fatal("RSA public key accepted as HMAC secret")
	}
}
