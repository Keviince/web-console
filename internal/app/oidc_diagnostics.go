package app

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (a *App) oidcFailure(w http.ResponseWriter, stage, reason string, status int, message string, details ...any) {
	requestID := token()[:12]
	attributes := []any{"stage", stage, "reason", reason, "request_id", requestID}
	attributes = append(attributes, details...)
	a.log.Warn("oidc authentication failed", attributes...)
	w.Header().Set("X-WebConsole-Request-ID", requestID)
	http.Error(w, fmt.Sprintf("%s（错误码：%s，参考编号：%s）", message, reason, requestID), status)
}

// Do not log raw verifier/OAuth errors: they can contain tokens, response bodies,
// callback URLs, or claims. Only emit known, fixed diagnostic codes.
func oidcVerificationReason(err error) string {
	var expired *oidc.TokenExpiredError
	if errors.As(err, &expired) {
		return "token_expired"
	}
	message := err.Error()
	switch {
	case strings.HasPrefix(message, "oidc: id token issued by a different provider"):
		return "issuer_mismatch"
	case strings.HasPrefix(message, "oidc: expected audience"):
		return "audience_mismatch"
	case strings.HasPrefix(message, "oidc: current time"):
		return "token_not_yet_valid"
	case strings.HasPrefix(message, "oidc: malformed jwt:"):
		if strings.Contains(message, "unexpected signature algorithm") {
			return "signing_algorithm_unsupported"
		}
		return "token_malformed"
	case strings.HasPrefix(message, "failed to verify signature:"):
		if strings.Contains(message, "fetching keys") || strings.Contains(message, "get keys failed") || strings.Contains(message, "failed to decode keys") {
			return "jwks_fetch_failed"
		}
		return "signature_invalid"
	default:
		return "id_token_invalid"
	}
}

func oidcExchangeReason(err error) (string, int) {
	var response *oauth2.RetrieveError
	if errors.As(err, &response) {
		status := 0
		if response.Response != nil {
			status = response.Response.StatusCode
		}
		return "token_" + safeOAuthError(response.ErrorCode), status
	}
	var unknownCA x509.UnknownAuthorityError
	var invalidCertificate x509.CertificateInvalidError
	var invalidHostname x509.HostnameError
	if errors.As(err, &unknownCA) || errors.As(err, &invalidCertificate) || errors.As(err, &invalidHostname) {
		return "token_tls_validation_failed", 0
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "token_dns_failed", 0
	}
	var network net.Error
	if errors.Is(err, context.DeadlineExceeded) || errors.As(err, &network) && network.Timeout() {
		return "token_endpoint_timeout", 0
	}
	return "token_exchange_failed", 0
}

func safeOAuthError(code string) string {
	switch code {
	case "invalid_request", "invalid_client", "invalid_grant", "unauthorized_client", "unsupported_grant_type", "invalid_scope", "access_denied", "server_error", "temporarily_unavailable", "unsupported_response_type":
		return code
	default:
		return "provider_error"
	}
}
