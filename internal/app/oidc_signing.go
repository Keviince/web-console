package app

import (
	"context"
	"errors"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
)

// HS256 uses this confidential client's secret, never a key from public JWKS.
// Asymmetric algorithms continue to use the provider's public signing keys.
type oidcSigningKeys struct {
	remote     oidc.KeySet
	secret     []byte
	algorithms []string
}

func (k *oidcSigningKeys) VerifySignature(ctx context.Context, raw string) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	algorithms := make([]jose.SignatureAlgorithm, len(k.algorithms))
	for i, algorithm := range k.algorithms {
		algorithms[i] = jose.SignatureAlgorithm(algorithm)
	}
	signed, err := jose.ParseSigned(raw, algorithms)
	if err != nil {
		return nil, err
	}
	if len(signed.Signatures) != 1 {
		return nil, errors.New("ID token requires exactly one signature")
	}
	if signed.Signatures[0].Header.Algorithm == "HS256" {
		return signed.Verify(k.secret)
	}
	return k.remote.VerifySignature(ctx, raw)
}

func allowedOIDCAlgorithms(advertised []string) []string {
	var algorithms []string
	for _, algorithm := range advertised {
		switch algorithm {
		case "HS256", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
			algorithms = append(algorithms, algorithm)
		}
	}
	if len(algorithms) == 0 {
		return []string{"RS256"}
	}
	return algorithms
}
