package shared

import (
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/yaronf/httpsign"
)

type SignerOption func(*httpsign.SignConfig)

// WithNonce sets the nonce in the signer config
func WithNonce(nonce string) SignerOption {
	return func(cfg *httpsign.SignConfig) {
		if nonce != "" {
			cfg.SetNonce(nonce)
		}
	}
}

// WithClaims sets expiry based on JWT claims
func WithClaims(claims *jwt.Claims) SignerOption {
	return func(cfg *httpsign.SignConfig) {
		if claims != nil && !claims.Expiry.Time().IsZero() {
			cfg.SetExpires(claims.Expiry.Time().Unix())
		}
	}
}

// WithKeyID sets the key ID returned as a signature parameter
func WithKeyID(keyID string) SignerOption {
	return func(cfg *httpsign.SignConfig) {
		if keyID != "" {
			cfg.SetKeyID(keyID)
		}
	}
}

func GetWITHTTPSigner(witSVIDKey string, signedHeaders []string, opts ...SignerOption) (*httpsign.Signer, error) {
	cfg := httpsign.NewSignConfig().
		SetTag("wimse-service-to-service")

	for _, opt := range opts {
		opt(cfg)
	}

	parsedWITSVIDKey, err := ParseWITSVIDKey(witSVIDKey)
	if err != nil {
		return nil, err
	}

	return httpsign.NewP256Signer(*parsedWITSVIDKey, cfg, httpsign.Headers(signedHeaders...))
}
