package shared

import (
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/yaronf/httpsign"
)

type SignerOption func(*httpsign.SignConfig)

// WithNonce sets the nonce in the signer config
// Note that a unique nonce is the responsibility of the request sender per the WIMSE S2S draft
// https://www.ietf.org/archive/id/draft-ietf-wimse-s2s-protocol-07.html#section-3.3-14
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

// GetWITHTTPSigner takes a witSVIDKey (i.e. the private key provided by the identity server
// issuing WIT-SVIDs) in string format and a slice of signed headers before returning an
// httpsign.Signer instance to make WIMSE HTTP signatures requests with
func GetWITHTTPSigner(witSVIDKey string, signedHeaders []string, opts ...SignerOption) (*httpsign.Signer, error) {
	cfg := httpsign.NewSignConfig().SetTag("wimse-workload-to-workload")

	for _, opt := range opts {
		opt(cfg)
	}

	parsedWITSVIDKey, err := parseWITSVIDKey(witSVIDKey)
	if err != nil {
		return nil, err
	}

	return httpsign.NewP256Signer(*parsedWITSVIDKey, cfg, httpsign.Headers(signedHeaders...))
}
