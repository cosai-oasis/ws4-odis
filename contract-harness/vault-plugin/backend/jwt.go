package backend

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

// jwtLeeway gives the standard ~1 minute of clock skew when checking time-based
// claims (exp/nbf/iat), matching jwt.DefaultLeeway.
const jwtLeeway = time.Minute

// Sentinel errors so callers fail closed with a clear reason when trust material
// is unusable.
var (
	errNoVerificationKeys = errors.New("issuer config has no usable verification keys")
	errNoPEMBlock         = errors.New("no PEM block found")
	// errTrustMaterial marks failures of the plugin's OWN trust material (issuer
	// config unreadable or unusable) — an internal/operator failure the issue
	// handler must log and 5xx, never report as a client "JWT rejected" 4xx.
	errTrustMaterial = errors.New("issuer trust material unavailable")
	errNoExpiry      = errors.New("token has no exp claim (a workload JWT must expire)")
	errTierNotScalar = errors.New("apf_tier claim is not a scalar (the tier ceiling would be bypassed)")
)

// allowedSignatureAlgorithms is the explicit allowlist of asymmetric signature
// algorithms the plugin accepts. ParseSigned requires it: accepting "none" or an
// unconstrained set would let a caller pick a weaker/forged algorithm.
func allowedSignatureAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{
		jose.RS256, jose.RS384, jose.RS512,
		jose.PS256, jose.PS384, jose.PS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.EdDSA,
	}
}

// validateJWT verifies a forwarded workload JWT against the stored issuerConfig
// and returns the validated identity to match against mappings. It fails closed
// on any error: missing config, bad signature, wrong issuer/audience, or expiry.
func (b *backend) validateJWT(ctx context.Context, s logical.Storage, token string) (matchInput, error) {
	cfg, err := b.readIssuerConfig(ctx, s)
	if err != nil {
		// Includes errIssuerNotConfigured — fail closed when no trust material is set.
		return matchInput{}, fmt.Errorf("validate jwt: %w: %w", errTrustMaterial, err)
	}

	keys, err := verificationKeys(cfg)
	if err != nil {
		return matchInput{}, fmt.Errorf("validate jwt: %w: %w", errTrustMaterial, err)
	}

	parsed, err := jwt.ParseSigned(token, allowedSignatureAlgorithms())
	if err != nil {
		return matchInput{}, fmt.Errorf("validate jwt: parse: %w", err)
	}

	// Verify against each trusted key (works whether or not the token carries a
	// kid, so jwks_pem keys — which have no KeyID — validate too). The algorithm
	// is already constrained by ParseSigned's asymmetric allowlist.
	claims, custom, err := verifyAny(parsed, keys)
	if err != nil {
		return matchInput{}, fmt.Errorf("validate jwt: %w", err)
	}

	expected := jwt.Expected{
		Issuer: cfg.BoundIssuer,
		Time:   time.Now(),
	}
	if len(cfg.BoundAudiences) > 0 {
		// AnyAudience matches if the token's aud intersects the bound set.
		expected.AnyAudience = jwt.Audience(cfg.BoundAudiences)
	}
	if err := claims.ValidateWithLeeway(expected, jwtLeeway); err != nil {
		return matchInput{}, fmt.Errorf("validate jwt: claims: %w", err)
	}
	// go-jose validates exp only when the claim is PRESENT: a token minted
	// without exp would otherwise verify forever. The issuance credential must
	// always expire.
	if claims.Expiry == nil {
		return matchInput{}, fmt.Errorf("validate jwt: claims: %w", errNoExpiry)
	}

	selectors, err := selectorClaims(custom)
	if err != nil {
		return matchInput{}, fmt.Errorf("validate jwt: claims: %w", err)
	}
	return matchInput{
		Issuer:    claims.Issuer,
		Audiences: []string(claims.Audience),
		Subject:   claims.Subject,
		Claims:    selectors,
	}, nil
}

// selectorClaims builds the selector map from the verified custom claims, failing
// closed on a claim shape that would silently weaken enforcement: an apf_tier the
// issuer emitted but stringClaims cannot represent (a non-scalar) must refuse
// issuance — dropped, it would bypass the tier ceiling (resolveCeiling would see
// no tier and apply no cap).
func selectorClaims(custom map[string]json.RawMessage) (map[string]string, error) {
	selectors := stringClaims(custom)
	if _, present := custom[claimTier]; present {
		if _, visible := selectors[claimTier]; !visible {
			return nil, errTierNotScalar
		}
	}
	return selectors, nil
}

// verificationKeys returns the flat list of trusted public keys from issuer
// config: a JWK Set (cfg.JWKS) and/or PEM public keys (cfg.JWKSPEM). Returning
// the raw keys (rather than a JSONWebKeySet) lets the verifier try each one
// regardless of the token's kid — PEM keys carry no KeyID.
func verificationKeys(cfg *issuerConfig) ([]any, error) {
	var keys []any

	if cfg.JWKS != "" {
		var parsed jose.JSONWebKeySet
		if err := json.Unmarshal([]byte(cfg.JWKS), &parsed); err != nil {
			return nil, fmt.Errorf("parse jwks: %w", err)
		}
		for i := range parsed.Keys {
			keys = append(keys, parsed.Keys[i].Key)
		}
	}

	for i, p := range cfg.JWKSPEM {
		key, err := parsePEMPublicKey(p)
		if err != nil {
			return nil, fmt.Errorf("parse jwks_pem[%d]: %w", i, err)
		}
		keys = append(keys, key)
	}

	if len(keys) == 0 {
		return nil, errNoVerificationKeys
	}
	return keys, nil
}

// verifyAny verifies the token against each trusted key, returning the claims
// from the first key that validates the signature. Fails closed if none do.
func verifyAny(parsed *jwt.JSONWebToken, keys []any) (jwt.Claims, map[string]json.RawMessage, error) {
	lastErr := errNoVerificationKeys
	for _, key := range keys {
		var (
			claims jwt.Claims
			custom map[string]json.RawMessage
		)
		if err := parsed.Claims(key, &claims, &custom); err != nil {
			lastErr = err
			continue
		}
		return claims, custom, nil
	}
	return jwt.Claims{}, nil, fmt.Errorf("verify signature: %w", lastErr)
}

// parsePEMPublicKey decodes a single PEM-encoded public key (PKIX) or certificate
// and returns its public key for signature verification.
func parsePEMPublicKey(pemStr string) (any, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errNoPEMBlock
	}
	if key, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return key, nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("not a PKIX public key or certificate: %w", err)
	}
	return cert.PublicKey, nil
}

// stringClaims renders every SCALAR custom claim (string, number, or bool) as a
// string, so the matcher (which compares string equality) and the tier-ceiling
// selector see every scalar claim. A non-string scalar is COERCED, not dropped: a
// dropped claim is invisible, and an invisible apf_tier claim would bypass the tier
// ceiling — resolveCeiling would see no tier, apply no cap, and the permission
// boundary would fail OPEN. Non-scalar claims (objects, arrays, null) are skipped:
// they cannot serve as a string selector. Registered claims are excluded.
func stringClaims(custom map[string]json.RawMessage) map[string]string {
	out := make(map[string]string, len(custom))
	for name, raw := range custom {
		switch name {
		case "iss", "sub", "aud", "exp", "nbf", "iat", "jti":
			// RFC 7519 registered claims: validated separately as ambient trust
			// gates (issuer / audience / subject / time); per the trust design
			// they must never act as bound_claims selectors.
			continue
		}
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			continue
		}
		switch t := v.(type) {
		case string:
			out[name] = t
		case bool:
			out[name] = strconv.FormatBool(t)
		case float64:
			// JSON numbers decode to float64; -1 precision renders the shortest
			// exact decimal (3 -> "3", not "3.000000").
			out[name] = strconv.FormatFloat(t, 'f', -1, 64)
		}
	}
	return out
}
