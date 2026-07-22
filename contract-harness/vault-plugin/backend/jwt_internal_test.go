package backend

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

// White-box tests for in-plugin workload-JWT validation.
// They mint JWTs in-test with go-jose so no network/issuer is required.

const (
	testJWTIssuer   = "https://fixture.issuer.odis.local/"
	testJWTAudience = "apf-bundle-issuer"
	testJWTSubject  = "spiffe://example.org/agent"
	testKeyID       = "test-signing-key"
)

// testSigner bundles an ES256 signer with the JWKS and PEM (public half) that trust it.
type testSigner struct {
	signer jose.Signer
	jwks   string
	pubPEM string
}

// newTestSigner mints an EC P-256 key, an ES256 signer, and the matching JWKS JSON.
func newTestSigner(t *testing.T) testSigner {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.ES256, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", testKeyID),
	)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}

	set := jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{
		Key:       priv.Public(),
		KeyID:     testKeyID,
		Algorithm: string(jose.ES256),
		Use:       "sig",
	}}}
	jwksBytes, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}

	der, err := x509.MarshalPKIXPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	return testSigner{signer: signer, jwks: string(jwksBytes), pubPEM: string(pubPEM)}
}

// configureIssuerPEM stores an issuerConfig that trusts via jwks_pem (no JWKS).
func configureIssuerPEM(t *testing.T, s logical.Storage, pubPEM string) {
	t.Helper()
	cfg := issuerConfig{
		JWKSPEM:        []string{pubPEM},
		BoundIssuer:    testJWTIssuer,
		BoundAudiences: []string{testJWTAudience},
	}
	entry, err := logical.StorageEntryJSON(storageKeyIssuerConfig, cfg)
	if err != nil {
		t.Fatalf("encode issuer config: %v", err)
	}
	if err := s.Put(context.Background(), entry); err != nil {
		t.Fatalf("put issuer config: %v", err)
	}
}

// TestValidateJWTAcceptsViaPEMTrust proves jwks_pem trust verifies a token even
// though PEM keys carry no kid — the verifier tries each trusted key.
func TestValidateJWTAcceptsViaPEMTrust(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuerPEM(t, s, ts.pubPEM)

	in, err := b.validateJWT(context.Background(), s, ts.mint(t, validClaims(), nil))
	if err != nil {
		t.Fatalf("validateJWT via jwks_pem: %v", err)
	}
	if in.Subject != testJWTSubject {
		t.Errorf("Subject = %q, want %q", in.Subject, testJWTSubject)
	}
}

// mint signs claims into a compact JWT string, folding in custom claims when present.
func (s testSigner) mint(t *testing.T, claims jwt.Claims, custom map[string]any) string {
	t.Helper()
	builder := jwt.Signed(s.signer).Claims(claims)
	if len(custom) > 0 {
		builder = builder.Claims(custom)
	}
	token, err := builder.Serialize()
	if err != nil {
		t.Fatalf("mint jwt: %v", err)
	}
	return token
}

func validClaims() jwt.Claims {
	return jwt.Claims{
		Issuer:   testJWTIssuer,
		Subject:  testJWTSubject,
		Audience: jwt.Audience{testJWTAudience},
		Expiry:   jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}
}

// configureIssuer stores an issuerConfig trusting the given JWKS.
func configureIssuer(t *testing.T, s logical.Storage, jwks string) {
	t.Helper()
	cfg := issuerConfig{
		JWKS:           jwks,
		BoundIssuer:    testJWTIssuer,
		BoundAudiences: []string{testJWTAudience},
	}
	entry, err := logical.StorageEntryJSON(storageKeyIssuerConfig, cfg)
	if err != nil {
		t.Fatalf("encode issuer config: %v", err)
	}
	if err := s.Put(context.Background(), entry); err != nil {
		t.Fatalf("put issuer config: %v", err)
	}
}

func TestValidateJWTValidToken(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	token := ts.mint(t, validClaims(), map[string]any{"group": "jira-writers"})

	in, err := b.validateJWT(context.Background(), s, token)
	if err != nil {
		t.Fatalf("validateJWT: %v", err)
	}
	if in.Issuer != testJWTIssuer {
		t.Errorf("Issuer = %q, want %q", in.Issuer, testJWTIssuer)
	}
	if in.Subject != testJWTSubject {
		t.Errorf("Subject = %q, want %q", in.Subject, testJWTSubject)
	}
	if len(in.Audiences) != 1 || in.Audiences[0] != testJWTAudience {
		t.Errorf("Audiences = %v, want [%s]", in.Audiences, testJWTAudience)
	}
	if in.Claims["group"] != "jira-writers" {
		t.Errorf("Claims[group] = %q, want jira-writers", in.Claims["group"])
	}
	// Registered claims are ambient trust gates, validated separately — they must
	// never surface in the selector map where bound_claims could match on them.
	for _, registered := range []string{"iss", "sub", "aud", "exp", "nbf", "iat", "jti"} {
		if v, ok := in.Claims[registered]; ok {
			t.Errorf("registered claim %q leaked into the selector map (=%q)", registered, v)
		}
	}
}

// A workload JWT minted WITHOUT an exp claim must be rejected: go-jose validates
// exp only when present, so without this check a leaked no-expiry token could be
// replayed to apf/issue forever.
func TestValidateJWTRequiresExpiry(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	claims := validClaims()
	claims.Expiry = nil
	if _, err := b.validateJWT(context.Background(), s, ts.mint(t, claims, nil)); err == nil {
		t.Error("expected a token without exp to be rejected")
	}
}

// An apf_tier claim the issuer emitted as a NON-SCALAR (array/object/null) must
// fail closed: silently dropped, it would bypass the tier ceiling entirely —
// resolveCeiling would see no tier and apply no cap (fail OPEN).
func TestValidateJWTNonScalarTierFailsClosed(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	token := ts.mint(t, validClaims(), map[string]any{"apf_tier": []string{"restricted"}})
	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected a non-scalar apf_tier to refuse issuance (ceiling bypass)")
	}
}

// A non-string scalar claim (a numeric or boolean) must be coerced to its string
// form, not silently dropped. This is a fail-closed requirement for the ceiling: an
// issuer that emits apf_tier as a JSON number must still select (or fail closed
// against) a ceiling. If the claim were dropped, resolveCeiling would see no tier,
// apply no cap, and the permission boundary would fail OPEN (full uncapped union).
func TestValidateJWTCoercesScalarClaims(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	token := ts.mint(t, validClaims(), map[string]any{
		"apf_tier": 3,                        // numeric tier: must coerce, not drop
		"active":   true,                     // bool: coerced
		"team":     "platform",               // string: unchanged
		"meta":     map[string]any{"k": "v"}, // non-scalar: dropped (not a selector)
	})
	in, err := b.validateJWT(context.Background(), s, token)
	if err != nil {
		t.Fatalf("validateJWT: %v", err)
	}
	if in.Claims["apf_tier"] != "3" {
		t.Errorf("apf_tier = %q, want %q — a numeric tier must coerce, else the ceiling fails open",
			in.Claims["apf_tier"], "3")
	}
	if in.Claims["active"] != "true" {
		t.Errorf("active = %q, want \"true\"", in.Claims["active"])
	}
	if in.Claims["team"] != "platform" {
		t.Errorf("team = %q, want \"platform\"", in.Claims["team"])
	}
	if got, ok := in.Claims["meta"]; ok {
		t.Errorf("a non-scalar claim must be dropped, got meta=%q", got)
	}
}

func TestValidateJWTTamperedSignature(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	// Trust one key, sign with a different one -> signature must not verify.
	trusted := newTestSigner(t)
	attacker := newTestSigner(t)
	configureIssuer(t, s, trusted.jwks)

	token := attacker.mint(t, validClaims(), nil)
	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected error for a token signed by an untrusted key")
	}
}

func TestValidateJWTWrongIssuer(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	claims := validClaims()
	claims.Issuer = "https://evil.issuer/"
	token := ts.mint(t, claims, nil)

	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected error for a token with the wrong issuer")
	}
}

func TestValidateJWTAudienceNotBound(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	claims := validClaims()
	claims.Audience = jwt.Audience{"some-other-audience"}
	token := ts.mint(t, claims, nil)

	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected error for a token whose audience is not in the bound set")
	}
}

func TestValidateJWTExpired(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)

	claims := validClaims()
	// Past the 1-minute leeway so it fails closed.
	claims.Expiry = jwt.NewNumericDate(time.Now().Add(-2 * time.Minute))
	token := ts.mint(t, claims, nil)

	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected error for an expired token")
	}
}

func TestValidateJWTIssuerNotConfigured(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ts := newTestSigner(t)
	// No issuer config stored -> must fail closed.

	token := ts.mint(t, validClaims(), nil)
	if _, err := b.validateJWT(context.Background(), s, token); err == nil {
		t.Error("expected error when the issuer is not configured")
	}
}
