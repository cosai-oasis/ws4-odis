package backend

import (
	"context"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/hashicorp/vault/sdk/logical"
)

// White-box proof that swapping the trusted issuer to a SPIRE-shaped identity is
// CONFIG-ONLY: a SPIRE-style issuerConfig + a JWT-SVID-shaped token verify through
// the unchanged validateJWT path. The agent-SVID -> Router hand-off
// (sidecar-mint vs. supervisor) is an UNRESOLVED production question documented in
// vault/README.md, not a code concern here.

const (
	// spireIssuer mimics SPIRE's OIDC Discovery Provider document URL, the `iss`
	// of a JWT-SVID. No trailing slash — discovery URLs are bare.
	spireIssuer = "https://oidc-discovery.example.org"
	// spireSubject is a SPIFFE ID, the `sub` SPIRE puts on a JWT-SVID.
	spireSubject = "spiffe://example.org/ns/agents/sa/jira-agent"
	// spireAudience is the dedicated bundle-issuance audience the JWT-SVID targets.
	spireAudience = "apf-bundle-issuer"
)

// configureSPIREIssuer stores an issuerConfig trusting a SPIRE-shaped issuer and
// audience against the given JWKS. It is local to this test: the swap is purely a
// matter of which iss/aud the operator binds, so the shared configureIssuer is left
// untouched.
func configureSPIREIssuer(t *testing.T, s logical.Storage, jwks string) {
	t.Helper()
	cfg := issuerConfig{
		JWKS:           jwks,
		BoundIssuer:    spireIssuer,
		BoundAudiences: []string{spireAudience},
	}
	entry, err := logical.StorageEntryJSON(storageKeyIssuerConfig, cfg)
	if err != nil {
		t.Fatalf("encode spire issuer config: %v", err)
	}
	if err := s.Put(context.Background(), entry); err != nil {
		t.Fatalf("put spire issuer config: %v", err)
	}
}

// spireClaims builds a JWT-SVID-shaped claim set: SPIFFE-ID subject, OIDC-discovery
// issuer, the bundle-issuance audience, and standard exp/iat.
func spireClaims() jwt.Claims {
	now := time.Now()
	return jwt.Claims{
		Issuer:   spireIssuer,
		Subject:  spireSubject,
		Audience: jwt.Audience{spireAudience},
		Expiry:   jwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: jwt.NewNumericDate(now),
	}
}

// TestValidateJWTAcceptsSPIREShapedToken proves the SPIRE swap is config-only: the
// same validateJWT that handles the MVP fixture issuer accepts a JWT-SVID-shaped
// token once the issuerConfig is repointed at the SPIRE OIDC-discovery issuer and
// audience — with no edit to jwt.go.
func TestValidateJWTAcceptsSPIREShapedToken(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	// Reuse the EC key/JWKS plumbing; SPIRE's discovery provider likewise serves a
	// standard JWKS. Only the bound iss/aud differ from the fixture issuer.
	ts := newTestSigner(t)
	configureSPIREIssuer(t, s, ts.jwks)

	token := ts.mint(t, spireClaims(), nil)

	in, err := b.validateJWT(context.Background(), s, token)
	if err != nil {
		t.Fatalf("validateJWT rejected a SPIRE-shaped token: %v", err)
	}
	if in.Subject != spireSubject {
		t.Errorf("Subject = %q, want SPIFFE ID %q", in.Subject, spireSubject)
	}
	if in.Issuer != spireIssuer {
		t.Errorf("Issuer = %q, want discovery URL %q", in.Issuer, spireIssuer)
	}
	if len(in.Audiences) != 1 || in.Audiences[0] != spireAudience {
		t.Errorf("Audiences = %v, want [%s]", in.Audiences, spireAudience)
	}
}
