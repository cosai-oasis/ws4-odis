package backend

import (
	"context"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// White-box tests for the issue endpoint. A fake Signer stands in for the
// transit self-call so the full validate->map->assemble->sign->envelope flow and
// its fail-closed paths are exercised without a live Vault.

type fakeSigner struct {
	signature string
	err       error
}

func (f fakeSigner) Sign(_ context.Context, _ []byte) (string, error) {
	return f.signature, f.err
}

func newIssueTestBackend(t *testing.T, signer Signer) (*backend, logical.Storage) {
	t.Helper()
	b := newBackend()
	b.signerFactory = func(_ *signingConfig) (Signer, error) {
		return signer, nil
	}
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b, config.StorageView
}

func storeMapping(t *testing.T, s logical.Storage) {
	t.Helper()
	entry := mappingEntry{
		Name:                "jira",
		BoundIssuer:         testJWTIssuer,
		BoundAudiences:      []string{testJWTAudience},
		BoundSubject:        testJWTSubject,
		DelegatingPrincipal: testPrincipal,
		LifecycleState:      lifecycleActive,
		RecordVersion:       1,
		GrantTTLSeconds:     int(defaultGrantTTL.Seconds()),
		Grant: grant{
			BundleID:      "odis-fixture-bundle",
			BundleVersion: "0.1.0",
			TrustRootID:   "fixture-trust-root",
			Families: map[string]grantFamily{
				"jira-prod": {
					VendorMCP: apfbundle.VendorMCP{
						EndpointID: "jira-prod-mcp-v1",
						URL:        "https://jira-prod-mcp.internal:8443/",
						EgressMode: apfbundle.EgressModeBridge,
					},
					Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
						{Verb: "update_issue", AllowFields: []string{"labels"}},
					}},
					DefaultMode: modeStrict,
				},
			},
		},
	}
	se, err := logical.StorageEntryJSON(storageKeyMappingPrefix+"jira", entry)
	if err != nil {
		t.Fatalf("encode mapping: %v", err)
	}
	if err := s.Put(context.Background(), se); err != nil {
		t.Fatalf("put mapping: %v", err)
	}
}

func storeSigningConfig(t *testing.T, s logical.Storage) {
	t.Helper()
	cfg := signingConfig{
		TransitMount: "transit",
		TransitKey:   "apf-bundle",
		ApproleMount: "approle",
		RoleID:       "test-role-id",
		SecretID:     "test-secret-id",
	}
	se, err := logical.StorageEntryJSON(storageKeySigningConfig, cfg)
	if err != nil {
		t.Fatalf("encode signing config: %v", err)
	}
	if err := s.Put(context.Background(), se); err != nil {
		t.Fatalf("put signing config: %v", err)
	}
}

func issueRequest(t *testing.T, b *backend, s logical.Storage, data map[string]any) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue",
		Storage:   s,
		Data:      data,
	})
}

func TestHandleIssueSuccess(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:ZmFrZXNpZw=="})
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)
	storeMapping(t, s)
	storeSigningConfig(t, s)

	token := ts.mint(t, validClaims(), map[string]any{"group": "jira-writers"})
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("unexpected error response: %v", resp)
	}
	if resp.Data["signature"] != "vault:v1:ZmFrZXNpZw==" {
		t.Errorf("signature = %v", resp.Data["signature"])
	}
	if payload, _ := resp.Data["payload"].(string); payload == "" {
		t.Error("expected a non-empty payload")
	}
	signing, _ := resp.Data["signing"].(map[string]any)
	if signing["key_version"] != 1 {
		t.Errorf("key_version = %v, want 1", signing["key_version"])
	}
	if signing["algorithm"] != "ed25519" {
		t.Errorf("algorithm = %v, want ed25519", signing["algorithm"])
	}
}

func TestHandleIssueRejectsUntrustedJWT(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:x"})
	trusted := newTestSigner(t)
	attacker := newTestSigner(t)
	configureIssuer(t, s, trusted.jwks)
	storeMapping(t, s)
	storeSigningConfig(t, s)

	token := attacker.mint(t, validClaims(), nil)
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error response for an untrusted JWT")
	}
	if resp != nil && resp.Data["payload"] != nil {
		t.Error("must not return a bundle on rejection")
	}
}

// No mapping matches -> genuine authorization-absence: a 4xx error-RESPONSE with a
// nil Go error (errNoAuthorizedBundle), NOT a 5xx. This is the only path that may
// return a client error response; every internal/config failure must 5xx (see below).
func TestHandleIssueNoMappingMatch(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:x"})
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)
	storeSigningConfig(t, s) // no mapping stored

	token := ts.mint(t, validClaims(), nil)
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err != nil {
		t.Fatalf("authorization-absence must be a nil Go error, got: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error response when no mapping matches")
	}
}

// storeCollidingMappings stores two assigned mappings the canonical token matches
// (both bound by its exact subject) that COLLIDE on the same family — composeMappings
// fails closed with a real, log-worthy error. This must surface as a 5xx
// (errIssuanceFailed), NOT a silent client 4xx that hides a real config error.
func storeCollidingMappings(t *testing.T, s logical.Storage) {
	t.Helper()
	fam := grantFamily{
		VendorMCP: apfbundle.VendorMCP{
			EndpointID: "e", URL: "https://v/", EgressMode: apfbundle.EgressModeBridge,
		},
		Policy:      policydsl.PolicySpec{Rules: []policydsl.Rule{{Verb: "update_issue", AllowFields: []string{"labels"}}}},
		DefaultMode: modeStrict,
	}
	for _, name := range []string{"a", "b"} {
		entry := mappingEntry{
			Name:                name,
			BoundSubject:        testJWTSubject,
			DelegatingPrincipal: testPrincipal,
			LifecycleState:      lifecycleActive,
			RecordVersion:       1,
			GrantTTLSeconds:     int(defaultGrantTTL.Seconds()),
			Grant: grant{
				BundleID: "b", BundleVersion: "1", TrustRootID: "r",
				Families: map[string]grantFamily{"jira-prod": fam},
			},
		}
		se, err := logical.StorageEntryJSON(storageKeyMappingPrefix+name, entry)
		if err != nil {
			t.Fatalf("encode mapping %q: %v", name, err)
		}
		if err := s.Put(context.Background(), se); err != nil {
			t.Fatalf("put mapping %q: %v", name, err)
		}
	}
}

// A real resolveBundle failure (here a same-family collision across two assigned
// mappings) must surface as a 5xx Go error (errIssuanceFailed) with NO payload — an
// internal/config error is reported and logged, not masked as a silent client 4xx.
func TestHandleIssueResolveErrorFailsClosed(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:x"})
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)
	storeCollidingMappings(t, s)
	storeSigningConfig(t, s)

	token := ts.mint(t, validClaims(), nil)
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err == nil {
		t.Error("expected a Go error (5xx) when resolveBundle hits a real failure, not a silent 4xx")
	}
	if resp != nil && resp.Data["payload"] != nil {
		t.Error("must not return a bundle when bundle resolution fails")
	}
}

// An identity whose apf_tier claim names a ceiling that is NOT configured is an
// operator config gap, not an internal failure: it must surface as genuine
// authorization-absence — a 4xx error RESPONSE with a NIL Go error and NO payload
// (the identity is denied, never left uncapped), NOT a 5xx.
func TestHandleIssueMissingCeilingDeniesNot5xx(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:ZmFrZXNpZw=="})
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)
	storeMapping(t, s)
	storeSigningConfig(t, s)
	// No ceilings/gold is configured, but the token claims apf_tier=gold.

	token := ts.mint(t, validClaims(), map[string]any{claimTier: "gold"})
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err != nil {
		t.Fatalf("a missing ceiling is authorization-absence (nil Go error), got 5xx: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected a 4xx error response when the claimed tier has no configured ceiling")
	}
	if resp != nil && resp.Data["payload"] != nil {
		t.Error("must not return a bundle (the identity is denied, never left uncapped)")
	}
}

func TestHandleIssueSignerFailureFailsClosed(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{err: errNoSignature})
	ts := newTestSigner(t)
	configureIssuer(t, s, ts.jwks)
	storeMapping(t, s)
	storeSigningConfig(t, s)

	token := ts.mint(t, validClaims(), nil)
	resp, err := issueRequest(t, b, s, map[string]any{"jwt": token})
	if err == nil {
		t.Error("expected an error when the signer fails (fail closed)")
	}
	if resp != nil && resp.Data["payload"] != nil {
		t.Error("must not return a bundle when signing fails")
	}
}

func TestHandleIssueRequiresJWT(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{signature: "vault:v1:x"})
	resp, err := issueRequest(t, b, s, map[string]any{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error response when jwt is missing")
	}
}
