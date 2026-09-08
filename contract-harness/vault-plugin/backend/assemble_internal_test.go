package backend

import (
	"encoding/json"
	"errors"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"testing"
)

// White-box tests for bundle assembly.

func assembleTestBundle() apfbundle.Bundle {
	return apfbundle.Bundle{
		BundleID:             "odis-fixture-bundle",
		BundleVersion:        "0.1.0",
		TrustRootID:          "fixture-trust-root",
		Actor:                "spiffe://example.org/agent/jira",
		OriginatingPrincipal: "vault:entity:e-platform",
		ContributingRecords: []apfbundle.MappingRecordRef{
			{Name: "jira", Version: 1, Digest: "sha256:x"},
		},
		DelegationChain:       apfbundle.RootDelegationChain(),
		AttenuationProfileRef: &apfbundle.AttenuationProfileRef{URI: "urn:x:v1", Digest: "sha256:y"},
		IssuedAt:              "2026-08-27T12:00:00Z",
		ExpiresAt:             "2026-08-27T13:00:00Z",
		Families: map[string]apfbundle.Family{
			"jira-prod": {
				VendorMCP: apfbundle.VendorMCP{
					EndpointID: "jira-prod-mcp-v1",
					URL:        "https://jira-prod-mcp.internal:8443/",
				},
				Policy:      "package odis_policy",
				DefaultMode: modeStrict,
			},
		},
	}
}

// TestAssembleBundleCanonical: a composed bundle yields deterministic canonical
// bytes that parse as JSON and carry the expected family.
func TestAssembleBundleCanonical(t *testing.T) {
	t.Parallel()

	bundle := assembleTestBundle()

	got, err := assembleBundle(bundle)
	if err != nil {
		t.Fatalf("assembleBundle: %v", err)
	}

	again, err := assembleBundle(bundle)
	if err != nil {
		t.Fatalf("assembleBundle (second): %v", err)
	}
	if string(got) != string(again) {
		t.Errorf("canonical bytes not deterministic:\n a=%s\n b=%s", got, again)
	}

	var parsed apfbundle.Bundle
	if err := json.Unmarshal(got, &parsed); err != nil {
		t.Fatalf("canonical bytes are not valid JSON: %v", err)
	}
	if _, ok := parsed.Families["jira-prod"]; !ok {
		t.Errorf("expected family %q in assembled bundle, got %v", "jira-prod", parsed.Families)
	}
}

// TestAssembleBundleZeroFamilies: a zero-family bundle fails closed (defense in depth).
func TestAssembleBundleZeroFamilies(t *testing.T) {
	t.Parallel()

	if _, err := assembleBundle(apfbundle.Bundle{BundleID: "x"}); err == nil {
		t.Error("expected an error for a bundle with zero families")
	}
}

// A bundle missing any part of its delegation record is never signed: the signing
// seam is the last place to catch an unstamped grant, which would be immortal and
// name nobody accountable (ODIS-L2-05 / L3-04).
func TestAssembleBundleRejectsUnstampedDelegation(t *testing.T) {
	t.Parallel()

	strip := map[string]func(*apfbundle.Bundle){
		"actor":                 func(b *apfbundle.Bundle) { b.Actor = "" },
		"originating_principal": func(b *apfbundle.Bundle) { b.OriginatingPrincipal = "" },
		"contributing_records":  func(b *apfbundle.Bundle) { b.ContributingRecords = nil },
		"empty contributing records": func(b *apfbundle.Bundle) {
			b.ContributingRecords = []apfbundle.MappingRecordRef{}
		},
		"attenuation_profile_ref": func(b *apfbundle.Bundle) { b.AttenuationProfileRef = nil },
		"issued_at":               func(b *apfbundle.Bundle) { b.IssuedAt = "" },
		"expires_at":              func(b *apfbundle.Bundle) { b.ExpiresAt = "" },
	}
	for name, mutate := range strip {
		bundle := assembleTestBundle()
		mutate(&bundle)
		if _, err := assembleBundle(bundle); !errors.Is(err, errUnstampedBundle) {
			t.Errorf("missing %s: got err %v, want errUnstampedBundle", name, err)
		}
	}
}
