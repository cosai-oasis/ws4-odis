package backend

import (
	"encoding/json"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"testing"
)

// White-box tests for bundle assembly.

func assembleTestBundle() apfbundle.Bundle {
	return apfbundle.Bundle{
		BundleID:      "odis-fixture-bundle",
		BundleVersion: "0.1.0",
		TrustRootID:   "fixture-trust-root",
		Families: map[string]apfbundle.Family{
			"jira-prod": {
				VendorMCP: apfbundle.VendorMCP{
					EndpointID: "jira-prod-mcp-v1",
					URL:        "https://jira-prod-mcp.internal:8443/",
				},
				Policy:      "package odis_policy",
				DefaultMode: "strict",
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
