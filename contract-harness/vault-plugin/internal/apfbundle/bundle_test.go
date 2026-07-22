package apfbundle_test

import (
	"bytes"
	"encoding/json"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"os"
	"path/filepath"
	"testing"
)

func sampleBundle() apfbundle.Bundle {
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
				Policy: "package odis_policy\n\n" +
					"default decision := {\"decision\": \"deny\", \"obligations\": {}}\n",
				Tools: map[string]apfbundle.ToolPolicy{
					"update_issue": {ActionLimits: map[string]any{"allowed_fields": []any{"labels"}}},
				},
				DefaultMode: "strict",
			},
		},
	}
}

// TestCanonicalBytesDeterministic: identical input -> byte-identical output, and
// reordering map insertion does not change the bytes.
func TestCanonicalBytesDeterministic(t *testing.T) {
	t.Parallel()

	first, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	second, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("canonical bytes not deterministic:\n a=%s\n b=%s", first, second)
	}
}

// TestCanonicalKeysSorted: top-level object keys are lexicographically sorted, so
// the form is independent of Go struct field order.
func TestCanonicalKeysSorted(t *testing.T) {
	t.Parallel()

	got, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	want := `{"bundle_id":"odis-fixture-bundle","bundle_version":"0.1.0","families":`
	if !bytes.HasPrefix(got, []byte(want)) {
		t.Errorf("keys not sorted at top level; got prefix %s", got[:min(len(got), len(want))])
	}
}

// TestCanonicalNestedKeysSorted: keys are sorted at EVERY map level (families,
// tools, action limits), so multi-entry bundles canonicalize identically across
// languages regardless of map iteration order.
func TestCanonicalNestedKeysSorted(t *testing.T) {
	t.Parallel()

	multi := sampleBundle()
	fam := multi.Families["jira-prod"]
	fam.Tools = map[string]apfbundle.ToolPolicy{
		"update_issue": {ActionLimits: map[string]any{
			"z_limit": "x", "allowed_fields": []any{"labels"}, "a_limit": "y",
		}},
		"create_issue": {ActionLimits: map[string]any{"allowed_fields": []any{"labels"}}},
	}
	multi.Families = map[string]apfbundle.Family{"z-fam": fam, "a-fam": fam}

	got, err := apfbundle.CanonicalBytes(multi)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	again, err := apfbundle.CanonicalBytes(multi)
	if err != nil {
		t.Fatalf("CanonicalBytes (second): %v", err)
	}
	if !bytes.Equal(got, again) {
		t.Error("multi-entry canonical bytes not deterministic")
	}

	// Lexicographic order must hold within each nesting level. The action-limit
	// check is scoped to the first update_issue block: a whole-document Index
	// would match "allowed_fields" in the earlier create_issue block.
	assertKeysOrdered(t, got, `"a-fam"`, `"z-fam"`)
	assertKeysOrdered(t, got, `"create_issue"`, `"update_issue"`)
	start := bytes.Index(got, []byte(`"update_issue"`))
	if start < 0 {
		t.Fatalf("update_issue missing from canonical form:\n%s", got)
	}
	assertKeysOrdered(t, got[start:], `"a_limit"`, `"allowed_fields"`, `"z_limit"`)
}

// assertKeysOrdered fails unless every key appears in region, in the given order.
func assertKeysOrdered(t *testing.T, region []byte, keys ...string) {
	t.Helper()
	last := -1
	for _, key := range keys {
		idx := bytes.Index(region, []byte(key))
		if idx < 0 || idx < last {
			t.Errorf("key %s missing or out of order in canonical form:\n%s", key, region)
			return
		}
		last = idx
	}
}

// TestCanonicalGolden pins the cross-language golden the Python harness validates
// against. Regenerate with UPDATE_GOLDEN=1.
func TestCanonicalGolden(t *testing.T) {
	t.Parallel()

	got, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}

	golden := filepath.Join("testdata", "golden_bundle.json")
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(golden, got, 0o600); err != nil {
			t.Fatalf("write golden: %v", err)
		}
	}

	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run once with UPDATE_GOLDEN=1): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("canonical bytes drifted from golden:\n got=%s\nwant=%s", got, want)
	}

	// The golden must itself be valid JSON.
	if !json.Valid(want) {
		t.Error("golden is not valid JSON")
	}
}
