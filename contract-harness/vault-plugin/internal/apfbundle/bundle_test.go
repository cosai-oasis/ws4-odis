package apfbundle_test

import (
	"bytes"
	"encoding/json"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sampleBundle() apfbundle.Bundle {
	return apfbundle.Bundle{
		BundleID:      "odis-fixture-bundle",
		BundleVersion: "0.1.0",
		TrustRootID:   "fixture-trust-root",
		// Delegation provenance (ODIS-L2-05): the golden covers it, so the
		// cross-language canonical form is pinned over the full issued shape.
		Actor:                "spiffe://example.org/agent/jira",
		OriginatingPrincipal: "vault:token:token",
		ContributingRecords: []apfbundle.MappingRecordRef{
			{Name: "jira", Version: 1, Digest: "sha256:" + strings.Repeat("ab", 32)},
		},
		DelegationChain: apfbundle.RootDelegationChain(),
		// The real profile ref, not a placeholder: the golden is what the Python
		// harness resolves the attenuation profile against.
		AttenuationProfileRef: &apfbundle.AttenuationProfileRef{
			URI:    policydsl.AttenuationProfileURI,
			Digest: policydsl.AttenuationProfileDigest(),
		},
		IssuedAt:  "2026-08-27T12:00:00Z",
		ExpiresAt: "2026-08-27T13:00:00Z",
		Families: map[string]apfbundle.Family{
			"jira-prod": {
				VendorMCP: apfbundle.VendorMCP{
					EndpointID: "jira-prod-mcp-v1",
					URL:        "https://jira-prod-mcp.internal:8443/",
					EgressMode: apfbundle.EgressModeBridge,
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
	want := `{"actor":"spiffe://example.org/agent/jira",` +
		`"attenuation_profile_ref":{"digest":`
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

// The provenance fields are omitted when unset, so a bundle assembled without a
// delegation record (a local, unissued grant) canonicalizes to the envelope-only
// shape the schema also accepts.
func TestCanonicalOmitsAbsentProvenance(t *testing.T) {
	t.Parallel()

	bare := sampleBundle()
	bare.Actor = ""
	bare.OriginatingPrincipal = ""
	bare.ContributingRecords = nil
	bare.DelegationChain = nil
	bare.AttenuationProfileRef = nil
	bare.IssuedAt = ""
	bare.ExpiresAt = ""

	got, err := apfbundle.CanonicalBytes(bare)
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	for _, key := range []string{
		"actor", "originating_principal", "contributing_records",
		"attenuation_profile_ref", "issued_at", "expires_at", "delegation_chain",
	} {
		if bytes.Contains(got, []byte(`"`+key+`"`)) {
			t.Errorf("unset %s must be omitted from the canonical form:\n%s", key, got)
		}
	}
}

// egress_mode rides inside the signed bytes, so the per-target declaration
// (ODIS-L2-15) cannot be altered without breaking the signature.
func TestCanonicalCarriesEgressMode(t *testing.T) {
	t.Parallel()

	got, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if !bytes.Contains(got, []byte(`"egress_mode":"bridge"`)) {
		t.Errorf("canonical form does not declare egress_mode:\n%s", got)
	}
}

// CanonicalJSON is the one canonicalizer: any value, sorted keys at every level.
func TestCanonicalJSONSortsAnyValue(t *testing.T) {
	t.Parallel()

	got, err := apfbundle.CanonicalJSON(map[string]any{"z": 1, "a": map[string]any{"y": 2, "b": 3}})
	if err != nil {
		t.Fatalf("CanonicalJSON: %v", err)
	}
	if want := `{"a":{"b":3,"y":2},"z":1}`; string(got) != want {
		t.Errorf("CanonicalJSON = %s, want %s", got, want)
	}
}

// An explicitly EMPTY delegation_chain is the assertion that this grant is a root
// record — one operator-to-agent hop, no sub-delegation. It rides in the signed bytes,
// so the assertion is protected; and it must serialize as [] rather than null, which
// the schema would reject.
func TestCanonicalCarriesEmptyDelegationChain(t *testing.T) {
	t.Parallel()

	got, err := apfbundle.CanonicalBytes(sampleBundle())
	if err != nil {
		t.Fatalf("CanonicalBytes: %v", err)
	}
	if !bytes.Contains(got, []byte(`"delegation_chain":[]`)) {
		t.Errorf("canonical form does not assert a root delegation chain:\n%s", got)
	}
	if bytes.Contains(got, []byte(`"delegation_chain":null`)) {
		t.Error("delegation_chain serialized as null; the schema requires an array")
	}
}
