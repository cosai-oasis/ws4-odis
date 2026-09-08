package policydsl

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// pinnedProfileDigest is the digest of attenuation profile v1. ODIS-L2-06 requires
// the comparison rules be identified by an IMMUTABLE versioned reference, so editing
// the profile document without minting a new version must break this test.
const pinnedProfileDigest = "sha256:252bbb3787e84cc39b6b975c9655ac9d3b49e7b2b92cb5dbdb98efa0523649cf"

// The profile ref carries the versioned URI and a content digest of the profile
// document — the two things ODIS-L2-06 requires a verifier be able to resolve.
func TestAttenuationProfileRefCarriesURIAndDigest(t *testing.T) {
	t.Parallel()

	uri, digest := AttenuationProfileURI, AttenuationProfileDigest()
	if !strings.Contains(uri, ":v1") {
		t.Errorf("profile URI %q does not pin a version", uri)
	}
	if !strings.HasPrefix(digest, "sha256:") || len(digest) != len("sha256:")+sha256.Size*2 {
		t.Errorf("profile digest %q is not a sha256:<hex> content digest", digest)
	}
}

// The digest must be the sha256 of the embedded profile document, so a verifier
// holding the document can confirm the ref resolves to it.
func TestAttenuationProfileDigestMatchesDocument(t *testing.T) {
	t.Parallel()

	sum := sha256.Sum256(AttenuationProfile())
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := AttenuationProfileDigest(); got != want {
		t.Errorf("digest = %q, want %q (sha256 of the profile document)", got, want)
	}
}

// The version is immutable: changing the rules requires a new version, so the
// digest of v1 is pinned here rather than recomputed from the document.
func TestAttenuationProfileDigestIsPinned(t *testing.T) {
	t.Parallel()

	if got := AttenuationProfileDigest(); got != pinnedProfileDigest {
		t.Errorf(
			"profile v1 digest changed: got %q, want %q — mint a new profile version "+
				"instead of editing v1 in place (ODIS-L2-06 immutability)",
			got, pinnedProfileDigest)
	}
}

// The document is the published artifact, so it must be valid JSON, declare the
// version its URI pins, and state the closed operator set the compiler enforces.
func TestAttenuationProfileDocumentIsResolvable(t *testing.T) {
	t.Parallel()

	var doc struct {
		ProfileVersion string   `json:"profile_version"`
		ProfileURI     string   `json:"profile_uri"`
		ConditionOps   []string `json:"condition_operators"`
	}
	if err := json.Unmarshal(AttenuationProfile(), &doc); err != nil {
		t.Fatalf("profile document is not valid JSON: %v", err)
	}
	if doc.ProfileVersion != "1" {
		t.Errorf("profile_version = %q, want %q", doc.ProfileVersion, "1")
	}
	if doc.ProfileURI != AttenuationProfileURI {
		t.Errorf("profile_uri = %q, want %q", doc.ProfileURI, AttenuationProfileURI)
	}
	// The document must enumerate exactly the ops ValidateSpec accepts; a document
	// that drifts from the code would misdescribe the rules a verifier applies.
	want := map[string]bool{OpEq: true, OpStartsWith: true}
	if len(doc.ConditionOps) != len(want) {
		t.Fatalf("condition_operators = %v, want %v", doc.ConditionOps, want)
	}
	for _, op := range doc.ConditionOps {
		if !want[op] {
			t.Errorf("condition_operators lists unsupported op %q", op)
		}
	}
}

// The embedded bytes must be the committed file, so the published document and the
// one the plugin digests can never diverge.
func TestAttenuationProfileEmbedsCommittedFile(t *testing.T) {
	t.Parallel()

	onDisk, err := os.ReadFile("attenuation_profile_v1.json")
	if err != nil {
		t.Fatalf("read profile document: %v", err)
	}
	if string(onDisk) != string(AttenuationProfile()) {
		t.Error("embedded profile document differs from the committed file")
	}
}
