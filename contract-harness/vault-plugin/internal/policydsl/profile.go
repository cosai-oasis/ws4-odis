package policydsl

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
)

// AttenuationProfileURI identifies the immutable, versioned normalization and
// comparison rules this package applies when narrowing a grant against a bound
// (ODIS-L2-06). The version is part of the URI: the rules for a given version never
// change, so a change to Intersect / ValidateSpec / Compile semantics mints a new
// profile document and a new URI rather than editing v1.
const AttenuationProfileURI = "urn:odis:contract-harness:attenuation-profile:v1"

// attenuationProfileV1 is the published profile document — the machine-readable
// statement of the comparison axes, the closed condition-operator set, and the
// fail-closed rules. Embedding it makes the bytes the plugin digests the same bytes
// a verifier resolves.
//
//go:embed attenuation_profile_v1.json
var attenuationProfileV1 []byte

// AttenuationProfile returns the profile document the ref's digest covers. A
// verifier resolves AttenuationProfileURI to these bytes and confirms the digest.
func AttenuationProfile() []byte {
	// Copy: the caller must not be able to mutate the bytes the digest covers.
	return append([]byte(nil), attenuationProfileV1...)
}

// AttenuationProfileDigest returns the content digest of the profile document as
// "sha256:<hex>" — the value carried on an issued bundle's attenuation_profile_ref.
func AttenuationProfileDigest() string {
	sum := sha256.Sum256(attenuationProfileV1)
	return "sha256:" + hex.EncodeToString(sum[:])
}
