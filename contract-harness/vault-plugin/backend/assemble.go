package backend

import (
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
)

var (
	// errEmptyBundle guards against signing a bundle that declares no families — an
	// authority statement that authorizes nothing (e.g. an empty union).
	errEmptyBundle = errors.New("composed bundle has zero families")
	// errUnstampedBundle guards against signing a bundle with an incomplete
	// delegation record. An unstamped grant names nobody accountable and never
	// expires, so it must not reach a signature.
	errUnstampedBundle = errors.New("composed bundle has an incomplete delegation record")
)

// assembleBundle returns the canonical bytes to be transit-signed for a composed
// bundle. It is the seam the issue endpoint signs; it never signs an empty bundle or
// one whose delegation record is incomplete (defense in depth — resolveBundle already
// refuses both).
func assembleBundle(bundle apfbundle.Bundle) ([]byte, error) {
	if len(bundle.Families) == 0 {
		return nil, errEmptyBundle
	}
	if missing := missingDelegationFields(bundle); missing != "" {
		return nil, fmt.Errorf("%w: %s", errUnstampedBundle, missing)
	}
	canonical, err := apfbundle.CanonicalBytes(bundle)
	if err != nil {
		return nil, fmt.Errorf("assemble bundle: %w", err)
	}
	return canonical, nil
}

// missingDelegationFields names the first delegation-record field the bundle does not
// carry, or "" when the record is complete.
func missingDelegationFields(bundle apfbundle.Bundle) string {
	switch {
	case bundle.Actor == "":
		return "actor"
	case bundle.OriginatingPrincipal == "":
		return "originating_principal"
	case len(bundle.ContributingRecords) == 0:
		return "contributing_records"
	case bundle.DelegationChain == nil:
		// Absent, not empty: an unasserted chain leaves the grant's position in a
		// delegation lineage unstated, which is the thing the field exists to state.
		return "delegation_chain"
	case bundle.AttenuationProfileRef == nil:
		return "attenuation_profile_ref"
	case bundle.IssuedAt == "":
		return "issued_at"
	case bundle.ExpiresAt == "":
		return "expires_at"
	default:
		return ""
	}
}
