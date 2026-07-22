package backend

import (
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
)

// errEmptyBundle guards against signing a bundle that declares no families — an
// authority statement that authorizes nothing (e.g. an empty union).
var errEmptyBundle = errors.New("composed bundle has zero families")

// assembleBundle returns the canonical bytes to be transit-signed for a composed
// bundle. It is the seam the issue endpoint signs; it never signs an empty bundle
// (defense in depth — an empty union authorizes nothing).
func assembleBundle(bundle apfbundle.Bundle) ([]byte, error) {
	if len(bundle.Families) == 0 {
		return nil, errEmptyBundle
	}
	canonical, err := apfbundle.CanonicalBytes(bundle)
	if err != nil {
		return nil, fmt.Errorf("assemble bundle: %w", err)
	}
	return canonical, nil
}
