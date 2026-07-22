package backend_test

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// TestFactoryRegistersAllPaths asserts the four contract paths are mounted.
// A path is "registered" if HandleRequest does not return ErrUnsupportedPath
// (an unsupported *operation* on a registered path is fine — e.g. issue is
// create-only).
func TestFactoryRegistersAllPaths(t *testing.T) {
	t.Parallel()

	b, s := newTestBackend(t)
	for _, path := range []string{"config/issuer", "config/signing", "mappings/example", "issue"} {
		_, reqErr := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      path,
			Storage:   s,
		})
		if errors.Is(reqErr, logical.ErrUnsupportedPath) {
			t.Errorf("path %q is not registered", path)
		}
	}
}

// TestBackendType pins the engine as a logical secrets engine.
func TestBackendType(t *testing.T) {
	t.Parallel()

	b, _ := newTestBackend(t)
	if got := b.Type(); got != logical.TypeLogical {
		t.Errorf("backend type = %v, want %v", got, logical.TypeLogical)
	}
}
