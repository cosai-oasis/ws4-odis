// Package backend implements the apf-bundle-issuer logical secrets engine: it
// validates a forwarded workload-identity JWT, maps it to operator-set bundle
// content, assembles an APF Signed Policy Bundle, and transit-signs it.
package backend

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory builds and sets up the backend for Vault to mount. The SDK contract
// requires returning the logical.Backend interface.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, fmt.Errorf("apf-bundle-issuer: backend setup: %w", err)
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	// signerFactory builds the Signer used by the issue endpoint. Defaults to the
	// production transit signer; tests inject a fake to exercise issuance without
	// a live Vault.
	signerFactory func(*signingConfig) (Signer, error)
}

func newBackend() *backend {
	b := &backend{signerFactory: defaultSignerFactory}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			b.pathConfig(),
			b.pathMappings(),
			b.pathCeilings(),
			[]*framework.Path{b.pathIssue()},
		),
	}
	return b
}

const backendHelp = `
The apf-bundle-issuer secrets engine exchanges a forwarded workload-identity JWT
for a transit-signed APF Signed Policy Bundle, scoped to the presenting workload
via operator-set mappings.
`
