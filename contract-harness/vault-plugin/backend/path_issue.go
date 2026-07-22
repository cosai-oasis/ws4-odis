package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathIssue registers the authenticated bundle-issuance endpoint: given a
// forwarded workload JWT (the bundle subject), it validates, maps, assembles, and
// transit-signs the bundle. The orchestration lives in handleIssue (issue.go).
func (b *backend) pathIssue() *framework.Path {
	return &framework.Path{
		Pattern: "issue",
		Fields: map[string]*framework.FieldSchema{
			fieldJWT: {
				Type:        framework.TypeString,
				Description: "The forwarded workload-identity JWT; the bundle subject, not the caller's Vault authz.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			// Issuance is a write (like transit/sign, pki/issue) → UpdateOperation.
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleIssue},
		},
		HelpSynopsis:    "Issue a transit-signed APF bundle for a validated workload JWT.",
		HelpDescription: "Validate the forwarded JWT, map it to allowed mechanisms, assemble the bundle, and sign it.",
	}
}
