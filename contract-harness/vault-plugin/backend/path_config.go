package backend

import (
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathConfig registers the operator config endpoints: config/issuer (trusted
// workload-JWT issuer material) and config/signing (how the plugin reaches
// transit to sign).
func (b *backend) pathConfig() []*framework.Path {
	return []*framework.Path{
		b.pathConfigIssuer(),
		b.pathConfigSigning(),
	}
}

func (b *backend) pathConfigIssuer() *framework.Path {
	return &framework.Path{
		Pattern: "config/issuer",
		Fields: map[string]*framework.FieldSchema{
			"jwks": {
				Type:        framework.TypeString,
				Description: "Trusted issuer JWK Set (JSON) used to verify workload-JWT signatures.",
			},
			"jwks_pem": {
				Type:        framework.TypeStringSlice,
				Description: "Trusted issuer PEM public keys (alternative to jwks).",
			},
			fieldBoundIssuer: {
				Type:        framework.TypeString,
				Description: "The iss claim the plugin trusts.",
			},
			fieldBoundAudiences: {
				Type:        framework.TypeCommaStringSlice,
				Description: "Dedicated issuance audience(s) the plugin requires.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			// A write (create-or-update) routes to UpdateOperation — the Vault idiom
			// for config writes, avoiding the CreateOperation+ExistenceCheck pair.
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWriteIssuer},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleReadIssuer},
		},
		HelpSynopsis:    "Configure the trusted workload-JWT issuer (JWKS/PEM + bound issuer).",
		HelpDescription: "Operator-set trust material used to validate forwarded workload JWTs.",
	}
}

func (b *backend) pathConfigSigning() *framework.Path {
	return &framework.Path{
		Pattern: "config/signing",
		Fields: map[string]*framework.FieldSchema{
			"transit_mount": {
				Type:        framework.TypeString,
				Default:     defaultTransitMount,
				Description: "Mount path of the transit engine holding the signing key.",
			},
			fieldTransitKey: {
				Type:        framework.TypeString,
				Description: "Transit key name used to sign bundles (ed25519).",
			},
			fieldApproleMount: {
				Type:        framework.TypeString,
				Default:     defaultApproleMount,
				Description: "Mount path of the AppRole auth method the plugin logs into for a signing token.",
			},
			fieldRoleID: {
				Type:        framework.TypeString,
				Description: "AppRole role_id whose policy grants only transit/sign on the bundle key.",
			},
			fieldSecretID: {
				Type:         framework.TypeString,
				Description:  "AppRole secret_id (sensitive: stored barrier-encrypted, never echoed back).",
				DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
			},
			fieldVaultAddr: {
				Type:        framework.TypeString,
				Description: "Address the plugin dials for its transit self-call (empty = VAULT_ADDR env).",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWriteSigning},
			logical.ReadOperation:   &framework.PathOperation{Callback: b.handleReadSigning},
		},
		HelpSynopsis:    "Configure how the plugin reaches transit to sign.",
		HelpDescription: "Transit mount/key plus the AppRole (role_id/secret_id) used to obtain a scoped signing token.",
	}
}
