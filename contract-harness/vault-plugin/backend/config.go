package backend

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageKeyIssuerConfig  = "config/issuer"
	storageKeySigningConfig = "config/signing"
)

// Field names shared between the path schema and the handlers (single source).
const (
	fieldBoundIssuer        = "bound_issuer"
	fieldBoundAudiences     = "bound_audiences"
	fieldBoundSubject       = "bound_subject"
	fieldBoundSubjectPrefix = "bound_subject_prefix"
	fieldBoundClaims        = "bound_claims"
	fieldName               = "name"
	fieldBundle             = "bundle"
	fieldJWT                = "jwt"
	fieldTransitKey         = "transit_key"
	fieldApproleMount       = "approle_mount"
	fieldRoleID             = "role_id"
	fieldSecretID           = "secret_id"
	fieldVaultAddr          = "vault_addr"
)

// Default mount paths for the signing self-call.
const (
	defaultTransitMount = "transit"
	defaultApproleMount = "approle"
)

// Sentinel errors so callers (e.g. the validation path) can fail closed with a
// clear reason when a config is absent.
var (
	errIssuerNotConfigured  = errors.New("issuer not configured")
	errSigningNotConfigured = errors.New("signing not configured")
)

// issuerConfig is the operator-set trust material for validating forwarded
// workload JWTs. No secrets: JWKS/PEM are public keys.
type issuerConfig struct {
	JWKS           string   `json:"jwks"`            // a JWK Set (JSON) — trust material
	JWKSPEM        []string `json:"jwks_pem"`        // OR PEM public keys
	BoundIssuer    string   `json:"bound_issuer"`    // the iss claim the plugin trusts
	BoundAudiences []string `json:"bound_audiences"` // dedicated issuance audience(s)
}

// signingConfig tells the plugin how to reach transit to sign. The plugin
// authenticates to transit via a provisioned AppRole scoped to ONLY transit/sign.
// On OSS Vault, plugin Workload Identity Federation (GenerateIdentityToken) is
// Enterprise-only, so the role_id + secret_id are stored here — an accepted,
// documented Secret-Zero tradeoff (the secret_id is barrier-encrypted at rest).
type signingConfig struct {
	TransitMount string `json:"transit_mount"`
	TransitKey   string `json:"transit_key"`
	ApproleMount string `json:"approle_mount"`
	RoleID       string `json:"role_id"`
	// SecretID is sensitive: barrier-encrypted at rest, never echoed on read, never logged.
	SecretID string `json:"secret_id"`
	// VaultAddr is the address the plugin dials for its transit self-call. Empty
	// falls back to api.DefaultConfig (the VAULT_ADDR env). Not a secret.
	VaultAddr string `json:"vault_addr"`
}

func (b *backend) readIssuerConfig(ctx context.Context, s logical.Storage) (*issuerConfig, error) {
	entry, err := s.Get(ctx, storageKeyIssuerConfig)
	if err != nil {
		return nil, fmt.Errorf("read issuer config: %w", err)
	}
	if entry == nil {
		return nil, errIssuerNotConfigured
	}
	cfg := &issuerConfig{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, fmt.Errorf("decode issuer config: %w", err)
	}
	return cfg, nil
}

func (b *backend) readSigningConfig(ctx context.Context, s logical.Storage) (*signingConfig, error) {
	entry, err := s.Get(ctx, storageKeySigningConfig)
	if err != nil {
		return nil, fmt.Errorf("read signing config: %w", err)
	}
	if entry == nil {
		return nil, errSigningNotConfigured
	}
	cfg := &signingConfig{}
	if err := entry.DecodeJSON(cfg); err != nil {
		return nil, fmt.Errorf("decode signing config: %w", err)
	}
	return cfg, nil
}

func (b *backend) handleReadIssuer(
	ctx context.Context, req *logical.Request, _ *framework.FieldData,
) (*logical.Response, error) {
	cfg, err := b.readIssuerConfig(ctx, req.Storage)
	if errors.Is(err, errIssuerNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		fieldBoundIssuer:    cfg.BoundIssuer,
		fieldBoundAudiences: cfg.BoundAudiences,
		// Never echo the key material itself; report only that it is set.
		"jwks_configured": cfg.JWKS != "" || len(cfg.JWKSPEM) > 0,
	}}, nil
}

func (b *backend) handleWriteIssuer(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	jwks, _ := data.Get("jwks").(string)
	jwksPEM, _ := data.Get("jwks_pem").([]string)
	boundIssuer, _ := data.Get(fieldBoundIssuer).(string)
	boundAudiences, _ := data.Get(fieldBoundAudiences).([]string)

	if boundIssuer == "" {
		return logical.ErrorResponse("bound_issuer is required"), nil
	}
	if len(boundAudiences) == 0 {
		// Required so the audience check can never silently no-op: a JWT
		// minted for another relying party must not be replayable to the issuer.
		return logical.ErrorResponse("bound_audiences is required (the dedicated issuance audience)"), nil
	}
	if jwks == "" && len(jwksPEM) == 0 {
		return logical.ErrorResponse("one of jwks or jwks_pem is required"), nil
	}

	cfg := issuerConfig{
		JWKS:           jwks,
		JWKSPEM:        jwksPEM,
		BoundIssuer:    boundIssuer,
		BoundAudiences: boundAudiences,
	}
	entry, err := logical.StorageEntryJSON(storageKeyIssuerConfig, cfg)
	if err != nil {
		return nil, fmt.Errorf("encode issuer config: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("persist issuer config: %w", err)
	}
	return nil, nil
}

func (b *backend) handleReadSigning(
	ctx context.Context, req *logical.Request, _ *framework.FieldData,
) (*logical.Response, error) {
	cfg, err := b.readSigningConfig(ctx, req.Storage)
	if errors.Is(err, errSigningNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		"transit_mount":   cfg.TransitMount,
		fieldTransitKey:   cfg.TransitKey,
		fieldApproleMount: cfg.ApproleMount,
		fieldRoleID:       cfg.RoleID,
		fieldVaultAddr:    cfg.VaultAddr,
		// Never echo the secret_id; report only that it is set.
		"secret_id_configured": cfg.SecretID != "",
	}}, nil
}

func (b *backend) handleWriteSigning(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	transitMount, _ := data.Get("transit_mount").(string)
	transitKey, _ := data.Get(fieldTransitKey).(string)
	approleMount, _ := data.Get(fieldApproleMount).(string)
	roleID, _ := data.Get(fieldRoleID).(string)
	secretID, _ := data.Get(fieldSecretID).(string)
	vaultAddr, _ := data.Get(fieldVaultAddr).(string)

	switch {
	case transitKey == "":
		return logical.ErrorResponse("transit_key is required"), nil
	case roleID == "":
		return logical.ErrorResponse("role_id is required"), nil
	case secretID == "":
		return logical.ErrorResponse("secret_id is required"), nil
	// The schema defaults apply only when a field is ABSENT; an explicitly empty
	// mount (e.g. an unset template variable) would store a config whose signing
	// paths are malformed and 5xx every subsequent issuance.
	case transitMount == "":
		return logical.ErrorResponse(`transit_mount must not be empty (omit it to default to "transit")`), nil
	case approleMount == "":
		return logical.ErrorResponse(`approle_mount must not be empty (omit it to default to "approle")`), nil
	}

	cfg := signingConfig{
		TransitMount: transitMount,
		TransitKey:   transitKey,
		ApproleMount: approleMount,
		RoleID:       roleID,
		SecretID:     secretID,
		VaultAddr:    vaultAddr,
	}
	entry, err := logical.StorageEntryJSON(storageKeySigningConfig, cfg)
	if err != nil {
		return nil, fmt.Errorf("encode signing config: %w", err)
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, fmt.Errorf("persist signing config: %w", err)
	}
	return nil, nil
}
