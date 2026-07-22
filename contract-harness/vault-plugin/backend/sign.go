package backend

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/vault/api"
)

const (
	signatureVersionUnknown = 0
	signatureParts          = 3
)

var (
	errEmptyLoginToken = errors.New("approle login returned no client token")
	errNoSignature     = errors.New("transit/sign returned no signature")
)

// Signer produces a Vault-transit signature string ("vault:vN:<base64>") over the
// given canonical bytes. The issue endpoint depends on this interface so its
// orchestration and fail-closed paths are testable without a live Vault.
type Signer interface {
	Sign(ctx context.Context, payload []byte) (string, error)
}

// transitSigner is the production Signer. It logs in to a provisioned AppRole
// scoped to ONLY transit/sign, then calls transit/sign as an API client. The private
// key never leaves Vault (transit, non-exportable). On OSS Vault, plugin Workload
// Identity Federation is Enterprise-only, so AppRole is the OSS-viable auth; the
// role_id/secret_id come from signingConfig (a documented Secret-Zero tradeoff).
type transitSigner struct {
	cfg *signingConfig
}

func (s *transitSigner) Sign(ctx context.Context, payload []byte) (string, error) {
	client, err := s.newClient()
	if err != nil {
		return "", err
	}

	// 1. Exchange the AppRole credentials for a transit-scoped Vault token.
	loginPath := fmt.Sprintf("auth/%s/login", s.cfg.ApproleMount)
	login, err := client.Logical().WriteWithContext(ctx, loginPath, map[string]any{
		fieldRoleID:   s.cfg.RoleID,
		fieldSecretID: s.cfg.SecretID,
	})
	if err != nil {
		return "", fmt.Errorf("approle login: %w", err)
	}
	if login == nil || login.Auth == nil || login.Auth.ClientToken == "" {
		return "", errEmptyLoginToken
	}
	client.SetToken(login.Auth.ClientToken)
	// Every Sign logs in fresh, so without revocation each issuance leaves a live
	// (if tightly scoped) token behind until its TTL expires. Best-effort: a failed
	// revoke must not turn a produced signature into an error.
	defer func() {
		_, _ = client.Logical().WriteWithContext(ctx, "auth/token/revoke-self", nil)
	}()

	// 2. transit/sign the canonical bytes. ed25519 is PureEdDSA; transit base64-decodes
	//    "input" and signs it directly, returning a "vault:vN:" prefixed signature.
	signPath := fmt.Sprintf("%s/sign/%s", s.cfg.TransitMount, s.cfg.TransitKey)
	signed, err := client.Logical().WriteWithContext(ctx, signPath, map[string]any{
		"input": base64.StdEncoding.EncodeToString(payload),
	})
	if err != nil {
		return "", fmt.Errorf("transit sign: %w", err)
	}
	if signed == nil {
		return "", errNoSignature
	}
	signature, _ := signed.Data["signature"].(string)
	if signature == "" {
		return "", errNoSignature
	}
	return signature, nil
}

func (s *transitSigner) newClient() (*api.Client, error) {
	cfg := api.DefaultConfig()
	if cfg.Error != nil {
		return nil, fmt.Errorf("vault api config: %w", cfg.Error)
	}
	if s.cfg.VaultAddr != "" {
		cfg.Address = s.cfg.VaultAddr
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("vault api client: %w", err)
	}
	return client, nil
}

// defaultSignerFactory builds the production transit signer (wired in newBackend).
func defaultSignerFactory(cfg *signingConfig) (Signer, error) {
	return &transitSigner{cfg: cfg}, nil
}

// parseSignatureVersion extracts N from a "vault:vN:..." signature, or 0 if absent.
func parseSignatureVersion(signature string) int {
	parts := strings.SplitN(signature, ":", signatureParts)
	if len(parts) < signatureParts || !strings.HasPrefix(parts[1], "v") {
		return signatureVersionUnknown
	}
	version, err := strconv.Atoi(parts[1][1:])
	if err != nil {
		return signatureVersionUnknown
	}
	return version
}
