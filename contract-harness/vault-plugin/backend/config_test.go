package backend_test

import (
	"context"
	"odis-contract-harness/vault-plugin/backend"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

func newTestBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{} // TestBackendConfig does not populate this
	b, err := backend.Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("Factory: %v", err)
	}
	return b, config.StorageView
}

func write(t *testing.T, b logical.Backend, s logical.Storage, path string, data map[string]any) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return resp
}

func read(t *testing.T, b logical.Backend, s logical.Storage, path string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return resp
}

// TestIssuerConfigRoundTrip: a written issuer config reads back.
func TestIssuerConfigRoundTrip(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := write(t, b, s, "config/issuer", map[string]any{
		"jwks":            `{"keys":[]}`,
		"bound_issuer":    "https://fixture.issuer.odis.local/",
		"bound_audiences": "apf-bundle-issuer",
	})
	if resp.IsError() {
		t.Fatalf("write returned error: %v", resp.Error())
	}

	got := read(t, b, s, "config/issuer")
	if got == nil {
		t.Fatal("read returned nil after write")
	}
	if got.Data["bound_issuer"] != "https://fixture.issuer.odis.local/" {
		t.Errorf("bound_issuer = %v", got.Data["bound_issuer"])
	}
	if got.Data["jwks_configured"] != true {
		t.Errorf("jwks_configured = %v, want true", got.Data["jwks_configured"])
	}
}

// TestIssuerConfigRequiresBoundIssuer: writing without bound_issuer fails closed.
func TestIssuerConfigRequiresBoundIssuer(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := write(t, b, s, "config/issuer", map[string]any{"jwks": `{"keys":[]}`})
	if !resp.IsError() {
		t.Error("expected an error response when bound_issuer is missing")
	}
}

// TestIssuerConfigRequiresAudiences: omitting bound_audiences fails closed so the
// audience check can never silently no-op.
func TestIssuerConfigRequiresAudiences(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := write(t, b, s, "config/issuer", map[string]any{
		"jwks":         `{"keys":[]}`,
		"bound_issuer": "https://fixture.issuer.odis.local/",
	})
	if !resp.IsError() {
		t.Error("expected an error response when bound_audiences is missing")
	}
}

// TestIssuerConfigRequiresTrustMaterial: neither jwks nor jwks_pem fails closed.
func TestIssuerConfigRequiresTrustMaterial(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := write(t, b, s, "config/issuer", map[string]any{"bound_issuer": "https://x/"})
	if !resp.IsError() {
		t.Error("expected an error response when no jwks/jwks_pem is given")
	}
}

// TestIssuerReadUnconfigured: read before write returns nil (404).
func TestIssuerReadUnconfigured(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	if got := read(t, b, s, "config/issuer"); got != nil {
		t.Errorf("expected nil for unconfigured issuer, got %#v", got)
	}
}

// TestSigningConfigRoundTrip: a written signing config reads back; mounts default.
func TestSigningConfigRoundTrip(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := write(t, b, s, "config/signing", map[string]any{
		"transit_key": "apf-bundle",
		"role_id":     "test-role-id",
		"secret_id":   "test-secret-id",
	})
	if resp.IsError() {
		t.Fatalf("write returned error: %v", resp.Error())
	}

	got := read(t, b, s, "config/signing")
	if got == nil {
		t.Fatal("read returned nil after write")
	}
	if got.Data["transit_key"] != "apf-bundle" {
		t.Errorf("transit_key = %v", got.Data["transit_key"])
	}
	if got.Data["transit_mount"] != "transit" {
		t.Errorf("transit_mount default = %v, want transit", got.Data["transit_mount"])
	}
	if got.Data["approle_mount"] != "approle" {
		t.Errorf("approle_mount default = %v, want approle", got.Data["approle_mount"])
	}
	if got.Data["secret_id_configured"] != true {
		t.Errorf("secret_id_configured = %v, want true", got.Data["secret_id_configured"])
	}
	if _, echoed := got.Data["secret_id"]; echoed {
		t.Error("secret_id must never be echoed back on read")
	}
}

// TestSigningConfigRequiresKey: missing transit_key fails closed.
func TestSigningConfigRequiresKey(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := write(t, b, s, "config/signing", map[string]any{
		"role_id":   "test-role-id",
		"secret_id": "test-secret-id",
	})
	if !resp.IsError() {
		t.Error("expected an error response when transit_key is missing")
	}
}

// TestSigningConfigRejectsEmptyMounts: schema defaults apply only to ABSENT
// fields — an explicitly empty mount (e.g. an unset template variable) would
// store a config whose signing paths are malformed and 5xx every issuance.
func TestSigningConfigRejectsEmptyMounts(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	for _, mount := range []string{"transit_mount", "approle_mount"} {
		resp := write(t, b, s, "config/signing", map[string]any{
			"transit_key": "apf-bundle",
			"role_id":     "test-role-id",
			"secret_id":   "test-secret-id",
			mount:         "",
		})
		if !resp.IsError() {
			t.Errorf("expected an error response for explicitly empty %s", mount)
		}
	}
}
