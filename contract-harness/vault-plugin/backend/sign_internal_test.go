package backend

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestParseSignatureVersion(t *testing.T) {
	t.Parallel()
	cases := map[string]int{
		"vault:v1:abc":  1,
		"vault:v42:xyz": 42,
		"vault:vX:abc":  0, // non-numeric version
		"not-a-sig":     0,
		"":              0,
	}
	for sig, want := range cases {
		if got := parseSignatureVersion(sig); got != want {
			t.Errorf("parseSignatureVersion(%q) = %d, want %d", sig, got, want)
		}
	}
}

// TestTransitSignerFailsClosedOnUnreachableVault: with no Vault listening, the
// AppRole login fails, so Sign fails closed without producing a signature.
// The live transit success path is covered by the requires_vault e2e.
func TestTransitSignerFailsClosedOnUnreachableVault(t *testing.T) {
	t.Parallel()

	// A test-owned ephemeral port that deterministically refuses connections:
	// bind a loopback listener for a free port, then close it before dialing.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var lc net.ListenConfig
	lis, err := lc.Listen(ctx, "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := lis.Addr().String()
	if err := lis.Close(); err != nil {
		t.Fatalf("release port: %v", err)
	}

	signer := &transitSigner{
		cfg: &signingConfig{
			TransitMount: "transit",
			TransitKey:   "apf-bundle",
			ApproleMount: "approle",
			RoleID:       "test-role-id",
			SecretID:     "test-secret-id",
			VaultAddr:    "http://" + addr, // nothing listening -> login fails
		},
	}
	signature, err := signer.Sign(ctx, []byte("payload"))
	if err == nil {
		t.Error("expected Sign to fail closed when Vault is unreachable")
	}
	if signature != "" {
		t.Errorf("Sign must not produce a signature on failure, got %q", signature)
	}
}
