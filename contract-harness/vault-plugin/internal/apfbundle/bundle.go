// Package apfbundle defines the APF Signed Policy Bundle (odis.bundle.v1) and its
// canonical byte serialization. The plugin assembles a Bundle from an operator
// mapping and signs its canonical bytes; the harness Router verifies the signature
// over those exact bytes.
package apfbundle

import (
	"encoding/json"
	"fmt"
)

// VendorMCP is a family's vendor MCP server endpoint.
type VendorMCP struct {
	EndpointID string `json:"endpoint_id"`
	URL        string `json:"url"`
}

// ToolPolicy declares one governed vendor tool and its optional post-policy limits.
type ToolPolicy struct {
	ActionLimits map[string]any `json:"action_limits,omitempty"`
}

// Family is one resource family declared in a bundle.
type Family struct {
	VendorMCP   VendorMCP             `json:"vendor_mcp"`
	Policy      string                `json:"policy"` // Rego source
	Tools       map[string]ToolPolicy `json:"tools"`
	DefaultMode string                `json:"default_mode"` // "strict" | "permissive"
}

// Bundle is the in-memory APF Signed Policy Bundle (odis.bundle.v1).
type Bundle struct {
	BundleID      string            `json:"bundle_id"`
	BundleVersion string            `json:"bundle_version"`
	TrustRootID   string            `json:"trust_root_id"`
	Families      map[string]Family `json:"families"`
}

// CanonicalBytes returns a deterministic, sorted-key, compact JSON encoding of the
// bundle. Determinism is the contract: the bytes returned here are the
// exact bytes signed and the exact bytes the Router verifies. A two-pass
// encode (struct -> generic -> re-encode) sorts every object's keys lexicographically
// regardless of Go struct field order, so the signed form never silently drifts when
// the structs are reordered.
func CanonicalBytes(b Bundle) ([]byte, error) {
	structForm, err := json.Marshal(b)
	if err != nil {
		return nil, fmt.Errorf("apfbundle: marshal bundle: %w", err)
	}

	var generic any
	if err := json.Unmarshal(structForm, &generic); err != nil {
		return nil, fmt.Errorf("apfbundle: normalize bundle: %w", err)
	}

	canonical, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("apfbundle: canonical marshal: %w", err)
	}
	return canonical, nil
}
