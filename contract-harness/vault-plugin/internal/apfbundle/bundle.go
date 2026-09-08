// Package apfbundle defines the APF Signed Policy Bundle (odis.bundle.v1) and its
// canonical byte serialization. The plugin assembles a Bundle from an operator
// mapping and signs its canonical bytes; the harness Router verifies the signature
// over those exact bytes.
package apfbundle

import (
	"encoding/json"
	"fmt"
)

// Egress modes a Provider Adapter may declare for a target (ODIS-L2-15). Native
// mode requires the target to validate the runtime credential and delegation record
// itself; bridge mode puts that enforcement in the adapter. This harness declares
// bridge: the vendor MCP server authenticates the Router's own leg, not the agent's.
const (
	EgressModeNative = "native"
	EgressModeBridge = "bridge"
)

// VendorMCP is a family's vendor MCP server endpoint plus the egress mode the
// adapter declares for it.
type VendorMCP struct {
	EndpointID string `json:"endpoint_id"`
	URL        string `json:"url"`
	EgressMode string `json:"egress_mode,omitempty"`
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

// MappingRecordRef points at one operator mapping record by name, record version,
// and content digest, so a verifier holding the record can confirm the grant came
// from that exact content.
type MappingRecordRef struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
	Digest  string `json:"digest"`
}

// AttenuationProfileRef names the immutable, versioned normalization and comparison
// rules that govern narrowing this grant (ODIS-L2-06), with the content digest a
// verifier uses to confirm it resolved the right profile.
type AttenuationProfileRef struct {
	URI    string `json:"uri"`
	Digest string `json:"digest"`
}

// Bundle is the in-memory APF Signed Policy Bundle (odis.bundle.v1).
//
// The delegation-provenance fields carry ODIS §6.3's Delegation Record content for
// the grant: who delegated (OriginatingPrincipal), who holds it (Actor), which
// records conferred it (ContributingRecords), that it is a root record
// (DelegationChain), the rules its attenuation follows (AttenuationProfileRef), and
// the window it is valid for. They are omitted when unset, which is the shape of
// a local grant assembled outside issuance.
type Bundle struct {
	BundleID      string            `json:"bundle_id"`
	BundleVersion string            `json:"bundle_version"`
	TrustRootID   string            `json:"trust_root_id"`
	Families      map[string]Family `json:"families"`

	Actor                string `json:"actor,omitempty"`
	OriginatingPrincipal string `json:"originating_principal,omitempty"`

	// ContributingRecords references every mapping record that conferred this grant.
	// It is a provenance manifest under a LOCAL name, deliberately not ODIS §6.3's
	// originating_authorization_ref: that field references the authoritative grant
	// that authorized the delegating principal to delegate — one upstream object
	// carrying issuer, subject, audience, grant identifier or digest, issued_at and
	// expires_at. A Vault operator's authority to write a mapping is their Vault
	// policy, and the plugin holds no reference to whatever approved it, so the
	// draft's field stays unset rather than carrying a different object under its name.
	ContributingRecords []MappingRecordRef `json:"contributing_records,omitempty"`

	// DelegationChain is the ordered list of prior delegation hops. This issuer mints
	// ROOT records only — one operator-to-agent hop — so it is always empty, and an
	// explicitly empty chain is a stronger claim than an absent field: absence says
	// nothing, [] asserts single-hop with no sub-delegation.
	//
	// It is a POINTER because Go cannot otherwise distinguish the two states the
	// schema needs. A nil slice marshals to null, which the schema rejects, and
	// `omitempty` on a slice drops an EMPTY one — which would erase the assertion.
	// A nil pointer is omitted (the unissued shape); a pointer to an empty slice
	// marshals as []. Use RootDelegationChain to build it.
	DelegationChain *[]string `json:"delegation_chain,omitempty"`

	AttenuationProfileRef *AttenuationProfileRef `json:"attenuation_profile_ref,omitempty"`
	IssuedAt              string                 `json:"issued_at,omitempty"`  // RFC 3339
	ExpiresAt             string                 `json:"expires_at,omitempty"` // RFC 3339
}

// RootDelegationChain returns the delegation chain of a root record: present and
// empty, so the issued bundle asserts single-hop rather than staying silent.
func RootDelegationChain() *[]string {
	chain := []string{}
	return &chain
}

// CanonicalBytes returns a deterministic, sorted-key, compact JSON encoding of the
// bundle. Determinism is the contract: the bytes returned here are the
// exact bytes signed and the exact bytes the Router verifies.
func CanonicalBytes(b Bundle) ([]byte, error) {
	return CanonicalJSON(b)
}

// CanonicalJSON returns the deterministic, sorted-key, compact JSON encoding of any
// value. A two-pass encode (value -> generic -> re-encode) sorts every object's keys
// lexicographically regardless of Go struct field order, so a signed or digested form
// never silently drifts when the structs are reordered.
func CanonicalJSON(v any) ([]byte, error) {
	structForm, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("apfbundle: marshal value: %w", err)
	}

	var generic any
	if err := json.Unmarshal(structForm, &generic); err != nil {
		return nil, fmt.Errorf("apfbundle: normalize value: %w", err)
	}

	canonical, err := json.Marshal(generic)
	if err != nil {
		return nil, fmt.Errorf("apfbundle: canonical marshal: %w", err)
	}
	return canonical, nil
}
