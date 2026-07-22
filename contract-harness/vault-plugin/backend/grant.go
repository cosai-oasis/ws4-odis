package backend

import (
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
)

// Family default_mode values. A strict family denies any tool without a policy
// rule; a permissive family forwards unpoliced tools without a gate — so a
// permissive family with zero rules is an unpoliced passthrough (rejected at write).
const (
	modeStrict     = "strict"
	modePermissive = "permissive"
)

// grantFamily is a structured, projectable grant for one provider family: the
// vendor endpoint plus a policy spec (the DSL, never raw Rego). It compiles to an
// apfbundle.Family at issuance.
type grantFamily struct {
	VendorMCP   apfbundle.VendorMCP  `json:"vendor_mcp"`
	Policy      policydsl.PolicySpec `json:"policy"`
	DefaultMode string               `json:"default_mode"`
}

// grant is the structured authority a mapping carries: a bundle envelope plus
// per-family structured policy. Raw Rego is never stored — it is generated from
// Policy at issuance (APF Policy Projection).
type grant struct {
	BundleID      string                 `json:"bundle_id"`
	BundleVersion string                 `json:"bundle_version"`
	TrustRootID   string                 `json:"trust_root_id"`
	Families      map[string]grantFamily `json:"families"`
}
