package backend

import (
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
)

// project lowers a structured grant to a signable apfbundle.Bundle: each family's
// policy spec is compiled to Rego (APF Policy Projection), and governed tool
// declarations are derived from that same spec, so the "is this tool governed?"
// set and its field limits come from one source (no hand-maintained duplicate).
func project(g grant) (apfbundle.Bundle, error) {
	out := apfbundle.Bundle{
		BundleID:      g.BundleID,
		BundleVersion: g.BundleVersion,
		TrustRootID:   g.TrustRootID,
		Families:      make(map[string]apfbundle.Family, len(g.Families)),
	}
	for name, gf := range g.Families {
		rego, err := policydsl.Compile(gf.Policy)
		if err != nil {
			return apfbundle.Bundle{}, fmt.Errorf("project family %q: %w", name, err)
		}
		out.Families[name] = apfbundle.Family{
			VendorMCP:   gf.VendorMCP,
			Policy:      rego,
			Tools:       deriveTools(gf.Policy),
			DefaultMode: gf.DefaultMode,
		}
	}
	return out, nil
}

// deriveTools builds the governed-tool map from the policy spec. A rule's verb
// becomes a governed-tool key; its AllowFields become action limits.
func deriveTools(spec policydsl.PolicySpec) map[string]apfbundle.ToolPolicy {
	tools := make(map[string]apfbundle.ToolPolicy, len(spec.Rules))
	for _, r := range spec.Rules {
		actionLimits := map[string]any{}
		if len(r.AllowFields) > 0 {
			actionLimits["allowed_fields"] = r.AllowFields
		}
		tools[r.Verb] = apfbundle.ToolPolicy{ActionLimits: actionLimits}
	}
	return tools
}
