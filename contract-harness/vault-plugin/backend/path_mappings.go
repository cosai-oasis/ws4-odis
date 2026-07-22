package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathMappings registers the operator-set identity->grant mapping endpoints:
// a LIST on mappings/ and CRUD on mappings/<name>.
func (b *backend) pathMappings() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "mappings/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleListMappings},
			},
			HelpSynopsis:    "List mapping entry names.",
			HelpDescription: "Enumerate the operator-set identity->bundle mappings.",
		},
		{
			Pattern: "mappings/" + framework.GenericNameRegex(fieldName),
			Fields: map[string]*framework.FieldSchema{
				fieldName: {
					Type:        framework.TypeString,
					Description: "Mapping entry name.",
				},
				fieldBoundIssuer: {
					Type:        framework.TypeString,
					Description: "Match: required iss claim (empty = any).",
				},
				fieldBoundAudiences: {
					Type:        framework.TypeCommaStringSlice,
					Description: "Match: any of these audiences (empty = any).",
				},
				fieldBoundSubject: {
					Type:        framework.TypeString,
					Description: "Match: exact sub claim (empty = any).",
				},
				fieldBoundSubjectPrefix: {
					Type: framework.TypeString,
					Description: "Match: subject subtree — the prefix itself or a '/'-delimited " +
						"descendant; a sibling that merely string-extends it does not match (empty = any).",
				},
				fieldBoundClaims: {
					Type:        framework.TypeKVPairs,
					Description: "Match: required claim key=value pairs.",
				},
				fieldBundle: {
					Type: framework.TypeString,
					Description: "The structured grant (JSON: bundle envelope + per-family vendor_mcp, " +
						"policy spec, default_mode) to project + sign for matching workloads.",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWriteMapping},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleReadMapping},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleDeleteMapping},
			},
			HelpSynopsis:    "Define an identity->grant mapping.",
			HelpDescription: "Match {iss, aud, sub, claims} to the structured grant to project + sign for that workload.",
		},
	}
}

func (b *backend) handleListMappings(
	ctx context.Context, req *logical.Request, _ *framework.FieldData,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storageKeyMappingPrefix)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	return logical.ListResponse(names), nil
}

func (b *backend) handleWriteMapping(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	// The wire field is still named "bundle" (fieldBundle) for fixture/ops
	// compatibility, but it carries a structured grant — errors say "grant".
	grantJSON, _ := data.Get(fieldBundle).(string)
	var g grant
	if err := json.Unmarshal([]byte(grantJSON), &g); err != nil {
		return logical.ErrorResponse("grant is not valid JSON: %v", err), nil
	}
	if errMsg := validateGrantFamilies(g); errMsg != "" {
		return logical.ErrorResponse("%s", errMsg), nil
	}

	entry := parseMappingEntry(name, g, data)
	if errMsg := validateMappingSelectors(&entry); errMsg != "" {
		return logical.ErrorResponse("%s", errMsg), nil
	}

	existing, err := b.allMappings(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if other := collidesWithExisting(&entry, existing); other != "" {
		// A co-satisfiable same-family collision would 5xx at issuance
		// (errSameFamilyCollision); reject it here so the operator sees it at write.
		return logical.ErrorResponse(
			"mapping %q would collide with existing mapping %q: both are assigned grants, "+
				"share a family, and a single token could match both (co-satisfiable). "+
				"Each family must have a single owner — give them disjoint selectors or families.",
			name, other,
		), nil
	}

	stored, err := logical.StorageEntryJSON(storageKeyMappingPrefix+name, entry)
	if err != nil {
		return nil, fmt.Errorf("encode mapping %q: %w", name, err)
	}
	if err := req.Storage.Put(ctx, stored); err != nil {
		return nil, fmt.Errorf("persist mapping %q: %w", name, err)
	}
	return nil, nil
}

// validateGrantFamilies fails closed on a grant that would project to an
// unenforceable or unloadable bundle. It returns a client-facing message ("" means
// valid). The grant must declare at least one family, and per family: the
// default_mode must be a known mode (an empty/typo'd mode would project to
// default_mode:"" and sign an unloadable bundle); the policy must compile
// (policydsl.ValidateSpec rejects a duplicate verb -> OPA eval_conflict_error, or an
// unknown condition op, before it is stored or signed); and no family may be
// permissive with zero policy rules — that projects to no governed tools, which
// the Router treats as unpoliced passthrough for every tool (the gate would
// forward unconditionally).
func validateGrantFamilies(g grant) string {
	if g.BundleID == "" || g.BundleVersion == "" || g.TrustRootID == "" {
		return "grant envelope requires non-empty bundle_id, bundle_version, and trust_root_id"
	}
	if len(g.Families) == 0 {
		return "grant must declare at least one family"
	}
	for name, gf := range g.Families {
		if msg := validateGrantFamily(name, gf); msg != "" {
			return msg
		}
	}
	return ""
}

// validateGrantFamily applies the per-family write-time checks, mirroring what the
// consumer's odis.bundle.v1 schema will enforce at load — the plugin must never
// sign a bundle the loader is guaranteed to reject.
func validateGrantFamily(name string, gf grantFamily) string {
	if !isValidResourceName(name) {
		return fmt.Sprintf("family name %q must match ^[a-z][a-z0-9-]*$", name)
	}
	if !isValidResourceName(gf.VendorMCP.EndpointID) {
		return fmt.Sprintf(
			"family %q vendor_mcp.endpoint_id %q must match ^[a-z][a-z0-9-]*$",
			name, gf.VendorMCP.EndpointID)
	}
	if !strings.HasPrefix(gf.VendorMCP.URL, "https://") &&
		!strings.HasPrefix(gf.VendorMCP.URL, "http://") {
		return fmt.Sprintf("family %q vendor_mcp.url must start with http:// or https://", name)
	}
	if gf.DefaultMode != modeStrict && gf.DefaultMode != modePermissive {
		return fmt.Sprintf(
			"family %q has an invalid default_mode %q (must be %q or %q)",
			name, gf.DefaultMode, modeStrict, modePermissive)
	}
	if err := policydsl.ValidateSpec(gf.Policy); err != nil {
		return fmt.Sprintf("family %q policy: %v", name, err)
	}
	if gf.DefaultMode == modePermissive && len(gf.Policy.Rules) == 0 {
		return fmt.Sprintf(
			"family %q is permissive with zero policy rules (unpoliced passthrough); "+
				"add a rule or set default_mode=strict", name)
	}
	return ""
}

// isValidResourceName reports whether s matches ^[a-z][a-z0-9-]*$ — the
// odis.bundle.v1 pattern for family names and endpoint ids.
func isValidResourceName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		c := s[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
			return false
		}
	}
	return true
}

// validateMappingSelectors fails closed on a mapping whose bound_* selectors are
// self-contradictory or absent. It returns a client-facing message ("" means valid):
//   - both bound_subject AND bound_subject_prefix set is self-contradictory
//     (subjectConstraintsCoSatisfiable assumes at most one subject field per mapping,
//     so both set could yield a spurious collision rejection);
//   - a zero-constraint mapping (no bound_* fields) matches every validated workload
//     (a wildcard), defeating least-privilege scoping.
func validateMappingSelectors(entry *mappingEntry) string {
	if entry.BoundSubject != "" && entry.BoundSubjectPrefix != "" {
		return "a mapping may set bound_subject or bound_subject_prefix, not both"
	}
	if !entry.hasBinding() {
		return "a mapping must bind at least one of bound_issuer, bound_audiences, " +
			"bound_subject, bound_subject_prefix, or bound_claims"
	}
	for claim, want := range entry.BoundClaims {
		if claim == "" || want == "" {
			return "bound_claims keys and values must be non-empty " +
				"(an empty value would select workloads MISSING the claim)"
		}
	}
	return ""
}

// parseMappingEntry reads the bound_* match fields off the request and assembles a
// mappingEntry around the already-parsed grant.
func parseMappingEntry(name string, g grant, data *framework.FieldData) mappingEntry {
	boundIssuer, _ := data.Get(fieldBoundIssuer).(string)
	boundAudiences, _ := data.Get(fieldBoundAudiences).([]string)
	boundSubject, _ := data.Get(fieldBoundSubject).(string)
	boundSubjectPrefix, _ := data.Get(fieldBoundSubjectPrefix).(string)
	boundClaims, _ := data.Get(fieldBoundClaims).(map[string]string)
	return mappingEntry{
		Name:               name,
		BoundIssuer:        boundIssuer,
		BoundAudiences:     boundAudiences,
		BoundSubject:       boundSubject,
		BoundSubjectPrefix: boundSubjectPrefix,
		BoundClaims:        boundClaims,
		Grant:              g,
	}
}

func (b *backend) handleReadMapping(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	mapping, err := b.readMapping(ctx, req.Storage, name)
	if errors.Is(err, errMappingNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &logical.Response{Data: map[string]any{
		fieldName:               mapping.Name,
		fieldBoundIssuer:        mapping.BoundIssuer,
		fieldBoundAudiences:     mapping.BoundAudiences,
		fieldBoundSubject:       mapping.BoundSubject,
		fieldBoundSubjectPrefix: mapping.BoundSubjectPrefix,
		fieldBoundClaims:        mapping.BoundClaims,
		// The complete grant (the JSON shape the write accepts) plus a family-name
		// summary, so an operator can audit exactly what a mapping confers.
		fieldBundle: mapping.Grant,
		"families":  familyNames(mapping.Grant),
	}}, nil
}

func (b *backend) handleDeleteMapping(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, storageKeyMappingPrefix+name); err != nil {
		return nil, fmt.Errorf("delete mapping %q: %w", name, err)
	}
	return nil, nil
}

func familyNames(g grant) []string {
	names := make([]string, 0, len(g.Families))
	for name := range g.Families {
		names = append(names, name)
	}
	return names
}
