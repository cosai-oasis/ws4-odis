package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Field names for the lifecycle and accountability surface of a mapping record.
// They live here rather than beside the config fields because they belong to this
// path alone.
const (
	fieldLifecycleState      = "lifecycle_state"
	fieldValidUntil          = "valid_until"
	fieldRecordVersion       = "record_version"
	fieldGrantTTL            = "grant_ttl"
	fieldDelegatingPrincipal = "delegating_principal"
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
			Fields:  mappingFields(),
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

// mappingFields is the request schema for a mapping record: the selectors that pick
// which workloads it applies to, the grant it confers, and the lifecycle fields that
// decide whether it still confers anything.
func mappingFields() map[string]*framework.FieldSchema {
	return map[string]*framework.FieldSchema{
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
				"policy spec, egress_mode, default_mode) to project + sign for matching workloads.",
		},
		fieldLifecycleState: {
			Type:    framework.TypeString,
			Default: lifecycleActive,
			Description: "Lifecycle state of this record: active, suspended, revoked, or " +
				"pending. Only an active record confers authority.",
		},
		fieldValidUntil: {
			Type: framework.TypeString,
			Description: "RFC 3339 instant after which this record no longer confers " +
				"authority (empty = unbounded). Also caps the expiry of grants issued from it.",
		},
		fieldRecordVersion: {
			Type: framework.TypeInt,
			Description: "Monotonically increasing record version for rollback detection. " +
				"Omit to advance automatically; an explicit value must exceed every version " +
				"previously accepted for this name.",
		},
		fieldGrantTTL: {
			Type:    framework.TypeDurationSecond,
			Default: int(defaultGrantTTL.Seconds()),
			Description: "Lifetime of a grant issued from this record. Bounds the issued " +
				"bundle's expires_at, which the Router enforces.",
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
	entry, errResp := buildMappingEntry(req, data)
	if errResp != nil {
		return errResp, nil
	}
	if errResp, err := b.assignRecordVersion(ctx, req.Storage, entry, data); errResp != nil || err != nil {
		return errResp, err
	}
	name := entry.Name

	existing, err := b.allMappings(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if errResp := refuseRewriteOfRevoked(entry, existing); errResp != nil {
		return errResp, nil
	}
	if other := collidesWithExisting(entry, existing); other != "" {
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
	// The high-water mark is raised BEFORE the record lands. Either order can fail
	// between the two writes, so the choice is which residue is safe: a raised mark with
	// no record refuses a later write at that version, which an operator sees and can
	// retry at the next one; a stored record with a stale mark silently re-accepts the
	// version it just consumed, which is the rollback this mark exists to detect. Fail
	// towards refusing a write, never towards accepting a replay.
	if err := b.recordVersionSeen(ctx, req.Storage, name, entry.RecordVersion); err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, stored); err != nil {
		return nil, fmt.Errorf("persist mapping %q: %w", name, err)
	}
	return nil, nil
}

// buildMappingEntry validates a write request and assembles the record it would
// store. A non-nil response is the client-facing refusal; every check fails closed,
// so nothing partially valid reaches storage. The record version is assigned
// separately, because it depends on stored history rather than on the request.
func buildMappingEntry(req *logical.Request, data *framework.FieldData) (*mappingEntry, *logical.Response) {
	name, _ := data.Get(fieldName).(string)
	if name == "" {
		return nil, logical.ErrorResponse("name is required")
	}

	// The write's own authenticated identity is the delegating principal; an
	// unattributable write has nobody to hold accountable for the authority it
	// confers, so it is refused rather than stored anonymously.
	principal := delegatingPrincipal(req)
	if principal == "" {
		return nil, logical.ErrorResponse(
			"this write carries no Vault identity entity to record as the delegating " +
				"principal; authenticate as an identity entity. A token display name is " +
				"not accepted: it is not unique per operator, so two writers would be " +
				"recorded as one and an accountability split would compose silently.",
		)
	}

	// fieldBundle is spelled "bundle" on the wire and carries a structured grant.
	// The name is fixed by its callers — vault/provision.sh and the Terraform module
	// both write `bundle=…` — while errors about the payload say "grant", which is
	// what it holds.
	grantJSON, _ := data.Get(fieldBundle).(string)
	var g grant
	if err := json.Unmarshal([]byte(grantJSON), &g); err != nil {
		return nil, logical.ErrorResponse("grant is not valid JSON: %v", err)
	}
	defaultEgressModes(g.Families)
	if errMsg := validateGrantFamilies(g); errMsg != "" {
		return nil, logical.ErrorResponse("%s", errMsg)
	}

	entry := parseMappingEntry(name, g, data)
	entry.DelegatingPrincipal = principal
	if errMsg := validateMappingSelectors(&entry); errMsg != "" {
		return nil, logical.ErrorResponse("%s", errMsg)
	}
	if errMsg := validateMappingLifecycle(&entry); errMsg != "" {
		return nil, logical.ErrorResponse("%s", errMsg)
	}
	return &entry, nil
}

// refuseRewriteOfRevoked reports an error response when `entry` would overwrite a record
// that is already revoked, or nil when the write may proceed.
//
// Revocation is terminal. Without this, re-writing a revoked mapping as `active` restores
// the authority it conferred, so "revoked" would claim more than the plugin enforces and
// would be indistinguishable from "suspended". Suspension is the reversible state;
// revocation is not, and an operator who needs the grant back creates a new record under
// a new name so the revoked one stays on the trail.
func refuseRewriteOfRevoked(entry *mappingEntry, existing []mappingEntry) *logical.Response {
	for i := range existing {
		if existing[i].Name != entry.Name || existing[i].LifecycleState != lifecycleRevoked {
			continue
		}
		return logical.ErrorResponse(
			"mapping %q is revoked, which is terminal: it cannot be rewritten to %q. "+
				"Create a new mapping instead; use %q for a reversible pause.",
			entry.Name, entry.LifecycleState, lifecycleSuspended,
		)
	}
	return nil
}

// delegatingPrincipal names the operator whose authenticated write created a record.
//
// An identity entity is preferred: it is unique per identity and stable across that
// operator's tokens. Otherwise the token's accessor is used, because it is unique per
// token — the display name alone is not, since every entity-less token reports "token",
// and `envelopeConflicts` compares this string to detect two operators delegating into
// one grant. Recorded as `<display name>:<accessor>` so the value stays readable while
// still distinguishing two operators. A token accessor is not a secret; Vault issues it
// precisely so a token can be referred to without presenting it.
//
// Two tokens belonging to the same operator therefore read as two principals, so their
// mappings will not compose — that fails closed, and the remedy is an identity entity.
// Empty means the request carries no identity at all, which is refused by the caller.
func delegatingPrincipal(req *logical.Request) string {
	if req.EntityID != "" {
		return "vault:entity:" + req.EntityID
	}
	if req.ClientTokenAccessor != "" {
		return "vault:token:" + req.DisplayName + ":" + req.ClientTokenAccessor
	}
	if req.DisplayName != "" {
		return "vault:token:" + req.DisplayName
	}
	return ""
}

// defaultEgressModes declares this harness's egress mode for any target that names
// none, writing it into families in place. ODIS-L2-15 requires a per-target
// declaration, and the harness enforces at the adapter rather than relying on the
// target to validate the agent's credential — that is bridge mode. Declaring it here
// rather than at issuance means the stored record says what it confers, and every
// signed bundle carries the declaration.
func defaultEgressModes(families map[string]grantFamily) {
	for name, gf := range families {
		if gf.VendorMCP.EgressMode == "" {
			gf.VendorMCP.EgressMode = apfbundle.EgressModeBridge
			families[name] = gf
		}
	}
}

// assignRecordVersion sets the record version for this write and rejects a rollback.
// An omitted record_version advances past every version already accepted for the
// name; an explicit one must exceed it, so the stored sequence is monotonic and a
// replayed record cannot be re-accepted (§6.1 rollback detection).
func (b *backend) assignRecordVersion(
	ctx context.Context, s logical.Storage, entry *mappingEntry, data *framework.FieldData,
) (*logical.Response, error) {
	seen, err := b.readRecordVersionSeen(ctx, s, entry.Name)
	if err != nil {
		return nil, err
	}
	requested, provided := data.GetOk(fieldRecordVersion)
	if !provided {
		entry.RecordVersion = seen + 1
		return nil, nil
	}
	version, _ := requested.(int)
	if version <= seen {
		return logical.ErrorResponse(
			"record_version %d must be greater than %d, the highest version already "+
				"accepted for mapping %q (rollback detection)",
			version, seen, entry.Name,
		), nil
	}
	entry.RecordVersion = version
	return nil, nil
}

// validateGrantFamilies fails closed on a grant that would project to an
// unenforceable or unloadable bundle. It returns a client-facing message ("" means
// valid). The grant must declare at least one family, and per family: the
// default_mode must be a known mode (an empty/typo'd mode would project to
// default_mode:"" and sign an unloadable bundle); the egress mode must be one of the
// two ODIS-L2-15 defines; the policy must compile (policydsl.ValidateSpec rejects a
// duplicate verb -> OPA eval_conflict_error, or an unknown condition op, before it is
// stored or signed); and no family may be permissive with zero policy rules — that
// projects to no governed tools, which the Router treats as unpoliced passthrough for
// every tool (the gate would forward unconditionally).
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
	if msg := validateVendorMCP(name, gf.VendorMCP); msg != "" {
		return msg
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

// validateVendorMCP checks one family's target declaration: an id and URL the
// consumer's schema will accept, and an egress mode ODIS-L2-15 defines.
func validateVendorMCP(family string, vendor apfbundle.VendorMCP) string {
	if !isValidResourceName(vendor.EndpointID) {
		return fmt.Sprintf(
			"family %q vendor_mcp.endpoint_id %q must match ^[a-z][a-z0-9-]*$",
			family, vendor.EndpointID)
	}
	if !strings.HasPrefix(vendor.URL, "https://") && !strings.HasPrefix(vendor.URL, "http://") {
		return fmt.Sprintf("family %q vendor_mcp.url must start with http:// or https://", family)
	}
	// `native` is a legal ODIS-L2-15 value but a false claim here: it asserts the target
	// itself validates the agent's runtime credential and delegation record, and this
	// harness is bridge-only — the Router never reads the field, so a signed `native`
	// declaration would tell a downstream consumer it may skip adapter-side enforcement
	// that nothing performs. Refused at the write rather than signed, the same way the
	// Python loader refuses a delegation_chain hop it cannot verify.
	if vendor.EgressMode == apfbundle.EgressModeNative {
		return fmt.Sprintf(
			"family %q vendor_mcp.egress_mode %q is not implemented: this issuer signs "+
				"only %q, because the Router enforces at the adapter",
			family, apfbundle.EgressModeNative, apfbundle.EgressModeBridge)
	}
	if vendor.EgressMode != apfbundle.EgressModeBridge {
		return fmt.Sprintf(
			"family %q vendor_mcp.egress_mode %q must be %q or %q",
			family, vendor.EgressMode, apfbundle.EgressModeNative, apfbundle.EgressModeBridge)
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

// validateMappingLifecycle fails closed on lifecycle fields that would store a record
// nothing can resolve. It returns a client-facing message ("" means valid): an
// unenumerated lifecycle state confers nothing and says nothing; a valid_until that
// is unparseable or already past stores a dead record; and a grant_ttl outside
// (0, maxGrantTTL] would either issue an already-expired grant or an effectively
// immortal one.
func validateMappingLifecycle(entry *mappingEntry) string {
	states := lifecycleStates()
	if !slices.Contains(states, entry.LifecycleState) {
		return fmt.Sprintf(
			"lifecycle_state %q must be one of: %s",
			entry.LifecycleState, strings.Join(states, ", "))
	}
	if entry.ValidUntil != "" {
		until, err := time.Parse(time.RFC3339, entry.ValidUntil)
		if err != nil {
			return fmt.Sprintf("valid_until %q must be an RFC 3339 instant", entry.ValidUntil)
		}
		if !until.After(time.Now().UTC()) {
			return fmt.Sprintf("valid_until %q is already past; the record would confer nothing", entry.ValidUntil)
		}
	}
	ttl := time.Duration(entry.GrantTTLSeconds) * time.Second
	if ttl <= 0 || ttl > maxGrantTTL {
		return fmt.Sprintf(
			"grant_ttl must be greater than 0 and at most %s (got %ds)",
			maxGrantTTL, entry.GrantTTLSeconds)
	}
	return ""
}

// parseMappingEntry reads the bound_* match and lifecycle fields off the request and
// assembles a mappingEntry around the already-parsed grant. The delegating principal
// and record version come from the request identity and stored history, not from
// request data, so they are set by the caller.
func parseMappingEntry(name string, g grant, data *framework.FieldData) mappingEntry {
	boundIssuer, _ := data.Get(fieldBoundIssuer).(string)
	boundAudiences, _ := data.Get(fieldBoundAudiences).([]string)
	boundSubject, _ := data.Get(fieldBoundSubject).(string)
	boundSubjectPrefix, _ := data.Get(fieldBoundSubjectPrefix).(string)
	boundClaims, _ := data.Get(fieldBoundClaims).(map[string]string)
	lifecycleState, _ := data.Get(fieldLifecycleState).(string)
	validUntil, _ := data.Get(fieldValidUntil).(string)
	grantTTL, _ := data.Get(fieldGrantTTL).(int)
	return mappingEntry{
		Name:               name,
		BoundIssuer:        boundIssuer,
		BoundAudiences:     boundAudiences,
		BoundSubject:       boundSubject,
		BoundSubjectPrefix: boundSubjectPrefix,
		BoundClaims:        boundClaims,
		Grant:              g,
		LifecycleState:     lifecycleState,
		ValidUntil:         validUntil,
		GrantTTLSeconds:    grantTTL,
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
		// Who is answerable for this grant, and whether the record still confers it.
		// The principal is an identity reference, not a credential.
		fieldDelegatingPrincipal: mapping.DelegatingPrincipal,
		fieldLifecycleState:      mapping.LifecycleState,
		fieldValidUntil:          mapping.ValidUntil,
		fieldRecordVersion:       mapping.RecordVersion,
		"grant_ttl_seconds":      mapping.GrantTTLSeconds,
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
	// Only the record is deleted. Its version high-water mark stays, so recreating
	// the name cannot restart the sequence and re-accept a superseded record.
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
