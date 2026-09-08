package backend

import (
	"context"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"slices"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

// White-box tests for mapping storage + the claim-match logic. Single-winner
// selectMapping/specificity were removed when grant selection became the union
// model — see composeMappings in compose_internal_test.go.

func TestAllMappingsLoadsEntries(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ctx := context.Background()
	for _, name := range []string{"one", "two"} {
		entry, err := logical.StorageEntryJSON(storageKeyMappingPrefix+name, mappingEntry{Name: name})
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if err := s.Put(ctx, entry); err != nil {
			t.Fatalf("put: %v", err)
		}
	}

	got, err := b.allMappings(ctx, s)
	if err != nil {
		t.Fatalf("allMappings: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d mappings, want 2", len(got))
	}
}

// TestMappingPolicySpecRoundTrips writes a mapping carrying a non-trivial PolicySpec
// through the real write handler, reads it back via readMapping, and asserts the
// stored spec (verb, condition, allow_fields) survives intact — so a JSON-tag drift
// on Rule/Condition is caught without booting Vault.
// minimalGrantJSON is a valid single-family grant reused by handler-level tests.
const minimalGrantJSON = `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
	`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
	`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`

func TestMappingPolicySpecRoundTrips(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); err != nil {
		t.Fatalf("setup: %v", err)
	}

	const grantJSON = `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
		`{"verb":"update_issue","where":[{"field":"issue_key","op":"startsWith","value":"APF-"}],` +
		`"allow_fields":["labels","summary"]}]},"default_mode":"strict"}}}`

	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "mappings/rt",
		Storage:   s,
		Data:      map[string]any{fieldBoundSubject: "spiffe://example.org/agent", fieldBundle: grantJSON},
		EntityID:  testWriterEntityID,
	})
	if err != nil {
		t.Fatalf("write mapping: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("write mapping errored: %v", resp.Error())
	}

	got, err := b.readMapping(ctx, s, "rt")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	fam, ok := got.Grant.Families["jira-prod"]
	if !ok {
		t.Fatal("stored grant missing the jira-prod family")
	}
	want := policydsl.Rule{
		Verb:        "update_issue",
		Where:       []policydsl.Condition{{Field: "issue_key", Op: policydsl.OpStartsWith, Value: "APF-"}},
		AllowFields: []string{"labels", "summary"},
	}
	rules := fam.Policy.Rules
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if !rulesEqual(rules[0], want) {
		t.Errorf("policy spec did not round-trip:\n got  %+v\n want %+v", rules[0], want)
	}
}

// The read HANDLER echoes the complete grant (auditable), not just family names.
func TestMappingReadHandlerEchoesGrant(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if _, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "mappings/echo",
		Storage:   s,
		Data:      map[string]any{fieldBoundSubject: "spiffe://example.org/agent", fieldBundle: minimalGrantJSON},
		EntityID:  testWriterEntityID,
	}); err != nil {
		t.Fatalf("write mapping: %v", err)
	}

	rresp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "mappings/echo",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("read mapping handler: %v", err)
	}
	echoed, ok := rresp.Data[fieldBundle].(grant)
	if !ok {
		t.Fatalf("read bundle = %T, want grant", rresp.Data[fieldBundle])
	}
	if _, hasFamily := echoed.Families["jira-prod"]; !hasFamily {
		t.Errorf("handler read did not preserve the grant families: %+v", echoed.Families)
	}
}

// rulesEqual compares two policy rules by verb, conditions, and allow_fields — the
// fields a JSON-tag drift on Rule/Condition would silently break.
func rulesEqual(a, b policydsl.Rule) bool {
	return a.Verb == b.Verb &&
		slices.Equal(a.Where, b.Where) &&
		slices.Equal(a.AllowFields, b.AllowFields)
}

// writeMapping drives the real write handler for a grant whose only binding is a
// fixed bound_subject, returning the handler's response so a test can assert on it.
func writeMapping(t *testing.T, grantJSON string) (*logical.Response, error) {
	t.Helper()
	b := newBackend()
	s := &logical.InmemStorage{}
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "mappings/x",
		Storage:   s,
		Data:      map[string]any{fieldBoundSubject: "spiffe://example.org/agent", fieldBundle: grantJSON},
		EntityID:  testWriterEntityID,
	})
}

// A grant whose vendor_mcp or envelope would fail the consumer's odis.bundle.v1
// schema is rejected at write — the plugin must never sign a bundle the loader is
// guaranteed to reject.
func TestWriteMappingRejectsUnloadableGrant(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"uppercase endpoint_id": `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
			`"jira-prod":{"vendor_mcp":{"endpoint_id":"Jira-Prod","url":"https://v/"},"policy":{"rules":[` +
			`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`,
		"schemeless url": `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
			`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"jira.internal"},"policy":{"rules":[` +
			`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`,
		"invalid family name": `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
			`"Jira_Prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
			`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`,
		"empty envelope": `{"bundle_id":"","bundle_version":"1","trust_root_id":"r","families":{` +
			`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
			`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`,
	}
	for label, grantJSON := range cases {
		resp, err := writeMapping(t, grantJSON)
		if err != nil {
			t.Fatalf("%s: unexpected err: %v", label, err)
		}
		if resp == nil || !resp.IsError() {
			t.Errorf("%s: expected the write to be rejected", label)
		}
	}
}

// A bound_claims entry with an empty value is rejected at write: matched against
// the selector map it would invert into "matches when the claim is ABSENT" — a
// constraint typo silently becoming a near-wildcard grant.
func TestWriteMappingRejectsEmptyBoundClaimValue(t *testing.T) {
	t.Parallel()

	b := newBackend()
	s := &logical.InmemStorage{}
	ctx := context.Background()
	if err := b.Setup(ctx, &logical.BackendConfig{StorageView: s}); err != nil {
		t.Fatalf("setup: %v", err)
	}
	resp, err := b.HandleRequest(ctx, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "mappings/typo",
		Storage:   s,
		Data: map[string]any{
			fieldBoundClaims: map[string]string{"group": ""},
			fieldBundle:      minimalGrantJSON,
		},
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error for an empty bound_claims value")
	}
}

// A grant whose family policy has two rules for the SAME verb is rejected at write:
// it would compile to conflicting Rego complete-rules (OPA eval_conflict_error), so
// validateGrantFamilies runs policydsl.ValidateSpec per family and fails closed.
func TestWriteMappingRejectsDuplicateVerb(t *testing.T) {
	t.Parallel()

	const dupVerb = `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
		`{"verb":"update_issue","allow_fields":["labels"]},` +
		`{"verb":"update_issue","allow_fields":["summary"]}]},"default_mode":"strict"}}}`

	resp, err := writeMapping(t, dupVerb)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error for a grant family with a duplicate verb")
	}
}

// A grant whose family policy has a condition with an unknown op is rejected at
// write: the op set is closed and an unknown op fails to compile, so the spec must
// never be stored or signed.
func TestWriteMappingRejectsUnknownOp(t *testing.T) {
	t.Parallel()

	const unknownOp = `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
		`{"verb":"update_issue","where":[{"field":"issue_key","op":"contains","value":"APF-"}]}]},` +
		`"default_mode":"strict"}}}`

	resp, err := writeMapping(t, unknownOp)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error for a grant family with an unknown condition op")
	}
}

// A grant family whose default_mode is empty or a typo is rejected at write: it
// would project to default_mode:"" (or a bogus value), signing a bundle the Router
// cannot load. Only the closed set {strict, permissive} is accepted.
func TestWriteMappingRejectsInvalidDefaultMode(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{"", "bogus"} {
		grantJSON := `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
			`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},"policy":{"rules":[` +
			`{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"` + mode + `"}}}`

		resp, err := writeMapping(t, grantJSON)
		if err != nil {
			t.Fatalf("default_mode=%q: unexpected err: %v", mode, err)
		}
		if resp == nil || !resp.IsError() {
			t.Errorf("default_mode=%q: expected an error for an invalid default_mode", mode)
		}
	}
}

func TestMappingMatchesClaims(t *testing.T) {
	t.Parallel()

	entry := mappingEntry{
		BoundAudiences: []string{"apf-bundle-issuer"},
		BoundClaims:    map[string]string{"group": "jira-writers"},
	}
	matching := matchInput{
		Audiences: []string{"apf-bundle-issuer"},
		Claims:    map[string]string{"group": "jira-writers"},
	}
	if !entry.matches(matching) {
		t.Error("expected match when audience and claim agree")
	}

	wrongClaim := matchInput{
		Audiences: []string{"apf-bundle-issuer"},
		Claims:    map[string]string{"group": "other"},
	}
	if entry.matches(wrongClaim) {
		t.Error("expected no match when a bound claim differs")
	}

	// Defense in depth below the write-time rejection: even if an empty-value
	// bound claim reached the matcher, a workload MISSING the claim must not match.
	emptyWant := mappingEntry{BoundClaims: map[string]string{"group": ""}}
	if emptyWant.matches(matchInput{Audiences: []string{"apf-bundle-issuer"}}) {
		t.Error("a workload missing the claim must not match an empty-value selector")
	}
}

// TestMappingMatchesSubjectPrefix: a subject-subtree mapping matches any identity
// under the bound prefix, rejects identities outside it, and confers a grant (the
// subtree is an assigned selector, like an exact subject or a claim).
func TestMappingMatchesSubjectPrefix(t *testing.T) {
	t.Parallel()

	entry := mappingEntry{BoundSubjectPrefix: "spiffe://example.org/team-foo/"}

	inSubtree := matchInput{Subject: "spiffe://example.org/team-foo/agent-1"}
	if !entry.matches(inSubtree) {
		t.Error("expected match for a subject under the bound subtree")
	}

	otherSubtree := matchInput{Subject: "spiffe://example.org/team-bar/agent-1"}
	if entry.matches(otherSubtree) {
		t.Error("expected no match for a subject outside the bound subtree")
	}

	// Subtree semantics honor "/" segment boundaries: a prefix without a trailing
	// separator matches itself and its descendants, never a sibling that merely
	// string-extends it (jira vs jira-support).
	bare := mappingEntry{BoundSubjectPrefix: "spiffe://example.org/agent/jira"}
	if !bare.matches(matchInput{Subject: "spiffe://example.org/agent/jira"}) {
		t.Error("expected the prefix to match itself exactly")
	}
	if !bare.matches(matchInput{Subject: "spiffe://example.org/agent/jira/worker-1"}) {
		t.Error("expected a descendant of the prefix to match")
	}
	if bare.matches(matchInput{Subject: "spiffe://example.org/agent/jira-support"}) {
		t.Error("a sibling that string-extends the prefix must NOT receive the grant")
	}

	if !entry.isAssignedGrant() {
		t.Error("a subject-subtree mapping is an assigned selector; isAssignedGrant must be true")
	}
}
