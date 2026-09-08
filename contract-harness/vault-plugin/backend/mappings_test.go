package backend_test

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	testMappingPath = "mappings/jira"
	testBundleJSON  = `{"bundle_id":"odis-fixture-bundle","bundle_version":"0.1.0",` +
		`"trust_root_id":"fixture-trust-root","families":{"jira-prod":{` +
		`"vendor_mcp":{"endpoint_id":"jira-prod-mcp-v1","url":"https://jira-prod-mcp.internal:8443/"},` +
		`"policy":{"rules":[{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`
)

// writeMappingAs writes a mapping as an authenticated Vault caller. Every real
// request carries the writer's identity, which the handler records as the mapping's
// delegating principal; a bare request carries none and is refused.
func writeMappingAs(
	t *testing.T, b logical.Backend, s logical.Storage, path string, data map[string]any,
) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
		EntityID:  "e-test-writer",
	})
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return resp
}

// grantForFamily builds a single-family grant JSON for a collision test.
func grantForFamily(family string) string {
	return `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"` + family + `":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},` +
		`"policy":{"rules":[{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"strict"}}}`
}

// TestWriteMappingRejectsSameFamilyCollision: two assigned mappings co-satisfiable by
// one token that both define the same family collide — the second WRITE is rejected
// (an operator-facing error response), moving enforcement from issuance-time 5xx to
// write time. The collision is co-satisfiability of the two selectors + a shared family.
func TestWriteMappingRejectsSameFamilyCollision(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("first mapping rejected: %v", resp.Error())
	}
	resp := writeMappingAs(t, b, s, "mappings/b", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	})
	if resp == nil || !resp.IsError() {
		t.Error("expected the colliding second mapping (same subject, same family) to be rejected")
	}
}

// TestWriteMappingRejectsPrefixCoversSubjectCollision: an exact subject under an
// existing prefix mapping is co-satisfiable (one token's subject satisfies both) — a
// shared family collides and the write is rejected.
func TestWriteMappingRejectsPrefixCoversSubjectCollision(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject_prefix": "spiffe://example.org/agent/", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("prefix mapping rejected: %v", resp.Error())
	}
	resp := writeMappingAs(t, b, s, "mappings/b", map[string]any{
		"bound_subject": "spiffe://example.org/agent/jira", "bundle": grantForFamily("jira-prod"),
	})
	if resp == nil || !resp.IsError() {
		t.Error("expected rejection: the prefix covers the exact subject (co-satisfiable, shared family)")
	}
}

// TestWriteMappingAcceptsDisjointSubjects: two DIFFERENT exact subjects can never be
// satisfied by one token's single subject — not co-satisfiable, so a shared family is
// accepted.
func TestWriteMappingAcceptsDisjointSubjects(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject": "spiffe://example.org/agent-1", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("first mapping rejected: %v", resp.Error())
	}
	if resp := writeMappingAs(t, b, s, "mappings/b", map[string]any{
		"bound_subject": "spiffe://example.org/agent-2", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Errorf("disjoint exact subjects must be accepted (not co-satisfiable): %v", resp.Error())
	}
}

// TestWriteMappingAcceptsDisjointFamilies: co-satisfiable selectors but DISJOINT
// families never collide at issuance — accepted.
func TestWriteMappingAcceptsDisjointFamilies(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("first mapping rejected: %v", resp.Error())
	}
	if resp := writeMappingAs(t, b, s, "mappings/b", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("github"),
	}); resp.IsError() {
		t.Errorf("disjoint families must be accepted (no shared family to collide): %v", resp.Error())
	}
}

// TestWriteMappingAcceptsConflictingClaim: two mappings requiring DIFFERENT values for
// the same claim key can never be satisfied by one token — not co-satisfiable, so a
// shared family is accepted.
func TestWriteMappingAcceptsConflictingClaim(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_claims": "team=alpha", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("first mapping rejected: %v", resp.Error())
	}
	if resp := writeMappingAs(t, b, s, "mappings/b", map[string]any{
		"bound_claims": "team=beta", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Errorf("a conflicting claim value makes the selectors disjoint; must be accepted: %v", resp.Error())
	}
}

// TestWriteMappingAcceptsSelfUpdate: re-writing a mapping under its OWN name with the
// same family is a self-update, not a collision (the existing entry of the same name
// is excluded from the check) — accepted.
func TestWriteMappingAcceptsSelfUpdate(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Fatalf("first write rejected: %v", resp.Error())
	}
	if resp := writeMappingAs(t, b, s, "mappings/a", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Errorf("re-writing the same mapping must be accepted (self-update, name excluded): %v", resp.Error())
	}
}

// TestWriteMappingRejectsBothSubjectAndPrefix: a self-contradictory mapping that pins
// BOTH an exact bound_subject and a bound_subject_prefix is rejected (the co-satisfiable
// check assumes at most one subject field per mapping). Setting either alone succeeds.
func TestWriteMappingRejectsBothSubjectAndPrefix(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := writeMappingAs(t, b, s, "mappings/both", map[string]any{
		"bound_subject":        "spiffe://example.org/agent",
		"bound_subject_prefix": "spiffe://example.org/",
		"bundle":               grantForFamily("jira-prod"),
	})
	if resp == nil || !resp.IsError() {
		t.Error("expected rejection: a mapping may set bound_subject or bound_subject_prefix, not both")
	}

	if resp := writeMappingAs(t, b, s, "mappings/subject-only", map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantForFamily("jira-prod"),
	}); resp.IsError() {
		t.Errorf("bound_subject alone must be accepted: %v", resp.Error())
	}
	if resp := writeMappingAs(t, b, s, "mappings/prefix-only", map[string]any{
		"bound_subject_prefix": "spiffe://example.org/team/", "bundle": grantForFamily("github"),
	}); resp.IsError() {
		t.Errorf("bound_subject_prefix alone must be accepted: %v", resp.Error())
	}
}

// TestMappingCRUDRoundTrip: write -> read -> list -> delete.
func TestMappingCRUDRoundTrip(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	resp := writeMappingAs(t, b, s, testMappingPath, map[string]any{
		"bound_issuer":    "https://fixture.issuer.odis.local/",
		"bound_audiences": "apf-bundle-issuer",
		"bound_subject":   "spiffe://example.org/agent",
		"bound_claims":    "group=jira-writers",
		"bundle":          testBundleJSON,
	})
	if resp.IsError() {
		t.Fatalf("write returned error: %v", resp.Error())
	}

	got := read(t, b, s, testMappingPath)
	if got == nil {
		t.Fatal("read returned nil after write")
	}
	if got.Data["bound_subject"] != "spiffe://example.org/agent" {
		t.Errorf("bound_subject = %v", got.Data["bound_subject"])
	}

	listResp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "mappings/",
		Storage:   s,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	keys, _ := listResp.Data["keys"].([]string)
	if len(keys) != 1 || keys[0] != "jira" {
		t.Errorf("list keys = %v, want [jira]", keys)
	}

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      testMappingPath,
		Storage:   s,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if after := read(t, b, s, testMappingPath); after != nil {
		t.Errorf("expected nil after delete, got %#v", after)
	}
}

// TestMappingRequiresFamily: a bundle with no families fails closed.
func TestMappingRequiresFamily(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := writeMappingAs(t, b, s, testMappingPath, map[string]any{
		"bundle": `{"bundle_id":"x","bundle_version":"1","trust_root_id":"r","families":{}}`,
	})
	if !resp.IsError() {
		t.Error("expected an error response for a bundle with no families")
	}
}

// TestMappingRejectsInvalidJSON: a non-JSON bundle fails closed.
func TestMappingRejectsInvalidJSON(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := writeMappingAs(t, b, s, testMappingPath, map[string]any{"bundle": "not json"})
	if !resp.IsError() {
		t.Error("expected an error response for invalid bundle JSON")
	}
}

// TestMappingRejectsZeroConstraint: a mapping with a valid bundle but no bound_*
// fields is a wildcard (matches every workload) and must be rejected.
func TestMappingRejectsZeroConstraint(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	resp := writeMappingAs(t, b, s, testMappingPath, map[string]any{"bundle": testBundleJSON})
	if !resp.IsError() {
		t.Error("expected an error response for a mapping with no bound_* constraints")
	}
}

// A permissive family with zero policy rules projects to no governed tools, so the
// Router treats every tool as unpoliced passthrough — fail closed at write.
func TestMappingRejectsPermissiveZeroRuleFamily(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)
	grantJSON := `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},` +
		`"policy":{"rules":[]},"default_mode":"permissive"}}}`
	resp := writeMappingAs(t, b, s, testMappingPath, map[string]any{
		"bound_subject": "spiffe://example.org/agent", "bundle": grantJSON,
	})
	if !resp.IsError() {
		t.Error("expected an error response for a permissive zero-rule family")
	}
}

// A strict zero-rule family is safe (every tool is denied, never forwarded), and a
// permissive family with at least one rule is policed — both are accepted.
func TestMappingAcceptsSafeZeroRuleAndPolicedPermissive(t *testing.T) {
	t.Parallel()
	b, s := newTestBackend(t)

	strictZero := `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},` +
		`"policy":{"rules":[]},"default_mode":"strict"}}}`
	if resp := writeMappingAs(t, b, s, "mappings/strict-zero", map[string]any{
		"bound_subject": "spiffe://example.org/strict", "bundle": strictZero,
	}); resp.IsError() {
		t.Errorf("strict zero-rule family was rejected: %v", resp.Error())
	}

	permissivePoliced := `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"},` +
		`"policy":{"rules":[{"verb":"update_issue","allow_fields":["labels"]}]},"default_mode":"permissive"}}}`
	if resp := writeMappingAs(t, b, s, "mappings/permissive-policed", map[string]any{
		"bound_subject": "spiffe://example.org/permissive", "bundle": permissivePoliced,
	}); resp.IsError() {
		t.Errorf("permissive family with a rule was rejected: %v", resp.Error())
	}
}
