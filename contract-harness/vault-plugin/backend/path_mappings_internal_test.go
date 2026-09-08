package backend

import (
	"context"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// Write-path tests for the fields ODIS-L2-14 (lifecycle), ODIS-L2-05 (delegating
// principal) and ODIS-L2-15 (egress mode) add to a mapping record.

// writeAs performs a mapping write as an authenticated Vault caller. Vault supplies
// the writer's identity on every real request; a bare logical.Request carries none,
// so the tests state it explicitly.
func writeAs(
	t *testing.T, b *backend, s logical.Storage,
	path string, data map[string]any, req func(*logical.Request),
) *logical.Response {
	t.Helper()
	r := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      path,
		Storage:   s,
		Data:      data,
		EntityID:  testWriterEntityID,
	}
	if req != nil {
		req(r)
	}
	resp, err := b.HandleRequest(context.Background(), r)
	if err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return resp
}

func mappingGrantJSON(egressMode string) string {
	mode := ""
	if egressMode != "" {
		mode = `,"egress_mode":"` + egressMode + `"`
	}
	return `{"bundle_id":"b","bundle_version":"1","trust_root_id":"r","families":{` +
		`"jira-prod":{"vendor_mcp":{"endpoint_id":"e","url":"https://v/"` + mode + `},` +
		`"policy":{"rules":[{"verb":"update_issue","allow_fields":["labels"]}]},` +
		`"default_mode":"strict"}}}`
}

// The delegating principal is the authenticated writer, taken from the request
// rather than from operator-supplied text — an unauthenticated string would be
// self-asserted accountability (ODIS-L2-05, §6.3 "authenticated ... principal").
func TestWriteMappingRecordsAuthenticatedWriter(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	resp := writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
	}, func(r *logical.Request) { r.EntityID = "e-platform" })
	if resp.IsError() {
		t.Fatalf("write rejected: %v", resp.Error())
	}

	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if entry.DelegatingPrincipal != "vault:entity:e-platform" {
		t.Errorf("delegating_principal = %q, want %q",
			entry.DelegatingPrincipal, "vault:entity:e-platform")
	}
}

// With no identity entity, the token's display name identifies the writer.
// A token display name is accepted so root-token bootstrap can write a mapping, and it
// is recorded verbatim — the non-uniqueness it carries is handled in composeMappings,
// not by refusing the write. See TestComposeRefusesSeveralRecordsUnderANonUniquePrincipal.
func TestWriteMappingAcceptsATokenDisplayNamePrincipal(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	resp := writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON("bridge"),
	}, func(r *logical.Request) {
		r.EntityID = ""
		r.DisplayName = "token"
		r.ClientTokenAccessor = "accessor-1"
	})
	if resp != nil && resp.IsError() {
		t.Fatalf("a display-name write must be accepted: %v", resp.Error())
	}

	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	want := "vault:token:token:accessor-1"
	if entry.DelegatingPrincipal != want {
		t.Errorf("delegating_principal = %q, want %q", entry.DelegatingPrincipal, want)
	}
}

func TestWriteMappingRecordsTheWritingEntity(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
	}, nil)

	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if entry.DelegatingPrincipal != vaultWriterPrincipal {
		t.Errorf("delegating_principal = %q, want %q", entry.DelegatingPrincipal, vaultWriterPrincipal)
	}
}

// A write carrying no authenticated identity at all has no principal to hold
// accountable, so it is refused rather than stored anonymously.
func TestWriteMappingRejectsUnattributedWriter(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	resp := writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
	}, func(r *logical.Request) { r.EntityID = ""; r.DisplayName = "" })
	if resp == nil || !resp.IsError() {
		t.Error("expected a write with no authenticated writer identity to be rejected")
	}
}

// A record is active and at version 1 unless the operator says otherwise, so an
// existing provisioning flow keeps conferring authority.
func TestWriteMappingDefaultsLifecycleFields(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
	}, nil)

	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if entry.LifecycleState != lifecycleActive {
		t.Errorf("lifecycle_state = %q, want %q", entry.LifecycleState, lifecycleActive)
	}
	if entry.RecordVersion != 1 {
		t.Errorf("record_version = %d, want 1", entry.RecordVersion)
	}
	if entry.GrantTTLSeconds != int(defaultGrantTTL.Seconds()) {
		t.Errorf("grant_ttl_seconds = %d, want %d",
			entry.GrantTTLSeconds, int(defaultGrantTTL.Seconds()))
	}
	if entry.ValidUntil != "" {
		t.Errorf("valid_until = %q, want empty (unbounded)", entry.ValidUntil)
	}
}

// A lifecycle state outside the enumerated set is refused: an unrecognized state
// would neither confer authority nor tell the operator why.
func TestWriteMappingRejectsUnknownLifecycleState(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	resp := writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
		"lifecycle_state": "paused",
	}, nil)
	if resp == nil || !resp.IsError() {
		t.Error("expected an unknown lifecycle_state to be rejected")
	}
}

// valid_until must be a future RFC 3339 instant: an unparseable or already-past
// value stores a record that can never confer authority.
func TestWriteMappingRejectsBadValidUntil(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	for name, value := range map[string]string{
		"unparseable": "next tuesday",
		"in the past": time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
	} {
		resp := writeAs(t, b, s, "mappings/jira", map[string]any{
			"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
			"valid_until": value,
		}, nil)
		if resp == nil || !resp.IsError() {
			t.Errorf("expected a %s valid_until to be rejected", name)
		}
	}
}

// record_version is monotonic: a re-write must move forward, so rollback via the
// API is impossible (§6.1 rollback detection).
func TestWriteMappingEnforcesMonotonicRecordVersion(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	base := map[string]any{"bound_subject": testSubject, "bundle": mappingGrantJSON("")}
	if resp := writeAs(t, b, s, "mappings/jira", base, nil); resp.IsError() {
		t.Fatalf("first write rejected: %v", resp.Error())
	}

	stale := map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""), "record_version": 1,
	}
	if resp := writeAs(t, b, s, "mappings/jira", stale, nil); resp == nil || !resp.IsError() {
		t.Error("expected a re-write at the same record_version to be rejected")
	}

	// An omitted record_version auto-advances, so ordinary re-writes still work.
	if resp := writeAs(t, b, s, "mappings/jira", base, nil); resp.IsError() {
		t.Fatalf("re-write rejected: %v", resp.Error())
	}
	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if entry.RecordVersion != 2 {
		t.Errorf("record_version = %d, want 2 after a re-write", entry.RecordVersion)
	}
}

// Deleting a mapping keeps its version high-water mark, so recreating it cannot
// silently reset the record to an earlier version.
func TestDeleteMappingKeepsVersionHighWaterMark(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	base := map[string]any{"bound_subject": testSubject, "bundle": mappingGrantJSON("")}
	writeAs(t, b, s, "mappings/jira", base, nil)
	writeAs(t, b, s, "mappings/jira", base, nil)
	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation, Path: "mappings/jira", Storage: s,
	}); err != nil {
		t.Fatalf("delete: %v", err)
	}

	writeAs(t, b, s, "mappings/jira", base, nil)
	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if entry.RecordVersion != 3 {
		t.Errorf("record_version = %d, want 3 (the high-water mark survives delete)", entry.RecordVersion)
	}
}

// A target with no declared egress mode gets this harness's mode, bridge — so every
// issued bundle carries the ODIS-L2-15 declaration.
func TestWriteMappingDefaultsEgressModeToBridge(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
	}, nil)

	entry, err := b.readMapping(context.Background(), s, "jira")
	if err != nil {
		t.Fatalf("readMapping: %v", err)
	}
	if got := entry.Grant.Families["jira-prod"].VendorMCP.EgressMode; got != "bridge" {
		t.Errorf("egress_mode = %q, want %q", got, "bridge")
	}
}

// Only the two modes ODIS-L2-15 defines are legal.
// Only `bridge` is signable here. An unrecognised mode is meaningless, and `native` is
// worse than meaningless: ODIS-L2-15 defines it as "the target independently validates
// the Agent Runtime Credential and active Delegation Record", the Router never reads the
// field, and this adapter enforces at the adapter. Signing it would put a false claim
// inside integrity-protected bytes and invite a downstream consumer to skip enforcement
// nothing performs — so it is refused at the write, as the Python loader refuses a
// delegation_chain hop it cannot verify.
func TestWriteMappingSignsOnlyBridgeEgressMode(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	for _, mode := range []string{"passthrough", "native"} {
		resp := writeAs(t, b, s, "mappings/"+mode, map[string]any{
			"bound_subject": testSubject, "bundle": mappingGrantJSON(mode),
		}, nil)
		if resp == nil || !resp.IsError() {
			t.Errorf("egress_mode %q must be refused, got %+v", mode, resp)
		}
	}

	ok := writeAs(t, b, s, "mappings/bridge", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON("bridge"),
	}, nil)
	if ok.IsError() {
		t.Errorf("egress_mode bridge must be accepted: %v", ok.Error())
	}
}

// grant_ttl bounds how long an issued grant lives; zero and over-long values are
// refused so a grant can never be effectively immortal (ODIS-L3-04).
func TestWriteMappingBoundsGrantTTL(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	for name, ttl := range map[string]any{
		"zero":      0,
		"negative":  -5,
		"over-long": int(maxGrantTTL.Seconds()) + 1,
	} {
		resp := writeAs(t, b, s, "mappings/jira", map[string]any{
			"bound_subject": testSubject, "bundle": mappingGrantJSON(""), "grant_ttl": ttl,
		}, nil)
		if resp == nil || !resp.IsError() {
			t.Errorf("expected a %s grant_ttl to be rejected", name)
		}
	}
}

// The read handler echoes the lifecycle and accountability fields so an operator
// can audit what a record confers and who is answerable for it.
func TestReadMappingEchoesLifecycleFields(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	until := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	writeAs(t, b, s, "mappings/jira", map[string]any{
		"bound_subject": testSubject, "bundle": mappingGrantJSON(""),
		"lifecycle_state": lifecycleSuspended, "valid_until": until, "grant_ttl": 600,
	}, nil)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation, Path: "mappings/jira", Storage: s,
	})
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if resp.Data["lifecycle_state"] != lifecycleSuspended {
		t.Errorf("lifecycle_state = %v, want %q", resp.Data["lifecycle_state"], lifecycleSuspended)
	}
	if resp.Data["valid_until"] != until {
		t.Errorf("valid_until = %v, want %q", resp.Data["valid_until"], until)
	}
	if resp.Data["record_version"] != 1 {
		t.Errorf("record_version = %v, want 1", resp.Data["record_version"])
	}
	if resp.Data["grant_ttl_seconds"] != 600 {
		t.Errorf("grant_ttl_seconds = %v, want 600", resp.Data["grant_ttl_seconds"])
	}
	if resp.Data["delegating_principal"] != vaultWriterPrincipal {
		t.Errorf("delegating_principal = %v, want %q",
			resp.Data["delegating_principal"], vaultWriterPrincipal)
	}
}
