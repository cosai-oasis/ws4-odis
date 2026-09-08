package backend

import (
	"context"
	"errors"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// White-box tests for the mapping-record lifecycle (ODIS-L2-14) and the delegation
// provenance stamped on an issued bundle (ODIS-L2-05 / L3-04).

const (
	testPrincipal = "vault:entity:e-platform"
	testSubject   = "spiffe://example.org/agent/jira"
	// testWriterEntityID stands in for the identity entity Vault attaches to the
	// operator performing a mapping write. An entity id is the only accepted source:
	// see delegatingPrincipal.
	testWriterEntityID = "e-platform-writer"
	// vaultWriterPrincipal is the principal derived from testWriterEntityID.
	vaultWriterPrincipal = "vault:entity:" + testWriterEntityID
)

func lifecycleFamily() grantFamily {
	return grantFamily{
		VendorMCP: apfbundle.VendorMCP{
			EndpointID: "ep",
			URL:        "https://vendor.example/",
			EgressMode: apfbundle.EgressModeBridge,
		},
		Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
			{Verb: "update_issue", AllowFields: []string{"labels"}},
		}},
		DefaultMode: modeStrict,
	}
}

// lifecycleEntry is an active, current mapping conferring one family by subject.
func lifecycleEntry(name, family string) mappingEntry {
	return mappingEntry{
		Name:                name,
		BoundSubject:        testSubject,
		DelegatingPrincipal: testPrincipal,
		LifecycleState:      lifecycleActive,
		RecordVersion:       1,
		GrantTTLSeconds:     int(defaultGrantTTL.Seconds()),
		Grant: grant{
			BundleID:      "b",
			BundleVersion: "1",
			TrustRootID:   "tr",
			Families:      map[string]grantFamily{family: lifecycleFamily()},
		},
	}
}

func lifecycleInput() matchInput {
	return matchInput{
		Issuer:    "https://issuer/",
		Audiences: []string{"apf-bundle-issuer"},
		Subject:   testSubject,
	}
}

func lifecycleBackend(t *testing.T) (*backend, logical.Storage) {
	t.Helper()
	b := newBackend()
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatalf("setup: %v", err)
	}
	return b, config.StorageView
}

// Two mappings that name DIFFERENT delegating principals fail issuance: the
// bundle's originating_principal is single-valued, so an accountability split must
// refuse rather than silently pick one operator's name (ODIS-L2-05).
func TestComposeMappingsPrincipalConflictFailsClosed(t *testing.T) {
	t.Parallel()

	first := lifecycleEntry("by-platform", "jira-prod")
	second := lifecycleEntry("by-security", "github")
	second.DelegatingPrincipal = "vault:entity:e-security"

	_, err := composeMappings([]mappingEntry{first, second}, lifecycleInput())
	if !errors.Is(err, errEnvelopeConflict) {
		t.Errorf("two delegating principals: got err %v, want errEnvelopeConflict", err)
	}
}

// Two mappings written by the SAME principal still union — the conflict rule must
// not break the multi-owner grant composition it sits beside.
func TestComposeMappingsUnionsUnderOnePrincipal(t *testing.T) {
	t.Parallel()

	got, err := composeMappings(
		[]mappingEntry{lifecycleEntry("a", "jira-prod"), lifecycleEntry("b", "github")},
		lifecycleInput(),
	)
	if err != nil {
		t.Fatalf("composeMappings: %v", err)
	}
	if len(got.grant.Families) != 2 {
		t.Errorf("got %d families, want 2 (the union under one principal)", len(got.grant.Families))
	}
	if got.originatingPrincipal != testPrincipal {
		t.Errorf("originatingPrincipal = %q, want %q", got.originatingPrincipal, testPrincipal)
	}
	if len(got.records) != 2 {
		t.Errorf("got %d contributing records, want 2 (one per contributor)", len(got.records))
	}
	// Records are sorted by name so the signed bytes do not depend on storage order.
	if got.records[0].Name != "a" || got.records[1].Name != "b" {
		t.Errorf("records not sorted by name: %+v", got.records)
	}
}

// A mapping with no delegating principal confers nothing signable: the envelope
// would carry an empty originating_principal, so issuance fails closed.
func TestComposeMappingsMissingPrincipalFailsClosed(t *testing.T) {
	t.Parallel()

	entry := lifecycleEntry("no-principal", "jira-prod")
	entry.DelegatingPrincipal = ""

	if _, err := composeMappings([]mappingEntry{entry}, lifecycleInput()); !errors.Is(err, errEmptyEnvelope) {
		t.Errorf("missing delegating principal: got err %v, want errEmptyEnvelope", err)
	}
}

// A suspended record confers nothing: L2-14 turns on the word "active", so any
// other lifecycle state must leave the identity with no authority.
func TestSuspendedMappingConfersNothing(t *testing.T) {
	t.Parallel()

	for _, state := range []string{lifecycleSuspended, lifecycleRevoked, ""} {
		entry := lifecycleEntry("jira", "jira-prod")
		entry.LifecycleState = state
		if entry.confersAuthority(time.Now().UTC()) {
			t.Errorf("lifecycle_state %q conferred authority; only %q may", state, lifecycleActive)
		}
	}
}

// A record past its valid_until confers nothing, and an unparseable valid_until is
// indeterminate — both fail closed.
func TestExpiredMappingConfersNothing(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC()
	expired := lifecycleEntry("jira", "jira-prod")
	expired.ValidUntil = now.Add(-time.Minute).Format(time.RFC3339)
	if expired.confersAuthority(now) {
		t.Error("a record past valid_until conferred authority")
	}

	garbled := lifecycleEntry("jira", "jira-prod")
	garbled.ValidUntil = "not-a-timestamp"
	if garbled.confersAuthority(now) {
		t.Error("an unparseable valid_until conferred authority; indeterminate must fail closed")
	}

	live := lifecycleEntry("jira", "jira-prod")
	live.ValidUntil = now.Add(time.Hour).Format(time.RFC3339)
	if !live.confersAuthority(now) {
		t.Error("an active record inside valid_until must confer authority")
	}
}

// End-to-end through resolveBundle: a suspended record yields no bundle, and the
// refusal is authorization-absence (a clean 4xx), not an internal failure.
func TestResolveBundleRejectsSuspendedRecord(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	entry := lifecycleEntry("jira", "jira-prod")
	entry.LifecycleState = lifecycleSuspended

	_, err := b.resolveBundle(context.Background(), s, []mappingEntry{entry}, lifecycleInput())
	if !errors.Is(err, errNoAuthorizedBundle) {
		t.Errorf("suspended record: got err %v, want errNoAuthorizedBundle", err)
	}
}

// A record whose version sits below the stored high-water mark is a rollback:
// §6.1's resolution rule requires it be detected, and it fails closed as an
// internal/storage-integrity failure rather than a silent authorization absence.
func TestResolveBundleRejectsSupersededRecord(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	entry := lifecycleEntry("jira", "jira-prod")
	entry.RecordVersion = 2
	if err := b.recordVersionSeen(context.Background(), s, entry.Name, 5); err != nil {
		t.Fatalf("seed high-water mark: %v", err)
	}

	_, err := b.resolveBundle(context.Background(), s, []mappingEntry{entry}, lifecycleInput())
	if !errors.Is(err, errRecordSuperseded) {
		t.Errorf("rolled-back record: got err %v, want errRecordSuperseded", err)
	}
}

// The happy path stamps the delegation's parties onto the issued bundle.
func TestResolveBundleStampsDelegationParties(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	bundle, err := b.resolveBundle(
		context.Background(), s, []mappingEntry{lifecycleEntry("jira", "jira-prod")}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}
	if bundle.Actor != testSubject {
		t.Errorf("actor = %q, want the validated JWT subject %q", bundle.Actor, testSubject)
	}
	if bundle.OriginatingPrincipal != testPrincipal {
		t.Errorf("originating_principal = %q, want %q", bundle.OriginatingPrincipal, testPrincipal)
	}
}

// The issued bundle references the mapping record that conferred it, and the
// versioned rules under which the grant was narrowed.
func TestResolveBundleStampsProvenanceRefs(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	bundle, err := b.resolveBundle(
		context.Background(), s, []mappingEntry{lifecycleEntry("jira", "jira-prod")}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}
	if len(bundle.ContributingRecords) != 1 {
		t.Fatalf("contributing_records = %+v, want one record", bundle.ContributingRecords)
	}
	ref := bundle.ContributingRecords[0]
	if ref.Name != "jira" || ref.Version != 1 || !strings.HasPrefix(ref.Digest, "sha256:") {
		t.Errorf("contributing record = %+v, want {jira 1 sha256:...}", ref)
	}
	profile := bundle.AttenuationProfileRef
	if profile == nil || profile.URI != policydsl.AttenuationProfileURI ||
		profile.Digest != policydsl.AttenuationProfileDigest() {
		t.Errorf("attenuation_profile_ref = %+v, want the policydsl profile", profile)
	}
}

// The issued grant carries a bounded validity window, so it is not immortal.
func TestResolveBundleStampsGrantWindow(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	bundle, err := b.resolveBundle(
		context.Background(), s, []mappingEntry{lifecycleEntry("jira", "jira-prod")}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}

	issued, err := time.Parse(time.RFC3339, bundle.IssuedAt)
	if err != nil {
		t.Fatalf("issued_at %q is not RFC 3339: %v", bundle.IssuedAt, err)
	}
	expires, err := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if err != nil {
		t.Fatalf("expires_at %q is not RFC 3339: %v", bundle.ExpiresAt, err)
	}
	if !expires.After(issued) {
		t.Errorf("expires_at %s must be after issued_at %s", bundle.ExpiresAt, bundle.IssuedAt)
	}
	if expires.Sub(issued) > defaultGrantTTL {
		t.Errorf("grant window %s exceeds the default TTL %s", expires.Sub(issued), defaultGrantTTL)
	}
}

// The record digest covers the mapping's content, so a changed selector changes the
// reference the issued bundle carries.
func TestAuthorizationRecordDigestCoversContent(t *testing.T) {
	t.Parallel()

	entry := lifecycleEntry("jira", "jira-prod")
	before, err := mappingRecordRef(entry)
	if err != nil {
		t.Fatalf("mappingRecordRef: %v", err)
	}
	entry.BoundSubject = "spiffe://example.org/agent/other"
	after, err := mappingRecordRef(entry)
	if err != nil {
		t.Fatalf("mappingRecordRef: %v", err)
	}
	if before.Digest == after.Digest {
		t.Error("record digest unchanged after a selector edit; it must cover the content")
	}
}

// expires_at must never outlive the record that authorized it: a valid_until inside
// the TTL window shortens the grant (§6.3 — a delegation cannot outlive its parent).
func TestGrantExpiryCappedByValidUntil(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	entry := lifecycleEntry("jira", "jira-prod")
	entry.ValidUntil = time.Now().UTC().Add(2 * time.Minute).Format(time.RFC3339)

	bundle, err := b.resolveBundle(context.Background(), s, []mappingEntry{entry}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}
	expires, err := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if err != nil {
		t.Fatalf("parse expires_at: %v", err)
	}
	until, err := time.Parse(time.RFC3339, entry.ValidUntil)
	if err != nil {
		t.Fatalf("parse valid_until: %v", err)
	}
	if expires.After(until) {
		t.Errorf("expires_at %s outlives the record's valid_until %s", bundle.ExpiresAt, entry.ValidUntil)
	}
}

// The narrowest contributing TTL wins, so unioning grants never lengthens the window.
func TestGrantExpiryTakesShortestContributorTTL(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	long := lifecycleEntry("long", "jira-prod")
	short := lifecycleEntry("short", "github")
	short.GrantTTLSeconds = 60

	bundle, err := b.resolveBundle(context.Background(), s, []mappingEntry{long, short}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}
	issued, _ := time.Parse(time.RFC3339, bundle.IssuedAt)
	expires, _ := time.Parse(time.RFC3339, bundle.ExpiresAt)
	if window := expires.Sub(issued); window > time.Minute {
		t.Errorf("grant window %s, want the shortest contributor TTL (1m)", window)
	}
}

// A token with no subject has no actor to record, and §6.3 makes actor a MUST — so
// no delegation record can be minted for it. Authorization-absence, not a 5xx.
func TestResolveBundleRequiresActor(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	in := lifecycleInput()
	in.Subject = ""
	entry := lifecycleEntry("by-claim", "jira-prod")
	entry.BoundSubject = ""
	entry.BoundClaims = map[string]string{"group": "jira-writers"}
	in.Claims = map[string]string{"group": "jira-writers"}

	_, err := b.resolveBundle(context.Background(), s, []mappingEntry{entry}, in)
	if !errors.Is(err, errNoAuthorizedBundle) {
		t.Errorf("subject-less token: got err %v, want errNoAuthorizedBundle", err)
	}
}

// The issued grant asserts a root delegation: an explicitly empty chain, not an
// absent field. Absence says nothing; [] says single-hop.
func TestResolveBundleAssertsRootDelegation(t *testing.T) {
	t.Parallel()
	b, s := lifecycleBackend(t)

	bundle, err := b.resolveBundle(
		context.Background(), s, []mappingEntry{lifecycleEntry("jira", "jira-prod")}, lifecycleInput())
	if err != nil {
		t.Fatalf("resolveBundle: %v", err)
	}
	if bundle.DelegationChain == nil {
		t.Fatal("delegation_chain is absent; an issued grant must assert its chain")
	}
	if len(*bundle.DelegationChain) != 0 {
		t.Errorf("delegation_chain = %v, want empty (this issuer mints root records only)",
			*bundle.DelegationChain)
	}
}

// Two entity-less operators must not compose into one grant. The display name alone
// cannot tell them apart — every such token reports "token" — so the principal carries
// the token accessor, which makes envelopeConflicts see two delegators and refuse.
func TestComposeRefusesTwoEntitylessOperators(t *testing.T) {
	t.Parallel()

	one := lifecycleEntry("jira", "jira-prod")
	one.DelegatingPrincipal = "vault:token:token:accessor-alice"
	two := lifecycleEntry("conf", "confluence-prod")
	two.DelegatingPrincipal = "vault:token:token:accessor-bob"

	in := lifecycleInput()
	if _, err := composeMappings([]mappingEntry{one, two}, in); !errors.Is(err, errEnvelopeConflict) {
		t.Errorf("two operators = %v, want errEnvelopeConflict", err)
	}

	// One operator's records compose, which is what the union is for.
	two.DelegatingPrincipal = one.DelegatingPrincipal
	if _, err := composeMappings([]mappingEntry{one, two}, in); err != nil {
		t.Errorf("one operator's records must compose: %v", err)
	}
}
