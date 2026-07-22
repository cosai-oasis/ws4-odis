package backend

import (
	"errors"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"testing"
)

// White-box tests for composeMappings — the union-of-assigned-grants authority
// model (RBAC + permission boundary). See specs/vault-bundle-issuer tasks.md task 20.

func composeTestFamily() grantFamily {
	return grantFamily{
		VendorMCP: apfbundle.VendorMCP{EndpointID: "ep", URL: "https://vendor.example/"},
		Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
			{Verb: "update_issue", AllowFields: []string{"labels"}},
		}},
		DefaultMode: "strict",
	}
}

func composeGrant(trustRoot string, families map[string]grantFamily) grant {
	return grant{
		BundleID:      "b",
		BundleVersion: "1",
		TrustRootID:   trustRoot,
		Families:      families,
	}
}

// An identity assigned a subject mapping AND a group-claim mapping receives the
// UNION of both grants — the delegated, multi-owner case single-winner can't serve.
func TestComposeMappingsUnionsAssignedGrants(t *testing.T) {
	t.Parallel()

	subjectGrant := mappingEntry{
		Name:         "by-subject",
		BoundSubject: "spiffe://example.org/agent/jira",
		Grant:        composeGrant("tr", map[string]grantFamily{"github": composeTestFamily()}),
	}
	groupGrant := mappingEntry{
		Name:        "by-group",
		BoundClaims: map[string]string{"group": "jira-writers"},
		Grant:       composeGrant("tr", map[string]grantFamily{"jira-prod": composeTestFamily()}),
	}
	in := matchInput{
		Issuer:    "https://issuer/",
		Audiences: []string{"apf-bundle-issuer"},
		Subject:   "spiffe://example.org/agent/jira",
		Claims:    map[string]string{"group": "jira-writers"},
	}

	got, err := composeMappings([]mappingEntry{subjectGrant, groupGrant}, in)
	if err != nil {
		t.Fatalf("composeMappings: %v", err)
	}
	if _, ok := got.Families["github"]; !ok {
		t.Errorf("union missing the subject-assigned family %q", "github")
	}
	if _, ok := got.Families["jira-prod"]; !ok {
		t.Errorf("union missing the group-assigned family %q", "jira-prod")
	}
	if len(got.Families) != 2 {
		t.Errorf("got %d families, want 2 (the union)", len(got.Families))
	}
}

// A mapping bound ONLY by issuer/audience is an ambient trust gate, never a grant —
// it must not contribute a family, even though it matches() the token.
func TestComposeMappingsIgnoresAmbientOnlyMappings(t *testing.T) {
	t.Parallel()

	ambient := mappingEntry{
		Name:           "ambient",
		BoundIssuer:    "https://issuer/",
		BoundAudiences: []string{"apf-bundle-issuer"},
		Grant:          composeGrant("tr", map[string]grantFamily{"jira-prod": composeTestFamily()}),
	}
	in := matchInput{
		Issuer:    "https://issuer/",
		Audiences: []string{"apf-bundle-issuer"},
		Subject:   "spiffe://example.org/agent/jira",
	}

	got, err := composeMappings([]mappingEntry{ambient}, in)
	if err != nil {
		t.Fatalf("composeMappings: %v", err)
	}
	if len(got.Families) != 0 {
		t.Errorf("issuer/audience-only mapping conferred %d families; want 0 (ambient is never a grant)", len(got.Families))
	}
}

// Two assigned mappings that define the SAME family collide; intersect-to-most-
// restrictive needs the policy DSL, so until then it fails closed (no bundle).
func TestComposeMappingsSameFamilyCollisionFailsClosed(t *testing.T) {
	t.Parallel()

	teamA := mappingEntry{
		Name:        "team-a",
		BoundClaims: map[string]string{"group": "a"},
		Grant:       composeGrant("tr", map[string]grantFamily{"jira-prod": composeTestFamily()}),
	}
	agentB := mappingEntry{
		Name:         "agent-b",
		BoundSubject: "spiffe://example.org/agent/jira",
		Grant:        composeGrant("tr", map[string]grantFamily{"jira-prod": composeTestFamily()}),
	}
	in := matchInput{
		Subject: "spiffe://example.org/agent/jira",
		Claims:  map[string]string{"group": "a"},
	}

	if _, err := composeMappings([]mappingEntry{teamA, agentB}, in); !errors.Is(err, errSameFamilyCollision) {
		t.Errorf("same-family collision: got err %v, want errSameFamilyCollision", err)
	}
}

// Assigned mappings that agree on trust_root_id but disagree on bundle_id fail
// closed — the whole envelope (not just the trust root) must be consistent, or the
// signed bundle silently first-wins one identity.
func TestComposeMappingsEnvelopeConflictFailsClosed(t *testing.T) {
	t.Parallel()

	bySubject := mappingEntry{
		Name:         "by-subject",
		BoundSubject: "spiffe://example.org/agent/jira",
		Grant: grant{
			BundleID: "bundle-a", BundleVersion: "1", TrustRootID: "tr",
			Families: map[string]grantFamily{"jira-prod": composeTestFamily()},
		},
	}
	byGroup := mappingEntry{
		Name:        "by-group",
		BoundClaims: map[string]string{"group": "g"},
		Grant: grant{
			BundleID: "bundle-b", BundleVersion: "1", TrustRootID: "tr",
			Families: map[string]grantFamily{"github": composeTestFamily()},
		},
	}
	in := matchInput{
		Subject: "spiffe://example.org/agent/jira",
		Claims:  map[string]string{"group": "g"},
	}

	if _, err := composeMappings([]mappingEntry{bySubject, byGroup}, in); !errors.Is(err, errEnvelopeConflict) {
		t.Errorf("bundle_id conflict: got err %v, want errEnvelopeConflict", err)
	}
}

// An assigned mapping with an empty envelope field (here trust_root_id) fails
// closed — an empty envelope must never be signed (Go-side parity with the
// schema's minLength:1).
func TestComposeMappingsEmptyEnvelopeFailsClosed(t *testing.T) {
	t.Parallel()

	bySubject := mappingEntry{
		Name:         "by-subject",
		BoundSubject: "spiffe://example.org/agent/jira",
		Grant: grant{
			BundleID: "b", BundleVersion: "1", TrustRootID: "", // empty trust root
			Families: map[string]grantFamily{"jira-prod": composeTestFamily()},
		},
	}
	in := matchInput{Subject: "spiffe://example.org/agent/jira"}

	if _, err := composeMappings([]mappingEntry{bySubject}, in); !errors.Is(err, errEmptyEnvelope) {
		t.Errorf("empty trust_root_id: got err %v, want errEmptyEnvelope", err)
	}
}

// Assigned mappings that disagree on trust_root_id fail closed — composing
// families across two trust anchors is a refusal, not a silent pick.
func TestComposeMappingsTrustRootConflictFailsClosed(t *testing.T) {
	t.Parallel()

	bySubject := mappingEntry{
		Name:         "by-subject",
		BoundSubject: "spiffe://example.org/agent/jira",
		Grant:        composeGrant("tr-1", map[string]grantFamily{"jira-prod": composeTestFamily()}),
	}
	byGroup := mappingEntry{
		Name:        "by-group",
		BoundClaims: map[string]string{"group": "g"},
		Grant:       composeGrant("tr-2", map[string]grantFamily{"github": composeTestFamily()}),
	}
	in := matchInput{
		Subject: "spiffe://example.org/agent/jira",
		Claims:  map[string]string{"group": "g"},
	}

	if _, err := composeMappings([]mappingEntry{bySubject, byGroup}, in); !errors.Is(err, errEnvelopeConflict) {
		t.Errorf("trust-root conflict: got err %v, want errEnvelopeConflict", err)
	}
}
