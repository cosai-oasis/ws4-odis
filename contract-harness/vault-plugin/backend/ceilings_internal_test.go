package backend

import (
	"context"
	"errors"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
)

const testTier = "gold"

func ceilingRequest(
	t *testing.T, b *backend, s logical.Storage, op logical.Operation, path string, data map[string]any,
) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: op,
		Path:      path,
		Storage:   s,
		Data:      data,
	})
}

// A written ceiling's maximum-permission spec round-trips in full.
func TestCeilingRoundTrip(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})

	famJSON := `{"jira-prod": {"rules": [{"verb": "update_issue", "allow_fields": ["labels"]}]}}`
	resp, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+testTier, map[string]any{fieldCeilingFamilies: famJSON})
	if err != nil {
		t.Fatalf("write ceiling: %v", err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("write ceiling errored: %v", resp)
	}

	entry, err := b.readCeiling(context.Background(), s, testTier)
	if err != nil {
		t.Fatalf("readCeiling: %v", err)
	}
	rules := entry.Families["jira-prod"].Rules
	if len(rules) != 1 {
		t.Fatalf("got %d rules, want 1", len(rules))
	}
	if rules[0].Verb != "update_issue" || len(rules[0].AllowFields) != 1 {
		t.Errorf("rule did not round-trip: %+v", rules[0])
	}
}

// The read HANDLER returns the complete per-family spec (auditable), not just
// the family names.
func TestCeilingReadHandlerReturnsFullSpec(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})

	famJSON := `{"jira-prod": {"rules": [{"verb": "update_issue", "allow_fields": ["labels"]}]}}`
	if _, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+testTier, map[string]any{fieldCeilingFamilies: famJSON}); err != nil {
		t.Fatalf("write ceiling: %v", err)
	}

	rresp, err := ceilingRequest(t, b, s, logical.ReadOperation,
		storageKeyCeilingPrefix+testTier, map[string]any{})
	if err != nil {
		t.Fatalf("read ceiling handler: %v", err)
	}
	families, ok := rresp.Data[fieldCeilingFamilies].(map[string]policydsl.PolicySpec)
	if !ok {
		t.Fatalf("read families = %T, want map[string]policydsl.PolicySpec", rresp.Data[fieldCeilingFamilies])
	}
	echoed := families["jira-prod"].Rules
	if len(echoed) != 1 || echoed[0].Verb != "update_issue" || len(echoed[0].AllowFields) != 1 {
		t.Errorf("handler read did not preserve the spec: %+v", echoed)
	}
}

// A ceiling is listed after write and gone after delete.
func TestCeilingListAndDelete(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})
	ctx := context.Background()

	if _, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+testTier, map[string]any{fieldCeilingFamilies: `{"jira-prod": {"rules": []}}`}); err != nil {
		t.Fatalf("write: %v", err)
	}

	list, err := ceilingRequest(t, b, s, logical.ListOperation, storageKeyCeilingPrefix, nil)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if keys, _ := list.Data["keys"].([]string); len(keys) != 1 || keys[0] != testTier {
		t.Errorf("list keys = %v, want [%s]", list.Data["keys"], testTier)
	}

	if _, err := ceilingRequest(t, b, s, logical.DeleteOperation, storageKeyCeilingPrefix+testTier, nil); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := b.readCeiling(ctx, s, testTier); !errors.Is(err, errCeilingNotFound) {
		t.Errorf("after delete, readCeiling err = %v, want errCeilingNotFound", err)
	}
}

// A ceiling write fails closed on malformed or empty input.
func TestCeilingWriteRejectsBadInput(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})

	bad, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+"x", map[string]any{fieldCeilingFamilies: "{not json"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bad == nil || !bad.IsError() {
		t.Error("expected an error for invalid families JSON")
	}

	empty, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+"y", map[string]any{fieldCeilingFamilies: "{}"})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if empty == nil || !empty.IsError() {
		t.Error("expected an error for an empty ceiling")
	}
}

// A ceiling family with two rules for the same verb fails closed at write: Intersect
// indexes ceiling rules by verb (last-wins), silently dropping the earlier rule, so
// the ceiling would not cap as authored. ValidateSpec rejects it.
func TestCeilingWriteRejectsDuplicateVerb(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})

	dupVerb := `{"jira-prod": {"rules": [` +
		`{"verb": "update_issue", "allow_fields": ["labels"]},` +
		`{"verb": "update_issue", "allow_fields": ["summary"]}]}}`
	resp, err := ceilingRequest(t, b, s, logical.UpdateOperation,
		storageKeyCeilingPrefix+"dup", map[string]any{fieldCeilingFamilies: dupVerb})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Error("expected an error for a ceiling family with duplicate verbs")
	}
}

// applyCeiling drops families the ceiling omits (family-level cap) and, for a
// family the ceiling permits, intersects the grant policy with the ceiling spec
// (field-level cap) so a tier can only ever shrink authority.
func TestApplyCeilingDropsDisallowedFamilies(t *testing.T) {
	t.Parallel()

	g := grant{
		TrustRootID: "tr",
		Families: map[string]grantFamily{
			"jira-prod": {DefaultMode: modePermissive, Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
				{Verb: "update_issue", AllowFields: []string{"labels", "summary"}},
			}}},
			"github": {},
		},
	}
	// The ceiling permits jira-prod but caps update_issue to labels only — summary
	// must be intersected away.
	ceiling := ceilingEntry{Name: testTier, Families: map[string]policydsl.PolicySpec{
		"jira-prod": {Rules: []policydsl.Rule{
			{Verb: "update_issue", AllowFields: []string{"labels"}},
		}},
	}}

	got := applyCeiling(g, ceiling)
	capped, ok := got.Families["jira-prod"]
	if !ok {
		t.Fatal("ceiling-permitted family jira-prod was dropped")
	}
	if _, ok := got.Families["github"]; ok {
		t.Error("ceiling did not drop the non-permitted github family")
	}
	// A ceiling-bounded family must never permissively forward unpoliced tools.
	if capped.DefaultMode != modeStrict {
		t.Errorf("kept family default_mode = %q, want strict", capped.DefaultMode)
	}
	if len(capped.Policy.Rules) != 1 {
		t.Fatalf("got %d rules after intersect, want 1", len(capped.Policy.Rules))
	}
	if fields := capped.Policy.Rules[0].AllowFields; len(fields) != 1 || fields[0] != "labels" {
		t.Errorf("field-level cap not applied: allow_fields = %v, want [labels]", fields)
	}
}

// A permissive grant family the ceiling caps to ZERO rules must be DROPPED — not
// kept as a permissive zero-rule family, which the Router would treat as unpoliced
// passthrough (a ceiling that widens, the opposite of its purpose).
func TestApplyCeilingDropsFamilyCappedToZeroRules(t *testing.T) {
	t.Parallel()

	g := grant{
		TrustRootID: "tr",
		Families: map[string]grantFamily{
			"jira-prod": {DefaultMode: modePermissive, Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
				{Verb: "update_issue", AllowFields: []string{"labels"}},
			}}},
		},
	}
	// The ceiling permits jira-prod but caps update_issue to a disjoint field set,
	// so Intersect denies the only verb -> zero rules remain.
	ceiling := ceilingEntry{Name: testTier, Families: map[string]policydsl.PolicySpec{
		"jira-prod": {Rules: []policydsl.Rule{
			{Verb: "update_issue", AllowFields: []string{"summary"}},
		}},
	}}

	got := applyCeiling(g, ceiling)
	if _, ok := got.Families["jira-prod"]; ok {
		t.Error("a family capped to zero rules must be dropped, not kept as a permissive passthrough")
	}
}

// resolveCeiling selects a ceiling by the identity's tier claim; no tier means no
// ceiling, and a tier naming a missing ceiling fails closed.
func TestResolveCeilingByTier(t *testing.T) {
	t.Parallel()
	b, s := newIssueTestBackend(t, fakeSigner{})
	ctx := context.Background()

	if _, err := ceilingRequest(t, b, s, logical.UpdateOperation, storageKeyCeilingPrefix+testTier,
		map[string]any{fieldCeilingFamilies: `{"jira-prod": {"rules": []}}`}); err != nil {
		t.Fatalf("write ceiling: %v", err)
	}

	c, found, err := b.resolveCeiling(ctx, s, matchInput{Claims: map[string]string{claimTier: testTier}})
	if err != nil || !found || c.Name != testTier {
		t.Errorf("resolve by tier: c=%+v found=%v err=%v", c, found, err)
	}

	if _, found, err := b.resolveCeiling(ctx, s, matchInput{}); err != nil || found {
		t.Errorf("no tier claim: found=%v err=%v, want found=false err=nil", found, err)
	}

	// An identity carrying a foreign "tier" claim must resolve to no ceiling; only
	// the namespaced "apf_tier" claim selects a ceiling.
	foreign := matchInput{Claims: map[string]string{"tier": testTier}}
	if _, found, err := b.resolveCeiling(ctx, s, foreign); err != nil || found {
		t.Errorf("foreign \"tier\" claim: found=%v err=%v, want found=false err=nil (uncapped)", found, err)
	}

	if _, _, err := b.resolveCeiling(ctx, s, matchInput{Claims: map[string]string{claimTier: "platinum"}}); err == nil {
		t.Error("tier naming a missing ceiling: expected an error (fail closed)")
	}
}
