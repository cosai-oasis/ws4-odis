package policydsl

import "testing"

// Intersect drops a verb the ceiling doesn't permit and caps the fields of one it does.
func TestIntersectCapsFieldsAndVerbs(t *testing.T) {
	t.Parallel()

	grant := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, AllowFields: []string{fieldLabels, "summary"}},
		{Verb: "delete_issue"},
	}}
	ceiling := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, AllowFields: []string{fieldLabels}},
	}}

	got := Intersect(grant, ceiling)
	if len(got.Rules) != 1 {
		t.Fatalf("got %d rules, want 1 (delete_issue not permitted by the ceiling)", len(got.Rules))
	}
	r := got.Rules[0]
	if r.Verb != verbUpdate {
		t.Errorf("verb = %q, want %q", r.Verb, verbUpdate)
	}
	if len(r.AllowFields) != 1 || r.AllowFields[0] != fieldLabels {
		t.Errorf("allow_fields = %v, want [%s] (capped)", r.AllowFields, fieldLabels)
	}
}

// Intersect ANDs the grant's and ceiling's conditions — both must hold.
func TestIntersectAndsConditions(t *testing.T) {
	t.Parallel()

	grant := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, Where: []Condition{{Field: fieldKey, Op: OpStartsWith, Value: "APF-"}}},
	}}
	ceiling := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, Where: []Condition{{Field: "project", Op: OpEq, Value: "APF"}}},
	}}

	got := Intersect(grant, ceiling)
	if len(got.Rules) != 1 || len(got.Rules[0].Where) != 2 {
		t.Fatalf("expected 1 rule with 2 ANDed conditions, got %+v", got.Rules)
	}
}

// An empty ceiling AllowFields means "no field cap", so the grant's restriction stands.
func TestIntersectEmptyCeilingFieldsKeepsGrant(t *testing.T) {
	t.Parallel()

	grant := PolicySpec{Rules: []Rule{{Verb: verbUpdate, AllowFields: []string{fieldLabels}}}}
	ceiling := PolicySpec{Rules: []Rule{{Verb: verbUpdate}}}

	got := Intersect(grant, ceiling)
	if len(got.Rules) != 1 || len(got.Rules[0].AllowFields) != 1 || got.Rules[0].AllowFields[0] != fieldLabels {
		t.Errorf("want the grant's fields [%s] preserved, got %+v", fieldLabels, got.Rules)
	}
}

// Two non-empty allow-lists with no field in common make the verb impossible to
// satisfy — an empty obligation list reads as "unrestricted" downstream, so the
// verb must be DROPPED (denied), never emitted with empty fields (which would
// WIDEN the grant). Deny-wins, not widen.
func TestIntersectDisjointFieldsDropsVerb(t *testing.T) {
	t.Parallel()

	grant := PolicySpec{Rules: []Rule{{Verb: verbUpdate, AllowFields: []string{fieldLabels}}}}
	ceiling := PolicySpec{Rules: []Rule{{Verb: verbUpdate, AllowFields: []string{"summary"}}}}

	got := Intersect(grant, ceiling)
	if len(got.Rules) != 0 {
		t.Errorf("disjoint allow-lists must drop the verb, got %+v", got.Rules)
	}
}
