package policydsl

import (
	"strings"
	"testing"
)

const (
	verbUpdate  = "update_issue"
	fieldKey    = "issue_key"
	fieldLabels = "labels"
)

// The canonical Jira wedge spec compiles to the expected Rego (golden). This is
// the same policy the harness hand-writes today, now generated (APF Policy Projection).
func TestCompileJiraWedge(t *testing.T) {
	t.Parallel()

	spec := PolicySpec{Rules: []Rule{{
		Verb:        verbUpdate,
		Where:       []Condition{{Field: fieldKey, Op: OpStartsWith, Value: "APF-"}},
		AllowFields: []string{"labels"},
	}}}

	const want = "package odis_policy\n" +
		"\n" +
		"default decision := {\"decision\": \"deny\", \"obligations\": {}}\n" +
		"\n" +
		"decision := {\"decision\": \"allow\", \"obligations\": {\"allowed_fields\": [\"labels\"]}} if {\n" +
		"\tinput.verb == \"update_issue\"\n" +
		"\tstartswith(input.request_body[\"issue_key\"], \"APF-\")\n" +
		"}\n"

	got, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if got != want {
		t.Errorf("Compile mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

// Compilation is deterministic — same spec, byte-identical output (the parity
// contract that lets a second consumer trust the bytes, cf. CanonicalBytes).
func TestCompileDeterministic(t *testing.T) {
	t.Parallel()

	spec := PolicySpec{Rules: []Rule{{
		Verb:        verbUpdate,
		Where:       []Condition{{Field: fieldKey, Op: OpStartsWith, Value: "APF-"}},
		AllowFields: []string{"labels", "summary"},
	}}}

	first, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	second, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if first != second {
		t.Errorf("non-deterministic compile:\n%s\n!=\n%s", first, second)
	}
}

// An unknown condition op fails closed — the compiler emits no malformed Rego.
func TestCompileUnknownOpFailsClosed(t *testing.T) {
	t.Parallel()

	spec := PolicySpec{Rules: []Rule{{
		Verb:  verbUpdate,
		Where: []Condition{{Field: fieldKey, Op: "regex", Value: ".*"}},
	}}}

	if _, err := Compile(spec); err == nil {
		t.Error("expected an error for an unknown op, got nil")
	}
}

// Two rules for the same verb would compile to conflicting Rego complete-rules
// (OPA eval_conflict_error at runtime — signed but broken). Compile must fail
// closed via ValidateSpec rather than emit such a bundle.
func TestCompileDuplicateVerbFailsClosed(t *testing.T) {
	t.Parallel()

	spec := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, AllowFields: []string{fieldLabels}},
		{Verb: verbUpdate, AllowFields: []string{"summary"}},
	}}

	if _, err := Compile(spec); err == nil {
		t.Error("expected an error compiling a spec with duplicate verbs, got nil")
	}
}

// ValidateSpec rejects a duplicate verb and an unknown op, and accepts a
// single-rule spec.
func TestValidateSpec(t *testing.T) {
	t.Parallel()

	dup := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate},
		{Verb: verbUpdate},
	}}
	if err := ValidateSpec(dup); err == nil {
		t.Error("expected ValidateSpec to reject duplicate verbs")
	}

	badOp := PolicySpec{Rules: []Rule{
		{Verb: verbUpdate, Where: []Condition{{Field: fieldKey, Op: "regex", Value: ".*"}}},
	}}
	if err := ValidateSpec(badOp); err == nil {
		t.Error("expected ValidateSpec to reject an unknown op")
	}

	ok := PolicySpec{Rules: []Rule{{Verb: verbUpdate, AllowFields: []string{fieldLabels}}}}
	if err := ValidateSpec(ok); err != nil {
		t.Errorf("ValidateSpec rejected a valid single-rule spec: %v", err)
	}
}

// A control byte in a value must be escaped JSON/Rego-legally (\u00HH), never with
// strconv.Quote's \a / \xHH forms which Rego's parser rejects (unloadable bundle).
func TestCompileEscapesControlBytesJSONLegal(t *testing.T) {
	t.Parallel()

	spec := PolicySpec{Rules: []Rule{{
		Verb:  verbUpdate,
		Where: []Condition{{Field: fieldKey, Op: OpEq, Value: "\x07"}}, // BEL: strconv.Quote -> \a
	}}}

	got, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	if strings.Contains(got, `\a`) {
		t.Errorf("output contains Rego-illegal \\a escape:\n%s", got)
	}
	if strings.Contains(got, `\x`) {
		t.Errorf("output contains Rego-illegal \\x escape:\n%s", got)
	}
	if !strings.Contains(got, `\u0007`) {
		t.Errorf("expected a JSON-legal \\u0007 escape, got:\n%s", got)
	}
}
