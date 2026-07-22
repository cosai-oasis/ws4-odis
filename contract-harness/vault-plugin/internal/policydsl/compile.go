package policydsl

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const regoPackage = "odis_policy"

// linesPerRule is the count of fixed lines every rule emits — the allow-decision
// head, the verb guard, and the closing brace; the rest are its Where conditions.
const linesPerRule = 3

var (
	// errUnknownOp is returned for a condition op outside the supported set. The
	// compiler fails closed rather than emit malformed or accidentally-permissive Rego.
	errUnknownOp = errors.New("policydsl: unknown condition op")
	// errDuplicateVerb is returned when two rules name the same verb — they would
	// compile to conflicting Rego complete-rules (OPA eval_conflict_error at runtime).
	errDuplicateVerb = errors.New("policydsl: duplicate verb")
)

// ValidateSpec rejects a spec that would compile to broken or accidentally-
// permissive Rego: a verb repeated across rules (conflicting complete-rules ->
// eval_conflict_error) or a condition op outside the supported set. It is the
// write-time gate and the first step of Compile, so a stored or signed spec is
// always loadable.
func ValidateSpec(spec PolicySpec) error {
	seen := make(map[string]struct{}, len(spec.Rules))
	for i := range spec.Rules {
		r := spec.Rules[i]
		if _, dup := seen[r.Verb]; dup {
			return fmt.Errorf("%w: %q", errDuplicateVerb, r.Verb)
		}
		seen[r.Verb] = struct{}{}
		for _, c := range r.Where {
			if c.Op != OpEq && c.Op != OpStartsWith {
				return fmt.Errorf("%w: %q", errUnknownOp, c.Op)
			}
		}
	}
	return nil
}

// Compile lowers a PolicySpec to Rego source. The output is deterministic —
// rules, conditions, and fields are emitted in declared order — so the bytes are
// stable (the parity contract that lets a second consumer trust them, cf.
// CanonicalBytes). Raw Rego is never an input; this is the only path by which
// policy becomes Rego.
func Compile(spec PolicySpec) (string, error) {
	if err := ValidateSpec(spec); err != nil {
		return "", err
	}
	parts := make([]string, 0, len(spec.Rules)+1)
	parts = append(parts, "package "+regoPackage+"\n\n"+
		`default decision := {"decision": "deny", "obligations": {}}`+"\n")
	for i := range spec.Rules {
		rule, err := renderRule(spec.Rules[i])
		if err != nil {
			return "", err
		}
		parts = append(parts, rule)
	}
	return strings.Join(parts, ""), nil
}

func renderRule(r Rule) (string, error) {
	lines := make([]string, 0, len(r.Where)+linesPerRule)
	lines = append(lines,
		"\ndecision := {\"decision\": \"allow\", \"obligations\": "+renderObligations(r.AllowFields)+"} if {\n",
		"\tinput.verb == "+regoString(r.Verb)+"\n",
	)
	for _, c := range r.Where {
		line, err := renderCondition(c)
		if err != nil {
			return "", err
		}
		lines = append(lines, "\t"+line+"\n")
	}
	lines = append(lines, "}\n")
	return strings.Join(lines, ""), nil
}

func renderObligations(allowFields []string) string {
	if len(allowFields) == 0 {
		return "{}"
	}
	quoted := make([]string, len(allowFields))
	for i, f := range allowFields {
		quoted[i] = regoString(f)
	}
	return `{"allowed_fields": [` + strings.Join(quoted, ", ") + "]}"
}

func renderCondition(c Condition) (string, error) {
	ref := "input.request_body[" + regoString(c.Field) + "]"
	switch c.Op {
	case OpEq:
		return ref + " == " + regoString(c.Value), nil
	case OpStartsWith:
		return "startswith(" + ref + ", " + regoString(c.Value) + ")", nil
	default:
		return "", fmt.Errorf("%w: %q", errUnknownOp, c.Op)
	}
}

// regoString quotes s as a Rego string literal using JSON escaping. Rego shares
// JSON's string grammar, so json.Marshal yields legal escapes (\u00HH for control
// bytes) — unlike strconv.Quote, whose \a / \v / \xHH forms the Rego parser rejects
// (an unloadable bundle). Marshalling a string never errors. For ASCII text the
// result is byte-identical to strconv.Quote, so the golden Rego is unchanged.
func regoString(s string) string {
	b, _ := json.Marshal(s) //nolint:errchkjson // string marshal never errors
	return string(b)
}
