// Package policydsl defines the structured capability policy authored in
// mappings (and ceilings) and lowers it to Rego — APF Policy Projection. The
// structured spec is the only policy language; raw Rego is never accepted as
// input. The generated Rego is the build artifact the Router runs via OPA.
package policydsl

// PolicySpec is a projectable policy: an ordered set of allow rules over a
// default-deny base. Order is preserved so compilation is deterministic.
type PolicySpec struct {
	Rules []Rule `json:"rules"`
}

// Rule allows a verb (tool) when every Where condition holds, emitting
// AllowFields as the request's field obligation.
type Rule struct {
	Verb        string      `json:"verb"`
	Where       []Condition `json:"where,omitempty"`
	AllowFields []string    `json:"allow_fields,omitempty"`
}

// Condition is one guard on a request_body field.
type Condition struct {
	Field string `json:"field"`
	Op    string `json:"op"` // OpEq | OpStartsWith
	Value string `json:"value"`
}

// Supported condition operators. The DSL is the only policy language, so the
// op set is closed — an unrecognized op fails closed at compile time.
const (
	OpEq         = "eq"
	OpStartsWith = "startsWith"
)
