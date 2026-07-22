package policydsl

// Intersect returns the most-permissive policy allowed by BOTH grant and ceiling —
// the effective policy when a grant is capped by a ceiling. For each verb present
// in both, the result requires both rules' Where conditions (AND) and permits only
// the fields both allow. A verb only the grant requests, or only the ceiling permits,
// is dropped: the ceiling must explicitly permit a verb and the grant must request it.
// An empty AllowFields means "no field restriction", so it never narrows the other
// side; but two non-empty allow-lists sharing no field deny the verb (it is dropped,
// never emitted with empty fields — that would read as unrestricted and WIDEN).
// Assumes at most one rule per verb per input (ValidateSpec enforces this at write);
// output is deterministic (grant rule order preserved).
func Intersect(grant, ceiling PolicySpec) PolicySpec {
	permitted := make(map[string]Rule, len(ceiling.Rules))
	for _, r := range ceiling.Rules {
		permitted[r.Verb] = r
	}

	out := PolicySpec{Rules: make([]Rule, 0, len(grant.Rules))}
	for _, g := range grant.Rules {
		ceilRule, ok := permitted[g.Verb]
		if !ok {
			continue
		}
		fields, denied := intersectFields(g.AllowFields, ceilRule.AllowFields)
		if denied {
			// Both sides cap fields but share none — the verb is impossible to
			// satisfy. Dropping it denies (an empty AllowFields reads as
			// "unrestricted" downstream, so emitting it here would WIDEN).
			continue
		}
		conditions := make([]Condition, 0, len(g.Where)+len(ceilRule.Where))
		conditions = append(conditions, g.Where...)
		conditions = append(conditions, ceilRule.Where...)
		out.Rules = append(out.Rules, Rule{
			Verb:        g.Verb,
			Where:       conditions,
			AllowFields: fields,
		})
	}
	return out
}

// intersectFields returns the fields permitted by both allow-lists and a bool that
// is true when the verb is DENIED. An empty list means "unrestricted", so it yields
// a copy of the other list (never aliasing the input backing array) with denied
// false. When both sides cap fields but share none, the intersection is empty and
// denied is true — the caller must drop the verb, because an empty AllowFields would
// otherwise read as unrestricted.
func intersectFields(grant, ceiling []string) ([]string, bool) {
	if len(grant) == 0 {
		return append([]string(nil), ceiling...), false
	}
	if len(ceiling) == 0 {
		return append([]string(nil), grant...), false
	}
	allowed := make(map[string]struct{}, len(ceiling))
	for _, f := range ceiling {
		allowed[f] = struct{}{}
	}
	out := make([]string, 0, len(grant))
	for _, f := range grant {
		if _, ok := allowed[f]; ok {
			out = append(out, f)
		}
	}
	return out, len(out) == 0
}
