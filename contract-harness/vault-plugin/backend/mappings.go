package backend

import (
	"context"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"strings"

	"github.com/hashicorp/vault/sdk/logical"
)

const storageKeyMappingPrefix = "mappings/"

var (
	errMappingNotFound     = errors.New("mapping not found")
	errSameFamilyCollision = errors.New("multiple assigned mappings define the same family")
	errEnvelopeConflict    = errors.New("assigned mappings disagree on the bundle envelope")
	errEmptyEnvelope       = errors.New("composed grant has an empty bundle envelope")
	// errNoAuthorizedBundle signals genuine authorization-absence — the identity is
	// trusted but no assigned grant (or none surviving the ceiling) confers a bundle.
	// It is the ONLY resolveBundle error that maps to a client 4xx; every other error
	// is an internal/config failure that handleIssue logs and returns as a 5xx.
	errNoAuthorizedBundle = errors.New("no authorized bundle for this identity")
)

// mappingEntry is one operator-set identity->grant mapping. The match
// fields select which workloads receive `Grant`'s structured authority; the
// grant is lowered to a signable bundle (Rego) only at issuance (project).
type mappingEntry struct {
	Name               string            `json:"name"`
	BoundIssuer        string            `json:"bound_issuer"`
	BoundAudiences     []string          `json:"bound_audiences"`
	BoundSubject       string            `json:"bound_subject"`
	BoundSubjectPrefix string            `json:"bound_subject_prefix"`
	BoundClaims        map[string]string `json:"bound_claims"`
	Grant              grant             `json:"grant"`
}

// matchInput is the validated identity the plugin matches against mappings.
type matchInput struct {
	Issuer    string
	Audiences []string
	Subject   string
	Claims    map[string]string
}

func (e *mappingEntry) matches(in matchInput) bool {
	return e.matchesTrust(in) && e.matchesSelectors(in)
}

// matchesTrust checks the ambient trust gates (issuer, audience) — they qualify a
// token but never select a grant.
func (e *mappingEntry) matchesTrust(in matchInput) bool {
	if e.BoundIssuer != "" && e.BoundIssuer != in.Issuer {
		return false
	}
	if len(e.BoundAudiences) > 0 && !anyAudienceMatches(e.BoundAudiences, in.Audiences) {
		return false
	}
	return true
}

// matchesSelectors checks the assigned selectors (exact subject, subject subtree,
// and claims) — the attributes that actually confer a grant.
func (e *mappingEntry) matchesSelectors(in matchInput) bool {
	if e.BoundSubject != "" && e.BoundSubject != in.Subject {
		return false
	}
	if e.BoundSubjectPrefix != "" && !matchesSubtree(in.Subject, e.BoundSubjectPrefix) {
		return false
	}
	for claim, want := range e.BoundClaims {
		// Presence is checked explicitly: a map miss yields "", and an
		// (operator-typo) empty want would otherwise invert the selector into
		// "matches when the claim is ABSENT" — a near-wildcard grant.
		got, present := in.Claims[claim]
		if !present || got != want {
			return false
		}
	}
	return true
}

// matchesSubtree reports whether subject sits inside the prefix's subtree: the
// prefix itself, or a "/"-delimited descendant. A raw HasPrefix would let a
// sibling identity that merely string-extends the prefix (agent/jira vs
// agent/jira-support) silently receive the grant.
func matchesSubtree(subject, prefix string) bool {
	if strings.HasSuffix(prefix, "/") {
		return strings.HasPrefix(subject, prefix)
	}
	return subject == prefix || strings.HasPrefix(subject, prefix+"/")
}

func anyAudienceMatches(bound, presented []string) bool {
	set := make(map[string]struct{}, len(presented))
	for _, a := range presented {
		set[a] = struct{}{}
	}
	for _, b := range bound {
		if _, ok := set[b]; ok {
			return true
		}
	}
	return false
}

// isAssignedGrant reports whether a mapping confers a grant. A grant must pin at
// least one ASSIGNED selector — a subject, a subject subtree (prefix), or a claim.
// A mapping bound only by issuer and/or audience is an ambient trust gate and never
// confers a grant (the ambient-vs-assigned rule).
func (e *mappingEntry) isAssignedGrant() bool {
	return e.BoundSubject != "" || e.BoundSubjectPrefix != "" || len(e.BoundClaims) > 0
}

// hasBinding reports whether the mapping pins at least one bound_* selector. A
// zero-constraint mapping matches every validated workload (a wildcard) and is
// rejected at write time.
func (e *mappingEntry) hasBinding() bool {
	return e.BoundIssuer != "" || len(e.BoundAudiences) > 0 || e.isAssignedGrant()
}

// collidesWithExisting returns the name of an existing mapping that the candidate
// would co-satisfiably collide with on a shared family, or "" if none. A collision
// is rejected at write time so the operator sees it, rather than 5xx-ing at issuance
// (where composeMappings keeps errSameFamilyCollision as defense-in-depth). The entry
// of the candidate's own name is excluded so re-writing a mapping in place never
// self-collides. Only ASSIGNED grants contribute families at issuance, so a collision
// requires both sides to be assigned grants.
func collidesWithExisting(candidate *mappingEntry, existing []mappingEntry) string {
	if !candidate.isAssignedGrant() {
		return ""
	}
	for i := range existing {
		e := &existing[i]
		if e.Name == candidate.Name || !e.isAssignedGrant() {
			continue
		}
		if sharesFamily(candidate.Grant, e.Grant) && selectorsCoSatisfiable(candidate, e) {
			return e.Name
		}
	}
	return ""
}

// sharesFamily reports whether two grants both define at least one common family name.
func sharesFamily(a, b grant) bool {
	for name := range a.Families {
		if _, ok := b.Families[name]; ok {
			return true
		}
	}
	return false
}

// selectorsCoSatisfiable reports whether a single token could match both mappings'
// selectors — the precondition for a real same-family collision at issuance. It is
// true unless some selector pair is provably disjoint:
//   - issuer: disjoint only if both pin a bound_issuer and they differ.
//   - audiences: never disjoint — a token may carry multiple audiences, so disjoint
//     bound-audience sets don't prevent a common token.
//   - subject (+ prefix together, since a token has ONE subject string): disjoint only
//     when no single subject string can satisfy both sides' subject constraints.
//   - claims: disjoint only if both require DIFFERENT values for the same claim key.
func selectorsCoSatisfiable(a, b *mappingEntry) bool {
	if a.BoundIssuer != "" && b.BoundIssuer != "" && a.BoundIssuer != b.BoundIssuer {
		return false
	}
	if !subjectConstraintsCoSatisfiable(a, b) {
		return false
	}
	return claimsCoSatisfiable(a.BoundClaims, b.BoundClaims)
}

// subjectConstraintsCoSatisfiable reports whether one subject string can satisfy both
// mappings' subject constraints (exact bound_subject and/or bound_subject_prefix). A
// side with neither pinned is unconstrained on subject, so it always co-satisfies.
func subjectConstraintsCoSatisfiable(a, b *mappingEntry) bool {
	switch {
	case a.BoundSubject != "" && b.BoundSubject != "":
		// Two exact subjects: co-satisfiable only if identical.
		return a.BoundSubject == b.BoundSubject
	case a.BoundSubject != "":
		// a is exact, b at most a prefix: the exact subject must lie under b's prefix.
		return strings.HasPrefix(a.BoundSubject, b.BoundSubjectPrefix)
	case b.BoundSubject != "":
		return strings.HasPrefix(b.BoundSubject, a.BoundSubjectPrefix)
	case a.BoundSubjectPrefix != "" && b.BoundSubjectPrefix != "":
		// Two prefixes: a subject can satisfy both iff one prefix extends the other.
		return strings.HasPrefix(a.BoundSubjectPrefix, b.BoundSubjectPrefix) ||
			strings.HasPrefix(b.BoundSubjectPrefix, a.BoundSubjectPrefix)
	default:
		// At least one side is unconstrained on subject -> co-satisfiable.
		return true
	}
}

// claimsCoSatisfiable reports whether one set of claim values can satisfy both
// bound-claim maps: disjoint only when both require DIFFERENT values for a shared key.
func claimsCoSatisfiable(a, b map[string]string) bool {
	for key, want := range a {
		if other, ok := b[key]; ok && other != want {
			return false
		}
	}
	return true
}

// composeMappings returns the UNION of every mapping the validated identity is
// explicitly assigned (by subject or bound_claims), as one structured grant.
// Issuer and audience are trust gates and never select a grant. The contributors'
// families are unioned; a same-family collision fails closed (each family must have
// a single owner), and the contributors must agree on the WHOLE bundle envelope
// (bundle_id, bundle_version, trust_root_id) — a disagreement fails closed rather
// than silently first-winning. A non-empty union with any empty envelope field also
// fails closed (an empty envelope must never be signed — schema minLength:1 parity).
// An empty union returns a zero-family grant, which resolveBundle rejects.
func composeMappings(entries []mappingEntry, in matchInput) (grant, error) {
	out := grant{Families: map[string]grantFamily{}}
	seeded := false
	for i := range entries {
		entry := &entries[i]
		if !entry.isAssignedGrant() || !entry.matches(in) {
			continue
		}
		if err := contributeGrant(&out, entry.Grant, &seeded); err != nil {
			return grant{}, err
		}
	}
	if seeded && (out.BundleID == "" || out.BundleVersion == "" || out.TrustRootID == "") {
		return grant{}, errEmptyEnvelope
	}
	return out, nil
}

// contributeGrant folds one assigned grant into the union: it seeds or conflict-
// checks the envelope and unions the families (a same-family collision fails closed).
func contributeGrant(out *grant, next grant, seeded *bool) error {
	if !*seeded {
		out.BundleID = next.BundleID
		out.BundleVersion = next.BundleVersion
		out.TrustRootID = next.TrustRootID
		*seeded = true
	} else if envelopeConflicts(*out, next) {
		return errEnvelopeConflict
	}
	for name, fam := range next.Families {
		if _, dup := out.Families[name]; dup {
			return fmt.Errorf("%w: %q", errSameFamilyCollision, name)
		}
		out.Families[name] = fam
	}
	return nil
}

// envelopeConflicts reports whether a contributing grant's envelope disagrees with
// the seeded one on any of the three envelope fields.
func envelopeConflicts(seeded, next grant) bool {
	return next.BundleID != seeded.BundleID ||
		next.BundleVersion != seeded.BundleVersion ||
		next.TrustRootID != seeded.TrustRootID
}

// resolveBundle composes the union of the identity's assigned grants, caps it by
// the identity's tier ceiling (if any), then projects the structured grant to a
// signable bundle (Rego). It distinguishes genuine authorization-absence from real
// failures: errNoAuthorizedBundle (a client 4xx) for an empty union, a ceiling that
// caps every family away, or a claimed tier whose ceiling is not configured (an
// operator gap that denies the identity — logged, never left uncapped); the
// underlying error (a logged 5xx) for a composeMappings failure (collision /
// envelope conflict / empty envelope), a ceiling STORAGE read failure, or a policy
// that fails to compile (project) — each fails closed.
func (b *backend) resolveBundle(
	ctx context.Context, s logical.Storage, entries []mappingEntry, in matchInput,
) (apfbundle.Bundle, error) {
	g, err := composeMappings(entries, in)
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	if len(g.Families) == 0 {
		return apfbundle.Bundle{}, errNoAuthorizedBundle
	}
	ceiling, hasCeiling, err := b.resolveCeiling(ctx, s, in)
	if errors.Is(err, errCeilingNotFound) {
		// The identity claims a tier whose ceiling the operator never configured —
		// an operator config gap, not authorization the identity actually holds.
		// Deny it as authorization-absence (a clean 4xx) and never leave it uncapped,
		// but log precisely so the operator can fix the gap. Only the tier value is
		// logged — never the JWT or the full identity.
		b.Logger().Warn(
			"apf-bundle-issuer: identity claims apf_tier with no configured ceiling",
			"tier", in.Claims[claimTier])
		return apfbundle.Bundle{}, errNoAuthorizedBundle
	}
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	if hasCeiling {
		g = applyCeiling(g, ceiling)
		if len(g.Families) == 0 {
			return apfbundle.Bundle{}, errNoAuthorizedBundle
		}
	}
	bundle, err := project(g)
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	return bundle, nil
}

func (b *backend) readMapping(ctx context.Context, s logical.Storage, name string) (*mappingEntry, error) {
	entry, err := s.Get(ctx, storageKeyMappingPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("read mapping %q: %w", name, err)
	}
	if entry == nil {
		return nil, errMappingNotFound
	}
	mapping := &mappingEntry{}
	if err := entry.DecodeJSON(mapping); err != nil {
		return nil, fmt.Errorf("decode mapping %q: %w", name, err)
	}
	return mapping, nil
}

// allMappings loads every stored mapping; the issue path runs composeMappings over them.
func (b *backend) allMappings(ctx context.Context, s logical.Storage) ([]mappingEntry, error) {
	names, err := s.List(ctx, storageKeyMappingPrefix)
	if err != nil {
		return nil, fmt.Errorf("list mappings: %w", err)
	}
	entries := make([]mappingEntry, 0, len(names))
	for _, name := range names {
		mapping, err := b.readMapping(ctx, s, name)
		if err != nil {
			return nil, err
		}
		entries = append(entries, *mapping)
	}
	return entries, nil
}
