package backend

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"sort"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageKeyMappingPrefix = "mappings/"
	// storageKeyMappingVersionPrefix holds the per-mapping record-version high-water
	// mark. It is a SEPARATE key from the record so a storage restore that rewinds
	// one mapping is detectable (§6.1 rollback detection), and it survives a delete
	// so recreating a mapping cannot reset it to version 1.
	storageKeyMappingVersionPrefix = "mapping-versions/"
)

// Lifecycle states a mapping record may hold (ODIS §6.1). Only lifecycleActive
// confers authority; every other state — and any unrecognized value — confers none.
const (
	lifecycleActive    = "active"
	lifecycleSuspended = "suspended"
	lifecycleRevoked   = "revoked"
)

// lifecycleStates returns the closed set, defined once so the write-time validity
// check and the message it returns to the operator cannot drift apart. Adding a state
// here is the only edit a new state needs. A function rather than a package var,
// matching allowedSignatureAlgorithms.
func lifecycleStates() []string {
	return []string{lifecycleActive, lifecycleSuspended, lifecycleRevoked}
}

// Grant window bounds. defaultGrantTTL applies when a mapping declares no
// grant_ttl; maxGrantTTL caps what an operator may declare, so an issued grant is
// always short-lived enough for the Router's expiry check to matter (ODIS-L3-04).
const (
	defaultGrantTTL = time.Hour
	maxGrantTTL     = 24 * time.Hour
)

var (
	errMappingNotFound     = errors.New("mapping not found")
	errSameFamilyCollision = errors.New("multiple assigned mappings define the same family")
	errEnvelopeConflict    = errors.New("assigned mappings disagree on the bundle envelope")
	errEmptyEnvelope       = errors.New("composed grant has an empty bundle envelope")
	errRecordPreLifecycle  = errors.New(
		"mapping record predates the lifecycle fields and confers nothing until rewritten")
	// errRecordSuperseded signals a mapping record whose version sits below the
	// version already recorded for that name — a rollback. It is a storage-integrity
	// failure, not authorization-absence, so handleIssue logs it and returns a 5xx.
	errRecordSuperseded = errors.New("mapping record is superseded by a newer version")
	// errNoAuthorizedBundle signals genuine authorization-absence — the identity is
	// trusted but no assigned grant (or none surviving the ceiling) confers a bundle.
	// It is the ONLY resolveBundle error that maps to a client 4xx; every other error
	// is an internal/config failure that handleIssue logs and returns as a 5xx.
	errNoAuthorizedBundle = errors.New("no authorized bundle for this identity")
)

// mappingEntry is one operator-set identity->grant mapping. The match
// fields select which workloads receive `Grant`'s structured authority; the
// grant is lowered to a signable bundle (Rego) only at issuance (project).
//
// DelegatingPrincipal, LifecycleState, ValidUntil and RecordVersion make the record
// resolvable the way ODIS §6.1 requires: an authenticated delegator to hold
// accountable, a state the word "active" can check, a validity horizon, and a
// version that detects rollback.
type mappingEntry struct {
	Name               string            `json:"name"`
	BoundIssuer        string            `json:"bound_issuer"`
	BoundAudiences     []string          `json:"bound_audiences"`
	BoundSubject       string            `json:"bound_subject"`
	BoundSubjectPrefix string            `json:"bound_subject_prefix"`
	BoundClaims        map[string]string `json:"bound_claims"`
	Grant              grant             `json:"grant"`

	// DelegatingPrincipal is the authenticated Vault identity of the operator whose
	// write created this record — the principal whose authority initiated the
	// delegation chain (§6.3 originating_principal). Derived from the request, never
	// from request data: an operator-supplied string would be self-asserted.
	DelegatingPrincipal string `json:"delegating_principal"`
	LifecycleState      string `json:"lifecycle_state"`
	// ValidUntil is the latest instant this record may be treated as current
	// (RFC 3339). Empty means unbounded.
	ValidUntil    string `json:"valid_until"`
	RecordVersion int    `json:"record_version"`
	// GrantTTLSeconds bounds the lifetime of a grant issued from this record.
	GrantTTLSeconds int `json:"grant_ttl_seconds"`
}

// matchInput is the validated identity the plugin matches against mappings.
type matchInput struct {
	Issuer    string
	Audiences []string
	Subject   string
	Claims    map[string]string
}

// composedGrant is the union of an identity's eligible mappings: the structured
// grant plus the delegation provenance its contributors agree on.
type composedGrant struct {
	grant                grant
	originatingPrincipal string
	// records references every contributing mapping, sorted by name so the signed
	// bytes do not depend on storage iteration order.
	records []apfbundle.MappingRecordRef
	// validUntil is the earliest contributor horizon (zero when all are unbounded);
	// ttl the shortest contributor TTL. Both narrow, never widen, the grant window.
	validUntil time.Time
	ttl        time.Duration
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

// confersAuthority reports whether this record may confer authority at now: it must
// be active and inside its validity horizon. An unrecognized lifecycle state and an
// unparseable valid_until are both indeterminate, so both confer nothing.
func (e *mappingEntry) confersAuthority(now time.Time) bool {
	if e.LifecycleState != lifecycleActive {
		return false
	}
	if e.ValidUntil == "" {
		return true
	}
	until, err := time.Parse(time.RFC3339, e.ValidUntil)
	if err != nil {
		return false
	}
	return now.Before(until)
}

// grantTTL is the grant lifetime this record allows, falling back to the default when
// unset and clamped to maxGrantTTL. A non-positive stored value would make every issued
// grant already expired, so it reads as unset.
//
// Clamped here as well as in the write handler because this is the seam issuance reads:
// a record that reached storage by any other route — an earlier plugin build, a restored
// snapshot, direct storage access — must not be able to mint an effectively immortal
// grant, which would defeat the expiry the Router's check relies on. Every other
// invariant in this subsystem is re-checked at the signing seam; this one is too.
func (e *mappingEntry) grantTTL() time.Duration {
	if e.GrantTTLSeconds <= 0 {
		return defaultGrantTTL
	}
	if ttl := time.Duration(e.GrantTTLSeconds) * time.Second; ttl <= maxGrantTTL {
		return ttl
	}
	return maxGrantTTL
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
// explicitly assigned (by subject or bound_claims), as one structured grant plus the
// delegation provenance its contributors agree on. Issuer and audience are trust
// gates and never select a grant. The contributors' families are unioned; a
// same-family collision fails closed (each family must have a single owner), and the
// contributors must agree on the WHOLE bundle envelope (bundle_id, bundle_version,
// trust_root_id, delegating_principal) — a disagreement fails closed rather than
// silently first-winning. Two operators delegating to one identity is exactly that
// disagreement, and §6.3's single-valued originating_principal has no field for the
// second, so refusing is the correct outcome for an accountability split. A non-empty
// union with any empty envelope field also fails closed (an empty envelope must never
// be signed — schema minLength:1 parity). An empty union returns a zero-family grant,
// which resolveBundle rejects.
// The assigned-and-matching predicate here repeats `eligibleMappings`'. That is
// deliberate, not an oversight: `composeMappings` is also called directly with unfiltered
// entries, so it must select rather than assume. `eligibleMappings` additionally checks
// the record version and the validity horizon, which this does not — so it narrows, and
// this one selects. A change to `matches` must land in `mappingEntry`, which both share,
// rather than in either loop.
func composeMappings(entries []mappingEntry, in matchInput) (composedGrant, error) {
	out := composedGrant{grant: grant{Families: map[string]grantFamily{}}}
	seeded := false
	for i := range entries {
		entry := &entries[i]
		if !entry.isAssignedGrant() || !entry.matches(in) {
			continue
		}
		if err := contributeGrant(&out, entry, &seeded); err != nil {
			return composedGrant{}, err
		}
	}
	if !seeded {
		return out, nil
	}
	if out.grant.BundleID == "" || out.grant.BundleVersion == "" ||
		out.grant.TrustRootID == "" || out.originatingPrincipal == "" {
		return composedGrant{}, errEmptyEnvelope
	}
	sort.Slice(out.records, func(i, j int) bool { return out.records[i].Name < out.records[j].Name })
	return out, nil
}

// contributeGrant folds one eligible mapping into the union: it seeds or conflict-
// checks the envelope, unions the families (a same-family collision fails closed),
// records the authorization reference, and narrows the grant window.
func contributeGrant(out *composedGrant, entry *mappingEntry, seeded *bool) error {
	next := entry.Grant
	if !*seeded {
		out.grant.BundleID = next.BundleID
		out.grant.BundleVersion = next.BundleVersion
		out.grant.TrustRootID = next.TrustRootID
		out.originatingPrincipal = entry.DelegatingPrincipal
		out.ttl = entry.grantTTL()
		*seeded = true
	} else {
		if envelopeConflicts(out, entry) {
			return errEnvelopeConflict
		}
		if ttl := entry.grantTTL(); ttl < out.ttl {
			out.ttl = ttl
		}
	}
	for name, fam := range next.Families {
		if _, dup := out.grant.Families[name]; dup {
			return fmt.Errorf("%w: %q", errSameFamilyCollision, name)
		}
		out.grant.Families[name] = fam
	}
	ref, err := mappingRecordRef(*entry)
	if err != nil {
		return err
	}
	out.records = append(out.records, ref)
	if until, err := time.Parse(time.RFC3339, entry.ValidUntil); err == nil {
		if out.validUntil.IsZero() || until.Before(out.validUntil) {
			out.validUntil = until
		}
	}
	return nil
}

// envelopeConflicts reports whether a contributing mapping's envelope disagrees with
// the seeded one on any envelope field, including the principal delegating it.
func envelopeConflicts(out *composedGrant, entry *mappingEntry) bool {
	return entry.Grant.BundleID != out.grant.BundleID ||
		entry.Grant.BundleVersion != out.grant.BundleVersion ||
		entry.Grant.TrustRootID != out.grant.TrustRootID ||
		entry.DelegatingPrincipal != out.originatingPrincipal
}

// mappingRecordRef builds the integrity-protected reference to one mapping record:
// its name, version, and a digest over its canonical content. A verifier that can
// read apf/mappings/<name> recomputes the digest to confirm the grant came from that
// exact record; the bundle signature protects the reference itself.
func mappingRecordRef(entry mappingEntry) (apfbundle.MappingRecordRef, error) {
	canonical, err := apfbundle.CanonicalJSON(entry)
	if err != nil {
		return apfbundle.MappingRecordRef{}, fmt.Errorf("digest mapping %q: %w", entry.Name, err)
	}
	sum := sha256.Sum256(canonical)
	return apfbundle.MappingRecordRef{
		Name:    entry.Name,
		Version: entry.RecordVersion,
		Digest:  "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

// resolveBundle resolves the identity to the mapping records that may confer
// authority, composes their union, caps it by the identity's tier ceiling (if any),
// projects the structured grant to a signable bundle (Rego), and stamps the
// delegation provenance on it. It distinguishes genuine authorization-absence from
// real failures: errNoAuthorizedBundle (a client 4xx) for an empty union, a record
// that confers nothing (suspended / revoked / pending / past its valid_until), a
// token with no subject to record as actor, a ceiling that caps every family away,
// or a claimed tier whose ceiling is not configured (an operator gap that denies the
// identity — logged, never left uncapped); the underlying error (a logged 5xx) for a
// composeMappings failure (collision / envelope conflict / empty envelope), a
// superseded record, a storage read failure, or a policy that fails to compile
// (project) — each fails closed.
func (b *backend) resolveBundle(
	ctx context.Context, s logical.Storage, entries []mappingEntry, in matchInput,
) (apfbundle.Bundle, error) {
	eligible, err := b.eligibleMappings(ctx, s, entries, in)
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	composed, err := composeMappings(eligible, in)
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	if len(composed.grant.Families) == 0 {
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
		composed.grant = applyCeiling(composed.grant, ceiling)
		if len(composed.grant.Families) == 0 {
			return apfbundle.Bundle{}, errNoAuthorizedBundle
		}
	}
	bundle, err := project(composed.grant)
	if err != nil {
		return apfbundle.Bundle{}, err
	}
	if err := stampDelegation(&bundle, composed, in); err != nil {
		return apfbundle.Bundle{}, err
	}
	return bundle, nil
}

// eligibleMappings narrows the stored records to those that may confer authority to
// this identity: assigned, matching, active, and inside their validity horizon. A
// record whose version sits below the high-water mark for its name is a rollback and
// fails the whole resolution rather than being skipped, because silently dropping it
// would read as ordinary authorization-absence.
//
// What the mark detects is a record rewound *relative to* its own version floor: a
// partial restore, a hand-edited record, or a replayed older write. It does NOT detect a
// whole-backend rollback — the mark lives in the same `logical.Storage` as the record, so
// a snapshot restore rewinds both in lockstep and the comparison passes. Detecting that
// would need an anchor outside this storage, which the plugin does not have.
func (b *backend) eligibleMappings(
	ctx context.Context, s logical.Storage, entries []mappingEntry, in matchInput,
) ([]mappingEntry, error) {
	now := time.Now().UTC()
	eligible := make([]mappingEntry, 0, len(entries))
	for i := range entries {
		entry := &entries[i]
		if !entry.isAssignedGrant() || !entry.matches(in) {
			continue
		}
		current, err := b.recordVersionCurrent(ctx, s, entry)
		if err != nil {
			return nil, err
		}
		if !current {
			return nil, fmt.Errorf("%w: %q at version %d", errRecordSuperseded, entry.Name, entry.RecordVersion)
		}
		// A record stored before the lifecycle fields existed decodes with an empty
		// state, which `confersAuthority` correctly refuses — but skipping it silently
		// yields errNoAuthorizedBundle, indistinguishable from "no mapping was ever
		// written". Named so an operator upgrading the plugin sees why authority stopped.
		//
		// Deliberately NOT normalized to `active`: the same record also carries no
		// delegating principal, and defaulting that would invent an accountable operator
		// for a delegation nobody is recorded as having made. Rewriting the mapping is the
		// migration, and it is one command.
		if entry.LifecycleState == "" {
			return nil, fmt.Errorf("%w: %q", errRecordPreLifecycle, entry.Name)
		}
		if !entry.confersAuthority(now) {
			continue
		}
		eligible = append(eligible, *entry)
	}
	return eligible, nil
}

// stampDelegation writes the delegation record onto the projected bundle: who holds
// it, who delegated it, which mapping records conferred it, that it is a root record,
// the rules its attenuation follows, and the window it is valid for. The window is the shortest
// contributing TTL, further capped by the earliest contributor valid_until — a
// delegation never outlives the authorization that produced it (§6.3).
func stampDelegation(bundle *apfbundle.Bundle, composed composedGrant, in matchInput) error {
	if in.Subject == "" {
		// §6.3 makes actor a MUST, and the actor is the validated token subject; a
		// subject-less token cannot receive a delegation record at all.
		return fmt.Errorf("%w: token has no subject to record as the delegation actor", errNoAuthorizedBundle)
	}
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(composed.ttl)
	if !composed.validUntil.IsZero() && composed.validUntil.Before(expires) {
		expires = composed.validUntil
	}
	if !expires.After(now) {
		return fmt.Errorf("%w: the grant window closed before it opened", errNoAuthorizedBundle)
	}

	bundle.Actor = in.Subject
	bundle.OriginatingPrincipal = composed.originatingPrincipal
	bundle.ContributingRecords = composed.records
	// This issuer delegates operator -> agent in one hop and supports no
	// sub-delegation, so every grant it mints is a root record.
	bundle.DelegationChain = apfbundle.RootDelegationChain()
	bundle.AttenuationProfileRef = &apfbundle.AttenuationProfileRef{
		URI:    policydsl.AttenuationProfileURI,
		Digest: policydsl.AttenuationProfileDigest(),
	}
	// Both stamps are forced to UTC here rather than relying on their sources: `now`
	// is already UTC, but `expires` may come from a contributor's valid_until, which
	// is parsed from RFC 3339 and can carry any offset. Two different offsets in the
	// signed bytes would make the window read as skewed to anything comparing them
	// textually.
	bundle.IssuedAt = now.UTC().Format(time.RFC3339)
	bundle.ExpiresAt = expires.UTC().Format(time.RFC3339)
	return nil
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

// mappingVersionEntry is the highest record version ever accepted for a mapping name.
type mappingVersionEntry struct {
	RecordVersion int `json:"record_version"`
}

// readRecordVersionSeen returns the high-water mark for a mapping name; 0 when the
// name has never been written.
func (b *backend) readRecordVersionSeen(
	ctx context.Context, s logical.Storage, name string,
) (int, error) {
	stored, err := s.Get(ctx, storageKeyMappingVersionPrefix+name)
	if err != nil {
		return 0, fmt.Errorf("read mapping version %q: %w", name, err)
	}
	if stored == nil {
		return 0, nil
	}
	seen := &mappingVersionEntry{}
	if err := stored.DecodeJSON(seen); err != nil {
		return 0, fmt.Errorf("decode mapping version %q: %w", name, err)
	}
	return seen.RecordVersion, nil
}

// recordVersionSeen raises the high-water mark for a mapping name.
func (b *backend) recordVersionSeen(
	ctx context.Context, s logical.Storage, name string, version int,
) error {
	// Monotonic: the mark only ever rises. Overwriting it would let two writes arriving
	// out of order (v3 then v2) leave the mark at v2, which makes the replayed v2 look
	// current — the rollback the mark exists to refuse.
	seen, err := b.readRecordVersionSeen(ctx, s, name)
	if err != nil {
		return err
	}
	if version < seen {
		version = seen
	}
	stored, err := logical.StorageEntryJSON(
		storageKeyMappingVersionPrefix+name, mappingVersionEntry{RecordVersion: version})
	if err != nil {
		return fmt.Errorf("encode mapping version %q: %w", name, err)
	}
	if err := s.Put(ctx, stored); err != nil {
		return fmt.Errorf("persist mapping version %q: %w", name, err)
	}
	return nil
}

// recordVersionCurrent reports whether a record is at or above the highest version ever
// accepted for its name — the rollback check §6.1's resolution rule requires.
//
// `>=`, not equality. What the mark defends against is a *replay*: a record rewound below
// a version already accepted. A record above the mark would mean one that reached storage
// without passing the write handler, and requiring equality does not defend against that
// — anyone able to write the record can write the mark beside it — while it does refuse
// legitimate direct seeding, which is how the fixtures and any out-of-band restore work.
func (b *backend) recordVersionCurrent(
	ctx context.Context, s logical.Storage, entry *mappingEntry,
) (bool, error) {
	seen, err := b.readRecordVersionSeen(ctx, s, entry.Name)
	if err != nil {
		return false, err
	}
	return entry.RecordVersion >= seen, nil
}
