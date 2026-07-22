package backend

import (
	"context"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/policydsl"

	"github.com/hashicorp/vault/sdk/logical"
)

const (
	storageKeyCeilingPrefix = "ceilings/"
	fieldCeilingFamilies    = "families"
	// claimTier is the namespaced JWT claim that selects a tier ceiling. It is
	// namespaced ("apf_tier", not a bare "tier") so an identity carrying an
	// unrelated "tier" claim does not accidentally select — or fail closed against
	// a missing — ceiling.
	claimTier = "apf_tier"
)

var errCeilingNotFound = errors.New("ceiling not found")

// ceilingEntry is an operator-set maximum-permission cap for a tier. Effective
// authority = the union of an identity's assigned grants INTERSECT the matching
// ceiling, so a tier can only ever shrink — never widen — what a grant confers.
// Families maps a family name to the most-permissive policy spec allowed there; a
// family absent from the ceiling is not permitted for the tier at all.
type ceilingEntry struct {
	Name     string                          `json:"name"`
	Families map[string]policydsl.PolicySpec `json:"families"`
}

func (b *backend) readCeiling(ctx context.Context, s logical.Storage, name string) (*ceilingEntry, error) {
	stored, err := s.Get(ctx, storageKeyCeilingPrefix+name)
	if err != nil {
		return nil, fmt.Errorf("read ceiling %q: %w", name, err)
	}
	if stored == nil {
		return nil, errCeilingNotFound
	}
	entry := &ceilingEntry{}
	if err := stored.DecodeJSON(entry); err != nil {
		return nil, fmt.Errorf("decode ceiling %q: %w", name, err)
	}
	return entry, nil
}

// resolveCeiling returns the maximum-permission ceiling for an identity, selected
// by its "apf_tier" claim. found is false (err nil) when there is no apf_tier claim
// — no ceiling, so the union is bounded only by what was assigned. An apf_tier claim
// naming a ceiling that is not configured is a misconfiguration and fails closed.
func (b *backend) resolveCeiling(
	ctx context.Context, s logical.Storage, in matchInput,
) (ceilingEntry, bool, error) {
	tier := in.Claims[claimTier]
	if tier == "" {
		return ceilingEntry{}, false, nil
	}
	entry, err := b.readCeiling(ctx, s, tier)
	if err != nil {
		return ceilingEntry{}, false, err
	}
	return *entry, true, nil
}

// applyCeiling caps a composed grant by the ceiling — both family-level and
// field-level. A family the ceiling omits is dropped entirely; a family the ceiling
// permits keeps its grant policy INTERSECTED with the ceiling spec (so the effective
// policy is the most-permissive allowed by both). A ceiling can only shrink a grant,
// never widen it: a family whose intersection leaves ZERO rules is dropped (it would
// otherwise become an unpoliced passthrough), and a kept family is forced to strict
// mode (a ceiling-bounded family never permissively forwards unpoliced tools).
func applyCeiling(g grant, ceiling ceilingEntry) grant {
	capped := g
	capped.Families = make(map[string]grantFamily, len(g.Families))
	for name, gf := range g.Families {
		ceilSpec, permitted := ceiling.Families[name]
		if !permitted {
			continue
		}
		gf.Policy = policydsl.Intersect(gf.Policy, ceilSpec)
		if len(gf.Policy.Rules) == 0 {
			// The ceiling capped every verb away — dropping the family denies it
			// rather than leaving a zero-rule passthrough at the Router.
			continue
		}
		gf.DefaultMode = modeStrict
		capped.Families[name] = gf
	}
	return capped
}
