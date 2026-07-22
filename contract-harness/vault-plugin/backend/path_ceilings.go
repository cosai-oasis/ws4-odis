package backend

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"odis-contract-harness/vault-plugin/internal/policydsl"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// pathCeilings registers the operator-set tier-ceiling endpoints: a LIST on
// ceilings/ and CRUD on ceilings/<tier>.
func (b *backend) pathCeilings() []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "ceilings/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.handleListCeilings},
			},
			HelpSynopsis:    "List tier-ceiling names.",
			HelpDescription: "Enumerate the operator-set maximum-permission tier ceilings.",
		},
		{
			Pattern: "ceilings/" + framework.GenericNameRegex(fieldName),
			Fields: map[string]*framework.FieldSchema{
				fieldName: {
					Type:        framework.TypeString,
					Description: "Tier (ceiling) name.",
				},
				fieldCeilingFamilies: {
					Type:        framework.TypeString,
					Description: "Maximum-permission spec: JSON map of family to max policy (the tier's cap).",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.UpdateOperation: &framework.PathOperation{Callback: b.handleWriteCeiling},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.handleReadCeiling},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.handleDeleteCeiling},
			},
			HelpSynopsis:    "Define a tier's maximum-permission ceiling.",
			HelpDescription: "The cap a tier's effective authority is intersected against (deny-wins); it only shrinks a grant.",
		},
	}
}

func (b *backend) handleListCeilings(
	ctx context.Context, req *logical.Request, _ *framework.FieldData,
) (*logical.Response, error) {
	names, err := req.Storage.List(ctx, storageKeyCeilingPrefix)
	if err != nil {
		return nil, fmt.Errorf("list ceilings: %w", err)
	}
	return logical.ListResponse(names), nil
}

func (b *backend) handleWriteCeiling(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	if name == "" {
		return logical.ErrorResponse("name is required"), nil
	}

	familiesJSON, _ := data.Get(fieldCeilingFamilies).(string)
	var families map[string]policydsl.PolicySpec
	if err := json.Unmarshal([]byte(familiesJSON), &families); err != nil {
		return logical.ErrorResponse("families is not valid JSON: %v", err), nil
	}
	if len(families) == 0 {
		return logical.ErrorResponse("a ceiling must permit at least one family"), nil
	}
	for famName, spec := range families {
		// Intersect indexes ceiling rules by verb (last-wins), so a duplicate verb
		// would silently drop a cap; an unknown op would later fail to compile.
		if err := policydsl.ValidateSpec(spec); err != nil {
			return logical.ErrorResponse("ceiling family %q: %v", famName, err), nil
		}
	}

	entry := ceilingEntry{Name: name, Families: families}
	stored, err := logical.StorageEntryJSON(storageKeyCeilingPrefix+name, entry)
	if err != nil {
		return nil, fmt.Errorf("encode ceiling %q: %w", name, err)
	}
	if err := req.Storage.Put(ctx, stored); err != nil {
		return nil, fmt.Errorf("persist ceiling %q: %w", name, err)
	}
	return nil, nil
}

func (b *backend) handleReadCeiling(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	entry, err := b.readCeiling(ctx, req.Storage, name)
	if errors.Is(err, errCeilingNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// Return the complete per-family spec (the JSON shape the write accepts), so
	// an operator can audit exactly what cap is configured, not just its keys.
	return &logical.Response{Data: map[string]any{
		fieldName:            entry.Name,
		fieldCeilingFamilies: entry.Families,
	}}, nil
}

func (b *backend) handleDeleteCeiling(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	name, _ := data.Get(fieldName).(string)
	if err := req.Storage.Delete(ctx, storageKeyCeilingPrefix+name); err != nil {
		return nil, fmt.Errorf("delete ceiling %q: %w", name, err)
	}
	return nil, nil
}
