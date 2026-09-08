package backend

import (
	"context"
	"encoding/base64"
	"errors"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const signatureAlgorithm = "ed25519"

// errIssuanceFailed is the generic, client-facing error for internal issuance
// failures. The specific cause is logged server-side via b.Logger(); the client
// never receives wrapped internals.
var errIssuanceFailed = errors.New("bundle issuance failed")

// handleIssue runs the bundle-issuance flow: validate the forwarded
// workload JWT, map it to a bundle, assemble canonical bytes, transit-sign, and
// return the signed envelope. Every failure path returns NO bundle (fail closed);
// no JWT, token, or secret appears in any error — client-facing
// errors are generic, with the cause logged server-side.
func (b *backend) handleIssue(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) (*logical.Response, error) {
	canonical, errResp, err := b.mapAndAssemble(ctx, req, data)
	if errResp != nil || err != nil {
		return errResp, err
	}

	cfg, err := b.readSigningConfig(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("apf-bundle-issuer: read signing config", "error", err)
		return nil, errIssuanceFailed
	}
	signer, err := b.signerFactory(cfg)
	if err != nil {
		b.Logger().Error("apf-bundle-issuer: build signer", "error", err)
		return nil, errIssuanceFailed
	}
	signature, err := signer.Sign(ctx, canonical)
	if err != nil {
		// Transit unreachable / token unobtainable: no unsigned bundle.
		b.Logger().Error("apf-bundle-issuer: transit sign", "error", err)
		return nil, errIssuanceFailed
	}

	version := parseSignatureVersion(signature)
	if version == signatureVersionUnknown {
		// A signature without a parseable vault:vN: version would propagate as
		// key_version 0; fail closed rather than emit an unusable envelope.
		b.Logger().Error("apf-bundle-issuer: unparseable signature version")
		return nil, errIssuanceFailed
	}

	return &logical.Response{Data: map[string]any{
		"payload":   base64.StdEncoding.EncodeToString(canonical),
		"signature": signature,
		"signing": map[string]any{
			"key_name":    cfg.TransitKey,
			"key_version": version,
			"algorithm":   signatureAlgorithm,
		},
	}}, nil
}

// mapAndAssemble runs the identity->canonical-bytes half of issuance: validate the
// workload JWT, map it to an authorized bundle, and assemble its canonical bytes.
// It separates the two failure classes the caller must treat differently: a non-nil
// errResp is a client 4xx error RESPONSE (bad/untrusted JWT or genuine
// authorization-absence) returned with a nil Go error; a non-nil err is a logged 5xx
// (errIssuanceFailed) for any internal/config failure. On success both are nil.
func (b *backend) mapAndAssemble(
	ctx context.Context, req *logical.Request, data *framework.FieldData,
) ([]byte, *logical.Response, error) {
	token, _ := data.Get(fieldJWT).(string)
	if token == "" {
		return nil, logical.ErrorResponse("jwt is required"), nil
	}

	identity, err := b.validateJWT(ctx, req.Storage, token)
	if errors.Is(err, errTrustMaterial) {
		// The plugin's OWN trust material is unusable (unreadable issuer config,
		// malformed stored JWKS): an internal failure, not a bad token — log it
		// and 5xx rather than masking it as a silent client 4xx.
		b.Logger().Error("apf-bundle-issuer: issuer trust material", "error", err)
		return nil, nil, errIssuanceFailed
	}
	if err != nil {
		// Deliberately generic toward the caller: never echo the JWT or
		// validation internals. Keep the reason in the server log.
		b.Logger().Debug("apf-bundle-issuer: workload JWT rejected", "error", err)
		return nil, logical.ErrorResponse("workload JWT rejected"), nil
	}

	mappings, err := b.allMappings(ctx, req.Storage)
	if err != nil {
		b.Logger().Error("apf-bundle-issuer: load mappings", "error", err)
		return nil, nil, errIssuanceFailed
	}
	bundle, err := b.resolveBundle(ctx, req.Storage, mappings, identity)
	if errors.Is(err, errNoAuthorizedBundle) {
		// Genuine authorization-absence: an empty union (no assigned grant), a record
		// that confers nothing (suspended / revoked / pending / past its valid_until),
		// a token with no subject to record as the delegation actor, or a ceiling that
		// caps every family away. A client 4xx, no server log.
		return nil, logical.ErrorResponse("no authorized bundle for this identity"), nil
	}
	if err != nil {
		// A real failure: a same-family collision, an envelope conflict (including two
		// operators delegating to one identity), an empty envelope, a superseded
		// mapping record, a storage read failure, or a policy that fails to compile.
		// Log it and return a generic 5xx rather than masking it as a silent 4xx.
		b.Logger().Error("apf-bundle-issuer: resolve bundle", "error", err)
		return nil, nil, errIssuanceFailed
	}

	canonical, err := assembleBundle(bundle)
	if err != nil {
		b.Logger().Error("apf-bundle-issuer: assemble bundle", "error", err)
		return nil, nil, errIssuanceFailed
	}
	return canonical, nil, nil
}
