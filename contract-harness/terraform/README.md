# Terraform: provisioning a real Vault for `apf-bundle-issuer`

This module provisions the non-secret Vault paths the `apf-bundle-issuer` plugin needs
using the `hashicorp/vault` provider. It is the **declarative counterpart to the
imperative [`vault/provision.sh`](../vault/provision.sh)** (the source of truth) — same
paths, matching least-privilege scoping, expressed as Terraform resources. One
deliberate delta: tokens minted here exclude Vault's **default policy**
(`token_no_default_policy`), so the `apf-sign` policy grants `auth/token/revoke-self`
explicitly — the plugin best-effort-revokes each signing token after use.

> **Status: experimental but ready to apply.** Terraform provisions the non-secret resources
> and deliberately does not manage `config/signing`, whose required `secret_id` would
> otherwise be stored in state. The initial apply—and any later change to the AppRole,
> plugin mount, or plugin-reachable Vault address—must be followed by
> the complete out-of-band signing configuration below before the plugin can issue bundles.
> The transit signing mount/key are deliberately **not** renameable here: the key resource
> carries `prevent_destroy` (a persistent trust root), so a rename fails at plan time —
> rotate key material in place with `vault write -f <transit>/keys/<key>/rotate` instead.

## Scope

- **Targets a REAL Vault** — a persistent, **unsealed** Vault you operate, **not** a
  `-dev` server. The throwaway `-dev` flow is `mise run smoke-vault`, which boots a
  dev Vault, provisions it via `provision.sh`, issues a bundle as the Router, and
  offline-verifies the signature. **This module complements that flow; it does not
  replace it.** Use the smoke test for a hermetic end-to-end check and this module for
  the persistent-Vault resource path.
- **OSS Community Vault only.** The plugin signs through an **AppRole scoped to
  `transit/sign/<key>`** (the OSS signing path) — Vault's plugin Workload Identity
  Federation (`GenerateIdentityToken`) is **Enterprise-only**. The Router's caller leg
  uses the **`jwt` auth method scoped to `<plugin>/issue`**.

### What it provisions

| Resource | Purpose |
| --- | --- |
| `transit` mount + ed25519 key | The non-exportable bundle-signing key (private half never leaves Vault). |
| policy `apf-sign` | Grants **only** `transit/sign/<key>` + `auth/token/revoke-self` (post-sign token cleanup; tokens exclude the default policy). |
| `approle` mount + role `apf-signer` | The plugin's transit self-call leg (token policy `apf-sign`). |
| policy `apf-issue` | Grants **only** `<plugin>/issue`. |
| `jwt` mount + role `router` | The Router's caller leg (token policy `apf-issue`). |
| `apf` plugin mount + catalog registration | The issue / config / mappings / ceilings surface. |
| `config/issuer` and the mapping | Issuer trust and the identity→grant mapping (a structured grant the plugin projects to Rego). |
| the tier ceiling (optional) | A maximum-permission cap under `ceilings/<tier>`, created only when `ceiling_tier` is set; the identity's assigned grant union is intersected against it (shrink-only, deny-wins). |

## Prerequisites

1. **A real, unsealed Vault** reachable at `VAULT_ADDR`, and an **admin token** with
   rights to enable mounts/auth methods, write policies, and register plugins. Set
   `VAULT_ADDR` and `VAULT_TOKEN` in the environment (the provider reads them) — do
   **not** put the token in `terraform.tfvars` or any committed file.
2. **The plugin binary, built and staged out-of-band.** `dist/` is gitignored, so the
   binary is not in the repo. Build it with a Go toolchain:
   ```bash
   mise run build-vault-plugin    # -> vault-plugin/dist/apf-bundle-issuer
   ```
   Then **copy it into the Vault server's configured `plugin_directory`** and compute
   its hash for `plugin_sha256`:
   ```bash
   sha256sum vault-plugin/dist/apf-bundle-issuer    # hex -> terraform.tfvars
   ```
   Vault registers a plugin by the SHA-256 of the binary it finds in
   `plugin_directory`; the hash must match the staged file exactly.
3. **Workload-JWT trust inputs.** Set a nonempty `jwks` for the plugin and configure
   either `jwt_validation_pubkeys` or `oidc_discovery_url` for Vault's JWT auth method.
   The empty defaults are intentionally not valid trust configuration.

## What is EXCLUDED, and why

- **The complete `config/signing` write.** This module **never** creates
  `vault_approle_auth_backend_role_secret_id` and never places `secret_id` in Terraform
  configuration or state. The plugin requires `role_id` and `secret_id` together, so the
  entire write happens out-of-band after apply.
- **The plugin BINARY.** Built and staged out-of-band (`mise run build-vault-plugin` +
  copy into `plugin_directory`); Terraform only registers it in the catalog by hash.
  **After changing `plugin_sha256`, run `vault plugin reload -plugin <name>`** — the
  catalog re-registration alone does not swap the binary the live mount is executing.

## Required post-apply signing configuration

After the initial apply—or after changing the AppRole, plugin mount, or
`ODIS_PLUGIN_VAULT_ADDR`—mint a `secret_id` and write the full `config/signing` body. The
secret travels via **the environment and stdin JSON, never argv** (a process arg list is
world-readable via `/proc/<pid>/cmdline` / `ps`). The task derives custom mount/key names
from Terraform outputs, keeps the generated secret out of output, and **rotates**: once
the new credential is delivered, every superseded `secret_id` is revoked by accessor (an
undelivered one is destroyed on any failure or interrupt):

```bash
mise run tf:configure-signing
```

By default the plugin receives `VAULT_ADDR`; set `ODIS_PLUGIN_VAULT_ADDR` when the address
the plugin can reach differs from the operator's address. A successful task is the
completion condition for provisioning. Terraform intentionally cannot detect drift for
this secret-bearing endpoint.

## Drift caveat (`vault_generic_endpoint`)

Every `vault_generic_endpoint` resource in this module — the plugin catalog
registration, `config/issuer`, the mapping, and the optional ceiling — sets
**`disable_read = true`** because its read shape does not match the write shape.
There is no drift detection on any of them: out-of-band changes to those paths go
unnoticed by `terraform plan`. The typed resources (transit, approle/JWT roles,
policies, mounts) do detect drift normally.

## Example `terraform.tfvars`

```hcl
# Plugin catalog registration: hash of the binary you staged in plugin_directory.
plugin_sha256  = "0000000000000000000000000000000000000000000000000000000000000000"
plugin_command = "apf-bundle-issuer"

# Fixture-issuer trust (the demo path). The jwt auth method takes PEM here; the plugin's
# config/issuer takes the JWKS. For SPIRE, set oidc_discovery_url instead and point both
# the jwt method and config/issuer at the SPIRE OIDC discovery document (see ../vault/README.md).
bound_issuer    = "https://fixture.issuer.odis.local/"
bound_audiences = ["apf-bundle-issuer"]
bound_subject   = "spiffe://example.org/agent/jira"

jwt_validation_pubkeys = [<<-PEM
  -----BEGIN PUBLIC KEY-----
  ...fixture issuer public key...
  -----END PUBLIC KEY-----
  PEM
]
jwks = "{\"keys\":[ ... fixture JWK Set ... ]}"

# Demo defaults: secret_id_ttl_seconds = 0 is a NON-EXPIRING secret_id. Production
# should set a short TTL and rotate (e.g. response-wrapped delivery + a refresh loop).
secret_id_ttl_seconds = 0
approle_token_ttl     = 600

# Optional tier ceiling (maximum-permission boundary). Leave ceiling_tier empty to skip.
# When set, an identity presenting apf_tier=<ceiling_tier> has its assigned grant union
# intersected against this cap (shrink-only; kept families forced to strict).
# ceiling_tier          = "standard"
# ceiling_families_json = "{\"jira-prod\":{\"rules\":[{\"verb\":\"update_issue\",\"allow_fields\":[\"labels\"]}]}}"
```

## Plan and apply

Create `terraform.tfvars` from the example above, stage the plugin binary in Vault's
`plugin_directory`, and set `VAULT_ADDR` plus `VAULT_TOKEN` in the environment. Then run:

```bash
mise run tf:lint
mise run tf:plan
mise run tf:apply
mise run tf:configure-signing
```

Terraform apply succeeds without handling the secret; the plugin becomes ready to issue
bundles only after `tf:configure-signing` succeeds.

## Destruction policy

The transit signing key has `prevent_destroy = true`. A blanket `terraform destroy` stops
at planning time instead of deleting the surrounding resources and then failing at the
protected Vault key. Retiring a signing root requires an explicit operational decision:
preserve any verification material still needed for issued bundles, then deliberately
change the key lifecycle policy before destroying the remaining resources.
