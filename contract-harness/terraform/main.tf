# Provisioning of the apf-bundle-issuer Vault paths against a REAL (persistent,
# unsealed) Vault. Terraform manages the non-secret resources; after apply, the
# operator must perform the complete config/signing write documented in README.md so
# the AppRole secret_id never enters Terraform state.
#
# What this sets up, on OSS Community Vault:
#   - transit:  a non-exportable ed25519 signing key (the bundle key)
#   - approle:  role apf-signer + policy apf-sign granting ONLY transit/sign/<key>
#               (the plugin's OSS signing path; WIF/GenerateIdentityToken is Enterprise-only)
#   - jwt:      role router + policy apf-issue granting ONLY <plugin>/issue
#               (the Router's caller leg)
#   - apf:      the plugin mount + catalog registration, config/issuer, the mapping,
#               and an optional tier ceiling
#
# DELIBERATELY EXCLUDED (see README.md): config/signing, because its required AppRole
# secret_id would land in tfstate in cleartext if Terraform managed the write. The
# complete role_id + secret_id body is written out-of-band after apply.

# --- transit: the ed25519 bundle-signing key ---------------------------------------

resource "vault_mount" "transit" {
  path        = var.transit_mount
  type        = "transit"
  description = "Transit engine holding the ed25519 APF bundle-signing key."
}

resource "vault_transit_secret_backend_key" "bundle" {
  backend = vault_mount.transit.path
  name    = var.transit_key_name
  type    = "ed25519"
  # The private half never leaves Vault: the plugin signs via transit/sign and
  # verifiers use only the exported PUBLIC key for offline verification.
  exportable = false

  # This persistent trust root may validate already-issued bundles. Stop a blanket
  # terraform destroy at planning time instead of partially tearing down the stack
  # before Vault refuses to delete the key.
  lifecycle {
    prevent_destroy = true
  }
}

# --- approle: the plugin's transit self-call leg (scoped to transit/sign only) -----

resource "vault_policy" "apf_sign" {
  name = "apf-sign"
  # Least-privilege: the signing token can ONLY sign with the bundle key, plus
  # revoke itself (the plugin best-effort-revokes each signing token after use;
  # tokens here exclude Vault's default policy, which normally grants that).
  policy = <<-EOT
    path "${var.transit_mount}/sign/${var.transit_key_name}" {
      capabilities = ["update"]
    }
    path "auth/token/revoke-self" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_auth_backend" "approle" {
  type = "approle"
  path = var.approle_mount
}

resource "vault_approle_auth_backend_role" "apf_signer" {
  backend        = vault_auth_backend.approle.path
  role_name      = "apf-signer"
  token_policies = [vault_policy.apf_sign.name]
  # Exclude Vault's default policy: the signing token needs exactly apf-sign
  # (which grants revoke-self explicitly), nothing more.
  token_no_default_policy = true
  token_ttl               = var.approle_token_ttl
  # secret_id_ttl default 0 = non-expiring and secret_id_num_uses = 0 = unlimited
  # uses: a DEMO simplification (the plugin holds ONE static secret_id, no re-fetch).
  # Production should set a short TTL and rotate. See variables.tf / README.md.
  secret_id_ttl      = var.secret_id_ttl_seconds
  secret_id_num_uses = 0
}

# NOTE: vault_approle_auth_backend_role_secret_id is INTENTIONALLY NOT declared here.
# A generated secret_id would be stored in tfstate in cleartext (Secret-Zero
# violation). Generate it post-apply and write it into config/signing out-of-band
# (see README.md "Required post-apply signing configuration").

# --- jwt: the Router caller leg (scoped to <plugin>/issue only) --------------------

resource "vault_policy" "apf_issue" {
  name = "apf-issue"
  # The Router's exchanged token can ONLY call the plugin's issue endpoint.
  policy = <<-EOT
    path "${var.plugin_mount}/issue" {
      capabilities = ["update"]
    }
  EOT
}

resource "vault_jwt_auth_backend" "jwt" {
  path = var.jwt_mount
  type = "jwt"

  bound_issuer = var.bound_issuer

  # Trust material for the jwt auth method. Set exactly one of:
  #   - var.oidc_discovery_url   — a served key set via OIDC discovery (e.g. SPIRE);
  #   - var.jwt_validation_pubkeys — static PEM public keys (the fixture-issuer path:
  #     provision.sh passes jwt_validation_pubkeys=@pub.pem). The jwt auth method takes
  #     PEM here, not a raw JWKS — the plugin's config/issuer is what consumes var.jwks.
  oidc_discovery_url     = var.oidc_discovery_url != "" ? var.oidc_discovery_url : null
  jwt_validation_pubkeys = var.oidc_discovery_url == "" ? var.jwt_validation_pubkeys : null

  lifecycle {
    # Fail at plan, not midway through apply: the module's defaults provide NO
    # trust material, and applying without any would strand a partial stack.
    precondition {
      condition     = (var.oidc_discovery_url != "") != (length(var.jwt_validation_pubkeys) > 0)
      error_message = "Set exactly one of oidc_discovery_url or jwt_validation_pubkeys as the jwt auth method's trust material."
    }
  }
}

resource "vault_jwt_auth_backend_role" "router" {
  backend         = vault_jwt_auth_backend.jwt.path
  role_name       = "router"
  role_type       = "jwt"
  user_claim      = "sub"
  bound_audiences = var.bound_audiences
  token_policies  = [vault_policy.apf_issue.name]
  # The exchanged token only ever POSTs <plugin>/issue; it needs no default-policy
  # self-management paths and simply expires.
  token_no_default_policy = true
  # Subject scoping lives on the mapping (bound_subject below), matching
  # provision.sh — the jwt role gates the caller leg by issuer + audience only.
}

# --- apf: the plugin mount, catalog registration, issuer trust, mapping, signing ---

# Register the external secrets-engine plugin in the catalog. The operator MUST stage
# the built binary in Vault's configured plugin_directory FIRST (the binary is built
# out-of-band with `mise run build-vault-plugin` into vault-plugin/dist/ — dist/ is
# gitignored — and copied into plugin_directory). plugin_sha256 must match that staged
# binary. Empty plugin_sha256 skips CREATING this registration (pre-registered plugin).
#
# Two lifecycle hazards a plan will not warn about:
#   - Re-registration does NOT swap the running binary: after changing plugin_sha256,
#     run `vault plugin reload -plugin <name>` (or remount) — until then the live apf
#     mount keeps executing the OLD binary.
#   - Changing a previously non-empty plugin_sha256 to "" flips count 1->0 and DESTROYS
#     this catalog entry while the mount still needs it (the mount fails to initialize
#     on the next Vault restart/reload). Blank it only as part of removing the mount.
resource "vault_generic_endpoint" "plugin_catalog" {
  count = var.plugin_sha256 != "" ? 1 : 0

  path = "sys/plugins/catalog/secret/${var.plugin_name}"
  # Write-only: Vault does not round-trip the catalog entry in a readable form here,
  # so disable read to avoid spurious drift. Re-registration on change is the intent.
  disable_read         = true
  ignore_absent_fields = true

  data_json = jsonencode({
    sha256  = var.plugin_sha256
    command = var.plugin_command
  })
}

resource "vault_mount" "apf" {
  path        = var.plugin_mount
  type        = var.plugin_name
  description = "apf-bundle-issuer: issues transit-signed APF Signed Policy Bundles for validated workload JWTs."

  # Mount only after the plugin is in the catalog (when we register it here).
  depends_on = [vault_generic_endpoint.plugin_catalog]
}

# config/issuer: trusted workload-JWT issuer material. For SPIRE, set bound_issuer
# to the server's configured jwt_issuer (the JWT-SVID iss value) and jwks to the
# JWK Set its OIDC Discovery Provider serves.
resource "vault_generic_endpoint" "config_issuer" {
  path = "${vault_mount.apf.path}/config/issuer"
  # Write-only config endpoint: no readable round-trip we can diff, so disable read
  # (no drift detection on this resource). The plugin has no DELETE operation for this
  # singleton endpoint; the parent mount deletion removes its storage during destroy.
  disable_read         = true
  disable_delete       = true
  ignore_absent_fields = true

  data_json = jsonencode({
    jwks            = var.jwks
    bound_issuer    = var.bound_issuer
    bound_audiences = var.bound_audiences
  })
}

# The identity->grant mapping: bound_subject is the ASSIGNED selector that confers the
# grant; bound_issuer/bound_audiences are ambient trust gates that filter but never confer.
# The plugin UNIONs every assigned mapping an identity matches (a same-family collision
# across mappings fails closed), so this grant merges with any others the identity holds.
resource "vault_generic_endpoint" "mapping" {
  path = "${vault_mount.apf.path}/mappings/${var.mapping_name}"
  # Write-only: the plugin's read echoes the DECODED grant (plus selector fields and
  # a family-name summary), not the JSON string written here, so a read-compare would
  # always diff. Disable read; no drift detection here.
  disable_read         = true
  ignore_absent_fields = true

  data_json = jsonencode({
    bound_issuer    = var.bound_issuer
    bound_audiences = var.bound_audiences
    bound_subject   = var.bound_subject
    bundle          = var.bundle_json
  })
}

# Optional tier ceiling (maximum-permission boundary). The assigned grant union is
# intersected against this for an identity presenting apf_tier=<ceiling_tier>; a ceiling
# only SHRINKS authority (deny-wins) and forces every family it caps to strict. Disabled
# by default (no ceiling_tier) — most demos don't tier-cap.
resource "vault_generic_endpoint" "ceiling" {
  count = var.ceiling_tier != "" ? 1 : 0

  path = "${vault_mount.apf.path}/ceilings/${var.ceiling_tier}"
  # Write-only: the plugin's read echoes the DECODED per-family spec, not the JSON
  # string written here, so a read-compare would always diff. Disable read; no drift
  # detection here.
  disable_read         = true
  ignore_absent_fields = true

  # families is a JSON STRING the plugin unmarshals into {family: capability-spec};
  # an invalid value is rejected at apply (a ceiling must permit at least one family).
  data_json = jsonencode({
    families = var.ceiling_families_json
  })

  lifecycle {
    precondition {
      condition     = var.ceiling_families_json != ""
      error_message = "ceiling_families_json is required when ceiling_tier is set."
    }
  }
}

# config/signing is intentionally absent from Terraform. The plugin requires role_id and
# secret_id in the same write, and managing that body here would persist secret_id in state.
# Complete the mandatory out-of-band write immediately after apply (README.md).
