# Inputs for the apf-bundle-issuer Vault provisioning module.
#
# Defaults mirror the imperative `vault/provision.sh` (the source of truth) so a plan
# against a fresh Vault reproduces the same paths. The fixture-issuer defaults are
# demo material; for production, repoint `bound_issuer` / `bound_audiences` / `jwks`
# at SPIRE's OIDC discovery document (see vault/README.md) and set a real plugin
# `plugin_sha256` for the staged binary.

variable "transit_mount" {
  type        = string
  description = "Mount path for the transit secrets engine that holds the ed25519 bundle-signing key."
  default     = "transit"
}

variable "transit_key_name" {
  type        = string
  description = "Name of the ed25519 transit key used to sign APF bundles. The private half never leaves Vault (exportable = false)."
  default     = "apf-bundle"
}

variable "approle_mount" {
  type        = string
  description = "Mount path for the AppRole auth method the plugin logs into for a transit/sign-scoped token (the OSS signing path; WIF/GenerateIdentityToken is Enterprise-only)."
  default     = "approle"
}

variable "jwt_mount" {
  type        = string
  description = "Mount path for the JWT auth method backing the Router's caller leg (exchanges a workload JWT for a token scoped to apf/issue)."
  default     = "jwt"
}

variable "bound_issuer" {
  type        = string
  description = "The iss claim trusted on workload JWTs, shared by the jwt auth method, its router role, the plugin's config/issuer, and the mapping. For SPIRE, set this to the issuer configured on the server (jwt_issuer) — the value stamped into JWT-SVID iss claims, for which the OIDC Discovery Provider serves discovery."
  default     = "https://fixture.issuer.odis.local/"
}

variable "bound_audiences" {
  type        = list(string)
  description = "Dedicated bundle-issuance audience(s) required on workload JWTs, shared by the jwt router role, config/issuer, and the mapping."
  default     = ["apf-bundle-issuer"]
}

variable "jwks" {
  type        = string
  description = "Trusted issuer JWK Set (JSON), supplied to the PLUGIN's config/issuer to verify workload-JWT signatures. Required — without it the plugin has no trust material and refuses issuance. (The jwt auth method takes PEM keys via jwt_validation_pubkeys or an oidc_discovery_url, not a raw JWKS.) For SPIRE, set this to the served JWK Set; see vault/README.md."
  default     = ""

  validation {
    # Fail at plan, not midway through apply: config/issuer with an empty JWKS
    # would apply cleanly and then 5xx every issuance.
    condition     = length(var.jwks) > 0
    error_message = "jwks is required: the plugin's config/issuer needs the trusted issuer's JWK Set."
  }
}

variable "jwt_validation_pubkeys" {
  type        = list(string)
  description = "PEM-encoded public keys the jwt auth method trusts to verify workload JWTs (the fixture-issuer path: provision.sh passes jwt_validation_pubkeys=@pub.pem). Used only when oidc_discovery_url is empty. Leave empty for the SPIRE/OIDC path."
  default     = []
}

variable "oidc_discovery_url" {
  type        = string
  description = "OIDC discovery URL for the jwt auth method, used instead of jwt_validation_pubkeys for a served key set (e.g. SPIRE's OIDC Discovery Provider). When set, it takes precedence over jwt_validation_pubkeys for the jwt method."
  default     = ""
}

variable "plugin_mount" {
  type        = string
  description = "Mount path for the apf-bundle-issuer secrets-engine plugin (the issue / config / mappings surface lives under this path)."
  default     = "apf"
}

variable "plugin_name" {
  type        = string
  description = "Catalog name and mount type for the external secrets-engine plugin."
  default     = "apf-bundle-issuer"
}

variable "plugin_sha256" {
  type        = string
  description = "SHA-256 (hex) of the staged plugin binary, for the catalog registration. The operator must stage the binary in Vault's plugin_directory first and compute this (e.g. `sha256sum vault-plugin/dist/apf-bundle-issuer`). Empty skips CREATING the registration (for a plugin pre-registered out-of-band) — but changing a previously non-empty value to empty DESTROYS the module-managed catalog entry the live mount still needs; blank it only when removing the mount. After changing the hash, run `vault plugin reload` — re-registration alone does not swap the running binary."
  default     = ""
}

variable "plugin_command" {
  type        = string
  description = "Command (relative to Vault's plugin_directory) that launches the staged plugin binary, for the catalog registration."
  default     = "apf-bundle-issuer"
}

variable "secret_id_ttl_seconds" {
  type        = number
  description = "secret_id_ttl for the apf-signer AppRole role. Default 0 = non-expiring, a DEMO simplification matching provision.sh (the plugin holds one static secret_id with no re-fetch). Production should set a short TTL and rotate (e.g. response-wrapped secret_id delivery + a refresh loop)."
  default     = 0
}

variable "approle_token_ttl" {
  type        = number
  description = "token_ttl in seconds for the apf-signer AppRole role (the lifetime of each short-lived transit/sign-scoped token the plugin obtains)."
  default     = 600
}

variable "bound_subject" {
  type        = string
  description = "Exact sub claim the demo mapping matches (the workload's identity; a SPIFFE ID under SPIRE). Used as the mapping's bound_subject so it scopes to one workload rather than wildcarding."
  default     = "spiffe://example.org/agent/jira"
}

variable "mapping_name" {
  type        = string
  description = "Name of the identity->bundle mapping entry created under <plugin_mount>/mappings/."
  default     = "jira"
}

variable "bundle_json" {
  type        = string
  description = "The structured grant (JSON) to issue for workloads matching the mapping: a bundle envelope (bundle_id / bundle_version / trust_root_id, all required) plus, per family, its vendor_mcp endpoint, a capability spec (policy.rules — verbs + argument conditions + allowed fields), and a default_mode. Must declare at least one family. The plugin compiles policy.rules to Rego at issuance (Policy Projection); raw Rego is never accepted. Default mirrors vault/provision.sh's fixture grant (the jira-prod family)."
  default     = <<-EOT
    {"bundle_id":"odis-fixture-bundle","bundle_version":"0.1.0","trust_root_id":"fixture-trust-root","families":{"jira-prod":{"vendor_mcp":{"endpoint_id":"jira-prod-mcp-v1","url":"https://jira-prod-mcp.internal:8443/"},"policy":{"rules":[{"verb":"update_issue","where":[{"field":"issue_key","op":"startsWith","value":"APF-"}],"allow_fields":["labels"]}]},"default_mode":"strict"}}}
  EOT
}

variable "ceiling_tier" {
  type        = string
  description = "Optional tier-ceiling name — the apf_tier claim value an identity presents to select this cap, created under <plugin_mount>/ceilings/. Empty (the default) disables ceiling provisioning, so the assigned grant union is bounded only by what the mappings assign. A ceiling can only SHRINK authority (intersected against the union, deny-wins) and forces every family it caps to strict."
  default     = ""
}

variable "ceiling_families_json" {
  type        = string
  description = "The ceiling's maximum-permission spec (JSON): a map of family name to the MOST that tier may do, each a capability spec {\"rules\":[{\"verb\":...,\"where\":[...],\"allow_fields\":[...]}]}. The union is intersected against this; a family or field the ceiling omits is unreachable for the tier. Required when ceiling_tier is set (an empty/invalid value is rejected at apply). Example: {\"jira-prod\":{\"rules\":[{\"verb\":\"update_issue\",\"allow_fields\":[\"labels\"]}]}}."
  default     = ""
}
