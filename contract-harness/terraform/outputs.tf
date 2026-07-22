# Outputs: mount paths, role names, and policy names only. No secrets are emitted
# (no role_id, no secret_id) — those are handled out-of-band post-apply (see README.md).

output "transit_mount" {
  description = "Mount path of the transit engine holding the ed25519 bundle-signing key."
  value       = vault_mount.transit.path
}

output "transit_key_name" {
  description = "Name of the ed25519 transit key used to sign bundles."
  value       = vault_transit_secret_backend_key.bundle.name
}

output "approle_mount" {
  description = "Mount path of the AppRole auth method (the plugin's transit self-call leg)."
  value       = vault_auth_backend.approle.path
}

output "approle_signer_role_name" {
  description = "Name of the AppRole role scoped to transit/sign on the bundle key (apf-signer)."
  value       = vault_approle_auth_backend_role.apf_signer.role_name
}

output "jwt_mount" {
  description = "Mount path of the jwt auth method (the Router's caller leg)."
  value       = vault_jwt_auth_backend.jwt.path
}

output "jwt_router_role_name" {
  description = "Name of the jwt role scoped to <plugin_mount>/issue (router)."
  value       = vault_jwt_auth_backend_role.router.role_name
}

output "plugin_mount" {
  description = "Mount path of the apf-bundle-issuer secrets-engine plugin."
  value       = vault_mount.apf.path
}

output "mapping_name" {
  description = "Name of the identity->bundle mapping entry created under <plugin_mount>/mappings/."
  value       = var.mapping_name
}

output "policy_sign_name" {
  description = "Name of the policy granting ONLY transit/sign on the bundle key (apf-sign)."
  value       = vault_policy.apf_sign.name
}

output "policy_issue_name" {
  description = "Name of the policy granting ONLY <plugin_mount>/issue (apf-issue)."
  value       = vault_policy.apf_issue.name
}
