# Terraform + provider version constraints for the apf-bundle-issuer Vault module.
#
# The hashicorp/vault provider talks to a REAL (persistent, unsealed) Vault, not a
# `-dev` server. See README.md for scope, prerequisites, and the deliberate exclusions
# (the AppRole secret_id and the plugin binary are handled out-of-band, never via
# Terraform state).

terraform {
  required_version = ">= 1.5"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = ">= 4.0, < 5.0"
    }
  }
}
