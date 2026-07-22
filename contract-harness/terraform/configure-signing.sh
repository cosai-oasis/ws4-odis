#!/usr/bin/env bash
# Complete the plugin's config/signing after `terraform apply`, keeping the AppRole
# secret_id out of Terraform state, argv, and output. Re-runs ROTATE: after the new
# credential is delivered, every superseded secret_id is revoked (by accessor).
set -euo pipefail

: "${VAULT_ADDR:?set VAULT_ADDR to the Vault API address}"
: "${VAULT_TOKEN:?set VAULT_TOKEN to a token able to mint secret-ids and write the plugin config}"

# One state read instead of one `terraform output` process per value.
outputs=$(terraform output -json)
tf_out() { printf '%s' "$outputs" | jq -er ".$1.value"; }
transit_mount=$(tf_out transit_mount)
transit_key=$(tf_out transit_key_name)
approle_mount=$(tf_out approle_mount)
approle_role=$(tf_out approle_signer_role_name)
plugin_mount=$(tf_out plugin_mount)
plugin_vault_addr=${ODIS_PLUGIN_VAULT_ADDR:-$VAULT_ADDR}

role_id=$(vault read -field=role_id "auth/${approle_mount}/role/${approle_role}/role-id")

# Accessors of any PRIOR secret_ids, captured before minting: a successful
# reconfigure revokes them afterward (rotation, not accumulation).
prior_accessors=$(vault list -format=json \
  "auth/${approle_mount}/role/${approle_role}/secret-id" 2>/dev/null | jq -r '.[]' || true)

# Mint. Keep the secret_id in memory only; the accessor (non-secret) is what we
# may print or pass on argv for revocation.
minted=$(vault write -f -format=json "auth/${approle_mount}/role/${approle_role}/secret-id")
secret_id=$(printf '%s' "$minted" | jq -er '.data.secret_id')
secret_accessor=$(printf '%s' "$minted" | jq -er '.data.secret_id_accessor')
unset minted

# Until the credential is delivered to the plugin, ANY exit (failure or Ctrl-C)
# destroys it — and reports honestly when it cannot.
delivered=""
cleanup() {
  [[ -n "$delivered" ]] && return 0
  if vault write "auth/${approle_mount}/role/${approle_role}/secret-id-accessor/destroy" \
    secret_id_accessor="$secret_accessor" >/dev/null 2>&1; then
    echo "cleanup: destroyed the undelivered secret_id (accessor ${secret_accessor})" >&2
  else
    echo "WARNING: could not destroy the undelivered secret_id — revoke it manually:" >&2
    echo "  vault write auth/${approle_mount}/role/${approle_role}/secret-id-accessor/destroy secret_id_accessor=${secret_accessor}" >&2
  fi
}
trap cleanup EXIT

# jq builds the body (proper JSON escaping for every value); the secret travels
# via the environment and stdin, never argv (a process arg list is world-readable
# via /proc/<pid>/cmdline / ps).
SECRET_ID="$secret_id" ROLE_ID="$role_id" jq -n \
  --arg tm "$transit_mount" --arg tk "$transit_key" \
  --arg am "$approle_mount" --arg va "$plugin_vault_addr" \
  '{transit_mount:$tm, transit_key:$tk, approle_mount:$am,
    role_id:env.ROLE_ID, secret_id:env.SECRET_ID, vault_addr:$va}' \
  | vault write "${plugin_mount}/config/signing" - >/dev/null
delivered=1
unset secret_id

# Rotation: the plugin now holds the new credential; revoke every superseded one.
if [[ -n "$prior_accessors" ]]; then
  while IFS= read -r accessor; do
    [[ -z "$accessor" ]] && continue
    if vault write "auth/${approle_mount}/role/${approle_role}/secret-id-accessor/destroy" \
      secret_id_accessor="$accessor" >/dev/null 2>&1; then
      printf 'revoked superseded secret_id (accessor %s)\n' "$accessor"
    else
      printf 'WARNING: failed to revoke superseded secret_id (accessor %s) — revoke manually\n' \
        "$accessor" >&2
    fi
  done <<<"$prior_accessors"
fi

printf 'configured %s/config/signing (secret_id stayed outside Terraform state, argv, and output)\n' \
  "$plugin_mount"
