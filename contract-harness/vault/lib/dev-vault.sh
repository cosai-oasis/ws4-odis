#!/usr/bin/env bash
# Boot a hermetic dev Vault with the apf-bundle-issuer plugin, and provision it.
#
# Sourced, not executed. Both `vault/smoke.sh` (issuance only) and
# `vault/demo-signed.sh` (issuance feeding a Router gate) need exactly this
# setup; it lives here so the two cannot drift on the readiness poll, the
# refuse-if-something-is-already-listening check, or the plugin directory.
#
# Exports HARNESS, VAULT, VAULT_ADDR, VAULT_TOKEN, FIXDIR. Installs an EXIT trap that
# kills the server, so a sourcing script inherits cleanup without repeating it —
# which means a caller must not set its own EXIT trap, since `trap` replaces.

boot_dev_vault() {
  local here harness plugin_dir vpid
  # Resolved from THIS file, not the caller's: the lib knows where it lives, and a
  # sourcing script in another directory must not silently repoint the plugin dir.
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"   # .../vault
  harness="$(dirname "$here")"
  export HARNESS="$harness"
  plugin_dir="$harness/vault-plugin/dist"
  # vault binary: ODIS_VAULT_BIN, else on PATH, else a sibling beside the harness dir (dev).
  export VAULT="${ODIS_VAULT_BIN:-$(command -v vault || echo "$harness/../vault")}"
  export VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="root"
  export FIXDIR=/tmp/odis-fix

  [[ -x "$VAULT" ]] || { echo "FAIL: vault binary not found at $VAULT (set ODIS_VAULT_BIN)"; exit 2; }
  [[ -x "$plugin_dir/apf-bundle-issuer" ]] || {
    echo "FAIL: plugin not built (run: mise run build-vault-plugin)"; exit 2; }

  # Refuse to run against a pre-existing Vault: the readiness poll below cannot
  # tell our dev server from one already serving 8200, and provisioning must never
  # write into an unrelated Vault.
  if "$VAULT" status >/dev/null 2>&1; then
    echo "FAIL: something is already serving $VAULT_ADDR; stop it or change the address"
    exit 2
  fi
  "$VAULT" server -dev -dev-root-token-id=root -dev-plugin-dir="$plugin_dir" \
    -dev-listen-address=127.0.0.1:8200 > /tmp/odis_dev_vault.log 2>&1 &
  vpid=$!
  # shellcheck disable=SC2064  # expand vpid now; the trap must outlive this function
  trap "kill $vpid 2>/dev/null || true" EXIT
  local ready=""
  for _ in $(seq 1 30); do
    kill -0 "$vpid" 2>/dev/null || {
      echo "FAIL: vault exited early (see /tmp/odis_dev_vault.log)"; exit 1; }
    if "$VAULT" status >/dev/null 2>&1; then ready=1; break; fi
    sleep 0.5
  done
  # `kill -0` only catches a server that died. One that starts and never becomes ready
  # exhausts the loop, and provisioning an unready Vault fails in a way that reads like a
  # plugin bug rather than a timeout.
  [[ -n "$ready" ]] || {
    echo "FAIL: vault did not become ready within 15s (see /tmp/odis_dev_vault.log)"; exit 1; }

  bash "$here/provision.sh"
}
