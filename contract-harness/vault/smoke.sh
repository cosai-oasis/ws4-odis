#!/usr/bin/env bash
# Hermetic smoke for the apf-bundle-issuer: boot a dev Vault, provision,
# mint-then-load a signed bundle AS THE ROUTER (jwt login -> apf/issue), then verify
# the signature OFFLINE (no Vault token) and load it. Exits non-zero on any failure.
# Requires: a vault binary (ODIS_VAULT_BIN, PATH, or a sibling ../vault) and a built plugin.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"   # .../vault
HARNESS="$(dirname "$HERE")"            # harness root (holds src/, vault-plugin/, vault/)
export HARNESS
PLUGIN_DIR="$HARNESS/vault-plugin/dist"
# vault binary: ODIS_VAULT_BIN, else on PATH, else a sibling beside the harness dir (dev).
export VAULT="${ODIS_VAULT_BIN:-$(command -v vault || echo "$HARNESS/../vault")}"
export VAULT_ADDR="http://127.0.0.1:8200" VAULT_TOKEN="root"
export FIXDIR=/tmp/odis-fix

[ -x "$VAULT" ] || { echo "FAIL: vault binary not found at $VAULT (set ODIS_VAULT_BIN)"; exit 2; }
[ -x "$PLUGIN_DIR/apf-bundle-issuer" ] || { echo "FAIL: plugin not built (run: mise run build-vault-plugin)"; exit 2; }

# Refuse to run against a pre-existing Vault: the readiness poll below cannot
# tell our dev server from one already serving 8200, and provisioning must never
# write into an unrelated Vault.
if "$VAULT" status >/dev/null 2>&1; then
  echo "FAIL: something is already serving $VAULT_ADDR; stop it or change the address"; exit 2
fi
"$VAULT" server -dev -dev-root-token-id=root -dev-plugin-dir="$PLUGIN_DIR" \
  -dev-listen-address=127.0.0.1:8200 > /tmp/odis_smoke_vault.log 2>&1 &
VPID=$!
trap 'kill "$VPID" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  kill -0 "$VPID" 2>/dev/null || { echo "FAIL: vault exited early (see /tmp/odis_smoke_vault.log)"; exit 1; }
  "$VAULT" status >/dev/null 2>&1 && break
  sleep 0.5
done

bash "$HERE/provision.sh"

# Router caller leg: exchange the workload JWT for a token scoped to apf/issue, then issue.
TOKEN="$("$VAULT" write -field=token auth/jwt/login role=router jwt=@"$FIXDIR/jwt")"
# set -e does not abort on a failed $(...) assignment; check explicitly so a login
# regression fails here rather than as a misleading downstream error.
[ -n "$TOKEN" ] || { echo "FAIL: jwt login (router) returned no token"; exit 1; }
VAULT_TOKEN="$TOKEN" "$VAULT" write -format=json apf/issue jwt=@"$FIXDIR/jwt" > /tmp/odis_smoke_issue.json
"$VAULT" read -format=json transit/keys/apf-bundle > /tmp/odis_smoke_key.json

cd "$HARNESS" && uv run python - <<'PY'
import base64, json
from odis_harness.bundle.vault_verifier import VaultTransitSignatureVerifier
from odis_harness.bundle.loader import BundleLoader

key = json.load(open("/tmp/odis_smoke_key.json"))["data"]["keys"]["1"]["public_key"]
env = json.load(open("/tmp/odis_smoke_issue.json"))["data"]
payload, sig = base64.b64decode(env["payload"]), env["signature"].encode("ascii")

verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
    key_name="apf-bundle", public_keys_b64={1: key})
if not verifier.verify(payload, sig):
    raise SystemExit("FAIL: offline signature verification failed")
bundle = BundleLoader(signature_verifier=verifier).load_signed(payload, sig)
print(f"SMOKE PASS: Router issued + offline-verified bundle "
      f"{bundle.bundle_id!r} families={list(bundle.families)}")
PY
