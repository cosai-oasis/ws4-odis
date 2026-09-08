#!/usr/bin/env bash
# Hermetic smoke for the apf-bundle-issuer: boot a dev Vault, provision,
# mint-then-load a signed bundle AS THE ROUTER (jwt login -> apf/issue), then verify
# the signature OFFLINE (no Vault token) and load it. Exits non-zero on any failure.
# Requires: a vault binary (ODIS_VAULT_BIN, PATH, or a sibling ../vault) and a built plugin.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"   # .../vault
# Boot + provision live in one place so this and `demo-signed.sh` cannot drift.
# shellcheck source=lib/dev-vault.sh
source "$HERE/lib/dev-vault.sh"
boot_dev_vault

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
