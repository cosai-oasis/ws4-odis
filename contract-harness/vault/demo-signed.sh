#!/usr/bin/env bash
# `demo --signed` against a hermetic dev Vault.
#
# The middle rung of the demo ladder: same Router, same gate, same MCP transport and
# in-process vendor as `mise run demo` — the only difference is where the Authority Grant
# comes from and that its Ed25519 signature is verified offline, rather than by
# the fixture verifier. `demo-openshell` then adds the enforcing substrate on top.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"   # .../vault
# shellcheck source=lib/dev-vault.sh
source "$HERE/lib/dev-vault.sh"
boot_dev_vault

# The offline trust anchor: the transit public key, out of band. The Router never needs a
# Vault capability beyond apf/issue to verify with it.
# The key lives inside a `keys` map, so `-field` cannot reach it and this does need an
# interpreter. `uv run python`, matching smoke.sh and provision.sh — a bare `python3` is
# not guaranteed to exist on a machine provisioned only by `mise install`.
"$VAULT" read -format=json transit/keys/apf-bundle > /tmp/odis_demo_signed_key.json

cd "$HARNESS"
uv run python -c '
import json
key = json.load(open("/tmp/odis_demo_signed_key.json"))["data"]["keys"]["1"]["public_key"]
open("'"$FIXDIR"'/bundle-pubkey.b64", "w").write(key)
'

ODIS_VAULT_ADDR="$VAULT_ADDR" \
ODIS_VAULT_JWT_FILE="$FIXDIR/jwt" \
ODIS_BUNDLE_PUBKEY_FILE="$FIXDIR/bundle-pubkey.b64" \
  uv run odis-harness demo --signed
