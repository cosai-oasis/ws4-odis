#!/usr/bin/env bash
# Provision a running dev-mode Vault for the apf-bundle-issuer demo.
# Assumes a reachable, unsealed Vault (root token). Sets up, on OSS Community Vault:
#   - transit: a non-exportable ed25519 signing key (apf-bundle)
#   - approle (auth): role apf-signer, policy apf-sign granting ONLY transit/sign/apf-bundle
#                     (the plugin's OSS signing path; WIF/GenerateIdentityToken is Enterprise-only)
#   - jwt    (auth): role router, policy apf-issue granting ONLY apf/issue (the Router's caller leg)
#   - apf    (plugin): config/signing (+ role_id/secret_id), config/issuer (fixture JWKS), a mapping
# A fresh fixture workload JWT + JWKS + PEM are minted into $FIXDIR.
set -euo pipefail
: "${VAULT:?set VAULT to the vault binary}" "${VAULT_ADDR:?}" "${VAULT_TOKEN:?}" "${HARNESS:?set HARNESS to the odis-harness dir}"
# Fixture material includes a workload JWT (a credential): keep the dir private.
FIXDIR="${FIXDIR:-/tmp/odis-fix}"; mkdir -p "$FIXDIR"; chmod 700 "$FIXDIR"
ISSUER="https://fixture.issuer.odis.local/"
AUD="apf-bundle-issuer"
SUBJECT="spiffe://example.org/agent/jira"

# 1. Mint a fresh fixture workload JWT + the JWKS/PEM that trust it.
# ttl=30m (not the 5m default): the session-scoped pytest fixture reuses this one
# JWT across the whole requires_vault suite, and 5m can expire mid-run on a slow box.
( cd "$HARNESS" && uv run python - "$FIXDIR" "$ISSUER" "$AUD" "$SUBJECT" <<'PY'
import json, sys
from datetime import timedelta
from odis_harness.vault.fixtures import FixtureIdentityIssuer
d, issuer, aud, sub = sys.argv[1:5]
iss = FixtureIdentityIssuer.generate(issuer=issuer)
jwt = iss.mint(audience=aud, subject=sub, claims={"group": "jira-writers"}, ttl=timedelta(minutes=30))
open(f"{d}/jwt", "w").write(jwt)
open(f"{d}/jwks.json", "w").write(json.dumps(iss.jwks()))
open(f"{d}/pub.pem", "wb").write(iss.public_pem())
PY
) >/dev/null
chmod 600 "$FIXDIR/jwt"   # the JWT is a bearer credential; jwks/pub.pem stay public

# 2. transit signing key (ed25519, private half never leaves Vault).
$VAULT secrets enable transit >/dev/null 2>&1 || true
$VAULT write -f transit/keys/apf-bundle type=ed25519 >/dev/null

# 3. AppRole for the plugin's transit self-call: policy grants ONLY transit/sign/apf-bundle.
$VAULT auth enable approle >/dev/null 2>&1 || true
printf 'path "transit/sign/apf-bundle" { capabilities = ["update"] }\n' | $VAULT policy write apf-sign - >/dev/null
# secret_id_ttl=0 / secret_id_num_uses=0 → a non-expiring secret_id, because the
# plugin holds ONE static secret_id (no re-fetch). This is a DEMO simplification:
# production should issue short-TTL secret_ids and rotate them (e.g. response-wrapped
# secret_id delivery + a refresh loop), not copy this non-expiring credential.
$VAULT write auth/approle/role/apf-signer token_policies=apf-sign token_ttl=10m secret_id_ttl=0 secret_id_num_uses=0 >/dev/null
RID=$($VAULT read -field=role_id auth/approle/role/apf-signer/role-id)
SID=$($VAULT write -f -field=secret_id auth/approle/role/apf-signer/secret-id)

# 4. jwt auth for the Router caller leg: policy grants ONLY apf/issue.
$VAULT auth enable jwt >/dev/null 2>&1 || true
$VAULT write auth/jwt/config jwt_validation_pubkeys=@"$FIXDIR/pub.pem" bound_issuer="$ISSUER" >/dev/null
printf 'path "apf/issue" { capabilities = ["update"] }\n' | $VAULT policy write apf-issue - >/dev/null
$VAULT write auth/jwt/role/router role_type=jwt user_claim=sub \
  bound_issuer="$ISSUER" bound_audiences="$AUD" token_policies=apf-issue >/dev/null

# 5. The plugin: mount + signing config (role_id/secret_id) + issuer trust + a mapping.
$VAULT secrets enable -path=apf apf-bundle-issuer >/dev/null 2>&1 || true
# Pass role_id/secret_id via stdin JSON, not argv: a process arg list is world-
# readable (/proc/<pid>/cmdline, ps), so the secret_id must not appear there.
printf '{"transit_key":"apf-bundle","role_id":"%s","secret_id":"%s","vault_addr":"%s"}' \
  "$RID" "$SID" "$VAULT_ADDR" | $VAULT write apf/config/signing - >/dev/null
$VAULT write apf/config/issuer jwks=@"$FIXDIR/jwks.json" bound_issuer="$ISSUER" bound_audiences="$AUD" >/dev/null
cat > "$FIXDIR/bundle.json" <<'JSON'
{"bundle_id":"odis-fixture-bundle","bundle_version":"0.1.0","trust_root_id":"fixture-trust-root","families":{"jira-prod":{"vendor_mcp":{"endpoint_id":"jira-prod-mcp-v1","url":"https://jira-prod-mcp.internal:8443/"},"policy":{"rules":[{"verb":"update_issue","where":[{"field":"issue_key","op":"startsWith","value":"APF-"}],"allow_fields":["labels"]}]},"default_mode":"strict"}}}
JSON
$VAULT write apf/mappings/jira bound_issuer="$ISSUER" bound_audiences="$AUD" bound_subject="$SUBJECT" bundle=@"$FIXDIR/bundle.json" >/dev/null

echo "provisioned (fixture material in $FIXDIR)"
