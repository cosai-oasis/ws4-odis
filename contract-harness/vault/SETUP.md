# Configuring Vault for the `apf-bundle-issuer`

This is the prose companion to `vault/provision.sh`. It explains **how to stand up
Vault** so the `apf-bundle-issuer` plugin can mint and transit-sign APF Signed
Policy Bundles, and so the Router can request them — using **OSS (Community)
Vault only**. `provision.sh` automates every step below for a dev server; this
guide states what each step does and how to reproduce it against a real Vault.

For repointing trust from the local fixture issuer to **SPIRE**, see
`vault/README.md` — that swap is configuration-only and orthogonal to this
setup.

## 1. Concepts: the two credential legs

The flow has exactly two privileged legs, each scoped to the **one** capability
it needs. Nothing here uses a static long-lived bearer token, and neither leg
uses an Enterprise-only feature.

**Leg A — plugin → `transit/sign` (AppRole).** When the plugin signs a bundle it
calls `transit/sign/apf-bundle` on Vault. It authenticates with an **AppRole**
(`role_id` + `secret_id`) whose policy (`apf-sign`) grants **only**
`transit/sign/apf-bundle` and nothing else. The clean way to do this on a
plugin would be Vault's **plugin Workload Identity Federation**
(`GenerateIdentityToken`) — but that API is **Enterprise-only**. So the OSS path
is an AppRole: the plugin holds one `role_id`/`secret_id` pair and exchanges it
for a short-TTL token scoped to signing alone.

**Leg B — Router → `apf/issue` (`jwt` auth).** The Router does not hold a Vault
token. It presents the agent's **workload-identity JWT** to Vault's `jwt` auth
method, which validates the token (issuer / audience / signature) and returns a
token whose policy (`apf-issue`) grants **only** `apf/issue`. The Router uses
that token to ask the plugin to mint a bundle, then verifies the returned
signature **offline** — no Vault token is needed at gate time.

| Primitive | One line | Upstream doc |
|---|---|---|
| `transit` | Encryption/signing as a service; the private key never leaves Vault. | https://developer.hashicorp.com/vault/docs/secrets/transit |
| `approle` | Machine login via a `role_id` + `secret_id` pair → a scoped token. | https://developer.hashicorp.com/vault/docs/auth/approle |
| `jwt` auth | Validate an externally-issued JWT (iss/aud/sig) → a scoped token. | https://developer.hashicorp.com/vault/docs/auth/jwt |
| JWKS | The public JWK Set the `jwt` method (and the plugin) verify tokens against. | https://datatracker.ietf.org/doc/html/rfc7517 |

## 2. Prerequisites

- **A Vault OSS (Community) binary.** The harness resolves it as
  `ODIS_VAULT_BIN`, else `vault` on `PATH`, else a sibling `vault` placed beside
  the harness directory (`$HARNESS/../vault`) for dev convenience. Set
  `ODIS_VAULT_BIN` to be explicit.
- **`opa`** — the real OPA binary the Router uses to evaluate the bundle's Rego
  (resolved via `ODIS_OPA_BIN` / `PATH`). Not used by Vault itself, but needed by
  the end-to-end demo.
- **A Go toolchain** to build the plugin. `vault-plugin/dist/` is **gitignored**,
  so the binary ships in no clone — build it:

  ```bash
  mise run build-vault-plugin   # → vault-plugin/dist/apf-bundle-issuer
  ```

## 3. Dev-mode quickstart

```bash
mise run smoke-vault            # depends on build-vault-plugin
```

`smoke.sh` boots an ephemeral `vault server -dev` (root token `root`, listening
on `127.0.0.1:8200`), runs `provision.sh` against it, then **as the Router**
exchanges the fixture workload JWT via `auth/jwt/login` for a token scoped to
`apf/issue`, issues a bundle, verifies its ed25519 signature **offline** (no
Vault token), and loads it. It exits non-zero on any failure and tears the
server down on exit.

The dev server is launched with `-dev-plugin-dir=$PLUGIN_DIR`, which
**auto-registers** the plugin binary found there (no manual `vault plugin
register`). **This is a dev-only convenience** — a real Vault requires explicit
registration (section 5).

## 4. The configuration walkthrough (mirrors `provision.sh`)

Set the environment the commands assume, then run the steps **in order**. The
plugin must already be built (section 2).

```bash
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=root            # dev root token; a real Vault uses a real token
VAULT=${ODIS_VAULT_BIN:-vault}     # the binary to drive
ISSUER="https://fixture.issuer.odis.local/"
AUD="apf-bundle-issuer"
SUBJECT="spiffe://example.org/agent/jira"
FIXDIR=/tmp/odis-fix
```

**Step 0 — fixture trust material.** Mint a fresh **fixture workload JWT** plus
the JWKS/PEM that trust it into `$FIXDIR` (run from the harness directory; this
is exactly what `provision.sh` does first). In production these trust anchors
come from your real issuer (e.g. SPIRE), not the fixture — see `vault/README.md`.

```bash
mkdir -p "$FIXDIR" && chmod 700 "$FIXDIR"   # holds a bearer JWT — keep it private
uv run python - "$FIXDIR" "$ISSUER" "$AUD" "$SUBJECT" <<'PY'
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
chmod 600 "$FIXDIR/jwt"
```

**Step 1 — transit signing key (non-exportable ed25519).** The bundle is signed
by a key whose private half never leaves Vault. `type=ed25519` and the key is
not created exportable, so it cannot be read out.

```bash
$VAULT secrets enable transit
$VAULT write -f transit/keys/apf-bundle type=ed25519
```

**Step 2 — AppRole + `apf-sign` policy (signing only).** This is Leg A. The
policy grants **only** `transit/sign/apf-bundle`; the role issues tokens bound to
that policy. (`secret_id_ttl=0 secret_id_num_uses=0` makes a **non-expiring**
`secret_id` — a demo simplification; see section 6.)

```bash
$VAULT auth enable approle
printf 'path "transit/sign/apf-bundle" { capabilities = ["update"] }\n' \
  | $VAULT policy write apf-sign -
$VAULT write auth/approle/role/apf-signer \
  token_policies=apf-sign token_ttl=10m secret_id_ttl=0 secret_id_num_uses=0
RID=$($VAULT read -field=role_id auth/approle/role/apf-signer/role-id)
SID=$($VAULT write -f -field=secret_id auth/approle/role/apf-signer/secret-id)
```

**Step 3 — `jwt` auth + `apf-issue` policy + `router` role.** This is Leg B. The
`jwt` method is configured to trust the fixture issuer's public key and bound
issuer; the `apf-issue` policy grants **only** `apf/issue`; the `router` role
maps a validated JWT (matching `bound_issuer` / `bound_audiences`, keyed on
`sub`) to that policy.

```bash
$VAULT auth enable jwt
$VAULT write auth/jwt/config \
  jwt_validation_pubkeys=@"$FIXDIR/pub.pem" bound_issuer="$ISSUER"
printf 'path "apf/issue" { capabilities = ["update"] }\n' \
  | $VAULT policy write apf-issue -
$VAULT write auth/jwt/role/router role_type=jwt user_claim=sub \
  bound_issuer="$ISSUER" bound_audiences="$AUD" token_policies=apf-issue
```

**Step 4 — mount the plugin.** Mount `apf-bundle-issuer` at path `apf`.

```bash
$VAULT secrets enable -path=apf apf-bundle-issuer
```

**Step 5 — `config/signing` (Leg A wiring).** Hand the plugin the transit key
name and the AppRole credentials. **Pass `role_id`/`secret_id` as stdin JSON, not
as CLI arguments** — a process arg list is world-readable
(`/proc/<pid>/cmdline`, `ps`), so the `secret_id` must never appear there.

```bash
printf '{"transit_key":"apf-bundle","role_id":"%s","secret_id":"%s","vault_addr":"%s"}' \
  "$RID" "$SID" "$VAULT_ADDR" | $VAULT write apf/config/signing -
```

**Step 6 — `config/issuer` (the plugin's own JWT trust).** The plugin
independently validates the workload JWT it is asked to mint a bundle for. Give
it the issuer's JWKS, bound issuer, and bound audiences.

```bash
$VAULT write apf/config/issuer \
  jwks=@"$FIXDIR/jwks.json" bound_issuer="$ISSUER" bound_audiences="$AUD"
```

**Step 7 — a mapping.** A mapping ties a validated identity (issuer + audience +
subject) to the structured grant the plugin should mint a bundle from. The grant
JSON carries the bundle envelope and, per family, the Target MCP endpoint, the
structured policy spec (compiled to Rego at issuance), and the default mode.

```bash
# The structured grant: envelope, families, vendor_mcp, policy spec, default mode.
# (The wire field is named "bundle" for fixture/ops compatibility.)
cat > "$FIXDIR/bundle.json" <<'JSON'
{"bundle_id":"odis-fixture-bundle","bundle_version":"0.1.0","trust_root_id":"fixture-trust-root","families":{"jira-prod":{"vendor_mcp":{"endpoint_id":"jira-prod-mcp-v1","url":"https://jira-prod-mcp.internal:8443/"},"policy":{"rules":[{"verb":"update_issue","where":[{"field":"issue_key","op":"startsWith","value":"APF-"}],"allow_fields":["labels"]}]},"default_mode":"strict"}}}
JSON
$VAULT write apf/mappings/jira \
  bound_issuer="$ISSUER" bound_audiences="$AUD" bound_subject="$SUBJECT" \
  bundle=@"$FIXDIR/bundle.json"
```

At this point a caller can run Leg B end-to-end:

```bash
TOKEN=$($VAULT write -field=token auth/jwt/login role=router jwt=@"$FIXDIR/jwt")
VAULT_TOKEN="$TOKEN" $VAULT write -format=json apf/issue jwt=@"$FIXDIR/jwt"
```

## 5. Real (non-dev) Vault

A production Vault is not started with `-dev`. The plugin **auto-registration**
from `-dev-plugin-dir` does **not** apply — you register the plugin explicitly.
Vault must also be **initialized and unsealed** before any of section 4 runs.

Minimal `config.hcl` (file storage shown; swap in `raft` for HA):

```hcl
storage "file" {
  path = "/var/lib/vault/data"
}

# storage "raft" {
#   path    = "/var/lib/vault/raft"
#   node_id = "vault-1"
# }

listener "tcp" {
  address       = "0.0.0.0:8200"
  # TLS in production: point these at your real certificate material.
  tls_cert_file = "/etc/vault/tls/vault.crt"
  tls_key_file  = "/etc/vault/tls/vault.key"
}

plugin_directory = "/etc/vault/plugins"
api_addr         = "https://vault.internal:8200"
```

Place the built binary in `plugin_directory`, start Vault
(`vault server -config=config.hcl`), then `vault operator init` +
`vault operator unseal`. Register and mount the plugin:

```bash
vault plugin register \
  -sha256="$(sha256sum vault-plugin/dist/apf-bundle-issuer | cut -d' ' -f1)" \
  secret apf-bundle-issuer
vault secrets enable -path=apf apf-bundle-issuer
```

Then run section 4 steps 1–3 and 5–7 (step 4 is the `secrets enable` above)
against the real `VAULT_ADDR` / token, substituting your real issuer's JWKS, PEM,
issuer URL, audience, subject, and bundle for the fixture material. Stage that
real trust material in a **freshly created private directory you own** (e.g.
`FIXDIR=$(mktemp -d)`), never a fixed world-known path like `/tmp/odis-fix`: on a
shared host, a pre-created directory or world-readable files would let another
local user read the workload JWT or swap the trust anchors between write and use.

## 6. Production hardening

The demo trades several controls for simplicity. Before relying on this for
anything real:

- **Short-TTL, rotating `secret_id`.** The demo's AppRole `secret_id` is
  **non-expiring** (`secret_id_ttl=0 secret_id_num_uses=0`) because the plugin
  holds one static credential and never re-fetches. Production should issue
  short-TTL `secret_id`s and rotate them — e.g. response-wrapped `secret_id`
  delivery plus a refresh loop — never copy the non-expiring credential.
- **Rotate the transit key.** Periodically `vault write -f
  transit/keys/apf-bundle/rotate`; verifiers accept all non-revoked key versions
  (the offline verifier is keyed by version). Set `min_decryption_version` to
  retire old versions.
- **Revoke mappings.** Delete a mapping
  (`vault delete apf/mappings/<name>`) to stop the plugin minting bundles for
  that identity; tighten `bound_*` matchers to the narrowest identity that should
  receive each bundle.
- **Replace the placeholder Target MCP URL.** The fixture bundle points each family's
  `vendor_mcp.url` at a placeholder (e.g. `https://jira-prod-mcp.internal:8443/`).
  Set it to the real Target MCP endpoint, over TLS, before use.
