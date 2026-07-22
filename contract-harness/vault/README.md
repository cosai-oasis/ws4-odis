# Swapping the workload-JWT issuer for SPIRE

The MVP trusts a **local fixture workload-JWT issuer** (a test signing key plus a
static JWKS that both Vault's `jwt` auth method and the `apf-bundle-issuer` plugin
trust). The production identity issuer is **SPIRE**: agents present **JWT-SVIDs**
served through SPIRE's **OIDC Discovery Provider**.

The swap is **configuration-only**. Repointing trust at SPIRE touches no
validate / map / sign code in the plugin — `backend/jwt.go`'s
`validateJWT` already verifies any standards-shaped JWT against the stored
issuer config. `backend/spire_internal_test.go` proves this: a JWT-SVID-shaped
token (SPIFFE-ID `sub`, OIDC-discovery `iss`, bundle-issuance `aud`) validates
through the unchanged path once the issuer config is repointed.

## What changes

Two trust anchors move from the fixture issuer to the SPIRE OIDC discovery
document at `https://<oidc-discovery-host>/.well-known/openid-configuration`
(JWKS at the advertised `jwks_uri`):

1. **The Vault `jwt` auth method** — set `bound_issuer` to the SPIRE OIDC
   discovery URL and point it at the discovery document's JWKS (`oidc_discovery_url`,
   or `jwks_url` for the served key set). This is the **OSS `jwt` auth path only**;
   the harness does **not** use the Enterprise SPIFFE/SVID auth method.

2. **The plugin's issuer config** (`config/issuer`) — set `bound_issuer` to the
   same SPIRE OIDC discovery URL and supply the discovery document's keys via
   `jwks` (the served JWK Set) or `jwks_pem` (PEM public keys). Leave
   `bound_audiences` as the dedicated bundle-issuance audience (e.g.
   `apf-bundle-issuer`) that JWT-SVIDs are minted against.

A SPIRE JWT-SVID then carries:

| Claim | Value |
| --- | --- |
| `iss` | the SPIRE OIDC discovery URL (e.g. `https://oidc-discovery.example.org`) |
| `sub` | the agent's SPIFFE ID (e.g. `spiffe://example.org/ns/agents/sa/jira-agent`) |
| `aud` | the bundle-issuance audience (e.g. `apf-bundle-issuer`) |

## What does NOT change

The validate / map / sign code path. The plugin verifies the SVID's signature
against the configured JWKS, checks `iss`/`aud`/`exp`, maps the SPIFFE-ID
subject to a bundle mapping, assembles the bundle, and transit-signs it —
exactly as it does for the fixture issuer. SPIFFE IDs are ordinary string
subjects to the matcher (`bound_subject` / `bound_claims`).

## Unresolved production question — agent SVID hand-off

**How the agent's real JWT-SVID reaches the Router is UNRESOLVED**.
This harness does **not** choose a mechanism. The two candidates:

- **Sidecar-mint** — a SPIRE-agent-backed sidecar mints the JWT-SVID and the
  agent reads it from a shared workload API socket / file.
- **OpenShell supervisor hand-off** — the sandbox supervisor obtains the SVID
  and injects it on the agent's behalf at egress.

**Caveat:** SPIRE attestation granularity (per-pod vs. per-container) decides
whether each agent container gets a **distinct** SVID or shares one with its
pod. Per-pod attestation collapses sibling-container identity; per-container
(or per-process) attestation preserves it. Which one applies — and therefore
which hand-off is sound — depends on the OpenShell / SPIRE deployment owners and
is **not decided here**.
