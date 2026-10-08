# PACT as a consumer of the ODIS registration record

Date: 2026-10-08
Status: draft for the 2026-10-14 WS4 call. Companion to [agent-manifest-trace-odis-mapping.md](agent-manifest-trace-odis-mapping.md). Discussion only: nothing here changes `ODIS.md`.

## Why this protocol

PACT 1.0 was published on 2026-10-06 (openpactprotocol/openpactprotocol, Apache-2.0, read at commit `838c6bd`). It lets a consumer's personal agent call a business ("Brand") over A2A 1.0 and act on the user's account. Its identity token proves only which platform is calling: PACT §3.3, "That a known personal agent is calling for someone it calls `sub`." One platform registration covers every user and every version of that platform's agent.

That is the gap the registration record fills. If ODIS is the place Agent Manifest content now lives, PACT is the first outside protocol that would consume it, and it tests whether the record works across a trust boundary rather than inside one organization.

## Role mapping

| PACT | Closest ODIS element | Fit |
|---|---|---|
| Personal agent platform | `record_issuer` of the 6.1 record for its agent; issuer of the 6.2 runtime credential | Partial. PACT has no record and no runtime credential. |
| Personal-agent JWT (§3.2): `iss`, `sub`, `aud`, `iat`, `exp`, ES256/RS256 | 6.2 credential presentation | Weak. No `registration_record_ref`, `runtime_instance_id`, `software_hash`, `attestation_evidence` or `holder_key_ref`. Bearer only. |
| Brand Provider | Layer 2 Delegation Service and the downstream target in one | Good. The Brand runs its own authorization server (§5.1). |
| Delegation token (§5.4) | Root 6.3 Delegation Record in bridge form | Partial, see below. |
| Receipt (§5.6): `grantId`, `user`, `pa`, `brand`, `scopesUsed`, `actions`, `ts` | No ODIS record. Audit evidence; TRACE side tracked in agentrust-io/trace-spec#483. | None in ODIS. |
| "Providers MAY disable a personal agent" (§3.1) | 6.1 `lifecycle_state`, revocation via SSF/CAEP (7.1) | PACT can only disable a whole platform. |

Delegation token to 6.3, field by field:

| PACT §5.4 claim | 6.3 field |
|---|---|
| `iss` (Brand authorization server) | `issuer` |
| `sub` (user id at the Brand) | `originating_principal` |
| `client_id` (platform issuer URL) | `actor`, but it names the platform, not an `agent_id` |
| `scope` | `granted_authorizations` |
| `aud` (Brand interface URL) | `resource_indicators` |
| `grant_id` | `originating_authorization_ref` grant identifier |
| `iat`, `exp` | `issued_at`, `expires_at` |
| none | `task_id`, `constraints`, `attenuation_profile_ref`, `binding_profile` |

## Proposed binding

PACT issue openpactprotocol#58 (filed 2026-10-08) proposes an optional claim on the personal-agent JWT so a Provider can tell which build is calling. As filed it carries `{uri, digest, media_type}`. If WS4 agrees, the claim would carry the same object 6.2 already defines as `registration_record_ref`:

```json
"agent_registration": {
  "record_issuer": "https://pa.example.com",
  "record_id": "urn:example:agent-record:7f3c",
  "record_version": 12,
  "record_digest": "sha256:<64 hex>"
}
```

A Brand that wants it resolves the record under the 6.1 resolution rule before it grants a write scope (`orders:cancel`, `booking:change`) and refuses if the record is `suspended` or `revoked`. A Brand that does not care ignores the claim, so PACT stays light. Revoking one record version stops one build, which is the per-deployment kill switch PACT lacks.

## Where it does not fit yet

These are the questions for 2026-10-14.

1. **Cross-domain resolution.** The 6.1 resolution rule says a resolver MUST "verify issuer authorization for the trust domain". A Brand is outside the platform's trust domain. Does ODIS define how an outside relying party establishes that authorization, or is that the cross-domain appraisal question in #20?
2. **Self-vouching.** The platform would be `record_issuer` for its own agent, so the record alone is the platform vouching for itself. The value to a Brand comes from 6.2 `attestation_evidence` appraised by a verifier the Brand trusts. Should a consumer profile require that evidence, or leave it to Brand policy per scope?
3. **Holder binding.** Both PACT tokens are bearer, and §3.2 says "Providers need not track replay." 6.2 requires `holder_key_ref`, and 7.1.1 lists TLS session binding, mTLS and DPoP. Can a profile accept bearer presentation, or is DPoP the floor?
4. **Agent, not platform.** PACT's `client_id` identifies the platform. 6.3 `actor` is an `agent_id`. Mapping one to the other needs the platform to issue a distinct `agent_id` per agent, which PACT does not ask for.
5. **Who states the requirement.** 6.1 `provider_entitlements` is held on the agent's side. In PACT the Brand would state, per scope, what it requires before granting. Is a relying-party requirement a profile field, or out of scope for ODIS?
6. **Receipts.** PACT receipts are signed only by the Brand and do not cover the reply text. ODIS has no record for executed actions; is that intentionally left to audit and TRACE?

## What this does not establish

No PACT implementation was run against an ODIS record. The field fits are proposals, and openpactprotocol#58 has not been discussed by the PACT maintainers.
