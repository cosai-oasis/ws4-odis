# ODIS conformance mapping

Where this implementation stands against the ODIS working draft
(`../../RFCs/ODIS.md`), requirement by requirement.

This is **not** a profile claim. Per ODIS §8.2, a component implementing a
subset of the layers "MAY be described only as a role-capability statement and
MUST NOT be represented as a profile claim." That is what this document is, and
describing a subset is the form's purpose, not a concession.

The harness implements part of Layer 3 and part of Layer 2, and consumes Layer 1
context from seams that are fixtures here. The Layer 2 half is easy to miss. The
Vault plugin validates a workload credential, resolves it to an authority an
operator delegated in advance, and narrows that authority semantically —
Delegation Service work under §3.2.

The signed bundle carries the delegation's **definition** —
§6.3's `granted_authorizations`, `resource_indicators` and `constraints`, at
argument granularity rather than as scope strings. What the bundle omits is the
delegation's **provenance**: it names no delegate, no delegating principal, and
no originating grant, so nothing downstream can say who delegated what to whom.
That half lives in Vault's storage and audit device and travels no further. The
Layer 2 rows below separate the two halves rather than averaging them.

ODIS is an unapproved contributor draft and this mapping tracks it as such. Where
the draft's structure and the harness's internal capability specs disagree, the
draft's requirement IDs are authoritative for this document.

## Status legend

| Status | Meaning |
|---|---|
| **met** | Implemented and covered by tests in this repository. |
| **partial** | Some of the requirement is implemented; the shortfall is named in the note. |
| **gap** | In scope for a role this document claims, not implemented. |
| **out-of-role** | Belongs to a role this document does not claim — a Layer 1 issuer, the Delegation Service functions listed under the declaration, or the sandbox. The harness consumes the result rather than producing it. |

"met" is a claim about *this* requirement only. It never implies profile
conformance, and several "met" rows are conditional on a deployment property
stated in the note.

## Role-capability declaration (ODIS §8.2)

```json
{
  "standard": "ODIS",
  "version": "unapproved-contributor-draft",
  "claim_target_id": "odis-contract-harness",
  "claim_target_version": "0.0.0",
  "claim_type": "role-capability",
  "components": [
    {
      "component_id": "odis-harness-router",
      "version": "0.0.0",
      "roles": ["Governance Checkpoint", "Tool/Service Discovery"],
      "integrity_ref": "source-tree"
    },
    {
      "component_id": "apf-bundle-issuer",
      "version": "0.0.0",
      "roles": ["Delegation Service", "Policy Projection", "Authority Grant Issuer"],
      "integrity_ref": "source-tree"
    }
  ],
  "layers_implemented": ["L2", "L3"],
  "trust_boundaries": ["tool-invocation"],
  "identity_technology": "other",
  "presenter_profile": "gateway",
  "key_custody": "remote-signer",
  "policy_engine": "opa",
  "maximum_agent_runtime_credential_lifetime_seconds": 300,
  "maximum_revocation_latency_seconds": null,
  "credential_reuse_ttl_seconds": 270,
  "revocation_check_mechanism": "none",
  "registration_record_authority": "other",
  "registration_resolution_method": "other"
}
```

**`profile` is intentionally absent.** §8.2 permits it only on a profile claim:
"For claim_type profile, profile MUST select exactly one of core, extended, or
safety. For claim_type role-capability, profile MUST be omitted." Its absence is
the required form here, not an unfilled field — adding `"profile": "core"` would
convert a legal role-capability statement into a profile claim that several Core
rows below immediately invalidate.

**`Delegation Service` is claimed for two of that role's five functions.** §3.2
gives it five: validate the Agent Runtime Credential, resolve it to an active
Agent Registration Record, evaluate originating-principal authorization context,
construct the Delegation Record, and enforce attenuation rules. The plugin does
the first and the last. ODIS-L2-14 states what stands between the mapping and an
ARR; ODIS-L2-05 states what stands between the issued bundle and a Delegation
Record. `Policy Projection` and `Authority Grant Issuer` are APF and local
vocabulary respectively, listed because no ODIS role covers policy issuance —
§3.4 places policy logic outside the standard on purpose.

`maximum_revocation_latency_seconds` is `null` and
`revocation_check_mechanism` is `"none"` because no revocation channel exists
(see ODIS-L3-04). Under §8.2's declaration rules those two values are by
themselves disqualifying for any profile claim, which is the honest position.

**Three template fields are omitted rather than filled**, because every value the
template offers would be an overclaim:

- `attestation_level` — the template offers only `software+runtime` or
  `software+runtime+hardware`. This component performs **neither**; software and
  runtime/workload attestation are Layer 1 obligations it does not implement
  (ODIS-L1-02, ODIS-L1-03).
- `delegation_wire_format` — no §6.3-complete Delegation Record is constructed or
  conveyed, so there is no wire format to declare. The Vault mappings are the standing
  form and never leave Vault; the Authority Grant that does travel is a policy bundle
  (ODIS-L2-05).
- `token_binding_method` — the template offers `tls-session-binding`, `mtls-cert`,
  `dpop` or `other`, and none applies: nothing here is holder-bound. Both the
  inbound agent credential and the leg-2 token the Bridge mints are plain
  bearers, validated but not bound to their presenter (ODIS-L1-09). `other`
  would read as a binding method this component does not have.

`key_custody: remote-signer` describes the bundle signing key, which never
leaves Vault. It does not describe an agent holder key, because there is none.

`identity_technology: other` is accurate rather than evasive. The template offers
`spiffe`, `did`, `cloud-native` or `other`; `serve --inbound-key` validates a
workload JWT against operator-supplied public keys with a bound issuer and
audience, which is the shape a SPIFFE JWT-SVID arrives in but is not tied to
SPIFFE — a SPIRE deployment configures it by pointing the same three settings at
SPIRE's OIDC Discovery Provider. Declaring `spiffe` would claim an integration
the component does not require and does not ship.

## Layer 1 — Identity & Attestation (§5.1)

The harness issues no Agent Runtime Credential. `substrate/identity.py` defines
the `WorkloadIdentityProvider` / `OriginatingPrincipalProvider` Protocols that a
Layer 1 issuer would satisfy, and ships fixtures behind them.

| ID | Profile | Status | Note |
|---|---|---|---|
| ODIS-L1-01 | Core | partial | The Router holds no static provider bearer, and `vendor_http.py` defaults `auth=None`; the optional Bridge mints short-lived audience-scoped tokens. The agent-to-Router leg now authenticates too: `serve --inbound-key` makes the MCP surface an OAuth 2.1 resource server that validates a workload JWT (signature, issuer, audience, expiry, asymmetric-algorithm allowlist) before any handler runs, and `agent_id` comes from the verified subject. Without `--inbound-key` the surface still accepts any caller, which the startup banner states outright. This row scores **verification only** — nothing in the harness hands an agent a credential, by design. On an OpenShell substrate the credential reaches the agent as a placeholder the egress proxy substitutes, so the agent never holds it, which is the L1-01 shape; see Deliberate omissions. |
| ODIS-L1-02 | Core | out-of-role | No software attestation. A Layer 1 issuer's obligation. |
| ODIS-L1-03 | Core | out-of-role | No runtime/workload attestation; `FixtureWorkloadIdentityProvider` stands in. |
| ODIS-L1-04 | Extended | out-of-role | No hardware attestation. |
| ODIS-L1-05 | Core | partial | The fixture workload JWT and the exchanged leg-2 token are both 5-minute TTL with automatic re-mint before expiry (`bridge/exchange.py`). An inbound agent credential must carry `exp` (pyjwt `require`), and is refused once past it plus 60s of clock leeway matching the Vault plugin's — but the Router only *enforces* a lifetime, it does not bound one: whatever TTL the issuer chose is the TTL, and no maximum is imposed. |
| ODIS-L1-06 | Core | out-of-role | No registration-record lifecycle. |
| ODIS-L1-07 | Extended | out-of-role | No federated trust. |
| ODIS-L1-08 | Core | out-of-role | No supply-chain gate on identity issuance. |
| ODIS-L1-09 | Core | gap | Nothing is holder-bound. Both legs present bearers: the inbound agent credential `serve --inbound-key` validates, and the leg-2 token the Bridge mints. Each is checked for signature, issuer, audience and expiry, and none is bound to its presenter — a stolen one replays until it expires. Proof-of-possession needs DPoP or mTLS binding, which is not implemented. |
| ODIS-L1-10 | Core | gap | Nothing here is a sponsor. L1-10 wants the point where the accountability chain terminates in something nameable and lifecycle-managed: §6.1's `sponsor_ref` on a durable Agent Registration Record, with ownership-change, departure and drain semantics attached. What the harness has is `OriginatingPrincipal(id="fixture-principal", type="entra_oidc")`, minted per call — an authentication source, which puts it in the **originating-principal** slot (§6.3), not the sponsor one. There is no registration record, no lifecycle state, and no drain. The one property that holds — that the value comes from a provider and never from agent input — belongs under ODIS-L2-05 / ODIS-CC-02 instead, and is now named `originating_principal` accordingly. `sponsor_ref`/`owner_ref` are not carried on the Vault mapping: the grant envelope is bundle-scoped while grants compose per family, so a union of mappings has no coherent owner for the field (see the underdetermined section). The nearest accountability the system has is the operator who writes a mapping — sponsor-shaped, originating-principal-shaped, or both, which §6.3 leaves open for a headless agent (see the underdetermined section). That operator is recorded: `mappingEntry.DelegatingPrincipal` is derived from the authenticated write request and `stampDelegation` carries it into the signed grant as `originating_principal`. It does not satisfy this row — there is no sponsor, no registration record and no drain — but it is the accountability reference ODIS-L2-05 depends on. |
| ODIS-L1-11 | Core | out-of-role | No attestation-bootstrapped issuance. |
| ODIS-L1-12 | Core | gap | No runtime-risk or compromise signal is consumed, and the envelope declares no such input — every property `odis.authz.request.v1` and `odis.runtime.context.v1` declare is required and populated, at the top level and inside every `$defs` shape (`test_total_envelope_declares_no_optional_input`). So the envelope cannot acquire another declared-but-unsupplied input, which is how both dead fields arrived. Consuming is SHOULD, and §6.4 types `runtime_risk_signals` as authenticated signal objects the checkpoint MUST validate for issuer trust, integrity, replay resistance, freshness and subject correlation before use; there is no signal authority here to validate against. The consequence half is out of reach for a second and harder reason: a confirmed signal MUST reject or revoke the affected credential, invalidate cached or derived credentials per ODIS-L2-11 and ODIS-L3-04, and require re-attestation before a new Agent Runtime Credential is issued. This target issues no Agent Runtime Credential and declares `revocation_check_mechanism: "none"`, so ODIS-L3-04 is the blocking dependency, not a field. `additionalProperties: false` also means a signal the checkpoint cannot validate has no route into the envelope at all (`test_authz_request_rejects_a_detector_verdict_field`). |

## Layer 2 — Delegation & Access (§5.2)

This is where the harness's actual contribution sits, and where the mapping is
least obvious. Two components answer here. The **Router** is an authorized
presenter enforcing approved authority before forwarding (L2-10, L2-13). The
**Vault plugin** validates a workload credential, resolves it to an entitlement,
and narrows that entitlement semantically (L2-02, L2-06, L2-14).

One fact runs through every row. An operator writing a Vault mapping **is**
delegating — they hold the authority to grant, they grant a bounded subset, and
the agent acts within it. L2-02 recognises the shape and calls it
"pre-authorized delegation". What no artifact captures is *that this happened*:
`mappingEntry` records no author, and the issued bundle names neither the
delegating principal nor the grant it derives from. So the requirements about
performing a delegation score, and the requirements about recording, bounding and
refreshing one do not.

Two shortfalls follow, and both are properties of the delegation rather than
evidence against it. The operator's authority is checked once, at write time,
where L2-01 requires effective authority to intersect the principal's **current**
authority — so an operator with write access to `apf/mappings` can confer
authority they do not personally hold. And nothing refreshes the mapping, so
L2-07's re-verification has no refresh point to attach to — the mapping does
expire, but authority lapses at the bound rather than being re-checked there.

For a headless pre-authorized agent the operator is a candidate for both of the
roles §6.3 separates — §6.1's accountable `sponsor_ref` and §6.3's
`originating_principal`, "distinct from the agent's accountable sponsor or
owner". The draft does not say which, and that ambiguity is recorded under
"Where the draft is underdetermined".

| ID | Profile | Status | Note |
|---|---|---|---|
| ODIS-L2-01 | Core | partial | The Vault plugin computes an effective-authority intersection at issuance — assigned mappings unioned, capped by the tier ceiling, failing closed on an empty result. That is L2-01's mechanism over **two** of the six inputs it names; the missing four are the originating principal's current authority, an active ARR, a parent Delegation Record, and the requested task. The originating principal — the operator who wrote the mapping — is not *captured* anywhere the intersection could reach it: `mappingEntry` has no author field, so their current authority cannot be consulted at issuance. Nothing in the issuance request supplies a second identity either; `VaultBundleClient` presents the **same** workload JWT as both its Vault login and the bundle subject, so at request time caller and subject are one identity. The Bridge separately performs an RFC 8693 exchange recording the delegation shape (`sub=odis-router`, `act.sub=<agent>`, RFC 8707 audience). |
| ODIS-L2-02 | Core | partial | L2-02 accepts "pre-authorized delegation" as a bounded-authorization mechanism for headless agents, and a Vault mapping is one: an operator pre-authorizes an identity's families and argument constraints, and the agent then runs unattended inside them. Of the six bindings L2-02 requires of an approval, the mapping carries three — requested authority (the grant), resource audience (`vendor_mcp`), and constraints (the DSL rules). Absent: the Agent Registration Record, a task, and an expiry. The deeper shortfall is that the approval is a *configuration row* rather than an artifact, so no action can carry a reference to the approval that authorized it — which is what would let ODIS-CC-02 name an originating principal for a headless agent. |
| ODIS-L2-03 | Core | partial | Three parts, scoring differently. **Manage expiry, refresh and re-authorization** — the mechanism exists on both credentialed paths: `BridgeAuth` manages expiry, re-mints under a lock and retries once on a vendor 401/403, and `--oauth2` delegates the same lifecycle to the SDK's OAuth provider. Both manage the *Router's* leg-2 credential, where L2-03 says "on behalf of the agent" — the agent's own credential is refreshed by the agent or its substrate, not here. **Fail closed** — met for refresh failure; the revocation limb cannot fire at all, since no revocation channel exists (ODIS-L3-04). **Must not override expiry, attenuation, approval, registration or revocation constraints** — vacuous, as no approval, registration or revocation constraint exists to override. All of it is conditional on `--bridge` or `--oauth2`; the default posture holds no credential, so there is no session to continue. |
| ODIS-L2-04 | Extended | partial | A mapping is a pre-authorization window in L2-04's sense: authority applies without new human interaction for as long as the mapping stands, and the window is now bounded — `valid_until` on the mapping record, `expires_at` on the issued grant. What falls short is the **auto-refresh** the requirement asks for. Nothing re-issues: the Router holds one grant for the process lifetime, and past `expires_at` every call is refused rather than a fresh grant obtained. Bounding the window created the refresh point ODIS-L2-07's re-verification would attach to, and left it unoccupied — which is also why L2-07 is never reached rather than performed. |
| ODIS-L2-05 | Core | partial | The definition is modelled and the provenance now largely is, but the binding is recorded rather than enforced. Of §6.3's thirteen named minimum fields the issued grant carries six by name — `actor` (the validated JWT subject), `originating_principal` (single-valued, so a grant composed from two delegating operators has nowhere to put the second and issuance refuses that composition), `attenuation_profile_ref`, `issued_at`, `expires_at`, and `delegation_chain` (present and constrained empty: this issuer mints root records only, so `[]` asserts a single hop where absence asserts nothing, and a claimed hop is refused). Three more are carried structurally rather than under their §6.3 names: `granted_authorizations` as the per-family policy rules, `resource_indicators` as `vendor_mcp.endpoint_id` plus the family names, `constraints` as the DSL conditions, `allow_fields` / `action_limits` and the validity window. `delegation_id` and `issuer` are `bundle_id` and `trust_root_id`. They are deliberately not duplicated under §6.3 names: two representations of one authority can disagree, and the signature would cover both. The invariant that matters most holds — integrity protection by the issuer, an Ed25519 transit signature over canonical bytes — and it is what protects the two fields `policy_digest` deliberately excludes, `issued_at` and `expires_at`: a digest covering them would change every re-issuance and stop identifying a policy. The recorded `originating_principal` is the writing operator's Vault identity entity, or that token's accessor when no entity is attached, since a bare display name is `"token"` for every entity-less token and could not distinguish two delegators. **What is absent, and why.** `task_id`: issuance happens once at Router startup rather than per task, and `task_intent` is per-call and agent-supplied, so it cannot fill this. `originating_authorization_ref`: §6.3 defines it as the reference to the authoritative grant that authorized the delegating principal *to delegate*, and the plugin holds no reference to whatever approved an operator's Vault policy, so it stays unset rather than carrying a different object under its name — the mapping records that did confer the grant travel under the local name `contributing_records` (each with name, version and content digest). **The load-bearing shortfall is that `actor` is unenforced.** Nothing in the Router reads it: the grant names the identity it was issued to, but no code checks the caller against that name, and a projected policy cannot either — `policydsl` emits references to `input.verb` and `input.request_body` only, so it cannot reach the `input.subject` the Router does supply. So the misconfiguration class survives recording it: a Router pointed at a grant issued for a different identity enforces it faithfully and reports nothing amiss. A second difference is positional. §6.4 puts `delegation` in the engine's **input** beside `action`, while here `family.policy` is handed to OPA as its **policy module**. The draft standardizes neither a policy language nor where composition runs, so this is not a violation; what it costs is late narrowing, since nothing arriving after issuance can shrink a decision. The expiry check is the one exception, and it is enforced in the Router rather than in policy. |
| ODIS-L2-06 | Core | met | Split by clause, because the requirement has three. **"Lexical scope-string subset is not sufficient unless semantic equivalence is proven"** — met in substance, and this is the hard clause: `applyCeiling` with `policydsl.Intersect` narrows on five axes (family, verb, field, condition, default mode) over structured typed rules, with no scope strings anywhere. **"Unknown, lossy, unsupported, or indeterminate comparisons MUST fail closed"** — met: the condition operator set is closed and an unrecognised op fails at compile time; a verb whose grant and ceiling field sets are disjoint is *dropped* rather than emitted with an empty `allow_fields`, which would read as unrestricted downstream and widen; a family reduced to zero rules is dropped rather than left an unpoliced passthrough; a kept family is forced to `strict`. **"MUST apply the immutable, versioned normalization and comparison rules identified by `attenuation_profile_ref`"** — now met: the grant names `urn:odis:contract-harness:attenuation-profile:v1` with a sha256 digest, and the profile document is `go:embed`ed and returned by `policydsl.AttenuationProfile()`, so a verifier resolves the URI to those bytes and confirms the digest. Changed rules mint a new version rather than mutating this one. The requirement's evidence clause — naming the authorization and constraint classes supported and the exact profile ref implemented — is satisfied by that URI plus the five axes above; no Provider Adapter Capability Manifest exists, and the draft does not require one. Two honest caveats that do not change the verdict: the axis differs, since a tier ceiling is an operator-set bound rather than a parent→child delegation hop, and coverage is unit-level (`ceilings_internal_test.go`, `intersect_internal_test.go`, `issue_internal_test.go`) — no runnable demo provisions a ceiling, so the narrowing is tested but not demonstrated. |
| ODIS-L2-07 | Core | gap | A durable pre-authorization does exist (ODIS-L2-04), so this requirement applies — and it is unmet in the way that matters. The mapping now expires (`valid_until`) and a suspended record stops conferring authority, so the window is bounded; but nothing refreshes it, so the moment L2-07 attaches its re-verification to still never arrives, and the operator's authority is checked exactly once, at write time. Bounding it does narrow the exposure — authority lapses on its own rather than persisting indefinitely — which is why this is a gap in the re-verification rather than in the window. |
| ODIS-L2-08 | Core | **met** | The Target MCP is unmodified and consumes no ODIS-native claim; it keeps its own provider credential and native auth. This is the design's central premise and it satisfies L2-08 directly. |
| ODIS-L2-09 | Core | partial | The bundle's `families → vendor_mcp + tools` map is the explicit ODIS-authority-to-target mapping, is versioned, and is bound into `policy_digest` so policy and routing cannot be mixed and matched. It is not expressed as provider-native scopes or roles. |
| ODIS-L2-10 | Core | **met, conditional** | No credential is ever issued to the agent or any model-visible process, and the Router enforces the approved resource/action/argument semantics *before* forwarding. This holds **only if the Target MCP is inside the declared conformance boundary**; against a third-party Target MCP the credential sits outside ODIS control and the claim does not hold. |
| ODIS-L2-11 | Core | **gap** | Both credentialed paths reuse: `BridgeAuth` serves a cached token with a 30s freshness leeway, and `--oauth2` reuses whatever the SDK holds in `InMemoryOAuthTokenStorage`. L2-11 permits reuse only under conditions none of which hold. Its closing sentence is unambiguous: "If the target does not declare a maximum revocation latency, or if the next mandatory revocation-state check cannot be determined, credential reuse MUST be disabled." No Target MCP here declares a revocation latency, and `revocation_check_mechanism` is `none`, so both limbs bind and reuse must be off — yet it is on. The declaration does state `credential_reuse_ttl_seconds: 270` as required, but a declared TTL does not satisfy a requirement to disable the behaviour. Scored a gap rather than partial for that reason. |
| ODIS-L2-12 | Core | partial | The presenter is the Router, and the agent never holds or substitutes the leg-2 credential. The Router itself is not attested, so "same attested component" is unproven. |
| ODIS-L2-13 | Core | **met** | The strongest mapping in the harness. The model-visible path gets no generic signing or proof-construction interface; every request is validated against policy, declared action limits, and routing before anything is forwarded, and every indeterminate state fails closed (`policy_error`, `invalid_rego_result`, `unenforceable_tool`, `unpoliced_tool`). |
| ODIS-L2-14 | Core | partial | The *function* the requirement protects is performed — authority is never issued to an identity holding no assigned mapping, and every indeterminate resolution fails closed — and the word **active** now has something to check. `mappingEntry` carries `lifecycle_state`, `valid_until` and a monotonic `record_version`, enforced at resolution: a suspended or expired record stops conferring authority, and `assignRecordVersion` refuses a replayed older version, which is §6.1's rollback detection for a record rewound against its own floor — not for a whole-backend snapshot restore, which rewinds the floor in lockstep and is out of reach without an anchor outside this storage. The vocabulary is also only what is enforced: `suspended` is a reversible pause, `revoked` is terminal and cannot be rewritten to any other state, and there is no `pending`, because nothing would have written it. What remains is that the record is still not an Agent Registration Record. It holds `bound_issuer` (≈ `approved_runtime_issuers`) and the grant (≈ `policy_profile_ref` and `provider_entitlements`, inline rather than by reference) plus the three lifecycle fields, and little else of §6.1's sixteen MUSTs. `bound_subject_prefix` still matches a whole subtree, so one mapping serves many agents where an ARR is keyed to a single `agent_id`; the resolution therefore verifies that *some* permitted identity asked, not that *this* agent is registered. `approved_software_refs` waits on Layer 1 to put a provenance claim in the credential. Covered by `lifecycle_internal_test.go` and `path_mappings_internal_test.go`. |
| ODIS-L2-15 | Core | met | `vendor_mcp.egress_mode` declares `native` or `bridge` per target. Issuance writes it for every family and `validateVendorMCP` rejects any other value, so the declaration always exists and cannot be unrecognised; the Python `VendorMcp` re-validates on construction and a document that omits it inherits `bridge`. This harness is `bridge` throughout, which is the mode L2-15 requires whenever the target does not itself validate the agent's runtime credential and delegation record — the vendor MCP server authenticates the Router's leg, not the agent's. The declaration is a statement about this deployment, not a switch, and this issuer will not sign the other value: `native` asserts that the target independently validates the agent's runtime credential and delegation record, which nothing here does, so writing it is refused rather than signed. That keeps the field from becoming the declared-but-unenforced kind — a consumer trusting a signed `native` would skip adapter-side enforcement that does not exist. |

## Layer 3 — Discovery & Governance (§5.3)

| ID | Profile | Status | Note |
|---|---|---|---|
| ODIS-L3-01 | Extended | **met** | `discovery.py` aggregates a family-prefixed catalog and filters it per family posture — governed tools are advertised, ungoverned ones are withheld in strict mode. |
| ODIS-L3-02 | Extended | **met, qualified** | `Router.forward` is a single chokepoint every entry point converges on: policed-tool gate → OPA decision → action limits → forward, auditing every refusal before raising. Qualified because the identity it evaluates is **synthesized at the checkpoint** rather than received (see ODIS-L1-01). |
| ODIS-L3-03 | Core | gap | No rate limiting of any kind, per-agent or per-tool. Core MUST. |
| ODIS-L3-04 | Core | gap | No revocation channel: nothing authenticates, correlates or propagates a revocation event, so the 300-second bound has nothing to measure. A grant now carries `issued_at` / `expires_at` and the Router refuses every call once `expires_at` has passed — checked before the policed-tool branch, so a `permissive` family cannot bypass it — which closes the narrower defect that a grant was immortal and held for the process lifetime. That is expiry, not revocation: it bounds how long a grant *can* be used, and says nothing about withdrawing one early. There is still no reload, so a grant revoked at the issuer keeps authorizing until it expires or the process restarts. Core MUST. |
| ODIS-L3-05 | Core | gap | No kill switch. Core MUST. |
| ODIS-L3-06 | Core | partial | Policy-engine integration is engine-agnostic in the right way: an `opa eval` subprocess over per-family Rego, off the event loop, default-deny on any malformed result. The input now carries `subject` (agent + originating principal) and `policy_digest`, so a policy can condition on who is calling. The requirement's first MUST — emit the §6.4 identity-context object — is unmet, and that is the operative gap. Most of it is ordinary work: `action` is a reshape, `request_timestamp` and `request_trace_id` are already carried, and `agent_registration` is a storage path this target could build since it declares Layer 2. `agent_runtime` is the piece that cannot be closed here — §6.2 wants `software_hash`, `attestation_evidence`, `holder_key_ref` and `runtime_instance_id`, which need attestation and holder binding rather than fields. See the underdetermined section; its second, delivery to an "external or co-located" decision point, is satisfied by a co-located `opa eval`. Organization-specific policy logic is present, in the operator-set tier ceiling that the projected Rego is intersected with, so the shortfall is the missing emission rather than an absent policy layer. What is emitted is still not the §6.4 Identity Context: `agent_registration`, `agent_runtime` and `delegation` are MUST objects this harness does not hold, and the draft defines no interface by which a Layer-3 component would receive them. The shortfall is expressive, not cosmetic: because the delegation arrives as OPA's policy module rather than in `input`, no rule can condition on the delegation's expiry, its originating principal's current status, or a runtime risk signal — the same root cause that leaves ODIS-L1-12 a gap. The validity window is the one such constraint that is enforced, and it is enforced by the Router before policy runs rather than by a rule. A further limit on how much the envelopes guarantee: only `odis.audit.event.v1` and `odis.bundle.v1` are validated on the live path (`audit/sink.py`, `bundle/loader.py`). `from_dict`, the only validating constructor for the runtime context and the authz request, is called nowhere in `src/`, so those two schemas are enforced against test-authored payloads and, via `test_router_built_authz_request_validates_against_its_schema`, against the Router's own output — but not at runtime. See the underdetermined section. §6.4's return contract `{decision, reason, obligations}` also differs from ours: our `reason_code` is a typed vocabulary the draft does not define, and our `obligations` is an object where §6.4 types it an array. |
| ODIS-L3-07 | Extended | partial | `task_intent` is carried on the runtime context and the authz request and **is** passed into the OPA input, so a policy could evaluate it. No shipped policy does, and the authz schema describes it as "informational, not policy-evaluable" — the schema and the code disagree. |
| ODIS-L3-08 | Extended | **met in enforced mode only** | The OpenShell example makes the Router the agent's only network path, so the boundary is independently enforceable. Without a sandbox that blocks the agent's direct network access the gate is advisory, and the README says so. |

## Cross-cutting (§5.4)

| ID | Profile | Status | Note |
|---|---|---|---|
| ODIS-CC-01 | Core | partial | Every decision is logged as one schema-validated JSON line, and the identifier now spans the checkpoint and the adapter: `call_tool` carries the Router's `correlation_id` and `HttpMcpClient` sends it as the `ODIS-Request-Trace-Id` header, so the id on the audit event is the one the Target MCP receives — asserted as an identity rather than as presence, since an id that arrived but differed would correlate nothing. Envelopes also carry the loaded grant's `bundle_id`, `bundle_version` and `trust_root_id` instead of `STUB_*` constants, so an event names the authority actually in force. Two shortfalls remain. The trail is **not tamper-evident** — plain JSONL, no chaining or signing. And it does not join the substrate's: OpenShell logs its own connection decisions with no `correlation_id` and the Router's events carry nothing OpenShell records, so two logs describe one call with no shared identifier, where CC-01 asks for identifiers spanning the agent, the checkpoint and the adapter. The agent end is the missing link, not the adapter end. |
| ODIS-CC-02 | Core | partial | Every forwarded or refused call names the logical agent and the authenticated originating principal, under `extra.actor` and in the envelope's `user_id`. Two event classes carry no actor, both correctly: `discovery_failed` belongs to no agent call, and a refusal at the protocol boundary fires before routing resolves a family, where minting an identity would mean calling the providers on agent-controlled input that is already being rejected. The third mandatory identity — the **executing runtime instance** — is absent. A validated credential now names the agent, but its subject identifies the workload, and nothing extracted from it distinguishes this run from the agent generally; recorded as absent rather than filled with a placeholder. The agent entry carries how it was established (`verified_bearer` vs `fixture_workload_identity`), so a reader can tell a received identity from an asserted one. The principal itself is still fixture-sourced (see ODIS-L1-01). |
| ODIS-CC-03 | Core | gap | No latency benchmark published. |
| ODIS-CC-04 | Core | gap | No availability objective published. |
| ODIS-CC-05 | Core | out-of-role | No Agent Registration Record exists (ODIS-L2-14), so there is nothing whose creation this could govern. The nearest analogue is governed: writing `apf/mappings/<name>` requires a Vault token carrying the write policy, so an agent cannot confer authority on itself, and Vault's own audit device records the write. That is the property CC-05 protects, applied to a mapping rather than to a registration record. |
| ODIS-CC-06 | Core | met | Mode-dependent, and met on every mode where the requirement applies. In the default posture the harness performs no terminal exchange — the Target MCP owns its credential — and CC-06 does not apply. Under `--bridge` and `--oauth2` it does, and both legs now emit `odis.bridge.terminal_exchange` (registered in `audit_taxonomy`) binding the grant in force (`policy_digest`, `bundle_id`, `bundle_version`, `trust_root_id`), the target's stable `endpoint_id` rather than a URL, and a sha256 fingerprint of each credential artifact. CC-06 permits an identifier, handle or fingerprint and forbids the raw secret, so the seam takes only handles and a secret cannot reach it. The anchor is a **required constructor argument** on both mechanisms, so a credential that could not be recorded cannot be minted: omitting it is a mypy `call-arg` error at the construction site rather than a runtime check. The two legs are not equivalent and the event shape shows it — the interactive OAuth leg binds no originating principal and no subject assertion, and requests no audience, so `endpoint_id` is its only target identifier there. Both follow from an interactive human grant this process never observes, not from a shortfall in the anchor. The pinned `mcp>=1.27.1,<2` client sends no RFC 8707 `resource`; if a later SDK does, that leg gains a real audience. |
| ODIS-CC-07 | Core | partial | Audit events carry tool name, family, endpoint id, decision id and reason code — never arguments, never secrets — and credential-bearing fields use `repr=False`. No documented retention or deletion policy. |

## Reading the mapping

The shape of the result is more interesting than any single row.

**The harness is strong on mediation and enforcement.** ODIS-L2-08, L2-10,
L2-13, L3-01, L3-02 and L3-08 are the requirements about keeping credentials away
from the model, refusing to broaden authority, validating each action on an
authorized presenter path, and making the boundary mandatory. That is the
contribution, and it maps onto Layer 2 requirements at least as much as Layer 3
ones — L2-13 is arguably the single closest fit in the whole document.

**Delegated authority and policy are one object here, and ODIS keeps them two.**
The draft puts delegated authority in the Delegation Record (§6.3) and leaves
policy outside the standard entirely (§3.4), evaluated by an external engine fed
the §6.4 Identity Context. This harness compiles an operator's delegation to
Rego, so the Authority Grant is simultaneously the authority and the policy
enforcing it. One decision, two partial rows: ODIS-L2-05 because the delegation
exists only in policy form rather than as a Record, and ODIS-L3-06 because there
is no separable `delegation` object to hand the engine — the delegation *is* the
ruleset it evaluates. Reading those rows as independent shortfalls overstates the
work; they close together or not at all.

**Layer 2's gap is a recording gap, not a missing participant.** The second
principal a delegation needs already exists: the operator who writes a Vault
mapping. Nothing captures them. `mappingEntry` has no author field, so who
delegated is visible only in Vault's request log and never travels with the
artifact; the issued bundle names neither them nor the mapping it derives from.
That single omission accounts for most of the Layer 2 shortfall — no
`originating_principal`, no `originating_authorization_ref`, no way for L2-01 to
intersect against the delegator's current authority, and no approval an audit
event could reference.

The practical consequence is that the headless case is much closer than it looks.
Recording the authoring principal at mapping-write time, and emitting it with a
reference to the mapping (its name plus a content digest and version), supplies
two §6.3 MUSTs and a third by implication, with no new integration and no IdP.
`actor` and `expires_at` are then additive. An IdP is needed for the
*interactive* case — a human delegating at request time — not for this one.

**It is weak on identity, lifecycle and operational safeguards, and Layer 3 is
inverted against the profiles.** Every Layer 1 row is out-of-role or a gap. Within
Layer 3 the split falls out cleanly and unflatteringly: every requirement this target
**meets** is Extended — tool discovery (L3-01), the governance checkpoint (L3-02),
boundary protection (L3-08) — and every **Core** one is a gap or partial — velocity
limits, revocation latency, kill switch, policy-engine integration (L3-03 to L3-06).
§8.4 has organizations "adopt Core first, extend as needed"; this built the governance
wedge first and left the operational safeguards, which is the opposite order. It is why
no profile claim is available even in the layer the harness is strongest in. The audit trail
names the
acting agent and the originating principal, but not the runtime instance, and the
principal behind the agent is a fixture.

**The structural gap is half closed.** ODIS §9.2 describes the checkpoint as
*receiving* Layer 1 identity and the Delegation Record. With `serve --inbound-key`
the agent half is received: a workload JWT is validated before any handler runs,
`agent_id` is its verified subject, and `agent.type` records it as `verified_bearer`
so a reader can tell a received identity from an assumed one. Three things are
authored or absent. The **originating principal** comes from a fixture provider
rather than from a delegation the Router was handed. The credential is a plain
bearer — validated, not holder-bound (ODIS-L1-09) — so possession is the only proof.
And **no delivery path ships in this component**: nothing here puts a credential in an
agent's hands,
so the received path is exercised by the test suite and by no demo. That last one is
a named seam, not unfinished work — see Deliberate omissions. Run without trust
material, every identity-shaped field is asserted by the enforcement point about
itself, and the startup banner says so.

**The migration order is inverted, and partly re-entered.** §7.3 sequences
adoption Phase 1 (L1) → Phase 2 (L1+L2) → Phase 3 (add governance). The harness
builds Phase 3 first, with Phase 1 as a fixture seam — a reasonable thing for a
demonstration of the governance wedge to do, and the reason so many Layer 1 rows
read out-of-role. Phase 2 is the interesting case: the Vault plugin re-enters it
from the authorization side, doing entitlement resolution and bounded
authorization without the delegation carrier those phases assume is built first.

## Defects, distinct from gaps

A gap is scope we did not build. These are things that are wrong, and a reader
should not have to infer the difference.

- **The action-limit enforcer's reach is wider than its name.** `_ENFORCERS` is
  keyed on the **unprefixed** tool name, so the `update_issue` enforcer runs for
  every family the bundle routes. Two families exposing a same-named tool with
  different argument semantics would both be checked against one rule set. Stated
  in the module docstring, but the design is still keyed too coarsely.
- **`require_review` is treated as a refusal.** Any decision that is not `allow`
  refuses, so a policy asking for human review is indistinguishable from a denial
  at the Router and in the trail (ODIS-L3-01).

## Where the draft is underdetermined

Separate from gaps (scope we did not build) and defects (things that are wrong). These are
places where implementing a requirement forced a choice the draft does not make. They are
the most useful thing a candidate implementation can hand back, so each one states what we
could not determine and what we chose.

**§6.4 bottoms out in Layer 1, so a Core requirement depends on a layer this target does not
claim.** `ODIS-L3-06` is **Core** and requires emitting the §6.4 Identity Context, whose
`agent_registration`, `agent_runtime` and `delegation` are all `MUST`. Sizing them separates
ordinary work from a genuine dependency. `action`, `request_timestamp` and `request_trace_id`
are present or a reshape of what the harness already sends. `delegation` needs the fields
under `ODIS-L2-05`. `agent_registration` needs a per-agent record — a storage path and a
resolution step, and since this target declares Layer 2 it is the plugin's to build.

`agent_runtime` is the one that cannot be closed by populating fields. §6.2 has fifteen
`MUST`s; a validated workload JWT supplies five (`agent_id`, `issuer`, `audiences`,
`issued_at`, `expires_at`). Among the rest, `software_hash` and `attestation_evidence` require
something to attest the workload, `holder_key_ref` requires a proof-of-possession credential
rather than the bearer this validates, and `runtime_instance_id` is the executing-instance
identity `ODIS-CC-02` also records as absent. Those are Layer 1 obligations
(`ODIS-L1-02`, `L1-03`, `L1-09`, `L1-11`), all out-of-role here by design.

Two draft gaps sharpen this rather than excuse it. §3.3(b) says the checkpoint "receives"
these objects and defines no interface, wire format, or trust model for receiving them — so
even a deployment that had them has no specified way to hand them over. And the draft does not
say whether a checkpoint may emit a partial Identity Context, or must withhold it entirely
when an upstream layer supplies nothing. **We emit what we hold, name the rest absent, and
score the row partial.**

**No MCP binding for §6.4's `action` object.** It is `{tool, method, resource, parameters}`,
and §7.1 explicitly blesses MCP ("the governance checkpoint can wrap MCP tool invocations
transparently"). For an MCP call named `jira-prod.update_issue`, the draft does not say
whether `tool` is the family, the server or the tool, nor whether `method` is the JSON-RPC
method (`tools/call`) or the tool name. **We map `method` to the unprefixed tool name and
`resource` to the resource family**, and note that any other implementation may choose
differently, so `action` is not interoperable today.

**`obligations` is typed but unschematised, and we already diverge.** §6.4 gives the
engine's return as `{decision, reason, obligations: array}`. Since ODIS standardizes no
policy language, `obligations` has no schema at all — which means the one field
argument-level enforcement depends on is the one field two conformant implementations
cannot agree on. **Ours is an object** (the action-limit enforcer does key lookups on it),
not an array.

**Decision vocabulary.** §6.4 says `permit` | `deny`; our Rego emits `allow`. The word
"allow" appears once in the entire draft, in an unrelated sentence. The draft never states
whether those two values are normative or illustrative. **We keep `allow` on the Rego wire**
because changing it touches every shipped policy, the Go policy projector and the golden
fixture; `Decision` in `mcp_forwarder/policy.py` records the divergence.

**`reason` has no vocabulary.** §6.4 types it `string`. Anyone implementing `L3-06` must
invent a refusal vocabulary, so no two implementations will produce comparable audit
trails. **Ours is `ReasonCode`** in `mcp_forwarder/reason_codes.py`, nine values, typed and
enumerable — offered as a starting point rather than a claim to conformance.

**`ODIS-L2-15` says an adapter "MUST declare native or bridge mode"** without saying where
or to whom — conformance declaration, bundle metadata, per request? **We declare nothing
and score the requirement a gap** rather than guess at a location.

**`ODIS-L3-03` is a Core MUST with no measurable criterion:** "configurable rate limits per
agent, especially for destructive operations." No definition of destructive, no units, no
scope (per tool? per family? per agent?). It cannot be objectively claimed or failed.

**`ODIS-L3-04`'s 300-second window has no consumable event format.** §7.1 gestures at
SSF/CAEP/RISC but binds nothing, so a Layer-3 component has no defined revocation input to
implement against.

**Is an operator who pre-authorizes an agent its originating principal, its sponsor, or
both?** `ODIS-L2-02` admits "pre-authorized delegation" as a bounded-authorization
mechanism for headless agents, and requires the approval be bound to record, task,
authority, audience, constraints and expiry — but it never says whose authority the approval
draws on. §6.3 defines `originating_principal` as the principal "whose authority initiated
the delegation chain — distinct from the agent's accountable sponsor or owner", and §6.1
puts accountability on `sponsor_ref`. For an interactive flow those are plainly two people.
For a headless agent whose authority was delegated in advance by an operator, they may be
one, and the draft does not say. It also does not say whether that operator's *current*
authority must bound the grant — `ODIS-L2-01` requires the intersection but is written for a
principal present at request time — nor what a delegation should do when its delegator is
deprovisioned. **We record neither role**: the operator is a delegating principal that
no artifact names, so the question is presently unanswerable from our own trail, and the
grant does not narrow when they leave. Answering it would settle whether a pre-authorization
is a delegation with a durable root or a governance configuration that merely resembles one.

**May an ARR be *derived* rather than stored?** §1.3 says only that it is "a control-plane
governance record consulted at runtime" whose managing authority may differ from the
credential issuer. Nothing says whether a per-agent record must be stored per agent or may
be computed at resolution time from operator-authored templates. Ours would be derived from
a selector-scoped Vault mapping, which makes `record_version` and rollback detection
template-scoped rather than record-scoped, and the draft does not say whether that
satisfies §6.1's resolution rule.

**Does signing an ARR field into a policy artifact make it integrity-protected?** §1.4
requires an Active ARR to be "authenticated, integrity-protected". Putting `sponsor_ref`
inside our Ed25519-signed Authority Grant would give it a signature — but that signature
covers policy and routing, not a governance record. The draft does not discuss artifact
composition. **Our reading is that it does not qualify**, so the accountability field would
be offered as audit value, not as ARR conformance.

**Accountability has no coherent scope in a union-composed grant.** Carrying §6.1's
`sponsor_ref` and `owner_ref` on the Vault mapping was implemented and then reverted,
because three problems surfaced that are properties of the model rather than the code:

- The Authority Grant envelope is **bundle-scoped**, but grants **compose per family**:
  an identity's authority is the union of every mapping it matches. If mapping A
  (family `jira`, `sponsor_ref: alice`) and mapping B (family `github`, no ref) both
  match, the signed bundle names alice as accountable for authority that came entirely
  from B. A tier ceiling that then drops `jira` leaves her named for nothing she granted.
- `owner_ref` belongs on a class selector and `sponsor_ref` on an exact subject, which puts
  them on *different* mappings — and the envelope conflict check refuses two contributing
  mappings that disagree on an envelope field, so that pair cannot compose.
- Nothing downstream consumes them. `Bundle` has no such fields, the loader would drop
  them, and `schemas/odis.bundle.v1.json` sets `additionalProperties: false`, so a bundle
  actually carrying one is refused at load. The plugin would sign what the Router cannot
  read.

**The envelope is the right home after all — for the delegator, not the agent's owner.**
The reverted experiment failed by asking one bundle-scoped field to carry per-family facts.
Invert it: the field that belongs in the envelope is **who delegated**, and it belongs there
precisely *because* the envelope-agreement rule forces every contributing mapping to agree
on it. An identity's authority then has one accountable delegator by construction, and two
teams granting the same agent identity fails issuance — the correct outcome for an
accountability split, not a limitation. §6.3 is asking for this: `originating_principal` and
`originating_authorization_ref` are both single-valued, which reads as the draft asserting
one accountable root per delegation. The principal is a team acting through a service
principal or an owning record — §6.1 `owner_ref` names a team, §6.3 wants an authenticated
principal, so they are not interchangeable.

Per-family provenance stays available as an audit detail rather than a conformance need:
`contributeGrant` rejects two mappings claiming the same family (`errSameFamilyCollision`),
so every family traces to exactly one mapping, and a tier ceiling only drops or narrows
whole families rather than merging them.

The remaining mismatch: ODIS attaches accountability to a **per-agent record** (the ARR),
and this harness has no per-agent artifact at all — the grant describes authority, not
agents. The field on the bundle envelope is the same wrong-noun error catalogued above,
and that is the part family scope fixes. What family scope does
not supply is the ARR itself: `sponsor_ref` on a per-family grant records who delegated
a capability, not who is accountable for an agent across its lifecycle. So `ODIS-L1-10`
stays a gap pending an agent-keyed record, while `ODIS-L2-05`'s provenance fields are
reachable at family scope now.

### A note on vocabulary provenance

Worth stating plainly, because the `odis.*` filenames imply more than they deliver: the
three envelopes in `schemas/` describe themselves as mirroring **APF** §6.1, §6.2 and §6.5,
not ODIS. `policy_digest`, `task_intent`, `correlation_id`, `verb` and `request_body` appear
**zero times** in the ODIS draft. `apf_semantic_enforcement` is explicitly APF. This is a
legitimate lineage — APF is a candidate ODIS implementation profile, and the harness
predates this draft — but it means the envelopes are APF-shaped, and aligning them with
§6.4 is outstanding work rather than a naming preference.

## Deliberate omissions

These are choices, not oversights, and they are the ones worth arguing about.

- **APF's Credential Proxy pillar is omitted here, and supplied by the substrate.**
  Target MCP servers hold their own provider credentials. This is what makes ODIS-L2-08
  clean and ODIS-L2-10 conditional at the same time — the conditional is whether the
  Target MCP counts as ODIS-controlled, which is a deployment property, not a code
  property. Worth stating positively rather than as a hole: OpenShell, the substrate this
  design names, **is** a credential proxy. It placeholderizes provider credentials in the
  sandbox environment and substitutes the credential at its egress proxy, so the agent
  uses a credential it never holds. Composed with OpenShell, the pattern has the pillar;
  this component simply is not where it lives.
- **No policy language is introduced.** Per §3.4 the harness consumes an external
  engine. `policy_digest` binds policy and routing together over the whole
  canonical bundle so the two cannot be recombined.
- **Every external boundary is a required constructor argument.** `RouterWiring`
  (identity + vendor transport) and `signature_verifier` have no defaults, and the
  non-production stand-ins live in `odis_harness.fixtures`, which the core may not import
  (`tests/test_fixture_isolation.py` enforces it, AST-based so a lazy import cannot slip
  through). This is what makes the claim below checkable rather than aspirational: a caller
  names what it wires, and a stub cannot arrive by default.
- **Passport is not implemented, and that is the design.** The harness verifies an
  agent credential; it does not issue or deliver one. Identity is the piece an adopter
  already has — SPIRE, an existing OIDC provider, a cloud workload identity — so a
  reference implementation that shipped its own would ask them to replace the component
  they least need replaced, and would bury the seam that actually matters. The split
  follows the roles: Passport *mints*, the Router *receives and verifies*, and verifying
  a presented bearer is the resource server's own obligation. That is why ODIS-L1-01 and
  ODIS-L1-05 are the only Layer 1 rows scored against behaviour this component actually
  implements; every other one is out-of-role or a gap.
- **The credential's shape is the deliverable, not its issuer.**
  `fixtures/issuer.py:FixtureIdentityIssuer` mints what a SPIRE JWT-SVID looks like:
  ES256 over EC P-256, `sub` a SPIFFE ID, `aud` required, a five-minute TTL, a `kid`
  header. One deliberate deviation: the verifier **requires `iss`**, which the SPIFFE
  JWT-SVID spec does not mandate — a raw Workload API SVID carries `sub`/`aud`/`exp` and
  often no issuer. The harness therefore targets SPIRE fronted by its **OIDC Discovery
  Provider**, or any OIDC-shaped IdP, which is the assumption the Vault leg already
  makes. An adopter reading SVIDs straight off the Workload API adds an issuer claim or
  relaxes that binding.
- **One trust root, not two.** `WorkloadJwtVerifier(public_keys, bound_issuer,
  bound_audience)` is structurally the plugin's `issuerConfig{jwks | jwks_pem,
  bound_issuer, bound_audiences}`, so one IdP serves both the agent→Router and
  Router→Vault legs. Two asymmetries remain: the plugin ingests a JWKS where the Python
  verifier takes PEM only, so key rotation is a restart rather than a refresh; and the
  plugin binds a list of audiences where the verifier binds one.
- **Credential delivery is the substrate's job, not this component's.** The harness
  verifies an inbound credential and never issues or ships one. Writing a JWT to a file and
  handing it to the agent at spawn would model delivery *badly* — a five-minute credential
  baked in at start is dead before a long run finishes — so no fixture does that. On an
  OpenShell substrate the substrate itself carries it: the agent holds only a placeholder and
  the egress proxy substitutes the real value, so the credential never enters the sandbox.
  The Router validates it normally and `agent_id` becomes the verified subject
  (`type: verified_bearer`). `docs/run-modes.md` section 3 states the four things that path
  requires. `mise run demo` mints and presents a credential to itself in-process, which
  exercises the verify path; `demo-openshell` serves unverified, so the shipped demos cover
  verification and not delivery.
- **Enforcement is only as strong as the sandbox.** Stated plainly rather than papered
  over: if the agent can reach a Target MCP without traversing the Router, the gate is
  governance-only. ODIS-L3-08 requires the boundary to be independently enforceable, and
  that property comes from the sandbox, not from this code.
