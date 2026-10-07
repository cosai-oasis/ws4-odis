# Agent Manifest and TRACE mapped onto ODIS records

Date: 2026-10-07
Status: draft for WS4 discussion ahead of the 2026-10-14 call. Not a proposal for adoption; field fits are open to dispute.
Follows the 2026-10-07 WS4 call, which agreed to fold Agent Manifest into the ODIS Agent Registration Record and to start from a sample record (see ws4-secure-design-agentic-systems discussion #209). Sample record: [sample-registration-record.json](sample-registration-record.json).

## Sources

Every field claim below cites one of these keys plus a section number. All were read at the pinned commit, not from a local clone.

| Key | Repo and file | Commit (main, read 2026-10-07) |
|---|---|---|
| ODIS | cosai-oasis/ws4-odis `RFCs/ODIS.md` (blob 1be049b01c7894a62b1d55bcfb4590d30dd4ede5, unchanged since the 2026-09-21 evidence pass) | 148dc4187139a41325e3c6d6e7533d956bd33144 |
| AM | agentrust-io/agent-manifest `spec/agent-manifest-spec-v0.2.md` | c6d0ec93681f3caa5c6d7f8d01cd1ee10c7c131e |
| AM-py | agentrust-io/agent-manifest `python/src/agent_manifest/models.py` | c6d0ec93681f3caa5c6d7f8d01cd1ee10c7c131e |
| TRACE | agentrust-io/trace-spec `spec/trace-v0.2.md` | 8dfeea9d44ce03f4c810baf5c2db1bcd0649b3e3 |
| TRACE-schema | agentrust-io/trace-spec `schema/trace-claim.json` (`$id` trace-v0.2.json) | 8dfeea9d44ce03f4c810baf5c2db1bcd0649b3e3 |
| TRACE-receipt | agentrust-io/trace-spec `schema/trace-decision-receipt-experimental-v1.json` | 8dfeea9d44ce03f4c810baf5c2db1bcd0649b3e3 |
| cA2A | agentrust-io/ca2a `docs/spec/delegation-chain.md`, `docs/spec/trace-a2a-profile.md`, `src/ca2a_runtime/delegation/credential.py` | a0924991e22ed72301d167c4ba9a4527fc37307d |
| Issues | cosai-oasis/ws4-odis #15, #16, #21, #22 bodies and comments via `gh api` | read 2026-10-07 |

Prior positions this draft holds to (all on the record in the issues above):

- `approved_software_refs` carries typed composition references; `software_hash` in 6.2 stays the digest of the verified software artifact (#21 item 1, #16 2026-09-21).
- Per-relationship assurance, `instance_to_key` and `instance_to_software`, appraised by the verifier rather than accepted as labels (#21 item 2, #15 2026-10-06).
- A quote whose report data commits to a key is evidence of that commitment only. It is not proof of key custody or of approved-image execution (#21 2026-09-21 replay).
- rithikha's rule 3 on #16: a credential naming a superseded registration version is accepted only while its issuance evidence still satisfies the current version. Endorsed on #16 on 2026-10-06.
- Digest inputs must be named: exact issued payload by default, canonical profiles named with their preprocessing (#22).

## Mapping 1: Agent Manifest to the ODIS 6.1 Agent Registration Record

Fit values:

- **exact**: same meaning, an ODIS field exists today.
- **via typed ref**: no ODIS field, but it lands as a typed entry in `approved_software_refs` under the #21 proposal (ODIS 6.1 describes that array as "software hashes, package identities, image digests, signing identities, or provenance references" and does not type its items).
- **partial**: an ODIS field or requirement covers part of the meaning, or the AM field moves to 6.2 or 6.3 rather than 6.1.
- **gap**: no home in ODIS text at 148dc41.

ODIS 6.1 fields (ODIS 6.1): `record_id`, `record_issuer`, `schema_version`, `record_version`, `agent_id`, `valid_until`, `lifecycle_state`, `sponsor_ref`, `owner_ref`, `approved_runtime_issuers`, `approved_software_refs`, `trust_domain`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements` (SHOULD), `created_at`, `updated_at`. All others are MUST.

### Top-level identity and lifecycle (AM 3.1, 2.2, 2.4)

| AM field | ODIS 6.1 field | Fit | Note |
|---|---|---|---|
| `@context`, `@type` | `schema_version` | partial | AM treats these as JSON-LD identifiers inside the signed pre-image (AM 2.3). ODIS names no carrier, so they become carrier detail; `schema_version` carries the version meaning. |
| `manifest_id` | `record_id` + `record_version` | partial | AM: new UUID v7 on every signed-field change, no in-place update (AM 2.2). ODIS: stable `record_id`, integer `record_version` for rollback detection. One AM manifest is one ODIS (`record_id`, `record_version`) pair. |
| `previous_manifest_id` | `record_version` | partial | AM back-links; ODIS orders by monotonic integer. ODIS has no explicit predecessor pointer. |
| `agent_id` | `agent_id` | exact | AM requires a SPIFFE URI and says it is the stable logical identity (AM 3.1). ODIS: "Stable logical agent identifier". |
| `agent_instance_id` | none in 6.1; 6.2 `runtime_instance_id` | gap | Correct by design: instance scope belongs on the runtime credential, consistent with the #16 resolution (credential bound to one instance). AM instance-scoped manifests become a registration choice, as rithikha noted. |
| `version` | `schema_version` | exact | AM spec version string, "0.2" (AM 2.4). |
| `min_verifier_version` | none | gap | Profile field. Low value once the record has a named schema version. |
| `issued_at` | `updated_at` (and `created_at` for the first version) | partial | ODIS separates registration creation from trusted last-update time assigned by `record_issuer`. |
| `expires_at` | `valid_until` | partial | AM: verifier MUST reject after expiry, at most 365 days at Level 1+ (AM 3.1). ODIS: latest time the version may be treated as current without authenticated refresh. ODIS is a freshness bound; AM is a hard expiry. |
| `issuer` | `record_issuer` | exact | AM: SPIFFE URI of signing authority. ODIS: authoritative issuer, which a resolver must authenticate and authorize for the trust domain (ODIS 6.1 resolution rule). |
| `crypto_profile` | none | gap | ODIS names no algorithm profile. Lands in the digest/signing profile #22 asks for. |
| `profile` (`composition-only`) | none | gap | This is the meeting's profile switching in miniature. AM 3.1.1: a composition-only manifest returns `INCOMPLETE` and is not a conformance claim. Proposed home: a named ODIS profile or `lifecycle_state: pending`. |
| `unbound_artifacts` | none | gap | Needed only with a partial profile. Lands with `profile`. |
| `source_bundle` | `approved_software_refs` | via typed ref | `{format, digest}`, format `agent-plugins-1.0.0` (AM 3.1.2). Maps cleanly as `ref_type: source-bundle`. |

### Artifact bindings (AM 3.2)

| AM field | ODIS 6.1 field | Fit | Note |
|---|---|---|---|
| `artifacts.system_prompt` (`hash`, `hash_algorithm`, `version`, `classification`, `language`, `bound_at`) | `approved_software_refs` | via typed ref | Per the #16 resolution, a prompt bundled into the packaged artifact is already covered by `software_hash`; a separately managed prompt needs its own typed entry. |
| `system_prompt.safety_level` | none | gap | AM 3.2.1 says a verifier MUST NOT treat it as evidence. Propose dropping it in the merge. |
| `system_prompt.assurance_test` | none | gap | Assessment result over an approved value (AM 3.2.1.1). Profile. |
| `artifacts.policy_bundle` (`hash`, `policy_language`, `version`) | `policy_profile_ref` | partial | ODIS types `policy_profile_ref` as a string, "Policy profile or policy context". It carries no digest. The meeting placed the bundle in the registration record; today the record can only point at it. |
| `policy_bundle.enforcement_mode` | none | gap | AM 3.2.2: a verifier MUST reject `advisory` where `enforce` is required. No ODIS field carries the mode. |
| `policy_bundle.scope`, `agt_version` | `provider_entitlements` | partial | Scope identifiers (`finance:ledger:write`) overlap with allowed scopes in `provider_entitlements`. `agt_version` has no home. |
| `artifacts.tool_manifest.tools[]` (`tool_id`, `tool_name`, `endpoint_id`, `version`) | `provider_entitlements` | partial | ODIS describes `provider_entitlements` as adapter mappings, scopes, roles, grants or mediated paths. That covers which endpoints an agent may reach, not which tool definitions it was approved against. |
| `tool_manifest.catalog_hash`, `tools[].schema_hash`, `tools[].description_hash` | `approved_software_refs` | via typed ref | Tool definition digests have no ODIS concept. `catalog_hash` is a domain-separated Merkle root over both hashes per tool (AM 3.2.3), so one typed entry carries the whole catalog. |
| `tools[].permission_scope`, `tools[].egress_destinations` | `provider_entitlements` | partial | Egress allowlists fit "mediated paths". `permission_scope` is a Cedar entity type with no ODIS equivalent. |
| `tool_manifest.allow_dynamic_registration`, `rug_pull_policy` | none | gap | Runtime enforcement policy on catalog change (AM 3.2.3.1). Profile; the Layer 3 router enforces it. |
| `artifacts.model_identity` (`provider`, `model_id`, `version`, `deployment_type`, `model_attestation_type`, `capability_level`, `safety_alignment_version`, `quantization`) | `approved_software_refs` | via typed ref | #16 settled that a runtime-selected model is outside `software_hash` and may be declared in the record as an approved composition. |
| `model_identity.model_hash` | `approved_software_refs` | via typed ref | Weights digest. AM requires it for `local` and `confidential-inference`, requires `null` for API models (AM 3.2.4). ODIS has no model concept today. |
| `artifacts.rag_corpus` (`corpus_id`, `merkle_root`, `document_count`, `ingestion_policy_hash`, `vector_store`, `embedding_model`, `last_updated`) | none | gap | No ODIS concept of bound data. |
| `rag_corpus.poisoning_scan` (`scanner_version`, `scanned_at`, `result`) | none | gap | AM 3.2.5: `flagged` MUST NOT be issued as VALID; `not-scanned` not permitted at Level 1+. The scan names no subject digest; it is bound to the corpus only by sitting in the same object. |
| `artifacts.memory_baseline` (`baseline_id`, `snapshot_hash`, `memory_type`, `store`, `approved_at`, `ttl_seconds`, `drift_policy`, `shared_memory_owner`, `check_interval_seconds`) | none | gap | No ODIS concept. |
| Memory checkpoint (`MemoryCheckpointBinding`: `memory_root`, `seq`, `approved_at`, `ttl_seconds`, `approval_signature`; AM 3.2.6.2, AM-py) | none | gap | Exists so memory can advance without re-issuing the root document. Under ODIS that matters more, because every record change increments `record_version`. |
| `artifacts.decision_trace` (`trace_type`, `audit_chain_root`, `audit_chain_uri`, `signing_key_id`, `audit_key_sealed`, `first_entry_at`, `last_entry_at`, `entry_count`) | none | gap | ODIS-CC-01 requires logging and, under Safety, hash-chained or equivalent audit. No record field commits to the chain. |
| Audit checkpoint (`AuditCheckpointBinding`: `audit_chain_root`, `tree_size`, `seq`, `observed_at`, `ttl_seconds`, `checkpoint_signature`; AM 3.2.7.1) | none | gap | Continuity proof format for the Safety audit requirement. |
| `artifacts.supply_chain.container_image_digest` | `approved_software_refs` | exact | "image digests" is named in ODIS 6.1. At runtime the matching 6.2 field is `software_hash`. |
| `supply_chain.base_image_digest` | `approved_software_refs` | exact | Image digest; needs a `role` to tell it from the harness image. |
| `supply_chain.slsa_provenance` (`builder_id`, `subject_digest`, `provenance_uri`, `rekor_entry_id`, `declared_level`) | `approved_software_refs`; 6.2 `supply_chain_ref` | exact | "provenance references" is named in 6.1, and ODIS-L1-08 requires a trusted supply chain. `declared_level` is non-normative in AM too. |
| `supply_chain.sbom` (`format`, `schema_version`, `document_id`, `sbom_hash`, `sbom_uri`) | `approved_software_refs` | partial | ODIS-L1-02: an SBOM MAY be supplemental inventory and MUST NOT by itself satisfy artifact-integrity verification. The typed entry must say so. |
| `supply_chain.mcp_servers[]` (`server_id`, `image_digest`, `slsa_level`, `phase2_attested`, `sbom`) | `provider_entitlements` | partial | Server identity overlaps the entitlement key. Server image digest and `phase2_attested` have no home. |

### Hardware attestation (AM 3.3)

Terminology from the meeting applies here. The AM `attestation` block is **evidence** appended after signing (AM 3.6 signing table: NOT signed). Under the merged model the registration record holds **reference values**; the observed evidence goes in the 6.2 `attestation_evidence` array; the Layer 2 verifier appraises one against the other and the result is the **credential**.

| AM field | ODIS 6.1 field | Fit | Note |
|---|---|---|---|
| `attestation.platform`, `tee_version`, `measurement` | none as reference values; observed values in 6.2 `attestation_evidence` | partial | 6.1 has nowhere to put an expected MRTD or launch measurement. ODIS-L1-04 makes hardware evidence supplemental (Extended SHOULD, Safety MUST). |
| `attestation.manifest_hash_in_report` | 6.2 `registration_record_ref.record_digest` (binding target) | partial | AM binds the exact COSE payload bytes into SNP `HOST_DATA` or TDX `RTMR[3]` (AM 3.3, 3.3.1). After the merge, what gets extended must be named. See the binding note under the sample record. |
| `attestation.policy_bundle_hash`, `enforcement_mode`, `audit_chain_root`, `audit_key_sealed`, `container_image_digest` | 6.2 `software_hash` (image digest only) | partial | Cross-check copies of signed values. Only the image digest has an ODIS runtime field. |
| `attestation.report_timestamp`, `report_uri` | 6.2 `attestation_evidence` (`issued_at`, evidence reference) | exact | ODIS 6.2 requires type, issuer, subject, issued_at, expires_at or maximum_age, evidence reference or embedded proof, and integrity metadata per evidence object. |
| `attestation.attestation_service` (`service_id`, `service_measurement`, `verification_endpoint`) | `approved_runtime_issuers`; 6.2 evidence `issuer` | partial | AM calls this a RATS Verifier (AM 3.3). ODIS trusts runtime credential issuers per agent; it does not list trusted evidence verifiers separately. |
| `evidence_requirements` (AM-py only, opt-in under profile `evidence-requirements-experimental-v1`; absent from the AM 3.6 signing table) | none | gap | Closest thing AM has to "what evidence the verifier must require". rithikha's #16 text ("once their registration requires it, issuance and continued acceptance MUST satisfy it") assumes the record can state requirements, and 6.1 has no field for that. |

### Delegation, oversight, compliance, integrity (AM 3.4 to 3.9, 8.1, 9.3, 9.4)

| AM field | ODIS 6.1 field | Fit | Note |
|---|---|---|---|
| `delegation_chain[]` (`hop`, `principal_type`, `principal_id`, `delegated_at`, `scope_grant`, `delegation_signature`, `principal_manifest_id`, `principal_attestation_hash`) | 6.3 Delegation Record; 6.1 `permitted_delegation_modes` | partial | A per-spawn chain does not belong in a durable registration record. 6.1 says which modes are permitted; 6.3 carries each hop. |
| `scope_grant.max_delegation_depth` | 6.3 `max_depth` | exact | AM default 3 (AM 3.4.1); ODIS SHOULD, no default. |
| `hitl_record.required`, `hitl_record.approvals[]` | ODIS-L2-02 approval binding; ODIS-CC-05 governed creation | partial | ODIS binds a human approval to the registration record, task, authority, audience, constraints and expiry. AM approvals approve artifacts with a `risk_tier`. No 6.1 field states that oversight is required. |
| `hitl_record.escalation_policy` (`trigger`, `escalation_target`, `timeout_action`) | none | gap | Profile. |
| `hitl_record.hitl_runtime` (`interrupt_endpoint`, `override_mechanism`, `monitoring_endpoint`, `automation_bias_disclosure`) | ODIS-L3-05 kill switch | partial | ODIS requires the capability at deployment level; the record does not name the endpoint. |
| `prior_transparency_log_entry` | none | gap | Key-rotation continuity (AM 2.2). ODIS uses `record_version` for rollback and says nothing about transparency logs. |
| `log_retention` (`minimum_retention_days`, `regulatory_retention_override`, `retention_enforced_by`) | none | gap | ODIS-CC-07 requires documented retention policies at implementation level, not per record. |
| `data_scope` (`personal_data_categories`, `legal_basis`, `automated_decision_making`, `dpia_reference`) | none | gap | Regulatory profile. ODIS-CC-07 pushes the other way: minimise sensitive data in records. |
| `operational_lifecycle` (`expected_lifetime_days`, `planned_maintenance_schedule`, `update_policy`, `reissuance_triggers`) | `lifecycle_state`, `valid_until` | partial | `reissuance_triggers` is the AM version of the #16 question of which changes force a new version. |
| `intent.statement` | none in 6.1; 6.3 `task_id`, `task_description` | gap | AM requires it to be issuer-signed and never self-asserted (AM 3.9). ODIS has purpose only per task (ODIS-L3-07), not per agent. |
| `signature` (v0.1, AM 3.6) and COSE_Sign1 envelope (v0.2, `agent-manifest-cose-envelope-v0.2.md`, referenced not re-read) | 6.1 resolution rule: authenticate `record_issuer` and the record's integrity protection | partial | ODIS requires integrity protection and names no carrier. |
| Canonicalization (AM 2.3, 4.3: RFC 8785, nulls omitted before JCS for manifest pre-images) | none | gap | Open in #22. AM's null-omission step is the preprocessing #22 says must be named. |
| `transparency_log_entry` | none | gap | NOT signed in AM; replaced by COSE `receipts` in v0.2. |
| Revocation record (AM 3.7: `revocation_id`, `manifest_id`, `agent_id`, `revoked_at`, `reason_code`, `scope`, `revocation_signature`, `transparency_log_entry`) | `lifecycle_state: revoked`; ODIS-L1-06, L3-04, L3-05 | partial | AM `scope: agent` with `AGENT_DECOMMISSION` is close to ODIS de-provisioning. ODIS adds a 300-second propagation ceiling that AM does not have. |
| Key rotation (AM 3.8) | `record_version` | partial | ODIS does not cover the issuer key changing. |

**Counts for Mapping 1 (58 rows): 8 exact, 5 via typed ref, 22 partial, 23 gap.**

## Gaps both ways, and where each lands

Three landing places, matching the meeting's "prescriptive core, profile switching":

- **Core field**: belongs in 6.1 for every conformant record.
- **Typed composition ref**: an entry in `approved_software_refs` with a `ref_type`, a digest and a named digest input (#21, #22). Core defines the envelope; the types are registered.
- **Named profile**: an extension block selected by name and version, outside Core. The sample uses `agentrust-composition-v0`.

### AM concepts ODIS lacks

| Concept | Lands as | Reason |
|---|---|---|
| Model weights digest (`model_hash`, `model_attestation_type`) | typed ref, `ref_type: model` | Same shape as an image digest. `provider-asserted` for API models is the AM version of the `platform-asserted` assurance value proposed in #21. |
| Tool definition digests (`catalog_hash`, `schema_hash`, `description_hash`) | typed ref, `ref_type: tool-catalog` | One Merkle root covers the catalog. Without it, `provider_entitlements` says where the agent may call and nothing about which tool definitions were approved. |
| System prompt digest | typed ref, `ref_type: prompt`, when managed outside the packaged artifact | Follows the #16 scope rule for `software_hash`. |
| Policy bundle digest and `enforcement_mode` | core change to `policy_profile_ref`: make it an object with `uri`, `digest`, `enforcement_mode` | The meeting placed the policy bundle in the registration record. A string reference with no digest cannot carry that. |
| RAG corpus binding (`merkle_root`, `ingestion_policy_hash`, `embedding_model`) | named profile | Data that changes on its own schedule. Putting it in Core would force a new `record_version` on every ingestion. |
| Poisoning scan bound to its subject | named profile, with `subject_digest` added | AM binds the scan to the corpus only by nesting. A portable result needs the corpus digest it scanned, the same way `assurance_test` carries `evidence_digest`. The sample adds `subject_digest`. |
| Memory baseline and checkpoint protocol | named profile | Checkpoint advances must not mutate the record. AM 3.2.6.2 already solved this; the profile reuses it. |
| Audit chain commitment (`decision_trace`, audit checkpoint) | named profile, required by a Safety claim that uses it | Gives ODIS-CC-01 under Safety something checkable. |
| Expected hardware measurements (reference values) | named profile now; candidate core field later | The meeting said the record holds reference values for the verifier. 6.1 has no field for them. |
| Required evidence, per relationship (`instance_to_software`, `instance_to_key`) | named profile | The #16 rule depends on the record stating what evidence it requires. |
| Canonicalization and signing profile (`crypto_profile`, JCS, null handling) | core: a named digest profile per #22 | Without it, `record_digest` in 6.2 is not reproducible across implementations. |
| Composition-only or partial binding (`profile`, `unbound_artifacts`) | core enum value, either `lifecycle_state: pending` or a profile flag | Lets a scanner or marketplace register a contribution without claiming a runnable agent. |
| Declared intent | core OPTIONAL field | ODIS-L3-07 validates actions against task purpose. An issuer-declared agent purpose is a registration fact and is free once the record is signed. |
| HITL requirement, escalation, interrupt endpoints | named profile | Deployment capability, required by ODIS-L3-05 at system level. |
| `log_retention`, `data_scope`, `operational_lifecycle` | named regulatory profile | Regulatory declarations. ODIS-CC-07 argues for keeping them out of Core. |
| Transparency log entry, key-rotation continuity | named profile | ODIS is carrier-neutral; a SCITT-style receipt is one carrier. |

### ODIS concepts AM lacks

| Concept | Lands as | Note |
|---|---|---|
| `record_version` as a monotonic integer | core (exists) | AM orders by UUID v7 and `previous_manifest_id`. The integer makes rollback detection a comparison. |
| `lifecycle_state` (active, suspended, revoked, pending) | core (exists) | AM has only verification outcomes (VALID, EXPIRED, REVOKED) and no suspended state. |
| `sponsor_ref`, `owner_ref` | core (exists) | AM's nearest equivalents are `issuer` and HITL `approver_id`, neither of which is an accountable owner. ODIS-L1-10 makes ownership change trigger re-verification or de-provisioning. |
| Who may update the record | **missing in both** | The meeting listed "who can update/manage" as a registration-record property. ODIS-CC-05 governs creation and forbids self-expansion, but 6.1 has no field naming the update authority. The sample carries `governance.authorized_updaters` as a profile field; this should be a core question. |
| `record_digest` | core, in 6.2 `registration_record_ref` | Not a 6.1 field. Its input is the #22 question. The sample does not store its own digest (same rule as AM 3.9 for `intent`). |
| `approved_runtime_issuers`, `trust_domain` | core (exists) | AM encodes trust domain only inside the SPIFFE `agent_id`. |
| `permitted_delegation_modes`, `provider_entitlements` | core (exists) | AM states delegation per hop, not as permitted modes. |
| De-provisioning and drain (ODIS-L1-06, L1-10, L3-05) | core (exists) | AM revocation `scope: agent` is the closest equivalent. AM has no drain state and no propagation latency bound. |
| Superseded-version acceptance (#16 rule 3) | core, pending rithikha's PR | AM has nothing comparable: every signed-field change is a new manifest and the old one is revoked on rotation. |

## Sample ODIS registration record

File: [sample-registration-record.json](sample-registration-record.json). It parses as JSON. Every `sha256:` value is 64 hex characters and the one `sha384:` value is 96; the script that wrote the file asserts both. The values are placeholders and digest nothing.

How it is laid out:

- Top level: only ODIS 6.1 field names, plus one `extensions` object. `record_id`, `record_issuer`, `schema_version`, `record_version`, `agent_id`, `valid_until`, `lifecycle_state`, `sponsor_ref`, `owner_ref`, `approved_runtime_issuers`, `approved_software_refs`, `trust_domain`, `policy_profile_ref`, `permitted_delegation_modes`, `provider_entitlements`, `created_at`, `updated_at` are all present.
- `approved_software_refs` holds six typed entries: harness image, base image, SLSA provenance, SBOM (`integrity_use: inventory-only`, per ODIS-L1-02), source bundle, and one `composition` entry whose digest covers the profile extension.
- `extensions.agentrust-composition-v0` is the clearly marked profile. It carries everything AM intended with no 6.1 home: prompt with `assurance_test`, policy bundle with `enforcement_mode`, model identity with weights digest, tool catalog with definition digests and tool servers, RAG corpus with `poisoning_scan.subject_digest`, memory baseline, audit commitment, reference values, human oversight, governance, and the regulatory blocks.
- `policy_profile_ref` stays a string because ODIS types it that way; the digest rides in a URI fragment as a stopgap. The proposed core change makes it an object.
- AM fields left out deliberately: `safety_level` (not evidence, per AM 3.2.1), `attestation` (evidence, belongs in 6.2), `delegation_chain` (belongs in 6.3), `agent_instance_id` (belongs in 6.2), `signature` and `transparency_log_entry` (carrier).

**Binding note.** AM extends the manifest hash into `RTMR[3]` or `HOST_DATA` at launch. The record cannot carry its own expected digest, and binding the whole record digest at launch would break rithikha's rule 3: a sponsor or owner change bumps `record_version`, the launch measurement then names a superseded version, and the instance fails a check that the rule says should pass. The sample therefore binds the **composition digest** at launch (`reference_values.launch_binding: rtmr3-extends-composition-digest`). Ownership changes then leave the hardware binding intact, and composition changes break it, which is the intended behaviour. That binding is evidence for `instance_to_software` only where a measured layer extends it before the workload runs (AM 3.2.8). It says nothing about `instance_to_key`, which needs its own evidence (#21 replay).

`canonicalization.null_handling` is set to `preserve`. AM 2.3 omits nulls before JCS. The two cannot both be the default, and #22 asks for the choice to be named.

## Checked against the registration-record schema proposed in #11

#11 (closed unmerged, head `10a718a`) proposed `contract-harness/schemas/odis.registration.record.v1.json`, the only machine-readable 6.1 schema so far. The sample record was validated against it with `jsonschema` (Draft 2020-12). After aligning `schema_version` to its constant and timestamps to its microsecond pattern, 7 errors remain, and all 7 are design questions rather than formatting:

- `approved_software_refs/0` to `/5`: the schema types each item as a string. The typed composition references proposed in #21 (and every typed entry in this sample) cannot be expressed.
- root: `additionalProperties: false`. A named profile extension, the meeting's profile switching, has nowhere to go.

`policy_profile_ref` is also a string there, matching ODIS 6.1, so it cannot carry the policy bundle digest or `enforcement_mode` either. If a 6.1 schema is adopted, these three are the decisions it encodes.

## Mapping 2: TRACE Trust Record to the ODIS 6.3 Delegation Record

The core mismatch: a TRACE Trust Record is per-execution evidence, signed by the runtime's `cnf` key (TRACE 3.1, 3.2.2). A Delegation Record is an authority grant created and integrity-protected by the Layer 2 issuer (ODIS 6.3). They share a lineage shape, and nothing else at the field level. Most TRACE fields belong with the 6.2 credential (evidence and appraisal) or a governance-checkpoint decision record (ODIS 6.4, #21 item 3).

TRACE-schema `required`: `eat_profile`, `iat`, `subject`, `model`, `runtime`, `policy`, `data_class`, `build_provenance`, `appraisal`, `cnf`. Optional: `tool_transcript`, `delegation`, `origin`, `references`, `reproducibility`, `transparency`, `signature`.

| TRACE field | ODIS 6.3 field | Fit | Where it does land |
|---|---|---|---|
| `eat_profile` | none | gap | Carrier profile id; analogous to 6.2 `format_version`. |
| `iat` | `issued_at` | partial | Different clocks and signers: TRACE `iat` is the runtime's record time; 6.3 `issued_at` is trusted time assigned by the Layer 2 issuer. |
| `subject` (SPIFFE or DID workload id) | `actor` | partial | `actor` is the stable `agent_id`. TRACE `subject` may name an instance; then it maps to 6.2 `runtime_instance_id`. |
| `model` (`provider`, `model_id`, `version`, `weights_digest`, `aibom_uri`) | none | gap | Observed model. Appraised against the 6.1 model typed ref. |
| `runtime` (`platform`, `measurement`, `rim_uri`, `nonce`, `firmware_version`) | none | gap | Evidence. 6.2 `attestation_evidence`. |
| `policy.bundle_hash`, `version`, `policy_uri` | none | gap | Checked against the 6.1 policy reference; feeds 6.4. |
| `policy.enforcement_mode` (`enforce`, `advisory`, `silent`, `declared`) | none | gap | Same gap as Mapping 1. Note the TRACE enum differs from AM's (`audit-only` there; AM 6.2.1 has the crosswalk). |
| `data_class` | `constraints` | partial | TRACE records the highest classification observed. A delegation constraint would carry a ceiling the verifier compares it to. |
| `tool_transcript` (`hash`, `call_count`, `transcript_uri`) | none | gap | Per-execution; 6.4 `action` is the request side. |
| `delegation.credential_id` | `delegation_id` | partial | Correct join key, but ODIS makes `delegation_id` unique only within the issuer's trust domain. The TRACE block needs the issuer too. |
| `delegation.parent_record_hash` | `parent_delegation_ref.record_digest` | partial | Same lineage pattern, different object: TRACE links the parent *evidence* record (JCS of the full record with signature, TRACE 3.1.3); ODIS links the parent *delegation* record. TRACE does have the named digest input #22 asks ODIS for. |
| `origin` | none | gap | Evidence provenance. |
| `references[]` (`rel: authorized-intent`) | `originating_authorization_ref` | partial | A pointer to the authorizing grant. TRACE 3.1.2 says a reference is not evidence, so it cannot satisfy ODIS chain validation. It can only point at the record that does. |
| `reproducibility` | none | gap | Evidence about coordination logic. |
| `build_provenance` | none | gap | 6.2 `software_hash` and `supply_chain_ref`, checked against 6.1 refs. |
| `appraisal` (`status`, `verifier`, `policy_ref`, `timestamp`, EAR) | none | gap | This is post-appraisal output, the meeting's "credential" side. Nearest ODIS object is 6.2. |
| `transparency` | none | gap | ODIS-CC-01 audit. |
| `cnf` (`jwk`) | `binding_profile` | partial | Holder-key confirmation. Closer to 6.2 `holder_key_ref`. |
| `signature` | record integrity invariant | partial | Different signer (runtime key, not Layer 2 issuer). |

**Counts for Mapping 2 (19 rows): 0 exact, 8 partial, 11 gap.**

6.3 MUST fields with no TRACE source: `issuer` (Layer 2 authority), `originating_principal`, `delegation_chain`, `task_id`, `granted_authorizations`, `resource_indicators`, `attenuation_profile_ref`, `expires_at`. `originating_authorization_ref` and `constraints` are only partly fed, as above. This is expected. TRACE records what happened under a grant; it is not the grant.

**Governance-checkpoint decision record.** #21 item 3 proposed a signed record with decision, policy digest, composition digest, `request_trace_id`, issuer and time. The TRACE v0.2 Trust Record has no `decision` field and no `request_trace_id`. The experimental TRACE-receipt schema does have `decision`, `reason`, `policy_digest`, `action_digest`, `call_id`, `session_id`, `trace_digest`, `issuer`, `issued_at` and `previous_receipt_hash`. That receipt, plus a `request_trace_id` field and a composition digest, is the shorter path to #21 item 3 than the Trust Record.

## cA2A convergence on the ODIS delegation record

cA2A `DelegationCredential` fields (cA2A delegation-chain.md, credential.py): `credential_id`, `issuer`, `subject`, `scope`, `depth`, `parent_id`, `signature`, optional `not_before`, `not_after`. What cA2A would need to adopt 6.3:

1. **Who issues.** cA2A hops are signed by the delegating agent's Ed25519 key (`issuer` is a raw public key). ODIS has the Layer 2 authority create and protect each record. Either cA2A hops are countersigned or re-issued by a Layer 2 issuer, or ODIS accepts peer-signed hops with the agent's runtime credential as the issuer identity. This is the main design decision.
2. **Identities, not keys.** `issuer` and `subject` hex keys map to `actor` (an `agent_id`) plus `binding_profile`. The key-to-agent link has to come from the 6.2 credential.
3. **Parent reference.** `parent_id` becomes `parent_delegation_ref` with `issuer`, `delegation_id` and `record_digest`. cA2A already hashes canonical bodies for revocation (`revoked_digest`), so the digest input exists.
4. **Missing MUST fields.** `originating_principal`, `originating_authorization_ref`, `task_id`, `resource_indicators`, `constraints`, `attenuation_profile_ref`, and mandatory `issued_at`/`expires_at` (cA2A bounds are optional).
5. **Attenuation semantics.** cA2A checks scope as a string subset. ODIS-L2-06 says lexical subset is not sufficient unless semantic equivalence is proven. cA2A can satisfy this by publishing an attenuation profile that declares scope strings opaque exact-match tokens, pinned by URI and digest in `attenuation_profile_ref`.
6. **Expiry nesting.** cA2A says windows need not nest across hops; the effective window is the intersection. ODIS 6.3 requires child `expires_at` no later than the parent's. The two produce the same usable window but different validity results for the same chain, so one rule has to win.
7. **Revocation.** cA2A `RevocationStatement` and snapshot staleness map onto ODIS-L3-04, but cA2A defines no publication protocol and ODIS requires propagation within the declared latency (at most 300 seconds). A deployment profile has to supply the feed.
8. **Trusted roots.** cA2A pins `trusted_root_issuers`; ODIS validates the root `originating_authorization_ref` against the authoritative grant. These are compatible, but the root object differs.

cA2A already emits a TRACE record per hop with `delegation.credential_id` and `parent_record_hash` (cA2A trace-a2a-profile.md). If `credential_id` becomes the ODIS `delegation_id` plus issuer, the TRACE evidence DAG and the ODIS authority chain join on one key.

## Open questions for 2026-10-14

1. Does `policy_profile_ref` become an object carrying digest and `enforcement_mode`, given the group placed the policy bundle in the registration record?
2. Is the typed-ref `ref_type` registry (software-artifact, provenance, sbom, source-bundle, model, tool-catalog, prompt, composition) defined in Core or per profile?
3. Do verifier reference values (expected measurements, required per-relationship assurance) get a 6.1 field, or do they live only in a named profile?
4. Should 6.1 name who may update a record, since ODIS-CC-05 covers creation and the meeting listed update authority as a registration-record property?
5. Is the launch-time hardware binding to the composition digest rather than the record digest, so ownership changes do not break the #16 superseded-version rule?
6. For cA2A convergence, are delegation records peer-signed by the delegating agent or issued by a Layer 2 authority, and does child expiry nest or intersect?

## What this does not establish

This mapping is from spec text at the pinned commits. No implementation was run: no Agent Manifest was converted, no sample record was validated against an ODIS schema (none is published), no TRACE record or cA2A chain was checked against 6.3. The JSON sample is checked for well-formedness, digest-string length, and against the #11 schema as above. Fit judgments (exact, partial, gap) are mine and open to dispute, especially the "partial" rows where semantics differ. The AM COSE envelope file was referenced, not re-read for this draft. `evidence_requirements` was read in AM-py only; I did not read `evidence_requirements.py` itself.
