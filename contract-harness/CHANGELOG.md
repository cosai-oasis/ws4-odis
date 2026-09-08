# Changelog

All notable changes to the ODIS Contract Harness are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Removed

- **Breaking (envelope wire format).** `active_verdicts` is gone from
  `odis.authz.request.v1` and from `AuthzRequest`. It declared a detector-verdict input no
  code path supplied. ODIS §6.4 types `runtime_risk_signals` as authenticated signal objects a
  checkpoint MUST validate for issuer trust, integrity, replay resistance, freshness and
  subject correlation before use, and there is no signal authority here to validate against;
  L1-12's consequence half is further out of reach while `revocation_check_mechanism` is
  `none`. Because the schema sets `additionalProperties: false`, a payload carrying the field
  is now rejected rather than ignored, and a signal the checkpoint cannot validate has no
  route into a decision. Nothing in this repo sent it.

- **Breaking (envelope wire format).** `instance_id` is gone from `$defs/ResourceRef` in
  both `odis.runtime.context.v1` and `odis.authz.request.v1`. It declared a resource-instance
  handle nothing supplied: the Router knows the resource family and the tool arguments at
  gate time, not an instance, and the provider-shaped key it would have carried already
  travels in `request_body`. Both schemas set `additionalProperties: false`, so a payload
  carrying it is now rejected rather than ignored. It was invisible to the type layer
  because it lived inside `target_resource: Mapping[str, Any]` — a JSON Schema `$defs`
  shape the dataclasses do not model, which is why the totality invariant is asserted
  against the schema files rather than against types.

### Changed

- **Breaking (issuer).** `vendor_mcp.egress_mode: "native"` is refused at the mapping
  write. It is a legal ODIS-L2-15 value but a false claim from this issuer: it asserts the
  target itself validates the agent's runtime credential and delegation record, the Router
  never reads the field, and this adapter enforces at the adapter. Signing it would put an
  unenforceable assertion inside integrity-protected bytes and invite a consumer to skip
  enforcement nothing performs. `bridge` is the only signable mode.
- **Breaking (issuer).** `lifecycle_state` drops `pending`, which nothing ever wrote, and
  `revoked` is terminal — a revoked mapping cannot be rewritten to any other state.
  Previously the four states shared one code path, so `revoked` claimed more than the
  plugin enforced and was indistinguishable from `suspended`. `suspended` is the reversible
  pause; recovering from `revoked` means a new record, so the revoked one stays on the trail.
- The recorded delegating principal carries the token accessor when no identity entity is
  attached (`vault:token:<display name>:<accessor>`). A display name alone is `"token"` for
  every entity-less token, so two operators compared equal and `envelopeConflicts` would
  compose an accountability split into one grant naming neither of them.

- **Breaking (envelope wire format).** The per-call identity field is `originating_principal`,
  not `sponsor`, in `odis.runtime.context.v1` and in `odis.authz.request.v1`'s `subject`.
  ODIS separates three identities: `sponsor_ref` and `owner_ref` (§6.1, who is accountable
  for an agent and where it belongs, on an Agent Registration Record) from
  `originating_principal` (§6.3, on whose authority it is acting right now). The harness had
  one per-call field under the sponsor name doing originating-principal work. The Python API
  follows: `OriginatingPrincipal`, `OriginatingPrincipalProvider`,
  `FixtureOriginatingPrincipalProvider`, `RuntimeContextFactory(principal_provider=...)`,
  `WorkloadIdentityProvider.issue(principal_id=...)`. Both schemas keep
  `additionalProperties: false`, so a payload carrying `sponsor` is now rejected.
- Envelopes carry the loaded Authority Grant's `bundle_id`, `bundle_version` and
  `trust_root_id` instead of fixture constants, so an audit event names the grant that
  authorized the call. Those three are no longer `const`-pinned in the envelope schemas.
- Refusal reasons are a typed `ReasonCode`, and the Router audits the evaluator's own
  reason, so a fail-closed `policy_error` is distinguishable from a policy `deny`.

### Fixed

- An expired grant no longer mints a credential. `build_router_from_bundle` refuses with
  `BundleExpired` before building any vendor client, because a minting posture performs its
  RFC 8693 exchange during the leg-2 establish phase — so an expired grant would have
  cached a live bearer and anchored it against a grant conferring nothing, before the first
  forward could refuse. The Router still re-checks per call.
- `policy_digest` identifies a policy again, not an issuance. `issued_at` and `expires_at`
  are excluded from it: with a one-hour default TTL, including them gave two grants with
  identical policy, routing, limits, actor and delegator different digests an hour apart,
  so an auditor grouping audit events by `policy_digest` got a fresh bucket every hour and
  could not tell "policy changed" from "grant re-issued". `actor` and
  `originating_principal` remain in the digest — re-issuing to a different agent is a
  different authority. Both excluded fields stay integrity-protected by the signature.
- The dev-Vault fixture directory is per-instance under the system temp dir and removed on
  teardown. It holds a live workload JWT, and a predictable name was either shared between
  concurrent runs or left behind by every one of them.
- `contracts.to_iso` rejects a tz-naive datetime instead of reading it as host-local, which
  silently shifted a credential expiry by the host's UTC offset.
- The record-version mark is monotonic: it stores the maximum of the stored and incoming
  version, so two writes arriving out of order cannot leave the mark below a version
  already accepted and make a replay look current.
- A mapping stored before the lifecycle fields existed now fails resolution with a named
  error instead of being skipped. Skipping produced `errNoAuthorizedBundle`, which an
  operator cannot distinguish from "no mapping was ever written". It is deliberately not
  normalized to `active`: such a record also carries no delegating principal, and
  defaulting that would invent an accountable operator for a delegation nobody is recorded
  as having made. Rewriting the mapping is the migration.
- The dev Vault is reaped after a forced kill, instead of lingering as a zombie for the
  test session.
- The mapping record-version floor is written before the record, not after: a failure
  between the two now refuses a later write at that version rather than silently
  re-accepting the version it just consumed.
- `grantTTL` clamps to `maxGrantTTL` at the issuance seam as well as at the write handler,
  so a record reaching storage by another route cannot mint an effectively immortal grant.
- `MappingRecordRef` and `AttenuationProfileRef` validate on construction, and both
  schemas require `sha256:<64 lowercase hex>` for a digest — the pattern was `minLength: 1`,
  which accepted `"sha256:abc"`.
- A vendor server that fails to start no longer leaks its task into later tests.
- MCP clients connect through `transports.mcp_url`, which carries the trailing slash the
  Starlette `Mount` requires. Six call sites built that URL themselves and every one
  omitted it, so each request took a 307 and re-POSTed its body. `serving_http` also takes
  a `log_level`, which the OpenShell example threads through `ODIS_DEMO_LOG_LEVEL` so the
  Router's access log can be turned on.

- The Vault test slice is reentrant. `DevVault` took a fixed port and a shared fixture
  directory, so two concurrent suite runs bound the same port and the second authenticated
  against the first's JWT role — surfacing as a `400`/`403` from `auth/jwt/login`,
  indistinguishable from a provisioning bug. Port and fixture directory are now
  per-instance.
- `mise run test` builds the Vault plugin first. `vault` is on `PATH` from `[tools]`, so the
  `requires_vault` slice always runs rather than auto-skipping, which meant it ran against
  whatever binary was already in `dist/`; a stale one fails on fields it does not yet emit
  and reads as a code defect. The build is incremental, so the dependency is free.
- One renderer produces the `Z`-suffixed instants the envelope schemas require, in
  `contracts.to_iso`. A second implementation could have drifted from the schemas silently,
  since nothing rejects a valid-but-differently-rendered instant.

- `resolve_opa_binary` rejects an unusable `$ODIS_OPA_BIN` instead of returning it, and the
  schemas directory resolves by probing for `odis.bundle.v1.json` rather than for any
  directory named `schemas`.
- `VendorMcp` validates `url` against the schema's `^https?://`.
- `mise run install` honours `uv.lock`; `mise run test-all` reaches the Vault test slice.
- An `obligation_violation` refusal audits the enforcer's own message, naming the argument
  that failed, instead of a bare reason code. The agent still receives only the code.
- Schema `$id`s are URNs. They pointed at `https://apf.local/`, under a TLD RFC 6762
  reserves for mDNS, so a consumer treating them as fetchable would emit a link-local
  multicast lookup. Nothing dereferences them: the validator keys on the file stem and
  every `$ref` is local.
- The OpenShell example's sandbox image pinned `mcp>=1.27`, which resolved to a 2.x client
  whose API the agent script is not written against — inside a sandbox egress-locked to the
  Router and unable to reach PyPI to correct it. Pinned to the version in `uv.lock`.


### Added

- An issued Authority Grant records who delegated it and under what rules (ODIS §6.3):
  `actor` (the validated JWT subject), `originating_principal` (single-valued, so a grant
  composed from two delegating operators has nowhere to put the second and issuance refuses
  it), `contributing_records` (each mapping's name, version and content digest),
  `attenuation_profile_ref` (a versioned URI plus digest resolving the shrink-only
  comparison rules, which were previously compiled into the plugin binary with nothing a
  verifier could resolve), and `issued_at`/`expires_at`. `delegation_chain` is present and
  constrained empty: this implementation mints root records only, so `[]` asserts a single
  hop where absence asserts nothing, and a claimed hop is refused rather than modelled.
  `contributing_records` deliberately does **not** use §6.3's `originating_authorization_ref`
  name — that field references the authoritative grant that authorized the delegating
  principal *to delegate*, and the plugin holds no reference to whatever approved an
  operator's Vault policy, so the draft's field stays unset rather than carrying a
  different object under its name.
- Mapping records carry `lifecycle_state`, `valid_until` and a monotonic `record_version`,
  enforced at resolution, so a suspended or superseded record stops conferring authority and
  a replayed older record is refused. This is what gives "active" in ODIS-L2-14 something to
  check.
- A grant has a validity window and the Router enforces it: `Bundle.expired()` is checked
  before the policed-tool branch, so an expired grant refuses every call with
  `grant_expired` — including on a `permissive` family, which forwards with no policy
  evaluation and would otherwise bypass the check. A grant declaring no expiry never
  expires, which is the shape of a hand-authored local grant.
- `vendor_mcp.egress_mode` declares `native` or `bridge` per target (ODIS-L2-15), defaulted
  and validated at issuance so the declaration always exists and cannot be an unrecognised
  value. This harness is `bridge` throughout: the vendor MCP server authenticates the
  Router's leg, not the agent's.
- The Router audits the terminal exchange on both legs that mint a Target-MCP credential
  (ODIS-CC-06), emitting `odis.bridge.terminal_exchange` bound to the grant in force, the
  target's stable `endpoint_id`, and a sha256 fingerprint of each credential artifact —
  never the secret. The anchor is a required constructor argument on both mechanisms, so a
  credential that could not be recorded cannot be minted: omitting it is a type error at
  the construction site, not a runtime check. The two legs are not equivalent, and the
  event shape shows it — the interactive OAuth leg binds no originating principal and no
  subject assertion, and requests no audience, so `endpoint_id` is its only target
  identifier. Both follow from an interactive human grant this process never observes.
- The call's trace identifier reaches the adapter (ODIS-CC-01): `call_tool` carries the
  Router's `correlation_id` and `HttpMcpClient` sends it as `ODIS-Request-Trace-Id`, so the
  identifier on the audit trail is the one the Target MCP receives.

- `demo --signed` and `mise run demo-signed`: the canonical scenarios against a Vault-issued
  grant whose ed25519 signature is verified offline. Same Router, gate, transport and vendor
  as `demo` — one axis changed.
- `serve` and `demo` require an explicit grant-trust choice for a local `--bundle`:
  `--bundle-pubkey-file` or `--trust-bundle-unverified`. There is no default, and the startup
  banner names which is in force. Previously a verifier that accepts any payload was
  hardcoded, so the deploy-shaped command trusted an unverified grant silently.


- `serve --inbound-key/--inbound-issuer/--inbound-audience` makes the Router's MCP surface
  an OAuth 2.1 resource server. A caller presents a workload JWT, validated for signature,
  issuer, audience and expiry against an asymmetric-algorithm allowlist matching the Vault
  plugin's, before any handler runs; `agent_id` is then the verified subject rather than a
  constant. Audit events record how the identity was established, so a received identity is
  distinguishable from an asserted one. Trust material is parsed strictly at startup — a
  private-key PEM, malformed material, or a key that cannot verify any allowed algorithm
  exits non-zero instead of serving. Without `--inbound-key` the surface still accepts any
  caller, which the startup banner states outright. It listens on plain HTTP and takes no
  certificate or key.

- Initial contribution to the CoSAI ODIS workstream: a runnable, 100%-open-source
  candidate implementation of the ODIS Router / governance-checkpoint wedge, built as an
  MCP policy-forwarder and contributed as a technical demonstration.
  - The Router forward pipeline: trusted identity context, policed-tool gate, real OPA
    (Rego) policy decisions, per-argument action limits, and schema-validated audit
    events — fail-closed at every step.
  - The `apf-bundle-issuer` HashiCorp Vault plugin (Go): workload-JWT validation,
    grant union with fail-closed collision rules, tier ceilings, policy-DSL-to-Rego
    projection, and Ed25519 transit-signed canonical bundles the Python harness
    verifies offline.
  - A Terraform module provisioning a persistent Vault's non-secret resources, with an
    out-of-band signing configuration step that keeps the AppRole `secret_id` out of
    Terraform state.
  - An OpenShell-gated example where a real sandbox makes the Router the agent's only
    network path — the gate as mandatory enforcement, not advisory convention.
  - Three proof levels runnable via mise: `demo` (local, zero infrastructure),
    `smoke-vault` (signed bundles), and `demo-openshell` (substrate-enforced).
