# `odis_harness.substrate`

The **Passport surface** — the trusted identity providers the Router consumes
to build a `RuntimeContext`, without re-implementing the systems that issue
those identities. Production deployments substitute their own issuers at the
interfaces these Protocols expose.

This package intentionally does not define orchestration or egress-guard
abstractions. The Router is the orchestrator; sandbox containment and egress
blocking are OpenShell's (or an equivalent substrate's) concern.

## Identity production

Two distinct provider Protocols separate the two trust sources production deployments
substitute independently:

- **Workload identity (Passport)** — `WorkloadIdentityProvider` returns an
  `AgentRuntimeCredential` (SPIFFE SVID, Kubernetes service-account token,
  cloud workload identity, hardware-attested token, …). The stand-in
  (`odis_harness.fixtures.identity:FixtureWorkloadIdentityProvider`) returns
  `fixture-svid-<agent_id>`.
- **Originating principal** — `OriginatingPrincipalProvider` returns an `OriginatingPrincipal`
  (the OIDC/SSO originating principal; the stand-in uses `fixture-principal` / `entra_oidc`).

This package holds **only the Protocols**. Both stand-ins live in `odis_harness.fixtures`,
which the core may not import — a caller supplies them, and `cli/builders.py:stub_context_factory`
is where the CLI does. No production implementation of either Protocol ships. `agent.type`
distinguishes the two cases in the trail rather than letting a stand-in pass for a verified
identity: `fixture_workload_identity` when the id came from these providers, and
`verified_bearer` when `serve --inbound-key` validated an inbound credential and took the
agent id from its subject.

The substrate **consumes** both; it does not issue either. The Router's
`RuntimeContextFactory` (`odis_harness.mcp_forwarder.identity`) calls the two
providers to assemble the trusted `RuntimeContext` — caller-supplied subject
fields are never trusted.

## Out-of-scope

- Kernel-level isolation and egress enforcement (namespaces, seccomp,
  Landlock, network policy) — OpenShell's responsibility, "OpenShell or
  equivalent."
- Credential minting / provider tokens — the Target MCP server holds its
  own provider credential; ODIS/Passport never mint or hold it.
