# `odis_harness.substrate`

The **Passport surface** — the trusted identity providers the Router consumes
to build a `RuntimeContext`, without re-implementing the systems that issue
those identities. Real deployments substitute their own issuers at the
interfaces these Protocols expose.

This package intentionally does not define orchestration or egress-guard
abstractions. The Router is the orchestrator; sandbox containment and egress
blocking are OpenShell's (or an equivalent substrate's) concern.

## Identity production

Two distinct provider Protocols separate the two trust sources real deployments
substitute independently:

- **Workload identity (Passport)** — `WorkloadIdentityProvider` returns an
  `AgentRuntimeCredential` (SPIFFE SVID, Kubernetes service-account token,
  cloud workload identity, hardware-attested token, …). The fixture
  (`FixtureWorkloadIdentityProvider`) returns `fixture-svid-<agent_id>`.
- **Sponsor identity** — `SponsorIdentityProvider` returns a `SponsorIdentity`
  (an OIDC/SSO sponsor; the fixture uses `fixture-sponsor` / `entra_oidc`).

The substrate **consumes** both; it does not issue either. The Router's
`RuntimeContextFactory` (`odis_harness.mcp_forwarder.identity`) calls the two
providers to assemble the trusted `RuntimeContext` — caller-supplied subject
fields are never trusted.

## Out-of-scope

- Real kernel-level isolation and egress enforcement (namespaces, seccomp,
  Landlock, network policy) — OpenShell's responsibility, "OpenShell or
  equivalent."
- Real credential minting / provider tokens — the Target MCP server holds its
  own provider credential; ODIS/Passport never mint or hold it.
