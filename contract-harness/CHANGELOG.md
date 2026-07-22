# Changelog

All notable changes to the ODIS Contract Harness are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow
[Semantic Versioning](https://semver.org/spec/v2.0.0.html) once it reaches 1.0.

## [Unreleased]

### Added

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
