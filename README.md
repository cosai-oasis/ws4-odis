[Placeholder README for ODIS repo]

# ODIS — Open Delegation & Identity Standard

This repository is part of the work of the **Coalition for Secure AI (CoSAI)**. CoSAI is an [OASIS Open Project](https://www.oasis-open.org/open-projects/) and an open ecosystem of AI and security experts from industry-leading organizations. We are dedicated to sharing best practices for secure AI deployment and collaborating on AI security research and tool development.

For more information on CoSAI, please visit the [CoSAI website](https://www.oasis-open.org/projects/cosai/) and the [Open Project repository](https://github.com/cosai-oasis/oasis-open-project), which contains our governance information and project charter.


## What is ODIS?

ODIS defines an open, vendor-neutral architecture for establishing cryptographic identity, delegation, and governance for autonomous AI agents operating across enterprise trust domains. It augments existing OAuth 2.0, OIDC, SPIFFE, SCIM, and policy-engine infrastructure; it does not replace them.

ODIS addresses four foundational pillars of agentic identity: delegated user identity, agent code or package identity, agent runtime instance identity, and cascaded multi-agent delegation. The architecture is organized as three implementation layers: Passport, Bridge, and Router.

This specification is designed for adoption by identity providers, cloud platforms, agent-framework developers, and enterprise security teams. Conformance profiles allow incremental adoption.

## In this repository

- [`contract-harness/`](contract-harness/) — a runnable, 100%-open-source candidate implementation of the ODIS Router / governance-checkpoint wedge (an MCP policy-forwarder gated by OPA policy, with an optional Vault-signed bundle-issuance path), contributed as a technical demonstration.
