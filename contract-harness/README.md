# ODIS Contract Harness

A runnable, 100%-open-source prototype of an ODIS/APF-style governance checkpoint for
agent tool calls. An agent calls the Router over MCP; the Router evaluates real Rego with
OPA, enforces argument-level limits, forwards approved calls to a Target MCP server, and
audits every outcome.

This directory contains one candidate **Router / governance-checkpoint wedge**
implementation, contributed to the [CoSAI](https://www.oasis-open.org/projects/cosai/)
(an OASIS Open Project) ODIS workstream as a technical demonstration. It is not all of
ODIS or APF, and both remain working drafts rather than ratified standards.

## The 30-second model

```text
agent ──MCP──> Router ──approved call──> Target MCP ──> provider
                 │                          │
                 ├─ OPA policy decision     └─ owns the provider credential
                 ├─ argument limits
                 └─ audit event
```

The harness demonstrates that model at three levels:

| Level | Command | What it proves |
| --- | --- | --- |
| Local | `mise run demo` | Real OPA and Router behavior against an in-process Target MCP stub. No Docker, Vault server, or OpenShell. |
| Signed | `mise run smoke-vault` | A local dev Vault issues and transit-signs a bundle; the harness verifies it offline. |
| Enforced | `mise run demo-openshell` (needs the gateway up first — see [Enforced OpenShell demo](#enforced-openshell-demo)) | A real OpenShell sandbox makes the Router the agent's only network path to the Target MCP. |

The local demo is the newcomer path. The other levels are optional extensions, not
prerequisites for understanding the project; their extra mise-managed tools are installed
on demand when those tasks run.

## Quick demo

Install [mise](https://mise.jdx.dev/), then from this directory (`contract-harness/`):

```bash
mise trust
mise install
mise run install
mise run demo
```

The demo runs four canonical calls against `policy/bundle.example.yaml`:

```text
Tier 3 allow                         -> forwarded
Tier 3 deny                          -> refused: deny
Tier 3 obligation violation          -> refused: obligation_violation
Unpoliced tool under strict mode      -> refused: unpoliced_tool
downstream vendor calls observed: 1
```

What just ran:

- the bundle was loaded from a local file using a fixture signature verifier;
- real OPA evaluated the bundle's Rego;
- the Router enforced the returned field limits;
- an in-process Target MCP stub received only the allowed call;
- structured audit events were written to `/tmp/odis-demo-audit.jsonl`.

This proves the gate logic, not hard containment. Without OpenShell or an equivalent
substrate preventing direct egress, an agent could bypass the Router.

## What is real and what is a fixture

| Surface | Implemented here | Production boundary |
| --- | --- | --- |
| Router | Real MCP server/forwarder, OPA decision, action-limit enforcement, audit | Deploy it on the agent's mandatory tool path. |
| Policy | Local example bundle or Vault-issued, Ed25519-signed runtime bundle | Operate signing roots, distribution, rotation, and revocation. |
| Passport / sponsor identity | Constructor-injected fixture providers | Real runtime identity and SVID handoff remain integration work. |
| Bridge | Optional fixture token exchange through `serve --bridge` | A production broker/exchanger is not included. |
| Target MCP | In-process or local HTTP stub | The real Target MCP owns the provider credential. |
| Substrate | Real OpenShell in the advanced example | OpenShell or equivalent must prevent direct Target MCP access. |

The Router does not accept a static provider bearer. `demo` and `serve` without
`--oauth2` or `--bridge` use no Router-to-Target credential; the optional fixture Bridge
demonstrates short-lived, audience-scoped leg-2 auth. The Target MCP remains the
provider-credential boundary.

## Running `serve`: policy source and Target MCP authentication

`serve` makes two independent choices: where the Router gets its Authority Grant and how
it authenticates to the downstream Target MCP. `--signed` controls the grant source;
`--oauth2` controls downstream authentication. `--bundle` selects a local grant only when
`--signed` is absent.

| Option | When present | When absent |
| --- | --- | --- |
| `--bundle PATH` | Plain `serve` loads that local YAML with the fixture verifier. In signed mode this option is ignored. | Plain `serve` uses `$ODIS_BUNDLE`, then `policy/bundle.example.yaml`; signed mode gets the grant from Vault. |
| `--signed` | The Router exchanges its workload JWT for a Vault token carrying the `apf-issue` policy, calls `apf/issue`, and offline-verifies the returned signed bundle. | No Vault call or cryptographic verification occurs; the Router trusts the selected local YAML through the fixture verifier. |
| `--oauth2` | Router-to-Target requests use interactive authorization-code/PKCE with dynamic client registration; tokens stay in memory. | Without `--bridge` either, the Router still attempts Target MCP discovery and calls, but with `auth=None`; an authentication-required endpoint fails closed. |

`--oauth2` and `--bridge` are mutually exclusive; selecting both is a CLI error.

For a local, convention-trusted GitLab policy plus real downstream OAuth:

```bash
mise exec -- odis-harness serve \
  --bundle policy/gitlab-readonly.bundle.yaml \
  --oauth2
```

For a Vault-issued grant plus downstream OAuth, use `--signed --oauth2` and provide the
required Vault address, workload-JWT file, and bundle-public-key file shown by
`odis-harness serve --help`. The Vault-issued grant itself must contain the Target MCP route
and policy. Although the CLI currently accepts `--signed --oauth2 --bundle PATH`, `PATH` has
no effect in signed mode.

## Signed-bundle demo

After the quick demo:

```bash
mise run smoke-vault
```

This builds the Go `apf-bundle-issuer` plugin, boots an ephemeral dev Vault, provisions
the scoped AppRole and JWT-auth legs, issues a bundle, and verifies its Ed25519 signature
offline. It does not require Docker or OpenShell.

The configuration details are in [`vault/SETUP.md`](vault/SETUP.md). The fixture-to-SPIRE
trust swap and the unresolved production SVID handoff are documented in
[`vault/README.md`](vault/README.md).

## Enforced OpenShell demo

The full example adds the substrate that makes the gate mandatory:

```bash
bash examples/openshell-gated-agent/gateway/setup.sh
mise run openshell-connect  # register/select the gateway + show status
mise run demo-openshell
```

This path additionally requires Docker and OpenSSL. See
[`examples/openshell-gated-agent/README.md`](examples/openshell-gated-agent/README.md)
for expected output, cleanup, and the exact enforcement boundary.

Current OpenShell can enforce MCP methods and tool names at L7. This example uses
OpenShell to force traffic through the Router, while the Router demonstrates the signed
grant, OPA, and tool-argument constraints that are specific to this harness.

## How the signed path works

The `apf-bundle-issuer` Vault plugin:

1. validates a workload JWT;
2. unions the structured grants assigned to that identity;
3. optionally intersects them with a shrink-only tier ceiling;
4. projects the structured capability rules to Rego and a governed-tools map;
5. serializes canonical bundle bytes and asks Vault transit to sign them.

The Router exchanges its workload JWT for access to `apf/issue`, receives the signed
bundle, and verifies the signature locally before loading it. Vault is not called during
individual policy decisions.

## Development

```bash
mise run check               # Ruff + strict mypy + pytest (Python)
mise run check-all           # check + the Go plugin lint/tests
mise run test-vault-plugin   # Go plugin tests
mise run lint-vault-plugin   # Go plugin lint
mise run tf:lint             # static Terraform checks
```

The test suite skips external-tool slices when their required binaries are unavailable;
check the skip count when using a partial tool installation.

The Terraform module under `terraform/` provisions the persistent Vault resources but
requires one complete, out-of-band `config/signing` write after apply so `secret_id` never
enters state. It is an advanced operational path, not part of the newcomer demo.

## Where to go next

- [`docs/run-modes.md`](docs/run-modes.md) — the conceptual walkthrough and honesty
  boundaries.
- [`policy/bundle.example.yaml`](policy/bundle.example.yaml) — the local runtime bundle
  used by `mise run demo`.
- [`examples/openshell-gated-agent/README.md`](examples/openshell-gated-agent/README.md)
  — the enforced demo.
- [`vault/SETUP.md`](vault/SETUP.md) — the signed-bundle issuer walkthrough.
- [`terraform/README.md`](terraform/README.md) — the experimental persistent-Vault
  provisioning path.

The Python package is `odis_harness`; the installed CLI is `odis-harness`.
