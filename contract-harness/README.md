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

The local demo proves that model end-to-end against an in-process Target MCP stub — real
OPA and Router behavior with no Docker, Vault server, or sandbox required.

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

This proves the gate logic, not hard containment. Without a substrate preventing direct
egress, an agent could bypass the Router.

## What is real and what is a fixture

| Surface | Implemented here | Production boundary |
| --- | --- | --- |
| Router | Real MCP server/forwarder, OPA decision, action-limit enforcement, audit | Deploy it on the agent's mandatory tool path. |
| Policy | Local example bundle or a Vault-issued, Ed25519-signed runtime bundle | Operate signing roots, distribution, rotation, and revocation. |
| Passport / sponsor identity | Constructor-injected fixture providers | Real runtime identity and SVID handoff remain integration work. |
| Bridge | Optional fixture token exchange through `serve --bridge` | A production broker/exchanger is not included. |
| Target MCP | In-process or local HTTP stub | The real Target MCP owns the provider credential. |
| Substrate | Not included in the local demo | A sandbox or equivalent must prevent direct Target MCP access. |

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

## Development

```bash
mise run check               # Ruff + strict mypy + pytest
```

The test suite skips external-tool slices when their required binaries are unavailable;
check the skip count when using a partial tool installation.

## Where to go next

- [`policy/bundle.example.yaml`](policy/bundle.example.yaml) — the local runtime bundle
  used by `mise run demo`.

The Python package is `odis_harness`; the installed CLI is `odis-harness`.
