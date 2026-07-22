# OpenShell-gated agent

The optional enforced extension of the local Router demo: an agent whose tool calls are gated by a
**Vault-issued, offline-verified** APF bundle, with **OpenShell** as the substrate that
makes the gate *enforcing* rather than advisory.

```
agent (MCP client)                ← runs INSIDE an OpenShell sandbox; its network
   │  MCP over HTTP                  policy (policy.yaml) allows egress ONLY to the
   ▼                                 Router. Default-deny blocks the vendor, the
ODIS Router  (MCP server)            provider, and the internet.
   │  policy gate — the bundle's Rego, evaluated by real OPA
   │  the bundle was MINTED + transit-SIGNED by Vault; the Router verified
   │  its ed25519 signature OFFLINE before trusting it (no Vault at gate time)
   ▼
vendor MCP server                 ← holds its own provider credential; the Router
                                     forwards only allowed, obligation-checked calls
```

## What it does

`mise run demo-openshell` runs the agent **inside a real OpenShell sandbox** whose egress is
locked to the Router only — so a direct call to the vendor is **actually blocked** by the
sandbox's proxy, making the Router the agent's sole path to a tool. The pipeline: Vault mints
+ transit-signs a bundle → the Router offline-verifies the ed25519 signature → gates an
allowed call (`update_issue(APF-123)`, labels-only) and a denied one (`update_issue(OTHER-1)`).

> Want the gate's *logic* with **zero infra** (no Docker/OpenShell)? Run `mise run demo`
> — the same gate against an in-process stub. This example is the *enforced* version.

## Running it

**Prerequisites** — first complete the root README's quick demo so the mise-managed
toolchain and project are installed. No OpenShell source checkout is required.

- A **running OpenShell gateway** — brought up from the *published* image:
  ```bash
  bash examples/openshell-gated-agent/gateway/setup.sh          # pulls ghcr.io/nvidia/openshell/gateway, generates JWT keys
  mise run openshell-connect                                  # register/select; status -> Connected
  ```
- **Docker** and **OpenSSL** (the gateway builds the sandbox image, runs sandbox
  containers, and generates local gateway keys), plus
  `vault` + the built `apf-bundle-issuer` plugin + `opa` (as for any Vault path). The
  `openshell` CLI is provided by mise (`pipx:openshell`).
- **Host port 8080 free.** The sandbox→gateway callback dials
  `host.openshell.internal:8080` through the host-published mapping, so the gateway
  must own host port 8080 — `setup.sh` fails fast when something else holds it.

**Run:**

```bash
mise run demo-openshell
```

Abbreviated output (build/provisioning lines omitted):

```text
[vault] minted + transit-signed + offline-verified bundle 'odis-openshell-demo'
[router] serving on 0.0.0.0:8088 (reachable from the sandbox)
[openshell] running the agent INSIDE the sandbox...
[agent] direct vendor connect host.openshell.internal:8099 ... BLOCKED (egress proxy) ✓
[agent] gated tool catalog: ['jira-prod.update_issue']
[agent] ALLOW  jira-prod.update_issue {issue_key: APF-123, labels}
          isError=False  vendor updated APF-123
[agent] DENY   jira-prod.update_issue {issue_key: OTHER-1}
          isError=True   refused: deny
[agent] RESULT: PASS — gate enforced + mandatory
DEMO PASS
```

The sandbox image (`sandbox/Dockerfile`) bakes the MCP client in at build time — it has to,
because the running sandbox is egress-locked and cannot reach PyPI. The agent itself
(`sandbox/agent.py`) is uploaded into `/tmp` at runtime and run with the sandbox's python.

## OpenShell's role — and the honesty boundary

The policy gate is only **enforcing** because the substrate stops the agent reaching the
vendor directly. OpenShell's sandbox is **default-deny outbound** with an L7 proxy that
intercepts every CONNECT; `policy.yaml` authorizes the agent's **one** egress — the Router
— so a direct call to the vendor is refused (you see the `BLOCKED` line above). Take the
substrate away and the gate becomes advisory: an agent could just skip the Router.

Boundary, stated plainly: current OpenShell can enforce MCP methods and tool names at L7,
but not tool-argument constraints. This example intentionally uses a host-scoped allow to
make the Router the only reachable MCP endpoint. The Router then demonstrates the extra
layer this project is about: a signed Authority Grant, OPA decisions, and argument-level
action limits. OpenShell forces the path; the Router applies the signed semantic policy.

## Cleanup

The demo deletes its sandbox. Stop the local gateway when you are done:

```bash
docker compose -f examples/openshell-gated-agent/gateway/docker-compose.yml down
```

## Files

| Path | Purpose |
|------|---------|
| `openshell_demo.py` | The demo — agent inside a real OpenShell sandbox (egress enforced). |
| `policy.yaml` | OpenShell network policy: the agent's only egress is the Router (`host.openshell.internal:8088`). |
| `sandbox/Dockerfile` | Sandbox image = base + the MCP client (baked at build time). |
| `sandbox/agent.py` | The agent run inside the sandbox: blocked-vendor check + allow/deny calls through the Router. |
| `gateway/` | Repo-free local gateway: `docker-compose.yml` + `gateway.toml` + `setup.sh` (pulls the published image). |

## Provenance of the pieces

- The bundle is **issued by the `apf-bundle-issuer` Vault plugin** (`vault/` + `vault-plugin/`)
  — minted, mapped from the workload JWT, and transit-signed.
- The Router, policy gate (OPA), discovery, and audit are the harness core
  (`src/odis_harness/`); the agent uses the official MCP SDK client.
- The OpenShell **gateway runs from the published image** (`ghcr.io/nvidia/openshell/gateway`);
  the **CLI** is installed via mise (`pipx:openshell`) — neither needs the OpenShell source.
