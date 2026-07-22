"""Real OpenShell-gated demo: the agent runs INSIDE an OpenShell sandbox.

The agent runs inside a real OpenShell sandbox whose network policy (`policy.yaml`) permits
exactly one destination — the Router — so a direct call to the vendor is *actually blocked*
by the sandbox's egress proxy. The gate is mandatory, not advisory. (For the gate's *logic*
with zero infra — no Docker/OpenShell — run `uv run odis-harness demo` instead.)

Topology (host services outside the sandbox; agent inside it):

    [OpenShell sandbox]  agent.py  ──MCP──►  ODIS Router (serve, 0.0.0.0:8088)
       egress-locked to                         │ gate: Vault-signed bundle's Rego via OPA
       the Router only                          ▼
                                             vendor MCP server (0.0.0.0:8099, host creds)
    direct agent→vendor  ──►  ⛔ blocked by the sandbox (not in the egress allow-list)

Prerequisites (all repo-free — no OpenShell source checkout):
  - the OpenShell gateway running + registered:  bash gateway/setup.sh
        mise run openshell-connect
  - vault + the built apf-bundle-issuer plugin + opa (as for `mise run demo-openshell`)
  - Docker (the gateway builds the sandbox image from sandbox/Dockerfile)

Run:  mise run demo-openshell
      (or: uv run python examples/openshell-gated-agent/openshell_demo.py)
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import os
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import uvicorn
from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from starlette.applications import Starlette

from odis_harness.bundle.vault_client import VaultBundleClient
from odis_harness.cli.builders import (
    SignedBundleSource,
    audit_stream,
    build_audit,
    build_router_signed,
    http_vendor_factory,
    resolve_opa_binary,
)
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import MCP_MOUNT_PATH, build_asgi_app
from odis_harness.vault.dev import DevVault, plugin_built, vault_bin

# Fixed ports — must match policy.yaml (Router endpoint) and agent.py defaults.
ROUTER_PORT = 8088
VENDOR_PORT = 8099
SANDBOX_NAME = "odis-openshell-demo"
_HERE = Path(__file__).resolve().parent

# The fixture identity dev-Vault provisioning mints + binds the mapping to.
_ISSUER = "https://fixture.issuer.odis.local/"
_AUDIENCE = "apf-bundle-issuer"
_SUBJECT = "spiffe://example.org/agent/jira"

# A structured policy spec (the DSL the mapping now stores); the Vault plugin
# compiles it to the Rego the Router runs via OPA at issuance (APF Policy Projection).
_POLICY_SPEC = {
    "rules": [
        {
            "verb": "update_issue",
            "where": [{"field": "issue_key", "op": "startsWith", "value": "APF-"}],
            "allow_fields": ["labels"],
        },
    ],
}


def _vendor_app() -> Starlette:
    server: Server = Server("demo-jira-vendor")

    @server.list_tools()
    async def _list() -> list[Tool]:
        return [Tool(name="update_issue", description="Update a Jira issue",
                     inputSchema={"type": "object", "required": ["issue_key"]})]

    @server.call_tool(validate_input=False)
    async def _call(_name: str, arguments: dict) -> list[TextContent]:
        return [TextContent(type="text", text=f"vendor updated {arguments.get('issue_key')}")]

    return build_asgi_app(server)


@contextlib.asynccontextmanager
async def _running(app: Starlette, port: int) -> AsyncIterator[None]:
    # Bound on 0.0.0.0 (not 127.0.0.1) — DELIBERATE for both services: the sandbox
    # reaches the Router via host.openshell.internal -> the docker-bridge gateway IP,
    # and the VENDOR must also be bridge-reachable so the agent's direct-connect
    # probe proves the egress POLICY blocks it (loopback-only would make that test
    # pass vacuously, with no policy enforced). Demo-only exposure: production
    # non-loopback binds should add Origin/Host validation (see transports.py).
    server = uvicorn.Server(uvicorn.Config(app, host="0.0.0.0", port=port, log_level="error"))  # noqa: S104
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        if not server.started:
            msg = f"server on :{port} did not start (port already in use?)"
            raise RuntimeError(msg)
        yield
    finally:
        server.should_exit = True
        await task


def _point_mapping_at_local_vendor(addr: str, vendor_url: str) -> None:
    bundle = {
        "bundle_id": "odis-openshell-demo",
        "bundle_version": "0.1.0",
        "trust_root_id": "fixture-trust-root",
        "families": {
            "jira-prod": {
                "vendor_mcp": {"endpoint_id": "jira-prod-mcp-v1", "url": vendor_url},
                "policy": _POLICY_SPEC,
                "default_mode": "strict",
            },
        },
    }
    resp = httpx.post(
        f"{addr}/v1/apf/mappings/jira",
        headers={"X-Vault-Token": "root"},
        json={
            "bound_issuer": _ISSUER,
            "bound_audiences": _AUDIENCE,
            "bound_subject": _SUBJECT,
            "bundle": json.dumps(bundle),
        },
        timeout=5.0,
    )
    resp.raise_for_status()


async def _sh(*args: str, timeout: float = 180.0) -> tuple[int, str]:  # noqa: ASYNC109 — one subprocess helper with per-call ceilings beats asyncio.timeout at 8 call sites
    """Run a command, capturing combined output."""
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        # Reap the child rather than orphaning it behind the cancelled communicate().
        proc.kill()
        await proc.wait()
        raise
    return proc.returncode or 0, out.decode("utf-8", "replace")


async def _run_agent_in_sandbox() -> int:
    """Build the sandbox image, create the egress-locked sandbox, run agent.py inside."""
    sandbox_dir = str(_HERE / "sandbox")
    policy = str(_HERE / "policy.yaml")

    await _sh("openshell", "sandbox", "delete", SANDBOX_NAME, timeout=60)

    print(
        f"[openshell] building sandbox image + creating '{SANDBOX_NAME}' "
        "(egress-locked to the Router)..."
    )
    rc, out = await _sh(
        "openshell", "sandbox", "create", "--from", sandbox_dir, "--policy", policy,
        "--name", SANDBOX_NAME, "--keep", "--no-tty", "--no-auto-providers", "--", "echo", "ready",
        timeout=900,
    )
    if rc != 0:
        print(out)
        print("[openshell] sandbox create FAILED")
        return 1

    # From here the sandbox exists (created with --keep): every exit path below —
    # early return, exception, or success — must delete it, so the work runs in a
    # try whose finally owns cleanup and reports (never swallows) a failed delete.
    try:
        rc, cfg = await _sh("openshell", "sandbox", "ssh-config", SANDBOX_NAME, timeout=60)
        match = re.search(r"^Host\s+(\S+)", cfg, re.MULTILINE)
        if rc != 0 or not match:
            print(cfg)
            print("[openshell] could not get sandbox ssh-config")
            return 1
        host = match.group(1)
        with tempfile.NamedTemporaryFile("w", suffix=".sshcfg", delete=False) as f:
            f.write(cfg)
            ssh_cfg = f.name

        # Wait for ssh.
        for _ in range(20):
            rc, _o = await _sh("ssh", "-F", ssh_cfg, host, "true", timeout=15)
            if rc == 0:
                break
            await asyncio.sleep(2)

        # Upload the agent into /tmp (read-write, owned by the sandbox user) — not baked
        # into the image (the base image's non-root build user can't own a COPY'd file).
        # The egress policy keys on the *binary* (/sandbox/.venv/bin/python3), so the
        # script's location is irrelevant.
        agent_local = str(_HERE / "sandbox" / "agent.py")
        rc, out = await _sh("scp", "-F", ssh_cfg, agent_local, f"{host}:/tmp/agent.py", timeout=30)
        if rc != 0:
            print(out)
            print("[openshell] failed to upload agent.py into the sandbox")
            return 1

        print("[openshell] running the agent INSIDE the sandbox...\n" + "-" * 60)
        rc, agent_out = await _sh(
            "ssh", "-F", ssh_cfg, host, "/sandbox/.venv/bin/python3 /tmp/agent.py", timeout=120
        )
        print(agent_out.rstrip())
        print("-" * 60)
        # Clamp: ssh/python propagate exotic codes (255 transport, 2 unopenable
        # script) that would collide with the demo's documented SKIP exit (2).
        return 0 if rc == 0 else 1
    finally:
        del_rc, del_out = await _sh("openshell", "sandbox", "delete", SANDBOX_NAME, timeout=60)
        if del_rc != 0:
            print(f"[openshell] WARNING: cleanup failed — delete '{SANDBOX_NAME}' manually:")
            print(del_out.rstrip())


async def main() -> int:
    # Preflight.
    if vault_bin() is None:
        print("SKIP: no vault binary (set ODIS_VAULT_BIN or place ./vault next to opa)")
        return 2
    if not plugin_built() and not DevVault.build_plugin():
        print("SKIP: plugin not built (run: mise run build-vault-plugin)")
        return 2
    try:
        rc, status = await _sh("openshell", "status", timeout=30)
    except FileNotFoundError:
        print("SKIP: `openshell` CLI not found (mise provisions it for `mise run demo-openshell`)")
        return 2
    if rc != 0 or "Connected" not in status:
        print("SKIP: OpenShell gateway not reachable. Bring it up first:")
        print("        bash examples/openshell-gated-agent/gateway/setup.sh")
        print("        mise run openshell-connect")
        return 2
    opa = resolve_opa_binary(None)
    if not opa:
        print("SKIP: no opa binary found (set ODIS_OPA_BIN or put 'opa' on PATH)")
        return 2

    # Audit like the other entry points: ODIS_AUDIT_OUTPUT ('-'=stdout,
    # 'stderr', or a file path appended to); the mise task points it at a file.
    audit_dest = os.environ.get("ODIS_AUDIT_OUTPUT", "stderr")
    stack = contextlib.ExitStack()
    with stack:
        audit = build_audit(audit_stream(audit_dest, stack))
        print(f"[audit] events -> {audit_dest}")
        async with _running(_vendor_app(), VENDOR_PORT):
            # The Router reaches the vendor host-locally; the sandbox cannot (policy blocks it).
            vendor_url = f"http://127.0.0.1:{VENDOR_PORT}{MCP_MOUNT_PATH}"
            with DevVault() as ctx:
                _point_mapping_at_local_vendor(ctx.addr, vendor_url)
                source = SignedBundleSource(
                    client=VaultBundleClient(
                        vault_addr=ctx.addr,
                        jwt_login_mount=ctx.jwt_login_mount,
                        jwt_login_role=ctx.jwt_login_role,
                        issue_path=ctx.issue_path,
                    ),
                    workload_jwt=ctx.workload_jwt,
                    bundle_pubkey_b64=ctx.transit_public_key_b64,
                )
                router = await build_router_signed(
                    source=source,
                    opa_binary=opa,
                    audit=audit,
                    vendor_client_factory=http_vendor_factory,
                )
                bundle_id = router.bundle.bundle_id
                print(f"[vault] minted + transit-signed + offline-verified bundle {bundle_id!r}")
                async with _running(build_asgi_app(build_mcp_server(router)), ROUTER_PORT):
                    print(f"[router] serving on 0.0.0.0:{ROUTER_PORT} (reachable from the sandbox)")
                    rc = await _run_agent_in_sandbox()

    print("\nDEMO PASS" if rc == 0 else "\nDEMO FAIL")
    return rc


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
