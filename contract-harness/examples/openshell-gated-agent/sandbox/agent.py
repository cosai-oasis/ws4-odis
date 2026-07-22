"""In-sandbox agent for the OpenShell-gated demo.

Runs INSIDE an OpenShell sandbox whose network policy permits exactly one destination:
the ODIS Router's MCP endpoint. Everything else — including the vendor MCP server — is
default-denied by the sandbox supervisor's egress proxy.

It demonstrates the enforced wedge end to end:
  1. A *direct* connection to the vendor is BLOCKED (the agent has no path to it).
  2. Driving the Router: an allowed tool call is gated + forwarded; a denied one is refused.

The agent never holds a provider credential and cannot bypass the Router — the OpenShell
sandbox makes the gate mandatory, not advisory.
"""

from __future__ import annotations

import asyncio
import os
import socket
import sys

# Defaults match the demo orchestration. host.openshell.internal is injected into the
# sandbox by the OpenShell Docker driver and resolves to the host (docker-bridge gateway).
ROUTER_URL = os.environ.get("ODIS_ROUTER_URL", "http://host.openshell.internal:8088/mcp")
VENDOR_HOST = os.environ.get("ODIS_VENDOR_HOST", "host.openshell.internal")
VENDOR_PORT = int(os.environ.get("ODIS_VENDOR_PORT", "8099"))


def _direct_vendor_blocked() -> bool:
    """A direct TCP connect to the vendor must FAIL — only the Router is in the allowlist.

    Assumption: the sandbox blocks disallowed egress at connect time (refused/
    unreachable), which is what the OpenShell Docker driver does. A gateway that
    instead accepted the TCP handshake and rejected at L7 (403 on CONNECT) would
    need an HTTP-level probe here rather than a raw socket.
    """
    try:
        with socket.create_connection((VENDOR_HOST, VENDOR_PORT), timeout=5):
            return False  # connected => egress NOT enforced => demo invariant violated
    except OSError:
        return True  # refused / blocked by the egress proxy => correct


def _text(result: object) -> str:
    content = getattr(result, "content", []) or []
    return " ".join(getattr(block, "text", "") for block in content).strip()[:160]


async def main() -> int:
    from mcp import ClientSession  # noqa: PLC0415 — only available inside the baked image
    from mcp.client.streamable_http import streamablehttp_client  # noqa: PLC0415

    print(f"[agent] direct vendor connect {VENDOR_HOST}:{VENDOR_PORT} ...", end=" ", flush=True)
    blocked = await asyncio.to_thread(_direct_vendor_blocked)
    print("BLOCKED (egress proxy) ✓" if blocked else "REACHABLE ✗ — egress NOT enforced!")
    if not blocked:
        # Fail closed: the substrate is not enforcing egress, so demonstrating the
        # gate would be theater. Stop before performing any gated call.
        print("[agent] RESULT: FAIL — refusing to continue without enforced egress")
        return 1

    print(f"[agent] connecting to Router at {ROUTER_URL}")
    async with (
        streamablehttp_client(ROUTER_URL) as (read, write, _),
        ClientSession(read, write) as session,
    ):
            await session.initialize()
            catalog = await session.list_tools()
            print(f"[agent] gated tool catalog: {[t.name for t in catalog.tools]}")

            print("[agent] ALLOW  jira-prod.update_issue {issue_key: APF-123, labels}")
            allow = await session.call_tool(
                "jira-prod.update_issue",
                {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
            )
            print(f"          isError={allow.isError}  {_text(allow)}")

            print("[agent] DENY   jira-prod.update_issue {issue_key: OTHER-1}")
            deny = await session.call_tool(
                "jira-prod.update_issue",
                {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
            )
            print(f"          isError={deny.isError}  {_text(deny)}")

    ok = blocked and not allow.isError and deny.isError
    print(f"\n[agent] RESULT: {'PASS — gate enforced + mandatory' if ok else 'FAIL'}")
    print(
        "  - direct vendor egress blocked by the sandbox" if blocked else "  - egress NOT blocked!"
    )
    print(
        "  - APF-123 allowed + forwarded through the Router"
        if not allow.isError
        else "  - allow path failed"
    )
    print("  - OTHER-1 refused at the Router gate" if deny.isError else "  - deny path leaked")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
