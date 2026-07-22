"""End-to-end: real MCP client → HTTP → Router (policy gate) → HTTP → vendor.

The deployment-shaped proof that every leg works stitched together:

    SDK MCP client
        --HTTP--> ODIS Router (built via cli.build_router, real OPA gate)
            --HTTP--> a real vendor MCP server (uvicorn)

Both servers run on loopback ports; the client is the official SDK Streamable
HTTP client. Exercises discovery over HTTP, an allowed tools/call forwarded to
the vendor with its response returned, and a denied call blocked at the gate
before the vendor is ever contacted.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import TYPE_CHECKING

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

from odis_harness.cli import build_router
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import MCP_MOUNT_PATH, build_asgi_app
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from tests.factories import audit_sink

if TYPE_CHECKING:
    from collections.abc import AsyncIterator
    from pathlib import Path

    from starlette.applications import Starlette

    from odis_harness.bundle import Family

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]


_BUNDLE_TEMPLATE = """
bundle_id: e2e-bundle
bundle_version: 0.1.0
trust_root_id: e2e-trust-root
families:
  jira-prod:
    vendor_mcp:
      endpoint_id: jira-prod-mcp-v1
      url: {vendor_url}
    policy: |
      package odis_policy
      default decision := {{"decision": "deny", "obligations": {{}}}}
      decision := {{"decision": "allow", "obligations": {{"allowed_fields": ["labels"]}}}} if {{
          input.verb == "update_issue"
          startswith(input.request_body.issue_key, "APF-")
      }}
    tools:
      update_issue:
        action_limits:
          allowed_fields: [labels]
    default_mode: strict
"""


def _http_vendor_factory(family: Family) -> HttpMcpClient:
    return HttpMcpClient(url=family.vendor_mcp.url)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _vendor_app() -> Starlette:
    """A real (if minimal) vendor MCP server — stands in for a Jira MCP server.

    Echoes the issue_key back so the test can prove the agent's args flowed all
    the way through the Router to the vendor.
    """
    server: Server = Server("fake-jira-vendor")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list() -> list[Tool]:
        return [
            Tool(
                name="update_issue",
                description="Update a Jira issue",
                inputSchema={"type": "object", "required": ["issue_key"]},
            ),
        ]

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def _call(name: str, arguments: dict) -> list[TextContent]:  # type: ignore[type-arg]
        issue = arguments.get("issue_key")
        return [TextContent(type="text", text=f"vendor updated {issue}")]

    return build_asgi_app(server)


@contextlib.asynccontextmanager
async def _running(app: Starlette, port: int) -> AsyncIterator[None]:
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(100):
            if server.started:
                break
            await asyncio.sleep(0.05)
        if not server.started:
            message = f"server on :{port} did not start"
            raise RuntimeError(message)
        yield
    finally:
        server.should_exit = True
        await task


async def test_e2e_full_chain_allow_and_deny(tmp_path: Path, opa_binary: str) -> None:
    vendor_port = _free_port()
    router_port = _free_port()

    bundle_path = tmp_path / "bundle.yaml"
    bundle_path.write_text(
        _BUNDLE_TEMPLATE.format(vendor_url=f"http://127.0.0.1:{vendor_port}{MCP_MOUNT_PATH}"),
        encoding="utf-8",
    )

    async with _running(_vendor_app(), vendor_port):
        # Build the Router via the real CLI wiring: HttpMcpClient toward the
        # vendor URL, discovery populated over HTTP.
        router = await build_router(
            bundle_path=bundle_path,
            opa_binary=opa_binary,
            audit=audit_sink(),
            vendor_client_factory=_http_vendor_factory,
        )
        async with _running(build_asgi_app(build_mcp_server(router)), router_port):
            url = f"http://127.0.0.1:{router_port}{MCP_MOUNT_PATH}"
            async with (
                streamable_http_client(url) as (read, write, _sid),
                ClientSession(read, write) as client,
            ):
                await client.initialize()

                # 1. Discovery flowed over HTTP: Router → vendor → catalog.
                tools = await client.list_tools()
                assert [t.name for t in tools.tools] == ["jira-prod.update_issue"]

                # 2. Allowed call: client → Router (gate) → vendor → back.
                allowed = await client.call_tool(
                    "jira-prod.update_issue",
                    {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
                )
                assert allowed.isError is False
                # The vendor actually handled the forwarded args:
                assert allowed.content[0].text == "vendor updated APF-123"

                # 3. Denied call: policy gate blocks it before the vendor.
                denied = await client.call_tool(
                    "jira-prod.update_issue",
                    {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
                )
                assert denied.isError is True
                # Exact reason — distinguishes a policy deny from a vendor error
                # (which would be "refused: vendor_unreachable").
                assert denied.content[0].text == "refused: deny"
