"""HTTP transport.

`build_asgi_app` is checked structurally; the real-bind smoke test starts a
uvicorn server on a loopback port and drives it with the SDK's Streamable HTTP
client to prove the actual deployment path (initialize + tools/list) works.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import (
    MCP_MOUNT_PATH,
    build_asgi_app,
)
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

pytestmark = pytest.mark.enable_socket


_POLICY = """
package odis_policy
default decision := {"decision": "allow", "obligations": {}}
"""


async def _router() -> Router:
    family = Family(
        vendor_mcp=VendorMcp(endpoint_id="jira-prod-mcp-v1", url="https://x.invalid/"),
        policy=_POLICY,
        tools={
            "update_issue": ToolPolicy(action_limits={"allowed_fields": ["labels"]}),
        },
        default_mode="strict",
    )
    bundle = Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families={"jira-prod": family},
    )
    vendor = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
    )
    discovery = DiscoveryCache()
    await discovery.populate(bundle, clients={"jira-prod": vendor})
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary="unused-in-this-test"),
        context_factory=RuntimeContextFactory(
            workload_identity=FixtureWorkloadIdentityProvider(),
            sponsor_provider=FixtureSponsorIdentityProvider(),
        ),
        audit=_NullAudit(),  # type: ignore[arg-type]
        vendor_clients={"jira-prod": vendor},
        discovery=discovery,
    )


class _NullAudit:
    def emit(self, event: object) -> None:
        return


async def test_build_asgi_app_mounts_mcp_endpoint() -> None:
    router = await _router()
    app = build_asgi_app(build_mcp_server(router))
    assert isinstance(app, Starlette)
    mount_paths = [getattr(r, "path", None) for r in app.routes]
    assert MCP_MOUNT_PATH in mount_paths


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


@pytest.mark.requires_opa
async def test_http_server_initialize_and_list_tools_over_real_socket() -> None:
    """End-to-end: uvicorn on a loopback port, driven by the SDK HTTP client."""
    port = _free_port()
    server = build_mcp_server(await _router())
    app = build_asgi_app(server)
    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error")
    uv_server = uvicorn.Server(config)

    serve_task = asyncio.create_task(uv_server.serve())
    try:
        # Wait for uvicorn to report started.
        for _ in range(100):
            if uv_server.started:
                break
            await asyncio.sleep(0.05)
        assert uv_server.started, "uvicorn did not start"

        url = f"http://127.0.0.1:{port}{MCP_MOUNT_PATH}"
        async with (
            streamable_http_client(url) as (read, write, _get_session_id),
            ClientSession(read, write) as session,
        ):
            await session.initialize()
            tools = await session.list_tools()
        names = [t.name for t in tools.tools]
        assert names == ["jira-prod.update_issue"]
    finally:
        uv_server.should_exit = True
        await serve_task
