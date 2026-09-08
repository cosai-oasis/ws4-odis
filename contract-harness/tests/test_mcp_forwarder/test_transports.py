"""HTTP transport.

`build_asgi_app` is checked structurally; the bind smoke test starts a
uvicorn server on a loopback port and drives it with the SDK's Streamable HTTP
client to prove the actual deployment path (initialize + tools/list) works.
"""

from __future__ import annotations

import asyncio

import pytest
import uvicorn
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client
from starlette.applications import Starlette

from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import (
    MCP_MOUNT_PATH,
    build_asgi_app,
    mcp_url,
)
from tests import factories

pytestmark = pytest.mark.enable_socket


_POLICY = """
package odis_policy
default decision := {"decision": "allow", "obligations": {}}
"""


async def _router() -> Router:
    """Like `factories.router`, plus a populated discovery cache for `tools/list`."""
    bundle = factories.bundle(factories.family(policy=_POLICY))
    clients = {factories.FAMILY_NAME: factories.in_memory_vendor()}
    discovery = DiscoveryCache()
    await discovery.populate(bundle, clients=clients)
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary="unused-in-this-test"),
        context_factory=factories.context_factory(),
        # This test asserts on the HTTP transport, not on audit.
        audit=factories.audit_sink(),
        vendor_clients=clients,
        discovery=discovery,
    )


async def test_build_asgi_app_mounts_mcp_endpoint() -> None:
    router = await _router()
    app = build_asgi_app(build_mcp_server(router, requires_authenticated_caller=False))
    assert isinstance(app, Starlette)
    mount_paths = [getattr(r, "path", None) for r in app.routes]
    assert MCP_MOUNT_PATH in mount_paths


@pytest.mark.requires_opa
async def test_http_server_initialize_and_list_tools_over_real_socket() -> None:
    """End-to-end: uvicorn on a loopback port, driven by the SDK HTTP client."""
    port = factories.free_port()
    server = build_mcp_server(await _router(), requires_authenticated_caller=False)
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

        url = mcp_url("127.0.0.1", port)
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
