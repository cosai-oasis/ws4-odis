"""odis-mcp-forwarder — HttpMcpClient: real vendor MCP client over HTTP.

The client-transport counterpart to Phase D's server transport. Tested against
a real vendor MCP server (a trivial SDK Server) bound to a loopback port.
"""

from __future__ import annotations

import asyncio
import socket
from typing import Self

import httpx
import pytest
import uvicorn
from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

from odis_harness.mcp_forwarder.transports import MCP_MOUNT_PATH, build_asgi_app
from odis_harness.mcp_forwarder.vendor_client import VendorUnreachable
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient

pytestmark = pytest.mark.enable_socket


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _vendor_server() -> Server:
    """A minimal stand-in for a vendor MCP server (e.g. a real Jira MCP)."""
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
        return [TextContent(type="text", text=f"{name}:{arguments.get('issue_key')}")]

    return server


def _capturing_app(inner, captured):
    """ASGI wrapper that records each inbound HTTP request's headers."""

    async def app(scope, receive, send):
        if scope["type"] == "http":
            captured.append({k.decode().lower(): v.decode() for k, v in scope.get("headers", [])})
        await inner(scope, receive, send)

    return app


class _RunningVendor:
    """Async context manager that serves a vendor MCP server on a loopback port.

    Pass `captured` to record the headers of every inbound HTTP request (used to
    assert the Router attaches its bearer per the MCP authorization spec).
    """

    def __init__(self, captured: list[dict[str, str]] | None = None) -> None:
        self.port = _free_port()
        app = build_asgi_app(_vendor_server())
        if captured is not None:
            app = _capturing_app(app, captured)
        self._server = uvicorn.Server(
            uvicorn.Config(
                app,
                host="127.0.0.1",
                port=self.port,
                log_level="error",
            )
        )
        self._task: asyncio.Task[None] | None = None

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}{MCP_MOUNT_PATH}"

    async def __aenter__(self) -> Self:
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(100):
            if self._server.started:
                break
            await asyncio.sleep(0.05)
        if not self._server.started:
            message = "vendor server did not start"
            raise RuntimeError(message)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        self._server.should_exit = True
        if self._task is not None:
            await self._task


async def test_http_client_list_tools_against_real_vendor() -> None:
    async with _RunningVendor() as vendor:
        client = HttpMcpClient(url=vendor.url)
        tools = await client.list_tools()
    assert [t.name for t in tools] == ["update_issue"]
    assert tools[0].input_schema == {"type": "object", "required": ["issue_key"]}


async def test_http_client_call_tool_against_real_vendor() -> None:
    async with _RunningVendor() as vendor:
        client = HttpMcpClient(url=vendor.url)
        result = await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert result.content[0]["type"] == "text"
    assert result.content[0]["text"] == "update_issue:APF-7"


async def test_http_client_list_tools_unreachable_raises_vendor_unreachable() -> None:
    # Nothing listening on this port.
    client = HttpMcpClient(url=f"http://127.0.0.1:{_free_port()}/mcp")
    with pytest.raises(VendorUnreachable):
        await client.list_tools()


async def test_http_client_call_tool_unreachable_raises_vendor_unreachable() -> None:
    client = HttpMcpClient(url=f"http://127.0.0.1:{_free_port()}/mcp")
    with pytest.raises(VendorUnreachable):
        await client.call_tool("update_issue", {"issue_key": "APF-1"})


class _StubAuth(httpx.Auth):
    """Test-only `httpx.Auth` proving the `auth` seam threads to every request.

    Production supplies the SDK's short-lived JWT-assertion provider; the harness
    ships no credential. This is test scaffolding, not a shipped auth mechanism.
    """

    def auth_flow(self, request):
        request.headers["Authorization"] = "Bearer test-only"
        yield request


async def test_http_client_threads_auth_onto_every_request() -> None:
    """With an `auth` provider set, its credential rides every HTTP request to
    the vendor (MCP 2025-11-25 Authorization — bearer per request)."""
    captured: list[dict[str, str]] = []
    async with _RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url, auth=_StubAuth())
        await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert captured, "no HTTP request reached the vendor"
    assert all(h.get("authorization") == "Bearer test-only" for h in captured)


async def test_http_client_omits_authorization_when_auth_none() -> None:
    """No `auth` → no Authorization header (current default behavior)."""
    captured: list[dict[str, str]] = []
    async with _RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url)
        await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert captured, "no HTTP request reached the vendor"
    assert all("authorization" not in h for h in captured)


async def test_http_client_establish_primes_bridge_auth() -> None:
    """establish() with a BridgeAuth primes its leg-2 token (one eager exchange)."""
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from odis_harness.bridge.exchange import BridgeAuth, ExchangedToken  # noqa: PLC0415

    calls = 0

    class _Exchanger:
        async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
            del subject_token, audience
            nonlocal calls
            calls += 1
            return ExchangedToken(
                bearer="primed", expires_at=datetime.now(UTC) + timedelta(minutes=5)
            )

    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=_Exchanger(),
    )
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp", auth=auth)
    audience = await client.establish()
    assert calls == 1, "establish() must trigger exactly one eager exchange"
    assert audience == "aud", "establish() returns the BridgeAuth audience it primed"


async def test_http_client_establish_is_noop_when_auth_none() -> None:
    """establish() with auth=None is a no-op (returns None, no work) — Secret-Zero default."""
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp")
    assert await client.establish() is None  # no token established, nothing primed
