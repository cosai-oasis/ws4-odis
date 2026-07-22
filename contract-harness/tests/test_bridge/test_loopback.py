"""Loopback e2e for the ODIS Bridge leg-2 auth.

Stands up a tiny capturing vendor MCP server on a loopback port, points an
`HttpMcpClient(auth=BridgeAuth(...))` at it via the MCP SDK, makes a real
`tools/call`, and asserts the captured `Authorization` header is `Bearer <jwt>`
whose `aud` is the configured vendor audience (RFC 8707) and whose `act.sub` is the
agent subject (RFC 8693). This proves the BridgeAuth seam threads a freshly-exchanged
bearer onto every SDK-sent HTTP request through the full transport — not just at the
httpx layer.

Reuses the loopback vendor harness shape from `test_vendor_http`; opts back into
sockets at the module level (the suite is `--disable-socket` by default).
"""

from __future__ import annotations

import asyncio
import socket
from typing import Self

import jwt
import pytest
import uvicorn
from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

from odis_harness.bridge.exchange import BridgeAuth
from odis_harness.bridge.fixtures import (
    FixtureTokenExchanger,
    fixture_subject_token_provider,
)
from odis_harness.mcp_forwarder.transports import MCP_MOUNT_PATH, build_asgi_app
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from odis_harness.vault.fixtures import FixtureIdentityIssuer

pytestmark = pytest.mark.enable_socket

_VENDOR_AUDIENCE = "https://vendor.example/mcp"
_AGENT_SUBJECT = "spiffe://fixture.odis.local/agent/mcp-client"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _vendor_server() -> Server:
    server: Server = Server("fake-vendor")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]  # MCP SDK decorator is untyped — see test_e2e.py
    async def _list() -> list[Tool]:
        return [
            Tool(
                name="update_issue",
                description="Update an issue",
                inputSchema={"type": "object"},
            ),
        ]

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]  # MCP SDK decorator is untyped — see test_e2e.py
    async def _call(name: str, arguments: dict) -> list[TextContent]:  # type: ignore[type-arg]  # SDK callback signature uses a bare dict — see test_e2e.py
        return [TextContent(type="text", text=f"{name}:{arguments.get('issue_key')}")]

    return server


def _capturing_app(inner, captured):  # type: ignore[no-untyped-def]  # ASGI wrapper over untyped scope/receive/send callables
    async def app(scope, receive, send):  # type: ignore[no-untyped-def]  # ASGI app callable is structurally untyped
        if scope["type"] == "http":
            captured.append({k.decode().lower(): v.decode() for k, v in scope.get("headers", [])})
        await inner(scope, receive, send)

    return app


class _RunningVendor:
    """Serves a capturing vendor MCP server on a loopback port for the duration."""

    def __init__(self, captured: list[dict[str, str]]) -> None:
        self.port = _free_port()
        app = _capturing_app(build_asgi_app(_vendor_server()), captured)
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
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


def _bridge_auth() -> BridgeAuth:
    agent_issuer = FixtureIdentityIssuer.generate()
    provider = fixture_subject_token_provider(
        agent_issuer, subject=_AGENT_SUBJECT, audience="https://bridge.odis.local/"
    )
    return BridgeAuth(
        subject_token_provider=provider,
        audience=_VENDOR_AUDIENCE,
        exchanger=FixtureTokenExchanger(),
    )


async def test_bridge_auth_threads_exchanged_bearer_through_the_sdk() -> None:
    captured: list[dict[str, str]] = []
    async with _RunningVendor(captured) as vendor:
        client = HttpMcpClient(url=vendor.url, auth=_bridge_auth())
        result = await client.call_tool("update_issue", {"issue_key": "APF-7"})

    assert result.content[0]["text"] == "update_issue:APF-7"
    assert captured, "no HTTP request reached the vendor"
    # Every request the SDK sent (initialize + tools/call) carries the leg-2 bearer.
    auth_headers = [h.get("authorization") for h in captured]
    assert all(h is not None and h.startswith("Bearer ") for h in auth_headers)
    bearer = auth_headers[0].removeprefix("Bearer ")  # type: ignore[union-attr]  # asserted non-None just above
    # All requests share the single exchanged token (no per-request re-mint).
    assert all(h == f"Bearer {bearer}" for h in auth_headers)
    claims = jwt.decode(bearer, options={"verify_signature": False})
    assert claims["aud"] == _VENDOR_AUDIENCE  # RFC 8707 audience binding
    assert claims["act"] == {"sub": _AGENT_SUBJECT}  # RFC 8693 delegation
