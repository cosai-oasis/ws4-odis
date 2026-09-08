"""HttpMcpClient — the vendor MCP client, over HTTP.

The client-transport counterpart to `transports.py`. Tested against
a vendor MCP server (a trivial SDK Server) bound to a loopback port.
"""

from __future__ import annotations

import asyncio
import builtins

import httpx
import pytest

from odis_harness.mcp_forwarder.vendor_client import (
    TRACE_HEADER_NAME,
    VendorUnreachable,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from tests import factories
from tests.loopback import RunningVendor

pytestmark = pytest.mark.enable_socket

_TRACE_HEADER = TRACE_HEADER_NAME.lower()
_CORRELATION_ID = "00000000-0000-4000-8000-000000000042"


async def test_http_client_list_tools_against_real_vendor() -> None:
    async with RunningVendor() as vendor:
        client = HttpMcpClient(url=vendor.url)
        tools = await client.list_tools()
    assert [t.name for t in tools] == ["update_issue"]
    assert tools[0].input_schema == {"type": "object", "required": ["issue_key"]}


async def test_http_client_call_tool_against_real_vendor() -> None:
    async with RunningVendor() as vendor:
        client = HttpMcpClient(url=vendor.url)
        result = await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert result.content[0]["type"] == "text"
    assert result.content[0]["text"] == "update_issue:APF-7"


async def test_http_client_list_tools_unreachable_raises_vendor_unreachable() -> None:
    # Nothing listening on this port.
    client = HttpMcpClient(url=f"http://127.0.0.1:{factories.free_port()}/mcp")
    with pytest.raises(VendorUnreachable):
        await client.list_tools()


async def test_http_client_call_tool_unreachable_raises_vendor_unreachable() -> None:
    client = HttpMcpClient(url=f"http://127.0.0.1:{factories.free_port()}/mcp")
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
    async with RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url, auth=_StubAuth())
        await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert captured, "no HTTP request reached the vendor"
    assert all(h.get("authorization") == "Bearer test-only" for h in captured)


async def test_http_client_omits_authorization_when_auth_none() -> None:
    """No `auth` → no Authorization header (current default behavior)."""
    captured: list[dict[str, str]] = []
    async with RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url)
        await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert captured, "no HTTP request reached the vendor"
    assert all("authorization" not in h for h in captured)


async def test_http_client_sends_the_trace_header_on_every_request() -> None:
    """ODIS-CC-01: the call's trace identifier reaches the Target MCP, so the trail does
    not stop at the Router boundary. It rides every request the SDK sends — initialize
    and tools/call — because the id belongs to the call, not to one message in it."""
    captured: list[dict[str, str]] = []
    async with RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url)
        await client.call_tool(
            "update_issue", {"issue_key": "APF-7"}, correlation_id=_CORRELATION_ID
        )
    assert captured, "no HTTP request reached the vendor"
    assert all(h.get(_TRACE_HEADER) == _CORRELATION_ID for h in captured)


async def test_http_client_omits_the_trace_header_without_a_correlation_id() -> None:
    """No id to propagate → no header, rather than an empty or invented one."""
    captured: list[dict[str, str]] = []
    async with RunningVendor(captured=captured) as vendor:
        client = HttpMcpClient(url=vendor.url)
        await client.call_tool("update_issue", {"issue_key": "APF-7"})
    assert captured, "no HTTP request reached the vendor"
    assert all(_TRACE_HEADER not in h for h in captured)


async def test_http_client_establish_primes_bridge_auth() -> None:
    """establish() with a BridgeAuth primes its leg-2 token (one eager exchange)."""
    from odis_harness.bridge.exchange import BridgeAuth  # noqa: PLC0415

    exchanger = factories.StubTokenExchanger()
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
        # Required to exchange at all (ODIS-CC-06); the record is test_audit.py's subject.
        anchor=factories.exchange_anchor(),
    )
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp", auth=auth)
    audience = await client.establish()
    assert exchanger.calls == 1, "establish() must trigger exactly one eager exchange"
    assert audience == "aud", "establish() returns the BridgeAuth audience it primed"


async def test_http_client_establish_primes_nothing_for_a_non_bridge_auth() -> None:
    """Only a `BridgeAuth` has a leg-2 token to prime. Any other `httpx.Auth` — the
    interactive OAuth provider, which mints on its own schedule inside the SDK — reports
    that nothing was established rather than claiming an audience it did not request.
    """
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp", auth=_StubAuth())
    assert await client.establish() is None


async def test_http_client_establish_is_noop_when_auth_none() -> None:
    """establish() with auth=None is a no-op (returns None, no work) — Secret-Zero default."""
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp")
    assert await client.establish() is None  # no token established, nothing primed


def test_secret_zero_client_never_reaches_the_bridge(monkeypatch) -> None:
    """`establish` returns before its lazy import when `auth` is None, so the Secret-Zero
    client costs nothing on the plain path.

    Asserted by making the import itself fail rather than by inspecting `sys.modules`:
    another test in the session may already have imported the Bridge, which would let an
    absence check pass for the wrong reason.
    """
    real_import = builtins.__import__

    def _guarded(name, *args, **kwargs):
        if name.startswith("odis_harness.bridge"):
            message = f"the plain path must not import {name}"
            raise AssertionError(message)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", _guarded)
    client = HttpMcpClient(url="http://127.0.0.1:9/mcp")
    assert asyncio.run(client.establish()) is None
