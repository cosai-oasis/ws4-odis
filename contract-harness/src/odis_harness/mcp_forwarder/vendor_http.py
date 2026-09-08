"""HttpMcpClient — vendor MCP client over HTTP.

The production `McpClient` toward a vendor MCP server, wrapping the SDK's
Streamable HTTP client. Isolated from `vendor_client.py` (which stays
SDK-free: Protocol + in-memory double) so the `mcp` dependency lives only at
the transport edges.

Open-per-call semantics: each `list_tools` / `call_tool` opens a fresh
connection, runs the operation, and closes. Simple and robust for the PoC;
the OPA eval + policy gate dominate latency anyway. Any transport- or
protocol-level failure surfaces as `VendorUnreachable`, which the Router maps
to an `odis.mcp.forward_refused` (reason `vendor_unreachable`).

Authentication: an optional `auth` (any `httpx.Auth`) is
threaded into the SDK's `create_mcp_http_client(auth=…)`, so — when set — the
bearer rides every HTTP request per the MCP 2025-11-25 Authorization spec (no
stateful session). The harness deliberately ships **no credential** and never
a static token (Secret-Zero / ODIS-L1-01): `auth` defaults to `None`.
Live smoke tests supply the SDK OAuth authorization-code/PKCE provider,
which acquires and refreshes access tokens through the authorization server.
Production supplies a short-lived, audience-scoped provider through the Bridge.
That token is the Router→vendor credential only; the provider credential lives
solely in the vendor MCP server.

Tracing: `call_tool` sends the call's `correlation_id` as `TRACE_HEADER_NAME` on every
request of that call, so the trail reaches the Target MCP and does not stop at the Router
(ODIS-CC-01, and the CC-06 clause on injecting correlation identifiers downstream). The
header is a client-level default, which is what makes it ride the SDK's `initialize`
handshake as well as the `tools/call` itself.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from mcp import ClientSession
from mcp.client.streamable_http import (  # type: ignore[attr-defined]  # SDK's documented client factory; not listed in the module __all__
    create_mcp_http_client,
    streamable_http_client,
)

from odis_harness.mcp_forwarder.vendor_client import (
    TRACE_HEADER_NAME,
    ToolDescriptor,
    ToolResult,
    VendorUnreachable,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    import httpx


@dataclass(frozen=True, kw_only=True, slots=True)
class HttpMcpClient:
    """`McpClient` implementation that talks to a vendor over Streamable HTTP.

    `auth`, when set, is any `httpx.Auth` — in production an SDK OAuth
    JWT-assertion / client-credentials provider (short-lived, audience-scoped). It
    is attached to the SDK's HTTP client so the bearer rides every request. The
    harness ships none (no static tokens): `auth` defaults to `None`.
    """

    url: str
    auth: httpx.Auth | None = None

    async def establish(self) -> str | None:
        """Eagerly prime the leg-2 session (the boot-time handshake).

        Satisfies `SupportsSessionEstablish`, returning the established audience
        (RFC 8707) when a token is minted, else `None`. When `auth` is a `BridgeAuth`,
        prime its cached leg-2 token (so discovery reuses it — one handshake per vendor)
        and return its audience; on the `auth=None` Secret-Zero default this returns
        early before importing anything, so the demo / plain-`serve` path imports the
        Bridge nowhere and establishes nothing. A non-Bridge `httpx.Auth` also returns
        `None` (nothing primed).
        """
        if self.auth is None:
            # No-import invariant on the plain path: return before touching the Bridge.
            return None
        # Lazy: keep the Bridge off the plain import path (it is opt-in via --bridge).
        from odis_harness.bridge.exchange import BridgeAuth  # noqa: PLC0415

        if isinstance(self.auth, BridgeAuth):
            await self.auth.establish()
            return self.auth.audience
        return None

    async def list_tools(self) -> list[ToolDescriptor]:
        try:
            async with (
                create_mcp_http_client(auth=self.auth) as http_client,
                streamable_http_client(self.url, http_client=http_client) as (
                    read,
                    write,
                    _session_id,
                ),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                result = await session.list_tools()
        except Exception as exc:
            # Client boundary: any transport/protocol failure → VendorUnreachable,
            # which the Router maps to reason `vendor_unreachable`.
            message = f"vendor list_tools failed for {self.url}: {exc}"
            raise VendorUnreachable(message) from exc
        return [
            ToolDescriptor(
                name=tool.name,
                description=tool.description or "",
                input_schema=dict(tool.inputSchema),
            )
            for tool in result.tools
        ]

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> ToolResult:
        """Forward one invocation, carrying the call's trace id downstream.

        `correlation_id` becomes the `TRACE_HEADER_NAME` header. It is also what the
        Bridge reads back off the outbound request to anchor an exchange to this call, so
        it is set as a client default rather than on one message: the SDK's `initialize`
        is the request that triggers the token handshake.
        """
        try:
            async with (
                create_mcp_http_client(
                    auth=self.auth, headers=_trace_headers(correlation_id)
                ) as http_client,
                streamable_http_client(self.url, http_client=http_client) as (
                    read,
                    write,
                    _session_id,
                ),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                result = await session.call_tool(name, dict(arguments))
        except Exception as exc:
            # Client boundary: any transport/protocol failure → VendorUnreachable.
            message = f"vendor call_tool {name!r} failed for {self.url}: {exc}"
            raise VendorUnreachable(message) from exc
        return ToolResult(
            content=[_block_to_dict(block) for block in result.content],
            is_error=bool(result.isError),
        )


def _trace_headers(correlation_id: str | None) -> dict[str, str] | None:
    """The downstream trace header for `correlation_id`, or `None` when there is none.

    `None` rather than an empty dict: an untraced call sends no trace header at all,
    rather than a present empty one a target might log as an actual trace id.
    """
    if correlation_id is None:
        return None
    return {TRACE_HEADER_NAME: correlation_id}


def _block_to_dict(block: object) -> dict[str, Any]:
    """Serialize an SDK content block back into a plain dict for the Router.

    The Router forwards the vendor's content unchanged to the agent; keeping it
    as plain dicts avoids re-binding to specific SDK content classes.
    """
    dump = getattr(block, "model_dump", None)
    if callable(dump):
        result: dict[str, Any] = dump(mode="json")
        return result
    return {"type": "text", "text": str(block)}


__all__ = ["HttpMcpClient"]
