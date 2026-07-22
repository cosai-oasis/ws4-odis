"""`McpClient` Protocol + `InMemoryMcpClient` test double.

The Router holds one `McpClient` per family (per the bundle's routing table)
and calls it during forward orchestration. The production implementation
wraps the official `mcp` Python SDK's client primitives over HTTP; this module
defines the Protocol the Router programs against and ships an in-memory test
double that exercises the same surface.

`VendorUnreachable` is the typed transport-failure error; the Router catches
it at the forward boundary and converts to `odis.mcp.forward_refused` with
`reason_code: vendor_unreachable`.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import Any


class VendorUnreachable(RuntimeError):  # noqa: N818 - domain term reads clearer without the Error suffix
    """Vendor MCP server cannot be contacted (transport-level failure).

    Distinct from refusals the vendor returns inside an MCP response — those
    bubble up as ToolResult content the Router passes through unchanged.
    """


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolDescriptor:
    """An MCP tool entry returned by `tools/list`.

    Mirrors the MCP spec's tool shape (`name`, `description`, `inputSchema`)
    without binding to the SDK's concrete `Tool` class — the Router treats
    vendor catalogs structurally.
    """

    name: str
    description: str
    input_schema: Mapping[str, Any]


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolResult:
    """The result of a `tools/call` the Router forwarded.

    `content` mirrors the MCP spec's content list (text/image/resource).
    `is_error` mirrors the spec's `isError`: a tool-level failure the vendor
    reported in-band (distinct from `VendorUnreachable`, a transport failure).
    The Router relays it so the agent sees the vendor's real success/error status.
    """

    content: list[Mapping[str, Any]]
    is_error: bool = False


@runtime_checkable
class McpClient(Protocol):
    """The Router's view of an upstream vendor MCP server.

    Production implementations wrap the `mcp` Python SDK client over HTTP;
    the in-memory variant below is for tests.
    """

    async def list_tools(self) -> list[ToolDescriptor]:
        """Return the vendor's tool catalog.

        Raises `VendorUnreachable` on transport failure.
        """

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        """Forward an invocation; return the vendor's response.

        Raises `VendorUnreachable` on transport failure.
        """


@runtime_checkable
class SupportsSessionEstablish(Protocol):
    """Opt-in capability: a vendor client that can eagerly prime its leg-2 session.

    Deliberately NARROW and SEPARATE from `McpClient` (which stays a pure
    call/list surface, and `InMemoryMcpClient` need not grow this method). At
    boot the Router establishes leg-2 sessions for clients that satisfy this
    Protocol (`HttpMcpClient` with a `BridgeAuth`), priming one token per family
    before discovery so the later `tools/list` reuses it (DL-2 / REQ-9.8).
    """

    async def establish(self) -> str | None:
        """Prime the leg-2 session/token, returning what was established.

        Returns the established audience (RFC 8707) when a token was actually
        minted, or `None` when nothing was established (not bridged). Idempotent.
        """


@dataclass
class InMemoryMcpClient:
    """In-process test double implementing `McpClient`.

    Construct with a catalog of tools and either a static `responses` map or
    a `responder` callable. If both are provided, `responder` wins (it is
    consulted first). Set `unreachable=True` to simulate a transport outage
    on every call.

    `self.calls` records every `call_tool` invocation — including ones that
    raise — so tests can assert "the Router attempted to call X" even when
    the vendor is unreachable.
    """

    tools: list[ToolDescriptor]
    responses: dict[str, ToolResult] = field(default_factory=dict)
    responder: Callable[[str, dict[str, Any]], ToolResult] | None = None
    unreachable: bool = False
    #: Captured calls for test assertions. Populated by `call_tool` BEFORE
    #: any exception is raised so tests can observe attempted-but-failed calls.
    calls: list[tuple[str, Mapping[str, Any]]] = field(default_factory=list)

    async def list_tools(self) -> list[ToolDescriptor]:
        if self.unreachable:
            message = "vendor in-memory client configured as unreachable"
            raise VendorUnreachable(message)
        return list(self.tools)

    async def call_tool(self, name: str, arguments: Mapping[str, Any]) -> ToolResult:
        # Record before any raise so tests can observe attempted-but-failed calls.
        self.calls.append((name, dict(arguments)))
        if self.unreachable:
            message = "vendor in-memory client configured as unreachable"
            raise VendorUnreachable(message)
        if self.responder is not None:
            return self.responder(name, dict(arguments))
        if name not in self.responses:
            message = f"no response configured for tool {name!r} on InMemoryMcpClient"
            raise VendorUnreachable(message)
        return self.responses[name]


__all__ = [
    "InMemoryMcpClient",
    "McpClient",
    "SupportsSessionEstablish",
    "ToolDescriptor",
    "ToolResult",
    "VendorUnreachable",
]
