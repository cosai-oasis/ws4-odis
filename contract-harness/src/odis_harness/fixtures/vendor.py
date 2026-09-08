"""In-process vendor client — the `McpClient` seam, without a socket.

Lives here rather than beside the Protocol it implements: `vendor_client.py` is on the
production path and should carry the contract and `HttpMcpClient`, not a double.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from odis_harness.mcp_forwarder.vendor_client import (
    ToolDescriptor,
    ToolResult,
    VendorUnreachable,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


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
    #: The trace id the Router passed with each call, in step with `calls`. Recorded
    #: rather than discarded so a test can assert the Router propagates it; there is no
    #: transport here to carry it downstream.
    correlation_ids: list[str | None] = field(default_factory=list)

    async def list_tools(self) -> list[ToolDescriptor]:
        if self.unreachable:
            message = "vendor in-memory client configured as unreachable"
            raise VendorUnreachable(message)
        return list(self.tools)

    async def call_tool(
        self,
        name: str,
        arguments: Mapping[str, Any],
        *,
        correlation_id: str | None = None,
    ) -> ToolResult:
        # Record before any raise so tests can observe attempted-but-failed calls.
        self.calls.append((name, dict(arguments)))
        self.correlation_ids.append(correlation_id)
        if self.unreachable:
            message = "vendor in-memory client configured as unreachable"
            raise VendorUnreachable(message)
        if self.responder is not None:
            return self.responder(name, dict(arguments))
        if name not in self.responses:
            message = f"no response configured for tool {name!r} on InMemoryMcpClient"
            raise VendorUnreachable(message)
        return self.responses[name]


__all__ = ["InMemoryMcpClient"]
