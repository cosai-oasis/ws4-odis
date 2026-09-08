"""MCP server glue (build_mcp_server) via in-memory client.

Uses the SDK's in-memory connected client/server so the full MCP lifecycle
(initialize → tools/list → tools/call) is exercised without a socket.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from odis_harness.fixtures.vendor import InMemoryMcpClient
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.identity import UNVERIFIED_AGENT_TYPE
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import DEFAULT_AGENT_ID, Router
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.vendor_client import (
    ToolDescriptor,
    ToolResult,
)
from tests import factories

if TYPE_CHECKING:
    from odis_harness.audit import AuditSink
    from odis_harness.bundle import Family
    from odis_harness.bundle.types import DefaultMode

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]


def _family(*, default_mode: DefaultMode = "strict") -> Family:
    return factories.family(policy=factories.ALLOW_LABELS_ON_APF, default_mode=default_mode)


async def _router(
    opa_binary: str, *, vendor: InMemoryMcpClient, audit: AuditSink | None = None
) -> Router:
    """Like `factories.router`, plus a populated discovery cache for `tools/list`.

    Most tests here assert on protocol responses and discard the audit; pass `audit=` for
    the ones whose subject is the emitted event.
    """
    bundle = factories.bundle(_family())
    clients = {factories.FAMILY_NAME: vendor}
    discovery = DiscoveryCache()
    await discovery.populate(bundle, clients=clients)
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary=opa_binary),
        context_factory=factories.context_factory(),
        audit=audit if audit is not None else factories.audit_sink(),
        vendor_clients=clients,
        discovery=discovery,
    )


def _vendor() -> InMemoryMcpClient:
    return InMemoryMcpClient(
        tools=[
            ToolDescriptor(
                name="update_issue",
                description="Update a Jira issue",
                input_schema={"type": "object", "required": ["issue_key"]},
            ),
        ],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )


_ALLOWED_ARGS = {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}


async def test_initialize_and_list_tools_returns_prefixed_catalog(
    opa_binary: str,
) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.list_tools()
    names = [t.name for t in result.tools]
    assert names == ["jira-prod.update_issue"]


async def test_list_tools_preserves_vendor_input_schema(opa_binary: str) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.list_tools()
    tool = result.tools[0]
    assert tool.inputSchema == {"type": "object", "required": ["issue_key"]}


async def test_call_tool_allow_returns_vendor_content(opa_binary: str) -> None:
    vendor = _vendor()
    router = await _router(opa_binary, vendor=vendor)
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("jira-prod.update_issue", _ALLOWED_ARGS)
    assert result.isError is False
    assert result.content[0].text == "ok"
    assert vendor.calls == [("update_issue", _ALLOWED_ARGS)]


async def test_call_tool_relays_vendor_in_band_error(opa_binary: str) -> None:
    """A forward that succeeds but whose vendor returned an in-band tool error
    must surface `isError=True` — not be re-emitted to the agent as success."""
    vendor = InMemoryMcpClient(
        tools=[
            ToolDescriptor(
                name="update_issue",
                description="Update a Jira issue",
                input_schema={"type": "object"},
            ),
        ],
        responses={
            "update_issue": ToolResult(
                content=[{"type": "text", "text": "permission denied"}],
                is_error=True,
            ),
        },
    )
    router = await _router(opa_binary, vendor=vendor)
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("jira-prod.update_issue", _ALLOWED_ARGS)
    assert result.isError is True
    assert "permission denied" in result.content[0].text


async def test_call_tool_deny_returns_error_result(opa_binary: str) -> None:
    vendor = _vendor()
    router = await _router(opa_binary, vendor=vendor)
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool(
            "jira-prod.update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        )
    assert result.isError is True
    assert "deny" in result.content[0].text
    assert vendor.calls == []


async def test_call_tool_unrouted_family_returns_error_result(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    router = await _router(opa_binary, vendor=_vendor(), audit=audit)
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("nope.whatever", {"x": 1})
    assert result.isError is True
    assert "unrouted_family" in result.content[0].text

    # A refusal before routing still names an agent, so this event has the same shape as
    # a forwarded one. `type` carries the caveat: this is the unauthenticated fallback,
    # not an identity the Router received.
    assert audit.event_types == ["odis.mcp.forward_refused"]
    assert audit.events[0].extra["actor"] == {
        "agent": {"id": DEFAULT_AGENT_ID, "type": UNVERIFIED_AGENT_TYPE}
    }
    # The originating principal stays unresolved: finding it means calling the identity
    # providers on a tool name that is already being rejected.
    assert "originating_principal" not in audit.events[0].extra["actor"]


async def test_call_tool_no_dot_name_returns_error_result(opa_binary: str) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("update_issue", _ALLOWED_ARGS)
    assert result.isError is True
    assert "unrouted_family" in result.content[0].text


async def test_call_tool_unexpected_error_fails_closed_without_leaking(
    opa_binary: str,
) -> None:
    """An unexpected error inside forward → generic refusal (no exception text
    leaked to the agent), and the call never succeeds."""
    vendor = _vendor()
    router = await _router(opa_binary, vendor=vendor)

    async def _boom(*_args: object, **_kwargs: object) -> object:
        message = "internal detail that must not leak to the agent"
        raise RuntimeError(message)

    router.forward = _boom  # type: ignore[method-assign]
    server = build_mcp_server(router, requires_authenticated_caller=False)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("jira-prod.update_issue", _ALLOWED_ARGS)
    assert result.isError is True
    assert "internal_error" in result.content[0].text
    assert "must not leak" not in result.content[0].text
