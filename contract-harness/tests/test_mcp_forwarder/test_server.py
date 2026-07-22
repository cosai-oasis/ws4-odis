"""MCP server glue (build_mcp_server) via in-memory client.

Uses the SDK's in-memory connected client/server so the full MCP lifecycle
(initialize → tools/list → tools/call) is exercised without a real socket.
"""

from __future__ import annotations

import pytest
from mcp.shared.memory import create_connected_server_and_client_session

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]


_ALLOW_LABELS_ON_APF = """
package odis_policy
default decision := {"decision": "deny", "obligations": {}}
decision := {"decision": "allow", "obligations": {"allowed_fields": ["labels"]}} if {
    input.verb == "update_issue"
    startswith(input.request_body.issue_key, "APF-")
}
"""


def _family(*, default_mode: str = "strict") -> Family:
    return Family(
        vendor_mcp=VendorMcp(endpoint_id="jira-prod-mcp-v1", url="https://x.invalid/"),
        policy=_ALLOW_LABELS_ON_APF,
        tools={
            "update_issue": ToolPolicy(action_limits={"allowed_fields": ["labels"]}),
        },
        default_mode=default_mode,  # type: ignore[arg-type]
    )


async def _router(opa_binary: str, *, vendor: InMemoryMcpClient) -> Router:
    family = _family()
    bundle = Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families={"jira-prod": family},
    )
    discovery = DiscoveryCache()
    await discovery.populate(bundle, clients={"jira-prod": vendor})
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary=opa_binary),
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
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.list_tools()
    names = [t.name for t in result.tools]
    assert names == ["jira-prod.update_issue"]


async def test_list_tools_preserves_vendor_input_schema(opa_binary: str) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.list_tools()
    tool = result.tools[0]
    assert tool.inputSchema == {"type": "object", "required": ["issue_key"]}


async def test_call_tool_allow_returns_vendor_content(opa_binary: str) -> None:
    vendor = _vendor()
    router = await _router(opa_binary, vendor=vendor)
    server = build_mcp_server(router)
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
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("jira-prod.update_issue", _ALLOWED_ARGS)
    assert result.isError is True
    assert "permission denied" in result.content[0].text


async def test_call_tool_deny_returns_error_result(opa_binary: str) -> None:
    vendor = _vendor()
    router = await _router(opa_binary, vendor=vendor)
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool(
            "jira-prod.update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        )
    assert result.isError is True
    assert "deny" in result.content[0].text
    assert vendor.calls == []


async def test_call_tool_unrouted_family_returns_error_result(opa_binary: str) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("nope.whatever", {"x": 1})
    assert result.isError is True
    assert "unrouted_family" in result.content[0].text


async def test_call_tool_no_dot_name_returns_error_result(opa_binary: str) -> None:
    router = await _router(opa_binary, vendor=_vendor())
    server = build_mcp_server(router)
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
    server = build_mcp_server(router)
    async with create_connected_server_and_client_session(server) as client:
        result = await client.call_tool("jira-prod.update_issue", _ALLOWED_ARGS)
    assert result.isError is True
    assert "internal_error" in result.content[0].text
    assert "must not leak" not in result.content[0].text
