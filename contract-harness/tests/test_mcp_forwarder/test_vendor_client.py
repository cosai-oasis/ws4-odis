"""McpClient Protocol + InMemoryMcpClient."""

from __future__ import annotations

import pytest

from odis_harness.fixtures.vendor import InMemoryMcpClient
from odis_harness.mcp_forwarder.vendor_client import (
    TRACE_HEADER_NAME,
    ToolDescriptor,
    ToolResult,
    VendorUnreachable,
)

# pytest-asyncio's event-loop setup touches sockets internally. These tests
# make no network calls; the in-memory client is purely in-process.
pytestmark = pytest.mark.enable_socket


async def test_in_memory_client_returns_configured_tools() -> None:
    client = InMemoryMcpClient(
        tools=[
            ToolDescriptor(
                name="update_issue",
                description="Update a Jira issue",
                input_schema={"type": "object"},
            ),
        ]
    )
    tools = await client.list_tools()
    assert len(tools) == 1
    assert tools[0].name == "update_issue"


async def test_in_memory_client_returns_response_for_configured_tool() -> None:
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )
    result = await client.call_tool("update_issue", {"issue_key": "APF-1"})
    assert result.content == [{"type": "text", "text": "ok"}]


async def test_in_memory_client_raises_vendor_unreachable_when_tool_unknown() -> None:
    client = InMemoryMcpClient(tools=[])
    with pytest.raises(VendorUnreachable):
        await client.call_tool("update_issue", {})


async def test_in_memory_client_simulate_outage_via_flag() -> None:
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
        unreachable=True,
    )
    with pytest.raises(VendorUnreachable):
        await client.list_tools()
    with pytest.raises(VendorUnreachable):
        await client.call_tool("update_issue", {})


async def test_in_memory_client_callable_response_receives_arguments() -> None:
    """Lets tests assert on the args the Router forwarded."""
    captured: list[dict[str, object]] = []

    def respond(name: str, args: dict[str, object]) -> ToolResult:
        captured.append({"name": name, "args": args})
        return ToolResult(content=[{"type": "text", "text": "ok"}])

    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responder=respond,
    )
    await client.call_tool("update_issue", {"issue_key": "APF-1"})
    assert captured == [{"name": "update_issue", "args": {"issue_key": "APF-1"}}]


async def test_in_memory_client_records_call_even_when_unreachable() -> None:
    """Tests can assert 'we tried' on outage paths."""
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
        unreachable=True,
    )
    with pytest.raises(VendorUnreachable):
        await client.call_tool("update_issue", {"issue_key": "APF-1"})
    assert client.calls == [("update_issue", {"issue_key": "APF-1"})]


async def test_in_memory_client_responder_wins_when_both_provided() -> None:
    """Documented precedence — responder is consulted first; responses is the fallback."""

    def respond(name: str, args: dict[str, object]) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": "from-responder"}])

    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "from-dict"}])},
        responder=respond,
    )
    result = await client.call_tool("update_issue", {})
    assert result.content == [{"type": "text", "text": "from-responder"}]


def test_trace_header_name_is_pinned() -> None:
    """The header is a wire contract with targets that know nothing about ODIS.

    Their log pipelines key on this exact name, so renaming it breaks correlation
    somewhere this repo cannot see. Transcribed here so the rename has to be deliberate.
    """
    assert TRACE_HEADER_NAME == "ODIS-Request-Trace-Id"
