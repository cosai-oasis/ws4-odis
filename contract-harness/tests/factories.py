"""Focused builders for tests that exercise public Router wiring."""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

from odis_harness.audit import AuditSink
from odis_harness.contracts import EnvelopeValidator
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
    ToolResult,
)

if TYPE_CHECKING:
    from odis_harness.bundle import Family

_REPO_ROOT = Path(__file__).resolve().parents[1]


def audit_sink() -> AuditSink:
    return AuditSink(output=io.StringIO(), validator=EnvelopeValidator(_REPO_ROOT / "schemas"))


def in_memory_vendor_from_family(family: Family) -> InMemoryMcpClient:
    tools = [
        ToolDescriptor(name=tool, description="", input_schema={"type": "object"})
        for tool in family.governed_tools()
    ]
    return InMemoryMcpClient(
        tools=tools,
        responses={
            tool.name: ToolResult(content=[{"type": "text", "text": f"handled {tool.name}"}])
            for tool in tools
        },
    )
