"""odis-mcp-forwarder — Router building block (ODIS canonical).

The Router exposes an MCP server toward the agent (HTTP transport per the MCP
spec), evaluates each tools/call against the signed bundle's policy via the
policy engine + action-limit enforcement, and forwards approved calls to the
vendor MCP server resolved from the bundle's routing entry. Vendor MCP servers
hold their own credentials at their own deploy time; the Router never sees a
provider bearer.
"""

from __future__ import annotations

from odis_harness.mcp_forwarder.action_limits import (
    ActionLimitViolation,
    enforce_action_limits,
)
from odis_harness.mcp_forwarder.audit import (
    ForwardMode,
    audit_forward,
    audit_refused,
)
from odis_harness.mcp_forwarder.discovery import (
    DiscoveryCache,
    DiscoveryFailureCallback,
)
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.names import UnroutedToolName, parse_tool_name
from odis_harness.mcp_forwarder.policy import PolicyDecision, PolicyEvaluator
from odis_harness.mcp_forwarder.router import (
    DEFAULT_AGENT_ID,
    McpRefusal,
    Router,
)
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import build_asgi_app, serve_http
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    McpClient,
    ToolDescriptor,
    ToolResult,
    VendorUnreachable,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient

__all__ = [
    "DEFAULT_AGENT_ID",
    "ActionLimitViolation",
    "DiscoveryCache",
    "DiscoveryFailureCallback",
    "ForwardMode",
    "HttpMcpClient",
    "InMemoryMcpClient",
    "McpClient",
    "McpRefusal",
    "PolicyDecision",
    "PolicyEvaluator",
    "Router",
    "RuntimeContextFactory",
    "ToolDescriptor",
    "ToolResult",
    "UnroutedToolName",
    "VendorUnreachable",
    "audit_forward",
    "audit_refused",
    "build_asgi_app",
    "build_mcp_server",
    "enforce_action_limits",
    "parse_tool_name",
    "serve_http",
]
