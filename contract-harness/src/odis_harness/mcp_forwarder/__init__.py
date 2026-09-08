"""The Router — an MCP policy-forwarder, one candidate implementation of part of the
ODIS Layer-3 governance checkpoint.

Part, and candidate, both deliberately: ODIS is an unratified draft, and three Layer-3
Core MUSTs (velocity limits, revocation latency, kill switch) are absent here. See
`docs/odis-conformance.md`.

The Router exposes an MCP server toward the agent (HTTP transport per the MCP spec),
evaluates a governed `tools/call` against the bundle's policy via the policy engine plus
action-limit enforcement, and forwards approved calls to the vendor MCP server resolved
from the bundle's routing entry. A tool the family does not govern is refused under
`strict`, and under `permissive` is forwarded with no policy evaluated at all — audited
as such. Vendor MCP servers hold their own credentials at their own deploy time; the
Router never sees a provider bearer.
"""

from __future__ import annotations

from odis_harness.mcp_forwarder.action_limits import (
    ActionLimitViolation,
    enforce_action_limits,
)
from odis_harness.mcp_forwarder.audit import (
    ForwardMode,
    audit_discovery_failed,
    audit_forward,
    audit_refused,
)
from odis_harness.mcp_forwarder.discovery import (
    DiscoveryCache,
    DiscoveryFailureCallback,
)
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.names import UnroutedToolName, parse_tool_name
from odis_harness.mcp_forwarder.policy import Decision, PolicyDecision, PolicyEvaluator
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import (
    DEFAULT_AGENT_ID,
    McpRefusal,
    Router,
)
from odis_harness.mcp_forwarder.server import build_mcp_server
from odis_harness.mcp_forwarder.transports import build_asgi_app, serve_http
from odis_harness.mcp_forwarder.vendor_client import (
    McpClient,
    ToolDescriptor,
    ToolResult,
    VendorUnreachable,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient

__all__ = [
    "DEFAULT_AGENT_ID",
    "ActionLimitViolation",
    "Decision",
    "DiscoveryCache",
    "DiscoveryFailureCallback",
    "ForwardMode",
    "HttpMcpClient",
    "McpClient",
    "McpRefusal",
    "PolicyDecision",
    "PolicyEvaluator",
    "ReasonCode",
    "Router",
    "RuntimeContextFactory",
    "ToolDescriptor",
    "ToolResult",
    "UnroutedToolName",
    "VendorUnreachable",
    "audit_discovery_failed",
    "audit_forward",
    "audit_refused",
    "build_asgi_app",
    "build_mcp_server",
    "enforce_action_limits",
    "parse_tool_name",
    "serve_http",
]
