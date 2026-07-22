"""Router — the ODIS Router building block.

Receives MCP `tools/call`, gates each call against the signed bundle's
per-family policy (via `PolicyEvaluator`) and action limits, then forwards
approved calls to the vendor MCP server resolved from the bundle's routing
entry. Vendor MCP servers hold their own credentials; the Router never sees a
provider bearer.

This module holds the forward orchestration (`forward` + `_permissive_forward`);
`serve()` exposes it as an MCP server over HTTP (the protocol handlers live in
`server.py`).
"""

from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, NoReturn

from odis_harness.contracts import AuthzRequest
from odis_harness.mcp_forwarder.action_limits import (
    ActionLimitViolation,
    enforce_action_limits,
)
from odis_harness.mcp_forwarder.audit import audit_forward, audit_refused
from odis_harness.mcp_forwarder.vendor_client import VendorUnreachable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from odis_harness.audit.sink import AuditSink
    from odis_harness.bundle import Bundle, Family
    from odis_harness.contracts import RuntimeContext
    from odis_harness.mcp_forwarder.discovery import DiscoveryCache
    from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
    from odis_harness.mcp_forwarder.policy import PolicyEvaluator
    from odis_harness.mcp_forwarder.vendor_client import McpClient, ToolResult


#: The agent identity recorded for forwarded calls. MCP `tools/call` carries no
#: per-call agent id; binding to a real Passport identity is Phase 1+ work.
DEFAULT_AGENT_ID = "mcp-client"


class McpRefusal(Exception):  # noqa: N818 - "Refusal" reads clearer than "RefusalError"
    """Raised inside the forward path to signal a refused call.

    Carries a structured `reason_code` the MCP-protocol handler maps to an
    error response. The audit event has already been emitted by the time this
    is raised.
    """

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(kw_only=True)
class Router:
    """The ODIS Router. Constructor-injected; holds no global state."""

    bundle: Bundle
    policy_evaluator: PolicyEvaluator
    context_factory: RuntimeContextFactory
    audit: AuditSink
    vendor_clients: Mapping[str, McpClient]
    discovery: DiscoveryCache | None = None
    agent_id: str = DEFAULT_AGENT_ID

    async def serve(self, *, host: str, port: int) -> None:
        """Build the MCP server over this Router and serve it via HTTP.

        Lazy imports keep `router.py` free of the `mcp`/Starlette dependency at
        module level — the forward engine above stays SDK-agnostic; only this
        entry point pulls in the protocol + transport layers.
        """
        from odis_harness.mcp_forwarder.server import (  # noqa: PLC0415
            build_mcp_server,
        )
        from odis_harness.mcp_forwarder.transports import (  # noqa: PLC0415
            serve_http,
        )

        await serve_http(build_mcp_server(self), host=host, port=port)

    async def forward(
        self,
        family_name: str,
        family: Family,
        tool: str,
        arguments: Mapping[str, Any],
    ) -> ToolResult:
        """Gate + forward a single tool call. Raises `McpRefusal` on any
        refusal (after emitting the refusal audit)."""
        correlation_id = str(uuid.uuid4())
        runtime_context = self.context_factory.build(
            agent_id=self.agent_id,
            resource_family=family_name,
            tool=tool,
            policy_digest=self.bundle.policy_digest,
            correlation_id=correlation_id,
        )

        has_policy = family.governs_tool(tool)
        if not has_policy:
            if family.default_mode == "permissive":
                return await self._permissive_forward(
                    family_name, family, tool, arguments, runtime_context
                )
            self._refuse(runtime_context, family_name, tool, "unpoliced_tool")

        # Policy path. `evaluate` shells out to OPA (blocking subprocess);
        # run it off the event loop so concurrent forwards aren't serialized.
        request = self._build_authz_request(runtime_context, family_name, tool, arguments)
        decision = await asyncio.to_thread(self.policy_evaluator.evaluate, family, request)
        if decision.decision != "allow":
            self._refuse(runtime_context, family_name, tool, "deny")

        # Action-limit enforcement (scoped authority from the decision). Empty
        # declared action limits mean "policy-gated, no post-policy argument
        # filter" for read-only tools such as GitLab list/get calls.
        declared_action_limits = family.action_limits_for(tool)
        if decision.obligations or declared_action_limits:
            try:
                enforce_action_limits(tool, arguments, decision.obligations)
            except ActionLimitViolation:
                self._refuse(runtime_context, family_name, tool, "obligation_violation")
            except NotImplementedError:
                # The bundle declared this tool as policed, but the harness has no
                # action-limit enforcer for it. Fail closed (deny) rather than
                # crash or passthrough — the author asked for a constraint we
                # cannot satisfy.
                self._refuse(runtime_context, family_name, tool, "unenforceable_tool")

        result = await self._call_vendor(family_name, tool, arguments, runtime_context)
        audit_forward(
            self.audit,
            correlation_id=correlation_id,
            policy_digest=self.bundle.policy_digest,
            family_name=family_name,
            family=family,
            tool=tool,
            decision_id=decision.decision_id,
            mode="policy_allow",
        )
        return result

    async def _permissive_forward(
        self,
        family_name: str,
        family: Family,
        tool: str,
        arguments: Mapping[str, Any],
        runtime_context: RuntimeContext,
    ) -> ToolResult:
        """Forward an unpoliced tool with no policy evaluation (permissive mode).

        Applies ONLY to the no-policy-for-this-tool case; policed tools never
        reach here (the caller routes them through the policy path).
        """
        result = await self._call_vendor(family_name, tool, arguments, runtime_context)
        audit_forward(
            self.audit,
            correlation_id=runtime_context.correlation_id,
            policy_digest=self.bundle.policy_digest,
            family_name=family_name,
            family=family,
            tool=tool,
            decision_id=None,
            mode="permissive",
        )
        return result

    # -- internals -----------------------------------------------------------

    async def _call_vendor(
        self,
        family_name: str,
        tool: str,
        arguments: Mapping[str, Any],
        runtime_context: RuntimeContext,
    ) -> ToolResult:
        try:
            return await self.vendor_clients[family_name].call_tool(tool, arguments)
        except VendorUnreachable:
            self._refuse(runtime_context, family_name, tool, "vendor_unreachable")

    def _build_authz_request(
        self,
        runtime_context: RuntimeContext,
        family_name: str,
        tool: str,
        arguments: Mapping[str, Any],
    ) -> AuthzRequest:
        return AuthzRequest(
            correlation_id=runtime_context.correlation_id,
            subject={
                "sponsor": dict(runtime_context.sponsor),
                "agent": dict(runtime_context.agent),
            },
            target_resource={"resource_family": family_name},
            verb=tool,
            request_body=dict(arguments),
            task_intent=runtime_context.task_intent,
            issued_at=runtime_context.issued_at,
            policy_digest=runtime_context.policy_digest,
        )

    def _refuse(
        self,
        runtime_context: RuntimeContext,
        family_name: str,
        tool: str,
        reason_code: str,
    ) -> NoReturn:
        audit_refused(
            self.audit,
            correlation_id=runtime_context.correlation_id,
            policy_digest=self.bundle.policy_digest,
            family_name=family_name,
            tool=tool,
            reason_code=reason_code,
        )
        raise McpRefusal(reason_code)


__all__ = ["DEFAULT_AGENT_ID", "McpRefusal", "Router"]
