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

import structlog

from odis_harness.contracts import AuthzRequest
from odis_harness.mcp_forwarder.action_limits import (
    ActionLimitViolation,
    enforce_action_limits,
)
from odis_harness.mcp_forwarder.audit import ForwardMode, audit_forward, audit_refused
from odis_harness.mcp_forwarder.identity import CallerIdentity
from odis_harness.mcp_forwarder.policy import Decision
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.vendor_client import VendorUnreachable

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from mcp.server.auth.provider import TokenVerifier

    from odis_harness.audit.sink import AuditSink
    from odis_harness.bundle import Bundle, Family
    from odis_harness.contracts import RuntimeContext
    from odis_harness.mcp_forwarder.discovery import DiscoveryCache
    from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
    from odis_harness.mcp_forwarder.policy import PolicyEvaluator
    from odis_harness.mcp_forwarder.vendor_client import McpClient, ToolResult


_LOG = structlog.get_logger(__name__)

#: Fallback agent identity for call paths with no inbound credential — `demo` and the
#: in-process tests. On the HTTP surface configured with `serve --inbound-key`, the id
#: comes from the verified bearer's subject (`server._caller_identity`), so it is
#: received rather than asserted. `serve` without trust material attributes every caller
#: to this constant, and says so in its startup banner.
DEFAULT_AGENT_ID = "mcp-client"


class McpRefusal(Exception):  # noqa: N818 - "Refusal" reads clearer than "RefusalError"
    """Raised inside the forward path to signal a refused call.

    Carries a structured `reason_code` the MCP-protocol handler maps to an
    error response. The audit event has already been emitted by the time this
    is raised.
    """

    def __init__(self, reason_code: ReasonCode) -> None:
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

    async def serve(
        self,
        *,
        host: str,
        port: int,
        token_verifier: TokenVerifier | None = None,
    ) -> None:
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

        # The handler needs the transport's posture to fail closed on a call it cannot
        # attribute, so it is passed to the server rather than stored on `self`: this is
        # a property of one `serve` call, not of the Router.
        server = build_mcp_server(self, requires_authenticated_caller=token_verifier is not None)
        await serve_http(server, host=host, port=port, token_verifier=token_verifier)

    async def forward(
        self,
        family_name: str,
        family: Family,
        tool: str,
        arguments: Mapping[str, Any],
        *,
        caller: CallerIdentity | None = None,
    ) -> ToolResult:
        """Gate + forward a single tool call. Raises `McpRefusal` on any
        refusal (after emitting the refusal audit).

        `caller` carries the subject of the caller's verified credential. It defaults to
        an unverified `self.agent_id` for the in-process paths (`demo`, tests) that carry
        no inbound credential — see the honesty note on `DEFAULT_AGENT_ID`.
        """
        correlation_id = str(uuid.uuid4())
        runtime_context = self.context_factory.build(
            caller=caller if caller is not None else CallerIdentity(agent_id=self.agent_id),
            resource_family=family_name,
            tool=tool,
            bundle=self.bundle,
            correlation_id=correlation_id,
        )

        try:
            return await self._gated_forward(
                family_name, family, tool, arguments, runtime_context
            )
        except McpRefusal:
            raise
        except Exception:  # noqa: BLE001 - fail-closed boundary: a bug must refuse and be
            # audited, never surface to the agent. Narrowing this would let an unlisted
            # exception type escape and reach the caller as raw text.
            # A bug, not a policy refusal. Audited with this call's own context and
            # correlation id so the event joins the trail, then converted to a generic
            # refusal — the agent never sees the exception.
            _LOG.exception(
                "router.forward.internal_error",
                correlation_id=correlation_id,
                resource_family=family_name,
                tool=tool,
            )
            self._refuse(runtime_context, family_name, tool, ReasonCode.INTERNAL_ERROR)

    async def _gated_forward(
        self,
        family_name: str,
        family: Family,
        tool: str,
        arguments: Mapping[str, Any],
        runtime_context: RuntimeContext,
    ) -> ToolResult:
        """The gate itself: grant window, policed-tool check, policy, action limits, forward."""
        correlation_id = runtime_context.correlation_id

        # The grant's validity window bounds everything downstream, so it is checked
        # before the policed-tool branch — a permissive family forwards with no policy
        # evaluation at all, and an expired grant must not reach that path either.
        # A grant declaring no expiry never expires; see `Bundle.expired`.
        if self.bundle.expired():
            self._refuse(runtime_context, family_name, tool, ReasonCode.GRANT_EXPIRED)

        has_policy = family.governs_tool(tool)
        if not has_policy:
            if family.default_mode == "permissive":
                return await self._permissive_forward(
                    family_name, family, tool, arguments, runtime_context
                )
            self._refuse(runtime_context, family_name, tool, ReasonCode.UNPOLICED_TOOL)

        # Policy path. `evaluate` shells out to OPA (blocking subprocess);
        # run it off the event loop so concurrent forwards aren't serialized.
        request = self._build_authz_request(runtime_context, family_name, tool, arguments)
        decision = await asyncio.to_thread(self.policy_evaluator.evaluate, family, request)
        if decision.decision != Decision.ALLOW:
            # Carry the evaluator's own reason: a fail-closed `policy_error` (OPA
            # unreachable) must not read as `deny` (the policy refused), which are the
            # two cases an operator most needs to tell apart.
            self._refuse(runtime_context, family_name, tool, decision.reason_code)

        # Action-limit enforcement (scoped authority from the decision). Empty
        # declared action limits mean "policy-gated, no post-policy argument
        # filter" for read-only tools such as GitLab list/get calls.
        declared_action_limits = family.action_limits_for(tool)
        if decision.obligations or declared_action_limits:
            try:
                enforce_action_limits(tool, arguments, decision.obligations)
            except ActionLimitViolation as exc:
                # Carry the enforcer's detail: it names the argument or value that
                # failed, and a bare `obligation_violation` leaves an operator unable to
                # tell a forbidden field from an out-of-scope project. It goes to the
                # audit record only — the agent still gets the reason code alone.
                self._refuse(
                    runtime_context,
                    family_name,
                    tool,
                    ReasonCode.OBLIGATION_VIOLATION,
                    detail=str(exc),
                )
            except NotImplementedError:
                # The bundle declared this tool as policed, but the harness has no
                # action-limit enforcer for it. Fail closed (deny) rather than
                # crash or passthrough — the author asked for a constraint we
                # cannot satisfy.
                self._refuse(runtime_context, family_name, tool, ReasonCode.UNENFORCEABLE_TOOL)

        result = await self._call_vendor(family_name, tool, arguments, runtime_context)
        audit_forward(
            self.audit,
            correlation_id=correlation_id,
            bundle=self.bundle,
            family_name=family_name,
            family=family,
            tool=tool,
            decision_id=decision.decision_id,
            mode=ForwardMode.POLICY_ALLOW,
            runtime_context=runtime_context,
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
            bundle=self.bundle,
            family_name=family_name,
            family=family,
            tool=tool,
            decision_id=None,
            mode=ForwardMode.PERMISSIVE,
            runtime_context=runtime_context,
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
            # The call's trace id crosses the vendor leg, so one identifier spans the
            # agent, the gate, and the downstream service (ODIS-CC-01).
            return await self.vendor_clients[family_name].call_tool(
                tool, arguments, correlation_id=runtime_context.correlation_id
            )
        except VendorUnreachable:
            self._refuse(runtime_context, family_name, tool, ReasonCode.VENDOR_UNREACHABLE)

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
                "originating_principal": dict(runtime_context.originating_principal),
                "agent": dict(runtime_context.agent),
                # Empty unconditionally, and true unconditionally: this Router
                # delegates to no sub-agent in either bundle mode, so a call never
                # arrives through parent hops. An explicit [] asserts single-hop where
                # an absent field asserts nothing — and it is a structural property of
                # this implementation, not something the grant tells us, so it is not
                # sourced from the bundle (the claim holds identically for a local one).
                "delegation_chain": [],
            },
            target_resource={"resource_family": family_name},
            verb=tool,
            request_body=dict(arguments),
            task_intent=runtime_context.task_intent,
            issued_at=runtime_context.issued_at,
            policy_digest=runtime_context.policy_digest,
            bundle_id=runtime_context.bundle_id,
            bundle_version=runtime_context.bundle_version,
            trust_root_id=runtime_context.trust_root_id,
        )

    def _refuse(
        self,
        runtime_context: RuntimeContext,
        family_name: str,
        tool: str,
        reason_code: ReasonCode,
        detail: str | None = None,
    ) -> NoReturn:
        """Audit the refusal, then raise. `detail` is audited, never returned.

        `McpRefusal` carries only the reason code, so nothing here reaches the agent —
        an explanation of *why* a constraint failed is exactly the kind of detail that
        helps a caller probe for the constraint's shape.
        """
        audit_refused(
            self.audit,
            correlation_id=runtime_context.correlation_id,
            bundle=self.bundle,
            family_name=family_name,
            tool=tool,
            reason_code=reason_code,
            runtime_context=runtime_context,
            detail=detail,
        )
        raise McpRefusal(reason_code)


__all__ = ["DEFAULT_AGENT_ID", "McpRefusal", "Router"]
