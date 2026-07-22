"""Router action-limit behavior for read-only policed tools.

These tests avoid the real OPA subprocess. The policy result is fixed so the
coverage is specifically on Router.forward's post-policy action-limit gate.
"""

from __future__ import annotations

import asyncio

import pytest

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyDecision
from odis_harness.mcp_forwarder.router import McpRefusal, Router
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

pytestmark = pytest.mark.enable_socket


class _CapturingAuditSink:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


class _AllowPolicyEvaluator:
    def evaluate(self, _family: Family, _request: object) -> PolicyDecision:
        return PolicyDecision(
            decision="allow",
            obligations={},
            reason_code="",
            decision_id="decision-1",
        )


def _event_types(sink: _CapturingAuditSink) -> list[str]:
    return [e.event_type for e in sink.events]  # type: ignore[attr-defined]


def _family(action_limits_by_tool: dict[str, dict[str, object]]) -> Family:
    return Family(
        vendor_mcp=VendorMcp(endpoint_id="gitlab-readonly", url="https://x.invalid/"),
        policy="package odis_policy\n",
        tools={
            tool: ToolPolicy(action_limits=action_limits)
            for tool, action_limits in action_limits_by_tool.items()
        },
        default_mode="strict",
    )


def _router(family: Family, client: InMemoryMcpClient, audit: _CapturingAuditSink) -> Router:
    return Router(
        bundle=Bundle(
            bundle_id="b",
            bundle_version="0.1.0",
            trust_root_id="r",
            families={"gitlab-readonly": family},
        ),
        policy_evaluator=_AllowPolicyEvaluator(),  # type: ignore[arg-type]
        context_factory=RuntimeContextFactory(
            workload_identity=FixtureWorkloadIdentityProvider(),
            sponsor_provider=FixtureSponsorIdentityProvider(),
        ),
        audit=audit,  # type: ignore[arg-type]
        vendor_clients={"gitlab-readonly": client},
    )


@pytest.fixture
def inline_policy_eval(monkeypatch: pytest.MonkeyPatch) -> None:
    """Run Router's policy-eval callable inline; this file tests action limits."""

    async def _inline_to_thread(func: object, /, *args: object, **kwargs: object) -> object:
        return func(*args, **kwargs)  # type: ignore[operator]

    monkeypatch.setattr("odis_harness.mcp_forwarder.router.asyncio.to_thread", _inline_to_thread)


def test_forward_policed_read_only_tool_allows_empty_obligations(
    inline_policy_eval: None,
) -> None:
    """A policed read/list tool can have no post-policy action-limit enforcer."""
    del inline_policy_eval
    audit = _CapturingAuditSink()
    family = _family({"gitlab_health": {}})
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="gitlab_health", description="", input_schema={})],
        responses={"gitlab_health": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )
    router = _router(family, client, audit)
    result = asyncio.run(router.forward("gitlab-readonly", family, "gitlab_health", {}))
    assert result.content == [{"type": "text", "text": "ok"}]
    assert client.calls == [("gitlab_health", {})]
    assert _event_types(audit) == ["odis.mcp.forward"]


def test_forward_declared_constraints_still_require_an_enforcer(
    inline_policy_eval: None,
) -> None:
    """A constrained tool without an action-limit enforcer still fails closed."""
    del inline_policy_eval
    audit = _CapturingAuditSink()
    family = _family({"transition_issue": {"allowed_fields": ["status"]}})
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="transition_issue", description="", input_schema={})],
        responses={"transition_issue": ToolResult(content=[])},
    )
    router = _router(family, client, audit)
    with pytest.raises(McpRefusal) as exc:
        asyncio.run(
            router.forward("gitlab-readonly", family, "transition_issue", {"issue_key": "APF-1"})
        )
    assert exc.value.reason_code == "unenforceable_tool"
    assert client.calls == []
    assert _event_types(audit) == ["odis.mcp.forward_refused"]
