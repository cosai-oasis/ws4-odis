"""Router action-limit behavior for read-only policed tools.

These tests avoid the OPA subprocess: the policy result is fixed via
`factories.AllowAllPolicyEvaluator`, so the coverage is specifically on
`Router.forward`'s post-policy action-limit gate.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import pytest

from odis_harness.mcp_forwarder.router import McpRefusal, Router
from tests import factories

if TYPE_CHECKING:
    from odis_harness.bundle import Family
    from odis_harness.fixtures.vendor import InMemoryMcpClient

pytestmark = pytest.mark.enable_socket

_FAMILY = "gitlab-readonly"


def _router(
    action_limits_by_tool: dict[str, dict[str, object]],
    *,
    vendor: InMemoryMcpClient,
    audit: factories.CapturingAuditSink,
) -> tuple[Router, Family]:
    """A Router whose policy always allows, so action limits are the only gate."""
    family = factories.family(
        policy="package odis_policy\n",
        action_limits_by_tool=action_limits_by_tool,
        endpoint_id=_FAMILY,
    )
    router = factories.router(
        factories.bundle(families={_FAMILY: family}),
        opa_binary="",
        audit=audit,
        vendor=vendor,
        policy_evaluator=factories.AllowAllPolicyEvaluator(),
    )
    return router, family


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
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor(tools={"gitlab_health": "ok"})
    router, family = _router({"gitlab_health": {}}, vendor=vendor, audit=audit)
    result = asyncio.run(router.forward(_FAMILY, family, "gitlab_health", {}))
    assert result.content == [{"type": "text", "text": "ok"}]
    assert vendor.calls == [("gitlab_health", {})]
    assert audit.event_types == ["odis.mcp.forward"]


def test_forward_declared_constraints_still_require_an_enforcer(
    inline_policy_eval: None,
) -> None:
    """A constrained tool without an action-limit enforcer still fails closed."""
    del inline_policy_eval
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor(tools={"transition_issue": "ok"})
    router, family = _router(
        {"transition_issue": {"allowed_fields": ["status"]}}, vendor=vendor, audit=audit
    )
    with pytest.raises(McpRefusal) as exc:
        asyncio.run(router.forward(_FAMILY, family, "transition_issue", {"issue_key": "APF-1"}))
    assert exc.value.reason_code == "unenforceable_tool"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]
