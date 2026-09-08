"""What `Router.forward` asserts and enforces on every call.

Three concerns, all of them only observable at the forward boundary: the Authority
Grant's validity window (ODIS-L3-04), the trace id crossing the vendor leg
(ODIS-CC-01), and the delegation chain the Router asserts to the policy engine
(ODIS-L2-05). The window is what put this file beside the bundle tests — `Bundle.expired`
decides and `forward` is the one place that acts on it.
"""

from __future__ import annotations

import dataclasses
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from odis_harness.mcp_forwarder.policy import Decision, PolicyDecision
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import McpRefusal
from tests import factories

if TYPE_CHECKING:
    from odis_harness.bundle import Family
    from odis_harness.contracts import AuthzRequest
    from odis_harness.fixtures.vendor import InMemoryMcpClient
    from odis_harness.mcp_forwarder.policy import PolicyEvaluator
    from odis_harness.mcp_forwarder.router import Router

pytestmark = pytest.mark.enable_socket

_ARGS = {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}


def _router_with_expiry(
    expires_at: str | None, *, audit: factories.CapturingAuditSink
) -> tuple[Router, InMemoryMcpClient]:
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(
        family,
        vendor=vendor,
        opa_binary="",
        audit=audit,
        policy_evaluator=factories.AllowAllPolicyEvaluator(),
    )
    router.bundle = dataclasses.replace(router.bundle, expires_at=expires_at)
    return router, vendor


async def test_forward_refuses_under_an_expired_grant() -> None:
    """An expired grant is no authority at all: the vendor is never called, and the
    refusal is audited before the caller hears about it."""
    audit = factories.CapturingAuditSink()
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    router, vendor = _router_with_expiry(past, audit=audit)

    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", router.bundle.family("jira-prod"), "update_issue", _ARGS)

    assert exc.value.reason_code == ReasonCode.GRANT_EXPIRED
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]
    assert audit.events[0].reason_code == "grant_expired"


async def test_forward_proceeds_inside_the_grant_window() -> None:
    audit = factories.CapturingAuditSink()
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    router, vendor = _router_with_expiry(future, audit=audit)

    await router.forward("jira-prod", router.bundle.family("jira-prod"), "update_issue", _ARGS)

    assert vendor.calls == [("update_issue", _ARGS)]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_forward_proceeds_when_the_grant_declares_no_window() -> None:
    """A local grant carries no expiry. It keeps working — and that it can never
    expire is the honest limit of the unsigned path."""
    audit = factories.CapturingAuditSink()
    router, vendor = _router_with_expiry(None, audit=audit)

    await router.forward("jira-prod", router.bundle.family("jira-prod"), "update_issue", _ARGS)

    assert vendor.calls == [("update_issue", _ARGS)]


async def test_expiry_is_checked_before_the_permissive_passthrough() -> None:
    """A permissive family forwards unpoliced tools with no policy evaluation, so the
    expiry check has to sit ahead of that path or it would be skipped entirely."""
    audit = factories.CapturingAuditSink()
    permissive = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"unpoliced_tool": "ok"})
    router = factories.router(
        permissive,
        vendor=vendor,
        opa_binary="",
        audit=audit,
        policy_evaluator=factories.AllowAllPolicyEvaluator(),
    )
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    router.bundle = dataclasses.replace(router.bundle, expires_at=past)

    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod", router.bundle.family("jira-prod"), "unpoliced_tool", {}
        )

    assert exc.value.reason_code == ReasonCode.GRANT_EXPIRED
    assert vendor.calls == []


async def test_forward_passes_the_calls_trace_id_to_the_vendor() -> None:
    """One identifier spans the agent, the gate and the downstream service
    (ODIS-CC-01). `forward` is the only place that wiring exists, so this is the only
    place it can be proven: the id the vendor receives is the one the Router minted
    for this call, and it is the same id the audit event carries."""
    audit = factories.CapturingAuditSink()
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    router, vendor = _router_with_expiry(future, audit=audit)

    await router.forward("jira-prod", router.bundle.family("jira-prod"), "update_issue", _ARGS)

    assert len(vendor.correlation_ids) == 1
    forwarded = vendor.correlation_ids[0]
    assert forwarded is not None
    assert forwarded == audit.events[0].correlation_id


async def test_a_refused_call_never_reaches_the_vendor_with_a_trace_id() -> None:
    """The propagation must not become a way for a refused call to touch the vendor."""
    audit = factories.CapturingAuditSink()
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    router, vendor = _router_with_expiry(past, audit=audit)

    with pytest.raises(McpRefusal):
        await router.forward("jira-prod", router.bundle.family("jira-prod"), "update_issue", _ARGS)

    assert vendor.correlation_ids == []


def _recording_evaluator() -> tuple[PolicyEvaluator, list[AuthzRequest]]:
    """An allow-everything evaluator plus the list of requests it was handed.

    The request the Router builds is not returned to any caller, so capturing it at
    the policy seam is the only way to assert what the Router asserts. The captured
    list lives in the closure because `PolicyEvaluator` is frozen — a subclass cannot
    hold state of its own.
    """
    captured: list[AuthzRequest] = []

    class _Recorder(factories.AllowAllPolicyEvaluator):
        def evaluate(self, fam: Family, request: AuthzRequest) -> PolicyDecision:  # type: ignore[override]
            captured.append(request)
            return PolicyDecision(
                decision=Decision.ALLOW, obligations={}, reason_code="", decision_id="d-1"
            )

    return _Recorder(), captured


async def test_forward_asserts_an_empty_delegation_chain_to_the_policy_engine() -> None:
    """`odis.authz.request.v1` declares `subject.delegation_chain`, and a declared
    field nothing populates advertises an input with no supply path. This Router
    delegates to no sub-agent, so `[]` is true unconditionally — and it asserts
    single-hop where an absent field asserts nothing."""
    evaluator, captured = _recording_evaluator()
    family = factories.family()
    router = factories.router(
        family,
        opa_binary="",
        audit=factories.CapturingAuditSink(),
        policy_evaluator=evaluator,
    )

    await router.forward("jira-prod", family, "update_issue", _ARGS)

    assert len(captured) == 1
    assert captured[0].subject["delegation_chain"] == []


async def test_the_asserted_chain_does_not_depend_on_the_grant() -> None:
    """The claim is a property of this implementation, not something the issuer tells
    us, so it holds identically for a local grant that carries no delegation record."""
    evaluator, captured = _recording_evaluator()
    family = factories.family()
    router = factories.router(
        family,
        opa_binary="",
        audit=factories.CapturingAuditSink(),
        policy_evaluator=evaluator,
    )
    assert router.bundle.delegation_chain is None, "a local grant asserts nothing itself"

    await router.forward("jira-prod", family, "update_issue", _ARGS)

    assert captured[0].subject["delegation_chain"] == []
