"""Router.forward + _permissive_forward."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import pytest

from odis_harness.contracts import AuthzRequest, EnvelopeValidator
from odis_harness.mcp_forwarder.policy import PolicyDecision, PolicyEvaluator
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import McpRefusal
from odis_harness.paths import default_schemas_dir
from tests import factories

if TYPE_CHECKING:
    from odis_harness.bundle import Family

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]

_ALLOWED_ARGS = {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}
_OUTSIDE_PROJECT_ARGS = {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}}
_ALLOW_ALL = 'package odis_policy\ndefault decision := {"decision": "allow", "obligations": {}}\n'


# -- policy path --------------------------------------------------------


async def test_forward_allow_calls_vendor_and_emits_forward_audit(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert vendor.calls == [("update_issue", _ALLOWED_ARGS)]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_forward_returns_vendor_response_unchanged(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor(tools={"update_issue": "the vendor's exact bytes"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "the vendor's exact bytes"}]


async def test_forward_emits_decision_id_in_audit_when_policy_evaluated(
    opa_binary: str,
) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    router = factories.router(family, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    extra = audit.events[0].extra
    assert extra is not None
    assert extra["decision_id"]  # non-empty
    assert extra["mode"] == "policy_allow"


async def test_forward_deny_does_not_call_vendor_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_obligation_violation_does_not_call_vendor(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    # Policy allows (APF- prefix), but the call mutates a field outside
    # the decision's obligations (allowed_fields=[labels]).
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "APF-1", "fields": {"summary": "nope"}},
        )
    assert exc.value.reason_code == "obligation_violation"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]

    # The enforcer's detail reaches the operator. A bare `obligation_violation` cannot
    # distinguish a forbidden field from an out-of-scope project, and the enforcer
    # already knows which it was.
    detail = audit.events[0].extra["detail"]
    assert "summary" in detail

    # And only the operator: the agent gets the reason code, never the explanation.
    # Telling a caller *which* field tripped the constraint hands it the shape of the
    # constraint, one refused call at a time.
    assert str(exc.value.reason_code) == str(exc.value)
    assert "summary" not in str(exc.value)


async def test_forward_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor(unreachable=True)
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert exc.value.reason_code == "vendor_unreachable"
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_policed_but_unenforceable_tool_fails_closed(opa_binary: str) -> None:
    """A tool the bundle declares as policed but the harness can't enforce
    denies (fail closed) rather than crashing or reaching the vendor."""
    audit = factories.CapturingAuditSink()
    # `transition_issue` is governed, but there is no registered action-limit
    # enforcer for it (only update_issue exists).
    family = factories.family(
        policy=_ALLOW_ALL,
        action_limits_by_tool={"transition_issue": {"allowed_fields": ["status"]}},
    )
    vendor = factories.in_memory_vendor(tools={"transition_issue": "ok"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "transition_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unenforceable_tool"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


async def test_forward_unpoliced_tool_strict_refuses(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    # Family declares policy for update_issue only; agent calls delete_issue.
    family = factories.family()
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unpoliced_tool"
    assert vendor.calls == []
    assert audit.event_types == ["odis.mcp.forward_refused"]


# -- permissive path -----------------------------------------------------


async def test_permissive_unpoliced_tool_forwards(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert result.content == [{"type": "text", "text": "deleted"}]
    assert vendor.calls == [("delete_issue", {"issue_key": "X-1"})]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_permissive_forward_audit_has_permissive_mode_no_decision_id(
    opa_binary: str,
) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"})
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    extra = audit.events[0].extra
    assert extra is not None
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


async def test_permissive_policed_tool_still_evaluates_policy(opa_binary: str) -> None:
    """Permissive only affects unpoliced tools; a policed tool still gets policy."""
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")  # update_issue IS policed
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    # Outside-project issue_key -> policy denies even in a permissive family.
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []


async def test_permissive_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = factories.CapturingAuditSink()
    family = factories.family(default_mode="permissive")
    vendor = factories.in_memory_vendor(tools={"delete_issue": "deleted"}, unreachable=True)
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert exc.value.reason_code == "vendor_unreachable"
    assert audit.event_types == ["odis.mcp.forward_refused"]


# -- end-to-end against the shipped example bundle ---------------------------
# Guards against Rego-vs-OPA-input-shape drift: the example bundle's policy
# must agree with what the Router actually sends (bare verb + raw args).


async def test_example_bundle_jira_prod_allows_labels_on_apf(opa_binary: str) -> None:
    bundle = factories.example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor()
    router = factories.router(bundle, vendor=vendor, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert audit.event_types == ["odis.mcp.forward"]


async def test_example_bundle_jira_prod_denies_other_project(opa_binary: str) -> None:
    bundle = factories.example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = factories.CapturingAuditSink()
    vendor = factories.in_memory_vendor()
    router = factories.router(bundle, vendor=vendor, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    assert exc.value.reason_code == "deny"
    assert vendor.calls == []


async def test_forward_audits_the_evaluators_reason_not_a_blanket_deny(
    opa_binary: str,
) -> None:
    """A fail-closed policy error must reach the audit trail as `policy_error`.

    Regression guard: auditing every non-allow decision as `deny` makes "OPA was
    unreachable" indistinguishable from "the policy refused".
    """
    del opa_binary  # this test deliberately supplies a broken binary
    audit = factories.CapturingAuditSink()
    family = factories.family()
    router = factories.router(family, opa_binary="/nonexistent/opa", audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert exc.value.reason_code == ReasonCode.POLICY_ERROR
    assert audit.events[0].reason_code == ReasonCode.POLICY_ERROR


async def test_forward_sends_the_audited_correlation_id_to_the_vendor(opa_binary: str) -> None:
    """ODIS-CC-01: one identifier correlates the governance checkpoint and the adapter.

    Asserted as an identity, not as presence: an id that reached the vendor but differed
    from the one on the trail would correlate nothing.
    """
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)

    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)

    assert audit.event_types == ["odis.mcp.forward"]
    forwarded = audit.events[0].correlation_id
    uuid.UUID(forwarded)
    assert vendor.correlation_ids == [forwarded]


async def test_refused_call_is_audited_under_its_own_id_and_sends_nothing(
    opa_binary: str,
) -> None:
    """A refusal never reaches the vendor, so it has no downstream half to join — but it is
    still audited under the call's own id, which is what keeps a refused call and a
    forwarded one separable in one trail.
    """
    audit = factories.CapturingAuditSink()
    family = factories.family()
    vendor = factories.in_memory_vendor()
    router = factories.router(family, vendor=vendor, opa_binary=opa_binary, audit=audit)

    with pytest.raises(McpRefusal):
        await router.forward("jira-prod", family, "update_issue", _OUTSIDE_PROJECT_ARGS)
    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)

    assert audit.event_types == ["odis.mcp.forward_refused", "odis.mcp.forward"]
    refused, forwarded = (e.correlation_id for e in audit.events)
    uuid.UUID(refused)
    assert refused != forwarded, "each call mints its own id"
    assert vendor.correlation_ids == [forwarded], "only the forwarded call reached the vendor"


# Not slotted, unlike its parent: `slots=True` makes the dataclass decorator return a new
# class object, which breaks zero-arg `super()`.
@dataclass(frozen=True, kw_only=True)
class _RecordingPolicyEvaluator(PolicyEvaluator):
    """Records each `AuthzRequest` the Router builds, then evaluates it for real.

    Wrapping the real evaluator rather than replacing it keeps the forward path intact,
    so the recorded request is the one an allowed call actually policed on.
    """

    seen: list[AuthzRequest] = field(default_factory=list)

    def evaluate(self, family: Family, request: AuthzRequest) -> PolicyDecision:
        self.seen.append(request)
        return super().evaluate(family, request)


async def test_router_built_authz_request_validates_against_its_schema(
    opa_binary: str,
) -> None:
    """Every field the Router puts in an `AuthzRequest` is one the schema declares.

    Nothing in the forward path validates this envelope — `from_dict` is the only
    validating constructor and the Router never calls it — so the schema is otherwise
    enforced only against test-authored payloads. Round-tripping the Router's own output
    through it is what makes a drift between emitter and schema fail: a field the Router
    stops emitting breaks `required`, and one it starts emitting breaks
    `additionalProperties: false`.
    """
    evaluator = _RecordingPolicyEvaluator(opa_binary=opa_binary)
    family = factories.family()
    router = factories.router(family, opa_binary=opa_binary, policy_evaluator=evaluator)

    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)

    assert len(evaluator.seen) == 1, "the allowed call policed exactly once"
    validator = EnvelopeValidator(default_schemas_dir())
    payload = evaluator.seen[0].to_dict()
    assert AuthzRequest.from_dict(payload, validator) == evaluator.seen[0]
