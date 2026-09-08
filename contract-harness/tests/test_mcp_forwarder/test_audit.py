"""audit emission helpers + new event types."""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

import pytest

from odis_harness.contracts import STUB_BUNDLE_VERSION
from odis_harness.contracts.audit_taxonomy import (
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.mcp_forwarder.audit import (
    ForwardMode,
    audit_discovery_failed,
    audit_forward,
    audit_refused,
)
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from tests import factories

if TYPE_CHECKING:
    from odis_harness.contracts import AuditEvent


# pytest-asyncio's event-loop setup touches sockets; these tests don't use sockets.
pytestmark = pytest.mark.enable_socket


# -- new event types are registered ------------------------------------------


@pytest.mark.parametrize(
    "event_type",
    [
        "odis.mcp.forward",
        "odis.mcp.forward_refused",
        "odis.mcp.discovery_failed",
    ],
)
def test_mcp_audit_events_are_registered(event_type: str) -> None:
    assert event_type in ODIS_EXTENSION_TYPES
    assert is_valid_event_type(event_type)


# -- audit_forward / audit_refused helpers -----------------------------------


#: A vendor URL with a host:port the audit event must never carry.
_VENDOR_URL = "https://jira-prod-mcp.internal:8443/"
_CORRELATION_ID = "00000000-0000-4000-8000-000000000001"


def _forward_event(
    *, mode: ForwardMode = ForwardMode.POLICY_ALLOW, decision_id: str | None = "dec-1"
) -> AuditEvent:
    sink = factories.CapturingAuditSink()
    audit_forward(
        sink,
        correlation_id=_CORRELATION_ID,
        bundle=factories.bundle(),
        family_name="jira-prod",
        family=factories.family(url=_VENDOR_URL, policy="package odis_policy\n"),
        tool="update_issue",
        decision_id=decision_id,
        mode=mode,
        runtime_context=factories.runtime_context(),
    )
    return sink.events[0]


def _refused_event(*, reason_code: str = "deny") -> AuditEvent:
    sink = factories.CapturingAuditSink()
    audit_refused(
        sink,
        correlation_id=_CORRELATION_ID,
        bundle=factories.bundle(),
        family_name="jira-prod",
        tool="update_issue",
        reason_code=reason_code,
        runtime_context=factories.runtime_context(),
    )
    return sink.events[0]


def test_audit_forward_shape_and_redaction() -> None:
    event = _forward_event()
    extra = event.extra or {}
    assert event.event_type == "odis.mcp.forward"
    assert event.resource_family == "jira-prod"
    # Compared exactly, not key-by-key: the audit event is a published contract, so a
    # new or renamed key has to be a deliberate edit here rather than a silent addition.
    assert extra == {
        "tool": "update_issue",
        "vendor_endpoint_id": "jira-prod-mcp-v1",
        "decision_id": "dec-1",
        "mode": "policy_allow",
        # ODIS-CC-02: every forwarded/refused action names who acted. Nested under
        # one key so it cannot collide with another `extra` entry.
        "actor": {
            "agent": {"id": "mcp-client", "type": "fixture_workload_identity"},
            "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
        },
    }
    assert event.user_id == "fixture-principal"
    uuid.UUID(event.event_id)
    for value in extra.values():
        assert "internal:8443" not in str(value)
    assert "args" not in extra
    assert "arguments" not in extra


def test_audit_forward_permissive_shape() -> None:
    event = _forward_event(mode=ForwardMode.PERMISSIVE, decision_id=None)
    extra = event.extra or {}
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


def test_audit_discovery_failed_shape() -> None:
    """The third emitter: a family whose tool catalog could not be fetched."""
    sink = factories.CapturingAuditSink()
    audit_discovery_failed(sink, bundle=factories.bundle(), family_name="jira-prod")
    event = sink.events[0]
    assert event.event_type == "odis.mcp.discovery_failed"
    assert event.resource_family == "jira-prod"
    assert event.reason_code == ReasonCode.VENDOR_UNREACHABLE
    # Each discovery failure belongs to no agent call, so it carries its own id.
    uuid.UUID(event.correlation_id)
    # The underlying exception can hold vendor detail and must not be carried.
    assert event.extra is None


def test_audit_refused_shape() -> None:
    event = _refused_event(reason_code="obligation_violation")
    assert event.event_type == "odis.mcp.forward_refused"
    assert event.reason_code == "obligation_violation"
    assert event.extra == {
        "tool": "update_issue",
        "actor": {
            "agent": {"id": "mcp-client", "type": "fixture_workload_identity"},
            "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
        },
    }


def test_events_name_the_loaded_grant_not_the_fixture_defaults() -> None:
    """An audit event must identify the Authority Grant actually in force.

    Guards all three emitters against reporting the `STUB_*` fallbacks instead of the
    loaded grant's identity, which would leave the trail unable to say which policy
    authorized a call.
    """
    grant = factories.bundle()
    # A grant whose identity differs from the fixture constants, so a regression to
    # the pinned values is visible rather than coincidentally correct.
    assert grant.bundle_version != STUB_BUNDLE_VERSION

    sink = factories.CapturingAuditSink()
    audit_forward(
        sink,
        correlation_id=_CORRELATION_ID,
        bundle=grant,
        family_name="jira-prod",
        family=factories.family(),
        tool="update_issue",
        decision_id="dec-1",
        mode=ForwardMode.POLICY_ALLOW,
        runtime_context=factories.runtime_context(),
    )
    audit_refused(
        sink,
        correlation_id=_CORRELATION_ID,
        bundle=grant,
        family_name="jira-prod",
        tool="update_issue",
        reason_code=ReasonCode.DENY,
        runtime_context=factories.runtime_context(),
    )
    audit_discovery_failed(sink, bundle=grant, family_name="jira-prod")

    assert len(sink.events) == 3
    for event in sink.events:
        assert event.bundle_id == grant.bundle_id
        assert event.bundle_version == grant.bundle_version
        assert event.trust_root_id == grant.trust_root_id
        assert event.policy_digest == grant.policy_digest


def test_handler_refusal_has_no_actor_and_claims_no_enforcement() -> None:
    """A refusal at the protocol boundary names no actor and claims no enforcement.

    It fires before routing resolves a family, so there is no identity context — and
    minting one would call the identity providers on agent-controlled input that is
    already being rejected. With no `resource_family`, the sink also derives
    `apf_semantic_enforcement` false, which is correct: the call reached neither policy
    nor an action-limit enforcer.
    """
    sink = factories.CapturingAuditSink()
    audit_refused(
        sink,
        correlation_id=_CORRELATION_ID,
        bundle=factories.bundle(),
        family_name=None,
        tool="whatever",
        reason_code=ReasonCode.UNROUTED_FAMILY,
        runtime_context=None,
    )
    event = sink.events[0]
    assert event.extra == {"tool": "whatever"}
    assert event.user_id is None
    assert event.resource_family is None
    assert json.loads(sink.output.getvalue())["apf_semantic_enforcement"] is False


def test_forward_mode_serializes_as_its_bare_wire_string() -> None:
    """`extra.mode` is read outside this repo, so the members are transcribed here rather
    than read off `.value` — the latter asserts only that the enum equals itself."""
    assert {m.value for m in ForwardMode} == {"policy_allow", "permissive"}
    event = _forward_event()
    assert json.loads(
        json.dumps({"mode": (event.extra or {})["mode"]})
    ) == {"mode": "policy_allow"}
