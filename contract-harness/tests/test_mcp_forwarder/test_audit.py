"""audit emission helpers + new event types."""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING

import pytest

from odis_harness.bundle import Family, ToolPolicy, VendorMcp
from odis_harness.contracts.audit_taxonomy import (
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.mcp_forwarder.audit import (
    ForwardMode,
    audit_forward,
    audit_refused,
)

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


def _family() -> Family:
    return Family(
        vendor_mcp=VendorMcp(
            endpoint_id="jira-prod-mcp-v1",
            url="https://jira-prod-mcp.internal:8443/",
        ),
        policy="package odis_policy\n",
        tools={
            "update_issue": ToolPolicy(action_limits={"allowed_fields": ["labels"]}),
        },
        default_mode="strict",
    )


class _CapturingAuditSink:
    """Minimal stand-in for the production AuditSink — captures emitted events."""

    def __init__(self) -> None:
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        self.events.append(event)


def _forward_event(
    *, mode: ForwardMode = "policy_allow", decision_id: str | None = "dec-1"
) -> AuditEvent:
    sink = _CapturingAuditSink()
    audit_forward(
        sink,  # type: ignore[arg-type]
        correlation_id="00000000-0000-4000-8000-000000000001",
        policy_digest="a" * 64,
        family_name="jira-prod",
        family=_family(),
        tool="update_issue",
        decision_id=decision_id,
        mode=mode,
    )
    return sink.events[0]


def _refused_event(*, reason_code: str = "deny") -> AuditEvent:
    sink = _CapturingAuditSink()
    audit_refused(
        sink,  # type: ignore[arg-type]
        correlation_id="00000000-0000-4000-8000-000000000001",
        policy_digest="a" * 64,
        family_name="jira-prod",
        tool="update_issue",
        reason_code=reason_code,
    )
    return sink.events[0]


def test_audit_forward_shape_and_redaction() -> None:
    event = _forward_event()
    extra = event.extra or {}
    assert event.event_type == "odis.mcp.forward"
    assert event.resource_family == "jira-prod"
    assert extra == {
        "tool": "update_issue",
        "vendor_endpoint_id": "jira-prod-mcp-v1",
        "decision_id": "dec-1",
        "mode": "policy_allow",
    }
    uuid.UUID(event.event_id)
    for value in extra.values():
        assert "internal:8443" not in str(value)
    assert "args" not in extra
    assert "arguments" not in extra


def test_audit_forward_permissive_shape() -> None:
    event = _forward_event(mode="permissive", decision_id=None)
    extra = event.extra or {}
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


def test_audit_refused_shape() -> None:
    event = _refused_event(reason_code="obligation_violation")
    assert event.event_type == "odis.mcp.forward_refused"
    assert event.reason_code == "obligation_violation"
    assert event.extra == {"tool": "update_issue"}
