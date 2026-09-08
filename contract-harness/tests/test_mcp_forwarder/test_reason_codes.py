"""`ReasonCode` — the refusal vocabulary audit consumers read off the wire."""

from __future__ import annotations

import pytest

from odis_harness.mcp_forwarder.reason_codes import ReasonCode


@pytest.mark.parametrize(
    ("member", "wire_value"),
    [
        (ReasonCode.GRANT_EXPIRED, "grant_expired"),
        (ReasonCode.UNPOLICED_TOOL, "unpoliced_tool"),
        (ReasonCode.DENY, "deny"),
        (ReasonCode.POLICY_ERROR, "policy_error"),
        (ReasonCode.INVALID_REGO_RESULT, "invalid_rego_result"),
        (ReasonCode.OBLIGATION_VIOLATION, "obligation_violation"),
        (ReasonCode.UNENFORCEABLE_TOOL, "unenforceable_tool"),
        (ReasonCode.VENDOR_UNREACHABLE, "vendor_unreachable"),
        (ReasonCode.UNROUTED_FAMILY, "unrouted_family"),
        (ReasonCode.UNATTRIBUTED_CALLER, "unattributed_caller"),
        (ReasonCode.INTERNAL_ERROR, "internal_error"),
    ],
)
def test_member_serializes_to_its_documented_wire_value(
    member: ReasonCode, wire_value: str
) -> None:
    """Each member's value is the string that lands in `reason_code` on an audit event.

    Pinned explicitly: renaming a member is free, but changing its *value* breaks every
    downstream audit consumer, and `StrEnum` makes that change invisible to mypy.
    """
    assert member == wire_value
    assert f"{member}" == wire_value


def test_vocabulary_is_exactly_the_documented_set() -> None:
    """A new refusal reason has to be added here deliberately.

    `audit_refused`'s docstring tells readers to iterate `ReasonCode` rather than keep a
    list; this is the test that makes that instruction load-bearing.
    """
    assert {r.value for r in ReasonCode} == {
        "grant_expired",
        "unpoliced_tool",
        "deny",
        "policy_error",
        "invalid_rego_result",
        "obligation_violation",
        "unenforceable_tool",
        "vendor_unreachable",
        "unrouted_family",
        "unattributed_caller",
        "internal_error",
    }
