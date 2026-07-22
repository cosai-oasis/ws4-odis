"""Audit emission helpers for the Router.

Two helpers — `audit_forward` and `audit_refused` — construct the
`odis.mcp.forward` / `odis.mcp.forward_refused` events and hand them to the
provided `AuditSink`. Both helpers stamp the supplied `policy_digest` (bound
to the bundle the decision was made against) so the audit trail attests to
the exact bundle in force.

`vendor_endpoint_id` (from `Family.vendor_mcp`) is recorded in the event's
`extra`. The vendor's URL is NOT recorded: audit records reference
the stable endpoint id from the bundle so URL changes don't break the trail.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal

from odis_harness.contracts import AuditEvent

if TYPE_CHECKING:
    from odis_harness.audit.sink import AuditSink
    from odis_harness.bundle import Family


ForwardMode = Literal["policy_allow", "permissive"]


def audit_forward(  # noqa: PLR0913 - audit event has many independent kw-only fields
    audit: AuditSink,
    *,
    correlation_id: str,
    policy_digest: str,
    family_name: str,
    family: Family,
    tool: str,
    decision_id: str | None,
    mode: ForwardMode,
) -> None:
    """Emit `odis.mcp.forward` for a successful (or permissive) forward.

    `decision_id` is the RPV decision that authorized the call for
    `mode="policy_allow"`; `None` when the call was a permissive-mode
    passthrough (no policy was evaluated).
    """
    audit.emit(
        AuditEvent(
            correlation_id=correlation_id,
            event_id=str(uuid.uuid4()),
            timestamp=_now_iso(),
            event_type="odis.mcp.forward",
            policy_digest=policy_digest,
            resource_family=family_name,
            extra={
                "tool": tool,
                "vendor_endpoint_id": family.vendor_mcp.endpoint_id,
                "decision_id": decision_id,
                "mode": mode,
            },
        )
    )


def audit_refused(  # noqa: PLR0913 - audit event has many independent kw-only fields
    audit: AuditSink,
    *,
    correlation_id: str,
    policy_digest: str,
    family_name: str,
    tool: str,
    reason_code: str,
) -> None:
    """Emit `odis.mcp.forward_refused` with a structured reason_code.

    `reason_code` is one of: `deny`, `obligation_violation`,
    `vendor_unreachable`, `unpoliced_tool`, `unrouted_family`.
    """
    audit.emit(
        AuditEvent(
            correlation_id=correlation_id,
            event_id=str(uuid.uuid4()),
            timestamp=_now_iso(),
            event_type="odis.mcp.forward_refused",
            policy_digest=policy_digest,
            resource_family=family_name,
            reason_code=reason_code,
            extra={"tool": tool},
        )
    )


def _now_iso() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


__all__ = ["ForwardMode", "audit_forward", "audit_refused"]
