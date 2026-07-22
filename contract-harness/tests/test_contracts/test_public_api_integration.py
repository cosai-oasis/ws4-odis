"""Public API surface + cross-cutting envelope integration.

Builds a Tier 3 Jira scenario at the contracts layer: construct each envelope
through its dataclass, validate via the shared EnvelopeValidator, and assert
the correlated sequence carries the same policy_digest and correlation_id
throughout. The forwarder flow is context → request → audit (the credential
and decision envelopes were retired with credential mediation; the Router's
decision is the internal `PolicyDecision`, not a wire envelope).
"""

from __future__ import annotations

import uuid
from pathlib import Path

import pytest

from odis_harness import contracts
from odis_harness.contracts import (
    AuditEvent,
    AuthzRequest,
    EnvelopeValidator,
    RuntimeContext,
    UnknownEnvelopeError,
    is_valid_event_type,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_DIGEST = "a" * 64


@pytest.fixture(scope="module")
def envelope_validator() -> EnvelopeValidator:
    return EnvelopeValidator(_REPO_ROOT / "schemas")


# -- Public API surface ------------------------------------------------------


def test_public_api_covers_expected_surface() -> None:
    """The umbrella surface every other capability imports — exact set, and
    every listed name resolves to a real symbol."""
    expected = {
        "APF_EVENT_TYPES",
        "ODIS_EXTENSION_TYPES",
        "PHASE",
        "SCHEMA_VERSION",
        "STUB_BUNDLE_ID",
        "STUB_BUNDLE_VERSION",
        "STUB_TRUST_ROOT_ID",
        "AuditEvent",
        "AuthzRequest",
        "RuntimeContext",
        "EnvelopeValidationError",
        "EnvelopeValidator",
        "UnknownEnvelopeError",
        "is_valid_event_type",
    }
    assert set(contracts.__all__) == expected
    for name in contracts.__all__:
        assert hasattr(contracts, name), f"__all__ names {name} which is not exported"


# -- Tier 3 cross-cutting scenario ------------------------------------------


def test_tier3_full_chain_at_contracts_layer(
    envelope_validator: EnvelopeValidator,
) -> None:
    """End-to-end at the contracts layer: every envelope built via dataclass,
    validated via the shared validator, with consistent policy_digest +
    correlation_id throughout."""
    correlation_id = str(uuid.uuid4())

    ctx = RuntimeContext(
        correlation_id=correlation_id,
        sponsor={"id": "fixture-sponsor", "type": "entra_oidc"},
        agent={"id": "fixture-agent", "type": "fixture_workload_identity"},
        task_intent="Add an 'odis-demo' label to APF-123",
        target_resource={"resource_family": "jira", "instance_id": "APF-123"},
        issued_at="2026-05-28T00:00:00Z",
        policy_digest=_DIGEST,
    )
    RuntimeContext.from_dict(ctx.to_dict(), envelope_validator)

    req = AuthzRequest(
        correlation_id=correlation_id,
        subject={"sponsor": ctx.sponsor, "agent": ctx.agent},
        target_resource=ctx.target_resource,
        verb="update_issue",
        request_body={"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        task_intent=ctx.task_intent,
        issued_at=ctx.issued_at,
        policy_digest=_DIGEST,
    )
    AuthzRequest.from_dict(req.to_dict(), envelope_validator)

    # Correlated audit sequence (the event types the Router emits).
    events: list[AuditEvent] = []
    for event_type in ("odis.mcp.forward", "odis.mcp.forward_refused"):
        event = AuditEvent(
            correlation_id=correlation_id,
            event_id=str(uuid.uuid4()),
            timestamp="2026-05-28T00:00:00.500Z",
            event_type=event_type,
            apf_semantic_enforcement=True,
            policy_digest=_DIGEST,
            resource_family="jira",
        )
        AuditEvent.from_dict(event.to_dict(), envelope_validator)
        events.append(event)

    for envelope in (ctx, req, *events):
        assert envelope.correlation_id == correlation_id
        assert envelope.policy_digest == _DIGEST
    for event in events:
        assert is_valid_event_type(event.event_type)


# -- Negative ----------------------------------------------------------------


def test_unknown_envelope_name_raises_unknown_envelope_error(
    envelope_validator: EnvelopeValidator,
) -> None:
    with pytest.raises(UnknownEnvelopeError):
        envelope_validator.validate("not.an.envelope.v1", {})
