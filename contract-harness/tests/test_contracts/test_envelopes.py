"""Typed dataclasses for every envelope."""

from __future__ import annotations

import dataclasses
from pathlib import Path

import pytest

from odis_harness.contracts.envelopes import (
    AuditEvent,
    AuthzRequest,
    RuntimeContext,
)
from odis_harness.contracts.validator import EnvelopeValidationError, EnvelopeValidator

_REPO_ROOT = Path(__file__).resolve().parents[2]


# -- Round-trip --------------------------------------------------------------


def _runtime_context() -> RuntimeContext:
    return RuntimeContext(
        correlation_id="11111111-2222-4333-8444-555555555555",
        originating_principal={"id": "fixture-principal", "type": "entra_oidc"},
        agent={"id": "fixture-agent", "type": "fixture_workload_identity"},
        task_intent="Add label",
        target_resource={"resource_family": "jira"},
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


def _authz_request() -> AuthzRequest:
    return AuthzRequest(
        correlation_id="11111111-2222-4333-8444-555555555555",
        subject={
            "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
            "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
            "delegation_chain": [],
        },
        target_resource={"resource_family": "jira"},
        verb="update_issue",
        request_body={"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        task_intent="Add label",
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


def _audit_event() -> AuditEvent:
    return AuditEvent(
        correlation_id="11111111-2222-4333-8444-555555555555",
        event_id="44444444-5555-4666-8777-888888888888",
        timestamp="2026-05-28T00:00:00.500Z",
        event_type="odis.mcp.forward",
        apf_semantic_enforcement=True,
        policy_digest="a" * 64,
        resource_family="jira",
    )


_ROUND_TRIP_FACTORIES = [_runtime_context, _authz_request, _audit_event]


@pytest.mark.parametrize("factory", _ROUND_TRIP_FACTORIES)
def test_to_dict_from_dict_round_trip(
    envelope_validator: EnvelopeValidator,
    factory: object,
) -> None:
    instance = factory()  # type: ignore[operator]
    payload = instance.to_dict()
    rebuilt = type(instance).from_dict(payload, envelope_validator)
    assert rebuilt == instance


@pytest.mark.parametrize("factory", _ROUND_TRIP_FACTORIES)
def test_from_dict_validates(
    envelope_validator: EnvelopeValidator,
    factory: object,
) -> None:
    instance = factory()  # type: ignore[operator]
    bad = dict(instance.to_dict())
    bad["correlation_id"] = "not-a-uuid"
    with pytest.raises(EnvelopeValidationError):
        type(instance).from_dict(bad, envelope_validator)


def test_envelope_name_maps_to_a_schema_file_on_disk() -> None:
    """ENVELOPE_NAME is the schema-file stem `from_dict()` validates against
    (EnvelopeValidator keys validators by file stem). Renaming or deleting a
    schema file without updating ENVELOPE_NAME would break every `from_dict()`
    at runtime while a literal-equality assertion stayed green — so pin the
    name to an existing file. (The round-trip tests above catch a *wrong* name; this
    catches a *missing* schema.)"""
    schemas_dir = _REPO_ROOT / "schemas"
    for envelope in (RuntimeContext, AuthzRequest, AuditEvent):
        schema_path = schemas_dir / f"{envelope.ENVELOPE_NAME}.json"
        assert schema_path.is_file(), (
            f"{envelope.__name__}.ENVELOPE_NAME={envelope.ENVELOPE_NAME!r} "
            f"resolves to no schema file at {schema_path}"
        )


def test_authz_request_carries_no_runtime_risk_signal_field() -> None:
    """Schema and dataclass state the same absence.

    No field stands in for ODIS §6.4's `runtime_risk_signals`, which the checkpoint
    MUST validate for issuer trust, integrity, replay resistance, freshness and
    subject correlation before use. A field nothing populates and nothing verifies
    makes the envelope read as though a signal had been consumed.
    """
    names = {f.name for f in dataclasses.fields(AuthzRequest)}
    assert not {n for n in names if "verdict" in n or "risk" in n}
