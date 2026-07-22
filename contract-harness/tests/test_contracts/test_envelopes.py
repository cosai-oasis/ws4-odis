"""Typed dataclasses for every envelope."""

from __future__ import annotations

from pathlib import Path

import pytest

from odis_harness.contracts.envelopes import (
    AuditEvent,
    AuthzRequest,
    RuntimeContext,
)
from odis_harness.contracts.validator import EnvelopeValidationError, EnvelopeValidator

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def envelope_validator() -> EnvelopeValidator:
    return EnvelopeValidator(_REPO_ROOT / "schemas")


# -- Round-trip --------------------------------------------------------------


def _runtime_context() -> RuntimeContext:
    return RuntimeContext(
        correlation_id="11111111-2222-4333-8444-555555555555",
        sponsor={"id": "fixture-sponsor", "type": "entra_oidc"},
        agent={"id": "fixture-agent", "type": "fixture_workload_identity"},
        task_intent="Add label",
        target_resource={"resource_family": "jira", "instance_id": "APF-123"},
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


def _authz_request() -> AuthzRequest:
    return AuthzRequest(
        correlation_id="11111111-2222-4333-8444-555555555555",
        subject={
            "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
            "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        },
        target_resource={"resource_family": "jira", "instance_id": "APF-123"},
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
    name to a real file. (The round-trip tests above catch a *wrong* name; this
    catches a *missing* schema.)"""
    schemas_dir = _REPO_ROOT / "schemas"
    for envelope in (RuntimeContext, AuthzRequest, AuditEvent):
        schema_path = schemas_dir / f"{envelope.ENVELOPE_NAME}.json"
        assert schema_path.is_file(), (
            f"{envelope.__name__}.ENVELOPE_NAME={envelope.ENVELOPE_NAME!r} "
            f"resolves to no schema file at {schema_path}"
        )
