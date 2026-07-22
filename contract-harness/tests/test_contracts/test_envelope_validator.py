"""`EnvelopeValidator` loads schemas, validates payloads, fails closed."""

from __future__ import annotations

from pathlib import Path

import pytest

from odis_harness.contracts import (
    PHASE,
    SCHEMA_VERSION,
    STUB_BUNDLE_ID,
    STUB_BUNDLE_VERSION,
    STUB_TRUST_ROOT_ID,
)
from odis_harness.contracts.validator import (
    EnvelopeValidationError,
    EnvelopeValidator,
    UnknownEnvelopeError,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMAS_DIR = _REPO_ROOT / "schemas"


@pytest.fixture(scope="module")
def envelope_validator() -> EnvelopeValidator:
    return EnvelopeValidator(_SCHEMAS_DIR)


# -- Examples for each envelope ---------------------------------------------


def _common_metadata() -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "correlation_id": "11111111-2222-4333-8444-555555555555",
        "bundle_id": STUB_BUNDLE_ID,
        "bundle_version": STUB_BUNDLE_VERSION,
        "trust_root_id": STUB_TRUST_ROOT_ID,
        "policy_digest": "a" * 64,
        "phase": PHASE,
    }


def _runtime_context() -> dict[str, object]:
    return _common_metadata() | {
        "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
        "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        "task_intent": "Add a label",
        "target_resource": {"resource_family": "jira", "instance_id": "APF-123"},
        "issued_at": "2026-05-28T00:00:00Z",
    }


def _authz_request() -> dict[str, object]:
    return _common_metadata() | {
        "subject": {
            "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
            "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        },
        "target_resource": {"resource_family": "jira", "instance_id": "APF-123"},
        "verb": "jira.update_issue",
        "request_body": {"project": "APF", "fields": {"labels": ["odis-demo"]}},
        "task_intent": "Add a label",
        "issued_at": "2026-05-28T00:00:00Z",
    }


def _audit_event() -> dict[str, object]:
    return _common_metadata() | {
        "event_id": "44444444-5555-4666-8777-888888888888",
        "timestamp": "2026-05-28T00:00:00.500Z",
        "event_type": "authorize",
        "apf_semantic_enforcement": True,
    }


_EXAMPLES: dict[str, dict[str, object]] = {
    "odis.runtime.context.v1": _runtime_context(),
    "odis.authz.request.v1": _authz_request(),
    "odis.audit.event.v1": _audit_event(),
}


# -- Tests ------------------------------------------------------------------


@pytest.mark.parametrize("envelope_name", sorted(_EXAMPLES))
def test_canonical_example_validates(
    envelope_validator: EnvelopeValidator, envelope_name: str
) -> None:
    envelope_validator.validate(envelope_name, _EXAMPLES[envelope_name])


def test_unknown_envelope_name_raises(envelope_validator: EnvelopeValidator) -> None:
    with pytest.raises(UnknownEnvelopeError) as ei:
        envelope_validator.validate("does.not.exist.v1", {})
    assert "does.not.exist.v1" in str(ei.value)


@pytest.mark.parametrize("envelope_name", sorted(_EXAMPLES))
def test_missing_required_field_raises_typed_error(
    envelope_validator: EnvelopeValidator, envelope_name: str
) -> None:
    payload = dict(_EXAMPLES[envelope_name])
    del payload["correlation_id"]
    with pytest.raises(EnvelopeValidationError) as ei:
        envelope_validator.validate(envelope_name, payload)
    err = ei.value
    assert err.envelope_name == envelope_name
    assert "correlation_id" in err.message


def test_invalid_uuid_caught_via_format_checker(
    envelope_validator: EnvelopeValidator,
) -> None:
    payload = dict(_EXAMPLES["odis.runtime.context.v1"], correlation_id="not-a-uuid")
    with pytest.raises(EnvelopeValidationError):
        envelope_validator.validate("odis.runtime.context.v1", payload)


def test_validation_error_carries_instance_and_schema_paths(
    envelope_validator: EnvelopeValidator,
) -> None:
    payload = dict(_runtime_context(), policy_digest="not-a-valid-digest")
    with pytest.raises(EnvelopeValidationError) as ei:
        envelope_validator.validate("odis.runtime.context.v1", payload)
    err = ei.value
    # JSON-pointer-style instance path names the failing field.
    assert "policy_digest" in err.instance_path or "policy_digest" in err.message
    assert err.schema_path  # non-empty
