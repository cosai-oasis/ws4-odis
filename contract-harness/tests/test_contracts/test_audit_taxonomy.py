"""`audit_taxonomy` constants + EnvelopeValidator integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from odis_harness.contracts.audit_taxonomy import (
    APF_EVENT_TYPES,
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.contracts.validator import EnvelopeValidationError, EnvelopeValidator

_REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def envelope_validator() -> EnvelopeValidator:
    return EnvelopeValidator(_REPO_ROOT / "schemas")


def _audit_event(event_type: str) -> dict[str, object]:
    return {
        "schema_version": "odis.v1",
        "correlation_id": "11111111-2222-4333-8444-555555555555",
        "bundle_id": "odis-fixture-bundle",
        "bundle_version": "0.0.0-odis-harness",
        "trust_root_id": "odis-fixture-trust-root",
        "policy_digest": "a" * 64,
        "event_id": "44444444-5555-4666-8777-888888888888",
        "timestamp": "2026-05-28T00:00:00.500Z",
        "event_type": event_type,
        "phase": "odis-harness",
        "apf_semantic_enforcement": True,
    }


# -- Constants (independent transcription of the canonical taxonomy) ---------
# These cross-check the src constants against a separate literal copy: the two
# can drift (edit one, not the other), so this catches a typo/add/drop in the
# taxonomy that the membership-based `is_valid_event_type` tests cannot.


def test_apf_event_types_match_apf_section_6_5() -> None:
    """APF §6.5 enum verbatim."""
    assert (
        frozenset(
            {
                "policy_load",
                "policy_reject",
                "authorize",
                "deny",
                "require_review",
                "review_decision",
                "credential_issue",
                "resource_call",
                "result",
                "detector_verdict",
                "quarantine",
                "stop_session",
                "revocation",
                "break_glass",
            }
        )
        == APF_EVENT_TYPES
    )


def test_odis_extension_types() -> None:
    assert (
        frozenset(
            {
                "odis.substrate.egress_violation",
                "odis.security.spoofing_attempt",
                "odis.mcp.forward",
                "odis.mcp.forward_refused",
                "odis.mcp.discovery_failed",
            }
        )
        == ODIS_EXTENSION_TYPES
    )


# -- is_valid_event_type -----------------------------------------------------


@pytest.mark.parametrize(
    ("event_type", "expected"),
    [
        ("authorize", True),
        ("odis.mcp.forward", True),
        ("", False),
        ("my_made_up_event", False),
        ("policy_load_failed", False),
        ("credential_refused", False),
        ("odis.something.unknown", False),
    ],
)
def test_is_valid_event_type(event_type: str, expected) -> None:
    assert is_valid_event_type(event_type) is expected


# -- EnvelopeValidator integration -------------------------------------------


def test_validator_rejects_taxonomy_violation_even_when_pattern_matches(
    envelope_validator: EnvelopeValidator,
) -> None:
    """The JSON Schema pattern accepts any `odis.<ns>.<name>`; the runtime
    taxonomy check restricts to the registered extension set."""
    payload = _audit_event("odis.something.unknown")
    with pytest.raises(EnvelopeValidationError) as ei:
        envelope_validator.validate("odis.audit.event.v1", payload)
    assert "odis.something.unknown" in ei.value.message
    assert "event_type" in ei.value.message or "event_type" in ei.value.instance_path
