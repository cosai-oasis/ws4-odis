"""Envelope JSON Schemas — structural validity, canonical examples, field rules.

One parametrized suite over the three envelope schemas. The generic checks
(valid Draft 2020-12, `$id` matches filename, canonical example validates, every
unknown top-level fields rejected, shared-metadata field rules) run across all
three envelopes; the genuinely envelope-specific behaviour (audit `event_type`
taxonomy, authz `subject` shape) follows as targeted tests.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from odis_harness.contracts import (
    PHASE,
    SCHEMA_VERSION,
    STUB_BUNDLE_ID,
    STUB_BUNDLE_VERSION,
    STUB_TRUST_ROOT_ID,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_SCHEMAS_DIR = Path(__file__).resolve().parents[2] / "schemas"


def _schema(name: str) -> dict[str, object]:
    return json.loads((_SCHEMAS_DIR / f"{name}.json").read_text(encoding="utf-8"))


def _validator(schema: Mapping[str, object]) -> Draft202012Validator:
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


_COMMON: dict[str, object] = {
    "schema_version": SCHEMA_VERSION,
    "correlation_id": "11111111-2222-4333-8444-555555555555",
    "bundle_id": STUB_BUNDLE_ID,
    "bundle_version": STUB_BUNDLE_VERSION,
    "trust_root_id": STUB_TRUST_ROOT_ID,
    "policy_digest": "a" * 64,
    "phase": PHASE,
}

_EXAMPLES: dict[str, dict[str, object]] = {
    "odis.runtime.context.v1": _COMMON
    | {
        "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
        "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        "task_intent": "Add an 'odis-demo' label to APF-123",
        "target_resource": {"resource_family": "jira", "instance_id": "APF-123"},
        "issued_at": "2026-05-28T00:00:00Z",
    },
    "odis.authz.request.v1": _COMMON
    | {
        "subject": {
            "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
            "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        },
        "target_resource": {"resource_family": "jira", "instance_id": "APF-123"},
        "verb": "update_issue",
        "request_body": {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        "task_intent": "Add an 'odis-demo' label to APF-123",
        "issued_at": "2026-05-28T00:00:00Z",
    },
    "odis.audit.event.v1": _COMMON
    | {
        "event_id": "44444444-5555-4666-8777-888888888888",
        "timestamp": "2026-05-28T00:00:00.500Z",
        "event_type": "authorize",
        "apf_semantic_enforcement": True,
    },
}
_NAMES = sorted(_EXAMPLES)


def _example(name: str) -> dict[str, object]:
    return dict(_EXAMPLES[name])


# -- Generic structural checks (every envelope) -----------------------------


@pytest.mark.parametrize("name", _NAMES)
def test_schema_is_valid_draft_2020_12(name: str) -> None:
    Draft202012Validator.check_schema(_schema(name))


@pytest.mark.parametrize("name", _NAMES)
def test_schema_id_matches_filename(name: str) -> None:
    assert _schema(name)["$id"] == f"https://apf.local/schemas/{name}.json"


@pytest.mark.parametrize("name", _NAMES)
def test_canonical_example_validates(name: str) -> None:
    _validator(_schema(name)).validate(_example(name))


@pytest.mark.parametrize("name", _NAMES)
def test_unknown_top_level_field_rejected(name: str) -> None:
    """Strict envelopes (additionalProperties: false) — extras suggest drift."""
    with pytest.raises(ValidationError):
        _validator(_schema(name)).validate(dict(_example(name), surprise_field="x"))


# -- Shared-metadata field rules (every envelope) ---------------------------


@pytest.mark.parametrize(
    ("field", "bad_value"),
    [
        ("schema_version", "apf.v1"),
        ("phase", "core"),
        ("correlation_id", "not-a-uuid"),
    ],
)
def test_shared_metadata_field_rules(field: str, bad_value: str) -> None:
    name = "odis.runtime.context.v1"
    with pytest.raises(ValidationError):
        _validator(_schema(name)).validate(dict(_example(name), **{field: bad_value}))


# -- audit.event: event_type taxonomy --------------------------------------

_AUDIT = "odis.audit.event.v1"


@pytest.mark.parametrize("event_type", ["authorize", "odis.mcp.forward"])
def test_audit_event_accepts_core_and_extension_event_types(event_type: str) -> None:
    _validator(_schema(_AUDIT)).validate(dict(_example(_AUDIT), event_type=event_type))


@pytest.mark.parametrize("event_type", ["my_made_up_event", "policy_load_failed"])
def test_audit_event_rejects_unknown_event_type(event_type: str) -> None:
    """Neither the APF §6.5 enum nor the `odis.<ns>.<name>` pattern — schema rejects it."""
    with pytest.raises(ValidationError):
        _validator(_schema(_AUDIT)).validate(dict(_example(_AUDIT), event_type=event_type))


# -- authz.request: subject shape ------------------------------------------

_AUTHZ = "odis.authz.request.v1"


def test_authz_request_subject_requires_sponsor_and_agent() -> None:
    bad = dict(_example(_AUTHZ), subject={"sponsor": {"id": "x", "type": "entra_oidc"}})
    with pytest.raises(ValidationError):
        _validator(_schema(_AUTHZ)).validate(bad)


def test_authz_request_subject_accepts_delegation_chain() -> None:
    extended = dict(_example(_AUTHZ))
    extended["subject"] = {
        "sponsor": {"id": "fixture-sponsor", "type": "entra_oidc"},
        "agent": {"id": "sub-agent", "type": "fixture_workload_identity"},
        "delegation_chain": [{"id": "parent-agent", "type": "fixture_workload_identity"}],
    }
    _validator(_schema(_AUTHZ)).validate(extended)
