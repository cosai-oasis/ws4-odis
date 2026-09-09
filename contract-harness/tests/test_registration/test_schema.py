"""`odis.registration.record.v1` JSON Schema validates the §6.1 record."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPO_ROOT / "schemas" / "odis.registration.record.v1.json"

#: The 16 MUST names from the RFC §6.1 table. Transcribed here rather than
#: imported from the conformance suite: this test guards the schema against the
#: RFC, and reusing the suite's frozenset would make one transcription check the
#: other rather than either checking the RFC.
_MUST_FIELDS = (
    "record_id",
    "record_issuer",
    "schema_version",
    "record_version",
    "agent_id",
    "valid_until",
    "lifecycle_state",
    "sponsor_ref",
    "owner_ref",
    "approved_runtime_issuers",
    "approved_software_refs",
    "trust_domain",
    "policy_profile_ref",
    "permitted_delegation_modes",
    "created_at",
    "updated_at",
)


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def canonical_record() -> dict[str, Any]:
    """All 16 MUST fields plus the one SHOULD field, populated."""
    return {
        "record_id": "reg-0001",
        "record_issuer": "registry.example",
        "schema_version": "odis.registration.record.v1",
        "record_version": 1,
        "agent_id": "agent-alpha",
        "valid_until": "2027-01-01T00:00:00.000000Z",
        "lifecycle_state": "active",
        "sponsor_ref": "human:sponsor-1",
        "owner_ref": "team:platform",
        "approved_runtime_issuers": ["spiffe://trust.example/issuer"],
        "approved_software_refs": ["sha256:abc"],
        "trust_domain": "trust.example",
        "policy_profile_ref": "profile:baseline",
        "permitted_delegation_modes": ["bridge"],
        "provider_entitlements": {"jira-prod": {"scopes": ["issue:update"]}},
        "created_at": "2026-01-01T00:00:00.000000Z",
        "updated_at": "2026-01-01T00:00:00.000000Z",
    }


def test_schema_is_valid_draft_2020_12(schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)


def test_schema_id_matches_filename(schema: dict[str, Any]) -> None:
    """`EnvelopeValidator` registers schemas by file stem, so a `$id` that
    disagrees with the filename would name the envelope twice, differently."""
    assert schema["$id"].endswith(f"/{_SCHEMA_PATH.name}")


def test_schema_accepts_the_canonical_record(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER).validate(
        canonical_record
    )


def test_schema_accepts_a_record_without_provider_entitlements(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    """`provider_entitlements` is the one SHOULD field; omitting it is valid."""
    without = {k: v for k, v in canonical_record.items() if k != "provider_entitlements"}
    Draft202012Validator(schema).validate(without)


@pytest.mark.parametrize("missing", _MUST_FIELDS)
def test_schema_rejects_a_record_missing_a_must_field(
    schema: dict[str, Any], canonical_record: dict[str, Any], missing: str
) -> None:
    bad = {k: v for k, v in canonical_record.items() if k != missing}
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_an_undeclared_field(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    """`additionalProperties: false`. A surprise field is a different record,
    and it would land inside `record_digest` unnoticed."""
    bad = dict(canonical_record, surprise="value")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_an_unknown_lifecycle_state(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    bad = dict(canonical_record, lifecycle_state="quiescent")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_record_version_below_one(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    bad = dict(canonical_record, record_version=0)
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


@pytest.mark.parametrize("field", ["valid_until", "created_at", "updated_at"])
@pytest.mark.parametrize(
    "bad_timestamp",
    [
        "tomorrow",
        "2027-01-01T00:00:00Z",  # no microseconds
        "2027-01-01T00:00:00.000000+08:00",  # an offset, not normalised to UTC
        "2027-01-01 00:00:00.000000Z",  # space instead of T
    ],
)
def test_schema_rejects_a_non_canonical_timestamp(
    schema: dict[str, Any], canonical_record: dict[str, Any], field: str, bad_timestamp: str
) -> None:
    """Enforced by `pattern`, not `format`.

    `Draft202012Validator.FORMAT_CHECKER` silently skips `date-time` unless an
    optional RFC 3339 validator is installed, and it is not — so a `format`-only
    schema would accept `"tomorrow"`. These fields are inside the signed
    canonical bytes, which is too load-bearing to leave to an optional
    dependency.
    """
    bad = dict(canonical_record, **{field: bad_timestamp})
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_a_foreign_schema_version(
    schema: dict[str, Any], canonical_record: dict[str, Any]
) -> None:
    """`schema_version` is `const`, so a v2 document cannot be read as a v1."""
    bad = dict(canonical_record, schema_version="odis.registration.record.v2")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)
