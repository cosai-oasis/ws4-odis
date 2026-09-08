"""`odis.bundle.v1` JSON Schema validates fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

_REPO_ROOT = Path(__file__).resolve().parents[2]
_SCHEMA_PATH = _REPO_ROOT / "schemas" / "odis.bundle.v1.json"


@pytest.fixture(scope="module")
def schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def minimal_bundle() -> dict[str, Any]:
    """One family, the minimum required fields populated."""
    return {
        "bundle_id": "odis-fixture-bundle",
        "bundle_version": "0.1.0",
        "trust_root_id": "fixture-trust-root",
        "families": {
            "jira-prod": {
                "vendor_mcp": {
                    "endpoint_id": "jira-prod-mcp-v1",
                    "url": "https://jira-prod-mcp.internal:8443/",
                },
                "policy": "package odis_policy\n",
                "tools": {
                    "update_issue": {"action_limits": {"allowed_fields": ["labels"]}},
                },
                "default_mode": "strict",
            },
        },
    }


def test_schema_is_valid_draft_2020_12(schema: dict[str, Any]) -> None:
    Draft202012Validator.check_schema(schema)


def test_schema_accepts_minimal_valid_bundle(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    Draft202012Validator(schema).validate(minimal_bundle)


def test_schema_rejects_empty_families(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    bad = dict(minimal_bundle, families={})
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_invalid_endpoint_id_pattern(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    bad = json.loads(json.dumps(minimal_bundle))
    bad["families"]["jira-prod"]["vendor_mcp"]["endpoint_id"] = "Jira-Prod-MCP"  # uppercase
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_invalid_default_mode(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    bad = json.loads(json.dumps(minimal_bundle))
    bad["families"]["jira-prod"]["default_mode"] = "lax"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_invalid_url(schema: dict[str, Any], minimal_bundle: dict[str, Any]) -> None:
    """A non-URL value is rejected by the url `pattern: ^https?://` — the schema
    pins url via `pattern`, not a JSON-Schema `format`."""
    bad = json.loads(json.dumps(minimal_bundle))
    bad["families"]["jira-prod"]["vendor_mcp"]["url"] = "not a uri at all"
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_extra_top_level_field(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    bad = dict(minimal_bundle, extra_field="surprise")
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)



#: The `sha256:<64 hex>` form the schema's digest pattern requires. Named because a
#: 71-character literal does not fit inline at this indent.
_RECORD_DIGEST = "sha256:" + hashlib.sha256(b"jira-mapping-v1").hexdigest()
_PROFILE_DIGEST = "sha256:" + hashlib.sha256(b"attenuation-profile-v1").hexdigest()

def test_schema_accepts_the_delegation_record(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    """The plugin signs the delegation record, and `additionalProperties: false`
    means a field the schema does not know fails at load."""
    issued = dict(
        minimal_bundle,
        actor="spiffe://example.org/agent/jira",
        originating_principal="vault:entity:e-platform",
        contributing_records=[
            {"name": "jira", "version": 1, "digest": _RECORD_DIGEST},
        ],
        attenuation_profile_ref={
            "uri": "urn:odis:contract-harness:attenuation-profile:v1",
            "digest": _PROFILE_DIGEST,
        },
        delegation_chain=[],
        issued_at="2026-08-27T12:00:00Z",
        expires_at="2026-08-27T13:00:00Z",
    )
    issued["families"]["jira-prod"]["vendor_mcp"]["egress_mode"] = "bridge"
    Draft202012Validator(schema).validate(issued)


@pytest.mark.parametrize("mode", ["passthrough", "Bridge", ""])
def test_schema_rejects_other_egress_modes(
    schema: dict[str, Any], minimal_bundle: dict[str, Any], mode: str
) -> None:
    bad = json.loads(json.dumps(minimal_bundle))
    bad["families"]["jira-prod"]["vendor_mcp"]["egress_mode"] = mode
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_requires_contributing_record_fields(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    """A record reference without a digest cannot be checked against the record it names."""
    bad = dict(minimal_bundle, contributing_records=[{"name": "jira", "version": 1}])
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_an_empty_contributing_records_list(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    """A manifest naming no record names nothing; omit it instead."""
    bad = dict(minimal_bundle, contributing_records=[])
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_the_draft_authorization_ref_name(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    """`additionalProperties: false` is what keeps the draft's field name from being
    reintroduced over the manifest's shape."""
    bad = dict(
        minimal_bundle,
        originating_authorization_ref={"records": [{"name": "j", "version": 1, "digest": "x"}]},
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)


def test_schema_rejects_a_claimed_delegation_hop(
    schema: dict[str, Any], minimal_bundle: dict[str, Any]
) -> None:
    """The chain is constrained empty, so a bundle claiming a hop is refused at load
    rather than accepted with lineage nothing can verify."""
    # A schema-shaped hop, so the refusal is `maxItems: 0` and not a type mismatch —
    # a plain string would be rejected whether or not the chain were constrained.
    bad = dict(
        minimal_bundle,
        delegation_chain=[{"id": "spiffe://example.org/agent/coordinator", "type": "agent"}],
    )
    with pytest.raises(ValidationError):
        Draft202012Validator(schema).validate(bad)
