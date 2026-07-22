"""`odis.bundle.v1` JSON Schema validates fixtures."""

from __future__ import annotations

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
