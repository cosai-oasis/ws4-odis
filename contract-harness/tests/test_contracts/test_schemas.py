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
from typing import TYPE_CHECKING, Any

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
        "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
        "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        "task_intent": "Add an 'odis-demo' label to APF-123",
        "target_resource": {"resource_family": "jira"},
        "issued_at": "2026-05-28T00:00:00Z",
    },
    "odis.authz.request.v1": _COMMON
    | {
        "subject": {
            "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
            "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
            "delegation_chain": [],
        },
        "target_resource": {"resource_family": "jira"},
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
    # A URN, not an https URL: nothing is published at a resolvable address and every
    # `$ref` is local, so a fetchable-looking id would only invite a consumer to try.
    # The `odis` NID is not IANA-registered; nothing dereferences these, so it is a local
    # label. Revisit if ODIS is ratified.
    assert _schema(name)["$id"] == f"urn:odis:contract-harness:schemas:{name}"


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
_CONTEXT = "odis.runtime.context.v1"

#: The envelopes on the Router's decision path, where every declared field has a
#: supplier. `odis.audit.event.v1` is not one: see
#: `test_total_envelope_declares_no_optional_input`.
_TOTAL_ENVELOPES = [_AUTHZ, _CONTEXT]


@pytest.mark.parametrize(
    "missing", ["originating_principal", "agent", "delegation_chain"]
)
def test_authz_request_subject_requires_every_member(missing: str) -> None:
    """The Router supplies all three, so dropping any one fails closed rather than
    reaching policy with a subject that states less than the Router knows."""
    subject = {k: v for k, v in _example(_AUTHZ)["subject"].items() if k != missing}
    with pytest.raises(ValidationError):
        _validator(_schema(_AUTHZ)).validate(dict(_example(_AUTHZ), subject=subject))


def _subject_with_chain(chain: list[object]) -> dict[str, object]:
    return {
        "originating_principal": {"id": "fixture-principal", "type": "entra_oidc"},
        "agent": {"id": "fixture-agent", "type": "fixture_workload_identity"},
        "delegation_chain": chain,
    }


def test_authz_request_subject_accepts_a_root_delegation_chain() -> None:
    """`[]` asserts a root record — one principal-to-agent hop, no sub-delegation
    (ODIS §6.3: "empty for the root record"). The Router mints exactly that one hop, so
    the empty array is a value it can state truthfully, where absence states nothing."""
    _validator(_schema(_AUTHZ)).validate(dict(_example(_AUTHZ), subject=_subject_with_chain([])))


def test_authz_request_subject_refuses_a_claimed_delegation_hop() -> None:
    """A claimed hop is refused rather than accepted unverified.

    §6.3's chain validation requires a verifier to authenticate every issuer,
    digest-match every `parent_delegation_ref`, and check each record's integrity,
    freshness and revocation state, failing closed on any that is missing, stale or
    ambiguous. This harness has no revocation channel (ODIS-L3-04), so it can do none
    of that. `subject` reaches the policy engine verbatim via
    `mcp_forwarder.policy._request_to_opa_input`, so a permitted hop would be an
    unverifiable lineage claim a Rego rule could read and widen a decision on.
    `odis.bundle.v1` constrains the same field empty for the same reason.
    """
    chain = [{"id": "parent-agent", "type": "fixture_workload_identity"}]
    with pytest.raises(ValidationError):
        _validator(_schema(_AUTHZ)).validate(
            dict(_example(_AUTHZ), subject=_subject_with_chain(chain))
        )


def _optional_properties(schema: dict[str, Any]) -> set[str]:
    """Declared-but-not-required properties, at the top level and inside `$defs`.

    Nested scopes are reported as `$defs/<name>/<property>`, so a failure names the
    scope it came from rather than a bare property name that could be either.
    """
    scopes: list[tuple[str, dict[str, Any]]] = [("", schema)]
    scopes += [(f"$defs/{n}/", d) for n, d in schema.get("$defs", {}).items()]
    return {
        f"{prefix}{name}"
        for prefix, obj in scopes
        for name in set(obj.get("properties", {})) - set(obj.get("required", []))
    }


@pytest.mark.parametrize("name", _TOTAL_ENVELOPES)
def test_total_envelope_declares_no_optional_input(name: str) -> None:
    """Every property these two envelopes declare is required, at every level, so
    neither advertises an input the harness has no path to supply.

    They are the decision path: the Router mints a `RuntimeContext` and projects an
    `AuthzRequest` from it, and it supplies every field of both. `odis.audit.event.v1`
    is excluded deliberately — its optional fields all have suppliers
    (`mcp_forwarder/audit.py` sets `user_id` and `extra`; the sink derives
    `apf_semantic_enforcement`), and a refusal event legitimately carries no
    `result_class`, so optionality there is a real distinction rather than a dead field.

    This is the guard that keeps the `active_verdicts` class of defect
    unrepresentable: a declared input with nothing to populate it fails here.
    """
    assert _optional_properties(_schema(name)) == set()


@pytest.mark.parametrize("name", _TOTAL_ENVELOPES)
def test_resource_instance_handle_is_rejected_not_ignored(name: str) -> None:
    """`target_resource` names a resource family and nothing finer.

    At the gate the Router holds a family name and the raw tool arguments, not a
    resource instance: `mcp_forwarder/identity.py` and `mcp_forwarder/router.py` both
    build `{"resource_family": ...}`. A provider-shaped handle like a Jira issue key
    lives in `request_body`, which policy already reads. `additionalProperties: false`
    on `ResourceRef` means a payload carrying one is rejected rather than ignored.
    """
    resource = {"resource_family": "jira", "instance_id": "APF-123"}
    with pytest.raises(ValidationError):
        _validator(_schema(name)).validate(dict(_example(name), target_resource=resource))


def test_authz_request_rejects_a_detector_verdict_field() -> None:
    """`additionalProperties: false` — a signal the checkpoint cannot validate has no
    way through this envelope, so it can never widen a decision (ODIS-L1-12 confirms a
    signal only when authenticated, integrity-protected, replay-resistant, fresh,
    from a trusted authority, and correlated to the affected subject)."""
    with pytest.raises(ValidationError):
        _validator(_schema(_AUTHZ)).validate(dict(_example(_AUTHZ), active_verdicts=["v-1"]))
