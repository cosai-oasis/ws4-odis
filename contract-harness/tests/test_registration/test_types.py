"""§6.1 record invariants, projection, and round-trip."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta

import pytest

from odis_harness.registration.digest import canonical_record_bytes, record_digest
from odis_harness.registration.fixtures import _FIXTURE_NOW, fixture_registration_record
from odis_harness.registration.types import (
    RECORD_SCHEMA_VERSION,
    AgentRegistrationRecord,
    IssuerAuthority,
)

_NAIVE = datetime(2026, 6, 1, 12, 0, 0)  # noqa: DTZ001 - the point of the test


@pytest.mark.parametrize("field", ["valid_until", "created_at", "updated_at"])
def test_naive_timestamps_are_rejected(field: str) -> None:
    """Rejected at construction so an aware/naive comparison `TypeError` can
    never surface inside `resolve()`, where it would be an untyped escape from
    a fail-closed path."""
    with pytest.raises(ValueError, match="timezone-aware"):
        replace(fixture_registration_record(), **{field: _NAIVE})


def test_unknown_lifecycle_state_is_rejected() -> None:
    """The RFC's 'or equivalent' is answered by a closed set. An open enum
    would make `is_usable()` guess."""
    with pytest.raises(ValueError, match="lifecycle_state"):
        replace(fixture_registration_record(), lifecycle_state="quiescent")  # type: ignore[arg-type]


def test_foreign_schema_version_is_rejected() -> None:
    with pytest.raises(ValueError, match="schema_version"):
        replace(fixture_registration_record(), schema_version="odis.registration.record.v2")


@pytest.mark.parametrize("bad_version", [0, -1])
def test_record_version_below_one_is_rejected(bad_version: int) -> None:
    """The floor is what makes `seen_versions.get(key, 0)` a safe default in
    the resolver's rollback check."""
    with pytest.raises(ValueError, match="record_version"):
        replace(fixture_registration_record(), record_version=bad_version)


def test_record_version_above_the_safe_integer_range_is_rejected() -> None:
    """The ceiling is the digest's, not the resolver's.

    `record_version` is serialised into the canonical document as a bare
    number, and it is the one number in the record that does not pass through
    `canonical.frozen_json` — so the rule that module enforces on entitlement
    values has to be repeated here or the field is a hole in it. Without this
    guard a record at 2**60 constructs and digests cleanly, producing bytes no
    ECMAScript-derived verifier can reproduce, which is the exact failure the
    canonical form's number rule exists to prevent.
    """
    with pytest.raises(ValueError, match="2\\*\\*53 - 1"):
        replace(fixture_registration_record(), record_version=2**53)


def test_record_version_at_the_safe_integer_boundary_is_accepted() -> None:
    """The other side of the edge, so the test above pins a boundary."""
    record = replace(fixture_registration_record(), record_version=2**53 - 1)
    assert b'"record_version":9007199254740991' in canonical_record_bytes(record)


def test_updated_at_may_not_precede_created_at() -> None:
    record = fixture_registration_record()
    with pytest.raises(ValueError, match="precedes"):
        replace(record, updated_at=record.created_at - timedelta(seconds=1))


def test_updated_at_equal_to_created_at_is_accepted() -> None:
    """A record that has never been updated. The invariant is an ordering, not
    a strict inequality."""
    record = fixture_registration_record()
    assert replace(record, updated_at=record.created_at).updated_at == record.created_at


@pytest.mark.parametrize(
    "field",
    ["approved_runtime_issuers", "approved_software_refs", "permitted_delegation_modes"],
)
def test_a_mutable_sequence_is_rejected(field: str) -> None:
    """`frozen=True` protects rebinding, not the interior. A caller who passed
    a list could keep the reference and mutate the record's content out from
    under a digest already embedded in a §6.2 reference."""
    with pytest.raises(ValueError, match="must be a tuple"):
        replace(fixture_registration_record(), **{field: ["a", "b"]})


def test_to_ref_carries_the_four_fields_that_name_this_record_version() -> None:
    """Asserted field by field rather than through a `matches()` helper.

    `RegistrationRecordRef` is deliberately behaviourless — see its docstring —
    so the only thing to check is that `to_ref` fills it from the record. The
    digest is recomputed here rather than copied from the ref, which is the same
    thing a §6.2 verifier does with a record it resolved independently.
    """
    record = fixture_registration_record()
    ref = record.to_ref()
    assert (ref.record_issuer, ref.record_id, ref.record_version) == (
        record.record_issuer,
        record.record_id,
        record.record_version,
    )
    assert ref.record_digest == record_digest(record)


def test_a_ref_commits_to_content_not_only_to_identity() -> None:
    """A record differing only in a field neither `record_id` nor
    `record_version` names still produces a different ref, because the fourth
    field is a digest of the whole record. This is what makes the resolver's
    digest check able to catch tampering that leaves the version alone."""
    record = fixture_registration_record()
    other = replace(record, owner_ref="team:other")
    assert record.to_ref() != other.to_ref()
    assert record.to_ref().record_id == other.to_ref().record_id


def test_a_later_version_produces_a_different_ref() -> None:
    record = fixture_registration_record()
    later = replace(record, record_version=2)
    assert record.to_ref().record_version != later.to_ref().record_version


def test_round_trip_preserves_the_record() -> None:
    record = fixture_registration_record()
    assert AgentRegistrationRecord.from_document(record.to_document()) == record


def test_round_trip_preserves_provider_entitlements() -> None:
    record = replace(
        fixture_registration_record(),
        provider_entitlements={"jira-prod": {"scopes": ["issue:update"]}},
    )
    rebuilt = AgentRegistrationRecord.from_document(record.to_document())
    assert rebuilt == record
    # Frozen at every depth, so the JSON array arrives back as a tuple. The
    # round-trip is over *content*, not over the container types the caller
    # happened to use — which is the point: two records built from the same
    # content compare equal however they were spelled.
    assert rebuilt.provider_entitlements == {"jira-prod": {"scopes": ("issue:update",)}}


def test_provider_entitlements_is_frozen_at_every_depth() -> None:
    """The aliasing hole the sequence fields are `tuple` to avoid, at depth.

    Without this a caller could keep a reference to the dict it passed, mutate
    it, and change the record's content — and therefore its digest — after that
    digest was embedded in a §6.2 reference.
    """
    supplied: dict[str, object] = {"jira-prod": {"scopes": ["issue:update"]}}
    record = replace(fixture_registration_record(), provider_entitlements=supplied)
    digest_before = record_digest(record)

    supplied["jira-prod"] = {"scopes": ["issue:delete"]}
    supplied["confluence-prod"] = {"scopes": ["page:write"]}

    assert record_digest(record) == digest_before
    assert "confluence-prod" not in record.provider_entitlements  # type: ignore[operator]

    with pytest.raises(TypeError):
        record.provider_entitlements["jira-prod"] = {}  # type: ignore[index]
    nested = record.provider_entitlements["jira-prod"]  # type: ignore[index]
    with pytest.raises(TypeError):
        nested["scopes"] = ()


@pytest.mark.parametrize(
    ("entitlements", "expected"),
    [
        pytest.param({"k": object()}, "no JSON representation", id="unserialisable-value"),
        pytest.param({1: "a", "b": 2}, "non-string key", id="mixed-key-types"),
        # nan/inf were once refused for having no JSON *representation*. They
        # are now refused one branch earlier, for being floats at all, so the
        # expected message moves with them rather than the cases being deleted:
        # the property under test is still "this record will not construct".
        pytest.param({"k": float("nan")}, "admits no floats", id="nan"),
        pytest.param({"k": float("inf")}, "admits no floats", id="infinity"),
        pytest.param({"k": {"nested": object()}}, "no JSON representation", id="nested-value"),
        pytest.param({"k": [1, object()]}, "no JSON representation", id="inside-an-array"),
        pytest.param(["not", "a", "mapping"], "must be a mapping", id="array-at-the-root"),
    ],
)
def test_uncanonicalisable_provider_entitlements_is_rejected(
    entitlements: object, expected: str
) -> None:
    """A record that constructs must be a record that digests.

    `provider_entitlements` is the only field whose contents the record cannot
    type, so it is the only place `json.dumps` could raise later — as a
    `TypeError`, which is neither `ValueError` nor `KeyError` and so escapes the
    fail-closed contract the loader and the resolver both document. `ValueError`
    here is what keeps that contract true.
    """
    with pytest.raises(ValueError, match=expected):
        replace(fixture_registration_record(), provider_entitlements=entitlements)  # type: ignore[arg-type]


# --------------------------------------------------------------------------
# The number rule — integers only, bounded to the double's exact range
#
# Not in the JSON Schema, and it cannot be: JSON has one number type, so `1`
# and `1.0` are the same *value* and `"type": "integer"` accepts both. The
# divergence is in spelling, which no schema keyword expresses. The rule lives
# in `canonical.frozen_json` and in `digest.py`'s rule table, nowhere else.
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "number",
    [
        pytest.param(1.0, id="integral-valued"),  # Python `1.0`, RFC 8785 `1`
        pytest.param(0.1, id="ordinary-decimal"),  # both spell `0.1` — refused anyway
        pytest.param(1e16, id="exponent-boundary"),  # `1e+16` vs `10000000000000000`
        pytest.param(1e-7, id="small-exponent"),  # `1e-07` vs `1e-7`
    ],
)
def test_a_float_entitlement_value_is_refused(number: float) -> None:
    """Every float, not only the ones whose spelling diverges.

    `0.1` is in the list on purpose: Python and ECMAScript agree on it, so a
    rule that rejected only the divergent spellings would accept it — and would
    then fail silently on `1.0` two lines later in the same document. A digest
    rule that is almost right is worse than one that is strict, because the
    caller learns nothing at construction and the disagreement surfaces as a
    mismatched `record_digest` in someone else's language.
    """
    with pytest.raises(ValueError, match="admits no floats"):
        replace(fixture_registration_record(), provider_entitlements={"quota": number})


def test_a_float_is_refused_even_where_it_is_nested() -> None:
    """The rule is recursive and names its path, like every other one here."""
    with pytest.raises(ValueError, match=r"provider_entitlements\.jira-prod\.rate\[0\]"):
        replace(
            fixture_registration_record(),
            provider_entitlements={"jira-prod": {"rate": [1.5]}},
        )


@pytest.mark.parametrize(
    "number",
    [pytest.param(2**53, id="just-above"), pytest.param(-(2**53), id="just-below")],
)
def test_an_integer_outside_the_safe_range_is_refused(number: int) -> None:
    """±(2**53 - 1) is the exact-integer range of an IEEE 754 double, which is
    the number model RFC 8785 pins JSON to. Above it two distinct Python ints
    map to one double, so the canonical bytes would stop distinguishing two
    records that genuinely differ."""
    with pytest.raises(ValueError, match=r"outside ±\(2\*\*53 - 1\)"):
        replace(fixture_registration_record(), provider_entitlements={"quota": number})


@pytest.mark.parametrize(
    "number",
    [
        pytest.param(0, id="zero"),
        pytest.param(100, id="ordinary"),
        pytest.param(2**53 - 1, id="the-boundary-itself"),
        pytest.param(-(2**53) + 1, id="the-negative-boundary"),
    ],
)
def test_an_integer_inside_the_safe_range_is_accepted(number: int) -> None:
    """The other side of the same edge, so the test above is pinning a boundary
    rather than an off-by-a-lot. The `100` case is what the second golden
    digest already covers, asserted here as a boundary rather than as bytes.

    The bytes assertion is the half that matters: surviving construction only
    proves the guard let the value past, while the canonical form is what the
    bound is actually about. An accepted boundary value that then serialised
    through a float would pass the first assertion and fail the second.
    """
    record = replace(fixture_registration_record(), provider_entitlements={"quota": number})
    assert record.provider_entitlements == {"quota": number}  # type: ignore[operator]
    assert f'"quota":{number}'.encode() in canonical_record_bytes(record)


def test_a_boolean_entitlement_value_survives_the_number_rule() -> None:
    """`True` is an `int` in Python.

    Testing `int` before `bool` in `frozen_json` would turn every boolean in
    `provider_entitlements` into a refusal — and the golden digests contain no
    booleans, so nothing else in this suite would catch it. `json.dumps` spells
    a boolean `true` in every language, so booleans were never part of the
    number problem.
    """
    record = replace(
        fixture_registration_record(), provider_entitlements={"enabled": True, "dry_run": False}
    )
    assert record.provider_entitlements == {"enabled": True, "dry_run": False}  # type: ignore[operator]
    # Asserted as the two key/value pairs rather than as a `count(b"true")` over
    # the whole document: a document-wide count is coupled to every other field's
    # value — `trust.example` is one character from breaking it — and would fail
    # with `assert 2 == 1`, which names nothing.
    raw = canonical_record_bytes(record)
    assert b'"enabled":true' in raw
    assert b'"dry_run":false' in raw


def test_a_rejected_entitlements_value_names_its_path() -> None:
    """A refusal three levels down has to say where, or the caller is left
    bisecting their own document."""
    with pytest.raises(ValueError, match=r"provider_entitlements\.jira-prod\.scopes\[1\]"):
        replace(
            fixture_registration_record(),
            provider_entitlements={"jira-prod": {"scopes": ["ok", object()]}},
        )


def test_absent_provider_entitlements_is_omitted_not_null() -> None:
    """`None` must not become `"provider_entitlements": null`, or a record
    without entitlements would digest differently from one that never had the
    key — and the two are the same record."""
    document = fixture_registration_record().to_document()
    assert "provider_entitlements" not in document


def test_to_document_normalises_timestamps_to_utc() -> None:
    """The canonical form is UTC with a `Z` suffix and microsecond precision,
    so the same instant expressed in any offset projects identically."""
    record = fixture_registration_record()
    document = record.to_document()
    assert document["created_at"] == "2026-01-01T00:00:00.000000Z"
    assert document["valid_until"] == "2027-01-01T00:00:00.000000Z"


def test_from_document_rejects_a_naive_timestamp() -> None:
    document = fixture_registration_record().to_document()
    document["valid_until"] = "2027-01-01T00:00:00.000000"
    with pytest.raises(ValueError, match="no timezone offset"):
        AgentRegistrationRecord.from_document(document)


def test_from_document_rejects_a_non_string_timestamp() -> None:
    """A bare `TypeError` out of `fromisoformat` would escape the loader's
    typed contract; this has to be a `ValueError` it already catches."""
    document = fixture_registration_record().to_document()
    document["valid_until"] = 1234567890
    with pytest.raises(ValueError, match="must be a string timestamp"):
        AgentRegistrationRecord.from_document(document)


def test_from_document_rejects_non_object_provider_entitlements() -> None:
    """`from_document` passes the field through untouched; the refusal comes
    from `__post_init__`, which every construction reaches. Asserted through the
    load path anyway, because that is the path a hostile document takes."""
    document = fixture_registration_record().to_document()
    document["provider_entitlements"] = ["not", "an", "object"]
    with pytest.raises(ValueError, match="provider_entitlements must be a mapping"):
        AgentRegistrationRecord.from_document(document)


def test_from_document_raises_key_error_on_a_missing_must_field() -> None:
    """The loader catches `KeyError` alongside `ValueError` precisely because
    this is the shape a missing MUST field takes."""
    document = fixture_registration_record().to_document()
    del document["owner_ref"]
    with pytest.raises(KeyError):
        AgentRegistrationRecord.from_document(document)


def test_is_usable_only_for_active() -> None:
    """`pending` has not been admitted, `suspended` was withdrawn, `revoked` is
    terminal. Only `active` may back a live request."""
    for state in ("suspended", "revoked", "pending"):
        assert not replace(fixture_registration_record(), lifecycle_state=state).is_usable()  # type: ignore[arg-type]
    assert fixture_registration_record().is_usable()


def test_the_fixture_uses_the_pinned_schema_version() -> None:
    assert fixture_registration_record().schema_version == RECORD_SCHEMA_VERSION


def test_issuer_authority_is_a_closed_set() -> None:
    """Deployment configuration, not a record field: a record naming its own
    authority would be self-certifying."""
    authority = IssuerAuthority(
        record_issuer="registry.example", trust_domains=frozenset({"trust.example"})
    )
    assert authority.may_issue_for("trust.example")
    assert not authority.may_issue_for("other.example")


def test_two_independent_constructions_compare_equal() -> None:
    """Equality is by value, which is what lets a verifier compare a record it
    resolved against one it was handed."""
    assert fixture_registration_record() == fixture_registration_record()


def test_the_fixture_validity_window_contains_the_fixture_clock() -> None:
    """Guards the fixture, not the type: a fixture whose window did not contain
    `_FIXTURE_NOW` would make every `registration_fixture_stack` happy-path test
    fail for the wrong reason.

    Asserted against the pinned clock rather than `datetime.now()` on purpose —
    a wall-clock assertion here would start failing on 2027-01-01 for a reason
    that has nothing to do with what this file is about.
    """
    record = fixture_registration_record()
    assert record.created_at < record.valid_until
    assert record.created_at <= _FIXTURE_NOW < record.valid_until
