"""`record_digest` canonicalisation.

`record_digest` is a cross-language wire commitment, not an internal stamp:
§6.2's `registration_record_ref` and §6.3's `parent_delegation_ref` both carry
one, and a verifier is expected to recompute it from a record it resolved
independently. So these tests pin the canonicalisation rules themselves, not
just that a digest is produced.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from datetime import UTC, datetime, timedelta, timezone

import pytest

from odis_harness.registration.digest import canonical_record_bytes, record_digest
from odis_harness.registration.fixtures import fixture_registration_record
from odis_harness.registration.types import AgentRegistrationRecord

#: The drift alarm. Pinned from a first run, then hardcoded — precedent:
#: `tests/test_bundle/test_canonical_golden.py`.
#:
#: If this changes, the canonicalisation changed, and every `record_digest`
#: already embedded in a §6.2 or §6.3 reference is now wrong. That is a
#: schema-version bump, not a test update. Change the constant only after
#: deciding it is.
_GOLDEN_DIGEST = "7134e5c64dd3070cf5c10ef80d188ff3b1795d2587b59097a5cac09ef3f7c932"

#: The entitlements the second golden covers. Two providers built in
#: non-alphabetical order, nested arrays, an int, and a `null`, so the golden
#: below pins recursive key sorting, array-order preservation, and the JSON
#: scalar spellings all at once.
_GOLDEN_ENTITLEMENTS: dict[str, object] = {
    "jira-prod": {"scopes": ["issue:update", "issue:read"], "quota": 100},
    "confluence-prod": {"scopes": ["page:read"], "quota": None},
}

#: A second drift alarm, over the only field whose *interior* the record cannot
#: type. The fixture record has no `provider_entitlements`, so `_GOLDEN_DIGEST`
#: alone pins nothing about how a nested mapping is canonicalised — recursive
#: key sorting, nested array order, and `None` becoming `null` rather than being
#: omitted are all unwitnessed by it. Those are exactly the rules a non-Python
#: issuer is most likely to get wrong, so they get a golden of their own.
_GOLDEN_ENTITLEMENTS_DIGEST = "84dc64f58bf86bd5cccb762d22625cbeed24b42d8692bd0cf8748c0475a77419"

#: The 16 MUST fields, with a value that differs from the fixture's for each.
#: Parametrized so a field added to the record without being covered here is
#: visible as an absence rather than as silence.
_MUST_FIELD_MUTATIONS: dict[str, object] = {
    "record_id": "reg-other",
    "record_issuer": "other.example",
    "schema_version": None,  # pinned by an invariant; handled separately below
    "record_version": 7,
    "agent_id": "agent-beta",
    "valid_until": datetime(2028, 1, 1, tzinfo=UTC),
    "lifecycle_state": "suspended",
    "sponsor_ref": "human:sponsor-2",
    "owner_ref": "team:other",
    "approved_runtime_issuers": ("spiffe://trust.example/other",),
    "approved_software_refs": ("sha256:ffffff",),
    "trust_domain": "other.example",
    "policy_profile_ref": "profile:elevated",
    "permitted_delegation_modes": ("passthrough",),
    "created_at": datetime(2025, 6, 1, tzinfo=UTC),
    "updated_at": datetime(2026, 6, 1, tzinfo=UTC),
}


def test_digest_is_lowercase_hex_sha256() -> None:
    assert re.fullmatch(r"[0-9a-f]{64}", record_digest(fixture_registration_record()))


def test_digest_is_deterministic_across_constructions() -> None:
    """Two independently built records with the same content digest the same.
    This is the property that lets a verifier recompute the digest rather than
    trust the bytes it was handed."""
    assert record_digest(fixture_registration_record()) == record_digest(
        fixture_registration_record()
    )


def test_digest_matches_the_pinned_golden() -> None:
    assert record_digest(fixture_registration_record()) == _GOLDEN_DIGEST


def test_nested_entitlements_digest_matches_the_pinned_golden() -> None:
    record = replace(fixture_registration_record(), provider_entitlements=_GOLDEN_ENTITLEMENTS)
    assert record_digest(record) == _GOLDEN_ENTITLEMENTS_DIGEST


def test_the_nested_entitlements_golden_pins_the_rules_it_claims_to() -> None:
    """Reads the bytes the golden above is a digest of.

    A golden hex says *that* something changed, never *what*. These assertions
    are what make the second golden diagnosable: if one of them fails alongside
    it, the failure names the rule that moved.
    """
    text = canonical_record_bytes(
        replace(fixture_registration_record(), provider_entitlements=_GOLDEN_ENTITLEMENTS)
    ).decode("utf-8")
    # Recursive key sorting, at both depths — `confluence-prod` was declared
    # second and `quota` after `scopes`.
    assert text.index('"confluence-prod"') < text.index('"jira-prod"')
    assert text.index('"quota"') < text.index('"scopes"')
    # Array order is content, so it survives sorting untouched.
    assert '["issue:update","issue:read"]' in text
    # `None` inside entitlements is a JSON `null`. Only an *absent*
    # `provider_entitlements` omits its key; a null-valued entry is data.
    assert '"quota":null' in text


def test_the_must_field_mutation_table_covers_every_must_field() -> None:
    """Guards the parametrization below. A §6.1 field added to the record but
    not to `_MUST_FIELD_MUTATIONS` would silently go untested for digest
    sensitivity."""
    record_fields = set(fixture_registration_record().to_document())
    assert record_fields == set(_MUST_FIELD_MUTATIONS)


@pytest.mark.parametrize(
    "field",
    [name for name, value in _MUST_FIELD_MUTATIONS.items() if value is not None],
)
def test_changing_any_must_field_changes_the_digest(field: str) -> None:
    baseline = fixture_registration_record()
    mutated = replace(baseline, **{field: _MUST_FIELD_MUTATIONS[field]})
    assert record_digest(mutated) != record_digest(baseline)


def test_schema_version_cannot_vary_without_a_new_type() -> None:
    """`schema_version` is the one MUST field the table above cannot mutate:
    the dataclass pins it. Its contribution to the digest is therefore fixed by
    construction rather than tested by variation."""
    with pytest.raises(ValueError, match="schema_version"):
        replace(fixture_registration_record(), schema_version="odis.registration.record.v2")


def test_array_order_is_significant() -> None:
    """Declared order is part of the digest. A record listing two approved
    software refs in one order is a different record from one listing them in
    the other; canonicalisation sorts keys, never array elements."""
    baseline = replace(
        fixture_registration_record(), approved_software_refs=("sha256:aa", "sha256:bb")
    )
    reordered = replace(baseline, approved_software_refs=("sha256:bb", "sha256:aa"))
    assert record_digest(reordered) != record_digest(baseline)


def test_absent_entitlements_and_empty_entitlements_digest_differently() -> None:
    """`None` omits the key; `{}` emits an empty object. "This record declares
    no entitlements" and "this record was never asked about entitlements" are
    different statements, so they must not collide."""
    absent = fixture_registration_record()
    empty = replace(absent, provider_entitlements={})
    assert record_digest(absent) != record_digest(empty)


def test_entitlement_key_order_does_not_change_the_digest() -> None:
    """`sort_keys=True` is recursive, so the order a nested mapping happened to
    be built in cannot move the digest."""
    one = replace(fixture_registration_record(), provider_entitlements={"a": 1, "b": 2})
    other = replace(fixture_registration_record(), provider_entitlements={"b": 2, "a": 1})
    assert record_digest(one) == record_digest(other)


def test_the_same_instant_in_a_different_offset_digests_identically() -> None:
    """Timestamps are normalised to UTC before serialisation, so an issuer in
    UTC+8 and one in UTC produce the same bytes for the same instant."""
    utc_record = fixture_registration_record()
    shifted = replace(
        utc_record,
        valid_until=utc_record.valid_until.astimezone(timezone(timedelta(hours=8))),
    )
    # Same instant, genuinely different offset — otherwise this test would pass
    # by comparing a record with itself.
    assert shifted.valid_until == utc_record.valid_until
    assert shifted.valid_until.utcoffset() != utc_record.valid_until.utcoffset()
    assert record_digest(shifted) == record_digest(utc_record)


def test_canonical_bytes_are_compact_and_key_sorted() -> None:
    """Compact separators and lexicographic keys — the two rules the Go
    plugin's `CanonicalBytes` already shares. It does *not* share the escaping
    rule the next test pins; `digest.py`'s docstring records why. Asserted on
    the bytes rather than on the digest so a failure says which rule broke."""
    raw = canonical_record_bytes(fixture_registration_record())
    text = raw.decode("utf-8")
    assert ", " not in text, "separators must be compact"
    assert '": ' not in text, "separators must be compact"
    keys = list(json.loads(text))
    assert keys == sorted(keys)


def test_canonical_bytes_are_utf8_without_ascii_escaping() -> None:
    """`ensure_ascii=False`, so a non-ASCII owner name is UTF-8 in the bytes
    rather than `\\uXXXX` escapes. Both are valid JSON, which is exactly why
    the choice has to be pinned: a Go issuer emitting raw UTF-8 and a Python
    one emitting escapes would disagree on the digest for the same record."""
    record = replace(fixture_registration_record(), owner_ref="team:平台")
    raw = canonical_record_bytes(record)
    assert "平台".encode() in raw
    assert rb"\u" not in raw


def test_html_significant_characters_are_not_escaped() -> None:
    """`<`, `>`, and `&` stay literal.

    Split out from the non-ASCII test because this is the rule a Go issuer gets
    wrong by default: `encoding/json.Marshal` escapes exactly these three to
    `\\u003c`, `\\u003e`, and `\\u0026`, and only an `Encoder` with
    `SetEscapeHTML(false)` opts out. An `owner_ref` of `team:R&D` is enough to
    make two conforming-looking implementations disagree on a `record_digest`,
    so the rule is pinned here rather than left implied by `ensure_ascii=False`.
    """
    raw = canonical_record_bytes(replace(fixture_registration_record(), owner_ref="team:<R&D>"))
    assert b"team:<R&D>" in raw
    for escape in (rb"\u003c", rb"\u003e", rb"\u0026"):
        assert escape not in raw


def test_canonical_bytes_round_trip_through_from_document() -> None:
    """The load path reproduces the exact bytes that were signed. Without this,
    a verifier could parse a document, rebuild the record, and compute a digest
    the issuer never signed."""
    original = canonical_record_bytes(fixture_registration_record())
    rebuilt = AgentRegistrationRecord.from_document(json.loads(original))
    assert canonical_record_bytes(rebuilt) == original


def test_round_trip_holds_with_provider_entitlements() -> None:
    record = replace(
        fixture_registration_record(),
        provider_entitlements={"jira-prod": {"scopes": ["issue:update"], "n": 1}},
    )
    original = canonical_record_bytes(record)
    rebuilt = AgentRegistrationRecord.from_document(json.loads(original))
    assert canonical_record_bytes(rebuilt) == original
