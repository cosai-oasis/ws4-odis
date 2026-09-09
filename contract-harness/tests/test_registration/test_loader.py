"""Loading a signed §6.1 record.

Fully hermetic: signs with an in-process ed25519 key wrapped in Vault's transit
envelope, and verifies offline through the same `VaultTransitSignatureVerifier`
the bundle path uses. No Vault, no network. Mirrors
`tests/test_bundle/test_vault_verifier.py`.

Signing here is a fixture, not a product. Verification is the
conformance-relevant half — §6.1's resolution rule is written from the
resolver's point of view — so a real signing plugin can be added later without
touching the canonical-bytes contract, which is the expensive thing to change.
"""

from __future__ import annotations

import base64
import json
from dataclasses import replace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from odis_harness.bundle.vault_verifier import VaultTransitSignatureVerifier
from odis_harness.registration.digest import canonical_record_bytes
from odis_harness.registration.errors import (
    RegistrationRecordSchemaInvalid,
    RegistrationRecordSignatureInvalid,
)
from odis_harness.registration.fixtures import fixture_registration_record
from odis_harness.registration.loader import (
    RegistrationRecordLoader,
    SignedRegistrationRecord,
)
from odis_harness.registration.types import AgentRegistrationRecord

_ISSUER = "registry.example"
_OTHER_ISSUER = "other-registry.example"


def _pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _verifier(private_key: Ed25519PrivateKey, *, key_name: str) -> VaultTransitSignatureVerifier:
    return VaultTransitSignatureVerifier.from_pem(
        key_name=key_name, public_key_pems={1: _pem(private_key)}
    )


def _sign(private_key: Ed25519PrivateKey, payload: bytes) -> bytes:
    """Wrap a raw ed25519 signature in Vault's ``vault:vN:<b64>`` envelope."""
    raw = private_key.sign(payload)
    return f"vault:v1:{base64.b64encode(raw).decode('ascii')}".encode("ascii")


@pytest.fixture
def issuer_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


@pytest.fixture
def loader(issuer_key: Ed25519PrivateKey) -> RegistrationRecordLoader:
    return RegistrationRecordLoader(
        verifiers={_ISSUER: _verifier(issuer_key, key_name="registration")}
    )


def _signed(
    private_key: Ed25519PrivateKey,
    payload: bytes,
    *,
    record_issuer: str = _ISSUER,
) -> SignedRegistrationRecord:
    return SignedRegistrationRecord(
        payload=payload, signature=_sign(private_key, payload), record_issuer=record_issuer
    )


def test_a_correctly_signed_record_loads(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    record = fixture_registration_record(record_issuer=_ISSUER)
    loaded = loader.load_signed(_signed(issuer_key, canonical_record_bytes(record)))
    assert loaded == record


def test_the_loaded_record_reproduces_the_signed_bytes(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """The D2 invariant, stated positively: the bytes signed, the bytes
    digested, and the bytes stored are the same bytes. If the loader's output
    did not reproduce its input, `record_digest` would commit to something no
    issuer signed. The three tests below are the negative direction — a payload
    that fails this is refused rather than quietly normalised."""
    payload = canonical_record_bytes(fixture_registration_record(record_issuer=_ISSUER))
    assert canonical_record_bytes(loader.load_signed(_signed(issuer_key, payload))) == payload


def test_a_signed_but_non_canonical_key_order_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """The signature is genuine and the document is a valid record; only the
    key order is wrong.

    This is the attack the canonicality check exists for. Without it the record
    loads, and its `record_digest` — recomputed from the *canonical* form —
    covers bytes the issuer never signed, so a §6.2 reference commits to a
    signature that does not exist. `to_document` emits keys in RFC table order,
    so serialising it compactly without sorting is already non-canonical.
    """
    document = fixture_registration_record(record_issuer=_ISSUER).to_document()
    payload = json.dumps(document, sort_keys=False, separators=(",", ":")).encode("utf-8")
    assert payload != canonical_record_bytes(fixture_registration_record(record_issuer=_ISSUER))
    with pytest.raises(RegistrationRecordSchemaInvalid, match="canonical serialization"):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_signed_but_pretty_printed_payload_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """Same record, same key order, only whitespace differs. Digest-bearing
    bytes have no cosmetic dimension."""
    document = fixture_registration_record(record_issuer=_ISSUER).to_document()
    payload = json.dumps(document, sort_keys=True, indent=2).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid, match="canonical serialization"):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_signed_but_ascii_escaped_payload_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """`ensure_ascii=True` produces valid JSON that parses to the same record.

    Worth its own test because this is the divergence a non-Python issuer is
    most likely to ship — Go's `encoding/json` escapes by default. Refusing it
    at load is what stops that issuer's records from resolving with a digest
    nobody can reproduce, rather than letting them fail later at a §6.2
    reference check where the cause is much harder to see.
    """
    record = replace(
        fixture_registration_record(record_issuer=_ISSUER), owner_ref="team:平台"
    )
    payload = json.dumps(
        record.to_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid, match="canonical serialization"):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_signature_from_the_wrong_key_is_refused(loader: RegistrationRecordLoader) -> None:
    other_key = Ed25519PrivateKey.generate()
    payload = canonical_record_bytes(fixture_registration_record(record_issuer=_ISSUER))
    with pytest.raises(RegistrationRecordSignatureInvalid, match="verification failed"):
        loader.load_signed(_signed(other_key, payload))


def test_a_tampered_payload_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    payload = canonical_record_bytes(fixture_registration_record(record_issuer=_ISSUER))
    signature = _sign(issuer_key, payload)
    tampered = payload.replace(b'"team:platform"', b'"team:attacker"')
    assert tampered != payload
    with pytest.raises(RegistrationRecordSignatureInvalid):
        loader.load_signed(
            SignedRegistrationRecord(
                payload=tampered, signature=signature, record_issuer=_ISSUER
            )
        )


def test_an_unknown_issuer_raises_the_typed_error_not_a_key_error(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """"I cannot verify this" and "this does not verify" are the same outcome
    to a caller, and both must fail closed. A `KeyError` escaping the verifier
    map would leave the loader's typed contract."""
    payload = canonical_record_bytes(fixture_registration_record(record_issuer=_OTHER_ISSUER))
    with pytest.raises(RegistrationRecordSignatureInvalid, match="no configured verifier"):
        loader.load_signed(_signed(issuer_key, payload, record_issuer=_OTHER_ISSUER))


def test_issuer_substitution_is_refused(issuer_key: Ed25519PrivateKey) -> None:
    """A document attributed to issuer B, signed with A's key, presented under
    A's name. The signature is genuine, so only the envelope/document
    cross-check catches it — and without that check the resolver, which reads
    the document, would apply B's authority configuration to A's record.
    """
    loader = RegistrationRecordLoader(
        verifiers={_ISSUER: _verifier(issuer_key, key_name="registration")}
    )
    document = fixture_registration_record(record_issuer=_OTHER_ISSUER)
    payload = canonical_record_bytes(document)
    with pytest.raises(RegistrationRecordSignatureInvalid, match="record_issuer mismatch"):
        loader.load_signed(_signed(issuer_key, payload, record_issuer=_ISSUER))


def test_malformed_json_is_a_schema_failure(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    with pytest.raises(RegistrationRecordSchemaInvalid, match="unparseable JSON"):
        loader.load_signed(_signed(issuer_key, b"{not json"))


def test_non_utf8_bytes_are_a_schema_failure(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """A `UnicodeDecodeError` must not escape as itself."""
    with pytest.raises(RegistrationRecordSchemaInvalid):
        loader.load_signed(_signed(issuer_key, b"\xff\xfe\x00garbage"))


@pytest.mark.parametrize("root", ["[]", '"a string"', "42", "null"])
def test_a_non_object_root_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey, root: str
) -> None:
    with pytest.raises(RegistrationRecordSchemaInvalid, match="must be a JSON object"):
        loader.load_signed(_signed(issuer_key, root.encode("utf-8")))


def test_a_record_missing_a_must_field_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    document = fixture_registration_record(record_issuer=_ISSUER).to_document()
    del document["policy_profile_ref"]
    payload = json.dumps(document).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid, match="schema validation failed"):
        loader.load_signed(_signed(issuer_key, payload))


def test_an_undeclared_field_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """`additionalProperties: false`. A surprise field would otherwise ride
    inside the signed canonical bytes unexamined."""
    document = fixture_registration_record(record_issuer=_ISSUER).to_document()
    document["surprise"] = "value"
    payload = json.dumps(document).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid, match="schema validation failed"):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_dataclass_invariant_violation_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """`updated_at < created_at` is an ordering JSON Schema cannot express, so
    the schema passes and only `__post_init__` catches it. The loader must turn
    that `ValueError` into its own typed failure rather than let it escape.
    """
    record = fixture_registration_record(record_issuer=_ISSUER)
    document = record.to_document()
    document["updated_at"] = "2025-01-01T00:00:00.000000Z"  # before created_at
    payload = json.dumps(document).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid, match="dataclass invariants"):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_lifecycle_state_outside_the_closed_set_is_refused(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    document = fixture_registration_record(record_issuer=_ISSUER).to_document()
    document["lifecycle_state"] = "quiescent"
    payload = json.dumps(document).encode("utf-8")
    with pytest.raises(RegistrationRecordSchemaInvalid):
        loader.load_signed(_signed(issuer_key, payload))


def test_a_suspended_record_still_loads(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """Loading is about authenticity and structure, not usability. A suspended
    record is a genuine record; refusing it belongs to the resolver, which is
    the component that knows whether the caller needs an active one."""
    record = fixture_registration_record(record_issuer=_ISSUER, lifecycle_state="suspended")
    loaded = loader.load_signed(_signed(issuer_key, canonical_record_bytes(record)))
    assert loaded.lifecycle_state == "suspended"


def test_an_expired_record_still_loads(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    """Same division. The loader holds no clock; `valid_until` is clause 4 and
    belongs to the resolver."""
    record = fixture_registration_record(record_issuer=_ISSUER)
    expired = replace(record, valid_until=record.created_at)
    loaded = loader.load_signed(_signed(issuer_key, canonical_record_bytes(expired)))
    assert loaded == expired


def test_multiple_issuers_are_kept_apart() -> None:
    """Each issuer verifies only against its own key. This is the bounded form
    of clause 1's "authenticate record_issuer" that the loader delivers: a
    document claiming A cannot be validated by B's key."""
    key_a = Ed25519PrivateKey.generate()
    key_b = Ed25519PrivateKey.generate()
    loader = RegistrationRecordLoader(
        verifiers={
            _ISSUER: _verifier(key_a, key_name="a"),
            _OTHER_ISSUER: _verifier(key_b, key_name="b"),
        }
    )
    record_b = fixture_registration_record(record_issuer=_OTHER_ISSUER)
    payload_b = canonical_record_bytes(record_b)

    assert loader.load_signed(_signed(key_b, payload_b, record_issuer=_OTHER_ISSUER)) == record_b
    # B's document signed by A's key, correctly attributed to B: refused.
    with pytest.raises(RegistrationRecordSignatureInvalid):
        loader.load_signed(_signed(key_a, payload_b, record_issuer=_OTHER_ISSUER))


def test_a_loaded_record_round_trips_to_the_same_document(
    loader: RegistrationRecordLoader, issuer_key: Ed25519PrivateKey
) -> None:
    record = fixture_registration_record(record_issuer=_ISSUER)
    payload = canonical_record_bytes(record)
    loaded = loader.load_signed(_signed(issuer_key, payload))
    assert AgentRegistrationRecord.from_document(json.loads(payload)) == loaded
