"""Tests for the offline transit-signature verifier.

Fully hermetic: signs with an in-test ed25519 key (mimicking Vault transit) and
verifies offline. No Vault, no network.
"""

from __future__ import annotations

import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from odis_harness.bundle.vault_verifier import (
    NonEd25519PublicKeyError,
    VaultTransitSignatureVerifier,
)

_KEY_NAME = "apf-bundle"
_PAYLOAD = b'{"bundle_id":"odis-fixture-bundle","bundle_version":"1"}'


def _pem(public_key: Ed25519PublicKey) -> bytes:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _transit_signature(private_key: Ed25519PrivateKey, payload: bytes, version: int) -> bytes:
    """Wrap a raw ed25519 signature in Vault's ``vault:vN:<b64>`` envelope."""
    raw = private_key.sign(payload)
    return f"vault:v{version}:{base64.b64encode(raw).decode('ascii')}".encode("ascii")


def test_valid_signature_verifies() -> None:
    # a correctly-signed, correctly-versioned payload verifies offline.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key.public_key())},
    )
    signature = _transit_signature(private_key, _PAYLOAD, version=1)
    assert verifier.verify(_PAYLOAD, signature) is True


def test_tampered_payload_fails() -> None:
    # a single flipped byte fails verification.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key.public_key())},
    )
    signature = _transit_signature(private_key, _PAYLOAD, version=1)
    tampered = bytearray(_PAYLOAD)
    tampered[0] ^= 0x01
    assert verifier.verify(bytes(tampered), signature) is False


def test_unknown_key_version_fails() -> None:
    # MVP, no refresh: a signature naming a version with no exported
    # public key fails closed.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key.public_key())},
    )
    signature = _transit_signature(private_key, _PAYLOAD, version=2)
    assert verifier.verify(_PAYLOAD, signature) is False


def test_wrong_key_same_version_fails() -> None:
    # A signature from a different key (same version slot) must not verify.
    signing_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(other_key.public_key())},
    )
    signature = _transit_signature(signing_key, _PAYLOAD, version=1)
    assert verifier.verify(_PAYLOAD, signature) is False


@pytest.mark.parametrize(
    "bad_signature",
    [
        b"not-a-vault-signature",
        b"vault:v1",  # missing the signature segment
        b"vault:vX:" + base64.b64encode(b"x" * 64),  # non-numeric version
        b"vault:v1:!!!not-base64!!!",  # malformed base64
        b"hsm:v1:" + base64.b64encode(b"x" * 64),  # wrong namespace
        b"",
    ],
)
def test_malformed_signature_fails(bad_signature: bytes) -> None:
    # a malformed signature string is treated as a failed verification,
    # never an exception.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key.public_key())},
    )
    assert verifier.verify(_PAYLOAD, bad_signature) is False


def test_from_transit_ed25519_raw_export_verifies() -> None:
    # Vault transit exports ed25519 public keys as base64 raw 32 bytes (not PEM).
    # The transit-native constructor must consume that form and verify.
    private_key = Ed25519PrivateKey.generate()
    raw_pub = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
        key_name=_KEY_NAME,
        public_keys_b64={1: base64.b64encode(raw_pub).decode("ascii")},
    )
    signature = _transit_signature(private_key, _PAYLOAD, version=1)
    assert verifier.verify(_PAYLOAD, signature) is True
    tampered = bytearray(_PAYLOAD)
    tampered[0] ^= 0x01
    assert verifier.verify(bytes(tampered), signature) is False


def test_from_transit_ed25519_rejects_malformed_key() -> None:
    # a malformed/wrong-length transit export raises a typed error (like
    # from_pem), not an opaque ValueError out of the constructor.
    with pytest.raises(NonEd25519PublicKeyError):
        VaultTransitSignatureVerifier.from_transit_ed25519(
            key_name=_KEY_NAME, public_keys_b64={1: "!!!not-base64!!!"}
        )


def test_zero_version_signature_rejected() -> None:
    # Transit key versions are >= 1; a vault:v0: signature is malformed -> reject.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME, public_key_pems={1: _pem(private_key.public_key())}
    )
    assert verifier.verify(_PAYLOAD, _transit_signature(private_key, _PAYLOAD, version=0)) is False


def test_non_ed25519_public_key_rejected() -> None:
    # the verifier only accepts ed25519 public keys.
    from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: PLC0415 — test-only path

    rsa_pub = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    rsa_pem = rsa_pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    with pytest.raises(NonEd25519PublicKeyError):
        VaultTransitSignatureVerifier.from_pem(key_name=_KEY_NAME, public_key_pems={1: rsa_pem})


def test_v1_signature_verifies_after_rotation_to_v2() -> None:
    # a bundle signed by an older key version still verifies when the
    # verifier holds multiple versions (post-rotation, the v1 key remains cached).
    v1_key = Ed25519PrivateKey.generate()
    v2_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(v1_key.public_key()), 2: _pem(v2_key.public_key())},
    )
    v1_signature = _transit_signature(v1_key, _PAYLOAD, version=1)
    v2_signature = _transit_signature(v2_key, _PAYLOAD, version=2)
    assert verifier.verify(_PAYLOAD, v1_signature) is True
    assert verifier.verify(_PAYLOAD, v2_signature) is True


def test_uncached_version_without_refresh_fails() -> None:
    # with no refresh callable, an uncached version fails closed.
    v1_key = Ed25519PrivateKey.generate()
    v2_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(v1_key.public_key())},
    )
    v2_signature = _transit_signature(v2_key, _PAYLOAD, version=2)
    assert verifier.verify(_PAYLOAD, v2_signature) is False


def test_uncached_version_triggers_refresh_once_then_verifies() -> None:
    # a signature naming an uncached version refreshes the
    # exported keys ONCE, then verifies against the freshly-fetched key.
    v1_key = Ed25519PrivateKey.generate()
    v2_key = Ed25519PrivateKey.generate()
    refresh_calls = 0

    def refresh() -> dict[tuple[str, int], Ed25519PublicKey]:
        nonlocal refresh_calls
        refresh_calls += 1
        return {
            (_KEY_NAME, 1): v1_key.public_key(),
            (_KEY_NAME, 2): v2_key.public_key(),
        }

    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(v1_key.public_key())},
        refresh=refresh,
    )
    v2_signature = _transit_signature(v2_key, _PAYLOAD, version=2)
    assert verifier.verify(_PAYLOAD, v2_signature) is True
    assert refresh_calls == 1
    # A second verify of the now-cached version does NOT re-refresh.
    assert verifier.verify(_PAYLOAD, v2_signature) is True
    assert refresh_calls == 1


def test_refresh_runs_at_most_once_per_verify_for_still_unknown_version() -> None:
    # even after a refresh that does not yield the named
    # version, verify() refreshes at most once and then fails closed.
    v1_key = Ed25519PrivateKey.generate()
    v99_key = Ed25519PrivateKey.generate()
    refresh_calls = 0

    def refresh() -> dict[tuple[str, int], Ed25519PublicKey]:
        nonlocal refresh_calls
        refresh_calls += 1
        return {(_KEY_NAME, 1): v1_key.public_key()}

    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(v1_key.public_key())},
        refresh=refresh,
    )
    v99_signature = _transit_signature(v99_key, _PAYLOAD, version=99)
    assert verifier.verify(_PAYLOAD, v99_signature) is False
    assert refresh_calls == 1


def test_refresh_that_raises_does_not_propagate() -> None:
    # verify() must never raise — a refresh callable that throws is
    # swallowed and the verification fails closed.
    v1_key = Ed25519PrivateKey.generate()
    v2_key = Ed25519PrivateKey.generate()

    def refresh() -> dict[tuple[str, int], Ed25519PublicKey]:
        message = "vault unreachable"
        raise RuntimeError(message)

    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(v1_key.public_key())},
        refresh=refresh,
    )
    v2_signature = _transit_signature(v2_key, _PAYLOAD, version=2)
    assert verifier.verify(_PAYLOAD, v2_signature) is False
