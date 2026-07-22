"""VaultTransitSignatureVerifier — offline ed25519 verification of a transit-signed bundle.

Implements the `bundle.loader.SignatureVerifier` Protocol. Verifies a Vault-transit
signature (`vault:vN:<base64>`) over the canonical bundle bytes against a
previously-exported ed25519 public key — with NO call to Vault at verify time.
The `vN` version selects which exported public key to use, so
bundles signed before a key rotation still verify. A signature naming a
version not yet exported triggers an optional one-shot key refresh before failing
closed.

ed25519 in Vault transit is plain PureEdDSA (no prehash), so the signature is verified
directly over the exact bytes that were signed — the canonical bundle bytes the issuer
returned.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Self

import structlog
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import load_pem_public_key

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

_logger = structlog.get_logger(__name__)

#: Vault transit signature shape: ``vault:v<N>:<base64-signature>`` — three
#: colon-delimited parts. base64 never contains ``:`` so the split is unambiguous.
_SIG_PARTS = 3
_SIG_NAMESPACE = "vault"


class NonEd25519PublicKeyError(TypeError):
    """An exported public key the verifier was given is not ed25519."""


def _parse_signature(signature: bytes) -> tuple[int, bytes] | None:
    """Parse ``vault:vN:<b64>`` into ``(version, raw_signature_bytes)``.

    Returns None for any malformed input — the caller treats that as a failed
    verification (fail closed), never an exception to the load path.
    """
    try:
        text = signature.decode("ascii")
    except UnicodeDecodeError:
        return None
    parts = text.split(":")
    if len(parts) != _SIG_PARTS or parts[0] != _SIG_NAMESPACE:
        return None
    version_token, b64_sig = parts[1], parts[2]
    if not version_token.startswith("v"):
        return None
    try:
        version = int(version_token[1:])
        raw = base64.b64decode(b64_sig, validate=True)
    except ValueError:
        # int() on a non-numeric version, or binascii.Error (a ValueError
        # subclass) from malformed base64.
        return None
    if version < 1:
        return None  # transit key versions are >= 1; reject v0 / negative as malformed
    return version, raw


#: Type of the cache mapping exported ed25519 public keys by ``(key_name, version)``.
PublicKeyCache = dict[tuple[str, int], Ed25519PublicKey]


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultTransitSignatureVerifier:
    """Offline verifier for Vault-transit-signed bundles.

    Holds exported public keys keyed by ``(key_name, version)`` so a single
    instance verifies across key rotations — a bundle signed by an
    older version still verifies as long as that version's key remains cached.
    Construct via `from_pem`.

    On a signature naming a version not in the cache, `verify` calls the
    optional `refresh` callable **once** to re-fetch the exported keys before
    failing closed — the live-rotation path where a new key
    version signed a bundle before the verifier had exported it.

    The dataclass is frozen, but the cache is a `dict` we mutate **in place** on
    refresh: frozen forbids rebinding the `public_keys` attribute, not mutating
    the dict it already points at — so the cache stays warm across calls without
    breaking immutability of the instance's identity.
    """

    key_name: str
    public_keys: PublicKeyCache
    #: Optional re-fetch of the full ``(key_name, version) -> key`` map. None
    #: disables refresh (the cache is fixed at construction). verify() never
    #: lets this raise — a failing refresh fails the verification closed.
    refresh: Callable[[], Mapping[tuple[str, int], Ed25519PublicKey]] | None = field(default=None)

    def verify(self, payload: bytes, signature: bytes) -> bool:
        """Return True iff `signature` is a valid transit signature over `payload`.

        Fails closed (returns False) on a malformed signature, an unknown key
        version (after at most one refresh attempt), or a cryptographic
        mismatch — never raises.
        """
        parsed = _parse_signature(signature)
        if parsed is None:
            return False
        version, raw_signature = parsed
        public_key = self._resolve_public_key(version)
        if public_key is None:
            return False
        try:
            public_key.verify(raw_signature, payload)
        except InvalidSignature:
            return False
        return True

    def _resolve_public_key(self, version: int) -> Ed25519PublicKey | None:
        """Cache lookup; on a miss, refresh the cache once and retry."""
        cache_key = (self.key_name, version)
        public_key = self.public_keys.get(cache_key)
        if public_key is not None:
            return public_key
        if self.refresh is None:
            return None
        self._refresh_cache()
        return self.public_keys.get(cache_key)

    def _refresh_cache(self) -> None:
        """Re-fetch exported keys and merge into the in-place cache.

        A frozen dataclass forbids rebinding `public_keys`, so we update the
        existing dict in place. Any exception from the (network-bound) refresh
        callable is swallowed: verify() must never raise.
        """
        if self.refresh is None:  # pragma: no cover - guarded by the caller
            return
        try:
            refreshed = self.refresh()
        except Exception:  # noqa: BLE001 - fail closed + logged: a broken refresh must not raise to verify()
            _logger.warning(
                "vault_verifier.key_refresh_failed", key_name=self.key_name, exc_info=True
            )
            return
        self.public_keys.update(refreshed)

    @classmethod
    def from_pem(
        cls,
        *,
        key_name: str,
        public_key_pems: Mapping[int, bytes],
        refresh: Callable[[], Mapping[tuple[str, int], Ed25519PublicKey]] | None = None,
    ) -> Self:
        """Build a verifier from exported PEM public keys keyed by transit version."""
        keys: PublicKeyCache = {}
        for version, pem in public_key_pems.items():
            loaded = load_pem_public_key(pem)
            if not isinstance(loaded, Ed25519PublicKey):
                message = f"key {key_name!r} v{version} is {type(loaded).__name__}, not ed25519"
                raise NonEd25519PublicKeyError(message)
            keys[(key_name, version)] = loaded
        return cls(key_name=key_name, public_keys=keys, refresh=refresh)

    @classmethod
    def from_transit_ed25519(
        cls,
        *,
        key_name: str,
        public_keys_b64: Mapping[int, str],
        refresh: Callable[[], Mapping[tuple[str, int], Ed25519PublicKey]] | None = None,
    ) -> Self:
        """Build a verifier from Vault transit's ed25519 public-key export.

        `GET transit/keys/<name>` returns each version's ed25519 public key as a
        base64-encoded raw 32-byte value (NOT PEM — only RSA/ECDSA transit keys
        export as PEM). This is the Router-startup path against a live Vault.
        """
        keys: PublicKeyCache = {}
        for version, b64 in public_keys_b64.items():
            try:
                raw = base64.b64decode(b64, validate=True)
                keys[(key_name, version)] = Ed25519PublicKey.from_public_bytes(raw)
            except (ValueError, TypeError) as exc:
                # Malformed base64 (binascii.Error ⊂ ValueError) or a wrong-length
                # key (from_public_bytes ValueError) — typed, like from_pem.
                message = f"key {key_name!r} v{version} is not a valid ed25519 public key"
                raise NonEd25519PublicKeyError(message) from exc
        return cls(key_name=key_name, public_keys=keys, refresh=refresh)


__all__ = ["NonEd25519PublicKeyError", "PublicKeyCache", "VaultTransitSignatureVerifier"]
