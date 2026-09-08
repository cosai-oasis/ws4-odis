"""A `SignatureVerifier` that verifies nothing.

**Never use this in production.** `verify` returns True for every payload, so a bundle
carrying no signature, a wrong signature, or a signature over different bytes all load
identically. It exists so the zero-infrastructure demo can run without key material.

`signature_verifier` is a required argument on every load path, so choosing this is a
visible act at the call site rather than a default.

Production uses `odis_harness.bundle.vault_verifier.VaultTransitSignatureVerifier`
(offline Ed25519).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class FixtureSignatureVerifier:
    """Accepts any payload. Non-production stand-in for the `SignatureVerifier` seam."""

    def verify(self, payload: bytes, signature: bytes) -> bool:  # noqa: ARG002
        """Always True. The arguments are accepted and ignored, which is the whole point."""
        return True


__all__ = ["FixtureSignatureVerifier"]
