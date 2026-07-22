"""odis-bundle-routing — the signed bundle's schema, dataclasses, loader, and digest.

The signed bundle is a single artifact carrying policy + routing + governed tools +
per-family `default_mode` under one signature (see [[bundle-signed-routing-and-policy]]).
The Router consumes the loaded bundle to resolve `<family>.<tool>` MCP calls to
vendor MCP server endpoints and to gate calls via the bundle's policy.
"""

from __future__ import annotations

from odis_harness.bundle.digest import policy_digest
from odis_harness.bundle.loader import (
    BundleLoader,
    BundleSchemaInvalid,
    BundleSignatureInvalid,
    FixtureSignatureVerifier,
    SignatureVerifier,
)
from odis_harness.bundle.types import Bundle, DefaultMode, Family, ToolPolicy, VendorMcp
from odis_harness.bundle.vault_client import (
    SignedBundle,
    VaultBundleClient,
    VaultBundleError,
)
from odis_harness.bundle.vault_verifier import (
    NonEd25519PublicKeyError,
    VaultTransitSignatureVerifier,
)

__all__ = [
    "Bundle",
    "BundleLoader",
    "BundleSchemaInvalid",
    "BundleSignatureInvalid",
    "DefaultMode",
    "Family",
    "FixtureSignatureVerifier",
    "NonEd25519PublicKeyError",
    "SignatureVerifier",
    "SignedBundle",
    "ToolPolicy",
    "VaultBundleClient",
    "VaultBundleError",
    "VaultTransitSignatureVerifier",
    "VendorMcp",
    "policy_digest",
]
