"""The Authority Grant — the bundle's schema, dataclasses, digest, and the two ways
to obtain one: a local file (`loader`) or a Vault-issued, Ed25519-signed grant
(`vault_client` to fetch, `vault_verifier` to check it offline).

The signed bundle is a single artifact carrying policy + routing + governed tools +
per-family `default_mode` under one signature, so policy and routing cannot be
mixed and matched (see `digest.py`).
The Router consumes the loaded bundle to resolve `<family>.<tool>` MCP calls to
vendor MCP server endpoints and to gate calls via the bundle's policy.
"""

from __future__ import annotations

from odis_harness.bundle.digest import policy_digest
from odis_harness.bundle.loader import (
    BundleExpired,
    BundleLoader,
    BundleSchemaInvalid,
    BundleSignatureInvalid,
    SignatureVerifier,
)
from odis_harness.bundle.types import (
    AttenuationProfileRef,
    Bundle,
    DefaultMode,
    EgressMode,
    Family,
    MappingRecordRef,
    ToolPolicy,
    VendorMcp,
)
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
    "AttenuationProfileRef",
    "Bundle",
    "BundleExpired",
    "BundleLoader",
    "BundleSchemaInvalid",
    "BundleSignatureInvalid",
    "DefaultMode",
    "EgressMode",
    "Family",
    "MappingRecordRef",
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
