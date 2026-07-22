"""Module-level constants for the contracts capability.

Fixed fixture policy-metadata literals are carried by every envelope because
the harness ships with a fixture signed bundle. They are intentionally not
configurable (env var / CLI flag) — making them configurable would invite
drift between what the harness claims to enforce and what is actually loaded.
"""

from __future__ import annotations

# -- Stub policy metadata ----------------------------------------------------

#: Fixed bundle identifier — the harness ships no real signed bundle.
STUB_BUNDLE_ID: str = "odis-fixture-bundle"

#: SemVer-shaped bundle version literal.
STUB_BUNDLE_VERSION: str = "0.0.0-odis-harness"

#: Stub trust-anchor identifier; not a real trust root.
STUB_TRUST_ROOT_ID: str = "odis-fixture-trust-root"

#: ``schema_version`` value carried by every ODIS Contract Harness envelope. Distinct from
#: ``apf.*.v1`` so no consumer mistakes a ODIS Contract Harness payload for an APF Core
#: artifact.
SCHEMA_VERSION: str = "odis.v1"

#: ``phase`` value injected into every emitted audit event by the Audit Sink.
PHASE: str = "odis-harness"

__all__ = [
    "PHASE",
    "SCHEMA_VERSION",
    "STUB_BUNDLE_ID",
    "STUB_BUNDLE_VERSION",
    "STUB_TRUST_ROOT_ID",
]
