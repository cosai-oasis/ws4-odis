"""Module-level constants for the contracts capability.

Two different kinds of constant live here, and the distinction matters.

`SCHEMA_VERSION` and `PHASE` identify the harness itself. They are genuinely fixed, are
`const`-pinned in the envelope schemas, and the audit sink rejects an emitter that tries
to state anything else.

The three `STUB_*` grant-identity values are fallbacks only, for an envelope built with
no grant in play — contract tests, mostly. Every production path stamps the values
from the `Bundle` in force, because an envelope has to name the grant it was produced
under for the audit trail to say which policy authorized a call. The envelope schemas
therefore leave those three free-form (`minLength: 1`): a pinned value would describe
this fixture rather than whatever is loaded.
"""

from __future__ import annotations

# -- Fallback grant identity (overridden by the loaded Bundle) ----------------

#: Grant identifier for an envelope built with no `Bundle` in play.
STUB_BUNDLE_ID: str = "odis-fixture-bundle"

#: SemVer-shaped grant version literal, for the same case.
STUB_BUNDLE_VERSION: str = "0.0.0-odis-harness"

#: Trust-anchor identifier for the same case; nothing is anchored to it.
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
