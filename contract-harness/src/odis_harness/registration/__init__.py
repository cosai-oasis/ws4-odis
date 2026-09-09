"""odis-registration — the ODIS §6.1 Agent Registration Record.

The durable organizational governance record for a logical agent. Every runtime
check in the RFC resolves upward to it: §6.2's `registration_record_ref` and
§6.3's `parent_delegation_ref` both carry a `record_digest` this package
defines.

The carrier is a **canonical JSON document plus a detached ed25519 signature**,
verified offline through the same `bundle.loader.SignatureVerifier` Protocol the
signed bundle uses. Not a JWT, despite PyJWT already being a dependency — a JWT
forces two canonicalisations, the JWS signing input and whatever `record_digest`
covers. With a detached signature the bytes signed, the bytes digested, and the
bytes stored are the same bytes, and that single property is what §6.2 and §6.3
inherit.

The §6.1 resolution rule is enforced in two places, which is the same split as
`BundleLoader` → `Router`:

- `RegistrationRecordLoader` — integrity, and issuer authentication to the
  extent that a document claiming issuer `A` verifies only against `A`'s key.
- `AuthoritativeRegistrationRecordResolver` — issuer authority for the trust
  domain, supersession, digest agreement, rollback, expiry, and lifecycle.

Nothing here returns a sentinel on failure; every path raises under
`RegistrationResolutionError` or one of the two terminal load errors.
"""

from __future__ import annotations

from odis_harness.registration.digest import canonical_record_bytes, record_digest
from odis_harness.registration.errors import (
    IssuerNotAuthorized,
    RegistrationRecordDigestMismatch,
    RegistrationRecordExpired,
    RegistrationRecordNotActive,
    RegistrationRecordRollback,
    RegistrationRecordSchemaInvalid,
    RegistrationRecordSignatureInvalid,
    RegistrationRecordSuperseded,
    RegistrationRecordUnavailable,
    RegistrationResolutionError,
    RegistrationWriteRefused,
)
from odis_harness.registration.fixtures import (
    FixtureRegistrationRecordIssuer,
    InMemoryRegistrationRecordStore,
    RegistrationRecordIssuer,
    fixture_registration_record,
    registration_fixture_stack,
)
from odis_harness.registration.loader import (
    RegistrationRecordLoader,
    SignedRegistrationRecord,
)
from odis_harness.registration.resolver import (
    AuthoritativeRegistrationRecordResolver,
    RegistrationRecordLifecycleStore,
    RegistrationRecordResolver,
    RegistrationRecordStore,
)
from odis_harness.registration.types import (
    RECORD_SCHEMA_VERSION,
    AgentRegistrationRecord,
    IssuerAuthority,
    LifecycleState,
    RegistrationRecordRef,
)

__all__ = [
    "RECORD_SCHEMA_VERSION",
    "AgentRegistrationRecord",
    "AuthoritativeRegistrationRecordResolver",
    "FixtureRegistrationRecordIssuer",
    "InMemoryRegistrationRecordStore",
    "IssuerAuthority",
    "IssuerNotAuthorized",
    "LifecycleState",
    "RegistrationRecordDigestMismatch",
    "RegistrationRecordExpired",
    "RegistrationRecordIssuer",
    "RegistrationRecordLifecycleStore",
    "RegistrationRecordLoader",
    "RegistrationRecordNotActive",
    "RegistrationRecordRef",
    "RegistrationRecordResolver",
    "RegistrationRecordRollback",
    "RegistrationRecordSchemaInvalid",
    "RegistrationRecordSignatureInvalid",
    "RegistrationRecordStore",
    "RegistrationRecordSuperseded",
    "RegistrationRecordUnavailable",
    "RegistrationResolutionError",
    "RegistrationWriteRefused",
    "SignedRegistrationRecord",
    "canonical_record_bytes",
    "fixture_registration_record",
    "record_digest",
    "registration_fixture_stack",
]
