"""Typed terminal failures for the §6.1 load and resolution paths.

Its own module, unlike `bundle`, which parks its two exceptions in `loader.py`.
Here the loader and the resolver raise from the same family, and the resolver
imports nothing else from the loader, so a shared module is what keeps the two
from importing each other.

Every failure in this package is one of these. §6.1's resolution rule requires
failing closed "when authoritative resolution is unavailable or indeterminate",
and a function that returns `None` on some paths and raises on others makes
fail-closed a property of each caller rather than of this package. Nothing here
returns a sentinel.

`RegistrationResolutionError` exists so a caller that only needs "resolution
failed" catches one thing, while audit and metrics — which need to distinguish
an expired record from a rolled-back one — catch the leaves.
"""

from __future__ import annotations


class RegistrationRecordSignatureInvalid(RuntimeError):  # noqa: N818 - reads clearer than the Error suffix
    """The record's detached signature failed verification, or its claimed
    `record_issuer` has no configured key. Terminal."""


class RegistrationRecordSchemaInvalid(RuntimeError):  # noqa: N818 - reads clearer than the Error suffix
    """The record's structure violates the JSON Schema, or the bytes are not
    parseable JSON, or the dataclass invariants refused it. Terminal."""


class RegistrationWriteRefused(RuntimeError):  # noqa: N818 - reads clearer than the Error suffix
    """A governed write to the registration store did not happen.

    §6.1 records are created and de-provisioned under governance
    (`ODIS-CC-05`, `ODIS-L3-05`), so a refusal is a normal outcome of those
    paths rather than an error in them.

    Covers both reasons a governed write is declined: the requester was not
    permitted to make it, and the record it names does not exist. Named for the
    write rather than for creation because `revoke` raises it too — an
    exception whose name covers three of its four raise sites is a small lie
    that costs a reader a trip to the source.
    """


class RegistrationResolutionError(RuntimeError):
    """Base for every reason a ref did not resolve to a usable record.

    Catch this to fail closed; catch a leaf to say why.
    """


class RegistrationRecordUnavailable(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """Authoritative resolution could not be completed. §6.1 clause 6.

    Three store outcomes, one exception, because clause 6's "unavailable or
    indeterminate" is one verdict rather than three: the store has no such
    record, the store itself raised, or the store answered with a record the
    ref does not name. The third is not a lookup failure but a substituted
    store contradicting itself, and it is indeterminate for the same reason —
    nothing the resolver can check afterwards is about the record it asked for.
    """


class IssuerNotAuthorized(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """The `record_issuer` has no configured authority, or is not authoritative
    for the record's `trust_domain`. §6.1 clause 2."""


class RegistrationRecordSuperseded(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """The ref names a version that is no longer the store's current one.
    §6.1 clause 3."""


class RegistrationRecordRollback(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """A version older than one already seen for this agent was presented.
    §6.1 clause 5."""


class RegistrationRecordExpired(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """`valid_until` has passed, so this version may no longer be treated as
    current without an authenticated refresh. §6.1 clause 4."""


class RegistrationRecordNotActive(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """The record resolved, but its `lifecycle_state` does not permit use.

    §6.2's clarifying rule: a credential "MUST resolve to an active Agent
    Registration Record before Layer 2 issues or mediates delegated authority".
    """


class RegistrationRecordDigestMismatch(RegistrationResolutionError):  # noqa: N818 - reads clearer than the Error suffix
    """The resolved record's canonical digest is not the one the ref committed
    to. Distinct from `Superseded`: the versions agree and the content does
    not, which is tampering rather than staleness.

    Not a §6.1 clause. §6.1 describes a record, not a reference to one; the
    `record_digest` a ref carries is §6.2's and §6.3's. Nor is it a second
    attempt at clause 1, which the loader discharged over the bytes it was
    handed — this asks whether the record the *store* returned is the one the
    ref was issued against.
    """


__all__ = [
    "IssuerNotAuthorized",
    "RegistrationRecordDigestMismatch",
    "RegistrationRecordExpired",
    "RegistrationRecordNotActive",
    "RegistrationRecordRollback",
    "RegistrationRecordSchemaInvalid",
    "RegistrationRecordSignatureInvalid",
    "RegistrationRecordSuperseded",
    "RegistrationRecordUnavailable",
    "RegistrationResolutionError",
    "RegistrationWriteRefused",
]
