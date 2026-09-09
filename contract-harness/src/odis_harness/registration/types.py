"""Frozen dataclasses mirroring the `odis.registration.record.v1` JSON Schema.

`AgentRegistrationRecord` is the ODIS RFC §6.1 Agent Registration Record: the
durable organizational governance record for a logical agent. Every runtime
check in the RFC resolves upward to it.

Carrier: a canonical JSON document plus a detached ed25519 signature. That
choice is what makes `to_document()` the load-bearing method here — it is the
projection `digest.canonical_record_bytes` serialises, so the bytes an issuer
signs, the bytes a verifier digests into `record_digest`, and the bytes at rest
are the same bytes. §6.2's `registration_record_ref` and §6.3's
`parent_delegation_ref` both rest on that single property.

`__post_init__` re-checks invariants the schema also enforces. This is the
`bundle/types.py` convention: the schema guards the wire, the dataclass guards
the programmatic path, and if one drifts the other still refuses to construct an
invalid instance.

The canonical form itself is not defined here. Timestamp spelling, the JSON
value rules, and the deep-freeze live in `odis_harness.canonical`, because §6.2
and §6.3 inherit them and a §6.2 module should not have to import a §6.1 module
to serialise.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import (
    datetime,  # noqa: TC003 - kept out of TYPE_CHECKING so get_type_hints() can resolve the fields
)
from typing import Any, Literal, Self

from odis_harness.canonical import (
    MAX_SAFE_INTEGER,
    canonical_timestamp,
    frozen_json,
    is_aware,
    parse_timestamp,
    plain_json,
)

#: The schema this record is pinned to. Distinct from
#: `contracts.SCHEMA_VERSION = "odis.v1"`, which versions the audit/authz
#: envelopes rather than a §6 data model.
RECORD_SCHEMA_VERSION: str = "odis.registration.record.v1"

LifecycleState = Literal["active", "suspended", "revoked", "pending"]

#: The RFC says "active, suspended, revoked, pending, or equivalent". We answer
#: "or equivalent" by declaring a closed set and failing closed outside it: an
#: open enum would make `is_usable()` guess, and a resolver that guesses is not
#: fail-closed. `Literal` rather than `enum` follows `DefaultMode`
#: (`bundle/types.py`) and `ForwardMode` (`mcp_forwarder/audit.py`) — `enum`
#: appears nowhere in `src/`. It also keeps the value a bare `str` at rest, so
#: canonicalisation needs no special case.
_LIFECYCLE_STATES: frozenset[str] = frozenset({"active", "suspended", "revoked", "pending"})

#: The states in which a record may back a live request. Deliberately narrower
#: than `_LIFECYCLE_STATES`: `pending` has not been admitted yet, `suspended`
#: has been withdrawn, and `revoked` is terminal.
_USABLE_LIFECYCLE_STATES: frozenset[str] = frozenset({"active"})

#: The three §6.1 array fields, in RFC table order. Named once so
#: `__post_init__` and `to_document`/`from_document` cannot disagree about which
#: fields are sequences.
_SEQUENCE_FIELDS: tuple[str, ...] = (
    "approved_runtime_issuers",
    "approved_software_refs",
    "permitted_delegation_modes",
)


def _check_record_version(version: int) -> None:
    """Both bounds on `record_version`, which exist for unrelated reasons.

    The floor is the resolver's: it is what makes `seen_versions.get(key, 0)`
    a safe default in the rollback check.

    The ceiling is the digest's. `record_version` is serialised into
    `to_document()` as a bare number, and it is the one number in the record
    that does not pass through `canonical.frozen_json` — so the rule that
    module enforces on entitlement values has to be repeated here, or the
    field is a hole in it. Above the exact-integer range of an IEEE 754
    double a record still digests, but the bytes cannot be reproduced by any
    ECMAScript-derived verifier, which is the failure the rule exists to
    prevent.

    Module-level rather than inline in `__post_init__` because they are one
    question about one field, and because the two of them inline push that
    method past ruff's complexity ceiling.
    """
    if version < 1:
        message = f"record_version must be >= 1, got {version}"
        raise ValueError(message)
    if version > MAX_SAFE_INTEGER:
        message = (
            f"record_version {version} exceeds 2**53 - 1 and has no stable "
            "cross-language form in the canonical document"
        )
        raise ValueError(message)


def _frozen_entitlements(value: object) -> Mapping[str, Any]:
    """`canonical.frozen_json` for the one field it is applied to, root typed.

    Split out so `__post_init__` reads as one branch per invariant. The root of
    `provider_entitlements` has to be a mapping — a JSON array there would
    freeze into a tuple perfectly happily and then fail the schema much later,
    at a point that no longer names the field.
    """
    if not isinstance(value, Mapping):
        message = f"provider_entitlements must be a mapping, got {type(value).__name__}"
        raise ValueError(message)  # noqa: TRY004 - the loader catches ValueError, not TypeError
    frozen: Mapping[str, Any] = frozen_json(value, path="provider_entitlements")
    return frozen


@dataclass(frozen=True, kw_only=True, slots=True)
class IssuerAuthority:
    """Which trust domains one `record_issuer` may issue records for.

    Deployment configuration, not a record field. A record naming its own
    authority would be self-certifying: an attacker who could mint a document
    could also mint the claim that they were entitled to. The resolver reads
    this from its own configuration and refuses any issuer it has no entry for,
    which is §6.1 resolution-rule clause 2.
    """

    record_issuer: str
    trust_domains: frozenset[str]

    def may_issue_for(self, trust_domain: str) -> bool:
        """True when this issuer is configured as authoritative for `trust_domain`."""
        return trust_domain in self.trust_domains


@dataclass(frozen=True, kw_only=True, slots=True)
class RegistrationRecordRef:
    """An authenticated reference to one version of one registration record.

    The four fields the RFC names in §6.2's `registration_record_ref` and, in the
    same shape, in §6.3's `parent_delegation_ref`. It lives in this module
    because `record_digest`'s meaning is a §6.1 decision — the ref is only
    checkable because §6.1 fixed what bytes get digested.

    Not yet carried by `AgentRuntimeCredential`; wiring it into the credential is
    §6.2 work.

    Deliberately behaviourless. A `matches(record)` convenience belongs here on
    looks, and was written and then removed: the resolver cannot call it,
    because it checks the same four conditions *separately* in order to report
    which one failed — the difference between `Superseded` and
    `DigestMismatch`. A second implementation of "does this ref name this
    record" with no caller is a second answer waiting to disagree with the
    first, and the only thing testing it would establish is that it agrees with
    itself.
    """

    record_issuer: str
    record_id: str
    record_version: int
    record_digest: str


@dataclass(frozen=True, kw_only=True, slots=True)
class AgentRegistrationRecord:
    """The ODIS §6.1 Agent Registration Record.

    Field order follows the RFC §6.1 table so this file diffs cleanly against
    it, which puts the SHOULD field `provider_entitlements` between
    `permitted_delegation_modes` and `created_at` rather than at the end.

    Timestamps are `datetime`, not ISO strings. The resolver compares
    `valid_until` against the current time on every call, so storing strings
    would push parsing into the enforcement path; and `AgentRuntimeCredential`
    already uses `datetime` for the same reason. ISO form exists in exactly one
    place, `to_document()`. Naive datetimes are refused at construction so an
    aware/naive `TypeError` can never surface inside a resolution.

    The three array fields are `tuple`, not `Sequence`. Not for hashability —
    digesting serialises, it never calls `hash()`. The reason is aliasing: with
    a `Sequence` a caller could pass a list, keep the reference, and mutate the
    record's content out from under a digest already embedded in a §6.2 ref.
    `frozen=True` protects rebinding, not the interior. `provider_entitlements`
    is the same argument at arbitrary depth: it is deep-frozen and validated at
    construction by `canonical.frozen_json`, since a declared type cannot
    describe it — which is also where the rule that numeric entitlement values
    are integers within ±(2**53 - 1) is enforced.

    `slots=True`, so there is deliberately no `cached_property` digest here.
    `Bundle` had to drop slots to memoize; the record's digest is a module-level
    function in `digest.py` instead, mirroring `bundle/digest.py::policy_digest`.
    """

    record_id: str
    record_issuer: str
    schema_version: str
    record_version: int
    agent_id: str
    valid_until: datetime
    lifecycle_state: LifecycleState
    sponsor_ref: str
    owner_ref: str
    approved_runtime_issuers: tuple[str, ...]
    approved_software_refs: tuple[str, ...]
    trust_domain: str
    policy_profile_ref: str
    permitted_delegation_modes: tuple[str, ...]
    #: The one SHOULD field. `None` means the key is omitted from the canonical
    #: document entirely, never serialised as `null`, so a record without
    #: entitlements digests identically to one that never had the key. Anything
    #: else is deep-frozen and checked JSON-representable by `__post_init__`:
    #: this is the only field whose contents the record cannot type, so it is
    #: the only one where "constructs" would not otherwise imply "digests".
    provider_entitlements: Mapping[str, Any] | None = None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        if self.schema_version != RECORD_SCHEMA_VERSION:
            message = (
                f"schema_version {self.schema_version!r} is not {RECORD_SCHEMA_VERSION!r}; "
                "a record of another schema version must be read by that version's type"
            )
            raise ValueError(message)
        if self.lifecycle_state not in _LIFECYCLE_STATES:
            message = (
                f"lifecycle_state {self.lifecycle_state!r} must be one of "
                f"{sorted(_LIFECYCLE_STATES)}"
            )
            raise ValueError(message)
        _check_record_version(self.record_version)
        for field in ("valid_until", "created_at", "updated_at"):
            value: datetime = getattr(self, field)
            if not is_aware(value):
                message = f"{field} must be timezone-aware; got a naive datetime"
                raise ValueError(message)
        if self.updated_at < self.created_at:
            message = (
                f"updated_at {self.updated_at.isoformat()} precedes "
                f"created_at {self.created_at.isoformat()}"
            )
            raise ValueError(message)
        for field in _SEQUENCE_FIELDS:
            sequence = getattr(self, field)
            if not isinstance(sequence, tuple):
                message = (
                    f"{field} must be a tuple, got {type(sequence).__name__}; "
                    "a mutable sequence would let a caller change the record's "
                    "content after its digest was embedded in a reference"
                )
                # ValueError, not TypeError: every other invariant below raises
                # one, and the loader catches `(ValueError, KeyError)` as the
                # shape of "this document was refused". A TypeError here would
                # escape that contract for one field out of sixteen.
                raise ValueError(message)  # noqa: TRY004
        if self.provider_entitlements is not None:
            # `object.__setattr__` is how a frozen dataclass normalises a field
            # in `__post_init__`; it is the only writable moment in the
            # instance's life, which is precisely why the freeze belongs here.
            object.__setattr__(
                self, "provider_entitlements", _frozen_entitlements(self.provider_entitlements)
            )

    def to_document(self) -> dict[str, Any]:
        """The JSON-serialisable projection that canonicalisation serialises.

        Explicit rather than `dataclasses.asdict()` for two reasons.
        `asdict()` cannot serialise the `datetime` fields at all, and it would
        emit `provider_entitlements: null` where the canonical form requires the
        key to be absent. Writing the projection out makes canonicalisation a
        decision rather than an accident.

        Key order here is irrelevant — `canonical_record_bytes` sorts. Fields are
        listed in RFC order anyway so this reads against §6.1.
        """
        document: dict[str, Any] = {
            "record_id": self.record_id,
            "record_issuer": self.record_issuer,
            "schema_version": self.schema_version,
            "record_version": self.record_version,
            "agent_id": self.agent_id,
            "valid_until": canonical_timestamp(self.valid_until),
            "lifecycle_state": self.lifecycle_state,
            "sponsor_ref": self.sponsor_ref,
            "owner_ref": self.owner_ref,
            "approved_runtime_issuers": list(self.approved_runtime_issuers),
            "approved_software_refs": list(self.approved_software_refs),
            "trust_domain": self.trust_domain,
            "policy_profile_ref": self.policy_profile_ref,
            "permitted_delegation_modes": list(self.permitted_delegation_modes),
            "created_at": canonical_timestamp(self.created_at),
            "updated_at": canonical_timestamp(self.updated_at),
        }
        if self.provider_entitlements is not None:
            document["provider_entitlements"] = plain_json(self.provider_entitlements)
        return document

    @classmethod
    def from_document(cls, document: Mapping[str, Any]) -> Self:
        """Rebuild a record from its canonical document.

        Raises `ValueError` or `KeyError` on a document the schema should have
        rejected; the loader converts both into a schema failure so nothing
        escapes its typed contract.

        `from_document(to_document(r)) == r` for every record, which is what
        lets a verifier recompute `record_digest` from a record it resolved
        independently rather than from bytes an attacker supplied.

        Nothing is validated here beyond the shape needed to call the
        constructor. `provider_entitlements` in particular is passed through
        untouched: `__post_init__` reaches `_frozen_entitlements` for any
        non-`None` value, which refuses a non-mapping root with a `ValueError`
        naming the field. Re-checking it here would be a second, weaker copy of
        that rule — weaker because it would test `dict` where the field is typed
        `Mapping` — and a copy that can drift is worse than the trip through the
        constructor it saves.
        """
        return cls(
            record_id=document["record_id"],
            record_issuer=document["record_issuer"],
            schema_version=document["schema_version"],
            record_version=document["record_version"],
            agent_id=document["agent_id"],
            valid_until=parse_timestamp(document["valid_until"], field="valid_until"),
            lifecycle_state=document["lifecycle_state"],
            sponsor_ref=document["sponsor_ref"],
            owner_ref=document["owner_ref"],
            approved_runtime_issuers=tuple(document["approved_runtime_issuers"]),
            approved_software_refs=tuple(document["approved_software_refs"]),
            trust_domain=document["trust_domain"],
            policy_profile_ref=document["policy_profile_ref"],
            permitted_delegation_modes=tuple(document["permitted_delegation_modes"]),
            provider_entitlements=document.get("provider_entitlements"),
            created_at=parse_timestamp(document["created_at"], field="created_at"),
            updated_at=parse_timestamp(document["updated_at"], field="updated_at"),
        )

    def to_ref(self) -> RegistrationRecordRef:
        """The authenticated reference a §6.2 credential would carry to this record."""
        from odis_harness.registration.digest import record_digest  # noqa: PLC0415

        return RegistrationRecordRef(
            record_issuer=self.record_issuer,
            record_id=self.record_id,
            record_version=self.record_version,
            record_digest=record_digest(self),
        )

    def is_usable(self) -> bool:
        """True when the lifecycle state permits this record to back a request.

        Only a lifecycle check. Freshness, rollback, and issuer authority are the
        resolver's, because they need a clock and deployment configuration this
        record deliberately does not carry.
        """
        return self.lifecycle_state in _USABLE_LIFECYCLE_STATES


__all__ = [
    "RECORD_SCHEMA_VERSION",
    "AgentRegistrationRecord",
    "IssuerAuthority",
    "LifecycleState",
    "RegistrationRecordRef",
]
