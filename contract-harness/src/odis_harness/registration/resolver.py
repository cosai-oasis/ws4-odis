"""Resolving an authenticated reference to a usable §6.1 registration record.

§6.1's resolution rule has six clauses. **Clause 1 — authenticate
`record_issuer` and the record's integrity protection — is discharged in
`loader.py`, not here.** The split is the same one `BundleLoader` and `Router`
already use: signature and structure at load, authority and freshness at
resolve. A reader looking only at this module would conclude clause 1 is
skipped, which is why both docstrings say so.

What this module enforces:

| # | Clause | Status | Mechanism |
|---|---|---|---|
| 2 | issuer authorized for the trust domain | satisfied | `IssuerAuthority`; an
  unconfigured issuer is refused outright |
| 3 | reject stale or superseded versions | partial | the ref's
  `record_version` must equal the version the store returns for that
  `record_id`, so a ref outlives its record version by exactly zero updates.
  What is *not* enforced: the store is asked for one record id, so a
  supersession that arrives as a new `record_id` is invisible here, and
  cross-authority supersession needs a revocation feed either way |
| 4 | enforce `valid_until` | satisfied | injected clock; the boundary instant
  itself is refused, which is deliberately one microsecond stricter than the
  RFC's wording — see `resolve` |
| 5 | detect rollback via `record_version` | satisfied | per-`(issuer,
  agent_id)` high-water mark. Three bounds worth stating: it is process-local,
  so it does not survive a restart; it is per *issuer*, so if two issuers are
  authoritative for one trust domain, an old version replayed under the second
  issuer meets a mark of its own; and it advances only on an *accepted* record,
  so a version that was refused — expired, revoked, digest-mismatched — leaves
  no mark behind. The third is deliberate rather than incidental: advancing on a
  refusal would let a revoked v5 permanently block a legitimate v4 rollback fix,
  and it is what makes `revoke()`'s version bump a supersession mechanism rather
  than a rollback one. The first two close with the durable revocation feed |
| 6 | fail closed when unavailable or indeterminate | satisfied | every path
  raises under `RegistrationResolutionError` |
| — | the ref's digest commitment | satisfied | not a §6.1 clause: §6.1 describes
  a record, not a reference to one. The check belongs to §6.2 and §6.3, whose
  refs carry a `record_digest`, and it is enforced here because this is where a
  ref meets a record. Do not read it as a second attempt at clause 1 — the
  loader already authenticated whatever it loaded; this asks a different
  question, whether the record the *store* returned is the one the ref was
  issued against |
| — | the store answered about the record it was asked for | satisfied |
  likewise not a clause. `RegistrationRecordStore` is substitutable, so `_fetch`
  re-checks identity; nothing else would catch a substitution |

Resolution is by authenticated *ref*, never by bare `agent_id`. §6.2 says a
runtime credential MUST resolve to an active registration record, and the
credential carries a ref — so a `resolve(agent_id)` overload would offer a path
that skips the digest commitment, which is the only thing tying the record a
verifier found to the record the credential was issued against.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from odis_harness.registration.digest import record_digest
from odis_harness.registration.errors import (
    IssuerNotAuthorized,
    RegistrationRecordDigestMismatch,
    RegistrationRecordExpired,
    RegistrationRecordNotActive,
    RegistrationRecordRollback,
    RegistrationRecordSuperseded,
    RegistrationRecordUnavailable,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from odis_harness.registration.types import (
        AgentRegistrationRecord,
        IssuerAuthority,
        RegistrationRecordRef,
    )


def _utcnow() -> datetime:
    return datetime.now(UTC)


class RegistrationRecordStore(Protocol):
    """Where authoritative registration records are read from.

    One method, because the resolver calls one method. A Protocol carrying
    anything the resolver does not call would overstate what a substituted store
    has to implement, and — worse — would let this module's docstrings describe
    behaviour no caller ever reaches.

    `None` for "not found" rather than raising, deliberately: converting absence
    into a refusal is the resolver's job, so §6.1's fail-closed clause is
    implemented once instead of being re-derived by every store a deployment
    substitutes.
    """

    def by_id(
        self, *, record_issuer: str, record_id: str
    ) -> AgentRegistrationRecord | None: ...


class RegistrationRecordLifecycleStore(RegistrationRecordStore, Protocol):
    """A store that can also be read and written by agent, not just by record id.

    Separate from `RegistrationRecordStore` because the two have different
    consumers and different conformance weight. The resolver needs only
    `by_id`; §6.1 lifecycle management — which is what `ODIS-L3-05` clause 1 is
    about — needs to find an agent's current record and replace it.

    `revoke` is on the Protocol rather than only on the in-memory fixture
    because `ODIS-L3-05` is claimed `partial` on the strength of that operation
    existing and being single. A claim resting on a method that only the test
    double has is a claim about the test double. Declaring it here is what makes
    "a deployment can substitute a real directory and keep the property" a
    checkable statement.

    Deliberately *not* extended to cover propagation. `revoke` changes the
    record; nothing here reaches an active session or a cached token, which is
    clause 2 and stays a gap.
    """

    def current(
        self, *, record_issuer: str, agent_id: str
    ) -> AgentRegistrationRecord | None: ...

    def revoke(
        self, *, record_issuer: str, agent_id: str, at: datetime | None = None
    ) -> AgentRegistrationRecord: ...


class RegistrationRecordResolver(Protocol):
    """Turns an authenticated reference into a record that may back a request.

    One method, and it either returns a usable record or raises. There is no
    "resolved but unusable" return value, because a caller holding one would
    have to remember to check.
    """

    def resolve(self, ref: RegistrationRecordRef) -> AgentRegistrationRecord: ...


@dataclass(frozen=True, kw_only=True, slots=True)
class AuthoritativeRegistrationRecordResolver:
    """The §6.1 resolution rule, clauses 2 through 6."""

    store: RegistrationRecordStore
    #: Deployment configuration, keyed by `record_issuer`. An issuer absent from
    #: this map has no authority at all, which is a refusal rather than a
    #: permissive default.
    authorities: Mapping[str, IssuerAuthority]
    #: Per-`(issuer, agent_id)` high-water mark for `record_version`. Mutated in
    #: place: `frozen` forbids rebinding the attribute, not mutating the dict it
    #: points at — the `VaultTransitSignatureVerifier.public_keys` precedent.
    #: Process-local, so it does not survive a restart; a durable mark is
    #: revocation-feed work.
    seen_versions: dict[tuple[str, str], int] = field(default_factory=dict)
    #: Injected so a test can place `now` exactly on `valid_until` rather than
    #: racing it.
    now: Callable[[], datetime] = _utcnow

    def _fetch(self, ref: RegistrationRecordRef) -> AgentRegistrationRecord:
        """The record `ref` names, or `RegistrationRecordUnavailable`. §6.1 clause 6.

        Three ways the store can fail to produce a usable answer, and clause 6
        treats them alike — "unavailable or indeterminate" is one outcome, not
        three. Separated from `resolve` so that the caller sees one step for
        "get the record" and the reasons a store can disappoint live together.

        The third is the one worth naming. `RegistrationRecordStore` is a
        Protocol a deployment substitutes, so "`by_id` returns the record you
        asked for" is an assumption about someone else's code. A store that
        answers with a *different* record hands every check in `resolve` a
        subject the caller never named, and the digest check would not catch it
        — the digest is recomputed from whatever came back, so it would agree
        with itself.
        """
        try:
            record = self.store.by_id(record_issuer=ref.record_issuer, record_id=ref.record_id)
        # Bare `Exception` on purpose: §6.1 requires failing closed on an
        # indeterminate answer, and a store substituted by a deployment can
        # fail in ways this module cannot enumerate.
        except Exception as exc:
            message = f"registration record {ref.record_id!r} could not be resolved: {exc}"
            raise RegistrationRecordUnavailable(message) from exc
        if record is None:
            message = f"no registration record {ref.record_id!r} from issuer {ref.record_issuer!r}"
            raise RegistrationRecordUnavailable(message)
        if (record.record_issuer, record.record_id) != (ref.record_issuer, ref.record_id):
            message = (
                f"store returned record {record.record_id!r} from issuer "
                f"{record.record_issuer!r} for a reference naming {ref.record_id!r} from "
                f"{ref.record_issuer!r}"
            )
            raise RegistrationRecordUnavailable(message)
        return record

    def resolve(self, ref: RegistrationRecordRef) -> AgentRegistrationRecord:
        """Return the record `ref` names, or raise.

        Checks run in a fixed order so the exception identifies the most
        specific failure. Version equality is checked before the digest: if a
        newer version exists, "superseded" is the useful answer, and the digest
        would disagree anyway for a reason that says less. The digest check
        still runs afterwards, which is what catches a same-version record whose
        content was altered after it was loaded.

        Raises:
            IssuerNotAuthorized: the issuer has no configured authority, or none
                covering the record's trust domain.
            RegistrationRecordUnavailable: the store has no such record, failed,
                or answered with a record the ref does not name.
            RegistrationRecordSuperseded: a newer version is current.
            RegistrationRecordDigestMismatch: the content is not what the ref
                committed to.
            RegistrationRecordRollback: an older version than one already seen.
            RegistrationRecordExpired: `valid_until` has passed.
            RegistrationRecordNotActive: the lifecycle state forbids use.
        """
        # 2. Issuer authority. First, because an issuer with no configured
        #    authority should not cause a store lookup at all.
        authority = self.authorities.get(ref.record_issuer)
        if authority is None:
            message = (
                f"record_issuer {ref.record_issuer!r} has no configured authority; "
                "an unconfigured issuer is refused, not trusted by default"
            )
            raise IssuerNotAuthorized(message)

        # 6. Fail closed when authoritative resolution is unavailable.
        record = self._fetch(ref)

        # 2 (cont). The authority is per trust domain, and the trust domain is a
        #    property of the record, so it can only be checked once the record
        #    is in hand.
        if not authority.may_issue_for(record.trust_domain):
            message = (
                f"issuer {ref.record_issuer!r} is not authoritative for trust domain "
                f"{record.trust_domain!r}"
            )
            raise IssuerNotAuthorized(message)

        # 3. Superseded.
        if record.record_version != ref.record_version:
            message = (
                f"registration record {ref.record_id!r} is at version "
                f"{record.record_version}; the reference names {ref.record_version}"
            )
            raise RegistrationRecordSuperseded(message)

        # The ref's digest commitment. Not a §6.1 clause — clause 1 is
        # discharged in the loader, which proved these bytes were signed. This
        # asks the §6.2/§6.3 question instead: is the record the *store*
        # returned the one the reference was issued against?
        actual_digest = record_digest(record)
        if actual_digest != ref.record_digest:
            message = (
                f"registration record {ref.record_id!r} digest {actual_digest} does not "
                f"match the reference's {ref.record_digest}"
            )
            raise RegistrationRecordDigestMismatch(message)

        # 5. Rollback. The high-water mark is per agent, not per record id, so
        #    re-issuing under a fresh record_id cannot reset it.
        key = (record.record_issuer, record.agent_id)
        highest_seen = self.seen_versions.get(key, 0)
        if record.record_version < highest_seen:
            message = (
                f"registration record for {record.agent_id!r} is at version "
                f"{record.record_version}; version {highest_seen} was already seen"
            )
            raise RegistrationRecordRollback(message)

        # 4. valid_until. `>=` rather than `>`, which is one microsecond
        #    stricter than the RFC. §6.1 defines the field as the *latest* time
        #    the version may be treated as current, and that reads inclusive —
        #    so the boundary instant is inside the window the RFC grants, and
        #    refusing it is a deliberate choice rather than the wording's
        #    consequence. The choice follows from clause 6: an issuer and a
        #    resolver with skewed clocks disagree about exactly one instant,
        #    and clause 6 says an indeterminate answer fails closed.
        current_time = self.now()
        if current_time >= record.valid_until:
            message = (
                f"registration record {ref.record_id!r} was valid until "
                f"{record.valid_until.isoformat()}; it is now {current_time.isoformat()}"
            )
            raise RegistrationRecordExpired(message)

        # §6.2's clarifying rule: Layer 2 needs an *active* record.
        if not record.is_usable():
            message = (
                f"registration record {ref.record_id!r} is {record.lifecycle_state!r}, "
                "not active"
            )
            raise RegistrationRecordNotActive(message)

        self.seen_versions[key] = record.record_version
        return record


__all__ = [
    "AuthoritativeRegistrationRecordResolver",
    "RegistrationRecordLifecycleStore",
    "RegistrationRecordResolver",
    "RegistrationRecordStore",
]
