"""The §6.1 resolution rule, clauses 2 through 6.

One test per fail-closed branch, each asserting the *specific* exception rather
than the base. A test that only asserted `RegistrationResolutionError` would
still pass if two branches were accidentally collapsed into one, and the
distinction between "this record is stale" and "this record was tampered with"
is the whole reason the leaves exist.

Clause 1 is discharged in `loader.py` and tested in `test_loader.py`. Nothing
here revisits it. Two checks in `resolve` look like they might and do not: the
ref's digest commitment is §6.2's and §6.3's, and the store-identity check
guards against a substituted store. Both are covered below under their own
headings rather than under clause 1's.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import pytest

from odis_harness.registration.errors import (
    IssuerNotAuthorized,
    RegistrationRecordDigestMismatch,
    RegistrationRecordExpired,
    RegistrationRecordNotActive,
    RegistrationRecordRollback,
    RegistrationRecordSuperseded,
    RegistrationRecordUnavailable,
    RegistrationResolutionError,
)
from odis_harness.registration.fixtures import (
    _FIXTURE_NOW,
    InMemoryRegistrationRecordStore,
    fixture_registration_record,
    registration_fixture_stack,
)
from odis_harness.registration.resolver import AuthoritativeRegistrationRecordResolver
from odis_harness.registration.types import IssuerAuthority

if TYPE_CHECKING:
    from odis_harness.registration.types import AgentRegistrationRecord

_ISSUER = "registry.example"
_TRUST_DOMAIN = "trust.example"


def _authorities(
    *, record_issuer: str = _ISSUER, trust_domains: frozenset[str] | None = None
) -> dict[str, IssuerAuthority]:
    return {
        record_issuer: IssuerAuthority(
            record_issuer=record_issuer,
            trust_domains=trust_domains
            if trust_domains is not None
            else frozenset({_TRUST_DOMAIN}),
        )
    }


def _stack_with(
    record: AgentRegistrationRecord,
    *,
    authorities: dict[str, IssuerAuthority] | None = None,
) -> tuple[InMemoryRegistrationRecordStore, AuthoritativeRegistrationRecordResolver]:
    """A store holding `record` and a resolver over it, on a pinned clock.

    The clock is `_FIXTURE_NOW` for the same reason `registration_fixture_stack`
    pins it: the fixture record expires on 2027-01-01, the expiry check runs
    *before* the lifecycle and rollback checks, and a resolver left on the wall
    clock would start answering `RegistrationRecordExpired` to every test built
    on this helper on that date — for a reason having nothing to do with what
    any of them asserts. The three tests that are actually about expiry build
    their own resolvers with an explicit `now`.
    """
    store = InMemoryRegistrationRecordStore()
    store.put(record)
    resolver = AuthoritativeRegistrationRecordResolver(
        store=store,
        authorities=authorities if authorities is not None else _authorities(),
        now=lambda: _FIXTURE_NOW,
    )
    return store, resolver


# --------------------------------------------------------------------------
# Happy path
# --------------------------------------------------------------------------


def test_a_matching_ref_resolves_to_its_record() -> None:
    _store, resolver, record = registration_fixture_stack()
    assert resolver.resolve(record.to_ref()) == record


def test_a_successful_resolution_advances_the_high_water_mark() -> None:
    """Clause 5's state. Without this the rollback check would have nothing to
    compare against, because the mark is only ever raised by a resolution that
    succeeded."""
    _store, resolver, record = registration_fixture_stack()
    assert resolver.seen_versions == {}
    resolver.resolve(record.to_ref())
    assert resolver.seen_versions == {(record.record_issuer, record.agent_id): 1}


def test_resolving_the_same_ref_twice_is_not_a_rollback() -> None:
    """The mark is a floor, not a strict ratchet: re-presenting the version
    already seen is the ordinary case, not an attack."""
    _store, resolver, record = registration_fixture_stack()
    ref = record.to_ref()
    assert resolver.resolve(ref) == resolver.resolve(ref)


# --------------------------------------------------------------------------
# Clause 2 — issuer authority
# --------------------------------------------------------------------------


def test_an_issuer_with_no_configured_authority_is_refused() -> None:
    """An unconfigured issuer is refused, not trusted by default. This is the
    difference between a deployment that has not been told about an issuer and
    one that has been told to accept it."""
    record = fixture_registration_record()
    _store, resolver = _stack_with(record, authorities={})
    with pytest.raises(IssuerNotAuthorized, match="no configured authority"):
        resolver.resolve(record.to_ref())


def test_an_unconfigured_issuer_is_refused_before_the_store_is_consulted() -> None:
    """Ordering, not decoration: an issuer with no authority should not be able
    to cause a lookup, or an unconfigured name becomes a probe of what the
    store holds."""

    class RecordingStore:
        """One method, which is the whole `RegistrationRecordStore` Protocol.

        `current` and `revoke` live on `RegistrationRecordLifecycleStore`, so a
        read-only store is a legal substitution here. That this double compiles
        and resolves is the check that the split is real.
        """

        def __init__(self) -> None:
            self.lookups: list[str] = []

        def by_id(self, *, record_issuer: str, record_id: str) -> None:
            self.lookups.append(record_id)

    store = RecordingStore()
    resolver = AuthoritativeRegistrationRecordResolver(store=store, authorities={})
    with pytest.raises(IssuerNotAuthorized):
        resolver.resolve(fixture_registration_record().to_ref())
    assert store.lookups == []


def test_an_issuer_outside_its_trust_domains_is_refused() -> None:
    """The authority is per trust domain, and the trust domain is a property of
    the record, so this can only be checked once the record is in hand."""
    record = fixture_registration_record(trust_domain="other.example")
    _store, resolver = _stack_with(
        record, authorities=_authorities(trust_domains=frozenset({_TRUST_DOMAIN}))
    )
    with pytest.raises(IssuerNotAuthorized, match="not authoritative for trust domain"):
        resolver.resolve(record.to_ref())


def test_an_issuer_authoritative_for_several_domains_resolves_each() -> None:
    authorities = _authorities(trust_domains=frozenset({_TRUST_DOMAIN, "other.example"}))
    for domain in (_TRUST_DOMAIN, "other.example"):
        record = fixture_registration_record(trust_domain=domain)
        _store, resolver = _stack_with(record, authorities=authorities)
        assert resolver.resolve(record.to_ref()).trust_domain == domain


# --------------------------------------------------------------------------
# Clause 6 — fail closed when unavailable or indeterminate
# --------------------------------------------------------------------------


def test_an_absent_record_is_refused() -> None:
    resolver = AuthoritativeRegistrationRecordResolver(
        store=InMemoryRegistrationRecordStore(), authorities=_authorities()
    )
    with pytest.raises(RegistrationRecordUnavailable, match="no registration record"):
        resolver.resolve(fixture_registration_record().to_ref())


def test_a_store_that_raises_becomes_unavailable_not_the_underlying_error() -> None:
    """"The store broke" and "the store said no" are the same answer to a
    caller: indeterminate. Letting the underlying exception escape would leave
    the typed contract and put the fail-closed decision on every caller."""

    class BrokenStore:
        def by_id(self, *, record_issuer: str, record_id: str) -> None:
            message = "connection reset"
            raise ConnectionError(message)

    resolver = AuthoritativeRegistrationRecordResolver(
        store=BrokenStore(), authorities=_authorities()
    )
    with pytest.raises(RegistrationRecordUnavailable, match="could not be resolved"):
        resolver.resolve(fixture_registration_record().to_ref())


def test_the_underlying_store_failure_is_preserved_as_the_cause() -> None:
    """Fail closed, but not silently: an operator needs to tell a missing
    record from a broken store."""

    class BrokenStore:
        def by_id(self, *, record_issuer: str, record_id: str) -> None:
            message = "connection reset"
            raise ConnectionError(message)

    resolver = AuthoritativeRegistrationRecordResolver(
        store=BrokenStore(), authorities=_authorities()
    )
    with pytest.raises(RegistrationRecordUnavailable) as caught:
        resolver.resolve(fixture_registration_record().to_ref())
    assert isinstance(caught.value.__cause__, ConnectionError)


@pytest.mark.parametrize(
    ("returned_id", "returned_issuer"),
    [
        pytest.param("reg-somebody-else", _ISSUER, id="wrong-record-id"),
        pytest.param("reg-agent-alpha", "other.example", id="wrong-issuer"),
    ],
)
def test_a_store_answering_with_a_different_record_is_refused(
    returned_id: str, returned_issuer: str
) -> None:
    """`RegistrationRecordStore` is a Protocol a deployment substitutes, so "the
    store returns the record you asked for" is an assumption about someone
    else's code.

    Worth its own branch because *no other check catches it*. The digest is
    recomputed from whatever came back, so it agrees with itself; the version
    and trust-domain checks read the substituted record too. Every downstream
    clause would be evaluated against a subject the caller never named, and
    resolution would succeed.
    """

    class SubstitutingStore:
        def by_id(self, *, record_issuer: str, record_id: str) -> AgentRegistrationRecord:
            return replace(
                fixture_registration_record(),
                record_id=returned_id,
                record_issuer=returned_issuer,
            )

    resolver = AuthoritativeRegistrationRecordResolver(
        store=SubstitutingStore(),
        authorities={**_authorities(), **_authorities(record_issuer="other.example")},
    )
    with pytest.raises(RegistrationRecordUnavailable, match="store returned record"):
        resolver.resolve(fixture_registration_record().to_ref())


# --------------------------------------------------------------------------
# Clause 3 — superseded
# --------------------------------------------------------------------------


def test_a_ref_to_a_superseded_version_is_refused() -> None:
    record = fixture_registration_record()
    stale_ref = record.to_ref()
    store, resolver = _stack_with(record)
    store.put(replace(record, record_version=2))
    with pytest.raises(RegistrationRecordSuperseded, match="is at version 2"):
        resolver.resolve(stale_ref)


def test_a_ref_ahead_of_the_store_is_also_superseded() -> None:
    """A ref naming a version the store has never held is refused on the same
    branch. The store is authoritative for what "current" means, so "ahead" is
    not a privileged direction."""
    record = fixture_registration_record()
    _store, resolver = _stack_with(record)
    with pytest.raises(RegistrationRecordSuperseded):
        resolver.resolve(replace(record.to_ref(), record_version=9))


# --------------------------------------------------------------------------
# The ref's digest commitment — not a §6.1 clause; §6.2's and §6.3's, enforced
# here because this is where a ref meets a record
# --------------------------------------------------------------------------


def test_a_ref_whose_digest_does_not_match_is_refused() -> None:
    """Distinct from superseded: the versions agree and the content does not,
    which is tampering rather than staleness."""
    record = fixture_registration_record()
    _store, resolver = _stack_with(record)
    with pytest.raises(RegistrationRecordDigestMismatch, match="does not match"):
        resolver.resolve(replace(record.to_ref(), record_digest="0" * 64))


def test_content_altered_at_the_same_version_is_caught_by_the_digest() -> None:
    """The case superseded cannot catch. A store returning a record whose owner
    was changed without a version bump passes the equality check and fails
    here — which is why the digest check runs even after versions agree."""
    record = fixture_registration_record()
    ref = record.to_ref()
    store, resolver = _stack_with(record)
    store.put(replace(record, owner_ref="team:attacker"))
    with pytest.raises(RegistrationRecordDigestMismatch):
        resolver.resolve(ref)


def test_superseded_wins_over_digest_mismatch() -> None:
    """Both are true when a newer version exists — the digest necessarily
    disagrees too. "Superseded" is the more useful answer, so it is checked
    first."""
    record = fixture_registration_record()
    stale_ref = record.to_ref()
    store, resolver = _stack_with(record)
    store.put(replace(record, record_version=2, owner_ref="team:other"))
    with pytest.raises(RegistrationRecordSuperseded):
        resolver.resolve(stale_ref)


# --------------------------------------------------------------------------
# Clause 5 — rollback
# --------------------------------------------------------------------------


def test_a_version_older_than_one_already_seen_is_refused() -> None:
    """Resolve v3, then present v2 as though it were current. Version equality
    cannot catch this — the store agrees v2 is current — so only the high-water
    mark does."""
    record = fixture_registration_record()
    v3 = replace(record, record_version=3)
    store, resolver = _stack_with(v3)
    assert resolver.resolve(v3.to_ref()).record_version == 3

    v2 = replace(record, record_version=2)
    store.put(v2)
    with pytest.raises(RegistrationRecordRollback, match="version 3 was already seen"):
        resolver.resolve(v2.to_ref())


def test_the_high_water_mark_is_per_agent_not_per_record_id() -> None:
    """Re-issuing under a fresh `record_id` must not reset the mark, or
    rollback protection would be defeated by renaming the record."""
    record = fixture_registration_record()
    v3 = replace(record, record_version=3)
    store, resolver = _stack_with(v3)
    resolver.resolve(v3.to_ref())

    reissued = replace(record, record_id="reg-fresh", record_version=2)
    store.put(reissued)
    with pytest.raises(RegistrationRecordRollback):
        resolver.resolve(reissued.to_ref())


def test_the_high_water_mark_does_not_leak_between_agents() -> None:
    """Keyed by `(issuer, agent_id)`. A busy agent at v9 must not make a newly
    registered agent's v1 look like a rollback."""
    busy = replace(fixture_registration_record(agent_id="agent-busy"), record_version=9)
    fresh = fixture_registration_record(agent_id="agent-fresh")
    store, resolver = _stack_with(busy)
    store.put(fresh)
    resolver.resolve(busy.to_ref())
    assert resolver.resolve(fresh.to_ref()) == fresh


def test_the_high_water_mark_does_not_leak_between_issuers() -> None:
    record = fixture_registration_record()
    v9 = replace(record, record_version=9)
    other = replace(record, record_issuer="other.example")
    store, resolver = _stack_with(
        v9,
        authorities={**_authorities(), **_authorities(record_issuer="other.example")},
    )
    store.put(other)
    resolver.resolve(v9.to_ref())
    assert resolver.resolve(other.to_ref()) == other


def test_a_rolled_back_resolution_does_not_lower_the_mark() -> None:
    """A refusal must not become a downgrade: if the mark fell to the rejected
    version, the same v2 would resolve on a second attempt."""
    record = fixture_registration_record()
    v3 = replace(record, record_version=3)
    store, resolver = _stack_with(v3)
    resolver.resolve(v3.to_ref())
    v2 = replace(record, record_version=2)
    store.put(v2)
    for _ in range(2):
        with pytest.raises(RegistrationRecordRollback):
            resolver.resolve(v2.to_ref())
    assert resolver.seen_versions[(record.record_issuer, record.agent_id)] == 3


# --------------------------------------------------------------------------
# Clause 4 — valid_until
# --------------------------------------------------------------------------


def test_an_expired_record_is_refused() -> None:
    record = fixture_registration_record()
    store = InMemoryRegistrationRecordStore()
    store.put(record)
    resolver = AuthoritativeRegistrationRecordResolver(
        store=store,
        authorities=_authorities(),
        now=lambda: record.valid_until + timedelta(seconds=1),
    )
    with pytest.raises(RegistrationRecordExpired, match="was valid until"):
        resolver.resolve(record.to_ref())


def test_the_boundary_instant_itself_is_refused() -> None:
    """`>=`, not `>`, which is one microsecond stricter than §6.1.

    The RFC calls `valid_until` the *latest* time the version may be treated as
    current, which reads inclusive — so this instant is inside the window the
    RFC grants, and refusing it is a choice made on clause 6's grounds rather
    than a consequence of the wording. Pinned as a test because a later reader
    finding `>=` and assuming it a typo would "fix" it and silently widen the
    window; the clock is injected so the boundary can be asserted rather than
    raced.
    """
    record = fixture_registration_record()
    store = InMemoryRegistrationRecordStore()
    store.put(record)
    resolver = AuthoritativeRegistrationRecordResolver(
        store=store, authorities=_authorities(), now=lambda: record.valid_until
    )
    with pytest.raises(RegistrationRecordExpired):
        resolver.resolve(record.to_ref())


def test_one_microsecond_before_the_boundary_still_resolves() -> None:
    """The other side of the same edge, so the test above is pinning a boundary
    rather than an off-by-a-lot."""
    record = fixture_registration_record()
    store = InMemoryRegistrationRecordStore()
    store.put(record)
    resolver = AuthoritativeRegistrationRecordResolver(
        store=store,
        authorities=_authorities(),
        now=lambda: record.valid_until - timedelta(microseconds=1),
    )
    assert resolver.resolve(record.to_ref()) == record


def test_the_default_clock_is_utc_aware() -> None:
    """A naive default would raise `TypeError` inside `resolve` on the first
    comparison — an untyped escape from a fail-closed path."""
    resolver = AuthoritativeRegistrationRecordResolver(
        store=InMemoryRegistrationRecordStore(), authorities=_authorities()
    )
    assert resolver.now().tzinfo is not None
    assert resolver.now().utcoffset() == datetime.now(UTC).utcoffset()


# --------------------------------------------------------------------------
# §6.2's clarifying rule — the record must be active
# --------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["suspended", "revoked", "pending"])
def test_a_record_that_is_not_active_is_refused(state: str) -> None:
    """§6.2: a credential MUST resolve to an *active* record. `pending` has not
    been admitted, `suspended` was withdrawn, `revoked` is terminal — all three
    are genuine records that may not back a live request."""
    record = fixture_registration_record(lifecycle_state=state)  # type: ignore[arg-type]
    _store, resolver = _stack_with(record)
    with pytest.raises(RegistrationRecordNotActive, match=state):
        resolver.resolve(record.to_ref())


def test_an_inactive_record_does_not_advance_the_high_water_mark() -> None:
    """The mark records versions that were *accepted*. Advancing it on a
    refusal would let a revoked v5 block a legitimate v4 rollback fix."""
    record = replace(
        fixture_registration_record(lifecycle_state="revoked"), record_version=5
    )
    _store, resolver = _stack_with(record)
    with pytest.raises(RegistrationRecordNotActive):
        resolver.resolve(record.to_ref())
    assert resolver.seen_versions == {}


def test_a_credential_ref_outstanding_at_revocation_is_refused_as_superseded() -> None:
    """What `revoke()`'s version bump actually buys, pinned as behaviour.

    A credential minted before revocation carries a ref naming the
    pre-revocation version. After `revoke()` the store answers one version
    higher, so the ref fails the *supersession* check — and fails it before the
    lifecycle check ever runs, which is why the answer is
    `RegistrationRecordSuperseded` and not `RegistrationRecordNotActive`.

    The negative half is the point of the test. `revoke()`'s docstring used to
    claim the bump stopped the revocation being "rolled back past a resolver's
    high-water mark"; it does not, and cannot, because the mark advances only on
    an accepted record and a revoked one never gets that far. Asserting the
    absence of `RegistrationRecordRollback` here is what keeps the corrected
    docstring honest: if someone later moves the mark update above the lifecycle
    check to make the old claim true, this test fails and
    `test_an_inactive_record_does_not_advance_the_high_water_mark` fails with it.
    """
    record = fixture_registration_record()
    outstanding_ref = record.to_ref()
    store, resolver = _stack_with(record)

    revoked = store.revoke(
        record_issuer=record.record_issuer,
        agent_id=record.agent_id,
        at=record.created_at,
    )
    assert revoked.lifecycle_state == "revoked"
    assert revoked.record_version == record.record_version + 1

    with pytest.raises(RegistrationRecordSuperseded, match="is at version 2"):
        resolver.resolve(outstanding_ref)
    # Not rollback, and no mark: the refusal left no state behind.
    assert resolver.seen_versions == {}

    # And the revoked record cannot be resolved on its own fresh ref either —
    # that is the branch the lifecycle check owns. The second assertion is what
    # makes this test the tripwire the docstring claims: without it, moving the
    # mark update above the lifecycle check would leave this test passing.
    with pytest.raises(RegistrationRecordNotActive):
        resolver.resolve(revoked.to_ref())
    assert resolver.seen_versions == {}


# --------------------------------------------------------------------------
# The family
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "leaf",
    [
        IssuerNotAuthorized,
        RegistrationRecordDigestMismatch,
        RegistrationRecordExpired,
        RegistrationRecordNotActive,
        RegistrationRecordRollback,
        RegistrationRecordSuperseded,
        RegistrationRecordUnavailable,
    ],
)
def test_every_resolution_failure_shares_one_base(leaf: type[Exception]) -> None:
    """A caller that only needs "resolution failed" catches the base. If a leaf
    escaped the family, that caller would fail open on it."""
    assert issubclass(leaf, RegistrationResolutionError)
