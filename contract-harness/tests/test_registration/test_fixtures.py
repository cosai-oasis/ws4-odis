"""The in-memory store, its `revoke` operation, and the governed issuer.

`revoke` is the `ODIS-L3-05` clause-1 mechanism — "immediate global
de-provisioning through a single operation" — so its behaviour is pinned here
rather than only where the conformance test exercises it.

`FixtureRegistrationRecordIssuer`'s three rules are the `ODIS-CC-05` mechanism.
They get their full coverage here precisely because the requirement is *not*
claimed: `requested_by` is unauthenticated, so the rules are real code with an
open hole above them, and the honest place to test real code is its own unit
test rather than a conformance assertion that would read as a claim.
"""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from odis_harness.registration.errors import (
    RegistrationRecordNotActive,
    RegistrationRecordSuperseded,
    RegistrationWriteRefused,
)
from odis_harness.registration.fixtures import (
    FixtureRegistrationRecordIssuer,
    InMemoryRegistrationRecordStore,
    fixture_registration_record,
    registration_fixture_stack,
)

_ISSUER = "registry.example"


@pytest.fixture
def store() -> InMemoryRegistrationRecordStore:
    return InMemoryRegistrationRecordStore()


# --------------------------------------------------------------------------
# Store
# --------------------------------------------------------------------------


def test_a_stored_record_round_trips_by_id(store: InMemoryRegistrationRecordStore) -> None:
    record = fixture_registration_record()
    store.put(record)
    assert store.by_id(record_issuer=record.record_issuer, record_id=record.record_id) == record


def test_a_stored_record_round_trips_by_agent(store: InMemoryRegistrationRecordStore) -> None:
    record = fixture_registration_record()
    store.put(record)
    assert store.current(record_issuer=record.record_issuer, agent_id=record.agent_id) == record


def test_an_absent_record_is_none_not_an_exception(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """Absence is not the store's decision to refuse. Converting it into a
    refusal is the resolver's job, so fail-closed lives in one place instead of
    being re-derived by every store a deployment substitutes."""
    assert store.by_id(record_issuer=_ISSUER, record_id="reg-missing") is None
    assert store.current(record_issuer=_ISSUER, agent_id="agent-missing") is None


def test_a_record_id_from_another_issuer_is_not_found(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """`record_id` is scoped by issuer, not global. Two registries may both
    name a record `reg-agent-alpha` without either shadowing the other."""
    record = fixture_registration_record()
    store.put(record)
    assert store.by_id(record_issuer="other.example", record_id=record.record_id) is None


def test_put_replaces_the_current_version(store: InMemoryRegistrationRecordStore) -> None:
    record = fixture_registration_record()
    store.put(record)
    store.put(replace(record, record_version=2))
    current = store.current(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert current is not None
    assert current.record_version == 2


def test_two_issuers_may_hold_records_for_the_same_agent_id(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """The key is `(record_issuer, agent_id)`. Nothing in §6.1 makes `agent_id`
    globally unique, so a store that collapsed the two would silently drop a
    record."""
    mine = fixture_registration_record()
    theirs = replace(mine, record_issuer="other.example", owner_ref="team:other")
    store.put(mine)
    store.put(theirs)
    assert store.current(record_issuer=_ISSUER, agent_id=mine.agent_id) == mine
    assert store.current(record_issuer="other.example", agent_id=mine.agent_id) == theirs


# --------------------------------------------------------------------------
# revoke — the ODIS-L3-05 clause 1 operation
# --------------------------------------------------------------------------


def test_revoke_moves_the_record_to_revoked(store: InMemoryRegistrationRecordStore) -> None:
    record = fixture_registration_record()
    store.put(record)
    revoked = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert revoked.lifecycle_state == "revoked"


def test_revoke_increments_the_version_by_exactly_one(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """Exactly one, so a resolver's high-water mark advances by the minimum
    that still makes the pre-revocation version unusable. A larger jump would
    burn version numbers a legitimate re-registration might want."""
    record = fixture_registration_record()
    store.put(record)
    revoked = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert revoked.record_version == record.record_version + 1


def test_revoke_stamps_updated_at_and_leaves_created_at(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """The record was changed, not re-created."""
    record = fixture_registration_record()
    store.put(record)
    at = datetime(2026, 7, 1, tzinfo=UTC)
    revoked = store.revoke(
        record_issuer=record.record_issuer, agent_id=record.agent_id, at=at
    )
    assert revoked.updated_at == at
    assert revoked.created_at == record.created_at


def test_revoke_defaults_to_now(store: InMemoryRegistrationRecordStore) -> None:
    record = fixture_registration_record()
    store.put(record)
    before = datetime.now(UTC)
    revoked = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert before <= revoked.updated_at <= datetime.now(UTC)


def test_revoke_persists_to_the_store(store: InMemoryRegistrationRecordStore) -> None:
    """A revocation a subsequent read does not see is not a de-provisioning."""
    record = fixture_registration_record()
    store.put(record)
    store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    current = store.current(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert current is not None
    assert current.lifecycle_state == "revoked"


def test_revoking_twice_does_not_un_revoke(store: InMemoryRegistrationRecordStore) -> None:
    """Revocation is terminal. A second call is a no-op in state and a version
    bump in fact; what it must never be is a path back to `active`."""
    record = fixture_registration_record()
    store.put(record)
    first = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    second = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    assert second.lifecycle_state == "revoked"
    assert second.record_version == first.record_version + 1


def test_revoking_an_unknown_agent_is_refused(store: InMemoryRegistrationRecordStore) -> None:
    """A typo must not look like a successful kill. Creating a revoked record
    for an agent that was never registered would report exactly that."""
    with pytest.raises(RegistrationWriteRefused, match="no registration record"):
        store.revoke(record_issuer=_ISSUER, agent_id="agent-typo")
    assert store.records == {}


def test_revoke_does_not_touch_another_agent(store: InMemoryRegistrationRecordStore) -> None:
    alpha = fixture_registration_record(agent_id="agent-alpha")
    beta = fixture_registration_record(agent_id="agent-beta")
    store.put(alpha)
    store.put(beta)
    store.revoke(record_issuer=_ISSUER, agent_id="agent-alpha")
    assert store.current(record_issuer=_ISSUER, agent_id="agent-beta") == beta


def test_revocation_reaches_the_resolver() -> None:
    """The store-to-resolver half of `ODIS-L3-05` clause 1, asserted on both
    refs: the pre-revocation ref is superseded, and the revoked record's own
    ref resolves far enough to be refused for its lifecycle state. Anything
    held *downstream* of the resolver — sessions, cached tokens — is clause 2
    and is not reached by this."""
    store, resolver, record = registration_fixture_stack()
    ref = record.to_ref()
    assert resolver.resolve(ref).lifecycle_state == "active"

    revoked = store.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    with pytest.raises(RegistrationRecordSuperseded):
        resolver.resolve(ref)
    with pytest.raises(RegistrationRecordNotActive):
        resolver.resolve(revoked.to_ref())


# --------------------------------------------------------------------------
# FixtureRegistrationRecordIssuer — the ODIS-CC-05 mechanism
# --------------------------------------------------------------------------


@pytest.fixture
def issuer(store: InMemoryRegistrationRecordStore) -> FixtureRegistrationRecordIssuer:
    return FixtureRegistrationRecordIssuer(
        store=store, administrators=frozenset({"human:admin-1"})
    )


def test_an_administrator_may_create_a_record(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    draft = fixture_registration_record()
    created = issuer.create(requested_by="human:admin-1", draft=draft)
    assert created == draft
    assert store.current(record_issuer=draft.record_issuer, agent_id=draft.agent_id) == draft


def test_a_non_administrator_is_refused(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    with pytest.raises(RegistrationWriteRefused, match="not an authorized administrator"):
        issuer.create(requested_by="human:intern", draft=fixture_registration_record())
    assert store.records == {}


def test_self_approval_is_refused(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    """§CC-05's prohibition clause: an agent may not approve or expand its own
    registration."""
    draft = fixture_registration_record()
    with pytest.raises(RegistrationWriteRefused, match="own registration record"):
        issuer.create(requested_by=draft.agent_id, draft=draft)
    assert store.records == {}


def test_self_approval_is_refused_even_for_a_listed_administrator(
    store: InMemoryRegistrationRecordStore,
) -> None:
    """The two rules are independent, and the self-approval one is checked
    first. An agent that talked its way onto the administrator list must still
    not be able to register itself."""
    draft = fixture_registration_record(agent_id="agent-alpha")
    issuer = FixtureRegistrationRecordIssuer(
        store=store, administrators=frozenset({"agent-alpha"})
    )
    with pytest.raises(RegistrationWriteRefused, match="own registration record"):
        issuer.create(requested_by="agent-alpha", draft=draft)


def test_re_creating_an_existing_agent_is_refused(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    """Creation is not the path for changing a record. Overwriting an existing
    one here would be expansion wearing creation's name, which is the other
    half of what CC-05 forbids."""
    draft = fixture_registration_record()
    issuer.create(requested_by="human:admin-1", draft=draft)
    with pytest.raises(RegistrationWriteRefused, match="already exists"):
        issuer.create(
            requested_by="human:admin-1",
            draft=replace(draft, record_version=2, owner_ref="team:other"),
        )


def test_the_existing_record_survives_a_refused_re_creation(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    draft = fixture_registration_record()
    issuer.create(requested_by="human:admin-1", draft=draft)
    with pytest.raises(RegistrationWriteRefused):
        issuer.create(
            requested_by="human:admin-1", draft=replace(draft, owner_ref="team:attacker")
        )
    assert store.current(record_issuer=draft.record_issuer, agent_id=draft.agent_id) == draft


def test_re_creation_is_scoped_to_the_issuer(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    """A record held by another registry is not this one's to collide with."""
    draft = fixture_registration_record()
    store.put(replace(draft, record_issuer="other.example"))
    assert issuer.create(requested_by="human:admin-1", draft=draft) == draft


def test_the_refusal_messages_are_distinguishable(
    store: InMemoryRegistrationRecordStore, issuer: FixtureRegistrationRecordIssuer
) -> None:
    """One exception type, three reasons. An operator reading an audit log
    needs to tell "wrong person" from "already registered"."""
    draft = fixture_registration_record()
    messages = []
    for requested_by in (draft.agent_id, "human:intern"):
        with pytest.raises(RegistrationWriteRefused) as caught:
            issuer.create(requested_by=requested_by, draft=draft)
        messages.append(str(caught.value))
    issuer.create(requested_by="human:admin-1", draft=draft)
    with pytest.raises(RegistrationWriteRefused) as caught:
        issuer.create(requested_by="human:admin-1", draft=draft)
    messages.append(str(caught.value))
    assert len(set(messages)) == len(messages)


# --------------------------------------------------------------------------
# The fixture stack
# --------------------------------------------------------------------------


def test_the_fixture_stack_resolves_out_of_the_box() -> None:
    """Guards the fixture: a stack that did not resolve would make every
    resolver test fail for a reason that is not the branch under test."""
    _store, resolver, record = registration_fixture_stack()
    assert resolver.resolve(record.to_ref()) == record


def test_the_fixture_stack_is_independent_across_calls() -> None:
    """Fresh store, fresh high-water mark. Shared state would let one test's
    revocation decide another's outcome."""
    store_a, resolver_a, record = registration_fixture_stack()
    store_a.revoke(record_issuer=record.record_issuer, agent_id=record.agent_id)
    _store_b, resolver_b, record_b = registration_fixture_stack()
    assert resolver_b.resolve(record_b.to_ref()) == record_b
    assert resolver_a.seen_versions is not resolver_b.seen_versions


def test_the_fixture_record_is_not_already_expired() -> None:
    """Same guard, on the clock rather than the store."""
    record = fixture_registration_record()
    assert record.valid_until > datetime.now(UTC) + timedelta(days=1)
