"""In-memory registration store, a governed issuer, and a canonical fixture record.

For tests and local development. Production substitutes a real store backed by
the directory or registry that owns the records; the `RegistrationRecordStore`
and `RegistrationRecordLifecycleStore` Protocols are what make that a
substitution rather than a rewrite.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Protocol

from odis_harness.registration.errors import RegistrationWriteRefused
from odis_harness.registration.types import (
    RECORD_SCHEMA_VERSION,
    AgentRegistrationRecord,
    LifecycleState,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

#: The fixture's fixed clock. A constant rather than `now()` so the golden
#: digest in `tests/test_registration/test_digest.py` is reproducible: a
#: fixture whose timestamps move would make the drift alarm fire every day
#: for the wrong reason.
_FIXTURE_CREATED_AT = datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC)
_FIXTURE_VALID_UNTIL = datetime(2027, 1, 1, 0, 0, 0, tzinfo=UTC)

#: What `registration_fixture_stack`'s resolver reads as "now". Fixed, and
#: inside `[_FIXTURE_CREATED_AT, _FIXTURE_VALID_UNTIL)` by construction.
#:
#: Without it the stack's resolver would read the wall clock against a
#: `valid_until` that the golden digest pins in place, so every test built on
#: the stack — including the non-xfail `ODIS-L3-05` clause 1 test — would begin
#: failing on 2027-01-01 with `RegistrationRecordExpired`, for a reason having
#: nothing to do with what it asserts. Moving `_FIXTURE_VALID_UNTIL` further out
#: would only move the date; pinning the clock removes it. A test that wants to
#: exercise expiry constructs its own resolver with its own `now`, which is what
#: `test_resolver.py` already does.
_FIXTURE_NOW = datetime(2026, 6, 1, 0, 0, 0, tzinfo=UTC)


def fixture_registration_record(
    *,
    agent_id: str = "agent-alpha",
    record_issuer: str = "registry.example",
    trust_domain: str = "trust.example",
    lifecycle_state: LifecycleState = "active",
) -> AgentRegistrationRecord:
    """A complete, valid §6.1 record.

    Four keyword parameters, not seventeen: these are the fields the resolver
    branches on, and every other variation is a `dataclasses.replace` at the
    call site — which is how this codebase already varies fixtures, and which
    keeps the factory under ruff's five-parameter ceiling.
    """
    return AgentRegistrationRecord(
        record_id=f"reg-{agent_id}",
        record_issuer=record_issuer,
        schema_version=RECORD_SCHEMA_VERSION,
        record_version=1,
        agent_id=agent_id,
        valid_until=_FIXTURE_VALID_UNTIL,
        lifecycle_state=lifecycle_state,
        sponsor_ref="human:sponsor-1",
        owner_ref="team:platform",
        approved_runtime_issuers=("spiffe://trust.example/issuer",),
        approved_software_refs=("sha256:0f0f0f",),
        trust_domain=trust_domain,
        policy_profile_ref="profile:baseline",
        permitted_delegation_modes=("bridge",),
        created_at=_FIXTURE_CREATED_AT,
        updated_at=_FIXTURE_CREATED_AT,
    )


@dataclass(kw_only=True, slots=True)
class InMemoryRegistrationRecordStore:
    """A `RegistrationRecordLifecycleStore` backed by a dict. Test and local-dev only.

    Keyed by `(record_issuer, agent_id)` and holding one current version per
    agent, which is what `by_id` and `current` both read. A real store would
    retain superseded versions; this one does not, because the resolver only
    ever asks for the current one and keeping history here would invite tests
    that assert on a retention policy the Protocol does not promise.

    Satisfying the *lifecycle* Protocol, not just `RegistrationRecordStore`, is
    the point of `revoke` being on a Protocol at all: `ODIS-L3-05` clause 1 is
    claimed on the strength of a single de-provisioning operation existing, and
    a claim that rested only on a method of this class would be a claim about a
    test double.
    """

    records: dict[tuple[str, str], AgentRegistrationRecord] = field(default_factory=dict)

    def put(self, record: AgentRegistrationRecord) -> None:
        """Insert or replace the current record for `(record_issuer, agent_id)`."""
        self.records[(record.record_issuer, record.agent_id)] = record

    def by_id(
        self, *, record_issuer: str, record_id: str
    ) -> AgentRegistrationRecord | None:
        """The current record with this `record_id`, or None.

        Returns None rather than raising. Converting absence into a refusal is
        the resolver's job, so fail-closed lives in one place instead of being
        re-implemented by every store.
        """
        for (issuer, _agent_id), record in self.records.items():
            if issuer == record_issuer and record.record_id == record_id:
                return record
        return None

    def current(self, *, record_issuer: str, agent_id: str) -> AgentRegistrationRecord | None:
        """The current record for this agent, or None."""
        return self.records.get((record_issuer, agent_id))

    def revoke(
        self,
        *,
        record_issuer: str,
        agent_id: str,
        at: datetime | None = None,
    ) -> AgentRegistrationRecord:
        """De-provision an agent. The `ODIS-L3-05` single operation.

        Moves the record to `revoked`, increments `record_version`, and stamps
        `updated_at`. `created_at` is left alone: the record was not re-created.

        The version bump buys **supersession**, not rollback protection, and the
        distinction matters enough to name.

        What it does: every credential already minted carries a
        `registration_record_ref` naming the pre-revocation version. After the
        bump, such a ref meets a store answering one version higher and is
        refused at the resolver's supersession check — `RegistrationRecordSuperseded`,
        with the record never reaching the lifecycle branch.

        The refusal itself is not what the bump buys, and claiming otherwise
        would be the same kind of overstatement this docstring was rewritten to
        remove. Without the bump that ref is still refused: `lifecycle_state`
        and `updated_at` are both digested, so a same-version revocation moves
        `record_digest` and the ref fails the *digest* check instead. What the
        bump buys is the right answer rather than a merely correct one —
        `Superseded` says "this ref names a version that is no longer current",
        where `DigestMismatch` says "someone rewrote this record", which is a
        false accusation for an ordinary revocation and would send an operator
        hunting a compromise that never happened.

        What it does *not* do: raise the resolver's high-water mark. The mark
        advances only on an accepted record, and a revoked record is refused
        before it gets there — see `AuthoritativeRegistrationRecordResolver` and
        `test_an_inactive_record_does_not_advance_the_high_water_mark`, which
        pins that on purpose so a revoked v5 cannot block a legitimate v4
        rollback fix. So the bump gives no protection against a store that is
        later rewound to serve the pre-revocation version as current; that case
        is caught, if at all, by the mark left behind by whatever version was
        last *accepted*.

        Refuses an unknown agent rather than creating a revoked record for one,
        so a typo cannot look like a successful kill.
        """
        existing = self.current(record_issuer=record_issuer, agent_id=agent_id)
        if existing is None:
            message = f"no registration record for {agent_id!r} issued by {record_issuer!r}"
            raise RegistrationWriteRefused(message)
        revoked = replace(
            existing,
            lifecycle_state="revoked",
            record_version=existing.record_version + 1,
            updated_at=at if at is not None else datetime.now(UTC),
        )
        self.put(revoked)
        return revoked


class RegistrationRecordIssuer(Protocol):
    """Creates registration records under governance.

    `ODIS-CC-05` requires creation to be authorized by an authenticated human
    administrator or an attributable governance workflow, and forbids an agent
    approving or expanding its own registration. This Protocol is where that
    authorization decision goes.
    """

    def create(
        self, *, requested_by: str, draft: AgentRegistrationRecord
    ) -> AgentRegistrationRecord: ...


@dataclass(frozen=True, kw_only=True, slots=True)
class FixtureRegistrationRecordIssuer:
    """A `RegistrationRecordIssuer` enforcing three governance rules.

    Refuses a requester outside `administrators`, refuses self-approval (an
    agent creating its own registration), and refuses re-creating an
    `agent_id` that already has a record — the last because `ODIS-CC-05`
    separates creation from expansion, and overwriting an existing record
    through the creation path is expansion wearing creation's name.

    `requested_by` is caller-supplied and unauthenticated. Nothing here
    verifies that the caller is who the string says, so an agent can claim to
    be an administrator and all three rules evaporate. So this does not satisfy
    `ODIS-CC-05` and is not claimed to: the clause is an authorization
    requirement, and a seam does not satisfy one. Closing it needs the same
    authenticated-principal machinery as `ODIS-L1-11`.
    """

    store: InMemoryRegistrationRecordStore
    administrators: frozenset[str]

    def create(
        self, *, requested_by: str, draft: AgentRegistrationRecord
    ) -> AgentRegistrationRecord:
        """Create `draft` if `requested_by` is permitted to. Otherwise refuse."""
        if requested_by == draft.agent_id:
            message = (
                f"{requested_by!r} may not create its own registration record; "
                "ODIS-CC-05 forbids an agent approving or expanding its own registration"
            )
            raise RegistrationWriteRefused(message)
        if requested_by not in self.administrators:
            message = f"{requested_by!r} is not an authorized administrator"
            raise RegistrationWriteRefused(message)
        existing = self.store.current(
            record_issuer=draft.record_issuer, agent_id=draft.agent_id
        )
        if existing is not None:
            message = (
                f"a registration record for {draft.agent_id!r} already exists "
                f"(version {existing.record_version}); creation is not the path for changing one"
            )
            raise RegistrationWriteRefused(message)
        self.store.put(draft)
        return draft


def registration_fixture_stack(
    *,
    authorities: Mapping[str, Any] | None = None,
) -> tuple[InMemoryRegistrationRecordStore, Any, AgentRegistrationRecord]:
    """A store, a resolver configured for it, and one record already in it.

    The three objects a test needs to exercise the §6.1 resolution rule end to
    end. Returned as a tuple rather than as a dataclass because every caller
    unpacks all three.

    The resolver's clock is `_FIXTURE_NOW`, so the stack does not expire.
    """
    # Local imports. Not a cycle — `resolver` imports only `digest` and
    # `errors` — but keeping the dependency out of module scope keeps
    # `fixtures` importable as leaf test scaffolding rather than as something
    # that drags the resolver in behind it.
    from odis_harness.registration.resolver import (  # noqa: PLC0415 - see the comment above
        AuthoritativeRegistrationRecordResolver,
    )
    from odis_harness.registration.types import IssuerAuthority  # noqa: PLC0415 - as above

    record = fixture_registration_record()
    store = InMemoryRegistrationRecordStore()
    store.put(record)
    resolver = AuthoritativeRegistrationRecordResolver(
        store=store,
        authorities=dict(authorities)
        if authorities is not None
        else {
            record.record_issuer: IssuerAuthority(
                record_issuer=record.record_issuer,
                trust_domains=frozenset({record.trust_domain}),
            )
        },
        now=lambda: _FIXTURE_NOW,
    )
    return store, resolver, record


__all__ = [
    "FixtureRegistrationRecordIssuer",
    "InMemoryRegistrationRecordStore",
    "RegistrationRecordIssuer",
    "fixture_registration_record",
    "registration_fixture_stack",
]
