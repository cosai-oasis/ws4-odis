"""Typed dataclasses for every envelope.

Each envelope has a frozen, keyword-only dataclass with the stub policy-metadata
fields defaulted to the constants from `odis_harness.contracts.constants`. The
non-default fields are required at construction.

`to_dict()` produces a JSON-serializable dict for transmission/audit.
`from_dict()` validates via `EnvelopeValidator` before constructing — every
envelope therefore goes through the same schema boundary.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, ClassVar, Self

from odis_harness.contracts.constants import (
    PHASE,
    SCHEMA_VERSION,
    STUB_BUNDLE_ID,
    STUB_BUNDLE_VERSION,
    STUB_TRUST_ROOT_ID,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from _typeshed import DataclassInstance

    from odis_harness.contracts.validator import EnvelopeValidator


def to_iso(moment: datetime) -> str:
    """`moment` in the `Z`-suffixed UTC form the envelope schemas require.

    The three envelope schemas declare `format: date-time` for `issued_at` and
    `timestamp`, so every emitter needs one rendering. It lives beside the schemas it
    satisfies: a second implementation elsewhere could drift from them silently, since
    nothing rejects a valid-but-differently-rendered instant.

    A tz-naive `moment` is rejected rather than converted. `astimezone` would read it as
    host-local and silently shift the instant by the host's offset, writing a wrong time
    into a record nothing would flag — and the callers stamp credential expiries, where
    being an hour out is the difference between valid and expired.
    """
    if moment.tzinfo is None:
        message = f"to_iso needs an aware datetime; {moment!r} has no tzinfo"
        raise ValueError(message)
    return moment.astimezone(UTC).isoformat().replace("+00:00", "Z")


def now_iso() -> str:
    """Current UTC time, rendered by `to_iso`."""
    return to_iso(datetime.now(UTC))


def _to_dict(instance: DataclassInstance, *, drop_unset: bool = False) -> dict[str, Any]:
    """The envelope as a JSON-serializable dict.

    Every envelope field is a scalar or a plain `Mapping`/`list`, so `asdict` has
    nothing nested to recurse into.

    `drop_unset` omits every `= None`-defaulted field still holding None, so the
    serialized envelope matches the canonical schema example shape. It is derived from
    the dataclass rather than a restated key list, and covers `default=None` only: a
    field declared with `default_factory` has `Field.default is MISSING` and needs its
    own rule.
    """
    d = dataclasses.asdict(instance)
    if drop_unset:
        for f in dataclasses.fields(instance):
            if f.default is None and d.get(f.name) is None:
                d.pop(f.name, None)
    return d


# -- Envelopes ---------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class RuntimeContext:
    ENVELOPE_NAME: ClassVar[str] = "odis.runtime.context.v1"

    correlation_id: str
    originating_principal: Mapping[str, Any]
    agent: Mapping[str, Any]
    task_intent: str
    target_resource: Mapping[str, Any]
    issued_at: str
    policy_digest: str
    schema_version: str = SCHEMA_VERSION
    bundle_id: str = STUB_BUNDLE_ID
    bundle_version: str = STUB_BUNDLE_VERSION
    trust_root_id: str = STUB_TRUST_ROOT_ID
    phase: str = PHASE

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], validator: EnvelopeValidator) -> Self:
        validator.validate(cls.ENVELOPE_NAME, payload)
        return cls(**payload)


@dataclass(frozen=True, kw_only=True)
class AuthzRequest:
    """The authorization request the Router builds for a policy decision.

    Every property the schema declares is required, so the envelope advertises no
    input the Router has no path to supply. It carries no runtime-risk signal in
    particular: ODIS §6.4 types `runtime_risk_signals` as authenticated signal objects
    a checkpoint MUST validate for issuer trust, integrity, replay resistance,
    freshness and subject correlation before use, and the harness has no signal
    authority to validate one against.
    """

    ENVELOPE_NAME: ClassVar[str] = "odis.authz.request.v1"

    correlation_id: str
    subject: Mapping[str, Any]
    target_resource: Mapping[str, Any]
    verb: str
    request_body: Mapping[str, Any]
    task_intent: str
    issued_at: str
    policy_digest: str
    schema_version: str = SCHEMA_VERSION
    bundle_id: str = STUB_BUNDLE_ID
    bundle_version: str = STUB_BUNDLE_VERSION
    trust_root_id: str = STUB_TRUST_ROOT_ID
    phase: str = PHASE

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], validator: EnvelopeValidator) -> Self:
        validator.validate(cls.ENVELOPE_NAME, payload)
        return cls(**payload)


@dataclass(frozen=True, kw_only=True)
class AuditEvent:
    ENVELOPE_NAME: ClassVar[str] = "odis.audit.event.v1"

    correlation_id: str
    event_id: str
    timestamp: str
    event_type: str
    policy_digest: str
    schema_version: str = SCHEMA_VERSION
    bundle_id: str = STUB_BUNDLE_ID
    bundle_version: str = STUB_BUNDLE_VERSION
    trust_root_id: str = STUB_TRUST_ROOT_ID
    phase: str = PHASE
    # `apf_semantic_enforcement` is **sink-derived**: the AuditSink sets it
    # before validation (true for resource-scoped events — the Tier 3 wedge).
    # Emitters leave it None; pre-setting a conflicting value is rejected with
    # a ConformancePostureViolation.
    apf_semantic_enforcement: bool | None = None
    user_id: str | None = None
    reason_code: str | None = None
    result_class: str | None = None
    resource_family: str | None = None
    extra: Mapping[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return _to_dict(self, drop_unset=True)

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], validator: EnvelopeValidator) -> Self:
        validator.validate(cls.ENVELOPE_NAME, payload)
        return cls(**payload)


__all__ = [
    "AuditEvent",
    "AuthzRequest",
    "RuntimeContext",
    "now_iso",
    "to_iso",
]
