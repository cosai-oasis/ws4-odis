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
from dataclasses import dataclass, field
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


# -- Sub-records ------------------------------------------------------------


# -- Base mixin --------------------------------------------------------------


def _to_dict(instance: DataclassInstance) -> dict[str, Any]:
    """`dataclasses.asdict`, recursing through nested dataclass fields."""
    return dataclasses.asdict(instance)


# -- Envelopes ---------------------------------------------------------------


@dataclass(frozen=True, kw_only=True)
class RuntimeContext:
    ENVELOPE_NAME: ClassVar[str] = "odis.runtime.context.v1"

    correlation_id: str
    sponsor: Mapping[str, Any]
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
    active_verdicts: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d = _to_dict(self)
        # `active_verdicts` is MAY in APF §6.2; omit when empty so the
        # serialized envelope matches the canonical example used by the
        # schema-validation tests.
        if not self.active_verdicts:
            d.pop("active_verdicts", None)
        return d

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
        d = _to_dict(self)
        # Drop all optional fields when unset, so the serialized event matches
        # the canonical schema example shape (omitted-when-None).
        for k in (
            "apf_semantic_enforcement",
            "user_id",
            "reason_code",
            "result_class",
            "resource_family",
            "extra",
        ):
            if d.get(k) is None:
                d.pop(k, None)
        return d

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any], validator: EnvelopeValidator) -> Self:
        validator.validate(cls.ENVELOPE_NAME, payload)
        return cls(**payload)


__all__ = [
    "AuditEvent",
    "AuthzRequest",
    "RuntimeContext",
]
