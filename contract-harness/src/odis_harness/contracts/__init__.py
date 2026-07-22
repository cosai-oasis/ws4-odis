"""Contracts capability — envelopes, audit taxonomy, validation.

This module is the only stable public surface of the contracts capability.
Every other ODIS Contract Harness capability imports from here; nothing reaches
into the submodules directly.
"""

from odis_harness.contracts.audit_taxonomy import (
    APF_EVENT_TYPES,
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.contracts.constants import (
    PHASE,
    SCHEMA_VERSION,
    STUB_BUNDLE_ID,
    STUB_BUNDLE_VERSION,
    STUB_TRUST_ROOT_ID,
)
from odis_harness.contracts.envelopes import (
    AuditEvent,
    AuthzRequest,
    RuntimeContext,
)
from odis_harness.contracts.validator import (
    EnvelopeValidationError,
    EnvelopeValidator,
    UnknownEnvelopeError,
)

__all__ = [
    "APF_EVENT_TYPES",
    "ODIS_EXTENSION_TYPES",
    "PHASE",
    "SCHEMA_VERSION",
    "STUB_BUNDLE_ID",
    "STUB_BUNDLE_VERSION",
    "STUB_TRUST_ROOT_ID",
    "AuditEvent",
    "AuthzRequest",
    "EnvelopeValidationError",
    "EnvelopeValidator",
    "RuntimeContext",
    "UnknownEnvelopeError",
    "is_valid_event_type",
]
