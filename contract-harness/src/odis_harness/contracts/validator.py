"""Envelope schema validator.

Loads every JSON Schema in a configured directory at construction time, builds
one `Draft202012Validator` per schema, and exposes a single `validate` method
keyed by envelope name (schema-file stem). The audit-event extension rule
(`odis.<ns>.<name>` namespace) is layered on top via a separate runtime check
that consumers can apply after schema validation.

Failures raise `EnvelopeValidationError` with the originating envelope name,
JSON-pointer-style instance path, JSON-pointer-style schema path, and the
underlying jsonschema message. The error type is the only signal emitters get;
they fail closed and let the audit sink record the drop.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from jsonschema import Draft202012Validator

from odis_harness.contracts.audit_taxonomy import is_valid_event_type

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_AUDIT_EVENT_ENVELOPE = "odis.audit.event.v1"


class UnknownEnvelopeError(KeyError):
    """Raised when a caller asks to validate against an envelope name the
    validator does not know about."""


class EnvelopeValidationError(ValueError):
    """Raised when a payload fails its envelope schema."""

    def __init__(
        self,
        envelope_name: str,
        instance_path: str,
        schema_path: str,
        message: str,
    ) -> None:
        super().__init__(
            f"{envelope_name}: {message} (instance path: {instance_path!r}, "
            f"schema path: {schema_path!r})",
        )
        self.envelope_name = envelope_name
        self.instance_path = instance_path
        self.schema_path = schema_path
        self.message = message


class EnvelopeValidator:
    """Construct once with a schemas directory; reuse for every emission.

    The validator is intentionally a single seam — every emitting capability
    imports it, so there is one truth source for envelope validity.
    """

    def __init__(self, schemas_dir: Path) -> None:
        self._validators: dict[str, Draft202012Validator] = {}
        for path in sorted(schemas_dir.glob("*.json")):
            schema = json.loads(path.read_text(encoding="utf-8"))
            # check_schema raises if the schema itself is malformed Draft 2020-12,
            # which is the fail-closed signal at startup.
            Draft202012Validator.check_schema(schema)
            self._validators[path.stem] = Draft202012Validator(
                schema,
                format_checker=Draft202012Validator.FORMAT_CHECKER,
            )

    def known_envelopes(self) -> set[str]:
        """Names this validator can validate (schema-file stems)."""
        return set(self._validators)

    def validate(self, envelope_name: str, payload: Mapping[str, Any]) -> None:
        """Validate `payload` against the schema for `envelope_name`.

        Raises:
            UnknownEnvelopeError: no schema registered under that name.
            EnvelopeValidationError: the payload failed schema validation.
        """
        validator = self._validators.get(envelope_name)
        if validator is None:
            message = f"unknown envelope {envelope_name!r}; known: {sorted(self._validators)}"
            raise UnknownEnvelopeError(message)
        for error in validator.iter_errors(payload):
            instance_path = "/" + "/".join(str(p) for p in error.absolute_path)
            schema_path = "/" + "/".join(str(p) for p in error.absolute_schema_path)
            raise EnvelopeValidationError(
                envelope_name=envelope_name,
                instance_path=instance_path,
                schema_path=schema_path,
                message=error.message,
            )
        # Layered runtime taxonomy check for audit events: the JSON Schema's
        # `oneOf` accepts any `odis.<ns>.<name>` pattern match, but the
        # registered ODIS extension set is the authoritative gate.
        if envelope_name == _AUDIT_EVENT_ENVELOPE:
            event_type = payload.get("event_type")
            if isinstance(event_type, str) and not is_valid_event_type(event_type):
                raise EnvelopeValidationError(
                    envelope_name=envelope_name,
                    instance_path="/event_type",
                    schema_path="/properties/event_type",
                    message=(
                        f"event_type {event_type!r} is not in the APF §6.5 enum or "
                        "the registered ODIS extension set; see audit_taxonomy."
                    ),
                )
