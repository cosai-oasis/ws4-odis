"""AuditSink — emit pipeline for `odis.audit.event.v1` records.

The pipeline per call to `emit(event)`:

1. **Derive** `apf_semantic_enforcement`: true for resource-scoped events (the
   harness only does the Tier 3 wedge — every forwarded/refused resource call is
   APF-semantically enforced); false for events without a `resource_family`
   (policy / substrate events do not assert semantic enforcement). Emitters MUST
   NOT pre-set a conflicting value — `ConformancePostureViolation`.
2. **Inject** `phase` if unset; raise `ConformancePostureViolation` if the
   emitter pre-set it to anything other than the documented constant.
3. **Validate** against the JSON Schema via the shared `EnvelopeValidator`. The
   layered audit-taxonomy check is enforced inside the validator.
4. **Write** one JSON line to the configured output stream.

(No credential-redaction pass: in the forwarder architecture no provider bearers
ever reach an audit event — events carry tool name, family, endpoint id, decision
id, reason code; never args or secrets.)
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from odis_harness.audit.errors import ConformancePostureViolation
from odis_harness.contracts import PHASE, AuditEvent

if TYPE_CHECKING:
    from typing import TextIO

    from odis_harness.contracts import EnvelopeValidator

_AUDIT_ENVELOPE = "odis.audit.event.v1"


class AuditSink:
    """Constructor-injected sink. No module-level singleton; every emitting
    capability is given an instance via its constructor.
    """

    def __init__(self, output: TextIO, validator: EnvelopeValidator) -> None:
        self._output = output
        self._validator = validator

    def emit(self, event: AuditEvent) -> None:
        """Run the derive → inject → validate → write pipeline."""
        payload = event.to_dict()

        # 1. apf_semantic_enforcement: sink-derived.
        derived = _derive_semantic_enforcement(payload)
        existing = payload.get("apf_semantic_enforcement")
        if existing is not None and existing != derived:
            message = (
                f"emitter set apf_semantic_enforcement={existing!r} but the sink "
                f"derives {derived!r}; this would misstate APF semantic-enforcement posture."
            )
            raise ConformancePostureViolation(message)
        payload["apf_semantic_enforcement"] = derived

        # 2. phase: inject if unset; raise if pre-set to anything else.
        phase = payload.get("phase")
        if phase is None:
            payload["phase"] = PHASE
        elif phase != PHASE:
            message = (
                f"emitter set phase={phase!r}; the only legitimate value is "
                f"{PHASE!r}. Setting another value would misstate harness identity."
            )
            raise ConformancePostureViolation(message)

        # 3. Validate.
        self._validator.validate(_AUDIT_ENVELOPE, payload)

        # 4. Write.
        self._output.write(json.dumps(payload) + "\n")
        self._output.flush()


def _derive_semantic_enforcement(payload: dict[str, Any]) -> bool:
    """True for resource-scoped events (Tier 3); False otherwise.

    Every resource call the Router gates is APF-semantically enforced (policy +
    action limits over coarse vendor access). Events without a `resource_family`
    (policy / substrate) do not assert semantic enforcement.
    """
    return isinstance(payload.get("resource_family"), str)


__all__ = ["AuditSink"]
