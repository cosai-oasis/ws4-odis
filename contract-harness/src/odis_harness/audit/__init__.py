"""Audit — the sink every emitter writes through, and the startup banner.

Every emitter writes through `AuditSink`, which derives the conformance fields, validates
against `odis.audit.event.v1` and writes one JSON line. Centralised so the posture is
enforced in one place: an emitter that misstates `phase` or `apf_semantic_enforcement`
raises rather than producing a record that overstates what was enforced.
"""

from odis_harness.audit.banner import BANNER_LINE, print_banner
from odis_harness.audit.errors import ConformancePostureViolation
from odis_harness.audit.sink import AuditSink

__all__ = [
    "BANNER_LINE",
    "AuditSink",
    "ConformancePostureViolation",
    "print_banner",
]
