"""apf-audit-conformance capability — audit sink, banner, HANDOFFS/CONFORMANCE artifacts.

The second foundation of the ODIS Contract Harness: every other capability
emits audit events through this sink, and every doc artifact (HANDOFFS.md,
CONFORMANCE.md, the startup banner) lives here so the audit posture is
enforced from one place.
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
