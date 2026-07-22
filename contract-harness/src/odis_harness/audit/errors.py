"""Audit-conformance error types."""

from __future__ import annotations


class ConformancePostureViolation(ValueError):  # noqa: N818 - domain term reads clearer without the Error suffix
    """Raised when an emitter constructs an audit event that would misstate
    the harness's conformance posture — e.g., setting `phase` to anything
    other than the documented constant, or pre-setting
    `apf_semantic_enforcement` to a value that doesn't match what the sink
    would derive from the resource family's tier.
    """


__all__ = ["ConformancePostureViolation"]
