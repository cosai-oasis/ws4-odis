"""AuditSink: derive apf_semantic_enforcement, inject phase, validate, write."""

from __future__ import annotations

import io
import json
import uuid

import pytest

from odis_harness.audit.banner import print_banner
from odis_harness.audit.errors import ConformancePostureViolation
from odis_harness.audit.sink import AuditSink
from odis_harness.contracts import (
    PHASE,
    AuditEvent,
    EnvelopeValidationError,
    EnvelopeValidator,
)


@pytest.fixture
def output() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def sink(output: io.StringIO, envelope_validator: EnvelopeValidator) -> AuditSink:
    return AuditSink(output=output, validator=envelope_validator)


def _base_event(**overrides: object) -> AuditEvent:
    kwargs: dict[str, object] = {
        "correlation_id": str(uuid.uuid4()),
        "event_id": str(uuid.uuid4()),
        "timestamp": "2026-05-28T00:00:00.500Z",
        "event_type": "odis.mcp.forward",
        "policy_digest": "a" * 64,
    }
    kwargs.update(overrides)
    return AuditEvent(**kwargs)  # type: ignore[arg-type]


# -- emit pipeline -----------------------------------------------------------


def test_emit_writes_one_json_line_per_event(sink: AuditSink, output: io.StringIO) -> None:
    sink.emit(_base_event(resource_family="jira-prod"))
    parsed = json.loads(output.getvalue().strip())
    assert parsed["event_type"] == "odis.mcp.forward"


def test_emit_multiple_events_share_correlation_id(sink: AuditSink, output: io.StringIO) -> None:
    correlation = str(uuid.uuid4())
    sink.emit(_base_event(correlation_id=correlation, resource_family="jira-prod"))
    sink.emit(
        _base_event(
            correlation_id=correlation,
            event_type="odis.mcp.forward_refused",
            resource_family="jira-prod",
            reason_code="deny",
        )
    )
    lines = [line for line in output.getvalue().splitlines() if line]
    assert len(lines) == 2
    assert all(json.loads(line)["correlation_id"] == correlation for line in lines)


def test_emit_invalid_event_type_raises_and_emits_nothing(
    sink: AuditSink, output: io.StringIO
) -> None:
    bad = AuditEvent(
        correlation_id=str(uuid.uuid4()),
        event_id=str(uuid.uuid4()),
        timestamp="2026-05-28T00:00:00.500Z",
        event_type="not_a_registered_event",  # taxonomy violation
        policy_digest="a" * 64,
    )
    with pytest.raises(EnvelopeValidationError):
        sink.emit(bad)
    assert output.getvalue() == ""


# -- apf_semantic_enforcement derivation -------------------------------------


def test_semantic_enforcement_true_for_resource_scoped_event(
    sink: AuditSink, output: io.StringIO
) -> None:
    sink.emit(_base_event(resource_family="jira-prod"))
    assert json.loads(output.getvalue().strip())["apf_semantic_enforcement"] is True


def test_semantic_enforcement_false_when_resource_family_omitted(
    sink: AuditSink, output: io.StringIO
) -> None:
    sink.emit(_base_event(event_type="policy_load"))
    assert json.loads(output.getvalue().strip())["apf_semantic_enforcement"] is False


def test_emitter_cannot_pre_set_conflicting_semantic_enforcement(
    sink: AuditSink, output: io.StringIO
) -> None:
    # resource-scoped event derives True; pre-setting False is a lie.
    event = _base_event(resource_family="jira-prod", apf_semantic_enforcement=False)
    with pytest.raises(ConformancePostureViolation):
        sink.emit(event)
    assert output.getvalue() == ""


def test_emitter_matching_derivation_is_accepted(sink: AuditSink, output: io.StringIO) -> None:
    event = _base_event(resource_family="jira-prod", apf_semantic_enforcement=True)
    sink.emit(event)
    assert json.loads(output.getvalue().strip())["apf_semantic_enforcement"] is True


# -- phase injection ---------------------------------------------------------


def test_phase_injected_when_unset(sink: AuditSink, output: io.StringIO) -> None:
    sink.emit(_base_event(resource_family="jira-prod"))
    assert json.loads(output.getvalue().strip())["phase"] == PHASE


def test_wrong_phase_raises(sink: AuditSink, output: io.StringIO) -> None:
    event = _base_event(resource_family="jira-prod", phase="core")
    with pytest.raises(ConformancePostureViolation):
        sink.emit(event)
    assert output.getvalue() == ""


# -- banner ------------------------------------------------------------------


def test_print_banner_writes_to_stream(output: io.StringIO) -> None:
    print_banner(output)
    assert output.getvalue() == "ODIS Contract Harness\n"
