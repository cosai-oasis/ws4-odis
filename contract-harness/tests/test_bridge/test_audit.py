"""Terminal-exchange audit anchor (`bridge/audit.py`) — ODIS-CC-06.

Hermetic: a stub `TokenExchanger` drives `BridgeAuth` over fake `httpx.Request`s with a
`CapturingAuditSink` behind the anchor — no network, no MCP transport. Covers one event
per exchange, the target and credential bindings, the absence of any token material, the
semantic-enforcement posture, where the correlation id comes from, and the fail-closed
behaviour when the anchor cannot record.

The expected fingerprints are transcribed here with `hashlib` rather than read back from
`CredentialHandle`: computing the expectation with the code under test would assert only
that the function equals itself.
"""

from __future__ import annotations

import hashlib
import io
import json
import uuid
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from odis_harness.audit.sink import AuditSink
from odis_harness.bridge.audit import (
    CorrelationSource,
    CredentialHandle,
    ExchangeAuditAnchor,
    ExchangeTrigger,
)
from odis_harness.bridge.exchange import BridgeAuth
from odis_harness.contracts.audit_taxonomy import (
    ODIS_EXTENSION_TYPES,
    is_valid_event_type,
)
from odis_harness.mcp_forwarder.vendor_client import TRACE_HEADER_NAME
from tests import factories

# pytest-asyncio's event-loop setup touches the self-pipe socket; no test here uses
# the network.
pytestmark = pytest.mark.enable_socket

_EVENT_TYPE = "odis.bridge.terminal_exchange"
#: Secrets the anchor must never write. Distinct values so a leak names which leg leaked.
_BEARER = "leg2-bearer-value-that-must-never-be-logged"
_SUBJECT = "agent-workload-jwt-that-must-never-be-logged"
_AUDIENCE = "jira-prod-mcp-v1"
_ENDPOINT_ID = "jira-prod-mcp-v1"
#: Fixed and far future, so the recorded expiry is deterministic and the token never
#: goes stale mid-test.
_EXPIRES_AT = datetime(2099, 1, 1, tzinfo=UTC)
_TRACE_ID = "00000000-0000-4000-8000-00000000abcd"


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _bearer(index: int) -> str:
    """The bearer the shared double mints on its `index`-th call for `_AUDIENCE`."""
    return f"{_BEARER}-{index}-{_AUDIENCE}"


def _exchanger(*, expires_at: datetime = _EXPIRES_AT) -> factories.StubTokenExchanger:
    """The shared double, pinned to this module's bearer prefix and a fixed expiry.

    Bearers here are asserted by fingerprint, so the prefix has to be a value this module
    controls; `expires_at` is fixed and far future so the recorded expiry is deterministic
    and the token never goes stale mid-test.
    """
    return factories.StubTokenExchanger(expiries=[expires_at], bearer_prefix=_BEARER)


def _anchor(sink: AuditSink | None = None) -> ExchangeAuditAnchor:
    """An anchor over `sink`, or a discarding one when the record is not the subject."""
    return factories.exchange_anchor(sink, target_endpoint_id=_ENDPOINT_ID)


def _bridge(
    *, exchanger: factories.StubTokenExchanger, anchor: ExchangeAuditAnchor
) -> BridgeAuth:
    return BridgeAuth(
        subject_token_provider=lambda: _SUBJECT,
        audience=_AUDIENCE,
        exchanger=exchanger,
        anchor=anchor,
    )


def _request(*, trace_id: str | None = None) -> httpx.Request:
    headers = {} if trace_id is None else {TRACE_HEADER_NAME: trace_id}
    return httpx.Request("POST", "http://vendor.local/mcp", headers=headers)


async def _run_flow(
    auth: BridgeAuth, *, trace_id: str | None = None, reject_status: int | None = None
) -> httpx.Request:
    """Drive `async_auth_flow` once and return the last request it yielded.

    With `reject_status` the first response is a rejection, so the flow re-mints and
    yields a second time (the retry-once path).
    """
    request = _request(trace_id=trace_id)
    gen = auth.async_auth_flow(request)
    sent = await gen.__anext__()
    if reject_status is not None:
        sent = await gen.asend(httpx.Response(reject_status, request=request))
    with pytest.raises(StopAsyncIteration):
        await gen.asend(httpx.Response(200, request=request))
    return sent


def _triggers(sink: factories.CapturingAuditSink) -> list[str]:
    return [(e.extra or {})["trigger"] for e in sink.events]


# -- registration -------------------------------------------------------------


def test_terminal_exchange_event_is_registered() -> None:
    """An unregistered event type fails validation, so the taxonomy entry is the gate."""
    assert _EVENT_TYPE in ODIS_EXTENSION_TYPES
    assert is_valid_event_type(_EVENT_TYPE)


# -- one event per exchange ---------------------------------------------------


async def test_one_exchange_emits_exactly_one_anchor_event() -> None:
    sink = factories.CapturingAuditSink()
    exchanger = _exchanger()
    auth = _bridge(exchanger=exchanger, anchor=_anchor(sink))

    await _run_flow(auth)
    # The cached token serves this one: no exchange, so no second anchor event.
    await _run_flow(auth)

    assert exchanger.calls == 1
    assert sink.event_types == [_EVENT_TYPE]


async def test_re_exchange_on_expiry_anchors_the_new_credential() -> None:
    """Each minted credential artifact gets its own anchor record."""
    sink = factories.CapturingAuditSink()
    exchanger = _exchanger(expires_at=datetime.now(UTC) - timedelta(seconds=1))
    auth = _bridge(exchanger=exchanger, anchor=_anchor(sink))

    await _run_flow(auth)
    await _run_flow(auth)

    assert exchanger.calls == 2
    assert sink.event_types == [_EVENT_TYPE, _EVENT_TYPE]
    fingerprints = [(e.extra or {})["credential"]["fingerprint"] for e in sink.events]
    assert fingerprints == [_sha256(_bearer(0)), _sha256(_bearer(1))]


def test_bridge_auth_cannot_be_built_without_an_anchor() -> None:
    """ODIS-CC-06 makes this component the authoritative audit anchor, and nothing
    downstream can record what was handed to the target. Requiring the anchor to
    construct the auth means an exchange that records nothing has no code path, rather
    than being refused once someone asks for one — the same rule, and the same
    enforcement, as `AnchoredOAuthTokenStorage`.
    """
    with pytest.raises(TypeError, match="anchor"):
        BridgeAuth(  # type: ignore[call-arg]
            subject_token_provider=lambda: _SUBJECT,
            audience=_AUDIENCE,
            exchanger=_exchanger(),
        )


# -- what the record binds ----------------------------------------------------


async def test_anchor_event_binds_target_identity_and_credential_handles() -> None:
    """ODIS-CC-06: the record binds the delegation context to the target system identity
    and to a handle for the credential artifact used."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=_TRACE_ID)

    event = sink.events[0]
    # Compared exactly: the audit event is a published contract, so a new or renamed key
    # has to be a deliberate edit here rather than a silent addition.
    assert event.extra == {
        "trigger": "request",
        "correlation_source": "downstream_request",
        "target": {
            # `endpoint_id` comes from the bundle's routing entry, `audience` from what
            # the exchange actually requested. Both are recorded: they are the same value
            # today, and a disagreement is the finding.
            "endpoint_id": _ENDPOINT_ID,
            "audience": _AUDIENCE,
            "family": factories.FAMILY_NAME,
        },
        "credential": {
            "fingerprint": _sha256(_bearer(0)),
            "expires_at": "2099-01-01T00:00:00Z",
        },
        "subject_credential": {"fingerprint": _sha256(_SUBJECT)},
    }


async def test_record_reports_the_requested_audience_not_the_endpoint_id() -> None:
    """`audience` is passed through as the mechanism supplied it, never derived from the
    target it is being recorded against.

    Asserted with the two deliberately different, which is the only way to see that they
    are independent: `cli.builders._vendor_audience` returns the endpoint id, so on
    `--bridge` they coincide, and a test using the real wiring could not tell a
    pass-through from a copy. A production exchanger scoping to something else is
    recorded as what it asked for.
    """
    sink = factories.CapturingAuditSink()
    anchor = _anchor(sink)
    auth = BridgeAuth(
        subject_token_provider=lambda: _SUBJECT,
        audience="https://vendor.example/mcp",
        exchanger=_exchanger(),
        anchor=anchor,
    )

    await auth.establish()

    target = (sink.events[0].extra or {})["target"]
    assert target["endpoint_id"] == "jira-prod-mcp-v1"
    assert target["audience"] == "https://vendor.example/mcp"


async def test_anchor_event_names_the_grant_in_force() -> None:
    sink = factories.CapturingAuditSink()
    grant = factories.bundle()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth)

    event = sink.events[0]
    assert event.bundle_id == grant.bundle_id
    assert event.bundle_version == grant.bundle_version
    assert event.trust_root_id == grant.trust_root_id
    assert event.policy_digest == grant.policy_digest


async def test_anchor_event_carries_no_token_material() -> None:
    """Raw target credential secrets MUST NOT be logged (ODIS-CC-06)."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=_TRACE_ID)

    written = sink.output.getvalue()
    assert _BEARER not in written
    assert _SUBJECT not in written
    assert "Bearer" not in written
    assert "authorization" not in written.lower()


async def test_anchor_event_claims_no_semantic_enforcement() -> None:
    """No `resource_family`, so the sink derives `apf_semantic_enforcement` false.

    A token exchange passes no policy and no action-limit enforcer, so claiming the APF
    Tier-3 wedge on it would misstate the posture. The family is still recorded, as
    routing context under `extra.target`.
    """
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth)

    payload = json.loads(sink.output.getvalue())
    assert payload["apf_semantic_enforcement"] is False
    assert "resource_family" not in payload
    assert sink.events[0].resource_family is None


# -- where the correlation id comes from (ODIS-CC-01) -------------------------


async def test_anchor_adopts_the_downstream_trace_id() -> None:
    """The id the Router put on the outbound request is the id the record carries, so the
    exchange joins that call's trail."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=_TRACE_ID)

    assert sink.events[0].correlation_id == _TRACE_ID


async def test_boot_handshake_mints_its_own_correlation_id() -> None:
    """`establish()` runs before any agent call, so it belongs to no trail of its own."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await auth.establish()

    event = sink.events[0]
    uuid.UUID(event.correlation_id)
    assert (event.extra or {})["trigger"] == "boot_handshake"
    assert (event.extra or {})["correlation_source"] == "anchor"


@pytest.mark.parametrize(
    "trace_id",
    [
        "not-a-uuid",
        # Forms `uuid.UUID()` parses but the envelope's `format: uuid` rejects. Adopting
        # one would fail the record at validation and take the agent's call down with it,
        # which is the opposite of what the fallback exists for.
        "{00000000-0000-4000-8000-00000000abcd}",
        "urn:uuid:00000000-0000-4000-8000-00000000abcd",
        "00000000000040008000000000000abc",
    ],
)
async def test_trace_id_the_envelope_would_reject_falls_back(trace_id: str) -> None:
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=trace_id)

    event = sink.events[0]
    uuid.UUID(event.correlation_id)
    assert (event.extra or {})["correlation_source"] == "anchor"
    assert trace_id not in sink.output.getvalue()


@pytest.mark.parametrize(
    "trace_id",
    ["00000000-0000-4000-8000-00000000abcd", "00000000-0000-4000-8000-00000000ABCD"],
)
async def test_canonical_trace_id_is_adopted_in_either_case(trace_id: str) -> None:
    """Hex case is not canonicalised: the id is a log key, and rewriting it would break
    the string match against the record the Router wrote."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=trace_id)

    assert sink.events[0].correlation_id == trace_id


@pytest.mark.parametrize("reject_status", [401, 403])
async def test_rejection_retry_anchors_the_second_exchange(reject_status: int) -> None:
    sink = factories.CapturingAuditSink()
    exchanger = _exchanger()
    auth = _bridge(exchanger=exchanger, anchor=_anchor(sink))

    await _run_flow(auth, trace_id=_TRACE_ID, reject_status=reject_status)

    assert exchanger.calls == 2
    assert _triggers(sink) == ["request", "rejection_retry"]
    # Both exchanges served the same agent call, so both join its trail.
    assert [e.correlation_id for e in sink.events] == [_TRACE_ID, _TRACE_ID]


# -- fail closed --------------------------------------------------------------


class _FailingSink(AuditSink):
    """An audit sink whose write fails — a full disk or a closed stream."""

    def __init__(self) -> None:
        super().__init__(output=io.StringIO(), validator=factories.envelope_validator())

    def emit(self, event: object) -> None:
        del event
        message = "audit stream unavailable"
        raise OSError(message)


async def test_exchange_the_anchor_cannot_record_serves_no_credential() -> None:
    """CC-06 makes this component the authoritative anchor, so an exchange it cannot
    record must not produce a usable credential."""
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(_FailingSink()))

    request = _request()
    gen = auth.async_auth_flow(request)
    with pytest.raises(OSError, match="audit stream unavailable"):
        await gen.__anext__()

    assert "Authorization" not in request.headers


async def test_unrecorded_exchange_is_not_cached() -> None:
    """The failed exchange left nothing behind, so the next attempt exchanges again."""
    exchanger = _exchanger()
    auth = _bridge(
        exchanger=exchanger,
        anchor=_anchor(_FailingSink()),
    )
    for _ in range(2):
        with pytest.raises(OSError, match="audit stream unavailable"):
            await auth.establish()
    assert exchanger.calls == 2, "a token that was never recorded must not be reused"


# -- CredentialHandle ---------------------------------------------------------


def test_credential_handle_fingerprints_without_carrying_the_secret() -> None:
    handle = CredentialHandle.of(_BEARER)
    assert handle.fingerprint == _sha256(_BEARER)
    assert _BEARER not in handle.fingerprint
    assert _BEARER not in repr(handle)


def test_credential_handle_fingerprint_is_stable_and_distinguishing() -> None:
    assert CredentialHandle.of(_BEARER).fingerprint == CredentialHandle.of(_BEARER).fingerprint
    assert CredentialHandle.of(_BEARER).fingerprint != CredentialHandle.of(_SUBJECT).fingerprint


def test_credential_handle_records_expiry_only_when_known() -> None:
    assert CredentialHandle.of(_BEARER).to_extra() == {"fingerprint": _sha256(_BEARER)}
    assert CredentialHandle.of(_BEARER, expires_at=_EXPIRES_AT).to_extra() == {
        "fingerprint": _sha256(_BEARER),
        "expires_at": "2099-01-01T00:00:00Z",
    }


# -- the vocabularies are a wire contract ------------------------------------


def test_trigger_and_source_serialize_as_their_bare_wire_strings() -> None:
    """`StrEnum` members must land in the JSON line as the plain strings a log pipeline
    keys on, not as `ExchangeTrigger.REQUEST`.

    Transcribed rather than derived from `.value`: reading the expectation off the enum
    would assert only that the enum equals itself, and these strings are consumed outside
    this repo.
    """
    assert {t.value for t in ExchangeTrigger} == {
        "boot_handshake",
        "request",
        "rejection_retry",
        "oauth_initial_token",
        "oauth_replacement_token",
    }
    assert {s.value for s in CorrelationSource} == {"downstream_request", "anchor"}


async def test_serialized_event_carries_plain_strings() -> None:
    """The end of that contract: what actually reaches the audit stream."""
    sink = factories.CapturingAuditSink()
    auth = _bridge(exchanger=_exchanger(), anchor=_anchor(sink))

    await _run_flow(auth, trace_id=_TRACE_ID)

    payload = json.loads(sink.output.getvalue())
    assert payload["extra"]["trigger"] == "request"
    assert payload["extra"]["correlation_source"] == "downstream_request"
