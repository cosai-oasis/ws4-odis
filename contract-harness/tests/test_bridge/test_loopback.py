"""Loopback e2e for the ODIS Bridge leg-2 auth.

Stands up a tiny capturing vendor MCP server on a loopback port, points an
`HttpMcpClient(auth=BridgeAuth(...))` at it via the MCP SDK, makes a
`tools/call`, and asserts the captured `Authorization` header is `Bearer <jwt>`
whose `aud` is the configured vendor audience (RFC 8707) and whose `act.sub` is the
agent subject (RFC 8693). This proves the BridgeAuth seam threads a freshly-exchanged
bearer onto every SDK-sent HTTP request through the full transport — not just at the
httpx layer.

It also proves the two ODIS cross-cutting halves meet through that same transport: the
call's trace id reaches the target as a header (ODIS-CC-01), and the Bridge reads that
same id back off the outbound request to anchor the terminal exchange to the call
(ODIS-CC-06) — so one correlation id joins the exchange record to the forward record.

Reuses the loopback vendor harness shape from `test_vendor_http`; opts back into
sockets at the module level (the suite is `--disable-socket` by default).
"""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

import jwt
import pytest

from odis_harness.bridge.exchange import BridgeAuth
from odis_harness.fixtures.bridge import FixtureTokenExchanger, fixture_subject_token_provider
from odis_harness.fixtures.issuer import FixtureIdentityIssuer
from odis_harness.mcp_forwarder.vendor_client import TRACE_HEADER_NAME
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from tests import factories
from tests.loopback import RunningVendor, authorization_headers

if TYPE_CHECKING:
    from odis_harness.bridge.audit import ExchangeAuditAnchor

pytestmark = pytest.mark.enable_socket

_VENDOR_AUDIENCE = "https://vendor.example/mcp"
_AGENT_SUBJECT = "spiffe://fixture.odis.local/agent/mcp-client"
_ENDPOINT_ID = "jira-prod-mcp-v1"
_CORRELATION_ID = "00000000-0000-4000-8000-0000000000e2"


def _bridge_auth(anchor: ExchangeAuditAnchor) -> BridgeAuth:
    """A fixture-Bridge auth. `anchor` is required: exchanging without one is refused."""
    agent_issuer = FixtureIdentityIssuer.generate()
    provider = fixture_subject_token_provider(
        agent_issuer, subject=_AGENT_SUBJECT, audience="https://bridge.odis.local/"
    )
    return BridgeAuth(
        subject_token_provider=provider,
        audience=_VENDOR_AUDIENCE,
        exchanger=FixtureTokenExchanger(),
        anchor=anchor,
    )


def _anchor(sink: factories.CapturingAuditSink | None = None) -> ExchangeAuditAnchor:
    return factories.exchange_anchor(sink, target_endpoint_id=_ENDPOINT_ID)


async def test_bridge_auth_threads_exchanged_bearer_through_the_sdk() -> None:
    captured: list[dict[str, str]] = []
    async with RunningVendor(captured) as vendor:
        client = HttpMcpClient(url=vendor.url, auth=_bridge_auth(_anchor()))
        result = await client.call_tool("update_issue", {"issue_key": "APF-7"})

    assert result.content[0]["text"] == "update_issue:APF-7"
    assert captured, "no HTTP request reached the vendor"
    # Every request the SDK sent (initialize + tools/call) carries the leg-2 bearer.
    auth_headers = authorization_headers(captured)
    assert all(h is not None and h.startswith("Bearer ") for h in auth_headers)
    bearer = auth_headers[0].removeprefix("Bearer ")  # type: ignore[union-attr]  # asserted non-None just above
    # All requests share the single exchanged token (no per-request re-mint).
    assert all(h == f"Bearer {bearer}" for h in auth_headers)
    claims = jwt.decode(bearer, options={"verify_signature": False})
    assert claims["aud"] == _VENDOR_AUDIENCE  # RFC 8707 audience binding
    assert claims["act"] == {"sub": _AGENT_SUBJECT}  # RFC 8693 delegation



async def test_trace_id_reaches_the_vendor_and_anchors_the_exchange() -> None:
    """One correlation id, both directions, through the full transport.

    The id the Router passed to `call_tool` arrives at the target as a header on every
    request, and the terminal-exchange record carries that same id — which is what lets
    an auditor put the credential mint and the forwarded call on one trail. Asserted
    together because they are one mechanism: the Bridge learns the id only by reading the
    header the transport wrote.
    """
    captured: list[dict[str, str]] = []
    sink = factories.CapturingAuditSink()
    async with RunningVendor(captured) as vendor:
        client = HttpMcpClient(url=vendor.url, auth=_bridge_auth(_anchor(sink)))
        await client.call_tool(
            "update_issue", {"issue_key": "APF-7"}, correlation_id=_CORRELATION_ID
        )

    trace_header = TRACE_HEADER_NAME.lower()
    assert captured, "no HTTP request reached the vendor"
    assert all(h.get(trace_header) == _CORRELATION_ID for h in captured)
    assert sink.event_types == ["odis.bridge.terminal_exchange"]
    event = sink.events[0]
    assert event.correlation_id == _CORRELATION_ID
    assert (event.extra or {})["correlation_source"] == "downstream_request"
    assert (event.extra or {})["target"]["endpoint_id"] == _ENDPOINT_ID
    # The exchanged bearer the vendor actually saw is the one the record fingerprints,
    # and the record holds no part of it.
    bearer = captured[0]["authorization"].removeprefix("Bearer ")
    assert bearer not in sink.output.getvalue()
    assert (event.extra or {})["credential"]["fingerprint"] == "sha256:" + hashlib.sha256(
        bearer.encode("utf-8")
    ).hexdigest()
