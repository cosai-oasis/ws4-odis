"""Tests for `cli.builders` — the leg-2 session establish boot phase (the DL-2 leg-2 boot phase).

`build_router_from_bundle` runs a named "establish leg-2 sessions" phase between
building the per-family vendor clients and populating discovery: every client that is
`SupportsSessionEstablish` is primed once, concurrently and resiliently (one family's
failure is logged + degraded, never fatal). `establish()` returns the audience it
established (or `None` when nothing was — e.g. `auth=None`); only a non-`None` return
emits `bridge.leg2.established`. These are hermetic — no OPA, no network: the
`PolicyEvaluator` is constructed but never invoked at build time.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.cli.builders import (
    build_router_from_bundle,
    establish_leg2_sessions,
)
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    McpClient,
    SupportsSessionEstablish,
    ToolDescriptor,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from tests.factories import audit_sink

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

# build_router_from_bundle drives async discovery; the event loop touches sockets.
pytestmark = pytest.mark.enable_socket


def _family(endpoint_id: str) -> Family:
    return Family(
        vendor_mcp=VendorMcp(endpoint_id=endpoint_id, url="https://example.invalid/"),
        policy="package odis_policy\n",
        tools={
            "update_issue": ToolPolicy(action_limits={"allowed_fields": ["labels"]}),
        },
        default_mode="strict",
    )


def _bundle(families: dict[str, Family]) -> Bundle:
    return Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families=families,
    )


class _EstablishingClient:
    """A vendor client that records establish() and can be made to raise.

    Implements the McpClient surface (list_tools/call_tool) plus the opt-in
    `establish` — so it is structurally `SupportsSessionEstablish`. `establish`
    returns `audience` (the established RFC 8707 audience), or `None` when it
    establishes nothing — mirroring `HttpMcpClient.establish`.
    """

    def __init__(self, *, raises: bool = False, audience: str | None = None) -> None:
        self.raises = raises
        self.audience = audience
        self.established = 0

    async def establish(self) -> str | None:
        self.established += 1
        if self.raises:
            message = "broker outage"
            raise RuntimeError(message)
        return self.audience

    async def list_tools(self) -> list[ToolDescriptor]:
        return [ToolDescriptor(name="update_issue", description="", input_schema={})]

    async def call_tool(
        self, name: str, arguments: Mapping[str, Any]
    ) -> object:  # pragma: no cover - not exercised here
        del name, arguments
        raise NotImplementedError


async def test_establish_phase_is_resilient_and_primes_other_families() -> None:
    """One family's establish() failure is logged + degraded; others still prime,
    and boot continues to a constructed Router (DL-2 resilience)."""
    failing = _EstablishingClient(raises=True)
    healthy = _EstablishingClient(audience="conf-mcp")
    clients = {"jira-prod": failing, "confluence-prod": healthy}
    bundle = _bundle({"jira-prod": _family("jira-mcp"), "confluence-prod": _family("conf-mcp")})

    router = await build_router_from_bundle(
        bundle=bundle,
        opa_binary="opa",  # never invoked at build time
        audit=audit_sink(),
        vendor_client_factory=lambda family: clients[
            next(n for n, f in bundle.families_iter() if f is family)
        ],
    )

    assert failing.established == 1, "the failing family's establish was attempted"
    assert healthy.established == 1, "a peer's failure must not skip other families"
    assert router.bundle is bundle, "boot continued past the failure to a Router"


async def test_establish_phase_is_noop_for_non_establishing_clients() -> None:
    """The default path: InMemoryMcpClient is NOT SupportsSessionEstablish, so the
    phase does nothing (no error) — mirrors the auth=None / no-`--bridge` default."""
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})]
    )
    assert not isinstance(client, SupportsSessionEstablish)
    bundle = _bundle({"jira-prod": _family("jira-mcp")})

    router = await build_router_from_bundle(
        bundle=bundle,
        opa_binary="opa",
        audit=audit_sink(),
        vendor_client_factory=lambda _family: client,
    )
    assert router.bundle is bundle


class _CapturingLog:
    """Stand-in for the builders module logger: records `info`/`exception` events as
    (event_name, kwargs) so a test can assert which structlog events fired."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict[str, Any]]] = []

    def info(self, event: str, **kwargs: Any) -> None:
        self.events.append((event, kwargs))

    def exception(self, event: str, **kwargs: Any) -> None:
        self.events.append((event, kwargs))

    def audiences(self, event: str = "bridge.leg2.established") -> list[str]:
        return [kw["audience"] for name, kw in self.events if name == event]

    def names(self) -> list[str]:
        return [name for name, _kw in self.events]


@pytest.fixture
def captured_log(monkeypatch: pytest.MonkeyPatch) -> _CapturingLog:
    """Patch the builders module logger with a recording double for the test."""
    log = _CapturingLog()
    monkeypatch.setattr("odis_harness.cli.builders._LOG", log)
    return log


async def test_plain_serve_clients_emit_no_established_event(
    captured_log: _CapturingLog,
) -> None:
    """The plain-`serve` path: an `HttpMcpClient(auth=None)` and an `InMemoryMcpClient`
    through the establish phase emit ZERO `bridge.leg2.established` logs — establish()
    returns None for both (one because not bridged, one because not establishing)."""
    clients: dict[str, McpClient] = {
        "jira-prod": HttpMcpClient(url="http://127.0.0.1:9/mcp"),  # auth=None
        "confluence-prod": InMemoryMcpClient(tools=[]),
    }
    await establish_leg2_sessions(clients)
    assert captured_log.audiences() == [], "plain path must log no established events"


async def test_bridged_client_emits_one_established_event_with_audience(
    captured_log: _CapturingLog,
) -> None:
    """A bridged `HttpMcpClient` (BridgeAuth) emits exactly one established event whose
    audience is the BridgeAuth's audience."""
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415

    from odis_harness.bridge.exchange import BridgeAuth, ExchangedToken  # noqa: PLC0415

    class _Exchanger:
        async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
            del subject_token, audience
            return ExchangedToken(
                bearer="primed", expires_at=datetime.now(UTC) + timedelta(minutes=5)
            )

    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="https://vendor.example/mcp",
        exchanger=_Exchanger(),
    )
    await establish_leg2_sessions(
        {"jira-prod": HttpMcpClient(url="http://127.0.0.1:9/mcp", auth=auth)}
    )
    assert captured_log.audiences() == ["https://vendor.example/mcp"]


async def test_establish_failure_is_isolated_from_concurrent_peer(
    captured_log: _CapturingLog,
) -> None:
    """A client whose establish raises is logged as failed while a concurrent bridged
    peer still establishes — the gather isolates each family."""
    failing = _EstablishingClient(raises=True)
    healthy = _EstablishingClient(audience="conf-mcp")

    await establish_leg2_sessions({"jira-prod": failing, "confluence-prod": healthy})

    assert failing.established == 1
    assert healthy.established == 1, "the healthy peer still established"
    assert captured_log.audiences() == ["conf-mcp"], "only the healthy peer is logged"
    failed = [n for n in captured_log.names() if n == "bridge.leg2.establish_failed"]
    assert len(failed) == 1, "the failing family logged exactly one establish_failed"
