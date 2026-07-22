"""Unit tests for the ODIS Bridge seam (`bridge/exchange.py`).

Hermetic: a stub `TokenExchanger` drives `BridgeAuth.async_auth_flow` over fake
`httpx.Request`s — no network, no MCP transport. Covers attach-bearer, no-remint
while fresh, remint when expired/within leeway, single-exchange under concurrency,
the sync-flow guard, and the secret never landing in a repr.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from odis_harness.bridge.exchange import BridgeAuth, ExchangedToken

# Async tests need the event loop's self-pipe socket (suite is --disable-socket).
pytestmark = pytest.mark.enable_socket


@dataclass
class _StubExchanger:
    """Records every `exchange` call and returns tokens from a FIFO of expiries.

    The bearer encodes the call index so a re-mint is observable. `subjects` records
    each subject_token seen (proving a FRESH one is fetched per re-mint).
    """

    expiries: list[datetime]
    calls: int = 0
    subjects: list[str] = field(default_factory=list)

    async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
        self.subjects.append(subject_token)
        idx = self.calls
        self.calls += 1
        expires_at = self.expiries[min(idx, len(self.expiries) - 1)]
        return ExchangedToken(bearer=f"bearer-{idx}-{audience}", expires_at=expires_at)


def _request() -> httpx.Request:
    return httpx.Request("POST", "http://vendor.local/mcp")


def _response(status_code: int = 200) -> httpx.Response:
    return httpx.Response(status_code, request=_request())


async def _run_flow(auth: BridgeAuth) -> httpx.Request:
    """Drive `async_auth_flow` once with a 200 response and return the mutated request.

    Sends a 200 back so the (single-yield) happy path completes without a retry.
    """
    request = _request()
    gen = auth.async_auth_flow(request)
    sent = await gen.__anext__()
    with pytest.raises(StopAsyncIteration):
        await gen.asend(_response(200))
    return sent


async def test_async_auth_flow_attaches_bearer() -> None:
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="https://vendor.example/mcp",
        exchanger=exchanger,
    )
    sent = await _run_flow(auth)
    assert sent.headers["Authorization"] == "Bearer bearer-0-https://vendor.example/mcp"
    assert exchanger.calls == 1


async def test_200_first_response_does_not_retry() -> None:
    """A 200 first response ends the flow after one yield — no re-mint, no second yield."""
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt", audience="aud", exchanger=exchanger
    )
    gen = auth.async_auth_flow(_request())
    await gen.__anext__()
    with pytest.raises(StopAsyncIteration):
        await gen.asend(_response(200))
    assert exchanger.calls == 1, "a 200 must not trigger a re-mint"


@pytest.mark.parametrize("reject_status", [401, 403])
async def test_remints_and_retries_once_on_rejection(reject_status: int) -> None:
    """A 401/403 first response re-mints a FRESH token and re-yields with the NEW bearer
    (a token the vendor rejected mid-TTL must not be re-presented)."""
    # Both expiries fresh: the re-mint is driven by the rejection, not staleness.
    exchanger = _StubExchanger(
        expiries=[
            datetime.now(UTC) + timedelta(minutes=5),
            datetime.now(UTC) + timedelta(minutes=5),
        ]
    )
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt", audience="aud", exchanger=exchanger
    )
    request = _request()
    gen = auth.async_auth_flow(request)
    first = await gen.__anext__()
    # Capture by value: httpx reuses the same request object across yields, so the
    # header string is read out NOW, before the retry overwrites it in place.
    first_bearer = first.headers["Authorization"]
    assert first_bearer == "Bearer bearer-0-aud"
    second = await gen.asend(_response(reject_status))
    assert second.headers["Authorization"] == "Bearer bearer-1-aud", "retry uses a NEW bearer"
    assert second.headers["Authorization"] != first_bearer, "the re-minted bearer differs"
    with pytest.raises(StopAsyncIteration):
        await gen.asend(_response(200))
    assert exchanger.calls == 2, "rejection forces exactly one re-exchange (retry once)"


async def test_does_not_remint_while_token_is_fresh() -> None:
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    first = await _run_flow(auth)
    second = await _run_flow(auth)
    assert first.headers["Authorization"] == second.headers["Authorization"]
    assert exchanger.calls == 1, "a fresh token must be reused, not re-minted"


async def test_reminted_once_expired() -> None:
    # First token already expired; second is fresh.
    exchanger = _StubExchanger(
        expiries=[
            datetime.now(UTC) - timedelta(seconds=1),
            datetime.now(UTC) + timedelta(minutes=5),
        ]
    )
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    first = await _run_flow(auth)
    second = await _run_flow(auth)
    assert first.headers["Authorization"] == "Bearer bearer-0-aud"
    assert second.headers["Authorization"] == "Bearer bearer-1-aud"
    assert exchanger.calls == 2, "an expired token must be re-minted"


async def test_reminted_when_within_leeway() -> None:
    # Token expires in 10s but leeway is 30s → treated as stale, re-minted.
    exchanger = _StubExchanger(
        expiries=[
            datetime.now(UTC) + timedelta(seconds=10),
            datetime.now(UTC) + timedelta(minutes=5),
        ]
    )
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
        leeway=timedelta(seconds=30),
    )
    await _run_flow(auth)
    second = await _run_flow(auth)
    assert second.headers["Authorization"] == "Bearer bearer-1-aud"
    assert exchanger.calls == 2


async def test_concurrent_requests_trigger_single_exchange() -> None:
    """Many concurrent first-time requests must trigger exactly one exchange (lock)."""

    @dataclass
    class _SlowExchanger:
        calls: int = 0

        async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
            del subject_token, audience
            self.calls += 1
            await asyncio.sleep(0.05)  # widen the race window
            return ExchangedToken(
                bearer="shared", expires_at=datetime.now(UTC) + timedelta(minutes=5)
            )

    exchanger = _SlowExchanger()
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    sents = await asyncio.gather(*(_run_flow(auth) for _ in range(20)))
    assert exchanger.calls == 1, "concurrent requests must share a single exchange"
    assert all(s.headers["Authorization"] == "Bearer shared" for s in sents)


async def test_provider_called_fresh_on_each_remint() -> None:
    """Each re-mint fetches a FRESH subject token (the Passport stand-in is re-read)."""
    minted: list[str] = []

    def _provider() -> str:
        token = f"agent-jwt-{len(minted)}"
        minted.append(token)
        return token

    exchanger = _StubExchanger(
        expiries=[
            datetime.now(UTC) - timedelta(seconds=1),  # forces a second mint
            datetime.now(UTC) + timedelta(minutes=5),
        ]
    )
    auth = BridgeAuth(subject_token_provider=_provider, audience="aud", exchanger=exchanger)
    await _run_flow(auth)
    await _run_flow(auth)
    assert exchanger.subjects == ["agent-jwt-0", "agent-jwt-1"]


def test_sync_auth_flow_raises_clear_error() -> None:
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=_StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)]),
    )
    with pytest.raises(RuntimeError, match="requires an async client"):
        next(auth.sync_auth_flow(_request()))
    with pytest.raises(RuntimeError, match="requires an async client"):
        next(auth.auth_flow(_request()))


def test_exchanged_token_repr_hides_bearer() -> None:
    token = ExchangedToken(
        bearer="super-secret-bearer", expires_at=datetime.now(UTC) + timedelta(minutes=5)
    )
    assert "super-secret-bearer" not in repr(token)


async def test_bridge_auth_repr_hides_bearer() -> None:
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    await _run_flow(auth)  # populate the cache
    # The bearer ("bearer-0-aud") is inside an ExchangedToken whose repr suppresses it.
    assert "bearer-0-aud" not in repr(auth)


async def test_establish_primes_token_with_a_single_exchange() -> None:
    """The eager handshake (DL-2): establish() exchanges exactly once."""
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    await auth.establish()
    assert exchanger.calls == 1


async def test_second_establish_while_fresh_does_not_re_exchange() -> None:
    """establish() is idempotent: a second call while the token is fresh is a no-op."""
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    await auth.establish()
    await auth.establish()
    assert exchanger.calls == 1, "a fresh primed token must be reused, not re-exchanged"


async def test_request_after_establish_reuses_primed_token() -> None:
    """A request after establish() reuses the primed token — no new exchange."""
    exchanger = _StubExchanger(expiries=[datetime.now(UTC) + timedelta(minutes=5)])
    auth = BridgeAuth(
        subject_token_provider=lambda: "agent-jwt",
        audience="aud",
        exchanger=exchanger,
    )
    await auth.establish()
    sent = await _run_flow(auth)
    assert sent.headers["Authorization"] == "Bearer bearer-0-aud"
    assert exchanger.calls == 1, "the primed token must serve the request (one handshake)"
