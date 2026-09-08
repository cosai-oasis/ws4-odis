"""Unit tests for the fixture ODIS Bridge (`bridge/fixtures.py`).

Hermetic: the fixture exchanger mints in-process — no network. Covers the RFC 8693
delegation shape (`aud`, `sub=odis-router`, `act.sub=<agent>`), the short TTL, the
best-effort subject fallback, and the Passport stand-in minting fresh JWTs.
"""

from __future__ import annotations

import jwt
import pytest

from odis_harness.fixtures.bridge import FixtureTokenExchanger, fixture_subject_token_provider
from odis_harness.fixtures.issuer import FixtureIdentityIssuer

# Async tests need the event loop's self-pipe socket (suite is --disable-socket).
pytestmark = pytest.mark.enable_socket

_LEG2_TTL_SECONDS = 5 * 60


def _decode(token: str) -> dict[str, object]:
    return jwt.decode(token, options={"verify_signature": False})


async def test_exchange_binds_audience_and_records_delegation() -> None:
    issuer = FixtureIdentityIssuer.generate()
    subject_token = issuer.mint(
        audience="https://bridge.odis.local/", subject="spiffe://agent/mcp-client"
    )
    exchanger = FixtureTokenExchanger()

    exchanged = await exchanger.exchange(
        subject_token=subject_token, audience="https://vendor.example/mcp"
    )

    claims = _decode(exchanged.bearer)
    # RFC 8707: token bound to the requested vendor audience.
    assert claims["aud"] == "https://vendor.example/mcp"
    # RFC 8693 delegation shape: router acting for the agent.
    assert claims["sub"] == "odis-router"
    assert claims["act"] == {"sub": "spiffe://agent/mcp-client"}


async def test_exchange_token_is_short_lived() -> None:
    exchanger = FixtureTokenExchanger()
    exchanged = await exchanger.exchange(subject_token="not-a-jwt", audience="aud")
    claims = _decode(exchanged.bearer)
    ttl = int(claims["exp"]) - int(claims["iat"])  # type: ignore[call-overload]  # JWT claim values are str at runtime
    assert ttl == _LEG2_TTL_SECONDS, "leg-2 token must be short-lived (~5 min)"


async def test_exchange_expires_at_matches_jwt_exp_to_the_second() -> None:
    """expires_at is floored to whole seconds so it equals the bearer's int `exp` claim
    — a sub-second expires_at would make is_fresh report fresh past the expiry."""
    exchanger = FixtureTokenExchanger()
    exchanged = await exchanger.exchange(subject_token="not-a-jwt", audience="aud")
    claims = _decode(exchanged.bearer)
    assert exchanged.expires_at.microsecond == 0, "expires_at must be whole seconds"
    assert int(exchanged.expires_at.timestamp()) == int(claims["exp"])  # type: ignore[call-overload]  # JWT exp is int at runtime


async def test_exchange_falls_back_when_subject_undecodable() -> None:
    """A non-JWT subject token still yields a scoped token (best-effort sub)."""
    exchanger = FixtureTokenExchanger()
    exchanged = await exchanger.exchange(subject_token="garbage", audience="aud")
    claims = _decode(exchanged.bearer)
    assert claims["act"] == {"sub": "unknown-agent"}
    assert claims["aud"] == "aud"


def test_subject_token_provider_mints_fresh_each_call() -> None:
    issuer = FixtureIdentityIssuer.generate()
    provider = fixture_subject_token_provider(
        issuer, subject="spiffe://agent/x", audience="https://bridge.odis.local/"
    )
    first = provider()
    second = provider()
    # Both are valid agent JWTs carrying the configured sub/aud.
    for token in (first, second):
        claims = _decode(token)
        assert claims["sub"] == "spiffe://agent/x"
        assert claims["aud"] == "https://bridge.odis.local/"


async def test_provider_token_drives_a_matching_exchange() -> None:
    """End-to-end of the fixture seam: provider JWT → exchange → act.sub matches."""
    issuer = FixtureIdentityIssuer.generate()
    provider = fixture_subject_token_provider(
        issuer, subject="spiffe://agent/y", audience="https://bridge.odis.local/"
    )
    exchanged = await FixtureTokenExchanger().exchange(
        subject_token=provider(), audience="https://vendor.example/mcp"
    )
    assert _decode(exchanged.bearer)["act"] == {"sub": "spiffe://agent/y"}
