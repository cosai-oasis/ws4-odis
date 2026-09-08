"""Fixture ODIS Bridge — an in-process stand-in for the RFC 7523/8693 broker.

`FixtureTokenExchanger` mints the leg-2 token in-process (no network), recording the
RFC 8693 delegation shape: the exchanged token carries `sub="odis-router"` (the Router
acting as the OAuth client) and an `act` claim `{"sub": <agent subject>}` ("router
acting for agent"), scoped to the requested `audience` (RFC 8707). It is short-lived
(5 min) so the `BridgeAuth` refresh path is exercisable.

`fixture_subject_token_provider` is the Passport stand-in: a `Callable[[], str]` that
mints a FRESH agent workload JWT each call (so `BridgeAuth` always exchanges current
identity, never a cached subject token).

Production broker clients implement `TokenExchanger` directly; this module only
ships the runnable in-process fixture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

import jwt
import structlog

from odis_harness.bridge.exchange import ExchangedToken
from odis_harness.fixtures.issuer import FixtureIdentityIssuer

if TYPE_CHECKING:
    from collections.abc import Callable

_LOG = structlog.get_logger(__name__)

#: Leg-2 tokens are short-lived, and re-minted before expiry rather than long-lived;
#: 5 min mirrors the workload-JWT TTL.
_LEG2_TTL = timedelta(minutes=5)
#: The Router is the OAuth client subject of the exchanged token.
_ROUTER_SUBJECT = "odis-router"
#: Fallback agent subject when the subject token can't be decoded (best-effort).
_UNKNOWN_AGENT = "unknown-agent"


def _agent_subject(subject_token: str) -> str:
    """Best-effort `sub` from the agent's workload JWT; fall back to a constant.

    Signature is not verified here — the fixture only needs the claimed subject to
    record the `act` delegation shape. A production broker validates the assertion.
    """
    try:
        claims = jwt.decode(subject_token, options={"verify_signature": False})
    except jwt.PyJWTError:
        # Fail soft to a constant: an undecodable subject still yields a scoped token,
        # and the broker (not the fixture) is the validation point.
        _LOG.debug("bridge.subject_token_undecodable")
        return _UNKNOWN_AGENT
    subject = claims.get("sub")
    return subject if isinstance(subject, str) and subject else _UNKNOWN_AGENT


@dataclass(frozen=True, kw_only=True, slots=True)
class FixtureTokenExchanger:
    """In-process `TokenExchanger` standing in for the RFC 7523/8693 broker.

    Mints a short-lived bearer scoped to the requested `audience`, recording the
    RFC 8693 delegation shape (`sub=odis-router`, `act.sub=<agent>`). No network.
    """

    #: The broker stand-in's signing issuer; `repr=False` is on its private key.
    issuer: FixtureIdentityIssuer = field(
        default_factory=lambda: FixtureIdentityIssuer.generate(
            issuer="https://fixture.bridge.odis.local/", key_id="fixture-bridge-key-1"
        )
    )

    async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
        """Exchange the agent's workload JWT for an `audience`-scoped leg-2 token."""
        agent_subject = _agent_subject(subject_token)
        issued_at = datetime.now(UTC)
        bearer = self.issuer.mint(
            audience=audience,
            subject=_ROUTER_SUBJECT,
            claims={"act": {"sub": agent_subject}},
            ttl=_LEG2_TTL,
            issued_at=issued_at,
        )
        # Floor expires_at to whole seconds so it equals the JWT's int-second `exp`
        # claim. A sub-second expires_at would let `is_fresh` report fresh ~1s past
        # the floored token expiry.
        expires_at = datetime.fromtimestamp(int((issued_at + _LEG2_TTL).timestamp()), tz=UTC)
        # Do not log the bearer or the subject token (secrets); audience is non-secret.
        _LOG.debug("bridge.exchanged", audience=audience, act_sub=agent_subject)
        return ExchangedToken(bearer=bearer, expires_at=expires_at)


def fixture_subject_token_provider(
    issuer: FixtureIdentityIssuer, *, subject: str, audience: str
) -> Callable[[], str]:
    """Return a Passport stand-in that mints a FRESH agent workload JWT per call.

    `audience` here is the Bridge/broker's own audience (who the agent presents the
    assertion *to*) — distinct from the leg-2 token's vendor audience. The provider
    holds no static bearer: each call mints a new short-lived JWT.
    """

    def _provide() -> str:
        return issuer.mint(audience=audience, subject=subject)

    return _provide


__all__ = [
    "FixtureTokenExchanger",
    "fixture_subject_token_provider",
]
