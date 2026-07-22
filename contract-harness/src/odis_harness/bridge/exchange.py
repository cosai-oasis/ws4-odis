"""The ODIS Bridge — leg-2 (Router→vendor MCP) token-exchange seam.

The Router authenticates to each vendor MCP as an OAuth 2.1 client, presenting a
SHORT-LIVED, audience-scoped bearer on every request (MCP 2025-11-25 Authorization).
That bearer is obtained via the **ODIS Bridge**: an RFC 8693 token exchange of the
agent's Passport identity (the workload JWT) for a vendor-`audience`-scoped
downstream access token (RFC 8707 Resource Indicators). It is NOT the agent's
inbound token re-presented — the no-token-passthrough rule (REQ-9.4) means the
leg-2 token is freshly minted/exchanged and distinct from both the caller's token
and the vendor→provider credential.

This module defines the seam:

- `ExchangedToken` — a short-lived bearer + its expiry (the bearer is `repr=False`).
- `TokenExchanger` (Protocol) — exchange a subject token for an audience-scoped one.
- `BridgeAuth` (`httpx.Auth`) — the seam wired into `HttpMcpClient.auth`. It hydrates
  the token at runtime, re-presents it per request, and re-mints on expiry (or within
  `leeway`), guarded by an `asyncio.Lock` so concurrent requests trigger a single
  exchange. The bearer never touches a log or a repr.

Production broker clients implement `TokenExchanger`; this module ships the seam
plus the async auth flow.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Protocol, runtime_checkable

import httpx

if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Callable, Generator

_DEFAULT_LEEWAY = timedelta(seconds=30)


@dataclass(frozen=True, kw_only=True, slots=True)
class ExchangedToken:
    """A short-lived, audience-scoped leg-2 bearer plus its expiry.

    The bearer is a credential, so `repr=False` keeps it out of reprs and locals
    dumps; it is hydrated at runtime and never persisted.
    """

    #: repr suppressed so the bearer never lands in a log/traceback locals dump.
    bearer: str = field(repr=False)
    expires_at: datetime

    def is_fresh(self, *, now: datetime, leeway: timedelta) -> bool:
        """True iff the token is still valid with `leeway` to spare before `expires_at`."""
        return now + leeway < self.expires_at


@runtime_checkable
class TokenExchanger(Protocol):
    """Exchanges the agent's workload JWT for a vendor-`audience`-scoped token.

    Production implementations POST an RFC 8693 token-exchange (or RFC 7523
    JWT-bearer) request to an OSS broker; the fixture mints the token in-process.
    """

    async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
        """Return a short-lived bearer bound to `audience` (RFC 8707)."""
        ...


class BridgeAuth(httpx.Auth):
    """`httpx.Auth` that attaches a Bridge-exchanged leg-2 bearer to every request.

    Wired into `HttpMcpClient.auth`, so the bearer rides every HTTP request the SDK
    sends to the vendor MCP (MCP 2025-11-25 Authorization — no stateful session). The
    cached token is hydrated at runtime, re-presented per call, and re-minted when it
    is missing or within `leeway` of expiry. An `asyncio.Lock` guards the re-mint so
    concurrent requests trigger a single exchange (no stampede). The bearer and the
    subject token are never logged.

    The forwarder is async, so only `async_auth_flow` is supported; the sync hooks
    raise a clear error.
    """

    def __init__(
        self,
        *,
        subject_token_provider: Callable[[], str],
        audience: str,
        exchanger: TokenExchanger,
        leeway: timedelta = _DEFAULT_LEEWAY,
    ) -> None:
        self._subject_token_provider = subject_token_provider
        self._audience = audience
        self._exchanger = exchanger
        self._leeway = leeway
        #: Cached exchanged token; repr-safe (the bearer inside is repr=False) and
        #: never persisted to disk. Underscored so it stays an implementation detail.
        self._token: ExchangedToken | None = None
        self._lock = asyncio.Lock()

    @property
    def audience(self) -> str:
        """The vendor-MCP audience (RFC 8707) this auth requests tokens for."""
        return self._audience

    async def establish(self) -> None:
        """Eagerly prime the cached leg-2 token (the boot-time handshake, DL-2).

        Idempotent: delegates to `_current_token`, so it exchanges once when the
        cache is cold and is a no-op when the cached token is still fresh. Lets the
        Router surface broker/handshake failures at a named boot phase rather than
        on a user's first forward; later requests reuse the primed token (one
        handshake per vendor). Fails closed — any exchange error propagates to the
        caller, which logs + degrades that family.
        """
        await self._current_token()

    async def _current_token(self, *, force: bool = False) -> ExchangedToken:
        """Return a fresh cached token, re-minting under the lock if needed.

        With `force=True` the freshness short-circuit is skipped on BOTH the outer
        check and the re-check under the lock, so a fresh-but-rejected token is always
        re-exchanged (the vendor-401/403 path); the bearer is never logged.
        """
        now = datetime.now(UTC)
        cached = self._token
        if not force and cached is not None and cached.is_fresh(now=now, leeway=self._leeway):
            return cached
        async with self._lock:
            # Re-check inside the lock: a concurrent request may have already minted.
            now = datetime.now(UTC)
            cached = self._token
            if not force and cached is not None and cached.is_fresh(now=now, leeway=self._leeway):
                return cached
            # Fetch a FRESH agent JWT, then exchange it for the leg-2 bearer.
            subject_token = self._subject_token_provider()
            token = await self._exchanger.exchange(
                subject_token=subject_token, audience=self._audience
            )
            self._token = token
            return token

    async def async_auth_flow(
        self, request: httpx.Request
    ) -> AsyncGenerator[httpx.Request, httpx.Response]:
        """httpx's async hook: attach the Bridge-exchanged bearer to the request.

        On a vendor 401/403 (the cached token was rejected mid-TTL — revoked, key
        rotation, or audience drift), re-mint a fresh token and retry exactly once so
        a stale-but-unexpired token is not re-presented until expiry.
        """
        token = await self._current_token()
        request.headers["Authorization"] = f"Bearer {token.bearer}"
        response = yield request
        if response.status_code in (401, 403):
            token = await self._current_token(force=True)
            request.headers["Authorization"] = f"Bearer {token.bearer}"
            yield request

    def sync_auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        """Not supported — the forwarder is async; use an async httpx client."""
        del request
        message = (
            "BridgeAuth requires an async client (the forwarder is async); "
            "use httpx.AsyncClient / async_auth_flow, not a sync client."
        )
        raise RuntimeError(message)

    def auth_flow(self, request: httpx.Request) -> Generator[httpx.Request, httpx.Response]:
        """Not supported — see `sync_auth_flow`."""
        return self.sync_auth_flow(request)


__all__ = ["BridgeAuth", "ExchangedToken", "TokenExchanger"]
