"""OAuth2 token storage and its ODIS-CC-06 anchor (`mcp_forwarder/oauth.py`).

`--oauth2` performs a terminal token exchange: the SDK's `OAuthClientProvider` mints a
Target-MCP access token through authorization-code/PKCE and refreshes it, and the target
validates it natively. Nothing downstream records that, so this component anchors it.

The flow is interactive, so these tests drive `set_tokens` directly — which is the SDK's
only observation point for a minted token, and is called after the authorization-code
exchange and after every refresh.
"""

from __future__ import annotations

import hashlib
import subprocess
import sys
from typing import TYPE_CHECKING

import pytest
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from odis_harness.mcp_forwarder.oauth import (
    AnchoredOAuthTokenStorage,
    InMemoryOAuthTokenStorage,
)
from tests import factories

if TYPE_CHECKING:
    from odis_harness.bridge.audit import ExchangeAuditAnchor

pytestmark = pytest.mark.enable_socket

_EVENT_TYPE = "odis.bridge.terminal_exchange"
_ACCESS_TOKEN = "oauth-access-token-that-must-never-be-logged"
_REFRESH_TOKEN = "oauth-refresh-token-that-must-never-be-logged"
_ENDPOINT_ID = "jira-prod-mcp-v1"


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _anchor(sink: factories.CapturingAuditSink) -> ExchangeAuditAnchor:
    return factories.exchange_anchor(sink, target_endpoint_id=_ENDPOINT_ID)


def _token(access: str = _ACCESS_TOKEN, *, expires_in: int | None = 3600) -> OAuthToken:
    return OAuthToken(
        access_token=access, expires_in=expires_in, refresh_token=_REFRESH_TOKEN
    )


# -- the anchor is not optional ----------------------------------------------


def test_anchored_storage_cannot_be_built_without_an_anchor() -> None:
    """Unconstructable rather than refused at runtime.

    The mint happens inside the SDK, so `set_tokens` is only reached once the token
    exists — a runtime refusal there would discard a minted credential unrecorded, which
    is the worse outcome. Requiring the anchor at construction removes the state.
    """
    with pytest.raises(TypeError, match="anchor"):
        AnchoredOAuthTokenStorage()  # type: ignore[call-arg]


# -- one record per minted token ---------------------------------------------


async def test_first_token_is_anchored() -> None:
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())

    assert sink.event_types == [_EVENT_TYPE]
    extra = sink.events[0].extra or {}
    assert extra["trigger"] == "oauth_initial_token"
    assert extra["target"]["endpoint_id"] == _ENDPOINT_ID
    assert extra["credential"]["fingerprint"] == _sha256(_ACCESS_TOKEN)


async def test_refresh_is_anchored_and_distinguished_from_the_first_token() -> None:
    """The refresh is the case an operator most needs and the one a request-time hook
    would miss: the credential changes without any agent call."""
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())
    await storage.set_tokens(_token("refreshed-access-token"))

    assert sink.event_types == [_EVENT_TYPE, _EVENT_TYPE]
    triggers = [(e.extra or {})["trigger"] for e in sink.events]
    assert triggers == ["oauth_initial_token", "oauth_replacement_token"]
    fingerprints = [(e.extra or {})["credential"]["fingerprint"] for e in sink.events]
    assert fingerprints == [_sha256(_ACCESS_TOKEN), _sha256("refreshed-access-token")]


async def test_storage_still_stores_what_it_anchored() -> None:
    """Anchoring is additive: the SDK's storage contract is unchanged."""
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(factories.CapturingAuditSink()))

    assert await storage.get_tokens() is None
    token = _token()
    await storage.set_tokens(token)
    assert await storage.get_tokens() is token


# -- what the record must not carry ------------------------------------------


async def test_no_token_material_reaches_the_record() -> None:
    """Neither the access token nor the refresh token may be logged (ODIS-CC-06)."""
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())

    written = sink.output.getvalue()
    assert _ACCESS_TOKEN not in written
    assert _REFRESH_TOKEN not in written
    assert "Bearer" not in written


async def test_record_binds_no_subject_assertion_on_the_interactive_path() -> None:
    """There is no delegation-input assertion to bind: authorization was an interactive
    human grant the harness never sees. Recorded as an explicit null, so "none" reads as
    a fact about this path rather than as a field someone forgot to populate.
    """
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())

    assert (sink.events[0].extra or {})["subject_credential"] is None


async def test_record_asks_for_no_audience_on_the_interactive_path() -> None:
    """Recording the endpoint id here as if it were the requested audience would make the
    pair equal by construction, so the record would report agreement on every `--oauth2`
    event whether or not anything agreed — and the one diagnostic the pair exists for, a
    target whose bundle identity and requested audience have drifted, would be
    permanently unavailable on this leg. Nothing requests an audience on an interactive
    authorization-code flow, so the accurate value is null.
    """
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())

    target = (sink.events[0].extra or {})["target"]
    assert target["audience"] is None
    assert target["endpoint_id"] == _ENDPOINT_ID, "the target is still identified"


async def test_expiry_is_recorded_only_when_the_token_declares_one() -> None:
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token(expires_in=None))
    await storage.set_tokens(_token("second", expires_in=60))

    assert "expires_at" not in (sink.events[0].extra or {})["credential"]
    assert (sink.events[1].extra or {})["credential"]["expires_at"].endswith("Z")


async def test_anchored_storage_claims_no_semantic_enforcement() -> None:
    """A token mint passes no policy and no action-limit enforcer, same as the Bridge."""
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    await storage.set_tokens(_token())

    assert sink.events[0].resource_family is None


def _client_info() -> OAuthClientInformationFull:
    """The minimal registration the SDK stores after dynamic client registration."""
    return OAuthClientInformationFull(
        client_id="odis-test-client",
        redirect_uris=["http://127.0.0.1:0/callback"],  # type: ignore[list-item]
    )


async def test_client_info_is_not_anchored() -> None:
    """Dynamic client registration mints no Target-MCP credential, so it is not a
    terminal exchange and produces no record."""
    sink = factories.CapturingAuditSink()
    storage = AnchoredOAuthTokenStorage(anchor=_anchor(sink))

    assert await storage.get_client_info() is None
    await storage.set_client_info(_client_info())
    assert sink.events == [], "registering a client is not a terminal exchange"
    assert await storage.get_client_info() is not None, "it is still stored"


# -- the unanchored storage stays available for what it is -------------------


async def test_plain_storage_records_nothing() -> None:
    """`InMemoryOAuthTokenStorage` is the SDK contract with no anchor; it is what the
    anchored one delegates storage to, and on its own it records nothing."""
    storage = InMemoryOAuthTokenStorage()
    token = _token()
    await storage.set_tokens(token)
    assert await storage.get_tokens() is token


# -- import hygiene -----------------------------------------------------------


def test_importing_oauth_does_not_pull_in_the_bridge() -> None:
    """`cli.serve` imports this module at module level, so anything imported here lands
    on every CLI invocation — plain `demo` included, which performs no token exchange at
    all. The anchor types are therefore reached lazily.

    Checked in a fresh interpreter because `sys.modules` in this session already holds
    the Bridge from other tests, which would let an in-process check pass for the wrong
    reason. Pinned as a test because this invariant is only stated in comments, and
    comments do not fail.
    """
    probe = (
        "import sys, odis_harness.mcp_forwarder.oauth as m; "
        "leaked = sorted(k for k in sys.modules if k.startswith('odis_harness.bridge')); "
        "print(','.join(leaked))"
    )
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell, no external input
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "", f"importing oauth leaked: {result.stdout.strip()}"
