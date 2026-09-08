"""Inbound credential validation on the Router's MCP surface (ODIS-L1-01)."""

from __future__ import annotations

import base64
import json
import re
from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from odis_harness.fixtures.issuer import FixtureIdentityIssuer
from odis_harness.mcp_forwarder.identity import UNVERIFIED_AGENT_TYPE, VERIFIED_AGENT_TYPE
from odis_harness.mcp_forwarder.inbound_auth import (
    ALLOWED_ALGORITHMS,
    WorkloadJwtVerifier,
    load_public_keys,
)
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import DEFAULT_AGENT_ID
from odis_harness.mcp_forwarder.server import _call, build_mcp_server
from odis_harness.mcp_forwarder.transports import build_asgi_app
from odis_harness.paths import repo_root
from tests import factories

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

    from httpx import Response

    from odis_harness.mcp_forwarder.inbound_auth import VerifyingKey

pytestmark = pytest.mark.enable_socket

#: Comfortably outside `_CLOCK_LEEWAY_SECONDS`, so an expiry test cannot pass by skew.
_WELL_PAST_LEEWAY = 3600

def _b64(part: dict[str, object]) -> str:
    """One JWT segment, unpadded base64url — for hand-forging a header pyjwt rejects."""
    raw = json.dumps(part).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


_PROTOCOL_VERSION = "2025-06-18"
_ISSUER = "https://spire.example.org/"
_AUDIENCE = "odis-router"
_SUBJECT = "spiffe://example.org/ns/default/sa/jira-bot"


@pytest.fixture(scope="module")
def issuer() -> FixtureIdentityIssuer:
    return FixtureIdentityIssuer.generate(issuer=_ISSUER, key_id="k1")


@pytest.fixture(scope="module")
def trusted_keys(
    issuer: FixtureIdentityIssuer, tmp_path_factory: pytest.TempPathFactory
) -> tuple[VerifyingKey, ...]:
    """The issuer's public key, loaded the way `serve` loads it — from a PEM on disk.

    Going through `load_public_keys` rather than handing the verifier raw PEM bytes
    keeps these tests on the path the CLI actually builds. pyjwt accepts bytes too, so
    a shortcut here would leave the strict loader unexercised by everything above it.
    """
    pem = tmp_path_factory.mktemp("keys") / "issuer.pem"
    pem.write_bytes(issuer.public_pem())
    return load_public_keys([pem])


def _verifier(keys: Sequence[VerifyingKey]) -> WorkloadJwtVerifier:
    return WorkloadJwtVerifier(
        public_keys=keys, bound_issuer=_ISSUER, bound_audience=_AUDIENCE
    )


@pytest.fixture
def audit() -> factories.CapturingAuditSink:
    return factories.CapturingAuditSink()


@pytest.fixture
def attributing_client(
    trusted_keys: tuple[VerifyingKey, ...], audit: factories.CapturingAuditSink
) -> Iterator[TestClient]:
    """An auth-gated client whose Router allows every call and records what it audits.

    `AllowAllPolicyEvaluator` keeps the subject of this test on identity rather than on
    the gate, and removes the `opa` dependency the evaluator would bring.
    """
    router = factories.router(
        opa_binary="",
        audit=audit,
        policy_evaluator=factories.AllowAllPolicyEvaluator(),
    )
    app = build_asgi_app(
        build_mcp_server(router, requires_authenticated_caller=True),
        token_verifier=_verifier(trusted_keys),
    )
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def client(trusted_keys: tuple[VerifyingKey, ...]) -> Iterator[TestClient]:
    """An ASGI client over the auth-gated app.

    Entered as a context manager so the session manager's lifespan runs — without it an
    admitted request fails inside the SDK, and only the rejected ones (which never reach
    it) would appear to pass.
    """
    router = factories.router(opa_binary="unused-in-this-test", audit=factories.audit_sink())
    app = build_asgi_app(
        build_mcp_server(router, requires_authenticated_caller=True),
        token_verifier=_verifier(trusted_keys),
    )
    with TestClient(app) as test_client:
        yield test_client


def _rpc(client: TestClient, headers: dict[str, str], body: dict[str, object]) -> Response:
    return client.post(
        "/mcp",
        headers={
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": _PROTOCOL_VERSION,
            **headers,
        },
        json=body,
    )


def _initialize(client: TestClient, headers: dict[str, str]) -> Response:
    return _rpc(
        client,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "t", "version": "1"},
            },
        },
    )


def test_call_without_a_bearer_is_refused(client: TestClient) -> None:
    """No credential, no entry — and the refusal happens before any handler runs."""
    response = _initialize(client, {})
    assert response.status_code == 401
    assert "www-authenticate" in {k.lower() for k in response.headers}


@pytest.mark.parametrize(
    ("label", "headers"),
    [
        ("garbage token", {"Authorization": "Bearer not-a-jwt"}),
        ("wrong scheme", {"Authorization": "Basic dXNlcjpwYXNz"}),
    ],
)
def test_unverifiable_credentials_are_refused(
    client: TestClient, label: str, headers: dict[str, str]
) -> None:
    del label
    assert _initialize(client, headers).status_code == 401


def test_token_for_another_audience_is_refused(
    client: TestClient, issuer: FixtureIdentityIssuer
) -> None:
    """A token minted for a different service must not be replayable at this Router."""
    token = issuer.mint(audience="some-other-service", subject=_SUBJECT)
    assert _initialize(client, {"Authorization": f"Bearer {token}"}).status_code == 401


def test_token_signed_by_an_untrusted_key_is_refused(client: TestClient) -> None:
    """Same `iss` string, different signing key. The claim is not the trust anchor."""
    other = FixtureIdentityIssuer.generate(issuer=_ISSUER, key_id="k2")
    token = other.mint(audience=_AUDIENCE, subject=_SUBJECT)
    assert _initialize(client, {"Authorization": f"Bearer {token}"}).status_code == 401


def test_a_valid_credential_is_admitted(
    client: TestClient, issuer: FixtureIdentityIssuer
) -> None:
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT)
    response = _initialize(client, {"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


# -- claim-level checks -------------------------------------------------------
# Direct against the verifier rather than through the ASGI stack: each of these is a
# property of the token, and routing them over HTTP would only re-assert that a `None`
# from `verify_token` becomes a 401, which the tests above already cover.


async def test_a_trusted_key_does_not_vouch_for_another_issuer(
    issuer: FixtureIdentityIssuer, trusted_keys: tuple[VerifyingKey, ...]
) -> None:
    """The key validates, so only the `iss` binding can refuse this one.

    Distinct from the untrusted-key case: here the signature is good and the token is
    rejected purely on which issuer minted it.
    """
    verifier = WorkloadJwtVerifier(
        public_keys=trusted_keys,
        bound_issuer="https://a-different-issuer.example.org/",
        bound_audience=_AUDIENCE,
    )
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT)
    assert await verifier.verify_token(token) is None


def test_an_expired_credential_is_refused(
    client: TestClient, issuer: FixtureIdentityIssuer
) -> None:
    """Past the clock leeway, so this fails on expiry rather than on skew tolerance."""
    token = issuer.mint(
        audience=_AUDIENCE, subject=_SUBJECT, ttl=-timedelta(seconds=_WELL_PAST_LEEWAY)
    )
    assert _initialize(client, {"Authorization": f"Bearer {token}"}).status_code == 401


def test_a_credential_within_the_clock_leeway_is_admitted(
    client: TestClient, issuer: FixtureIdentityIssuer
) -> None:
    """The other side of the leeway: a few seconds of skew must not refuse a live token.

    Guards the pairing with the Vault plugin's `jwtLeeway` — a credential the issuance
    endpoint accepts has to be accepted here too. Over HTTP rather than against the
    verifier directly, because the transport applies an expiry check of its own: asserting
    on `verify_token` alone passes while every legitimate caller is still 401'd.
    """
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT, ttl=-timedelta(seconds=5))
    assert _initialize(client, {"Authorization": f"Bearer {token}"}).status_code == 200


async def test_the_verified_subject_becomes_the_access_token_identity(
    issuer: FixtureIdentityIssuer, trusted_keys: tuple[VerifyingKey, ...]
) -> None:
    """`sub` is what the handler reads back as the agent id."""
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT)
    access = await _verifier(trusted_keys).verify_token(token)
    assert access is not None
    assert access.client_id == _SUBJECT


# -- attribution --------------------------------------------------------------
# The point of validating the credential at all: the identity the Router policies and
# logs is the one it received, not one it asserted about itself.


async def test_the_verified_subject_is_the_audited_agent(
    attributing_client: TestClient,
    audit: factories.CapturingAuditSink,
    issuer: FixtureIdentityIssuer,
) -> None:
    """A forwarded call is attributed to the token's `sub`, marked as verified."""
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT)
    headers = {"Authorization": f"Bearer {token}"}
    assert _initialize(attributing_client, headers).status_code == 200
    response = _rpc(
        attributing_client,
        headers,
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": f"{factories.FAMILY_NAME}.{factories.TOOL_NAME}",
                "arguments": {"issue_key": "APF-1", "fields": {"labels": ["x"]}},
            },
        },
    )
    assert response.status_code == 200

    assert audit.event_types == ["odis.mcp.forward"]
    agent = audit.events[0].extra["actor"]["agent"]
    assert agent == {"id": _SUBJECT, "type": VERIFIED_AGENT_TYPE}
    # And not the fallback the unauthenticated paths use — the distinction is the
    # difference between a received identity and an asserted one.
    assert agent["id"] != DEFAULT_AGENT_ID
    assert agent["type"] != UNVERIFIED_AGENT_TYPE


def test_the_algorithm_allowlist_matches_the_vault_plugin() -> None:
    """The two verifiers must accept the same algorithms.

    `inbound_auth` says it mirrors the plugin's trust model, and an operator configures
    one issuer for both. A credential the plugin mints and the Router refuses is an
    outage debugged across two languages, so the claim is checked rather than asserted.
    """
    source = (repo_root() / "vault-plugin" / "backend" / "jwt.go").read_text(encoding="utf-8")
    # The slice literal only — the enclosing `[]jose.SignatureAlgorithm` return type
    # would otherwise read as an eleventh algorithm.
    literal = source.split("return []jose.SignatureAlgorithm{", 1)[1].split("}", 1)[0]
    assert set(re.findall(r"jose\.(\w+)", literal)) == set(ALLOWED_ALGORITHMS)


async def test_a_call_that_cannot_be_attributed_is_refused_not_downgraded(
    audit: factories.CapturingAuditSink,
) -> None:
    """Auth is declared on, but no verified token reached the handler.

    Defence in depth against the SDK changing how the request task is spawned: the
    contextvar the handler reads is set by middleware, so a change there would leave the
    token behind while the transport still refused unauthenticated requests. Falling back
    to `router.agent_id` would keep forwarding under a name that is not the caller's.
    Built directly rather than over HTTP because the transport, working correctly, makes
    this state unreachable — that is exactly why it needs asserting.
    """
    router = factories.router(
        opa_binary="",
        audit=audit,
        policy_evaluator=factories.AllowAllPolicyEvaluator(),
    )
    result = await _call(
        router,
        f"{factories.FAMILY_NAME}.{factories.TOOL_NAME}",
        {"issue_key": "APF-1"},
        auth_required=True,
    )

    assert result.isError
    assert audit.event_types == ["odis.mcp.forward_refused"]
    event = audit.events[0]
    # Its own code, not `internal_error`: a caller that got past the gate without an
    # identity is a different incident from a bug in the forward path.
    assert event.reason_code == ReasonCode.UNATTRIBUTED_CALLER
    # No actor and no resource family: the call was refused before either was resolved,
    # and inventing them would misreport who acted and that policy was consulted.
    assert "actor" not in event.extra
    assert event.resource_family is None


# -- key/algorithm mismatch ---------------------------------------------------
# pyjwt raises a bare `TypeError` — not a `PyJWTError` — when the token's `alg` names a
# family the key cannot serve, and it does so before checking the signature. Both cases
# below escaped the verifier as a 500 until `_decode` caught it.


async def test_a_forged_alg_header_is_refused_not_raised(
    trusted_keys: tuple[VerifyingKey, ...],
) -> None:
    """`alg` is attacker-controlled and unauthenticated: it must not reach the caller."""
    header = _b64({"alg": "RS256", "typ": "JWT"})
    payload = _b64({"sub": _SUBJECT, "iss": _ISSUER, "aud": _AUDIENCE, "exp": 9999999999})
    assert await _verifier(trusted_keys).verify_token(f"{header}.{payload}.AAAA") is None


async def test_a_valid_token_is_admitted_past_a_key_of_another_type(
    issuer: FixtureIdentityIssuer, trusted_keys: tuple[VerifyingKey, ...]
) -> None:
    """The shape of a key rotation: two key types in the trust set, one valid token.

    Aborting the loop on the first type-mismatched key rejects every legitimate caller
    for the length of the rotation, so the mismatch has to be skipped, not fatal.
    """
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    verifier = WorkloadJwtVerifier(
        public_keys=(rsa_key, *trusted_keys), bound_issuer=_ISSUER, bound_audience=_AUDIENCE
    )
    token = issuer.mint(audience=_AUDIENCE, subject=_SUBJECT)
    access = await verifier.verify_token(token)
    assert access is not None
    assert access.client_id == _SUBJECT
