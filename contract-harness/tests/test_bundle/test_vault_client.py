"""Tests for the Router-side VaultBundleClient.

Hermetic via `httpx.MockTransport` — no real socket, so these pass under
`pytest-socket --disable-socket`. The live dev-vault path is a separate task.

The client performs the mint-then-load handshake:
 1. JWT login (mechanism 1, caller authz) -> a client token,
 2. `apf/issue` with that token + the workload JWT -> the signed envelope.

The workload JWT is the ONLY credential the Router holds (Secret-Zero).
On any failure the client fails closed with a `VaultBundleError`.
"""

from __future__ import annotations

import base64
import json

import httpx
import pytest

from odis_harness.bundle.vault_client import (
    SignedBundle,
    VaultBundleClient,
    VaultBundleError,
)

# These tests are hermetic: every HTTP call is served in-process by
# `httpx.MockTransport`, so no real network socket is ever opened. The marker
# only re-enables the AF_UNIX self-pipe that pytest-asyncio's event loop needs
# under the suite-wide `--disable-socket`; it grants no real network access.
pytestmark = pytest.mark.enable_socket

_VAULT_ADDR = "https://vault.example:8200"
_LOGIN_MOUNT = "jwt"
_LOGIN_ROLE = "router"
_ISSUE_PATH = "apf/issue"
_WORKLOAD_JWT = "eyJ.workload.jwt"
_CLIENT_TOKEN = "s.deadbeefclienttoken"  # noqa: S105 — fixture token, not a real secret

#: A small canonical bundle JSON the issuer would sign — the payload that
#: `BundleLoader.load_signed` consumes downstream.
_BUNDLE_JSON = b'{"bundle_id":"odis-fixture-bundle","bundle_version":"1"}'
_SIGNATURE = "vault:v1:c29tZS1zaWduYXR1cmU="


def _login_response() -> httpx.Response:
    return httpx.Response(200, json={"auth": {"client_token": _CLIENT_TOKEN}})


def _issue_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "data": {
                "payload": base64.b64encode(_BUNDLE_JSON).decode("ascii"),
                "signature": _SIGNATURE,
                "signing": {
                    "key_name": "apf-bundle",
                    "key_version": 1,
                    "algorithm": "ed25519",
                },
            },
        },
    )


def _client(
    handler: httpx.MockTransport,
) -> VaultBundleClient:
    return VaultBundleClient(
        vault_addr=_VAULT_ADDR,
        jwt_login_mount=_LOGIN_MOUNT,
        jwt_login_role=_LOGIN_ROLE,
        issue_path=_ISSUE_PATH,
        transport=handler,
    )


async def test_fetch_signed_bundle_happy_path() -> None:
    # mint-then-load — login, then issue, returning the
    # decoded envelope ready for BundleLoader.load_signed.
    requests: list[httpx.Request] = []

    def handle(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == f"/v1/auth/{_LOGIN_MOUNT}/login":
            return _login_response()
        if request.url.path == f"/v1/{_ISSUE_PATH}":
            return _issue_response()
        message = f"unexpected path {request.url.path}"
        raise AssertionError(message)

    signed = await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
        workload_jwt=_WORKLOAD_JWT,
    )

    assert isinstance(signed, SignedBundle)
    assert signed.payload == _BUNDLE_JSON
    assert signed.signature == _SIGNATURE.encode("ascii")
    assert signed.key_name == "apf-bundle"
    assert signed.key_version == 1
    assert signed.algorithm == "ed25519"

    login_req, issue_req = requests
    # Login (mechanism 1, caller authz): role + workload jwt in the body.
    assert json.loads(login_req.content) == {
        "role": _LOGIN_ROLE,
        "jwt": _WORKLOAD_JWT,
    }
    # Issue: the login token rides as X-Vault-Token; the workload jwt is the
    # mechanism-2 credential (no static token).
    assert issue_req.headers["X-Vault-Token"] == _CLIENT_TOKEN
    assert json.loads(issue_req.content) == {"jwt": _WORKLOAD_JWT}


async def test_fetch_signed_bundle_connect_error_fails_closed() -> None:
    # a transport-level failure surfaces as VaultBundleError, never a
    # partial/empty SignedBundle.
    def handle(request: httpx.Request) -> httpx.Response:
        message = "connection refused"
        raise httpx.ConnectError(message, request=request)

    with pytest.raises(VaultBundleError):
        await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
            workload_jwt=_WORKLOAD_JWT,
        )


async def test_fetch_signed_bundle_non_2xx_issue_fails_closed() -> None:
    # a non-2xx from apf/issue (e.g. policy denied / no mapping) fails closed.
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/auth/{_LOGIN_MOUNT}/login":
            return _login_response()
        return httpx.Response(403, json={"errors": ["permission denied"]})

    with pytest.raises(VaultBundleError):
        await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
            workload_jwt=_WORKLOAD_JWT,
        )


async def test_fetch_signed_bundle_non_2xx_login_fails_closed() -> None:
    # a non-2xx from the JWT login fails closed before issue is attempted.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"errors": ["role not found"]})

    with pytest.raises(VaultBundleError):
        await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
            workload_jwt=_WORKLOAD_JWT,
        )


async def test_fetch_signed_bundle_missing_field_fails_closed() -> None:
    # a 2xx issue response missing a required field fails closed.
    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == f"/v1/auth/{_LOGIN_MOUNT}/login":
            return _login_response()
        return httpx.Response(200, json={"data": {"signature": _SIGNATURE}})

    with pytest.raises(VaultBundleError):
        await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
            workload_jwt=_WORKLOAD_JWT,
        )


async def test_fetch_signed_bundle_missing_login_token_fails_closed() -> None:
    # a 2xx login response without auth.client_token fails closed.
    def handle(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"auth": {}})

    with pytest.raises(VaultBundleError):
        await _client(httpx.MockTransport(handle)).fetch_signed_bundle(
            workload_jwt=_WORKLOAD_JWT,
        )
