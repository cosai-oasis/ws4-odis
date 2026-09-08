"""VaultBundleClient — Router-side mint-then-load fetch of a signed bundle.

The Router calls Vault to obtain a freshly-minted, transit-signed bundle in a
two-step handshake:

 1. **JWT login** (mechanism 1 — caller authorization): present the workload JWT
    to the JWT auth mount, receive a short-lived Vault client token.
 2. **Issue** (`apf/issue`): present that client token plus the workload JWT,
    receive the canonical bundle bytes + a detached Vault-transit signature +
    the signing-key metadata.

The returned `SignedBundle.payload` / `.signature` feed
`BundleLoader.load_signed` for offline verification — the Router holds
NO static token; the workload JWT is the only credential it carries
(Secret-Zero).

Fail closed: any transport error, non-2xx response, or missing field
raises `VaultBundleError`; the client never returns a partial or empty
`SignedBundle`.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import httpx

if TYPE_CHECKING:
    from collections.abc import Mapping


class VaultBundleError(RuntimeError):
    """A signed bundle could not be fetched from Vault. Terminal, fail-closed."""


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedBundle:
    """The issued envelope: canonical bundle bytes + detached transit signature.

    `payload` is the exact bytes that were signed (so it round-trips into
    `BundleLoader.load_signed` unchanged); `signature` is the
    ``vault:vN:<base64>`` envelope as bytes. The `key_name` / `key_version` /
    `algorithm` describe the transit signing key for offline verification.
    """

    payload: bytes
    signature: bytes
    key_name: str
    key_version: int
    algorithm: str


@dataclass(frozen=True, kw_only=True, slots=True)
class VaultBundleClient:
    """Fetches a signed bundle from Vault via the mint-then-load handshake.

    `transport`, when set, is injected into the async HTTP client so tests can
    pass an `httpx.MockTransport` (fully hermetic — no socket). Production omits
    it and the client opens connections to `vault_addr`.
    """

    vault_addr: str
    jwt_login_mount: str
    jwt_login_role: str
    issue_path: str
    #: Optional transport for hermetic testing (e.g. `httpx.MockTransport`).
    #: None in production — the client uses the default network transport.
    transport: httpx.AsyncBaseTransport | None = field(default=None)

    async def fetch_signed_bundle(self, *, workload_jwt: str) -> SignedBundle:
        """Login then issue, returning the decoded `SignedBundle`.

        Fails closed with `VaultBundleError` on any transport error, non-2xx
        response, or missing/ill-typed field.
        """
        async with httpx.AsyncClient(
            base_url=self.vault_addr,
            transport=self.transport,
        ) as client:
            client_token = await self._login(client, workload_jwt=workload_jwt)
            return await self._issue(client, workload_jwt=workload_jwt, client_token=client_token)

    async def _login(self, client: httpx.AsyncClient, *, workload_jwt: str) -> str:
        """Mechanism 1 (caller authz): exchange the workload JWT for a client token."""
        body = await self._post_json(
            client,
            f"/v1/auth/{self.jwt_login_mount}/login",
            json={"role": self.jwt_login_role, "jwt": workload_jwt},
        )
        return _require_str(body, "auth", "client_token")

    async def _issue(
        self,
        client: httpx.AsyncClient,
        *,
        workload_jwt: str,
        client_token: str,
    ) -> SignedBundle:
        """Mechanism 2: present the client token + workload JWT for the signed envelope."""
        body = await self._post_json(
            client,
            f"/v1/{self.issue_path}",
            json={"jwt": workload_jwt},
            headers={"X-Vault-Token": client_token},
        )
        data = _require_mapping(body, "data")
        signing = _require_mapping(data, "signing")
        return SignedBundle(
            payload=_decode_b64(_require_str(data, "payload")),
            signature=_encode_ascii(_require_str(data, "signature")),
            key_name=_require_str(signing, "key_name"),
            key_version=_require_int(signing, "key_version"),
            algorithm=_require_str(signing, "algorithm"),
        )

    @staticmethod
    async def _post_json(
        client: httpx.AsyncClient,
        path: str,
        *,
        json: Mapping[str, Any],
        headers: Mapping[str, str] | None = None,
    ) -> Mapping[str, Any]:
        """POST JSON, raise `VaultBundleError` on transport error or non-2xx."""
        try:
            response = await client.post(path, json=dict(json), headers=dict(headers or {}))
            response.raise_for_status()
            parsed = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            # httpx.HTTPError covers transport errors AND raise_for_status's
            # HTTPStatusError; ValueError covers a non-JSON body. Fail closed.
            message = f"vault request to {path} failed: {exc}"
            raise VaultBundleError(message) from exc
        if not isinstance(parsed, dict):
            message = f"vault response from {path} was not a JSON object"
            raise VaultBundleError(message)
        return parsed


def _require_mapping(body: Mapping[str, Any], *keys: str) -> Mapping[str, Any]:
    value = _navigate(body, keys)
    if not isinstance(value, dict):
        message = f"vault response field {'.'.join(keys)!r} is not an object"
        raise VaultBundleError(message)
    return value


def _require_str(body: Mapping[str, Any], *keys: str) -> str:
    value = _navigate(body, keys)
    if not isinstance(value, str):
        message = f"vault response field {'.'.join(keys)!r} is not a string"
        raise VaultBundleError(message)
    return value


def _require_int(body: Mapping[str, Any], *keys: str) -> int:
    value = _navigate(body, keys)
    # bool is an int subclass; reject it so a JSON true/false isn't taken as a version.
    if not isinstance(value, int) or isinstance(value, bool):
        message = f"vault response field {'.'.join(keys)!r} is not an integer"
        raise VaultBundleError(message)
    return value


def _navigate(body: Mapping[str, Any], keys: tuple[str, ...]) -> Any:  # noqa: ANN401 — JSON value of any type; callers narrow it
    current: Any = body
    for key in keys:
        if not isinstance(current, dict) or key not in current:
            message = f"vault response missing field {'.'.join(keys)!r}"
            raise VaultBundleError(message)
        current = current[key]
    return current


def _decode_b64(payload: str) -> bytes:
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError) as exc:
        message = "vault response payload is not valid base64"
        raise VaultBundleError(message) from exc


def _encode_ascii(signature: str) -> bytes:
    """Encode a Vault transit signature (`vault:vN:<b64>`) as ASCII bytes.

    Vault signatures are ASCII by construction; a non-ASCII value means a
    malformed response, so fail closed rather than let `UnicodeEncodeError`
    escape the module's `VaultBundleError` contract.
    """
    try:
        return signature.encode("ascii")
    except UnicodeEncodeError as exc:
        message = "vault response signature is not ASCII"
        raise VaultBundleError(message) from exc


__all__ = ["SignedBundle", "VaultBundleClient", "VaultBundleError"]
