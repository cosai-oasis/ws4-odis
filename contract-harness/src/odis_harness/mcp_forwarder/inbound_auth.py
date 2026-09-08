"""Inbound credential validation for the Router's MCP surface.

The Router is an OAuth 2.1 resource server: an agent presents a workload JWT as a bearer
on every `tools/call`, and the Router validates it before any handler runs. `agent_id`
then comes from the verified `sub`, so the identity a policy is evaluated against and the
identity an audit event records are both *received* rather than asserted by the
enforcement point about itself.

Trust material mirrors the Vault plugin's `config/issuer` (`vault-plugin/backend/jwt.go`):
public keys, a bound issuer, and a bound audience, with an explicit algorithm allowlist.
Keeping the two in step means an operator configures one trust root, not two.

This validates a bearer; it does not make the credential holder-bound. A stolen token
replays until it expires. Proof-of-possession (ODIS-L1-09) needs DPoP or mTLS binding and
is not implemented.

Handling note: the SDK's `AccessToken` carries the raw JWT in `token` and renders it in
full under pydantic's default `repr`, and this module cannot set `repr=False` on a model
it does not own. So the credential must never reach a log call — no `AccessToken` and no
token string is passed to `_LOG`, and the rejection warnings below deliberately carry a
reason and nothing else. The other half is the logging config: structlog's development
`ConsoleRenderer` renders tracebacks with `show_locals=True`, which would dump the local
`token` from any exception crossing `verify_token`, so a deployment must configure the
JSON renderer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

import jwt
import structlog
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from mcp.server.auth.provider import AccessToken

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path


_LOG = structlog.get_logger(__name__)

#: Asymmetric algorithms only, and deliberately not configurable. Permitting an HMAC alg
#: would let a caller sign a token with a public key the Router publishes — the classic
#: JWT confusion attack — so this is not a knob an operator can widen.
#:
#: Matches `allowedSignatureAlgorithms` in `vault-plugin/backend/jwt.go`; `test_inbound_auth`
#: fails if the two diverge.
ALLOWED_ALGORITHMS = (
    "ES256",
    "ES384",
    "ES512",
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "EdDSA",
)

#: Matches `jwtLeeway` in `vault-plugin/backend/jwt.go`, so a credential the issuance
#: endpoint accepts is not rejected here over a few seconds of clock skew. Applied twice
#: on purpose — once by pyjwt, once by widening the `expires_at` handed to the SDK, whose
#: own re-check has no leeway of its own.
_CLOCK_LEEWAY_SECONDS = 60

#: Key types that can verify a member of ALLOWED_ALGORITHMS — RSA for RS*/PS*, EC for
#: ES*, Ed25519 for EdDSA. Written once: PEP 604 unions work in `isinstance`, so the
#: runtime check and the annotation cannot drift apart the way a parallel tuple would.
VerifyingKey = rsa.RSAPublicKey | ec.EllipticCurvePublicKey | ed25519.Ed25519PublicKey


class UntrustworthyKeyError(ValueError):
    """Trust material that cannot be used to verify a credential."""


def load_public_keys(pem_paths: Sequence[Path]) -> tuple[VerifyingKey, ...]:
    """Read and strictly parse each PEM as a public key.

    Strict on purpose. Handing `jwt.decode` raw bytes accepts anything pyjwt can coerce,
    including a *private* key PEM — so a one-character path mistake would park the
    issuer's signing key in the Router process and still verify tokens. Malformed
    material is equally bad in the other direction: pyjwt raises a `cryptography`
    `ValueError`, not a `PyJWTError`, which escapes the verifier and turns every request
    into a 500 instead of a 401. Both are caught here, at startup, before serving.
    """
    keys: list[VerifyingKey] = []
    for path in pem_paths:
        try:
            raw = path.read_bytes()
        except OSError as exc:
            message = f"cannot read inbound key {str(path)!r}: {exc}"
            raise UntrustworthyKeyError(message) from exc
        if b"PRIVATE KEY" in raw:
            message = (
                f"inbound key {str(path)!r} is a PRIVATE key. Supply the issuer's public "
                "key; a verifier never needs the signing key."
            )
            raise UntrustworthyKeyError(message)
        try:
            key = serialization.load_pem_public_key(raw)
        except (ValueError, TypeError, UnsupportedAlgorithm) as exc:
            message = f"inbound key {str(path)!r} is not a usable PEM public key: {exc}"
            raise UntrustworthyKeyError(message) from exc
        if not isinstance(key, VerifyingKey):
            # DH and DSA keys parse as public keys but cannot verify any algorithm in
            # ALLOWED_ALGORITHMS, so accepting one would mean rejecting every token at
            # request time instead of failing here.
            message = (
                f"inbound key {str(path)!r} is a {type(key).__name__}, which cannot verify "
                f"any of {', '.join(ALLOWED_ALGORITHMS)}"
            )
            raise UntrustworthyKeyError(message)
        keys.append(key)
    return tuple(keys)


@dataclass(frozen=True, kw_only=True, slots=True)
class WorkloadJwtVerifier:
    """Validates an inbound workload JWT against configured trust material.

    Returns `None` for anything that does not verify — a bad signature, the wrong issuer
    or audience, an expired token, an unlisted algorithm, or a missing `sub`. The SDK
    turns `None` into a 401, so every failure mode is a refusal rather than a
    partially-trusted call.
    """

    #: Parsed public keys of the trusted issuer, from `load_public_keys`. A production
    #: deployment fetches the equivalent from a JWKS endpoint.
    public_keys: Sequence[VerifyingKey]
    #: The `iss` this Router accepts. Required: a verifier that accepts any issuer
    #: authenticates the signature and nothing else.
    bound_issuer: str
    #: The `aud` this Router accepts — this Router's own identifier. Required, because
    #: without it any token the key signed replays here, including one minted for a
    #: different service entirely.
    bound_audience: str

    async def verify_token(self, token: str) -> AccessToken | None:
        claims = self._decode(token)
        if claims is None:
            return None
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            # Without a subject there is no agent identity to carry, which is the entire
            # point of validating the token.
            _LOG.warning("inbound_auth.rejected", reason="missing_sub")
            return None
        expires_at = claims.get("exp")
        return AccessToken(
            token=token,
            # `sub` in the SDK's `client_id` slot. A stretch — in OAuth those are different
            # things — but `AccessToken` models only `token`/`client_id`/`scopes`/
            # `expires_at`/`resource`, and `client_id` is the field `get_access_token()`
            # exposes to a handler. The workload's own identity is what we need there, so
            # this is the field it has to travel in.
            client_id=subject,
            scopes=[],
            # `BearerAuthBackend` re-checks this with **zero** leeway, so reporting the
            # raw `exp` would silently undo the leeway pyjwt just applied: a token five
            # seconds past expiry verifies here and is then 401'd at the transport, with
            # nothing logged to explain it. Report the instant our own policy actually
            # refuses at, so both checks agree.
            expires_at=(
                expires_at + _CLOCK_LEEWAY_SECONDS if isinstance(expires_at, int) else None
            ),
        )

    def _decode(self, token: str) -> dict[str, object] | None:
        """Verify against each trusted key in turn; `None` if none of them validate.

        `TypeError` is caught alongside `PyJWTError` because pyjwt does not normalize it:
        when the token's `alg` names a family the key cannot serve (an `RS256` header
        against an EC key, say), `Algorithm.prepare_key` raises a bare
        `TypeError("Expecting a PEM-formatted key.")` *before* checking the signature.
        The `alg` header is attacker-controlled and unauthenticated, so letting that
        escape turns a forged one-line token into a 500 out of the auth backend instead
        of a 401 — and, worse, aborts this loop on the first mismatched key, so a mixed
        RSA/EC trust set during a key rotation rejects every legitimate caller.
        go-jose returns an error here, which is why
        `vault-plugin/backend/jwt.go:verifyAny` has no equivalent case.
        """
        for key in self.public_keys:
            try:
                return jwt.decode(
                    token,
                    key,
                    algorithms=list(ALLOWED_ALGORITHMS),
                    issuer=self.bound_issuer,
                    audience=self.bound_audience,
                    # A minute of leeway, matching the Vault plugin's `jwtLeeway`, so a
                    # token that issuer accepts is not rejected here on clock skew.
                    leeway=_CLOCK_LEEWAY_SECONDS,
                    options={"require": ["exp", "sub", "iss", "aud"]},
                )
            except (jwt.PyJWTError, TypeError):
                continue
        # Deliberately coarse: the caller learns only that the token was rejected. Which
        # key failed, and why, stays in the log rather than going back to the agent.
        _LOG.warning("inbound_auth.rejected", reason="no_trusted_key_validated")
        return None


__all__ = ["ALLOWED_ALGORITHMS", "UntrustworthyKeyError", "WorkloadJwtVerifier", "load_public_keys"]
