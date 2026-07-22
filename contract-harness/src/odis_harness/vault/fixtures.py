"""Fixture workload-identity JWT issuer for the MVP.

Mints a signed ES256 workload JWT and exposes the matching JWKS / PEM so the plugin
and Vault `jwt` auth can trust it — no SPIRE, no network. Production swaps this for
SPIRE (JWT-SVID via its OIDC Discovery Provider) by repointing the trusted issuer;
the validate / map / sign path is unchanged.

Fixture/dev material only: the private key is generated in-process, never persisted.
It exists to make the issuance flow exercisable hermetically. ES256 (EC P-256) mirrors
the shape of a real JWT-SVID.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Self

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

if TYPE_CHECKING:
    from collections.abc import Mapping

_ALG = "ES256"
_DEFAULT_ISSUER = "https://fixture.issuer.odis.local/"
#: Short-lived workload JWTs: a five-minute lifetime bounds replay of a leaked token.
_DEFAULT_TTL = timedelta(minutes=5)


@dataclass(frozen=True, kw_only=True, slots=True)
class FixtureIdentityIssuer:
    """An in-process ES256 issuer standing in for a real workload IdP."""

    issuer: str
    key_id: str
    #: repr suppressed so the key object never lands in a log/traceback locals dump.
    private_key: ec.EllipticCurvePrivateKey = field(repr=False)

    @classmethod
    def generate(cls, *, issuer: str = _DEFAULT_ISSUER, key_id: str = "fixture-key-1") -> Self:
        """Create an issuer with a freshly-generated P-256 key."""
        private_key = ec.generate_private_key(ec.SECP256R1())
        return cls(issuer=issuer, key_id=key_id, private_key=private_key)

    def mint(
        self,
        *,
        audience: str,
        subject: str,
        claims: Mapping[str, object] | None = None,
        ttl: timedelta | None = None,
        issued_at: datetime | None = None,
    ) -> str:
        """Mint a signed workload JWT carrying iss/sub/aud/iat/exp (+ extra claims)."""
        iat = issued_at or datetime.now(UTC)
        exp = iat + (ttl or _DEFAULT_TTL)
        payload: dict[str, object] = {
            "iss": self.issuer,
            "sub": subject,
            "aud": audience,
            "iat": int(iat.timestamp()),
            "exp": int(exp.timestamp()),
        }
        if claims:
            payload.update(claims)
        return jwt.encode(payload, self.private_key, algorithm=_ALG, headers={"kid": self.key_id})

    def public_pem(self) -> bytes:
        """The signing key's public half as PEM (SubjectPublicKeyInfo)."""
        return self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def jwks(self) -> dict[str, list[dict[str, str]]]:
        """The signing key as a one-entry JWK Set (RFC 7517) for `jwt` auth / the plugin."""
        jwk: dict[str, str] = json.loads(ECAlgorithm.to_jwk(self.private_key.public_key()))
        jwk.update({"kid": self.key_id, "use": "sig", "alg": _ALG})
        return {"keys": [jwk]}


__all__ = ["FixtureIdentityIssuer"]
