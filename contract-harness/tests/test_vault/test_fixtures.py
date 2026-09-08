"""Tests for the fixture workload-JWT issuer.

Hermetic: an in-process EC key signs and verifies. No SPIRE, no network.
"""

from __future__ import annotations

import jwt
import pytest

from odis_harness.fixtures.issuer import FixtureIdentityIssuer

_AUD = "apf-bundle-issuer"


def test_minted_jwt_has_claims_and_verifies() -> None:
    # A minted JWT carries the requested iss/aud/sub/claims and verifies
    # against the exposed public key.
    issuer = FixtureIdentityIssuer.generate()
    token = issuer.mint(
        audience=_AUD,
        subject="spiffe://example.org/agent/jira",
        claims={"group": "jira-writers"},
    )
    decoded = jwt.decode(token, issuer.public_pem(), algorithms=["ES256"], audience=_AUD)
    assert decoded["iss"] == issuer.issuer
    assert decoded["sub"] == "spiffe://example.org/agent/jira"
    assert decoded["aud"] == _AUD
    assert isinstance(decoded["aud"], str)  # a single dedicated audience, never a list
    assert decoded["group"] == "jira-writers"


def test_jwks_exposes_the_signing_key() -> None:
    # The plugin / jwt-auth trust the issuer via this JWK Set.
    issuer = FixtureIdentityIssuer.generate()
    jwks = issuer.jwks()
    assert len(jwks["keys"]) == 1
    key = jwks["keys"][0]
    assert key["kty"] == "EC"
    assert key["crv"] == "P-256"
    assert key["kid"] == issuer.key_id
    assert key["use"] == "sig"


def test_expired_token_is_rejected() -> None:
    # A stale token fails verification (the plugin checks exp upstream).
    from datetime import UTC, datetime, timedelta  # noqa: PLC0415 — test-only clock control

    issuer = FixtureIdentityIssuer.generate()
    token = issuer.mint(
        audience=_AUD,
        subject="s",
        issued_at=datetime.now(UTC) - timedelta(hours=1),
        ttl=timedelta(minutes=5),
    )
    with pytest.raises(jwt.ExpiredSignatureError):
        jwt.decode(token, issuer.public_pem(), algorithms=["ES256"], audience=_AUD)
