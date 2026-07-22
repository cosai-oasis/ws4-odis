"""Fixture providers — deterministic identities for tests + demos.

Real candidates (SPIFFE / k8s SAT / cloud workload identity / HW-attested for
workload identity; Entra/OIDC / SAML / CLI flow for sponsor).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from odis_harness.substrate.identity import (
    AgentRuntimeCredential,
    SponsorIdentity,
)


class FixtureWorkloadIdentityProvider:
    """Returns a deterministic credential per `agent_id`."""

    def issue(self, sponsor_id: str, agent_id: str) -> AgentRuntimeCredential:
        del sponsor_id  # unused by the fixture issuer
        now = datetime.now(UTC)
        return AgentRuntimeCredential(
            agent_id=agent_id,
            workload_proof=f"fixture-svid-{agent_id}",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )


class FixtureSponsorIdentityProvider:
    """Returns a fixed sponsor identity for the canonical demo."""

    def current_sponsor(self) -> SponsorIdentity:
        return SponsorIdentity(id="fixture-sponsor", type="entra_oidc")


__all__ = [
    "FixtureSponsorIdentityProvider",
    "FixtureWorkloadIdentityProvider",
]
