"""Fixture providers — deterministic identities for tests + demos.

Candidates (SPIFFE / k8s SAT / cloud workload identity / HW-attested for
workload identity; Entra/OIDC / SAML / CLI flow for originating_principal).
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from odis_harness.substrate.identity import (
    AgentRuntimeCredential,
    OriginatingPrincipal,
)


class FixtureWorkloadIdentityProvider:
    """Returns a deterministic credential per `agent_id`."""

    def issue(self, principal_id: str, agent_id: str) -> AgentRuntimeCredential:
        del principal_id  # unused by the fixture issuer
        now = datetime.now(UTC)
        return AgentRuntimeCredential(
            agent_id=agent_id,
            workload_proof=f"fixture-svid-{agent_id}",
            issued_at=now,
            expires_at=now + timedelta(hours=1),
        )


class FixtureOriginatingPrincipalProvider:
    """Returns a fixed originating principal for the canonical demo."""

    def current_principal(self) -> OriginatingPrincipal:
        return OriginatingPrincipal(id="fixture-principal", type="entra_oidc")


__all__ = [
    "FixtureOriginatingPrincipalProvider",
    "FixtureWorkloadIdentityProvider",
]
