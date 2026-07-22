"""AgentRuntimeCredential + identity provider Protocols.

These types describe what a real workload-identity provider (SPIFFE,
k8s SAT, a cloud workload-identity token, HW-attested) would *issue* and what a
real sponsor-identity provider (Entra/OIDC) would surface. The substrate
*consumes* both; it does not issue either.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from datetime import datetime


@dataclass(frozen=True, kw_only=True)
class AgentRuntimeCredential:
    """Opaque workload-identity credential issued by Passport."""

    agent_id: str
    workload_proof: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True, kw_only=True)
class SponsorIdentity:
    """The Entra/OIDC-shaped sponsor identity the substrate trusts."""

    id: str
    type: str  # "entra_oidc", "saml", "local", etc.


class WorkloadIdentityProvider(Protocol):
    """Passport — issues short-lived runtime credentials.

    Real candidates: SPIFFE SVID, Kubernetes SAT, a cloud workload-identity
    token, a hardware-attested token. The substrate consumes; it does not issue.
    """

    def issue(self, sponsor_id: str, agent_id: str) -> AgentRuntimeCredential: ...


class SponsorIdentityProvider(Protocol):
    """The Entra/OIDC source. Distinct Protocol from WorkloadIdentityProvider
    because deployments often substitute one without the other."""

    def current_sponsor(self) -> SponsorIdentity: ...


__all__ = [
    "AgentRuntimeCredential",
    "SponsorIdentity",
    "SponsorIdentityProvider",
    "WorkloadIdentityProvider",
]
