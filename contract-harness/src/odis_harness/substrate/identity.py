"""AgentRuntimeCredential + identity provider Protocols.

What a workload-identity provider (SPIFFE, k8s SAT, a cloud workload-identity
token, HW-attested) would *issue*, and what an originating-principal source
(Entra/OIDC) would surface. The Router consumes both; it issues neither.
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
class OriginatingPrincipal:
    """ODIS §6.3's originating principal: the authenticated human or service principal
    whose authority initiated this task.

    Distinct from the agent's `sponsor_ref` / `owner_ref`, which are registration-time
    accountability fields on an Agent Registration Record (§6.1) and are not modelled here.
    """

    id: str
    type: str  # "entra_oidc", "saml", "local", etc.


class WorkloadIdentityProvider(Protocol):
    """Passport — issues short-lived runtime credentials.

    Candidates: SPIFFE SVID, Kubernetes SAT, a cloud workload-identity
    token, a hardware-attested token. The substrate consumes; it does not issue.
    """

    def issue(self, principal_id: str, agent_id: str) -> AgentRuntimeCredential: ...


class OriginatingPrincipalProvider(Protocol):
    """The Entra/OIDC source. A separate Protocol from WorkloadIdentityProvider because
    deployments often substitute one without the other: who is running is established by
    attestation, on whose authority by delegation."""

    def current_principal(self) -> OriginatingPrincipal: ...


__all__ = [
    "AgentRuntimeCredential",
    "OriginatingPrincipal",
    "OriginatingPrincipalProvider",
    "WorkloadIdentityProvider",
]
