"""Passport providers — agent runtime identity + originating principal.

This package exposes only the identity Protocols and fixtures consumed by the
Router's `RuntimeContextFactory` (`odis_harness.mcp_forwarder.identity`).
Orchestration belongs to the Router; sandbox containment belongs to OpenShell
or the equivalent substrate.
"""

from odis_harness.substrate.identity import (
    AgentRuntimeCredential,
    OriginatingPrincipal,
    OriginatingPrincipalProvider,
    WorkloadIdentityProvider,
)

__all__ = [
    "AgentRuntimeCredential",
    "OriginatingPrincipal",
    "OriginatingPrincipalProvider",
    "WorkloadIdentityProvider",
]
