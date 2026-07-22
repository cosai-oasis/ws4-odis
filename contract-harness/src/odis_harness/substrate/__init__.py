"""Passport providers — agent runtime + sponsor identity.

This package exposes only the identity Protocols and fixtures consumed by the
Router's `RuntimeContextFactory` (`odis_harness.mcp_forwarder.identity`).
Orchestration belongs to the Router; sandbox containment belongs to OpenShell
or the equivalent substrate.
"""

from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)
from odis_harness.substrate.identity import (
    AgentRuntimeCredential,
    SponsorIdentity,
    SponsorIdentityProvider,
    WorkloadIdentityProvider,
)

__all__ = [
    "AgentRuntimeCredential",
    "FixtureSponsorIdentityProvider",
    "FixtureWorkloadIdentityProvider",
    "SponsorIdentity",
    "SponsorIdentityProvider",
    "WorkloadIdentityProvider",
]
