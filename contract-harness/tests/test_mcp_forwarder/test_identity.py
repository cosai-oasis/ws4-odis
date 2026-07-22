"""RuntimeContextFactory (trusted identity production).

Replaces the SubstrateStub orchestrator's runtime-context-building role for the
Router. Reuses the kept Passport identity providers (substrate/identity.py +
fixtures.py). The security property: sponsor identity always comes from the
trusted provider, never from agent input.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

if TYPE_CHECKING:
    from odis_harness.contracts import RuntimeContext


def _factory() -> RuntimeContextFactory:
    return RuntimeContextFactory(
        workload_identity=FixtureWorkloadIdentityProvider(),
        sponsor_provider=FixtureSponsorIdentityProvider(),
    )


def _build() -> RuntimeContext:
    return _factory().build(
        agent_id="mcp-client",
        resource_family="jira-prod",
        tool="update_issue",
        policy_digest="a" * 64,
        correlation_id="11111111-2222-4333-8444-555555555555",
    )


def test_build_sources_sponsor_from_provider() -> None:
    ctx = _build()
    # FixtureSponsorIdentityProvider returns id="fixture-sponsor", type="entra_oidc"
    assert ctx.sponsor == {"id": "fixture-sponsor", "type": "entra_oidc"}


def test_build_agent_reflects_issued_credential() -> None:
    ctx = _build()
    assert ctx.agent["id"] == "mcp-client"


def test_build_sets_resource_family_explicitly_not_from_tool() -> None:
    """The factory uses the family name passed in, NOT a value parsed from the tool."""
    ctx = _build()
    assert ctx.target_resource == {"resource_family": "jira-prod"}


def test_build_threads_scalar_inputs_into_context() -> None:
    ctx = _build()
    assert ctx.correlation_id == "11111111-2222-4333-8444-555555555555"
    assert ctx.policy_digest == "a" * 64


def test_build_default_task_intent_when_empty() -> None:
    ctx = _build()
    assert "update_issue" in ctx.task_intent


def test_build_honors_explicit_task_intent() -> None:
    ctx = _factory().build(
        agent_id="mcp-client",
        resource_family="jira-prod",
        tool="update_issue",
        policy_digest="a" * 64,
        correlation_id="11111111-2222-4333-8444-555555555555",
        task_intent="add the odis-demo label",
    )
    assert ctx.task_intent == "add the odis-demo label"


def test_build_sponsor_is_provider_controlled_regardless_of_agent_id() -> None:
    """Security property: a different agent_id never changes the sponsor."""
    factory = _factory()
    ctx_a = factory.build(
        agent_id="agent-a",
        resource_family="jira-prod",
        tool="update_issue",
        policy_digest="a" * 64,
        correlation_id="11111111-2222-4333-8444-555555555555",
    )
    ctx_b = factory.build(
        agent_id="agent-b-claims-admin",
        resource_family="jira-prod",
        tool="update_issue",
        policy_digest="a" * 64,
        correlation_id="22222222-3333-4444-8555-666666666666",
    )
    assert ctx_a.sponsor == ctx_b.sponsor  # sponsor never reflects agent claims
