"""RuntimeContextFactory (trusted identity production).

The Router builds its own identity context from the injected Passport and
originating-principal providers. The security property under test: the principal always
comes from the provider, never from agent input, so an agent cannot claim whose authority
it acts under.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from odis_harness.fixtures.identity import (
    FixtureOriginatingPrincipalProvider,
    FixtureWorkloadIdentityProvider,
)
from odis_harness.mcp_forwarder.identity import CallerIdentity, RuntimeContextFactory
from tests import factories

if TYPE_CHECKING:
    from odis_harness.contracts import RuntimeContext


def _factory() -> RuntimeContextFactory:
    return RuntimeContextFactory(
        workload_identity=FixtureWorkloadIdentityProvider(),
        principal_provider=FixtureOriginatingPrincipalProvider(),
    )


def _build() -> RuntimeContext:
    return _factory().build(
        caller=CallerIdentity(agent_id="mcp-client"),
        resource_family="jira-prod",
        tool="update_issue",
        bundle=factories.bundle(),
        correlation_id="11111111-2222-4333-8444-555555555555",
    )


def test_build_sources_principal_from_provider() -> None:
    ctx = _build()
    # FixtureOriginatingPrincipalProvider returns id="fixture-principal", type="entra_oidc"
    assert ctx.originating_principal == {"id": "fixture-principal", "type": "entra_oidc"}


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
    assert ctx.policy_digest == factories.bundle().policy_digest


def test_build_default_task_intent_when_empty() -> None:
    ctx = _build()
    assert "update_issue" in ctx.task_intent


def test_build_honors_explicit_task_intent() -> None:
    ctx = _factory().build(
        caller=CallerIdentity(agent_id="mcp-client"),
        resource_family="jira-prod",
        tool="update_issue",
        bundle=factories.bundle(),
        correlation_id="11111111-2222-4333-8444-555555555555",
        task_intent="add the odis-demo label",
    )
    assert ctx.task_intent == "add the odis-demo label"


def test_build_principal_is_provider_controlled_regardless_of_agent_id() -> None:
    """Security property: a different agent_id never changes the originating principal."""
    factory = _factory()
    ctx_a = factory.build(
        caller=CallerIdentity(agent_id="agent-a"),
        resource_family="jira-prod",
        tool="update_issue",
        bundle=factories.bundle(),
        correlation_id="11111111-2222-4333-8444-555555555555",
    )
    ctx_b = factory.build(
        caller=CallerIdentity(agent_id="agent-b-claims-admin"),
        resource_family="jira-prod",
        tool="update_issue",
        bundle=factories.bundle(),
        correlation_id="22222222-3333-4444-8555-666666666666",
    )
    # The principal is provider-sourced, so a different agent_id cannot change it.
    assert ctx_a.originating_principal == ctx_b.originating_principal
