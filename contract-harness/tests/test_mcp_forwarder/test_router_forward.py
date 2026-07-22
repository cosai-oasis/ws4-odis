"""Router.forward + _permissive_forward."""

from __future__ import annotations

import pytest

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import McpRefusal, Router
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

pytestmark = [pytest.mark.enable_socket, pytest.mark.requires_opa]


_ALLOW_LABELS_ON_APF = """
package odis_policy
default decision := {"decision": "deny", "obligations": {}}
decision := {"decision": "allow", "obligations": {"allowed_fields": ["labels"]}} if {
    input.verb == "update_issue"
    startswith(input.request_body.issue_key, "APF-")
}
"""


class _CapturingAuditSink:
    def __init__(self) -> None:
        self.events: list[object] = []

    def emit(self, event: object) -> None:
        self.events.append(event)


def _event_types(sink: _CapturingAuditSink) -> list[str]:
    return [e.event_type for e in sink.events]  # type: ignore[attr-defined]


def _family(
    *,
    policy: str = _ALLOW_LABELS_ON_APF,
    action_limits_by_tool: dict[str, dict[str, object]] | None = None,
    default_mode: str = "strict",
) -> Family:
    default_action_limits = {"update_issue": {"allowed_fields": ["labels"]}}
    tool_limits = default_action_limits if action_limits_by_tool is None else action_limits_by_tool
    return Family(
        vendor_mcp=VendorMcp(endpoint_id="jira-prod-mcp-v1", url="https://x.invalid/"),
        policy=policy,
        tools={
            tool: ToolPolicy(action_limits=action_limits)
            for tool, action_limits in tool_limits.items()
        },
        default_mode=default_mode,  # type: ignore[arg-type]
    )


def _bundle(family: Family) -> Bundle:
    return Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families={"jira-prod": family},
    )


def _router(
    family: Family,
    *,
    vendor: InMemoryMcpClient | None = None,
    opa_binary: str,
    audit: _CapturingAuditSink,
) -> Router:
    client = vendor or InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )
    return Router(
        bundle=_bundle(family),
        policy_evaluator=PolicyEvaluator(opa_binary=opa_binary),
        context_factory=RuntimeContextFactory(
            workload_identity=FixtureWorkloadIdentityProvider(),
            sponsor_provider=FixtureSponsorIdentityProvider(),
        ),
        audit=audit,  # type: ignore[arg-type]
        vendor_clients={"jira-prod": client},
    )


_ALLOWED_ARGS = {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}


# -- policy path --------------------------------------------------------


async def test_forward_allow_calls_vendor_and_emits_forward_audit(
    opa_binary: str,
) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert client.calls == [("update_issue", _ALLOWED_ARGS)]
    assert _event_types(audit) == ["odis.mcp.forward"]


async def test_forward_returns_vendor_response_unchanged(opa_binary: str) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    payload = [{"type": "text", "text": "the vendor's exact bytes"}]
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=payload)},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == payload


async def test_forward_emits_decision_id_in_audit_when_policy_evaluated(
    opa_binary: str,
) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    router = _router(family, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    extra = audit.events[0].extra  # type: ignore[attr-defined]
    assert extra["decision_id"]  # non-empty
    assert extra["mode"] == "policy_allow"


async def test_forward_deny_does_not_call_vendor_emits_refused(
    opa_binary: str,
) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        )
    assert exc.value.reason_code == "deny"
    assert client.calls == []
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


async def test_forward_obligation_violation_does_not_call_vendor(
    opa_binary: str,
) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    # Policy allows (APF- prefix), but the call mutates a field outside
    # the decision's obligations (allowed_fields=[labels]).
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "APF-1", "fields": {"summary": "nope"}},
        )
    assert exc.value.reason_code == "obligation_violation"
    assert client.calls == []
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


async def test_forward_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = _CapturingAuditSink()
    family = _family()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
        unreachable=True,
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert exc.value.reason_code == "vendor_unreachable"
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


async def test_forward_policed_but_unenforceable_tool_fails_closed(
    opa_binary: str,
) -> None:
    """A tool the bundle declares as policed but the harness can't enforce
    denies (fail closed) rather than crashing or reaching the vendor."""
    audit = _CapturingAuditSink()
    # `transition_issue` is governed, but there is no
    # registered action-limit enforcer for it (only update_issue exists).
    family = _family(
        policy=(
            'package odis_policy\ndefault decision := {"decision": "allow", "obligations": {}}\n'
        ),
        action_limits_by_tool={"transition_issue": {"allowed_fields": ["status"]}},
    )
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="transition_issue", description="", input_schema={})],
        responses={"transition_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "transition_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unenforceable_tool"
    assert client.calls == []
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


async def test_forward_unpoliced_tool_strict_refuses(opa_binary: str) -> None:
    audit = _CapturingAuditSink()
    # Family declares policy for update_issue only; agent calls delete_issue.
    family = _family()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="delete_issue", description="", input_schema={})],
        responses={"delete_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "APF-1"})
    assert exc.value.reason_code == "unpoliced_tool"
    assert client.calls == []
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


# -- permissive path -----------------------------------------------------


async def test_permissive_unpoliced_tool_forwards(opa_binary: str) -> None:
    audit = _CapturingAuditSink()
    family = _family(default_mode="permissive")
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="delete_issue", description="", input_schema={})],
        responses={"delete_issue": ToolResult(content=[{"type": "text", "text": "deleted"}])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert result.content == [{"type": "text", "text": "deleted"}]
    assert client.calls == [("delete_issue", {"issue_key": "X-1"})]
    assert _event_types(audit) == ["odis.mcp.forward"]


async def test_permissive_forward_audit_has_permissive_mode_no_decision_id(
    opa_binary: str,
) -> None:
    audit = _CapturingAuditSink()
    family = _family(default_mode="permissive")
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="delete_issue", description="", input_schema={})],
        responses={"delete_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    extra = audit.events[0].extra  # type: ignore[attr-defined]
    assert extra["mode"] == "permissive"
    assert extra["decision_id"] is None


async def test_permissive_policed_tool_still_evaluates_policy(opa_binary: str) -> None:
    """Permissive only affects unpoliced tools; a policed tool still gets policy."""
    audit = _CapturingAuditSink()
    family = _family(default_mode="permissive")  # update_issue IS policed
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    # Outside-project issue_key → policy denies even in permissive family.
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        )
    assert exc.value.reason_code == "deny"
    assert client.calls == []


async def test_permissive_vendor_unreachable_emits_refused(opa_binary: str) -> None:
    audit = _CapturingAuditSink()
    family = _family(default_mode="permissive")
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="delete_issue", description="", input_schema={})],
        responses={"delete_issue": ToolResult(content=[])},
        unreachable=True,
    )
    router = _router(family, vendor=client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward("jira-prod", family, "delete_issue", {"issue_key": "X-1"})
    assert exc.value.reason_code == "vendor_unreachable"
    assert _event_types(audit) == ["odis.mcp.forward_refused"]


# -- end-to-end against the shipped example bundle ---------------------------
# Guards against Rego-vs-OPA-input-shape drift: the example bundle's policy
# must agree with what the Router actually sends (bare verb + raw args).


def _example_bundle() -> Bundle:
    from pathlib import Path  # noqa: PLC0415

    from odis_harness.bundle import BundleLoader, FixtureSignatureVerifier  # noqa: PLC0415

    repo_root = Path(__file__).resolve().parents[2]
    loader = BundleLoader(signature_verifier=FixtureSignatureVerifier())
    return loader.load(repo_root / "policy" / "bundle.example.yaml")


def _router_for_example(
    bundle: Bundle, client: InMemoryMcpClient, *, opa_binary: str, audit: _CapturingAuditSink
) -> Router:
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary=opa_binary),
        context_factory=RuntimeContextFactory(
            workload_identity=FixtureWorkloadIdentityProvider(),
            sponsor_provider=FixtureSponsorIdentityProvider(),
        ),
        audit=audit,  # type: ignore[arg-type]
        vendor_clients={"jira-prod": client},
    )


async def test_example_bundle_jira_prod_allows_labels_on_apf(opa_binary: str) -> None:
    bundle = _example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = _CapturingAuditSink()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[{"type": "text", "text": "ok"}])},
    )
    router = _router_for_example(bundle, client, opa_binary=opa_binary, audit=audit)
    result = await router.forward("jira-prod", family, "update_issue", _ALLOWED_ARGS)
    assert result.content == [{"type": "text", "text": "ok"}]
    assert _event_types(audit) == ["odis.mcp.forward"]


async def test_example_bundle_jira_prod_denies_other_project(opa_binary: str) -> None:
    bundle = _example_bundle()
    family = bundle.family("jira-prod")
    assert family is not None
    audit = _CapturingAuditSink()
    client = InMemoryMcpClient(
        tools=[ToolDescriptor(name="update_issue", description="", input_schema={})],
        responses={"update_issue": ToolResult(content=[])},
    )
    router = _router_for_example(bundle, client, opa_binary=opa_binary, audit=audit)
    with pytest.raises(McpRefusal) as exc:
        await router.forward(
            "jira-prod",
            family,
            "update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        )
    assert exc.value.reason_code == "deny"
    assert client.calls == []
