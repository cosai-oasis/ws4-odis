"""Shared test builders.

The single home for test-side construction of `Family`, `Bundle`, `Router`, a recording
audit sink, an in-memory vendor, and a free localhost port. Tests build these from here
rather than declaring their own, so a change to a contract lands in one place.

Defaults describe the canonical Tier-3 scenario: one `jira-prod` family governing
`update_issue`, labels-only on `APF-` issues.

The Bridge/OAuth builders (`exchange_anchor`, `StubTokenExchanger`) follow the same rule as
the rest: one construction point per contract, so a change to `ExchangeAuditAnchor`'s fields
or to the `TokenExchanger` protocol lands here and nowhere else.
"""

from __future__ import annotations

import functools
import io
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any

from odis_harness.audit import AuditSink
from odis_harness.bridge.audit import ExchangeAuditAnchor
from odis_harness.bridge.exchange import ExchangedToken
from odis_harness.bundle import (
    Bundle,
    BundleLoader,
    Family,
    ToolPolicy,
    VendorMcp,
)
from odis_harness.cli.builders import RouterWiring
from odis_harness.contracts import AuthzRequest, EnvelopeValidator, RuntimeContext
from odis_harness.fixtures.identity import (
    FixtureOriginatingPrincipalProvider,
    FixtureWorkloadIdentityProvider,
)
from odis_harness.fixtures.signature import FixtureSignatureVerifier
from odis_harness.fixtures.vendor import InMemoryMcpClient
from odis_harness.mcp_forwarder.identity import CallerIdentity, RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyDecision, PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.transports import free_loopback_port
from odis_harness.mcp_forwarder.vendor_client import (
    McpClient,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.paths import default_schemas_dir, repo_root

if TYPE_CHECKING:
    from collections.abc import Mapping

    from odis_harness.bundle.types import DefaultMode
    from odis_harness.cli.builders import VendorClientContext
    from odis_harness.contracts import AuditEvent

# -- shared constants ---------------------------------------------------------

#: The family name every builder defaults to, matching the example bundle.
FAMILY_NAME = "jira-prod"
#: The governed tool the action-limit enforcer is registered for.
TOOL_NAME = "update_issue"

#: Allows `update_issue` on an `APF-` issue, obliging labels-only. The default policy
#: for forward tests.
ALLOW_LABELS_ON_APF = """
package odis_policy
default decision := {"decision": "deny", "obligations": {}}
decision := {"decision": "allow", "obligations": {"allowed_fields": ["labels"]}} if {
    input.verb == "update_issue"
    startswith(input.request_body.issue_key, "APF-")
}
"""


# -- validation / audit -------------------------------------------------------


@functools.lru_cache(maxsize=1)
def envelope_validator() -> EnvelopeValidator:
    """A validator over the repo's schemas directory.

    Cached: constructing one reads and compiles every schema, and the result is
    read-only, so every sink and fixture can share a single instance.
    """
    return EnvelopeValidator(default_schemas_dir())


def audit_sink() -> AuditSink:
    """A schema-validating sink that discards its output.

    For tests that need a sink to exist but never inspect what it wrote. Use
    `CapturingAuditSink` when the emitted events are the thing under test.
    """
    return AuditSink(output=io.StringIO(), validator=envelope_validator())


class CapturingAuditSink(AuditSink):
    """Records every emitted event *and* runs the validate-then-write pipeline.

    Subclasses `AuditSink` rather than duck-typing it for two reasons: `Router(audit=...)`
    accepts it without a `type: ignore`, and router-level tests still exercise schema
    validation — a double that only records would let an event violating its own schema
    pass a router test.
    """

    def __init__(self) -> None:
        self.output = io.StringIO()
        super().__init__(output=self.output, validator=envelope_validator())
        self.events: list[AuditEvent] = []

    def emit(self, event: AuditEvent) -> None:
        # Validate/write first: an event the sink rejects must not show up in `events`,
        # or the double would report an event that was never actually emitted.
        super().emit(event)
        self.events.append(event)

    @property
    def event_types(self) -> list[str]:
        """Emitted `event_type`s in order — the usual assertion target."""
        return [e.event_type for e in self.events]


# -- bundle / router ----------------------------------------------------------


def family(
    *,
    policy: str = ALLOW_LABELS_ON_APF,
    action_limits_by_tool: Mapping[str, Mapping[str, Any]] | None = None,
    default_mode: DefaultMode = "strict",
    endpoint_id: str = "jira-prod-mcp-v1",
    url: str = "https://x.invalid/",
) -> Family:
    """A `Family` governing `update_issue` with a labels-only action limit."""
    tool_limits: Mapping[str, Mapping[str, Any]] = (
        {TOOL_NAME: {"allowed_fields": ["labels"]}}
        if action_limits_by_tool is None
        else action_limits_by_tool
    )
    return Family(
        vendor_mcp=VendorMcp(endpoint_id=endpoint_id, url=url),
        policy=policy,
        tools={
            tool: ToolPolicy(action_limits=dict(limits)) for tool, limits in tool_limits.items()
        },
        default_mode=default_mode,
    )


def bundle(
    fam: Family | None = None,
    *,
    families: Mapping[str, Family] | None = None,
) -> Bundle:
    """A single-family `Bundle`, or a multi-family one via `families=`."""
    if fam is not None and families is not None:
        message = "pass either fam or families, not both"
        raise ValueError(message)
    if families is None:
        families = {FAMILY_NAME: fam if fam is not None else family()}
    return Bundle(bundle_id="b", bundle_version="0.1.0", trust_root_id="r", families=families)


def example_bundle() -> Bundle:
    """The shipped `policy/bundle.example.yaml`, loaded with the fixture verifier.

    Tests that assert against the shipped example bundle guard the Rego-vs-OPA-input
    contract: the shipped policy has to agree with what the Router actually sends.
    """
    loader = BundleLoader(signature_verifier=FixtureSignatureVerifier())
    return loader.load(repo_root() / "policy" / "bundle.example.yaml")


def authz_request(
    *,
    verb: str = TOOL_NAME,
    request_body: Mapping[str, Any] | None = None,
    task_intent: str = "add label",
    correlation_id: str = "11111111-2222-4333-8444-555555555555",
) -> AuthzRequest:
    """An `AuthzRequest` in the shape `Router._build_authz_request` produces."""
    return AuthzRequest(
        correlation_id=correlation_id,
        subject={
            "originating_principal": {"id": "s"},
            "agent": {"id": "a"},
            # Required, and empty for a root record: this harness delegates to no
            # sub-agent. `test_router_built_authz_request_validates_against_its_schema`
            # is what keeps this factory in step with what the Router emits.
            "delegation_chain": [],
        },
        target_resource={"resource_family": FAMILY_NAME},
        verb=verb,
        request_body=dict(
            request_body
            if request_body is not None
            else {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}}
        ),
        task_intent=task_intent,
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


def context_factory() -> RuntimeContextFactory:
    """The fixture-backed identity factory the Router takes."""
    return RuntimeContextFactory(
        workload_identity=FixtureWorkloadIdentityProvider(),
        principal_provider=FixtureOriginatingPrincipalProvider(),
    )


def runtime_context() -> RuntimeContext:
    """A `RuntimeContext` as the Router builds one, for testing the audit emitters."""
    return context_factory().build(
        caller=CallerIdentity(agent_id="mcp-client"),
        resource_family=FAMILY_NAME,
        tool=TOOL_NAME,
        bundle=bundle(),
        correlation_id="11111111-2222-4333-8444-555555555555",
    )


def wiring(vendor: McpClient | None = None) -> RouterWiring:
    """`RouterWiring` for the `build_router*` helpers.

    The seams are required arguments, so a test says what it is wiring rather than
    inheriting a hidden default. Defaults to the fixture identity providers and one
    in-memory vendor PER FAMILY: `InMemoryMcpClient` is mutable — `tools` is the discovery
    catalog and `calls` accumulates — so one shared instance would make discovery report
    one family's catalog for another, and let a call against family A satisfy an assertion
    about family B.
    """
    if vendor is not None:
        return RouterWiring(
            context_factory=context_factory(), vendor_client_factory=lambda _ctx: vendor
        )
    return RouterWiring(
        context_factory=context_factory(),
        vendor_client_factory=in_memory_vendor_from_family,
    )


def router(
    routed: Family | Bundle | None = None,
    *,
    opa_binary: str,
    audit: AuditSink | None = None,
    vendor: McpClient | None = None,
    policy_evaluator: PolicyEvaluator | None = None,
) -> Router:
    """A `Router` over `routed`, serving `vendor` for every family it declares.

    `routed` takes either a single `Family`, which is wrapped in a default one-family
    bundle, or a whole `Bundle`. Pass `policy_evaluator=AllowAllPolicyEvaluator()` for a
    test whose subject is a later stage than the gate, which also drops the `opa`
    dependency — `opa_binary` is then unused.
    """
    resolved = routed if isinstance(routed, Bundle) else bundle(routed)
    single = vendor if vendor is not None else in_memory_vendor()
    vendor_clients = {name: single for name, _ in resolved.families_iter()}
    return Router(
        bundle=resolved,
        policy_evaluator=(
            policy_evaluator
            if policy_evaluator is not None
            else PolicyEvaluator(opa_binary=opa_binary)
        ),
        context_factory=context_factory(),
        audit=audit if audit is not None else audit_sink(),
        vendor_clients=vendor_clients,
    )


class AllowAllPolicyEvaluator(PolicyEvaluator):
    """Returns a fixed `allow` with no obligations, without invoking OPA.

    Subclasses `PolicyEvaluator` so `Router(policy_evaluator=...)` accepts it directly.
    For tests whose subject is a later stage of the forward pipeline — action limits,
    audit shape — where running Rego through OPA would only add a dependency.
    """

    def __init__(self) -> None:
        super().__init__(opa_binary="")

    def evaluate(self, fam: Family, request: object) -> PolicyDecision:
        return PolicyDecision(
            decision="allow",
            obligations={},
            reason_code="",
            decision_id="decision-1",
        )


# -- terminal-exchange doubles (ODIS-CC-06) -----------------------------------


def exchange_anchor(
    sink: AuditSink | None = None,
    *,
    target_endpoint_id: str = "jira-prod-mcp-v1",
) -> ExchangeAuditAnchor:
    """An `ExchangeAuditAnchor` over `sink`, defaulting to one that validates and discards.

    The default suits a test whose subject is the token lifecycle rather than the record;
    pass a `CapturingAuditSink` when the emitted event is what is being asserted.

    The bundle is built from `target_endpoint_id` rather than from the factory default, so
    the anchor's target and the grant's declared target cannot disagree — a mismatch would
    be fixture metadata crossed between families, which no assertion would catch.
    `family_name` is not a parameter: the bundle keys its single family on `FAMILY_NAME`,
    so a caller-supplied name would be the same crossing in the other direction.
    """
    return ExchangeAuditAnchor(
        audit=sink if sink is not None else audit_sink(),
        bundle=bundle(family(endpoint_id=target_endpoint_id)),
        target_endpoint_id=target_endpoint_id,
        family_name=FAMILY_NAME,
    )


@dataclass
class StubTokenExchanger:
    """A `TokenExchanger` double that mints a distinct bearer per call.

    `expiries` is consumed in order and the last value repeats, so a test drives the
    freshness path by listing the expiries it wants rather than by patching a clock. The
    bearer encodes the call index, which is what makes a re-mint observable, and
    `subjects` records each subject token seen — proving a FRESH one is fetched per
    re-mint rather than a cached one replayed.
    """

    expiries: list[datetime] = field(default_factory=list)
    bearer_prefix: str = "bearer"
    calls: int = 0
    subjects: list[str] = field(default_factory=list)

    async def exchange(self, *, subject_token: str, audience: str) -> ExchangedToken:
        self.subjects.append(subject_token)
        index = self.calls
        self.calls += 1
        return ExchangedToken(
            bearer=f"{self.bearer_prefix}-{index}-{audience}",
            expires_at=self._expiry(index),
        )

    def _expiry(self, index: int) -> datetime:
        if not self.expiries:
            return datetime.now(UTC) + timedelta(minutes=5)
        return self.expiries[min(index, len(self.expiries) - 1)]


# -- vendor doubles -----------------------------------------------------------


def in_memory_vendor(
    *,
    tools: Mapping[str, str] | None = None,
    unreachable: bool = False,
) -> InMemoryMcpClient:
    """An in-memory vendor serving `tools` as name -> response text.

    `unreachable=True` makes every call raise `VendorUnreachable`, for the
    vendor-down refusal path.
    """
    responses = {TOOL_NAME: "ok"} if tools is None else dict(tools)
    descriptors = [
        ToolDescriptor(name=name, description="", input_schema={"type": "object"})
        for name in responses
    ]
    return InMemoryMcpClient(
        tools=descriptors,
        responses={
            name: ToolResult(content=[{"type": "text", "text": text}])
            for name, text in responses.items()
        },
        unreachable=unreachable,
    )


def in_memory_vendor_from_family(ctx: VendorClientContext) -> InMemoryMcpClient:
    """An in-memory vendor serving exactly the tools `ctx.family` governs."""
    return in_memory_vendor(
        tools={tool: f"handled {tool}" for tool in ctx.family.governed_tools()}
    )


# -- network ------------------------------------------------------------------


def free_port() -> int:
    """An unused localhost TCP port, for tests that bind a server."""
    return free_loopback_port()


__all__ = [
    "ALLOW_LABELS_ON_APF",
    "FAMILY_NAME",
    "AllowAllPolicyEvaluator",
    "CapturingAuditSink",
    "StubTokenExchanger",
    "audit_sink",
    "authz_request",
    "bundle",
    "context_factory",
    "envelope_validator",
    "example_bundle",
    "exchange_anchor",
    "family",
    "free_port",
    "in_memory_vendor",
    "in_memory_vendor_from_family",
    "router",
    "runtime_context",
    "wiring",
]
