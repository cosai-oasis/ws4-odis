"""PolicyEvaluator tests: per-family Rego via real OPA."""

from __future__ import annotations

import pytest

from odis_harness.bundle import Family, ToolPolicy, VendorMcp
from odis_harness.contracts import AuthzRequest
from odis_harness.mcp_forwarder.policy import PolicyEvaluator

pytestmark = pytest.mark.requires_opa


_ALLOW_LABELS_ON_APF = """
package odis_policy

default decision := {"decision": "deny", "obligations": {}}

decision := {"decision": "allow", "obligations": {"allowed_fields": ["labels"]}} if {
    input.verb == "update_issue"
    startswith(input.request_body.issue_key, "APF-")
}
"""

_RETURNS_NON_DICT = """
package odis_policy
decision := "not-an-object"
"""

_ALLOW_WITH_NON_DICT_OBLIGATIONS = """
package odis_policy
decision := {"decision": "allow", "obligations": ["labels"]}
"""

_MALFORMED_REGO = """
this is not valid rego !!! {{{
"""


def _family(policy: str) -> Family:
    return Family(
        vendor_mcp=VendorMcp(endpoint_id="jira-prod-mcp-v1", url="https://x.invalid/"),
        policy=policy,
        tools={
            "update_issue": ToolPolicy(action_limits={"allowed_fields": ["labels"]}),
        },
        default_mode="strict",
    )


def _request(*, verb: str = "update_issue", issue_key: str = "APF-123") -> AuthzRequest:
    return AuthzRequest(
        correlation_id="11111111-2222-4333-8444-555555555555",
        subject={"sponsor": {"id": "s"}, "agent": {"id": "a"}},
        target_resource={"resource_family": "jira-prod"},
        verb=verb,
        request_body={"issue_key": issue_key, "fields": {"labels": ["odis-demo"]}},
        task_intent="add label",
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


def test_evaluate_allow_returns_allow_decision(opa_binary: str) -> None:
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    decision = evaluator.evaluate(_family(_ALLOW_LABELS_ON_APF), _request())
    assert decision.decision == "allow"
    assert decision.obligations == {"allowed_fields": ["labels"]}


def test_evaluate_deny_when_issue_key_outside_project(opa_binary: str) -> None:
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    decision = evaluator.evaluate(_family(_ALLOW_LABELS_ON_APF), _request(issue_key="OTHER-1"))
    assert decision.decision == "deny"


def test_evaluate_generates_unique_decision_id(opa_binary: str) -> None:
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    d1 = evaluator.evaluate(_family(_ALLOW_LABELS_ON_APF), _request())
    d2 = evaluator.evaluate(_family(_ALLOW_LABELS_ON_APF), _request())
    assert d1.decision_id != d2.decision_id


def test_evaluate_non_dict_rego_result_fails_closed(opa_binary: str) -> None:
    """A policy that returns a non-object decision is treated as deny."""
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    decision = evaluator.evaluate(_family(_RETURNS_NON_DICT), _request())
    assert decision.decision == "deny"
    assert decision.reason_code == "invalid_rego_result"


def test_evaluate_non_dict_obligations_fails_closed(opa_binary: str) -> None:
    """`obligations` is handed to the enforcer (which calls `.get`); a non-object
    value (e.g. a list) must deny rather than crash the forward path."""
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    decision = evaluator.evaluate(_family(_ALLOW_WITH_NON_DICT_OBLIGATIONS), _request())
    assert decision.decision == "deny"
    assert decision.reason_code == "invalid_rego_result"


def test_evaluate_malformed_rego_fails_closed_to_deny(opa_binary: str) -> None:
    """A family shipping un-compilable Rego denies rather than crashing forward."""
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    decision = evaluator.evaluate(_family(_MALFORMED_REGO), _request())
    assert decision.decision == "deny"
    assert decision.reason_code == "policy_error"


def test_evaluate_missing_opa_binary_fails_closed_to_deny() -> None:
    """A bad OPA binary path denies rather than crashing (no requires_opa)."""
    evaluator = PolicyEvaluator(opa_binary="/nonexistent/opa-binary")
    decision = evaluator.evaluate(_family(_ALLOW_LABELS_ON_APF), _request())
    assert decision.decision == "deny"
    assert decision.reason_code == "policy_error"
