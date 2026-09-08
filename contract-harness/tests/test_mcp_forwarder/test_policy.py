"""PolicyEvaluator tests: per-family Rego via OPA."""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from tests import factories

if TYPE_CHECKING:
    from odis_harness.bundle import Family
    from odis_harness.contracts import AuthzRequest

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
    return factories.family(policy=policy)


def _request(*, verb: str = "update_issue", issue_key: str = "APF-123") -> AuthzRequest:
    return factories.authz_request(
        verb=verb,
        request_body={"issue_key": issue_key, "fields": {"labels": ["odis-demo"]}},
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


def test_missing_opa_binary_reports_policy_error_not_deny() -> None:
    """A fail-closed decision must be distinguishable from a policy refusal.

    Both deny the call, but "the PDP was unreachable" and "the policy said no" are the
    two cases an operator most needs to tell apart in the audit trail.
    """
    evaluator = PolicyEvaluator(opa_binary="/nonexistent/opa")
    decision = evaluator.evaluate(_family("package odis_policy\n"), _request())
    assert decision.decision == "deny"
    assert decision.reason_code == ReasonCode.POLICY_ERROR


@pytest.mark.requires_opa
def test_policy_can_condition_on_the_calling_identity(opa_binary: str) -> None:
    """The point of putting `subject` in the OPA input: a policy can gate on WHO calls.

    Without this, nothing in the repo reads `input.subject` — no shipped policy, no test,
    no Rego the Vault plugin generates — so the field could be renamed or dropped and the
    whole suite would stay green.
    """
    principal_gated = """
package odis_policy
default decision := {"decision": "deny", "obligations": {}}
decision := {"decision": "allow", "obligations": {}} if {
    input.subject.originating_principal.id == "alice"
}
"""
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    family = factories.family(policy=principal_gated)

    allowed = factories.authz_request()
    object.__setattr__(
        allowed, "subject", {"originating_principal": {"id": "alice"}, "agent": {"id": "a"}}
    )
    assert evaluator.evaluate(family, allowed).decision == "allow"

    refused = factories.authz_request()
    object.__setattr__(
        refused, "subject", {"originating_principal": {"id": "mallory"}, "agent": {"id": "a"}}
    )
    assert evaluator.evaluate(family, refused).decision == "deny"
