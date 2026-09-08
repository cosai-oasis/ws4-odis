"""PolicyEvaluator — per-family Rego evaluation via OPA.

ODIS terminology: this is the Router's policy engine (APF Phase 1 calls it the
RPV). The evaluator uses the low-level `opa_eval` primitive and operates on a
`Bundle`'s per-family Rego string.

The evaluator returns whatever `decision` string the Rego produces, and the Router
treats anything other than `allow` as a refusal. So a policy that answers
`require_review` — or any third branch — refuses, and is indistinguishable from a
`deny` at the Router and in the audit trail. Distinguishing them needs a decision
vocabulary the Router acts on rather than a two-way `allow`/not-`allow` test.
"""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING

from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.rpv.opa import OpaEvalError, opa_eval

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from odis_harness.bundle import Family
    from odis_harness.contracts import AuthzRequest


class Decision(StrEnum):
    """The decision values the Router acts on.

    ODIS §6.4 specifies `permit` | `deny` for the policy engine's return; the Rego in
    this harness emits `allow`, and the spec does not state whether those values are
    normative, so the divergence is deliberate and unresolved rather than an oversight.
    """

    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyDecision:
    """The Router-internal result of evaluating a family's policy.

    Minimal by design — not a wire envelope (no expires_at / policy_digest;
    those are credential-evidence concerns that aren't part of the forwarder
    model).
    """

    #: Whatever the Rego emitted, verbatim — `Decision` names the two values the
    #: Router acts on, but a policy may return others (`require_review`, say), and
    #: anything that is not `Decision.ALLOW` is a refusal.
    decision: str
    obligations: Mapping[str, Any]
    #: Why, in the Router's vocabulary — audited verbatim on a refusal.
    reason_code: ReasonCode
    decision_id: str


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyEvaluator:
    """Evaluates a `Family`'s Rego policy against an `AuthzRequest` via OPA."""

    opa_binary: str

    def evaluate(self, family: Family, request: AuthzRequest) -> PolicyDecision:
        """Run the family's Rego over the request; return a `PolicyDecision`.

        The family's Rego source is materialized to a temp file (OPA `--data`
        requires a path); the temp dir is removed on exit. Default-deny on any
        non-object Rego result.
        """
        opa_input = _request_to_opa_input(request)
        decision_id = str(uuid.uuid4())
        try:
            with tempfile.TemporaryDirectory(prefix="odis-policy-") as tmp:
                rego_path = Path(tmp) / "policy.rego"
                rego_path.write_text(family.policy, encoding="utf-8")
                result = opa_eval(
                    opa_binary=self.opa_binary,
                    rego_path=rego_path,
                    input_payload=opa_input,
                )
        except OpaEvalError:
            # Fail closed: a malformed Rego policy, a missing/failed OPA
            # binary, or unparseable output all deny rather than crash the
            # Router's forward path.
            return PolicyDecision(
                decision=Decision.DENY,
                obligations={},
                reason_code=ReasonCode.POLICY_ERROR,
                decision_id=decision_id,
            )

        if not isinstance(result, dict):
            return PolicyDecision(
                decision=Decision.DENY,
                obligations={},
                reason_code=ReasonCode.INVALID_REGO_RESULT,
                decision_id=decision_id,
            )
        # `obligations` must be an object: it is handed to the action-limit
        # enforcer, which calls `.get(...)` on it. A non-object value (e.g. a
        # Rego rule that returns a list) would raise inside enforcement, so fail
        # closed here rather than let a malformed policy crash the forward path.
        obligations = result.get("obligations", {})
        if not isinstance(obligations, dict):
            return PolicyDecision(
                decision=Decision.DENY,
                obligations={},
                reason_code=ReasonCode.INVALID_REGO_RESULT,
                decision_id=decision_id,
            )
        # A well-formed Rego `decision` is an object; a non-`allow` value (or a
        # wrong-typed one) still fails closed via the Router's `!= "allow"` check.
        return PolicyDecision(
            decision=result.get("decision", Decision.DENY),
            obligations=obligations,
            # A Rego-supplied reason string is not in our vocabulary, so a refusal
            # from a well-formed policy audits as DENY.
            reason_code=ReasonCode.DENY,
            decision_id=decision_id,
        )


def _request_to_opa_input(request: AuthzRequest) -> dict[str, Any]:
    """The policy input document for per-family Rego.

    Carries `subject` — the acting agent and the principal whose authority it acts under —
    so a policy can condition on *who* is calling, not only on what.

    This is not yet ODIS §6.4's Identity Context. §6.4 requires `agent_registration`
    (§6.1), `agent_runtime` (§6.2) and `delegation` (§6.3) as MUST objects; this harness
    holds none of them, and the draft defines no interface by which a Layer-3 component
    would receive them. See the conformance doc's underdetermined section.
    """
    return {
        "verb": request.verb,
        "subject": dict(request.subject),
        "target_resource": dict(request.target_resource),
        "request_body": dict(request.request_body),
        "task_intent": request.task_intent,
        "correlation_id": request.correlation_id,
        "policy_digest": request.policy_digest,
    }


__all__ = ["Decision", "PolicyDecision", "PolicyEvaluator"]
