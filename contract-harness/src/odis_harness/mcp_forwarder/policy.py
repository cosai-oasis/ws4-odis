"""PolicyEvaluator — per-family Rego evaluation via real OPA.

ODIS terminology: this is the Router's policy engine (APF Phase 1 calls it the
RPV). The evaluator uses the low-level `opa_eval` primitive and operates on a
`Bundle`'s per-family Rego string.

`require_review` and other non-allow/deny decision branches are out of scope
for the forwarder's first iteration; the evaluator returns whatever decision
string the Rego produces and the Router treats anything other than `allow`
as a refusal.
"""

from __future__ import annotations

import tempfile
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from odis_harness.rpv.opa import OpaEvalError, opa_eval

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from odis_harness.bundle import Family
    from odis_harness.contracts import AuthzRequest


@dataclass(frozen=True, kw_only=True, slots=True)
class PolicyDecision:
    """The Router-internal result of evaluating a family's policy.

    Minimal by design — not a wire envelope (no expires_at / policy_digest;
    those are credential-evidence concerns that aren't part of the forwarder
    model).
    """

    decision: str  # "allow" | "deny" | (other Rego-produced values → treated as refusal)
    obligations: Mapping[str, Any]
    reason_code: str
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
                decision="deny",
                obligations={},
                reason_code="policy_error",
                decision_id=decision_id,
            )

        if not isinstance(result, dict):
            return PolicyDecision(
                decision="deny",
                obligations={},
                reason_code="invalid_rego_result",
                decision_id=decision_id,
            )
        # `obligations` must be an object: it is handed to the action-limit
        # enforcer, which calls `.get(...)` on it. A non-object value (e.g. a
        # Rego rule that returns a list) would raise inside enforcement, so fail
        # closed here rather than let a malformed policy crash the forward path.
        obligations = result.get("obligations", {})
        if not isinstance(obligations, dict):
            return PolicyDecision(
                decision="deny",
                obligations={},
                reason_code="invalid_rego_result",
                decision_id=decision_id,
            )
        # A well-formed Rego `decision` is an object; a non-`allow` value (or a
        # wrong-typed one) still fails closed via the Router's `!= "allow"` check.
        return PolicyDecision(
            decision=result.get("decision", "deny"),
            obligations=obligations,
            reason_code=result.get("reason_code", ""),
            decision_id=decision_id,
        )


def _request_to_opa_input(request: AuthzRequest) -> dict[str, Any]:
    """Minimal projection of AuthzRequest into the OPA input document.

    This is the policy input contract for per-family Rego: `verb`,
    `target_resource`, `request_body`, `task_intent`, and `correlation_id`.
    """
    return {
        "verb": request.verb,
        "target_resource": dict(request.target_resource),
        "request_body": dict(request.request_body),
        "task_intent": request.task_intent,
        "correlation_id": request.correlation_id,
    }


__all__ = ["PolicyDecision", "PolicyEvaluator"]
