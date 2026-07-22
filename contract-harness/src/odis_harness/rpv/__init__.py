"""OPA evaluation primitive.

The Router's `PolicyEvaluator` (`odis_harness.mcp_forwarder.policy`) uses the
low-level `opa_eval` helper from here. Higher-level policy orchestration lives
with the Router.
"""

from odis_harness.rpv.opa import OpaEvalError, opa_eval

__all__ = [
    "OpaEvalError",
    "opa_eval",
]
