"""The refusal vocabulary the Router and its MCP handler emit.

Every refusal the forward path can produce, in one place. `StrEnum` members are
strings, so an emitted audit event and an `McpRefusal.reason_code` carry the same
wire value they always have — the enum only stops a typo from inventing a tenth
reason that nothing downstream recognises.

`reason_code` is free-form in `odis.audit.event.v1` (`type: string, minLength: 1`):
ODIS registers no refusal vocabulary, so this set is the harness's own.
"""

from __future__ import annotations

from enum import StrEnum


class ReasonCode(StrEnum):
    """Why a call was refused. Ordered by where it arises in the forward path."""

    #: The Authority Grant's `expires_at` has passed. It confers nothing, so every
    #: call is refused regardless of the tool or the policy.
    GRANT_EXPIRED = "grant_expired"
    #: The bundle governs this family but declares no policy for this tool, and the
    #: family is `strict`.
    UNPOLICED_TOOL = "unpoliced_tool"
    #: The policy engine refused. Emitted for *any* non-allow decision from a
    #: well-formed policy, including values this harness does not model such as
    #: `require_review` — so it means "not allowed", not "the policy said deny".
    DENY = "deny"
    #: OPA could not be run, or its result was unusable. Fails closed.
    POLICY_ERROR = "policy_error"
    #: The Rego produced a well-formed-looking result of the wrong shape. Fails closed.
    INVALID_REGO_RESULT = "invalid_rego_result"
    #: The call exceeded the action limits the decision obliged.
    OBLIGATION_VIOLATION = "obligation_violation"
    #: The bundle declares the tool as policed, but no action-limit enforcer is
    #: registered for it. Fails closed rather than forwarding unchecked.
    UNENFORCEABLE_TOOL = "unenforceable_tool"
    VENDOR_UNREACHABLE = "vendor_unreachable"
    #: The tool name carried no routable family prefix, or named an unknown family.
    UNROUTED_FAMILY = "unrouted_family"
    #: An unexpected error at the handler boundary. The agent is told nothing more.
    UNATTRIBUTED_CALLER = "unattributed_caller"
    """The transport validates credentials, but no verified identity reached the handler.

    Distinct from `INTERNAL_ERROR`: that is a bug in the forward path, this is a call that
    got past the gate without an identity — a middleware bypass or a mounting mistake.
    An operator reading the trail after an incident needs to tell the two apart.
    """

    INTERNAL_ERROR = "internal_error"


__all__ = ["ReasonCode"]
