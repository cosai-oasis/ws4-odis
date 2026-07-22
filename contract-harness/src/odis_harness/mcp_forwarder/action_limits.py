"""`enforce_action_limits` — per-tool scoped-authority enforcement.

ODIS terminology: action-limit enforcement. APF Phase 1 policy decisions call
these "obligations"; the bundle declares expected action limits per governed
tool. Per [[odis-vocabulary-canonical]].

Per-tool dispatch — adding a new gated tool means adding an enforcer
function and a dispatch entry. Data-driven (bundle-declared) enforcement is
follow-up work; this initial implementation
is per-tool Python for the canonical wedge `jira.update_issue`.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from typing import Any


class ActionLimitViolation(ValueError):  # noqa: N818 - domain term reads clearer without the Error suffix
    """Raised when call args violate the decision's scoped authority.

    The Router catches this and refuses the forward with reason
    `obligation_violation`.
    """


def enforce_action_limits(
    tool: str,
    args: Mapping[str, Any],
    obligations: Mapping[str, Any],
) -> None:
    """Verify `args` comply with the decision's `obligations` for `tool`.

    Raises `ActionLimitViolation` on violation. Returns None on pass.
    Raises `NotImplementedError` if no enforcer is registered for `tool`
    — adding a new tool to the gated set is an explicit code change.
    """
    enforcer = _ENFORCERS.get(tool)
    if enforcer is None:
        message = f"no action-limit enforcer registered for tool {tool!r}"
        raise NotImplementedError(message)
    enforcer(args, obligations)


# -- per-tool enforcers ------------------------------------------------------


_JIRA_ISSUE_KEY_RE = re.compile(r"^([A-Z][A-Z0-9_]*)-(\d+)$")

#: Top-level `update_issue` arguments the enforcer understands. `issue_key`
#: identifies the target; `fields` is the sole mutation channel the
#: `allowed_fields` obligation scopes. Any other top-level key is a mutation
#: surface the enforcer cannot reason about (e.g. Jira's parallel `update` verb
#: object, `transition`, `properties`) — it is refused so the scoped authority
#: cannot be bypassed by mutating through an unchecked channel.
_JIRA_UPDATE_ISSUE_KNOWN_ARGS = frozenset({"issue_key", "fields"})


def _enforce_jira_update_issue(
    args: Mapping[str, Any],
    obligations: Mapping[str, Any],
) -> None:
    """Tier 3 wedge: labels-only on a specific project.

    Obligation keys honored:
      - `allowed_fields`: list[str] — every key in `args.fields` must be in this list.
      - `project`: str — `issue_key` must start with `<project>-`.
    """
    allowed_fields = obligations.get("allowed_fields")
    if allowed_fields is not None:
        # Fail closed on any mutation channel outside the scoped `fields` object:
        # the vendor sees the original arguments, so an unchecked top-level key
        # (Jira's `update`, `transition`, ...) would defeat the labels-only scope.
        unknown = set(args.keys()) - _JIRA_UPDATE_ISSUE_KNOWN_ARGS
        if unknown:
            message = (
                f"jira.update_issue: unexpected argument(s) {sorted(unknown)!r} "
                f"outside the scoped 'fields' channel; obligation requires "
                f"allowed_fields={allowed_fields!r}"
            )
            raise ActionLimitViolation(message)
        # Empty / missing `fields` is a violation when the obligation restricts.
        fields = args.get("fields")
        if not isinstance(fields, dict):
            message = (
                f"jira.update_issue: 'fields' missing or not an object, "
                f"obligation requires allowed_fields={allowed_fields!r}"
            )
            raise ActionLimitViolation(message)
        allowed_set = set(allowed_fields)
        actual_set = set(fields.keys())
        forbidden = actual_set - allowed_set
        if forbidden:
            message = (
                f"jira.update_issue: fields {sorted(forbidden)!r} not in "
                f"obligation allowed_fields={sorted(allowed_set)!r}"
            )
            raise ActionLimitViolation(message)

    required_project = obligations.get("project")
    if required_project is not None:
        issue_key = str(args.get("issue_key", ""))
        match = _JIRA_ISSUE_KEY_RE.fullmatch(issue_key)
        actual_project = match.group(1) if match else None
        if actual_project != required_project:
            message = (
                f"jira.update_issue: issue_key {issue_key!r} project "
                f"{actual_project!r} does not match obligation "
                f"project={required_project!r}"
            )
            raise ActionLimitViolation(message)


#: Per-tool dispatch table. Adding a gated tool = one entry + one function.
_ENFORCERS: dict[str, Callable[[Mapping[str, Any], Mapping[str, Any]], None]] = {
    "update_issue": _enforce_jira_update_issue,
}


__all__ = ["ActionLimitViolation", "enforce_action_limits"]
