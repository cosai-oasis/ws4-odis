"""`parse_tool_name` — split `<family>.<tool>` into a (family, tool) tuple.

The Router accepts MCP `tools/call` invocations whose tool names are prefixed
by the bundle's resource-family name (e.g. `jira-prod.update_issue`). The
prefix is used to resolve the call to a vendor MCP endpoint via the bundle's
routing table.

Tool names that lack a valid family prefix raise `UnroutedToolName`. The
Router's caller converts this into an MCP-protocol error with reason
`unrouted_family`.
"""

from __future__ import annotations

import re

#: Family-name pattern matches the bundle's `endpoint_id` shape: lowercase
#: kebab, must start with a letter. Mirrors the JSON Schema's pattern in
#: `schemas/odis.bundle.v1.json` so a tool whose family prefix can never appear
#: in the bundle is rejected up front.
_FAMILY_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")


class UnroutedToolName(ValueError):  # noqa: N818 - domain term reads clearer without the Error suffix
    """Raised when an MCP tool name cannot be split into (family, tool).

    Catchable as `ValueError` for callers that don't care about the specific
    reason.
    """


def parse_tool_name(name: str) -> tuple[str, str]:
    """Split `<family>.<tool>` → (family, tool).

    Splits on the first `.` only — tools may contain further dots. Raises
    `UnroutedToolName` if `name` has no dot, an empty family, an empty tool,
    or a family that doesn't match the bundle's family-name pattern.
    """
    if "." not in name:
        message = f"tool name {name!r} has no family prefix"
        raise UnroutedToolName(message)
    family, _, tool = name.partition(".")
    if not family:
        message = f"tool name {name!r} has an empty family prefix"
        raise UnroutedToolName(message)
    if not tool:
        message = f"tool name {name!r} has an empty tool component"
        raise UnroutedToolName(message)
    if not _FAMILY_PATTERN.fullmatch(family):
        message = (
            f"tool name {name!r} has family prefix {family!r} that does not "
            f"match the bundle's family-name pattern"
        )
        raise UnroutedToolName(message)
    return family, tool


__all__ = ["UnroutedToolName", "parse_tool_name"]
