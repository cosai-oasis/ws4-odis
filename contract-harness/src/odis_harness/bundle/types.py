"""Frozen dataclasses mirroring the `odis.bundle.v1` JSON Schema.

These types are the in-memory representation the Router consumes. They are
immutable; reloading a bundle replaces the instance rather than mutating it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from functools import cached_property
from typing import TYPE_CHECKING, Literal

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from typing import Any

#: `endpoint_id` and family-name pattern, matched against the JSON Schema
#: regex in `schemas/odis.bundle.v1.json`. Lowercase kebab.
_ENDPOINT_ID_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")

#: Allowed values for `Family.default_mode`. Schema-enforced; the dataclass
#: re-validates so Python construction (e.g. tests) fails fast.
_DEFAULT_MODES: frozenset[str] = frozenset({"strict", "permissive"})

DefaultMode = Literal["strict", "permissive"]


@dataclass(frozen=True, kw_only=True, slots=True)
class VendorMcp:
    """Per-family vendor MCP server endpoint. HTTP transport per the MCP spec."""

    endpoint_id: str
    url: str

    def __post_init__(self) -> None:
        if not _ENDPOINT_ID_PATTERN.fullmatch(self.endpoint_id):
            message = (
                f"endpoint_id {self.endpoint_id!r} does not match {_ENDPOINT_ID_PATTERN.pattern!r}"
            )
            raise ValueError(message)


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolPolicy:
    """Bundle declaration for one governed vendor tool.

    Presence in `Family.tools` means the Router evaluates the family policy for
    that tool. `action_limits` are optional post-policy constraints; an empty map
    is valid for read-only tools that need policy gating but no argument filter.
    """

    action_limits: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True, slots=True)
class Family:
    """One resource family declared in the bundle's `families` map."""

    vendor_mcp: VendorMcp
    policy: str  # Rego source
    tools: Mapping[str, ToolPolicy]  # keyed by vendor tool name (unprefixed)
    default_mode: DefaultMode

    def __post_init__(self) -> None:
        if self.default_mode not in _DEFAULT_MODES:
            message = f"default_mode {self.default_mode!r} must be one of {sorted(_DEFAULT_MODES)}"
            raise ValueError(message)

    def governs_tool(self, tool_name: str) -> bool:
        """True when `tool_name` is explicitly governed by the family policy."""
        return tool_name in self.tools

    def governed_tools(self) -> Iterator[str]:
        """Iterate vendor tool names explicitly governed by this family."""
        return iter(self.tools)

    def action_limits_for(self, tool_name: str) -> Mapping[str, Any]:
        """Return declared post-policy action limits for a governed tool."""
        return self.tools[tool_name].action_limits


@dataclass(frozen=True, kw_only=True)
class Bundle:
    """A loaded, validated bundle. The Router holds one of these at a time.

    Not slotted: `cached_property` needs `__dict__` to memoize the digest.
    Bundle instances are created once per load and held for the lifetime of
    the Router; the slots optimization is irrelevant.
    """

    bundle_id: str
    bundle_version: str
    trust_root_id: str
    families: Mapping[str, Family]

    def __post_init__(self) -> None:
        # Family names must match the routing pattern `parse_tool_name` enforces:
        # a name the router can never parse would be advertised by discovery yet
        # be permanently unroutable. The YAML loader relies on the schema for
        # this; re-validate here so the programmatic `build_router_from_bundle`
        # path (a documented seam) fails fast instead of shipping dead tools.
        for name in self.families:
            if not _ENDPOINT_ID_PATTERN.fullmatch(name):
                message = f"family name {name!r} does not match {_ENDPOINT_ID_PATTERN.pattern!r}"
                raise ValueError(message)

    def family(self, name: str) -> Family | None:
        """Return the family entry for `name`, or None if not declared."""
        return self.families.get(name)

    def families_iter(self) -> Iterator[tuple[str, Family]]:
        """Iterate (family_name, family) pairs in declaration order.

        Backed by the underlying mapping; `dict.items()` preserves insertion
        order in Python 3.7+, and the loader preserves the bundle file's
        family ordering.
        """
        return iter(self.families.items())

    @cached_property
    def policy_digest(self) -> str:
        """sha256 hex digest of the canonical serialization of the entire
        bundle. Computed once on first access. See `digest.policy_digest`."""
        # Local import avoids a circular import between types.py and digest.py.
        from odis_harness.bundle.digest import policy_digest  # noqa: PLC0415

        return policy_digest(self)


__all__ = ["Bundle", "DefaultMode", "Family", "ToolPolicy", "VendorMcp"]
