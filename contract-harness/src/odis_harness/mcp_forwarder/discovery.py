"""DiscoveryCache — vendor tool-catalog cache, populated at Router startup.

For each family in the loaded bundle, the Router calls `tools/list` on the
corresponding vendor MCP client at startup and stores the result here. The
cache is consulted by the Router's MCP `tools/list` handler to produce a
family-prefixed, filtered catalog (`aggregate`).

Vendor unreachability at populate time emits `odis.mcp.discovery_failed`
(callback-driven so this module stays free of audit-sink imports) and leaves
the family's catalog empty — other families continue to serve.

Aggregation filter (per family):
  - Tool is declared in `Family.tools` → include (prefixed).
  - Tool has no policy AND `Family.default_mode == "permissive"` → include.
  - Tool has no policy AND `Family.default_mode == "strict"` → hide.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from odis_harness.mcp_forwarder.vendor_client import ToolDescriptor

if TYPE_CHECKING:
    from collections.abc import Mapping

    from odis_harness.bundle import Bundle, Family
    from odis_harness.mcp_forwarder.vendor_client import McpClient


#: Callback signature for discovery failures. The Router passes a closure that
#: emits `odis.mcp.discovery_failed`; tests pass a list-appender. The error is
#: typically `VendorUnreachable` but any `Exception` a vendor client raises
#: during discovery is isolated and reported through this callback.
DiscoveryFailureCallback = Callable[[str, Exception], None]


@dataclass
class DiscoveryCache:
    """Holds the per-family vendor tool catalog.

    Constructed empty; the Router calls `populate` at startup. `aggregate`
    produces the outward `tools/list` response.
    """

    #: family-name → list of ToolDescriptors as returned by the vendor.
    _catalog: dict[str, list[ToolDescriptor]] = field(default_factory=dict)

    async def populate(
        self,
        bundle: Bundle,
        *,
        clients: Mapping[str, McpClient],
        on_discovery_failed: DiscoveryFailureCallback | None = None,
    ) -> None:
        """For each family in the bundle, fetch `tools/list` and cache.

        A vendor failure is isolated per family — one failure does not block
        other families (every task is awaited via `gather(return_exceptions=
        True)`, so none are leaked). The callback (when provided) is invoked
        with `(family_name, exception)` for each failed family so the Router
        can emit `odis.mcp.discovery_failed` audit events.

        Families in the bundle without a corresponding client are skipped
        (they serve zero tools — fail closed). The Router's wiring builds one
        client per family, so this is a defensive no-op in practice.
        """
        names = [name for name, _ in bundle.families_iter() if name in clients]
        results = await asyncio.gather(
            *(clients[name].list_tools() for name in names),
            return_exceptions=True,
        )
        for name, result in zip(names, results, strict=True):
            if isinstance(result, BaseException):
                # Never swallow cancellation / interpreter-exit signals.
                if not isinstance(result, Exception):
                    raise result
                self._catalog[name] = []
                if on_discovery_failed is not None:
                    on_discovery_failed(name, result)
            else:
                self._catalog[name] = result

    def catalog_for(self, family_name: str) -> list[ToolDescriptor]:
        """Return the cached catalog for `family_name`, or `[]` if unknown."""
        return list(self._catalog.get(family_name, []))

    def aggregate(self, bundle: Bundle) -> list[ToolDescriptor]:
        """Produce the outward-facing tool list with family-prefixed names.

        Filter:
          - Tool is governed (entry in Family.tools) → include.
          - Tool has no policy AND family.default_mode == "permissive" → include.
          - Tool has no policy AND family.default_mode == "strict" → hide.
        """
        out: list[ToolDescriptor] = []
        for family_name, family in bundle.families_iter():
            for tool in self._catalog.get(family_name, []):
                if not _should_expose(tool.name, family):
                    continue
                out.append(
                    ToolDescriptor(
                        name=f"{family_name}.{tool.name}",
                        description=tool.description,
                        input_schema=tool.input_schema,
                    )
                )
        return out


def _should_expose(tool_name: str, family: Family) -> bool:
    """Apply the strict/permissive filter."""
    if family.governs_tool(tool_name):
        return True
    return family.default_mode == "permissive"


__all__ = ["DiscoveryCache", "DiscoveryFailureCallback"]
