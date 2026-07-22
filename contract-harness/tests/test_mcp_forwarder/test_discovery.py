"""DiscoveryCache.populate + aggregate."""

from __future__ import annotations

import pytest

from odis_harness.bundle import Bundle, Family, ToolPolicy, VendorMcp
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    ToolDescriptor,
)

pytestmark = pytest.mark.enable_socket


def _vendor(endpoint_id: str = "jira-prod-mcp-v1") -> VendorMcp:
    return VendorMcp(endpoint_id=endpoint_id, url="https://example.invalid/")


def _family(
    *,
    action_limits_by_tool: dict[str, dict[str, object]] | None = None,
    default_mode: str = "strict",
) -> Family:
    tool_limits = action_limits_by_tool or {"update_issue": {"allowed_fields": ["labels"]}}
    return Family(
        vendor_mcp=_vendor(),
        policy="package odis_policy\n",
        tools={
            tool: ToolPolicy(action_limits=action_limits)
            for tool, action_limits in tool_limits.items()
        },
        default_mode=default_mode,  # type: ignore[arg-type]
    )


def _bundle(families: dict[str, Family] | None = None) -> Bundle:
    return Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families=families or {"jira-prod": _family()},
    )


def _tool(name: str) -> ToolDescriptor:
    return ToolDescriptor(name=name, description="", input_schema={"type": "object"})


# -- populate ----------------------------------------------------------------


async def test_populate_calls_list_tools_per_family() -> None:
    bundle = _bundle(
        families={
            "jira-prod": _family(),
            "confluence-prod": _family(
                action_limits_by_tool={"update_page": {"allowed_fields": ["body"]}}
            ),
        }
    )
    jira_client = InMemoryMcpClient(tools=[_tool("update_issue")])
    conf_client = InMemoryMcpClient(tools=[_tool("update_page")])
    cache = DiscoveryCache()
    audit_events: list[dict[str, object]] = []
    await cache.populate(
        bundle,
        clients={"jira-prod": jira_client, "confluence-prod": conf_client},
        on_discovery_failed=lambda family_name, error: audit_events.append(
            {"family": family_name, "error": str(error)}
        ),
    )
    assert cache.catalog_for("jira-prod") == [_tool("update_issue")]
    assert cache.catalog_for("confluence-prod") == [_tool("update_page")]
    assert audit_events == []


async def test_populate_isolates_one_family_failure_from_others() -> None:
    bundle = _bundle(
        families={
            "jira-prod": _family(),
            "confluence-prod": _family(
                action_limits_by_tool={"update_page": {"allowed_fields": ["body"]}}
            ),
        }
    )
    jira_client = InMemoryMcpClient(tools=[_tool("update_issue")])
    conf_client = InMemoryMcpClient(tools=[_tool("update_page")], unreachable=True)
    cache = DiscoveryCache()
    failed: list[str] = []
    await cache.populate(
        bundle,
        clients={"jira-prod": jira_client, "confluence-prod": conf_client},
        on_discovery_failed=lambda family_name, _error: failed.append(family_name),
    )
    # jira-prod populated normally
    assert cache.catalog_for("jira-prod") == [_tool("update_issue")]
    # confluence-prod empty + failure recorded
    assert cache.catalog_for("confluence-prod") == []
    assert failed == ["confluence-prod"]


async def test_populate_invokes_on_discovery_failed_callback_with_error() -> None:
    bundle = _bundle()
    client = InMemoryMcpClient(tools=[], unreachable=True)
    cache = DiscoveryCache()
    captured: list[tuple[str, type]] = []
    await cache.populate(
        bundle,
        clients={"jira-prod": client},
        on_discovery_failed=lambda family_name, error: captured.append((family_name, type(error))),
    )
    assert len(captured) == 1
    assert captured[0][0] == "jira-prod"
    # error subclass is VendorUnreachable per the in-memory client
    from odis_harness.mcp_forwarder.vendor_client import VendorUnreachable  # noqa: PLC0415

    assert issubclass(captured[0][1], VendorUnreachable)


async def test_populate_works_when_callback_is_none() -> None:
    """Caller may opt out of discovery-failure handling."""
    bundle = _bundle()
    client = InMemoryMcpClient(tools=[], unreachable=True)
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    assert cache.catalog_for("jira-prod") == []


# -- aggregate ---------------------------------------------------------------


async def test_aggregate_strict_mode_hides_unpoliced_tools() -> None:
    bundle = _bundle()  # default_mode=strict, tools={update_issue: ...}
    client = InMemoryMcpClient(
        tools=[_tool("update_issue"), _tool("delete_issue")]  # delete not in bundle
    )
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    aggregated = cache.aggregate(bundle)
    names = [t.name for t in aggregated]
    assert "jira-prod.update_issue" in names
    assert "jira-prod.delete_issue" not in names  # hidden in strict


async def test_aggregate_permissive_mode_exposes_unpoliced_tools() -> None:
    bundle = _bundle(families={"jira-prod": _family(default_mode="permissive")})
    client = InMemoryMcpClient(tools=[_tool("update_issue"), _tool("delete_issue")])
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    aggregated = cache.aggregate(bundle)
    names = [t.name for t in aggregated]
    assert "jira-prod.update_issue" in names
    assert "jira-prod.delete_issue" in names  # exposed in permissive


async def test_aggregate_prefixes_tools_with_family_name() -> None:
    bundle = _bundle()
    client = InMemoryMcpClient(tools=[_tool("update_issue")])
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    aggregated = cache.aggregate(bundle)
    assert len(aggregated) == 1
    assert aggregated[0].name == "jira-prod.update_issue"


async def test_aggregate_returns_empty_when_no_families_have_catalog() -> None:
    bundle = _bundle()
    cache = DiscoveryCache()
    # No populate
    assert cache.aggregate(bundle) == []


async def test_aggregate_skips_families_with_empty_catalog_in_strict() -> None:
    """A family whose vendor was unreachable at startup has empty catalog; still
    presents as zero tools, doesn't error."""
    bundle = _bundle()
    client = InMemoryMcpClient(tools=[], unreachable=True)
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    assert cache.aggregate(bundle) == []


async def test_aggregate_preserves_tool_descriptor_metadata() -> None:
    """The descriptor's input_schema and description survive aggregation."""
    bundle = _bundle()
    tool = ToolDescriptor(
        name="update_issue",
        description="Update a Jira issue",
        input_schema={"type": "object", "required": ["issue_key"]},
    )
    client = InMemoryMcpClient(tools=[tool])
    cache = DiscoveryCache()
    await cache.populate(bundle, clients={"jira-prod": client})
    aggregated = cache.aggregate(bundle)
    assert aggregated[0].description == "Update a Jira issue"
    assert aggregated[0].input_schema == {"type": "object", "required": ["issue_key"]}


# -- catalog_for accessor ----------------------------------------------------


def test_catalog_for_unknown_family_returns_empty() -> None:
    cache = DiscoveryCache()
    assert cache.catalog_for("nonexistent") == []
