"""typed frozen dataclasses."""

from __future__ import annotations

import pytest

from odis_harness.bundle.types import Bundle, Family, VendorMcp


def _ok_vendor() -> VendorMcp:
    return VendorMcp(endpoint_id="jira-prod-mcp-v1", url="https://example.invalid/")


def _ok_family() -> Family:
    return Family(vendor_mcp=_ok_vendor(), policy="", tools={}, default_mode="strict")


def test_family_default_mode_must_be_strict_or_permissive() -> None:
    with pytest.raises(ValueError, match="default_mode"):
        Family(
            vendor_mcp=_ok_vendor(),
            policy="",
            tools={},
            default_mode="lax",  # type: ignore[arg-type]
        )


@pytest.mark.parametrize("endpoint_id", ["Jira-Prod-MCP", "1-bad-start"])
def test_vendor_mcp_endpoint_id_pattern_enforced(endpoint_id: str) -> None:
    with pytest.raises(ValueError, match="endpoint_id"):
        VendorMcp(endpoint_id=endpoint_id, url="https://example.invalid/")


@pytest.mark.parametrize("url", ["not-a-url", "ftp://example.invalid/", "//example.invalid/"])
def test_vendor_mcp_url_scheme_enforced(url: str) -> None:
    """`url` is schema-constrained to `^https?://`, and the dataclass re-checks it.

    `build_router_from_bundle` is a documented seam that never sees the schema, so
    without this a programmatic caller could route a family at an unreachable scheme.
    """
    with pytest.raises(ValueError, match="url"):
        VendorMcp(endpoint_id="jira-prod", url=url)


@pytest.mark.parametrize("url", ["http://example.invalid/", "https://example.invalid/mcp"])
def test_vendor_mcp_accepts_http_and_https(url: str) -> None:
    assert VendorMcp(endpoint_id="jira-prod", url=url).url == url


@pytest.mark.parametrize("family_name", ["Jira_Prod", "1-bad", "has space"])
def test_bundle_family_name_pattern_enforced(family_name: str) -> None:
    """A family name the router can't parse would be advertised yet unroutable;
    the programmatic Bundle path must reject it up front."""
    with pytest.raises(ValueError, match="family name"):
        Bundle(
            bundle_id="b",
            bundle_version="0.1.0",
            trust_root_id="r",
            families={family_name: _ok_family()},
        )


def test_bundle_accepts_valid_family_name() -> None:
    bundle = Bundle(
        bundle_id="b",
        bundle_version="0.1.0",
        trust_root_id="r",
        families={"jira-prod": _ok_family()},
    )
    assert bundle.family("jira-prod") is not None
