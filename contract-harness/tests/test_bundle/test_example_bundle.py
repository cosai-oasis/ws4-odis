"""`policy/bundle.example.yaml` end-to-end integration."""

from __future__ import annotations

from pathlib import Path

import pytest

from odis_harness.bundle import (
    Bundle,
    BundleLoader,
    FixtureSignatureVerifier,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_EXAMPLE_BUNDLE = _REPO_ROOT / "policy" / "bundle.example.yaml"
_GITLAB_READONLY_BUNDLE = _REPO_ROOT / "policy" / "gitlab-readonly.bundle.yaml"


@pytest.fixture(scope="module")
def example_bundle() -> Bundle:
    loader = BundleLoader(signature_verifier=FixtureSignatureVerifier())
    return loader.load(_EXAMPLE_BUNDLE)


@pytest.fixture(scope="module")
def gitlab_readonly_bundle() -> Bundle:
    loader = BundleLoader(signature_verifier=FixtureSignatureVerifier())
    return loader.load(_GITLAB_READONLY_BUNDLE)


def test_example_bundle_declares_expected_router_posture(example_bundle: Bundle) -> None:
    assert example_bundle.bundle_id == "odis-fixture-bundle"
    names = {name for name, _ in example_bundle.families_iter()}
    assert names == {"jira-prod", "jira-staging"}

    prod = example_bundle.family("jira-prod")
    staging = example_bundle.family("jira-staging")
    assert prod is not None
    assert staging is not None
    assert prod.default_mode == "strict"
    assert staging.default_mode == "permissive"
    assert prod.vendor_mcp.endpoint_id == "jira-prod-mcp-v1"
    assert prod.governs_tool("update_issue")
    assert prod.action_limits_for("update_issue")["allowed_fields"] == ["labels"]


def test_gitlab_readonly_bundle_declares_read_only_surface(gitlab_readonly_bundle: Bundle) -> None:
    assert gitlab_readonly_bundle.bundle_id == "odis-gitlab-readonly-example"
    family = gitlab_readonly_bundle.family("gitlab-readonly")
    assert family is not None
    assert family.default_mode == "strict"
    assert family.vendor_mcp.endpoint_id == "gitlab-readonly"
    assert family.vendor_mcp.url == "https://gitlab-mcp.example.com/mcp"
    assert family.governs_tool("gitlab_health")
    assert family.action_limits_for("gitlab_health") == {}
    assert family.action_limits_for("gitlab_get_file_contents") == {}
    assert not family.governs_tool("gitlab_create_issue")
