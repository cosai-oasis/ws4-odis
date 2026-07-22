"""Hermetic end-to-end: a dev Vault issues a signed bundle → the Router governs it.

Boots a dev-mode Vault (the `dev_vault` fixture), then drives the real Router-side
path: VaultBundleClient mint-then-load (jwt login → apf/issue) → offline signature
verification against the exported transit public key → BundleLoader.load_signed →
the real OPA PolicyEvaluator governs an `update_issue` call (allow on APF-*, deny
otherwise). Proves a Vault-issued bundle is interchangeable with a fixture bundle for
governance. Skipped when no vault binary is present.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

import httpx
import pytest

from odis_harness.bundle.loader import BundleLoader
from odis_harness.bundle.vault_verifier import VaultTransitSignatureVerifier
from odis_harness.cli import SignedBundleSource, build_router_signed
from odis_harness.contracts.envelopes import AuthzRequest
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    McpClient,
    ToolDescriptor,
    ToolResult,
)
from tests.factories import audit_sink, in_memory_vendor_from_family

if TYPE_CHECKING:
    from collections.abc import Callable

    from odis_harness.bundle import Bundle, Family
    from odis_harness.bundle.vault_client import VaultBundleClient
    from odis_harness.vault.dev import DevVaultContext

pytestmark = [
    pytest.mark.requires_vault,
    pytest.mark.requires_opa,
    pytest.mark.enable_socket,
]

_FIXTURE_ISSUER = "https://fixture.issuer.odis.local/"
_FIXTURE_AUDIENCE = "apf-bundle-issuer"
_FIXTURE_SUBJECT = "spiffe://example.org/agent/jira"
_GITLAB_READONLY_TOOLS = [
    "gitlab_health",
    "gitlab_search_repositories",
    "gitlab_list_projects",
    "gitlab_get_project_details",
    "gitlab_get_repo_tree",
    "gitlab_get_file_contents",
    "gitlab_list_commits",
    "gitlab_get_commit",
    "gitlab_list_epics",
    "gitlab_get_epic",
    "gitlab_list_issues",
    "gitlab_get_issue",
    "gitlab_list_merge_requests",
    "gitlab_get_merge_request",
    "gitlab_get_merge_request_diffs",
    "gitlab_list_pipelines_jobs",
    "gitlab_get_job_log",
    "gitlab_get_job_log_metadata",
    "gitlab_get_job_log_paginated",
    "gitlab_get_pipeline_tree",
]


def _request(*, issue_key: str) -> AuthzRequest:
    return AuthzRequest(
        correlation_id="11111111-2222-4333-8444-555555555555",
        subject={"sponsor": {"id": "s"}, "agent": {"id": "a"}},
        target_resource={"resource_family": "jira-prod"},
        verb="update_issue",
        request_body={"issue_key": issue_key, "fields": {"labels": ["odis-demo"]}},
        task_intent="add label",
        issued_at="2026-05-28T00:00:00Z",
        policy_digest="a" * 64,
    )


async def _fetch_and_load(client: VaultBundleClient, dev_vault: DevVaultContext) -> Bundle:
    signed = await client.fetch_signed_bundle(workload_jwt=dev_vault.workload_jwt)
    verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
        key_name=signed.key_name,
        public_keys_b64={signed.key_version: dev_vault.transit_public_key_b64},
    )
    assert verifier.verify(signed.payload, signed.signature), "offline verify failed"
    loader = BundleLoader(signature_verifier=verifier)
    return loader.load_signed(signed.payload, signed.signature)


def _gitlab_readonly_grant_json() -> str:
    grant = {
        "bundle_id": "odis-fixture-bundle",
        "bundle_version": "0.1.0",
        "trust_root_id": "fixture-trust-root",
        "families": {
            "gitlab-readonly": {
                "vendor_mcp": {
                    "endpoint_id": "gitlab-readonly",
                    "url": "https://gitlab-mcp.example.com/mcp",
                },
                "policy": {"rules": [{"verb": tool} for tool in _GITLAB_READONLY_TOOLS]},
                "default_mode": "strict",
            }
        },
    }
    return json.dumps(grant, separators=(",", ":"))


def _write_gitlab_readonly_mapping(dev_vault: DevVaultContext) -> None:
    response = httpx.post(
        f"{dev_vault.addr}/v1/apf/mappings/gitlab-readonly",
        headers={"X-Vault-Token": "root"},
        json={
            "bound_issuer": _FIXTURE_ISSUER,
            "bound_audiences": _FIXTURE_AUDIENCE,
            "bound_subject": _FIXTURE_SUBJECT,
            "bundle": _gitlab_readonly_grant_json(),
        },
        timeout=5.0,
    )
    response.raise_for_status()


def _vault_union_vendor_factory(
    clients_by_endpoint: dict[str, InMemoryMcpClient],
) -> Callable[[Family], McpClient]:
    def _factory(family: Family) -> McpClient:
        tools = [
            ToolDescriptor(
                name=tool,
                description=f"{tool} (vault union test stub)",
                input_schema={"type": "object"},
            )
            for tool in family.governed_tools()
        ]
        client = InMemoryMcpClient(
            tools=tools,
            responses={
                "gitlab_health": ToolResult(
                    content=[{"type": "text", "text": "vault-issued gitlab ok"}]
                ),
                "update_issue": ToolResult(
                    content=[{"type": "text", "text": "vault-issued jira ok"}]
                ),
            },
        )
        clients_by_endpoint[family.vendor_mcp.endpoint_id] = client
        return client

    return _factory


async def test_vault_issued_bundle_governs_via_router(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient, opa_binary: str
) -> None:
    # Mint-then-load a Vault-issued, offline-verified bundle.
    bundle = await _fetch_and_load(vault_client, dev_vault)
    assert bundle.bundle_id == "odis-fixture-bundle"
    family = bundle.family("jira-prod")
    assert family is not None

    # The same bundle drives a real OPA governance decision (the Router's gate).
    evaluator = PolicyEvaluator(opa_binary=opa_binary)
    allow = evaluator.evaluate(family, _request(issue_key="APF-123"))
    assert allow.decision == "allow"
    assert allow.obligations == {"allowed_fields": ["labels"]}

    deny = evaluator.evaluate(family, _request(issue_key="OTHER-1"))
    assert deny.decision == "deny"


async def test_vault_issued_signature_is_tamper_evident(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    # A flipped payload byte must fail offline verification.
    signed = await vault_client.fetch_signed_bundle(workload_jwt=dev_vault.workload_jwt)
    verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
        key_name=signed.key_name,
        public_keys_b64={signed.key_version: dev_vault.transit_public_key_b64},
    )
    assert verifier.verify(signed.payload, signed.signature) is True
    assert verifier.verify(signed.payload + b"x", signed.signature) is False


async def test_serve_signed_builds_router_from_vault(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient, opa_binary: str
) -> None:
    # The build_router_signed orchestration `serve --signed` uses, against a REAL
    # dev Vault: fetch (jwt-login → apf/issue) → offline verify → build the Router.
    source = SignedBundleSource(
        client=vault_client,
        workload_jwt=dev_vault.workload_jwt,
        bundle_pubkey_b64=dev_vault.transit_public_key_b64,
    )
    router = await build_router_signed(
        source=source,
        opa_binary=opa_binary,
        audit=audit_sink(),
        vendor_client_factory=in_memory_vendor_from_family,
    )
    assert router.bundle.bundle_id == "odis-fixture-bundle"
    assert router.bundle.family("jira-prod") is not None


async def test_vault_issued_gitlab_readonly_bundle_governs_read_only_tool(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient, opa_binary: str
) -> None:
    # Add a second assigned mapping for the same fixture identity. The plugin must
    # union this disjoint family with the provisioned Jira family, then sign one
    # bundle that the Router verifies offline before governing GitLab calls.
    _write_gitlab_readonly_mapping(dev_vault)

    clients_by_endpoint: dict[str, InMemoryMcpClient] = {}
    source = SignedBundleSource(
        client=vault_client,
        workload_jwt=dev_vault.workload_jwt,
        bundle_pubkey_b64=dev_vault.transit_public_key_b64,
    )
    router = await build_router_signed(
        source=source,
        opa_binary=opa_binary,
        audit=audit_sink(),
        vendor_client_factory=_vault_union_vendor_factory(clients_by_endpoint),
    )

    assert router.bundle.bundle_id == "odis-fixture-bundle"
    assert router.bundle.family("jira-prod") is not None
    family = router.bundle.family("gitlab-readonly")
    assert family is not None
    assert family.default_mode == "strict"
    assert family.governs_tool("gitlab_health")
    assert family.action_limits_for("gitlab_health") == {}

    assert router.discovery is not None
    aggregate = router.discovery.aggregate(router.bundle)
    assert "gitlab-readonly.gitlab_health" in {tool.name for tool in aggregate}

    result = await router.forward("gitlab-readonly", family, "gitlab_health", {})
    assert result.content == [{"type": "text", "text": "vault-issued gitlab ok"}]
    assert clients_by_endpoint["gitlab-readonly"].calls == [("gitlab_health", {})]
