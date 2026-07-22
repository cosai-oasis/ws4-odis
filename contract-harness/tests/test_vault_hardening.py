"""Least-privilege + secret-hygiene hardening against a live dev Vault.

Asserts the Router's caller token can reach ONLY apf/issue, the signer policy grants
ONLY transit/sign, the secret_id is never echoed, issue errors leak no secret/JWT, and
provisioning uses no Enterprise-only features. Skipped when no vault binary is present.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

if TYPE_CHECKING:
    from odis_harness.vault.dev import DevVaultContext

pytestmark = [pytest.mark.requires_vault, pytest.mark.enable_socket]

_ROOT = "root"  # dev-mode root token
_FORBIDDEN = 403


def _router_token(ctx: DevVaultContext) -> str:
    resp = httpx.post(
        f"{ctx.addr}/v1/auth/{ctx.jwt_login_mount}/login",
        json={"role": ctx.jwt_login_role, "jwt": ctx.workload_jwt},
        timeout=5.0,
    )
    resp.raise_for_status()
    return resp.json()["auth"]["client_token"]


def test_router_token_cannot_reach_beyond_issue(dev_vault: DevVaultContext) -> None:
    # The jwt-auth caller token (apf-issue policy) is denied everywhere else.
    token = _router_token(dev_vault)
    headers = {"X-Vault-Token": token}
    mounts = httpx.get(f"{dev_vault.addr}/v1/sys/mounts", headers=headers, timeout=5.0)
    assert mounts.status_code == _FORBIDDEN
    sign = httpx.post(
        f"{dev_vault.addr}/v1/transit/sign/apf-bundle",
        headers=headers,
        json={"input": "eA=="},
        timeout=5.0,
    )
    assert sign.status_code == _FORBIDDEN


def test_apf_sign_policy_is_least_privilege(dev_vault: DevVaultContext) -> None:
    # The signer policy grants ONLY transit/sign on the bundle key.
    resp = httpx.get(
        f"{dev_vault.addr}/v1/sys/policies/acl/apf-sign",
        headers={"X-Vault-Token": _ROOT},
        timeout=5.0,
    )
    resp.raise_for_status()
    policy = resp.json()["data"]["policy"]
    assert "transit/sign/apf-bundle" in policy
    assert policy.count('path "') == 1  # exactly one granted path
    assert "sys/" not in policy
    assert "transit/keys" not in policy


def test_signing_config_never_echoes_secret_id(dev_vault: DevVaultContext) -> None:
    # secret_id is reported as a boolean, never returned.
    resp = httpx.get(
        f"{dev_vault.addr}/v1/apf/config/signing",
        headers={"X-Vault-Token": _ROOT},
        timeout=5.0,
    )
    resp.raise_for_status()
    data = resp.json()["data"]
    assert data["secret_id_configured"] is True
    assert "secret_id" not in data


def test_issue_error_leaks_no_secret_or_jwt(dev_vault: DevVaultContext) -> None:
    # A rejected issue echoes neither the forwarded JWT nor any secret.
    token = _router_token(dev_vault)
    bad_jwt = "not.a.valid.jwt"
    resp = httpx.post(
        f"{dev_vault.addr}/v1/{dev_vault.issue_path}",
        headers={"X-Vault-Token": token},
        json={"jwt": bad_jwt},
        timeout=5.0,
    )
    assert resp.is_client_error  # the invalid JWT is rejected, not just redacted
    body = resp.text
    assert bad_jwt not in body
    assert "secret" not in body.lower()


def test_provisioning_uses_no_enterprise_features() -> None:
    # The OSS provisioning path touches no Enterprise-only feature.
    script = (Path(__file__).resolve().parents[1] / "vault" / "provision.sh").read_text(
        encoding="utf-8"
    )
    lowered = script.lower()
    # Enterprise-only Vault command *invocations* — not bare words, which appear
    # legitimately (e.g. the workload's spiffe:// subject, or a comment explaining
    # why GenerateIdentityToken is avoided).
    for enterprise in ("enable spiffe", "managed-key", "vault namespace"):
        assert enterprise not in lowered
