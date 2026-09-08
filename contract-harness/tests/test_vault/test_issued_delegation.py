"""What a real Vault-issued grant carries, end to end.

The unit tests cover each field in isolation; this proves the assembled article: a
dev Vault, provisioned the way the ops scripts provision it, issues a grant whose
delegation record is complete, whose target declares an egress mode, and whose
attenuation profile resolves to the published document. Skipped when no vault binary
is present.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import httpx
import pytest

from odis_harness.bundle.loader import BundleLoader
from odis_harness.bundle.vault_client import VaultBundleError
from odis_harness.bundle.vault_verifier import VaultTransitSignatureVerifier

if TYPE_CHECKING:
    from odis_harness.bundle import Bundle
    from odis_harness.bundle.vault_client import VaultBundleClient
    from odis_harness.vault.dev import DevVaultContext

pytestmark = [pytest.mark.requires_vault, pytest.mark.enable_socket]

_REPO_ROOT = Path(__file__).resolve().parents[2]
_PROFILE = _REPO_ROOT / "vault-plugin" / "internal" / "policydsl" / "attenuation_profile_v1.json"
_FIXTURE_SUBJECT = "spiffe://example.org/agent/jira"


async def _issue(client: VaultBundleClient, dev_vault: DevVaultContext) -> Bundle:
    """Fetch, verify offline, and load a freshly issued grant."""
    signed = await client.fetch_signed_bundle(workload_jwt=dev_vault.workload_jwt)
    verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
        key_name=signed.key_name,
        public_keys_b64={signed.key_version: dev_vault.transit_public_key_b64},
    )
    return BundleLoader(signature_verifier=verifier).load_signed(signed.payload, signed.signature)


async def test_issued_grant_names_the_actor_and_the_delegator(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    """`actor` is the validated JWT subject and `originating_principal` the operator
    whose write created the mapping — both inside the signature, so neither can be
    changed after issuance."""
    bundle = await _issue(vault_client, dev_vault)

    assert bundle.actor == _FIXTURE_SUBJECT
    # provision.sh writes the mapping with the dev root token, which Vault reports as an
    # entity-less token named "token". The recorded principal appends that token's
    # accessor, because the display name alone is "token" for every entity-less token and
    # could not tell two operators apart — so the value is asserted by shape, and the
    # accessor's presence is the property that matters.
    principal = bundle.originating_principal
    assert principal is not None
    assert principal.startswith("vault:token:token:")
    accessor = principal.removeprefix("vault:token:token:")
    assert accessor, "the principal must carry the token accessor, not just the display name"


async def test_issued_grant_references_the_mapping_it_came_from(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    bundle = await _issue(vault_client, dev_vault)

    assert bundle.delegation_chain == (), "an issued grant must assert a root record"
    names = {record.name for record in bundle.contributing_records}
    assert "jira" in names, f"expected the provisioned mapping in {names}"
    for record in bundle.contributing_records:
        assert record.version >= 1
        assert record.digest.startswith("sha256:")


async def test_issued_grant_expires(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    """A grant with no expiry keeps authorizing until the Router restarts, which is
    what ODIS-L3-04 forbids. The issuer stamps a bounded window."""
    bundle = await _issue(vault_client, dev_vault)

    assert bundle.issued_at is not None
    assert bundle.expires_at is not None
    assert bundle.expired() is False
    assert datetime.fromisoformat(bundle.expires_at) > datetime.now(UTC)


async def test_issued_grant_declares_an_egress_mode_per_target(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    bundle = await _issue(vault_client, dev_vault)

    for name, family in bundle.families_iter():
        assert family.vendor_mcp.egress_mode == "bridge", f"family {name} declares no mode"


async def test_issued_grant_names_a_resolvable_attenuation_profile(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    bundle = await _issue(vault_client, dev_vault)

    ref = bundle.attenuation_profile_ref
    assert ref is not None
    assert ref.uri.endswith(":v1")
    assert ref.digest == "sha256:" + hashlib.sha256(_PROFILE.read_bytes()).hexdigest()


async def test_suspended_mapping_stops_conferring_authority(
    dev_vault: DevVaultContext, vault_client: VaultBundleClient
) -> None:
    """Suspending the mapping that confers the Jira family must take that family out
    of reach for the identity. Restored afterwards so the session dev Vault stays
    usable by whatever runs next.

    Other tests in the session may have added mappings for the same identity, so this
    asserts the family is unreachable rather than that issuance fails outright: with
    another mapping still active the grant is issued without jira-prod, and with none
    the plugin refuses. Either way the suspended record confers nothing.
    """
    family_name = "jira-prod"
    assert (await _issue(vault_client, dev_vault)).family(family_name) is not None

    def set_state(state: str) -> None:
        response = httpx.post(
            f"{dev_vault.addr}/v1/apf/mappings/jira",
            headers={"X-Vault-Token": "root"},
            json={
                "bound_issuer": "https://fixture.issuer.odis.local/",
                "bound_audiences": "apf-bundle-issuer",
                "bound_subject": _FIXTURE_SUBJECT,
                "bundle": _provisioned_grant_json(dev_vault),
                "lifecycle_state": state,
            },
            timeout=5.0,
        )
        response.raise_for_status()

    set_state("suspended")
    try:
        outcome = await _issue_or_refusal(vault_client, dev_vault)
    finally:
        set_state("active")

    if isinstance(outcome, str):
        # Nothing else conferred anything, so the plugin refused. 400, not 500: a
        # suspended record is authorization the identity does not hold, which is
        # absence rather than an internal failure.
        assert "400 Bad Request" in outcome
        assert "500" not in outcome
    else:
        assert outcome.family(family_name) is None, "a suspended record still conferred its family"

    assert (await _issue(vault_client, dev_vault)).family(family_name) is not None


async def _issue_or_refusal(
    client: VaultBundleClient, dev_vault: DevVaultContext
) -> Bundle | str:
    """The issued grant, or the refusal text when nothing confers one."""
    try:
        return await _issue(client, dev_vault)
    except VaultBundleError as exc:
        return str(exc)


def _provisioned_grant_json(dev_vault: DevVaultContext) -> str:
    """Read back the grant provision.sh wrote, so a re-write does not change it."""
    response = httpx.get(
        f"{dev_vault.addr}/v1/apf/mappings/jira",
        headers={"X-Vault-Token": "root"},
        timeout=5.0,
    )
    response.raise_for_status()
    import json  # noqa: PLC0415 — one local use, keeps the module's imports about the subject

    return json.dumps(response.json()["data"]["bundle"], separators=(",", ":"))
