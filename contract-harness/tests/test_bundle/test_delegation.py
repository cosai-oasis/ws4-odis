"""The delegation record an issued grant carries, and the egress mode it declares.

Covers the Python side of ODIS-L2-05 (who delegated, and to whom), ODIS-L3-04 (the
grant expires), ODIS-L2-15 (per-target egress mode) and ODIS-L2-06 (the versioned
attenuation profile the grant was narrowed under).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from odis_harness.bundle.types import (
    AttenuationProfileRef,
    Bundle,
    Family,
    MappingRecordRef,
    ToolPolicy,
    VendorMcp,
)

_REPO_ROOT = Path(__file__).resolve().parents[2]
_GOLDEN = _REPO_ROOT / "vault-plugin" / "internal" / "apfbundle" / "testdata" / "golden_bundle.json"
_PROFILE = _REPO_ROOT / "vault-plugin" / "internal" / "policydsl" / "attenuation_profile_v1.json"


def _family() -> Family:
    return Family(
        vendor_mcp=VendorMcp(endpoint_id="jira-prod", url="https://example.invalid/"),
        policy="package odis_policy\n",
        tools={"update_issue": ToolPolicy()},
        default_mode="strict",
    )


def _bundle(**overrides: object) -> Bundle:
    fields: dict[str, object] = {
        "bundle_id": "b",
        "bundle_version": "0.1.0",
        "trust_root_id": "r",
        "families": {"jira-prod": _family()},
    }
    fields.update(overrides)
    return Bundle(**fields)  # type: ignore[arg-type]


# -- ODIS-L2-15: the egress-mode declaration ---------------------------------


def test_vendor_mcp_declares_bridge_by_default() -> None:
    """This harness enforces at the adapter rather than at the target, so a target
    that names no mode is declared bridge."""
    assert VendorMcp(endpoint_id="jira-prod", url="https://x.invalid/").egress_mode == "bridge"


@pytest.mark.parametrize("mode", ["native", "bridge"])
def test_vendor_mcp_accepts_both_legal_modes(mode: str) -> None:
    vendor = VendorMcp(endpoint_id="jira-prod", url="https://x.invalid/", egress_mode=mode)  # type: ignore[arg-type]
    assert vendor.egress_mode == mode


@pytest.mark.parametrize("mode", ["passthrough", "BRIDGE", ""])
def test_vendor_mcp_rejects_other_egress_modes(mode: str) -> None:
    """ODIS-L2-15 defines exactly two modes; a third would declare nothing checkable."""
    with pytest.raises(ValueError, match="egress_mode"):
        VendorMcp(endpoint_id="jira-prod", url="https://x.invalid/", egress_mode=mode)  # type: ignore[arg-type]


# -- ODIS-L3-04: the grant expires -------------------------------------------


def test_bundle_without_expiry_is_not_expired() -> None:
    """A local grant declares no window. It is not expired — and `expires_at` being
    absent is exactly why such a grant is immortal."""
    assert _bundle().expired() is False


def test_bundle_expired_when_expires_at_has_passed() -> None:
    past = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    assert _bundle(expires_at=past).expired() is True


def test_bundle_not_expired_before_expires_at() -> None:
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _bundle(expires_at=future).expired() is False


def test_bundle_expired_evaluated_at_supplied_instant() -> None:
    """`now` is injected so the Router's check is testable without sleeping."""
    expires = datetime(2026, 8, 27, 12, 0, tzinfo=UTC)
    bundle = _bundle(expires_at=expires.isoformat())
    assert bundle.expired(now=expires - timedelta(minutes=1)) is False
    assert bundle.expired(now=expires + timedelta(minutes=1)) is True


@pytest.mark.parametrize("stamp", ["not-a-timestamp", "2026-13-01T00:00:00Z", ""])
def test_bundle_rejects_unparseable_timestamps(stamp: str) -> None:
    """An unparseable window is indeterminate. Refusing to construct the Bundle fails
    closed at load, rather than leaving the Router to guess at forward time."""
    with pytest.raises(ValueError, match="expires_at"):
        _bundle(expires_at=stamp)


def test_bundle_rejects_a_stamped_issuance_with_no_expiry() -> None:
    """The one incoherent combination: stamped, therefore looks governed, yet
    unbounded. No issuer produces it — the signing seam refuses a partial record — so
    only a hand-authored grant can reach here, and it fails closed."""
    with pytest.raises(ValueError, match="issued_at"):
        _bundle(issued_at=datetime.now(UTC).isoformat())


def test_bundle_accepts_an_expiry_without_an_issuance_stamp() -> None:
    """Deliberately permitted: hand-authoring a local grant with an expiry and letting
    the Router enforce it is a real capability, so load is more permissive than the
    signing seam rather than symmetric with it."""
    future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
    assert _bundle(expires_at=future).expired() is False


def test_bundle_rejects_window_that_closes_before_it_opens() -> None:
    now = datetime.now(UTC)
    with pytest.raises(ValueError, match="expires_at"):
        _bundle(
            issued_at=now.isoformat(),
            expires_at=(now - timedelta(hours=1)).isoformat(),
        )


# -- ODIS-L2-05: the delegation chain ----------------------------------------


def test_bundle_asserts_a_root_delegation_chain() -> None:
    """`()` is an assertion; `None` is silence. An issued grant says single-hop."""
    assert _bundle(delegation_chain=()).delegation_chain == ()
    assert _bundle().delegation_chain is None


def test_bundle_rejects_a_claimed_delegation_hop() -> None:
    """A non-empty chain could only come from an issuer whose lineage this harness has
    no way to verify — there is no sub-delegation path here, so it fails closed."""
    with pytest.raises(ValueError, match="delegation_chain"):
        _bundle(delegation_chain=("spiffe://example.org/agent/coordinator",))


def test_issued_golden_asserts_a_root_chain() -> None:
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert golden["delegation_chain"] == [], "the issued grant must assert a root record"


# -- ODIS-L2-05 / L2-06: the provenance references ---------------------------


#: Full-length digests, because `MappingRecordRef` / `AttenuationProfileRef` require the
#: `sha256:<64 hex>` form the schema declares. Named rather than inlined: at 71 characters
#: each they exceed the line limit at any realistic indent.
_RECORD_DIGEST = "sha256:" + hashlib.sha256(b"jira-mapping-v3").hexdigest()
_PROFILE_DIGEST = "sha256:" + hashlib.sha256(b"attenuation-profile-v1").hexdigest()


def test_bundle_carries_delegation_provenance() -> None:
    bundle = _bundle(
        actor="spiffe://example.org/agent/jira",
        originating_principal="vault:entity:e-platform",
        contributing_records=(
            MappingRecordRef(name="jira", version=3, digest=_RECORD_DIGEST),
        ),
        attenuation_profile_ref=AttenuationProfileRef(
            uri="urn:x:v1", digest=_PROFILE_DIGEST
        ),
    )
    assert bundle.actor == "spiffe://example.org/agent/jira"
    assert bundle.originating_principal == "vault:entity:e-platform"
    assert bundle.contributing_records[0].version == 3
    assert bundle.attenuation_profile_ref is not None
    assert bundle.attenuation_profile_ref.uri == "urn:x:v1"


def test_bundle_does_not_claim_the_draft_authorization_ref() -> None:
    """`contributing_records` is a provenance manifest, not ODIS §6.3's
    `originating_authorization_ref` — that field references the authoritative grant
    that authorized the delegating principal, which this issuer does not hold. The
    draft's name must not appear over a different shape."""
    assert not hasattr(_bundle(), "originating_authorization_ref")
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    assert "originating_authorization_ref" not in golden
    assert golden["contributing_records"], "the manifest must be populated on an issued grant"


def test_provenance_changes_the_policy_digest() -> None:
    """The digest covers the whole grant, so re-issuing to a different actor under a
    different delegator cannot reuse the audit trail's identity for the old one."""
    base = _bundle(actor="spiffe://example.org/agent/jira")
    other = _bundle(actor="spiffe://example.org/agent/other")
    assert base.policy_digest != other.policy_digest


def test_attenuation_profile_ref_resolves_to_the_published_document() -> None:
    """ODIS-L2-06 requires the comparison rules be resolvable by a verifier. The
    digest on the Go-issued golden must be the digest of the published profile."""
    golden = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    ref = golden.get("attenuation_profile_ref")
    assert ref is not None, "the issued bundle must name the attenuation profile"
    digest = hashlib.sha256(_PROFILE.read_bytes()).hexdigest()
    assert ref["digest"] == f"sha256:{digest}"
    assert ref["uri"].endswith(":v1")
