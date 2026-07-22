"""`policy_digest` derivation."""

from __future__ import annotations

import dataclasses

from hypothesis import given, settings
from hypothesis import strategies as st

from odis_harness.bundle.digest import policy_digest
from odis_harness.bundle.types import Bundle, Family, ToolPolicy, VendorMcp


def _vendor(endpoint_id: str = "jira-prod-mcp-v1") -> VendorMcp:
    return VendorMcp(endpoint_id=endpoint_id, url="https://example.invalid/")


def _family(
    *,
    policy: str = "package odis_policy\n",
    action_limits: dict[str, object] | None = None,
    default_mode: str = "strict",
) -> Family:
    return Family(
        vendor_mcp=_vendor(),
        policy=policy,
        tools={
            "update_issue": ToolPolicy(
                action_limits=action_limits or {"allowed_fields": ["labels"]}
            )
        },
        default_mode=default_mode,  # type: ignore[arg-type]
    )


def _bundle(families: dict[str, Family] | None = None) -> Bundle:
    return Bundle(
        bundle_id="odis-fixture-bundle",
        bundle_version="0.1.0",
        trust_root_id="fixture-trust-root",
        families=families or {"jira-prod": _family()},
    )


def test_digest_is_64_hex_chars() -> None:
    digest = policy_digest(_bundle())
    assert len(digest) == 64
    assert all(c in "0123456789abcdef" for c in digest)


def test_digest_is_deterministic() -> None:
    """Same bundle content → same digest."""
    assert policy_digest(_bundle()) == policy_digest(_bundle())


def test_digest_changes_when_policy_changes() -> None:
    base = policy_digest(_bundle())
    altered = policy_digest(_bundle(families={"jira-prod": _family(policy="package different\n")}))
    assert base != altered


def test_digest_changes_when_routing_changes() -> None:
    base = policy_digest(_bundle())
    altered_family = dataclasses.replace(
        _family(), vendor_mcp=_vendor(endpoint_id="jira-prod-mcp-v2")
    )
    altered = policy_digest(_bundle(families={"jira-prod": altered_family}))
    assert base != altered


def test_digest_changes_when_action_limits_change() -> None:
    base = policy_digest(_bundle())
    altered = policy_digest(
        _bundle(
            families={"jira-prod": _family(action_limits={"allowed_fields": ["labels", "summary"]})}
        )
    )
    assert base != altered


def test_digest_changes_when_default_mode_changes() -> None:
    base = policy_digest(_bundle())
    altered = policy_digest(_bundle(families={"jira-prod": _family(default_mode="permissive")}))
    assert base != altered


def test_digest_changes_when_bundle_metadata_changes() -> None:
    base = policy_digest(_bundle())
    altered = dataclasses.replace(_bundle(), bundle_version="0.2.0")
    assert base != policy_digest(altered)


def test_digest_changes_when_family_name_changes() -> None:
    """Multi-instance via naming: `jira-prod` and `jira-staging` distinct."""
    bundle_prod = _bundle(families={"jira-prod": _family()})
    bundle_staging = _bundle(families={"jira-staging": _family()})
    assert policy_digest(bundle_prod) != policy_digest(bundle_staging)


def test_digest_changes_when_a_family_is_added() -> None:
    base = policy_digest(_bundle())
    augmented = policy_digest(_bundle(families={"jira-prod": _family(), "jira-staging": _family()}))
    assert base != augmented


@given(
    st.dictionaries(
        keys=st.from_regex(r"^[a-z][a-z0-9-]{0,10}$", fullmatch=True),
        values=st.builds(_family),
        min_size=1,
        max_size=4,
    )
)
@settings(max_examples=50, deadline=None)
def test_digest_stable_across_dict_insertion_order(
    families: dict[str, Family],
) -> None:
    """Property: a dict built with the same key/value set must yield the same
    digest no matter the insertion order. The canonicalization uses sort_keys=True."""
    forward = Bundle(
        bundle_id="b",
        bundle_version="v",
        trust_root_id="r",
        families=dict(families.items()),
    )
    backward = Bundle(
        bundle_id="b",
        bundle_version="v",
        trust_root_id="r",
        families=dict(reversed(families.items())),
    )
    assert policy_digest(forward) == policy_digest(backward)
