"""BundleLoader, SignatureVerifier Protocol, fixture."""

from __future__ import annotations

import base64
from typing import TYPE_CHECKING

import pytest
import yaml
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from odis_harness.bundle.loader import (
    BundleLoader,
    BundleSchemaInvalid,
    BundleSignatureInvalid,
)
from odis_harness.bundle.types import Bundle
from odis_harness.bundle.vault_verifier import VaultTransitSignatureVerifier
from odis_harness.fixtures.signature import FixtureSignatureVerifier

if TYPE_CHECKING:
    from pathlib import Path

_KEY_NAME = "apf-bundle"

_MINIMAL_BUNDLE_YAML = """
bundle_id: odis-fixture-bundle
bundle_version: 0.1.0
trust_root_id: fixture-trust-root
families:
  jira-prod:
    vendor_mcp:
      endpoint_id: jira-prod-mcp-v1
      url: https://jira-prod-mcp.internal:8443/
    policy: |
      package odis_policy
    tools:
      update_issue:
        action_limits:
          allowed_fields:
            - labels
    default_mode: strict
"""


@pytest.fixture
def bundle_path(tmp_path: Path) -> Path:
    path = tmp_path / "bundle.yaml"
    path.write_text(_MINIMAL_BUNDLE_YAML, encoding="utf-8")
    return path


@pytest.fixture
def loader() -> BundleLoader:
    return BundleLoader(signature_verifier=FixtureSignatureVerifier())


def test_fixture_verifier_always_accepts() -> None:
    """The fixture verifier is the do-nothing implementation used in tests
    and the harness's local-dev mode. Production substitutes."""
    assert FixtureSignatureVerifier().verify(b"any-payload", b"any-signature") is True


def test_loader_returns_bundle_on_valid_input(loader: BundleLoader, bundle_path: Path) -> None:
    bundle = loader.load(bundle_path)
    assert isinstance(bundle, Bundle)
    assert bundle.bundle_id == "odis-fixture-bundle"
    assert "jira-prod" in bundle.families
    assert bundle.families["jira-prod"].default_mode == "strict"
    assert bundle.families["jira-prod"].vendor_mcp.endpoint_id == "jira-prod-mcp-v1"


def test_loader_raises_signature_invalid_when_verifier_returns_false(
    bundle_path: Path,
) -> None:
    class RejectingVerifier:
        def verify(self, payload: bytes, signature: bytes) -> bool:
            return False

    loader = BundleLoader(signature_verifier=RejectingVerifier())
    with pytest.raises(BundleSignatureInvalid):
        loader.load(bundle_path)


@pytest.mark.parametrize(
    "missing_field",
    ["bundle_id", "bundle_version", "trust_root_id", "families"],
)
def test_loader_raises_schema_invalid_when_required_top_level_field_missing(
    loader: BundleLoader,
    tmp_path: Path,
    missing_field: str,
) -> None:
    import yaml as _yaml  # local import — keep PyYAML out of the module-level deps  # noqa: PLC0415

    parsed = _yaml.safe_load(_MINIMAL_BUNDLE_YAML)
    parsed.pop(missing_field)
    bad = tmp_path / "bad.yaml"
    bad.write_text(_yaml.safe_dump(parsed), encoding="utf-8")
    with pytest.raises(BundleSchemaInvalid):
        loader.load(bad)


def test_loader_raises_schema_invalid_on_invalid_url_format(
    loader: BundleLoader, tmp_path: Path
) -> None:
    """Loader uses FORMAT_CHECKER, so an unparseable URI is rejected."""
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        _MINIMAL_BUNDLE_YAML.replace("https://jira-prod-mcp.internal:8443/", "not a uri at all"),
        encoding="utf-8",
    )
    with pytest.raises(BundleSchemaInvalid):
        loader.load(bad)


def test_loader_raises_schema_invalid_on_non_utf8_payload(
    loader: BundleLoader, tmp_path: Path
) -> None:
    """Non-UTF-8 bytes are surfaced as BundleSchemaInvalid, not raw UnicodeDecodeError."""
    bad = tmp_path / "bad.yaml"
    bad.write_bytes(b"\xff\xfe\x00bundle_id: latin-1-garbage")
    with pytest.raises(BundleSchemaInvalid):
        loader.load(bad)


def test_loader_raises_schema_invalid_when_endpoint_id_pattern_violated(
    loader: BundleLoader, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        _MINIMAL_BUNDLE_YAML.replace("jira-prod-mcp-v1", "Jira-Prod"),
        encoding="utf-8",
    )
    with pytest.raises(BundleSchemaInvalid):
        loader.load(bad)


def test_loader_raises_schema_invalid_on_unparseable_yaml(
    loader: BundleLoader, tmp_path: Path
) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("[: not valid yaml :", encoding="utf-8")
    with pytest.raises(BundleSchemaInvalid):
        loader.load(bad)


def test_loader_raises_file_not_found_on_missing_path(loader: BundleLoader, tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError):
        loader.load(tmp_path / "does-not-exist.yaml")


def _pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def _transit_signature(private_key: Ed25519PrivateKey, payload: bytes, version: int) -> bytes:
    raw = private_key.sign(payload)
    return f"vault:v{version}:{base64.b64encode(raw).decode('ascii')}".encode("ascii")


def test_load_signed_returns_bundle_on_valid_signed_payload() -> None:
    # load_signed verifies via the injected verifier, then
    # schema-validates and constructs the Bundle — all from in-memory bytes.
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key)},
    )
    # JSON is a YAML subset, so yaml.safe_load parses the canonical bytes.
    payload = yaml.safe_dump(yaml.safe_load(_MINIMAL_BUNDLE_YAML)).encode("utf-8")
    signature = _transit_signature(private_key, payload, version=1)

    bundle = BundleLoader(signature_verifier=verifier).load_signed(payload, signature)

    assert isinstance(bundle, Bundle)
    assert bundle.bundle_id == "odis-fixture-bundle"
    assert bundle.families["jira-prod"].default_mode == "strict"


def test_load_signed_raises_signature_invalid_on_bad_signature() -> None:
    # a signature that does not verify surfaces BundleSignatureInvalid.
    signing_key = Ed25519PrivateKey.generate()
    other_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(other_key)},
    )
    payload = yaml.safe_dump(yaml.safe_load(_MINIMAL_BUNDLE_YAML)).encode("utf-8")
    signature = _transit_signature(signing_key, payload, version=1)

    with pytest.raises(BundleSignatureInvalid):
        BundleLoader(signature_verifier=verifier).load_signed(payload, signature)


def test_load_signed_raises_schema_invalid_on_bad_schema() -> None:
    # a correctly-signed payload that violates odis.bundle.v1 still
    # raises BundleSchemaInvalid (verification passes, validation fails).
    private_key = Ed25519PrivateKey.generate()
    verifier = VaultTransitSignatureVerifier.from_pem(
        key_name=_KEY_NAME,
        public_key_pems={1: _pem(private_key)},
    )
    parsed = yaml.safe_load(_MINIMAL_BUNDLE_YAML)
    del parsed["trust_root_id"]  # required top-level field
    payload = yaml.safe_dump(parsed).encode("utf-8")
    signature = _transit_signature(private_key, payload, version=1)

    with pytest.raises(BundleSchemaInvalid):
        BundleLoader(signature_verifier=verifier).load_signed(payload, signature)


_ISSUED_BUNDLE_YAML = """
bundle_id: odis-fixture-bundle
bundle_version: 0.1.0
trust_root_id: fixture-trust-root
actor: spiffe://example.org/agent/jira
originating_principal: vault:entity:e-platform
contributing_records:
  - name: jira
    version: 2
    digest: sha256:89896f50203a4a2b01404a5599245f5d1e2e264f4804e9cab0389f09b3ae97a5
delegation_chain: []
attenuation_profile_ref:
  uri: urn:odis:contract-harness:attenuation-profile:v1
  digest: sha256:bc84f75825a2de866ed4ffaa86b817bccfc1fdc2fc4d0090070812e92eeff953
issued_at: "2026-08-27T12:00:00Z"
expires_at: "2026-08-27T13:00:00Z"
families:
  jira-prod:
    vendor_mcp:
      endpoint_id: jira-prod-mcp-v1
      url: https://jira-prod-mcp.internal:8443/
      egress_mode: bridge
    policy: |
      package odis_policy
    tools:
      update_issue: {}
    default_mode: strict
"""


def test_loader_reads_the_delegation_record(loader: BundleLoader, tmp_path: Path) -> None:
    """A Vault-issued grant carries its delegation record in the signed bytes; the
    loader must surface it, or the Router cannot enforce the expiry."""
    path = tmp_path / "issued.yaml"
    path.write_text(_ISSUED_BUNDLE_YAML, encoding="utf-8")

    bundle = loader.load(path)
    assert bundle.actor == "spiffe://example.org/agent/jira"
    assert bundle.originating_principal == "vault:entity:e-platform"
    assert bundle.contributing_records[0].name == "jira"
    assert bundle.contributing_records[0].version == 2
    assert bundle.delegation_chain == ()
    assert bundle.attenuation_profile_ref is not None
    assert bundle.attenuation_profile_ref.uri.endswith(":v1")
    assert bundle.issued_at == "2026-08-27T12:00:00Z"
    assert bundle.expires_at == "2026-08-27T13:00:00Z"
    assert bundle.families["jira-prod"].vendor_mcp.egress_mode == "bridge"


def test_loader_rejects_an_unparseable_grant_window(loader: BundleLoader, tmp_path: Path) -> None:
    """An indeterminate window fails at load rather than at the first forward."""
    path = tmp_path / "bad-window.yaml"
    path.write_text(_ISSUED_BUNDLE_YAML.replace('"2026-08-27T13:00:00Z"', '"whenever"'), "utf-8")

    with pytest.raises(BundleSchemaInvalid):
        loader.load(path)
