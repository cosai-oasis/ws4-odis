"""Tests for the CLI entry points (`demo` + `serve` subcommands)."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from odis_harness.bundle.loader import BundleSignatureInvalid
from odis_harness.bundle.vault_client import VaultBundleClient
from odis_harness.cli import SignedBundleSource, build_router, build_router_signed, main
from tests.factories import audit_sink, in_memory_vendor_from_family

_REPO_ROOT = Path(__file__).resolve().parents[1]
_EXAMPLE_BUNDLE = _REPO_ROOT / "policy" / "bundle.example.yaml"

# The CLI runs the Router (async + real OPA); event-loop setup touches sockets.
pytestmark = pytest.mark.enable_socket


def _run(
    capsys: pytest.CaptureFixture[str],
    *argv: str,
) -> tuple[int, str, str]:
    exit_code = main(list(argv))
    captured = capsys.readouterr()
    return exit_code, captured.out, captured.err


@pytest.mark.requires_opa
def test_demo_runs_against_real_opa(
    capsys: pytest.CaptureFixture[str],
    opa_binary: str,
) -> None:
    exit_code, stdout, _ = _run(
        capsys,
        "demo",
        "--bundle",
        str(_EXAMPLE_BUNDLE),
        "--opa-binary",
        opa_binary,
        "--audit-output",
        "stderr",
    )
    assert exit_code == 0
    assert "ODIS Contract Harness" in stdout  # banner
    assert "Tier 3 allow" in stdout
    assert "Tier 3 deny" in stdout
    assert "obligation violation" in stdout
    assert "Unpoliced tool" in stdout
    # allow forwards to the vendor; deny + obligation + unpoliced do not.
    assert "downstream vendor calls observed: 1" in stdout


def test_demo_exits_non_zero_when_opa_missing(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ODIS_OPA_BIN", raising=False)
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("odis_harness.cli.commands._resolve_opa_binary", lambda _value: "")
    exit_code, _, stderr = _run(
        capsys,
        "demo",
        "--bundle",
        str(_EXAMPLE_BUNDLE),
    )
    assert exit_code == 2
    assert "no opa binary found" in stderr


@pytest.mark.requires_opa
def test_demo_audit_output_to_file(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    opa_binary: str,
) -> None:
    audit_path = tmp_path / "audit.jsonl"
    exit_code, _, _ = _run(
        capsys,
        "demo",
        "--bundle",
        str(_EXAMPLE_BUNDLE),
        "--opa-binary",
        opa_binary,
        "--audit-output",
        str(audit_path),
    )
    assert exit_code == 0
    assert audit_path.is_file()
    lines = [line for line in audit_path.read_text().splitlines() if line]
    assert lines  # at least one audit event written
    for line in lines:
        json.loads(line)  # every line is valid JSON
    # The allow scenario records a forward (Tier-3 semantic enforcement).
    assert any("odis.mcp.forward" in line for line in lines)


@pytest.mark.requires_opa
def test_demo_missing_bundle_fails_closed_with_clean_error(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    opa_binary: str,
) -> None:
    """A missing bundle exits 2 with a one-line error, not a raw traceback."""
    exit_code, _, stderr = _run(
        capsys,
        "demo",
        "--bundle",
        str(tmp_path / "does-not-exist.yaml"),
        "--opa-binary",
        opa_binary,
        "--audit-output",
        "stderr",
    )
    assert exit_code == 2
    assert "could not load the bundle" in stderr


@pytest.mark.requires_opa
def test_demo_audit_output_appends_across_runs(
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
    opa_binary: str,
) -> None:
    """The audit trail is append-only: a second run must not truncate the first."""
    audit_path = tmp_path / "audit.jsonl"
    argv = ("demo", "--bundle", str(_EXAMPLE_BUNDLE), "--opa-binary", opa_binary,
            "--audit-output", str(audit_path))
    _run(capsys, *argv)
    first = len([ln for ln in audit_path.read_text().splitlines() if ln])
    _run(capsys, *argv)
    second = len([ln for ln in audit_path.read_text().splitlines() if ln])
    assert second == 2 * first  # prior events preserved, not overwritten


@pytest.mark.requires_opa
async def test_build_router_loads_example_bundle(opa_binary: str) -> None:
    """build_router wires the Router from the example bundle + in-process vendor."""
    router = await build_router(
        bundle_path=_EXAMPLE_BUNDLE,
        opa_binary=opa_binary,
        audit=audit_sink(),
        vendor_client_factory=in_memory_vendor_from_family,
    )
    assert router.bundle.family("jira-prod") is not None
    assert router.discovery is not None
    catalog = router.discovery.aggregate(router.bundle)
    assert "jira-prod.update_issue" in [t.name for t in catalog]


def test_serve_command_surface_and_defaults() -> None:
    """The Typer `serve` command exposes the public serve flags and pinned defaults."""
    from typer.main import get_command  # noqa: PLC0415

    from odis_harness.cli import app  # noqa: PLC0415

    params = {p.name: p for p in get_command(app).commands["serve"].params}
    assert {
        "bundle",
        "opa_binary",
        "audit_output",
        "host",
        "port",
        "signed",
        "bridge",
        "oauth2",
        "oauth2_scopes",
        "oauth2_client_name",
        "oauth2_callback_host",
        "oauth2_callback_port",
        "oauth2_callback_timeout",
        "vault_addr",
        "vault_jwt_file",
        "vault_jwt_mount",
        "vault_jwt_role",
        "vault_issue_path",
        "bundle_pubkey_file",
    } <= set(params)
    assert params["host"].default == "127.0.0.1"
    assert params["port"].default == 8765
    assert params["vault_jwt_mount"].default == "jwt"


def test_serve_bridge_and_oauth2_are_mutually_exclusive(
    capsys: pytest.CaptureFixture[str],
) -> None:
    exit_code, _, stderr = _run(
        capsys,
        "serve",
        "--bridge",
        "--oauth2",
    )
    assert exit_code == 2
    assert "--bridge and --oauth2 are mutually exclusive" in stderr


def test_module_entry_point_dispatches_and_runs() -> None:
    """`python -m odis_harness` dispatches to cli.main; --help returns 0 via the bridge."""
    import odis_harness.__main__  # noqa: PLC0415

    assert odis_harness.__main__.main is main  # the -m shim points at the real CLI
    assert main(["--help"]) == 0  # (argv) -> int bridge: --help prints help, returns 0


# -- serve --signed (Vault-issued, offline-verified bundle) -----------------

_SIGNED_BUNDLE = {
    "bundle_id": "odis-signed-test",
    "bundle_version": "1",
    "trust_root_id": "fixture-trust-root",
    "families": {
        "jira-prod": {
            "vendor_mcp": {
                "endpoint_id": "jira-prod-mcp-v1",
                "url": "http://127.0.0.1:9/mcp",
            },
            "policy": (
                'package odis_policy\ndefault decision := {"decision": "deny", "obligations": {}}\n'
            ),
            "tools": {
                "update_issue": {"action_limits": {"allowed_fields": ["labels"]}},
            },
            "default_mode": "strict",
        },
    },
}


def _ed25519_keypair() -> tuple[Ed25519PrivateKey, str]:
    """A keypair + its public half as Vault transit's base64 raw-32-byte export."""
    key = Ed25519PrivateKey.generate()
    raw_pub = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return key, base64.b64encode(raw_pub).decode("ascii")


def _signed_issue_transport(key: Ed25519PrivateKey) -> httpx.MockTransport:
    """MockTransport serving jwt-login then apf/issue with a real ed25519 signature
    over the canonical bundle bytes — mimicking Vault transit, fully in-process."""
    payload = json.dumps(_SIGNED_BUNDLE, sort_keys=True, separators=(",", ":")).encode()
    signature = f"vault:v1:{base64.b64encode(key.sign(payload)).decode('ascii')}"

    def handle(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/auth/jwt/login":
            return httpx.Response(200, json={"auth": {"client_token": "s.tok"}})
        if request.url.path == "/v1/apf/issue":
            return httpx.Response(
                200,
                json={
                    "data": {
                        "payload": base64.b64encode(payload).decode("ascii"),
                        "signature": signature,
                        "signing": {
                            "key_name": "apf-bundle",
                            "key_version": 1,
                            "algorithm": "ed25519",
                        },
                    },
                },
            )
        message = f"unexpected path {request.url.path}"
        raise AssertionError(message)

    return httpx.MockTransport(handle)


def _signed_source(transport: httpx.MockTransport, pubkey_b64: str) -> SignedBundleSource:
    return SignedBundleSource(
        client=VaultBundleClient(
            vault_addr="https://vault.example:8200",
            jwt_login_mount="jwt",
            jwt_login_role="router",
            issue_path="apf/issue",
            transport=transport,
        ),
        workload_jwt="eyJ.workload.jwt",
        bundle_pubkey_b64=pubkey_b64,
    )


async def test_build_router_signed_verifies_offline_and_builds() -> None:
    """serve --signed's core: fetch a signed bundle, verify ed25519 offline, build."""
    key, pubkey_b64 = _ed25519_keypair()
    router = await build_router_signed(
        source=_signed_source(_signed_issue_transport(key), pubkey_b64),
        opa_binary="opa",  # stored, not invoked at build time
        audit=audit_sink(),
        vendor_client_factory=in_memory_vendor_from_family,
    )
    assert router.bundle.bundle_id == "odis-signed-test"
    assert router.bundle.family("jira-prod") is not None


async def test_build_router_signed_rejects_wrong_key() -> None:
    """Offline verification is real, not a fixture: a bundle signed by a different
    key fails closed with BundleSignatureInvalid before the Router is built."""
    signing_key, _ = _ed25519_keypair()
    _, wrong_pubkey_b64 = _ed25519_keypair()  # a DIFFERENT key's public half
    with pytest.raises(BundleSignatureInvalid):
        await build_router_signed(
            source=_signed_source(_signed_issue_transport(signing_key), wrong_pubkey_b64),
            opa_binary="opa",
            audit=audit_sink(),
            vendor_client_factory=in_memory_vendor_from_family,
        )


def test_serve_signed_fails_closed_without_vault_config(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """serve --signed with no Vault config exits 2 before serving (fail closed)."""
    monkeypatch.setattr(
        "odis_harness.cli.commands._resolve_opa_binary", lambda _value: "/usr/bin/opa"
    )
    for var in ("ODIS_VAULT_ADDR", "ODIS_VAULT_JWT_FILE", "ODIS_BUNDLE_PUBKEY_FILE"):
        monkeypatch.delenv(var, raising=False)
    exit_code, _, stderr = _run(capsys, "serve", "--signed")
    assert exit_code == 2
    assert "serve --signed requires" in stderr


async def test_build_router_signed_raises_on_malformed_pubkey() -> None:
    """A malformed trust-anchor pubkey surfaces NonEd25519PublicKeyError (which
    _serve_signed catches to fail closed) — not a generic crash."""
    from odis_harness.bundle.vault_verifier import NonEd25519PublicKeyError  # noqa: PLC0415

    key, _ = _ed25519_keypair()
    with pytest.raises(NonEd25519PublicKeyError):
        await build_router_signed(
            source=_signed_source(_signed_issue_transport(key), "!!!not-base64!!!"),
            opa_binary="opa",
            audit=audit_sink(),
            vendor_client_factory=in_memory_vendor_from_family,
        )


def test_serve_signed_fails_closed_on_non_ascii_input_file(
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A non-ASCII JWT/pubkey file exits 2 cleanly (UnicodeDecodeError caught), not a traceback."""
    monkeypatch.setattr(
        "odis_harness.cli.commands._resolve_opa_binary", lambda _value: "/usr/bin/opa"
    )
    jwt_file = tmp_path / "jwt"
    jwt_file.write_bytes(b"\xff\xfe not ascii")
    pubkey_file = tmp_path / "pub"
    pubkey_file.write_text("AAAA", encoding="ascii")
    exit_code, _, stderr = _run(
        capsys,
        "serve",
        "--signed",
        "--vault-addr",
        "https://vault.example:8200",
        "--vault-jwt-file",
        str(jwt_file),
        "--bundle-pubkey-file",
        str(pubkey_file),
    )
    assert exit_code == 2
    assert "cannot read signed-mode input file" in stderr
