"""The Typer CLI surface: the `demo` and `serve` commands, their run logic, and
the `main` entry point. Router construction lives in `cli.builders`.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import typer

from odis_harness.audit.banner import print_banner
from odis_harness.bundle.loader import BundleSchemaInvalid, BundleSignatureInvalid
from odis_harness.cli.builders import (
    SignedBundleSource,
    _build_audit,
    _demo_vendor_factory,
    _http_vendor_factory,
    build_router,
    build_router_signed,
    make_fixture_bridged_http_vendor_factory,
    make_oauth2_http_vendor_factory,
)
from odis_harness.mcp_forwarder.oauth import OAuth2InteractiveConfig
from odis_harness.mcp_forwarder.router import McpRefusal

#: Bundle-load failures the local `demo`/`serve` paths turn into a clean,
#: fail-closed one-line error + exit 2 (mirroring `serve --signed`) instead of
#: an unhandled traceback. `FileNotFoundError` is an `OSError` subclass.
_BUNDLE_LOAD_ERRORS = (OSError, BundleSchemaInvalid, BundleSignatureInvalid)

if TYPE_CHECKING:
    from collections.abc import Callable
    from typing import TextIO

    from odis_harness.bundle import Family
    from odis_harness.mcp_forwarder.vendor_client import McpClient


@dataclass(frozen=True, kw_only=True, slots=True)
class DemoSettings:
    bundle: str | None
    opa_binary: str | None
    audit_output: str


@dataclass(frozen=True, kw_only=True, slots=True)
class VendorAuthSettings:
    bridge: bool
    oauth2: bool
    oauth2_scopes: str | None
    oauth2_client_name: str
    oauth2_callback_host: str
    oauth2_callback_port: int | None
    oauth2_callback_timeout: float


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedBundleSettings:
    vault_addr: str | None
    vault_jwt_file: str | None
    vault_jwt_mount: str
    vault_jwt_role: str
    vault_issue_path: str
    bundle_pubkey_file: str | None


@dataclass(frozen=True, kw_only=True, slots=True)
class ServeSettings:
    bundle: str | None
    opa_binary: str | None
    audit_output: str
    host: str
    port: int
    signed: bool
    vendor_auth: VendorAuthSettings
    signed_bundle: SignedBundleSettings


def _serve_vendor_factory(settings: VendorAuthSettings) -> Callable[[Family], McpClient]:
    """Pick the leg-2 auth posture for `serve`.

    `--bridge` wires the fixture ODIS Bridge (a short-lived, audience-scoped token
    exchanged per vendor audience); the default stays `auth=None` (Secret-Zero), so
    plain `serve` and `demo` are unchanged.
    """
    if settings.bridge:
        return make_fixture_bridged_http_vendor_factory()
    if settings.oauth2:
        return make_oauth2_http_vendor_factory(_oauth2_config(settings))
    return _http_vendor_factory


def _resolve_bundle_path(value: str | None) -> Path:
    if value:
        return Path(value).resolve()
    return (Path.cwd() / "policy" / "bundle.example.yaml").resolve()


def _resolve_opa_binary(value: str | None) -> str:
    if value:
        return value
    env = os.environ.get("ODIS_OPA_BIN")
    if env:
        return env
    on_path = shutil.which("opa")
    if on_path:
        return on_path
    sibling = Path(__file__).resolve().parents[4] / "opa"
    if sibling.is_file() and os.access(sibling, os.X_OK):
        return str(sibling)
    return ""


def _audit_stream(value: str, stack: ExitStack) -> TextIO:
    if value == "-":
        return sys.stdout
    if value == "stderr":
        return sys.stderr
    # Append, never truncate: the audit trail is the governance artifact this
    # harness exists to preserve — a restart must not wipe prior events.
    stream = Path(value).open("a", encoding="utf-8", buffering=1)  # noqa: SIM115 - closed via ExitStack
    stack.callback(stream.close)
    return stream


# -- serve --------------------------------------------------------------------


def _run_serve(settings: ServeSettings) -> int:
    auth_error = _validate_vendor_auth(settings.vendor_auth)
    if auth_error is not None:
        sys.stderr.write(auth_error)
        return 2
    opa_binary = _resolve_opa_binary(settings.opa_binary)
    if not opa_binary:
        sys.stderr.write("ERROR: no opa binary found. Set ODIS_OPA_BIN or place 'opa' on PATH.\n")
        return 2
    if settings.signed:
        return _serve_signed(settings, opa_binary)
    return _serve_local(settings, opa_binary)


def _validate_vendor_auth(settings: VendorAuthSettings) -> str | None:
    if settings.bridge and settings.oauth2:
        return "ERROR: --bridge and --oauth2 are mutually exclusive.\n"
    return None


def _oauth2_config(settings: VendorAuthSettings) -> OAuth2InteractiveConfig:
    return OAuth2InteractiveConfig(
        client_name=settings.oauth2_client_name,
        scopes=settings.oauth2_scopes,
        callback_host=settings.oauth2_callback_host,
        callback_port=settings.oauth2_callback_port,
        callback_timeout=settings.oauth2_callback_timeout,
    )


def _leg2_mode(settings: VendorAuthSettings) -> str:
    if settings.bridge:
        return "bridge (fixture, short-lived per-vendor)"
    if settings.oauth2:
        return "oauth2 authorization_code PKCE"
    return "none (Secret-Zero)"


def _serve_local(settings: ServeSettings, opa_binary: str) -> int:
    bundle_path = _resolve_bundle_path(settings.bundle)
    vendor_client_factory = _serve_vendor_factory(settings.vendor_auth)

    async def _serve() -> int:
        with ExitStack() as stack:
            audit_stream = _audit_stream(settings.audit_output, stack)
            try:
                router = await build_router(
                    bundle_path=bundle_path,
                    opa_binary=opa_binary,
                    audit=_build_audit(audit_stream),
                    vendor_client_factory=vendor_client_factory,
                )
            except _BUNDLE_LOAD_ERRORS as exc:
                sys.stderr.write(f"ERROR: could not load the bundle {bundle_path}: {exc}\n")
                return 2
            print_banner(sys.stderr)
            sys.stderr.write(
                f"bundle:     {bundle_path}\n"
                f"opa_binary: {opa_binary}\n"
                f"leg-2 auth: {_leg2_mode(settings.vendor_auth)}\n"
                f"listening:  http://{settings.host}:{settings.port}/mcp\n"
            )
            await router.serve(host=settings.host, port=settings.port)
            return 0

    return asyncio.run(_serve())


def _serve_signed(settings: ServeSettings, opa_binary: str) -> int:
    """Serve a Vault-issued, offline-verified signed bundle. Fails closed."""
    signed = settings.signed_bundle
    vault_addr = signed.vault_addr
    vault_jwt_file = signed.vault_jwt_file
    bundle_pubkey_file = signed.bundle_pubkey_file
    required = {
        "--vault-addr": vault_addr,
        "--vault-jwt-file": vault_jwt_file,
        "--bundle-pubkey-file": bundle_pubkey_file,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        sys.stderr.write(
            "ERROR: serve --signed requires "
            + ", ".join(missing)
            + " (or the matching ODIS_* env vars).\n"
        )
        return 2
    if vault_addr is None or vault_jwt_file is None or bundle_pubkey_file is None:
        sys.stderr.write("ERROR: serve --signed received incomplete Vault configuration.\n")
        return 2
    try:
        workload_jwt = Path(vault_jwt_file).read_text(encoding="ascii").strip()
        bundle_pubkey_b64 = Path(bundle_pubkey_file).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        sys.stderr.write(f"ERROR: cannot read signed-mode input file: {exc}\n")
        return 2

    # Lazy: the vault path is a distinct capability; keep its types off the local import.
    from odis_harness.bundle.loader import (  # noqa: PLC0415
        BundleSchemaInvalid,
        BundleSignatureInvalid,
    )
    from odis_harness.bundle.vault_client import (  # noqa: PLC0415
        VaultBundleClient,
        VaultBundleError,
    )
    from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
        NonEd25519PublicKeyError,
    )

    source = SignedBundleSource(
        client=VaultBundleClient(
            vault_addr=vault_addr,
            jwt_login_mount=signed.vault_jwt_mount,
            jwt_login_role=signed.vault_jwt_role,
            issue_path=signed.vault_issue_path,
        ),
        workload_jwt=workload_jwt,
        bundle_pubkey_b64=bundle_pubkey_b64,
    )
    vendor_client_factory = _serve_vendor_factory(settings.vendor_auth)

    async def _serve() -> int:
        with ExitStack() as stack:
            audit_stream = _audit_stream(settings.audit_output, stack)
            try:
                router = await build_router_signed(
                    source=source,
                    opa_binary=opa_binary,
                    audit=_build_audit(audit_stream),
                    vendor_client_factory=vendor_client_factory,
                )
            except (
                VaultBundleError,
                NonEd25519PublicKeyError,
                BundleSignatureInvalid,
                BundleSchemaInvalid,
            ) as exc:
                sys.stderr.write(f"ERROR: could not load the signed bundle: {exc}\n")
                return 2
            print_banner(sys.stderr)
            sys.stderr.write(
                f"mode:       signed (Vault {signed.vault_addr}, issue {signed.vault_issue_path})\n"
                f"opa_binary: {opa_binary}\n"
                f"leg-2 auth: {_leg2_mode(settings.vendor_auth)}\n"
                f"listening:  http://{settings.host}:{settings.port}/mcp\n"
            )
            await router.serve(host=settings.host, port=settings.port)
            return 0

    return asyncio.run(_serve())


# -- demo ---------------------------------------------------------------------

#: (heading, family, tool, args, expectation-hint)
_DEMO_SCENARIOS: list[tuple[str, str, str, dict[str, object], str]] = [
    (
        "Tier 3 allow (labels on project APF)",
        "jira-prod",
        "update_issue",
        {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        "expect: success",
    ),
    (
        "Tier 3 deny (issue outside project APF)",
        "jira-prod",
        "update_issue",
        {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        "expect: refused=deny",
    ),
    (
        "Tier 3 obligation violation (non-label field)",
        "jira-prod",
        "update_issue",
        {"issue_key": "APF-1", "fields": {"summary": "leak"}},
        "expect: refused=obligation_violation",
    ),
    (
        "Unpoliced tool under strict mode",
        "jira-prod",
        "delete_issue",
        {"issue_key": "APF-1"},
        "expect: refused=unpoliced_tool",
    ),
]


def _run_demo(settings: DemoSettings) -> int:
    bundle_path = _resolve_bundle_path(settings.bundle)
    opa_binary = _resolve_opa_binary(settings.opa_binary)
    if not opa_binary:
        sys.stderr.write("ERROR: no opa binary found. Set ODIS_OPA_BIN or place 'opa' on PATH.\n")
        return 2

    async def _demo() -> int:
        with ExitStack() as stack:
            audit_stream = _audit_stream(settings.audit_output, stack)
            try:
                router = await build_router(
                    bundle_path=bundle_path,
                    opa_binary=opa_binary,
                    audit=_build_audit(audit_stream),
                    vendor_client_factory=_demo_vendor_factory,
                )
            except _BUNDLE_LOAD_ERRORS as exc:
                sys.stderr.write(f"ERROR: could not load the bundle {bundle_path}: {exc}\n")
                return 2
            print_banner(sys.stdout)
            sys.stdout.write(f"bundle:     {bundle_path}\nopa_binary: {opa_binary}\n\n")
            forwarded = 0
            for heading, family_name, tool, call_args, hint in _DEMO_SCENARIOS:
                sys.stdout.write(f"=== {heading} ({hint}) ===\n")
                family = router.bundle.family(family_name)
                if family is None:
                    sys.stdout.write(f"  (no such family {family_name!r})\n\n")
                    continue
                try:
                    await router.forward(family_name, family, tool, call_args)
                except McpRefusal as refusal:
                    sys.stdout.write(f"  refused: {refusal.reason_code}\n\n")
                else:
                    forwarded += 1
                    sys.stdout.write("  success: forwarded to vendor\n\n")
            sys.stdout.write(f"downstream vendor calls observed: {forwarded}\n")
        return 0

    return asyncio.run(_demo())


# -- Typer app ----------------------------------------------------------------


app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="ODIS Contract Harness — local runnable entry point.",
)

_BUNDLE_HELP = (
    "local bundle YAML for demo/plain serve; ignored by serve --signed "
    "(default: $ODIS_BUNDLE or ./policy/bundle.example.yaml)"
)
_OPA_HELP = "opa binary path (default: $ODIS_OPA_BIN or PATH lookup)"
_AUDIT_HELP = "'-' for stdout, 'stderr' for stderr, or a file path"


@app.command()
def demo(
    bundle: str | None = typer.Option(None, envvar="ODIS_BUNDLE", help=_BUNDLE_HELP),
    opa_binary: str | None = typer.Option(None, help=_OPA_HELP),
    audit_output: str = typer.Option("stderr", envvar="ODIS_AUDIT_OUTPUT", help=_AUDIT_HELP),
) -> None:
    """Run the canonical Tier 3 scenarios against an in-process vendor stub."""
    settings = DemoSettings(bundle=bundle, opa_binary=opa_binary, audit_output=audit_output)
    raise typer.Exit(_run_demo(settings))


@app.command()
def serve(
    bundle: str | None = typer.Option(None, envvar="ODIS_BUNDLE", help=_BUNDLE_HELP),
    opa_binary: str | None = typer.Option(None, help=_OPA_HELP),
    audit_output: str = typer.Option("stderr", envvar="ODIS_AUDIT_OUTPUT", help=_AUDIT_HELP),
    host: str = typer.Option("127.0.0.1", help="bind host"),
    port: int = typer.Option(8765, help="bind port"),
    signed: bool = typer.Option(
        False,
        "--signed",
        help=(
            "load a Vault-issued signed bundle (offline-verified) instead of a local file; "
            "--bundle and ODIS_BUNDLE are ignored"
        ),
    ),
    bridge: bool = typer.Option(
        False,
        "--bridge",
        help=(
            "wire the ODIS Bridge for leg-2 auth: present a short-lived, audience-scoped "
            "bearer per vendor (fixture token-exchange); mutually exclusive with --oauth2. "
            "Default: auth=None (Secret-Zero)"
        ),
    ),
    oauth2: bool = typer.Option(
        False,
        "--oauth2",
        envvar="ODIS_OAUTH2",
        help=(
            "use OAuth2 authorization-code/PKCE with dynamic client registration "
            "for Router-to-vendor auth; mutually exclusive with --bridge. Without either "
            "auth option, downstream requests use auth=None"
        ),
    ),
    oauth2_scopes: str | None = typer.Option(
        None,
        "--oauth2-scopes",
        envvar="ODIS_OAUTH2_SCOPES",
        help="space-separated OAuth2 scopes",
    ),
    oauth2_client_name: str = typer.Option(
        "ODIS Contract Harness",
        "--oauth2-client-name",
        envvar="ODIS_OAUTH2_CLIENT_NAME",
        help="OAuth2 dynamic-registration client name",
    ),
    oauth2_callback_host: str = typer.Option(
        "127.0.0.1",
        "--oauth2-callback-host",
        envvar="ODIS_OAUTH2_CALLBACK_HOST",
        help="OAuth2 loopback callback bind host",
    ),
    oauth2_callback_port: int | None = typer.Option(
        None,
        "--oauth2-callback-port",
        envvar="ODIS_OAUTH2_CALLBACK_PORT",
        help="OAuth2 loopback callback port (default: random available port)",
    ),
    oauth2_callback_timeout: float = typer.Option(
        300.0,
        "--oauth2-callback-timeout",
        envvar="ODIS_OAUTH2_CALLBACK_TIMEOUT",
        help="seconds to wait for OAuth2 callback",
    ),
    vault_addr: str | None = typer.Option(
        None, envvar="ODIS_VAULT_ADDR", help="Vault address for --signed"
    ),
    vault_jwt_file: str | None = typer.Option(
        None,
        envvar="ODIS_VAULT_JWT_FILE",
        help="file holding the workload JWT presented to Vault for --signed",
    ),
    vault_jwt_mount: str = typer.Option(
        "jwt", envvar="ODIS_VAULT_JWT_MOUNT", help="Vault JWT auth mount for --signed"
    ),
    vault_jwt_role: str = typer.Option(
        "router", envvar="ODIS_VAULT_JWT_ROLE", help="Vault JWT auth role for --signed"
    ),
    vault_issue_path: str = typer.Option(
        "apf/issue", envvar="ODIS_VAULT_ISSUE_PATH", help="plugin issue path for --signed"
    ),
    bundle_pubkey_file: str | None = typer.Option(
        None,
        envvar="ODIS_BUNDLE_PUBKEY_FILE",
        help="base64 ed25519 transit public-key file — the offline trust anchor for --signed",
    ),
) -> None:
    """Run the Router as an MCP server over HTTP (add --signed for a Vault-issued bundle)."""
    settings = ServeSettings(
        bundle=bundle,
        opa_binary=opa_binary,
        audit_output=audit_output,
        host=host,
        port=port,
        signed=signed,
        vendor_auth=VendorAuthSettings(
            bridge=bridge,
            oauth2=oauth2,
            oauth2_scopes=oauth2_scopes,
            oauth2_client_name=oauth2_client_name,
            oauth2_callback_host=oauth2_callback_host,
            oauth2_callback_port=oauth2_callback_port,
            oauth2_callback_timeout=oauth2_callback_timeout,
        ),
        signed_bundle=SignedBundleSettings(
            vault_addr=vault_addr,
            vault_jwt_file=vault_jwt_file,
            vault_jwt_mount=vault_jwt_mount,
            vault_jwt_role=vault_jwt_role,
            vault_issue_path=vault_issue_path,
            bundle_pubkey_file=bundle_pubkey_file,
        ),
    )
    raise typer.Exit(_run_serve(settings))


def main(argv: list[str] | None = None) -> int:
    """Console-script / `python -m` entry: run the Typer app, return its exit code.

    `standalone_mode=False` makes Click return the code (and re-raise usage errors)
    instead of calling `sys.exit`, so this stays a testable `(argv) -> int` while the
    `demo` / `serve` commands raise `typer.Exit`.
    """
    import click  # noqa: PLC0415 — only to map Click's exit/usage exceptions to a code

    try:
        result = app(args=argv, standalone_mode=False)
    except click.exceptions.Exit as exc:
        return int(getattr(exc, "exit_code", 0) or 0)
    except click.exceptions.ClickException as exc:
        exc.show()
        return exc.exit_code
    return int(result or 0)


__all__ = ["app", "main"]
