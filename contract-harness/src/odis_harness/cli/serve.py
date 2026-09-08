"""The `serve` command: run the Router as an MCP server over HTTP.

Holds the command, its option-to-settings plumbing, the two grant sources (local file and
Vault-issued), the leg-2 vendor-auth posture, and the inbound-credential configuration.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import ExitStack
from typing import TYPE_CHECKING

import typer

from odis_harness.audit.banner import print_banner
from odis_harness.bundle.loader import BundleSchemaInvalid, BundleSignatureInvalid

# Runtime import, not type-only: Typer resolves the `Annotated` aliases in the command
# signature via `get_type_hints`, and `from __future__ import annotations` makes those
# annotations strings. Under TYPE_CHECKING the name is absent and the command fails to build.
from odis_harness.cli import options  # noqa: TC001
from odis_harness.cli.app import app
from odis_harness.cli.builders import (
    BUNDLE_LOAD_ERRORS,
    GrantSourceConfigError,
    RouterWiring,
    SignedSourceConfigError,
    audit_stream,
    build_audit,
    build_router,
    build_router_signed,
    grant_banner_line,
    http_vendor_factory,
    make_fixture_bridged_http_vendor_factory,
    make_oauth2_http_vendor_factory,
    reject_unverified_with_signed,
    resolve_bundle_path,
    resolve_file_verifier,
    resolve_opa_binary,
    resolve_signed_source,
    stub_context_factory,
)
from odis_harness.cli.settings import (
    InboundAuthSettings,
    ServeSettings,
    SignedBundleSettings,
    VendorAuthSettings,
)
from odis_harness.mcp_forwarder.oauth import OAuth2InteractiveConfig

if TYPE_CHECKING:
    from mcp.server.auth.provider import TokenVerifier

    from odis_harness.cli.builders import VendorClientFactory



def _serve_vendor_factory(settings: VendorAuthSettings) -> VendorClientFactory:
    """Pick the leg-2 auth posture for `serve`.

    `--bridge` wires the fixture ODIS Bridge (a short-lived, audience-scoped token
    exchanged per vendor audience); the default stays `auth=None` (Secret-Zero), so
    plain `serve` and `demo` are unchanged.
    """
    if settings.bridge:
        return make_fixture_bridged_http_vendor_factory()
    if settings.oauth2:
        return make_oauth2_http_vendor_factory(_oauth2_config(settings))
    return http_vendor_factory


# -- serve --------------------------------------------------------------------


def _run_serve(settings: ServeSettings) -> int:
    auth_error = _validate_vendor_auth(settings.vendor_auth)
    if auth_error is not None:
        sys.stderr.write(auth_error)
        return 2
    opa_binary = resolve_opa_binary(settings.opa_binary)
    if not opa_binary:
        sys.stderr.write("ERROR: no opa binary found. Set ODIS_OPA_BIN or place 'opa' on PATH.\n")
        return 2
    try:
        verifier = _build_inbound_verifier(settings.inbound_auth)
    except _InboundAuthConfigError as exc:
        # Configuration that would not actually authenticate anyone. Checked here, before
        # the router is built: in signed mode that build performs a Vault login, bundle
        # issuance and a vendor-discovery pass that emits audit events for connections it
        # opened — all of it wasted work for a run that cannot legally serve.
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2
    if settings.signed:
        return _serve_signed(settings, opa_binary, verifier)
    return _serve_local(settings, opa_binary, verifier)


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


def _serve_local(
    settings: ServeSettings, opa_binary: str, verifier: TokenVerifier | None
) -> int:
    bundle_path = resolve_bundle_path(settings.bundle)
    try:
        file_verifier = resolve_file_verifier(
            bundle_pubkey_file=settings.signed_bundle.bundle_pubkey_file,
            trust_unverified=settings.trust_bundle_unverified,
            command="serve",
        )
    except GrantSourceConfigError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2
    vendor_client_factory = _serve_vendor_factory(settings.vendor_auth)

    async def _serve() -> int:
        with ExitStack() as stack:
            stream = audit_stream(settings.audit_output, stack)
            try:
                router = await build_router(
                    bundle_path=bundle_path,
                    opa_binary=opa_binary,
                    audit=build_audit(stream),
                    signature_verifier=file_verifier,
                    wiring=RouterWiring(
                        context_factory=stub_context_factory(),
                        vendor_client_factory=vendor_client_factory,
                    ),
                )
            except BUNDLE_LOAD_ERRORS as exc:
                sys.stderr.write(f"ERROR: could not load the bundle {bundle_path}: {exc}\n")
                return 2
            grant = grant_banner_line(
                bundle_path=bundle_path,
                trust_unverified=settings.trust_bundle_unverified,
            )
            print_banner(sys.stderr)
            sys.stderr.write(
                f"grant:      {grant}\n"
                f"opa_binary: {opa_binary}\n"
                f"leg-2 auth: {_leg2_mode(settings.vendor_auth)}\n"
                f"inbound:    {_inbound_mode(settings.inbound_auth)}\n"
                f"listening:  http://{settings.host}:{settings.port}/mcp\n"
            )
            if settings.inbound_auth.enabled:
                sys.stderr.write(f"{_CLEARTEXT_BEARER_WARNING}\n")
            await router.serve(
                host=settings.host,
                port=settings.port,
                token_verifier=verifier,
            )
            return 0

    return asyncio.run(_serve())


def _serve_signed(
    settings: ServeSettings, opa_binary: str, verifier: TokenVerifier | None
) -> int:
    """Serve a Vault-issued, offline-verified signed bundle. Fails closed."""
    try:
        reject_unverified_with_signed(
            trust_unverified=settings.trust_bundle_unverified, command="serve"
        )
    except GrantSourceConfigError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2
    # Lazy: the vault path is a distinct capability; keep its types off the local import.
    from odis_harness.bundle.vault_client import VaultBundleError  # noqa: PLC0415
    from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
        NonEd25519PublicKeyError,
    )

    signed = settings.signed_bundle
    vendor_client_factory = _serve_vendor_factory(settings.vendor_auth)
    try:
        source = resolve_signed_source(signed, command="serve")
    except SignedSourceConfigError as exc:
        sys.stderr.write(f"ERROR: {exc}\n")
        return 2

    async def _serve() -> int:
        with ExitStack() as stack:
            stream = audit_stream(settings.audit_output, stack)
            try:
                router = await build_router_signed(
                    source=source,
                    opa_binary=opa_binary,
                    audit=build_audit(stream),
                    wiring=RouterWiring(
                        context_factory=stub_context_factory(),
                        vendor_client_factory=vendor_client_factory,
                    ),
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
                f"inbound:    {_inbound_mode(settings.inbound_auth)}\n"
                f"listening:  http://{settings.host}:{settings.port}/mcp\n"
            )
            if settings.inbound_auth.enabled:
                sys.stderr.write(f"{_CLEARTEXT_BEARER_WARNING}\n")
            await router.serve(
                host=settings.host,
                port=settings.port,
                token_verifier=verifier,
            )
            return 0

    return asyncio.run(_serve())


@app.command()
def serve(
    bundle: options.Bundle = None,
    opa_binary: options.OpaBinary = None,
    audit_output: options.AuditOutput = "stderr",
    host: options.Host = "127.0.0.1",
    port: options.Port = 8765,
    inbound_key: options.InboundKey = None,
    inbound_issuer: options.InboundIssuer = "",
    inbound_audience: options.InboundAudience = "",
    signed: options.Signed = False,
    bridge: options.Bridge = False,
    oauth2: options.OAuth2 = False,
    oauth2_scopes: options.OAuth2Scopes = None,
    oauth2_client_name: options.OAuth2ClientName = "ODIS Contract Harness",
    oauth2_callback_host: options.OAuth2CallbackHost = "127.0.0.1",
    oauth2_callback_port: options.OAuth2CallbackPort = None,
    oauth2_callback_timeout: options.OAuth2CallbackTimeout = 300.0,
    vault_addr: options.VaultAddr = None,
    vault_jwt_file: options.VaultJwtFile = None,
    vault_jwt_mount: options.VaultJwtMount = "jwt",
    vault_jwt_role: options.VaultJwtRole = "router",
    vault_issue_path: options.VaultIssuePath = "apf/issue",
    bundle_pubkey_file: options.BundlePubkeyFile = None,
    trust_bundle_unverified: options.TrustBundleUnverified = False,
) -> None:
    """Run the Router as an MCP server over HTTP (add --signed for a Vault-issued bundle)."""
    settings = ServeSettings(
        bundle=bundle,
        opa_binary=opa_binary,
        audit_output=audit_output,
        host=host,
        port=port,
        signed=signed,
        trust_bundle_unverified=trust_bundle_unverified,
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
        inbound_auth=InboundAuthSettings(
            # `options.InboundKey` is `list[Path] | None`, so the empty case is None
            # rather than a mutable default in the signature.
            key_paths=tuple(inbound_key or ()),
            issuer=inbound_issuer,
            audience=inbound_audience,
        ),
    )
    raise typer.Exit(_run_serve(settings))


def _build_inbound_verifier(settings: InboundAuthSettings) -> TokenVerifier | None:
    """Build the inbound credential verifier, or None when no trust material is given.

    Raises `_InboundAuthConfigError` on anything that would leave the surface looking
    protected while not being — an unreadable or malformed key, a private key supplied by
    mistake, a partial configuration — or, in the other direction, anything that would
    silently serve unauthenticated when the operator asked for auth. Called from
    `_run_serve` before the router is built, so a misconfiguration exits non-zero having
    opened no connection and issued no bundle.
    """
    if not settings.enabled:
        return None
    from odis_harness.mcp_forwarder.inbound_auth import (  # noqa: PLC0415
        UntrustworthyKeyError,
        WorkloadJwtVerifier,
        load_public_keys,
    )

    missing = [
        name
        for name, value in (
            ("--inbound-key", settings.key_paths),
            ("--inbound-issuer", settings.issuer),
            ("--inbound-audience", settings.audience),
        )
        if not value
    ]
    if missing:
        # All three or none. Without the bindings the verifier checks the signature and
        # nothing else, so any token that key ever signed — including one minted for a
        # different service — replays here as an agent credential. Without the key there
        # is no verifier at all, and the bindings the operator did supply say plainly
        # that they expected one.
        message = (
            f"inbound auth needs {' and '.join(missing)}. Configure --inbound-key, "
            "--inbound-issuer and --inbound-audience together, or none of them: a "
            "partial configuration would serve an unauthenticated surface."
        )
        raise _InboundAuthConfigError(message)
    try:
        keys = load_public_keys(settings.key_paths)
    except UntrustworthyKeyError as exc:
        raise _InboundAuthConfigError(str(exc)) from exc
    return WorkloadJwtVerifier(
        public_keys=keys, bound_issuer=settings.issuer, bound_audience=settings.audience
    )


class _InboundAuthConfigError(ValueError):
    """Inbound-auth configuration that would not actually authenticate anyone."""


def _inbound_mode(settings: InboundAuthSettings) -> str:
    """One line for the startup banner, so an unauthenticated surface is never silent."""
    if not settings.enabled:
        return "NONE - any caller accepted, all calls attributed to the fallback agent id"
    return (
        f"workload JWT ({len(settings.key_paths)} key(s), iss={settings.issuer}, "
        f"aud={settings.audience})"
    )


#: Printed whenever inbound auth is on. `serve` speaks plain HTTP and takes no certificate
#: or key, so the bearer crosses the wire readable: anyone on-path can read it and replay
#: it until it expires. Stated at startup rather than left to the docs, because a Router
#: that authenticates looks protected and this is the assumption that makes it not.
_CLEARTEXT_BEARER_WARNING = (
    "WARNING:    serves plain HTTP — the bearer is readable and replayable by anyone "
    "on-path.\n"
    "            Terminate TLS in front of this before it leaves the loopback interface."
)
