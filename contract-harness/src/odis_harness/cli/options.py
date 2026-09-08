"""Reusable Typer option declarations.

One `Annotated` alias per option, so a flag is declared once and used by every command that
takes it. Two reasons this is not just tidiness:

- `demo` and `serve` share the bundle/opa/audit options and the whole `--signed` Vault
  group. Declared inline, those are verbatim duplicates whose help text and env var names
  drift independently — and adding `--signed` to `demo` would have duplicated seven more.
- Declared inline, `serve`'s signature ran to roughly 148 lines, which is most of why the
  command module was unreadable.

The default value belongs in the command signature, not in the `typer.Option(...)` here —
that is how Typer's `Annotated` form works, and it lets two commands share a declaration
while differing on the default if they ever need to.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Annotated

import typer

_BUNDLE_HELP = (
    "path to the Authority Grant (signed bundle) YAML "
    "(default: $ODIS_BUNDLE or ./policy/bundle.example.yaml)"
)
_OPA_HELP = "opa binary path (default: $ODIS_OPA_BIN or PATH lookup)"
_AUDIT_HELP = "'-' for stdout, 'stderr' for stderr, or a file path"
_INBOUND_KEY_HELP = (
    "PEM public key that signs agent credentials; repeatable. Supplying at least "
    "one turns on inbound authentication: callers must present a valid workload "
    "JWT and the agent identity comes from its subject, and --inbound-issuer "
    "and --inbound-audience become required. Without it the MCP surface accepts "
    f"any caller. Several paths in the env var are separated by {os.pathsep!r}"
)

# -- shared by demo and serve -------------------------------------------------

Bundle = Annotated[str | None, typer.Option(envvar="ODIS_BUNDLE", help=_BUNDLE_HELP)]
OpaBinary = Annotated[str | None, typer.Option(help=_OPA_HELP)]
AuditOutput = Annotated[str, typer.Option(envvar="ODIS_AUDIT_OUTPUT", help=_AUDIT_HELP)]

Signed = Annotated[
    bool,
    typer.Option(
        "--signed",
        help=(
            "load a Vault-issued signed bundle (offline-verified) instead of a local file; "
            "--bundle and ODIS_BUNDLE are ignored"
        ),
    ),
]
TrustBundleUnverified = Annotated[
    bool,
    typer.Option(
        "--trust-bundle-unverified",
        help=(
            "load a local --bundle WITHOUT verifying its signature. Required to make that "
            "choice explicit: the alternative verifiers are --signed (Vault-issued) or "
            "--bundle-pubkey-file (a sibling <bundle>.sig against a local trust anchor)"
        ),
    ),
]
VaultAddr = Annotated[
    str | None, typer.Option(envvar="ODIS_VAULT_ADDR", help="Vault address for --signed")
]
VaultJwtFile = Annotated[
    str | None,
    typer.Option(
        envvar="ODIS_VAULT_JWT_FILE",
        help="file holding the workload JWT presented to Vault for --signed",
    ),
]
VaultJwtMount = Annotated[
    str, typer.Option(envvar="ODIS_VAULT_JWT_MOUNT", help="Vault JWT auth mount for --signed")
]
VaultJwtRole = Annotated[
    str, typer.Option(envvar="ODIS_VAULT_JWT_ROLE", help="Vault JWT auth role for --signed")
]
VaultIssuePath = Annotated[
    str, typer.Option(envvar="ODIS_VAULT_ISSUE_PATH", help="plugin issue path for --signed")
]
BundlePubkeyFile = Annotated[
    str | None,
    typer.Option(
        envvar="ODIS_BUNDLE_PUBKEY_FILE",
        help=(
            "base64 ed25519 transit public-key file — the offline trust anchor. With "
            "--signed it verifies the Vault-issued grant; on a local --bundle it verifies "
            "a sibling <bundle>.sig, which must hold a Vault transit signature "
            "(vault:v<N>:<base64>)"
        ),
    ),
]

# -- serve only ---------------------------------------------------------------

Host = Annotated[str, typer.Option(help="bind host")]
Port = Annotated[int, typer.Option(help="bind port")]

#: `| None` rather than a `[]` default: with the `Annotated` form the default moves into the
#: signature, and a literal `[]` there is a mutable default argument. Callers coerce with
#: `tuple(inbound_key or ())`.
InboundKey = Annotated[
    list[Path] | None,
    typer.Option("--inbound-key", envvar="ODIS_INBOUND_KEYS", help=_INBOUND_KEY_HELP),
]
InboundIssuer = Annotated[
    str,
    typer.Option(
        "--inbound-issuer",
        envvar="ODIS_INBOUND_ISSUER",
        help="required `iss` on agent credentials; mandatory with --inbound-key",
    ),
]
InboundAudience = Annotated[
    str,
    typer.Option(
        "--inbound-audience",
        envvar="ODIS_INBOUND_AUDIENCE",
        help=(
            "required `aud` on agent credentials — this Router's own identifier; "
            "mandatory with --inbound-key"
        ),
    ),
]

Bridge = Annotated[
    bool,
    typer.Option(
        "--bridge",
        help=(
            "wire the ODIS Bridge for leg-2 auth: present a short-lived, audience-scoped "
            "bearer per vendor (fixture token-exchange); mutually exclusive with --oauth2. "
            "Default: auth=None (Secret-Zero)"
        ),
    ),
]
OAuth2 = Annotated[
    bool,
    typer.Option(
        "--oauth2",
        envvar="ODIS_OAUTH2",
        help=(
            "use OAuth2 authorization-code/PKCE with dynamic client registration "
            "for Router-to-vendor auth; mutually exclusive with --bridge. Without either "
            "auth option, downstream requests use auth=None"
        ),
    ),
]
OAuth2Scopes = Annotated[
    str | None,
    typer.Option(
        "--oauth2-scopes", envvar="ODIS_OAUTH2_SCOPES", help="space-separated OAuth2 scopes"
    ),
]
OAuth2ClientName = Annotated[
    str,
    typer.Option(
        "--oauth2-client-name",
        envvar="ODIS_OAUTH2_CLIENT_NAME",
        help="OAuth2 dynamic-registration client name",
    ),
]
OAuth2CallbackHost = Annotated[
    str,
    typer.Option(
        "--oauth2-callback-host",
        envvar="ODIS_OAUTH2_CALLBACK_HOST",
        help="OAuth2 loopback callback bind host",
    ),
]
OAuth2CallbackPort = Annotated[
    int | None,
    typer.Option(
        "--oauth2-callback-port",
        envvar="ODIS_OAUTH2_CALLBACK_PORT",
        help="OAuth2 loopback callback port (default: random available port)",
    ),
]
OAuth2CallbackTimeout = Annotated[
    float,
    typer.Option(
        "--oauth2-callback-timeout",
        envvar="ODIS_OAUTH2_CALLBACK_TIMEOUT",
        help="seconds to wait for OAuth2 callback",
    ),
]

__all__ = [
    "AuditOutput",
    "Bridge",
    "Bundle",
    "BundlePubkeyFile",
    "Host",
    "InboundAudience",
    "InboundIssuer",
    "InboundKey",
    "OAuth2",
    "OAuth2CallbackHost",
    "OAuth2CallbackPort",
    "OAuth2CallbackTimeout",
    "OAuth2ClientName",
    "OAuth2Scopes",
    "OpaBinary",
    "Port",
    "Signed",
    "TrustBundleUnverified",
    "VaultAddr",
    "VaultIssuePath",
    "VaultJwtFile",
    "VaultJwtMount",
    "VaultJwtRole",
]
