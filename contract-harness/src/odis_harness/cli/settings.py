"""Resolved CLI settings.

One frozen dataclass per group of related options. The Typer command functions do nothing
but collect flags into these and hand them to a `_run_*` function, so every decision below
the CLI reads a settings object rather than a pile of positional arguments — and the run
logic is callable from a test without going through Typer at all.

Option *declarations* live in `cli.options`; this module is only the resolved shape.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # Type-only: `from __future__ import annotations` makes these dataclass field
    # annotations strings, and nothing here evaluates them at runtime. Contrast
    # `cli/options.py`, where `Path` is a runtime subscript inside `Annotated`
    # and Typer resolves it — there it must stay a runtime import.
    from pathlib import Path


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedBundleSettings:
    """Where a Vault-issued Authority Grant comes from, and how to verify it."""

    vault_addr: str | None
    vault_jwt_file: str | None
    vault_jwt_mount: str
    vault_jwt_role: str
    vault_issue_path: str
    bundle_pubkey_file: str | None


@dataclass(frozen=True, kw_only=True, slots=True)
class DemoSettings:
    bundle: str | None
    opa_binary: str | None
    audit_output: str
    signed: bool
    #: Only read when `signed` is true; `demo` and `serve` take the same six `--vault-*`
    #: options with the same env vars, so the shape is shared rather than re-modelled.
    #: Required, matching `ServeSettings` — the command always builds one, and an Optional
    #: here only buys unreachable guards.
    signed_bundle: SignedBundleSettings
    #: Explicitly accept a local grant whose signature is not checked.
    trust_bundle_unverified: bool = False


@dataclass(frozen=True, kw_only=True, slots=True)
class VendorAuthSettings:
    """How the Router authenticates to the Target MCP — the leg-2 posture."""

    bridge: bool
    oauth2: bool
    oauth2_scopes: str | None
    oauth2_client_name: str
    oauth2_callback_host: str
    oauth2_callback_port: int | None
    oauth2_callback_timeout: float


@dataclass(frozen=True, kw_only=True, slots=True)
class InboundAuthSettings:
    """Trust material for validating the agent's credential on the way in.

    With no keys the MCP surface accepts any caller and every call is attributed to the
    fallback agent id, so `serve` says so at startup rather than leaving it implicit.
    """

    key_paths: tuple[Path, ...] = ()
    issuer: str = ""
    audience: str = ""

    @property
    def enabled(self) -> bool:
        """True when the operator asked for inbound auth in any way at all.

        Any one of the three settings counts, not just the key. Keying this on the key
        alone made the validation one-directional: a bad key path exited 2, but a
        *missing* one — issuer and audience set, `ODIS_INBOUND_KEYS` unset because a
        secret mount had not attached yet — silently served an unauthenticated surface
        and exited 0. A partial configuration is now a startup failure, never a downgrade.
        """
        return bool(self.key_paths or self.issuer or self.audience)


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
    inbound_auth: InboundAuthSettings
    #: Explicitly accept a local grant whose signature is not checked.
    trust_bundle_unverified: bool = False


__all__ = [
    "DemoSettings",
    "InboundAuthSettings",
    "ServeSettings",
    "SignedBundleSettings",
    "VendorAuthSettings",
]
