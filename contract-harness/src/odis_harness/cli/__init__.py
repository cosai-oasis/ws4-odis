"""Local runnable entry point for the ODIS Contract Harness.

Two subcommands, both wired to the ODIS Router (the generic MCP-policy-forwarder):

- ``serve`` — runs the Router as an MCP server over HTTP. Any standard MCP
  client (Claude Code, MCP Inspector, Cursor) connects to ``http://host:port/mcp``.
  Forwards approved ``tools/call`` to the vendor MCP servers named in the loaded
  bundle's routing entries. With ``--signed`` it fetches a Vault-issued,
  offline-verified bundle (jwt-login → ``apf/issue`` → offline ed25519 verify)
  instead of loading a local file; ``--bundle`` / ``ODIS_BUNDLE`` are ignored in
  that mode.

- ``demo``  — runs the canonical Tier 3 scenarios end-to-end against an
  in-process vendor stub and prints the outcomes. Zero external infrastructure,
  though it does bind a loopback port and drive the Router over MCP, so it
  exercises the transport and inbound-auth path as well as the policy chain
  (OPA + action limits + audit).

Environment variables:

- ``ODIS_BUNDLE``     — local bundle YAML for ``demo`` / plain ``serve`` (default:
                        ``./policy/bundle.example.yaml``; ignored by ``serve --signed``)
- ``ODIS_OPA_BIN``    — path to the ``opa`` binary (default: PATH lookup)
- ``ODIS_AUDIT_OUTPUT``— ``-`` for stdout, ``stderr`` for stderr, or a file path
                        (default: ``stderr`` — keeps stdout clean).

OAuth2 vendor auth (``serve --oauth2``) adds:

Without ``--oauth2`` or ``--bridge``, downstream MCP requests still occur but use
``auth=None``; an authentication-required Target MCP fails discovery.

- ``ODIS_OAUTH2_SCOPES``        — optional space-separated scopes
- ``ODIS_OAUTH2_CLIENT_NAME``   — optional dynamic-registration client name
- ``ODIS_OAUTH2_CALLBACK_HOST`` / ``ODIS_OAUTH2_CALLBACK_PORT`` /
  ``ODIS_OAUTH2_CALLBACK_TIMEOUT`` — optional loopback callback controls

Signed mode (``serve --signed``) adds:

- ``ODIS_VAULT_ADDR``        — Vault address
- ``ODIS_VAULT_JWT_FILE``    — file holding the workload JWT presented to Vault
- ``ODIS_BUNDLE_PUBKEY_FILE``— file holding the base64 ed25519 transit public key
                               (the offline trust anchor)
- ``ODIS_VAULT_JWT_MOUNT`` / ``ODIS_VAULT_JWT_ROLE`` / ``ODIS_VAULT_ISSUE_PATH``
                               (defaults ``jwt`` / ``router`` / ``apf/issue``)

`builders` holds the Router-construction wiring and the grant/opa/bundle resolvers;
`app` holds the Typer application and `main`; `serve` and `demo` hold one command
each; `options` and `settings` hold the shared flag declarations and their resolved
shapes.
"""

from __future__ import annotations

# Imported for their `@app.command()` registration side effect, not for their names.
from odis_harness.cli import demo as _demo  # noqa: F401
from odis_harness.cli import serve as _serve  # noqa: F401
from odis_harness.cli.app import app, main
from odis_harness.cli.builders import (
    SignedBundleSource,
    build_router,
    build_router_from_bundle,
    build_router_signed,
)

__all__ = [
    "SignedBundleSource",
    "app",
    "build_router",
    "build_router_from_bundle",
    "build_router_signed",
    "main",
]
