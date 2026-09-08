"""The `demo` command: the canonical Tier-3 scenarios, end to end, zero infrastructure.

Everything demo-specific lives here — the scenarios, the MCP client that drives them, and
the self-issued credential. That separation is hygiene, not a safety boundary: what keeps
demo convenience out of the library is that the seams are required arguments and the
stand-ins live in `odis_harness.fixtures`, which the core may not import.
"""

from __future__ import annotations

import asyncio
import sys
from contextlib import ExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import typer

from odis_harness.audit.banner import print_banner

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
    reject_unverified_with_signed,
    resolve_bundle_path,
    resolve_file_verifier,
    resolve_opa_binary,
    resolve_signed_source,
    stub_context_factory,
)
from odis_harness.cli.settings import DemoSettings, SignedBundleSettings
from odis_harness.fixtures.vendor import InMemoryMcpClient
from odis_harness.mcp_forwarder.vendor_client import ToolDescriptor, ToolResult

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from mcp.server.auth.provider import TokenVerifier

    from odis_harness.audit.sink import AuditSink
    from odis_harness.cli.builders import VendorClientContext
    from odis_harness.fixtures.issuer import FixtureIdentityIssuer
    from odis_harness.mcp_forwarder.router import Router
    from odis_harness.mcp_forwarder.vendor_client import McpClient


# -- demo ---------------------------------------------------------------------

#: Identity the demo mints for itself. `.invalid` is RFC 2606 reserved, so these names
#: cannot collide with or resolve to anything routable — the same reason the envelope schema
#: `$id`s are URNs rather than a `.local` host nothing serves.
_DEMO_ISSUER = "https://issuer.demo.odis.invalid/"
_DEMO_AUDIENCE = "odis-router-demo"
_DEMO_SUBJECT = "spiffe://demo.odis.invalid/ns/demo/sa/demo-agent"


@dataclass(frozen=True, kw_only=True, slots=True)
class DemoScenario:
    """One call the demo makes, and what the gate is expected to do with it."""

    heading: str
    family: str
    tool: str
    arguments: Mapping[str, Any]
    expectation: str

    @property
    def mcp_tool_name(self) -> str:
        """The prefixed name an MCP client calls.

        Clients see `<family>.<tool>`; the bundle keys policy and action limits on the
        unprefixed `tool`. Keeping both on one object is what stops a caller pairing the
        wrong halves.
        """
        return f"{self.family}.{self.tool}"


_DEMO_SCENARIOS: tuple[DemoScenario, ...] = (
    DemoScenario(
        heading="Tier 3 allow (labels on project APF)",
        family="jira-prod",
        tool="update_issue",
        arguments={"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        expectation="expect: success",
    ),
    DemoScenario(
        heading="Tier 3 deny (issue outside project APF)",
        family="jira-prod",
        tool="update_issue",
        arguments={"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
        expectation="expect: refused=deny",
    ),
    DemoScenario(
        heading="Tier 3 obligation violation (non-label field)",
        family="jira-prod",
        tool="update_issue",
        arguments={"issue_key": "APF-1", "fields": {"summary": "leak"}},
        expectation="expect: refused=obligation_violation",
    ),
    DemoScenario(
        heading="Unpoliced tool under strict mode",
        family="jira-prod",
        tool="delete_issue",
        arguments={"issue_key": "APF-1"},
        expectation="expect: refused=unpoliced_tool",
    ),
)


def _demo_inbound_verifier(issuer: FixtureIdentityIssuer) -> TokenVerifier:
    """Trust exactly the demo's own issuer, bound to its issuer and audience.

    Both bindings are mandatory on the CLI for a reason — a verifier with only a key
    accepts any token that key ever signed — and the demo holds itself to the same bar
    rather than demonstrating a configuration `serve` would refuse to start with.
    """
    from odis_harness.mcp_forwarder.inbound_auth import WorkloadJwtVerifier  # noqa: PLC0415

    return WorkloadJwtVerifier(
        public_keys=[issuer.public_key()],
        bound_issuer=_DEMO_ISSUER,
        bound_audience=_DEMO_AUDIENCE,
    )


async def _drive_demo_scenarios(url: str, token: str) -> int:
    """Run every scenario as an MCP client would, and report what the agent sees.

    Deliberately over the wire rather than calling `Router.forward` directly: the direct
    call skips the MCP server, its handler, the discovery filter and the whole inbound-auth
    path, which is most of what an adopter actually deploys. The bearer rides on a
    preconfigured `httpx.AsyncClient` because `streamable_http_client` takes no `headers`
    argument — in a production deployment this is where an agent would attach a credential it
    fetched from a workload API.
    """
    import httpx  # noqa: PLC0415 — heavy; only the HTTP demo path needs it
    from mcp import ClientSession  # noqa: PLC0415
    from mcp.client.streamable_http import streamable_http_client  # noqa: PLC0415

    forwarded = 0
    async with (
        # `follow_redirects` matches what the SDK's own default client does, and is
        # required: the Router mounts at /mcp via a Starlette `Mount`, which 307s the
        # bare path to `/mcp/`. Worth knowing beyond this demo — an L7 policy scoped on
        # `path: /mcp` does not match the redirected `/mcp/` either.
        httpx.AsyncClient(
            headers={"Authorization": f"Bearer {token}"}, follow_redirects=True
        ) as http_client,
        streamable_http_client(url, http_client=http_client) as (read, write, _sid),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        for scenario in _DEMO_SCENARIOS:
            sys.stdout.write(f"=== {scenario.heading} ({scenario.expectation}) ===\n")
            result = await session.call_tool(scenario.mcp_tool_name, dict(scenario.arguments))
            text = " ".join(getattr(block, "text", "") for block in result.content).strip()
            if result.isError:
                sys.stdout.write(f"  {text or 'refused'}\n\n")
            else:
                forwarded += 1
                sys.stdout.write("  success: forwarded to vendor\n\n")
    sys.stdout.write(f"downstream vendor calls observed: {forwarded}\n")
    return 0


def _grant_line(settings: DemoSettings, bundle_path: Path) -> str:
    """Where the Authority Grant came from, and whether it was verified.

    In signed mode the local `--bundle` path is never opened, so naming it here would
    describe a file that has nothing to do with the policy in force.
    """
    if settings.signed:
        return (
            f"Vault-issued ({settings.signed_bundle.vault_addr}, "
            f"{settings.signed_bundle.vault_issue_path}) — ed25519 verified offline"
        )
    return grant_banner_line(
        bundle_path=bundle_path,
        trust_unverified=settings.trust_bundle_unverified,
    )


def _load_errors(*, signed: bool) -> tuple[type[Exception], ...]:
    """Grant-load failures for the mode in play.

    The signed path adds Vault transport and trust-anchor failures. They are imported
    lazily because those modules pull in httpx and the crypto stack, which the default
    file path should not pay for.
    """
    if not signed:
        return BUNDLE_LOAD_ERRORS
    from odis_harness.bundle.vault_client import VaultBundleError  # noqa: PLC0415
    from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
        NonEd25519PublicKeyError,
    )

    return (*BUNDLE_LOAD_ERRORS, VaultBundleError, NonEd25519PublicKeyError)


async def _signed_router(
    settings: DemoSettings, opa_binary: str, audit: AuditSink, wiring: RouterWiring
) -> Router:
    """Fetch a Vault-issued grant, verify its signature offline, and build the Router.

    Shares `resolve_signed_source` with `serve --signed`, so the two commands validate the
    same six options identically. `--bundle` is ignored in this mode, exactly as it is for
    `serve`.
    """
    source = resolve_signed_source(settings.signed_bundle, command="demo")
    return await build_router_signed(
        source=source, opa_binary=opa_binary, audit=audit, wiring=wiring
    )


def _run_demo(settings: DemoSettings) -> int:
    bundle_path = resolve_bundle_path(settings.bundle)
    opa_binary = resolve_opa_binary(settings.opa_binary)
    if not opa_binary:
        sys.stderr.write("ERROR: no opa binary found. Set ODIS_OPA_BIN or place 'opa' on PATH.\n")
        return 2

    async def _demo() -> int:
        with ExitStack() as stack:
            stream = audit_stream(settings.audit_output, stack)
            wiring = RouterWiring(
                context_factory=stub_context_factory(),
                vendor_client_factory=_demo_vendor_factory,
            )
            audit = build_audit(stream)
            try:
                if settings.signed:
                    reject_unverified_with_signed(
                        trust_unverified=settings.trust_bundle_unverified, command="demo"
                    )
                    router = await _signed_router(settings, opa_binary, audit, wiring)
                else:
                    # Resolved inside the branch that uses it: in signed mode the verifier
                    # comes back with the bundle, so there is nothing here to choose.
                    router = await build_router(
                        bundle_path=bundle_path,
                        opa_binary=opa_binary,
                        audit=audit,
                        signature_verifier=resolve_file_verifier(
                            bundle_pubkey_file=settings.signed_bundle.bundle_pubkey_file,
                            trust_unverified=settings.trust_bundle_unverified,
                            command="demo",
                        ),
                        wiring=wiring,
                    )
            except (GrantSourceConfigError, SignedSourceConfigError) as exc:
                sys.stderr.write(f"ERROR: {exc}\n")
                return 2
            except _load_errors(signed=settings.signed) as exc:
                # Branch on the mode, not the exception type: a signature failure can
                # arise on either path, and reporting it against `bundle_path` in signed
                # mode names a file that path never opened.
                source_desc = (
                    "the signed bundle" if settings.signed else f"the bundle {bundle_path}"
                )
                sys.stderr.write(f"ERROR: could not load {source_desc}: {exc}\n")
                return 2
            # Lazy: these pull in the MCP server/transport stack, which a bundle-load
            # failure above should not pay for.
            from odis_harness.fixtures.issuer import FixtureIdentityIssuer  # noqa: PLC0415
            from odis_harness.mcp_forwarder.server import build_mcp_server  # noqa: PLC0415
            from odis_harness.mcp_forwarder.transports import (  # noqa: PLC0415
                build_asgi_app,
                free_loopback_port,
                mcp_url,
                serving_http,
            )

            # The demo is its own issuer AND its own caller. That is not a delivery story
            # — everything here is one process — but it does exercise the verify path,
            # so the audit trail carries a subject the Router received rather than the
            # `mcp-client` constant it would otherwise assume.
            issuer = FixtureIdentityIssuer.generate(issuer=_DEMO_ISSUER, key_id="demo-key-1")
            verifier = _demo_inbound_verifier(issuer)
            app = build_asgi_app(
                build_mcp_server(router, requires_authenticated_caller=True),
                token_verifier=verifier,
            )
            port = free_loopback_port()
            url = mcp_url("127.0.0.1", port)


            print_banner(sys.stdout)
            sys.stdout.write(
                f"grant:      {_grant_line(settings, bundle_path)}\n"
                f"opa_binary: {opa_binary}\n"
                f"transport:  {url}\n"
                f"inbound:    workload JWT (fixture issuer, aud={_DEMO_AUDIENCE})\n\n"
            )
            token = issuer.mint(audience=_DEMO_AUDIENCE, subject=_DEMO_SUBJECT)
            try:
                async with serving_http(app, port=port):
                    return await _drive_demo_scenarios(url, token)
            except OSError as exc:
                # `free_loopback_port` releases the port before `serving_http` binds it, so
                # a busy machine can lose the race. Reporting it as one line beats a
                # traceback in the demo a newcomer runs first.
                sys.stderr.write(f"ERROR: could not serve the demo on port {port}: {exc}\n")
                return 2

    return asyncio.run(_demo())


@app.command()
def demo(
    bundle: options.Bundle = None,
    opa_binary: options.OpaBinary = None,
    audit_output: options.AuditOutput = "stderr",
    signed: options.Signed = False,
    vault_addr: options.VaultAddr = None,
    vault_jwt_file: options.VaultJwtFile = None,
    vault_jwt_mount: options.VaultJwtMount = "jwt",
    vault_jwt_role: options.VaultJwtRole = "router",
    vault_issue_path: options.VaultIssuePath = "apf/issue",
    bundle_pubkey_file: options.BundlePubkeyFile = None,
    trust_bundle_unverified: options.TrustBundleUnverified = False,
) -> None:
    """Run the canonical Tier 3 scenarios against an in-process vendor stub.

    `--signed` swaps the grant source for a Vault-issued bundle whose Ed25519 signature is
    verified offline, so the scenarios run against a *really* verified Authority Grant
    rather than the fixture verifier. Everything else — the Router, the gate, the MCP
    transport, the in-process vendor — is identical, which is the point: the two demos
    differ by exactly one axis.
    """
    settings = DemoSettings(
        bundle=bundle,
        opa_binary=opa_binary,
        audit_output=audit_output,
        signed=signed,
        trust_bundle_unverified=trust_bundle_unverified,
        signed_bundle=SignedBundleSettings(
            vault_addr=vault_addr,
            vault_jwt_file=vault_jwt_file,
            vault_jwt_mount=vault_jwt_mount,
            vault_jwt_role=vault_jwt_role,
            vault_issue_path=vault_issue_path,
            bundle_pubkey_file=bundle_pubkey_file,
        ),
    )
    raise typer.Exit(_run_demo(settings))


def _demo_vendor_factory(ctx: VendorClientContext) -> McpClient:
    """An in-process vendor stub seeded with the family's policed tools."""
    tools = [
        ToolDescriptor(
            name=tool,
            description=f"{tool} (demo vendor stub)",
            input_schema={"type": "object"},
        )
        for tool in ctx.family.governed_tools()
    ]

    def _respond(name: str, _arguments: dict[str, object]) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": f"vendor stub handled {name}"}])

    return InMemoryMcpClient(tools=tools, responder=_respond)
