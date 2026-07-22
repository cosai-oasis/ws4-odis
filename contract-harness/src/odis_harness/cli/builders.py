"""Router construction for the CLI.

Build a governed Router from a local bundle file (`build_router`), an
already-loaded bundle (`build_router_from_bundle`), or a Vault-issued signed
bundle (`build_router_signed`). These are the wiring helpers the CLI commands,
the tests, and the example all share.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import sys
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from odis_harness.audit.sink import AuditSink
from odis_harness.bundle import (
    BundleLoader,
    FixtureSignatureVerifier,
)
from odis_harness.contracts import AuditEvent, EnvelopeValidator
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.vendor_client import (
    InMemoryMcpClient,
    McpClient,
    SupportsSessionEstablish,
    ToolDescriptor,
    ToolResult,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from odis_harness.substrate.fixtures import (
    FixtureSponsorIdentityProvider,
    FixtureWorkloadIdentityProvider,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from contextlib import ExitStack
    from typing import TextIO

    from odis_harness.bridge import TokenExchanger
    from odis_harness.bundle import Bundle, Family
    from odis_harness.bundle.vault_client import VaultBundleClient
    from odis_harness.mcp_forwarder.oauth import OAuth2InteractiveConfig


_LOG = structlog.get_logger(__name__)


def _schemas_dir() -> Path:
    """Repo-relative schemas directory; works in development and after install."""
    candidates = [
        Path.cwd() / "schemas",
        Path(__file__).resolve().parents[3] / "schemas",
    ]
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return candidates[-1]


def build_audit(output: TextIO) -> AuditSink:
    """An AuditSink writing schema-validated JSONL events to `output`."""
    return AuditSink(output=output, validator=EnvelopeValidator(_schemas_dir()))


def resolve_opa_binary(value: str | None) -> str:
    """Resolve the opa binary: explicit value, ODIS_OPA_BIN, PATH, or a sibling
    `opa` one level above the harness directory. Returns "" when none resolves,
    so callers can fail (or SKIP) with a clear preflight message."""
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


def audit_stream(value: str, stack: ExitStack) -> TextIO:
    """The audit output stream for `value`: "-" = stdout, "stderr" = stderr, else
    a file path opened line-buffered for APPEND (never truncate: the audit trail
    is the governance artifact this harness exists to preserve) and closed via
    `stack`."""
    if value == "-":
        return sys.stdout
    if value == "stderr":
        return sys.stderr
    stream = Path(value).open("a", encoding="utf-8", buffering=1)  # noqa: SIM115 - closed via ExitStack
    stack.callback(stream.close)
    return stream


async def build_router(
    *,
    bundle_path: Path,
    opa_binary: str,
    audit: AuditSink,
    vendor_client_factory: Callable[[Family], McpClient],
) -> Router:
    """Load the signed bundle from a file, then build the Router (fixture verifier)."""
    loader = BundleLoader(signature_verifier=FixtureSignatureVerifier())
    bundle = loader.load(bundle_path)
    return await build_router_from_bundle(
        bundle=bundle,
        opa_binary=opa_binary,
        audit=audit,
        vendor_client_factory=vendor_client_factory,
    )


async def build_router_from_bundle(
    *,
    bundle: Bundle,
    opa_binary: str,
    audit: AuditSink,
    vendor_client_factory: Callable[[Family], McpClient],
) -> Router:
    """Build a vendor client per family, populate discovery, and construct the
    Router from an already-loaded `Bundle` — independent of the bundle's source
    (a file via `build_router`, or a Vault-issued bundle via `load_signed`)."""
    clients: dict[str, McpClient] = {
        name: vendor_client_factory(family) for name, family in bundle.families_iter()
    }
    await establish_leg2_sessions(clients)
    discovery = DiscoveryCache()
    await discovery.populate(
        bundle,
        clients=clients,
        on_discovery_failed=_make_discovery_failed_cb(audit, bundle),
    )
    return Router(
        bundle=bundle,
        policy_evaluator=PolicyEvaluator(opa_binary=opa_binary),
        context_factory=RuntimeContextFactory(
            workload_identity=FixtureWorkloadIdentityProvider(),
            sponsor_provider=FixtureSponsorIdentityProvider(),
        ),
        audit=audit,
        vendor_clients=clients,
        discovery=discovery,
    )


async def establish_leg2_sessions(clients: Mapping[str, McpClient]) -> None:
    """Named boot phase (DL-2 / REQ-9.8): eagerly prime each bridged vendor's leg-2
    session after loading the bundle and before discovery — so the later `tools/list`
    reuses the primed token (one handshake per vendor). Establishes concurrently
    (`asyncio.gather`), mirroring discovery's fan-out.

    Resilient + fail-closed: a client that fails to establish is logged and that
    family is degraded (never crashes boot — mirrors discovery's `discovery_failed`
    path); its later calls fail closed when the broker stays down. Only a client that
    carries a `BridgeAuth` actually establishes and returns an audience; a client with
    no bridge auth (`auth=None`, no `--bridge`, or `InMemoryMcpClient`) returns `None`
    and is NOT logged as established, so the demo / plain-`serve` path emits no
    `bridge.leg2.established` event. The skip/no-log predicate is auth presence (a
    `BridgeAuth`), not method presence. Observability is `structlog` only — no audit
    `event_type` (avoid taxonomy churn). The bearer and subject token are never logged;
    the established audience is non-secret.
    """
    await asyncio.gather(
        *(
            _establish_one(name, client)
            for name, client in clients.items()
            if isinstance(client, SupportsSessionEstablish)
        )
    )


async def _establish_one(name: str, client: SupportsSessionEstablish) -> None:
    """Establish one family's leg-2 session, isolated and fail-closed.

    Logs `bridge.leg2.established` only when `establish()` returns an audience (a
    token was actually minted); a client with no bridge auth returns `None` and is
    silent. A failure degrades just this family (peers, run concurrently, are
    unaffected) and is logged — never re-raised.
    """
    try:
        audience = await client.establish()
    except Exception:  # noqa: BLE001 - boot-phase boundary: fail closed + logged, one broker outage must not crash the Router
        # Degrade this one family, keep booting. Exception text is not echoed
        # to audit; the family's later calls fail closed if the broker stays down.
        _LOG.exception("bridge.leg2.establish_failed", family=name, degraded=True)
        return
    if audience is not None:
        _LOG.info("bridge.leg2.established", family=name, audience=audience)


def _make_discovery_failed_cb(audit: AuditSink, bundle: Bundle) -> Callable[[str, Exception], None]:
    def _cb(family_name: str, error: Exception) -> None:
        del error  # not echoed into audit (could carry vendor detail)
        audit.emit(
            AuditEvent(
                correlation_id=str(uuid.uuid4()),
                event_id=str(uuid.uuid4()),
                timestamp=datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                event_type="odis.mcp.discovery_failed",
                policy_digest=bundle.policy_digest,
                resource_family=family_name,
                reason_code="vendor_unreachable",
            )
        )

    return _cb


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedBundleSource:
    """A signed bundle's origin for `build_router_signed`: the Vault client, the
    caller's workload JWT, and the out-of-band ed25519 trust-anchor public key
    (base64). `workload_jwt` is a credential, so it is kept out of reprs.
    """

    client: VaultBundleClient
    workload_jwt: str = field(repr=False)
    bundle_pubkey_b64: str


async def build_router_signed(
    *,
    source: SignedBundleSource,
    opa_binary: str,
    audit: AuditSink,
    vendor_client_factory: Callable[[Family], McpClient],
) -> Router:
    """Fetch a Vault-issued signed bundle, verify it OFFLINE, then build the Router.

    The signed counterpart to `build_router`: `source.client` does the mint-then-load
    handshake (jwt-login → `apf/issue`); the ed25519 signature is verified offline
    against `source.bundle_pubkey_b64` (a non-secret trust anchor supplied out of
    band — so no Vault capability beyond `apf/issue` is needed); the verified bundle
    then feeds the shared `build_router_from_bundle` sink. The Router presents only
    the workload JWT to Vault (Secret-Zero).

    Raises `VaultBundleError` (fetch), `NonEd25519PublicKeyError` (a malformed
    trust-anchor pubkey), or `BundleSignatureInvalid` / `BundleSchemaInvalid`
    (verify/parse); the caller fails closed.
    """
    # Lazy: keep the vault/crypto stack off the demo + local-serve import path.
    from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
        VaultTransitSignatureVerifier,
    )

    signed = await source.client.fetch_signed_bundle(workload_jwt=source.workload_jwt)
    verifier = VaultTransitSignatureVerifier.from_transit_ed25519(
        key_name=signed.key_name,
        public_keys_b64={signed.key_version: source.bundle_pubkey_b64},
    )
    bundle = BundleLoader(signature_verifier=verifier).load_signed(signed.payload, signed.signature)
    return await build_router_from_bundle(
        bundle=bundle,
        opa_binary=opa_binary,
        audit=audit,
        vendor_client_factory=vendor_client_factory,
    )


def http_vendor_factory(family: Family) -> McpClient:
    # No Router→vendor credential in the harness (Secret-Zero): `auth`
    # stays None. Production constructs a short-lived, audience-scoped provider here
    # — for live smoke tests, the SDK OAuth authorization-code/PKCE provider;
    # for production, Bridge-backed token exchange — never a static token.
    return HttpMcpClient(url=family.vendor_mcp.url)


def _vendor_audience(family: Family) -> str:
    """The leg-2 token audience for `family` (RFC 8707 Resource Indicator).

    The vendor MCP's `endpoint_id` is its stable canonical identity; it is required
    and validated non-empty, so it is the audience directly.
    """
    return family.vendor_mcp.endpoint_id


def make_oauth2_http_vendor_factory(
    config: OAuth2InteractiveConfig,
) -> Callable[[Family], McpClient]:
    """Build a vendor factory using interactive OAuth2 authorization-code/PKCE.

    No caller-supplied bearer or pre-provisioned client secret is accepted: the
    SDK OAuth provider performs dynamic client registration and obtains access
    tokens from the authorization server.
    """
    from odis_harness.mcp_forwarder.oauth import (  # noqa: PLC0415
        InMemoryOAuthTokenStorage,
        make_interactive_oauth2_auth,
    )

    def _factory(family: Family) -> McpClient:
        return HttpMcpClient(
            url=family.vendor_mcp.url,
            auth=make_interactive_oauth2_auth(
                server_url=family.vendor_mcp.url,
                storage=InMemoryOAuthTokenStorage(),
                config=config,
            ),
        )

    return _factory


def make_bridged_http_vendor_factory(
    *,
    exchanger: TokenExchanger,
    subject_token_provider: Callable[[], str],
) -> Callable[[Family], McpClient]:
    """Build a vendor factory whose `HttpMcpClient`s carry a `BridgeAuth` leg-2 auth.

    Each client gets a `BridgeAuth` that exchanges the agent's workload identity (via
    `subject_token_provider`) for a token scoped to that family's vendor audience
    (`endpoint_id` or URL, RFC 8707). The agent's inbound token is never passed through;
    the leg-2 bearer is short-lived, audience-scoped, hydrated at runtime, and re-minted on
    expiry by `BridgeAuth`. `subject_token_provider` and `exchanger` are captured once and
    shared across families.
    """
    # Lazy: keep the Bridge off the demo / plain-serve import path (parallels the
    # vault verifier in build_router_signed).
    from odis_harness.bridge import BridgeAuth  # noqa: PLC0415

    def _factory(family: Family) -> McpClient:
        return HttpMcpClient(
            url=family.vendor_mcp.url,
            auth=BridgeAuth(
                subject_token_provider=subject_token_provider,
                audience=_vendor_audience(family),
                exchanger=exchanger,
            ),
        )

    return _factory


def make_fixture_bridged_http_vendor_factory() -> Callable[[Family], McpClient]:
    """A bridged vendor factory wired with the fixture Bridge (the `--bridge` default).

    Stands up a `FixtureTokenExchanger` (the in-process RFC 7523/8693 broker stand-in)
    plus a Passport stand-in (`fixture_subject_token_provider`) minting a fresh agent
    workload JWT per exchange. No network, no static bearer; the real broker is the
    production `TokenExchanger` implementation.
    """
    # Lazy: the Bridge + fixture issuer are only needed on the opt-in `--bridge` path.
    from odis_harness.bridge import (  # noqa: PLC0415
        FixtureTokenExchanger,
        fixture_subject_token_provider,
    )
    from odis_harness.vault.fixtures import FixtureIdentityIssuer  # noqa: PLC0415

    agent_issuer = FixtureIdentityIssuer.generate(
        issuer="https://fixture.passport.odis.local/", key_id="fixture-agent-key-1"
    )
    subject_token_provider = fixture_subject_token_provider(
        agent_issuer,
        subject="spiffe://fixture.odis.local/agent/mcp-client",
        audience="https://fixture.bridge.odis.local/",
    )
    return make_bridged_http_vendor_factory(
        exchanger=FixtureTokenExchanger(),
        subject_token_provider=subject_token_provider,
    )


def _demo_vendor_factory(family: Family) -> McpClient:
    """An in-process vendor stub seeded with the family's policed tools."""
    tools = [
        ToolDescriptor(
            name=tool,
            description=f"{tool} (demo vendor stub)",
            input_schema={"type": "object"},
        )
        for tool in family.governed_tools()
    ]

    def _respond(name: str, _arguments: dict[str, object]) -> ToolResult:
        return ToolResult(content=[{"type": "text", "text": f"vendor stub handled {name}"}])

    return InMemoryMcpClient(tools=tools, responder=_respond)


__all__ = [
    "SignedBundleSource",
    "audit_stream",
    "build_audit",
    "build_router",
    "build_router_from_bundle",
    "build_router_signed",
    "establish_leg2_sessions",
    "http_vendor_factory",
    "make_bridged_http_vendor_factory",
    "make_fixture_bridged_http_vendor_factory",
    "make_oauth2_http_vendor_factory",
    "resolve_opa_binary",
]
