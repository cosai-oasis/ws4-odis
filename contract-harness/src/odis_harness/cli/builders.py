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
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from odis_harness.audit.sink import AuditSink
from odis_harness.bundle import (
    BundleLoader,
)
from odis_harness.bundle.loader import (
    BundleExpired,
    BundleSchemaInvalid,
    BundleSignatureInvalid,
)
from odis_harness.contracts import EnvelopeValidator
from odis_harness.fixtures.identity import (
    FixtureOriginatingPrincipalProvider,
    FixtureWorkloadIdentityProvider,
)
from odis_harness.mcp_forwarder.audit import audit_discovery_failed
from odis_harness.mcp_forwarder.discovery import DiscoveryCache
from odis_harness.mcp_forwarder.identity import RuntimeContextFactory
from odis_harness.mcp_forwarder.policy import PolicyEvaluator
from odis_harness.mcp_forwarder.router import Router
from odis_harness.mcp_forwarder.vendor_client import (
    McpClient,
    SupportsSessionEstablish,
)
from odis_harness.mcp_forwarder.vendor_http import HttpMcpClient
from odis_harness.paths import default_schemas_dir

if TYPE_CHECKING:
    from collections.abc import Mapping
    from contextlib import ExitStack
    from typing import TextIO

    from odis_harness.bridge import TokenExchanger
    from odis_harness.bridge.audit import ExchangeAuditAnchor
    from odis_harness.bundle import Bundle, Family, SignatureVerifier
    from odis_harness.bundle.vault_client import VaultBundleClient
    from odis_harness.cli.settings import SignedBundleSettings
    from odis_harness.mcp_forwarder.oauth import OAuth2InteractiveConfig


_LOG = structlog.get_logger(__name__)


def build_audit(output: TextIO) -> AuditSink:
    """An AuditSink writing schema-validated JSONL events to `output`."""
    return AuditSink(output=output, validator=EnvelopeValidator(default_schemas_dir()))


#: Bundle-load failures the `demo`/`serve` paths turn into a clean, fail-closed one-line
#: error + exit 2 (mirroring `serve --signed`) instead of an unhandled traceback.
#: `FileNotFoundError` is an `OSError` subclass.
BUNDLE_LOAD_ERRORS = (OSError, BundleSchemaInvalid, BundleSignatureInvalid)


class GrantSourceConfigError(ValueError):
    """A grant configuration that does not say how the Authority Grant is trusted."""


#: The transit key name and version a local `<bundle>.sig` is verified under. The name is
#: only a cache label — the `vault:vN:` envelope carries the version but not the name. The
#: version is not: a `vault:v2:` signature was made by a different key, so an anchor
#: exported from v1 cannot verify it and the operator must export the matching one.
_LOCAL_SIG_VERSION = 1
_LOCAL_SIG_KEY_NAME = "apf-bundle"

def grant_banner_line(*, bundle_path: Path, trust_unverified: bool) -> str:
    """The banner's account of where a local grant came from and whether it was checked.

    Beside `resolve_file_verifier`, which makes the choice this describes: the two must
    agree, and the strings are asserted by tests, so a copy per command is a copy that can
    drift into saying something false about the trust posture. Two branches, not three —
    `resolve_file_verifier` refuses before any banner prints, so "neither" never reaches
    here.
    """
    if trust_unverified:
        return f"{bundle_path}  SIGNATURE NOT VERIFIED (--trust-bundle-unverified)"
    return f"{bundle_path}  ed25519 verified against the supplied trust anchor"


def reject_unverified_with_signed(*, trust_unverified: bool, command: str) -> None:
    """`--signed` and `--trust-bundle-unverified` together are a contradiction.

    The stricter option would win, so this changes no outcome — but silently ignoring a
    flag that asks to skip verification is the wrong shape for a security option. It
    mirrors the `--bundle-pubkey-file` + `--trust-bundle-unverified` rejection.
    """
    if trust_unverified:
        message = (
            f"{command}: --trust-bundle-unverified has no meaning with --signed, which "
            "always verifies the issued grant. Drop one."
        )
        raise GrantSourceConfigError(message)


def resolve_file_verifier(
    *, bundle_pubkey_file: str | None, trust_unverified: bool, command: str
) -> SignatureVerifier:
    """Pick the verifier for a local `--bundle`, or refuse to guess.

    Exactly one of the two must be chosen; there is no default, because a default here is
    an unverified grant nobody decided to accept. Demanding the choice is meaningful rather
    than ceremony because an alternative exists: `VaultTransitSignatureVerifier`.

    `bundle_pubkey_file` verifies the sibling `<bundle>.sig` that `BundleLoader.load`
    resolves. That signature must be in Vault transit form (`vault:v<N>:<base64>`) — the
    verifier parses that framing and fails closed on anything else, so a bare Ed25519
    signature does not verify. Version 1 and key name `apf-bundle` match what the
    `apf-bundle-issuer` plugin emits.
    """
    if bundle_pubkey_file and trust_unverified:
        message = (
            f"{command}: --bundle-pubkey-file and --trust-bundle-unverified are mutually "
            "exclusive; pick whether the grant's signature is checked."
        )
        raise GrantSourceConfigError(message)
    if bundle_pubkey_file:
        from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
            VaultTransitSignatureVerifier,
        )

        try:
            key_b64 = Path(bundle_pubkey_file).read_text(encoding="ascii").strip()
        except (OSError, UnicodeDecodeError) as exc:
            # Both, and here rather than at each call site: a trust anchor that is missing
            # and one that is not ASCII are the same operator error, and a `UnicodeDecodeError`
            # is not an `OSError`, so a caller catching only the latter leaks a traceback.
            message = f"cannot read --bundle-pubkey-file {bundle_pubkey_file!r}: {exc}"
            raise GrantSourceConfigError(message) from exc
        from odis_harness.bundle.vault_verifier import (  # noqa: PLC0415
            NonEd25519PublicKeyError,
        )

        try:
            return VaultTransitSignatureVerifier.from_transit_ed25519(
                key_name=_LOCAL_SIG_KEY_NAME,
                public_keys_b64={_LOCAL_SIG_VERSION: key_b64},
            )
        except NonEd25519PublicKeyError as exc:
            message = f"--bundle-pubkey-file {bundle_pubkey_file!r} is not an ed25519 key: {exc}"
            raise GrantSourceConfigError(message) from exc
    if trust_unverified:
        from odis_harness.fixtures.signature import (  # noqa: PLC0415
            FixtureSignatureVerifier,
        )

        return FixtureSignatureVerifier()
    message = (
        f"{command} needs to say how the grant is trusted: --signed (Vault-issued), "
        "--bundle-pubkey-file (verify a sibling <bundle>.sig), or "
        "--trust-bundle-unverified (explicitly accept an unverified grant)."
    )
    raise GrantSourceConfigError(message)


class SignedSourceConfigError(ValueError):
    """Vault configuration that cannot produce a signed Authority Grant."""


def resolve_signed_source(signed: SignedBundleSettings, *, command: str) -> SignedBundleSource:
    """Build a `SignedBundleSource` from the `--vault-*` settings, or fail closed.

    Shared by `serve --signed` and `demo --signed` rather than duplicated: the two take the
    same six options with the same env vars, and a validation rule that held in one command
    and not the other would be worse than no validation at all.

    Raises `SignedSourceConfigError` with an operator-readable message; callers turn that
    into exit 2. Mirrors `InboundAuthConfigError` in `cli.serve`.
    """
    required = {
        "--vault-addr": signed.vault_addr,
        "--vault-jwt-file": signed.vault_jwt_file,
        "--bundle-pubkey-file": signed.bundle_pubkey_file,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        message = (
            f"{command} --signed requires "
            + ", ".join(missing)
            + " (or the matching ODIS_* env vars)."
        )
        raise SignedSourceConfigError(message)
    # Narrowing for the type checker; `missing` above already guarantees all three.
    if (
        signed.vault_addr is None
        or signed.vault_jwt_file is None
        or signed.bundle_pubkey_file is None
    ):  # pragma: no cover - unreachable given the check above
        message = f"{command} --signed received incomplete Vault configuration."
        raise SignedSourceConfigError(message)
    try:
        workload_jwt = Path(signed.vault_jwt_file).read_text(encoding="ascii").strip()
        bundle_pubkey_b64 = Path(signed.bundle_pubkey_file).read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        message = f"cannot read signed-mode input file: {exc}"
        raise SignedSourceConfigError(message) from exc

    # Lazy: the vault path is a distinct capability; keep its types off the local import.
    from odis_harness.bundle.vault_client import VaultBundleClient  # noqa: PLC0415

    return SignedBundleSource(
        client=VaultBundleClient(
            vault_addr=signed.vault_addr,
            jwt_login_mount=signed.vault_jwt_mount,
            jwt_login_role=signed.vault_jwt_role,
            issue_path=signed.vault_issue_path,
        ),
        workload_jwt=workload_jwt,
        bundle_pubkey_b64=bundle_pubkey_b64,
    )


def resolve_bundle_path(value: str | None) -> Path:
    """The Authority Grant path: explicit flag, else the shipped example under `cwd`.

    Shared by `demo` and `serve` — both take `--bundle` with the same meaning, and the
    default has to agree between them or the two commands read different policy.
    """
    if value:
        return Path(value).resolve()
    return (Path.cwd() / "policy" / "bundle.example.yaml").resolve()


def resolve_opa_binary(value: str | None) -> str:
    """Resolve the opa binary: explicit value, ODIS_OPA_BIN, PATH, or a sibling
    `opa` one level above the harness directory. Returns "" when none resolves,
    so callers can fail (or SKIP) with a clear preflight message.

    Every candidate must be an executable file to be accepted. A stale or typo'd
    `ODIS_OPA_BIN` therefore falls through to PATH instead of being handed back: the
    alternative is worse than a clean "not found", because `PolicyEvaluator` fails
    closed on a broken binary, so every policy decision silently becomes `deny`.
    """
    candidates = [
        value,
        os.environ.get("ODIS_OPA_BIN"),
        shutil.which("opa"),
        str(Path(__file__).resolve().parents[4] / "opa"),
    ]
    for candidate in candidates:
        if not candidate:
            continue
        path = Path(candidate)
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
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


@dataclass(frozen=True, kw_only=True, slots=True)
class VendorClientContext:
    """Everything a vendor factory needs that the family alone does not carry.

    A plain `HttpMcpClient` needs only its `Family`. A factory that anchors the
    credential it mints (ODIS-CC-06) also needs the grant in force and the sink to
    record against, and those are known only to `build_router_from_bundle`: the
    factory itself is built from CLI settings before any bundle is loaded. Passing
    them as one frozen argument keeps that ordering honest — a client cannot be
    constructed without the context, so it cannot mint before the grant is in force.
    """

    family_name: str
    family: Family
    bundle: Bundle
    audit: AuditSink


#: What `RouterWiring.vendor_client_factory` is. Named because it appears in the
#: wiring type, in every `make_*_vendor_factory` return type, and in the test
#: doubles, and a change to the context should have one place to land.
VendorClientFactory = Callable[[VendorClientContext], McpClient]


@dataclass(frozen=True, kw_only=True, slots=True)
class RouterWiring:
    """The two boundaries the Router needs that an Authority Grant does not supply.

    Grouped, and required, on purpose. The harness's central claim is that every external
    boundary is a constructor-injected Protocol, so swapping a fixture for a production
    implementation never touches the Router. Required rather than defaulted, so a caller
    has to say what it is wiring and a stub cannot arrive unannounced.

    `signature_verifier` is deliberately NOT here:
    it is a *loader* concern, chosen only on the file path, and `build_router_signed`
    derives its own from the signing metadata that comes back with the bundle.
    """

    context_factory: RuntimeContextFactory
    vendor_client_factory: VendorClientFactory


def stub_context_factory() -> RuntimeContextFactory:
    """The non-production identity providers the CLI wires when no Passport is configured.

    Named `stub`, not `fixture`, and supplied explicitly rather than defaulted: no production
    `WorkloadIdentityProvider` or `OriginatingPrincipalProvider` ships, so requiring an
    operator to choose one would be a box everyone ticks. The honesty lives elsewhere
    instead — the startup banner names these, and `agent.type` records
    `fixture_workload_identity` on every audited call, so a stub cannot pass for a
    verified identity in the trail.
    """
    return RuntimeContextFactory(
        workload_identity=FixtureWorkloadIdentityProvider(),
        principal_provider=FixtureOriginatingPrincipalProvider(),
    )


async def build_router(
    *,
    bundle_path: Path,
    opa_binary: str,
    audit: AuditSink,
    signature_verifier: SignatureVerifier,
    wiring: RouterWiring,
) -> Router:
    """Load an Authority Grant from a file, verify it, then build the Router.

    `signature_verifier` is required and has no default: the caller names what it trusts.
    """
    loader = BundleLoader(signature_verifier=signature_verifier)
    bundle = loader.load(bundle_path)
    return await build_router_from_bundle(
        bundle=bundle,
        opa_binary=opa_binary,
        audit=audit,
        wiring=wiring,
    )


async def build_router_from_bundle(
    *,
    bundle: Bundle,
    opa_binary: str,
    audit: AuditSink,
    wiring: RouterWiring,
) -> Router:
    """Build a vendor client per family, populate discovery, and construct the
    Router from an already-loaded `Bundle` — independent of the bundle's source
    (a file via `build_router`, or a Vault-issued bundle via `load_signed`)."""
    # Before any client is built: a factory on a minting posture performs an RFC 8693
    # exchange during `establish_leg2_sessions`, so an expired grant would mint and cache
    # a live bearer — and anchor it against a grant that confers nothing — before the
    # first forward could refuse. The Router re-checks per call; this is the boot half.
    if bundle.expired():
        message = "Authority Grant has expired; it confers nothing"
        raise BundleExpired(message)

    clients: dict[str, McpClient] = {
        name: wiring.vendor_client_factory(
            VendorClientContext(
                family_name=name, family=family, bundle=bundle, audit=audit
            )
        )
        for name, family in bundle.families_iter()
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
        context_factory=wiring.context_factory,
        audit=audit,
        vendor_clients=clients,
        discovery=discovery,
    )


async def establish_leg2_sessions(clients: Mapping[str, McpClient]) -> None:
    """Named boot phase: prime each bridged vendor's leg-2 session.

    Runs after the bundle loads and before discovery, so discovery's own `tools/list`
    reuses the primed token — one handshake per vendor. Establishes concurrently
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
        audit_discovery_failed(audit, bundle=bundle, family_name=family_name)

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
    wiring: RouterWiring,
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
        wiring=wiring,
    )


def http_vendor_factory(ctx: VendorClientContext) -> McpClient:
    # No Router→vendor credential in the harness (Secret-Zero): `auth`
    # stays None. Production constructs a short-lived, audience-scoped provider here
    # — for live smoke tests, the SDK OAuth authorization-code/PKCE provider;
    # for production, Bridge-backed token exchange — never a static token.
    return HttpMcpClient(url=ctx.family.vendor_mcp.url)


def _anchor_for(ctx: VendorClientContext) -> ExchangeAuditAnchor:
    """The ODIS-CC-06 audit anchor for one target.

    One anchor per family: the record names the target it was minted for. The
    whole `Bundle` goes in rather than the four fields it stamps, so the record
    cannot disagree with the grant in force.
    """
    # Lazy: keeps the Bridge off the plain `demo` / `serve` import path, which
    # mints nothing and needs no anchor.
    from odis_harness.bridge.audit import ExchangeAuditAnchor  # noqa: PLC0415

    return ExchangeAuditAnchor(
        audit=ctx.audit,
        bundle=ctx.bundle,
        target_endpoint_id=ctx.family.vendor_mcp.endpoint_id,
        family_name=ctx.family_name,
    )


def _vendor_audience(family: Family) -> str:
    """The leg-2 token audience for `family` (RFC 8707 Resource Indicator).

    The vendor MCP's `endpoint_id` is its stable canonical identity; it is required
    and validated non-empty, so it is the audience directly.
    """
    return family.vendor_mcp.endpoint_id


def make_oauth2_http_vendor_factory(
    config: OAuth2InteractiveConfig,
) -> VendorClientFactory:
    """Build a vendor factory using interactive OAuth2 authorization-code/PKCE.

    No caller-supplied bearer or pre-provisioned client secret is accepted: the
    SDK OAuth provider performs dynamic client registration and obtains access
    tokens from the authorization server.
    """
    from odis_harness.mcp_forwarder.oauth import (  # noqa: PLC0415
        AnchoredOAuthTokenStorage,
        make_interactive_oauth2_auth,
    )

    def _factory(ctx: VendorClientContext) -> McpClient:
        # The SDK mints and refreshes the Target-MCP credential inside its own
        # provider, so the only place the harness sees it is the token store.
        # Anchoring there is what makes ODIS-CC-06 hold on this leg.
        return HttpMcpClient(
            url=ctx.family.vendor_mcp.url,
            auth=make_interactive_oauth2_auth(
                server_url=ctx.family.vendor_mcp.url,
                storage=AnchoredOAuthTokenStorage(anchor=_anchor_for(ctx)),
                config=config,
            ),
        )

    return _factory


def make_bridged_http_vendor_factory(
    *,
    exchanger: TokenExchanger,
    subject_token_provider: Callable[[], str],
) -> VendorClientFactory:
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

    def _factory(ctx: VendorClientContext) -> McpClient:
        return HttpMcpClient(
            url=ctx.family.vendor_mcp.url,
            auth=BridgeAuth(
                subject_token_provider=subject_token_provider,
                audience=_vendor_audience(ctx.family),
                exchanger=exchanger,
                anchor=_anchor_for(ctx),
            ),
        )

    return _factory


def make_fixture_bridged_http_vendor_factory() -> VendorClientFactory:
    """A bridged vendor factory wired with the fixture Bridge (the `--bridge` default).

    Stands up a `FixtureTokenExchanger` (the in-process RFC 7523/8693 broker stand-in)
    plus a Passport stand-in (`fixture_subject_token_provider`) minting a fresh agent
    workload JWT per exchange. No network, no static bearer; the broker is the
    production `TokenExchanger` implementation.
    """
    # Lazy: the Bridge + fixture stand-ins are only needed on the opt-in `--bridge` path.
    from odis_harness.fixtures.bridge import (  # noqa: PLC0415
        FixtureTokenExchanger,
        fixture_subject_token_provider,
    )
    from odis_harness.fixtures.issuer import FixtureIdentityIssuer  # noqa: PLC0415

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
__all__ = [
    "BUNDLE_LOAD_ERRORS",
    "GrantSourceConfigError",
    "RouterWiring",
    "SignedBundleSource",
    "SignedSourceConfigError",
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
    "resolve_bundle_path",
    "resolve_file_verifier",
    "resolve_opa_binary",
    "resolve_signed_source",
    "stub_context_factory",
]
