"""Frozen dataclasses mirroring the `odis.bundle.v1` JSON Schema.

These types are the in-memory representation the Router consumes. They are
immutable; reloading a bundle replaces the instance rather than mutating it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from functools import cached_property
from typing import TYPE_CHECKING, Literal, get_args

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from typing import Any

#: Vendor MCP URL scheme, mirroring the `url` pattern in the same schema. HTTP-only:
#: the Router speaks Streamable HTTP, so any other scheme is unroutable.
_URL_PATTERN = re.compile(r"^https?://")

#: `endpoint_id` and family-name pattern. Lowercase kebab. The authority is the
#: `pattern` in `schemas/odis.bundle.v1.json`; this and `mcp_forwarder.names` each
#: restate it rather than sharing a constant, because `names` is a leaf that must not
#: import this package (doing so drags httpx and cryptography in via `bundle/__init__`).
#: All three must agree: a family name the schema accepts but `parse_tool_name` rejects
#: would be advertised by discovery and then be permanently unroutable.
_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9-]*$")

#: `sha256:<64 hex>` — the one digest form the delegation references carry. The
#: algorithm prefix is part of the value so a change of algorithm stays legible
#: rather than silently producing differently-shaped hex.
_DIGEST_PATTERN = re.compile(r"^sha256:[0-9a-f]{64}$")

DefaultMode = Literal["strict", "permissive"]

#: Egress mode a Provider Adapter declares for one target (ODIS-L2-15). `native` is
#: only legal when the target itself validates the agent's runtime credential and
#: delegation record; otherwise the adapter enforces, which is `bridge`. This harness
#: is bridge throughout: the vendor MCP server authenticates the Router's leg, not
#: the agent's.
EgressMode = Literal["native", "bridge"]

#: Allowed values for `VendorMcp.egress_mode`, derived from `EgressMode`.
_EGRESS_MODES: frozenset[str] = frozenset(get_args(EgressMode))

#: Allowed values for `Family.default_mode`, derived from `DefaultMode` so the closed
#: set is written once. Schema-enforced too; the dataclass re-validates so Python
#: construction (e.g. tests, `build_router_from_bundle`) fails fast.
_DEFAULT_MODES: frozenset[str] = frozenset(get_args(DefaultMode))


@dataclass(frozen=True, kw_only=True, slots=True)
class VendorMcp:
    """Per-family vendor MCP server endpoint. HTTP transport per the MCP spec.

    `egress_mode` is the ODIS-L2-15 per-target declaration. It defaults to `bridge`
    because that is what this harness does; a bundle document may omit it, and the
    Vault issuer always writes it explicitly into the signed bytes.
    """

    endpoint_id: str
    url: str
    egress_mode: EgressMode = "bridge"

    def __post_init__(self) -> None:
        if not _NAME_PATTERN.fullmatch(self.endpoint_id):
            message = f"endpoint_id {self.endpoint_id!r} does not match {_NAME_PATTERN.pattern!r}"
            raise ValueError(message)
        # The schema constrains `url` too, and `loader` relies on this method to re-check
        # schema invariants for the programmatic `build_router_from_bundle` path, which
        # never sees the schema.
        if not _URL_PATTERN.match(self.url):
            message = f"url {self.url!r} does not match {_URL_PATTERN.pattern!r}"
            raise ValueError(message)
        if self.egress_mode not in _EGRESS_MODES:
            message = (
                f"egress_mode {self.egress_mode!r} must be one of {sorted(_EGRESS_MODES)}"
            )
            raise ValueError(message)


@dataclass(frozen=True, kw_only=True, slots=True)
class MappingRecordRef:
    """Reference to one issuer-side record that conferred a grant: its name, the
    version that conferred it, and a digest over its content.

    A verifier that can read the record recomputes the digest to confirm the grant
    came from that exact content; the bundle signature protects the reference.
    """

    name: str
    version: int
    digest: str

    def __post_init__(self) -> None:
        # Schema parity, for the same reason `VendorMcp` re-validates: the schema guards
        # a loaded document, and `build_router_from_bundle` accepts a `Bundle` built in
        # Python, where nothing has run. A reference that names no record, carries a
        # non-monotonic version, or holds a digest a verifier cannot compare against is
        # unusable, so it fails at construction rather than at verification.
        if not self.name:
            message = "MappingRecordRef.name must be non-empty"
            raise ValueError(message)
        if self.version < 1:
            message = f"MappingRecordRef.version must be >= 1, got {self.version}"
            raise ValueError(message)
        if not _DIGEST_PATTERN.fullmatch(self.digest):
            message = f"digest {self.digest!r} must match {_DIGEST_PATTERN.pattern!r}"
            raise ValueError(message)


@dataclass(frozen=True, kw_only=True, slots=True)
class AttenuationProfileRef:
    """The immutable, versioned normalization and comparison rules that govern the
    grant's attenuation (ODIS-L2-06), plus the content digest that resolves them."""

    uri: str
    digest: str

    def __post_init__(self) -> None:
        # A profile ref that cannot be resolved or compared is the ODIS-L2-06 clause it
        # exists to satisfy, unsatisfied — so both halves are required, not merely typed.
        if not self.uri:
            message = "AttenuationProfileRef.uri must be non-empty"
            raise ValueError(message)
        if not _DIGEST_PATTERN.fullmatch(self.digest):
            message = f"digest {self.digest!r} must match {_DIGEST_PATTERN.pattern!r}"
            raise ValueError(message)


@dataclass(frozen=True, kw_only=True, slots=True)
class ToolPolicy:
    """Bundle declaration for one governed vendor tool.

    Presence in `Family.tools` means the Router evaluates the family policy for
    that tool. `action_limits` are optional post-policy constraints; an empty map
    is valid for read-only tools that need policy gating but no argument filter.
    """

    action_limits: Mapping[str, Any] = field(default_factory=dict)


@dataclass(frozen=True, kw_only=True, slots=True)
class Family:
    """One resource family declared in the bundle's `families` map."""

    vendor_mcp: VendorMcp
    policy: str  # Rego source
    tools: Mapping[str, ToolPolicy]  # keyed by vendor tool name (unprefixed)
    default_mode: DefaultMode

    def __post_init__(self) -> None:
        if self.default_mode not in _DEFAULT_MODES:
            message = f"default_mode {self.default_mode!r} must be one of {sorted(_DEFAULT_MODES)}"
            raise ValueError(message)

    def governs_tool(self, tool_name: str) -> bool:
        """True when `tool_name` is explicitly governed by the family policy."""
        return tool_name in self.tools

    def governed_tools(self) -> Iterator[str]:
        """Iterate vendor tool names explicitly governed by this family."""
        return iter(self.tools)

    def action_limits_for(self, tool_name: str) -> Mapping[str, Any]:
        """Return declared post-policy action limits for a governed tool."""
        return self.tools[tool_name].action_limits


@dataclass(frozen=True, kw_only=True)
class Bundle:
    """A loaded, validated bundle. The Router holds one of these at a time.

    Not slotted: `cached_property` needs `__dict__` to memoize the digest.
    Bundle instances are created once per load and held for the lifetime of
    the Router; the slots optimization is irrelevant.
    """

    bundle_id: str
    bundle_version: str
    trust_root_id: str
    families: Mapping[str, Family]

    #: The delegation record the issuer stamped on this grant (ODIS §6.3): who holds
    #: it (`actor`), who delegated it (`originating_principal`), which records
    #: conferred it, the comparison rules its attenuation follows, and the window it
    #: is valid for. All absent on a grant assembled outside issuance — a local file has
    #: no issuer to stamp them, which is why such a grant never expires.
    #:
    #: The invariant is ASYMMETRIC on purpose, and the halves have different jobs. The
    #: Vault plugin refuses to *sign* a record missing any field, so no issued grant is
    #: ever partial. Loading is deliberately more permissive: a hand-authored local
    #: grant may carry `expires_at` alone and have the Router enforce it, which is a
    #: real capability. What load refuses is the one incoherent combination —
    #: `issued_at` without `expires_at`.
    actor: str | None = None
    originating_principal: str | None = None
    #: A provenance manifest under a local name. NOT §6.3's
    #: `originating_authorization_ref`, which references the authoritative grant that
    #: authorized the delegating principal to delegate; the issuer holds no such
    #: reference, so the draft's field stays unset rather than being filled with a
    #: different object.
    contributing_records: tuple[MappingRecordRef, ...] = ()
    #: Prior delegation hops. `None` is an unissued grant saying nothing; `()` is an
    #: issued grant asserting a ROOT record — one operator-to-agent hop, no
    #: sub-delegation. A non-empty chain is refused: this harness has no
    #: sub-delegation path, so it could only arrive from an issuer whose lineage the
    #: Router cannot verify.
    delegation_chain: tuple[str, ...] | None = None
    attenuation_profile_ref: AttenuationProfileRef | None = None
    issued_at: str | None = None
    expires_at: str | None = None

    def __post_init__(self) -> None:
        # Family names must match the routing pattern `parse_tool_name` enforces:
        # a name the router can never parse would be advertised by discovery yet
        # be permanently unroutable. The YAML loader relies on the schema for
        # this; re-validate here so the programmatic `build_router_from_bundle`
        # path (a documented seam) fails fast instead of shipping dead tools.
        for name in self.families:
            if not _NAME_PATTERN.fullmatch(name):
                message = f"family name {name!r} does not match {_NAME_PATTERN.pattern!r}"
                raise ValueError(message)
        self._validate_window()
        if self.delegation_chain:
            message = (
                f"delegation_chain {list(self.delegation_chain)} must be empty: this "
                "harness mints and verifies root records only, so a claimed hop has "
                "no lineage it can check"
            )
            raise ValueError(message)

    def _validate_window(self) -> None:
        """Reject a grant window the Router could not act on.

        An unparseable or backwards window is indeterminate, and the Router asks
        `expired()` on every call — so it fails here, at load, rather than at the
        first forward.
        """
        issued = _parse_instant(self.issued_at, "issued_at")
        expires = _parse_instant(self.expires_at, "expires_at")
        if issued is not None and expires is None:
            # A stamped issuance with no expiry reads as governed while being
            # immortal, which no issuer produces: the plugin's signing seam refuses
            # to sign a delegation record missing any of its fields. Only a
            # hand-authored local grant can reach here, and it fails closed.
            message = f"issued_at {self.issued_at!r} is set but expires_at is absent"
            raise ValueError(message)
        if issued is not None and expires is not None and expires <= issued:
            message = (
                f"expires_at {self.expires_at!r} is not after issued_at {self.issued_at!r}"
            )
            raise ValueError(message)

    def expired(self, *, now: datetime | None = None) -> bool:
        """True when this grant declares an expiry that has passed.

        A grant declaring no expiry is never expired — which is why a local grant,
        having no issuer to stamp a window, keeps authorizing until the process ends.

        `__post_init__` has already rejected an unparseable `expires_at`, so the parse
        here cannot raise.
        """
        expiry = _parse_instant(self.expires_at, "expires_at")
        if expiry is None:
            return False
        return (now if now is not None else datetime.now(UTC)) >= expiry

    def family(self, name: str) -> Family | None:
        """Return the family entry for `name`, or None if not declared."""
        return self.families.get(name)

    def families_iter(self) -> Iterator[tuple[str, Family]]:
        """Iterate (family_name, family) pairs in declaration order.

        Backed by the underlying mapping; `dict.items()` preserves insertion
        order in Python 3.7+, and the loader preserves the bundle file's
        family ordering.
        """
        return iter(self.families.items())

    @cached_property
    def policy_digest(self) -> str:
        """sha256 hex digest of the canonical serialization of the entire
        bundle. Computed once on first access. See `digest.policy_digest`."""
        # Local import avoids a circular import between types.py and digest.py.
        from odis_harness.bundle.digest import policy_digest  # noqa: PLC0415

        return policy_digest(self)


def _parse_instant(value: str | None, field_name: str) -> datetime | None:
    """Parse an RFC 3339 instant, or None when absent.

    A naive timestamp is read as UTC: the issuer stamps UTC, and comparing a naive
    value against an aware `now` would raise inside `expired()`.
    """
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        message = f"{field_name} {value!r} is not an RFC 3339 instant: {exc}"
        raise ValueError(message) from exc
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=UTC)


__all__ = [
    "AttenuationProfileRef",
    "Bundle",
    "DefaultMode",
    "EgressMode",
    "Family",
    "MappingRecordRef",
    "ToolPolicy",
    "VendorMcp",
]
