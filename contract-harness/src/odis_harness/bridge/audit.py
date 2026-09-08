"""Terminal-exchange audit anchor — ODIS-CC-06.

The Bridge performs the terminal token exchange for a Target MCP that knows nothing about
ODIS: it presents a bearer the target validates natively, and nothing downstream of this
component can record what was handed over. CC-06 therefore makes the exchanging component
the authoritative audit anchor, and this module is that anchor.

`ExchangeAuditAnchor.record` emits one `odis.bridge.terminal_exchange` per exchange,
binding:

- the **Authority Grant in force** — `policy_digest`, `bundle_id`, `bundle_version`,
  `trust_root_id`, stamped by the same rule every other event in the harness follows;
- the **target system identity** — the bundle's stable `vendor_mcp.endpoint_id`. Never the
  URL: the trail has to survive a target moving hosts;
- **what the minting mechanism requested** — `audience`, which is the discriminator
  between the two legs rather than a cross-check on the endpoint id. `--bridge` requests
  the endpoint id as an RFC 8707 resource indicator; `--oauth2` requests no audience at
  all and records `None`;
- a **handle to each credential artifact** — a `CredentialHandle`, which carries a sha256
  fingerprint and nothing else. CC-06 permits an identifier, handle or cryptographic
  fingerprint and forbids the raw secret, so the seam is shaped so a raw secret cannot
  reach it: the caller fingerprints where it already holds the token, and `record`
  accepts only handles.

Two mechanisms anchor here, and they bind different amounts. `BridgeAuth` performs an
RFC 8693 exchange, so it has both an audience it requested and a subject assertion the
agent presented. The OAuth2 authorization-code path (`mcp_forwarder.oauth`) has neither:
authorization was an interactive human grant the harness never sees, and the flow sends
no resource indicator, so it records `audience=None` and `subject=None`. Those are
explicit absences — "this mechanism asks for no audience and binds no delegation-input
assertion" is a fact worth stating, and not the same as a field nobody filled in.

The vocabularies are `StrEnum`s, matching `mcp_forwarder.reason_codes.ReasonCode`: same
kind of thing — a closed set of wire strings on an audit event — so it is modelled the
same way, and members serialize as the bare string they always were.

Two deliberate absences:

- **No `resource_family`.** `AuditSink` reads that field as the claim "this call was
  APF-semantically enforced" (the Tier-3 wedge). An exchange passes no policy and no
  action-limit enforcer, so the claim would be false and the sink would be right to reject
  it. The family is recorded as routing context under `extra.target.family`.
- **No actor block.** The anchor sits below the identity factory and holds no
  `RuntimeContext`; the only subject it can see is a claim inside an assertion it does not
  verify. It binds that assertion by fingerprint instead, and the originating principal is
  named on the `odis.mcp.forward` event that shares this record's `correlation_id`.
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Self

from odis_harness.contracts import AuditEvent, now_iso, to_iso

if TYPE_CHECKING:
    from datetime import datetime

    from odis_harness.audit.sink import AuditSink
    from odis_harness.bundle import Bundle


class ExchangeTrigger(StrEnum):
    """Why an exchange happened. Grouped by the mechanism that produces it."""

    #: `BridgeAuth.establish` priming a family before it serves anything.
    BOOT_HANDSHAKE = "boot_handshake"
    #: A cold or stale token cache on an agent call.
    REQUEST = "request"
    #: The target rejected a token mid-TTL — revocation, key rotation, audience drift.
    #: The one an operator most needs to see.
    REJECTION_RETRY = "rejection_retry"
    # S105 reads "TOKEN" in these two names as a hardcoded credential. They are trigger
    # classifications, and "token" is the accurate word for what OAuth2 mints — renaming
    # them to satisfy the heuristic would trade a precise vocabulary for a false positive.
    #
    #: The first token an OAuth2 store has held. Named for what is observable rather
    #: than for a grant type: the SDK calls `TokenStorage.set_tokens` for both an
    #: authorization-code exchange and a refresh without saying which.
    OAUTH_INITIAL_TOKEN = "oauth_initial_token"  # noqa: S105
    #: An OAuth2 token replacing one the store already held. Usually a refresh, and also
    #: what a re-authorization after a failed refresh looks like from here.
    OAUTH_REPLACEMENT_TOKEN = "oauth_replacement_token"  # noqa: S105


class CorrelationSource(StrEnum):
    """Whether the record's `correlation_id` links to an agent call or was minted here."""

    #: Adopted from the trace header the Router put on the outbound request.
    DOWNSTREAM_REQUEST = "downstream_request"
    #: Minted by the anchor, because no usable id arrived. The exchange joins no call.
    ANCHOR = "anchor"


def _is_envelope_uuid(value: str) -> bool:
    """True iff `value` is a uuid in the one form the envelope's `correlation_id` accepts.

    `uuid.UUID()` alone is too lenient to decide this: it also parses the braced,
    `urn:uuid:`-prefixed and un-hyphenated 32-hex forms, none of which satisfy the
    schema's `format: uuid`. Accepting one of those would put it in the record and fail
    validation, taking the agent's call down — the opposite of what the fallback is for.
    So the parse is confirmed by round-tripping to the canonical form. Hex case is
    compared loosely and NOT rewritten: the schema accepts either, and the id is a log
    key, so normalising it would break the string match against the Router's own record.
    """
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return False
    return str(parsed) == value.lower()


def _resolve_correlation(correlation_id: str | None) -> tuple[str, CorrelationSource]:
    """The record's `correlation_id`, and where it came from.

    The id the Router injected into the outbound request wins, so the exchange joins that
    call's trail (ODIS-CC-01). The envelope requires a uuid, so a value that is not one is
    replaced with a minted id rather than left to fail the record — and the record says
    which happened, because an unlinked exchange is a gap an auditor has to see rather
    than a linkage they would otherwise assume. The unusable value is not carried: it came
    off the wire, and the audit record is not the place to reflect it back.
    """
    if correlation_id is not None and _is_envelope_uuid(correlation_id):
        return correlation_id, CorrelationSource.DOWNSTREAM_REQUEST
    return str(uuid.uuid4()), CorrelationSource.ANCHOR


@dataclass(frozen=True, kw_only=True, slots=True)
class CredentialHandle:
    """A non-reversible handle to one credential artifact: fingerprint plus expiry.

    Built through `of`, the only place a secret is read. The instance then holds a digest,
    so nothing that accepts a `CredentialHandle` is able to log the credential.
    """

    fingerprint: str
    expires_at: datetime | None = None

    @classmethod
    def of(cls, secret: str, *, expires_at: datetime | None = None) -> Self:
        """The handle for `secret` — sha256 over its UTF-8 bytes, `sha256:`-prefixed.

        The prefix names the digest, so changing algorithm stays legible in the trail
        instead of silently producing differently-shaped hex.
        """
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return cls(fingerprint=f"sha256:{digest}", expires_at=expires_at)

    def to_extra(self) -> dict[str, Any]:
        """The audit-record shape. `expires_at` is omitted when it is not known."""
        if self.expires_at is None:
            return {"fingerprint": self.fingerprint}
        return {"fingerprint": self.fingerprint, "expires_at": to_iso(self.expires_at)}


@dataclass(frozen=True, kw_only=True, slots=True)
class TerminalExchange:
    """The facts about one exchange, as the mechanism that performed it knows them.

    Separate from `ExchangeAuditAnchor`, which holds the durable per-target context: this
    is what varies per exchange, built where those facts are in hand. Keeping them apart
    is what keeps `record` to a single argument, so a new fact worth recording becomes a
    field here and the signature does not grow.
    """

    #: What the mechanism asked the credential to be scoped to, or `None` when it asks
    #: for nothing. The discriminator between the two legs — see the module docstring.
    audience: str | None
    credential: CredentialHandle
    #: The delegation input, or `None` for a mechanism that binds no assertion.
    subject: CredentialHandle | None
    #: The trace id of the call this exchange serves, if it serves one.
    correlation_id: str | None
    trigger: ExchangeTrigger


@dataclass(frozen=True, kw_only=True, slots=True)
class ExchangeAuditAnchor:
    """The authoritative audit anchor for one target's terminal token exchanges.

    One per routed family: `target_endpoint_id` and `family_name` come from the bundle
    entry the exchanges are for, so each record names its target without the caller
    repeating it per exchange.
    """

    audit: AuditSink
    bundle: Bundle
    target_endpoint_id: str
    family_name: str

    def record(self, exchange: TerminalExchange) -> None:
        """Emit the anchor record for one completed exchange.

        Whatever the sink raises propagates. Callers record before they cache, so an
        exchange this cannot record does not leave a stored credential behind.
        """
        resolved, source = _resolve_correlation(exchange.correlation_id)
        self.audit.emit(
            AuditEvent(
                correlation_id=resolved,
                event_id=str(uuid.uuid4()),
                timestamp=now_iso(),
                event_type="odis.bridge.terminal_exchange",
                policy_digest=self.bundle.policy_digest,
                bundle_id=self.bundle.bundle_id,
                bundle_version=self.bundle.bundle_version,
                trust_root_id=self.bundle.trust_root_id,
                extra={
                    "trigger": exchange.trigger,
                    "correlation_source": source,
                    "target": {
                        # `endpoint_id` identifies the target; `audience` says what the
                        # mechanism requested, which is how the two legs are told apart:
                        # the endpoint id as an RFC 8707 resource indicator on `--bridge`,
                        # null on `--oauth2`.
                        "endpoint_id": self.target_endpoint_id,
                        "audience": exchange.audience,
                        "family": self.family_name,
                    },
                    "credential": exchange.credential.to_extra(),
                    # Both nulls are explicit rather than omitted: a mechanism that
                    # requests no audience, or binds no delegation-input assertion, is
                    # stating a fact about itself, and an absent key would read as an
                    # oversight instead.
                    "subject_credential": (
                        None if exchange.subject is None else exchange.subject.to_extra()
                    ),
                },
            )
        )


__all__ = [
    "CorrelationSource",
    "CredentialHandle",
    "ExchangeAuditAnchor",
    "ExchangeTrigger",
    "TerminalExchange",
]
