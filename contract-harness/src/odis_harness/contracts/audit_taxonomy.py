"""Audit-event type taxonomy.

Two-bucket discipline for `odis.audit.event.v1.event_type`:

1. **APF §6.5 enum is strict.** The harness uses only values APF defines:
   `policy_load`, `policy_reject`, `authorize`, `deny`, `require_review`,
   `review_decision`, `credential_issue`, `resource_call`, `result`,
   `detector_verdict`, `quarantine`, `stop_session`, `revocation`,
   `break_glass`. Specifics that are sub-cases of an APF event go in
   `reason_code` (APF §6.2 / §6.5) and the harness extension field
   `result_class`.
2. **Genuinely outside the APF taxonomy → ODIS Contract Harness extension type**,
   prefixed `odis.<ns>.<name>` so it is unmistakable.

Mapping table (the only legitimate uses):

| Conceptual event              | event_type       | qualifier                       |
|-------------------------------|------------------|---------------------------------|
| Policy load failed            | policy_reject    | reason_code=load_failed         |
| Credential refused            | credential_issue | result_class=refused            |
| Credential binding violation  | credential_issue | result_class=binding_violation  |
| Obligation stripped / refused | deny             | reason_code=obligation_violation|

Extension event types:

| event_type                       | When emitted                              |
|----------------------------------|-------------------------------------------|
| odis.substrate.egress_violation  | Agent attempted non-MCP egress            |
| odis.security.spoofing_attempt   | Caller-supplied subject fields detected   |
| odis.mcp.forward                 | Router forwarded an approved tool call    |
| odis.mcp.forward_refused         | Router refused a tool call (see reason_code) |
| odis.mcp.discovery_failed        | Vendor `tools/list` failed at startup     |
| odis.bridge.terminal_exchange    | Bridge minted a Target-MCP credential (ODIS-CC-06) |
"""

from __future__ import annotations

#: APF §6.5 `event_type` enum verbatim.
APF_EVENT_TYPES: frozenset[str] = frozenset(
    {
        "policy_load",
        "policy_reject",
        "authorize",
        "deny",
        "require_review",
        "review_decision",
        "credential_issue",
        "resource_call",
        "result",
        "detector_verdict",
        "quarantine",
        "stop_session",
        "revocation",
        "break_glass",
    }
)

#: Genuinely outside the APF taxonomy; reserved for ODIS Contract Harness use.
ODIS_EXTENSION_TYPES: frozenset[str] = frozenset(
    {
        "odis.substrate.egress_violation",
        "odis.security.spoofing_attempt",
        "odis.mcp.forward",
        "odis.mcp.forward_refused",
        "odis.mcp.discovery_failed",
        "odis.bridge.terminal_exchange",
    }
)


def is_valid_event_type(event_type: str) -> bool:
    """True iff `event_type` is in the APF enum OR the registered ODIS extension set.

    The JSON Schema pattern accepts any `odis.<ns>.<name>`; this function is
    the authoritative runtime gate that rejects unregistered extensions.
    """
    return event_type in APF_EVENT_TYPES or event_type in ODIS_EXTENSION_TYPES


__all__ = [
    "APF_EVENT_TYPES",
    "ODIS_EXTENSION_TYPES",
    "is_valid_event_type",
]
