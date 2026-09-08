"""The ODIS Bridge — leg-2 (Router→vendor MCP) token-exchange.

The Router authenticates to each vendor MCP with a SHORT-LIVED, audience-scoped bearer
obtained by exchanging the agent's workload identity for a vendor-audience-scoped
downstream token (RFC 8693 token-exchange / RFC 7523 JWT-bearer; RFC 8707 audience
binding). The agent's inbound token is NOT passed through (MCP no-token-passthrough);
the leg-2 token is freshly minted/exchanged, distinct from both the caller's token and
the vendor→provider credential, hydrated at runtime and never persisted.

`exchange` holds the seam (`ExchangedToken`, `TokenExchanger`, `BridgeAuth`); `audit`
holds the ODIS-CC-06 audit anchor for the exchange (`ExchangeAuditAnchor`,
`CredentialHandle`); `fixtures` holds the in-process stand-in.
"""

from __future__ import annotations

from odis_harness.bridge.exchange import BridgeAuth, ExchangedToken, TokenExchanger

__all__ = [
    "BridgeAuth",
    "ExchangedToken",
    "TokenExchanger",
]
