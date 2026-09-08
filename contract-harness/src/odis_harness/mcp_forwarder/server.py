"""MCP protocol glue — exposes a Router as an MCP `Server`.

Isolates the `mcp` SDK dependency from the forward engine (`router.py` stays
SDK-free). `build_mcp_server(router)` wires the SDK's low-level `Server` with
`tools/list` (from the discovery cache) and `tools/call` (dispatch to
`Router.forward`).

`tools/call` is registered with `validate_input=False`: the Router's own
policy + action-limit pipeline is the authority and audits every call. Letting
the SDK reject on inputSchema first would bypass that audit trail.
"""

from __future__ import annotations

import json
import uuid
from typing import TYPE_CHECKING

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.lowlevel import Server
from mcp.types import CallToolResult, ContentBlock, TextContent, Tool

from odis_harness.mcp_forwarder.audit import audit_refused
from odis_harness.mcp_forwarder.identity import CallerIdentity
from odis_harness.mcp_forwarder.names import UnroutedToolName, parse_tool_name
from odis_harness.mcp_forwarder.reason_codes import ReasonCode
from odis_harness.mcp_forwarder.router import McpRefusal

if TYPE_CHECKING:
    from collections.abc import Mapping
    from typing import Any

    from odis_harness.mcp_forwarder.router import Router
    from odis_harness.mcp_forwarder.vendor_client import ToolResult

#: Server name advertised in the MCP `initialize` handshake.
SERVER_NAME = "odis-router"


def build_mcp_server(router: Router, *, requires_authenticated_caller: bool) -> Server:
    """Construct an MCP `Server` backed by `router`.

    `requires_authenticated_caller` is the transport's posture: True when the surface
    validates an inbound credential. The handler then refuses a call it cannot attribute
    rather than falling back to `router.agent_id`, because a silent identity downgrade
    would keep forwarding while the audit trail named the wrong caller.

    Required rather than defaulted. It has to agree with the `token_verifier` passed to
    `build_asgi_app`, and both are public seams — a default would let an auth-gated app
    be built with the handler's refusal branch quietly dead.
    """
    server: Server = Server(SERVER_NAME)

    # The SDK's list_tools/call_tool decorators are untyped; the ignores are
    # the documented pattern for a third-party stub limitation.
    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]
    async def _list_tools() -> list[Tool]:
        return _tool_catalog(router)

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]
    async def _call_tool(name: str, arguments: dict[str, Any]) -> CallToolResult:
        return await _call(router, name, arguments, auth_required=requires_authenticated_caller)

    return server


def _tool_catalog(router: Router) -> list[Tool]:
    if router.discovery is None:
        return []
    descriptors = router.discovery.aggregate(router.bundle)
    return [
        Tool(
            name=d.name,
            description=d.description,
            inputSchema=dict(d.input_schema),
        )
        for d in descriptors
    ]


class _UnattributableCallError(Exception):
    """The transport requires a credential but this call carries no verified identity."""


def _caller_identity(router: Router, *, auth_required: bool) -> CallerIdentity:
    """The agent identity for this call: the verified token's subject when there is one.

    `get_access_token()` reads the token `BearerAuthBackend` validated for this request,
    so the subject is one the Router *received* and checked, not one it asserted about
    itself. Falls back to `router.agent_id` only on the unauthenticated transport paths
    (`demo`, in-process tests), where there is no inbound credential to derive it from.
    """
    token = get_access_token()
    if token is not None:
        # `client_id` is where `WorkloadJwtVerifier` puts the verified `sub` — the
        # only identity field the SDK's AccessToken exposes to a handler.
        return CallerIdentity.verified(token.client_id)
    if auth_required:
        # Auth is configured, so a missing token here means the verified identity did not
        # reach the handler — a middleware bypass, or an SDK change to how the request
        # task is spawned.
        # Forwarding anyway would attribute the call to the fallback id and keep going,
        # which is a silent identity downgrade. Refuse instead.
        raise _UnattributableCallError
    return CallerIdentity(agent_id=router.agent_id)


async def _call(
    router: Router, name: str, arguments: Mapping[str, Any], *, auth_required: bool
) -> CallToolResult:
    args = dict(arguments or {})
    # Resolve the caller before routing: it is a contextvar read, it needs nothing from
    # the tool name, and doing it first means every refusal below can name who was
    # refused rather than only the ones that got as far as a family.
    try:
        caller = _caller_identity(router, auth_required=auth_required)
    except _UnattributableCallError:
        _audit_handler_refusal(
            router, family_name=None, tool=name, reason_code=ReasonCode.UNATTRIBUTED_CALLER
        )
        return _refusal_result(ReasonCode.UNATTRIBUTED_CALLER)

    try:
        family_name, tool = parse_tool_name(name)
    except UnroutedToolName:
        _audit_handler_refusal(
            router,
            family_name=None,
            tool=name,
            reason_code=ReasonCode.UNROUTED_FAMILY,
            caller=caller,
        )
        return _refusal_result(ReasonCode.UNROUTED_FAMILY)

    family = router.bundle.family(family_name)
    if family is None:
        # family_name is None: the bundle declares no such family, so there is no
        # resource family to name. The sink derives `apf_semantic_enforcement` from
        # the presence of one, and a call refused before policy was not enforced.
        _audit_handler_refusal(
            router,
            family_name=None,
            tool=tool,
            reason_code=ReasonCode.UNROUTED_FAMILY,
            caller=caller,
        )
        return _refusal_result(ReasonCode.UNROUTED_FAMILY)

    try:
        result = await router.forward(family_name, family, tool, args, caller=caller)
    except McpRefusal as refusal:
        return _refusal_result(refusal.reason_code)
    except Exception:  # noqa: BLE001 - handler boundary: fail closed, audit, never leak internals
        # An unexpected error (a bug, not a policy refusal) still fails closed
        # AND is audited. The agent gets a generic refusal — never the
        # exception text, which could leak internal detail.
        _audit_handler_refusal(
            router,
            family_name=family_name,
            tool=tool,
            reason_code=ReasonCode.INTERNAL_ERROR,
            caller=caller,
        )
        return _refusal_result(ReasonCode.INTERNAL_ERROR)
    return _success_result(result)


def _audit_handler_refusal(
    router: Router,
    *,
    family_name: str | None,
    tool: str,
    reason_code: ReasonCode,
    caller: CallerIdentity | None = None,
) -> None:
    """Emit the refusal audit for a call rejected at the handler, before `forward`.

    `forward` audits its own refusals; this covers the ones it never sees — an
    unroutable tool name, a call that cannot be attributed, and an unexpected error at
    the protocol boundary.

    `caller` is the actor when one was resolved, and `None` when the call could not be
    attributed at all. No full identity context either way: minting one calls the
    identity providers — network I/O in a production deployment — on agent-controlled input
    that is already being rejected, so the event carries the agent without the
    originating principal.
    """
    # `family_name` is None whenever routing did not resolve one, so the sink does not
    # derive `apf_semantic_enforcement` for a call that reached neither policy nor an
    # enforcer.
    audit_refused(
        router.audit,
        correlation_id=str(uuid.uuid4()),
        bundle=router.bundle,
        family_name=family_name,
        tool=tool,
        reason_code=reason_code,
        runtime_context=None,
        caller=caller,
    )


def _refusal_result(reason_code: ReasonCode) -> CallToolResult:
    return CallToolResult(
        content=[TextContent(type="text", text=f"refused: {reason_code}")],
        isError=True,
    )


def _success_result(result: ToolResult) -> CallToolResult:
    # The Router forwarded successfully, but the vendor may have returned an
    # in-band tool error — relay its status rather than hard-coding success.
    return CallToolResult(content=_to_text_blocks(result.content), isError=result.is_error)


def _to_text_blocks(blocks: list[Mapping[str, Any]]) -> list[ContentBlock]:
    """Convert vendor MCP content blocks into SDK content blocks.

    Text blocks pass through; non-text blocks are JSON-serialized into a text
    block (PoC fidelity limit — image/resource passthrough is future work).
    """
    out: list[ContentBlock] = []
    for block in blocks:
        if block.get("type") == "text" and "text" in block:
            out.append(TextContent(type="text", text=str(block["text"])))
        else:
            out.append(TextContent(type="text", text=json.dumps(block)))
    return out


__all__ = ["SERVER_NAME", "build_mcp_server"]
