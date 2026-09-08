"""HTTP transport for the Router's MCP server.

HTTP only (Streamable HTTP per the MCP spec). No stdio: the Router is a network
chokepoint an agent is routed *through*, not a subprocess it launches.
Any standard MCP client (Inspector, Claude Code, Cursor) connects to the server's URL
with no special handling — unless `serve --inbound-key` configured a token verifier, in
which case the client must also present a bearer the Router accepts.

`build_asgi_app` constructs the Starlette app (testable / mountable);
`serve_http` runs it under uvicorn until shutdown.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
from typing import TYPE_CHECKING

import uvicorn
from mcp.server.auth.middleware.auth_context import AuthContextMiddleware
from mcp.server.auth.middleware.bearer_auth import BearerAuthBackend, RequireAuthMiddleware
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
from starlette.applications import Starlette
from starlette.middleware import Middleware
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.routing import Mount

if TYPE_CHECKING:
    from collections.abc import AsyncIterator

    from mcp.server.auth.provider import TokenVerifier
    from mcp.server.lowlevel import Server
    from starlette.types import ASGIApp, Receive, Scope, Send

#: Path the MCP endpoint is mounted at. Clients connect to `http://host:port/mcp`.
MCP_MOUNT_PATH = "/mcp"

#: The path an MCP client must POST to. Starlette's `Mount` answers the bare mount path
#: with a 307 to the trailing-slash form, so a client using `MCP_MOUNT_PATH` directly pays
#: a redirect and re-sends its body on every request. Under an egress proxy that re-POST
#: intermittently fails, which surfaced as a ~1-in-3 failure of the gated OpenShell demo:
#: the `tools/call` redirect was not followed and the agent saw a read error while the
#: Router never received the call. Clients use `mcp_url`; the mount itself keeps the bare
#: path, which is what `Mount` expects.
MCP_CLIENT_PATH = MCP_MOUNT_PATH + "/"


def mcp_url(host: str, port: int) -> str:
    """The URL an MCP client should connect to for a Router or vendor stub on `host:port`.

    One builder because the trailing slash is the whole point: six call sites previously
    assembled this string themselves and every one of them omitted it.
    """
    return f"http://{host}:{port}{MCP_CLIENT_PATH}"


def build_asgi_app(
    server: Server,
    *,
    token_verifier: TokenVerifier | None = None,
    json_response: bool = True,
) -> Starlette:
    """Wrap an MCP `Server` in a Starlette ASGI app via Streamable HTTP.

    `stateless=True`: each request is self-contained (no server-side session
    persistence) — appropriate for a stateless policy forwarder. `json_response`
    returns plain JSON responses (simpler for clients than an SSE stream) while
    remaining MCP-spec compliant.

    Security note: `StreamableHTTPSessionManager` accepts a
    `security_settings` (`TransportSecuritySettings`) param for Origin/Host
    validation, which defends against browser-driven DNS-rebinding. We do not
    set it here: our client is an MCP agent (not a browser), and the default
    CLI bind is loopback. A production deployment exposed to browsers, or bound
    to a non-loopback interface, SHOULD configure allowed Origins/Hosts.
    """
    session_manager = StreamableHTTPSessionManager(
        app=server,
        json_response=json_response,
        stateless=True,
    )

    async def handle_mcp(scope: Scope, receive: Receive, send: Send) -> None:
        await session_manager.handle_request(scope, receive, send)

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        async with session_manager.run():
            yield

    mounted: ASGIApp = handle_mcp
    middleware: list[Middleware] = []
    if token_verifier is not None:
        # Order matters: authenticate, publish to the request context, then require.
        # The 401 lands before the MCP handler runs.
        #
        # No `resource_metadata_url`, so the challenge omits RFC 9728's `resource_metadata`
        # pointer: a client cannot discover the issuer from the 401 and must be provisioned
        # out of band. Serving that discovery is a deployment decision, not ours.
        mounted = RequireAuthMiddleware(handle_mcp, required_scopes=[])
        middleware = [
            Middleware(AuthenticationMiddleware, backend=BearerAuthBackend(token_verifier)),
            Middleware(AuthContextMiddleware),
        ]

    return Starlette(
        routes=[Mount(MCP_MOUNT_PATH, app=mounted)],
        middleware=middleware,
        lifespan=lifespan,
    )


#: Startup poll budget for `serving_http`: 100 x 50ms = 5s. Generous — uvicorn on
#: loopback reports `started` in milliseconds — because the failure it prevents is the
#: confusing one: a client that connects before the socket listens gets a transport error
#: that reads like a policy refusal.
_STARTUP_POLLS = 100
_STARTUP_POLL_INTERVAL_S = 0.05


def free_loopback_port() -> int:
    """An unused loopback TCP port.

    Inherently racy — the port is released before the caller binds it — but the window is
    small, and the alternative of binding port 0 and reading the assignment back off the
    running server means a caller cannot build its own URL until after startup.
    """
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@contextlib.asynccontextmanager
async def serving_http(
    app: Starlette, *, host: str = "127.0.0.1", port: int, log_level: str = "error"
) -> AsyncIterator[None]:
    """Serve `app` for the duration of the block, then shut it down.

    The bounded counterpart to `serve_http`, which serves until the process exits. Three
    callers want a server that outlives a block and no longer — `demo`, the end-to-end
    tests, and the OpenShell example — and each carried its own copy of this loop.

    Takes a Starlette app rather than an MCP `Server` because callers also stand up plain
    vendor stubs with it, which are not MCP servers at all.
    """
    # `log_level` defaults to errors only, so a demo's output stays its own. Raise it to
    # "info" for an access log when diagnosing whether a request reached the app at all —
    # the difference between "the gate refused it" and "it never arrived".
    server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level=log_level))
    task = asyncio.create_task(server.serve())
    try:
        for _ in range(_STARTUP_POLLS):
            if server.started:
                break
            if task.done():
                # uvicorn failed before it finished starting — an address already in use,
                # say. Awaiting re-raises that, which is the diagnosis; polling on to the
                # timeout would report "did not start" and discard it.
                await task
                break
            await asyncio.sleep(_STARTUP_POLL_INTERVAL_S)
        if not server.started:
            message = f"server on {host}:{port} did not start"
            raise RuntimeError(message)
        yield
    finally:
        server.should_exit = True
        # Guarded: on the startup-failure path the task is already finished and its
        # exception already retrieved, so awaiting again would only re-raise it from the
        # `finally` and obscure where it came from.
        if not task.done():
            await task


async def serve_http(
    server: Server,
    *,
    host: str,
    port: int,
    token_verifier: TokenVerifier | None = None,
) -> None:
    """Serve the MCP `Server` over HTTP until the process is shut down."""
    app = build_asgi_app(server, token_verifier=token_verifier)
    config = uvicorn.Config(app, host=host, port=port, log_level="warning")
    await uvicorn.Server(config).serve()


__all__ = [
    "MCP_CLIENT_PATH",
    "MCP_MOUNT_PATH",
    "build_asgi_app",
    "free_loopback_port",
    "mcp_url",
    "serve_http",
    "serving_http",
]
