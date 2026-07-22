"""OAuth helpers for Router-to-vendor MCP clients.

The harness does not accept static bearer tokens for live vendor calls. For
OAuth-protected MCP servers, use authorization-code + PKCE with dynamic client
registration so the user authenticates with the authorization server and the
Router receives minted access tokens through the OAuth flow.
"""

from __future__ import annotations

import functools
import socket
import sys
import webbrowser
from contextlib import suppress
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

import anyio
from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientMetadata
from pydantic import AnyHttpUrl
from starlette.applications import Starlette
from starlette.responses import HTMLResponse
from starlette.routing import Route
from uvicorn import Config, Server

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
    from starlette.requests import Request


def _reserve_port(host: str) -> tuple[socket.socket, int]:
    """Bind an ephemeral port and KEEP the socket open.

    Returning only the port (binding then closing) leaves a window in which another
    process can claim it before the callback server binds — the redirect_uri would
    then point at a port the server can't take. Holding the socket and handing it to
    uvicorn (`serve(sockets=[sock])`) closes that window; uvicorn closes it on shutdown.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, 0))
    return sock, int(sock.getsockname()[1])


@dataclass(frozen=True, kw_only=True, slots=True)
class OAuth2InteractiveConfig:
    """Configuration for interactive OAuth2 authorization-code/PKCE vendor auth."""

    client_name: str = "ODIS Contract Harness"
    scopes: str | None = None
    callback_host: str = "127.0.0.1"
    callback_port: int | None = None
    callback_timeout: float = 300.0


@dataclass(kw_only=True, slots=True)
class InMemoryOAuthTokenStorage(TokenStorage):
    """Process-local OAuth token storage.

    This is intentionally non-persistent for smoke tests and local router runs;
    bearer access tokens and client registration details are kept out of reprs.
    """

    _tokens: OAuthToken | None = field(default=None, repr=False)
    _client_info: OAuthClientInformationFull | None = field(default=None, repr=False)

    async def get_tokens(self) -> OAuthToken | None:
        return self._tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        return self._client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._client_info = client_info


@dataclass(kw_only=True, slots=True)
class _OAuthCallbackState:
    code: str | None = None
    state: str | None = None
    error: Exception | None = None


def make_interactive_oauth2_auth(
    *,
    server_url: str,
    storage: TokenStorage,
    config: OAuth2InteractiveConfig,
) -> OAuthClientProvider:
    """Create the MCP SDK OAuth2 provider for a vendor MCP server.

    Uses dynamic client registration plus authorization-code/PKCE. The provider
    prints the authorization URL and attempts to open it in the user's browser.
    """
    # Auto-selected ports are reserved (socket held) to avoid a bind race; an
    # explicitly configured port is left for uvicorn to bind directly.
    if config.callback_port is not None:
        callback_socket: socket.socket | None = None
        callback_port = config.callback_port
    else:
        callback_socket, callback_port = _reserve_port(config.callback_host)
    redirect_uri = f"http://{config.callback_host}:{callback_port}/callback"
    client_metadata = OAuthClientMetadata(
        client_name=config.client_name,
        redirect_uris=[AnyHttpUrl(redirect_uri)],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope=config.scopes,
        token_endpoint_auth_method="none",  # noqa: S106 - public-client auth method, not a credential.
    )
    return OAuthClientProvider(
        server_url=server_url,
        client_metadata=client_metadata,
        storage=storage,
        redirect_handler=_make_redirect_handler(),
        callback_handler=_make_callback_handler(
            host=config.callback_host,
            port=callback_port,
            timeout=config.callback_timeout,
            sock=callback_socket,
        ),
        timeout=config.callback_timeout,
    )


def _make_redirect_handler() -> Callable[[str], Awaitable[None]]:
    async def _redirect(authorization_url: str) -> None:
        sys.stderr.write(
            f"OAuth required for vendor MCP. Open this URL to authorize:\n{authorization_url}\n"
        )
        with suppress(Exception):
            webbrowser.open(authorization_url)

    return _redirect


def _make_callback_handler(
    *, host: str, port: int, timeout: float, sock: socket.socket | None
) -> Callable[[], Awaitable[tuple[str, str | None]]]:
    async def _callback() -> tuple[str, str | None]:
        result = _OAuthCallbackState()
        ready = anyio.Event()
        server = _callback_server(host=host, port=port, result=result, ready=ready)
        # Hand the pre-reserved socket to uvicorn so it binds the exact port the
        # redirect_uri advertised; uvicorn closes it on shutdown. A fixed port
        # (sock is None) is bound by uvicorn from the Config host/port.
        serve = server.serve if sock is None else functools.partial(server.serve, sockets=[sock])
        async with anyio.create_task_group() as task_group:
            task_group.start_soon(serve)
            try:
                with anyio.fail_after(timeout):
                    await ready.wait()
            finally:
                server.should_exit = True
                await anyio.sleep(0.1)
                task_group.cancel_scope.cancel()
            if result.error is not None:
                raise result.error
            if not result.code:
                message = "OAuth callback did not include an authorization code"
                raise RuntimeError(message)
            return result.code, result.state
        message = "OAuth callback handler exited without a result"
        raise RuntimeError(message)

    return _callback


def _callback_server(
    *,
    host: str,
    port: int,
    result: _OAuthCallbackState,
    ready: anyio.Event,
) -> Server:
    async def _callback_route(request: Request) -> HTMLResponse:
        if ready.is_set():
            return _html_response("OAuth callback already received.")

        error = request.query_params.get("error")
        if error:
            description = request.query_params.get("error_description") or error
            result.error = RuntimeError(f"OAuth authorization failed: {description}")
            ready.set()
            return _html_response("OAuth authorization failed.", status_code=400)

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code:
            result.error = RuntimeError("OAuth callback missing authorization code")
            ready.set()
            return _html_response("OAuth callback missing authorization code.", status_code=400)

        result.code = code
        result.state = state
        ready.set()
        return _html_response("OAuth authorization complete. You can close this tab.")

    app = Starlette(routes=[Route("/callback", _callback_route)])
    return Server(
        Config(
            app=app,
            host=host,
            port=port,
            lifespan="off",
            log_level="warning",
        )
    )


def _html_response(message: str, *, status_code: int = 200) -> HTMLResponse:
    return HTMLResponse(
        f"<!doctype html><title>ODIS OAuth</title><p>{message}</p>",
        status_code=status_code,
    )


__all__ = [
    "InMemoryOAuthTokenStorage",
    "OAuth2InteractiveConfig",
    "make_interactive_oauth2_auth",
]
