"""A vendor MCP server on a loopback port, for tests that need a real transport.

Separate from `factories.py` on purpose. `conftest.py` keeps the `mcp`/`httpx`/`starlette`/
`uvicorn` import graph out of anything every test module loads, so that one broken optional
dependency yields a targeted skip rather than zero collected tests. `factories.py` is
loaded by nearly every module; this is imported only by the two that bind a socket.

Every test using it needs a module-level `pytestmark = pytest.mark.enable_socket` — the
suite runs `--disable-socket`.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING, Self

import uvicorn
from mcp.server.lowlevel import Server
from mcp.types import TextContent, Tool

from odis_harness.mcp_forwarder.transports import build_asgi_app, mcp_url
from tests import factories

if TYPE_CHECKING:
    from collections.abc import Sequence

#: The one tool the stand-in serves. `required` is asserted by the `list_tools` test, so
#: it is part of the contract this double presents, not decoration.
VENDOR_TOOL = Tool(
    name="update_issue",
    description="Update a Jira issue",
    inputSchema={"type": "object", "required": ["issue_key"]},
)


def vendor_server() -> Server:
    """A minimal stand-in for a vendor MCP server (e.g. a Jira MCP).

    `call_tool` echoes `<name>:<issue_key>`, which is what lets a caller prove the
    arguments arrived intact rather than merely that a call was made.
    """
    server: Server = Server("fake-jira-vendor")

    @server.list_tools()  # type: ignore[no-untyped-call, untyped-decorator]  # MCP SDK decorator is untyped — see test_e2e.py
    async def _list() -> list[Tool]:
        return [VENDOR_TOOL]

    @server.call_tool(validate_input=False)  # type: ignore[untyped-decorator]  # MCP SDK decorator is untyped — see test_e2e.py
    async def _call(name: str, arguments: dict) -> list[TextContent]:  # type: ignore[type-arg]  # SDK callback signature uses a bare dict — see test_e2e.py
        return [TextContent(type="text", text=f"{name}:{arguments.get('issue_key')}")]

    return server


def _capturing_app(inner, captured):  # type: ignore[no-untyped-def]  # ASGI wrapper over untyped scope/receive/send callables
    """ASGI wrapper recording each inbound request's headers, lowercased."""

    async def app(scope, receive, send):  # type: ignore[no-untyped-def]  # ASGI app callable is structurally untyped
        if scope["type"] == "http":
            captured.append({k.decode().lower(): v.decode() for k, v in scope.get("headers", [])})
        await inner(scope, receive, send)

    return app


class RunningVendor:
    """Serves `vendor_server()` on a loopback port for the duration of the context.

    Pass `captured` to record the headers of every inbound HTTP request — the hook for
    asserting what the Router actually put on the wire (its bearer, its trace id).
    """

    def __init__(self, captured: list[dict[str, str]] | None = None) -> None:
        self.port = factories.free_port()
        app = build_asgi_app(vendor_server())
        if captured is not None:
            app = _capturing_app(app, captured)
        self._server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error")
        )
        self._task: asyncio.Task[None] | None = None

    @property
    def url(self) -> str:
        return mcp_url("127.0.0.1", self.port)

    async def __aenter__(self) -> Self:
        self._task = asyncio.create_task(self._server.serve())
        for _ in range(100):
            if self._server.started:
                break
            if self._task.done():
                # The task raising is the common failure (a port already bound). Break
                # rather than polling out the full timeout, so `_stop` re-raises the real
                # exception instead of the generic "did not start" five seconds later.
                break
            await asyncio.sleep(0.05)
        if not self._server.started:
            # Started the task before deciding it failed, so tear it down here: an
            # abandoned uvicorn task keeps its socket and surfaces in whichever later
            # test happens to bind next, which is the hardest kind of flake to trace.
            await self._stop()
            message = "vendor server did not start"
            raise RuntimeError(message)
        return self

    async def __aexit__(self, *_exc: object) -> None:
        await self._stop()

    async def _stop(self) -> None:
        """Ask the server to exit, then await the task with a bound.

        Bounded because `should_exit` is cooperative: a server wedged before its loop
        checks the flag would otherwise hang the whole suite on teardown.
        """
        self._server.should_exit = True
        if self._task is None:
            return
        task, self._task = self._task, None
        # `wait_for` cancels the task itself on timeout, so there is nothing to cancel
        # by hand — only the resulting exception to swallow.
        with contextlib.suppress(TimeoutError, asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)


def authorization_headers(captured: Sequence[dict[str, str]]) -> list[str | None]:
    """The `Authorization` header of every captured request, in order."""
    return [h.get("authorization") for h in captured]


__all__ = [
    "VENDOR_TOOL",
    "RunningVendor",
    "authorization_headers",
    "vendor_server",
]
