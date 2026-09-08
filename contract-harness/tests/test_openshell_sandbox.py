"""The OpenShell sandbox image must ship the MCP client the agent is written against.

The sandbox is egress-locked to the Router once it starts, so it cannot reach PyPI to
correct a bad resolve — a wrong version there fails a hundred seconds into a Docker
build rather than here. The pin lives in a Dockerfile the Python suite never imports,
which is exactly why it needs a guard: nothing else makes the two drift visibly.
"""

from __future__ import annotations

import re

from odis_harness.paths import repo_root

_DOCKERFILE = repo_root() / "examples" / "openshell-gated-agent" / "sandbox" / "Dockerfile"
_PIN = re.compile(r'"mcp==(?P<version>[^"]+)"')
_LOCKED = re.compile(r'name = "mcp"\nversion = "(?P<version>[^"]+)"')


def _locked_mcp_version() -> str:
    """The `mcp` version in `uv.lock` — the committed resolution, not the live venv.

    Deliberately not `importlib.metadata.version`: a developer whose venv has drifted
    from the lock would see this test demand the Dockerfile match the drift, and the
    sandbox agent is written against the locked major.
    """
    match = _LOCKED.search((repo_root() / "uv.lock").read_text(encoding="utf-8"))
    assert match is not None, "uv.lock does not pin mcp"
    return match.group("version")


def test_sandbox_pins_the_same_mcp_version_the_router_is_tested_with() -> None:
    match = _PIN.search(_DOCKERFILE.read_text(encoding="utf-8"))
    assert match is not None, (
        f"{_DOCKERFILE} must pin mcp exactly. A floor (`mcp>=…`) resolves to whatever is "
        "newest at build time, and the client API is not stable across majors."
    )
    assert match.group("version") == _locked_mcp_version()
