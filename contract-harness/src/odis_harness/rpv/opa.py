"""`opa eval` subprocess wrapper.

Spawns the `opa` binary in a sandboxed mode and parses the result. The sandbox
makes the "hermetic policy evaluation" claim real on two fronts: a minimal
process environment (so a policy's `opa.runtime().env` cannot read the Router's
secrets) and a capabilities allowlist that removes the network/DNS built-ins
(`http.send`, `net.lookup_ip_addr`) — a bundle's Rego cannot exfiltrate.
Passes the AuthzRequest payload as `--stdin-input`; raises `OpaEvalError` on any
non-zero exit or unparseable output.
"""

from __future__ import annotations

import functools
import json
import os
import subprocess
import tempfile
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path


class OpaEvalError(RuntimeError):
    """`opa eval` exited non-zero, timed out, or returned unparseable output."""


#: Wall-clock ceiling for a single policy evaluation. A pathological or malicious
#: operator-supplied Rego (e.g. an unbounded comprehension) would otherwise hang
#: the Router's forward path; a timeout surfaces as OpaEvalError → fail closed (deny).
_OPA_EVAL_TIMEOUT_S = 5.0

#: Built-ins dropped from the policy sandbox: network egress (`http.send`), DNS
#: (`net.lookup_ip_addr`), and host-runtime introspection (`opa.runtime`, which
#: exposes the process environment). A bundle's Rego cannot reach the network or
#: read the Router's secrets through them.
_SANDBOXED_BUILTINS = frozenset({"http.send", "net.lookup_ip_addr", "opa.runtime"})


def _sandbox_env() -> dict[str, str]:
    """A minimal environment for the opa subprocess.

    `opa.runtime().env` cannot expose the Router's secrets if the subprocess
    carries none. Only `PATH` is retained (a sane default for process spawning).
    """
    return {"PATH": os.environ.get("PATH", "")}


@functools.lru_cache(maxsize=8)
def _restricted_capabilities_file(opa_binary: str) -> str | None:
    """Build (once per binary) a capabilities file dropping `_SANDBOXED_BUILTINS`.

    Derives the allowlist from the binary's own `opa capabilities --current`, so
    it tracks the installed OPA version. Returns the file path, or `None` if the
    binary cannot report its capabilities — the caller then still applies the
    environment sandbox (defense-in-depth degrades, it does not vanish).
    """
    try:
        completed = subprocess.run(  # noqa: S603 - opa_binary is deployment-config-pinned
            [opa_binary, "capabilities", "--current"],
            capture_output=True,
            check=True,
            timeout=_OPA_EVAL_TIMEOUT_S,
            env=_sandbox_env(),
        )
        caps = json.loads(completed.stdout)
    except (OSError, subprocess.SubprocessError, json.JSONDecodeError):
        return None
    caps["builtins"] = [
        b for b in caps.get("builtins", []) if b.get("name") not in _SANDBOXED_BUILTINS
    ]
    fd, path = tempfile.mkstemp(prefix="odis-opa-caps-", suffix=".json")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(caps, handle)
    return path


def opa_eval(
    *,
    opa_binary: str,
    rego_path: Path,
    input_payload: Mapping[str, Any],
    query: str = "data.odis_policy.decision",
) -> Any:  # noqa: ANN401 — Rego decision shape varies by query
    """Evaluate `query` against `rego_path` with `input_payload` as `--input`.

    Returns the parsed result `value`. Raises `OpaEvalError` if the binary
    exits non-zero, returns no expressions, or returns unparseable JSON.
    """
    if not opa_binary:
        message = "no opa binary configured; set ODIS_OPA_BIN or pass opa_binary"
        raise OpaEvalError(message)

    cmd = [
        opa_binary,
        "eval",
        "--format=json",
        "--data",
        str(rego_path),
        "--stdin-input",
        query,
    ]
    # Sandbox: drop network/runtime built-ins when the binary reports capabilities.
    # The flag is an `eval` sub-flag, so it must follow the "eval" subcommand.
    capabilities_file = _restricted_capabilities_file(opa_binary)
    if capabilities_file is not None:
        cmd[2:2] = ["--capabilities", capabilities_file]
    payload = json.dumps(input_payload).encode("utf-8")
    # Security: opa_binary MUST come from a trusted configuration source
    # (deployment-pinned path, not an env var in untrusted contexts). The
    # harness inherits the deployment's trust assumptions about the path.
    try:
        completed = subprocess.run(  # noqa: S603 - opa_binary is deployment-config-pinned
            cmd,
            input=payload,
            capture_output=True,
            check=False,
            timeout=_OPA_EVAL_TIMEOUT_S,
            env=_sandbox_env(),
        )
    except FileNotFoundError as e:
        message = f"opa binary not found at {opa_binary!r}"
        raise OpaEvalError(message) from e
    except subprocess.TimeoutExpired as e:
        message = f"opa eval timed out after {_OPA_EVAL_TIMEOUT_S}s"
        raise OpaEvalError(message) from e

    if completed.returncode != 0:
        # Compile/type errors (e.g. a sandbox-blocked built-in like http.send)
        # land on stdout as a JSON `errors` array; only runtime failures use
        # stderr. Surface whichever carries the detail so the fail-closed reason
        # is meaningful rather than an opaque exit code.
        stderr = completed.stderr.decode("utf-8", errors="replace").strip()
        stdout = completed.stdout.decode("utf-8", errors="replace").strip()
        detail = stderr or stdout or "(no output)"
        message = f"opa eval exited {completed.returncode}: {detail}"
        raise OpaEvalError(message)

    try:
        parsed = json.loads(completed.stdout.decode("utf-8"))
    except json.JSONDecodeError as e:
        message = f"opa eval returned unparseable JSON: {e}"
        raise OpaEvalError(message) from e

    # opa eval shape:
    # {"result": [{"expressions": [{"value": <result>, "text": ..., ...}]}]}
    results = parsed.get("result") or []
    if not results:
        message = "opa eval returned no results"
        raise OpaEvalError(message)
    expressions = results[0].get("expressions") or []
    if not expressions:
        message = "opa eval result had no expressions"
        raise OpaEvalError(message)
    return expressions[0].get("value")


__all__ = ["OpaEvalError", "opa_eval"]
