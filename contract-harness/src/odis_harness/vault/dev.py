"""Dev-mode Vault lifecycle for hermetic `requires_vault` tests and the smoke.

Boots `vault server -dev` with the built apf-bundle-issuer plugin, provisions it via
`vault/provision.sh`, and exposes the workload JWT + the transit public key. Intended
for tests gated on `ODIS_VAULT_BIN` (skip when absent) — the dev server is local,
ephemeral, and torn down on exit, matching the harness's no-external-service ethos.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

from odis_harness.mcp_forwarder.transports import free_loopback_port

if TYPE_CHECKING:
    from types import TracebackType

# Repo root — the dir holding src/, vault/, vault-plugin/. parents[3] of this file
# resolves it in BOTH the nested dev layout and a standalone clone of the repo.
_HARNESS = Path(__file__).resolve().parents[3]
_PLUGIN_DIR = _HARNESS / "vault-plugin" / "dist"
_PLUGIN_BIN = _PLUGIN_DIR / "apf-bundle-issuer"
_PROVISION = _HARNESS / "vault" / "provision.sh"
_READY_TIMEOUT_S = 20.0


def vault_bin() -> str | None:
    """The vault binary to drive: ODIS_VAULT_BIN, else on PATH, else a sibling beside
    the repo (dev convenience), else None."""
    env = os.environ.get("ODIS_VAULT_BIN")
    if env and Path(env).is_file():
        return env
    on_path = shutil.which("vault")
    if on_path:
        return on_path
    sibling = _HARNESS.parent / "vault"
    return str(sibling) if sibling.is_file() else None


def plugin_built() -> bool:
    return _PLUGIN_BIN.is_file()


def plugin_current() -> bool:
    """True when the built plugin is present **and** newer than every source it is built from.

    Presence alone is not enough. `vault` resolves from the ambient PATH on most developer
    machines, so the `requires_vault` slice runs rather than skipping, and it then runs
    against whatever binary happens to be in `dist/`. A binary predating a field the
    plugin now emits fails on that field, which reads as a code defect and is really a
    build gap.

    Checked here rather than by making the test task depend on the Go build: the root
    `[tools]` deliberately omits `go` so a fresh clone stays focused on the
    zero-infrastructure demo, and `DevVault.build_plugin` already rebuilds when a
    toolchain is present.
    """
    if not _PLUGIN_BIN.is_file():
        return False
    built = _PLUGIN_BIN.stat().st_mtime
    plugin_root = _HARNESS / "vault-plugin"
    return all(
        src.stat().st_mtime <= built
        for pattern in ("**/*.go", "**/*.json", "go.mod", "go.sum")
        for src in plugin_root.glob(pattern)
        if "/dist/" not in src.as_posix()
    )


@dataclass(frozen=True, kw_only=True, slots=True)
class DevVaultContext:
    """Handles to a provisioned dev Vault for the Router-side flow."""

    addr: str
    workload_jwt: str
    transit_public_key_b64: str
    jwt_login_mount: str
    jwt_login_role: str
    issue_path: str


class DevVault:
    """Context manager that boots, provisions, and tears down a dev-mode Vault."""

    def __init__(self, *, port: int | None = None, fixdir: str | None = None) -> None:
        """Boot on `port`, or an ephemeral free port when it is not given.

        The port and the fixture directory are per-instance so two suite runs can
        provision concurrently. A fixed port makes the second run attach to the first
        run's Vault and authenticate against its JWT role, which surfaces as a 403 from
        `auth/jwt/login` — indistinguishable from a real provisioning bug.
        """
        self._bin = vault_bin()
        self._port = port if port is not None else free_loopback_port()
        # The fixture dir holds a live workload JWT, so it is created per instance under
        # the system temp dir and removed in `_terminate` rather than named by port: a
        # predictable name is either shared between concurrent runs or left behind by
        # every one of them, and this material must not outlive its Vault.
        self._fixdir = fixdir if fixdir is not None else tempfile.mkdtemp(prefix="odis-dev-fix-")
        self._owns_fixdir = fixdir is None
        self._addr = f"http://127.0.0.1:{self._port}"
        self._proc: subprocess.Popen[bytes] | None = None
        self._log = Path(f"/tmp/odis-dev-vault-{self._port}.log")  # noqa: S108 — ephemeral dev log

    def __enter__(self) -> DevVaultContext:
        if self._bin is None:
            message = "no vault binary (set ODIS_VAULT_BIN or place ./vault)"
            raise RuntimeError(message)
        if not plugin_built():
            message = f"plugin not built at {_PLUGIN_BIN} (run: mise run build-vault-plugin)"
            raise RuntimeError(message)

        with self._log.open("wb") as log:
            self._proc = subprocess.Popen(  # noqa: S603 — fixed argv, local dev binary
                [
                    self._bin,
                    "server",
                    "-dev",
                    "-dev-root-token-id=root",
                    f"-dev-plugin-dir={_PLUGIN_DIR}",
                    f"-dev-listen-address=127.0.0.1:{self._port}",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        # __exit__ (which terminates the process) only runs if __enter__ returns,
        # so tear the subprocess down here if readiness/provisioning fails —
        # otherwise a spawned dev Vault would leak.
        try:
            self._wait_ready()
            self._provision()
        except BaseException:
            self._terminate()
            raise
        return self._gather()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._terminate()

    def _terminate(self) -> None:
        """Terminate the dev Vault and shred the fixture dir (idempotent).

        The fixture dir goes even if the subprocess teardown raises: it holds a bearer,
        and leaving it behind is the worse of the two failures.
        """
        try:
            if self._proc is not None:
                self._proc.terminate()
                try:
                    self._proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self._proc.kill()
                    # `kill` only signals; without a second wait the dev Vault stays a
                    # zombie for the life of the test session.
                    self._proc.wait(timeout=10)
        finally:
            if self._owns_fixdir:
                shutil.rmtree(self._fixdir, ignore_errors=True)

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + _READY_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(f"{self._addr}/v1/sys/health", timeout=1.0)
            except httpx.HTTPError:
                time.sleep(0.3)
                continue
            if resp.status_code in {200, 429, 473}:  # initialized/unsealed/standby
                return
            time.sleep(0.3)
        message = "dev Vault did not become ready in time"
        raise RuntimeError(message)

    def _provision(self) -> None:
        env = {
            **os.environ,
            "VAULT": self._bin or "",
            "VAULT_ADDR": self._addr,
            "VAULT_TOKEN": "root",
            "HARNESS": str(_HARNESS),
            "FIXDIR": self._fixdir,
        }
        subprocess.run(  # noqa: S603 — fixed script path, local dev
            ["bash", str(_PROVISION)],  # noqa: S607 — bash on PATH
            env=env,
            check=True,
            capture_output=True,
        )

    def _gather(self) -> DevVaultContext:
        workload_jwt = (Path(self._fixdir) / "jwt").read_text(encoding="ascii")
        resp = httpx.get(
            f"{self._addr}/v1/transit/keys/apf-bundle",
            headers={"X-Vault-Token": "root"},
            timeout=5.0,
        )
        resp.raise_for_status()
        pub_b64 = resp.json()["data"]["keys"]["1"]["public_key"]
        return DevVaultContext(
            addr=self._addr,
            workload_jwt=workload_jwt,
            transit_public_key_b64=pub_b64,
            jwt_login_mount="jwt",
            jwt_login_role="router",
            issue_path="apf/issue",
        )

    @classmethod
    def build_plugin(cls) -> bool:
        """Build the plugin if a Go toolchain is available; return whether it's present."""
        go = shutil.which("go") or str(Path.home() / ".local/go/bin/go")
        if Path(go).is_file():
            subprocess.run(  # noqa: S603 — fixed argv, local toolchain
                [go, "build", "-o", "dist/apf-bundle-issuer", "."],
                cwd=str(_HARNESS / "vault-plugin"),
                check=True,
                capture_output=True,
            )
        return plugin_current()
